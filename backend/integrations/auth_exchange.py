#!/usr/bin/env python3
"""授权凭据交换与导出。

将注册得到的 SSO 凭据转换为下游服务可导入的数据，并负责探测、缓存和原子写入。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from backend.shared.paths import DATA_ROOT

from curl_cffi import requests

CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
OIDC_ISSUER = "https://auth.x.ai"
# 与 CPA internal/auth/xai/types.go 的 Scope 严格一致。
# 不可加 conversations:read/write —— 该 client 未获授权，device/code 与 consent
# 均会通过，但 token 端点会以 invalid_grant "Access denied" 拒绝签发。
SCOPES = "openid profile email offline_access grok-cli:access api:access"

# --- Device Flow 常量（主路径，对齐 CPA internal/auth/xai） --------------------
DEVICE_CODE_URL = f"{OIDC_ISSUER}/oauth2/device/code"
DEVICE_VERIFY_URL = f"{OIDC_ISSUER}/oauth2/device/verify"
DEVICE_APPROVE_URL = f"{OIDC_ISSUER}/oauth2/device/approve"
DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
DEVICE_DEFAULT_INTERVAL = 5
DEVICE_DEFAULT_EXPIRES = 1800
DEVICE_POLL_CAP_SECONDS = 90
# 浏览器点完「允许」后，服务端落库可能有延迟；协议路径 approve 多半无效，快速回退
DEVICE_GRACE_BROWSER = 60
DEVICE_GRACE_PROTOCOL = 10

# --- Authorization Code Flow 常量（回退路径） --------------------------------
# authorize 必须注入 referrer=grok-build，否则 access_token 无该 claim，
# cli-chat-proxy 会 403。实测 referrer=cli-proxy-api 会得到 referrer=None。
# plan=generic 对齐 grok-build-auth；consent.referrer 仍置空。
REDIRECT_URI = "http://127.0.0.1:56121/callback"
GROK_REFERRER = "grok-build"
GROK_PLAN = "generic"
GROK_VERSION = "0.2.93"
GROK_TOKEN_UA = f"grok-pager/{GROK_VERSION} grok-shell/{GROK_VERSION} (linux; x86_64)"
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
)
# consent 提交用的 Next.js Server Action ID（bootstrap；失效时扫 JS / 读本地缓存）
# 2026-07 实测：401b73e22a5e... 已 404；成功 ID 会写入 data/.next_action_id.cache 供下次快速路径
NEXT_ACTION_ID = "401b73e22a5e68737d0037e1aa449fef82cd1b35fb"
_NEXT_ACTION_CACHE_PATH = DATA_ROOT / ".next_action_id.cache"
_NEXT_ACTION_ID_RE = re.compile(r"^[0-9a-f]{40,44}$", re.I)
_working_next_action_id = ""  # 启动时由 _load_working_next_action_id() 填充
_NEXT_ACTION_RE = re.compile(
    r'(?:\$ACTION_ID_|next-action["\']?\s*[:=]\s*["\']|["\'])([0-9a-f]{40,44})["\']',
    re.I,
)
_CREATE_SERVER_REF_RE = re.compile(
    r'createServerReference\)?\(["\']([0-9a-f]{40,44})["\']',
    re.I,
)
_CALL_SERVER_RE = re.compile(
    r'["\']([0-9a-f]{40,44})["\']\s*,\s*(?:callServer|findSourceMapURL)',
    re.I,
)
_SCRIPT_SRC_RE = re.compile(r'src=["\']([^"\']+)["\']', re.I)

# --- CLIProxyAPI (CPA) 扁平格式常量 ------------------------------------------
# CPA 的 internal/auth/xai/token.go TokenStorage 读的是扁平字段。
# Build/CLI token（scope 含 grok-cli:access）必须走 cli-chat-proxy.grok.com，
# 不能用默认 api.x.ai/v1（那是计费通道，会 402）。
# headers 对齐 @xai-official/grok CLI / grok-build-auth（无 x-authenticateresponse）
CPA_TOKEN_ENDPOINT = f"{OIDC_ISSUER}/oauth2/token"
CPA_GROK_BASE_URL = "https://cli-chat-proxy.grok.com/v1"
CPA_GROK_HEADERS = {
    "User-Agent": GROK_TOKEN_UA,
    "X-XAI-Token-Auth": "xai-grok-cli",
    "x-authenticateresponse": "authenticate-response",
    "x-grok-client-identifier": "grok-pager",
    "x-grok-client-version": GROK_VERSION,
}
CPA_PROBE_MODEL = "grok-4.5"
CPA_PROBE_URL = f"{CPA_GROK_BASE_URL}/responses"
GROK_HOME_URL = "https://grok.com/"


def _normalize_next_action_id(value: str) -> str:
    val = str(value or "").strip().lower()
    if _NEXT_ACTION_ID_RE.fullmatch(val):
        return val
    return ""


def _load_working_next_action_id() -> str:
    """优先读磁盘缓存（上次成功的 consent Next-Action），否则回落内置 bootstrap。"""
    try:
        cached = _normalize_next_action_id(
            _NEXT_ACTION_CACHE_PATH.read_text(encoding="utf-8")
        )
        if cached:
            return cached
    except Exception:
        pass
    return _normalize_next_action_id(NEXT_ACTION_ID) or NEXT_ACTION_ID.lower()


def _save_working_next_action_id(action_id: str) -> None:
    """把已验证可用的 Next-Action 持久化，避免进程重启后再次扫 JS chunks。"""
    val = _normalize_next_action_id(action_id)
    if not val:
        return
    try:
        _NEXT_ACTION_CACHE_PATH.write_text(val + "\n", encoding="utf-8")
    except Exception:
        pass


def _invalidate_working_next_action_id(action_id: str = "") -> None:
    """某 ID 返回 Server action not found 时剔除，避免反复 404。"""
    global _working_next_action_id
    bad = _normalize_next_action_id(action_id)
    current = _normalize_next_action_id(_working_next_action_id)
    if bad and current and bad != current:
        return
    _working_next_action_id = ""
    try:
        if _NEXT_ACTION_CACHE_PATH.is_file():
            if not bad:
                _NEXT_ACTION_CACHE_PATH.unlink(missing_ok=True)
            else:
                cached = _normalize_next_action_id(
                    _NEXT_ACTION_CACHE_PATH.read_text(encoding="utf-8")
                )
                if not cached or cached == bad:
                    _NEXT_ACTION_CACHE_PATH.unlink(missing_ok=True)
    except Exception:
        pass


def _remember_working_next_action_id(action_id: str) -> None:
    global _working_next_action_id
    val = _normalize_next_action_id(action_id)
    if not val:
        return
    _working_next_action_id = val
    _save_working_next_action_id(val)


# 模块导入时加载缓存，保证 Web 冷启动也能走快速路径
_working_next_action_id = _load_working_next_action_id()


def b64url_decode(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)


def decode_jwt_payload(token: str) -> dict:
    try:
        return json.loads(b64url_decode(token.split(".")[1]))
    except Exception:
        return {}


def access_token_bfs(token: str):
    """读取 OAuth access_token 上的 bfs 声明；缺失时返回 None。"""
    payload = decode_jwt_payload(token)
    if not isinstance(payload, dict) or "bfs" not in payload:
        return None
    return payload.get("bfs")


def access_token_bot_risk(token: str) -> bool:
    """access_token 的 bfs=1 表示风控标记。"""
    bfs = access_token_bfs(token)
    return bfs == 1 or bfs == "1"


def rfc3339_ns(ts: float | None = None) -> str:
    """2026-07-10T01:00:00.000000000Z"""
    if ts is None:
        ts = time.time()
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + ".000000000Z"


def _urlopen(req, proxy: str = "", timeout: int = 15):
    """urllib 请求，proxy 非空时走代理。"""
    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
        return opener.open(req, timeout=timeout)
    return urllib.request.urlopen(req, timeout=timeout)


def _gen_pkce() -> tuple[str, str, str, str]:
    """生成 (code_verifier, code_challenge, state, nonce)。"""
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()
    nonce = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()
    return verifier, challenge, state, nonce


def _parse_consent_result(body: str) -> tuple[str | None, str]:
    """解析 consent 的 text/x-component 响应，返回 (code, 服务端错误)。

    服务端拒绝时回 {"success":false,"error":"Access denied"}——这是账号资质裁决，
    与 Next-Action 是否正确无关。必须把 error 透出来，否则会被误判成
    「这个 action id 不对」而去徒劳地换 ID、扫 JS chunk。
    """
    error = ""
    for line in body.split("\n"):
        start = line.find("{")
        if start < 0:
            continue
        try:
            data = json.loads(line[start:])
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        if data.get("code") and data.get("success") is not False:
            return data.get("code"), ""
        if data.get("error"):
            error = str(data.get("error"))
        elif data.get("success") is False and not error:
            error = "success=false"
    return None, error


def _parse_consent_code(body: str) -> str | None:
    """从 consent 提交的 text/x-component 响应里解析出 authorization code。"""
    return _parse_consent_result(body)[0]


def _extract_next_action_ids(html: str) -> list[str]:
    """仅从 HTML 文本抽哈希（弱信号；真正 id 多在 JS chunk）。"""
    found: list[str] = []
    seen: set[str] = set()
    text = html or ""

    def _add(val: str):
        v = (val or "").strip().lower()
        if len(v) < 40 or v in seen:
            return
        seen.add(v)
        found.append(v)

    for m in _CREATE_SERVER_REF_RE.finditer(text):
        _add(m.group(1))
    for m in _CALL_SERVER_RE.finditer(text):
        _add(m.group(1))
    for m in _NEXT_ACTION_RE.finditer(text):
        _add(m.group(1))
    if NEXT_ACTION_ID and NEXT_ACTION_ID.lower() not in seen:
        found.append(NEXT_ACTION_ID.lower())
    return found


def _discover_action_ids_from_js(session, html: str, base_url: str = "https://accounts.x.ai", log=None) -> list[str]:
    """从 consent 页引用的 /_next/static/chunks/*.js 解析 createServerReference 的 action id。

    HTML 内嵌的 40 位 hex 经常是错误候选（会 404）；真实 allow consent 在 JS 里。
    """
    found: list[str] = []
    seen: set[str] = set()
    priority: list[str] = []  # consent/oauth 相关 chunk 里的 id 优先

    def _add(val: str, prefer: bool = False):
        v = (val or "").strip().lower()
        if len(v) < 40 or v in seen:
            return
        seen.add(v)
        if prefer:
            priority.append(v)
        else:
            found.append(v)

    srcs = _SCRIPT_SRC_RE.findall(html or "")
    # 优先扫可能含 consent 逻辑的 chunk；其余也扫但限数量
    scored: list[tuple[int, str]] = []
    for src in srcs:
        low = src.lower()
        score = 0
        if "chunk" not in low and "/_next/" not in low:
            continue
        if any(k in low for k in ("consent", "oauth", "auth", "login", "sign")):
            score += 5
        scored.append((score, src))
    scored.sort(key=lambda x: (-x[0], x[1]))

    fetched = 0
    max_fetch = 40
    for score, src in scored:
        if fetched >= max_fetch:
            break
        full = src if src.startswith("http") else urllib.parse.urljoin(base_url.rstrip("/") + "/", src.lstrip("/"))
        try:
            resp = session.get(full, impersonate="chrome", timeout=15)
            text = str(resp.text or "")
        except Exception:
            continue
        fetched += 1
        prefer = score > 0 or ("consent" in text.lower() and "oauth" in text.lower())
        # 含 allow + createServerReference 的 chunk 更优先
        if "createServerReference" in text or "callServer" in text:
            prefer = True
        for m in _CREATE_SERVER_REF_RE.finditer(text):
            _add(m.group(1), prefer=prefer)
        for m in _CALL_SERVER_RE.finditer(text):
            _add(m.group(1), prefer=prefer)

    # HTML 弱信号放后
    for aid in _extract_next_action_ids(html):
        _add(aid, prefer=False)

    ordered = priority + [x for x in found if x not in priority]
    if log:
        log(f"  [*] 从 JS chunks 解析 Next-Action {len(ordered)} 个（扫 {fetched} 个脚本）")
    return ordered


def _new_sso_session(sso_cookie: str, proxy: str = ""):
    """创建带 SSO cookie 的 curl_cffi Session。"""
    proxies = {"http": proxy, "https": proxy} if proxy else None
    s = requests.Session()
    if proxies:
        s.proxies = proxies
    for domain in (".x.ai", "accounts.x.ai", "auth.x.ai", ".grok.com", "grok.com"):
        s.cookies.set("sso", sso_cookie, domain=domain)
        s.cookies.set("sso-rw", sso_cookie, domain=domain)
    return s


def _parse_grok_account_state(page_html: str) -> dict:
    """从 grok.com 首页 RSC 数据解析账号注册风控状态。"""
    raw = str(page_html or "")
    # Next.js 会把对象嵌入字符串，字段名通常表现为 \"botFlagSource\"。
    # 解开这一层即可按普通 JSON 片段稳定提取，不依赖具体 chunk 或组件名。
    normalized = raw.replace('\\"', '"')
    source_match = re.search(r'botFlagSource"\s*:\s*(null|-?\d+)', normalized)
    details_match = re.search(
        r'botFlagDetails"\s*:\s*(?:null|"([^"]*)")', normalized
    )

    source = None
    if source_match and source_match.group(1) != "null":
        try:
            source = int(source_match.group(1))
        except (TypeError, ValueError):
            source = None
    details = details_match.group(1) if details_match and details_match.group(1) else ""

    detail_fields: dict[str, str] = {}
    for item in details.split(","):
        key, sep, value = item.partition("=")
        if sep and key.strip():
            detail_fields[key.strip().lower()] = value.strip()
    risk = None
    try:
        if detail_fields.get("risk"):
            risk = float(detail_fields["risk"])
    except (TypeError, ValueError):
        risk = None
    policy = detail_fields.get("policy", "").lower()
    event = detail_fields.get("event", "")
    denied = policy == "deny" and event == "$registration"

    return {
        "found": bool(source_match or details_match),
        "bot_flag_source": source,
        "bot_flag_details": details,
        "policy": policy,
        "risk": risk,
        "event": event,
        "denied": denied,
    }


def inspect_sso_account_state(
    sso_cookie: str,
    proxy: str = "",
    log=print,
    timeout: int = 20,
) -> dict:
    """读取 grok.com 当前账号状态；诊断失败时返回 unknown，不阻断 OAuth。"""
    result = _parse_grok_account_state("")
    result.update({"status_code": 0, "url": "", "error": ""})
    token = str(sso_cookie or "").strip()
    if not token:
        result["error"] = "sso 为空"
        return result

    try:
        session = _new_sso_session(token, proxy=proxy)
        response = session.get(
            GROK_HOME_URL,
            headers={"User-Agent": DEFAULT_UA, "Accept": "text/html,application/xhtml+xml"},
            impersonate="chrome",
            timeout=timeout,
            allow_redirects=True,
        )
        result["status_code"] = int(getattr(response, "status_code", 0) or 0)
        result["url"] = str(getattr(response, "url", "") or "")
        if result["status_code"] != 200:
            suffix = "（可能是 Cloudflare/出口限制）" if result["status_code"] in (403, 429, 503) else ""
            result["error"] = f"grok.com HTTP {result['status_code']}{suffix}"
            return result
        parsed = _parse_grok_account_state(getattr(response, "text", "") or "")
        result.update(parsed)
        if parsed["denied"]:
            log(
                "  ❌ 注册风控状态: "
                f"botFlagSource={parsed['bot_flag_source']} "
                f"{parsed['bot_flag_details']}"
            )
        elif parsed["found"]:
            log(
                "  ✅ 注册风控状态可用: "
                f"botFlagSource={parsed['bot_flag_source']}"
            )
        else:
            result["error"] = "grok.com 未发现 botFlag 字段"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result


def _normalize_token_payload(token: dict) -> dict | None:
    if not isinstance(token, dict) or not token.get("access_token"):
        return None
    if not token.get("expires_in"):
        token["expires_in"] = 21600
    if not token.get("token_type"):
        token["token_type"] = "Bearer"
    return token


def _is_trusted_xai_url(raw: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(str(raw or "").strip())
    except Exception:
        return False
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    host = parsed.hostname.lower()
    return host == "x.ai" or host.endswith(".x.ai")


def _sso_principal_id(sso_cookie: str) -> str:
    claims = decode_jwt_payload(sso_cookie)
    for key in ("sub", "principal_id", "user_id", "uid", "id"):
        val = str(claims.get(key) or "").strip()
        if val:
            return val
    return ""


def _device_authorized(url: str = "", body: str = "") -> bool:
    u = str(url or "").lower()
    b = str(body or "").lower()
    if "/oauth2/device/done" in u or u.rstrip("/").endswith("/device/done"):
        return True
    markers = (
        "device authorized",
        "you have authorized",
        "device is authorized",
        "authorization complete",
        "设备已授权",
        "已授权此设备",
    )
    return any(m in b for m in markers)


def request_device_code(proxy: str = "", log=print, session=None) -> dict | None:
    """申请 device_code / user_code（对齐 CPA；可不带 SSO）。"""
    s = session
    own = False
    if s is None:
        own = True
        proxies = {"http": proxy, "https": proxy} if proxy else None
        s = requests.Session()
        if proxies:
            s.proxies = proxies
    try:
        log("  🔑 Device Flow: 申请 device_code / user_code ...")
        try:
            r = s.post(
                DEVICE_CODE_URL,
                data={"client_id": CLIENT_ID, "scope": SCOPES},
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                    "User-Agent": DEFAULT_UA,
                },
                impersonate="chrome",
                timeout=20,
            )
        except Exception as e:
            log(f"  ❌ device/code 异常: {e}")
            return None
        if r.status_code < 200 or r.status_code >= 300:
            log(f"  ❌ device/code HTTP {r.status_code}: {str(r.text)[:200]}")
            return None
        try:
            device = r.json()
        except Exception:
            log(f"  ❌ device/code 非 JSON: {str(r.text)[:200]}")
            return None
        device_code = str(device.get("device_code") or "").strip()
        user_code = str(device.get("user_code") or "").strip()
        if not device_code or not user_code:
            log(f"  ❌ device/code 响应缺字段: {device}")
            return None
        try:
            interval = max(1, int(device.get("interval") or DEVICE_DEFAULT_INTERVAL))
        except Exception:
            interval = DEVICE_DEFAULT_INTERVAL
        try:
            expires_in = max(30, int(device.get("expires_in") or DEVICE_DEFAULT_EXPIRES))
        except Exception:
            expires_in = DEVICE_DEFAULT_EXPIRES
        verification_complete = str(
            device.get("verification_uri_complete")
            or device.get("verification_url_complete")
            or ""
        ).strip()
        verification_uri = str(
            device.get("verification_uri") or device.get("verification_url") or ""
        ).strip()
        open_url = verification_complete or (
            f"{verification_uri}?user_code={urllib.parse.quote(user_code)}"
            if verification_uri
            else f"https://accounts.x.ai/oauth2/device?user_code={urllib.parse.quote(user_code)}"
        )
        log(f"  [*] user_code={user_code} interval={interval}s expires_in={expires_in}s")
        return {
            "device_code": device_code,
            "user_code": user_code,
            "interval": interval,
            "expires_in": expires_in,
            "verification_uri": verification_uri,
            "verification_uri_complete": verification_complete,
            "open_url": open_url,
        }
    finally:
        if own:
            try:
                s.close()
            except Exception:
                pass


def poll_device_token(
    device_code: str,
    interval: int = DEVICE_DEFAULT_INTERVAL,
    expires_in: int = DEVICE_DEFAULT_EXPIRES,
    proxy: str = "",
    log=print,
    session=None,
    grace_invalid_grant: float = 0.0,
) -> dict | None:
    """轮询 device_code → access/refresh token。

    grace_invalid_grant: x.ai 在设备尚未授权时返回 invalid_grant（而非 RFC 8628
    的 authorization_pending）。该秒数内把 invalid_grant 当作 pending 继续轮询，
    超出后才判为终态。浏览器授权路径应传较大值，纯协议路径传较小值以快速回退。
    """
    device_code = str(device_code or "").strip()
    if not device_code:
        log("  ❌ device_code 为空")
        return None
    s = session
    own = False
    if s is None:
        own = True
        proxies = {"http": proxy, "https": proxy} if proxy else None
        s = requests.Session()
        if proxies:
            s.proxies = proxies
    try:
        interval = max(1, int(interval or DEVICE_DEFAULT_INTERVAL))
        expires_in = max(30, int(expires_in or DEVICE_DEFAULT_EXPIRES))
        log("  [*] Device Flow: 轮询 access/refresh token ...")
        started_at = time.time()
        poll_deadline = started_at + min(expires_in, DEVICE_POLL_CAP_SECONDS)
        try:
            grace_deadline = started_at + max(0.0, float(grace_invalid_grant or 0.0))
        except Exception:
            grace_deadline = started_at
        last_err = ""
        while time.time() < poll_deadline:
            try:
                r = s.post(
                    f"{OIDC_ISSUER}/oauth2/token",
                    data={
                        "grant_type": DEVICE_CODE_GRANT_TYPE,
                        "device_code": device_code,
                        "client_id": CLIENT_ID,
                    },
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Accept": "application/json",
                        "User-Agent": GROK_TOKEN_UA,
                        "X-Grok-Client-Version": GROK_VERSION,
                    },
                    impersonate="chrome",
                    timeout=20,
                )
            except Exception as e:
                last_err = f"token 异常: {e}"
                log(f"  ⚠️ {last_err}")
                time.sleep(interval)
                continue
            payload = {}
            try:
                payload = r.json()
            except Exception:
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            err = str(payload.get("error") or "").strip()
            if r.status_code >= 200 and r.status_code < 300 and payload.get("access_token"):
                token = _normalize_token_payload(payload)
                if not token:
                    last_err = "token 缺 access_token"
                    break
                ap = decode_jwt_payload(token["access_token"])
                ref = ap.get("referrer")
                if ref:
                    log(f"  ✅ access_token referrer={ref!r}")
                log(
                    f"  ✅ access_token (expires_in={token.get('expires_in')}s)"
                    + (" + refresh_token" if token.get("refresh_token") else "")
                )
                return token
            if err == "authorization_pending":
                last_err = err
                time.sleep(interval)
                continue
            if err == "slow_down":
                interval = min(interval + 5, 30)
                last_err = err
                time.sleep(interval)
                continue
            if err == "invalid_grant" and time.time() < grace_deadline:
                # 授权刚提交时服务端可能尚未落库，宽限期内按 pending 处理
                last_err = "invalid_grant(宽限期内重试)"
                time.sleep(interval)
                continue
            if err in ("expired_token", "access_denied", "invalid_grant"):
                desc = str(payload.get("error_description") or "").strip()
                log(f"  ❌ device token 终态: {err} {desc}")
                return None
            last_err = f"HTTP {r.status_code} err={err or str(r.text)[:120]}"
            log(f"  ⚠️ token 轮询: {last_err}")
            time.sleep(interval)
        log(f"  ❌ device-flow 轮询超时/失败: {last_err}")
        return None
    finally:
        if own:
            try:
                s.close()
            except Exception:
                pass


def sso_to_token_device_browser(
    sso_cookie: str,
    browser_approve,
    proxy: str = "",
    log=print,
) -> dict | None:
    """Device Flow：HTTP 申请 code + 浏览器点「继续/允许」+ HTTP 轮询 token。

    browser_approve(user_code, open_url) -> bool
    """
    sso_cookie = str(sso_cookie or "").strip()
    if not sso_cookie:
        log("  ❌ sso 为空")
        return None
    if not callable(browser_approve):
        log("  ❌ browser_approve 回调不可用")
        return None

    # 轻量校验 SSO（带 cookie 的独立会话）
    s_check = _new_sso_session(sso_cookie, proxy=proxy)
    try:
        r = s_check.get("https://accounts.x.ai/", impersonate="chrome", timeout=15)
        final = str(getattr(r, "url", "") or "")
        if "sign-in" in final or "sign-up" in final or int(getattr(r, "status_code", 0) or 0) == 401:
            log("  ❌ sso 无效")
            return None
        log("  ✅ sso 有效（浏览器 Device 授权路径）")
    except Exception as e:
        log(f"  ❌ 网络错误: {e}")
        return None
    finally:
        try:
            s_check.close()
        except Exception:
            pass

    # device_code 申请不强制绑 SSO，对齐 CPA 服务端角色
    device = request_device_code(proxy=proxy, log=log, session=None)
    if not device:
        return None
    open_url = str(device.get("open_url") or "").strip()
    if open_url and not _is_trusted_xai_url(open_url):
        log(f"  ❌ verification URL 不受信: {open_url[:120]}")
        return None
    log(f"  [*] 浏览器授权: {open_url[:120]}")
    try:
        ok = bool(browser_approve(device["user_code"], open_url))
    except Exception as e:
        log(f"  ❌ 浏览器授权异常: {e}")
        return None
    if not ok:
        log("  ❌ 浏览器未完成 继续/允许")
        return None
    log("  ✅ 浏览器已提交「允许」，由 token 端点裁决结果")
    return poll_device_token(
        device["device_code"],
        interval=device.get("interval", DEVICE_DEFAULT_INTERVAL),
        expires_in=device.get("expires_in", DEVICE_DEFAULT_EXPIRES),
        proxy=proxy,
        log=log,
        session=None,
        grace_invalid_grant=DEVICE_GRACE_BROWSER,
    )


def sso_to_token_device_flow(sso_cookie: str, proxy: str = "", log=print) -> dict | None:
    """SSO cookie → token（纯协议 Device Flow + verify/approve，回退路径）。

    对齐 sub2api/gptGrok2api 的 /oauth2/device/verify + approve。
    主路径优先用 sso_to_token_device_browser（复用注册浏览器点允许）。
    """
    sso_cookie = str(sso_cookie or "").strip()
    if not sso_cookie:
        log("  ❌ sso 为空")
        return None

    principal_id = _sso_principal_id(sso_cookie)
    s = _new_sso_session(sso_cookie, proxy=proxy)
    try:
        r = s.get("https://accounts.x.ai/", impersonate="chrome", timeout=15)
    except Exception as e:
        log(f"  ❌ 网络错误: {e}")
        return None
    final = str(getattr(r, "url", "") or "")
    if "sign-in" in final or "sign-up" in final or int(getattr(r, "status_code", 0) or 0) == 401:
        log("  ❌ sso 无效")
        return None
    log("  ✅ sso 有效" + (f" principal_id={principal_id[:12]}..." if principal_id else "（协议路径）"))

    device = request_device_code(proxy=proxy, log=log, session=s)
    if not device:
        return None
    user_code = device["user_code"]
    open_url = str(device.get("open_url") or "")
    if open_url and _is_trusted_xai_url(open_url):
        try:
            s.get(open_url, impersonate="chrome", timeout=15, allow_redirects=True)
        except Exception as e:
            log(f"  ⚠️ 打开 verification URL 失败（继续 verify）: {e}")

    log("  [*] Device Flow: verify user_code ...")
    try:
        r = s.post(
            DEVICE_VERIFY_URL,
            data={"user_code": user_code},
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                "Origin": "https://accounts.x.ai",
                "Referer": open_url or "https://accounts.x.ai/",
                "User-Agent": DEFAULT_UA,
            },
            impersonate="chrome",
            timeout=20,
            allow_redirects=True,
        )
    except Exception as e:
        log(f"  ❌ device/verify 异常: {e}")
        return None
    verify_url = str(getattr(r, "url", "") or "")
    verify_body = str(getattr(r, "text", "") or "")
    if r.status_code in (401, 403) or "sign-in" in verify_url or "sign-up" in verify_url:
        log(f"  ❌ device/verify 会话无效 HTTP {r.status_code} url={verify_url[:120]}")
        return None
    if r.status_code < 200 or r.status_code >= 400:
        log(f"  ❌ device/verify HTTP {r.status_code}: {verify_body[:180]}")
        return None
    # 只认 URL：consent 页的 JS bundle / i18n 字典里含有「设备已授权」等全站文案，
    # 用 body 文本判定会误判成已授权而跳过 approve，导致一直 authorization_pending。
    if "/oauth2/device/done" in verify_url.lower():
        log("  ✅ device/verify 已直接授权")
    else:
        log(f"  ✅ device/verify OK → {verify_url[:120]}")
        log(
            "  [*] Device Flow: approve allow"
            + (f" principal_id={principal_id[:12]}..." if principal_id else " principal_id=(empty)")
            + " ..."
        )
        try:
            r = s.post(
                DEVICE_APPROVE_URL,
                data={
                    "user_code": user_code,
                    "action": "allow",
                    "principal_type": "User",
                    "principal_id": principal_id,
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                    "Origin": "https://accounts.x.ai",
                    "Referer": verify_url or "https://accounts.x.ai/",
                    "User-Agent": DEFAULT_UA,
                },
                impersonate="chrome",
                timeout=20,
                allow_redirects=True,
            )
        except Exception as e:
            log(f"  ❌ device/approve 异常: {e}")
            return None
        approve_url = str(getattr(r, "url", "") or "")
        approve_body = str(r.text or "")
        if r.status_code in (401, 403) or "sign-in" in approve_url:
            log(f"  ❌ device/approve 被拒 HTTP {r.status_code}")
            return None
        if r.status_code < 200 or r.status_code >= 400:
            log(f"  ❌ device/approve HTTP {r.status_code}: {approve_body[:180]}")
            return None
        if _device_authorized(approve_url, approve_body):
            log("  ✅ device/approve 已允许")
        else:
            # 不再把任意 HTTP 200 当成功；未到 done 直接失败，交给外层回退
            log(f"  ❌ device/approve 未到 done: {approve_url[:120]}")
            return None

    return poll_device_token(
        device["device_code"],
        interval=device.get("interval", DEVICE_DEFAULT_INTERVAL),
        expires_in=device.get("expires_in", DEVICE_DEFAULT_EXPIRES),
        proxy=proxy,
        log=log,
        session=s,
        grace_invalid_grant=DEVICE_GRACE_PROTOCOL,
    )


def sso_to_token_auth_code(sso_cookie: str, proxy: str = "", log=print) -> dict | None:
    """SSO cookie → token（Authorization Code + PKCE，回退路径）。

    authorize 注入 referrer=grok-build + plan=generic，
    consent 优先复用已成功的 Next-Action，失效时才扫描页面 JS 并重试。
    """
    global _working_next_action_id

    s = _new_sso_session(sso_cookie, proxy=proxy)
    try:
        r = s.get("https://accounts.x.ai/", impersonate="chrome", timeout=15)
    except Exception as e:
        log(f"  ❌ 网络错误: {e}")
        return None
    if "sign-in" in r.url or "sign-up" in r.url:
        log("  ❌ sso 无效")
        return None
    log("  ✅ sso 有效")

    verifier, challenge, state, nonce = _gen_pkce()

    # 1) 打开 authorize 页，跟随重定向进入 consent
    log(f"  🔑 Authorization Code Flow (referrer={GROK_REFERRER}, plan={GROK_PLAN})...")
    authorize_params = urllib.parse.urlencode({
        "client_id": CLIENT_ID,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "nonce": nonce,
        "plan": GROK_PLAN,
        "redirect_uri": REDIRECT_URI,
        "referrer": GROK_REFERRER,
        "response_type": "code",
        "scope": SCOPES,
        "state": state,
    })
    authorize_url = f"{OIDC_ISSUER}/oauth2/authorize?{authorize_params}"

    def _open_consent(discover_actions=False):
        try:
            resp = s.get(
                authorize_url,
                impersonate="chrome",
                timeout=15,
                allow_redirects=True,
            )
        except Exception as e:
            log(f"  ❌ authorize 异常: {e}")
            return None, "", []
        url = str(resp.url)
        if "sign-in" in url or "sign-up" in url:
            log("  ❌ sso 无效")
            return None, url, []
        if "/oauth2/consent" not in url:
            log(f"  ❌ authorize 未进入 consent: {url}")
            return None, url, []
        html = str(resp.text or "")
        # consent 实际在 accounts.x.ai（从 auth.x.ai authorize 重定向）
        base = "https://accounts.x.ai"
        if "auth.x.ai" in url and "accounts.x.ai" not in url:
            base = "https://auth.x.ai"
        if discover_actions:
            action_ids = _discover_action_ids_from_js(s, html, base_url=base, log=log)
        else:
            action_ids = []
            # 磁盘/内存中上次成功的 ID 优先；无缓存时再试 bootstrap
            for candidate in (
                _normalize_next_action_id(_working_next_action_id),
                _normalize_next_action_id(NEXT_ACTION_ID),
            ):
                if candidate and candidate not in action_ids:
                    action_ids.append(candidate)
            for action_id in _extract_next_action_ids(html):
                aid = _normalize_next_action_id(action_id) or str(action_id or "").strip().lower()
                if aid and aid not in action_ids:
                    action_ids.append(aid)
            log(f"  [*] consent 快速路径 Next-Action {len(action_ids)} 个（跳过 JS chunks 扫描）")
        return resp, url, action_ids

    r, final_url, action_ids = _open_consent()
    if r is None:
        return None
    if not action_ids:
        action_ids = [NEXT_ACTION_ID]
        log(f"  ⚠️ 未解析到 Next-Action，使用 fallback {NEXT_ACTION_ID[:12]}...")
    else:
        log(f"  [*] consent Next-Action 候选 {len(action_ids)} 个（首个 {action_ids[0][:12]}...）")

    # 2) 提交 consent（allow），拿 authorization code
    # consent 也必须带 referrer=grok-build，否则 JWT claim 为 None
    consent_payload = json.dumps([{
        "action": "allow",
        "clientId": CLIENT_ID,
        "redirectUri": REDIRECT_URI,
        "scope": SCOPES,
        "state": state,
        "codeChallenge": challenge,
        "codeChallengeMethod": "S256",
        "nonce": nonce,
        "principalType": "User",
        "principalId": "",
        "referrer": GROK_REFERRER,
    }])

    code = None
    last_err = ""
    tried: set[str] = set()
    # 最多 2 轮：第一轮优先试上次成功/内置 id；失败再重开 consent 扫 JS chunks。
    for round_i in range(2):
        if round_i > 0:
            log("  [*] consent 失败，重新进入 authorize/consent 并解析 Next-Action...")
            r, final_url, action_ids = _open_consent(discover_actions=True)
            if r is None:
                return None
            if not action_ids:
                action_ids = [NEXT_ACTION_ID]

        for action_id in action_ids[:8]:
            if action_id in tried:
                continue
            tried.add(action_id)
            try:
                r = s.post(
                    final_url,
                    data=consent_payload,
                    headers={
                        "Content-Type": "text/plain;charset=UTF-8",
                        "Accept": "text/x-component",
                        "Origin": "https://accounts.x.ai",
                        "Referer": final_url,
                        "Next-Action": action_id,
                    },
                    impersonate="chrome",
                    timeout=15,
                    allow_redirects=True,
                )
            except Exception as e:
                last_err = f"consent 异常: {e}"
                log(f"  ❌ {last_err}")
                continue
            body = str(r.text or "")
            if r.status_code == 404 or "server action not found" in body.lower():
                last_err = f"consent HTTP {r.status_code}: {body[:160]}"
                log(f"  ⚠️ Next-Action {action_id[:12]}... 无效: {last_err}")
                # 剔除失效 ID，避免下次冷启动仍优先打 404
                _invalidate_working_next_action_id(action_id)
                continue
            if r.status_code < 200 or r.status_code >= 300:
                last_err = f"consent HTTP {r.status_code}: {body[:200]}"
                log(f"  ⚠️ {last_err}")
                continue
            code, server_err = _parse_consent_result(body)
            if code:
                _remember_working_next_action_id(action_id)
                log(f"  [*] Next-Action {action_id[:12]}... 返回 authorization code")
                break
            if server_err:
                # 服务端已受理并明确裁决（如 Access denied）：说明这个 action id
                # 是对的，问题在账号资质。再换 ID 或扫 JS chunk 都是白费。
                _remember_working_next_action_id(action_id)
                log(f"  ❌ consent 被服务端拒绝: {server_err}")
                log("     （Next-Action 有效，属账号资质裁决，换 ID 重试无意义）")
                return None
            # 200 但无 code 也无裁决：多半是别的 server action（如读用户信息）
            last_err = f"consent 未返回 code: {body[:180]}"
            log(f"  ⚠️ Next-Action {action_id[:12]}... 非 allow 响应，继续试")
        if code:
            break

    if not code:
        log(f"  ❌ consent 失败（已试 {len(tried)} 个 Next-Action）: {last_err}")
        return None
    log("  ✅ 授权确认")

    # 3) 用 authorization code 换 token
    token_data = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "code_verifier": verifier,
    })
    try:
        r = s.post(
            f"{OIDC_ISSUER}/oauth2/token",
            data=token_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": GROK_TOKEN_UA,
                "X-Grok-Client-Version": GROK_VERSION,
                "Accept": "*/*",
            },
            impersonate="chrome",
            timeout=15,
        )
    except Exception as e:
        log(f"  ❌ token 异常: {e}")
        return None
    if r.status_code < 200 or r.status_code >= 300:
        log(f"  ❌ token HTTP {r.status_code}: {str(r.text)[:200]}")
        return None
    try:
        token = r.json()
    except Exception:
        log(f"  ❌ token 返回非 JSON: {str(r.text)[:200]}")
        return None
    token = _normalize_token_payload(token or {})
    if not token:
        log("  ❌ token 缺少 access_token")
        return None

    # 校验 referrer claim（authorize 注入 grok-build 后应写入 JWT）
    ap = decode_jwt_payload(token["access_token"])
    ref = ap.get("referrer")
    if ref not in (GROK_REFERRER, "grok-build", "cli-proxy-api"):
        log(f"  ⚠️ access_token referrer={ref!r}（预期 {GROK_REFERRER!r} 或 grok-build）")
    else:
        log(f"  ✅ access_token referrer={ref!r}")
    log(
        f"  ✅ access_token (expires_in={token.get('expires_in')}s)"
        + (" + refresh_token" if token.get("refresh_token") else "")
    )
    return token


def sso_to_token(
    sso_cookie: str,
    proxy: str = "",
    log=print,
    prefer: str = "device",
    allow_fallback: bool = True,
    browser_approve=None,
) -> dict | None:
    """SSO cookie → token dict。

    默认顺序：
      1) 浏览器 Device（有 browser_approve 时）
      2) 纯协议 Device verify/approve
      3) Authorization Code（allow_fallback）
    prefer: "device" | "auth_code"
    """
    sso_cookie = str(sso_cookie or "").strip()
    if not sso_cookie:
        log("  ❌ sso 为空")
        return None

    order: list[str] = []
    if prefer == "auth_code":
        order = ["auth_code"]
        if allow_fallback:
            if callable(browser_approve):
                order.append("device_browser")
            order.append("device_protocol")
    else:
        if callable(browser_approve):
            order.append("device_browser")
        order.append("device_protocol")
        if allow_fallback:
            order.append("auth_code")
    if not allow_fallback and prefer == "device":
        # 已按上面构造；若只要单路径且无 browser，仅 protocol
        pass

    last_label = ""
    for method in order:
        last_label = method
        if method == "device_browser":
            log("  [*] 尝试浏览器 Device Flow（继续/允许）...")
            token = sso_to_token_device_browser(
                sso_cookie, browser_approve, proxy=proxy, log=log
            )
        elif method == "device_protocol":
            log("  [*] 尝试协议 Device Flow 换 token ...")
            token = sso_to_token_device_flow(sso_cookie, proxy=proxy, log=log)
        else:
            log("  [*] 尝试 Authorization Code 换 token ...")
            token = sso_to_token_auth_code(sso_cookie, proxy=proxy, log=log)
        if token and token.get("access_token"):
            if method != order[0]:
                log(f"  ✅ 回退路径 {method} 成功")
            return token
        if method != order[-1]:
            log(f"  ⚠️ {method} 失败，回退下一路径 ...")
    log(f"  ❌ 全部换 token 路径失败（最后尝试 {last_label}）")
    return None


def _iso_utc_from_unix(ts) -> str:
    """unix 秒 → CPA 认的 RFC3339（秒级，带 Z）。"""
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return ""


def _safe_email_for_filename(email: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "._-@" else "_" for ch in email)
    return safe or "unknown"


def token_to_cpa_record(token: dict, email: str = "", sso: str = "") -> dict:
    """token dict → CLIProxyAPI 扁平 xai auth 记录。

    对齐 CPA internal/auth/xai/token.go 的 TokenStorage 字段，以及
    grok-build-auth build_cliproxyapi_auth_record 的输出。
    """
    access = token.get("access_token") or token.get("key") or ""
    refresh = token.get("refresh_token") or ""
    id_token = token.get("id_token") or ""
    payload = decode_jwt_payload(access)
    id_payload = decode_jwt_payload(id_token) if id_token else {}

    if not email:
        email = id_payload.get("email") or payload.get("email") or ""
    sub = payload.get("sub") or id_payload.get("sub") or ""

    # expired: 优先 access token 的 exp，其次 expires_in 推算
    expired = ""
    if "exp" in payload:
        expired = _iso_utc_from_unix(payload["exp"])
    elif token.get("expires_in") is not None:
        try:
            expired = _iso_utc_from_unix(int(time.time()) + int(token["expires_in"]))
        except Exception:
            expired = ""

    record = {
        "type": "xai",
        "auth_kind": "oauth",
        "email": email or "",
        "sub": sub,
        "access_token": access,
        "refresh_token": refresh,
        "id_token": id_token,
        "token_type": token.get("token_type", "Bearer"),
        "expires_in": token.get("expires_in", None),
        "expired": expired,
        "last_refresh": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "redirect_uri": REDIRECT_URI,
        "token_endpoint": CPA_TOKEN_ENDPOINT,
        "base_url": CPA_GROK_BASE_URL,
        "disabled": False,
        "headers": dict(CPA_GROK_HEADERS),
    }
    sso_val = str(sso or "").strip()
    if sso_val:
        record["sso"] = sso_val
    return record


def cpa_auth_filename(record: dict) -> str:
    """生成 CPA auth 文件名：xai-<email>.json。"""
    ident = str(record.get("email") or "").strip() or str(record.get("sub") or "").strip()
    safe = _safe_email_for_filename(ident)
    # 避免 email 本地部分已是 xai 时出现 "xai-xai..."
    fname = safe if safe.lower().startswith("xai") else f"xai-{safe}"
    return f"{fname}.json"


def probe_cpa_record(
    record: dict,
    proxy: str = "",
    timeout: int = 30,
    model: str = CPA_PROBE_MODEL,
) -> tuple[int | None, str]:
    """直连 CLI chat proxy 自测，返回 (HTTP 状态码, 响应摘要)。"""
    access = str(record.get("access_token") or "").strip()
    if not access:
        return None, "missing access_token"

    headers = dict(record.get("headers") or {})
    headers["Authorization"] = f"Bearer {access}"
    headers["Content-Type"] = "application/json"
    kwargs = {
        "headers": headers,
        "json": {
            "model": model,
            "input": "ping",
            "max_output_tokens": 2,
            "stream": False,
        },
        "impersonate": "chrome",
        "timeout": timeout,
    }
    if proxy:
        kwargs["proxy"] = proxy
    try:
        resp = requests.post(CPA_PROBE_URL, **kwargs)
        summary = str(resp.text or "").replace("\n", " ").strip()
        return int(resp.status_code), summary[:300]
    except Exception as exc:
        return None, str(exc)[:300]


def write_cpa_auth(auth_dir: Path, record: dict) -> Path:
    """写出 CPA 可热加载的 xai-<email>.json（原子替换）。

    无 email 时用 sub(user_id) 命名，避免多个无 email 账号写成同一个
    xai-unknown.json 互相覆盖。
    """
    auth_dir.mkdir(parents=True, exist_ok=True)
    path = auth_dir / cpa_auth_filename(record)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


def grok2api_auth_filename(entry: dict, email: str = "") -> str:
    """Grok2API grok_build 导入文件名。"""
    ident = (
        str(email or "").strip()
        or str(entry.get("email") or "").strip()
        or str(entry.get("name") or "").strip()
        or str(entry.get("user_id") or "").strip()
        or secrets.token_hex(4)
    )
    safe = _safe_email_for_filename(ident)
    return f"g2a-{safe}.json"


def grok2api_format_filename(format_name: str, entry: dict, email: str = "") -> str:
    """返回三种 Grok2API 账号格式对应的文件名。"""
    normalized = str(format_name or "").strip().lower()
    if normalized == "grok_build":
        return grok2api_auth_filename(entry, email=email)
    if normalized not in {"grok_web", "grok_console"}:
        raise ValueError("format_name 必须是 grok_build、grok_web 或 grok_console")
    ident = (
        str(email or "").strip()
        or str(entry.get("email") or "").strip()
        or str(entry.get("name") or "").strip()
        or str(entry.get("user_id") or "").strip()
        or secrets.token_hex(4)
    )
    safe = _safe_email_for_filename(ident)
    prefix = "grok-web" if normalized == "grok_web" else "grok-console"
    return f"{prefix}-{safe}.json"


def token_to_grok2api_account(token: dict, email: str = "") -> dict:
    """token dict → Grok2API grok_build 导入账号条目。

    对齐 grok2api:
      - backend/internal/infra/provider/cli/import.go marshalCredentials
      - backend/internal/infra/provider/web/sso_build.go ConvertToBuild 输出字段
    可直接作为 {"accounts":[...]} 导入 Grok Build。
    """
    access = str(token.get("access_token") or token.get("key") or "").strip()
    refresh = str(token.get("refresh_token") or "").strip()
    id_token = str(token.get("id_token") or "").strip()
    payload = decode_jwt_payload(access)
    id_payload = decode_jwt_payload(id_token) if id_token else {}

    email_val = (
        str(email or "").strip()
        or str(id_payload.get("email") or "").strip()
        or str(payload.get("email") or "").strip()
    )
    user_id = (
        str(payload.get("sub") or "").strip()
        or str(payload.get("principal_id") or "").strip()
        or str(id_payload.get("sub") or "").strip()
        or str(id_payload.get("principal_id") or "").strip()
    )
    team_id = (
        str(payload.get("team_id") or "").strip()
        or str(id_payload.get("team_id") or "").strip()
    )
    name = email_val or user_id or "Grok Build account"

    expires_at = ""
    if "exp" in payload:
        expires_at = rfc3339_ns(float(payload["exp"]))
    elif token.get("expires_in") is not None:
        try:
            expires_at = rfc3339_ns(time.time() + int(token["expires_in"]))
        except Exception:
            expires_at = ""

    return {
        "provider": "grok_build",
        "name": name,
        "client_id": CLIENT_ID,
        "access_token": access,
        "refresh_token": refresh,
        # 导出格式对齐 marshalCredentials：不回填 id_token/scope/sub/principal_id
        "id_token": "",
        "token_type": str(token.get("token_type") or "Bearer") or "Bearer",
        "scope": "",
        "expires_at": expires_at,
        "expires_in": 0,
        "email": email_val,
        "sub": "",
        "user_id": user_id,
        "principal_id": "",
        "team_id": team_id,
    }


def _grok2api_template_identity(token: dict, email: str = "") -> tuple[str, str]:
    build_account = token_to_grok2api_account(token, email=email)
    email_value = str(build_account.get("email") or email or "").strip()
    user_id = str(build_account.get("user_id") or "").strip() or email_value
    return email_value, user_id


def token_to_grok2api_web_account(token: dict, email: str = "", sso: str = "") -> dict:
    """将 Token 和 SSO 转换为 Grok Web 的严格 accounts 条目。"""
    email_value, user_id = _grok2api_template_identity(token, email=email)
    return {
        "name": email_value,
        "email": email_value,
        "user_id": user_id,
        "sso_token": str(sso or "").strip(),
        "token": "",
        "tier": "basic",
        "cloudflare_cookies": "",
    }


def token_to_grok2api_console_account(token: dict, email: str = "", sso: str = "") -> dict:
    """将 Token 和 SSO 转换为 Grok Console 的严格 accounts 条目。"""
    email_value, user_id = _grok2api_template_identity(token, email=email)
    local_part = email_value.split("@", 1)[0] if email_value else user_id
    return {
        "name": f"Grok Console {local_part}".strip(),
        "email": email_value,
        "user_id": user_id,
        "sso_token": str(sso or "").strip(),
        "token": "",
        "cloudflare_cookies": "",
    }


def _write_grok2api_document(path: Path, document: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


def write_grok2api_auth(auth_dir: Path, token: dict, email: str = "") -> Path:
    """写出 Grok2API 可导入的 grok_build auth（accounts[] 包装）。"""
    account = token_to_grok2api_account(token, email=email)
    path = auth_dir / grok2api_auth_filename(account, email=email)
    return _write_grok2api_document(path, {"accounts": [account]})


def write_grok2api_auth_bundle(
    auth_dir: Path,
    token: dict,
    email: str = "",
    sso: str = "",
) -> dict[str, Path]:
    """同时写出 Grok Build、Grok Web 和 Grok Console 三种导入文件。"""
    web_account = token_to_grok2api_web_account(token, email=email, sso=sso)
    console_account = token_to_grok2api_console_account(token, email=email, sso=sso)
    return {
        "grok_build": write_grok2api_auth(auth_dir, token, email=email),
        "grok_web": _write_grok2api_document(
            auth_dir / grok2api_format_filename("grok_web", web_account, email=email),
            {"provider": "grok_web", "accounts": [web_account]},
        ),
        "grok_console": _write_grok2api_document(
            auth_dir / grok2api_format_filename("grok_console", console_account, email=email),
            {"provider": "grok_console", "accounts": [console_account]},
        ),
    }


def upload_cpa_auth_remote(
    base_url: str,
    management_key: str,
    record: dict,
    timeout: int = 30,
    proxy: str = "",
) -> str:
    """通过 CPA Management API 上传 auth 文件到远程实例。

    POST /v0/management/auth-files?name=<file.json>
    Header: Authorization: Bearer <management_key>
    Body: raw JSON auth record

    使用 curl_cffi（Chrome TLS 指纹）替代标准 requests，
    避免 CPA 服务端 Cloudflare 将裸 TLS 识别为非浏览器流量返回 403。
    """
    base = str(base_url or "").strip().rstrip("/")
    key = str(management_key or "").strip()
    if not base:
        raise ValueError("cpa_remote_url 为空")
    if not key:
        raise ValueError("cpa_management_key 为空")

    name = cpa_auth_filename(record)
    url = f"{base}/v0/management/auth-files"
    proxies = {"http": proxy, "https": proxy} if proxy else None
    # 不继承 HTTP_PROXY/HTTPS_PROXY；调用方如确实需要代理，必须显式传 proxy。
    with requests.Session(trust_env=False) as session:
        resp = session.post(
            url,
            params={"name": name},
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
            data=json.dumps(record, ensure_ascii=False).encode("utf-8"),
            timeout=timeout,
            proxies=proxies,
            impersonate="chrome",
        )
    if resp.status_code >= 400:
        body = (resp.text or "").strip()
        if len(body) > 300:
            body = body[:300] + "..."
        raise RuntimeError(f"远程上传失败 HTTP {resp.status_code}: {body or resp.reason}")
    return name
