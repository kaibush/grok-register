# -*- coding: utf-8 -*-
"""启动前依赖检查。

集中验证代理出口、邮箱渠道和授权服务配置，返回适合控制台展示的结构化结果。
"""
from __future__ import annotations

import socket
import time
from typing import Callable, List, Tuple
from urllib.parse import urlparse

from backend.mailbox import cloudflare_worker as cloudflare_provider
from backend.integrations.proxy import resolve_proxy_url
from backend.shared.paths import resolve_project_path

CheckResult = Tuple[str, bool, str]  # name, ok, detail
XAI_SIGNUP_CHECK_NAME = "xAI注册页"
XAI_SIGNUP_URL = "https://accounts.x.ai/sign-up?redirect=grok-com"


def _tcp_open(host: str, port: int, timeout: float = 2.0) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def _trace_exit_ip(http_get: Callable, proxies: dict) -> str:
    """请求 Cloudflare trace 端点并解析出口 IP（失败返回空串）。"""
    resp = http_get(
        "https://www.cloudflare.com/cdn-cgi/trace",
        timeout=8,
        proxies=proxies,
    )
    text = str(getattr(resp, "text", "") or "")
    ip = ""
    loc = ""
    for line in text.splitlines():
        if line.startswith("ip="):
            ip = line[3:].strip()
        elif line.startswith("loc="):
            loc = line[4:].strip()
    if ip and loc:
        return f"{ip} ({loc})"
    return ip


def check_proxy(proxy_url: str, http_get: Callable) -> CheckResult:
    proxy_url = (proxy_url or "").strip()
    if not proxy_url:
        # 直连也打印出口 IP，方便与走代理时对比确认代理是否生效
        try:
            direct_ip = _trace_exit_ip(http_get, {})
        except Exception:
            direct_ip = ""
        detail = "未配置（直连）"
        if direct_ip:
            detail += f"，出口IP {direct_ip}"
        return "代理", True, detail
    try:
        u = urlparse(proxy_url)
        host = u.hostname or "127.0.0.1"
        port = u.port or (443 if u.scheme == "https" else 80)
        if not _tcp_open(host, port):
            return "代理", False, f"无法连接 {host}:{port}"
        # 轻量探测 + 解析出口 IP，确认代理确实生效
        try:
            exit_ip = _trace_exit_ip(
                http_get, {"http": proxy_url, "https": proxy_url}
            )
        except Exception as exc:
            # TCP 通但出站失败也提示
            return "代理", False, f"TCP 通，出站探测失败: {exc}"
        if exit_ip:
            return "代理", True, f"{host}:{port} 可用，出口IP {exit_ip}"
        return "代理", True, f"{host}:{port} 可用（未解析到出口IP）"
    except Exception as exc:
        return "代理", False, str(exc)


def check_xai_signup(proxy_url: str, http_get: Callable) -> CheckResult:
    """按注册浏览器同一出口检查 accounts.x.ai，CF 拦截时禁止继续建号。"""
    proxy_url = str(proxy_url or "").strip()
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else {}
    try:
        resp = http_get(
            XAI_SIGNUP_URL,
            headers={
                "Accept": "text/html,application/xhtml+xml",
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/138.0.0.0 Safari/537.36"
                ),
            },
            timeout=15,
            allow_redirects=True,
            proxies=proxies,
            # curl_cffi 默认指纹容易被 accounts.x.ai 的 Cloudflare 判为非浏览器。
            # 预检必须使用与 OAuth 请求相同的 Chrome 指纹，否则会把可访问页面误判为 403。
            impersonate="chrome",
            _allow_direct_fallback=False,
        )
        status = int(getattr(resp, "status_code", 0) or 0)
        text = str(getattr(resp, "text", "") or "").lower()
        headers = {
            str(k).lower(): str(v).lower()
            for k, v in dict(getattr(resp, "headers", {}) or {}).items()
        }
        body_challenge = (
            "just a moment" in text[:2000]
            or "checking your browser" in text[:2000]
            or "__cf_chl" in text
            or "cf-error" in text
        )
        # Cloudflare 可能给正常页面也加 server: cloudflare，不能仅凭该头阻断。
        cf_challenge = body_challenge or (
            status in (403, 429, 503) and "cloudflare" in headers.get("server", "")
        )
        if status in (403, 429, 503) and cf_challenge:
            return (
                XAI_SIGNUP_CHECK_NAME,
                False,
                f"Cloudflare 拦截 HTTP {status}；请更换当前 proxy 后重试",
            )
        if cf_challenge:
            return XAI_SIGNUP_CHECK_NAME, False, "仍停留在 Cloudflare 挑战页"
        if status >= 400 or status <= 0:
            return XAI_SIGNUP_CHECK_NAME, False, f"HTTP {status or 'unknown'}"
        return XAI_SIGNUP_CHECK_NAME, True, f"可达 HTTP {status}"
    except Exception as exc:
        return XAI_SIGNUP_CHECK_NAME, False, str(exc)


def has_blocking_xai_failure(results: List[CheckResult]) -> bool:
    return any(name == XAI_SIGNUP_CHECK_NAME and not ok for name, ok, _ in results)


def check_email_api(provider: str, config: dict, http_get: Callable, http_post: Callable) -> CheckResult:
    provider = (provider or "").strip().lower()
    try:
        if provider == "cloudflare":
            base = str(config.get("cloudflare_api_base", "") or "").rstrip("/")
            if not base:
                return "邮箱API", False, "未配置 cloudflare_api_base"
            api_key = str(config.get("cloudflare_api_key", "") or "")
            auth_mode = str(config.get("cloudflare_auth_mode", "none") or "none")
            custom_auth = str(config.get("cloudflare_custom_auth", "") or "")
            accounts_path = str(
                config.get("cloudflare_path_accounts", "/admin/new_address")
                or "/admin/new_address"
            )
            if not accounts_path.startswith("/"):
                accounts_path = "/" + accounts_path

            auth_is_none = auth_mode.lower() == "none"

            if auth_is_none:
                # 直建模式：建号走 /new_address，不依赖 domains 端点。
                # 不发 HTTP 请求到 domains（避免 401 困扰），只验证服务器是否在线。
                parsed = urlparse(base)
                host = parsed.hostname
                if host:
                    port = 443 if parsed.scheme == "https" else 80
                    if not _tcp_open(host, port):
                        return "邮箱API", False, f"Cloudflare 服务不可达: {host}:{port}"
                note = ""
                return (
                    "邮箱API",
                    True,
                    f"Cloudflare 直建模式可用（建号端点 {accounts_path}）",
                )

            # auth_mode != none：探活建号端点本身，而不是 /api/domains。
            # cloudflare_temp_email 的 /api/domains 并不存在，且 /api/* 一律要求
            # 邮箱地址 Bearer JWT，用 admin/全局密码头探它必然 401 误报；建号端点
            # 才是注册真正调用的路径。GET 无副作用，可同时验证服务在线与鉴权通过：
            # 鉴权失败返回 401/403，鉴权通过但方法不允许返回 404（POST-only）。
            path = accounts_path
            url = f"{base}{path}"
            headers = cloudflare_provider.build_headers(api_key, auth_mode, custom_auth)
            params = cloudflare_provider.apply_auth_params({}, api_key, auth_mode)
            resp = http_get(url, headers=headers, params=params, timeout=10)
            code = resp.status_code
            if code in (401, 403):
                return "邮箱API", False, f"Cloudflare 鉴权失败 HTTP {code}（auth_mode={auth_mode}，探活端点 {path}）"
            if code >= 500:
                return "邮箱API", False, f"Cloudflare 服务异常 HTTP {code}（auth_mode={auth_mode}，探活端点 {path}）"
            if code == 404:
                # POST-only 建号端点 GET 探测返回 404（方法不允许）= 服务在线且鉴权通过。
                return "邮箱API", True, f"Cloudflare 鉴权通过，建号端点可用（探活端点 {path}）"
            return "邮箱API", True, f"Cloudflare 可达 HTTP {code}（auth_mode={auth_mode}，探活端点 {path}）"

        if provider == "duckmail":
            base = str(config.get("duckmail_api_base", "") or "https://api.duckmail.sbs").rstrip("/")
            resp = http_get(f"{base}/domains", headers={"Accept": "application/json"}, timeout=12)
            if resp.status_code >= 400:
                return "邮箱API", False, f"DuckMail/Mail.tm HTTP {resp.status_code}"
            return "邮箱API", True, f"DuckMail/Mail.tm 可达 HTTP {resp.status_code}"

        if provider == "yyds":
            key = str(config.get("yyds_api_key", "") or "")
            jwt = str(config.get("yyds_jwt", "") or "")
            if not key and not jwt:
                return "邮箱API", False, "YYDS 需配置 API Key 或 JWT"
            headers = {}
            if jwt:
                headers["Authorization"] = f"Bearer {jwt}"
            elif key:
                headers["X-API-Key"] = key
            resp = http_get("https://maliapi.215.im/v1/domains", headers=headers, timeout=12)
            ok = resp.status_code < 400
            return "邮箱API", ok, f"YYDS HTTP {resp.status_code}"

        if provider == "outlookemail":
            base = str(config.get("outlookemail_api_base", "") or "").strip().rstrip("/")
            if not base:
                return "邮箱API", False, "未配置 outlookemail_api_base"
            source = str(config.get("outlookemail_source", "accounts") or "accounts").strip().lower()
            if source == "temp":
                password = str(config.get("outlookemail_web_password", "") or "")
                cookie = str(config.get("outlookemail_session_cookie", "") or "").strip()
                if password:
                    resp = http_post(
                        f"{base}/api/extension/login",
                        json={"password": password, "next": "/"},
                        headers={"Content-Type": "application/json"},
                        timeout=12,
                        proxies={},
                    )
                    if resp.status_code >= 400:
                        return "邮箱API", False, f"OutlookEmail 网页登录 HTTP {resp.status_code}"
                    data = resp.json()
                    ok = isinstance(data, dict) and bool(data.get("success")) and bool(data.get("launch_url"))
                    return "邮箱API", ok, "OutlookEmail temp 网页登录可用" if ok else f"OutlookEmail 登录响应异常: {str(data)[:160]}"
                if not cookie:
                    return "邮箱API", False, "OutlookEmail temp 需配置网页登录密码或 Session Cookie"
                resp = http_get(
                    f"{base}/api/temp-emails",
                    headers={"Cookie": cookie},
                    timeout=12,
                    proxies={},
                )
                if resp.status_code >= 400:
                    return "邮箱API", False, f"OutlookEmail temp HTTP {resp.status_code}"
                data = resp.json()
                ok = not (isinstance(data, dict) and data.get("success") is False)
                return "邮箱API", ok, f"OutlookEmail temp HTTP {resp.status_code}"

            key = str(config.get("outlookemail_api_key", "") or "").strip()
            if not key:
                return "邮箱API", False, "OutlookEmail accounts 需配置 API Key"
            params = {"limit": 1, "offset": 0, "sort_by": "created_at", "sort_order": "asc"}
            group_id = str(config.get("outlookemail_group_id", "") or "").strip()
            if group_id:
                params["group_id"] = group_id
            resp = http_get(
                f"{base}/api/external/accounts",
                headers={"X-API-Key": key},
                params=params,
                timeout=12,
                proxies={},
            )
            if resp.status_code >= 400:
                return "邮箱API", False, f"OutlookEmail accounts HTTP {resp.status_code}"
            data = resp.json()
            ok = isinstance(data, dict) and bool(data.get("success")) and isinstance(data.get("accounts"), list)
            return "邮箱API", ok, f"OutlookEmail accounts HTTP {resp.status_code}"

        if provider == "mailnest":
            key = str(config.get("mailnest_api_key", "") or "").strip()
            if not key:
                return "邮箱API", False, "MailNest 需配置 API Key"
            # 不实际买号，只检查鉴权头能否打到站点
            resp = http_get(
                "https://mailnest.top/",
                headers={"Authorization": f"Bearer {key}"},
                timeout=12,
            )
            return "邮箱API", resp.status_code < 400, f"MailNest 站点 HTTP {resp.status_code}"

        if provider == "cloudmail":
            url = str(config.get("cloudmail_url", "") or "").rstrip("/")
            if not url:
                return "邮箱API", False, "未配置 cloudmail_url"
            resp = http_get(url, timeout=10)
            return "邮箱API", resp.status_code < 400, f"CloudMail HTTP {resp.status_code}"

        return "邮箱API", True, f"提供商 {provider} 跳过深度探测"
    except Exception as exc:
        return "邮箱API", False, str(exc)


def check_cpa(config: dict, http_get: Callable) -> CheckResult:
    if not config.get("cpa_auto_add"):
        return "CPA", True, "未开启 SSO→auth（跳过）"
    auth_dir = str(config.get("cpa_auth_dir", "") or "").strip()
    remote = str(config.get("cpa_remote_url", "") or "").strip()
    key = str(config.get("cpa_management_key", "") or "").strip()
    g2a_dir = str(config.get("grok2api_auth_dir", "") or "").strip()

    # 配置中的相对目录统一以项目根目录为基准。
    if auth_dir:
        auth_dir = str(resolve_project_path(auth_dir))
    if g2a_dir:
        g2a_dir = str(resolve_project_path(g2a_dir))

    if not auth_dir and not remote and not g2a_dir:
        return "CPA", False, "已开启但未配置 CPA auth 目录 / 远程地址 / Grok2API 目录"
    parts = []
    import os
    if auth_dir:
        if os.path.isdir(auth_dir):
            parts.append("CPA本地目录OK")
        else:
            # 自动创建目录
            try:
                os.makedirs(auth_dir, exist_ok=True)
                parts.append("CPA本地目录已创建")
            except Exception as exc:
                return "CPA", False, f"CPA auth 目录不存在且无法创建: {auth_dir} ({exc})"
    if g2a_dir:
        if os.path.isdir(g2a_dir):
            parts.append("Grok2API目录OK")
        else:
            try:
                os.makedirs(g2a_dir, exist_ok=True)
                parts.append("Grok2API目录已创建")
            except Exception as exc:
                return "CPA", False, f"Grok2API 目录不存在且无法创建: {g2a_dir} ({exc})"
    if remote:
        if not key:
            return "CPA", False, "已配远程地址但缺少管理密钥"
        try:
            u = urlparse(remote)
            host = u.hostname or "127.0.0.1"
            port = u.port or (443 if u.scheme == "https" else 80)
            if not _tcp_open(host, port):
                return "CPA", False, f"远程不可达 {host}:{port}"
            base = remote.rstrip("/")
            # 管理 API 列表
            resp = http_get(
                f"{base}/v0/management/auth-files",
                headers={"Authorization": f"Bearer {key}"},
                timeout=8,
                proxies={},  # CPA 一般本机
                impersonate="chrome",
            )
            if resp.status_code in (401, 403):
                return "CPA", False, f"管理密钥无效 HTTP {resp.status_code}"
            if resp.status_code >= 500:
                return "CPA", False, f"CPA 服务异常 HTTP {resp.status_code}"
            parts.append(f"远程OK HTTP {resp.status_code}")
        except Exception as exc:
            return "CPA", False, f"远程探测失败: {exc}"
    return "CPA", True, "；".join(parts) if parts else "OK"


def run_connectivity_checks(config: dict, http_get: Callable, http_post: Callable) -> List[CheckResult]:
    results = []
    proxy = resolve_proxy_url(config.get("proxy", ""))
    results.append(check_proxy(proxy, http_get))
    results.append(check_xai_signup(proxy, http_get))
    results.append(
        check_email_api(
            str(config.get("email_provider", "") or ""),
            config,
            http_get,
            http_post,
        )
    )
    results.append(check_cpa(config, http_get))
    return results


def format_check_results(results: List[CheckResult]) -> str:
    lines = []
    for name, ok, detail in results:
        mark = "OK" if ok else "FAIL"
        lines.append(f"[{mark}] {name}: {detail}")
    return "\n".join(lines)
