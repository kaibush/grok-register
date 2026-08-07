"""Outlook 账号池与临时邮箱渠道适配器。

同时支持 API Key 查询、Web Session 登录、CSRF 状态更新和验证码轮询。
"""

from __future__ import annotations

import random
import re
import threading
import time
from datetime import datetime
from email.utils import parsedate_to_datetime
from http.cookies import SimpleCookie
from typing import Any, Callable, Iterable, List, Optional
from urllib.parse import urlsplit

from backend.mailbox.utilities import extract_verification_code, strip_html

HttpGet = Callable[..., Any]
SessionFactory = Callable[[], Any]
UnavailableCheck = Callable[[str], bool]

_state_lock = threading.RLock()
_account_index = 0
_session_cookie = ""
_session_cookie_key: tuple[str, str] | None = None
_reserved_emails: set[str] = set()
_reserved_accounts: dict[str, dict] = {}


def response_error_detail(resp: Any, *, url: str = "", request_body: Any = None) -> str:
    """Keep HTTP failures actionable without dumping cookies or auth headers."""
    status = int(getattr(resp, "status_code", 0) or 0)
    body = ""
    try:
        body = str(resp.text or "").strip()
    except Exception:
        try:
            body = str(resp.json())
        except Exception:
            body = ""
    if len(body) > 1000:
        body = body[:1000] + "..."
    parts = [f"HTTP {status}"]
    if url:
        parts.append(f"url={url}")
    if request_body is not None:
        parts.append(f"request_body={request_body!r}")
    if body:
        parts.append(f"response_body={body}")
    return "; ".join(parts)


def normalize_base(api_base: str) -> str:
    base = str(api_base or "").strip().rstrip("/")
    if not base:
        raise Exception("OutlookEmail API Base 未配置")
    return base


def normalize_source(source: str) -> str:
    value = str(source or "accounts").strip().lower()
    return value if value in {"accounts", "temp"} else "accounts"


def api_headers(api_key: str) -> dict:
    key = str(api_key or "").strip()
    if not key:
        raise Exception("OutlookEmail accounts 来源需要配置 API Key")
    return {"X-API-Key": key}


def reset_runtime_state() -> None:
    global _account_index, _session_cookie, _session_cookie_key
    with _state_lock:
        _account_index = 0
        _session_cookie = ""
        _session_cookie_key = None
        _reserved_emails.clear()
        _reserved_accounts.clear()


def release_email(email: str) -> None:
    normalized = str(email or "").strip().lower()
    if not normalized:
        return
    with _state_lock:
        _reserved_emails.discard(normalized)


def cookie_from_response(resp: Any) -> str:
    try:
        raw_cookie = str(resp.headers.get("set-cookie", "") or "")
    except Exception:
        raw_cookie = ""
    if not raw_cookie:
        return ""
    try:
        cookie = SimpleCookie()
        cookie.load(raw_cookie)
        return "; ".join(f"{key}={value.value}" for key, value in cookie.items())
    except Exception:
        return ""


def cookie_from_session(session: Any) -> str:
    try:
        items = list(session.cookies.items())
        if items:
            return "; ".join(f"{key}={value}" for key, value in items)
    except Exception:
        pass
    try:
        jar = getattr(session.cookies, "jar", None)
        if jar:
            items = [f"{item.name}={item.value}" for item in jar]
            if items:
                return "; ".join(items)
    except Exception:
        pass
    return ""


def merge_cookie_headers(*values: str) -> str:
    """合并多次响应里的 Cookie，同名项以后者为准。"""
    merged: dict[str, str] = {}
    for raw in values:
        text = str(raw or "").strip()
        if not text:
            continue
        try:
            cookie = SimpleCookie()
            cookie.load(text)
            for key, value in cookie.items():
                merged[key] = value.value
        except Exception:
            for part in text.split(";"):
                if "=" not in part:
                    continue
                key, value = part.split("=", 1)
                key = key.strip()
                if key:
                    merged[key] = value.strip()
    return "; ".join(f"{key}={value}" for key, value in merged.items())


def seed_session_cookie(session: Any, cookie_header: str, api_base: str = "") -> bool:
    """Put an existing Cookie header into the session jar.

    The OutlookEmail CSRF endpoint rotates the Flask session cookie. Keeping the
    cookie in the jar lets the following PUT use that rotated value instead of
    an explicit stale ``Cookie`` header.
    """
    text = str(cookie_header or "").strip()
    if not text:
        return False
    pairs: list[tuple[str, str]] = []
    try:
        parsed = SimpleCookie()
        parsed.load(text)
        pairs = [(key, morsel.value) for key, morsel in parsed.items()]
    except Exception:
        pairs = []
    if not pairs:
        pairs = [
            (part.split("=", 1)[0].strip(), part.split("=", 1)[1].strip())
            for part in text.split(";")
            if "=" in part and part.split("=", 1)[0].strip()
        ]
    hostname = str(urlsplit(normalize_base(api_base)).hostname or "").strip() if api_base else ""
    try:
        for key, value in pairs:
            setter = getattr(session.cookies, "set", None)
            if callable(setter):
                if hostname:
                    # A leading dot keeps the seeded cookie ahead of the
                    # host-only cookie rotated by Flask. This works for IPs,
                    # localhost and single-label Docker service names.
                    setter(key, value, domain=f".{hostname}", path="/")
                else:
                    setter(key, value)
            else:
                session.cookies[key] = value
        return bool(pairs)
    except Exception:
        return False


def login_cookie(
    session_factory: SessionFactory,
    api_base: str,
    web_password: str,
    *,
    proxies: Optional[dict] = None,
    force_refresh: bool = False,
) -> str:
    global _session_cookie, _session_cookie_key
    base = normalize_base(api_base)
    password = str(web_password or "")
    if not password:
        return ""
    cache_key = (base, password)
    with _state_lock:
        if not force_refresh and _session_cookie and _session_cookie_key == cache_key:
            return _session_cookie

    session = session_factory()
    if proxies:
        try:
            session.proxies = proxies
        except Exception:
            pass
    login_resp = session.post(
        f"{base}/api/extension/login",
        json={"password": password, "next": "/"},
        headers={"Content-Type": "application/json"},
        timeout=15,
    )
    login_resp.raise_for_status()
    data = login_resp.json()
    if not isinstance(data, dict) or not data.get("success") or not data.get("launch_url"):
        raise Exception(f"OutlookEmail 网页登录失败: {str(data)[:200]}")
    launch_url = str(data.get("launch_url") or "")
    url = launch_url if launch_url.startswith(("http://", "https://")) else f"{base}/{launch_url.lstrip('/')}"
    session_resp = session.get(url, allow_redirects=True, timeout=15)
    session_resp.raise_for_status()
    cookie = merge_cookie_headers(
        cookie_from_response(login_resp),
        cookie_from_response(session_resp),
        cookie_from_session(session),
    )
    if not cookie:
        raise Exception("OutlookEmail 登录成功但未获取到 Session Cookie")
    with _state_lock:
        _session_cookie = cookie
        _session_cookie_key = cache_key
    return cookie


def account_for_email(
    http_get: HttpGet,
    api_base: str,
    api_key: str,
    email: str,
    *,
    group_id: str = "",
) -> dict:
    normalized = str(email or "").strip().lower()
    if not normalized:
        raise Exception("OutlookEmail 停用缺少邮箱地址")
    with _state_lock:
        cached = dict(_reserved_accounts.get(normalized) or {})
    if cached.get("id"):
        return cached
    for item in get_accounts(http_get, api_base, api_key, group_id=group_id):
        if item_email(item).strip().lower() == normalized:
            with _state_lock:
                _reserved_accounts[normalized] = dict(item)
            return item
    raise Exception(f"OutlookEmail 账号池中未找到邮箱: {email}")


def disable_account(
    http_get: HttpGet,
    session_factory: SessionFactory,
    api_base: str,
    email: str,
    *,
    api_key: str = "",
    group_id: str = "",
    web_password: str = "",
    session_cookie: str = "",
    proxies: Optional[dict] = None,
) -> dict:
    """把 accounts 来源的邮箱状态更新为 inactive。

    API Key 用于定位账号 ID；网页登录密码会自动换 Session Cookie，再自动获取
    CSRF Token。Session Cookie 仅作为没有网页登录密码时的兼容回退。
    """
    base = normalize_base(api_base)
    account = account_for_email(
        http_get,
        base,
        api_key,
        email,
        group_id=group_id,
    )
    account_id = account.get("id")
    try:
        account_id = int(account_id)
    except (TypeError, ValueError):
        raise Exception(f"OutlookEmail 账号缺少有效 ID: {email}")
    if str(account.get("status", "") or "").strip().lower() == "inactive":
        return {
            "success": True,
            "account_id": account_id,
            "already_inactive": True,
            "message": "邮箱已处于停用状态",
        }

    password = str(web_password or "")
    manual_cookie = str(session_cookie or "").strip()
    if not password and not manual_cookie:
        raise Exception("OutlookEmail 自动停用需要配置 Web 登录密码")

    last_error = ""
    for attempt in range(2):
        cookie = login_cookie(
            session_factory,
            base,
            password,
            proxies=proxies,
            force_refresh=attempt > 0,
        ) if password else manual_cookie
        if not cookie:
            raise Exception("OutlookEmail 未获取到 Web Session Cookie")

        session = session_factory()
        if proxies:
            try:
                session.proxies = proxies
            except Exception:
                pass
        cookie_in_jar = seed_session_cookie(session, cookie, base)
        csrf_headers = {"Accept": "application/json"}
        if not cookie_in_jar:
            csrf_headers["Cookie"] = cookie
        csrf_resp = session.get(
            f"{base}/api/csrf-token",
            headers=csrf_headers,
            timeout=15,
        )
        if int(getattr(csrf_resp, "status_code", 0) or 0) in (401, 403):
            last_error = "Web Session 已失效"
            if password and attempt == 0:
                continue
            raise Exception(f"OutlookEmail {last_error}")
        if int(getattr(csrf_resp, "status_code", 0) or 0) >= 400:
            raise Exception(response_error_detail(csrf_resp, url=f"{base}/api/csrf-token"))
        csrf_data = csrf_resp.json()
        if not isinstance(csrf_data, dict):
            raise Exception("OutlookEmail CSRF 响应格式错误")
        csrf_disabled = bool(csrf_data.get("csrf_disabled"))
        csrf_token = str(csrf_data.get("csrf_token") or "")
        if not csrf_disabled and not csrf_token:
            raise Exception("OutlookEmail 未获取到 CSRF Token")

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if not cookie_in_jar:
            # Fallback for minimal/custom session implementations without a jar.
            headers["Cookie"] = merge_cookie_headers(cookie, cookie_from_response(csrf_resp))
        if csrf_token:
            headers["X-CSRFToken"] = csrf_token
        update_resp = session.put(
            f"{base}/api/accounts/{account_id}",
            headers=headers,
            json={"status": "inactive"},
            timeout=15,
        )
        if int(getattr(update_resp, "status_code", 0) or 0) in (401, 403):
            last_error = "Web Session 或 CSRF 校验失效"
            if password and attempt == 0:
                continue
            raise Exception(f"OutlookEmail {last_error}")
        if int(getattr(update_resp, "status_code", 0) or 0) >= 400:
            detail = response_error_detail(
                update_resp,
                url=f"{base}/api/accounts/{account_id}",
                request_body={"status": "inactive"},
            )
            raise Exception(f"OutlookEmail 停用请求失败: {detail}")
        data = update_resp.json()
        if not isinstance(data, dict) or not data.get("success"):
            error = data.get("error") if isinstance(data, dict) else ""
            message = data.get("message") if isinstance(data, dict) else ""
            raise Exception(f"OutlookEmail 停用失败: {error or message or str(data)[:200]}")
        with _state_lock:
            current = dict(_reserved_accounts.get(str(email).strip().lower()) or account)
            current["status"] = "inactive"
            _reserved_accounts[str(email).strip().lower()] = current
        return {
            "success": True,
            "account_id": account_id,
            "already_inactive": False,
            "message": str(data.get("message") or "状态更新成功"),
        }
    raise Exception(f"OutlookEmail 停用失败: {last_error or '未知错误'}")


def session_headers(
    session_factory: SessionFactory,
    api_base: str,
    *,
    web_password: str = "",
    session_cookie: str = "",
    proxies: Optional[dict] = None,
) -> dict:
    cookie = login_cookie(
        session_factory,
        api_base,
        web_password,
        proxies=proxies,
    ) or str(session_cookie or "").strip()
    if not cookie:
        raise Exception("OutlookEmail temp 来源需要配置网页登录密码或 Session Cookie")
    return {"Cookie": cookie}


def pick_list(data: Any) -> List[dict]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        return []
    for key in ("emails", "items", "results", "accounts", "temp_emails", "tempEmails", "messages"):
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    nested = data.get("data")
    if isinstance(nested, list):
        return [item for item in nested if isinstance(item, dict)]
    if isinstance(nested, dict):
        return pick_list(nested)
    return []


def item_email(item: Any) -> str:
    if not isinstance(item, dict):
        return ""
    for key in ("email", "address", "name"):
        value = str(item.get(key, "") or "").strip()
        if "@" in value:
            return value
    return ""


def item_is_active(item: Any) -> bool:
    """账号池中 status=inactive 表示已停用，不参与注册。"""
    if not isinstance(item, dict):
        return False
    return str(item.get("status", "") or "").strip().lower() != "inactive"


def parse_tag_ids(raw: str | Iterable[Any]) -> set[str]:
    if isinstance(raw, str):
        return {item.strip() for item in re.split(r"[,，\s]+", raw) if item.strip()}
    return {str(item).strip() for item in (raw or []) if str(item).strip()}


def temp_matches_tags(item: Any, tag_ids: set[str]) -> bool:
    if not tag_ids:
        return True
    tags = item.get("tags") if isinstance(item, dict) else None
    if not isinstance(tags, list):
        return False
    for tag in tags:
        if isinstance(tag, dict) and str(tag.get("id", "")).strip() in tag_ids:
            return True
        if str(tag).strip() in tag_ids:
            return True
    return False


def get_accounts(
    http_get: HttpGet,
    api_base: str,
    api_key: str,
    *,
    group_id: str = "",
) -> List[dict]:
    params: dict[str, Any] = {
        "limit": 10000,
        "offset": 0,
        "sort_by": "created_at",
        "sort_order": "asc",
    }
    group = str(group_id or "").strip()
    if group:
        params["group_id"] = group
    resp = http_get(
        f"{normalize_base(api_base)}/api/external/accounts",
        headers=api_headers(api_key),
        params=params,
    )
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict) or not data.get("success"):
        raise Exception(f"OutlookEmail 获取账号列表失败: {str(data)[:200]}")
    accounts = data.get("accounts")
    if not isinstance(accounts, list):
        raise Exception(f"OutlookEmail accounts 格式错误: {str(data)[:200]}")
    return [item for item in accounts if isinstance(item, dict)]


def get_temp_emails(
    http_get: HttpGet,
    session_factory: SessionFactory,
    api_base: str,
    *,
    web_password: str = "",
    session_cookie: str = "",
    temp_tag_ids: str = "",
    proxies: Optional[dict] = None,
) -> List[dict]:
    resp = http_get(
        f"{normalize_base(api_base)}/api/temp-emails",
        headers=session_headers(
            session_factory,
            api_base,
            web_password=web_password,
            session_cookie=session_cookie,
            proxies=proxies,
        ),
    )
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict) and data.get("success") is False:
        raise Exception(f"OutlookEmail 获取临时邮箱失败: {str(data)[:200]}")
    tag_ids = parse_tag_ids(temp_tag_ids)
    return [
        item
        for item in pick_list(data)
        if item_email(item) and temp_matches_tags(item, tag_ids)
    ]


def acquire_email(
    http_get: HttpGet,
    session_factory: SessionFactory,
    api_base: str,
    *,
    api_key: str = "",
    source: str = "accounts",
    group_id: str = "",
    web_password: str = "",
    session_cookie: str = "",
    temp_tag_ids: str = "",
    pick_mode: str = "random",
    proxies: Optional[dict] = None,
    is_unavailable: Optional[UnavailableCheck] = None,
) -> tuple[str, str]:
    global _account_index
    normalized_source = normalize_source(source)
    if normalized_source == "temp":
        accounts = get_temp_emails(
            http_get,
            session_factory,
            api_base,
            web_password=web_password,
            session_cookie=session_cookie,
            temp_tag_ids=temp_tag_ids,
            proxies=proxies,
        )
    else:
        accounts = get_accounts(http_get, api_base, api_key, group_id=group_id)

    candidates = []
    for item in accounts:
        email = item_email(item)
        if not email or not item_is_active(item):
            continue
        if is_unavailable:
            try:
                if is_unavailable(email):
                    continue
            except Exception:
                pass
        candidates.append(item)
    if not candidates:
        raise Exception("OutlookEmail 邮箱池为空或已全部使用")

    mode = str(pick_mode or "random").strip().lower()
    with _state_lock:
        account = None
        if mode == "random":
            shuffled = candidates[:]
            random.shuffle(shuffled)
            for item in shuffled:
                normalized = item_email(item).lower()
                if normalized not in _reserved_emails:
                    _reserved_emails.add(normalized)
                    account = item
                    break
        else:
            for _ in range(len(candidates)):
                item = candidates[_account_index % len(candidates)]
                _account_index += 1
                normalized = item_email(item).lower()
                if normalized not in _reserved_emails:
                    _reserved_emails.add(normalized)
                    account = item
                    break
    if account is None:
        raise Exception("OutlookEmail 可用邮箱已被当前运行占用")
    email = item_email(account)
    with _state_lock:
        _reserved_accounts[email.lower()] = dict(account)
    return email, f"outlookemail:{normalized_source}:{email}"


def get_messages(
    http_get: HttpGet,
    api_base: str,
    api_key: str,
    email: str,
    *,
    folder: str = "all",
    top: int = 10,
) -> List[dict]:
    try:
        limit = max(1, min(50, int(top)))
    except Exception:
        limit = 10
    params = {
        "email": email,
        "folder": str(folder or "all").strip() or "all",
        "top": limit,
        "skip": 0,
    }
    resp = http_get(
        f"{normalize_base(api_base)}/api/external/emails",
        headers=api_headers(api_key),
        params=params,
    )
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict) or not data.get("success"):
        raise Exception(f"OutlookEmail 获取邮件失败: {str(data)[:200]}")
    messages = data.get("emails")
    return [item for item in messages if isinstance(item, dict)] if isinstance(messages, list) else []


def get_temp_messages(
    http_get: HttpGet,
    session_factory: SessionFactory,
    api_base: str,
    email: str,
    *,
    web_password: str = "",
    session_cookie: str = "",
    proxies: Optional[dict] = None,
) -> List[dict]:
    resp = http_get(
        f"{normalize_base(api_base)}/api/temp-emails/{email}/messages",
        headers=session_headers(
            session_factory,
            api_base,
            web_password=web_password,
            session_cookie=session_cookie,
            proxies=proxies,
        ),
    )
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict) and data.get("success") is False:
        raise Exception(f"OutlookEmail 获取临时邮箱邮件失败: {str(data)[:200]}")
    return pick_list(data)


def message_received_at(message: Any) -> Optional[float]:
    """Return an email's received time as a Unix timestamp when available."""
    if not isinstance(message, dict):
        return None

    for key in (
        "timestamp",
        "received_at",
        "receivedAt",
        "receivedDateTime",
        "date",
        "created_at",
        "createdAt",
    ):
        raw_value = message.get(key)
        if raw_value is None or isinstance(raw_value, bool):
            continue

        if isinstance(raw_value, (int, float)):
            timestamp = float(raw_value)
        else:
            value = str(raw_value or "").strip()
            if not value:
                continue
            try:
                timestamp = float(value)
            except ValueError:
                try:
                    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError:
                    try:
                        parsed = parsedate_to_datetime(value)
                    except (TypeError, ValueError, OverflowError):
                        continue
                timestamp = parsed.timestamp()

        # Some temp-mail APIs expose Unix milliseconds instead of seconds.
        if timestamp > 100_000_000_000:
            timestamp /= 1000
        if timestamp > 0:
            return timestamp
    return None


def mail_text(message: Any) -> str:
    if not isinstance(message, dict):
        return ""
    parts = []
    for key in ("body_preview", "body", "text", "content", "snippet", "intro"):
        value = message.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(value)
        elif isinstance(value, dict):
            content = value.get("content") or value.get("text")
            if isinstance(content, str) and content.strip():
                parts.append(content)
    html_value = message.get("html")
    if isinstance(html_value, str):
        parts.append(strip_html(html_value))
    elif isinstance(html_value, list):
        for item in html_value:
            if isinstance(item, str):
                parts.append(strip_html(item))
    return "\n".join(parts)


def sender_text(message: Any) -> str:
    if not isinstance(message, dict):
        return ""
    sender = message.get("from") or message.get("sender") or ""
    if isinstance(sender, str):
        return sender
    if isinstance(sender, dict):
        email_address = sender.get("emailAddress")
        if isinstance(email_address, dict):
            return str(email_address.get("address") or email_address.get("name") or "")
        return str(sender.get("address") or sender.get("email") or sender.get("name") or "")
    return str(sender or "")


def wait_for_code(
    http_get: HttpGet,
    session_factory: SessionFactory,
    api_base: str,
    email: str,
    *,
    api_key: str = "",
    source: str = "accounts",
    web_password: str = "",
    session_cookie: str = "",
    folder: str = "all",
    top: int = 10,
    proxies: Optional[dict] = None,
    timeout: int = 180,
    poll_interval: int = 3,
    raise_if_cancelled: Callable[[Optional[Callable[[], bool]]], None],
    sleep_with_cancel: Callable[[float, Optional[Callable[[], bool]]], None],
    log_callback: Optional[Callable[[str], None]] = None,
    cancel_callback: Optional[Callable[[], bool]] = None,
    min_received_at: Optional[float] = None,
) -> str:
    deadline = time.time() + timeout
    seen_ids: set[str] = set()
    normalized_source = normalize_source(source)
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        try:
            if normalized_source == "temp":
                messages = get_temp_messages(
                    http_get,
                    session_factory,
                    api_base,
                    email,
                    web_password=web_password,
                    session_cookie=session_cookie,
                    proxies=proxies,
                )
            else:
                messages = get_messages(
                    http_get,
                    api_base,
                    api_key,
                    email,
                    folder=folder,
                    top=top,
                )
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] OutlookEmail 拉取邮件失败: {exc}")
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        if log_callback:
            log_callback(f"[Debug] OutlookEmail 本轮邮件数量: {len(messages)}")
        for message in messages:
            subject = str(message.get("subject", "") or "")
            text = mail_text(message)
            message_id = str(
                message.get("id")
                or message.get("message_id")
                or message.get("internet_message_id")
                or f"{subject}|{text[:120]}"
            )
            if message_id in seen_ids:
                continue
            seen_ids.add(message_id)
            if min_received_at is not None:
                received_at = message_received_at(message)
                if received_at is None:
                    if log_callback:
                        log_callback("[Debug] OutlookEmail 跳过无可用收件时间的邮件")
                    continue
                if received_at <= min_received_at:
                    if log_callback:
                        log_callback(
                            "[Debug] OutlookEmail 跳过提交邮箱前收到的邮件: "
                            f"received_at={received_at:.3f} <= submitted_at={min_received_at:.3f}"
                        )
                    continue
            if log_callback:
                log_callback(f"[Debug] OutlookEmail 收到邮件: {subject} ({sender_text(message)})")
            code = extract_verification_code(text, subject)
            if code:
                if log_callback:
                    log_callback(f"[*] OutlookEmail 从邮件中提取到验证码: {code}")
                return code
        sleep_with_cancel(poll_interval, cancel_callback)
    raise Exception(f"OutlookEmail 在 {timeout}s 内未收到验证码邮件")
