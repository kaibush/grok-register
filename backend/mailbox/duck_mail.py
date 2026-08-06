"""DuckMail 与 Mail.tm 兼容渠道适配器。"""

from __future__ import annotations

import secrets
import string
from typing import Any, Callable, Dict, List, Optional

from backend.mailbox.utilities import strip_html

API_BASE_DEFAULT = "https://api.duckmail.sbs"

HttpGet = Callable[..., Any]
HttpPost = Callable[..., Any]


def normalize_base(base_url: str = "") -> str:
    base = str(base_url or API_BASE_DEFAULT).strip().rstrip("/")
    return base or API_BASE_DEFAULT


def should_use_api_key(base_url: str, api_key: str = "") -> bool:
    """mail.tm 公共接口不需要 dk_ key；DuckMail 私有域才需要。"""
    if not api_key:
        return False
    base = normalize_base(base_url).lower()
    if "mail.tm" in base and "duckmail" not in base:
        return False
    return True


def build_headers(
    api_key: str = "",
    content_type: bool = False,
    bearer_token: str = "",
) -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if content_type:
        headers["Content-Type"] = "application/json"
    token = bearer_token or api_key
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def list_payload(data: Any) -> List[dict]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("hydra:member", "member", "items", "data", "domains", "messages"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def domain_is_usable(domain: dict) -> bool:
    if not isinstance(domain, dict) or not domain.get("domain"):
        return False
    if domain.get("isPrivate") is True:
        return False
    if domain.get("isVerified") is False:
        return False
    if domain.get("isActive") is False:
        return False
    return True


def get_domains(
    http_get: HttpGet,
    base_url: str,
    api_key: str = "",
) -> List[dict]:
    base = normalize_base(base_url)
    use_key = should_use_api_key(base, api_key)
    resp = http_get(
        f"{base}/domains",
        headers=build_headers(api_key=api_key if use_key else ""),
    )
    resp.raise_for_status()
    return list_payload(resp.json())


def pick_domain(domains: List[dict]) -> str:
    if not domains:
        raise Exception("DuckMail/Mail.tm 没有返回任何可用域名")
    private = [
        d
        for d in domains
        if d.get("ownerId")
        and (d.get("isVerified") is not False)
        and (d.get("isActive") is not False)
    ]
    if private:
        return private[0]["domain"]
    public = [d for d in domains if domain_is_usable(d)]
    if public:
        return public[0]["domain"]
    for d in domains:
        if d.get("domain"):
            return d["domain"]
    raise Exception("DuckMail/Mail.tm 无可用域名")


def create_account(
    http_post: HttpPost,
    base_url: str,
    address: str,
    password: str,
    api_key: str = "",
    expires_in: int = 0,
) -> dict:
    base = normalize_base(base_url)
    use_key = should_use_api_key(base, api_key)
    data: Dict[str, Any] = {"address": address, "password": password}
    if use_key or "duckmail" in base.lower():
        data["expiresIn"] = expires_in
    headers = build_headers(api_key=api_key if use_key else "", content_type=True)
    resp = http_post(f"{base}/accounts", json=data, headers=headers)
    if resp.status_code >= 400 and "expiresIn" in data:
        data = {"address": address, "password": password}
        resp = http_post(f"{base}/accounts", json=data, headers=headers)
    resp.raise_for_status()
    payload = resp.json()
    return payload if isinstance(payload, dict) else {}


def get_token(
    http_post: HttpPost,
    base_url: str,
    address: str,
    password: str,
) -> Optional[str]:
    base = normalize_base(base_url)
    resp = http_post(
        f"{base}/token",
        json={"address": address, "password": password},
        headers=build_headers(content_type=True),
    )
    resp.raise_for_status()
    payload = resp.json() or {}
    if isinstance(payload, dict):
        return payload.get("token")
    return None


def get_messages(http_get: HttpGet, base_url: str, token: str) -> List[dict]:
    base = normalize_base(base_url)
    resp = http_get(
        f"{base}/messages",
        headers=build_headers(bearer_token=token),
    )
    resp.raise_for_status()
    return list_payload(resp.json())


def get_message_detail(
    http_get: HttpGet,
    base_url: str,
    token: str,
    message_id: str,
) -> dict:
    base = normalize_base(base_url)
    resp = http_get(
        f"{base}/messages/{message_id}",
        headers=build_headers(bearer_token=token),
    )
    resp.raise_for_status()
    payload = resp.json()
    return payload if isinstance(payload, dict) else {}


def generate_username(length: int = 10) -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(max(3, length)))


def create_mailbox(
    http_get: HttpGet,
    http_post: HttpPost,
    base_url: str,
    api_key: str = "",
    expires_in: int = 0,
) -> tuple[str, str]:
    domains = get_domains(http_get, base_url, api_key=api_key)
    domain = pick_domain(domains)
    username = generate_username(10)
    address = f"{username}@{domain}"
    password = secrets.token_urlsafe(12)
    create_account(
        http_post,
        base_url,
        address,
        password,
        api_key=api_key,
        expires_in=expires_in,
    )
    token = get_token(http_post, base_url, address, password)
    if not token:
        raise Exception("获取 DuckMail/Mail.tm token 失败")
    return address, token


def wait_for_code(
    http_get: HttpGet,
    base_url: str,
    token: str,
    email: str,
    *,
    timeout: int = 180,
    poll_interval: int = 3,
    extract_code: Callable[[str, str], Optional[str]],
    raise_if_cancelled: Callable[[Optional[Callable[[], bool]]], None],
    sleep_with_cancel: Callable[[float, Optional[Callable[[], bool]]], None],
    log_callback: Optional[Callable[[str], None]] = None,
    cancel_callback: Optional[Callable[[], bool]] = None,
) -> str:
    import time

    deadline = time.time() + timeout
    seen_ids = set()
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        try:
            messages = get_messages(http_get, base_url, token)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] 拉取邮件列表失败: {exc}")
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        for msg in messages:
            msg_id = msg.get("id") or msg.get("msgid")
            if not msg_id or msg_id in seen_ids:
                continue
            recipients = [t.get("address", "").lower() for t in (msg.get("to") or [])]
            if email.lower() not in recipients:
                # mail.tm 部分列表项 to 为空，仍尝试读详情
                if recipients:
                    seen_ids.add(msg_id)
                    continue
            try:
                detail = get_message_detail(http_get, base_url, token, msg_id)
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] 获取邮件详情失败: {exc}")
                continue
            seen_ids.add(msg_id)
            parts = []
            text_body = detail.get("text") or ""
            if text_body:
                parts.append(text_body)
            html_list = detail.get("html") or []
            if isinstance(html_list, str):
                html_list = [html_list]
            for h in html_list:
                if isinstance(h, str):
                    parts.append(strip_html(h))
            combined = "\n".join(parts)
            subject = str(detail.get("subject", "") or "")
            if log_callback:
                log_callback(f"[Debug] 收到邮件: {subject}")
            code = extract_code(combined, subject)
            if code:
                if log_callback:
                    log_callback(f"[*] 从邮件中提取到验证码: {code}")
                return code
        sleep_with_cancel(poll_interval, cancel_callback)
    raise Exception(f"在 {timeout}s 内未收到验证码邮件")
