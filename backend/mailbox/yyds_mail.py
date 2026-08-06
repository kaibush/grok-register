"""YYDS 邮箱渠道适配器。"""

from __future__ import annotations

import secrets
import string
import time
from typing import Any, Callable, List, Optional

from backend.mailbox.utilities import extract_verification_code, strip_html

API_BASE = "https://maliapi.215.im/v1"
HttpGet = Callable[..., Any]
HttpPost = Callable[..., Any]


def _auth_headers(api_key: str = "", jwt: str = "", content_type: bool = False) -> dict:
    headers = {"Content-Type": "application/json"} if content_type else {}
    if jwt:
        headers["Authorization"] = f"Bearer {jwt}"
    elif api_key:
        headers["X-API-Key"] = api_key
    return headers


def get_domains(http_get: HttpGet, api_key: str = "", jwt: str = "") -> List[dict]:
    resp = http_get(f"{API_BASE}/domains", headers=_auth_headers(api_key, jwt))
    resp.raise_for_status()
    data = resp.json()
    return data.get("data", []) if data.get("success") else []


def create_account(
    http_post: HttpPost,
    local_part: str = "",
    domain: str = "",
    api_key: str = "",
    jwt: str = "",
) -> dict:
    payload = {}
    if local_part:
        payload["localPart"] = local_part
    if domain:
        payload["domain"] = domain
    elif api_key or jwt:
        payload["autoDomainStrategy"] = "prefer_owned"
    resp = http_post(
        f"{API_BASE}/accounts",
        json=payload,
        headers=_auth_headers(api_key, jwt, content_type=True),
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("success"):
        return data.get("data", {})
    raise Exception(f"YYDS 创建邮箱失败: {data}")


def get_token(http_post: HttpPost, address: str, api_key: str = "", jwt: str = "") -> Optional[str]:
    resp = http_post(
        f"{API_BASE}/token",
        json={"address": address},
        headers=_auth_headers(api_key, jwt, content_type=True),
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("success"):
        return data.get("data", {}).get("token")
    raise Exception(f"YYDS 获取token失败: {data}")


def get_messages(
    http_get: HttpGet,
    address: str,
    token: str = "",
    api_key: str = "",
    jwt: str = "",
) -> List[dict]:
    temp_token = token or jwt
    headers = _auth_headers(api_key, temp_token)
    resp = http_get(
        f"{API_BASE}/messages",
        params={"address": address},
        headers=headers,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("success"):
        return data.get("data", {}).get("messages", [])
    return []


def get_message_detail(
    http_get: HttpGet,
    message_id: str,
    token: str = "",
    api_key: str = "",
    jwt: str = "",
) -> dict:
    temp_token = token or jwt
    headers = _auth_headers(api_key, temp_token)
    resp = http_get(f"{API_BASE}/messages/{message_id}", headers=headers)
    resp.raise_for_status()
    data = resp.json()
    if data.get("success"):
        return data.get("data", {})
    raise Exception(f"YYDS 获取邮件详情失败: {data}")


def generate_username(length: int = 10) -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def pick_domain(http_get: HttpGet, api_key: str = "", jwt: str = "") -> str:
    domains = get_domains(http_get, api_key=api_key, jwt=jwt)
    if not domains:
        raise Exception("YYDS 没有返回任何可用域名")
    private = [d for d in domains if d.get("isVerified") and not d.get("isPublic")]
    if private:
        return private[0]["domain"]
    public = [d for d in domains if d.get("isVerified") and d.get("isPublic")]
    if public:
        return public[0]["domain"]
    verified = [d for d in domains if d.get("isVerified")]
    if verified:
        return verified[0]["domain"]
    raise Exception("YYDS 无已验证域名可用")


def create_mailbox(
    http_get: HttpGet,
    http_post: HttpPost,
    api_key: str = "",
    jwt: str = "",
    default_domain: str = "",
) -> tuple[str, str]:
    if not jwt and not api_key:
        raise Exception("YYDS API Key 或 JWT 未配置")
    domain = (default_domain or "").strip() or pick_domain(http_get, api_key=api_key, jwt=jwt)
    username = generate_username(10)
    result = create_account(
        http_post,
        local_part=username,
        domain=domain,
        api_key=api_key,
        jwt=jwt,
    )
    address = result.get("address") or f"{username}@{domain}"
    temp_token = result.get("token")
    if not temp_token:
        temp_token = get_token(http_post, address, api_key=api_key, jwt=jwt)
    if not temp_token:
        raise Exception("获取 YYDS token 失败")
    print(f"[*] 已创建 YYDS 邮箱: {address}")
    return address, temp_token


def wait_for_code(
    http_get: HttpGet,
    token: str,
    address: str,
    *,
    timeout: int = 180,
    poll_interval: int = 3,
    jwt: str = "",
    raise_if_cancelled: Callable[[Optional[Callable[[], bool]]], None],
    sleep_with_cancel: Callable[[float, Optional[Callable[[], bool]]], None],
    log_callback: Optional[Callable[[str], None]] = None,
    cancel_callback: Optional[Callable[[], bool]] = None,
) -> str:
    deadline = time.time() + timeout
    seen_ids = set()
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        try:
            messages = get_messages(http_get, address, token=token, jwt=jwt)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] YYDS 拉取邮件列表失败: {exc}")
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        for msg in messages:
            msg_id = msg.get("id")
            if not msg_id or msg_id in seen_ids:
                continue
            to_addrs = [t.get("address", "").lower() for t in (msg.get("to") or [])]
            if to_addrs and address.lower() not in to_addrs:
                seen_ids.add(msg_id)
                continue
            try:
                detail = get_message_detail(http_get, msg_id, token=token, jwt=jwt)
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] YYDS 获取邮件详情失败: {exc}")
                continue
            seen_ids.add(msg_id)
            parts = []
            text_body = detail.get("text") or ""
            if text_body:
                parts.append(text_body)
            html_list = detail.get("html") or []
            for h in html_list:
                parts.append(strip_html(h))
            combined = "\n".join(parts)
            subject = detail.get("subject", "")
            if log_callback:
                log_callback(f"[Debug] YYDS 收到邮件: {subject}")
            code = extract_verification_code(combined, subject)
            if code:
                if log_callback:
                    log_callback(f"[*] YYDS 从邮件中提取到验证码: {code}")
                return code
        sleep_with_cancel(poll_interval, cancel_callback)
    raise Exception(f"YYDS 在 {timeout}s 内未收到验证码邮件")
