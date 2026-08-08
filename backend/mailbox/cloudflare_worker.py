"""Cloudflare Worker 邮箱渠道适配器。"""

from __future__ import annotations

import secrets
import string
import time
from typing import Any, Callable, Dict, List, Optional

from backend.mailbox.utilities import (
    extract_verification_code,
    generate_username,
    pick_list_payload,
    strip_html,
)

HttpGet = Callable[..., Any]
HttpPost = Callable[..., Any]


def path_from_config(config: dict, key: str, default_path: str) -> str:
    raw = str(config.get(key, default_path) or default_path).strip()
    if not raw.startswith("/"):
        raw = "/" + raw
    return raw


def apply_custom_auth(headers: dict, custom_auth: str = "") -> dict:
    if custom_auth:
        headers["x-custom-auth"] = custom_auth
    return headers


def build_headers(
    api_key: str = "",
    auth_mode: str = "none",
    custom_auth: str = "",
    content_type: bool = False,
) -> dict:
    headers = {"Content-Type": "application/json"} if content_type else {}
    mode = (auth_mode or "none").lower()
    if api_key:
        if mode == "x-api-key":
            headers["X-API-Key"] = api_key
        elif mode == "x-admin-auth":
            headers["x-admin-auth"] = api_key
        elif mode != "none":
            headers["Authorization"] = f"Bearer {api_key}"
    return apply_custom_auth(headers, custom_auth)


def apply_auth_params(params: Optional[dict], api_key: str = "", auth_mode: str = "none") -> dict:
    merged = dict(params or {})
    if api_key and (auth_mode or "").lower() == "query-key":
        merged["key"] = api_key
    return merged


def is_admin_create_path(path: str) -> bool:
    return str(path or "").rstrip("/").lower() == "/admin/new_address"


def next_default_domain(domains: List[str], index: int) -> tuple[str, int]:
    cleaned = [x.strip() for x in domains if str(x).strip()]
    if not cleaned:
        return "", index
    domain = cleaned[index % len(cleaned)]
    return domain, index + 1


def create_temp_address(
    http_post: HttpPost,
    api_base: str,
    *,
    accounts_path: str = "/api/new_address",
    domain: str = "",
    api_key: str = "",
    auth_mode: str = "none",
    custom_auth: str = "",
    name: str = "",
) -> tuple[str, str]:
    path = accounts_path if accounts_path.startswith("/") else f"/{accounts_path}"
    url = f"{api_base.rstrip('/')}{path}"
    if is_admin_create_path(path):
        payload = {"name": name or generate_username(10), "enablePrefix": True}
        if domain:
            payload["domain"] = domain
        headers = build_headers(api_key, auth_mode, custom_auth, content_type=True)
    else:
        payload = {}
        if domain:
            payload["domain"] = domain
        headers = apply_custom_auth({"Content-Type": "application/json"}, custom_auth)
    resp = http_post(url, json=payload, headers=headers)
    resp.raise_for_status()
    try:
        data = resp.json()
    except Exception:
        raise Exception(f"Cloudflare {path} 返回非JSON: {resp.text[:300]}")
    address = data.get("address")
    jwt = data.get("jwt")
    if not address or not jwt:
        raise Exception(f"Cloudflare {path} 缺少 address/jwt: {data}")
    return address, jwt


def get_domains(
    http_get: HttpGet,
    api_base: str,
    *,
    domains_path: str = "/domains",
    api_key: str = "",
    auth_mode: str = "none",
    custom_auth: str = "",
) -> List[dict]:
    headers = build_headers(api_key, auth_mode, custom_auth, content_type=False)
    path = domains_path if domains_path.startswith("/") else f"/{domains_path}"
    params = apply_auth_params({}, api_key, auth_mode)
    resp = http_get(f"{api_base.rstrip('/')}{path}", headers=headers, params=params)
    resp.raise_for_status()
    return pick_list_payload(resp.json())


def create_account(
    http_post: HttpPost,
    api_base: str,
    address: str,
    password: str,
    *,
    accounts_path: str = "/accounts",
    api_key: str = "",
    auth_mode: str = "none",
    custom_auth: str = "",
    expires_in: int = 0,
) -> dict:
    headers = build_headers(api_key, auth_mode, custom_auth, content_type=True)
    path = accounts_path if accounts_path.startswith("/") else f"/{accounts_path}"
    params = apply_auth_params({}, api_key, auth_mode)
    payload = {"address": address, "password": password, "expiresIn": expires_in}
    resp = http_post(
        f"{api_base.rstrip('/')}{path}",
        json=payload,
        headers=headers,
        params=params,
    )
    resp.raise_for_status()
    return resp.json()


def get_token(
    http_post: HttpPost,
    api_base: str,
    address: str,
    password: str,
    *,
    token_path: str = "/token",
    api_key: str = "",
    auth_mode: str = "none",
    custom_auth: str = "",
) -> Optional[str]:
    headers = build_headers(api_key, auth_mode, custom_auth, content_type=True)
    path = token_path if token_path.startswith("/") else f"/{token_path}"
    resp = http_post(
        f"{api_base.rstrip('/')}{path}",
        json={"address": address, "password": password},
        headers=headers,
        params=apply_auth_params({}, api_key, auth_mode),
    )
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict):
        if data.get("token"):
            return data.get("token")
        if isinstance(data.get("data"), dict) and data["data"].get("token"):
            return data["data"].get("token")
    return None


def get_messages(
    http_get: HttpGet,
    api_base: str,
    token: str,
    *,
    messages_path: str = "/messages",
    api_key: str = "",
    auth_mode: str = "none",
    custom_auth: str = "",
) -> List[dict]:
    headers = apply_custom_auth({"Authorization": f"Bearer {token}"}, custom_auth)
    path = messages_path if messages_path.startswith("/") else f"/{messages_path}"
    params = apply_auth_params({"limit": 20, "offset": 0}, api_key, auth_mode)
    resp = http_get(f"{api_base.rstrip('/')}{path}", headers=headers, params=params)
    resp.raise_for_status()
    try:
        data = resp.json()
    except Exception:
        raise Exception(f"Cloudflare messages 返回非JSON: {resp.text[:300]}")
    return pick_list_payload(data)


def get_message_detail(
    http_get: HttpGet,
    api_base: str,
    token: str,
    message_id: str,
    *,
    messages_path: str = "/messages",
    api_key: str = "",
    auth_mode: str = "none",
    custom_auth: str = "",
) -> dict:
    headers = apply_custom_auth({"Authorization": f"Bearer {token}"}, custom_auth)
    path = messages_path if messages_path.startswith("/") else f"/{messages_path}"
    candidates = [
        f"{api_base.rstrip('/')}/api/mail/{message_id}",
        f"{api_base.rstrip('/')}{path}/{message_id}",
    ]
    last_err = None
    for url in candidates:
        try:
            resp = http_get(
                url,
                headers=headers,
                params=apply_auth_params({}, api_key, auth_mode),
            )
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, dict) and isinstance(data.get("data"), dict):
                return data["data"]
            return data if isinstance(data, dict) else {}
        except Exception as exc:
            last_err = exc
            continue
    raise Exception(f"Cloudflare 获取邮件详情失败: {last_err}")


def create_mailbox_fallback(
    http_get: HttpGet,
    http_post: HttpPost,
    api_base: str,
    *,
    domains_path: str,
    accounts_path: str,
    token_path: str,
    api_key: str = "",
    auth_mode: str = "none",
    custom_auth: str = "",
) -> tuple[str, str]:
    domains = get_domains(
        http_get,
        api_base,
        domains_path=domains_path,
        api_key=api_key,
        auth_mode=auth_mode,
        custom_auth=custom_auth,
    )
    if not domains:
        raise Exception("Cloudflare 无可用域名")
    verified = [d for d in domains if d.get("isVerified")]
    target = verified[0] if verified else domains[0]
    domain = target.get("domain")
    if not domain:
        raise Exception("Cloudflare 域名数据格式错误，缺少 domain 字段")
    username = generate_username(10)
    address = f"{username}@{domain}"
    password = secrets.token_urlsafe(12)
    create_account(
        http_post,
        api_base,
        address,
        password,
        accounts_path=accounts_path,
        api_key=api_key,
        auth_mode=auth_mode,
        custom_auth=custom_auth,
        expires_in=0,
    )
    token = get_token(
        http_post,
        api_base,
        address,
        password,
        token_path=token_path,
        api_key=api_key,
        auth_mode=auth_mode,
        custom_auth=custom_auth,
    )
    if not token:
        raise Exception("获取 Cloudflare 邮箱 token 失败")
    return address, token


def wait_for_code(
    http_get: HttpGet,
    api_base: str,
    dev_token: str,
    email: str,
    *,
    messages_path: str = "/messages",
    api_key: str = "",
    auth_mode: str = "none",
    custom_auth: str = "",
    timeout: int = 180,
    poll_interval: int = 3,
    raise_if_cancelled: Callable[[Optional[Callable[[], bool]]], None],
    sleep_with_cancel: Callable[[float, Optional[Callable[[], bool]]], None],
    log_callback: Optional[Callable[[str], None]] = None,
    cancel_callback: Optional[Callable[[], bool]] = None,
    resend_callback: Optional[Callable[[], None]] = None,
) -> str:
    if not api_base:
        raise Exception("Cloudflare API Base 未配置")
    deadline = time.time() + timeout
    seen_attempts = {}
    next_resend_at = time.time() + 35
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        if resend_callback and time.time() >= next_resend_at:
            try:
                resend_callback()
                if log_callback:
                    log_callback("[*] 已触发重新发送验证码")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] 触发重发验证码失败: {exc}")
            next_resend_at = time.time() + 35
        try:
            messages = get_messages(
                http_get,
                api_base,
                dev_token,
                messages_path=messages_path,
                api_key=api_key,
                auth_mode=auth_mode,
                custom_auth=custom_auth,
            )
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] Cloudflare 拉取邮件列表失败: {exc}")
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        if log_callback:
            log_callback(f"[Debug] Cloudflare 本轮邮件数量: {len(messages)}")
        for msg in messages:
            msg_id = msg.get("id") or msg.get("msgid")
            if not msg_id:
                continue
            attempt = int(seen_attempts.get(msg_id, 0))
            if attempt >= 5:
                continue
            seen_attempts[msg_id] = attempt + 1
            recipients = [t.get("address", "").lower() for t in (msg.get("to") or [])]
            msg_addr = str(msg.get("address", "")).lower()
            address_matched = True
            if recipients:
                address_matched = email.lower() in recipients
            elif msg_addr:
                address_matched = msg_addr == email.lower()
            if not address_matched and log_callback:
                log_callback(
                    f"[Debug] 跳过疑似非目标邮件 id={msg_id} address={msg_addr} to={recipients}"
                )
                continue
            parts = []
            for field in ("text", "raw", "content", "intro", "body", "snippet"):
                value = msg.get(field)
                if isinstance(value, str) and value.strip():
                    parts.append(value)
            html_list = msg.get("html") or []
            if isinstance(html_list, str):
                html_list = [html_list]
            for h in html_list:
                parts.append(strip_html(h))
            subject = str(msg.get("subject", "") or "")
            combined = "\n".join(parts)
            try:
                detail = get_message_detail(
                    http_get,
                    api_base,
                    dev_token,
                    msg_id,
                    messages_path=messages_path,
                    api_key=api_key,
                    auth_mode=auth_mode,
                    custom_auth=custom_auth,
                )
                for field in ("text", "raw", "content", "intro", "body", "snippet"):
                    value = detail.get(field)
                    if isinstance(value, str) and value.strip():
                        combined += "\n" + value
                html_list2 = detail.get("html") or []
                if isinstance(html_list2, str):
                    html_list2 = [html_list2]
                for h in html_list2:
                    combined += "\n" + strip_html(h)
                if not subject:
                    subject = str(detail.get("subject", "") or "")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] Cloudflare detail接口失败，改用列表内容解析: {exc}")
            if log_callback:
                log_callback(f"[Debug] Cloudflare 收到邮件: {subject}")
            code = extract_verification_code(combined, subject)
            if code:
                if log_callback:
                    log_callback(f"[*] Cloudflare 从邮件中提取到验证码: {code}")
                return code
            if log_callback:
                log_callback(
                    f"[Debug] 邮件已解析但未提取到验证码 id={msg_id} attempt={seen_attempts[msg_id]}"
                )
        sleep_with_cancel(poll_interval, cancel_callback)
    raise Exception(f"Cloudflare 在 {timeout}s 内未收到验证码邮件")
