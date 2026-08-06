"""Cloud Mail 邮箱渠道适配器。"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from backend.mailbox.utilities import extract_verification_code, generate_username, strip_html

HttpGet = Callable[..., Any]
HttpPost = Callable[..., Any]
HttpDelete = Callable[..., Any]

_domain_index = 0
_public_token = None
_public_token_config = None
_public_token_lock = threading.Lock()
_account_ids: Dict[str, Any] = {}
_account_ids_lock = threading.Lock()


def reset_runtime_state() -> None:
    global _domain_index, _public_token, _public_token_config
    _domain_index = 0
    _public_token = None
    _public_token_config = None
    with _account_ids_lock:
        _account_ids.clear()


def _response_data(resp, action: str):
    resp.raise_for_status()
    try:
        data = resp.json()
    except Exception as exc:
        preview = str(getattr(resp, "text", "") or "")[:200]
        raise Exception(f"CloudMail {action}返回非 JSON: {preview}") from exc
    if not isinstance(data, dict) or data.get("code") != 200:
        if isinstance(data, dict):
            detail = data.get("message", str(data))
        else:
            detail = str(data)
        raise Exception(f"CloudMail {action}失败: {detail}")
    return data.get("data")


def login(http_post: HttpPost, url: str, email: str, password: str) -> str:
    resp = http_post(
        f"{url}/api/login",
        json={"email": email, "password": password},
        headers={"Content-Type": "application/json"},
    )
    token_data = _response_data(resp, "登录")
    token = token_data.get("token") if isinstance(token_data, dict) else None
    if not token:
        raise Exception("CloudMail 登录失败: 响应缺少 token")
    return token


def add_address(
    http_post: HttpPost,
    url: str,
    admin_email: str,
    admin_password: str,
    address: str,
) -> dict:
    jwt = login(http_post, url, admin_email, admin_password)
    resp = http_post(
        f"{url}/api/account/add",
        json={"email": address, "token": ""},
        headers={"Content-Type": "application/json", "Authorization": jwt},
    )
    data = _response_data(resp, "添加邮箱")
    return data if isinstance(data, dict) else {}


def delete_address(
    http_post: HttpPost,
    http_delete: HttpDelete,
    url: str,
    admin_email: str,
    admin_password: str,
    account_id,
) -> Any:
    jwt = login(http_post, url, admin_email, admin_password)
    resp = http_delete(
        f"{url}/api/account/delete",
        params={"accountId": account_id},
        headers={"Content-Type": "application/json", "Authorization": jwt},
    )
    return _response_data(resp, "删除邮箱")


def gen_public_token(
    http_post: HttpPost,
    url: str,
    admin_email: str,
    admin_password: str,
) -> str:
    resp = http_post(
        f"{url}/api/public/genToken",
        json={"email": admin_email, "password": admin_password},
        headers={"Content-Type": "application/json"},
    )
    token_data = _response_data(resp, "获取公开 token")
    token = token_data.get("token") if isinstance(token_data, dict) else None
    if not token:
        raise Exception("CloudMail 获取公开 token 失败: 响应缺少 token")
    return token


def public_email_list(
    http_post: HttpPost,
    url: str,
    public_token: str,
    to_email: str = "",
    size: int = 20,
) -> List[dict]:
    payload = {"size": size}
    if to_email:
        payload["toEmail"] = to_email
    resp = http_post(
        f"{url}/api/public/emailList",
        json=payload,
        headers={"Content-Type": "application/json", "Authorization": public_token},
    )
    data = _response_data(resp, "查询邮件")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("list", "rows", "emails", "records"):
            items = data.get(key)
            if isinstance(items, list):
                return items
    return []


def get_shared_token(
    http_post: HttpPost,
    url: str,
    admin_email: str,
    admin_password: str,
    force_refresh: bool = False,
) -> str:
    global _public_token, _public_token_config
    if not url or not admin_email or not admin_password:
        raise Exception("CloudMail 配置不完整")
    cache_key = (url, admin_email, admin_password)
    with _public_token_lock:
        if _public_token and _public_token_config == cache_key and not force_refresh:
            return _public_token
        token = gen_public_token(http_post, url, admin_email, admin_password)
        _public_token = token
        _public_token_config = cache_key
        return token


def cleanup_address(
    http_post: HttpPost,
    http_delete: HttpDelete,
    url: str,
    admin_email: str,
    admin_password: str,
    email: str,
) -> None:
    with _account_ids_lock:
        account_id = _account_ids.pop(email, None)
    if account_id is None:
        return
    try:
        delete_address(http_post, http_delete, url, admin_email, admin_password, account_id)
        print(f"[CloudMail] 已删除临时邮箱: {email} (accountId={account_id})")
    except Exception as exc:
        print(f"[CloudMail] 删除邮箱失败: {email} -> {exc}")


def create_mailbox(
    http_post: HttpPost,
    url: str,
    admin_email: str,
    admin_password: str,
    domains: List[str],
    username: str = "",
) -> Tuple[str, str]:
    global _domain_index
    cleaned = [item.strip() for item in domains if str(item).strip()]
    if not url:
        raise Exception("CloudMail URL 未配置")
    if not admin_email:
        raise Exception("CloudMail 管理员邮箱未配置")
    if not admin_password:
        raise Exception("CloudMail 管理员密码未配置")
    if not cleaned:
        raise Exception("CloudMail 需要在 defaultDomains 中配置可用域名")
    domain = cleaned[_domain_index % len(cleaned)]
    _domain_index += 1
    address = f"{(username or generate_username(10))}@{domain}"
    result = add_address(http_post, url, admin_email, admin_password, address)
    account_id = result.get("accountId") or result.get("id")
    if account_id is not None:
        with _account_ids_lock:
            _account_ids[address] = account_id
    print(f"[CloudMail] 添加邮箱成功: {address}")
    return address, "cloudmail_catch_all"


def wait_for_code(
    http_post: HttpPost,
    http_delete: HttpDelete,
    url: str,
    admin_email: str,
    admin_password: str,
    email: str,
    *,
    timeout: int = 180,
    poll_interval: int = 3,
    raise_if_cancelled: Callable[[Optional[Callable[[], bool]]], None],
    sleep_with_cancel: Callable[[float, Optional[Callable[[], bool]]], None],
    log_callback: Optional[Callable[[str], None]] = None,
    cancel_callback: Optional[Callable[[], bool]] = None,
    resend_callback: Optional[Callable[[], None]] = None,
) -> str:
    if not url:
        raise Exception("CloudMail URL 未配置")
    deadline = time.time() + timeout
    seen_attempts = {}
    next_resend_at = time.time() + 35
    try:
        public_token = get_shared_token(http_post, url, admin_email, admin_password)
        if log_callback:
            log_callback("[Debug] CloudMail 公开 token 获取成功")
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
                messages = public_email_list(http_post, url, public_token, to_email=email, size=20)
            except Exception as exc:
                err_msg = str(exc)
                if log_callback:
                    log_callback(f"[Debug] CloudMail 邮件查询失败: {err_msg}")
                if any(m in err_msg.lower() for m in ("token", "401", "unauthorized", "鉴权")):
                    try:
                        public_token = get_shared_token(
                            http_post, url, admin_email, admin_password, force_refresh=True
                        )
                        if log_callback:
                            log_callback("[Debug] CloudMail 公开 token 已刷新")
                    except Exception:
                        pass
                sleep_with_cancel(poll_interval, cancel_callback)
                continue
            if log_callback:
                log_callback(f"[Debug] CloudMail 本轮邮件数量: {len(messages)}")
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                msg_id = msg.get("emailId") or msg.get("id") or msg.get("messageId")
                if not msg_id:
                    continue
                attempt = int(seen_attempts.get(msg_id, 0))
                if attempt >= 5:
                    continue
                seen_attempts[msg_id] = attempt + 1
                parts = []
                for field in (
                    "content",
                    "text",
                    "textContent",
                    "text_content",
                    "body",
                    "snippet",
                    "intro",
                ):
                    value = msg.get(field)
                    if isinstance(value, str) and value.strip():
                        parts.append(value)
                html_value = msg.get("html") or msg.get("htmlContent") or msg.get("html_content")
                if isinstance(html_value, str):
                    parts.append(strip_html(html_value))
                elif isinstance(html_value, list):
                    parts.extend(
                        strip_html(item)
                        for item in html_value
                        if isinstance(item, str)
                    )
                subject = str(msg.get("subject", "") or "")
                if log_callback:
                    log_callback(f"[Debug] CloudMail 收到邮件: {subject}")
                combined = "\n".join(parts)
                plain_text = strip_html(combined)
                code = extract_verification_code(f"{combined}\n{plain_text}", subject)
                if code:
                    if log_callback:
                        log_callback(f"[*] CloudMail 从邮件中提取到验证码: {code}")
                    return code
                if log_callback:
                    log_callback(
                        "[Debug] 邮件已解析但未提取到验证码 "
                        f"id={msg_id} attempt={seen_attempts[msg_id]}"
                    )
            sleep_with_cancel(poll_interval, cancel_callback)
        raise Exception(f"CloudMail 在 {timeout}s 内未收到验证码邮件")
    finally:
        cleanup_address(http_post, http_delete, url, admin_email, admin_password, email)
