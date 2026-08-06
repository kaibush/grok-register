# -*- coding: utf-8 -*-
"""已注册账号的重新登录流程。

仅使用现有邮箱和密码打开登录页并刷新 SSO，不进入注册页，也不访问邮箱服务。
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, Optional

from backend.automation.session import (
    active_browser,
    active_page,
    page,
    set_browser_session,
    start_browser,
)
from backend.registration.signup_flow import (
    _dismiss_cookie_consent,
    _native_click_action,
    _native_input_candidates,
    _native_type_element,
    _try_sync_turnstile,
)


SIGNIN_URL = "https://accounts.x.ai/sign-in"


def _wait_until(predicate: Callable[[], bool], timeout: float, interval: float = 0.25) -> bool:
    deadline = time.time() + max(float(timeout or 0), 0)
    while time.time() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def _visible_login_error() -> str:
    """提取登录表单中的短错误提示，避免把整页条款当成错误。"""
    try:
        value = page.run_js(
            r"""
const selectors = [
  '[role="alert"]', '[aria-live="assertive"]', '[aria-live="polite"]',
  '[data-testid*="error" i]', '[class*="error" i]'
];
for (const selector of selectors) {
  for (const node of document.querySelectorAll(selector)) {
    const style = getComputedStyle(node);
    const rect = node.getBoundingClientRect();
    if (style.display === 'none' || style.visibility === 'hidden' || !rect.width || !rect.height) continue;
    const text = (node.innerText || node.textContent || '').replace(/\s+/g, ' ').trim();
    if (text && text.length <= 300) return text;
  }
}
return '';
            """
        )
    except Exception:
        return ""
    return str(value or "").strip()


def _click_submit(keywords) -> bool:
    """优先点击稳定的 sign-in-submit，再回退到可见文案。"""
    # Cookie SDK 可能在表单出现后才挂载，提交前必须再次关闭。
    try:
        _dismiss_cookie_consent()
    except Exception:
        pass
    try:
        buttons = page.eles('[data-testid="sign-in-submit"]') or []
    except Exception:
        buttons = []
    for button in buttons:
        try:
            if button.states.is_displayed and button.states.is_enabled:
                # force 仍走 Playwright 鼠标事件，但不被延迟出现的 Cookie 横幅拦截。
                button._raw.click(force=True, timeout=5000)
                return True
        except Exception:
            continue
    return bool(
        _native_click_action(
            keywords,
            deny_keywords=("注册", "sign up", "google", "apple", "login with x"),
        )
    )


def _type_login_value(element, value: str, log_callback=None) -> bool:
    """一次性使用 Playwright 键盘输入，兼容 React 受控登录框重渲染。"""
    if not element:
        return False
    text = str(value or "")
    try:
        locator = element._raw
        locator.click(force=True, timeout=5000)
        locator.fill("", force=True)
        locator.press_sequentially(text, delay=45)
        current = str(locator.input_value() or "").strip()
        if current == text.strip():
            return True
        # 某些页面重渲染后 locator 句柄短暂失效，重新读取当前稳定元素。
        fresh = _native_input_candidates("email" if "@" in text else "password")
        if fresh:
            current = str(fresh[0]._raw.input_value() or "").strip()
        return current == text.strip()
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] 登录框真实输入异常: {type(exc).__name__}: {exc}")
        return False


def _navigate_signin(log_callback=None) -> None:
    if active_browser() is None:
        start_browser(log_callback=log_callback)
    browser_obj = active_browser()
    tabs = browser_obj.get_tabs() if browser_obj is not None else []
    page_obj = tabs[-1] if tabs else browser_obj.new_tab()
    set_browser_session(browser_obj, page_obj)
    page_obj.get(SIGNIN_URL)
    try:
        page_obj.wait.doc_loaded()
    except Exception:
        pass
    current = str(getattr(page_obj, "url", "") or "")
    if not any(host in current for host in ("accounts.x.ai", "auth.x.ai", "grok.com")):
        raise RuntimeError(f"打开登录页失败，当前 URL: {current or 'empty'}")


def _read_sso_cookie() -> str:
    try:
        cookies = page.cookies(all_domains=True, all_info=True) or []
    except Exception:
        return ""
    fallback = ""
    for item in cookies:
        if isinstance(item, dict):
            name = str(item.get("name") or "")
            value = str(item.get("value") or "")
        else:
            name = str(getattr(item, "name", "") or "")
            value = str(getattr(item, "value", "") or "")
        if name == "sso" and value:
            return value
        if name == "sso-rw" and value:
            fallback = value
    return fallback


def _reuse_logged_in_sso(log_callback=None, stage="") -> str:
    """登录页可能已被会话直接重定向，优先复用当前 SSO。"""
    token = _read_sso_cookie()
    if token and log_callback:
        suffix = f"（{stage}）" if stage else ""
        log_callback(f"[*] 当前浏览器已登录，复用现有 sso cookie{suffix}")
    return token


def _wait_for_login_sso(timeout: int, log_callback=None) -> str:
    """自然等待登录跳转与 SSO，期间不主动导航到 grok.com。"""
    deadline = time.time() + max(int(timeout or 90), 30)
    last_log = 0.0
    while time.time() < deadline:
        token = _read_sso_cookie()
        if token:
            if log_callback:
                log_callback("[*] 重新登录成功，已获取新的 sso cookie")
            return token
        now = time.time()
        if log_callback and now - last_log >= 5:
            last_log = now
            current = str(getattr(active_page(), "url", "") or "")
            log_callback(f"[*] 等待重新登录 SSO... 剩余 {max(int(deadline - now), 0)}s | url={current[:90]}")
        error = _visible_login_error()
        if error:
            raise RuntimeError(f"登录失败: {error}")
        time.sleep(0.4)
    current = str(getattr(active_page(), "url", "") or "")
    raise RuntimeError(f"重新登录超时，未获取到 SSO；当前 URL: {current[:120]}")


def login_with_password(
    email: str,
    password: str,
    *,
    timeout: int = 90,
    log_callback=None,
) -> str:
    """使用邮箱密码登录并返回新的 SSO cookie。"""
    normalized_email = str(email or "").strip()
    secret = str(password or "")
    if not normalized_email or "@" not in normalized_email:
        raise ValueError("账号记录缺少有效邮箱")
    if not secret:
        raise ValueError("账号记录缺少密码")

    _navigate_signin(log_callback=log_callback)
    existing_sso = _reuse_logged_in_sso(log_callback=log_callback, stage="打开登录页后")
    if existing_sso:
        return existing_sso
    _dismiss_cookie_consent(log_callback)
    if log_callback:
        log_callback(f"[*] 打开重新登录页: {normalized_email}")

    clicked = _native_click_action(
        ("login with email", "使用邮箱登录", "邮箱登录", "continue with email"),
        deny_keywords=("sign up", "注册"),
    )
    if not clicked:
        existing_sso = _reuse_logged_in_sso(
            log_callback=log_callback, stage="未找到邮箱登录按钮时"
        )
        if existing_sso:
            return existing_sso
        raise RuntimeError("登录页未找到“使用邮箱登录”按钮")

    if not _wait_until(lambda: bool(_native_input_candidates("email")), 12):
        raise RuntimeError("登录页未出现邮箱输入框")
    email_inputs = _native_input_candidates("email")
    if not email_inputs or not _type_login_value(email_inputs[0], normalized_email, log_callback):
        raise RuntimeError("邮箱输入失败")
    if not _click_submit(("下一步", "next", "continue")):
        raise RuntimeError("邮箱页未找到下一步按钮")

    if not _wait_until(lambda: bool(_native_input_candidates("password")), 15):
        detail = _visible_login_error()
        raise RuntimeError(detail or "登录页未出现密码输入框")
    password_inputs = _native_input_candidates("password")
    if not password_inputs or not _type_login_value(password_inputs[0], secret, log_callback):
        raise RuntimeError("密码输入失败")
    if not _try_sync_turnstile(
        log_callback=log_callback,
        cancel_callback=None,
        reason="等待登录安全验证",
    ):
        raise RuntimeError("登录安全验证未通过")
    if not _click_submit(("登录", "sign in", "log in", "continue")):
        raise RuntimeError("密码页未找到登录按钮")

    # 先给表单错误一个快速反馈窗口；正常成功会立即进入 redirect。
    for _ in range(12):
        time.sleep(0.25)
        error = _visible_login_error()
        if error:
            raise RuntimeError(f"登录失败: {error}")
        try:
            if "sign-in" not in str(active_page().url or ""):
                break
        except Exception:
            break

    return _wait_for_login_sso(timeout=max(int(timeout or 90), 30), log_callback=log_callback)


def capture_login_failure(path: Path) -> str:
    """保存重新登录失败现场；返回已写入路径。"""
    page_obj = active_page()
    if page_obj is None:
        return ""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        page_obj.screenshot(path=str(path), full_page=True)
    except Exception:
        return ""
    return str(path) if path.is_file() else ""
