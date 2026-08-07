#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""账号注册编排引擎。

组合邮箱渠道、浏览器流程、授权交换、结果持久化与任务取消机制，提供 Web 后台
调用的批量注册入口。
"""

import threading
import datetime
import time
import os
import gc
import secrets
import struct
import random
import re
import string
import json
import base64
import traceback
from urllib.parse import urlsplit

from playwright._impl._errors import TargetClosedError as PageDisconnectedError
from curl_cffi import requests

# 授权交换和导出逻辑集中在 integrations 包，编排层只负责调用。
from backend.integrations import auth_exchange as _s2cpa
from backend.integrations import grok2api_client as _grok2api
from backend.mailbox import cloudflare_worker as cloudflare_provider
from backend.mailbox import cloud_mail as cloudmail_provider
from backend.mailbox import duck_mail as duckmail_provider
from backend.mailbox import mail_nest as mailnest_provider
from backend.mailbox import outlook_pool as outlookemail_provider
from backend.mailbox import yyds_mail as yyds_provider
from backend.mailbox.utilities import extract_verification_code as _extract_code
from backend.mailbox.utilities import generate_username as _generate_username
from backend.mailbox.utilities import pick_list_payload as _pick_list

from backend.automation import session as _bs
from backend.registration import signup_flow as _rf
from backend.integrations import network_checks as _conn
from backend.registration.store import RegistrationRepository
from backend.integrations.proxy import resolve_proxy_url
from backend.shared.paths import DATA_ROOT, PROJECT_ROOT
from backend.automation.session import (
    browser,
    page,
    active_browser as _active_browser,
    active_page as _active_page,
    set_browser_session as _set_browser_session,
    start_browser,
    stop_browser,
    restart_browser,
    cleanup_runtime_memory,
    refresh_active_page,
    extract_cf_clearance_and_ua,
    create_browser_options,
    get_start_fail_streak,
    cleanup_stale_profiles as _cleanup_stale_profiles,
)
from backend.registration.signup_flow import (
    SIGNUP_URL,
    authorize_device_in_browser,
    click_email_signup_button,
    open_signup_page,
    has_profile_form,
    detect_email_domain_rejection,
    raise_if_email_domain_rejected,
    fill_email_and_submit,
    fill_code_and_submit,
    getTurnstileToken,
    build_profile,
    fill_profile_and_submit,
    wait_for_sso_cookie,
)



APP_DIR = str(PROJECT_ROOT)
DATA_DIR = str(DATA_ROOT)
CONFIG_FILE = os.path.abspath(
    os.path.expanduser(os.environ.get("GROK_CONFIG_FILE", os.path.join(APP_DIR, "config.json")))
)
# 所有注册运行数据统一放入 data/，避免与前后端代码混放。
ACCOUNTS_DIR = os.path.join(DATA_DIR, "accounts")
RESULTS_DB_FILE = os.path.join(ACCOUNTS_DIR, "registration_results.sqlite3")
MEMORY_CLEANUP_INTERVAL = 5
TRACEBACK_MAX_CHARS = 60_000
TRACEBACK_LOG_MAX_CHARS = 16_000

_repository = None
_repository_lock = threading.Lock()
_network_route_log_lock = threading.Lock()
_network_route_log_keys = set()


def current_exception_traceback(max_chars=TRACEBACK_MAX_CHARS):
    """返回当前异常的标准堆栈；没有活动异常时返回空字符串。"""
    text = traceback.format_exc().strip()
    if not text or text == "NoneType: None":
        return ""

    limit = max(1_000, int(max_chars or TRACEBACK_MAX_CHARS))
    if len(text) > limit:
        tail_size = min(4_000, limit // 4)
        text = (
            text[: limit - tail_size]
            + "\n... 异常堆栈过长，已截断 ...\n"
            + text[-tail_size:]
        )
    return text


def ensure_accounts_dir():
    """确保 data/accounts/ 存在，返回目录绝对路径。"""
    os.makedirs(ACCOUNTS_DIR, exist_ok=True)
    return ACCOUNTS_DIR


def account_file_for_email(email):
    """单个账号的独立输出路径：data/accounts/{email}.txt"""
    ensure_accounts_dir()
    safe_email = str(email or "").strip().replace("/", "_").replace("\\", "_")
    return os.path.join(ACCOUNTS_DIR, f"{safe_email}.txt")


def accounts_side_file(name):
    """data/accounts/ 下的附属文件路径（mail_credentials / sso_pending 等）。"""
    ensure_accounts_dir()
    return os.path.join(ACCOUNTS_DIR, name)


def get_registration_repository():
    """懒加载 SQLite；首次启动时把旧账号 TXT 补录为成功结果。"""
    global _repository
    if _repository is not None:
        return _repository
    with _repository_lock:
        if _repository is None:
            store = RegistrationRepository(RESULTS_DB_FILE)
            store.import_existing_accounts(ACCOUNTS_DIR)
            _repository = store
    return _repository


def backfill_access_token_bot_risk(log_callback=None) -> int:
    """从已有 CPA / Grok2API 授权文件回填 access_token 的 bfs 风控标记。"""
    try:
        repo = get_registration_repository()
    except Exception as exc:
        if log_callback:
            log_callback(f"[!] bot_risk 回填初始化失败: {exc}")
        return 0

    auth_dirs = []
    for key in ("cpa_auth_dir", "grok2api_auth_dir"):
        raw = str(config.get(key, "") or "").strip()
        if not raw:
            continue
        path = raw if os.path.isabs(raw) else os.path.join(APP_DIR, raw)
        if os.path.isdir(path):
            auth_dirs.append(path)
    if not auth_dirs:
        return 0

    updated = 0
    seen_emails = set()
    for auth_dir in auth_dirs:
        try:
            names = os.listdir(auth_dir)
        except OSError:
            continue
        for name in names:
            if not name.endswith(".json"):
                continue
            file_path = os.path.join(auth_dir, name)
            try:
                with open(file_path, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            except Exception:
                continue
            candidates = []
            if isinstance(payload, dict):
                if payload.get("access_token"):
                    candidates.append(payload)
                accounts = payload.get("accounts")
                if isinstance(accounts, list):
                    candidates.extend(item for item in accounts if isinstance(item, dict))
            for item in candidates:
                token = str(item.get("access_token") or "").strip()
                if not token:
                    continue
                email = str(item.get("email") or "").strip().lower()
                if not email:
                    email = str(
                        _s2cpa.decode_jwt_payload(token).get("email")
                        or _s2cpa.decode_jwt_payload(token).get("sub")
                        or ""
                    ).strip().lower()
                if not email or "@" not in email or email in seen_emails:
                    continue
                seen_emails.add(email)
                bfs = _s2cpa.access_token_bfs(token)
                bot_risk = _s2cpa.access_token_bot_risk(token)
                if not bot_risk and bfs is None:
                    continue
                try:
                    count = repo.update_bot_risk_by_email(
                        email, bot_risk=bot_risk, bfs=bfs if bfs is not None else ""
                    )
                except Exception:
                    continue
                if count:
                    updated += count
    if updated and log_callback:
        log_callback(f"[*] 已从授权文件回填 bot_risk 标记 {updated} 条")
    return updated


def email_registered_successfully(email):
    """数据库或旧账号文件中已有成功/已消耗记录时返回 True。

    除正式 success 外，已保存 SSO、已判定 already_registered、或已尝试停用
    的 Outlook 邮箱也应跳过，避免邮箱池重复取用造成死循环。
    """
    normalized = str(email or "").strip()
    if not normalized:
        return False
    try:
        repo = get_registration_repository()
        if repo.has_success(normalized):
            return True
        if hasattr(repo, "has_registered_or_consumed") and repo.has_registered_or_consumed(normalized):
            return True
    except Exception:
        pass
    return os.path.isfile(account_file_for_email(normalized))


DEFAULT_CONFIG = {
    "email_provider": "cloudflare",
    "duckmail_api_key": "",
    "duckmail_api_base": "https://api.duckmail.sbs",
    "defaultDomains": "",
    "cloudmail_url": "",
    "cloudmail_admin_email": "",
    "cloudmail_password": "",
    "cloudflare_api_base": "",
    "cloudflare_api_key": "",
    "cloudflare_auth_mode": "none",
    "cloudflare_custom_auth": "",
    "cloudflare_path_domains": "/api/domains",
    "cloudflare_path_accounts": "/admin/new_address",
    "cloudflare_path_token": "/api/token",
    "cloudflare_path_messages": "/api/mails",
    "outlookemail_api_base": "",
    "outlookemail_api_key": "",
    "outlookemail_source": "accounts",
    "outlookemail_group_id": "",
    "outlookemail_web_password": "",
    "outlookemail_session_cookie": "",
    "outlookemail_temp_tag_ids": "",
    "outlookemail_folder": "all",
    "outlookemail_top": 10,
    "outlookemail_pick_mode": "random",
    "outlookemail_disable_after_cpa_success": False,
    "proxy": "http://127.0.0.1:7890",
    "enable_nsfw": True,
    "debug_mode": False,
    "browser_headless": False,
    "browser_locale": "en-US",
    "close_browser_on_stop": False,
    "log_level": "info",
    "register_count": 1,
    "register_workers": 1,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    # CLIProxyAPI(CPA) 直出：注册拿到 SSO 后换 token，写入 CPA / Grok2API
    "cpa_auto_add": True,
    # Token 换取方式：device_protocol（协议 Device Flow，默认）/ device_browser（浏览器 Device Flow）/ auth_code
    "cpa_token_mode": "device_protocol",
    # CPA 本地 auth 目录
    "cpa_auth_dir": "data/cpa_auth",
    # 远程 CPA：通过 Management API POST /v0/management/auth-files 上传
    "cpa_remote_url": "",
    "cpa_management_key": "",
    # Grok2API grok_build 导入目录
    "grok2api_auth_dir": "data/grok2api_auth",
    # 远程 Grok2API 管理端：登录后通过 SSE 导入 grok_build JSON
    "grok2api_remote_url": "",
    "grok2api_remote_username": "",
    "grok2api_remote_password": "",
    "grok2api_auto_import": True,
    "mailnest_api_key": "",
    "mailnest_project_code": "x-ai001",
    # YYDS：留空自动选已验证域名；填写则固定该域名
    "yyds_default_domain": "",
    # 账号间注册间隔（秒），0=不等待。填一个整数=N秒固定等待，填区间"60-120"=随机等待
    "account_interval": "60-120",
}

config = DEFAULT_CONFIG.copy()
_cf_domain_index = 0


class RegistrationCancelled(Exception):
    pass


class AccountRetryNeeded(Exception):
    pass


class EmailDomainRejected(Exception):
    """xAI 拒绝当前邮箱域名（如公共临时域被拉黑）。"""

    def __init__(self, email="", message=""):
        self.email = email or ""
        self.message = message or "邮箱域名已被拒绝"
        domain = ""
        if "@" in self.email:
            domain = self.email.split("@", 1)[1]
        detail = self.message
        if domain and domain not in detail:
            detail = f"{detail}（域名: {domain}）"
        if self.email and self.email not in detail:
            detail = f"{detail} | 邮箱: {self.email}"
        super().__init__(detail)


class RegistrationRiskDenied(Exception):
    """账号已创建，但服务端将本次注册裁决为 OAuth 不可用。"""



FAIL_DOMAIN = "domain_rejected"
FAIL_ALREADY_REGISTERED = "already_registered"
FAIL_RISK = "registration_risk"
FAIL_CODE = "code_timeout"
FAIL_BROWSER = "browser"
FAIL_CPA = "cpa"
FAIL_STUCK = "stuck_retry"
FAIL_SSO = "sso_timeout"
FAIL_OTHER = "other"

FAIL_LABELS = {
    FAIL_DOMAIN: "域名拒绝",
    FAIL_ALREADY_REGISTERED: "账号已注册",
    FAIL_RISK: "注册风控",
    FAIL_CODE: "验证码超时",
    FAIL_BROWSER: "浏览器断开",
    FAIL_CPA: "CPA失败",
    FAIL_STUCK: "流程卡住",
    FAIL_SSO: "SSO超时",
    FAIL_OTHER: "其它",
}


def classify_failure(exc) -> str:
    if isinstance(exc, EmailDomainRejected):
        return FAIL_DOMAIN
    if isinstance(exc, _rf.AccountAlreadyRegistered):
        return FAIL_ALREADY_REGISTERED
    if isinstance(exc, RegistrationRiskDenied):
        return FAIL_RISK
    msg = str(exc or "")
    low = msg.lower()
    if isinstance(exc, AccountRetryNeeded) or "达到最大重试" in msg or "流程卡住" in msg:
        return FAIL_STUCK
    if "sso_timeout" in low or "未获取到 sso" in msg or "未获取到 sso cookie" in msg:
        return FAIL_SSO
    if "未收到验证码" in msg or "验证码阶段失败" in msg or "验证码" in msg and "失败" in msg:
        return FAIL_CODE
    if (
        "浏览器" in msg
        or "page disconnected" in low
        or "与页面的连接已断开" in msg
        or "PageDisconnected" in msg
        or "disconnected" in low
    ):
        return FAIL_BROWSER
    if "[CPA]" in msg or "CPA" in msg and ("失败" in msg or "跳过" in msg):
        return FAIL_CPA
    return FAIL_OTHER


def empty_fail_stats():
    return {k: 0 for k in FAIL_LABELS}


def format_fail_stats(stats: dict) -> str:
    parts = [f"{FAIL_LABELS.get(k, k)}={stats.get(k, 0)}" for k in FAIL_LABELS if stats.get(k, 0)]
    if not parts:
        return "无分类失败"
    return " | ".join(parts)


def new_registration_batch_id(source="web"):
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{source}-{stamp}-{secrets.token_hex(3)}"


def current_attempt_email(email="", exc=None):
    return str(
        getattr(exc, "email", "")
        or email
        or _rf.last_acquired_email()
        or ""
    ).strip()


def current_attempt_password(profile=None):
    current = dict(profile or {})
    if current.get("password"):
        return str(current.get("password") or "")
    return str(_rf.last_profile().get("password") or "")


def capture_failure_screenshot(
    *,
    batch_id="",
    worker_id=0,
    email="",
    failure_type="",
    log_callback=None,
):
    """保存当前活动页面；页面不存在或已经断开时返回空路径。"""
    current_page = _active_page()
    if current_page is None:
        return ""

    def _safe_part(value, fallback):
        normalized = re.sub(r"[^A-Za-z0-9._@-]+", "_", str(value or "").strip())
        return normalized.strip("._-")[:80] or fallback

    folder = os.path.join(DATA_DIR, "screenshots", "registration-failures")
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    filename = "-".join(
        (
            _safe_part(batch_id, "batch"),
            f"w{max(int(worker_id or 0), 0) + 1}",
            _safe_part(email, "unknown"),
            _safe_part(failure_type, "failure"),
            stamp,
            secrets.token_hex(2),
        )
    ) + ".png"
    path = os.path.abspath(os.path.join(folder, filename))
    try:
        os.makedirs(folder, exist_ok=True)
        current_page.screenshot(path=path, full_page=True)
        if not os.path.isfile(path) or os.path.getsize(path) <= 0:
            return ""
        if log_callback:
            log_callback(f"[截图] 浏览器失败现场已保存: {path}")
        return path
    except Exception as exc:
        try:
            if os.path.isfile(path):
                os.remove(path)
        except OSError:
            pass
        if log_callback:
            log_callback(f"[Debug] 浏览器失败截图保存失败: {exc}")
        return ""


def is_outlookemail_registration(provider="") -> bool:
    value = str(provider or config.get("email_provider", "") or "").strip().lower()
    return value == "outlookemail"


def cpa_conversion_succeeded(cpa_detail=None) -> bool:
    return dict(cpa_detail or {}).get("status") == "success"


def registration_counts_as_success(cpa_detail=None) -> bool:
    """所有邮箱服务商统一以 CPA 的 success 状态作为注册成功标准。"""
    return cpa_conversion_succeeded(cpa_detail)


def cpa_failure_reason(cpa_detail=None) -> str:
    detail = dict(cpa_detail or {})
    error = str(detail.get("error") or "").strip()
    status = str(detail.get("status") or "not_attempted").strip() or "not_attempted"
    return error or f"CPA 转换状态为 {status}，未达到 success"


def default_email_disable_detail(provider="", cpa_detail=None) -> dict:
    if not is_outlookemail_registration(provider):
        status = "not_applicable"
    elif not cpa_conversion_succeeded(cpa_detail):
        status = "skipped_cpa"
    elif not bool(config.get("outlookemail_disable_after_cpa_success", False)):
        status = "feature_disabled"
    elif get_outlookemail_source() != "accounts":
        status = "unsupported_source"
    else:
        status = "not_attempted"
    return {
        "status": status,
        "account_id": "",
        "disabled_at": "",
        "error": "",
    }


def persist_registration_result(
    *,
    batch_id,
    source,
    started_at,
    email="",
    password="",
    status="failure",
    provider="",
    worker_id=0,
    cpa_detail=None,
    email_disable_detail=None,
    failure_type="",
    failure_reason="",
    screenshot_path="",
    account_file="",
    sso_saved=False,
    nsfw_status="",
    extra=None,
    log_callback=None,
):
    """统一保存 Web 注册结果；写库异常不打断注册流程。"""
    finished_epoch = time.time()
    try:
        started_epoch = float(started_at or finished_epoch)
    except (TypeError, ValueError):
        started_epoch = finished_epoch
    started_text = datetime.datetime.fromtimestamp(started_epoch).astimezone().strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    finished_text = datetime.datetime.fromtimestamp(finished_epoch).astimezone().strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    detail = dict(cpa_detail or {})
    provider_name = provider or str(config.get("email_provider", "") or "")
    cpa_enabled = bool(detail.get("enabled", config.get("cpa_auto_add", False)))
    cpa_status = str(
        detail.get("status")
        or ("disabled" if not cpa_enabled else "not_attempted")
    )
    auth_info = detail.get("auth_info", "")
    if isinstance(auth_info, (list, tuple, set)):
        auth_info = "\n".join(str(item) for item in auth_info if str(item).strip())
    extra_data = dict(extra or {})
    if detail.get("error"):
        extra_data["cpa_error"] = str(detail.get("error"))
    if detail.get("mode"):
        extra_data["cpa_mode"] = str(detail.get("mode"))
    disable_detail = default_email_disable_detail(provider_name, detail)
    disable_detail.update(dict(email_disable_detail or {}))
    try:
        return get_registration_repository().add_result(
            {
                "batch_id": batch_id,
                "source": source,
                "started_at": started_text,
                "finished_at": finished_text,
                "duration_seconds": max(finished_epoch - started_epoch, 0),
                "email": email,
                "password": password,
                "status": status,
                "success": status == "success",
                "provider": provider_name,
                "worker_id": worker_id,
                "cpa_enabled": cpa_enabled,
                "cpa_status": cpa_status,
                "auth_info": auth_info,
                "auth_path": detail.get("auth_path", ""),
                "cpa_auth_path": detail.get("cpa_auth_path", ""),
                "grok2api_auth_path": detail.get("grok2api_auth_path", ""),
                "cpa_remote_status": detail.get("cpa_remote_status", "not_configured"),
                "cpa_remote_imported_at": detail.get("cpa_remote_imported_at", ""),
                "cpa_remote_error": detail.get("cpa_remote_error", ""),
                "grok2api_remote_status": detail.get(
                    "grok2api_remote_status", "not_configured"
                ),
                "grok2api_remote_imported_at": detail.get(
                    "grok2api_remote_imported_at", ""
                ),
                "grok2api_remote_error": detail.get("grok2api_remote_error", ""),
                "email_account_id": disable_detail.get("account_id", ""),
                "email_disable_status": disable_detail.get("status", "not_attempted"),
                "email_disabled_at": disable_detail.get("disabled_at", ""),
                "email_disable_error": disable_detail.get("error", ""),
                "failure_type": failure_type,
                "failure_reason": str(failure_reason or ""),
                "screenshot_path": screenshot_path,
                "account_file": account_file,
                "sso_saved": sso_saved,
                "nsfw_status": nsfw_status,
                "bot_risk": bool(detail.get("bot_risk")),
                "bfs": "" if detail.get("bfs") is None else detail.get("bfs"),
                "extra": extra_data,
            }
        )
    except Exception as exc:
        if log_callback:
            log_callback(f"[!] SQLite 保存注册结果失败: {exc}")
        return None



def load_config():
    global config
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            config = {**DEFAULT_CONFIG, **loaded}
        except Exception:
            config = DEFAULT_CONFIG.copy()
    return config


def parse_account_interval() -> float:
    """解析 account_interval 配置，返回等待秒数。

    "0" / "" → 0（不等待）
    "30" → 30.0（固定 30 秒）
    "60-120" → 60~120 之间的随机值
    """
    raw = str(config.get("account_interval", "0") or "0").strip()
    if not raw or raw == "0":
        return 0.0
    if "-" in raw:
        parts = raw.split("-", 1)
        try:
            lo = max(int(parts[0].strip()), 0)
            hi = max(int(parts[1].strip()), lo)
            return float(random.randint(lo, hi))
        except (ValueError, IndexError):
            return 0.0
    try:
        return float(int(raw))
    except ValueError:
        return 0.0


def save_config():
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"保存配置失败: {e}")


load_config()

# turnstilePatch 是 Chrome 扩展，Camoufox 基于 Firefox 不兼容，已移除。
# Turnstile 交互由 signup_flow.getTurnstileToken 统一处理。
EXTENSION_PATH = ""


DUCKMAIL_API_BASE_DEFAULT = duckmail_provider.API_BASE_DEFAULT


def get_proxies():
    proxy = resolve_proxy_url(config.get("proxy", ""))
    if proxy:
        return {"http": proxy, "https": proxy}
    return {}


def reset_network_route_logs():
    with _network_route_log_lock:
        _network_route_log_keys.clear()


def _log_actual_http_route(method, url, *, proxies=None, proxy=""):
    """记录实际请求的接口和路由；相同方法/接口/路由只记录一次。"""
    parsed = urlsplit(str(url or ""))
    display_url = (
        f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        if parsed.netloc
        else str(url or "")
    )
    proxy_value = str(proxy or "").strip()
    if not proxy_value and isinstance(proxies, dict):
        proxy_value = str(
            proxies.get(parsed.scheme)
            or proxies.get("all")
            or proxies.get("https")
            or proxies.get("http")
            or ""
        ).strip()
    route = f"代理 {proxy_value}" if proxy_value else "直连（不使用代理）"
    key = (str(method or "GET").upper(), display_url, route)
    with _network_route_log_lock:
        if key in _network_route_log_keys:
            return
        _network_route_log_keys.add(key)
    registration_log(f"[*] [网络] {key[0]} {display_url} -> {route}")


def get_duckmail_api_base():
    return duckmail_provider.normalize_base(str(config.get("duckmail_api_base", "") or ""))


def get_duckmail_api_key():
    return config.get("duckmail_api_key", "")



def get_cloudflare_api_base():
    return str(config.get("cloudflare_api_base", "") or "").rstrip("/")


def get_cloudflare_api_key():
    return config.get("cloudflare_api_key", "")


def get_cloudflare_auth_mode():
    return str(config.get("cloudflare_auth_mode", "none") or "none").lower()


def get_cloudflare_custom_auth():
    """全局访问密码（cloudflare_temp_email 的 PASSWORDS）。"""
    return str(config.get("cloudflare_custom_auth", "") or "").strip()


def cloudflare_apply_custom_auth(headers):
    return cloudflare_provider.apply_custom_auth(headers, get_cloudflare_custom_auth())


def get_cloudflare_path(key, default_path):
    return cloudflare_provider.path_from_config(config, key, default_path)


def cloudflare_build_headers(content_type=False):
    return cloudflare_provider.build_headers(
        get_cloudflare_api_key(),
        get_cloudflare_auth_mode(),
        get_cloudflare_custom_auth(),
        content_type=content_type,
    )


def cloudflare_apply_auth_params(params=None):
    return cloudflare_provider.apply_auth_params(
        params, get_cloudflare_api_key(), get_cloudflare_auth_mode()
    )


def cloudflare_next_default_domain():
    global _cf_domain_index
    domains = [x.strip() for x in str(config.get("defaultDomains", "") or "").split(",") if x.strip()]
    domain, _cf_domain_index = cloudflare_provider.next_default_domain(domains, _cf_domain_index)
    return domain


def cloudflare_is_admin_create_path(path):
    return cloudflare_provider.is_admin_create_path(path)


def _pick_list_payload(data):
    return _pick_list(data)


def cloudflare_create_temp_address(api_base):
    return cloudflare_provider.create_temp_address(
        http_post,
        api_base,
        accounts_path=get_cloudflare_path("cloudflare_path_accounts", "/admin/new_address"),
        domain=cloudflare_next_default_domain(),
        api_key=get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
        name=generate_username(10),
    )


MAILNEST_API_BASE = mailnest_provider.API_BASE
MAILNEST_DEFAULT_PROJECT_CODE = mailnest_provider.DEFAULT_PROJECT_CODE


def get_mailnest_api_key():
    key = str(config.get("mailnest_api_key", "") or "").strip()
    if not key:
        raise Exception(f"请在配置文件中配置 mailnest_api_key | 注册网址：{MAILNEST_API_BASE}")
    return key


def get_mailnest_project_code():
    code = str(config.get("mailnest_project_code", "") or "").strip()
    return code or MAILNEST_DEFAULT_PROJECT_CODE


def mailnest_buy_email():
    return mailnest_provider.buy_email(http_post, get_mailnest_api_key(), get_mailnest_project_code())


def mailnest_receive_email(email):
    return mailnest_provider.receive_email(http_post, get_mailnest_api_key(), email)


def mailnest_get_code(email, timeout=180, poll_interval=3, log_callback=None, cancel_callback=None):
    return mailnest_provider.wait_for_code(
        http_post,
        get_mailnest_api_key(),
        email,
        timeout=timeout,
        poll_interval=poll_interval,
        raise_if_cancelled=raise_if_cancelled,
        sleep_with_cancel=sleep_with_cancel,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )


def get_outlookemail_api_base():
    return str(config.get("outlookemail_api_base", "") or "").strip().rstrip("/")


def get_outlookemail_api_key():
    return str(config.get("outlookemail_api_key", "") or "").strip()


def get_outlookemail_source():
    return outlookemail_provider.normalize_source(config.get("outlookemail_source", "accounts"))


def _outlookemail_account_already_saved(email):
    return email_registered_successfully(email)


def reset_outlookemail_runtime_state():
    outlookemail_provider.reset_runtime_state()


def disable_outlookemail_after_cpa_success(email, cpa_detail=None, log_callback=None) -> dict:
    """CPA 成功后停用 accounts 来源邮箱；结果独立记录，不改变 CPA 成功状态。"""
    detail = default_email_disable_detail("outlookemail", cpa_detail)
    if detail["status"] != "not_attempted":
        if log_callback and detail["status"] == "feature_disabled":
            log_callback("[*] OutlookEmail CPA 成功后停用功能未开启")
        return detail

    normalized_email = str(email or "").strip()
    try:
        account = outlookemail_provider.account_for_email(
            http_get,
            get_outlookemail_api_base(),
            get_outlookemail_api_key(),
            normalized_email,
            group_id=str(config.get("outlookemail_group_id", "") or "").strip(),
        )
        detail["account_id"] = str(account.get("id") or "")
        if log_callback:
            log_callback(
                f"[OutlookEmail] CPA 转换成功，正在停用邮箱账号 ID={detail['account_id'] or '-'}"
            )
        result = outlookemail_provider.disable_account(
            http_get,
            direct_http_session,
            get_outlookemail_api_base(),
            normalized_email,
            api_key=get_outlookemail_api_key(),
            group_id=str(config.get("outlookemail_group_id", "") or "").strip(),
            web_password=str(config.get("outlookemail_web_password", "") or ""),
            session_cookie=str(config.get("outlookemail_session_cookie", "") or "").strip(),
            proxies={},
        )
        detail.update(
            status="success",
            account_id=str(result.get("account_id") or detail.get("account_id") or ""),
            disabled_at=RegistrationRepository.now_text(),
            error="",
        )
        if log_callback:
            suffix = "（原本已停用）" if result.get("already_inactive") else ""
            log_callback(f"[+] OutlookEmail 邮箱已停用{suffix}: {normalized_email}")
    except Exception as exc:
        detail.update(status="failed", error=str(exc))
        if log_callback:
            log_callback(f"[!] OutlookEmail 邮箱停用失败，CPA 成功记录保留: {exc}")
    return detail


def disable_outlookemail_consumed(
    email,
    *,
    reason: str = "",
    log_callback=None,
) -> dict:
    """在账号已存在 / 已拿 SSO 等场景下停用 Outlook 邮箱，避免重复取用。

    与 CPA 成功后停用共用同一开关 outlookemail_disable_after_cpa_success：
    仅在开关开启且来源为 accounts 时才会远程停用。
    """
    if not is_outlookemail_registration():
        return default_email_disable_detail("", None)
    if get_outlookemail_source() != "accounts":
        return {
            "status": "unsupported_source",
            "account_id": "",
            "disabled_at": "",
            "error": "",
        }
    if not bool(config.get("outlookemail_disable_after_cpa_success", False)):
        if log_callback:
            log_callback("[*] OutlookEmail 自动停用功能未开启，跳过停用")
        return {
            "status": "feature_disabled",
            "account_id": "",
            "disabled_at": "",
            "error": "",
        }

    normalized_email = str(email or "").strip()
    detail = {
        "status": "not_attempted",
        "account_id": "",
        "disabled_at": "",
        "error": "",
    }
    if not normalized_email:
        detail.update(status="failed", error="缺少邮箱地址")
        return detail
    try:
        account = outlookemail_provider.account_for_email(
            http_get,
            get_outlookemail_api_base(),
            get_outlookemail_api_key(),
            normalized_email,
            group_id=str(config.get("outlookemail_group_id", "") or "").strip(),
        )
        detail["account_id"] = str(account.get("id") or "")
        reason_text = str(reason or "").strip()
        if log_callback:
            already = ("已注册" in reason_text) or ("already" in reason_text.lower()) or (
                "existing account" in reason_text.lower()
            )
            if already:
                log_callback(
                    f"[OutlookEmail] 账号已注册，正在停用 Outlook 邮箱: {normalized_email}"
                    f" (ID={detail['account_id'] or '-'})"
                )
                if reason_text:
                    log_callback(f"[OutlookEmail] 已注册详情: {reason_text}")
            else:
                suffix = f"（原因: {reason_text}）" if reason_text else ""
                log_callback(
                    f"[OutlookEmail] 正在停用已消耗邮箱 ID={detail['account_id'] or '-'}{suffix}"
                )
        result = outlookemail_provider.disable_account(
            http_get,
            direct_http_session,
            get_outlookemail_api_base(),
            normalized_email,
            api_key=get_outlookemail_api_key(),
            group_id=str(config.get("outlookemail_group_id", "") or "").strip(),
            web_password=str(config.get("outlookemail_web_password", "") or ""),
            session_cookie=str(config.get("outlookemail_session_cookie", "") or "").strip(),
            proxies={},
        )
        detail.update(
            status="success",
            account_id=str(result.get("account_id") or detail.get("account_id") or ""),
            disabled_at=RegistrationRepository.now_text(),
            error="",
        )
        if log_callback:
            extra = "（原本已停用）" if result.get("already_inactive") else ""
            already = ("已注册" in reason_text) or ("already" in reason_text.lower()) or (
                "existing account" in reason_text.lower()
            )
            if already:
                log_callback(
                    f"[+] 账号已注册场景：Outlook 邮箱已停用{extra}: {normalized_email}"
                )
            else:
                log_callback(f"[+] OutlookEmail 邮箱已停用{extra}: {normalized_email}")
    except Exception as exc:
        detail.update(status="failed", error=str(exc))
        if log_callback:
            already = ("已注册" in str(reason or "")) or ("already" in str(reason or "").lower())
            prefix = "账号已注册场景：" if already else ""
            log_callback(f"[!] {prefix}OutlookEmail 邮箱停用失败: {exc}")
    return detail


def outlookemail_get_email_and_token():
    return outlookemail_provider.acquire_email(
        http_get,
        direct_http_session,
        get_outlookemail_api_base(),
        api_key=get_outlookemail_api_key(),
        source=get_outlookemail_source(),
        group_id=str(config.get("outlookemail_group_id", "") or "").strip(),
        web_password=str(config.get("outlookemail_web_password", "") or ""),
        session_cookie=str(config.get("outlookemail_session_cookie", "") or "").strip(),
        temp_tag_ids=str(config.get("outlookemail_temp_tag_ids", "") or ""),
        pick_mode=str(config.get("outlookemail_pick_mode", "random") or "random"),
        proxies={},
        is_unavailable=_outlookemail_account_already_saved,
    )


def outlookemail_get_oai_code(
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    min_received_at=None,
):
    return outlookemail_provider.wait_for_code(
        http_get,
        direct_http_session,
        get_outlookemail_api_base(),
        email,
        api_key=get_outlookemail_api_key(),
        source=get_outlookemail_source(),
        web_password=str(config.get("outlookemail_web_password", "") or ""),
        session_cookie=str(config.get("outlookemail_session_cookie", "") or "").strip(),
        folder=str(config.get("outlookemail_folder", "all") or "all"),
        top=config.get("outlookemail_top", 10),
        proxies={},
        timeout=timeout,
        poll_interval=poll_interval,
        min_received_at=min_received_at,
        raise_if_cancelled=raise_if_cancelled,
        sleep_with_cancel=sleep_with_cancel,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )


def get_user_agent():
    return config.get(
        "user_agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    )


def _normalize_sso_token(raw_token):
    token = str(raw_token or "").strip()
    if token.startswith("sso="):
        token = token[4:]
    return token


def _resolve_cpa_proxy():
    """CPA 换 token 用的代理：优先 config.proxy，其次环境变量，否则直连。"""
    proxy = resolve_proxy_url(config.get("proxy", ""))
    if proxy:
        return proxy
    for key in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"):
        val = str(os.environ.get(key, "") or "").strip()
        if val:
            return val
    return ""


def _append_sso_pending(email: str, sso: str, log_callback=None):
    """授权转换失败时保留 SSO，便于之后重新交换凭据。"""
    try:
        path = accounts_side_file("sso_pending.txt")
        line = f"{email}----{sso}\n" if email else f"{sso}\n"
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
        if log_callback:
            log_callback(f"[CPA] 已追加待重转 SSO → {path}")
    except Exception as exc:
        if log_callback:
            log_callback(f"[CPA] 写入 sso_pending 失败: {exc}")


def _append_sso_risk_rejected(email: str, sso: str, details: str, log_callback=None):
    """保存注册风控拒绝的 SSO；该类账号不进入待重转队列。"""
    try:
        path = accounts_side_file("sso_risk_rejected.txt")
        safe_details = re.sub(r"[\r\n\t]+", " ", str(details or "")).strip()
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{email}----{sso}----{safe_details}\n")
        if log_callback:
            log_callback(f"[CPA] 已保存注册风控拒绝记录 → {path}")
    except Exception as exc:
        if log_callback:
            log_callback(f"[CPA] 保存注册风控拒绝记录失败: {exc}")


def ensure_sso_oauth_eligible(raw_token, email="", log_callback=None) -> dict:
    """复查新账号风控状态；无法稳定判定时不进入 OAuth。"""
    if not config.get("cpa_auto_add", False):
        return {}
    if not any(
        str(config.get(key, "") or "").strip()
        for key in ("cpa_auth_dir", "cpa_remote_url", "grok2api_auth_dir")
    ):
        return {}
    sso = _normalize_sso_token(raw_token)
    if not sso:
        raise RegistrationRiskDenied("注册风控检查失败: sso 为空")

    def _risk_log(message):
        if log_callback:
            log_callback(f"[CPA] {str(message).strip()}")

    retry_delays = (0, 2, 4, 8)
    proxy = _resolve_cpa_proxy()
    last_state = {}

    for attempt, delay in enumerate(retry_delays, start=1):
        if delay:
            _risk_log(f"风控字段尚未稳定，{delay}s 后进行第 {attempt} 次检查")
            time.sleep(delay)
        _risk_log(f"检查新账号注册风控状态 ({attempt}/{len(retry_delays)}) ...")
        state = _s2cpa.inspect_sso_account_state(
            sso,
            proxy=proxy,
            log=_risk_log,
        )
        last_state = state
        source = state.get("bot_flag_source")
        source_flagged = source not in (None, 0, "0", "")
        if state.get("denied") or source_flagged:
            details = str(
                state.get("bot_flag_details")
                or f"botFlagSource={source},policy=unknown,event=unknown"
            )
            _append_sso_risk_rejected(email, sso, details, log_callback=log_callback)
            raise RegistrationRiskDenied(
                "注册风控拒绝，已跳过 OAuth: "
                f"botFlagSource={source} {details}"
            )

        # 明确读取到非风险状态后即可继续；字段为 null 时继续短时复查，避免注册结果延迟写入。
        if state.get("found") and (
            source == 0
            or str(state.get("policy") or "").lower() in {"allow", "review"}
            or bool(state.get("bot_flag_details"))
        ):
            return state

        _risk_log(
            "本次未得到稳定风控结论: "
            f"{state.get('error') or 'botFlag 字段为空'}"
        )

    reason = str(last_state.get("error") or "botFlag 字段持续为空")
    _risk_log(f"注册风控状态无法确认，继续 OAuth: {reason}")
    return last_state


def add_sso_to_cpa(raw_token, email="", log_callback=None, result_out=None) -> bool:
    """SSO → Device Flow（失败回退授权码）换 token → 写入 CPA / Grok2API。

    返回 True 表示入库成功（或未开启/无需转换）；False 表示转换失败（SSO 仍可能已写入 accounts）。
    """
    result = result_out if isinstance(result_out, dict) else None

    def _set_result(**values):
        if result is not None:
            result.update(values)

    cpa_enabled = bool(config.get("cpa_auto_add", False))
    _set_result(
        enabled=cpa_enabled,
        status="not_attempted" if cpa_enabled else "disabled",
        mode=str(config.get("cpa_token_mode", "device_protocol") or "device_protocol"),
        auth_info=[],
        auth_path="",
        cpa_auth_path="",
        grok2api_auth_path="",
        cpa_remote_status="not_configured",
        cpa_remote_imported_at="",
        cpa_remote_error="",
        grok2api_remote_status="not_configured",
        grok2api_remote_imported_at="",
        grok2api_remote_error="",
        bot_risk=False,
        bfs="",
        error="",
    )
    if not cpa_enabled:
        if log_callback:
            log_callback("[*] 已关闭 SSO→auth，仅保存 SSO；CPA 非 success，本账号不计注册成功")
        return True
    auth_dir = str(config.get("cpa_auth_dir", "") or "").strip()
    remote_url = str(config.get("cpa_remote_url", "") or "").strip()
    management_key = str(config.get("cpa_management_key", "") or "").strip()
    g2a_dir = str(config.get("grok2api_auth_dir", "") or "").strip()
    g2a_remote_configured = _grok2api.Grok2APIClient.is_configured(config)
    g2a_auto_import = bool(config.get("grok2api_auto_import", False))
    _set_result(
        cpa_remote_status="ready" if remote_url and management_key else "not_configured",
        grok2api_remote_status="ready" if g2a_remote_configured else "not_configured",
    )

    # 相对路径基于项目根目录解析，并自动创建目录
    if auth_dir and not os.path.isabs(auth_dir):
        auth_dir = os.path.join(APP_DIR, auth_dir)
    if g2a_dir and not os.path.isabs(g2a_dir):
        g2a_dir = os.path.join(APP_DIR, g2a_dir)

    preflight_errors = []
    if not auth_dir and not remote_url and not g2a_dir:
        _set_result(status="skipped", error="未配置 CPA/Grok2API 授权目标")
        if log_callback:
            log_callback(
                "[Debug] 已开启 SSO→auth 但未配置 cpa_auth_dir / cpa_remote_url / grok2api_auth_dir，跳过"
            )
        return True
    if remote_url and not management_key:
        remote_error = "远程 CPA 缺少管理密钥"
        preflight_errors.append(remote_error)
        _set_result(auth_info=list(preflight_errors), error=remote_error)
        if log_callback:
            log_callback("[Debug] 已配置 cpa_remote_url 但未配置 cpa_management_key，跳过远程上传")
        remote_url = ""
    if not auth_dir and not remote_url and not g2a_dir:
        error_text = "; ".join(preflight_errors) or "没有可用的 CPA/Grok2API 授权目标"
        _set_result(status="skipped", auth_info=list(preflight_errors), error=error_text)
        return True
    sso = _normalize_sso_token(raw_token)
    if not sso:
        _set_result(status="failed", error="SSO 为空")
        return False
    proxy = _resolve_cpa_proxy()

    def _cpa_log(message):
        if log_callback:
            log_callback(f"[CPA] {str(message).strip()}")

    try:
        token_mode = str(config.get("cpa_token_mode", "device_protocol") or "device_protocol").lower()
        if token_mode not in ("device_protocol", "device_browser", "auth_code"):
            token_mode = "device_protocol"
        _set_result(mode=token_mode)
        _mode_labels = {
            "device_protocol": "协议 Device Flow",
            "device_browser": "浏览器 Device Flow",
            "auth_code": "Authorization Code",
        }
        _cpa_log(f"SSO → {_mode_labels.get(token_mode, token_mode)} 换 token (proxy={proxy}) ...")

        def _browser_approve(user_code, open_url):
            return authorize_device_in_browser(
                user_code,
                open_url,
                timeout=90,
                log_callback=log_callback,
                cancel_callback=None,
            )

        # device_browser 模式：需要活动浏览器来点「继续/允许」
        # device_protocol 模式：纯 HTTP 协议换 token，不依赖浏览器
        # auth_code 模式：走授权码流程
        use_browser = token_mode == "device_browser" and _active_page() is not None
        if token_mode == "device_browser" and not use_browser:
            _cpa_log("无活动浏览器，回退到协议 Device Flow")
            token_mode = "device_protocol"
            _set_result(mode=token_mode)

        # sso_to_token 的 prefer 只区分 device / auth_code
        # browser_approve 是否传入决定走浏览器还是协议
        prefer = "auth_code" if token_mode == "auth_code" else "device"
        browser_cb = _browser_approve if use_browser else None

        token = _s2cpa.sso_to_token(
            sso,
            proxy=proxy,
            log=_cpa_log,
            prefer=prefer,
            allow_fallback=True,
            browser_approve=browser_cb,
        )
        if not token:
            _set_result(status="failed", error="SSO 换 token 失败")
            _cpa_log("换 token 失败；SSO 已在 accounts 文件，稍后可重转")
            _append_sso_pending(email, sso, log_callback=log_callback)
            return False
        record = _s2cpa.token_to_cpa_record(token, email=email, sso=sso)
        access_token = str(record.get("access_token") or "")
        ap = _s2cpa.decode_jwt_payload(access_token)
        ref = ap.get("referrer")
        if ref:
            _cpa_log(f"access_token referrer={ref!r}")
        bfs = _s2cpa.access_token_bfs(access_token)
        bot_risk = _s2cpa.access_token_bot_risk(access_token)
        _set_result(bfs=bfs if bfs is not None else "", bot_risk=bot_risk)
        if bot_risk:
            _cpa_log(f"access_token 风控标记 bfs={bfs!r}")
        elif bfs is not None:
            _cpa_log(f"access_token bfs={bfs!r}")
        wrote_ok = False
        auth_entries = []
        auth_errors = list(preflight_errors)
        auth_path_value = ""
        cpa_auth_path_value = ""
        grok2api_auth_path_value = ""
        if auth_dir:
            try:
                path = _s2cpa.write_cpa_auth(_s2cpa.Path(auth_dir), record)
                _cpa_log(f"已写入 CPA 本地 {path}")
                wrote_ok = True
                cpa_auth_path_value = str(path)
                auth_path_value = auth_path_value or str(path)
                auth_entries.append(f"CPA 本地: {path}")
            except Exception as local_exc:
                _cpa_log(f"CPA 本地写入失败: {local_exc}")
                auth_errors.append(f"CPA 本地失败: {local_exc}")
        if remote_url:
            try:
                # CPA 管理端通常是本机或内网服务，远程上传固定直连；
                # config.proxy 只用于 xAI/Grok 的 SSO→token/Auth 链路。
                _cpa_log(f"CPA 远程上传网络: 直连 -> {remote_url.rstrip('/')}")
                name = _s2cpa.upload_cpa_auth_remote(
                    remote_url,
                    management_key,
                    record,
                    proxy="",
                )
                _cpa_log(f"已上传 CPA 远程 {remote_url.rstrip('/')}/.../{name}")
                wrote_ok = True
                auth_entries.append(f"CPA 远程: {remote_url.rstrip('/')}/.../{name}")
                _set_result(
                    cpa_remote_status="success",
                    cpa_remote_imported_at=RegistrationRepository.now_text(),
                    cpa_remote_error="",
                )
            except Exception as remote_exc:
                _cpa_log(f"CPA 远程上传失败: {remote_exc}")
                auth_errors.append(f"CPA 远程失败: {remote_exc}")
                _set_result(cpa_remote_status="failed", cpa_remote_error=str(remote_exc))
        if g2a_dir:
            try:
                gpaths = _s2cpa.write_grok2api_auth_bundle(
                    _s2cpa.Path(g2a_dir), token, email=email, sso=sso
                )
                gpath = gpaths["grok_build"]
                _cpa_log(
                    "已写入 Grok2API "
                    + ", ".join(f"{kind}={path}" for kind, path in gpaths.items())
                )
                wrote_ok = True
                grok2api_auth_path_value = str(gpath)
                auth_path_value = auth_path_value or str(gpath)
                auth_entries.extend(f"Grok2API {kind}: {path}" for kind, path in gpaths.items())
                if g2a_remote_configured and g2a_auto_import:
                    _cpa_log(
                        "Grok2API 远程导入网络: 直连 -> "
                        f"{str(config.get('grok2api_remote_url') or '').rstrip('/')}"
                    )
                    remote_results = {}
                    remote_errors = {}
                    try:
                        with _grok2api.Grok2APIClient.from_config(config) as client:
                            for format_name, format_path in gpaths.items():
                                try:
                                    remote_result = client.import_auth_file(
                                        format_path, format_name=format_name
                                    )
                                    remote_results[format_name] = remote_result
                                    _cpa_log(
                                        f"已导入远程 Grok2API {format_name} "
                                        f"(created={remote_result.get('created', 0)}, "
                                        f"updated={remote_result.get('updated', 0)}, "
                                        f"synced={remote_result.get('synced', 0)})"
                                    )
                                except Exception as remote_g2a_exc:
                                    remote_errors[format_name] = str(remote_g2a_exc)
                                    _cpa_log(
                                        f"Grok2API 远程导入失败 [{format_name}]: {remote_g2a_exc}"
                                    )
                    except Exception as remote_client_exc:
                        remote_errors["client"] = str(remote_client_exc)
                        _cpa_log(f"Grok2API 远程客户端初始化失败: {remote_client_exc}")
                    imported_at = RegistrationRepository.now_text()
                    sync_failed = sum(
                        int(result.get("syncFailed", 0) or 0)
                        for result in remote_results.values()
                    )
                    if remote_errors:
                        remote_status = "partial" if remote_results else "failed"
                    else:
                        remote_status = "partial" if sync_failed else "success"
                    remote_error_parts = [
                        f"{format_name}: {error}"
                        for format_name, error in remote_errors.items()
                    ]
                    auth_errors.extend(remote_error_parts)
                    if sync_failed:
                        remote_error_parts.append(f"远程同步失败 {sync_failed} 个")
                    _set_result(
                        grok2api_remote_status=remote_status,
                        grok2api_remote_imported_at=imported_at if remote_results else "",
                        grok2api_remote_error="; ".join(remote_error_parts),
                        grok2api_remote_result={
                            "formats": remote_results,
                            "errors": remote_errors,
                        },
                    )
                elif g2a_remote_configured:
                    _set_result(grok2api_remote_status="ready")
            except Exception as g2a_exc:
                _cpa_log(f"Grok2API 写入失败: {g2a_exc}")
                auth_errors.append(f"Grok2API 失败: {g2a_exc}")
        if not wrote_ok:
            error_text = "; ".join(auth_errors) or "CPA/Grok2API 均未写入成功"
            _set_result(
                status="failed",
                auth_info=auth_entries + auth_errors,
                auth_path=auth_path_value,
                cpa_auth_path=cpa_auth_path_value,
                grok2api_auth_path=grok2api_auth_path_value,
                error=error_text,
            )
            _cpa_log("token 已换出但 CPA/Grok2API 均未写入成功")
            _append_sso_pending(email, sso, log_callback=log_callback)
            return False
        _set_result(
            status="success",
            auth_info=auth_entries + auth_errors,
            auth_path=auth_path_value,
            cpa_auth_path=cpa_auth_path_value,
            grok2api_auth_path=grok2api_auth_path_value,
            error="; ".join(auth_errors),
        )
        return True
    except Exception as exc:
        _set_result(status="failed", error=str(exc))
        _cpa_log(f"直出失败: {exc}")
        _append_sso_pending(email, sso, log_callback=log_callback)
        return False


# 浏览器启动参数由 automation.session 统一生成。

def _build_request_kwargs(**kwargs):
    request_kwargs = dict(kwargs)
    proxies = request_kwargs.pop("proxies", None)
    # 通用 HTTP 默认直连。只有 xAI/Grok 调用方可以显式传入 get_proxies()。
    request_kwargs["proxies"] = proxies or {}
    request_kwargs.setdefault("timeout", 15)
    return request_kwargs


def _http_request(method, url, **kwargs):
    kwargs.pop("_allow_direct_fallback", None)
    with direct_http_session() as session:
        return session.request(method, url, **_build_request_kwargs(**kwargs))


def http_get(url, **kwargs):
    return _http_request("GET", url, **kwargs)


def http_post(url, **kwargs):
    return _http_request("POST", url, **kwargs)


def http_delete(url, **kwargs):
    return _http_request("DELETE", url, **kwargs)


def direct_http_session():
    """创建不读取项目代理或环境代理的 HTTP 会话。"""
    session = requests.Session(trust_env=False)
    raw_request = session.request

    def logged_request(method, url, *args, **kwargs):
        _log_actual_http_route(
            method,
            url,
            proxies=kwargs.get("proxies"),
            proxy=kwargs.get("proxy", ""),
        )
        return raw_request(method, url, *args, **kwargs)

    session.request = logged_request
    return session


def raise_if_cancelled(cancel_callback=None):
    if cancel_callback and cancel_callback():
        raise RegistrationCancelled("用户停止注册")


def sleep_with_cancel(seconds, cancel_callback=None):
    deadline = time.time() + max(seconds, 0)
    while True:
        raise_if_cancelled(cancel_callback)
        remaining = deadline - time.time()
        if remaining <= 0:
            return
        time.sleep(min(0.2, remaining))


def get_domains(api_key=None):
    return duckmail_provider.get_domains(
        http_get,
        get_duckmail_api_base(),
        api_key=api_key or get_duckmail_api_key(),
    )


def create_account(address, password, api_key=None, expires_in=0):
    return duckmail_provider.create_account(
        http_post,
        get_duckmail_api_base(),
        address,
        password,
        api_key=api_key or get_duckmail_api_key(),
        expires_in=expires_in,
    )


def get_token(address, password):
    return duckmail_provider.get_token(
        http_post,
        get_duckmail_api_base(),
        address,
        password,
    )


def get_messages(token):
    return duckmail_provider.get_messages(
        http_get,
        get_duckmail_api_base(),
        token,
    )


def get_message_detail(token, message_id):
    return duckmail_provider.get_message_detail(
        http_get,
        get_duckmail_api_base(),
        token,
        message_id,
    )



def cloudflare_get_domains(api_base, api_key=None):
    return cloudflare_provider.get_domains(
        http_get,
        api_base,
        domains_path=get_cloudflare_path("cloudflare_path_domains", "/domains"),
        api_key=api_key or get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
    )


def cloudflare_create_account(api_base, address, password, api_key=None, expires_in=0):
    return cloudflare_provider.create_account(
        http_post,
        api_base,
        address,
        password,
        accounts_path=get_cloudflare_path("cloudflare_path_accounts", "/accounts"),
        api_key=api_key or get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
        expires_in=expires_in,
    )


def cloudflare_get_token(api_base, address, password, api_key=None):
    return cloudflare_provider.get_token(
        http_post,
        api_base,
        address,
        password,
        token_path=get_cloudflare_path("cloudflare_path_token", "/token"),
        api_key=api_key or get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
    )


def cloudflare_get_messages(api_base, token):
    return cloudflare_provider.get_messages(
        http_get,
        api_base,
        token,
        messages_path=get_cloudflare_path("cloudflare_path_messages", "/messages"),
        api_key=get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
    )


def cloudflare_get_message_detail(api_base, token, message_id):
    return cloudflare_provider.get_message_detail(
        http_get,
        api_base,
        token,
        message_id,
        messages_path=get_cloudflare_path("cloudflare_path_messages", "/messages"),
        api_key=get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
    )


YYDS_API_BASE = yyds_provider.API_BASE


def get_yyds_api_key():
    return config.get("yyds_api_key", "")


def get_yyds_jwt():
    return config.get("yyds_jwt", "")


def get_yyds_default_domain():
    return str(config.get("yyds_default_domain", "") or "").strip()


def yyds_get_domains(api_key=None, jwt=None):
    return yyds_provider.get_domains(http_get, api_key=api_key or get_yyds_api_key(), jwt=jwt or get_yyds_jwt())


def yyds_create_account(local_part=None, domain=None, api_key=None, jwt=None):
    return yyds_provider.create_account(
        http_post,
        local_part=local_part or "",
        domain=domain or "",
        api_key=api_key or get_yyds_api_key(),
        jwt=jwt or get_yyds_jwt(),
    )


def yyds_get_token(address, api_key=None, jwt=None):
    return yyds_provider.get_token(http_post, address, api_key=api_key or get_yyds_api_key(), jwt=jwt or get_yyds_jwt())


def yyds_get_messages(address, token=None, api_key=None, jwt=None):
    return yyds_provider.get_messages(
        http_get,
        address,
        token=token or "",
        api_key=api_key or get_yyds_api_key(),
        jwt=jwt or get_yyds_jwt(),
    )


def yyds_get_message_detail(message_id, token=None, api_key=None, jwt=None):
    return yyds_provider.get_message_detail(
        http_get,
        message_id,
        token=token or "",
        api_key=api_key or get_yyds_api_key(),
        jwt=jwt or get_yyds_jwt(),
    )


def yyds_generate_username(length=10):
    return yyds_provider.generate_username(length)


def yyds_pick_domain(api_key=None, jwt=None):
    return yyds_provider.pick_domain(http_get, api_key=api_key or get_yyds_api_key(), jwt=jwt or get_yyds_jwt())


def yyds_get_email_and_token(api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    token = jwt or get_yyds_jwt()
    if not token and not key:
        raise Exception("YYDS API Key 或 JWT 未配置")
    domain = get_yyds_default_domain() or yyds_pick_domain(api_key=key, jwt=token)
    username = yyds_generate_username(10)
    result = yyds_create_account(
        local_part=username, domain=domain, api_key=key, jwt=token
    )
    address = result.get("address") or f"{username}@{domain}"
    temp_token = result.get("token")
    if not temp_token:
        temp_token = yyds_get_token(address, api_key=key, jwt=token)
    if not temp_token:
        raise Exception("获取 YYDS token 失败")
    print(f"[*] 已创建 YYDS 邮箱: {address}")
    return address, temp_token


def yyds_get_oai_code(token, address, timeout=180, poll_interval=3, log_callback=None, jwt=None, cancel_callback=None):
    return yyds_provider.wait_for_code(
        http_get,
        token,
        address,
        timeout=timeout,
        poll_interval=poll_interval,
        jwt=jwt or get_yyds_jwt(),
        raise_if_cancelled=raise_if_cancelled,
        sleep_with_cancel=sleep_with_cancel,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )



def generate_username(length=10):
    return _generate_username(length)


def pick_domain(api_key=None):
    return duckmail_provider.pick_domain(get_domains(api_key=api_key))


def get_cloudmail_url():
    return str(os.environ.get("CLOUDMAIL_URL") or config.get("cloudmail_url", "") or "").strip().rstrip("/")


def get_cloudmail_admin_email():
    return str(os.environ.get("CLOUDMAIL_ADMIN_EMAIL") or config.get("cloudmail_admin_email", "") or "").strip()


def get_cloudmail_password():
    return str(os.environ.get("CLOUDMAIL_PASSWORD") or config.get("cloudmail_password", "") or "")


def cloudmail_get_email_and_token():
    raw_domains = str(config.get("defaultDomains", "") or "")
    domains = [item.strip() for item in re.split(r"[,，\s]+", raw_domains) if item.strip()]
    return cloudmail_provider.create_mailbox(
        http_post,
        get_cloudmail_url(),
        get_cloudmail_admin_email(),
        get_cloudmail_password(),
        domains,
        username=generate_username(10),
    )


def cloudmail_get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    del dev_token
    return cloudmail_provider.wait_for_code(
        http_post,
        http_delete,
        get_cloudmail_url(),
        get_cloudmail_admin_email(),
        get_cloudmail_password(),
        email,
        timeout=timeout,
        poll_interval=poll_interval,
        raise_if_cancelled=raise_if_cancelled,
        sleep_with_cancel=sleep_with_cancel,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
        resend_callback=resend_callback,
    )


def get_email_provider():
    return config.get("email_provider", "cloudflare")


def get_email_and_token(api_key=None):
    provider = get_email_provider()
    if provider == "outlookemail":
        return outlookemail_get_email_and_token()
    if provider == "yyds":
        return yyds_get_email_and_token(api_key=api_key, jwt=get_yyds_jwt())
    if provider == "cloudmail":
        return cloudmail_get_email_and_token()
    if provider == "cloudflare":
        api_base = get_cloudflare_api_base()
        if not api_base:
            raise Exception("Cloudflare API Base 未配置")
        try:
            # cloudflare_temp_email 专用模式
            return cloudflare_create_temp_address(api_base)
        except Exception as primary_exc:
            create_path = get_cloudflare_path("cloudflare_path_accounts", "/admin/new_address")
            try:
                return cloudflare_provider.create_mailbox_fallback(
                    http_get,
                    http_post,
                    api_base,
                    domains_path=get_cloudflare_path("cloudflare_path_domains", "/domains"),
                    accounts_path=get_cloudflare_path("cloudflare_path_accounts", "/accounts"),
                    token_path=get_cloudflare_path("cloudflare_path_token", "/token"),
                    api_key=api_key or get_cloudflare_api_key(),
                    auth_mode=get_cloudflare_auth_mode(),
                    custom_auth=get_cloudflare_custom_auth(),
                )
            except Exception as fallback_exc:
                raise Exception(
                    "Cloudflare 创建邮箱失败；"
                    f"主接口 {create_path}: "
                    f"{primary_exc.__class__.__name__}: {primary_exc}；"
                    f"兼容回退: "
                    f"{fallback_exc.__class__.__name__}: {fallback_exc}"
                ) from fallback_exc
    if provider == "mailnest":
        return mailnest_buy_email(), "_"
    return duckmail_provider.create_mailbox(
        http_get,
        http_post,
        get_duckmail_api_base(),
        api_key=api_key or get_duckmail_api_key(),
        expires_in=0,
    )


def get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
    min_received_at=None,
):
    provider = get_email_provider()
    if provider == "outlookemail":
        return outlookemail_get_oai_code(
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            min_received_at=min_received_at,
        )
    if provider == "yyds":
        return yyds_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            jwt=get_yyds_jwt(),
            cancel_callback=cancel_callback,
        )
    if provider == "cloudmail":
        return cloudmail_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            resend_callback=resend_callback,
        )
    if provider == "cloudflare":
        return cloudflare_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            resend_callback=resend_callback,
        )
    if provider == "mailnest":
        return mailnest_get_code(
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
        )
    return duckmail_get_oai_code(
        dev_token,
        email,
        timeout=timeout,
        poll_interval=poll_interval,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )



def extract_verification_code(text, subject=""):
    return _extract_code(text, subject)


def duckmail_get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
):
    return duckmail_provider.wait_for_code(
        http_get,
        get_duckmail_api_base(),
        dev_token,
        email,
        timeout=timeout,
        poll_interval=poll_interval,
        extract_code=extract_verification_code,
        raise_if_cancelled=raise_if_cancelled,
        sleep_with_cancel=sleep_with_cancel,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )


def cloudflare_get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    return cloudflare_provider.wait_for_code(
        http_get,
        get_cloudflare_api_base(),
        dev_token,
        email,
        messages_path=get_cloudflare_path("cloudflare_path_messages", "/messages"),
        api_key=get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
        timeout=timeout,
        poll_interval=poll_interval,
        raise_if_cancelled=raise_if_cancelled,
        sleep_with_cancel=sleep_with_cancel,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
        resend_callback=resend_callback,
    )


def generate_random_birthdate():
    import datetime as dt

    today = dt.date.today()
    age = random.randint(20, 40)
    birth_year = today.year - age
    birth_month = random.randint(1, 12)
    birth_day = random.randint(1, 28)
    return f"{birth_year}-{birth_month:02d}-{birth_day:02d}T16:00:00.000Z"


def response_preview(res, limit=200):
    """安全预览 HTTP 响应体；gRPC/二进制内容不直接当文本打印。"""
    try:
        headers = {str(k).lower(): str(v).lower() for k, v in dict(getattr(res, "headers", {}) or {}).items()}
        content_type = headers.get("content-type", "")
        raw = getattr(res, "content", None)
        if raw is None:
            try:
                raw = (res.text or "").encode("utf-8", errors="replace")
            except Exception:
                raw = b""
        if not isinstance(raw, (bytes, bytearray)):
            raw = str(raw).encode("utf-8", errors="replace")
        raw = bytes(raw)

        # gRPC / protobuf 常见 content-type 或正文以不可打印字节为主
        is_binaryish = (
            "grpc" in content_type
            or "protobuf" in content_type
            or "octet-stream" in content_type
            or (raw[:1] in (b"\x00", b"\x01") and b"grpc-status" in raw)
        )
        if is_binaryish or (raw and sum(1 for b in raw[:64] if b < 9 or (13 < b < 32)) > 8):
            # 尽量抽出可读的 trailer 片段（如 grpc-status:0）
            readable = re.findall(rb"[ -~]{3,}", raw)
            text = " ".join(part.decode("ascii", errors="ignore") for part in readable)
            text = re.sub(r"\s+", " ", text).strip()
            if not text:
                text = f"<binary {len(raw)} bytes>"
            return text[:limit]

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
        text = re.sub(r"\s+", " ", text).strip()
        return text[:limit]
    except Exception:
        return ""


def is_cloudflare_block_response(res):
    try:
        headers = {str(k).lower(): str(v).lower() for k, v in dict(res.headers).items()}
        text = str(res.text or "").lower()
        server = headers.get("server", "")
        content_type = headers.get("content-type", "")
        return (
            res.status_code in (403, 429, 503)
            and (
                "cloudflare" in server
                or "cloudflare" in text
                or "cf-error" in text
                or "__cf_chl" in text
                or "text/html" in content_type
            )
        )
    except Exception:
        return False


def set_birth_date(session, log_callback=None):
    url = "https://grok.com/rest/auth/set-birth-date"
    new_headers = {
        "content-type": "application/json",
        "origin": "https://grok.com",
        "referer": "https://grok.com/",
    }
    payload = {"birthDate": generate_random_birthdate()}
    try:
        res = session.post(url, json=payload, headers=new_headers, timeout=15)
        body_preview = response_preview(res)
        if log_callback:
            log_callback(
                f"[Debug] set_birth_date status: {res.status_code}, body: {body_preview}"
            )
        if 200 <= res.status_code < 300:
            return True, "ok"
        # 生日一旦写过就不能改；算已完成，不能当失败中断后续 NSFW
        text = str(res.text or "")
        if res.status_code in (400, 409, 429) and (
            "birth-date-change-limit-reached" in text
            or "Birth date is locked" in text
            or "already set" in text.lower()
        ):
            return True, "already_set"
        if is_cloudflare_block_response(res):
            return (
                False,
                "set_birth_date 被 grok.com 的 Cloudflare 防护拦截，HTTP "
                f"{res.status_code}",
            )
        return False, f"set_birth_date HTTP {res.status_code}: {body_preview}"
    except Exception as e:
        if log_callback:
            log_callback(f"[set_birth_date] 异常: {e}")
        return False, f"set_birth_date 异常: {e}"


def set_tos_accepted(session, log_callback=None):
    url = "https://accounts.x.ai/auth_mgmt.AuthManagement/SetTosAcceptedVersion"
    payload = struct.pack("B", (2 << 3) | 0) + struct.pack("B", 1)
    data = b"\x00" + struct.pack(">I", len(payload)) + payload
    new_headers = {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "x-user-agent": "connect-es/2.1.1",
        "origin": "https://accounts.x.ai",
        "referer": "https://accounts.x.ai/accept-tos",
    }
    try:
        res = session.post(url, data=data, headers=new_headers, timeout=15)
        if log_callback:
            log_callback(f"[Debug] set_tos_accepted status: {res.status_code}")
        if 200 <= res.status_code < 300:
            return True, "ok"
        if is_cloudflare_block_response(res):
            return (
                False,
                "set_tos_accepted 被 accounts.x.ai 的 Cloudflare 防护拦截，HTTP "
                f"{res.status_code}",
            )
        return False, f"set_tos_accepted HTTP {res.status_code}: {response_preview(res)}"
    except Exception as e:
        if log_callback:
            log_callback(f"[set_tos_accepted] 异常: {e}")
        return False, f"set_tos_accepted 异常: {e}"


def encode_grpc_nsfw_settings():
    field1_content = bytes([0x10, 0x01])
    field1 = bytes([0x0A, len(field1_content)]) + field1_content
    nsfw_string = b"always_show_nsfw_content"
    field2_inner = bytes([0x0A, len(nsfw_string)]) + nsfw_string
    field2 = bytes([0x12, len(field2_inner)]) + field2_inner
    payload = field1 + field2
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def update_nsfw_settings(session, log_callback=None):
    url = "https://grok.com/auth_mgmt.AuthManagement/UpdateUserFeatureControls"
    data = encode_grpc_nsfw_settings()
    new_headers = {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "origin": "https://grok.com",
        "referer": "https://grok.com/",
    }
    try:
        res = session.post(url, data=data, headers=new_headers, timeout=15)
        if log_callback:
            log_callback(
                f"[Debug] update_nsfw status: {res.status_code}, body: {response_preview(res)}"
            )
        if 200 <= res.status_code < 300:
            return True, "ok"
        if is_cloudflare_block_response(res):
            return (
                False,
                "update_nsfw_settings 被 grok.com 的 Cloudflare 防护拦截，HTTP "
                f"{res.status_code}",
            )
        return False, f"update_nsfw_settings HTTP {res.status_code}: {response_preview(res)}"
    except Exception as e:
        if log_callback:
            log_callback(f"[update_nsfw] 异常: {e}")
        return False, f"update_nsfw_settings 异常: {e}"


def enable_nsfw_via_browser(token="", log_callback=None):
    """在已登录的注册浏览器内调用 grok.com 接口，绕过外部 HTTP 的 CF 拦截。"""
    page_obj = _active_page()
    if page_obj is None:
        return False, "浏览器页面未就绪"

    birth = generate_random_birthdate()
    nsfw_bytes = encode_grpc_nsfw_settings()
    nsfw_b64 = base64.b64encode(nsfw_bytes).decode("ascii")

    try:
        if log_callback:
            log_callback("[*] 浏览器内开启 NSFW：打开 grok.com ...")
        # 确保 SSO cookie 在浏览器上下文中
        if token:
            try:
                page_obj.set.cookies(
                    [
                        {"name": "sso", "value": token, "domain": ".x.ai", "path": "/"},
                        {"name": "sso-rw", "value": token, "domain": ".x.ai", "path": "/"},
                        {"name": "sso", "value": token, "domain": ".grok.com", "path": "/"},
                        {"name": "sso-rw", "value": token, "domain": ".grok.com", "path": "/"},
                    ]
                )
            except Exception:
                try:
                    page_obj.run_js(
                        """
const token = arguments[0];
document.cookie = 'sso=' + token + '; path=/; domain=.grok.com';
document.cookie = 'sso-rw=' + token + '; path=/; domain=.grok.com';
                        """,
                        token,
                    )
                except Exception:
                    pass
        page_obj.get("https://grok.com/")
        try:
            page_obj.wait.doc_loaded()
        except Exception:
            pass
        # 等 CF 挑战结束，否则 fetch 也会拿到 Just a moment
        for i in range(25):
            try:
                title = str(page_obj.run_js("return document.title || '';") or "").lower()
                body = str(
                    page_obj.run_js(
                        "return (document.body && (document.body.innerText||'')) || '';"
                    )
                    or ""
                ).lower()
                if "just a moment" not in title and "just a moment" not in body[:200]:
                    if "checking your browser" not in body[:300]:
                        break
            except Exception:
                pass
            time.sleep(1.0)
        else:
            if log_callback:
                log_callback("[!] grok.com 仍停在 Cloudflare 挑战页，浏览器内 NSFW 可能失败")
        time.sleep(1.0)

        result = page_obj.run_js(
            r"""
const birthDate = arguments[0];
const nsfwB64 = arguments[1];
function b64ToBytes(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
return (async () => {
  const out = { birthStatus: 0, birthBody: '', nsfwStatus: 0, nsfwBody: '', url: location.href };
  try {
    const birthRes = await fetch('https://grok.com/rest/auth/set-birth-date', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'content-type': 'application/json',
        'origin': 'https://grok.com',
        'referer': 'https://grok.com/',
      },
      body: JSON.stringify({ birthDate }),
    });
    out.birthStatus = birthRes.status;
    out.birthBody = (await birthRes.text()).slice(0, 240);
  } catch (e) {
    out.birthBody = String(e);
  }
  const birthOk = (out.birthStatus >= 200 && out.birthStatus < 300)
    || /birth-date-change-limit-reached|Birth date is locked|already set/i.test(out.birthBody || '');
  if (!birthOk && out.birthStatus !== 0) {
    return out;
  }
  try {
    const body = b64ToBytes(nsfwB64);
    const nsfwRes = await fetch('https://grok.com/auth_mgmt.AuthManagement/UpdateUserFeatureControls', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'content-type': 'application/grpc-web+proto',
        'x-grpc-web': '1',
        'origin': 'https://grok.com',
        'referer': 'https://grok.com/',
      },
      body,
    });
    out.nsfwStatus = nsfwRes.status;
    out.nsfwBody = (await nsfwRes.text()).slice(0, 240);
  } catch (e) {
    out.nsfwBody = String(e);
  }
  return out;
})();
            """,
            birth,
            nsfw_b64,
        )
        if not isinstance(result, dict):
            return False, f"浏览器 NSFW 返回异常: {result!r}"

        if log_callback:
            log_callback(
                f"[Debug] browser NSFW birth={result.get('birthStatus')} "
                f"nsfw={result.get('nsfwStatus')} body={str(result.get('birthBody') or '')[:120]}"
            )

        birth_status = int(result.get("birthStatus") or 0)
        birth_body = str(result.get("birthBody") or "")
        birth_ok = (200 <= birth_status < 300) or (
            birth_status in (400, 409, 429)
            and (
                "birth-date-change-limit-reached" in birth_body
                or "Birth date is locked" in birth_body
                or "already set" in birth_body.lower()
            )
        )
        if not birth_ok:
            if "just a moment" in birth_body.lower() or birth_status == 403:
                return False, f"浏览器内 set_birth_date 仍被 CF 拦截 HTTP {birth_status}"
            return False, f"浏览器内 set_birth_date HTTP {birth_status}: {birth_body[:160]}"

        nsfw_status = int(result.get("nsfwStatus") or 0)
        nsfw_body = str(result.get("nsfwBody") or "")
        if 200 <= nsfw_status < 300:
            return True, "成功开启 NSFW（浏览器内）"
        if "just a moment" in nsfw_body.lower() or nsfw_status == 403:
            return False, f"浏览器内 update_nsfw 被 CF 拦截 HTTP {nsfw_status}"
        return False, f"浏览器内 update_nsfw HTTP {nsfw_status}: {nsfw_body[:160]}"
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] 浏览器内 NSFW 异常: {exc}")
        return False, f"浏览器内 NSFW 异常: {exc}"


def enable_nsfw_for_token(token, cf_clearance="", user_agent="", log_callback=None):
    proxies = get_proxies()
    ua = user_agent or get_user_agent()
    if log_callback:
        log_callback(
            f"[Debug] NSFW 准备: cf_clearance={'有' if cf_clearance else '无'} | ua_len={len(ua)} | browser={'有' if _active_page() else '无'}"
        )

    # 有活动浏览器时直接走浏览器路径（HTTP 快速路径会被 accounts.x.ai Cloudflare 拦截）
    if _active_page() is not None:
        if log_callback:
            log_callback("[*] NSFW 通过浏览器执行...")
        return enable_nsfw_via_browser(token=token, log_callback=log_callback)

    # 无活动浏览器时尝试 HTTP 快速路径
    def _browser_fallback(reason):
        if _active_page() is None:
            return False, reason
        if log_callback:
            log_callback(f"[*] NSFW HTTP 快速路径未成功: {reason}，回退浏览器过盾...")
        ok, message = enable_nsfw_via_browser(token=token, log_callback=log_callback)
        if ok:
            return True, message
        return False, f"{reason}; browser fallback: {message}"

    try:
        if log_callback:
            log_callback("[*] NSFW 先尝试 HTTP 快速路径...")
        with requests.Session(impersonate="chrome120", proxies=proxies) as session:
            cookie_parts = [f"sso={token}", f"sso-rw={token}"]
            if cf_clearance:
                cookie_parts.append(f"cf_clearance={cf_clearance}")
            session.headers.update(
                {
                    "user-agent": ua,
                    "cookie": "; ".join(cookie_parts),
                    "accept": "application/json, text/plain, */*",
                    "accept-language": "en-US,en;q=0.9",
                }
            )
            ok, message = set_tos_accepted(session, log_callback)
            if not ok:
                return _browser_fallback(message)
            ok, message = set_birth_date(session, log_callback)
            if not ok:
                return _browser_fallback(message)
            ok, message = update_nsfw_settings(session, log_callback)
            if not ok:
                return _browser_fallback(message)
            return True, "成功开启 NSFW（HTTP 快速路径）"
    except Exception as e:
        return _browser_fallback(f"HTTP 快速路径异常: {e}")


# 浏览器状态由 automation.session 持有。

def is_debug_mode():
    return bool(config.get("debug_mode", False))


def is_browser_headless():
    force_headed = str(os.environ.get("GROK_FORCE_HEADED", "") or "").strip().lower()
    if force_headed in {"1", "true", "yes", "on"}:
        return False
    return bool(config.get("browser_headless", False))


def get_browser_locale() -> str:
    value = str(config.get("browser_locale", "en-US") or "en-US").strip()
    return value if value in {"en-US", "zh-CN"} else "en-US"


def should_close_browser_after_run(user_stopped: bool) -> bool:
    """正常结束时非调试模式关闭；手动停止时严格以勾选项为准。"""
    if user_stopped:
        return bool(config.get("close_browser_on_stop", False))
    return not is_debug_mode()


def maybe_stop_browser(user_stopped: bool = False, log_callback=None):
    if should_close_browser_after_run(user_stopped):
        # 手动勾选关闭时应优先于调试模式，因此这里显式 force。
        stop_browser(force=True)
        if log_callback:
            reason = "用户停止" if user_stopped else "任务结束"
            log_callback(f"[*] {reason}：已执行浏览器关闭")
        return
    if log_callback:
        if user_stopped:
            log_callback("[*] 用户停止：按当前勾选设置保留浏览器")
        else:
            log_callback("[*] 调试模式：正常结束后保留浏览器")


def get_log_level() -> str:
    level = str(config.get("log_level", "info") or "info").strip().lower()
    return level if level in ("info", "debug") else "info"


def should_emit_log(message: str) -> bool:
    """info 级别过滤 [Debug] 行；debug 全开。"""
    if get_log_level() == "debug":
        return True
    text = str(message or "")
    if text.lstrip().startswith("[Debug]") or " [Debug] " in text:
        return False
    return True


def _wire_runtime_modules():
    """向浏览器运行时和页面流程注入本次任务依赖。"""
    _bs.configure(
        get_proxies=get_proxies,
        is_debug=is_debug_mode,
        is_headless=is_browser_headless,
        get_locale=get_browser_locale,
        extension_path=EXTENSION_PATH,
    )
    _rf.configure(
        get_email_and_token=get_email_and_token,
        get_oai_code=get_oai_code,
        raise_if_cancelled=raise_if_cancelled,
        sleep_with_cancel=sleep_with_cancel,
        RegistrationCancelled=RegistrationCancelled,
        EmailDomainRejected=EmailDomainRejected,
        AccountRetryNeeded=AccountRetryNeeded,
        email_unavailable=email_registered_successfully,
    )

# 页面步骤由 registration.signup_flow 实现。

class RegistrationStopController:
    def __init__(self):
        self.stop_requested = False

    def should_stop(self):
        return self.stop_requested

    def stop(self):
        self.stop_requested = True


def registration_log(message):
    if not should_emit_log(message):
        return
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line, flush=True)


def run_registration(count):
    controller = RegistrationStopController()
    reset_network_route_logs()
    if get_email_provider() == "outlookemail":
        reset_outlookemail_runtime_state()

    success_count = 0
    fail_count = 0
    fail_stats = empty_fail_stats()
    batch_id = new_registration_batch_id("web")
    retry_count_for_slot = 0
    max_slot_retry = 3
    accounts_output_file = ""  # 已改为按邮箱单独保存，不再使用批量文件
    workers = max(1, min(int(config.get("register_workers", 1) or 1), 8, int(count or 1)))
    registration_log(f"[*] Web 任务启动，目标数量: {count} | 并发: {workers}")
    _interval_raw = str(config.get("account_interval", "0") or "0").strip()
    if _interval_raw and _interval_raw != "0":
        registration_log(f"[*] 账号间注册间隔: {_interval_raw}s")
    _token_mode_map = {"device_protocol": "协议 Device Flow", "device_browser": "浏览器 Device Flow", "auth_code": "Authorization Code"}
    _token_mode_label = _token_mode_map.get(str(config.get("cpa_token_mode", "device_protocol")), "协议 Device Flow")
    registration_log(f"[*] SSO→auth: {'开' if config.get('cpa_auto_add') else '关（账号将不计成功）'}" + (f"（{_token_mode_label}）" if config.get('cpa_auto_add') else ""))
    traceback_log_lock = threading.Lock()
    logged_traceback_signatures = set()
    # 启动前清理上次崩溃 / 强杀残留的临时 profile 目录
    try:
        _cleanup_stale_profiles(log_callback=registration_log)
    except Exception:
        pass
    try:
        startup_checks = _conn.run_connectivity_checks(config, http_get, http_post)
        for name, ok, detail in startup_checks:
            registration_log(f"[检查] [{'OK' if ok else 'FAIL'}] {name}: {detail}")
        if _conn.has_blocking_xai_failure(startup_checks):
            registration_log("[!] xAI 注册页被 Cloudflare 拦截，已停止建号；请更换当前 proxy 后重试")
            return
    except Exception as exc:
        registration_log(f"[!] 启动连通性检查异常，继续注册: {exc}")

    def _record_failure(exc):
        nonlocal fail_count
        kind = classify_failure(exc)
        fail_count += 1
        fail_stats[kind] = fail_stats.get(kind, 0) + 1
        return kind

    def _persist_result(*, started_at, worker_id=0, **kwargs):
        trace_text = ""
        if str(kwargs.get("status") or "").strip().lower() == "failure":
            trace_text = current_exception_traceback()
            if trace_text:
                extra = dict(kwargs.get("extra") or {})
                extra["exception_traceback"] = trace_text
                extra["exception_type"] = trace_text.rstrip().splitlines()[-1]
                kwargs["extra"] = extra
                signature = hash(trace_text)
                with traceback_log_lock:
                    should_log_traceback = signature not in logged_traceback_signatures
                    if should_log_traceback:
                        logged_traceback_signatures.add(signature)
                if should_log_traceback:
                    registration_log(
                        "[异常堆栈]\n"
                        + current_exception_traceback(TRACEBACK_LOG_MAX_CHARS)
                    )
        if (
            str(kwargs.get("status") or "").strip().lower() == "failure"
            and str(kwargs.get("failure_type") or "") != FAIL_CPA
            and not kwargs.get("screenshot_path")
        ):
            kwargs["screenshot_path"] = capture_failure_screenshot(
                batch_id=batch_id,
                worker_id=worker_id,
                email=str(kwargs.get("email") or ""),
                failure_type=str(kwargs.get("failure_type") or FAIL_OTHER),
                log_callback=registration_log,
            )
        return persist_registration_result(
            batch_id=batch_id,
            source="web",
            started_at=started_at,
            provider=str(config.get("email_provider", "") or ""),
            worker_id=int(worker_id) + 1,
            log_callback=registration_log,
            **kwargs,
        )

    if workers > 1:
        # Web 并发：多线程，每线程独立浏览器（thread-local）
        stats_lock = threading.Lock()
        accounts_lock = threading.Lock()
        base, rem = divmod(count, workers)
        chunks = [base + (1 if i < rem else 0) for i in range(workers)]
        threads = []
        shared = {"success": 0, "fail": 0, "fail_stats": empty_fail_stats()}

        def worker(n, wid):
            local_success = 0
            local_fail = 0
            local_fail_stats = empty_fail_stats()
            try:
                boot_started_at = time.time()
                try:
                    start_browser(log_callback=lambda m: registration_log(f"[W{wid+1}] {m}"))
                except Exception as boot_exc:
                    local_fail = n
                    local_fail_stats[FAIL_BROWSER] = local_fail_stats.get(FAIL_BROWSER, 0) + n
                    registration_log(f"[W{wid+1}] [-] 浏览器启动失败，{n} 个任务均记为失败: {boot_exc}")
                    for _ in range(max(int(n or 0), 0)):
                        _persist_result(
                            started_at=boot_started_at,
                            worker_id=wid,
                            status="failure",
                            failure_type=FAIL_BROWSER,
                            failure_reason=str(boot_exc),
                            cpa_detail={
                                "enabled": bool(config.get("cpa_auto_add", False)),
                                "status": "not_attempted" if config.get("cpa_auto_add") else "disabled",
                            },
                        )
                    return
                i = 0
                retry = 0
                while i < n and not controller.should_stop():
                    attempt_started_at = time.time()
                    email = ""
                    profile = {}
                    sso = ""
                    email_file = ""
                    cpa_detail = {
                        "enabled": bool(config.get("cpa_auto_add", False)),
                        "status": "not_attempted" if config.get("cpa_auto_add") else "disabled",
                    }
                    nsfw_status = "未执行"
                    try:
                        open_signup_page(
                            log_callback=lambda m: registration_log(f"[W{wid+1}] {m}"),
                            cancel_callback=controller.should_stop,
                        )
                        email, dev_token, submitted_at = fill_email_and_submit(
                            log_callback=lambda m: registration_log(f"[W{wid+1}] {m}"),
                            cancel_callback=controller.should_stop,
                        )
                        code = fill_code_and_submit(
                            email,
                            dev_token,
                            submitted_at=submitted_at,
                            log_callback=lambda m: registration_log(f"[W{wid+1}] {m}"),
                            cancel_callback=controller.should_stop,
                        )
                        profile = fill_profile_and_submit(
                            log_callback=lambda m: registration_log(f"[W{wid+1}] {m}"),
                            cancel_callback=controller.should_stop,
                        )
                        sso = wait_for_sso_cookie(
                            log_callback=lambda m: registration_log(f"[W{wid+1}] {m}"),
                            cancel_callback=controller.should_stop,
                        )
                        ensure_sso_oauth_eligible(
                            sso,
                            email=email,
                            log_callback=lambda m: registration_log(f"[W{wid+1}] {m}"),
                        )
                        if config.get("enable_nsfw", True):
                            nsfw_ok, nsfw_msg = enable_nsfw_for_token(
                                sso,
                                log_callback=lambda m: registration_log(f"[W{wid+1}] {m}"),
                            )
                            nsfw_status = "成功" if nsfw_ok else f"失败: {nsfw_msg}"
                        else:
                            nsfw_status = "未开启"
                        line = f"{email}----{profile.get('password','')}----{sso}\n"
                        try:
                            with accounts_lock:
                                # 以邮箱命名单独保存
                                email_file = account_file_for_email(email)
                                with open(email_file, "w", encoding="utf-8") as f:
                                    f.write(line)
                        except Exception as file_exc:
                            registration_log(
                                f"[W{wid+1}] [!] 保存账号文件失败，当前账号不计为成功: {file_exc}"
                            )
                            _append_sso_pending(
                                email,
                                sso,
                                log_callback=lambda m: registration_log(f"[W{wid+1}] {m}"),
                            )
                            raise RuntimeError(f"保存账号文件失败: {file_exc}") from file_exc
                        cpa_ok = add_sso_to_cpa(
                            sso,
                            email=email,
                            log_callback=lambda m: registration_log(f"[W{wid+1}] {m}"),
                            result_out=cpa_detail,
                        )
                        if not registration_counts_as_success(cpa_detail):
                            reason = cpa_failure_reason(cpa_detail)
                            local_fail_stats[FAIL_CPA] = local_fail_stats.get(FAIL_CPA, 0) + 1
                            local_fail += 1
                            i += 1
                            retry = 0
                            # xAI 侧账号通常已创建，按自动停用开关尝试停用 Outlook 邮箱，避免下次再取到同一邮箱。
                            email_disable_detail = (
                                disable_outlookemail_consumed(
                                    email,
                                    reason=f"CPA失败但已保存SSO: {reason}",
                                    log_callback=lambda m: registration_log(f"[W{wid+1}] {m}")
                                )
                                if is_outlookemail_registration()
                                else default_email_disable_detail("", cpa_detail)
                            )
                            _persist_result(
                                started_at=attempt_started_at,
                                worker_id=wid,
                                email=email,
                                password=current_attempt_password(profile),
                                status="failure",
                                cpa_detail=cpa_detail,
                                email_disable_detail=email_disable_detail,
                                failure_type=FAIL_CPA,
                                failure_reason=reason,
                                account_file=email_file,
                                sso_saved=True,
                                nsfw_status=nsfw_status,
                                extra={"任务序号": i, "并发数": workers},
                            )
                            registration_log(
                                f"[W{wid+1}] [-] 注册未计成功 [CPA失败]: {reason}"
                            )
                        else:
                            email_disable_detail = (
                                disable_outlookemail_after_cpa_success(
                                    email,
                                    cpa_detail,
                                    log_callback=lambda m: registration_log(f"[W{wid+1}] {m}"),
                                )
                                if is_outlookemail_registration()
                                else default_email_disable_detail("", cpa_detail)
                            )
                            local_success += 1
                            i += 1
                            retry = 0
                            if cpa_ok:
                                registration_log(f"[W{wid+1}] [+] 注册成功: {email}")
                            else:
                                registration_log(f"[W{wid+1}] [+] 注册成功（SSO 已保存，CPA 入库失败）: {email}")
                            _persist_result(
                                started_at=attempt_started_at,
                                worker_id=wid,
                                email=email,
                                password=current_attempt_password(profile),
                                status="success",
                                cpa_detail=cpa_detail,
                                email_disable_detail=email_disable_detail,
                                account_file=email_file,
                                sso_saved=True,
                                nsfw_status=nsfw_status,
                                extra={"任务序号": i, "并发数": workers},
                            )
                    except RegistrationCancelled:
                        cancelled_email = current_attempt_email(email)
                        if cancelled_email:
                            _persist_result(
                                started_at=attempt_started_at,
                                worker_id=wid,
                                email=cancelled_email,
                                password=current_attempt_password(profile),
                                status="cancelled",
                                cpa_detail=cpa_detail,
                                failure_reason="用户停止注册",
                                account_file=email_file,
                                sso_saved=bool(email_file),
                                nsfw_status=nsfw_status,
                            )
                        break
                    except EmailDomainRejected as exc:
                        kind = classify_failure(exc)
                        local_fail_stats[kind] = local_fail_stats.get(kind, 0) + 1
                        local_fail += 1
                        i += 1
                        retry = 0
                        _persist_result(
                            started_at=attempt_started_at,
                            worker_id=wid,
                            email=current_attempt_email(email, exc),
                            password=current_attempt_password(profile),
                            status="failure",
                            cpa_detail=cpa_detail,
                            failure_type=kind,
                            failure_reason=str(exc),
                            nsfw_status=nsfw_status,
                        )
                        registration_log(f"[W{wid+1}] [-] 域名拒绝: {exc}")
                    except AccountRetryNeeded as exc:
                        retry += 1
                        if retry > max_slot_retry:
                            retry_used = retry
                            kind = classify_failure(exc)
                            local_fail_stats[kind] = local_fail_stats.get(kind, 0) + 1
                            local_fail += 1
                            i += 1
                            retry = 0
                            _persist_result(
                                started_at=attempt_started_at,
                                worker_id=wid,
                                email=current_attempt_email(email, exc),
                                password=current_attempt_password(profile),
                                status="failure",
                                cpa_detail=cpa_detail,
                                failure_type=kind,
                                failure_reason=str(exc),
                                account_file=email_file,
                                sso_saved=bool(email_file),
                                nsfw_status=nsfw_status,
                                extra={"重试次数": retry_used},
                            )
                            registration_log(f"[W{wid+1}] [-] 卡住跳过: {exc}")
                    except Exception as exc:
                        kind = classify_failure(exc)
                        local_fail_stats[kind] = local_fail_stats.get(kind, 0) + 1
                        local_fail += 1
                        i += 1
                        retry = 0
                        if kind == FAIL_RISK:
                            cpa_detail.update(status="rejected", error=str(exc))
                        fail_email = current_attempt_email(email, exc)
                        email_disable_detail = None
                        if kind == FAIL_ALREADY_REGISTERED and is_outlookemail_registration() and fail_email:
                            registration_log(
                                f"[W{wid+1}] [*] 账号已注册，按自动停用开关处理 Outlook 邮箱: {fail_email}"
                            )
                            email_disable_detail = disable_outlookemail_consumed(
                                fail_email,
                                reason=f"账号已注册: {exc}",
                                log_callback=lambda m: registration_log(f"[W{wid+1}] {m}")
                            )
                            status = str((email_disable_detail or {}).get("status") or "")
                            if status == "success":
                                registration_log(
                                    f"[W{wid+1}] [+] 账号已注册：Outlook 邮箱停用完成: {fail_email}"
                                )
                            elif status == "feature_disabled":
                                registration_log(
                                    f"[W{wid+1}] [*] 账号已注册：自动停用开关未开启，跳过停用 Outlook: {fail_email}"
                                )
                            elif status == "failed":
                                registration_log(
                                    f"[W{wid+1}] [!] 账号已注册：Outlook 邮箱停用失败: {fail_email}"
                                    f" — {(email_disable_detail or {}).get('error') or ''}"
                                )
                        _persist_result(
                            started_at=attempt_started_at,
                            worker_id=wid,
                            email=fail_email,
                            password=current_attempt_password(profile),
                            status="failure",
                            cpa_detail=cpa_detail,
                            email_disable_detail=email_disable_detail,
                            failure_type=kind,
                            failure_reason=str(exc),
                            account_file=email_file,
                            sso_saved=bool(email_file) or bool(sso and kind == FAIL_RISK),
                            nsfw_status=nsfw_status,
                        )
                        registration_log(f"[W{wid+1}] [-] 失败 [{FAIL_LABELS.get(kind, kind)}]: {exc}")
                    finally:
                        if i < n and not controller.should_stop():
                            try:
                                stop_browser()
                                time.sleep(0.3)
                            except Exception:
                                pass
            finally:
                try:
                    maybe_stop_browser(
                        user_stopped=bool(controller.should_stop()),
                        log_callback=lambda m: registration_log(f"[W{wid+1}] {m}"),
                    )
                except Exception:
                    pass
                with stats_lock:
                    shared["success"] += local_success
                    shared["fail"] += local_fail
                    for k, v in local_fail_stats.items():
                        shared["fail_stats"][k] = shared["fail_stats"].get(k, 0) + v

        for wid, n in enumerate(chunks):
            if n <= 0:
                continue
            t = threading.Thread(target=worker, args=(n, wid), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        success_count = shared["success"]
        fail_count = shared["fail"]
        fail_stats = shared["fail_stats"]
        registration_log(
            f"[*] 任务结束。成功 {success_count} | 失败 {fail_count}"
            + (f" | {format_fail_stats(fail_stats)}" if fail_count else "")
        )
        return

    try:
        boot_started_at = time.time()
        try:
            start_browser(log_callback=registration_log)
        except Exception as boot_exc:
            fail_count += count
            fail_stats[FAIL_BROWSER] = fail_stats.get(FAIL_BROWSER, 0) + count
            registration_log(f"[-] 浏览器启动失败，{count} 个任务均记为失败: {boot_exc}")
            for _ in range(max(int(count or 0), 0)):
                _persist_result(
                    started_at=boot_started_at,
                    status="failure",
                    failure_type=FAIL_BROWSER,
                    failure_reason=str(boot_exc),
                    cpa_detail={
                        "enabled": bool(config.get("cpa_auto_add", False)),
                        "status": "not_attempted" if config.get("cpa_auto_add") else "disabled",
                    },
                )
            return
        registration_log("[*] 浏览器已启动")
        i = 0
        while i < count:
            if controller.should_stop():
                break
            registration_log(f"--- 开始第 {i + 1}/{count} 个账号 ---")
            attempt_started_at = time.time()
            email = ""
            profile = {}
            sso = ""
            email_file = ""
            cpa_detail = {
                "enabled": bool(config.get("cpa_auto_add", False)),
                "status": "not_attempted" if config.get("cpa_auto_add") else "disabled",
            }
            nsfw_status = "未执行"
            try:
                dev_token = ""
                code = ""
                mail_ok = False
                max_mail_retry = 3
                for mail_try in range(1, max_mail_retry + 1):
                    mail_attempt_started_at = time.time()
                    registration_log(f"[*] 1. 打开注册页 (尝试 {mail_try}/{max_mail_retry})")
                    open_signup_page(
                        log_callback=registration_log, cancel_callback=controller.should_stop
                    )
                    registration_log("[*] 2. 创建邮箱并提交")
                    email, dev_token, submitted_at = fill_email_and_submit(
                        log_callback=registration_log, cancel_callback=controller.should_stop
                    )
                    registration_log(f"[*] 邮箱: {email}")
                    registration_log(f"[Debug] 邮箱 token 已获取 (len={len(str(dev_token or ''))})")
                    try:
                        with open(
                            accounts_side_file("mail_credentials.txt"),
                            "a",
                            encoding="utf-8",
                        ) as f:
                            f.write(f"{email}\t{dev_token}\n")
                    except Exception:
                        pass
                    registration_log("[*] 3. 拉取验证码")
                    try:
                        code = fill_code_and_submit(
                            email,
                            dev_token,
                            submitted_at=submitted_at,
                            log_callback=registration_log,
                            cancel_callback=controller.should_stop,
                        )
                        mail_ok = True
                        break
                    except Exception as mail_exc:
                        msg = str(mail_exc)
                        if ("未收到验证码" in msg or "验证码" in msg) and mail_try < max_mail_retry:
                            _persist_result(
                                started_at=mail_attempt_started_at,
                                email=email,
                                status="failure",
                                cpa_detail=cpa_detail,
                                failure_type=classify_failure(mail_exc),
                                failure_reason=str(mail_exc),
                                extra={"邮箱已更换重试": True, "邮箱尝试次数": mail_try},
                            )
                            registration_log(f"[!] 本邮箱未取到验证码，自动更换新邮箱重试: {msg}")
                            restart_browser(log_callback=registration_log)
                            sleep_with_cancel(1, controller.should_stop)
                            continue
                        raise

                if not mail_ok:
                    raise Exception("验证码阶段失败，已达到最大重试次数")
                registration_log(f"[*] 验证码: {code}")
                registration_log("[*] 4. 填写资料")
                profile = fill_profile_and_submit(
                    log_callback=registration_log, cancel_callback=controller.should_stop
                )
                registration_log(f"[*] 资料已填: {profile.get('given_name')} {profile.get('family_name')}")
                registration_log("[*] 5. 等待 sso cookie")
                sso = wait_for_sso_cookie(
                    log_callback=registration_log, cancel_callback=controller.should_stop
                )
                ensure_sso_oauth_eligible(sso, email=email, log_callback=registration_log)
                if config.get("enable_nsfw", True):
                    registration_log("[*] 6. 开启 NSFW")
                    nsfw_ok, nsfw_msg = enable_nsfw_for_token(
                        sso, log_callback=registration_log
                    )
                    if nsfw_ok:
                        nsfw_status = "成功"
                        registration_log(f"[+] NSFW 开启成功: {nsfw_msg}")
                    else:
                        nsfw_status = f"失败: {nsfw_msg}"
                        registration_log(f"[!] NSFW 未开启，继续保存账号: {nsfw_msg}")
                else:
                    nsfw_status = "未开启"
                try:
                    line = f"{email}----{profile.get('password','')}----{sso}\n"
                    # 以邮箱命名单独保存
                    email_file = account_file_for_email(email)
                    with open(email_file, "w", encoding="utf-8") as f:
                        f.write(line)
                except Exception as file_exc:
                    registration_log(f"[!] 保存账号文件失败，当前账号不计为成功: {file_exc}")
                    _append_sso_pending(email, sso, log_callback=registration_log)
                    raise RuntimeError(f"保存账号文件失败: {file_exc}") from file_exc
                cpa_ok = add_sso_to_cpa(
                    sso,
                    email=email,
                    log_callback=registration_log,
                    result_out=cpa_detail,
                )
                counted_success = False
                if not registration_counts_as_success(cpa_detail):
                    reason = cpa_failure_reason(cpa_detail)
                    _record_failure(RuntimeError(f"[CPA] {reason}"))
                    retry_count_for_slot = 0
                    i += 1
                    email_disable_detail = (
                        disable_outlookemail_consumed(
                            email,
                            reason=f"CPA失败但已保存SSO: {reason}",
                            log_callback=registration_log
                        )
                        if is_outlookemail_registration()
                        else default_email_disable_detail("", cpa_detail)
                    )
                    _persist_result(
                        started_at=attempt_started_at,
                        email=email,
                        password=current_attempt_password(profile),
                        status="failure",
                        cpa_detail=cpa_detail,
                        email_disable_detail=email_disable_detail,
                        failure_type=FAIL_CPA,
                        failure_reason=reason,
                        account_file=email_file,
                        sso_saved=True,
                        nsfw_status=nsfw_status,
                        extra={"任务序号": i, "并发数": 1},
                    )
                    registration_log(f"[-] 注册未计成功 [CPA失败]: {reason}")
                else:
                    email_disable_detail = (
                        disable_outlookemail_after_cpa_success(
                            email, cpa_detail, log_callback=registration_log
                        )
                        if is_outlookemail_registration()
                        else default_email_disable_detail("", cpa_detail)
                    )
                    success_count += 1
                    counted_success = True
                    retry_count_for_slot = 0
                    i += 1
                    if cpa_ok:
                        registration_log(f"[+] 注册成功: {email}")
                    else:
                        registration_log(f"[+] 注册成功（SSO 已保存，CPA 入库失败）: {email}")
                    _persist_result(
                        started_at=attempt_started_at,
                        email=email,
                        password=current_attempt_password(profile),
                        status="success",
                        cpa_detail=cpa_detail,
                        email_disable_detail=email_disable_detail,
                        account_file=email_file,
                        sso_saved=True,
                        nsfw_status=nsfw_status,
                        extra={"任务序号": i, "并发数": 1},
                    )
                registration_log(f"[*] 当前统计: 成功 {success_count} | 失败 {fail_count}")
                if (
                    counted_success
                    and success_count > 0
                    and success_count % MEMORY_CLEANUP_INTERVAL == 0
                    and i < count
                ):
                    cleanup_runtime_memory(
                        log_callback=registration_log,
                        reason=f"已成功 {success_count} 个账号，执行定期清理",
                    )
            except RegistrationCancelled:
                cancelled_email = current_attempt_email(email)
                if cancelled_email:
                    _persist_result(
                        started_at=attempt_started_at,
                        email=cancelled_email,
                        password=current_attempt_password(profile),
                        status="cancelled",
                        cpa_detail=cpa_detail,
                        failure_reason="用户停止注册",
                        account_file=email_file,
                        sso_saved=bool(email_file),
                        nsfw_status=nsfw_status,
                    )
                registration_log("[!] 注册被停止")
                break
            except EmailDomainRejected as exc:
                kind = _record_failure(exc)
                retry_count_for_slot = 0
                i += 1
                _persist_result(
                    started_at=attempt_started_at,
                    email=current_attempt_email(email, exc),
                    password=current_attempt_password(profile),
                    status="failure",
                    cpa_detail=cpa_detail,
                    failure_type=kind,
                    failure_reason=str(exc),
                    nsfw_status=nsfw_status,
                )
                registration_log(f"[-] 邮箱域名被 xAI 拒绝 [{FAIL_LABELS.get(kind, kind)}]: {exc}")
                registration_log("[!] 请更换邮箱提供商或域名（如 Cloudflare 自建域 / MailNest），公共临时域常被拉黑")
            except AccountRetryNeeded as exc:
                retry_count_for_slot += 1
                if retry_count_for_slot <= max_slot_retry:
                    registration_log(
                        f"[!] 当前账号流程卡住，重试第 {retry_count_for_slot}/{max_slot_retry} 次: {exc}"
                    )
                else:
                    retry_used = retry_count_for_slot
                    kind = _record_failure(exc)
                    retry_count_for_slot = 0
                    i += 1
                    _persist_result(
                        started_at=attempt_started_at,
                        email=current_attempt_email(email, exc),
                        password=current_attempt_password(profile),
                        status="failure",
                        cpa_detail=cpa_detail,
                        failure_type=kind,
                        failure_reason=str(exc),
                        account_file=email_file,
                        sso_saved=bool(email_file),
                        nsfw_status=nsfw_status,
                        extra={"重试次数": retry_used},
                    )
                    registration_log(f"[-] 当前账号已达到最大重试次数，跳过 [{FAIL_LABELS.get(kind, kind)}]: {exc}")
            except Exception as exc:
                kind = _record_failure(exc)
                retry_count_for_slot = 0
                i += 1
                if kind == FAIL_RISK:
                    cpa_detail.update(status="rejected", error=str(exc))
                fail_email = current_attempt_email(email, exc)
                email_disable_detail = None
                if kind == FAIL_ALREADY_REGISTERED and is_outlookemail_registration() and fail_email:
                    registration_log(
                        f"[*] 账号已注册，按自动停用开关处理 Outlook 邮箱: {fail_email}"
                    )
                    email_disable_detail = disable_outlookemail_consumed(
                        fail_email,
                        reason=f"账号已注册: {exc}",
                        log_callback=registration_log
                    )
                    status = str((email_disable_detail or {}).get("status") or "")
                    if status == "success":
                        registration_log(
                            f"[+] 账号已注册：Outlook 邮箱停用完成: {fail_email}"
                        )
                    elif status == "feature_disabled":
                        registration_log(
                            f"[*] 账号已注册：自动停用开关未开启，跳过停用 Outlook: {fail_email}"
                        )
                    elif status == "failed":
                        registration_log(
                            f"[!] 账号已注册：Outlook 邮箱停用失败: {fail_email}"
                            f" — {(email_disable_detail or {}).get('error') or ''}"
                        )
                _persist_result(
                    started_at=attempt_started_at,
                    email=fail_email,
                    password=current_attempt_password(profile),
                    status="failure",
                    cpa_detail=cpa_detail,
                    email_disable_detail=email_disable_detail,
                    failure_type=kind,
                    failure_reason=str(exc),
                    account_file=email_file,
                    sso_saved=bool(email_file) or bool(sso and kind == FAIL_RISK),
                    nsfw_status=nsfw_status,
                )
                registration_log(f"[-] 注册失败 [{FAIL_LABELS.get(kind, kind)}]: {exc}")
            finally:
                if controller.should_stop():
                    break
                # 每轮结束只关浏览器，不立刻再开。
                # 下一轮 open_signup_page 会按需启动并导航到官网，避免空浏览器残留。
                if i >= count:
                    continue
                # 账号间随机间隔
                wait_sec = parse_account_interval()
                if wait_sec > 0:
                    registration_log(f"[*] 下一个账号前等待 {wait_sec:.0f} 秒...")
                    sleep_with_cancel(wait_sec, controller.should_stop)
                try:
                    stop_browser()
                    time.sleep(0.5)
                except RegistrationCancelled:
                    break
                except Exception as close_exc:
                    if controller.should_stop():
                        break
                    registration_log(f"[Debug] 轮次关闭浏览器失败: {close_exc}")
    except RegistrationCancelled:
        registration_log("[!] 注册被停止")
    except Exception as exc:
        registration_log(f"[!] 任务异常: {exc}")
    finally:
        try:
            user_stopped = bool(controller.should_stop())
            if user_stopped:
                maybe_stop_browser(user_stopped=True, log_callback=registration_log)
            else:
                cleanup_runtime_memory(log_callback=registration_log, reason="任务结束")
        except BaseException:
            pass
        try:
            registration_log(
                f"[*] 任务结束。成功 {success_count} | 失败 {fail_count}"
                + (f" | {format_fail_stats(fail_stats)}" if fail_count else "")
            )
        except BaseException:
            pass
