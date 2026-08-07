# -*- coding: utf-8 -*-
"""浏览器运行时管理。

隔离每个工作线程的浏览器与页面对象，并统一处理启动、重启、进程回收和临时
profile 清理。
"""
from __future__ import annotations

import gc
import os
import signal
import shutil
import tempfile
import threading
import time
import uuid
from typing import Callable, Optional, Tuple
from urllib.parse import urlparse

import asyncio
from greenlet import greenlet
from typing import cast as _tcast

from camoufox.sync_api import Camoufox as _Camoufox, NewBrowser
from playwright._impl._connection import Connection as _PwConnection
from playwright._impl._greenlets import MainGreenlet as _PwMainGreenlet
from playwright._impl._object_factory import create_remote_object as _pw_create_remote
from playwright._impl._playwright import Playwright as _PwImpl
from playwright._impl._transport import PipeTransport as _PwPipeTransport
from playwright.sync_api._generated import Playwright as _SyncPlaywright

from backend.automation.page_adapter import CamoufoxBrowser, CamoufoxPage


class IsolatedCamoufox(_Camoufox):
    """Camoufox 子类，绕过 PlaywrightContextManager 的事件循环检查。

    PlaywrightContextManager.__enter__() 调用 asyncio.get_running_loop()，
    如果当前线程有运行中的 asyncio 事件循环（如其他库遗留），
    就会报错 "Sync API inside the asyncio loop"。

    此子类直接创建全新的、非运行状态的事件循环，完全绕过该检查。
    通过重写 __enter__()，跳过 get_running_loop() / is_running() 判断，
    直接用 asyncio.new_event_loop() 创建干净的事件循环。
    """

    def __enter__(self):
        # 强制创建全新的事件循环，跳过 get_running_loop() / is_running() 检查
        self._loop = asyncio.new_event_loop()
        self._own_loop = True

        # 复制 PlaywrightContextManager.__enter__() 的 greenlet 调度逻辑
        def _greenlet_main():
            self._loop.run_until_complete(self._connection.run_as_sync())

        dispatcher_fiber = _PwMainGreenlet(_greenlet_main)

        self._connection = _PwConnection(
            dispatcher_fiber,
            _pw_create_remote,
            _PwPipeTransport(self._loop),
            self._loop,
        )

        g_self = greenlet.getcurrent()

        def _callback_wrapper(channel_owner):
            playwright_impl = _tcast(_PwImpl, channel_owner)
            self._playwright = _SyncPlaywright(playwright_impl)
            g_self.switch()

        self._connection.call_on_object_with_known_name("Playwright", _callback_wrapper)
        dispatcher_fiber.switch()

        playwright = self._playwright
        playwright.stop = self.__exit__

        # Camoufox 特有：启动浏览器
        try:
            self.browser = NewBrowser(self._playwright, **self.launch_options)
        except BaseException as e:
            super().__exit__(type(e), e, e.__traceback__)
            raise
        return self.browser


# 仅允许删除该目录树下的临时 profile，防止误删其它路径
_PROFILE_ROOT_MARKER = "grok-register-camoufox"

_tls = threading.local()
_get_proxy: Optional[Callable[[], dict]] = None
_is_debug: Optional[Callable[[], bool]] = None
_is_headless: Optional[Callable[[], bool]] = None
_get_locale: Optional[Callable[[], str]] = None
_extension_path: str = ""
_start_fail_lock = threading.Lock()
_start_fail_streak = 0
_start_fail_threshold = 3
_browser_launch_blocked = threading.Event()


def configure(get_proxies=None, is_debug=None, is_headless=None, get_locale=None, extension_path=""):
    global _get_proxy, _is_debug, _is_headless, _get_locale, _extension_path
    _get_proxy = get_proxies
    _is_debug = is_debug
    _is_headless = is_headless
    _get_locale = get_locale
    _extension_path = extension_path or ""


def get_start_fail_streak() -> int:
    with _start_fail_lock:
        return _start_fail_streak


def _note_start_success():
    global _start_fail_streak
    with _start_fail_lock:
        _start_fail_streak = 0


def _note_start_failure():
    global _start_fail_streak
    with _start_fail_lock:
        _start_fail_streak += 1
        return _start_fail_streak


def _proxies() -> dict:
    if _get_proxy:
        return _get_proxy() or {}
    return {}


def _browser_locale() -> str:
    value = str(_get_locale() if _get_locale else "en-US").strip()
    return value if value in {"en-US", "zh-CN"} else "en-US"


def _debug() -> bool:
    return bool(_is_debug()) if _is_debug else False


def _headless() -> bool:
    return bool(_is_headless()) if _is_headless else False


def allow_browser_launches() -> None:
    _browser_launch_blocked.clear()


def block_browser_launches() -> None:
    _browser_launch_blocked.set()


def active_browser():
    return getattr(_tls, "browser", None)


def active_page():
    return getattr(_tls, "page", None)


def set_browser_session(browser_obj=None, page_obj=None):
    _tls.browser = browser_obj
    _tls.page = page_obj


class _SessionProxy:
    __slots__ = ("_key",)

    def __init__(self, key):
        self._key = key

    def _obj(self):
        return getattr(_tls, self._key, None)

    def __bool__(self):
        return self._obj() is not None

    def __eq__(self, other):
        return self._obj() is other

    def __ne__(self, other):
        return self._obj() is not other

    def __getattr__(self, name):
        obj = self._obj()
        if obj is None:
            raise AttributeError(f"{self._key} is not started")
        return getattr(obj, name)


browser = _SessionProxy("browser")
page = _SessionProxy("page")


def _is_managed_profile_dir(path: str) -> bool:
    """是否为本工具创建的临时 Camoufox 资料目录。"""
    if not path:
        return False
    norm = os.path.normpath(path).replace("\\", "/").lower()
    marker = _PROFILE_ROOT_MARKER.lower()
    return f"/{marker}/" in f"/{norm}/" or norm.rstrip("/").endswith(f"/{marker}")


def _rmtree_with_retry(path: str, max_retries: int = 3, delay: float = 0.5) -> bool:
    """Windows 上文件锁可能导致 rmtree 失败，带重试。

    返回 True 表示最终删除成功。
    """
    for attempt in range(max_retries):
        try:
            shutil.rmtree(path, ignore_errors=False)
            return True
        except Exception:
            if attempt < max_retries - 1:
                time.sleep(delay * (attempt + 1))
            # 最后一次尝试：强制忽略错误
            try:
                shutil.rmtree(path, ignore_errors=True)
                return not os.path.isdir(path)
            except Exception:
                return False
    return not os.path.isdir(path)


def _cleanup_profile_dir(profile_dir=None) -> None:
    """关闭浏览器后删除临时 user-data，避免 TEMP 堆积。"""
    path = profile_dir if profile_dir is not None else getattr(_tls, "profile_dir", None)
    try:
        if getattr(_tls, "profile_dir", None) and (
            profile_dir is None
            or os.path.normpath(str(getattr(_tls, "profile_dir")))
            == os.path.normpath(str(path or ""))
        ):
            _tls.profile_dir = None
    except Exception:
        pass
    if not path or not _is_managed_profile_dir(str(path)):
        return
    if os.path.isdir(path):
        _rmtree_with_retry(path)


def cleanup_stale_profiles(log_callback=None) -> int:
    """启动时清理上次崩溃 / 强杀残留的临时 profile 目录。

    扫描 TEMP/grok-register-camoufox/ 下的子目录，
    删除所有未被当前进程占用的旧目录。
    返回清理的目录数量。
    """
    root = os.path.join(tempfile.gettempdir(), _PROFILE_ROOT_MARKER)
    if not os.path.isdir(root):
        return 0

    current_pid = os.getpid()
    cleaned = 0
    try:
        for entry in os.listdir(root):
            entry_path = os.path.join(root, entry)
            if not os.path.isdir(entry_path):
                continue
            # 目录名格式: {pid}-{thread_id}-{uuid8}
            # 只跳过当前进程的活跃目录
            if entry.startswith(f"{current_pid}-"):
                continue
            if _rmtree_with_retry(entry_path):
                cleaned += 1
    except Exception:
        pass

    # 如果 root 目录已空，顺便删掉
    if cleaned > 0:
        try:
            remaining = os.listdir(root)
            if not remaining:
                shutil.rmtree(root, ignore_errors=True)
        except Exception:
            pass

    if cleaned > 0 and log_callback:
        log_callback(f"[*] 启动清理: 已删除 {cleaned} 个残留浏览器资料目录")
    return cleaned


def _is_camoufox_process(executable: str, command_line: str) -> bool:
    """Match Camoufox browser processes without touching regular Firefox."""
    exe = os.path.normpath(str(executable or "")).replace("\\", "/").lower()
    command = str(command_line or "").replace("\\", "/").lower()
    basename = os.path.basename(exe)
    if basename in {"camoufox", "camoufox-bin", "camoufox.exe"}:
        return True
    return "/camoufox/" in exe or _PROFILE_ROOT_MARKER.lower() in command


def _linux_processes() -> dict[int, tuple[int, str, str]]:
    processes: dict[int, tuple[int, str, str]] = {}
    proc_root = "/proc"
    if not os.path.isdir(proc_root):
        return processes
    for entry in os.listdir(proc_root):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open(os.path.join(proc_root, entry, "stat"), "r", encoding="utf-8") as handle:
                stat = handle.read()
            closing = stat.rfind(")")
            ppid = int(stat[closing + 2 :].split()[1])
            executable = os.readlink(os.path.join(proc_root, entry, "exe"))
            with open(os.path.join(proc_root, entry, "cmdline"), "rb") as handle:
                raw = handle.read()
            command = raw.replace(b"\0", b" ").decode("utf-8", errors="replace")
            processes[pid] = (ppid, executable, command)
        except (FileNotFoundError, PermissionError, ProcessLookupError, OSError, ValueError):
            continue
    return processes


def _cleanup_all_managed_profiles() -> int:
    root = os.path.join(tempfile.gettempdir(), _PROFILE_ROOT_MARKER)
    if not os.path.isdir(root):
        return 0
    cleaned = 0
    for entry in list(os.listdir(root)):
        path = os.path.join(root, entry)
        if os.path.isdir(path) and _rmtree_with_retry(path):
            cleaned += 1
    try:
        if not os.listdir(root):
            os.rmdir(root)
    except OSError:
        pass
    return cleaned


def kill_all_camoufox_processes(log_callback=None) -> dict:
    """Terminate every Camoufox process tree and remove managed profiles."""
    block_browser_launches()
    if os.name != "posix" or not os.path.isdir("/proc"):
        raise RuntimeError("当前系统暂不支持批量终止 Camoufox")

    processes = _linux_processes()
    current_pid = os.getpid()
    targets = {
        pid
        for pid, (_, executable, command) in processes.items()
        if pid != current_pid and _is_camoufox_process(executable, command)
    }

    # Include helper/content descendants even if their executable name differs.
    changed = True
    while changed:
        changed = False
        for pid, (ppid, _, _) in processes.items():
            if pid != current_pid and ppid in targets and pid not in targets:
                targets.add(pid)
                changed = True

    attempted = set()
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid in sorted(targets, reverse=True):
            try:
                os.kill(pid, sig)
                attempted.add(pid)
            except ProcessLookupError:
                pass
            except PermissionError as exc:
                raise RuntimeError(f"没有权限终止 Camoufox 进程 {pid}") from exc
        if sig == signal.SIGTERM and targets:
            time.sleep(0.8)

    cleaned_profiles = _cleanup_all_managed_profiles()
    result = {"killed": len(attempted), "profiles_cleaned": cleaned_profiles}
    if log_callback:
        log_callback(
            f"[!] 已终止 {result['killed']} 个 Camoufox 进程，清理 {cleaned_profiles} 个资料目录"
        )
    return result


def _build_camoufox_proxy(proxy_str: str) -> dict:
    """把 http://host:port 格式的代理 URL 转换为 Camoufox/Playwright proxy dict。"""
    proxy_str = proxy_str.strip()
    if not proxy_str:
        return {}
    parsed = urlparse(proxy_str)
    if parsed.scheme and parsed.hostname:
        server = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            server += f":{parsed.port}"
    else:
        server = proxy_str
    result: dict = {"server": server}
    if parsed.username:
        result["username"] = parsed.username
    if parsed.password:
        result["password"] = parsed.password
    return result


def _detect_camoufox_exe() -> str:
    """检测 Camoufox 可执行文件路径，支持新旧两种安装格式。

    新格式（multiversion）：browsers/{repo}/{version}/camoufox.exe + .0.5_FLAG
    旧格式（legacy）：直接在 INSTALL_DIR 下，无 .0.5_FLAG

    旧格式下 installed_verstr() 会报错 "official/stable is not installed"，
    需要传 executable_path + ff_version 绕过该检查。
    """
    import json as _json
    from camoufox.pkgman import INSTALL_DIR, LAUNCH_FILE, OS_NAME

    exe_name = LAUNCH_FILE.get(OS_NAME, "camoufox.exe")
    compat_flag = INSTALL_DIR / ".0.5_FLAG"

    # 新格式：COMPAT_FLAG 存在，让 launch_options() 自行处理
    if compat_flag.exists():
        return ""

    # 旧格式：直接在 INSTALL_DIR 下查找
    legacy_exe = INSTALL_DIR / exe_name
    if legacy_exe.exists():
        return str(legacy_exe)

    return ""


def _detect_ff_version() -> str:
    """从 version.json 读取 Firefox 主版本号（如 "152"）。

    旧格式安装的 version.json 格式：{"version": "152.0.4", "release": "beta.28"}
    新格式还包含 "build" 字段。
    """
    import json as _json
    from camoufox.pkgman import INSTALL_DIR

    version_file = INSTALL_DIR / "version.json"
    if not version_file.exists():
        # 检查 browsers/ 子目录
        browsers_dir = INSTALL_DIR / "browsers"
        if browsers_dir.exists():
            for vf in browsers_dir.rglob("version.json"):
                version_file = vf
                break
    if not version_file.exists():
        return ""

    try:
        data = _json.loads(version_file.read_bytes())
        version_str = str(data.get("version", ""))
        major = version_str.split(".")[0]
        return major if major.isdigit() else ""
    except Exception:
        return ""



def _is_valid_firefox_addon(path: str) -> bool:
    """Camoufox 要求 addon 为已解压目录，且根目录含 manifest.json。"""
    root = str(path or "").strip()
    if not root or not os.path.isdir(root):
        return False
    return os.path.isfile(os.path.join(root, "manifest.json"))


def _ensure_default_addons_or_exclude():
    """默认会加载 uBlock。若缓存目录损坏（缺 manifest），自动排除以免启动失败。"""
    try:
        from camoufox.addons import DefaultAddons, get_addon_path
    except Exception:
        return []
    exclude = []
    for addon in DefaultAddons:
        addon_path = get_addon_path(addon.name)
        if os.path.exists(addon_path) and not _is_valid_firefox_addon(addon_path):
            # 半下载/损坏目录：删掉，让 camoufox 下次可重下；本次先 exclude
            try:
                shutil.rmtree(addon_path, ignore_errors=True)
            except Exception:
                pass
            exclude.append(addon)
    return exclude


def create_browser_options(unique_profile=True) -> dict:
    """构建 Camoufox 启动参数 dict。

    返回可直接传给 Camoufox(**opts) 的参数字典。
    替代原 DrissionPage 的 ChromiumOptions。

    浏览器策略：
    - headless：由 Web 设置控制，默认使用有头模式
    - humanize=True：人类化鼠标移动 + 点击轨迹
    - geoip=True：基于代理 IP 匹配时区 / 经纬度
    - locale：固定为英文或简体中文，避免代理出口改变页面语言
    - block_webrtc=True：WebRTC IP 泄漏防护（避免真实 IP 通过 STUN 暴露）
    - 指纹由 BrowserForge 自动生成（匹配 Firefox/Camoufox 引擎）
    """
    headless = _headless()
    opts: dict = {
        "headless": headless,
        "humanize": True,       # 人类化鼠标移动 + 贝塞尔轨迹
        "geoip": True,          # 基于 IP 匹配时区 / 经纬度；语言由 locale 单独固定
        "locale": _browser_locale(),  # 覆盖 GeoIP 语言，保持页面元素文本稳定
        "block_webrtc": True,   # 防止 WebRTC 泄漏真实 IP（即使使用代理）
        "i_know_what_im_doing": True,  # 抑制 Firefox 版本伪装警告（Camoufox 引擎层伪装是预期行为）
    }

    # 旧格式安装兼容：传 executable_path 绕过 installed_verstr() 检查
    # 注意：不传 ff_version，让 Camoufox 自动检测版本号
    # 传 ff_version 会导致指纹中版本号与引擎不匹配，Turnstile 检测到不一致会拒绝通过
    # 前提：config.json 中已设置 active_version="." 让 installed_verstr() 正常工作
    exe_path = _detect_camoufox_exe()
    if exe_path:
        opts["executable_path"] = exe_path

    # 代理
    proxies = _proxies()
    proxy = str(proxies.get("https") or proxies.get("http") or "").strip()
    if proxy:
        opts["proxy"] = _build_camoufox_proxy(proxy)

    # 扩展（Camoufox 使用 addons 参数，加载已解压的 Firefox 扩展目录）
    # 默认会附带 uBlock；若缓存损坏则自动 exclude，避免 manifest.json missing。
    exclude_addons = _ensure_default_addons_or_exclude()
    if exclude_addons:
        opts["exclude_addons"] = exclude_addons
    if _extension_path:
        if _is_valid_firefox_addon(_extension_path):
            opts["addons"] = [_extension_path]
        # 无效路径直接忽略，不阻断浏览器启动

    # Profile 隔离
    if unique_profile:
        profile_dir = os.path.join(
            tempfile.gettempdir(),
            _PROFILE_ROOT_MARKER,
            f"{os.getpid()}-{threading.get_ident()}-{uuid.uuid4().hex[:8]}",
        )
        os.makedirs(profile_dir, exist_ok=True)
        opts["persistent_context"] = True
        opts["user_data_dir"] = profile_dir
        _tls.profile_dir = profile_dir

    return opts


def start_browser(log_callback=None) -> Tuple[object, object]:
    """启动 Camoufox 浏览器，返回 (CamoufoxBrowser, CamoufoxPage)。

    使用 Camoufox C++ 引擎层指纹伪装：
    - 从编译层修改 Gecko，JS 完全不可检测
    - 内置 BrowserForge 指纹生成器
    - GeoIP 自动匹配时区 / 语言
    - 人类化鼠标轨迹
    """
    last_exc = None
    for attempt in range(1, 5):
        if _browser_launch_blocked.is_set():
            raise RuntimeError("Camoufox 启动已被紧急终止操作阻止")
        profile_dir = None
        try:
            opts = create_browser_options(unique_profile=True)
            profile_dir = getattr(_tls, "profile_dir", None)

            # IsolatedCamoufox.__enter__() 直接创建全新事件循环，
            # 完全绕过 PlaywrightContextManager 的 get_running_loop() 检查
            camoufox = IsolatedCamoufox(**opts)
            browser_context = camoufox.__enter__()

            # 获取或创建页面
            raw_pages = (
                browser_context.pages
                if hasattr(browser_context, "pages")
                else []
            )
            if raw_pages:
                raw_page = raw_pages[0]
            else:
                raw_page = browser_context.new_page()

            page_obj = CamoufoxPage(raw_page, browser_context)
            browser_obj = CamoufoxBrowser(
                browser=None,
                context=browser_context,
                camoufox_instance=camoufox,
            )
            browser_obj.user_data_path = profile_dir or ""

            set_browser_session(browser_obj, page_obj)
            _note_start_success()

            if log_callback:
                log_callback(f"[*] 浏览器模式: {'无头' if opts['headless'] else '有头'}")
                log_callback(f"[*] 浏览器语言: {opts['locale']}")
                proxy_options = opts.get("proxy") if isinstance(opts.get("proxy"), dict) else {}
                proxy_server = str(proxy_options.get("server") or "").strip()
                log_callback(
                    f"[*] Camoufox 网络: {'代理 ' + proxy_server if proxy_server else '直连（未配置代理）'}"
                )
            if log_callback and profile_dir:
                log_callback(f"[Debug] 当前浏览器资料目录: {profile_dir}")
            if log_callback and attempt > 1:
                log_callback(f"[*] 浏览器第 {attempt} 次启动成功")
            return browser_obj, page_obj
        except Exception as exc:
            last_exc = exc
            streak = _note_start_failure()
            if log_callback:
                log_callback(
                    f"[Debug] 浏览器启动失败(第{attempt}/4次, 连续失败{streak}): {exc}"
                )
            profile_dir = profile_dir or getattr(_tls, "profile_dir", None)
            try:
                cur = active_browser()
                if cur is not None:
                    cur.quit(del_data=True)
            except Exception:
                pass
            set_browser_session(None, None)
            _cleanup_profile_dir(profile_dir)
            time.sleep(min(1.5 * attempt, 4))
    raise Exception(f"浏览器启动失败，已重试4次: {last_exc}")


def stop_browser(force=False):
    if _debug() and not force:
        return
    current = active_browser()
    profile_dir = getattr(_tls, "profile_dir", None)
    set_browser_session(None, None)
    if current is None:
        _cleanup_profile_dir(profile_dir)
        return
    try:
        current.quit(del_data=True)
    except BaseException:
        pass
    _cleanup_profile_dir(profile_dir)


def restart_browser(log_callback=None):
    stop_browser(force=True)
    return start_browser(log_callback=log_callback)


def cleanup_runtime_memory(log_callback=None, reason="定期清理"):
    try:
        if _debug():
            if log_callback:
                log_callback(f"[*] 调试模式：保留浏览器（{reason}）")
            collected = gc.collect()
            if log_callback:
                log_callback(f"[*] Python GC 已回收对象数: {collected}")
            return
        if log_callback:
            log_callback(f"[*] {reason}: 关闭浏览器并清理内存")
        stop_browser(force=True)
        collected = gc.collect()
        if log_callback:
            log_callback(f"[*] Python GC 已回收对象数: {collected}")
    except BaseException:
        try:
            if not _debug():
                stop_browser(force=True)
        except BaseException:
            pass


def refresh_active_page():
    if active_browser() is None:
        restart_browser()
    try:
        browser_obj = active_browser()
        tabs = browser_obj.get_tabs()
        page_obj = tabs[-1] if tabs else browser_obj.new_tab()
        set_browser_session(browser_obj, page_obj)
    except Exception:
        restart_browser()
    return page


def extract_cf_clearance_and_ua(log_callback=None, ensure_grok=True):
    """提取 grok.com 域 cf_clearance + UA。"""
    cf_clearance = ""
    user_agent = ""
    try:
        active = refresh_active_page()
        if active is None:
            return "", ""

        def _read_cf_and_ua(page_obj, grok_only=False):
            clearance = ""
            ua_text = ""
            cookies = page_obj.cookies(all_domains=True, all_info=True) or []
            for item in cookies:
                if isinstance(item, dict):
                    name = str(item.get("name", "")).strip()
                    value = str(item.get("value", "")).strip()
                    domain = str(item.get("domain", "")).strip().lower()
                else:
                    name = str(getattr(item, "name", "")).strip()
                    value = str(getattr(item, "value", "")).strip()
                    domain = str(getattr(item, "domain", "")).strip().lower()
                if name != "cf_clearance" or not value:
                    continue
                if grok_only and "grok.com" not in domain:
                    continue
                if "grok.com" in domain:
                    clearance = value
                    break
                if not clearance and not grok_only:
                    clearance = value
            try:
                ua = page_obj.run_js("return navigator.userAgent;")
                if ua:
                    ua_text = str(ua).strip()
            except Exception:
                pass
            return clearance, ua_text

        def _page_passed_cf(page_obj):
            try:
                title = str(
                    page_obj.run_js("return document.title || '';") or ""
                ).lower()
                body = str(
                    page_obj.run_js(
                        "return (document.body && (document.body.innerText||'')) || '';"
                    )
                    or ""
                ).lower()
                if "just a moment" in title or "just a moment" in body[:200]:
                    return False
                if "checking your browser" in body[:300]:
                    return False
                return True
            except Exception:
                return False

        cf_clearance, user_agent = _read_cf_and_ua(active, grok_only=True)
        if ensure_grok and not cf_clearance:
            if log_callback:
                log_callback("[*] 未找到 grok.com 的 cf_clearance，打开 grok.com 过盾...")
            try:
                active.get("https://grok.com/")
                try:
                    active.wait.doc_loaded()
                except Exception:
                    pass
                time.sleep(2)
                for _ in range(20):
                    if _page_passed_cf(active):
                        cf_clearance, user_agent = _read_cf_and_ua(
                            active, grok_only=True
                        )
                        if cf_clearance:
                            break
                    time.sleep(1.0)
                if log_callback:
                    if cf_clearance:
                        log_callback("[*] 已取得 grok.com 的 cf_clearance")
                    else:
                        log_callback(
                            "[!] 打开 grok.com 后仍无有效 cf_clearance"
                            "（页面可能仍卡在 Just a moment）"
                        )
            except Exception as nav_exc:
                if log_callback:
                    log_callback(f"[Debug] 打开 grok.com 取 cf_clearance 失败: {nav_exc}")
                cf_clearance, user_agent = _read_cf_and_ua(active, grok_only=True)
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] 提取 cf_clearance 失败: {exc}")
    return cf_clearance, user_agent
