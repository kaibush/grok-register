# -*- coding: utf-8 -*-
"""账号重新登录后台任务。

Web 请求只负责启动任务；浏览器登录、SSO 刷新与授权文件重建在单独线程执行。
"""
from __future__ import annotations

import datetime
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


class ReloginJobCoordinator:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._running = False
        self._account_id = 0
        self._email = ""
        self._stage = "等待启动"
        self._error = ""
        self._started_at: Optional[float] = None
        self._finished_at: Optional[float] = None
        self._total_count = 0
        self._completed_count = 0
        self._success_count = 0
        self._failed_count = 0
        self._thread: Optional[threading.Thread] = None

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "running": self._running,
                "account_id": self._account_id,
                "email": self._email,
                "stage": self._stage,
                "error": self._error,
                "started_at": self._started_at,
                "finished_at": self._finished_at,
                "total_count": self._total_count,
                "completed_count": self._completed_count,
                "success_count": self._success_count,
                "failed_count": self._failed_count,
            }

    def _set(self, **values: Any) -> None:
        with self._lock:
            for key, value in values.items():
                setattr(self, f"_{key}", value)

    def start(self, account_id: int) -> Dict[str, Any]:
        return self.start_many([account_id])

    def start_many(self, account_ids: Iterable[int]) -> Dict[str, Any]:
        from backend.registration import engine as gr

        normalized_ids: List[int] = []
        seen = set()
        for raw_id in account_ids or []:
            try:
                account_id = int(raw_id)
            except (TypeError, ValueError):
                continue
            if account_id <= 0 or account_id in seen:
                continue
            seen.add(account_id)
            normalized_ids.append(account_id)
        if not normalized_ids:
            raise ValueError("请选择要重新登录的账号")
        with self._lock:
            if self._running:
                raise RuntimeError(f"账号 {self._email or self._account_id} 正在重新登录")

        store = gr.get_registration_repository()
        records = store.get_results_by_ids(normalized_ids)
        if not records:
            message = "记录不存在" if len(normalized_ids) == 1 else "没有匹配的记录"
            raise LookupError(message)
        records_by_id = {int(record.get("id") or 0): record for record in records}

        runnable: List[Dict[str, Any]] = []
        validation_errors: List[str] = []
        for account_id in normalized_ids:
            record = records_by_id.get(account_id)
            if record is None:
                validation_errors.append(f"账号 {account_id}: 记录不存在")
                continue
            email = str(record.get("email") or "").strip()
            password = str(record.get("password") or "")
            label = email or f"账号 {account_id}"
            if not email or "@" not in email:
                validation_errors.append(f"{label}: 缺少有效邮箱")
            elif not password:
                validation_errors.append(f"{label}: 没有保存密码")
            else:
                runnable.append(record)
        if not runnable:
            raise ValueError(f"所选账号均无法重新登录：{validation_errors[0]}")

        with self._lock:
            if self._running:
                raise RuntimeError(f"账号 {self._email or self._account_id} 正在重新登录")
            first = runnable[0]
            self._running = True
            self._account_id = int(first.get("id") or 0)
            self._email = str(first.get("email") or "").strip()
            self._stage = "启动浏览器"
            self._error = ""
            self._started_at = time.time()
            self._finished_at = None
            self._total_count = len(normalized_ids)
            self._completed_count = len(validation_errors)
            self._success_count = 0
            self._failed_count = len(validation_errors)

        def runner() -> None:
            errors = list(validation_errors)
            try:
                for record in runnable:
                    error = ""
                    try:
                        self._set(
                            account_id=int(record.get("id") or 0),
                            email=str(record.get("email") or "").strip(),
                            stage="启动浏览器",
                        )
                        error = self._run_record(record, store)
                    except Exception as exc:
                        error = str(exc) or exc.__class__.__name__
                    if error:
                        errors.append(f"{record.get('email') or record.get('id')}: {error}")
                    with self._lock:
                        self._completed_count += 1
                        if error:
                            self._failed_count += 1
                        else:
                            self._success_count += 1
            finally:
                with self._lock:
                    if self._total_count == 1:
                        self._stage = "重新登录失败" if errors else "重新登录完成"
                        self._error = errors[0].split(": ", 1)[-1] if errors else ""
                    else:
                        self._stage = (
                            f"批量重新登录完成（成功 {self._success_count}，失败 {self._failed_count}）"
                        )
                        self._error = f"{self._failed_count} 个账号重新登录失败" if errors else ""
                    self._running = False
                    self._finished_at = time.time()

        self._thread = threading.Thread(
            target=runner,
            name=f"account-relogin-{self._account_id}",
            daemon=True,
        )
        try:
            self._thread.start()
        except Exception as exc:
            self._set(running=False, error=str(exc), finished_at=time.time())
            raise
        return self.status()

    def _run_record(self, record: Dict[str, Any], store: Any) -> str:
        from backend.automation.session import stop_browser
        from backend.registration import engine as gr
        from backend.registration.login_flow import capture_login_failure, login_with_password

        account_id = int(record.get("id") or 0)
        email = str(record.get("email") or "").strip()
        password = str(record.get("password") or "")
        cpa_detail: Dict[str, Any] = {}
        account_file = ""

        def log(message: str) -> None:
            text = str(message or "")
            if "打开重新登录页" in text:
                self._set(stage="填写邮箱和密码")
            elif "等待 sso" in text:
                self._set(stage="等待新的 SSO")
            elif "[CPA]" in text:
                self._set(stage="重建授权文件")

        try:
            gr.load_config()
            gr._wire_runtime_modules()
            gr._bs.allow_browser_launches()
            sso = login_with_password(email, password, timeout=100, log_callback=log)

            self._set(stage="保存账号文件")
            account_path = Path(gr.account_file_for_email(email))
            account_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = account_path.with_name(f".{account_path.name}.{uuid.uuid4().hex}.tmp")
            temporary.write_text(f"{email}----{password}----{sso}\n", encoding="utf-8")
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
            os.replace(temporary, account_path)
            account_file = str(account_path)

            self._set(stage="重建 CPA / Grok2API 文件")
            cpa_ok = gr.add_sso_to_cpa(
                sso,
                email=email,
                log_callback=log,
                result_out=cpa_detail,
            )
            cpa_success = cpa_ok and str(cpa_detail.get("status") or "") == "success"
            if not cpa_success:
                raise RuntimeError(str(cpa_detail.get("error") or "授权文件重建未完成"))
            store.update_relogin_result(
                account_id,
                account_file=account_file,
                cpa_detail=cpa_detail,
                status="success",
                error="",
            )
            return ""
        except Exception as exc:
            error = str(exc) or exc.__class__.__name__
            stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            safe_email = email.replace("/", "_").replace("\\", "_")
            try:
                screenshot_path = capture_login_failure(
                    Path(gr.DATA_DIR)
                    / "screenshots"
                    / "relogin-failures"
                    / f"relogin-{account_id}-{safe_email}-{stamp}.png"
                )
            except Exception:
                screenshot_path = ""
            store.update_relogin_result(
                account_id,
                account_file=account_file,
                cpa_detail=cpa_detail,
                status="partial" if account_file else "failed",
                error=error,
                screenshot_path=screenshot_path,
            )
            return error
        finally:
            try:
                stop_browser(force=True)
            except BaseException:
                pass


relogin_coordinator = ReloginJobCoordinator()
