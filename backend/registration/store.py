# -*- coding: utf-8 -*-
"""注册结果仓储。

使用 SQLite WAL 保存任务结果和邮箱停用状态；每次操作建立独立连接以适配后台
线程并发。
"""
from __future__ import annotations

import datetime as _datetime
import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple


RESULT_COLUMNS = (
    "source_key",
    "batch_id",
    "source",
    "started_at",
    "finished_at",
    "duration_seconds",
    "email",
    "password",
    "status",
    "success",
    "provider",
    "worker_id",
    "cpa_enabled",
    "cpa_status",
    "auth_info",
    "auth_path",
    "cpa_auth_path",
    "grok2api_auth_path",
    "cpa_remote_status",
    "cpa_remote_imported_at",
    "cpa_remote_error",
    "grok2api_remote_status",
    "grok2api_remote_imported_at",
    "grok2api_remote_error",
    "email_account_id",
    "email_disable_status",
    "email_disabled_at",
    "email_disable_error",
    "failure_type",
    "failure_reason",
    "screenshot_path",
    "account_file",
    "sso_saved",
    "nsfw_status",
    "extra_json",
)

SQLITE_IN_BATCH_SIZE = 900


class RegistrationRepository:
    def __init__(self, database_path: os.PathLike[str] | str):
        self.database_path = os.path.abspath(os.fspath(database_path))
        os.makedirs(os.path.dirname(self.database_path), exist_ok=True)
        self._initialize()

    @staticmethod
    def now_text() -> str:
        return _datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.database_path, timeout=15.0)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=15000")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS registration_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_key TEXT UNIQUE,
                    batch_id TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT 'web',
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    duration_seconds REAL NOT NULL DEFAULT 0,
                    email TEXT NOT NULL DEFAULT '',
                    password TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'failure',
                    success INTEGER NOT NULL DEFAULT 0,
                    provider TEXT NOT NULL DEFAULT '',
                    worker_id INTEGER NOT NULL DEFAULT 0,
                    cpa_enabled INTEGER NOT NULL DEFAULT 0,
                    cpa_status TEXT NOT NULL DEFAULT 'disabled',
                    auth_info TEXT NOT NULL DEFAULT '',
                    auth_path TEXT NOT NULL DEFAULT '',
                    cpa_auth_path TEXT NOT NULL DEFAULT '',
                    grok2api_auth_path TEXT NOT NULL DEFAULT '',
                    cpa_remote_status TEXT NOT NULL DEFAULT 'not_configured',
                    cpa_remote_imported_at TEXT NOT NULL DEFAULT '',
                    cpa_remote_error TEXT NOT NULL DEFAULT '',
                    grok2api_remote_status TEXT NOT NULL DEFAULT 'not_configured',
                    grok2api_remote_imported_at TEXT NOT NULL DEFAULT '',
                    grok2api_remote_error TEXT NOT NULL DEFAULT '',
                    email_account_id TEXT NOT NULL DEFAULT '',
                    email_disable_status TEXT NOT NULL DEFAULT 'not_attempted',
                    email_disabled_at TEXT NOT NULL DEFAULT '',
                    email_disable_error TEXT NOT NULL DEFAULT '',
                    failure_type TEXT NOT NULL DEFAULT '',
                    failure_reason TEXT NOT NULL DEFAULT '',
                    screenshot_path TEXT NOT NULL DEFAULT '',
                    account_file TEXT NOT NULL DEFAULT '',
                    sso_saved INTEGER NOT NULL DEFAULT 0,
                    nsfw_status TEXT NOT NULL DEFAULT '',
                    extra_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_registration_results_finished
                    ON registration_results(finished_at DESC);
                CREATE INDEX IF NOT EXISTS idx_registration_results_email_success
                    ON registration_results(email COLLATE NOCASE, success);
                CREATE INDEX IF NOT EXISTS idx_registration_results_status
                    ON registration_results(status);
                CREATE INDEX IF NOT EXISTS idx_registration_results_batch
                    ON registration_results(batch_id);
                """
            )
            existing_columns = {
                str(row["name"])
                for row in conn.execute("PRAGMA table_info(registration_results)").fetchall()
            }
            migrations = {
                "cpa_auth_path": "TEXT NOT NULL DEFAULT ''",
                "grok2api_auth_path": "TEXT NOT NULL DEFAULT ''",
                "email_account_id": "TEXT NOT NULL DEFAULT ''",
                "email_disable_status": "TEXT NOT NULL DEFAULT 'not_attempted'",
                "email_disabled_at": "TEXT NOT NULL DEFAULT ''",
                "email_disable_error": "TEXT NOT NULL DEFAULT ''",
                "screenshot_path": "TEXT NOT NULL DEFAULT ''",
                "cpa_remote_status": "TEXT NOT NULL DEFAULT 'not_configured'",
                "cpa_remote_imported_at": "TEXT NOT NULL DEFAULT ''",
                "cpa_remote_error": "TEXT NOT NULL DEFAULT ''",
                "grok2api_remote_status": "TEXT NOT NULL DEFAULT 'not_configured'",
                "grok2api_remote_imported_at": "TEXT NOT NULL DEFAULT ''",
                "grok2api_remote_error": "TEXT NOT NULL DEFAULT ''",
            }
            for column, definition in migrations.items():
                if column not in existing_columns:
                    conn.execute(
                        f"ALTER TABLE registration_results ADD COLUMN {column} {definition}"
                    )
            conn.execute(
                """
                UPDATE registration_results
                SET email_disable_status = 'not_applicable'
                WHERE lower(provider) != 'outlookemail'
                  AND email_disable_status = 'not_attempted'
                """
            )
            conn.execute(
                """
                UPDATE registration_results
                SET cpa_remote_status = 'success'
                WHERE cpa_remote_status = 'not_configured'
                  AND auth_info LIKE '%CPA 远程:%'
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_registration_results_email_disable_status
                ON registration_results(email_disable_status)
                """
            )
            conn.execute("PRAGMA user_version = 4")

    def add_result(self, record: Dict[str, Any]) -> int:
        now = self.now_text()
        status = str(record.get("status") or "failure").strip().lower()
        success = 1 if status == "success" or bool(record.get("success")) else 0
        extra = record.get("extra_json", record.get("extra", {}))
        if isinstance(extra, str):
            extra_json = extra
        else:
            extra_json = json.dumps(extra or {}, ensure_ascii=False, sort_keys=True)

        normalized = {
            "source_key": record.get("source_key") or None,
            "batch_id": str(record.get("batch_id") or ""),
            "source": str(record.get("source") or "web"),
            "started_at": str(record.get("started_at") or now),
            "finished_at": str(record.get("finished_at") or now),
            "duration_seconds": max(float(record.get("duration_seconds") or 0), 0.0),
            "email": str(record.get("email") or "").strip(),
            "password": str(record.get("password") or ""),
            "status": status,
            "success": success,
            "provider": str(record.get("provider") or ""),
            "worker_id": int(record.get("worker_id") or 0),
            "cpa_enabled": 1 if bool(record.get("cpa_enabled")) else 0,
            "cpa_status": str(record.get("cpa_status") or "disabled"),
            "auth_info": str(record.get("auth_info") or ""),
            "auth_path": str(record.get("auth_path") or ""),
            "cpa_auth_path": str(record.get("cpa_auth_path") or ""),
            "grok2api_auth_path": str(record.get("grok2api_auth_path") or ""),
            "cpa_remote_status": str(record.get("cpa_remote_status") or "not_configured"),
            "cpa_remote_imported_at": str(record.get("cpa_remote_imported_at") or ""),
            "cpa_remote_error": str(record.get("cpa_remote_error") or ""),
            "grok2api_remote_status": str(
                record.get("grok2api_remote_status") or "not_configured"
            ),
            "grok2api_remote_imported_at": str(
                record.get("grok2api_remote_imported_at") or ""
            ),
            "grok2api_remote_error": str(record.get("grok2api_remote_error") or ""),
            "email_account_id": str(record.get("email_account_id") or ""),
            "email_disable_status": str(
                record.get("email_disable_status") or "not_attempted"
            ).strip().lower(),
            "email_disabled_at": str(record.get("email_disabled_at") or ""),
            "email_disable_error": str(record.get("email_disable_error") or ""),
            "failure_type": str(record.get("failure_type") or ""),
            "failure_reason": str(record.get("failure_reason") or ""),
            "screenshot_path": str(record.get("screenshot_path") or ""),
            "account_file": str(record.get("account_file") or ""),
            "sso_saved": 1 if bool(record.get("sso_saved")) else 0,
            "nsfw_status": str(record.get("nsfw_status") or ""),
            "extra_json": extra_json,
        }
        columns = ", ".join(RESULT_COLUMNS)
        placeholders = ", ".join(f":{name}" for name in RESULT_COLUMNS)
        with self._connect() as conn:
            cursor = conn.execute(
                f"INSERT INTO registration_results ({columns}) VALUES ({placeholders})",
                normalized,
            )
            return int(cursor.lastrowid)

    def has_success(self, email: str) -> bool:
        normalized = str(email or "").strip()
        if not normalized:
            return False
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT 1
                FROM registration_results
                WHERE success = 1 AND email = ? COLLATE NOCASE
                LIMIT 1
                """,
                (normalized,),
            ).fetchone()
        return row is not None

    @staticmethod
    def _result_filters(
        *,
        status: str = "",
        email_disable_status: str = "",
        keyword: str = "",
    ) -> Tuple[str, List[Any]]:
        clauses = []
        params: List[Any] = []
        normalized_status = str(status or "").strip().lower()
        if normalized_status:
            clauses.append("status = ?")
            params.append(normalized_status)
        normalized_disable_status = str(email_disable_status or "").strip().lower()
        if normalized_disable_status:
            clauses.append("email_disable_status = ?")
            params.append(normalized_disable_status)
        normalized_keyword = str(keyword or "").strip()
        if normalized_keyword:
            like = f"%{normalized_keyword}%"
            clauses.append(
                "(email LIKE ? OR provider LIKE ? OR failure_reason LIKE ? OR auth_info LIKE ? "
                "OR batch_id LIKE ? OR email_account_id LIKE ? OR email_disable_error LIKE ?)"
            )
            params.extend([like, like, like, like, like, like, like])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def list_results(
        self,
        *,
        status: str = "",
        email_disable_status: str = "",
        keyword: str = "",
        limit: int = 2000,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        where, params = self._result_filters(
            status=status,
            email_disable_status=email_disable_status,
            keyword=keyword,
        )
        safe_limit = max(1, min(int(limit or 2000), 10000))
        safe_offset = max(0, int(offset or 0))
        params.extend([safe_limit, safe_offset])
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT *
                FROM registration_results
                {where}
                ORDER BY finished_at DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def count_results(
        self,
        *,
        status: str = "",
        email_disable_status: str = "",
        keyword: str = "",
    ) -> int:
        """返回与账号列表相同筛选条件下的记录总数。"""
        where, params = self._result_filters(
            status=status,
            email_disable_status=email_disable_status,
            keyword=keyword,
        )
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT COUNT(*) AS total FROM registration_results {where}", params
            ).fetchone()
        return int(row["total"] or 0)

    def get_results_by_ids(self, ids: Iterable[int | str]) -> List[Dict[str, Any]]:
        """按主键批量读取记录，保持传入顺序。"""
        normalized: List[int] = []
        seen = set()
        for raw in ids or []:
            try:
                value = int(raw)
            except (TypeError, ValueError):
                continue
            if value <= 0 or value in seen:
                continue
            seen.add(value)
            normalized.append(value)
        if not normalized:
            return []
        by_id: Dict[int, Dict[str, Any]] = {}
        with self._connect() as conn:
            for start in range(0, len(normalized), SQLITE_IN_BATCH_SIZE):
                batch = normalized[start : start + SQLITE_IN_BATCH_SIZE]
                placeholders = ", ".join("?" for _ in batch)
                rows = conn.execute(
                    f"""
                    SELECT *
                    FROM registration_results
                    WHERE id IN ({placeholders})
                    """,
                    batch,
                ).fetchall()
                by_id.update({int(row["id"]): dict(row) for row in rows})
        return [by_id[item_id] for item_id in normalized if item_id in by_id]

    def update_relogin_result(
        self,
        account_id: int,
        *,
        account_file: str = "",
        cpa_detail: Optional[Dict[str, Any]] = None,
        status: str = "success",
        error: str = "",
        screenshot_path: str = "",
    ) -> bool:
        """记录重新登录结果，并在成功时刷新授权文件路径。"""
        try:
            normalized_id = int(account_id)
        except (TypeError, ValueError):
            return False
        if normalized_id <= 0:
            return False
        detail = dict(cpa_detail or {})
        relogin_status = str(status or "failed").strip().lower()
        now = self.now_text()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT extra_json FROM registration_results WHERE id = ?",
                (normalized_id,),
            ).fetchone()
            if row is None:
                return False
            try:
                extra = json.loads(str(row["extra_json"] or "{}"))
                if not isinstance(extra, dict):
                    extra = {}
            except (TypeError, ValueError, json.JSONDecodeError):
                extra = {}
            extra.update(
                {
                    "relogin_status": relogin_status,
                    "relogin_at": now,
                    "relogin_error": str(error or ""),
                }
            )
            values: Dict[str, Any] = {
                "extra_json": json.dumps(extra, ensure_ascii=False, sort_keys=True),
                "id": normalized_id,
            }
            assignments = ["extra_json = :extra_json"]
            if screenshot_path:
                assignments.append("screenshot_path = :screenshot_path")
                values["screenshot_path"] = str(screenshot_path)
            if relogin_status in {"success", "partial"} and account_file:
                auth_info = detail.get("auth_info", "")
                if isinstance(auth_info, (list, tuple, set)):
                    auth_info = "\n".join(str(item) for item in auth_info if str(item).strip())
                values.update(
                    {
                        "account_file": str(account_file or ""),
                        "sso_saved": 1,
                        "cpa_enabled": 1 if bool(detail.get("enabled")) else 0,
                        "cpa_status": str(detail.get("status") or "not_attempted"),
                        "auth_info": str(auth_info or ""),
                        "auth_path": str(detail.get("auth_path") or ""),
                        "cpa_auth_path": str(detail.get("cpa_auth_path") or ""),
                        "grok2api_auth_path": str(detail.get("grok2api_auth_path") or ""),
                        "cpa_remote_status": str(
                            detail.get("cpa_remote_status") or "not_configured"
                        ),
                        "cpa_remote_imported_at": str(
                            detail.get("cpa_remote_imported_at") or ""
                        ),
                        "cpa_remote_error": str(detail.get("cpa_remote_error") or ""),
                        "grok2api_remote_status": str(
                            detail.get("grok2api_remote_status") or "not_configured"
                        ),
                        "grok2api_remote_imported_at": str(
                            detail.get("grok2api_remote_imported_at") or ""
                        ),
                        "grok2api_remote_error": str(
                            detail.get("grok2api_remote_error") or ""
                        ),
                    }
                )
                assignments.extend(
                    [
                        "account_file = :account_file",
                        "sso_saved = :sso_saved",
                        "cpa_enabled = :cpa_enabled",
                        "cpa_status = :cpa_status",
                        "auth_info = :auth_info",
                        "auth_path = :auth_path",
                        "cpa_auth_path = :cpa_auth_path",
                        "grok2api_auth_path = :grok2api_auth_path",
                        "cpa_remote_status = :cpa_remote_status",
                        "cpa_remote_imported_at = :cpa_remote_imported_at",
                        "cpa_remote_error = :cpa_remote_error",
                        "grok2api_remote_status = :grok2api_remote_status",
                        "grok2api_remote_imported_at = :grok2api_remote_imported_at",
                        "grok2api_remote_error = :grok2api_remote_error",
                    ]
                )
                if relogin_status == "success" and not screenshot_path:
                    assignments.append("screenshot_path = ''")
            cursor = conn.execute(
                f"UPDATE registration_results SET {', '.join(assignments)} WHERE id = :id",
                values,
            )
            return bool(cursor.rowcount)

    def update_remote_import_status(
        self,
        account_id: int,
        kind: str,
        *,
        status: str,
        error: str = "",
        imported_at: str = "",
    ) -> bool:
        """更新 CPA 或 Grok2API 的远程入库状态。"""
        normalized_kind = str(kind or "").strip().lower()
        if normalized_kind not in {"cpa", "grok2api"}:
            raise ValueError("kind 必须是 cpa 或 grok2api")
        try:
            normalized_id = int(account_id)
        except (TypeError, ValueError):
            return False
        if normalized_id <= 0:
            return False
        normalized_status = str(status or "failed").strip().lower()
        timestamp = str(imported_at or "")
        if normalized_status in {"success", "partial"} and not timestamp:
            timestamp = self.now_text()
        prefix = f"{normalized_kind}_remote"
        with self._connect() as conn:
            cursor = conn.execute(
                f"""
                UPDATE registration_results
                SET {prefix}_status = ?, {prefix}_imported_at = ?, {prefix}_error = ?
                WHERE id = ?
                """,
                (normalized_status, timestamp, str(error or ""), normalized_id),
            )
            return bool(cursor.rowcount)

    def delete_results(self, ids: Iterable[int | str]) -> List[Dict[str, Any]]:
        """删除指定记录，返回实际删除前的记录快照。"""
        records = self.get_results_by_ids(ids)
        if not records:
            return []
        delete_ids = [int(row["id"]) for row in records]
        with self._connect() as conn:
            for start in range(0, len(delete_ids), SQLITE_IN_BATCH_SIZE):
                batch = delete_ids[start : start + SQLITE_IN_BATCH_SIZE]
                placeholders = ", ".join("?" for _ in batch)
                conn.execute(
                    f"DELETE FROM registration_results WHERE id IN ({placeholders})",
                    batch,
                )
        return records

    def stats(self) -> Dict[str, Any]:

        today = _datetime.datetime.now().astimezone().strftime("%Y-%m-%d")
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) AS success,
                    SUM(CASE WHEN status = 'failure' THEN 1 ELSE 0 END) AS failure,
                    SUM(CASE WHEN status = 'skipped' THEN 1 ELSE 0 END) AS skipped,
                    SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) AS cancelled,
                    SUM(CASE WHEN cpa_status = 'success' THEN 1 ELSE 0 END) AS cpa_success,
                    SUM(CASE WHEN cpa_status = 'failed' THEN 1 ELSE 0 END) AS cpa_failed,
                    SUM(CASE WHEN email_disable_status = 'success' THEN 1 ELSE 0 END) AS email_disabled,
                    SUM(CASE WHEN email_disable_status = 'failed' THEN 1 ELSE 0 END) AS email_disable_failed,
                    SUM(CASE WHEN substr(finished_at, 1, 10) = ? THEN 1 ELSE 0 END) AS today_total,
                    SUM(CASE WHEN substr(finished_at, 1, 10) = ? AND status = 'success' THEN 1 ELSE 0 END) AS today_success,
                    COUNT(DISTINCT CASE WHEN success = 1 THEN lower(email) END) AS unique_success_emails,
                    AVG(CASE WHEN status = 'success' AND duration_seconds > 0 THEN duration_seconds END) AS avg_success_seconds
                FROM registration_results
                """,
                (today, today),
            ).fetchone()
            providers = conn.execute(
                """
                SELECT provider, COUNT(*) AS total,
                       SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) AS success
                FROM registration_results
                GROUP BY provider
                ORDER BY total DESC, provider ASC
                """
            ).fetchall()
        result = {key: (row[key] or 0) for key in row.keys()}
        result["providers"] = [dict(item) for item in providers]
        return result

    def import_existing_accounts(self, accounts_dir: os.PathLike[str] | str) -> int:
        """把旧的账号 TXT 补录为成功记录；同邮箱已有成功记录时跳过。"""
        root = Path(accounts_dir)
        if not root.is_dir():
            return 0
        excluded_prefixes = ("mail_", "sso_", "accounts_summary_", "sso_summary_")
        imported = 0
        for path in sorted(root.glob("*.txt")):
            if path.name.startswith(excluded_prefixes):
                continue
            try:
                lines: Iterable[str] = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
            except OSError:
                continue
            for raw_line in lines:
                parts = raw_line.strip().split("----", 2)
                if len(parts) != 3:
                    continue
                email, password, sso = (part.strip() for part in parts)
                if "@" not in email or not password or not sso or self.has_success(email):
                    continue
                try:
                    stamp = _datetime.datetime.fromtimestamp(
                        path.stat().st_mtime,
                        tz=_datetime.datetime.now().astimezone().tzinfo,
                    ).strftime("%Y-%m-%d %H:%M:%S")
                    self.add_result(
                        {
                            "source_key": f"legacy-success:{email.lower()}",
                            "batch_id": "legacy-import",
                            "source": "legacy_import",
                            "started_at": stamp,
                            "finished_at": stamp,
                            "email": email,
                            "password": password,
                            "status": "success",
                            "success": True,
                            "provider": "历史文件",
                            "cpa_enabled": False,
                            "cpa_status": "unknown",
                            "account_file": str(path.resolve()),
                            "sso_saved": True,
                            "extra": {"imported_from": str(path.resolve())},
                        }
                    )
                    imported += 1
                except (OSError, sqlite3.IntegrityError, ValueError):
                    continue
        return imported
