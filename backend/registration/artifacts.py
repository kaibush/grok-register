# -*- coding: utf-8 -*-
"""注册产物定位与清理。

根据数据库记录收集关联授权文件，并限制删除范围以保护数据库及公共清单文件。
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple


_PATH_IN_TEXT_RE = re.compile(
    r"(?P<path>(?:[A-Za-z]:[\\/]|\\|/)[^\r\n\t\"']+\.(?:json|txt|png|jpe?g|webp))",
    re.IGNORECASE,
)
_PROTECTED_BASENAMES = {
    "registration_results.sqlite3",
    "registration_results.sqlite3-wal",
    "registration_results.sqlite3-shm",
    "mail_credentials.txt",
    "sso_pending.txt",
    "sso_risk_rejected.txt",
}


def _normalize_email(email: Any) -> str:
    return str(email or "").strip()


def _safe_email_name(email: str) -> str:
    return _normalize_email(email).replace("/", "_").replace("\\", "_")


def _extract_paths_from_text(text: Any) -> List[str]:
    """从 auth_info / 自由文本中提取疑似本地文件路径。"""
    found: List[str] = []
    seen: Set[str] = set()
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip().strip("\"'")
        if not line:
            continue
        candidates: List[str] = []
        if ": " in line:
            candidates.append(line.split(": ", 1)[1].strip().strip("\"'"))
        candidates.append(line)
        for match in _PATH_IN_TEXT_RE.finditer(line):
            candidates.append(match.group("path").strip().strip("\"'"))
        for candidate in candidates:
            value = str(candidate or "").strip().strip("\"'")
            if not value:
                continue
            lower = value.lower()
            if not lower.endswith((".json", ".txt", ".png", ".jpg", ".jpeg", ".webp")):
                continue
            if value in seen:
                continue
            seen.add(value)
            found.append(value)
    return found


def collect_related_file_paths(
    record: Dict[str, Any],
    *,
    accounts_dir: str,
    app_dir: str = "",
) -> List[str]:
    """收集注册记录关联的本地真实文件路径（去重，仅已存在文件）。"""
    accounts_root = os.path.abspath(accounts_dir)
    # app_dir 传入 data/ 目录时，授权目录直接位于其下；兼容旧调用的项目根目录。
    root = os.path.abspath(app_dir) if app_dir else os.path.dirname(accounts_root)
    email = _normalize_email(record.get("email"))
    safe_email = _safe_email_name(email)

    candidates: List[str] = []
    for key in ("account_file", "auth_path", "screenshot_path"):
        value = str(record.get(key) or "").strip()
        if value:
            candidates.append(value)
    candidates.extend(_extract_paths_from_text(record.get("auth_info")))

    if safe_email:
        candidates.extend(
            [
                os.path.join(accounts_root, f"{safe_email}.txt"),
                os.path.join(root, "cpa_auth", f"xai-{safe_email}.json"),
                os.path.join(root, "grok2api_auth", f"g2a-{safe_email}.json"),
                os.path.join(root, "grok2api_auth", f"g2a-{safe_email}-web.json"),
                os.path.join(root, "grok2api_auth", f"g2a-{safe_email}-console.json"),
            ]
        )

    resolved: List[str] = []
    seen: Set[str] = set()
    for raw in candidates:
        path = os.path.abspath(os.path.expanduser(str(raw or "").strip()))
        if not path or path in seen:
            continue
        base = os.path.basename(path).lower()
        if base in _PROTECTED_BASENAMES:
            continue
        if not os.path.isfile(path):
            continue
        seen.add(path)
        resolved.append(path)
    return resolved


def _line_matches_email(line: str, email: str) -> bool:
    normalized = _normalize_email(email).lower()
    if not normalized:
        return False
    raw = str(line or "").strip()
    if not raw:
        return False
    head = raw.split("----", 1)[0]
    head = head.split("\t", 1)[0].strip()
    if " " in head:
        maybe_email = head.split(" ", 1)[0].strip()
        if "@" in maybe_email:
            head = maybe_email
    return head.lower() == normalized


def remove_email_lines_from_file(path: str, emails: Iterable[str]) -> int:
    """从汇总/附属文本中删除匹配邮箱的行，返回删除行数。"""
    target = os.path.abspath(path)
    if not os.path.isfile(target):
        return 0
    email_set = {_normalize_email(item).lower() for item in emails if _normalize_email(item)}
    if not email_set:
        return 0
    try:
        original = Path(target).read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return 0

    kept: List[str] = []
    removed = 0
    for line in original.splitlines(keepends=True):
        body = line[:-1] if line.endswith("\n") else line
        if body.endswith("\r"):
            body = body[:-1]
        if any(_line_matches_email(body, email) for email in email_set):
            removed += 1
            continue
        kept.append(line if line.endswith("\n") else f"{line}\n")
    if removed <= 0:
        return 0

    tmp = f"{target}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8", newline="") as handle:
            handle.write("".join(kept))
        os.replace(tmp, target)
    except OSError:
        try:
            if os.path.isfile(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return 0
    return removed


def cleanup_side_files_for_emails(accounts_dir: str, emails: Iterable[str]) -> Dict[str, int]:
    """清理 accounts 附属汇总文件中的邮箱行。"""
    root = os.path.abspath(accounts_dir)
    email_list = sorted({_normalize_email(item) for item in emails if _normalize_email(item)})
    result: Dict[str, int] = {}
    if not email_list or not os.path.isdir(root):
        return result

    for name in ("sso_pending.txt", "sso_risk_rejected.txt", "mail_credentials.txt"):
        path = os.path.join(root, name)
        removed = remove_email_lines_from_file(path, email_list)
        if removed:
            result[path] = removed

    try:
        batch_files = sorted(Path(root).glob("accounts_*.txt"))
    except OSError:
        batch_files = []
    for path in batch_files:
        removed = remove_email_lines_from_file(str(path), email_list)
        if removed:
            result[str(path)] = removed
    return result


def delete_related_files(paths: Iterable[str]) -> Tuple[List[str], List[str]]:
    """删除关联文件，返回 (成功列表, 失败描述列表)。"""
    deleted: List[str] = []
    errors: List[str] = []
    for raw in paths:
        path = os.path.abspath(str(raw or "").strip())
        if not path:
            continue
        base = os.path.basename(path).lower()
        if base in _PROTECTED_BASENAMES:
            continue
        if not os.path.isfile(path):
            continue
        try:
            os.remove(path)
            deleted.append(path)
        except OSError as exc:
            errors.append(f"{path}: {exc}")
    return deleted, errors
