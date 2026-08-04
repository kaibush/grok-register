# -*- coding: utf-8 -*-
"""账号授权文件批量导出。"""
from __future__ import annotations

import io
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, Iterable

AuthFileResolver = Callable[[Dict[str, Any], Dict[str, Any], str], Path]


def build_account_auth_archive(
    records: Iterable[Dict[str, Any]],
    raw_config: Dict[str, Any],
    kind: str,
    resolve_file: AuthFileResolver,
) -> tuple[bytes, int, int]:
    if kind not in {"cpa", "grok2api"}:
        raise ValueError("kind 必须是 cpa 或 grok2api")
    buffer = io.BytesIO()
    exported = 0
    skipped = 0
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for record in records:
            try:
                path = resolve_file(record, raw_config, kind)
                archive.write(path, arcname=f"{int(record.get('id') or 0)}-{path.name}")
            except (FileNotFoundError, OSError, TypeError, ValueError):
                skipped += 1
                continue
            exported += 1
    return buffer.getvalue(), exported, skipped
