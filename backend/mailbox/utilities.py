"""邮箱渠道共享的小型解析工具。"""

from __future__ import annotations

import re
import secrets
import string
from typing import Any, List, Optional


def generate_username(length: int = 10) -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(max(3, length)))


def pick_list_payload(data: Any) -> List[dict]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        if isinstance(data.get("results"), list):
            return [item for item in data["results"] if isinstance(item, dict)]
        if isinstance(data.get("hydra:member"), list):
            return [item for item in data["hydra:member"] if isinstance(item, dict)]
        if isinstance(data.get("data"), list):
            return [item for item in data["data"] if isinstance(item, dict)]
        if isinstance(data.get("messages"), list):
            return [item for item in data["messages"] if isinstance(item, dict)]
        if isinstance(data.get("data"), dict):
            nested = data.get("data") or {}
            if isinstance(nested.get("messages"), list):
                return [item for item in nested["messages"] if isinstance(item, dict)]
    return []


_SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b[^>]*>.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")

# 验证码形如 I6R-B2W：必须全大写，否则邮件模板里的 CSS 类名（如 sm-w-per-100）会被误判。
_CODE_TOKEN = r"[A-Z0-9]{3}-[A-Z0-9]{3}"
_CODE_WITH_CONTEXT_RE = re.compile(
    r"(?:code|验证码)\s*(?:is|：|:)?\s*\b(" + _CODE_TOKEN + r")\b", re.IGNORECASE
)
_CODE_BARE_RE = re.compile(r"\b(" + _CODE_TOKEN + r")\b")
_NUMERIC_CODE_RES = [
    re.compile(r"verification\s+code[:\s]+(\d{4,8})", re.IGNORECASE),
    re.compile(r"your\s+code[:\s]+(\d{4,8})", re.IGNORECASE),
    re.compile(r"confirm(?:ation)?\s+code[:\s]+(\d{4,8})", re.IGNORECASE),
]


def strip_html(html: str) -> str:
    """剥掉 HTML 标签，取纯文本。

    必须先删除 script/style 块与注释：只删尖括号的话，<style> 里的 CSS 正文
    会原样留在结果里，其中的类名（如 .sm-w-per-100）会被验证码正则误命中。
    """
    if not html:
        return ""
    cleaned = _SCRIPT_STYLE_RE.sub(" ", html)
    cleaned = _COMMENT_RE.sub(" ", cleaned)
    return _TAG_RE.sub(" ", cleaned)


def _match_code(pattern: re.Pattern, source: str) -> Optional[str]:
    """取第一个含字母的匹配，纯数字串（如 100-200）不是验证码。"""
    for match in pattern.finditer(source):
        token = match.group(1)
        if any(ch.isalpha() for ch in token):
            return token
    return None


def extract_verification_code(text: str, subject: str = "") -> Optional[str]:
    subject = subject or ""
    text = text or ""
    # 主题最干净，优先；正文里带 code 关键字的上下文次之，裸 token 最后。
    for pattern in (_CODE_WITH_CONTEXT_RE, _CODE_BARE_RE):
        for source in (subject, text):
            code = _match_code(pattern, source)
            if code:
                return code
    for pattern in _NUMERIC_CODE_RES:
        match = pattern.search(text) or pattern.search(subject)
        if match:
            return match.group(1)
    return None
