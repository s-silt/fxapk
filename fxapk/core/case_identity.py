"""Stable case identifier rules shared by phase packages and corpus."""

from __future__ import annotations

import unicodedata

MAX_CASE_ID_LENGTH = 240


def normalize_case_id(value: object) -> str:
    """Normalize an explicitly supplied case id, or fail closed.

    NFC prevents visually identical composed/decomposed Unicode ids from
    becoming separate cases.  The function never derives an id from a path,
    filename, display label, or row position.
    """
    text = unicodedata.normalize("NFC", str(value)).strip() if value is not None else ""
    if not text:
        raise ValueError("case_id 不能为空")
    if len(text) > MAX_CASE_ID_LENGTH:
        raise ValueError(f"case_id 不能超过 {MAX_CASE_ID_LENGTH} 个字符")
    if any(unicodedata.category(ch) in {"Cc", "Cf", "Cs"} for ch in text):
        raise ValueError("case_id 不能包含控制字符、不可见格式字符或代理码位")
    return text


__all__ = ["MAX_CASE_ID_LENGTH", "normalize_case_id"]
