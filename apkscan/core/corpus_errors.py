"""语料库记录契约违例的窄异常与稳定错误码。

与普通 ``ValueError`` 的区别：这些校验的文案完全由本模块的封闭映射决定，不拼路径、
不回显 inventory 行内容、不带下游异常消息，因而可以随 ``reason`` / ``error`` 字段
落进对账结果供人阅读——读的人据此知道"是哪一项没过"，而不是只看到一个 ``ValueError``。
"""

from __future__ import annotations

from enum import Enum
from typing import cast

from apkscan.core.redact import PublicDiagnosticError, register_public_diagnostic


class CorpusRecordErrorCode(str, Enum):
    """语料库记录契约违例的稳定错误码。"""

    INVENTORY_ROW_NOT_OBJECT = "inventory_row_not_object"
    CASE_ID_NOT_STRING = "case_id_not_string"
    REPORT_PATH_EMPTY = "report_path_empty"
    REPORT_ROOT_NOT_OBJECT = "report_root_not_object"
    REPORT_MISSING_SAMPLE_SHA256 = "report_missing_sample_sha256"
    REPORT_MISSING_TOOL_IDENTITY = "report_missing_tool_identity"
    PACKAGE_REPORT_ARTIFACT_COUNT = "package_report_artifact_count"
    PACKAGE_REPORT_PATH_MISSING = "package_report_path_missing"
    PACKAGE_REPORT_PATH_ABSOLUTE = "package_report_path_absolute"
    PACKAGE_REPORT_PATH_ESCAPES_ROOT = "package_report_path_escapes_root"
    PACKAGE_REPORT_SHA256_INVALID = "package_report_sha256_invalid"
    PACKAGE_REPORT_SIZE_INVALID = "package_report_size_invalid"
    PACKAGE_REPORT_SIZE_CHANGED = "package_report_size_changed"
    PACKAGE_REPORT_HASH_CHANGED = "package_report_hash_changed"


_CORPUS_RECORD_MESSAGES: dict[CorpusRecordErrorCode, str] = {
    CorpusRecordErrorCode.INVENTORY_ROW_NOT_OBJECT: "inventory 行必须是对象",
    CorpusRecordErrorCode.CASE_ID_NOT_STRING: "case_id 必须是字符串",
    CorpusRecordErrorCode.REPORT_PATH_EMPTY: "report_path 不能为空",
    CorpusRecordErrorCode.REPORT_ROOT_NOT_OBJECT: "report 顶层必须是对象",
    CorpusRecordErrorCode.REPORT_MISSING_SAMPLE_SHA256: "report 缺少 sample_sha256",
    CorpusRecordErrorCode.REPORT_MISSING_TOOL_IDENTITY: "report 缺少 tool_version/ruleset_digest",
    CorpusRecordErrorCode.PACKAGE_REPORT_ARTIFACT_COUNT:
        "case package must contain exactly one report artifact",
    CorpusRecordErrorCode.PACKAGE_REPORT_PATH_MISSING:
        "case package report artifact path is missing",
    CorpusRecordErrorCode.PACKAGE_REPORT_PATH_ABSOLUTE:
        "case package report artifact path is absolute",
    CorpusRecordErrorCode.PACKAGE_REPORT_PATH_ESCAPES_ROOT:
        "case package report artifact escapes package root",
    CorpusRecordErrorCode.PACKAGE_REPORT_SHA256_INVALID:
        "case package report artifact sha256 is invalid",
    CorpusRecordErrorCode.PACKAGE_REPORT_SIZE_INVALID:
        "case package report artifact size is invalid",
    CorpusRecordErrorCode.PACKAGE_REPORT_SIZE_CHANGED:
        "case package report artifact size changed",
    CorpusRecordErrorCode.PACKAGE_REPORT_HASH_CHANGED:
        "case package report artifact hash changed",
}


class CorpusRecordError(ValueError, PublicDiagnosticError):
    """语料库记录违反契约。

    构造器只收本模块枚举（精确类型判定），文案由 code 重新生成、不读 ``args``——
    调用点无法把 inventory 行内容、报告路径或下游异常消息拼进去。
    仍是 ``ValueError`` 子类，既有 ``except ValueError`` 调用点不受影响。
    """

    def __init__(self, code: CorpusRecordErrorCode) -> None:
        if type(code) is not CorpusRecordErrorCode:
            raise TypeError(f"code 必须是 CorpusRecordErrorCode，收到 {type(code).__name__}")
        self._code = code
        super().__init__(_CORPUS_RECORD_MESSAGES[code])

    @property
    def code(self) -> CorpusRecordErrorCode:
        return self._code

    @property
    def public_message(self) -> str:
        return _CORPUS_RECORD_MESSAGES[self._code]

    @property
    def diagnostic_code(self) -> str:
        return self._code.value


register_public_diagnostic(
    CorpusRecordError, lambda exc: cast(CorpusRecordError, exc).public_message
)


__all__ = ["CorpusRecordError", "CorpusRecordErrorCode"]
