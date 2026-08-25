"""Strict JSON primitives shared by persisted report/package boundaries."""

from __future__ import annotations

import math
from enum import Enum
from typing import NoReturn, cast

from apkscan.core.redact import PublicDiagnosticError, register_public_diagnostic


class JsonContractErrorCode(str, Enum):
    """JSON 边界契约违例的稳定错误码。"""

    NON_FINITE_NUMBER = "non_finite_json_number"


_JSON_CONTRACT_MESSAGES: dict[JsonContractErrorCode, str] = {
    JsonContractErrorCode.NON_FINITE_NUMBER: "non-finite JSON number is not permitted",
}


class JsonContractError(ValueError, PublicDiagnosticError):
    """JSON 边界契约违例。

    **不回显 token**：触发它的 token 直接来自待解析的不可信 JSON，是典型的输入回显面
    （可能异常长、含特殊字符、用换行伪造日志行）。错误码已足以区分是哪条契约没过。
    构造器只收本模块枚举，文案由 code 重新生成（不读 ``args``）。
    仍是 ``ValueError`` 子类，``json.loads`` 的既有 ``except ValueError`` 调用点不受影响。
    """

    def __init__(self, code: JsonContractErrorCode) -> None:
        if type(code) is not JsonContractErrorCode:
            raise TypeError(f"code 必须是 JsonContractErrorCode，收到 {type(code).__name__}")
        self._code = code
        super().__init__(_JSON_CONTRACT_MESSAGES[code])

    @property
    def code(self) -> JsonContractErrorCode:
        return self._code

    @property
    def public_message(self) -> str:
        return _JSON_CONTRACT_MESSAGES[self._code]

    @property
    def diagnostic_code(self) -> str:
        return self._code.value


register_public_diagnostic(
    JsonContractError, lambda exc: cast(JsonContractError, exc).public_message
)


def reject_nonfinite_json_constant(token: str) -> NoReturn:
    """Reject Python's permissive NaN/Infinity extensions at a JSON boundary."""
    raise JsonContractError(JsonContractErrorCode.NON_FINITE_NUMBER)


def parse_finite_json_float(token: str) -> float:
    """Parse a JSON float while rejecting exponent overflow to infinity."""
    value = float(token)
    if not math.isfinite(value):
        reject_nonfinite_json_constant(token)
    return value


__all__ = [
    "JsonContractError",
    "JsonContractErrorCode",
    "parse_finite_json_float",
    "reject_nonfinite_json_constant",
]
