"""公开诊断契约的锁：领域错误保住可操作性，未知异常仍塌缩成类型名。

背景：把所有 ``str(exc)`` 一律换成类型名会连"哪一项校验没过"一起丢掉——读的人只看到
``ValueError``，无从判断案件包是哪个锚点被伪造。:class:`PublicDiagnosticError` 划出的
边界是：**文案来自封闭的错误码→文案映射**的领域错误可以原样公开，其余一律只给类型名。

本文件锁三件事，缺一不可：
1. 领域错误公开的是固定文案与稳定错误码；
2. 不可信输入（原始 token / 案件目标值 / 本地路径）不得出现在公开诊断里；
3. 普通异常（消息可能来自第三方库或网络响应）仍然塌缩成类型名。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from apkscan.core.case_package import (
    CasePackageError,
    CasePackageErrorCode,
    verify_case_package,
)
from apkscan.core.corpus_errors import CorpusRecordError, CorpusRecordErrorCode
from apkscan.core.json_contract import (
    JsonContractError,
    reject_nonfinite_json_constant,
)
from apkscan.core.redact import PublicDiagnosticError, safe_exception_text

#: 三类不可信/环境值的哨兵，任一出现在公开诊断里都是回显面。
_CANARY_TOKEN = "1e99999999"
_CANARY_TARGET = "canary-target.example"
_CANARY_PATH = "/home/canary-user/cases/CASE-CANARY"


def test_domain_error_publishes_fixed_message_and_stable_code() -> None:
    exc = CasePackageError(CasePackageErrorCode.INVALID_SAMPLE_SHA256)

    assert exc.public_message == "sample_sha256 must be exactly 64 hexadecimal characters"
    assert exc.diagnostic_code == "invalid_sample_sha256"
    # 走 safe_exception_text 这条统一出口也必须拿到文案，而不是 "CasePackageError"。
    assert safe_exception_text(exc) == exc.public_message


def test_domain_error_index_is_the_only_dynamic_value() -> None:
    exc = CasePackageError(CasePackageErrorCode.CLOSURE_TARGET_NOT_OBJECT, index=3)

    assert exc.public_message == "closure target is not an object at index 3"
    assert exc.diagnostic_code == "closure_target_not_object"


@pytest.mark.parametrize(
    "bad_code",
    [
        "artifact outside package root: /home/alice/x",  # 不匹配任何枚举值
        "invalid_sample_sha256",  # ★恰好等于某个枚举**值**
    ],
)
def test_case_package_error_constructor_rejects_free_text(bad_code: str) -> None:
    """构造器只收枚举——这是"封闭"的实现手段，不是约定。

    ★第二个用例是真实的绕过路径：``CasePackageErrorCode`` 是 ``str, Enum``，与 str 同 hash，
    裸字符串 ``"invalid_sample_sha256"`` 会**命中**文案映射字典、构造成功，随后
    ``diagnostic_code`` 取 ``.value`` 时炸 AttributeError。只测"不匹配的自由文本"抓不到它。
    """
    with pytest.raises(TypeError):
        CasePackageError(bad_code)  # type: ignore[arg-type]


def test_case_package_error_rejects_non_int_index() -> None:
    """``index`` 是唯一允许的动态值，必须是真 int。

    ``type(index) is int`` 而非 ``isinstance``：``bool`` 是 ``int`` 子类，
    ``index=True`` 会渲染成 "at index True"。
    """
    for bad in ("CANARY_INDEX", True, 1.0):
        with pytest.raises(TypeError):
            CasePackageError(  # type: ignore[arg-type]
                CasePackageErrorCode.CLOSURE_TARGET_NOT_OBJECT, index=bad
            )


def test_public_message_ignores_mutated_args() -> None:
    """``public_message`` 由校验过的 code 重新生成，不读 ``args``。

    若它取自 ``str(self)``，事后 ``exc.args = (canary,)`` 就能把任意文本送出公开边界。
    """
    exc = CasePackageError(CasePackageErrorCode.INVALID_SAMPLE_SHA256)
    exc.args = (f"{_CANARY_TARGET} {_CANARY_PATH}",)

    assert exc.public_message == "sample_sha256 must be exactly 64 hexadecimal characters"
    assert safe_exception_text(exc) == exc.public_message
    assert _CANARY_TARGET not in safe_exception_text(exc)


def test_external_subclass_is_not_trusted() -> None:
    """继承基类 ≠ 被信任：放行与否由**精确类型**注册表决定。

    Python 无法密封继承层次；用 ``isinstance`` 判定的话，任何外部子类覆写
    ``public_message`` 就能放行任意文本。
    """

    class EvilError(PublicDiagnosticError):
        @property
        def public_message(self) -> str:
            return f"{_CANARY_TARGET} {_CANARY_PATH}"

        @property
        def diagnostic_code(self) -> str:
            return "evil"

    assert safe_exception_text(EvilError()) == "EvilError"
    assert _CANARY_TARGET not in safe_exception_text(EvilError())


def test_json_contract_error_does_not_echo_the_offending_token() -> None:
    with pytest.raises(JsonContractError) as excinfo:
        reject_nonfinite_json_constant(_CANARY_TOKEN)

    assert excinfo.value.diagnostic_code == "non_finite_json_number"
    assert _CANARY_TOKEN not in excinfo.value.public_message
    assert _CANARY_TOKEN not in safe_exception_text(excinfo.value)


def test_corpus_record_error_publishes_domain_message() -> None:
    exc = CorpusRecordError(CorpusRecordErrorCode.CASE_ID_NOT_STRING)

    assert exc.public_message == "case_id 必须是字符串"
    assert exc.diagnostic_code == "case_id_not_string"
    assert isinstance(exc, PublicDiagnosticError)
    # 仍是 ValueError 子类：既有 except ValueError 调用点不受影响。
    assert isinstance(exc, ValueError)


def test_unknown_exception_still_collapses_to_type_name() -> None:
    """契约的另一半：没实现契约的异常绝不放行消息。"""
    exc = RuntimeError(
        f"provider failed https://user:secret@{_CANARY_TARGET}/a?key=TOKEN {_CANARY_PATH}"
    )

    assert safe_exception_text(exc) == "RuntimeError"
    assert _CANARY_TARGET not in safe_exception_text(exc)
    assert _CANARY_PATH not in safe_exception_text(exc)


def test_verify_case_package_reports_codes_without_echoing_untrusted_input(
    tmp_path: Path,
) -> None:
    """走真入口：损坏的 manifest → 结果里有错误码，且原始 token 不外泄。"""
    manifest = tmp_path / "case-package.json"
    manifest.write_text('{"bad":' + _CANARY_TOKEN + "}", encoding="utf-8")

    result = verify_case_package(manifest)

    assert result["status"] == "failed"
    assert result["issues"] == ["non-finite JSON number is not permitted"]
    serialized = json.dumps(result, ensure_ascii=False)
    assert _CANARY_TOKEN not in serialized


def test_verify_case_package_does_not_echo_manifest_path(tmp_path: Path) -> None:
    """路径也不进公开诊断：它会泄露用户名、工作区、案件目录名。"""
    root = tmp_path / "canary-user" / "CASE-CANARY"
    root.mkdir(parents=True)
    manifest = root / "case-package.json"
    manifest.write_text("[]", encoding="utf-8")

    result = verify_case_package(manifest)

    assert result["status"] == "failed"
    assert result["issues"] == ["JSON record root must be an object"]
    assert "canary-user" not in json.dumps(result, ensure_ascii=False)


def test_project_case_status_survives_non_finite_json(tmp_path: Path) -> None:
    """回归：``JsonContractError`` 从 ``_load_object`` 穿透，曾让 ``case status`` 直接崩。

    投影函数只 catch ``CasePackageError`` 时，含 NaN 的 manifest 会把异常抛给 CLI；
    正确行为是投影成 ``package_integrity=failed``（校验失败 ≠ 命令崩溃）。
    """
    from apkscan.core.case_package import project_case_status

    manifest = tmp_path / "case-package.json"
    manifest.write_text('{"bad":' + _CANARY_TOKEN + "}", encoding="utf-8")

    projected = project_case_status(manifest)

    assert projected["package_integrity"] == "failed"
    assert _CANARY_TOKEN not in json.dumps(projected, ensure_ascii=False)
