"""静态守卫：已治理模块里不得把异常/证据原值插进公开输出。

一处 formatter（``logsetup.LocatingFormatter``）挡住了带 ``exc_info`` 的 traceback，
但它拦不住**不带 exc_info 的普通插值**——``logger.error("失败：%s", exc)``、
``f"...{exc}"``、把子进程 tail 拼进返回值，这些的原文照样进终端。那只能靠调用点自觉，
而自觉会随新代码退化。本文件用 AST 把规则钉死在**已迁移的模块**上。

★覆盖边界（不可夸大）：只扫下面 ``_GUARDED`` 列出的模块。仓库其余历史日志插值尚未审计，
在完成全仓审计之前，不能宣称"整个 apkscan 默认终端无敏感信息泄露"。
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1] / "apkscan"

#: 已完成异常文本治理的模块——新增违规会在这里被拦下。
_GUARDED = [
    "core/case_package.py",
    "core/corpus_errors.py",
    "core/json_contract.py",
    "core/logsetup.py",
    "core/proctree.py",
    "core/redact.py",
    "dynamic/auto.py",
    "dynamic/repackage.py",
    "dynamic/unpack.py",
]

#: 禁止直接插值的名字：异常对象与子进程原始输出。
_FORBIDDEN_NAMES = {"exc", "tail", "err", "stderr_text"}

#: 允许把异常传进去的安全出口——它们自己负责脱敏。
_SAFE_CALLS = {
    "safe_exception_text",
    "safe_exception_diagnostic",
    "redact_url",
    "scrub_urls",
    "dexdump_public_hint",
    "_classify_dexdump_output",
    "log_evidence",
    "type",
    "isinstance",
    "repr",  # 仅在断言/调试语境，下面单独判 f-string 才拦
}


def _is_safe_wrapped(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """该节点是否被某个安全出口的调用包住。"""
    current = parents.get(node)
    while current is not None:
        if isinstance(current, ast.Call):
            func = current.func
            name = getattr(func, "id", None) or getattr(func, "attr", None)
            if name in _SAFE_CALLS:
                return True
        current = parents.get(current)
    return False


def _violations(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    found: list[str] = []
    for node in ast.walk(tree):
        # f"...{exc}..." / f"...{tail}..."
        if isinstance(node, ast.FormattedValue):
            value = node.value
            name = value.id if isinstance(value, ast.Name) else None
            if name in _FORBIDDEN_NAMES and not _is_safe_wrapped(value, parents):
                found.append(f"{path.name}:{node.lineno} f-string 直接插值 {name}")
        # str(exc) / repr(exc)
        if isinstance(node, ast.Call):
            func_name = getattr(node.func, "id", None)
            if func_name in {"str", "repr"} and node.args:
                arg = node.args[0]
                arg_name = arg.id if isinstance(arg, ast.Name) else None
                if arg_name in _FORBIDDEN_NAMES and not _is_safe_wrapped(node, parents):
                    found.append(f"{path.name}:{node.lineno} {func_name}({arg_name})")
            # logger.xxx("...%s", exc)：除 exception/log_evidence 外，实参不得是裸异常
            attr = getattr(node.func, "attr", None)
            target = getattr(node.func, "value", None)
            is_logger = isinstance(target, ast.Name) and target.id == "logger"
            if is_logger and attr in {"debug", "info", "warning", "error", "critical"}:
                for arg in node.args[1:]:
                    name = arg.id if isinstance(arg, ast.Name) else None
                    if name in _FORBIDDEN_NAMES:
                        found.append(f"{path.name}:{node.lineno} logger.{attr} 传入裸 {name}")
    return found


@pytest.mark.parametrize("relative", _GUARDED)
def test_guarded_module_has_no_raw_exception_interpolation(relative: str) -> None:
    path = _ROOT / relative
    assert path.is_file(), f"守卫清单里的模块不存在：{relative}"

    violations = _violations(path)

    assert not violations, (
        "公开输出里出现异常/证据原值——请改用 safe_exception_text / "
        "safe_exception_diagnostic / log_evidence，或改成固定文案：\n  "
        + "\n  ".join(violations)
    )


def test_guard_actually_detects_violations(tmp_path: Path) -> None:
    """守卫本身要能抓到东西——否则它只是一个恒绿的空壳。"""
    sample = tmp_path / "sample.py"
    sample.write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def f(exc, tail):\n"
        '    logger.warning("boom %s", exc)\n'
        '    a = f"failed: {exc}"\n'
        '    b = str(exc)\n'
        '    c = f"tail: {tail}"\n'
        "    return a, b, c\n",
        encoding="utf-8",
    )

    violations = _violations(sample)

    assert len(violations) == 4, violations
