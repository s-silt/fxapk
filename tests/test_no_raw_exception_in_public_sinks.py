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
    "enrichers/whois.py",
    "enrichers/dns.py",
]

#: 禁止直接插值的名字：异常对象与子进程原始输出。
#:
#: 这里刻意采用精确名称匹配，不按 ``*_exc`` 后缀匹配。dns.enrich 中的
#: ``doh_exc`` / ``socket_exc`` 保存的是 safe_error_type() 返回的稳定分类码，
#: 并非异常对象；精确匹配既允许这两个分类码进入日志，也仍会拦住名为 ``exc``
#: 的原始异常对象。
_FORBIDDEN_NAMES = {"exc", "tail", "err", "stderr_text"}

#: 允许接收异常/证据原值的安全出口——它们自己负责分类或脱敏。
#:
#: ``repr`` 不在白名单中：repr(exc) 和 str(exc) 一样可能公开 provider 原文。
_SAFE_CALLS = {
    "safe_exception_text",
    "safe_exception_diagnostic",
    "safe_error_type",
    "redact_url",
    "scrub_urls",
    "dexdump_public_hint",
    "_classify_dexdump_output",
    "log_evidence",
    "type",
    "isinstance",
}


#: 允许从禁止对象读取的稳定、安全属性。
#:
#: 白名单按完整访问形态判断，只允许直接的 ``exc.<attr>``。不会放行
#: ``exc.args``、``exc.stderr``、``exc.response.text``，也不会把任意对象上的
#: 同名属性视为安全。
_SAFE_FORBIDDEN_ATTRIBUTES = {
    ("exc", "diagnostic_code"),
    ("exc", "public_message"),
    ("exc", "code"),
}


def _call_name(node: ast.Call) -> str | None:
    """返回调用目标的末级名称，兼容 func(...) 与 module.func(...)。"""
    func = node.func
    return getattr(func, "id", None) or getattr(func, "attr", None)


def _unsafe_forbidden_names(node: ast.AST) -> set[str]:
    """找出表达式中未经过安全调用或安全属性访问的禁止名称。

    安全调用只跳过该调用自己的子树；安全属性只允许精确列出的直接访问，
    例如 ``exc.diagnostic_code``。其他属性访问仍会继续下钻，因此
    ``exc.args``、``exc.stderr`` 和 ``exc.response.text`` 都会命中 ``exc``。
    """
    found: set[str] = set()

    def visit(current: ast.AST) -> None:
        if isinstance(current, ast.Call) and _call_name(current) in _SAFE_CALLS:
            return

        if isinstance(current, ast.Attribute):
            value = current.value
            if (
                isinstance(value, ast.Name)
                and (value.id, current.attr) in _SAFE_FORBIDDEN_ATTRIBUTES
            ):
                return

        if isinstance(current, ast.Name) and current.id in _FORBIDDEN_NAMES:
            found.add(current.id)
            return

        for child in ast.iter_child_nodes(current):
            visit(child)

    visit(node)
    return found

def _parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    """构建 AST 节点到直接父节点的映射。"""
    return {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }


def _is_safe_wrapped(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
) -> bool:
    """判断节点是否直接处于安全调用的参数表达式中。

    可以跨越参数内部的普通表达式节点，例如：

        scrub_urls(str(exc))
        scrub_urls(prefix + str(exc))

    但遇到另一个调用边界便停止。因此：

        scrub_urls(logger.debug("boom %s", exc))

    扫描 ``logger.debug`` 时不会因为外层 ``scrub_urls`` 而被放行。
    """
    current = node

    while current in parents:
        parent = parents[current]

        if isinstance(parent, ast.Call):
            if _call_name(parent) in _SAFE_CALLS and (
                current in parent.args
                or any(keyword.value is current for keyword in parent.keywords)
            ):
                return True

            # 不能跨越任意其他调用边界寻找更外层的安全调用。
            return False

        current = parent

    return False


def _violations(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    parents = _parent_map(tree)

    found: list[str] = []
    logger_methods = {
        "debug",
        "info",
        "warning",
        "error",
        "critical",
        "exception",
    }

    for node in ast.walk(tree):
        # f"...{exc}..." / f"...{tail}..."，也覆盖转换标志 f"{exc!r}"。
        if isinstance(node, ast.FormattedValue):
            for name in sorted(_unsafe_forbidden_names(node.value)):
                found.append(f"{path.name}:{node.lineno} f-string 直接插值 {name}")

        if not isinstance(node, ast.Call):
            continue

        # str(exc) / repr(exc) 默认禁止。仅当这个转换调用本身处于安全调用
        # 的参数表达式中时放行，例如 scrub_urls(str(exc))。
        func_name = _call_name(node)
        if func_name in {"str", "repr"} and not _is_safe_wrapped(node, parents):
            for arg in node.args:
                for name in sorted(_unsafe_forbidden_names(arg)):
                    found.append(f"{path.name}:{node.lineno} {func_name}({name})")
            for keyword in node.keywords:
                for name in sorted(_unsafe_forbidden_names(keyword.value)):
                    found.append(f"{path.name}:{node.lineno} {func_name}({name})")

        # logger.xxx(...) 的消息、插值参数和关键字参数均不得包含裸异常/证据。
        # 这里不使用 _is_safe_wrapped：logger 调用不能因外层恰好存在安全调用
        # 而被豁免。
        attr = getattr(node.func, "attr", None)
        target = getattr(node.func, "value", None)
        is_logger = isinstance(target, ast.Name) and target.id == "logger"
        if is_logger and attr in logger_methods:
            for arg in node.args:
                for name in sorted(_unsafe_forbidden_names(arg)):
                    found.append(
                        f"{path.name}:{node.lineno} logger.{attr} 传入裸 {name}"
                    )
            for keyword in node.keywords:
                for name in sorted(_unsafe_forbidden_names(keyword.value)):
                    found.append(
                        f"{path.name}:{node.lineno} logger.{attr} 传入裸 {name}"
                    )

    return found

@pytest.mark.parametrize("relative", _GUARDED)
def test_guarded_module_has_no_raw_exception_interpolation(relative: str) -> None:
    path = _ROOT / relative
    assert path.is_file(), f"守卫清单里的模块不存在：{relative}"

    violations = _violations(path)

    assert not violations, (
        "公开输出里出现异常/证据原值——请改用 safe_exception_text / "
        "safe_exception_diagnostic / safe_error_type / log_evidence，或改成固定文案：\n  "
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
        "    b = str(exc)\n"
        '    c = f"tail: {tail}"\n'
        "    return a, b, c\n",
        encoding="utf-8",
    )

    violations = _violations(sample)

    assert len(violations) == 4, violations


def test_guard_allows_safe_wrappers_and_classification_codes(
    tmp_path: Path,
) -> None:
    """允许安全包装、稳定分类码和契约保证安全的异常属性。"""
    sample = tmp_path / "safe_sample.py"
    sample.write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def f(exc, doh_exc, socket_exc):\n"
        '    logger.debug("diag=%s", safe_exception_diagnostic(exc))\n'
        '    logger.debug("type=%s", safe_error_type(exc))\n'
        '    logger.debug("doh=%s socket=%s", doh_exc, socket_exc)\n'
        '    logger.debug("public=%s", exc.public_message)\n'
        '    a = f"code={exc.diagnostic_code}"\n'
        '    b = f"enum={exc.code}"\n'
        "    c, _ = scrub_urls(str(exc))\n"
        '    return f"type={safe_error_type(exc)}", a, b, c\n',
        encoding="utf-8",
    )

    assert _violations(sample) == []


def test_guard_rejects_unsafe_exception_attributes(tmp_path: Path) -> None:
    """安全属性白名单不得扩张为允许异常对象上的任意属性。"""
    sample = tmp_path / "unsafe_attributes.py"
    sample.write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def f(exc):\n"
        '    logger.error("args=%s", exc.args)\n'
        '    a = f"stderr={exc.stderr}"\n'
        '    b = f"body={exc.response.text}"\n'
        "    return a, b\n",
        encoding="utf-8",
    )

    violations = _violations(sample)

    assert len(violations) == 3, violations
    assert all("exc" in violation for violation in violations)


def test_guard_safe_outer_call_does_not_hide_nested_logger(
    tmp_path: Path,
) -> None:
    """外层安全调用不能掩盖其参数中的不安全 logger 调用。"""
    sample = tmp_path / "nested_logger.py"
    sample.write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def f(exc):\n"
        '    return scrub_urls(logger.debug("boom %s", exc))\n',
        encoding="utf-8",
    )

    violations = _violations(sample)

    assert len(violations) == 1, violations
    assert "logger.debug 传入裸 exc" in violations[0]


def test_guard_only_allows_str_inside_safe_call_argument(
    tmp_path: Path,
) -> None:
    """str(exc) 仅在安全调用参数内放行，普通调用包装仍违规。"""
    sample = tmp_path / "wrapped_str.py"
    sample.write_text(
        "def f(exc):\n"
        "    safe = scrub_urls(str(exc))\n"
        "    unsafe = ordinary_wrapper(str(exc))\n"
        "    return safe, unsafe\n",
        encoding="utf-8",
    )

    violations = _violations(sample)

    assert len(violations) == 1, violations
    assert "str(exc)" in violations[0]
