"""静默 except 的冻结基线：把「不吞异常」从文字规则变成可执行检查。

静默 except 的定义
------------------

``except`` 块体只由 ``pass`` / ``continue`` / ``break`` / ``...`` / 裸字符串组成：异常被丢弃，
没有日志、没有回执、没有返回值区分。这类写法会把工具失败伪装成阴性结果，
与「工具失败 ≠ 阴性」的口径直接冲突。

基线粒度是 ``文件::函数限定名::异常类型::语句`` → 出现次数，不含行号，
因此无关改动造成的行号漂移不会让测试变红。

与孤儿键基线一样双向严格相等：

- 新增静默 except → 红。改成记录日志、写入回执或返回明确的失败状态；
  确属预期控制流（例如探测可选文件不存在）也要至少留一行 debug 日志。
- 存量被修好 → 也红。把基线对应条目删掉，让改善留痕。

更新基线（每条差异都必须有人看过）::

    python -m tests.contracts.silent_except --write
"""

from __future__ import annotations

import ast
import json
import sys
from collections import Counter
from pathlib import Path

BASELINE_PATH = Path(__file__).with_name("silent_except_baseline.json")

_README = [
    "静默 except 基线：except 块体只有 pass/continue/break/.../裸字符串的存量写法。",
    "键 = 文件::函数限定名::异常类型::语句；count = 出现次数（不含行号）；reason = 为什么允许静默（必填）。",
    "本文件由 python -m tests.contracts.silent_except --write 生成，",
    "由 test_silent_except_baseline.py 与现实做双向严格比对。",
    "★不要为了变绿无脑重生成：新增项应改成留日志或返回失败状态。",
]

_SILENT = (ast.Pass, ast.Continue, ast.Break)


def _is_noop(stmt: ast.stmt) -> bool:
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)


def _silent_kind(body: list[ast.stmt]) -> str | None:
    """块体不做任何事时返回最后生效的控制语句名，否则 None。

    把 ``...``、裸字符串和多条 pass 也算进来，防止用填充语句绕过检查。
    """
    if not all(isinstance(s, _SILENT) or _is_noop(s) for s in body):
        return None
    for stmt in body:
        if isinstance(stmt, (ast.Continue, ast.Break)):
            return type(stmt).__name__.lower()
    return "pass"


class _Collector(ast.NodeVisitor):
    def __init__(self, rel: str) -> None:
        self.rel = rel
        self.scope: list[str] = []
        self.found: Counter[str] = Counter()

    def _visit_scope(self, node: ast.AST, name: str) -> None:
        self.scope.append(name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_scope(node, node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_scope(node, node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_scope(node, node.name)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        stmt = _silent_kind(node.body)
        if stmt is not None:
            exc = ast.unparse(node.type) if node.type is not None else "<bare>"
            qual = ".".join(self.scope) or "<module>"
            self.found[f"{self.rel}::{qual}::{exc}::{stmt}"] += 1
        self.generic_visit(node)


def scan_source(source: str, rel: str) -> Counter[str]:
    collector = _Collector(rel)
    collector.visit(ast.parse(source))
    return collector.found


def compute_silent_excepts(root: Path) -> dict[str, int]:
    total: Counter[str] = Counter()
    for path in sorted((root / "fxapk").rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        total.update(scan_source(path.read_text(encoding="utf-8"), rel))
    return dict(sorted(total.items()))


def diff_against_baseline(current: dict[str, int], baseline: dict[str, int]) -> list[str]:
    problems: list[str] = []
    for key in sorted(set(current) | set(baseline)):
        now, base = current.get(key, 0), baseline.get(key, 0)
        if now > base:
            problems.append(f"新增静默 except（{base} → {now}）：{key}")
        elif now < base:
            problems.append(f"已修复，请从基线移除或下调（{base} → {now}）：{key}")
    return problems


def _read_payload() -> dict[str, dict[str, object]]:
    data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    return {str(k): dict(v) for k, v in data["entries"].items()}


def load_baseline() -> dict[str, int]:
    return {k: int(str(v["count"])) for k, v in _read_payload().items()}


def load_reasons() -> dict[str, str]:
    """每条存量都必须写明为什么可以静默；空理由由契约测试拦下。"""
    return {k: str(v.get("reason", "")) for k, v in _read_payload().items()}


def write_baseline(root: Path) -> dict[str, int]:
    """按现实重写次数，保留已有理由；新增键的理由留空，必须手工补写。"""
    entries = compute_silent_excepts(root)
    reasons = load_reasons() if BASELINE_PATH.exists() else {}
    payload = {
        "readme": _README,
        "entries": {k: {"count": n, "reason": reasons.get(k, "")} for k, n in entries.items()},
    }
    BASELINE_PATH.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return entries


def main(argv: list[str]) -> int:
    if argv != ["--write"]:
        print("用法：python -m tests.contracts.silent_except --write", file=sys.stderr)
        return 2
    entries = write_baseline(Path(__file__).resolve().parents[2])
    print(f"已写入 {BASELINE_PATH.name}：{len(entries)} 个键，共 {sum(entries.values())} 处")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
