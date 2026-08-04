"""``report.meta`` 键的静态扫描器 —— meta 契约机制的地基。

为什么需要它
------------

本项目反复栽同一类缺陷：某个分析器往 ``report.meta`` 写了一个信号，**下游根本没人读**。
历史上至少四次（``tier`` / ``dex_available`` / ``is_hardened`` / ``native_obfuscation``）。
实测一次全仓统计：183 个 meta 键里，32 个全仓零消费方、112 个不进任何渲染出口。

根因是结构性的：``report.meta`` 是 ``dict[str, Any]``，**谁都能写、写完没人管**，
而「少写一个消费者」不会让任何测试变红——缺席型缺陷是沉默的。
对照组 ``Endpoint.enrichment`` 零孤儿，因为它的键由富化器 ``provider`` 字段决定，
等于有一张隐式注册表。本模块就是把那张表对 meta 显式化的第一步。

★本模块自己必须有测试（见 ``test_meta_scan.py``）：它是整套机制的地基，
  它漏扫一种写法，基线就会把一个真孤儿漏登记，后面所有检查都建在错的集合上。

判据边界（诚实标注）
--------------------

- 只认**字面量**键。``meta[some_var]`` 一律记进 :attr:`ScanResult.unresolved`，
  **绝不静默跳过**——静默跳过等于给绕过留了一条无声的路。
- 别名传播只做一层（``m = state.meta`` 之后的 ``m["k"]`` 认得，
  再传一层 ``n = m`` 不认）。够用且可预测；不够时由 unresolved 兜底暴露。
- 不做跨文件的数据流分析。真正的兜底是运行期观测（另一路证据），不是这里。
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

#: 被视为 meta 容器的属性名。``X.meta`` / ``X.debug`` 之外的属性不认。
_META_ATTRS = frozenset({"meta"})
#: 直接以这些名字出现的局部变量也视为 meta 容器（本仓 pipeline 里的既有写法）。
_META_NAMES = frozenset({"meta", "_meta", "raw_meta", "merged_meta"})


@dataclass(frozen=True)
class Access:
    """一次 meta 访问。``kind`` 为 ``"write"`` 或 ``"read"``。"""

    key: str
    kind: str
    file: str
    line: int


@dataclass
class ScanResult:
    """扫描结果。★生产消费与测试消费**必须分开**——否则那 66 个「只有测试读」的键
    会假装合格通过检查，而它们恰恰是问题最集中的一批。"""

    produced: dict[str, list[Access]] = field(default_factory=dict)
    production_consumed: dict[str, list[Access]] = field(default_factory=dict)
    test_consumed: dict[str, list[Access]] = field(default_factory=dict)
    #: 无法解析为字面量的访问点（动态键）。绝不丢弃：它们是扫描器的已知盲区，必须可见。
    unresolved: list[Access] = field(default_factory=list)

    @property
    def written_keys(self) -> set[str]:
        return set(self.produced)

    def orphans(self) -> set[str]:
        """写了、但**生产代码**里没有任何读取方的键。"""
        return {k for k in self.produced if k not in self.production_consumed}


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str, out: list[Access]) -> None:
        self.path = path
        self.out = out
        self.aliases: set[str] = set()

    # -- 别名：m = state.meta / m = meta ---------------------------------
    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        if self._is_meta_expr(node.value):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.aliases.add(t.id)
        self.generic_visit(node)

    def _is_meta_expr(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Attribute) and node.attr in _META_ATTRS:
            return True
        if isinstance(node, ast.Name) and (node.id in _META_NAMES or node.id in self.aliases):
            return True
        # raw = report.get("meta") 之类
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get" and node.args
                and isinstance(node.args[0], ast.Constant) and node.args[0].value == "meta"):
            return True
        return False

    # -- 下标：meta["k"] = v（写） / x = meta["k"]（读）--------------------
    def visit_Subscript(self, node: ast.Subscript) -> None:  # noqa: N802
        if self._is_meta_expr(node.value):
            kind = "write" if isinstance(node.ctx, (ast.Store, ast.Del)) else "read"
            self._record(node.slice, kind, node.lineno)
        self.generic_visit(node)

    # -- 方法：meta.get("k") / setdefault / update / pop ------------------
    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        f = node.func
        if isinstance(f, ast.Attribute) and self._is_meta_expr(f.value):
            if f.attr in ("get", "pop"):
                if node.args:
                    self._record(node.args[0], "read", node.lineno)
            elif f.attr == "setdefault":
                if node.args:
                    self._record(node.args[0], "write", node.lineno)
            elif f.attr == "update":
                for a in node.args:
                    if isinstance(a, ast.Dict):
                        for k in a.keys:
                            self._record(k, "write", node.lineno)
                    else:  # meta.update(other_dict) —— 键不可知
                        self.out.append(Access("<dynamic:update>", "write",
                                               self.path, node.lineno))
                for kw in node.keywords:
                    if kw.arg:
                        self.out.append(Access(kw.arg, "write", self.path, node.lineno))
                    else:  # **kwargs
                        self.out.append(Access("<dynamic:update>", "write",
                                               self.path, node.lineno))
        self.generic_visit(node)

    def _record(self, key_node: ast.expr | None, kind: str, line: int) -> None:
        if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
            self.out.append(Access(key_node.value, kind, self.path, line))
        else:
            # ★动态键：记为 unresolved，绝不静默跳过
            self.out.append(Access("<dynamic>", kind, self.path, line))


def scan_source(src: str, path: str = "<mem>") -> list[Access]:
    """扫一段 Python 源码，返回全部 meta 访问点。语法错误直接抛（地基不容忍静默失败）。"""
    tree = ast.parse(src)
    out: list[Access] = []
    v = _Visitor(path, out)
    v.visit(tree)
    # 别名可能在使用之后才赋值（少见），再扫一遍让别名生效
    if v.aliases:
        out2: list[Access] = []
        v2 = _Visitor(path, out2)
        v2.aliases = set(v.aliases)
        v2.visit(tree)
        return out2
    return out


def scan_repository(root: Path, *, prod_dir: str = "apkscan",
                    test_dir: str = "tests") -> ScanResult:
    """扫全仓，按生产/测试分开归集。"""
    res = ScanResult()
    for sub, is_test in ((prod_dir, False), (test_dir, True)):
        base = root / sub
        if not base.is_dir():
            continue
        for py in sorted(base.rglob("*.py")):
            rel = str(py.relative_to(root)).replace("\\", "/")
            try:
                accesses = scan_source(py.read_text(encoding="utf-8"), rel)
            except SyntaxError:  # 语法错的文件必须暴露，不吞
                raise
            for a in accesses:
                if a.key.startswith("<dynamic"):
                    res.unresolved.append(a)
                elif a.kind == "write":
                    if not is_test:
                        res.produced.setdefault(a.key, []).append(a)
                else:
                    bucket = res.test_consumed if is_test else res.production_consumed
                    bucket.setdefault(a.key, []).append(a)
    return res


def scan_templates(root: Path) -> dict[str, list[Access]]:
    """扫 Jinja 模板里的 meta 读取。

    ★必须单独扫、且不复用 AST 逻辑：模板是另一套语法，而本仓模板里确有
      ``meta.get("uni_app")`` / ``meta.get("uniapp")`` 这类**兼容旧键**的读法——
      漏扫它们会把仍在被渲染的键误判成孤儿。
    """
    import re

    pat = re.compile(r"""meta(?:\.get\(\s*|\[\s*)["']([A-Za-z_][\w]*)["']""")
    out: dict[str, list[Access]] = {}
    for tpl in sorted(root.rglob("*.j2")):
        rel = str(tpl.relative_to(root)).replace("\\", "/")
        for i, line in enumerate(tpl.read_text(encoding="utf-8").splitlines(), 1):
            for m in pat.finditer(line):
                out.setdefault(m.group(1), []).append(Access(m.group(1), "read", rel, i))
    return out
