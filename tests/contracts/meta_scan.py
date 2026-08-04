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

#: 真正持有报告 meta 的构造器。``f(meta=...)`` 只在这些之上才算写入——
#: 否则 ``template.render(meta=...)`` 这类纯传参会被误算成创造键（复审实证）。
_META_BEARING_CTORS = frozenset({"AnalyzerResult", "Report"})

#: 生成「有限键族」的工厂函数：``函数名 -> 族名``。
#: ★这类键在运行时拼出，但**定义域静态封闭**（有限后缀表 × 权威注册表里的分析器名），
#:   属于 Codex 分类里的 C 类「有限模板族」，不是开放动态键——
#:   它们记录的是「我没看全」，绝不能因为写法动态就被排除在契约之外。
_KEY_FAMILY_FUNCS: dict[str, str] = {
    "coverage_meta_key": "web_coverage",
}


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
    #: 有限键族的访问点（``<family:族名:后缀>``）。定义域静态封闭，不算盲区。
    #: ★展开成具体键**由契约层负责**——展开需要权威分析器注册表，
    #:   而扫描器刻意不 import 生产模块（import 会执行代码，地基不该有副作用）。
    families: list[Access] = field(default_factory=list)

    @property
    def written_keys(self) -> set[str]:
        return set(self.produced)

    def orphans(self) -> set[str]:
        """写了、但**生产代码**里没有任何读取方的键。"""
        return {k for k in self.produced if k not in self.production_consumed}


def collect_module_constants(src: str) -> dict[str, str]:
    """收集模块级的字符串常量 ``NAME = "literal"``，供常量键解析。

    ★为什么解析常量而不是把它们列进豁免名单：豁免名单会不断增长，最终变成动态访问的
      逃生口；常量被重命名时基线看不到键变化；而且豁免抹掉了「固定常量」与「真正开放的
      ``meta[key]``」之间的区别——后者才是必须堵的绕过通道。

    ★边界刻意收窄，**不执行 Python、不 import 生产模块**：只认模块级的
      ``NAME = "字符串字面量"``。条件赋值、函数调用、f-string、重赋值一律不认，
      认不出就落回 unresolved——宁可少认，不可猜错。
    """
    #: 名字 → 绑定次数。★只有**恰好绑定一次**、且那一次是顶层简单字面量赋值的，才算常量。
    #:   不比较值是否相同：早先写成「值不同才 pop」，于是 ``a → b → c`` 三次赋值后
    #:   ``c`` 会被重新接受（复审实测）。解析错比不解析更糟——把真实键登记成错名字，
    #:   基线从此建在错的集合上，而且是无声的。
    binds: dict[str, int] = {}
    literals: dict[str, str] = {}

    def _bind(name: str, value: str | None = None) -> None:
        binds[name] = binds.get(name, 0) + 1
        if value is not None and name not in literals:
            literals[name] = value

    try:
        tree = ast.parse(src)
    except SyntaxError:
        return {}

    # ★不枚举语句类型，而是**统一收集模块作用域内的一切绑定**（复审建议）：
    #   walrus、match capture、except-as、类/函数定义、解构、AsyncFor/With……
    #   逐个枚举必然漏，而漏一个就意味着可能解析出过期值。
    #   comprehension 是独立作用域，其绑定不泄漏，故显式跳过。
    _NESTED_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
                      ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)

    def _all_bindings(n: ast.AST, skip: set[int] | None = None) -> None:
        """收集本作用域的每一次名字绑定。``skip`` 里的节点已被顶层字面量赋值计过，不重复计。"""
        skip = skip or set()
        for child in ast.iter_child_nodes(n):
            if id(child) in skip:
                continue
            if isinstance(child, _NESTED_SCOPES):
                # 函数/lambda/推导式：自身的名字**是**一次模块级绑定（def K(): ...）
                name = getattr(child, "name", None)
                if name:
                    _bind(name, None)
                continue
            if isinstance(child, ast.ClassDef):
                _bind(child.name, None)  # 类名绑定；类体是独立作用域，不下探
                continue
            if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
                _bind(child.id, None)
            elif isinstance(child, (ast.Import, ast.ImportFrom)):
                for a in child.names:
                    _bind(a.asname or a.name.split(".")[0], None)
            elif isinstance(child, ast.ExceptHandler) and child.name:
                _bind(child.name, None)
            _all_bindings(child, skip)

    # 顶层「简单字面量赋值」带值记一次绑定；其余一切绑定形态由 _all_bindings 记（不带值）。
    simple: set[int] = set()
    for node in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = list(node.targets), node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        for t in targets:
            if isinstance(t, ast.Name):
                _bind(t.id, value.value)
                simple.add(id(t))  # 标记：这次绑定已计过，_all_bindings 里跳过

    _all_bindings(tree, skip=simple)
    # ★只保留恰好绑定一次的：多于一次 = 被重赋值/遮蔽/导入覆盖过，一律不解析
    return {k: v for k, v in literals.items() if binds.get(k) == 1}


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str, out: list[Access],
                 consts: dict[str, str] | None = None,
                 imported: dict[str, dict[str, str]] | None = None) -> None:
        self.path = path
        self.out = out
        self.aliases: set[str] = set()
        #: 本模块的字符串常量（含 from-import 带进来的）
        self.consts: dict[str, str] = dict(consts or {})
        #: ``模块别名 -> {常量名: 值}``，供 ``_inv.INVENTORY_META_KEY`` 这类跨模块引用解析
        self.imported: dict[str, dict[str, str]] = dict(imported or {})

    def _scoped(self, node: ast.AST) -> None:
        """进入函数体：**局部绑定同名的模块常量在本作用域内不解析**。

        ★复审实测：函数内 ``K = "b"`` 会让模块级 ``K = "a"`` 被误用成 "a"。
          静态看不出哪个绑定生效，宁可落 unresolved。
        """
        # ★只收**本作用域**的绑定，不穿透嵌套函数/类/comprehension：
        #   Python 3 里那些是独立作用域，它们的绑定不泄漏到外层。
        #   穿透会把本可安全解析的常量误失效，虚增 unresolved（复审实证）。
        local: set[str] = set()
        _NESTED = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda,
                   ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)

        def _walk_own(n: ast.AST) -> None:
            for child in ast.iter_child_nodes(n):
                if isinstance(child, _NESTED):
                    continue  # 独立作用域，其绑定不影响本层
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                    local.add(child.id)
                elif isinstance(child, ast.arg):
                    local.add(child.arg)
                elif isinstance(child, (ast.Import, ast.ImportFrom)):
                    for a in child.names:
                        local.add(a.asname or a.name.split(".")[0])
                elif isinstance(child, ast.ExceptHandler) and child.name:
                    local.add(child.name)
                _walk_own(child)

        fn_args = getattr(node, "args", None)
        if fn_args is not None:
            for a in list(fn_args.args) + list(fn_args.posonlyargs) + list(fn_args.kwonlyargs):
                local.add(a.arg)
        _walk_own(node)
        shadowed = {k: v for k, v in self.consts.items() if k not in local}
        saved = self.consts
        self.consts = shadowed
        try:
            for child in ast.iter_child_nodes(node):
                self.visit(child)
        finally:
            self.consts = saved

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._scoped(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._scoped(node)

    # -- 别名：m = state.meta / m = meta ---------------------------------
    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        if self._is_meta_expr(node.value):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.aliases.add(t.id)
        # ★整体字典赋值：``result.meta = {"a": 1, "b": 2}``。
        #   本仓真实写法（analyzers/permissions.py、remote_config.py 等），
        #   而且**路径 A 最初就漏了它**——是运行期观测（路径 C）把这 7 个键抓出来的。
        #   这正是「不能让单一扫描器既生成真相又验证自己的真相」的实证。
        for t in node.targets:
            if self._is_meta_target(t):
                if isinstance(node.value, ast.Dict):
                    for k in node.value.keys:
                        self._record(k, "write", node.lineno)
                elif not self._is_meta_expr(node.value):
                    # ★整体赋一个**非字典字面量**（``result.meta = build_meta()``）：
                    #   键完全不可知，必须记进 unresolved。此前这里没有兜底，
                    #   这类写法被静默跳过——与「动态键绝不静默跳过」的核心保证冲突，
                    #   且会让「已无开放写入」这个结论假成立（复审实测指出）。
                    self.out.append(Access("<dynamic:whole-meta>", "write",
                                           self.path, node.lineno))
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        """带类型标注的整体赋值：``meta: dict = {...}``（core/pipeline.py 的写法）。"""
        if self._is_meta_target(node.target) and node.value is not None:
            if isinstance(node.value, ast.Dict):
                for k in node.value.keys:
                    self._record(k, "write", node.lineno)
            elif not self._is_meta_expr(node.value):
                self.out.append(Access("<dynamic:whole-meta>", "write",
                                       self.path, node.lineno))
        if node.value is not None and self._is_meta_expr(node.value):
            if isinstance(node.target, ast.Name):
                self.aliases.add(node.target.id)
        self.generic_visit(node)

    def _is_meta_target(self, node: ast.expr) -> bool:
        """赋值左侧是不是**报告的 meta 容器本身**（而非它的某个键）。

        ★只认属性形态 ``X.meta``，**不认裸变量名**。复审实测：认裸名会把一堆无关东西
          当成开放写入——`merge.py` 里叫 `merged_meta` 的 crypto 子字典、
          `pcap_ingest.py` 里叫 `meta` 的 QUIC 包头解析结果、以及任何函数内的
          `meta = {...}` 局部变量。19 处「开放整体写入」全是这么误报出来的。

        ★下标访问（``meta["k"] = v``）仍认裸名：那种写法在本仓确实指 report meta，
          且键是具体的、可登记的——两者的误判代价不同。
        """
        return isinstance(node, ast.Attribute) and node.attr in _META_ATTRS

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
        # ★构造时传入：``AnalyzerResult(meta={"a": 1})`` / ``f(..., meta={...})``。
        #   与整体赋值同源的盲区，一并认。
        # ★只认**已知的 meta 载体构造器**：`template.render(meta=...)`、
        #   `foo(meta=bar)` 这类传参不创造报告 meta 键，全算写入会造出大量误报（实证）。
        ctor = node.func.id if isinstance(node.func, ast.Name) else (
            node.func.attr if isinstance(node.func, ast.Attribute) else "")
        if ctor in _META_BEARING_CTORS:
            for kw in node.keywords:
                if kw.arg in _META_ATTRS:
                    if isinstance(kw.value, ast.Dict):
                        for k in kw.value.keys:
                            self._record(k, "write", node.lineno)
                    elif not self._is_meta_expr(kw.value):
                        self.out.append(Access("<dynamic:whole-meta>", "write",
                                               self.path, node.lineno))
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

    def _resolve_key(self, node: ast.expr | None) -> str | None:
        """把键节点解析成字面量字符串；解析不出返回 None（→ unresolved，绝不猜）。"""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        # 本模块常量：meta[DEX_TRUNCATED_META_KEY]
        if isinstance(node, ast.Name):
            return self.consts.get(node.id)
        # 跨模块一跳：meta[_inv.INVENTORY_META_KEY]
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            return self.imported.get(node.value.id, {}).get(node.attr)
        # ★有限键族：``meta[coverage_meta_key(analyzer, "read_failed")]``。
        #   键名运行时拼出，但**定义域静态封闭**（有限后缀表 × 权威注册表里的分析器名），
        #   属 C 类「有限模板族」，不是开放动态键——它们记的是「我没看全」，
        #   绝不能因为写法动态就被排除在契约之外。返回族标记，具体键由契约层展开。
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in _KEY_FAMILY_FUNCS
                and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)):
            return f"<family:{_KEY_FAMILY_FUNCS[node.func.id]}:{node.args[1].value}>"
        return None

    def _record(self, key_node: ast.expr | None, kind: str, line: int) -> None:
        key = self._resolve_key(key_node)
        if key is not None:
            self.out.append(Access(key, kind, self.path, line))
        else:
            # ★动态键：记为 unresolved，绝不静默跳过
            self.out.append(Access("<dynamic>", kind, self.path, line))


def _import_map(src: str, symbols: dict[str, dict[str, str]]) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    """解析本模块的 import，返回 (从别处 from-import 进来的常量, 模块别名 → 常量表)。

    ★只走一跳、不解析星号导入、不解析重导出。解析不出就落回 unresolved。
    """
    from_consts: dict[str, str] = {}
    alias_map: dict[str, dict[str, str]] = {}
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return from_consts, alias_map
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and not node.level:
            # ★按**完整模块路径**查表，不用短名：本仓已有 apkscan.commands.corpus 与
            #   apkscan.core.corpus 同名，短名做键会把两张常量表合并、无声取到错的那张。
            #   相对导入（level>0）不解析——解析它要还原当前 package，超出「不猜」的边界。
            table = symbols.get(node.module, {})
            for a in node.names:
                if a.name == "*":
                    continue  # 星号导入不解析
                if a.name in table:
                    from_consts[a.asname or a.name] = table[a.name]
                else:  # from apkscan.core import runtime_inventory as _inv
                    full = f"{node.module}.{a.name}"
                    if full in symbols:
                        alias_map[a.asname or a.name] = symbols[full]
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name in symbols:
                    alias_map[a.asname or a.name.split(".")[-1]] = symbols[a.name]
    return from_consts, alias_map


def scan_source(src: str, path: str = "<mem>",
                symbols: dict[str, dict[str, str]] | None = None) -> list[Access]:
    """扫一段 Python 源码，返回全部 meta 访问点。语法错误直接抛（地基不容忍静默失败）。

    ``symbols`` 是 ``模块短名 → {常量名: 值}`` 的全仓符号表，供跨模块常量键解析。
    """
    tree = ast.parse(src)
    consts = collect_module_constants(src)
    from_consts, alias_map = _import_map(src, symbols or {})
    consts.update(from_consts)

    def _run() -> list[Access]:
        out: list[Access] = []
        v = _Visitor(path, out, consts=consts, imported=alias_map)
        v.visit(tree)
        if v.aliases:  # 别名可能在使用之后才赋值，再扫一遍让它生效
            out2: list[Access] = []
            v2 = _Visitor(path, out2, consts=consts, imported=alias_map)
            v2.aliases = set(v.aliases)
            v2.visit(tree)
            return out2
        return out

    return _run()


def scan_repository(root: Path, *, prod_dir: str = "apkscan",
                    test_dir: str = "tests") -> ScanResult:
    """扫全仓，按生产/测试分开归集。"""
    res = ScanResult()
    # ★先建全仓符号表：常量键（meta[DEX_TRUNCATED_META_KEY]）要靠它解析成真实键名。
    #   这是「解析而非豁免」的实现基础——豁免会不断增长成动态访问的逃生口。
    #   ★键是**完整模块路径**（apkscan.core.runtime_inventory），不是文件名短名：
    #     本仓已有 apkscan.commands.corpus 与 apkscan.core.corpus 同名，
    #     用短名会把两张常量表合并、后扫描者无声覆盖前者。
    symbols: dict[str, dict[str, str]] = {}
    for sub in (prod_dir, test_dir):
        base = root / sub
        if base.is_dir():
            for py in base.rglob("*.py"):
                consts = collect_module_constants(py.read_text(encoding="utf-8", errors="ignore"))
                if not consts:
                    continue
                parts = list(py.relative_to(root).with_suffix("").parts)
                if parts and parts[-1] == "__init__":
                    parts.pop()
                symbols[".".join(parts)] = consts

    for sub, is_test in ((prod_dir, False), (test_dir, True)):
        base = root / sub
        if not base.is_dir():
            continue
        for py in sorted(base.rglob("*.py")):
            rel = str(py.relative_to(root)).replace("\\", "/")
            try:
                accesses = scan_source(py.read_text(encoding="utf-8"), rel, symbols=symbols)
            except SyntaxError:  # 语法错的文件必须暴露，不吞
                raise
            for a in accesses:
                if a.key.startswith("<family:"):
                    res.families.append(a)
                elif a.key.startswith("<dynamic"):
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
