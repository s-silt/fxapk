"""同一 ``report.meta`` 键的多生产者「写入形状」扫描器 —— 契约 B 的地基。

为什么需要它
------------

``meta_scan`` 管「写了的键有没有人读」；本模块管「同一个键的多个写入方，写的
**字段集合**一不一致」。问题形态：``remote_config_artifacts`` 由
``pipeline._fetch_decode_one`` 与 ``cli._merge_config_probe_into_report`` 两处写，
消费方（``config/chain.py`` / ``corpus.py`` / ``closure/``）按字段名 ``art.get("...")``
取值——两边少一个字段，其中一条生产路径上就**静默取到 None**，没有任何测试会红。
这与 Lead 四步链是同一类病：每条路径单看自洽，全局不齐。

实现分工：写点**发现**复用 ``meta_scan``（receiver 判定、别名传播、setdefault/update
建模都在那边、且有自己的测试）；本模块只负责在已知写点上把「写进去的值」解析成
字面量键集（shape）。meta_scan 看得见的写点本模块解析不了时**必须记 unresolved**——
静默跳过等于给形状漂移留一条无声的路。

判据边界（诚实标注）
--------------------

- 只解析静态可证的形状来源：写点处的 dict/list 字面量、同函数内对该名字的
  ``.append({字面量})`` / ``.extend([{…}])``、``[helper(...) for …]`` 推导式里
  **同模块模块级 helper** 的 ``return {字面量}``、``setdefault(键, {字面量})``、
  绑定名上的 ``blob["字段"] = …`` / ``blob.update({…})``（并进字面量形状）。
- 绑定自 ``X.get(<同键>)`` / ``X[<同键>]`` 的名字不产形状：那是回读**已写**的值，
  其形状在写它的那个写点被检查，重复计会把旧值形状错算到本写点头上。
- 追不动的形态（未知函数返回值、名字逃逸进未知调用、未建模方法、helper 的非
  dict 返回路径）一律 unresolved → 契约红。宁可红了有人看，不可猜。
- 盲区（meta_scan 也看不见，本模块保护不了）：``meta[K].append(...)`` 这类不经过
  顶层写点的直接变异、``meta[K]["子键"] = v`` 嵌套写。当前仓库无此写法；出现时
  meta_scan 只记一次 read，两边都不红——这条边界写在这里，别当它被守着。
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from tests.contracts import meta_scan

#: 逃逸检查放行的只读内建：把名字传给它们不会加/删字段。
#: 白名单之外的一切调用都视为可能改形状 → unresolved（与 meta_scan 的
#: ``_MODELED_DICT_METHODS`` 同一纪律：只放行已建模的，其余如实不认）。
_BENIGN_CALLEES = frozenset({
    "len", "sorted", "list", "tuple", "set", "sum", "min", "max",
    "any", "all", "bool", "enumerate", "reversed", "isinstance", "print",
})

#: 名字上的只读方法：不影响键集。
_READ_METHODS = frozenset({"get", "keys", "values", "items", "copy", "index", "count"})

_FUNC_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef)
_SCOPE_DEFS = (*_FUNC_DEFS, ast.Lambda, ast.ClassDef)


@dataclass(frozen=True)
class Shape:
    """一个写点写入的一种字面量键集。``site_*`` 是写点（生产者），``origin``
    说明形状从哪条证据链解析出来（写点字面量 / append / helper 返回值…）。"""

    keys: frozenset[str]
    site_file: str
    site_function: str
    site_line: int
    origin: str


@dataclass
class ShapeReport:
    """一个 meta 键的全部生产者形状。``sites`` 单独暴露：契约层用它做生产者
    登记表的双向比对（防扫描器失明后契约空转）。"""

    key: str
    shapes: list[Shape] = field(default_factory=list)
    #: 解析不了的写点/形态描述。契约层必须把它当红——绝不静默。
    unresolved: list[str] = field(default_factory=list)
    #: (文件, 函数, 行) —— 被处理过的写点（含解析出 0 个形状的）。
    sites: list[tuple[str, str, int]] = field(default_factory=list)


def _const_str(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _dict_keys(d: ast.Dict) -> frozenset[str] | None:
    """字典字面量的键集；含 ``**`` 展开或非字符串字面量键 → None（不可证）。"""
    out: set[str] = set()
    for k in d.keys:
        v = _const_str(k)
        if v is None:
            return None
        out.add(v)
    return frozenset(out)


def _callee_simple_name(call: ast.Call) -> str:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def _helper_return_shapes(
    helper: ast.FunctionDef | ast.AsyncFunctionDef, path: str,
) -> tuple[list[tuple[frozenset[str], int]], list[str]]:
    """helper 的每条 ``return`` 解析成键集（键集, 行号）。只看 helper 自己的作用域
    （嵌套 def 的 return 不算它的）；``return`` 的一跳别名（名字恰好绑定一次到
    dict 字面量）认，其余返回路径 unresolved——helper 能返回非 dict 时，列表里
    就会混进消费方按字段取值必炸/必 None 的元素，这不是形状检查能默许的。
    """
    shapes: list[tuple[frozenset[str], int]] = []
    notes: list[str] = []
    binds: dict[str, int] = {}
    dict_binds: dict[str, ast.Dict] = {}
    returns: list[ast.Return] = []
    stack: list[ast.AST] = list(helper.body)
    while stack:
        node = stack.pop()
        if isinstance(node, _SCOPE_DEFS):
            continue  # 嵌套作用域的 return / 绑定不属于本 helper
        if isinstance(node, ast.Return):
            returns.append(node)
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name):
                    binds[t.id] = binds.get(t.id, 0) + 1
                    if isinstance(node.value, ast.Dict):
                        dict_binds[t.id] = node.value
        stack.extend(ast.iter_child_nodes(node))

    for ret in returns:
        v = ret.value
        keys = _dict_keys(v) if isinstance(v, ast.Dict) else None
        if keys is not None:
            shapes.append((keys, ret.lineno))
            continue
        if isinstance(v, ast.Name) and binds.get(v.id) == 1 and v.id in dict_binds:
            keys = _dict_keys(dict_binds[v.id])
            if keys is not None:
                shapes.append((keys, ret.lineno))
                continue
        notes.append(
            f"{path}:{ret.lineno} helper {helper.name} 存在解析不了的返回路径"
            "（非 dict 字面量/一跳别名）——该路径的元素形状不可证"
        )
    return shapes, notes


def _mutation_effects(
    fn: ast.AST, name: str, key: str, path: str,
) -> tuple[set[str], list[tuple[frozenset[str], int, str]], list[str]]:
    """名字 ``name`` 在函数子树内被怎样改：返回（并进 dict 形状的额外键，
    独立元素形状（append/extend 进列表的 dict），unresolved 说明）。

    逃逸如实记：名字被直接传给白名单外的调用后，形状在别处可被任意改，
    静态追不了——记 unresolved，不赌。
    """
    extra: set[str] = set()
    elements: list[tuple[frozenset[str], int, str]] = []
    notes: list[str] = []
    for node in ast.walk(fn):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            # ★别名逃逸：`tmp = arts` 之后，对 tmp 的任何变异都改着同一个对象，而下面只盯
            #   `name` 这个名字，一概看不见。同仓 meta_scan 的 _locally_built_dicts 把
            #   「搬去另一个名字」明确算作逃逸，这里对齐——它漏掉过一次，实证 `tmp = arts;
            #   tmp.append({...})` 能让整个生产者的形状静默地不参与比对。
            aliases = [t.id for t in targets
                       if isinstance(t, ast.Name) and t.id != name]
            if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Name)
                    and node.value.id == name and aliases):
                # 只认「赋给另一个**裸名字**」。写进下标/属性（`report.meta[k] = arts`、
                # `obj.field = arts`）是这个扫描器要找的**写点本身**，不是逃逸——
                # 第一版没做这个区分，把每个正常写点都判成了逃逸。
                notes.append(
                    f"{path}:{node.lineno} {name} 被搬去另一个名字（{', '.join(aliases)}）"
                    f"——此后经该别名做的改动追不回来，形状不可证")
            for t in targets:
                if (isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name)
                        and t.value.id == name):
                    k = _const_str(t.slice)
                    if k is None:
                        notes.append(f"{path}:{t.lineno} {name}[动态键] = … —— 键不可证")
                    else:
                        extra.add(k)
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == name:
            if f.attr == "append":
                arg = node.args[0] if node.args else None
                keys = _dict_keys(arg) if isinstance(arg, ast.Dict) else None
                if keys is None:
                    notes.append(
                        f"{path}:{node.lineno} {name}.append(非 dict 字面量) —— 元素形状不可证")
                else:
                    elements.append((keys, node.lineno, f"append 字面量(行 {node.lineno})"))
            elif f.attr == "extend":
                arg = node.args[0] if node.args else None
                ok = False
                if isinstance(arg, ast.List):
                    ok = True
                    for elt in arg.elts:
                        keys = _dict_keys(elt) if isinstance(elt, ast.Dict) else None
                        if keys is None:
                            ok = False
                            break
                        elements.append((keys, elt.lineno, f"extend 字面量(行 {elt.lineno})"))
                if not ok:
                    notes.append(
                        f"{path}:{node.lineno} {name}.extend(非字面量列表) —— 元素形状不可证")
            elif f.attr == "update":
                arg = node.args[0] if node.args else None
                keys = _dict_keys(arg) if isinstance(arg, ast.Dict) else None
                if node.args and keys is None:
                    notes.append(
                        f"{path}:{node.lineno} {name}.update(非 dict 字面量) —— 新增键不可证")
                elif keys is not None:
                    extra.update(keys)
                extra.update(kw.arg for kw in node.keywords if kw.arg)
                if any(kw.arg is None for kw in node.keywords):
                    notes.append(f"{path}:{node.lineno} {name}.update(**…) —— 新增键不可证")
            elif f.attr in _READ_METHODS:
                pass
            else:
                notes.append(
                    f"{path}:{node.lineno} {name}.{f.attr}(…) 未建模——可能改键集，形状不可证")
            continue
        # 逃逸：名字直接作为参数传给白名单外的调用
        passed = any(isinstance(a, ast.Name) and a.id == name for a in node.args) or any(
            isinstance(kw.value, ast.Name) and kw.value.id == name for kw in node.keywords
        )
        if passed and _callee_simple_name(node) not in _BENIGN_CALLEES:
            notes.append(
                f"{path}:{node.lineno} {name} 被传给 {_callee_simple_name(node) or '?'}(…)"
                " —— 逃逸后形状可在别处被改，静态追不了")
    return extra, elements, notes


def _resolve_value(
    value: ast.expr,
    fn: ast.AST,
    bound_names: list[str],
    site: tuple[str, str, int],
    key: str,
    module_funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    report: ShapeReport,
) -> None:
    """把写点右值解析成形状，登记进 report。解析不了 → unresolved。"""
    path, fn_name, line = site

    def _add(keys: frozenset[str], origin: str) -> None:
        report.shapes.append(Shape(keys, path, fn_name, line, origin))

    if isinstance(value, ast.Dict):
        keys = _dict_keys(value)
        if keys is None:
            report.unresolved.append(f"{path}:{value.lineno} 写点 dict 字面量含不可证键（**展开/动态键）")
            return
        extra: set[str] = set()
        for name in bound_names:
            more, elements, notes = _mutation_effects(fn, name, key, path)
            extra |= more
            report.unresolved.extend(notes)
            for e_keys, _e_line, e_origin in elements:
                _add(e_keys, e_origin)
        _add(keys | extra, f"写点 dict 字面量(行 {value.lineno})")
        return

    if isinstance(value, ast.List):
        for elt in value.elts:
            keys = _dict_keys(elt) if isinstance(elt, ast.Dict) else None
            if keys is None:
                report.unresolved.append(
                    f"{path}:{elt.lineno} 写点列表字面量含非 dict 字面量元素——形状不可证")
            else:
                _add(keys, f"列表字面量元素(行 {elt.lineno})")
        return

    if isinstance(value, ast.Name):
        _resolve_name(value.id, fn, site, key, module_funcs, report)
        return

    report.unresolved.append(
        f"{path}:{line} 写点右值形态追不了（{type(value).__name__}）——请改成可证形态或扩展扫描器")


def _resolve_name(
    name: str,
    fn: ast.AST,
    site: tuple[str, str, int],
    key: str,
    module_funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    report: ShapeReport,
) -> None:
    """写点右值是名字：在同函数作用域内追它的绑定与变异。"""
    path, fn_name, line = site

    def _add(keys: frozenset[str], origin: str) -> None:
        report.shapes.append(Shape(keys, path, fn_name, line, origin))

    # 进来时的计数：末尾用它判断本次解析到底产出了什么（形状 or 说明），
    # 而不是去数整个 report——别的写点写进去的不算本写点的交代。
    shapes_before = len(report.shapes)
    notes_before = len(report.unresolved)

    dict_bind_keys: list[tuple[frozenset[str], int]] = []
    #: 这个名字**有没有**在本函数里被绑定过（无论形态可不可证）。用来区分两种情形：
    #: 「绑定了但形态追不了」（下面各分支已各自记 unresolved）与「压根没找到任何绑定」
    #: （函数参数、AugAssign、walrus…）——后者曾经**什么都不记**，于是这个生产者的形状
    #: 静默地不参与比对，而契约要防的正是这种静默。
    bound_anywhere = False
    for node in ast.walk(fn):
        # AugAssign(`x += [...]`)与 walrus(`(x := ...)`)也是绑定：不认它们，
        # 这个名字就会被当成"从未绑定"，而下面的兜底又只报一次泛泛的 unresolved。
        # 认出来才能落到各自的形态分支上、给出说得出口的理由。
        if isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and node.target.id == name:
                bound_anywhere = True
                report.unresolved.append(
                    f"{path}:{node.lineno} {name} 由增量赋值（{type(node.op).__name__}）构造"
                    "——累积形状不可证")
            continue
        if isinstance(node, ast.NamedExpr):
            if isinstance(node.target, ast.Name) and node.target.id == name:
                bound_anywhere = True
                report.unresolved.append(
                    f"{path}:{node.lineno} {name} 由海象表达式绑定——形状不可证")
            continue
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(t, ast.Name) and t.id == name for t in targets):
            continue
        bound_anywhere = True
        v = node.value
        if v is None:
            continue
        if isinstance(v, ast.Dict):
            keys = _dict_keys(v)
            if keys is None:
                report.unresolved.append(f"{path}:{v.lineno} {name} 绑定的 dict 字面量含不可证键")
            else:
                dict_bind_keys.append((keys, v.lineno))
        elif isinstance(v, ast.List):
            for elt in v.elts:
                keys = _dict_keys(elt) if isinstance(elt, ast.Dict) else None
                if keys is None:
                    report.unresolved.append(
                        f"{path}:{elt.lineno} {name} 绑定的列表含非 dict 字面量元素")
                else:
                    _add(keys, f"列表字面量元素(行 {elt.lineno})")
        elif isinstance(v, (ast.ListComp, ast.GeneratorExp)):
            elt = v.elt
            helper = None
            if isinstance(elt, ast.Call) and isinstance(elt.func, ast.Name):
                helper = module_funcs.get(elt.func.id)
            if helper is None:
                report.unresolved.append(
                    f"{path}:{v.lineno} {name} 由推导式产生但元素不是同模块模块级 helper 的调用"
                    "——形状不可证")
            else:
                shapes, notes = _helper_return_shapes(helper, path)
                report.unresolved.extend(notes)
                for keys, r_line in shapes:
                    _add(keys, f"helper {helper.name} 返回值(行 {r_line})")
        elif isinstance(v, ast.Call):
            callee = _callee_simple_name(v)
            arg0 = _const_str(v.args[0]) if v.args else None
            if callee in ("get", "setdefault") and arg0 == key:
                pass  # 回读/复用已写值：形状在写它的写点被检查，这里不重复计
            else:
                report.unresolved.append(
                    f"{path}:{v.lineno} {name} 绑定自调用 {callee or '?'}(…)——返回形状不可证")
        elif isinstance(v, ast.Subscript) and _const_str(v.slice) == key:
            pass  # 回读同键
        else:
            report.unresolved.append(
                f"{path}:{v.lineno} {name} 的绑定形态追不了（{type(v).__name__}）")

    extra, elements, notes = _mutation_effects(fn, name, key, path)
    report.unresolved.extend(notes)
    for keys, _e_line, origin in elements:
        _add(keys, origin)
    for keys, b_line in dict_bind_keys:
        _add(keys | extra, f"dict 字面量绑定(行 {b_line})")
    if not dict_bind_keys and extra:
        report.unresolved.append(
            f"{path}:{line} {name} 有下标/update 写入但没有可证的 dict 字面量绑定"
            "——新增键并不进任何形状，不可证")
    # ★兜底：走到这里若既没解析出任何形状、也没记下任何 unresolved，说明这个名字的来源
    #   本扫描器完全没建模（最常见的是**函数参数**：值从调用方传进来，同函数内看不到绑定）。
    #   曾经这种情形静默通过——生产者 site 照常登记、形状集为空、于是它永远不参与比对。
    #   契约 B 防的就是"缺字段静默取到 None"，扫描器自己却在解析层复刻了同一个错误。
    #   宁可红：解析不了就说解析不了，别让沉默冒充通过。
    produced_nothing = (
        len(report.shapes) == shapes_before and len(report.unresolved) == notes_before
    )
    if not bound_anywhere and produced_nothing:
        report.unresolved.append(
            f"{path}:{line} {name} 在本函数内找不到任何绑定（多半是函数参数，值来自调用方）"
            "——形状不可证；请改为在本函数内构造字面量，或把该生产路径显式登记豁免")


def _scan_file(src: str, path: str, wanted: set[int], key: str, report: ShapeReport) -> None:
    """在一个文件里定位 meta_scan 已确认的写点并解析形状。语法错误直接抛。"""
    tree = ast.parse(src)
    module_funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {
        n.name: n for n in tree.body if isinstance(n, _FUNC_DEFS)
    }
    matched: set[int] = set()

    def _consider(stmt: ast.stmt, fn: ast.AST | None) -> None:
        fn_name = fn.name if isinstance(fn, _FUNC_DEFS) else "<module>"
        scope: ast.AST = fn if fn is not None else tree

        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            value = stmt.value
            name_targets = [t.id for t in targets if isinstance(t, ast.Name)]
            # 形态①：X[键] = 值
            for t in targets:
                if (isinstance(t, ast.Subscript) and _const_str(t.slice) == key
                        and t.lineno in wanted and t.lineno not in matched
                        and value is not None):
                    matched.add(t.lineno)
                    site = (path, fn_name, t.lineno)
                    report.sites.append(site)
                    _resolve_value(value, scope, [], site, key, module_funcs, report)
            # 形态②：N = X.setdefault(键, 默认值) —— 默认值即写入形状，且 N 的后续
            # 下标写会长在同一个对象上，必须并进形状。
            if (isinstance(value, ast.Call)
                    and _callee_simple_name(value) == "setdefault"
                    and value.args and _const_str(value.args[0]) == key
                    and value.lineno in wanted and value.lineno not in matched):
                matched.add(value.lineno)
                site = (path, fn_name, value.lineno)
                report.sites.append(site)
                if len(value.args) >= 2:
                    _resolve_value(value.args[1], scope, name_targets, site, key,
                                   module_funcs, report)
                else:
                    report.unresolved.append(f"{path}:{value.lineno} setdefault 无默认值参数")
        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            call = stmt.value
            callee = _callee_simple_name(call)
            # 形态③：裸 X.setdefault(键, {…})
            if (callee == "setdefault" and call.args and _const_str(call.args[0]) == key
                    and call.lineno in wanted and call.lineno not in matched):
                matched.add(call.lineno)
                site = (path, fn_name, call.lineno)
                report.sites.append(site)
                if len(call.args) >= 2:
                    _resolve_value(call.args[1], scope, [], site, key, module_funcs, report)
            # 形态④：X.update({键: 值, …})
            elif (callee == "update" and call.args and isinstance(call.args[0], ast.Dict)
                    and call.lineno in wanted and call.lineno not in matched):
                for k_node, v_node in zip(call.args[0].keys, call.args[0].values):
                    if _const_str(k_node) == key:
                        matched.add(call.lineno)
                        site = (path, fn_name, call.lineno)
                        report.sites.append(site)
                        _resolve_value(v_node, scope, [], site, key, module_funcs, report)

    def _walk(node: ast.AST, fn: ast.AST | None) -> None:
        for child in ast.iter_child_nodes(node):
            next_fn = child if isinstance(child, _FUNC_DEFS) else fn
            if isinstance(child, ast.stmt):
                _consider(child, next_fn if isinstance(child, _FUNC_DEFS) else fn)
            _walk(child, next_fn)

    _walk(tree, None)

    for line in sorted(wanted - matched):
        report.unresolved.append(
            f"{path}:{line} meta_scan 记到 {key!r} 的写点，但形状扫描器不认识该写法"
            "——扩展 meta_shape_scan 或把写法收拢成可证形态，别让形状检查漏这一处")


def collect_shapes(
    root: Path, key: str, *, prod_dir: str = "apkscan",
    scan: meta_scan.ScanResult | None = None,
) -> ShapeReport:
    """全仓收集一个 meta 键的生产者形状。写点由 meta_scan（有测试的地基）发现，
    本模块只解析形状——两层各自可测，谁失明谁的测试红。

    ``scan`` 允许复用一次算好的 meta_scan 结果（全仓扫描是本测试套里最贵的一步，
    逐键重扫纯属浪费）；不传则自己扫。
    """
    res = scan if scan is not None else meta_scan.scan_repository(root, prod_dir=prod_dir)
    report = ShapeReport(key=key)
    by_file: dict[str, set[int]] = {}
    for a in res.produced.get(key, []):
        by_file.setdefault(a.file, set()).add(a.line)
    for file, lines in sorted(by_file.items()):
        src = (root / file).read_text(encoding="utf-8")
        _scan_file(src, file, lines, key, report)
    return report


def diff_shapes(
    report: ShapeReport, declared_variants: dict[frozenset[str], str],
) -> list[str]:
    """契约判定：全部未声明形状必须键集一致；变体必须显式声明且仍然存在；
    每个生产者都必须写得出主形状。返回问题清单（空 = 契约成立）。"""
    problems = [
        f"形状解析不了（先让代码可证或扩展扫描器，别静默）：{u}" for u in report.unresolved
    ]
    if not report.shapes:
        if not problems:
            problems.append(
                f"meta 键 {report.key!r} 没扫到任何写入形状——契约空转"
                "（写点消失或全部退化），请核对生产代码与登记表")
        return problems

    undeclared: dict[frozenset[str], list[Shape]] = {}
    for s in report.shapes:
        if s.keys not in declared_variants:
            undeclared.setdefault(s.keys, []).append(s)

    if not undeclared:
        problems.append(
            f"{report.key!r} 的所有形状都是已声明变体，没有任何生产者写出主形状"
            "——变体声明失去参照，检查退化为自说自话")
    elif len(undeclared) > 1:
        ref = max(undeclared, key=lambda ks: (len(undeclared[ks]), sorted(ks)))
        for ks in sorted(undeclared, key=sorted):
            locs = ", ".join(
                f"{s.site_file}::{s.site_function}(行 {s.site_line}, {s.origin})"
                for s in undeclared[ks]
            )
            if ks == ref:
                problems.append(f"{report.key!r} 主形状分裂：参照键集 {sorted(ks)} ← {locs}")
            else:
                problems.append(
                    f"{report.key!r} 主形状分裂：{locs} 相对参照缺 {sorted(ref - ks)} / "
                    f"多 {sorted(ks - ref)}——消费方按字段名取值，缺字段的那条生产路径会静默取到 None")

    producers = {(s.site_file, s.site_function, s.site_line) for s in report.shapes}
    covered = {
        (s.site_file, s.site_function, s.site_line)
        for shapes in undeclared.values() for s in shapes
    }
    for p in sorted(producers - covered):
        problems.append(
            f"{report.key!r} 的生产者只写已声明变体、从不写主形状：{p[0]}::{p[1]}(行 {p[2]})"
            "——要么它缺字段，要么变体声明已经名不副实")

    observed = {s.keys for s in report.shapes}
    for ks in sorted(set(declared_variants) - observed, key=sorted):
        problems.append(
            f"{report.key!r} 的变体声明已过期（现实中无人再写这个键集）：{sorted(ks)}"
            f"（声明理由：{declared_variants[ks]}）——请删除声明，过期豁免会吞掉将来的真漂移")
    return problems
