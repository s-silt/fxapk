"""Lead 生产链「四步必经」的静态扫描器 —— 契约 A 的地基。

为什么需要它
------------

往 ``report.leads`` 追加 DOMAIN/IP 线索的每条生产路径都必须走完同样四步::

    build_endpoint_leads → _apply_default_advice → seal_base_advice → apply_repack_quarantine

这四步不是风格约定，缺任何一步都有具体后果（见 :data:`STEP_CONSEQUENCES`）。
2026-08 实发生：config-probe 跨轮回灌（``cli._merge_config_probe_into_report``）新接进
出口时只做了前三步、漏了 ``apply_repack_quarantine``——重打包件（正版 App 被重签名）里
取回的域名属**被仿冒的正版厂商**，以最高档直达文书套打 / IOC 导出 / HTML
红标。这类缺陷**读代码看不出来**：每条路径单看都自洽，只有把「所有调用点 × 四步齐备」
摆到一张表上才暴露。本模块就是那张表的生成器。

与 ``meta_scan`` 的分工：meta_scan 管「写了的信号有没有人读」（缺席型），本模块管
「读/写序列走没走全」（步骤型）。两者同属一类病：单条路径自洽、全局不齐。

判据边界（诚实标注）
--------------------

- 调用点靠**发现**不靠清单：凡生产代码里对 ``build_endpoint_leads`` 的调用（``Name``
  或 ``Attribute`` 形态）都算一条生产路径。硬编码已知调用点的清单在第 N+1 条路径
  出现时照样漏——那正是这次事故的形态。
- 「同一函数作用域」= 调用点所在（最内层）函数的整个子树；步骤也可以在它**直接调用的
  同模块模块级 helper** 里（一跳、不递归、不跨模块）。跨模块 helper / 两跳以上 /
  调用点藏在嵌套函数而步骤在外层——这些形态本扫描器如实不认，出现即红，作者要么
  收拢结构、要么显式豁免。宁可红了有人看，不可扫描器假装看懂。
- 把 ``build_endpoint_leads`` 赋给变量 / 当参数传递等**间接引用**，静态追不了数据流，
  一律记违规——静默放过等于给绕过留一条无声的路。
- 豁免必须显式：在调用点所在函数的 ``def`` 行加 ``# lead-chain: exempt <理由>``，
  理由不能为空；挂在不含调用点的函数上算过期豁免，同样红。当前生产代码应为 0 个豁免。
- 只扫生产目录；注释 / docstring 里的提及不是 AST 调用节点，天然不算调用点。
- 步骤检测走整个函数子树：函数里「定义了却从未调用」的嵌套函数若含步骤调用，会被误认
  已做。该绕过形态需要刻意构造，不是本契约要防的「忘了调」这类事故形态，如实记为盲区。
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

#: 生产链入口。对它的每个生产代码调用点都是一条「必须四步走全」的路径。
ENTRY = "build_endpoint_leads"

#: 每一步缺席的后果——报错信息直接引用，让红的时候能看懂「为什么必须补」。
STEP_CONSEQUENCES: dict[str, str] = {
    "_apply_default_advice": (
        "advice 为空的线索会直通出口：报告的研判建议列空白，"
        "letters / ioc / closure 这些按 advice 字面档位筛选的出口对空档位行为不定。"
    ),
    "seal_base_advice": (
        "base_advice 恒为 None，这批线索在降档账本体系里被当「来源不可考的旧报告」对待："
        "降档无从撤销复算（fxapk lead restore/replay 的锚点缺失），判据链结论的快照断档。"
    ),
    "apply_repack_quarantine": (
        "样本判为正版重打包时，这条路径新产的域名/IP 属被仿冒的正版厂商，"
        "会以最高档直达文书套打 / IOC 导出 / HTML 红标 / closure 出口"
        "（2026-08 config-probe 回灌路径实发生过）。"
    ),
}

#: 步骤的规范顺序。顺序本身是判据：封存（seal）必须先于任何抑制（quarantine），
#: 颠倒会把抑制后的档位烙进 base_advice——棘轮，撤销时回不去（见 models.seal_base_advice 注释）。
STEP_ORDER: tuple[str, ...] = (
    "_apply_default_advice",
    "seal_base_advice",
    "apply_repack_quarantine",
)

#: 豁免标记（写在调用点所在函数的 ``def`` 行行尾注释里），后跟非空理由。
#: 仿照本仓 ``# leak-scan: allow <理由>`` 的既有约定：豁免与理由钉在同一行，git blame 可溯。
EXEMPT_MARKER = "lead-chain: exempt"


@dataclass(frozen=True)
class Site:
    """一个 ``build_endpoint_leads`` 生产调用点。"""

    file: str
    function: str
    line: int


@dataclass(frozen=True)
class Violation:
    """一条契约违规。``kind`` ∈ missing-step / order / indirect-ref /
    module-level-call / exempt-no-reason / stale-exempt。"""

    file: str
    function: str
    line: int
    kind: str
    detail: str


@dataclass
class ChainScan:
    """扫描结果。``sites`` 单独暴露：契约层要用它做「路径登记表」的双向比对
    （防扫描器失明后契约空转——0 个调用点 = 0 条违规 = 假绿）。"""

    sites: list[Site] = field(default_factory=list)
    exemptions: list[tuple[Site, str]] = field(default_factory=list)
    violations: list[Violation] = field(default_factory=list)


def _callee_name(call: ast.Call) -> str:
    """调用的简单名：``f(...)`` → ``f``；``mod.f(...)`` / ``obj.f(...)`` → ``f``。

    Attribute 形态不看 receiver：本仓步骤函数名全局唯一（pipeline 对 leads 的再导出
    也是同名），按名匹配的误认方向是**多认**（把无关同名方法当步骤）——那会让缺步骤
    的路径假绿，所以名字的唯一性由契约层的路径登记表 + 变异验证兜底，不在这里赌。
    """
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def _exempt_reason(fn: ast.FunctionDef | ast.AsyncFunctionDef, src_lines: list[str]) -> str | None:
    """``def`` 行上的豁免理由。无标记 → None；有标记但理由为空 → ""（契约层判违规）。

    只认 ``def`` 关键字所在那一行（多行签名的后续行不认）：标记必须钉在最显眼、
    git blame 一眼可溯的位置，不能藏在参数列表中间。
    """
    if not (0 < fn.lineno <= len(src_lines)):
        return None
    line = src_lines[fn.lineno - 1]
    if EXEMPT_MARKER not in line:
        return None
    return line.split(EXEMPT_MARKER, 1)[1].strip(" \t:#")


def _step_lines(
    fn: ast.AST,
    module_funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> dict[str, int]:
    """函数子树内各步骤的「生效行号」：直接调用取调用行；经一跳 helper 满足的取
    **helper 在本函数里被调用的那一行**（顺序检查以本函数视角为准）。

    一跳的边界：helper 必须是**同模块的模块级函数、以裸名调用**。这是本仓的实际形态
    （merge._build_runtime_leads → _quarantine_leads）；更远的拆法静态追不可靠，
    如实不认（见模块 docstring）。
    """
    found: dict[str, int] = {}

    def _note(step: str, line: int) -> None:
        found[step] = min(found.get(step, line), line)

    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        name = _callee_name(node)
        if name in STEP_ORDER:
            _note(name, node.lineno)
        elif (
            isinstance(node.func, ast.Name)
            and name in module_funcs
            and module_funcs[name] is not fn
        ):
            for sub in ast.walk(module_funcs[name]):
                if isinstance(sub, ast.Call):
                    sub_name = _callee_name(sub)
                    if sub_name in STEP_ORDER:
                        _note(sub_name, node.lineno)
    return found


def scan_source(src: str, path: str = "<mem>") -> ChainScan:
    """扫一段生产源码。语法错误直接抛——地基不容忍静默失败。"""
    tree = ast.parse(src)
    src_lines = src.splitlines()
    res = ChainScan()

    module_funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {
        n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    # ★入口的本地名集合：`from ... import build_endpoint_leads as bel` 之后，调用点写的是
    #   `bel(...)`，既不是名为 ENTRY 的 Call、也不是 Name/Attribute 节点（alias 的名字是
    #   ast.alias 的字符串字段），三层检查全看不见——实证过一条只走一步的新路径能这样隐形。
    #   把别名收进来，入口匹配才对得上「这个模块里它叫什么」。
    entry_names = {ENTRY}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                if a.name.rsplit(".", 1)[-1] == ENTRY and a.asname:
                    entry_names.add(a.asname)

    # --- 一遍走全树：函数清单、入口调用点（记最内层函数）、Call.func 节点集合 ---------
    all_funcs: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    call_func_ids: set[int] = set()
    #: 入口调用 → 最内层包围函数（None = 模块级）
    entry_calls: list[tuple[ast.Call, ast.FunctionDef | ast.AsyncFunctionDef | None]] = []

    def _walk(node: ast.AST, stack: list[ast.FunctionDef | ast.AsyncFunctionDef]) -> None:
        for child in ast.iter_child_nodes(node):
            next_stack = stack
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                all_funcs.append(child)
                next_stack = stack + [child]
            if isinstance(child, ast.Call):
                call_func_ids.add(id(child.func))
                if _callee_name(child) in entry_names:
                    entry_calls.append((child, stack[-1] if stack else None))
            _walk(child, next_stack)

    _walk(tree, [])

    # --- 间接引用：入口被取值而非调用（赋给变量 / 当参数传 / getattr 目标…） ----------
    # 静态追不了这种数据流，一律违规：静默放过 = 给绕过留一条无声的路。
    for node in ast.walk(tree):
        # 先窄到带位置信息的两类节点，下面才取得到 lineno。
        if not isinstance(node, (ast.Name, ast.Attribute)):
            continue
        is_ref = (isinstance(node, ast.Name) and node.id in entry_names) or (
            isinstance(node, ast.Attribute) and node.attr in entry_names
        )
        if is_ref and id(node) not in call_func_ids:
            res.violations.append(Violation(
                path, "<间接引用>", node.lineno, "indirect-ref",
                f"{ENTRY} 被取值而非直接调用——扫描器追不了它随后在哪被调、四步有没有跟上。"
                "请改为直接调用，或把整条路径收进一个函数并显式豁免。",
            ))

    # --- 逐调用点检查 ----------------------------------------------------------------
    seen_fn_ids: set[int] = set()
    for call, enclosing in entry_calls:
        if enclosing is None:
            res.violations.append(Violation(
                path, "<module>", call.lineno, "module-level-call",
                f"模块级直接调用 {ENTRY}：无函数作用域可查四步、也无 def 行可挂豁免，"
                "请包进函数。",
            ))
            continue
        if enclosing.name == ENTRY:
            continue  # 入口函数自身（递归/重定义）不是消费路径
        res.sites.append(Site(path, enclosing.name, call.lineno))
        if id(enclosing) in seen_fn_ids:
            continue  # 同函数多个入口调用只分析一次（四步按函数作用域计）
        seen_fn_ids.add(id(enclosing))

        reason = _exempt_reason(enclosing, src_lines)
        if reason is not None:
            if reason:
                res.exemptions.append((Site(path, enclosing.name, enclosing.lineno), reason))
            else:
                res.violations.append(Violation(
                    path, enclosing.name, enclosing.lineno, "exempt-no-reason",
                    f"豁免标记 `# {EXEMPT_MARKER}` 后必须写非空理由——没有理由的豁免"
                    "与隐式规则无异，下一个人无从判断它还成不成立。",
                ))
            continue

        found = _step_lines(enclosing, module_funcs)
        missing = [s for s in STEP_ORDER if s not in found]
        for step in missing:
            res.violations.append(Violation(
                path, enclosing.name, call.lineno, "missing-step",
                f"缺 {step}。后果：{STEP_CONSEQUENCES[step]}",
            ))
        if not missing:
            # 顺序检查：入口 < 各步骤（生效行）非降序。行号相同（两步经同一个 helper
            # 调用满足）不算颠倒——一跳视角下 helper 内部顺序不可见，如实不判。
            seq: list[tuple[str, int]] = [(ENTRY, call.lineno)]
            seq += [(s, found[s]) for s in STEP_ORDER]
            for (n1, l1), (n2, l2) in zip(seq, seq[1:]):
                if l2 < l1:
                    res.violations.append(Violation(
                        path, enclosing.name, l2, "order",
                        f"{n2}(行 {l2}) 出现在 {n1}(行 {l1}) 之前——四步顺序即判据："
                        "封存必须先于抑制，颠倒会把抑制后的档位烙进 base_advice（棘轮）。",
                    ))

    # --- 过期豁免：标记挂在不含入口调用的函数上 --------------------------------------
    entry_fn_ids = {id(fn) for _, fn in entry_calls if fn is not None}
    for fn in all_funcs:
        if _exempt_reason(fn, src_lines) is None or id(fn) in entry_fn_ids:
            continue
        if any(isinstance(n, ast.Call) and _callee_name(n) == ENTRY for n in ast.walk(fn)):
            continue  # 嵌套函数里有入口调用：标记应挂到最内层函数上，但不算过期
        res.violations.append(Violation(
            path, fn.name, fn.lineno, "stale-exempt",
            f"函数不含 {ENTRY} 调用却挂着豁免标记——过期豁免必须删，"
            "否则将来真加了调用会被它无声吞掉。",
        ))

    return res


def scan_repository(root: Path, *, prod_dir: str = "apkscan") -> ChainScan:
    """扫全部生产代码（测试目录刻意不扫：测试里调 build_endpoint_leads 是在测它本身）。"""
    res = ChainScan()
    base = root / prod_dir
    for py in sorted(base.rglob("*.py")):
        rel = str(py.relative_to(root)).replace("\\", "/")
        one = scan_source(py.read_text(encoding="utf-8"), rel)
        res.sites.extend(one.sites)
        res.exemptions.extend(one.exemptions)
        res.violations.extend(one.violations)
    return res


def format_violations(violations: list[Violation]) -> str:
    """把违规排成可直接指导修复的清单：文件::函数:行 + 类别 + 后果。"""
    return "\n  ".join(
        f"{v.file}::{v.function}:{v.line} [{v.kind}] {v.detail}" for v in violations
    )
