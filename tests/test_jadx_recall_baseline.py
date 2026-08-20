"""召回基线对比机制：相对 master `bd58041` 不丢边 / 不丢路径，可测、可回归。

背景（codex 第二轮复审 P1-1 的方法论教训）：召回验证只在分支内自洽是不够的，
必须回到 master 基线做对比，否则「截断行为」会被误钉成「预期行为」。本模块把
对比机制固化成四层契约 + 一层自守护：

1. **提取召回地板**：master 在语料上提取到的每条 (callee, line) 调用记录，除非
   列入 `INTENDED_EXTRACTION_REMOVALS`（逐条、带理由、过准入证明），当前实现
   必须仍然提取到。
2. **提取新增须解释**：当前实现多提取出的记录必须列入
   `INTENDED_EXTRACTION_ADDITIONS`——精度与召回的每一次变化都是显式编辑、可复核。
3. **遍历 oracle 保真**：`_ORACLE_LIMITS`（fanout/gaps 放到实际无穷；depth/paths/
   visited 与 master 默认一致）下的 trace_callpath 路径**节点序**与 master 默认
   限额下的实测一致。★可比面到节点序为止——resolution/scope/gaps/reason_codes
   是本分支引入的输出面，master 无从提供「master 值」；这些字段由第 5 层的
   分支侧 golden 钉扎，且默认限额与 oracle 限额另做全字段对象等值比较
   （test_traversal_default_trace_equals_oracle_trace_object_level）。
4. **默认限额对等**：默认 `CallPathLimits()` 下必须复现 master 找到的每条路径
   （PARITY_QUERIES），除非查询列入 `REMOVAL_QUERIES`（唯一路由是声明伪边、
   剔除属精度修正——且每条 master 路径都必须穿过已证声明伪边，机器裁决）。
5. **基线契约自守护**（第三轮复审 P1-d 后门补板 + 第四轮复审 N1 加固；见
   「三、基线契约自守护」节）：
   - 剔除白名单每条必须过**独立证明器**（与生产端同判据、独立第二实现）在语料
     原文上证明「绝非调用表达式」，且剔的必须是 master 真提取过的记录；证明器
     自带负例锁：六条语料实装负例 + 放行集**逐关键字**参数化负例（削放行集
     任何一个成员立即红）。
   - 路径剔除（REMOVAL_QUERIES）必须锚定在「完全剔断」的跳上——该跳的全部
     同名支撑记录**逐行号**列入白名单；同 caller 里声明与真实调用同名并存时
     （语料 dup 包实装此构型），只剔声明行不足以合法化路径消失。与
     PARITY_QUERIES 互斥且并集恰好覆盖 MASTER_PATHS——不存在无人裁决的基线路径。
   - 语料 + 基线 + 白名单 + 证明器裁决数据（放行集/消毒标记）全量内容有指纹
     （BASELINE_FINGERPRINT，v2）：改闸门必然是显式两步编辑，静默改基线字面量
     同样现形。
   - 分支行为全字段 golden（BRANCH_TRACE_GOLDEN）钉住 edges 的
     line/resolution/scope 与 gaps/coverage/reason_codes，防静默漂移。
   - 再生成脚本的 verify 裁判逻辑有单测（合成 dump 篡改必现形、非 master
     schema 的 dump 拒收）。

★守门的真实保证边界（第四轮复审定性，避免过度声称）：
- 对**只改生产代码**的编辑（本模块与语料不动）：守门是机器强制的——提取/
  遍历召回回归、借白名单藏损失、把真实调用证成声明，全部当场红。
- 对**连同本模块/语料/白名单一起改**的编辑：守门保证的是「不可静默」——
  绕道必然表现为对守门文件自身的显式 diff（白名单条目、锚定判据、放行集、
  指纹……），供人审阅质询；其中「改 master 基线字面量谎报 master 行为」这一
  路自 CI 端到端重放（jadx-recall-replay）起更进一层：CI 每次对 bd58041 的树
  真重放对账，谎报是机器红，静默通道只剩连 MASTER_COMMIT / workflow / 对账
  逻辑一起改。测试不可能阻止「修改测试自身」的编辑，这是测试作为守门手段的
  本质边界，不是实现缺陷。
- 对**蓄意合谋且复审失职**的场景：无保证。任何测试体系都无此保证。

基线数据的来源与再生成：`MASTER_EXTRACTION` / `MASTER_PATHS` 由 master
`bd58041` 的 scan_java_sources + trace_callpath 在同一语料上实测生成（非手写、
非记忆）。生成/对账/指纹脚本已入库：`tests/gen_jadx_recall_baseline.py`
（replay / dump / verify / digest 四个子命令，完整流程见其模块 docstring）。
2026-08-21 已用 `git archive bd58041` 导出树全量重放 dump 并 verify 对账两次
（第二次为 dup 语料扩充后），与本模块字面量逐项一致；同日起该重放上 CI 端到
端（ci.yml `jadx-recall-replay` job 跑 `replay` 子命令）：每次 push/PR 从
origin 取 bd58041 对象、导树、实测语料、对账字面量——出处宣称逐次机器重证，
不再依赖执行者的命令行纪律。

历史注记：本模块落盘时四条剔除契约与 C32 fanout 对等契约刻意为红；生产侧
「声明行不记为调用点」与「fanout 默认无界（与 master 对齐）」落地后已全部
转绿，红态窗口的经过见 round-2/round-3 规格与 git 历史。
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import pytest

from apkscan.core.jadx_callpath import (
    CallPathEdge,
    CallPathLimits,
    CallPathTrace,
    trace_callpath,
)
from apkscan.core.jadx_index import (
    INDEX_SCHEMA_VERSION,
    DexInput,
    DexRole,
    IndexBuildResult,
    IndexBuildState,
    JadxIndexManifest,
    JadxIndexStore,
    Limits,
    LoadedIndex,
    build_key_material,
    derive_index_key,
    scan_java_sources,
    verify_dex_inputs,
)
from tests.gen_jadx_recall_baseline import (
    MASTER_COMMIT,
    MASTER_INDEX_SCHEMA,
    DumpShapeError,
    _cmd_replay,
    baseline_fingerprint,
    diff_dump_against_pinned,
)
from tests.gen_jadx_recall_baseline import main as gen_baseline_main
from tests.jadx_recall_corpus import (
    CORPUS,
    FANOUT_CANDIDATES,
    PARITY_QUERIES,
    REMOVAL_QUERIES,
)

_OPTS = "sha256:" + "a" * 64

#: oracle 限额：fanout/gaps 放到实际无穷（master 无此二闸），其余三个与 master
#: 默认值一致（max_depth=16 / max_paths=8 / max_visited=100_000）。
_ORACLE_LIMITS = CallPathLimits(max_fanout=10**9, max_gaps=10**9)

# ---------------------------------------------------------------------------
# master bd58041 基线（gen_baseline.py 实测生成，不是手写；改动须走再生成流程）
# ---------------------------------------------------------------------------

#: method_id -> master 提取到的 (callee, line) 集合。
#: ★集合语义：同名同行的重复计数不入契约（语料里没有；BFS 消费侧本就按序去重）。
MASTER_EXTRACTION: dict[str, set[tuple[str, int]]] = {
    "com.rc.arrow.Arrow#arm/0": set(),
    "com.rc.arrow.Arrow#fallback/0": set(),
    "com.rc.arrow.Arrow#go/1": {
        ("arm", 10),
        ("armBlock", 12),
        ("colon", 18),
        ("fallback", 14),
        ("lam", 5),
        ("lamBlock", 7),
        ("tailTwo", 21),
    },
    "com.rc.arrow.Arrow#lam/0": set(),
    "com.rc.calls.Calls#chain/0": set(),
    "com.rc.calls.Calls#check/1": {("probe", 9)},
    "com.rc.calls.Calls#fail/0": set(),
    "com.rc.calls.Calls#go/1": {
        ("branch", 30),
        ("caught", 38),
        ("chain", 28),
        ("check", 43),
        ("fail", 44),
        ("fin", 40),
        ("local", 25),
        ("loop", 33),
        ("make", 42),
        ("next", 28),
        ("risky", 36),
        ("self", 26),
        ("size", 29),
        ("size", 32),
        ("stat", 27),
    },
    "com.rc.calls.Calls#probe/1": set(),
    "com.rc.calls.Calls#size/0": set(),
    "com.rc.chain.ChainA#top/0": {("mid", 5)},
    "com.rc.chain.ChainB#mid/0": {("deep", 11)},
    "com.rc.chain.ChainC#deep/0": set(),
    # 同名并存构型（第四轮复审 N1）：ping@6 是匿名类方法声明伪边、ping@9 是
    # 真实调用——同一 caller、同一简单名、不同行。锚定判据的「完全剔断」语义
    # 靠它实证：只剔 @6 时该跳仍有支撑，路径必须留在对等侧。
    "com.rc.dup.Dup#go/0": {("ping", 6), ("ping", 9), ("reg", 5)},
    "com.rc.dup.Dup#reg/1": set(),
    "com.rc.dup.P#ping/0": {("pong", 5)},
    "com.rc.dup.P#pong/0": set(),
    "com.rc.fan.M#go/0": {("foo", 5)},
    "com.rc.nested.Nested#after/0": set(),
    "com.rc.nested.Nested#attach/1": set(),
    "com.rc.nested.Nested#go/0": {
        ("Local", 15),
        ("after", 23),
        ("attach", 5),
        ("m", 19),
        ("mm", 20),
        ("names", 10),
        ("run", 6),
        ("seed", 16),
        ("sink", 7),
    },
    # 局部类自身入索引（master 既有行为）：体内调用同时归属局部类方法本体。
    "com.rc.nested.Nested$Local#<init>/0": {("seed", 16)},
    "com.rc.nested.Nested$Local#m/0": {("mm", 20)},
    "com.rc.nested.S#sink/0": set(),
    "com.rc.nested.T#run/0": {("tail", 5)},
    "com.rc.nested.T#tail/0": set(),
}
for _i in range(FANOUT_CANDIDATES):
    MASTER_EXTRACTION[f"com.rc.fan.C{_i:02d}#foo/0"] = set()

#: "source => target" -> master 默认限额下找到的路径（节点序列，顺序有意义）。
MASTER_PATHS: dict[str, tuple[tuple[str, ...], ...]] = {
    "com.rc.fan.M#go/0 => com.rc.fan.C00#foo/0": (
        ("com.rc.fan.M#go/0", "com.rc.fan.C00#foo/0"),
    ),
    "com.rc.fan.M#go/0 => com.rc.fan.C32#foo/0": (
        ("com.rc.fan.M#go/0", "com.rc.fan.C32#foo/0"),
    ),
    "com.rc.chain.ChainA#top/0 => com.rc.chain.ChainC#deep/0": (
        (
            "com.rc.chain.ChainA#top/0",
            "com.rc.chain.ChainB#mid/0",
            "com.rc.chain.ChainC#deep/0",
        ),
    ),
    "com.rc.dup.Dup#go/0 => com.rc.dup.P#pong/0": (
        (
            "com.rc.dup.Dup#go/0",
            "com.rc.dup.P#ping/0",
            "com.rc.dup.P#pong/0",
        ),
    ),
    "com.rc.nested.Nested#go/0 => com.rc.nested.S#sink/0": (
        ("com.rc.nested.Nested#go/0", "com.rc.nested.S#sink/0"),
    ),
    "com.rc.nested.Nested#go/0 => com.rc.nested.T#tail/0": (
        (
            "com.rc.nested.Nested#go/0",
            "com.rc.nested.T#run/0",
            "com.rc.nested.T#tail/0",
        ),
    ),
}

# ---------------------------------------------------------------------------
# 有意变更清单：召回/精度的每次变化都必须在这里显式落名、给理由
# ---------------------------------------------------------------------------

#: (method_id, callee, line) -> 剔除理由。列入即要求当前实现**不再**提取该记录
#: （见 test_intended_extraction_removals_are_actually_removed）。
#: ★准入标准：只允许「文本可判定绝非调用表达式」的记录进来——方法/构造器声明行
#: 与注解使用。该标准不是注释承诺而是机器裁决：每条都要过
#: test_removal_whitelist_entries_are_textually_provable_declarations 的独立证明器。
INTENDED_EXTRACTION_REMOVALS: dict[tuple[str, str, int], str] = {
    ("com.rc.nested.Nested#go/0", "run", 6): (
        "匿名类方法声明 `public void run() {`：前邻 token 是普通标识符（void），"
        "Java 文法下 `ident ident(` 不可能是调用表达式"
    ),
    ("com.rc.nested.Nested#go/0", "names", 10): (
        "匿名类泛型返回方法声明 `public java.util.List<String> names() {`："
        "自身配对右括号后紧跟 `{`，合法 Java 中调用表达式后不可能直接开块"
    ),
    ("com.rc.nested.Nested#go/0", "m", 19): (
        "局部类方法声明 `void m() {`：前邻 token 是普通标识符（void）"
    ),
    ("com.rc.nested.Nested#go/0", "Local", 15): (
        "局部类构造器声明 `Local() {`：自身配对右括号后紧跟 `{`"
    ),
    ("com.rc.dup.Dup#go/0", "ping", 6): (
        "匿名类方法声明 `public void ping() {`：前邻 token 是普通标识符（void）。"
        "★同 caller 第 9 行另有真实调用 `ping();`——只剔本行，(ping, 9) 必须保留"
    ),
}

#: (method_id, callee, line) -> 新增理由。当前为空：分支相对 master 零新增
#: （gen_baseline.py branch 模式实测 extraction identical）。
INTENDED_EXTRACTION_ADDITIONS: dict[tuple[str, str, int], str] = {}


# ---------------------------------------------------------------------------
# 夹具：语料建索引（module 级建一次）
# ---------------------------------------------------------------------------


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@pytest.fixture(scope="module")
def corpus_index(tmp_path_factory: pytest.TempPathFactory) -> LoadedIndex:
    tmp_path = tmp_path_factory.mktemp("jadx-recall")
    src = tmp_path / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "classes.dex").write_bytes(b"dex-0")
    inputs = [
        DexInput(
            role=DexRole.APK_DEX,
            ordinal=0,
            source_label="classes.dex",
            relative_path="classes.dex",
            declared_digest=_digest(b"dex-0"),
        )
    ]
    lineage = verify_dex_inputs(src, inputs)
    key = derive_index_key(lineage, "1.5.2", _OPTS)
    manifest = JadxIndexManifest(
        index_key=key,
        key_material=build_key_material(lineage, "1.5.2", _OPTS),
        dex_lineage=lineage,
        jadx_version="1.5.2",
        options_digest=_OPTS,
    )
    out = tmp_path / "out"
    for rel, content in CORPUS.items():
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    scan = scan_java_sources(out, [], lineage=lineage[0], limits=Limits())
    # 语料必须整树可扫：partial 之下的「不丢」没有意义。
    assert scan.coverage == "complete"
    store = JadxIndexStore(tmp_path / "cache")
    result = store.build_index(src, manifest, scan=scan)
    assert isinstance(result, IndexBuildResult) and result.state == IndexBuildState.BUILT
    loaded = store.load_index(manifest.index_key)
    assert isinstance(loaded, LoadedIndex)
    return loaded


def _current_extraction(loaded: LoadedIndex) -> dict[str, set[tuple[str, int]]]:
    """当前实现的提取面：method_id -> (callee, line) 集合（shard 结构直读）。"""
    table: dict[str, set[tuple[str, int]]] = {}
    for shard in loaded.shards:
        for cls in shard["structure"]["classes"]:  # type: ignore[index]
            for method in cls["methods"]:  # type: ignore[index]
                ident = f"{cls['name']}#{method['name']}/{method['arity']}"  # type: ignore[index]
                assert ident not in table, f"语料内方法身份撞名：{ident}"
                table[ident] = {
                    (c["callee"], c["line"])  # type: ignore[index]
                    for c in method["calls"]  # type: ignore[index]
                }
    return table


def _default_paths(
    loaded: LoadedIndex, source: str, target: str
) -> tuple[tuple[str, ...], ...]:
    return tuple(p.nodes for p in trace_callpath(loaded, source, target).paths)


def _oracle_paths(
    loaded: LoadedIndex, source: str, target: str
) -> tuple[tuple[str, ...], ...]:
    return tuple(
        p.nodes
        for p in trace_callpath(loaded, source, target, limits=_ORACLE_LIMITS).paths
    )


# ---------------------------------------------------------------------------
# 一、提取召回
# ---------------------------------------------------------------------------


def test_extraction_never_loses_master_edges(corpus_index: LoadedIndex) -> None:
    """提取召回地板：master 提取到且未列入剔除清单的每条 (callee, line)，
    当前实现必须仍提取到。丢任何一条都是负优化，先在这里现形。"""
    current = _current_extraction(corpus_index)
    missing: list[tuple[str, str, int]] = []
    for ident, master_pairs in MASTER_EXTRACTION.items():
        got = current.get(ident, set())
        for callee, line in sorted(master_pairs):
            if (ident, callee, line) in INTENDED_EXTRACTION_REMOVALS:
                continue
            if (callee, line) not in got:
                missing.append((ident, callee, line))
    assert missing == [], f"相对 master 基线丢失调用记录（召回回归）：{missing}"


def test_extraction_method_universe_matches_master(corpus_index: LoadedIndex) -> None:
    """方法宇宙对齐：语料上可见的方法身份集合与 master 一致。方法整个消失
    （比如声明解析被改坏）不该伪装成『该方法零调用』溜过地板测试。"""
    current = _current_extraction(corpus_index)
    assert set(current) == set(MASTER_EXTRACTION)


def test_extraction_adds_no_unexplained_edges(corpus_index: LoadedIndex) -> None:
    """提取新增须解释：当前实现多出的 (callee, line) 必须逐条列入
    INTENDED_EXTRACTION_ADDITIONS。防止提取器改动静默引入假边。"""
    current = _current_extraction(corpus_index)
    unexplained: list[tuple[str, str, int]] = []
    for ident, got in current.items():
        master_pairs = MASTER_EXTRACTION.get(ident, set())
        for callee, line in sorted(got - master_pairs):
            if (ident, callee, line) not in INTENDED_EXTRACTION_ADDITIONS:
                unexplained.append((ident, callee, line))
    assert unexplained == [], f"相对 master 基线出现未解释的新增记录：{unexplained}"


def test_intended_extraction_removals_are_actually_removed(
    corpus_index: LoadedIndex,
) -> None:
    """列入剔除清单的方法声明记录必须真的不再被提取。清单不是许可，是义务——
    挂着不修等于伪边继续入索引、继续能成路径。（落盘时为红态契约，生产侧
    「声明行不记为调用点」落地后转绿并常驻。）"""
    current = _current_extraction(corpus_index)
    still_present = [
        (ident, callee, line)
        for (ident, callee, line) in sorted(INTENDED_EXTRACTION_REMOVALS)
        if (callee, line) in current.get(ident, set())
    ]
    assert still_present == [], (
        f"声明行仍被记为调用点（伪边仍在索引里）：{still_present}"
    )


# ---------------------------------------------------------------------------
# 二、遍历召回
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("source", "target"), PARITY_QUERIES)
def test_traversal_oracle_matches_master_baseline(
    corpus_index: LoadedIndex, source: str, target: str
) -> None:
    """oracle 保真：fanout/gaps 实际无穷 + 其余限额同 master 默认，路径的
    **节点序列与顺序**必须与 master 实测一致。这条钉死「oracle == master
    语义」，让默认限额对等测试的裁判永不漂移。★比较面刻意只到节点序：
    resolution/scope 等字段是分支引入的，master 无从提供对照值——它们由
    BRANCH_TRACE_GOLDEN 全字段钉扎（见「四、分支侧全字段钉扎」节）。"""
    key = f"{source} => {target}"
    assert _oracle_paths(corpus_index, source, target) == MASTER_PATHS[key]


@pytest.mark.parametrize(("source", "target"), PARITY_QUERIES)
def test_traversal_default_limits_match_master_baseline(
    corpus_index: LoadedIndex, source: str, target: str
) -> None:
    """默认限额对等：默认 CallPathLimits() 必须复现 master 找到的每条路径。
    底线：**默认配置不得丢 master 可达路径**。C32 探针（字典序末位第 33 个
    同名候选）钉住 fanout 默认档位——落盘时默认 max_fanout=32 截掉它、此测试
    为红；裁决后默认改 None（与 master 一致全展开）转绿。真样本实测（87MB
    混淆 APK）135 个简单名候选数 >32、最大 3038：旧默认截的正是 R8 单字母名
    与常见覆写，此探针保住的不是边角。★把语料候选数改小或把默认上限抬到
    恰好盖过夹具，都是躲避而非修复，复审时按躲避处理。"""
    key = f"{source} => {target}"
    assert _default_paths(corpus_index, source, target) == MASTER_PATHS[key]


@pytest.mark.parametrize(("source", "target"), sorted(REMOVAL_QUERIES))
def test_intended_path_removals_are_actually_removed(
    corpus_index: LoadedIndex, source: str, target: str
) -> None:
    """唯一路由是「声明伪边」的查询必须是空结果——且在 oracle 限额下也为空，
    证明消失源自提取修正而非预算截断。master 在该查询上有路径；剔除它是精度
    修正，理由见 REMOVAL_QUERIES（每条须锚定已证声明伪边，见自守护节）。
    （落盘时为红态契约，声明剔除落地后转绿并常驻。）"""
    assert _default_paths(corpus_index, source, target) == ()
    assert _oracle_paths(corpus_index, source, target) == ()


# ---------------------------------------------------------------------------
# 三、基线契约自守护（第三轮复审 P1-d：剔除白名单不再是自由通行证）
# ---------------------------------------------------------------------------

#: 左证放行集：这些 token 之后可以直接跟调用表达式，不能作为声明证据。
#: 比生产端的 `_CALL_AFTER_KEYWORDS` 更宽（多 new/break/continue）——证明器
#: 只求 sound（绝不把真实调用证成声明），漏证由人工升级证明器解决。
_DECL_PROOF_DENY = frozenset(
    {"return", "throw", "yield", "assert", "else", "do", "case",
     "instanceof", "new", "break", "continue"}
)
#: 证明器只在无字符串字面量/注释的语料文件上 sound；出现这些标记就拒绝证明，
#: 逼着编辑者要么保持宿主文件素净、要么给证明器补消毒并配自测。
_PROOF_MARKERS = ('"', "'", "//", "/*")


def _is_ident_char(char: str) -> bool:
    return char.isascii() and (char.isalnum() or char in "_$")


def _find_corpus_file(ident: str) -> list[str]:
    """从方法身份定位语料宿主文件（包目录前缀 + 最外层简单类名的类型声明）。"""
    cls = ident.split("#", 1)[0]
    package, _, nested = cls.rpartition(".")
    outer = nested.split("$", 1)[0]
    prefix = package.replace(".", "/") + "/" if package else ""
    hosts = [
        (rel, text)
        for rel, text in sorted(CORPUS.items())
        if rel.startswith(prefix)
        and re.search(
            rf"\b(?:class|interface|enum|record)\s+{re.escape(outer)}\b", text
        )
    ]
    assert len(hosts) == 1, (
        f"{ident} 在语料中定位宿主文件失败（命中 {[rel for rel, _ in hosts]}）"
    )
    rel, text = hosts[0]
    assert not any(marker in text for marker in _PROOF_MARKERS), (
        f"{rel} 含字符串/注释标记，独立证明器在其上不 sound——"
        "要在此类文件挂白名单条目，须先给证明器补消毒并配自测"
    )
    return text.splitlines()


def _prev_nonspace(lines: list[str], row: int, cursor: int) -> tuple[int, int] | None:
    while row >= 0:
        text = lines[row]
        if cursor >= len(text):
            cursor = len(text) - 1
        while cursor >= 0 and text[cursor].isspace():
            cursor -= 1
        if cursor >= 0:
            return row, cursor
        row -= 1
        cursor = len(lines[row]) - 1 if row >= 0 else -1
    return None


def _next_nonspace(lines: list[str], row: int, cursor: int) -> tuple[int, int] | None:
    while row < len(lines):
        text = lines[row]
        while cursor < len(text):
            if not text[cursor].isspace():
                return row, cursor
            cursor += 1
        row += 1
        cursor = 0
    return None


def _left_token_proof(lines: list[str], row: int, start: int) -> bool:
    """左证：`@ Ident (` 与限定名 `@ a.b.Ident (` 是注解使用；
    `ident Ident (`（放行集外）是声明。

    点链回溯**只服务注解证明**：命中左邻是 `.` 时逐段跳过 `标识符.` 看链头，
    链头是 `@` 才放行；链头是任何别的东西（含普通标识符）一律不作声明证据——
    `x.y.f(` 是真实调用形态，点链上不存在 sound 的声明判据。"""
    position = _prev_nonspace(lines, row, start - 1)
    if position is None:
        return False
    token_row, token_col = position
    char = lines[token_row][token_col]
    qualified = False
    while char == ".":
        qualified = True
        position = _prev_nonspace(lines, token_row, token_col - 1)
        if position is None:
            return False
        token_row, token_col = position
        if not _is_ident_char(lines[token_row][token_col]):
            return False
        while token_col >= 0 and _is_ident_char(lines[token_row][token_col]):
            token_col -= 1
        position = _prev_nonspace(lines, token_row, token_col)
        if position is None:
            return False
        token_row, token_col = position
        char = lines[token_row][token_col]
    if char == "@":
        return True
    if qualified or not _is_ident_char(char):
        return False
    end = token_col + 1
    while token_col >= 0 and _is_ident_char(lines[token_row][token_col]):
        token_col -= 1
    token = lines[token_row][token_col + 1 : end]
    if token[0].isdigit():
        return False
    return token not in _DECL_PROOF_DENY


def _right_brace_proof(lines: list[str], row: int, open_paren: int) -> bool:
    """右证：自身配对右括号后第一个非空白是 `{`。配不平 → 不作证明（保守）。"""
    depth = 0
    cursor = open_paren
    for scan_row in range(row, len(lines)):
        text = lines[scan_row]
        while cursor < len(text):
            char = text[cursor]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    following = _next_nonspace(lines, scan_row, cursor + 1)
                    return (
                        following is not None
                        and lines[following[0]][following[1]] == "{"
                    )
            cursor += 1
        cursor = 0
    return False


def _provable_declaration_site(lines: list[str], callee: str, line: int) -> bool:
    """独立证明器：该行的每个 `callee(` 命中是否都可证「绝非调用表达式」。

    与生产端同判据、**独立第二实现**，只承担白名单准入守门：
    - 左证：前邻非空白是 `@`（合法 Java 中 `@ Ident (` 只能是注解使用），或
      一个不在放行集的普通标识符（`ident ident(` 不可能是调用表达式）；
    - 右证：自身配对右括号后第一个非空白是 `{`（调用表达式后不可能直接开块）。
    同行多处命中须全部可证才算证明（保守）。"""
    row = line - 1
    assert 0 <= row < len(lines), f"行号越界：{line}"
    matches = list(re.finditer(rf"(?<![\w$]){re.escape(callee)}\s*\(", lines[row]))
    assert matches, f"第 {line} 行不存在 `{callee}(` 形态命中"
    return all(
        _left_token_proof(lines, row, match.start())
        or _right_brace_proof(lines, row, match.end() - 1)
        for match in matches
    )


def test_removal_whitelist_entries_are_textually_provable_declarations() -> None:
    """★P1-d 后门补板：剔除白名单条目逐条过机器准入。每条必须同时满足
    (1) 剔的是 master 真提取过的记录（防幽灵条目）；(2) 理由有实义长度；
    (3) 独立证明器在语料原文上证得该行绝非调用表达式。想借白名单藏真实
    召回损失的编辑在这里现形（负例锁见下一条测试）。"""
    for (ident, callee, line), reason in sorted(INTENDED_EXTRACTION_REMOVALS.items()):
        assert ident in MASTER_EXTRACTION, f"剔除条目挂在未知方法上：{ident}"
        assert (callee, line) in MASTER_EXTRACTION[ident], (
            f"剔除条目不是 master 提取过的记录：{(ident, callee, line)}"
        )
        assert isinstance(reason, str) and len(reason.strip()) >= 12, (
            f"剔除理由缺失或过短：{(ident, callee, line)}"
        )
        lines = _find_corpus_file(ident)
        assert _provable_declaration_site(lines, callee, line), (
            f"无法在语料文本上证明为声明/注解使用，禁止进入剔除清单："
            f"{(ident, callee, line)}"
        )


def test_declaration_prover_rejects_real_calls() -> None:
    """证明器负例锁（突变验证的常驻形态）：把真实调用塞进剔除清单，准入测试
    必须红。负例覆盖六类形态：普通语句调用、`>` 比较守卫（round-2 明令的
    角括号陷阱）、实参含匿名类的调用、`assert`/`return`/`throw` 后调用
    （后两条为第四轮复审 N1 补板：`return probe(x);` 曾无负例——放行集删掉
    `return` 时四条旧负例全数照绿，真实调用可被证成声明）。"""
    for ident, callee, line in [
        ("com.rc.calls.Calls#go/1", "local", 25),
        ("com.rc.calls.Calls#go/1", "size", 29),
        ("com.rc.calls.Calls#go/1", "check", 43),
        ("com.rc.nested.Nested#go/0", "attach", 5),
        ("com.rc.calls.Calls#check/1", "probe", 9),
        ("com.rc.calls.Calls#go/1", "fail", 44),
    ]:
        lines = _find_corpus_file(ident)
        assert not _provable_declaration_site(lines, callee, line), (
            f"证明器把真实调用证成了声明（准入闸失效）：{(ident, callee, line)}"
        )


#: ★负例锁的参数源**独立钉死**，绝不写成 `sorted(_DECL_PROOF_DENY)`——参数化
#: 若由被守护的集合自身驱动，删成员时对应负例参数会静默消失而不是变红。
_DENY_KEYWORDS_PINNED: tuple[str, ...] = (
    "assert", "break", "case", "continue", "do", "else",
    "instanceof", "new", "return", "throw", "yield",
)


def test_deny_keyword_set_matches_pinned_tuple() -> None:
    """放行集内容与钉死元组等值：增删 `_DECL_PROOF_DENY` 任何成员都必须同步
    改 `_DENY_KEYWORDS_PINNED`（显式两步），逐关键字负例的参数面才不会被
    静默抽走。"""
    assert _DECL_PROOF_DENY == set(_DENY_KEYWORDS_PINNED)
    assert len(_DENY_KEYWORDS_PINNED) == len(set(_DENY_KEYWORDS_PINNED))


@pytest.mark.parametrize("keyword", _DENY_KEYWORDS_PINNED)
def test_declaration_prover_rejects_call_after_each_deny_keyword(
    keyword: str,
) -> None:
    """★第四轮复审 N1 负例锁：放行集 `_DECL_PROOF_DENY` **逐关键字**上锁。
    `<关键字> probe(1);` 是关键字后调用、绝不可证成声明；从集合删掉任何一个
    成员，本条（参数源是独立钉死的 `_DENY_KEYWORDS_PINNED`，不随集合缩水）
    立即红。削放行集从此必须同时显式改：集合、钉死元组、基线指纹（v2 起
    集合内容在指纹覆盖面里）——单点隐身编辑三处现形。"""
    assert not _provable_declaration_site([f"{keyword} probe(1);"], "probe", 1), (
        f"`{keyword} probe(1);` 被证成声明——放行集或左证逻辑被削弱"
    )


def test_declaration_prover_accepts_annotation_usage() -> None:
    """`@Ident(` 与限定名 `@a.b.Ident(` 是注解使用、文本可判定绝非调用——
    证明器放行（限定名回溯为第四轮复审 N2 配套：生产端剔除扩到限定名注解后，
    白名单条目在此过准入）。点链只服务注解证明：链头不是 `@` 的点链命中
    （真实限定调用 `x.y.f(`）必须拒绝，见下一条负例。"""
    assert _provable_declaration_site(["@Anno(v = 1)"], "Anno", 1)
    assert _provable_declaration_site(["void f(@Size(max = 1) String x) {"], "Size", 1)
    assert _provable_declaration_site(["@com.x.Anno(v = 1)"], "Anno", 1)
    assert _provable_declaration_site(["@a.b(1)"], "b", 1)


def test_declaration_prover_rejects_qualified_real_calls() -> None:
    """点链负例（第四轮复审 N2 配套）：`x.y.f(1);` 是真实限定调用，点链回溯
    发现链头不是 `@` 时必须拒绝证明——点链上不存在 sound 的声明判据，
    `foo bar.f(` 这类「链头左邻是普通标识符」的构型同样不放行。"""
    assert not _provable_declaration_site(["util.log.d(1);"], "d", 1)
    assert not _provable_declaration_site(["this.self(1);"], "self", 1)
    assert not _provable_declaration_site(["int v = obj.probe(1);"], "probe", 1)


def test_addition_whitelist_entries_are_constrained() -> None:
    """新增白名单同等约束（当前为空，约束仍上锁待未来条目）：只许挂在 master
    已知方法上（方法宇宙由 universe 测试独立钉死）、不得复述 master 已有记录、
    理由非空。"""
    for (ident, callee, line), reason in sorted(INTENDED_EXTRACTION_ADDITIONS.items()):
        assert ident in MASTER_EXTRACTION, f"新增条目挂在未知方法上：{ident}"
        assert (callee, line) not in MASTER_EXTRACTION[ident], (
            f"新增条目复述 master 已有记录：{(ident, callee, line)}"
        )
        assert isinstance(reason, str) and reason.strip(), (
            f"新增理由缺失：{(ident, callee, line)}"
        )


def _hop_fully_removed(
    extraction: dict[str, set[tuple[str, int]]],
    removals: set[tuple[str, str, int]],
    caller: str,
    callee_node: str,
) -> bool:
    """一跳「完全剔断」：caller 对 callee **简单名**的全部 master 支撑记录
    （逐行号）都已列入剔除白名单。边解析按简单名展开候选——同名任何一行记录
    存活，这一跳就仍然成立；只有支撑集整个清空，路径消失才归因于声明剔除。
    支撑集为空同样不算剔断（该跳不由提取记录支撑 = 基线数据异常，不能作为
    路径剔除的理由）。"""
    simple = callee_node.split("#", 1)[1].split("/", 1)[0]
    support = {
        (callee, line)
        for callee, line in extraction.get(caller, set())
        if callee == simple
    }
    return bool(support) and all(
        (caller, callee, line) in removals for callee, line in support
    )


def test_removal_queries_are_anchored_in_fully_removed_hops() -> None:
    """★路径级剔除必须锚定在「完全剔断」的跳上：REMOVAL_QUERIES 每个查询的
    每条 master 路径，都要有至少一跳的**全部**同名支撑记录（逐行号）列入已证
    剔除白名单。第四轮复审 N1 修法：旧判据把白名单压成 (caller, 简单名) 丢了
    行号——同 caller 里第 6 行已证声明 + 第 20 行真实调用同名并存时，真实调用
    支撑的路径也能借声明「过锚定」，真实路径损失被合法化。行号进入判据后，
    支撑集不清空的跳不算剔断，此路封死（负例见
    test_anchoring_rejects_partially_removed_hops；语料实装见 dup 包）。"""
    removals = set(INTENDED_EXTRACTION_REMOVALS)
    for (source, target), reason in sorted(REMOVAL_QUERIES.items()):
        assert isinstance(reason, str) and len(reason.strip()) >= 12, (
            f"路径剔除理由缺失或过短：{(source, target)}"
        )
        key = f"{source} => {target}"
        assert key in MASTER_PATHS, f"路径剔除查询不在 master 基线里：{key}"
        assert MASTER_PATHS[key], f"master 该查询本就无路径，剔除无意义：{key}"
        for nodes in MASTER_PATHS[key]:
            assert any(
                _hop_fully_removed(MASTER_EXTRACTION, removals, caller, callee_node)
                for caller, callee_node in zip(nodes, nodes[1:], strict=False)
            ), (
                f"{key} 的 master 路径 {nodes} 没有任何一跳被完全剔断"
                "（存在未列入白名单的同名支撑记录，路径消失不能归因于声明剔除）"
            )


def test_anchoring_rejects_partially_removed_hops() -> None:
    """★第四轮复审 N1 负例锁（锚定判据的失败构型直测）：同 caller 同名
    callee『声明@6 已证剔除 + 真实调用@20 仍在』时，该跳不得算被剔断——
    借他行声明合法化真实路径损失在此现形。语料实装对照：dup 包的
    ping@6/ping@9 并存构型，其查询钉在 PARITY_QUERIES 一侧、路径必须仍在。"""
    extraction = {"a.A#go/0": {("run", 6), ("run", 20)}}
    only_declaration = {("a.A#go/0", "run", 6)}
    assert not _hop_fully_removed(
        extraction, only_declaration, "a.A#go/0", "b.B#run/0"
    ), "只剔声明行、真实调用行仍在——该跳不得算完全剔断"
    both_lines = only_declaration | {("a.A#go/0", "run", 20)}
    assert _hop_fully_removed(extraction, both_lines, "a.A#go/0", "b.B#run/0"), (
        "同名支撑记录全部列入白名单后，该跳才算完全剔断"
    )
    assert not _hop_fully_removed(
        extraction, both_lines, "a.A#go/0", "b.B#other/0"
    ), "支撑集为空（跳不由提取记录支撑）不得算剔断"


def test_master_paths_are_fully_adjudicated() -> None:
    """MASTER_PATHS 的每个查询必须被恰好一个阵营认领：对等（PARITY_QUERIES）
    或剔除（REMOVAL_QUERIES）——互斥且并集恰好覆盖。不许存在无人裁决的基线
    路径（静默腐烂位），也不许一个查询两头下注。"""
    parity = {f"{source} => {target}" for source, target in PARITY_QUERIES}
    removal = {f"{source} => {target}" for source, target in REMOVAL_QUERIES}
    assert parity.isdisjoint(removal), f"两头下注：{sorted(parity & removal)}"
    assert set(MASTER_PATHS) == parity | removal, (
        f"未认领 {sorted(set(MASTER_PATHS) - parity - removal)}；"
        f"凭空认领 {sorted((parity | removal) - set(MASTER_PATHS))}"
    )


#: 基线闸门内容指纹。合法更新流程：改字面量/清单/语料后跑
#: `python tests/gen_jadx_recall_baseline.py digest` 取新值粘回，并按其模块
#: docstring 的 dump/verify 流程对 master 重放对账。
BASELINE_FINGERPRINT = (
    "sha256:d9ecf69bd1c099c6d95ca505db1aaf36fb75d1dd84d2194262518c079ce15159"
)


def test_baseline_fingerprint_is_pinned() -> None:
    """★基线指纹（P2-a 出处硬化 + P1-d 反静默篡改）：语料、master 两面基线、
    查询集、两份白名单、证明器裁决数据（放行集/消毒标记，v2 起）任何一处变动
    都在此现形——改闸门必然是显式两步编辑，直接改 MASTER_EXTRACTION 字面量、
    改白名单、削放行集同样藏不住。"""
    assert baseline_fingerprint(
        corpus=CORPUS,
        fanout_candidates=FANOUT_CANDIDATES,
        master_extraction=MASTER_EXTRACTION,
        master_paths=MASTER_PATHS,
        parity_queries=PARITY_QUERIES,
        removal_queries=REMOVAL_QUERIES,
        extraction_removals=INTENDED_EXTRACTION_REMOVALS,
        extraction_additions=INTENDED_EXTRACTION_ADDITIONS,
        decl_proof_deny=_DECL_PROOF_DENY,
        proof_markers=_PROOF_MARKERS,
    ) == BASELINE_FINGERPRINT


# ---------------------------------------------------------------------------
# 三之二、再生成对账的裁判逻辑（第四轮复审 N1：verify 不再只活在人工流程里）
# ---------------------------------------------------------------------------


def _dump_from_pinned() -> dict[str, object]:
    """把钉住基线字面量反序列化成 dump JSON 形态（与 gen 脚本 _measure 同构）。"""
    return {
        "index_schema": MASTER_INDEX_SCHEMA,
        "extraction": {
            ident: sorted([callee, line] for callee, line in pairs)
            for ident, pairs in MASTER_EXTRACTION.items()
        },
        "paths": {
            key: [list(nodes) for nodes in paths]
            for key, paths in MASTER_PATHS.items()
        },
    }


def test_verify_judge_passes_pinned_and_catches_tampering() -> None:
    """verify 裁判逻辑单测（第四轮复审 N1：`_cmd_verify` 此前无任何测试端到端
    覆盖）：与钉住基线全等的 dump 判过；篡改任何一条提取记录或路径，差异必须
    逐条现形。★边界如实声明：这里测的是**裁决逻辑**；「dump 确实来自 master
    bd58041 的树」由 replay 子命令的 git 内容寻址（导树用 MASTER_COMMIT）
    保证，CI 的 jadx-recall-replay job 每次重放——完整保证边界见 gen 脚本
    docstring。"""
    assert diff_dump_against_pinned(_dump_from_pinned()) == []

    tampered = _dump_from_pinned()
    extraction = tampered["extraction"]
    assert isinstance(extraction, dict)
    extraction["com.rc.calls.Calls#check/1"] = []  # 抹掉 probe@9
    problems = diff_dump_against_pinned(tampered)
    assert len(problems) == 1 and "com.rc.calls.Calls#check/1" in problems[0]

    tampered_paths = _dump_from_pinned()
    paths = tampered_paths["paths"]
    assert isinstance(paths, dict)
    key = "com.rc.dup.Dup#go/0 => com.rc.dup.P#pong/0"
    paths[key] = []
    problems = diff_dump_against_pinned(tampered_paths)
    assert len(problems) == 1 and key in problems[0]


def test_verify_judge_rejects_non_master_schema() -> None:
    """verify 的 schema 硬校验（第四轮复审 N1：此前 dump 里的 index_schema
    写了但没人读）：分支自身的 dump（1.6）冒充 master 对账必须被拒且不再往下
    比对——「基线 == master 实测」的宣称不允许被错误来源的 dump 打穿。"""
    forged = _dump_from_pinned()
    forged["index_schema"] = INDEX_SCHEMA_VERSION
    problems = diff_dump_against_pinned(forged)
    assert len(problems) == 1 and "index_schema" in problems[0]
    assert INDEX_SCHEMA_VERSION != MASTER_INDEX_SCHEMA, (
        "分支 schema 与 master 相同时本护栏失去区分力——重新审视校验设计"
    )


@pytest.mark.parametrize(
    ("payload", "fragment"),
    [
        pytest.param([], "dump 顶层", id="toplevel-list"),
        pytest.param("1.3", "dump 顶层", id="toplevel-scalar"),
        pytest.param({}, "缺字段", id="empty-dict"),
        pytest.param(
            {"index_schema": MASTER_INDEX_SCHEMA, "paths": {}},
            "'extraction'",
            id="missing-extraction",
        ),
        pytest.param(
            {"index_schema": MASTER_INDEX_SCHEMA, "extraction": {}},
            "'paths'",
            id="missing-paths",
        ),
        pytest.param(
            {"index_schema": 13, "extraction": {}, "paths": {}},
            "index_schema",
            id="schema-not-str",
        ),
        pytest.param(
            {"index_schema": MASTER_INDEX_SCHEMA, "extraction": "oops", "paths": {}},
            "extraction",
            id="extraction-not-mapping",
        ),
        pytest.param(
            {"index_schema": MASTER_INDEX_SCHEMA, "extraction": {"a#b/0": 7}, "paths": {}},
            "extraction[a#b/0]",
            id="extraction-value-not-list",
        ),
        pytest.param(
            {"index_schema": MASTER_INDEX_SCHEMA, "extraction": {"a#b/0": [["x"]]}, "paths": {}},
            "两元列表",
            id="pair-not-two-elements",
        ),
        pytest.param(
            {
                "index_schema": MASTER_INDEX_SCHEMA,
                "extraction": {"a#b/0": [["x", "9"]]},
                "paths": {},
            },
            "line",
            id="line-not-int",
        ),
        pytest.param(
            {
                "index_schema": MASTER_INDEX_SCHEMA,
                "extraction": {"a#b/0": [["x", True]]},
                "paths": {},
            },
            "line",
            id="line-bool-refused",
        ),
        pytest.param(
            {"index_schema": MASTER_INDEX_SCHEMA, "extraction": {}, "paths": {"q => r": "abc"}},
            "paths[q => r]",
            id="paths-value-str-silent-poison",
        ),
        pytest.param(
            {"index_schema": MASTER_INDEX_SCHEMA, "extraction": {}, "paths": {"q => r": ["ab"]}},
            "第 0 条路径",
            id="path-nodes-not-list",
        ),
        pytest.param(
            {"index_schema": MASTER_INDEX_SCHEMA, "extraction": {}, "paths": {"q => r": [["a", 3]]}},
            "节点",
            id="path-node-not-str",
        ),
    ],
)
def test_corrupted_dump_is_exit_2_process_failure(
    payload: object, fragment: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """守门代码自身的健壮性（第五轮复审）：合法 JSON 但结构损坏的 dump 必须
    得到 **exit 2（流程失败）** 而非 1——此前缺字段/类型错/顶层非 dict 是未
    捕获 traceback 假装 exit 1，空 dict 被 schema 粗筛误诊成「分支冒充」，
    ``paths`` 值为字符串则静默迭代字符产出假差异。三种形态都会误导人以为
    基线漂移了去改基线，全部收敛到可读的 exit 2。报错须点名坏的字段。"""
    dump_path = tmp_path / "corrupted.json"
    dump_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    assert gen_baseline_main(["verify", str(dump_path)]) == 2
    err = capsys.readouterr().err
    assert "结构损坏" in err and fragment in err


def test_diff_judge_raises_shape_error_before_adjudication() -> None:
    """形状校验在裁决之前、且走异常通道：损坏 dump 抛 :class:`DumpShapeError`，
    绝不返回差异列表——返回列表会被 ``_report_diff`` 判成 exit 1 的「对账
    差异」，正是第五轮复审点名的误导方向。"""
    with pytest.raises(DumpShapeError):
        diff_dump_against_pinned({})
    with pytest.raises(DumpShapeError):
        diff_dump_against_pinned([])
    with pytest.raises(DumpShapeError):
        diff_dump_against_pinned(
            {"index_schema": MASTER_INDEX_SCHEMA, "extraction": {}, "paths": {"q": "s"}}
        )


def test_shape_error_reports_location_not_data(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """输出纪律：形状报错点名坏在哪个字段（定位坐标），但损坏的**值**本身
    绝不进 stdout/stderr——守门脚本不倒 dump 数据。"""
    sentinel = "ZZ-SENTINEL-VALUE-MUST-NOT-LEAK-ZZ"
    payload = {
        "index_schema": MASTER_INDEX_SCHEMA,
        "extraction": {},
        "paths": {"q => r": sentinel},
    }
    dump_path = tmp_path / "leaky.json"
    dump_path.write_text(json.dumps(payload), encoding="utf-8")
    assert gen_baseline_main(["verify", str(dump_path)]) == 2
    captured = capsys.readouterr()
    assert sentinel not in captured.err and sentinel not in captured.out
    assert "paths[q => r]" in captured.err


def test_verify_exit_tristate_contract(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """verify 入口的三态 exit 契约整体钉住：全等=0；形状完好的内容差异与
    schema 冒充仍是 1（形状刀不得把既有的对账/粗筛语义误伤成 2）；结构损坏
    =2 由前两测覆盖。"""
    good = tmp_path / "good.json"
    good.write_text(json.dumps(_dump_from_pinned()), encoding="utf-8")
    assert gen_baseline_main(["verify", str(good)]) == 0

    tampered = _dump_from_pinned()
    extraction = tampered["extraction"]
    assert isinstance(extraction, dict)
    extraction["com.rc.calls.Calls#check/1"] = []
    drifted = tmp_path / "drifted.json"
    drifted.write_text(json.dumps(tampered), encoding="utf-8")
    assert gen_baseline_main(["verify", str(drifted)]) == 1

    forged = _dump_from_pinned()
    forged["index_schema"] = INDEX_SCHEMA_VERSION
    forged_path = tmp_path / "forged.json"
    forged_path.write_text(json.dumps(forged), encoding="utf-8")
    assert gen_baseline_main(["verify", str(forged_path)]) == 1
    capsys.readouterr()  # 输出已断言过语义，这里只清缓冲


def test_replay_corrupted_dump_output_is_exit_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """replay 通道（CI 走的那条）对结构损坏同样必须 exit 2：真入口
    ``_cmd_replay`` 从头走到尾，只在进程边界换假 ``subprocess.run``——git
    探测/导树按原序放行（导出树给一个含 apkscan/__init__.py 的最小 tar），
    master 树上的 dump 子进程「成功」但输出 ``{}``。防的是 replay 侧绕开
    ``_judge_dump`` 共用通道、让流程失败重新伪装成对账差异的回归。"""
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tar:
        tar.addfile(tarfile.TarInfo("apkscan/__init__.py"), io.BytesIO(b""))
    tar_bytes = tar_buf.getvalue()

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[Any]:
        if "rev-parse" in args:
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        if "archive" in args:
            return subprocess.CompletedProcess(args, 0, stdout=tar_bytes, stderr=b"")
        assert "dump" in args, f"意料外的子进程调用：{args!r}"
        return subprocess.CompletedProcess(args, 0, stdout="{}", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert _cmd_replay(None) == 2
    err = capsys.readouterr().err
    assert "结构损坏" in err


def test_master_commit_constant_is_the_documented_baseline_sha() -> None:
    """MASTER_COMMIT 是完整 40 位 SHA，且就是两模块文档通篇引用的 bd58041。
    CI 的 jadx-recall-replay 用它导树重放：把常量旋到别的 commit = 换基线，
    必须连同本测试与全部文档引用一起显式改（且 CI 重放会逼出新树实测与旧
    字面量的不一致）——防的是「文档说 bd58041、机器实际对着另一棵树对账」
    的静默错位。"""
    assert re.fullmatch(r"[0-9a-f]{40}", MASTER_COMMIT)
    assert MASTER_COMMIT.startswith("bd58041")


# ---------------------------------------------------------------------------
# 四、分支侧全字段钉扎（第三轮复审 P2-a：master 只能钉节点序，其余字段在此钉）
# ---------------------------------------------------------------------------


def _edge_snapshot(edge: CallPathEdge) -> dict[str, object]:
    return {
        "caller": edge.caller,
        "callee": edge.callee,
        "caller_path": edge.caller_path,
        "line": edge.line,
        "resolution": edge.resolution,
        "scope": edge.scope,
    }


def _trace_snapshot(trace: CallPathTrace) -> dict[str, object]:
    return {
        "paths": [
            {"nodes": list(path.nodes), "edges": [_edge_snapshot(e) for e in path.edges]}
            for path in trace.paths
        ],
        "gaps": [_edge_snapshot(gap) for gap in trace.gaps],
        "coverage": trace.coverage,
        "reason_codes": list(trace.reason_codes),
    }


@pytest.mark.parametrize(("source", "target"), PARITY_QUERIES)
def test_traversal_default_trace_equals_oracle_trace_object_level(
    corpus_index: LoadedIndex, source: str, target: str
) -> None:
    """默认限额与 oracle 限额的输出**全字段对象等值**（不只节点序）：edges 的
    line/resolution/scope、gaps、coverage、reason_codes 一并参与比较。语料上
    默认限额不触任何闸；任何字段在两档位间漂移（例如引入按档位变化的标注）
    都在此现形。"""
    assert trace_callpath(corpus_index, source, target) == trace_callpath(
        corpus_index, source, target, limits=_ORACLE_LIMITS
    )


#: 分支行为全字段 golden（2026-08-21 由本分支实测生成，probe_golden_traces）。
#: ★这不是 master 对等面——resolution/scope/gaps/reason_codes 是分支引入的输出，
#: 钉住它们是防「行为静默漂移」：生产侧任何改变这些字段的编辑都必须显式改这里。
BRANCH_TRACE_GOLDEN: dict[str, dict[str, object]] = {
    "com.rc.fan.M#go/0 => com.rc.fan.C00#foo/0": {
        "paths": [
            {
                "nodes": ["com.rc.fan.M#go/0", "com.rc.fan.C00#foo/0"],
                "edges": [
                    {
                        "caller": "com.rc.fan.M#go/0",
                        "callee": "com.rc.fan.C00#foo/0",
                        "caller_path": "com/rc/fan/M.java",
                        "line": 5,
                        "resolution": "ambiguous",
                        "scope": "method",
                    }
                ],
            }
        ],
        "gaps": [],
        "coverage": "complete",
        "reason_codes": [],
    },
    "com.rc.chain.ChainA#top/0 => com.rc.chain.ChainC#deep/0": {
        "paths": [
            {
                "nodes": [
                    "com.rc.chain.ChainA#top/0",
                    "com.rc.chain.ChainB#mid/0",
                    "com.rc.chain.ChainC#deep/0",
                ],
                "edges": [
                    {
                        "caller": "com.rc.chain.ChainA#top/0",
                        "callee": "com.rc.chain.ChainB#mid/0",
                        "caller_path": "com/rc/chain/Chain.java",
                        "line": 5,
                        "resolution": "name_unique",
                        "scope": "method",
                    },
                    {
                        "caller": "com.rc.chain.ChainB#mid/0",
                        "callee": "com.rc.chain.ChainC#deep/0",
                        "caller_path": "com/rc/chain/Chain.java",
                        "line": 11,
                        "resolution": "name_unique",
                        "scope": "method",
                    },
                ],
            }
        ],
        "gaps": [],
        "coverage": "complete",
        "reason_codes": [],
    },
    # 同名并存构型（第四轮复审 N1）：声明伪边 ping@6 剔除后，边 locator 指向
    # 真实调用行 9（master 首展开的是声明行 6）——路径不丢且行号更真实。
    "com.rc.dup.Dup#go/0 => com.rc.dup.P#pong/0": {
        "paths": [
            {
                "nodes": [
                    "com.rc.dup.Dup#go/0",
                    "com.rc.dup.P#ping/0",
                    "com.rc.dup.P#pong/0",
                ],
                "edges": [
                    {
                        "caller": "com.rc.dup.Dup#go/0",
                        "callee": "com.rc.dup.P#ping/0",
                        "caller_path": "com/rc/dup/Dup.java",
                        "line": 9,
                        "resolution": "name_unique",
                        "scope": "method",
                    },
                    {
                        "caller": "com.rc.dup.P#ping/0",
                        "callee": "com.rc.dup.P#pong/0",
                        "caller_path": "com/rc/dup/P.java",
                        "line": 5,
                        "resolution": "name_unique",
                        "scope": "method",
                    },
                ],
            }
        ],
        "gaps": [],
        "coverage": "complete",
        "reason_codes": [],
    },
    "com.rc.nested.Nested#go/0 => com.rc.nested.S#sink/0": {
        "paths": [
            {
                "nodes": ["com.rc.nested.Nested#go/0", "com.rc.nested.S#sink/0"],
                "edges": [
                    {
                        "caller": "com.rc.nested.Nested#go/0",
                        "callee": "com.rc.nested.S#sink/0",
                        "caller_path": "com/rc/nested/Nested.java",
                        "line": 7,
                        "resolution": "name_unique",
                        "scope": "nested_type",
                    }
                ],
            }
        ],
        "gaps": [
            {
                "caller": "com.rc.nested.Nested#go/0",
                "callee": "mm",
                "caller_path": "com/rc/nested/Nested.java",
                "line": 20,
                "resolution": "not_in_index",
                "scope": "nested_type",
            },
            {
                "caller": "com.rc.nested.Nested#go/0",
                "callee": "seed",
                "caller_path": "com/rc/nested/Nested.java",
                "line": 16,
                "resolution": "not_in_index",
                "scope": "nested_type",
            },
        ],
        "coverage": "complete",
        "reason_codes": [],
    },
    "com.rc.calls.Calls#go/1 => com.rc.calls.Calls#probe/1": {
        "paths": [
            {
                "nodes": [
                    "com.rc.calls.Calls#go/1",
                    "com.rc.calls.Calls#check/1",
                    "com.rc.calls.Calls#probe/1",
                ],
                "edges": [
                    {
                        "caller": "com.rc.calls.Calls#go/1",
                        "callee": "com.rc.calls.Calls#check/1",
                        "caller_path": "com/rc/calls/Calls.java",
                        "line": 43,
                        "resolution": "name_unique",
                        "scope": "method",
                    },
                    {
                        "caller": "com.rc.calls.Calls#check/1",
                        "callee": "com.rc.calls.Calls#probe/1",
                        "caller_path": "com/rc/calls/Calls.java",
                        "line": 9,
                        "resolution": "name_unique",
                        "scope": "method",
                    },
                ],
            }
        ],
        "gaps": [
            {
                "caller": "com.rc.calls.Calls#go/1",
                "callee": "branch",
                "caller_path": "com/rc/calls/Calls.java",
                "line": 30,
                "resolution": "not_in_index",
                "scope": "method",
            },
            {
                "caller": "com.rc.calls.Calls#go/1",
                "callee": "caught",
                "caller_path": "com/rc/calls/Calls.java",
                "line": 38,
                "resolution": "not_in_index",
                "scope": "method",
            },
            {
                "caller": "com.rc.calls.Calls#go/1",
                "callee": "fin",
                "caller_path": "com/rc/calls/Calls.java",
                "line": 40,
                "resolution": "not_in_index",
                "scope": "method",
            },
            {
                "caller": "com.rc.calls.Calls#go/1",
                "callee": "local",
                "caller_path": "com/rc/calls/Calls.java",
                "line": 25,
                "resolution": "not_in_index",
                "scope": "method",
            },
            {
                "caller": "com.rc.calls.Calls#go/1",
                "callee": "loop",
                "caller_path": "com/rc/calls/Calls.java",
                "line": 33,
                "resolution": "not_in_index",
                "scope": "method",
            },
            {
                "caller": "com.rc.calls.Calls#go/1",
                "callee": "make",
                "caller_path": "com/rc/calls/Calls.java",
                "line": 42,
                "resolution": "not_in_index",
                "scope": "method",
            },
            {
                "caller": "com.rc.calls.Calls#go/1",
                "callee": "next",
                "caller_path": "com/rc/calls/Calls.java",
                "line": 28,
                "resolution": "not_in_index",
                "scope": "method",
            },
            {
                "caller": "com.rc.calls.Calls#go/1",
                "callee": "risky",
                "caller_path": "com/rc/calls/Calls.java",
                "line": 36,
                "resolution": "not_in_index",
                "scope": "method",
            },
            {
                "caller": "com.rc.calls.Calls#go/1",
                "callee": "self",
                "caller_path": "com/rc/calls/Calls.java",
                "line": 26,
                "resolution": "not_in_index",
                "scope": "method",
            },
            {
                "caller": "com.rc.calls.Calls#go/1",
                "callee": "stat",
                "caller_path": "com/rc/calls/Calls.java",
                "line": 27,
                "resolution": "not_in_index",
                "scope": "method",
            },
        ],
        "coverage": "complete",
        "reason_codes": [],
    },
}


@pytest.mark.parametrize("query", sorted(BRANCH_TRACE_GOLDEN))
def test_traversal_branch_golden_full_fields(
    corpus_index: LoadedIndex, query: str
) -> None:
    """分支行为全字段 golden：默认限额下 trace 的 paths（含逐边
    line/resolution/scope）、gaps、coverage、reason_codes 与钉住值逐字段一致。
    覆盖五类构型：ambiguous 扇出、双跳 name_unique 链、嵌套体内边 +
    nested_type gaps、多 gap 富查询、同名并存（声明剔除后 locator 落真实
    调用行）。行为变更必须显式改 golden，静默漂移在此现形。"""
    source, target = query.split(" => ")
    trace = trace_callpath(corpus_index, source, target)
    assert _trace_snapshot(trace) == BRANCH_TRACE_GOLDEN[query]
