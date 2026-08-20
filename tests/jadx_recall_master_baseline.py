"""master `bd58041` 召回基线字面量（纯数据模块，gen 脚本实测生成、非手写）。

为什么单独成模块（CI 依赖对齐，PR #37 首跑实证）：replay 裁决进程
（``gen_jadx_recall_baseline.py`` 的 ``diff_dump_against_pinned``）要在
**只装运行期依赖**的环境里 import 这两个字面量——ci.yml 的
``jadx-recall-replay`` job 只 ``pip install -e "."``，不装 dev 依赖。字面量
原先住在 ``test_jadx_recall_baseline.py``，其顶层 ``import pytest`` 让 replay
在 CI 上 ``ModuleNotFoundError`` 挂掉（本地 venv 有 pytest 所以看不出来）。
数据归数据：本模块的 import 面只许标准库与纯数据语料模块
``tests.jadx_recall_corpus``——**永远不得**引入 pytest / apkscan / 任何
dev-only 依赖。

内容契约（与测试模块解耦但语义不变）：

- :data:`MASTER_EXTRACTION` —— method_id -> master 提取到的 (callee, line)
  集合。★集合语义：同名同行的重复计数不入契约（语料里没有；BFS 消费侧本就
  按序去重）。fanout 蜡烛 C00..C{FANOUT_CANDIDATES-1} 的空集由循环追加，
  规模跟着语料常量走。
- :data:`MASTER_PATHS` —— "source => target" -> master 默认限额下找到的路径
  （节点序列，顺序有意义）。

改动纪律：这些字面量声称「master `bd58041` 实测」，改动必须走
``gen_jadx_recall_baseline.py`` 的再生成流程（replay 对账 + digest 换指纹），
不许手编——CI 的 jadx-recall-replay job 每次对 bd58041 的树真重放对账，
手编谎报是机器红。消费方：gen 脚本（diff 裁决 + digest 指纹）与
``test_jadx_recall_baseline.py``（四层契约 + 指纹钉扎）。
"""

from __future__ import annotations

from tests.jadx_recall_corpus import FANOUT_CANDIDATES

#: method_id -> master 提取到的 (callee, line) 集合。
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
