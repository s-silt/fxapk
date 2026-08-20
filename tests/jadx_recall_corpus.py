"""JADX 召回基线语料（纯数据，供 test_jadx_recall_baseline 与再生成脚本共用）。

本模块**不得 import apkscan**：master 基线再生成脚本会在 master 工作树的
sys.path 下加载它，任何 apkscan 依赖都会把语料钉死在单一 schema 版本上。

语料覆盖两类召回面：
- 提取召回：调用点形态（普通/this/静态限定/链式/关键字后调用/比较后调用/
  循环与异常块内/数组初始化器内/嵌套体内），以及现状会被误记为调用点的
  方法**声明**行（匿名类方法、局部类方法与构造器、泛型返回类型声明），
  外加「同 caller 内同名声明伪边与真实调用并存」的锚定判据探针（dup 包）。
- 遍历召回：同名候选扇出（33 个候选，越过历史默认 max_fanout=32——该探针
  钉住「默认档位不得丢 master 可达路径」，现默认已改无界）、多跳链、
  穿匿名体的真实调用边。

再生成（仅当语料扩充时需要；基线定义为 master bd58041 的行为，永久可从
git 历史检出）：脚本已入库 `tests/gen_jadx_recall_baseline.py`
（dump / verify / digest，完整流程见其模块 docstring；master 环境用
`git archive bd58041 apkscan` 导出树 + PYTHONPATH 前插，无须 worktree）。
把 dump 输出的字面量粘回 test_jadx_recall_baseline.py 后必须同步换
BASELINE_FINGERPRINT（digest 子命令打印）。
"""

from __future__ import annotations

#: 提取/遍历共用语料：相对路径 -> Java 源文本。
CORPUS: dict[str, str] = {
    # -- 调用形态召回面：任何「声明剔除」启发式都不得误伤这里的真实调用 --
    "com/rc/calls/Calls.java": (
        "package com.rc.calls;\n"
        "\n"
        "public class Calls {\n"
        "    int size() {\n"
        "        return 0;\n"
        "    }\n"
        "\n"
        "    boolean check(int x) {\n"
        "        return probe(x);\n"
        "    }\n"
        "\n"
        "    boolean probe(int x) {\n"
        "        return x > 0;\n"
        "    }\n"
        "\n"
        "    RuntimeException fail() {\n"
        "        return new RuntimeException();\n"
        "    }\n"
        "\n"
        "    Calls chain() {\n"
        "        return this;\n"
        "    }\n"
        "\n"
        "    void go(int count) {\n"
        "        local();\n"
        "        this.self();\n"
        "        Helper.stat();\n"
        "        chain().next();\n"
        "        if (count > size()) {\n"
        "            branch();\n"
        "        }\n"
        "        for (int i = 0; i < size(); i++) {\n"
        "            loop();\n"
        "        }\n"
        "        try {\n"
        "            risky();\n"
        "        } catch (RuntimeException e) {\n"
        "            caught();\n"
        "        } finally {\n"
        "            fin();\n"
        "        }\n"
        "        int[] xs = new int[]{ make() };\n"
        "        assert check(count);\n"
        "        throw fail();\n"
        "    }\n"
        "}\n"
    ),
    # -- 嵌套体：匿名类/局部类里的方法声明是现状误记的调用点；真实调用必须保留 --
    "com/rc/nested/Nested.java": (
        "package com.rc.nested;\n"
        "\n"
        "public class Nested {\n"
        "    void go() {\n"
        "        attach(new Runnable() {\n"
        "            public void run() {\n"
        "                sink();\n"
        "            }\n"
        "\n"
        "            public java.util.List<String> names() {\n"
        "                return null;\n"
        "            }\n"
        "        });\n"
        "        class Local {\n"
        "            Local() {\n"
        "                seed();\n"
        "            }\n"
        "\n"
        "            void m() {\n"
        "                mm();\n"
        "            }\n"
        "        }\n"
        "        after();\n"
        "    }\n"
        "\n"
        "    void attach(Runnable r) {\n"
        "    }\n"
        "\n"
        "    void after() {\n"
        "    }\n"
        "}\n"
    ),
    "com/rc/nested/S.java": (
        "package com.rc.nested;\n"
        "\n"
        "public class S {\n"
        "    void sink() {\n"
        "    }\n"
        "}\n"
    ),
    #: T.run 存在只为让「声明伪边」可以成路径（Nested#go -> T#run -> T#tail）。
    "com/rc/nested/T.java": (
        "package com.rc.nested;\n"
        "\n"
        "public class T {\n"
        "    void run() {\n"
        "        tail();\n"
        "    }\n"
        "\n"
        "    void tail() {\n"
        "    }\n"
        "}\n"
    ),
    # -- 同名并存构型（第四轮复审 N1：锚定判据的失败构型实证）：同一 caller 里
    #    第 6 行是匿名类方法**声明** `public void ping() {`（伪边、进剔除白名单），
    #    第 9 行是**真实调用** `ping();`。声明剔除后路径必须仍在（真实调用支撑），
    #    该查询只能进 PARITY——想借第 6 行的已证声明把它塞进 REMOVAL_QUERIES，
    #    会被「跳必须完全剔断」的锚定判据拒绝（(ping,9) 不在白名单，支撑集未清空）。
    "com/rc/dup/Dup.java": (
        "package com.rc.dup;\n"
        "\n"
        "public class Dup {\n"
        "    void go() {\n"
        "        reg(new Runnable() {\n"
        "            public void ping() {\n"
        "            }\n"
        "        });\n"
        "        ping();\n"
        "    }\n"
        "\n"
        "    void reg(Runnable r) {\n"
        "    }\n"
        "}\n"
    ),
    "com/rc/dup/P.java": (
        "package com.rc.dup;\n"
        "\n"
        "public class P {\n"
        "    void ping() {\n"
        "        pong();\n"
        "    }\n"
        "\n"
        "    void pong() {\n"
        "    }\n"
        "}\n"
    ),
    # -- 箭头形态：lambda（表达式/块）与 switch rule（表达式/块/default）--
    "com/rc/arrow/Arrow.java": (
        "package com.rc.arrow;\n"
        "\n"
        "public class Arrow {\n"
        "    void go(int x) {\n"
        "        Runnable r = () -> lam();\n"
        "        Runnable b = () -> {\n"
        "            lamBlock();\n"
        "        };\n"
        "        switch (x) {\n"
        "            case 1 -> arm();\n"
        "            case 2 -> {\n"
        "                armBlock();\n"
        "            }\n"
        "            default -> fallback();\n"
        "        }\n"
        "        switch (x) {\n"
        "            case 1:\n"
        "                colon();\n"
        "                break;\n"
        "        }\n"
        "        tailTwo();\n"
        "    }\n"
        "\n"
        "    void lam() {\n"
        "    }\n"
        "\n"
        "    void arm() {\n"
        "    }\n"
        "\n"
        "    void fallback() {\n"
        "    }\n"
        "}\n"
    ),
    # -- 多跳链（遍历恒绿对照）--
    "com/rc/chain/Chain.java": (
        "package com.rc.chain;\n"
        "\n"
        "public class ChainA {\n"
        "    void top() {\n"
        "        mid();\n"
        "    }\n"
        "}\n"
        "\n"
        "class ChainB {\n"
        "    void mid() {\n"
        "        deep();\n"
        "    }\n"
        "}\n"
        "\n"
        "class ChainC {\n"
        "    void deep() {\n"
        "    }\n"
        "}\n"
    ),
}

#: 扇出探针：33 个同名候选（越过默认 max_fanout=32 一个身位）。
FANOUT_CANDIDATES = 33
CORPUS["com/rc/fan/M.java"] = (
    "package com.rc.fan;\n"
    "\n"
    "public class M {\n"
    "    void go() {\n"
    "        foo();\n"
    "    }\n"
    "}\n"
)
for _i in range(FANOUT_CANDIDATES):
    _cls = f"C{_i:02d}"
    CORPUS[f"com/rc/fan/{_cls}.java"] = (
        "package com.rc.fan;\n"
        "\n"
        f"public class {_cls} {{\n"
        "    void foo() {\n"
        "    }\n"
        "}\n"
    )

#: 遍历召回对等查询：默认限额下必须与 master 基线路径**完全一致**。
PARITY_QUERIES: tuple[tuple[str, str], ...] = (
    # 扇出截断幸存者（字典序首位候选）：恒绿对照。
    ("com.rc.fan.M#go/0", "com.rc.fan.C00#foo/0"),
    # ★扇出回归探针：字典序末位候选。master 可达；默认 max_fanout=32 丢失。
    ("com.rc.fan.M#go/0", "com.rc.fan.C32#foo/0"),
    # 多跳链：恒绿对照。
    ("com.rc.chain.ChainA#top/0", "com.rc.chain.ChainC#deep/0"),
    # 匿名体内真实调用边：声明剔除不得伤及（恒绿对照）。
    ("com.rc.nested.Nested#go/0", "com.rc.nested.S#sink/0"),
    # ★同名并存探针（第四轮复审 N1）：ping 的声明伪边（@6）被剔后，真实调用
    # （@9）仍支撑该路径——它必须留在对等侧，任何人想把它挪进 REMOVAL_QUERIES
    # 都过不了「跳完全剔断」锚定。
    ("com.rc.dup.Dup#go/0", "com.rc.dup.P#pong/0"),
)

#: 有意剔除的查询：唯一路由是「方法声明被误记为调用」的伪边。master 有路径；
#: 声明剔除落地后必须为空。键 = (source, target)，值 = 剔除理由。
REMOVAL_QUERIES: dict[tuple[str, str], str] = {
    ("com.rc.nested.Nested#go/0", "com.rc.nested.T#tail/0"): (
        "首跳来自匿名类方法声明行 `public void run() {`（声明不是调用）；"
        "该路径是伪边产物，剔除是精度修正、不是召回损失"
    ),
}

__all__ = [
    "CORPUS",
    "FANOUT_CANDIDATES",
    "PARITY_QUERIES",
    "REMOVAL_QUERIES",
]
