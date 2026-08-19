"""P1-A：方法 arity 的泛型感知计数（schema 1.3）。

旧实现按 `split(",")` 数参数，泛型实参里的逗号被当成参数分隔符——
`Map<String, String> m` 算成 2。方法身份是 `cls#name/arity`，算错即令
callpath 按真实 arity 查假阴性、ownership 与 baseline 对不齐。

★畸形参数段必须返回 None 由调用方丢弃，不能折叠成「看起来正常」的数字：
`f(,,,,)` 折叠后是 0，与真实的 `f()` 撞成同一个 `cls#name/arity` 身份，而
`_index_methods` 按同 id 合并出边——敌对样本即可把伪造调用边挂到真实方法上。
参数段是样本可控输入，不可判定就必须说不可判定，而不是给个默认值。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from apkscan.core.jadx_index import (
    DexLineage,
    DexRole,
    Limits,
    _declared_arity,
    scan_java_sources,
)

_LINEAGE = DexLineage(DexRole.APK_DEX, 0, "classes.dex", "sha256:" + "0" * 64)


def _scan(tmp_path: Path, source: str):
    out = tmp_path / "out" / "com" / "a"
    out.mkdir(parents=True)
    (out / "A.java").write_bytes(source.encode("utf-8"))
    return scan_java_sources(tmp_path / "out", [], lineage=_LINEAGE, limits=Limits())


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ("", 0),
        ("   ", 0),
        ("String a", 1),
        ("String a, int b", 2),
        ("Map<String, String> m", 1),
        ("List<Map<String, Integer>> x, int y", 2),
        ("Map<String, String> a, List<Integer> b, int c", 3),
        ("Function<A, B> f", 1),
        ("int[] a, String... b", 2),
        ("Map<String, ? super Integer> m", 1),
        ("final int a", 1),
        ("@NonNull String x", 1),
    ],
)
def test_declared_arity_counts_top_level_commas(params: str, expected: int) -> None:
    assert _declared_arity(params) == expected


@pytest.mark.parametrize(
    "params",
    [
        "Map<String, String m",  # '<' 未闭合
        "a > b, c",              # 多余的 '>'
        ">>>",
        "<<<",
        ",,,,",                  # 全空参数段——折叠后会与真实 f() 撞身份
        ",",
        "int a,",                # 尾随逗号：不是合法 Java 声明
        ",int a",                # 前导逗号
        "int a,,int b",          # 中间空段
        "   ,   ",
        "x",                     # 无类型的裸名字——折叠后是 1，与真实 f(String x) 撞身份
        "int",                   # 只有类型没有名字
        "Map<String,String>m",   # 类型与名字之间无分隔空白
    ],
)
def test_declared_arity_rejects_malformed_params(params: str) -> None:
    """畸形一律 None：调用方据此丢弃声明，绝不产生可与真实重载碰撞的身份。

    合法 Java 形参必然是 `类型 名字` 两部分、中间有空白（`String... a` /
    `int[] a` / `@NonNull String x` / `final int a` 都满足），所以「顶层段不含空白」
    是一条零误杀的拒绝判据。
    """
    assert _declared_arity(params) is None


def test_declared_arity_heuristic_boundary_is_documented() -> None:
    """诚实标注有界启发式的已知边界：漏写逗号这类语法错仍会被当成一个形参。

    要根治须引入 Java 类型语法解析器，那是另一个量级、且与本模块「有界启发式、
    未识别语法跳过而非报错」的定位不符。本用例把边界写成契约，避免它被误当成
    「已经验证过语法」。
    """
    assert _declared_arity("int a int b") == 1


def test_declared_arity_rejects_over_jvm_limit() -> None:
    """超 JVM 255 参数上限的声明不是真实可编译方法，不予采信。"""
    assert _declared_arity(", ".join(["int a"] * 255)) == 255
    assert _declared_arity(", ".join(["int a"] * 256)) is None


def test_declared_arity_bounded_on_adversarial_input() -> None:
    """样本可控的超长参数段：不得挂死，也不得返回一个巨大的可信 arity。"""
    assert _declared_arity("x," * (1024 * 1024)) is None


def test_malformed_declaration_never_reaches_structure(tmp_path: Path) -> None:
    """★接线锁：畸形声明整条不入 structure，且 coverage 诚实降为 partial。

    单测 `_declared_arity` 返回 None 证明不了「调用方真的丢弃了它」——本用例走
    `scan_java_sources` 真入口。夹具里 `g(,,,,)` 若被折叠成 `g/0`，就会与真实的
    零参方法撞进同一身份空间，而 `_index_methods` 按同 id 合并出边。
    """
    scan = _scan(
        tmp_path,
        "package com.a;\n"
        "public class A {\n"
        "    public void f() {\n"
        "    }\n"
        "    public void g(,,,,) {\n"
        "    }\n"
        "}\n",
    )
    entries = [
        (method["name"], method["arity"])
        for cls in scan.structure
        for method in cls["methods"]  # type: ignore[union-attr]
    ]
    assert ("f", 0) in entries, "良构声明必须照常入索引"
    assert not any(name == "g" for name, _ in entries), "畸形声明整条都不得入索引"
    assert scan.coverage == "partial", "丢弃了声明就不能再声称 complete"


def test_generic_and_plain_overloads_get_distinct_identities(tmp_path: Path) -> None:
    """★重载塌缩锁：泛型重载与普通重载必须落成两个独立身份。

    旧的 `split(",")` 计数把 `handle(Map<String, String> m)` 也算成 2 个参数，
    于是它与 `handle(String a, String b)` 塌缩成同一个 `handle/2`——`_index_methods`
    按同 id **合并出边**（产生伪调用路径），`_regions_by_identity` 把两个不同方法的
    区间混进同一身份组（ownership 比对失真）。与畸形参数那条不同，这发生在
    **完全合法的 Java 代码**上：泛型重载很常见。
    """
    scan = _scan(
        tmp_path,
        "package com.a;\n"
        "public class A {\n"
        "    public void handle(Map<String, String> m) {\n"
        "    }\n"
        "    public void handle(String a, String b) {\n"
        "    }\n"
        "}\n",
    )
    entries = sorted(
        (method["name"], method["arity"])
        for cls in scan.structure
        for method in cls["methods"]  # type: ignore[union-attr]
    )
    assert entries == [("handle", 1), ("handle", 2)], "两个重载必须是两个独立身份"


def test_wellformed_generic_declaration_keeps_coverage_complete(tmp_path: Path) -> None:
    """对照组：全良构（含泛型参数）时不得误判为畸形而降级 coverage。"""
    scan = _scan(
        tmp_path,
        "package com.a;\n"
        "public class A {\n"
        "    public void h(Map<String, String> m, int n) {\n"
        "    }\n"
        "}\n",
    )
    entries = [
        (method["name"], method["arity"])
        for cls in scan.structure
        for method in cls["methods"]  # type: ignore[union-attr]
    ]
    assert ("h", 2) in entries
    assert scan.coverage == "complete"
