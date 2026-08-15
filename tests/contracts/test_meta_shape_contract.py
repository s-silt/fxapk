"""契约 B：同一 meta 键的多个生产者，写入形状必须一致 —— 主契约 + 扫描器原语测试。

★锁的缺陷形态：``remote_config_artifacts`` 这类键由多条路径写（pipeline 授权档下载 /
cli config-probe 回灌），消费方（config/chain.py、corpus.py、closure/）按字段名
``art.get("...")`` 取值。一边加了字段另一边没加，不炸、不红，只是其中一条生产路径上
**永远取到 None**——比如 corpus 的跨样本串联突然在 config-probe 回灌的报告上失灵。
cli 侧写入处的注释已经手工声明「形状与 pipeline._fetch_decode_one 的返回逐字段对齐」，
本契约把那句注释变成会红的断言。

与契约 A 同一套三层纪律：主契约 + 生产者登记表（防扫描器失明后空转）+ 扫描器原语测试。
"""

from __future__ import annotations

import functools
from pathlib import Path

import pytest

from tests.contracts import meta_scan
from tests.contracts.meta_shape_scan import ShapeReport, collect_shapes, diff_shapes


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


@functools.lru_cache(maxsize=None)
def _collected(key: str) -> ShapeReport:
    """真仓库的形状收集，按键缓存；底层的全仓 meta 扫描只跑一次（贵）。"""
    return collect_shapes(_repo_root(), key, scan=_repo_scan())


@functools.lru_cache(maxsize=None)
def _repo_scan() -> meta_scan.ScanResult:
    return meta_scan.scan_repository(_repo_root())


# --- 主契约 -----------------------------------------------------------------

#: 受契约保护的键 → (生产者登记表, 显式声明的形状变体)。
#:
#: - 登记表 = {(文件, 函数)}：与现实双向严格相等。新写点在这里红——不是违规，
#:   是要求作者有意识地确认「新生产者的形状与既有生产者对齐」后登记。
#: - 变体 = {键集: 为什么允许它偏离主形状}。变体不是豁免口子：过期即红，
#:   且任何生产者都必须写得出主形状（只写变体的生产者会被 diff_shapes 点名）。
_PROTECTED: dict[str, tuple[set[tuple[str, str]], dict[frozenset[str], str]]] = {
    "remote_config_artifacts": (
        {
            ("apkscan/core/pipeline.py", "_stage_remote_config_fetch"),
            ("apkscan/cli.py", "_merge_config_probe_into_report"),
        },
        {
            # pipeline._fetch_decode_one 未取到字节时的占位记录：如实入账失败本身，
            # 不伪造 sha256/size。消费方按 sha256/decoded 缺失识别（corpus 注释即写明
            # 「authorized-active 才有 sha」）；cli 侧的对应做法是直接跳过无 sha256 的
            # outcome（「没取到字节的不是 artifact」），两边口径不同但各自成立。
            frozenset({"source_url", "decoded", "error"}):
                "下载失败占位记录（pipeline._fetch_decode_one 早退分支），消费方按 sha256 缺失识别",
        },
    ),
    "repack_quarantine": (
        {
            ("apkscan/core/pipeline.py", "_stage_build_leads"),
            ("apkscan/dynamic/merge.py", "_quarantine_leads"),
            ("apkscan/cli.py", "_merge_config_probe_into_report"),
        },
        # 审计块三处写入必须同形：values 是 closure 兜底门放行的唯一凭据，
        # 哪一处少写 values，那条路径隔离的值就过不了闭环兜底门。
        {},
    ),
}


@pytest.mark.parametrize("key", sorted(_PROTECTED))
def test_multi_producer_meta_key_shapes_agree(key: str) -> None:
    """★主契约。红 = 某条生产路径写的字段集与其它路径不一致（或扫描器解析不了）。

    修法：把缺的字段补齐到**所有**生产者（对照报错里的参照键集），或在确属有意的
    偏离上补一条带理由的变体声明——绝不是改声明表把红按掉。
    """
    _, variants = _PROTECTED[key]
    report = _collected(key)
    problems = diff_shapes(report, variants)
    assert not problems, f"meta 键 {key!r} 的多生产者形状契约违规：\n  " + "\n  ".join(problems)


@pytest.mark.parametrize("key", sorted(_PROTECTED))
def test_producer_registry_matches_reality_both_ways(key: str) -> None:
    """生产者登记表双向相等：防扫描器失明（0 写点 = 0 形状 = 主契约空转假绿），
    也让「第 N+1 个生产者出现」成为一次显式确认。"""
    expected, _ = _PROTECTED[key]
    report = _collected(key)
    actual = {(f, fn) for f, fn, _line in report.sites}
    added = actual - expected
    removed = expected - actual
    problems = [f"新增生产者（确认形状对齐后登记）：{p}" for p in sorted(added)]
    problems += [f"生产者已消失（有意删除请注销）：{p}" for p in sorted(removed)]
    assert not problems, f"meta 键 {key!r} 生产者登记表与现实不一致：\n  " + "\n  ".join(problems)


# --- 扫描器原语：每种解析形态与每个「该红的方向」都要有自己的测试 -----------


def _write_repo(tmp_path: Path, prod: dict[str, str]) -> Path:
    (tmp_path / "apkscan").mkdir(parents=True, exist_ok=True)
    for name, src in prod.items():
        (tmp_path / "apkscan" / name).write_text(src, encoding="utf-8")
    return tmp_path


def _keysets(report: ShapeReport) -> set[frozenset[str]]:
    return {s.keys for s in report.shapes}


def test_identical_literal_shapes_across_files_are_clean(tmp_path: Path) -> None:
    root = _write_repo(tmp_path, {
        "a.py": 'def f(report):\n    report.meta["k"] = {"x": 1, "y": 2}\n',
        "b.py": 'def g(report):\n    report.meta["k"] = {"y": 4, "x": 3}\n',
    })
    report = collect_shapes(root, "k")
    assert diff_shapes(report, {}) == []
    assert len(report.sites) == 2


def test_divergent_shape_names_the_missing_field(tmp_path: Path) -> None:
    """★核心红方向：一边少一个字段。报错必须指名生产者和缺的字段。"""
    root = _write_repo(tmp_path, {
        "a.py": 'def f(report):\n    report.meta["k"] = {"x": 1, "y": 2}\n',
        "b.py": 'def g(report):\n    report.meta["k"] = {"x": 3}\n',
    })
    problems = diff_shapes(collect_shapes(root, "k"), {})
    assert problems, "形状分裂没有被发现"
    joined = "\n".join(problems)
    assert "'y'" in joined, "报错必须点名差的字段"
    assert "b.py" in joined and "g" in joined, "报错必须点名生产者"


def test_append_literal_is_a_shape(tmp_path: Path) -> None:
    """cli._merge_config_probe_into_report 的真实形态：空列表 + append 字面量。"""
    root = _write_repo(tmp_path, {
        "a.py": ('def f(report, items):\n'
                 '    arts = []\n'
                 '    for it in items:\n'
                 '        arts.append({"u": it, "v": 1})\n'
                 '    report.meta["k"] = arts\n'),
    })
    report = collect_shapes(root, "k")
    assert _keysets(report) == {frozenset({"u", "v"})}
    assert report.unresolved == []


def test_listcomp_over_module_helper_uses_its_return_shapes(tmp_path: Path) -> None:
    """pipeline._stage_remote_config_fetch 的真实形态：推导式调同模块 helper，
    形状 = helper 每条 return 的 dict 字面量（含失败早退的变体分支）。"""
    root = _write_repo(tmp_path, {
        "a.py": ('def _one(x):\n'
                 '    if not x:\n'
                 '        return {"u": None, "err": 1}\n'
                 '    return {"u": x, "v": 1, "w": 2}\n'
                 '\n'
                 'def f(report, items):\n'
                 '    arts = [_one(x) for x in items]\n'
                 '    report.meta["k"] = arts\n'),
    })
    report = collect_shapes(root, "k")
    assert _keysets(report) == {frozenset({"u", "err"}), frozenset({"u", "v", "w"})}
    assert report.unresolved == []


def test_rereading_same_key_produces_no_shape(tmp_path: Path) -> None:
    """回读已写值再写回（merge/cli 的并入写法）不产形状——它的形状在真正
    创造它的写点被检查，重复计会把旧值形状错算到并入点头上。"""
    root = _write_repo(tmp_path, {
        "a.py": ('def f(report):\n'
                 '    arts = report.meta.get("k")\n'
                 '    if not isinstance(arts, list):\n'
                 '        arts = []\n'
                 '    report.meta["k"] = arts\n'),
    })
    report = collect_shapes(root, "k")
    assert report.shapes == []
    assert report.unresolved == []
    assert len(report.sites) == 1


def test_setdefault_literal_with_later_subscript_grows_the_shape(tmp_path: Path) -> None:
    """merge._quarantine_leads 的真实形态：setdefault 字面量 + 绑定名下标写。
    下标新增的键必须并进形状——否则单边加字段的漂移会隐形。"""
    root = _write_repo(tmp_path, {
        "a.py": ('def f(report, vals):\n'
                 '    blob = report.meta.setdefault("k", {"reason": 1, "values": []})\n'
                 '    blob["values"] = vals\n'
                 '    blob["extra"] = 1\n'),
    })
    report = collect_shapes(root, "k")
    assert _keysets(report) == {frozenset({"reason", "values", "extra"})}


def test_opaque_binding_is_unresolved_not_silent(tmp_path: Path) -> None:
    root = _write_repo(tmp_path, {
        "a.py": ('def f(report):\n'
                 '    arts = build()\n'
                 '    report.meta["k"] = arts\n'),
    })
    report = collect_shapes(root, "k")
    assert report.shapes == []
    assert len(report.unresolved) == 1
    assert "build" in report.unresolved[0]
    assert diff_shapes(report, {}), "unresolved 必须让契约红"


def test_unknown_mutation_method_is_unresolved(tmp_path: Path) -> None:
    root = _write_repo(tmp_path, {
        "a.py": ('def f(report, other):\n'
                 '    arts = []\n'
                 '    arts.absorb(other)\n'
                 '    report.meta["k"] = arts\n'),
    })
    report = collect_shapes(root, "k")
    assert any("absorb" in u for u in report.unresolved)


def test_escape_into_unknown_call_is_unresolved(tmp_path: Path) -> None:
    """名字被传给未知调用后形状可在别处被改——静态追不了，必须红不能赌。"""
    root = _write_repo(tmp_path, {
        "a.py": ('def f(report):\n'
                 '    arts = [{"u": 1}]\n'
                 '    fill(arts)\n'
                 '    report.meta["k"] = arts\n'),
    })
    report = collect_shapes(root, "k")
    assert any("fill" in u for u in report.unresolved)


def test_declared_variant_is_allowed_and_stale_declaration_is_flagged(tmp_path: Path) -> None:
    root = _write_repo(tmp_path, {
        "a.py": ('def f(report):\n'
                 '    report.meta["k"] = [{"u": 1, "v": 2}, {"u": 1, "err": 2}]\n'),
    })
    report = collect_shapes(root, "k")
    variant = frozenset({"u", "err"})
    assert diff_shapes(report, {variant: "失败占位"}) == []
    # 声明了但现实里没人写的变体 = 过期豁免，必须红
    stale = frozenset({"u", "gone"})
    problems = diff_shapes(report, {variant: "失败占位", stale: "早删了"})
    assert any("过期" in p for p in problems)


def test_producer_emitting_only_variants_is_flagged(tmp_path: Path) -> None:
    """某生产者只写「变体」从不写主形状：要么它缺字段，要么变体声明名不副实。"""
    root = _write_repo(tmp_path, {
        "a.py": 'def f(report):\n    report.meta["k"] = [{"u": 1, "v": 2}]\n',
        "b.py": 'def g(report):\n    report.meta["k"] = [{"u": 1, "err": 2}]\n',
    })
    report = collect_shapes(root, "k")
    problems = diff_shapes(report, {frozenset({"u", "err"}): "失败占位"})
    assert any("只写已声明变体" in p for p in problems)


def test_no_shapes_at_all_is_vacuous_and_flagged(tmp_path: Path) -> None:
    """键没人写 → 契约空转，必须可见地红，不能假绿。"""
    root = _write_repo(tmp_path, {"a.py": "def f():\n    return 1\n"})
    report = collect_shapes(root, "k")
    problems = diff_shapes(report, {})
    assert any("空转" in p for p in problems)


def test_unrecognized_write_form_at_known_site_is_unresolved(tmp_path: Path) -> None:
    """meta_scan 记到写点但形状扫描器不认识的写法（如 |= 合并）必须落 unresolved：
    发现层与解析层的缝隙要可见，不能让新写法从缝里静默溜走。"""
    root = _write_repo(tmp_path, {
        "a.py": ('def f(report, other):\n'
                 '    report.meta.update(k=other)\n'),
    })
    report = collect_shapes(root, "k")
    assert report.shapes == []
    assert any("不认识该写法" in u for u in report.unresolved)
