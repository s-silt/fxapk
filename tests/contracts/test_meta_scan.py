"""扫描器自身的测试 —— 整套 meta 契约的地基，它错了全盘皆错。

★为什么这份测试要先于扫描器的任何使用方存在：基线集合由扫描器生成，
  若它漏扫一种写法，那个键就不会进基线，后面所有检查都建在错的集合上，
  而且**错得无声无息**（正是本机制要治的那种缺陷形态）。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.contracts import meta_scan


def _keys(src: str, kind: str) -> set[str]:
    return {a.key for a in meta_scan.scan_source(src) if a.kind == kind}


def _dynamic(src: str) -> list[meta_scan.Access]:
    return [a for a in meta_scan.scan_source(src) if a.key.startswith("<dynamic")]


# --- 写入的各种写法 ---------------------------------------------------------

WRITE_CASES = [
    pytest.param('report.meta["a"] = 1', {"a"}, id="下标赋值"),
    pytest.param('state.meta["b"] = 1', {"b"}, id="state.meta"),
    pytest.param('result.meta["c"] = 1', {"c"}, id="result.meta"),
    pytest.param('meta["d"] = 1', {"d"}, id="裸 meta 变量"),
    pytest.param('report.meta.setdefault("e", [])', {"e"}, id="setdefault"),
    pytest.param('report.meta.update({"f": 1, "g": 2})', {"f", "g"}, id="update 字典字面量"),
    pytest.param('report.meta.update(h=1)', {"h"}, id="update 关键字参数"),
    pytest.param('m = state.meta\nm["i"] = 1', {"i"}, id="别名传播"),
    pytest.param('raw_meta = report.get("meta")\nraw_meta["j"] = 1', {"j"}, id="report.get(meta) 别名"),
]


@pytest.mark.parametrize(("src", "expect"), WRITE_CASES)
def test_write_forms_are_detected(src: str, expect: set[str]) -> None:
    """每种写法都必须被认出——漏一种，那种写法写的键就永远进不了基线。"""
    assert _keys(src, "write") >= expect


# --- 读取的各种写法 ---------------------------------------------------------

READ_CASES = [
    pytest.param('x = report.meta["a"]', {"a"}, id="下标读取"),
    pytest.param('x = report.meta.get("b")', {"b"}, id="get"),
    pytest.param('x = report.meta.get("c", None)', {"c"}, id="get 带默认值"),
    pytest.param('x = report.meta.pop("d", None)', {"d"}, id="pop"),
    pytest.param('m = report.meta\nx = m.get("e")', {"e"}, id="别名后读取"),
]


@pytest.mark.parametrize(("src", "expect"), READ_CASES)
def test_read_forms_are_detected(src: str, expect: set[str]) -> None:
    """漏认读取方 = 把一个有人消费的键误判成孤儿，进而被错误地清理掉。"""
    assert _keys(src, "read") >= expect


# --- 动态键：必须暴露，绝不静默跳过 ------------------------------------------


DYNAMIC_CASES = [
    pytest.param('report.meta[key] = 1', id="变量作键"),
    pytest.param('report.meta[f"{name}_count"] = 1', id="f-string 作键"),
    pytest.param('report.meta.update(other)', id="update 非字面量字典"),
    pytest.param('report.meta.update(**kw)', id="update 双星展开"),
    pytest.param('x = report.meta.get(key)', id="变量作键读取"),
]


@pytest.mark.parametrize("src", DYNAMIC_CASES)
def test_dynamic_keys_are_surfaced_not_dropped(src: str) -> None:
    """★动态键必须记进 unresolved。

    静默跳过等于给「绕过契约」留一条无声的路：写 ``meta[k] = v`` 就能凭空造一个
    不在任何基线里的键，而没有任何检查会红。这与本机制要治的缺陷是同一形态。
    """
    assert _dynamic(src), f"动态键被静默跳过了：{src!r}"


# --- 生产 / 测试消费必须分开 -------------------------------------------------


def test_production_and_test_consumers_are_separated(tmp_path: Path) -> None:
    """★这条锁的是那 66 个「只有测试读」的键。

    若扫描把 tests/ 的读取算作消费方，这批键会假装合格通过检查——
    而它们恰恰是问题最集中的一批（有人写、有测试读、但**产物链路上无人消费**）。
    """
    (tmp_path / "apkscan").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "apkscan" / "w.py").write_text(
        'def f(report):\n    report.meta["only_test_reads"] = 1\n', encoding="utf-8"
    )
    (tmp_path / "tests" / "t.py").write_text(
        'def test_x(report):\n    assert report.meta.get("only_test_reads")\n', encoding="utf-8"
    )

    res = meta_scan.scan_repository(tmp_path)

    assert "only_test_reads" in res.produced
    assert "only_test_reads" in res.test_consumed
    assert "only_test_reads" not in res.production_consumed
    assert "only_test_reads" in res.orphans(), "测试读取被误算成生产消费方"


def test_repository_scan_finds_real_known_keys() -> None:
    """在真仓库上跑一遍，锚定几个已知键，防止扫描器整体失效后所有断言空对空。"""
    root = Path(__file__).resolve().parents[2]
    res = meta_scan.scan_repository(root)

    assert len(res.produced) > 50, f"只扫到 {len(res.produced)} 个 meta 键，扫描器可能整体失效"
    # 这三个键的存在与消费关系是本次调查中人工确认过的事实
    assert "dex_strings_truncated" in res.produced
    assert "dex_strings_truncated" in res.production_consumed  # core/visibility.py 读它
    assert "app_classification" in res.produced


def test_template_scan_catches_jinja_reads() -> None:
    """模板是独立一路证据：本仓模板里有 ``meta.get("uniapp")`` 这类兼容旧键的读法，
    漏扫会把仍在被渲染的键误判成孤儿。"""
    root = Path(__file__).resolve().parents[2]
    tpl_keys = meta_scan.scan_templates(root / "apkscan")
    assert tpl_keys, "模板里一个 meta 读取都没扫到，正则或路径有问题"
