"""覆盖度协议（``apkscan/core/coverage.py``）的契约测试。

这层协议存在的意义是让下游能区分「没有」与「没扫全」，故测试盯的是两件事：
键名拼装不许出错（拼错=痕迹静默丢失），以及收集时不许把「没发生」当成缺口。
"""

from __future__ import annotations

import pytest

from apkscan.core.coverage import (
    COVERAGE_SUFFIXES,
    collect_coverage,
    coverage_meta_key,
    coverage_meta_keys_for,
    iter_coverage_meta_keys,
)


def test_coverage_key_roundtrip() -> None:
    """键名按 ``<analyzer>_<suffix>`` 拼装；未知后缀必须抛而不是静默拼出个怪键。"""
    assert coverage_meta_key("card_merchant", "oversize_skipped") == "card_merchant_oversize_skipped"
    with pytest.raises(ValueError):
        coverage_meta_key("card_merchant", "not_a_real_suffix")


def test_keys_for_analyzer_covers_all_suffixes() -> None:
    keys = coverage_meta_keys_for("api_surface")
    assert len(keys) == len(COVERAGE_SUFFIXES)
    assert "api_surface_read_failed" in keys


def test_iter_keys_is_union_across_analyzers() -> None:
    keys = iter_coverage_meta_keys(["a", "b"])
    assert len(keys) == 2 * len(COVERAGE_SUFFIXES)
    assert {"a_list_failed", "b_list_failed"} <= keys


def test_collect_coverage_only_returns_truthy() -> None:
    """★只收真值：按「缺失=无事件」的约定，写进来的 0/False 是噪音。

    突变：把 ``collect_coverage`` 的真值判断去掉 → ``y_files_truncated: 0`` 混进结果 →
    消费方会把「没发生截断」渲染成一条覆盖缺口警告 → 本测试红。
    """
    got = collect_coverage(
        {"x_read_failed": 3, "y_files_truncated": 0, "z_budget_exhausted": False, "unrelated": 1}
    )
    assert got == {"x_read_failed": 3}


def test_collect_coverage_ignores_non_coverage_keys() -> None:
    """非覆盖度键（哪怕值为真）不得混进来——它们各有各的语义与消费方。"""
    assert collect_coverage({"card_merchant_count": 7, "sample_sha256": "0" * 64}) == {}
