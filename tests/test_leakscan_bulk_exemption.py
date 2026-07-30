"""护栏自身的完整性：批量按掉豁免要被看见、被拦住。

行内豁免只校验"有没有写理由"，不校验理由**成不成立**——写一句听着合理的话就能把该行的
全部判据关掉。真实发生过的形态是：门禁报了几十条阻断，于是用脚本把**同一句**理由批量贴到
每一行，再跑就绿了。那句理由是假的，而门禁看不出"批量按掉"与"逐条豁免"的区别。

机器判不了理由的真假，能判的是**动作形态**：同一条理由被复制到大量新增行。本文件钉住两件事：
① 超阈值即阻断；② 阈值以下的正常豁免一条都不误伤——本仓一次合法改动最多加过 17 条同理由
夹具（判据要求全球可路由字面，换合成值就失去被测形态），那种必须照常通过。
"""

from __future__ import annotations

from apkscan.core import leakscan
from apkscan.core.leakscan import _BULK_EXEMPTION_THRESHOLD as LIMIT


def _diff(lines: list[str], path: str = "tests/test_x.py") -> str:
    body = "".join(f"+{line}\n" for line in lines)
    return f"--- a/{path}\n+++ b/{path}\n@@ -0,0 +1,{len(lines)} @@\n{body}"


def _exempted(count: int, reason: str, *, start: int = 0) -> list[str]:
    """count 行各带一个豁免；值用文档保留段，确保只有豁免本身可能触发判据。"""
    return [f'    "192.0.2.{start + i}",  # leak-scan: allow {reason}' for i in range(count)]


def test_identical_reason_beyond_threshold_blocks() -> None:
    """★超阈值即红：这正是"用脚本把同一句理由贴满每一行"的形态。"""
    findings = leakscan.scan_diff(_diff(_exempted(LIMIT, "判据夹具，形态本身就是被测对象")))
    bulk = [f for f in findings if f.rule == "bulk_exemption"]
    assert len(bulk) == 1, f"应恰好一条 bulk_exemption，实得 {[f.rule for f in findings]}"
    assert str(LIMIT) in bulk[0].detail
    assert bulk[0].blocking is True, "护栏自身的完整性检查必须恒阻断"


def test_just_under_threshold_passes() -> None:
    """★阈值以下一条都不误伤：合法的成批夹具照常通过。"""
    findings = leakscan.scan_diff(_diff(_exempted(LIMIT - 1, "判据夹具，形态本身就是被测对象")))
    assert [f for f in findings if f.rule == "bulk_exemption"] == []


def test_distinct_reasons_do_not_aggregate() -> None:
    """按理由分组：逐条写出各自成立的理由，正是希望的做法，不该被罚。"""
    lines = [
        f'    "192.0.2.{i}",  # leak-scan: allow 第 {i} 条各自成立的理由'
        for i in range(LIMIT * 2)
    ]
    assert [f for f in leakscan.scan_diff(_diff(lines)) if f.rule == "bulk_exemption"] == []


def test_reason_whitespace_is_normalised_before_grouping() -> None:
    """靠多打几个空格来绕过分组，不算数。"""
    reason = "判据夹具，形态本身就是被测对象"
    lines = _exempted(LIMIT // 2, reason) + _exempted(
        LIMIT - LIMIT // 2, f"  {reason}   ", start=100
    )
    assert [f for f in leakscan.scan_diff(_diff(lines)) if f.rule == "bulk_exemption"]


def test_bulk_rule_counts_across_files() -> None:
    """跨文件复制同一句理由同样算——按文件分摊不该能绕过。"""
    half = LIMIT // 2 + 1
    diff = _diff(_exempted(half, "同一句"), "tests/a.py") + _diff(
        _exempted(half, "同一句", start=100), "tests/b.py"
    )
    bulk = [f for f in leakscan.scan_diff(diff) if f.rule == "bulk_exemption"]
    assert bulk and "2 个文件" in bulk[0].detail


def test_full_tree_scan_never_emits_the_bulk_rule(tmp_path) -> None:
    """★只在增量模式判。

    全树看到的是历史累积——单个文件里已有 45 条同理由的合法夹具。对它施压只会逼人把理由
    改花，护栏反而更弱；而且那是既有代码，不是这次改动做的事。
    """
    target = tmp_path / "legacy.py"
    target.write_text("\n".join(_exempted(LIMIT * 2, "历史累积的合法夹具")), encoding="utf-8")
    findings = leakscan.scan_paths([target], [])
    assert [f for f in findings if f.rule == "bulk_exemption"] == []


def test_exemptions_are_enumerable_for_reporting() -> None:
    """把"按掉了多少护栏"变成可呈现的数据——此前这件事完全不可见。"""
    entries = leakscan.iter_exemptions(_diff(_exempted(3, "某个理由")))
    assert len(entries) == 3
    assert {reason for _p, _l, reason in entries} == {"某个理由"}
    assert all(path == "tests/test_x.py" for path, _l, _r in entries)


def test_exemption_without_a_reason_is_not_counted_as_one() -> None:
    """没写理由的豁免走既有的 ``exemption`` 判据（恒阻断），不混进批量统计。"""
    diff = _diff(['    "192.0.2.1",  # leak-scan: allow'])
    assert leakscan.iter_exemptions(diff) == []
    assert [f for f in leakscan.scan_diff(diff) if f.rule == "exemption"]


def test_bulk_rule_is_registered_and_blocking() -> None:
    """判据名进 RULES、且在默认档就阻断——不能只在 --strict 下才有牙。"""
    assert "bulk_exemption" in leakscan.RULES
    assert "bulk_exemption" in leakscan.BLOCKING_RULES
