"""P2-C：ownership 摘要落报告可见面（不动 verdict）。红态契约。

真入口 = JadxAnalyzer.analyze(ctx)；ctx.jadx_baseline_index 为 opt-in 通道
（须同时启用 jadx_cache_root）。设计见本地 specs §P2-C。

红线：断言「带 baseline 与不带 baseline 的分析产出除新增摘要键外 byte-for-byte 一致」
——INHERITED_OFFICIAL 绝不能被排版成鉴真结论，摘要绝不影响任何 verdict。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from apkscan.analyzers import jadx
from apkscan.analyzers.jadx import JadxAnalyzer
from tests.conftest import FakeContext
from tests.test_jadx_index_wiring import _ctx, _owned, _patch  # 复用 P2-A 夹具

# 结构投影要有方法 region 才有 match 可数——P2-A 公共夹具的单行类没有方法，
# 这里换成带方法体的类（JADX 形态：类声明与 { 同行、方法可被结构提取器识别）。
_JAVA_WITH_METHODS = (
    "class Alpha {\n"
    "    void work() {\n"
    '        String u = "https://cfg-host.example/api";\n'
    "    }\n"
    "}\n"
)


def _patch_with_methods(monkeypatch: pytest.MonkeyPatch) -> None:
    """run_owned 替身：--version 分流 + 写带方法的合成 java 树。"""

    def _run(cmd, *, timeout, env=None):  # noqa: ANN001
        if "--version" in cmd:
            return _owned(0, stdout="1.5.2\n")
        out_dir = Path(cmd[cmd.index("-d") + 1])
        pkg = out_dir / "sources" / "com" / "x"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "Alpha.java").write_text(_JAVA_WITH_METHODS, encoding="utf-8")
        return _owned(0)

    monkeypatch.setattr(jadx.proctree, "run_owned", _run)


# ---------------------------------------------------------------------------
# 夹具：先跑一次 analyze 建 baseline 索引，再对 subject 启用 baseline key
# ---------------------------------------------------------------------------


def _built_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[FakeContext, str]:
    """建一份索引并返回 (ctx, key)：同一 ctx 再次 analyze 会 reused 同 key。"""
    _patch_with_methods(monkeypatch)
    ctx = _ctx(tmp_path)
    result = JadxAnalyzer().analyze(ctx)
    assert result.meta["jadx_index_status"] == "built"
    return ctx, result.meta["jadx_index_key"]


def test_no_baseline_no_summary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """不给 baseline → 现行为：无 jadx_ownership_summary 键。"""
    ctx, _ = _built_key(tmp_path, monkeypatch)
    result = JadxAnalyzer().analyze(ctx)
    assert "jadx_ownership_summary" not in result.meta


def test_baseline_without_cache_root_ignored(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """只给 baseline、不给 cache root → 索引整体 disabled，摘要不出现（opt-in 前提）。"""
    _patch(monkeypatch)
    ctx = _ctx(tmp_path, cache=False)
    ctx.jadx_baseline_index = "a" * 64
    result = JadxAnalyzer().analyze(ctx)
    assert result.meta["jadx_index_status"] == "disabled"
    assert "jadx_ownership_summary" not in result.meta


def test_summary_self_comparison_all_match(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★subject 对自身索引作 baseline：全 match；四个防误读字段一个不能少。"""
    ctx, key = _built_key(tmp_path, monkeypatch)
    ctx.jadx_baseline_index = key
    result = JadxAnalyzer().analyze(ctx)
    summary = result.meta["jadx_ownership_summary"]
    # ★四个防误读字段：缺一即是在把结构匹配排版成鉴真结论。
    assert summary["baseline_designation"] == "caller_asserted_official"
    assert summary["comparison_semantics"] == "structural_match_only"
    assert summary["authenticity_asserted"] is False
    assert summary["verdict_effect"] == "none"
    # 身份与计数。
    assert summary["baseline_index_key"] == key
    assert summary["subject_index_key"] == key
    assert summary["baseline_manifest_digest"].startswith("sha256:")
    assert summary["matches"] >= 1  # 合成树至少一个方法，自比全 match
    assert summary["modified"] == 0
    assert summary["absent"] == 0
    assert isinstance(summary["absence_claimable"], bool)
    assert summary["subject_coverage"] in ("complete", "partial")
    assert summary["baseline_coverage"] in ("complete", "partial")


def test_baseline_key_syntax_checked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """baseline key 语法非法 → 摘要 unavailable + 稳定 reason，主分析照常。"""
    ctx, _ = _built_key(tmp_path, monkeypatch)
    ctx.jadx_baseline_index = "NOT-A-KEY"
    result = JadxAnalyzer().analyze(ctx)
    summary = result.meta["jadx_ownership_summary"]
    assert summary["status"] == "unavailable"
    assert all(c.islower() or c.isdigit() or c == "_" for c in summary["reason"])
    assert result.meta["jadx_status"] == "ok"


def test_baseline_missing_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """baseline key 合法但 cache 里没有 → unavailable，不影响 subject 索引状态。"""
    ctx, _ = _built_key(tmp_path, monkeypatch)
    ctx.jadx_baseline_index = "f" * 64
    result = JadxAnalyzer().analyze(ctx)
    assert result.meta["jadx_index_status"] == "reused"  # subject 不受牵连
    summary = result.meta["jadx_ownership_summary"]
    assert summary["status"] == "unavailable"


def test_verdict_surface_byte_identical_with_and_without_baseline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★红线：除新增摘要键外，带/不带 baseline 的产出 byte-for-byte 一致。"""
    ctx, key = _built_key(tmp_path, monkeypatch)
    plain = JadxAnalyzer().analyze(ctx)
    ctx.jadx_baseline_index = key
    with_baseline = JadxAnalyzer().analyze(ctx)

    def _canon(result, *, drop: set[str]) -> str:  # noqa: ANN001
        meta = {k: v for k, v in result.meta.items() if k not in drop}
        # receipt.index.baseline 是设计要求的比较留痕（记录面），不属于 verdict 面；
        # 红线比较剔除它——其余 receipt 内容必须逐字节一致。
        receipt = meta.get("jadx_receipt")
        if isinstance(receipt, dict):
            index_block = receipt.get("index")
            if isinstance(index_block, dict):
                index_block = {k: v for k, v in index_block.items() if k != "baseline"}
                receipt = {**receipt, "index": index_block}
                meta = {**meta, "jadx_receipt": receipt}
        payload = {
            "meta": meta,
            "endpoints": [e.value for e in result.endpoints],
            "findings": [f.id for f in result.findings],
            "error": result.error,
        }
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)

    assert _canon(plain, drop={"jadx_ownership_summary"}) == _canon(
        with_baseline, drop={"jadx_ownership_summary"}
    )


def test_meta_key_registered() -> None:
    assert JadxAnalyzer.meta_key_categories.get("jadx_ownership_summary") == "record"


def test_digest_comparison_subsection(tmp_path: Path) -> None:
    """digest 透出：摘要嵌在 jadx_index.comparison 小节下并带非鉴真 caveat。"""
    from apkscan.report.digest import build_digest

    key = "a1" * 32
    report = {
        "meta": {
            "jadx_index_status": "built",
            "jadx_index_key": key,
            "jadx_ownership_summary": {
                "baseline_designation": "caller_asserted_official",
                "comparison_semantics": "structural_match_only",
                "authenticity_asserted": False,
                "verdict_effect": "none",
                "baseline_index_key": "b2" * 32,
                "subject_index_key": key,
                "baseline_manifest_digest": "sha256:" + "c3" * 32,
                "matches": 5, "modified": 1, "absent": 2,
                "absence_claimable": True,
                "subject_coverage": "complete", "baseline_coverage": "complete",
            },
        },
        "leads": [],
    }
    d = build_digest(report)
    comparison = d["jadx_index"]["comparison"]
    assert comparison["matches"] == 5
    assert comparison["authenticity_asserted"] is False
    # 非鉴真 caveat 必须直接可见——INHERITED_OFFICIAL 绝不能被排版成鉴真结论。
    assert "非鉴真" in comparison["caveat"] or "结构匹配" in comparison["caveat"]
    # 无摘要时 digest 无 comparison 小节。
    d2 = build_digest({"meta": {"jadx_index_status": "built", "jadx_index_key": key}, "leads": []})
    assert "comparison" not in d2["jadx_index"]
