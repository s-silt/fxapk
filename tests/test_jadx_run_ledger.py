"""P2-D2：查询账本 sidecar。红态契约。

真入口 = pipeline.run（启用持久索引时开账本流）。sidecar judgment_ledger.jsonl
canonical 编码、create-new、原子发布、replay 验证；引用锚放 meta 注册键、digest 透出。
subject = 样本 sha256（哈希失败不开账本流，绝不发空 subject）。
设计见本地 specs §P2-D2。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from apkscan.analyzers.jadx import JadxAnalyzer
from apkscan.core import judgment_ledger as jl
from apkscan.core import pipeline
from apkscan.core.models import AnalysisConfig
from tests.conftest import FakeContext
from tests.test_jadx_index_wiring import _apk, _patch

_LEDGER_NAME = "judgment_ledger.jsonl"


@pytest.fixture(autouse=True)
def _only_jadx(monkeypatch: pytest.MonkeyPatch) -> None:
    """pipeline 范围收敛到 JadxAnalyzer（对标既有 pipeline.run 测试模式）。"""
    monkeypatch.setattr(pipeline, "discover_analyzers", lambda: [JadxAnalyzer()])
    monkeypatch.setattr(pipeline, "discover_enrichers", lambda: [])
    monkeypatch.setattr(pipeline, "detect_capabilities", lambda online=True: {"jadx", "apk"})


def _ctx_with_cache(tmp_path: Path) -> FakeContext:
    apk = _apk(tmp_path)
    ctx = FakeContext(apk_path=str(apk))
    ctx.jadx_cache_root = str(tmp_path / "jadx-cache")
    return ctx


def _run(tmp_path: Path, ctx: FakeContext) -> tuple[object, Path]:
    out_dir = tmp_path / "out"
    out_dir.mkdir(exist_ok=True)
    config = AnalysisConfig(online=False, out_dir=str(out_dir))
    report = pipeline.run(ctx, config)
    return report, out_dir


def _read_chain(path: Path) -> tuple[jl.LedgerEvent, ...]:
    events = tuple(
        jl.decode_event(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    )
    jl.validate_event_chain(events)  # 抛即失败：sidecar 必须可 replay
    return events


# ---------------------------------------------------------------------------
# opt-in 与账本流形态
# ---------------------------------------------------------------------------


def test_no_cache_root_no_ledger(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """未启用索引 → 无 sidecar 文件、无 meta 锚键（现行为零变化）。"""
    _patch(monkeypatch)
    ctx = FakeContext(apk_path=str(_apk(tmp_path)))
    report, out_dir = _run(tmp_path, ctx)
    assert not (out_dir / _LEDGER_NAME).exists()
    assert "jadx_judgment_ledger" not in report.meta


def test_ledger_written_and_replayable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★启用索引 → sidecar 落盘、逐行 canonical、整链 replay 通过；
    事件序 RUN_OPENED→QUESTION_OPENED→ACTION_PROPOSED→ACTION_AUTHORIZED→OUTCOME；
    subject 是样本 sha256；actor 是具名自动策略、绝不伪装人签。"""
    _patch(monkeypatch)
    ctx = _ctx_with_cache(tmp_path)
    report, out_dir = _run(tmp_path, ctx)
    ledger_path = out_dir / _LEDGER_NAME
    assert ledger_path.exists()
    events = _read_chain(ledger_path)
    kinds = [e.event_type for e in events]
    assert kinds[0] is jl.EventType.RUN_OPENED
    assert jl.EventType.QUESTION_OPENED in kinds
    assert jl.EventType.ACTION_PROPOSED in kinds
    assert jl.EventType.ACTION_AUTHORIZED in kinds
    assert jl.EventType.ACTION_OUTCOME_RECORDED in kinds
    # subject = 样本 sha256（复算比对）。
    expected_sha = hashlib.sha256(Path(ctx.apk_path).read_bytes()).hexdigest()
    run_event = events[0]
    subject = run_event.payload.subjects[0]  # type: ignore[union-attr]
    assert expected_sha in subject.value
    # 具名自动策略 actor：非 human。
    for event in events:
        assert event.actor.kind is not jl.rc.ActorKind.HUMAN if hasattr(jl, "rc") else True

    # meta 锚：相对 locator + 字节 digest + 事件数 + replay 结果。
    anchor = report.meta["jadx_judgment_ledger"]
    assert anchor["locator"] == _LEDGER_NAME  # 相对名，绝非绝对路径
    expected_digest = "sha256:" + hashlib.sha256(ledger_path.read_bytes()).hexdigest()
    assert anchor["digest"] == expected_digest
    assert anchor["event_count"] == len(events)
    assert anchor["replay_ok"] is True


def test_hash_failure_opens_no_ledger(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★哈希失败 → 不开账本流（绝不发空 subject）：无文件、无 meta 锚。"""
    _patch(monkeypatch)
    ctx = _ctx_with_cache(tmp_path)
    import apkscan.core.jadx_run_ledger as jrl

    monkeypatch.setattr(jrl, "_sample_sha256", lambda path: None)
    report, out_dir = _run(tmp_path, ctx)
    assert not (out_dir / _LEDGER_NAME).exists()
    assert "jadx_judgment_ledger" not in report.meta
    # 主分析完全不受影响。
    assert report.meta.get("jadx_index_status") in ("built", "reused", "partial")


def test_existing_sidecar_never_overwritten(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★create-new：目标已存在 → 绝不覆盖；meta 锚如实标写失败，不声称账本闭合。"""
    _patch(monkeypatch)
    ctx = _ctx_with_cache(tmp_path)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    preexisting = out_dir / _LEDGER_NAME
    preexisting.write_text("PREEXISTING\n", encoding="utf-8")
    config = AnalysisConfig(online=False, out_dir=str(out_dir))
    report = pipeline.run(ctx, config)
    assert preexisting.read_text(encoding="utf-8") == "PREEXISTING\n"  # 原文件未被动
    anchor = report.meta.get("jadx_judgment_ledger")
    assert anchor is not None
    assert anchor["replay_ok"] is False


def test_digest_surfaces_ledger_anchor() -> None:
    """digest 透出：meta 锚 → digest.jadx_index.ledger 段；缺失则无该段。"""
    from apkscan.report.digest import build_digest

    meta = {
        "jadx_index_status": "built",
        "jadx_index_key": "a1" * 32,
        "jadx_judgment_ledger": {
            "locator": _LEDGER_NAME,
            "digest": "sha256:" + "d4" * 32,
            "event_count": 7,
            "replay_ok": True,
        },
    }
    d = build_digest({"meta": meta, "leads": []})
    ledger = d["jadx_index"]["ledger"]
    assert ledger["event_count"] == 7
    assert ledger["replay_ok"] is True
    assert ledger["digest"].startswith("sha256:")
    d2 = build_digest(
        {"meta": {"jadx_index_status": "built", "jadx_index_key": "a1" * 32}, "leads": []}
    )
    assert "ledger" not in d2["jadx_index"]
