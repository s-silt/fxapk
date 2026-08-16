"""P2-D2：查询账本 sidecar。红态契约。

真入口 = pipeline.run（启用持久索引时开账本流）。sidecar judgment_ledger.jsonl
canonical 编码、create-new、原子发布、replay 验证；引用锚放 meta 注册键、digest 透出。
subject = 样本 sha256（哈希失败不开账本流，绝不发空 subject）。
设计见本地 specs §P2-D2。
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from apkscan.analyzers.jadx import JadxAnalyzer
from apkscan.core import judgment_ledger as jl
from apkscan.core import pipeline
from apkscan.core.models import AnalysisConfig
from tests.conftest import FakeContext
from tests.test_jadx_index_wiring import _apk, _patch


@pytest.fixture(autouse=True)
def _stub_resolve_jadx(monkeypatch: pytest.MonkeyPatch) -> None:
    """CI 机器没有真 jadx——resolve 必须 stub，否则本文件在装了 jadx 的机器上绿、
    CI 上 disabled（环境巧合不是结论；同 conftest 的 adb 教训，P2-C 已犯过一次）。"""
    from apkscan.analyzers import jadx as jadx_mod

    monkeypatch.setattr(jadx_mod.tools, "resolve_jadx", lambda: (["jadx"], {}))

def _ledger_name(ctx: FakeContext) -> str:
    """sidecar 是样本寻址的（同 out 目录多样本不冲突）。"""
    sha = hashlib.sha256(Path(ctx.apk_path).read_bytes()).hexdigest()
    return f"judgment-ledger-{sha}.jsonl"


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
    assert not list(out_dir.glob("judgment-ledger-*.jsonl"))
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
    ledger_path = out_dir / _ledger_name(ctx)
    assert ledger_path.exists()
    events = _read_chain(ledger_path)
    kinds = [e.event_type for e in events]
    # ★精确事件序（单 usage 动作、hits=() 零观察、无 callpath、gap 驱动）。
    assert kinds == [
        jl.EventType.RUN_OPENED,
        jl.EventType.QUESTION_OPENED,
        jl.EventType.GAP_IDENTIFIED,
        jl.EventType.ACTION_PROPOSED,
        jl.EventType.ACTION_AUTHORIZED,
        jl.EventType.ACTION_OUTCOME_RECORDED,
    ]
    actions = [e.payload for e in events if e.event_type is jl.EventType.ACTION_PROPOSED]
    assert [a.action_type for a in actions] == ["jadx-usage-query"]  # 绝无 callpath
    # 授权契约锁：SYSTEM 自动策略、OFFLINE、policy_pre_authorized。
    from apkscan.core import recognition_contract as rc2

    (auth,) = [e.payload for e in events if e.event_type is jl.EventType.ACTION_AUTHORIZED]
    assert auth.granted_level is rc2.AuthorizationLevel.OFFLINE
    assert "policy_pre_authorized" in auth.reason_codes
    # nonce 恰 32 hex 且确定性派生（不含时间）。
    run_payload = events[0].payload
    assert len(run_payload.execution_nonce) == 32
    assert all(c in "0123456789abcdef" for c in run_payload.execution_nonce)
    # subject = 样本 sha256（复算比对）。
    expected_sha = hashlib.sha256(Path(ctx.apk_path).read_bytes()).hexdigest()
    run_event = events[0]
    subject = run_event.payload.subjects[0]  # type: ignore[union-attr]
    assert expected_sha in subject.value
    # 具名自动策略 actor：绝不伪装人签。
    from apkscan.core import recognition_contract as rc

    for event in events:
        assert event.actor.kind is not rc.ActorKind.HUMAN
        assert event.actor.actor_id == "fxapk.pipeline.auto_policy"

    # meta 锚：相对 locator + 字节 digest + 事件数 + replay 结果。
    anchor = report.meta["jadx_judgment_ledger"]
    assert anchor["locator"] == _ledger_name(ctx)  # 相对名，绝非绝对路径
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
    assert not list(out_dir.glob("judgment-ledger-*.jsonl"))
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
    preexisting = out_dir / _ledger_name(ctx)
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
            "locator": "judgment-ledger-" + "e5" * 32 + ".jsonl",
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


def test_ownership_action_lands_when_compared(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★baseline compared → 账本落第二个动作（jadx-ownership-projection），
    自比全 match 产 INHERITED_OFFICIAL 观察。"""
    from tests.test_jadx_ownership_wiring import _patch_with_methods

    _patch_with_methods(monkeypatch)
    ctx = _ctx_with_cache(tmp_path)
    # 第一跑建索引拿 key。
    report1, _ = _run(tmp_path, ctx)
    key = report1.meta["jadx_index_key"]
    # 第二跑自比 baseline，账本落到新 out 目录。
    ctx.jadx_baseline_index = key
    out2 = tmp_path / "out2"
    out2.mkdir()
    config = AnalysisConfig(online=False, out_dir=str(out2))
    report2 = pipeline.run(ctx, config)
    assert report2.meta["jadx_ownership_summary"]["status"] == "compared"
    events = _read_chain(out2 / _ledger_name(ctx))
    actions = [e.payload for e in events if e.event_type is jl.EventType.ACTION_PROPOSED]
    assert [a.action_type for a in actions] == [
        "jadx-usage-query", "jadx-ownership-projection",
    ]
    observations = [
        e for e in events if e.event_type is jl.EventType.OBSERVATION_ADDED
    ]
    assert observations, "自比全 match 必须产 ownership 匹配观察"
    assert all(
        e.payload.observation_type == "jadx_ownership_match" for e in observations
    )


def test_two_samples_share_out_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """★样本寻址 sidecar：两个不同 APK 共用 out 目录，各自成功发布、locator 不同。"""
    _patch(monkeypatch)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    anchors = []
    for i in range(2):
        sub = tmp_path / f"s{i}"
        sub.mkdir()
        # 两个 APK 内容必须不同（不同 sha256 → 不同 locator）；同内容样本共享账本是预期行为。
        apk = _apk(sub, dex_names=("classes.dex",) if i == 0 else ("classes.dex", "classes2.dex"))
        ctx = FakeContext(apk_path=str(apk))
        ctx.jadx_cache_root = str(sub / "jadx-cache")
        config = AnalysisConfig(online=False, out_dir=str(out_dir))
        report = pipeline.run(ctx, config)
        anchors.append(report.meta["jadx_judgment_ledger"])
    assert anchors[0]["replay_ok"] is True and anchors[1]["replay_ok"] is True
    assert anchors[0]["locator"] != anchors[1]["locator"]


def test_ownership_subject_key_mismatch_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★错配反例：摘要 subject_index_key 指向另一个有效索引 → ownership 动作拒落。"""
    import apkscan.core.jadx_run_ledger as jrl
    from tests.test_jadx_ownership_wiring import _patch_with_methods

    _patch_with_methods(monkeypatch)
    ctx = _ctx_with_cache(tmp_path)
    report1, _ = _run(tmp_path, ctx)
    real_key = report1.meta["jadx_index_key"]
    forged_summary = dict(report1.meta.get("jadx_ownership_summary") or {})
    forged_summary.update({
        "status": "compared",
        "subject_index_key": real_key,
        "baseline_index_key": real_key,
        "baseline_manifest_digest": "sha256:" + hashlib.sha256(
            (Path(ctx.jadx_cache_root) / real_key / "manifest.json").read_bytes()
        ).hexdigest(),
    })
    # current_index_key 与摘要 subject 不一致（伪造成另一个 key）→ 拒落。
    events = jrl._append_ownership_action_if_available(
        (), question=None, gap_id="gap-x", subjects=(), input_anchor_ids=(),  # type: ignore[arg-type]
        summary=forged_summary, cache_root=str(ctx.jadx_cache_root),
        producer=None, policy=None, actor=None, occurred_at="",  # type: ignore[arg-type]
        current_index_key="f" * 64,
    )
    assert events == ()


def test_stage_failure_never_degrades_analysis_status(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★账本 stage 异常 → stage_status 留痕但 analysis_status 不降级（附加消费面）。"""
    import apkscan.core.jadx_run_ledger as jrl

    _patch(monkeypatch)

    def _boom(**kwargs):  # noqa: ANN003, ANN202
        raise RuntimeError("ledger stage exploded")

    monkeypatch.setattr(jrl, "build_and_publish", _boom)
    ctx = _ctx_with_cache(tmp_path)
    report, _ = _run(tmp_path, ctx)
    assert report.analysis_status == "complete"
