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


def test_ledger_written_and_replayable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
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
    #   P3-E2 起中段插入 visibility 块：QUESTION_OPENED + N×GAP_IDENTIFIED，
    #   N 从 anchor 取（同夹具确定）。
    vis_note = report.meta["jadx_judgment_ledger"]["visibility_gaps"]
    assert vis_note["appended"] is True
    assert kinds == [
        jl.EventType.RUN_OPENED,
        jl.EventType.QUESTION_OPENED,
        jl.EventType.GAP_IDENTIFIED,
        jl.EventType.QUESTION_OPENED,
        *[jl.EventType.GAP_IDENTIFIED] * vis_note["gap_count"],
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


def test_hash_failure_opens_no_ledger(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
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
        "jadx-usage-query",
        "jadx-ownership-projection",
    ]
    observations = [e for e in events if e.event_type is jl.EventType.OBSERVATION_ADDED]
    assert observations, "自比全 match 必须产 ownership 匹配观察"
    assert all(e.payload.observation_type == "jadx_ownership_match" for e in observations)


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
    forged_summary.update(
        {
            "status": "compared",
            "subject_index_key": real_key,
            "baseline_index_key": real_key,
            "baseline_manifest_digest": "sha256:"
            + hashlib.sha256(
                (Path(ctx.jadx_cache_root) / real_key / "manifest.json").read_bytes()
            ).hexdigest(),
        }
    )
    # current_index_key 与摘要 subject 不一致（伪造成另一个 key）→ 拒落。
    events = jrl._append_ownership_action_if_available(
        (),
        question=None,
        gap_id="gap-x",
        subjects=(),
        input_anchor_ids=(),  # type: ignore[arg-type]
        summary=forged_summary,
        cache_root=str(ctx.jadx_cache_root),
        producer=None,
        policy=None,
        actor=None,
        occurred_at="",  # type: ignore[arg-type]
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


# ---------------------------------------------------------------------------
# P3-E2：visibility gap 入账（spec 2026-08-19-p3e2-gap-ledger-wiring-design.md）
# ---------------------------------------------------------------------------

_VIS_PREDICATE = "analysis-visibility-recoverable"


def _questions(events: tuple[jl.LedgerEvent, ...]) -> list[object]:
    return [e.payload for e in events if e.event_type is jl.EventType.QUESTION_OPENED]


def _gaps(events: tuple[jl.LedgerEvent, ...]) -> list[object]:
    return [e.payload for e in events if e.event_type is jl.EventType.GAP_IDENTIFIED]


def _vis_question(events: tuple[jl.LedgerEvent, ...]) -> object:
    hits = [
        q
        for q in _questions(events)
        if any(c.predicate == _VIS_PREDICATE for c in q.allowed_conclusions)
    ]
    assert len(hits) == 1, f"visibility question 数={len(hits)}"
    return hits[0]


def _complete_visibility(*_args: object, **_kw: object) -> dict:
    sources = {
        name: {"visibility": "complete", "why": [], "inputs_seen": []}
        for name in ("dex", "java", "native", "resource", "runtime")
    }
    return {
        "schema_version": "1.1",
        "sources": sources,
        "claims": {},
        "blocked_claims": [],
        "remediation": "not_attempted",
        "notes": [],
        "next_actions": [],
        "degraded": False,
    }


def test_visibility_gaps_enter_ledger(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """L1 真入口：静态跑 runtime 恒 unknown → 至少一个 visibility gap 入账。"""
    _patch(monkeypatch)
    ctx = _ctx_with_cache(tmp_path)
    report, out_dir = _run(tmp_path, ctx)
    events = _read_chain(out_dir / _ledger_name(ctx))
    vq = _vis_question(events)
    vis_gaps = [g for g in _gaps(events) if g.question_id == vq.question_id]
    assert vis_gaps, "visibility question 下必须挂 gap"
    # runtime 未观测的具体档位由 assess 定（此夹具实测为 unavailable）；
    # 锁稳定的主张令牌，不锁易变档位。
    assert any("claim.runtime_contact_observed" in g.reason_codes for g in vis_gaps)
    anchor = report.meta["jadx_judgment_ledger"]["visibility_gaps"]
    assert anchor["appended"] is True
    assert anchor["gap_count"] == len(vis_gaps)
    assert anchor["question_id"] == vq.question_id


def test_no_blocked_claims_keeps_single_question(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """L2 无封锁主张 → 不开空 question，事件形态与旧版一致。"""
    _patch(monkeypatch)
    monkeypatch.setattr("apkscan.core.visibility.assess", _complete_visibility)
    ctx = _ctx_with_cache(tmp_path)
    report, out_dir = _run(tmp_path, ctx)
    events = _read_chain(out_dir / _ledger_name(ctx))
    assert len(_questions(events)) == 1
    anchor = report.meta["jadx_judgment_ledger"]["visibility_gaps"]
    assert anchor == {"appended": False, "reason": "no_blocked_claims"}


def test_missing_visibility_meta_skips_with_reason(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """L3 visibility 阶段崩掉 → meta 无键 → 显式 skip，主账本照常发布。"""
    _patch(monkeypatch)

    def _boom(*_args: object, **_kw: object) -> dict:
        raise RuntimeError("visibility stage down")

    monkeypatch.setattr("apkscan.core.visibility.assess", _boom)
    ctx = _ctx_with_cache(tmp_path)
    report, out_dir = _run(tmp_path, ctx)
    events = _read_chain(out_dir / _ledger_name(ctx))  # 主账本仍可 replay
    assert len(_questions(events)) == 1
    anchor = report.meta["jadx_judgment_ledger"]["visibility_gaps"]
    assert anchor == {"appended": False, "reason": "visibility_missing"}


def test_invalid_visibility_shape_skips_with_reason(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """L4 形状非法 → gap 生产 fail-closed 转显式 skip，绝不杀主账本。"""
    _patch(monkeypatch)
    monkeypatch.setattr(
        "apkscan.core.visibility.assess", lambda *_a, **_k: {"schema_version": "9.9"}
    )
    ctx = _ctx_with_cache(tmp_path)
    report, out_dir = _run(tmp_path, ctx)
    _read_chain(out_dir / _ledger_name(ctx))
    anchor = report.meta["jadx_judgment_ledger"]["visibility_gaps"]
    assert anchor["appended"] is False
    assert anchor["reason"] == "visibility_invalid"


def test_visibility_ids_deterministic_across_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """L5 同样本两次独立构建 → visibility question/gap id 逐一相同。"""
    _patch(monkeypatch)
    ids: list[tuple[str, tuple[str, ...]]] = []
    # ★同一份 APK 字节复制到两个目录：zipfile 会往 APK 里写时间戳，重建的
    #   "同内容" APK 跨秒即不同 sha → subjects 不同 → 封印必然漂移（曾以
    #   同秒巧合假绿过一轮）。确定性主张只对同字节样本成立。
    source_apk: bytes | None = None
    for name in ("one", "two"):
        base = tmp_path / name
        base.mkdir()
        if source_apk is None:
            source_apk = _apk(base).read_bytes()
        else:
            (base / "app.apk").write_bytes(source_apk)
        # 不走 _ctx_with_cache：它会重建 APK（新时间戳）冲掉同字节副本。
        ctx = FakeContext(apk_path=str(base / "app.apk"))
        ctx.jadx_cache_root = str(base / "jadx-cache")
        _report, out_dir = _run(base, ctx)
        events = _read_chain(out_dir / _ledger_name(ctx))
        vq = _vis_question(events)
        gap_ids = tuple(g.gap_id for g in _gaps(events) if g.question_id == vq.question_id)
        ids.append((vq.question_id, gap_ids))
    assert ids[0] == ids[1]


def test_duplicate_claim_never_kills_main_ledger(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """L6 重复主张 → gap 生产层拒绝 → 显式 skip 簿记；主账本必须照常发布。"""
    _patch(monkeypatch)
    doc = _complete_visibility()
    doc["blocked_claims"] = ["no_sms_interception", "no_sms_interception"]
    doc["sources"]["dex"]["visibility"] = "partial"
    monkeypatch.setattr("apkscan.core.visibility.assess", lambda *_a, **_k: doc)
    ctx = _ctx_with_cache(tmp_path)
    report, out_dir = _run(tmp_path, ctx)
    events = _read_chain(out_dir / _ledger_name(ctx))  # 主账本可 replay
    assert len(_questions(events)) == 1
    anchor = report.meta["jadx_judgment_ledger"]["visibility_gaps"]
    assert anchor == {"appended": False, "reason": "visibility_invalid"}


def test_append_failure_is_transactional_not_fatal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """L7 事务式护栏：gap 绑到不存在的 question（追加层契约异常）→
    回到原事件链 + 稳定 reason，绝不杀主账本。"""
    _patch(monkeypatch)
    from apkscan.core import gap_production as gp
    from apkscan.core import recognition_codec as codec
    from apkscan.core import recognition_contract as rc

    def _rogue_gaps(_visibility, *, question_id, producer):
        rogue = codec.build_evidence_gap(
            question_id="question-sha256:" + "ff" * 32,  # 账本中不存在
            claim_id=None,
            effect=rc.GapEffect.BLOCKS_CLAIM,
            reason_codes=("claim.fixture", "dex_visibility_partial"),
            required_observation_types=("dex_string_surface",),
            coverage_requirements=(),
            producer=producer,
        )
        return (rogue,)

    # 账本侧是函数内 from-import，同一模块对象——打在模块本体上才生效。
    monkeypatch.setattr(gp, "build_visibility_gaps", _rogue_gaps)
    ctx = _ctx_with_cache(tmp_path)
    report, out_dir = _run(tmp_path, ctx)
    events = _read_chain(out_dir / _ledger_name(ctx))
    assert len(_questions(events)) == 1  # visibility 块整体回滚
    anchor = report.meta["jadx_judgment_ledger"]["visibility_gaps"]
    assert anchor == {"appended": False, "reason": "visibility_ledger_append_failed"}


def test_e2e_first_nonempty_reanalysis_requests(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★P3 线里程碑锁（P3-E3 T6）：真入口 pipeline → sidecar →
    fxapk recognize reanalysis 首次产出非空请求（jadx_callpath）。

    java 面在本夹具由 stub jadx 产出（复杂度自然不完整——若某日夹具变
    complete，用 visibility monkeypatch 把 java 打成 partial 即可，勿放宽谓词）。"""
    from typer.testing import CliRunner

    from apkscan import cli as apkscan_cli

    _patch(monkeypatch)
    doc = _complete_visibility()
    doc["blocked_claims"] = ["static_endpoint_exhaustive"]
    doc["sources"]["java"]["visibility"] = "partial"
    monkeypatch.setattr("apkscan.core.visibility.assess", lambda *_a, **_k: doc)
    ctx = _ctx_with_cache(tmp_path)
    _report, out_dir = _run(tmp_path, ctx)
    sidecar = out_dir / _ledger_name(ctx)
    assert sidecar.exists()

    requests_out = tmp_path / "requests.jsonl"
    result = CliRunner().invoke(
        apkscan_cli.app,
        ["recognize", "reanalysis", str(sidecar), "--out", str(requests_out)],
    )
    assert result.exit_code == 0, result.output + (result.stderr or "")
    lines = [l for l in requests_out.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) >= 1  # ★诚实空时代结束的那一行
    import json as _json

    rows = [_json.loads(line) for line in lines]
    assert any(row["analysis_type"] == "jadx_callpath" for row in rows)
    receipt = _json.loads((tmp_path / "requests.jsonl.receipt.json").read_text("utf-8"))
    assert receipt["emitted"]["count"] >= 1
