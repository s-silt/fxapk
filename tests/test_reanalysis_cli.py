"""P3-D 红态契约：``fxapk recognize reanalysis``（profile p2d2-v1）。

真入口 = CliRunner 调 ``fxapk recognize reanalysis <ledger.jsonl> --out <requests.jsonl>``。
核心不变量（设计见本地 P3 v4 spec §1.5/§3/§6 P3-D）：
- 输入 profile p2d2-v1：单 run 单 question、SAMPLE subject 恰一且 64hex、账本
  decode/链校验/replay 全过才开始重建；违反 → 非零退出、零输出文件；
- 合法输入无产出 = 成功空文件 + receipt（与非法输入严格可区分）；
- 双文件 create-only：任一目标已存在 → 动工前拒绝；
- 授权提示走 stderr、无 quiet 抑制路径；CLI 零网络/零子进程；
- ``--ledger-out`` 是 P3-C 投影的生产接线：有提案时发布扩展链 sidecar。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkscan import cli
from apkscan.commands import reanalysis_cli
from apkscan.core import judgment_ledger as jl
from apkscan.core import reanalysis as rp
from apkscan.core import reanalysis_contract as rxc
from apkscan.core import recognition_codec as codec
from apkscan.core import recognition_contract as rc
from tests.recognition_fixtures import (
    FIXED_TIME,
    make_actor,
    make_anchor,
    make_policy,
    make_producer,
)

runner = CliRunner()

HEX_SAMPLE = "e" * 64
_SUBJECT = rc.SubjectRef(kind=rc.SubjectKind.SAMPLE, value=HEX_SAMPLE, role=None)


def _question(predicate: str = "p3d-observation-surface"):
    return codec.build_question(
        question_type=rc.QuestionType.PLAN_REANALYSIS,
        subjects=(_SUBJECT,),
        allowed_conclusions=(
            rc.AllowedConclusion(
                predicate=predicate,
                claim_modes=(rc.ClaimMode.POSITIVE,),
                object_kind=rc.ObjectKind.NONE,
                allowed_categorical_values=(),
            ),
        ),
    )


def _gap(question, reason: str = "p3d-fixture-reason"):
    return codec.build_evidence_gap(
        question_id=question.question_id,
        claim_id=None,
        effect=rc.GapEffect.BLOCKS_REVIEW,
        reason_codes=(reason,),
        required_observation_types=("jadx_value_usage",),
        coverage_requirements=(),
        producer=make_producer(rc.ProducerKind.SYSTEM),
    )


def _ledger_events(*, extra_question=None):
    run = codec.build_reasoning_run(
        execution_nonce="4" * 32,
        purpose="p3d_cli_fixture",
        subjects=(_SUBJECT,),
        input_anchors=(make_anchor(),),
        initial_coverage=(),
        policies=(make_policy(),),
        producers=(make_producer(),),
    )
    actor = make_actor()
    question = _question()
    events = jl.append_event((), jl.make_event((), jl.EventType.RUN_OPENED, actor, FIXED_TIME, run))
    events = jl.append_event(
        events,
        jl.make_event(events, jl.EventType.QUESTION_OPENED, actor, FIXED_TIME, question),
    )
    if extra_question is not None:
        events = jl.append_event(
            events,
            jl.make_event(events, jl.EventType.QUESTION_OPENED, actor, FIXED_TIME, extra_question),
        )
    events = jl.append_event(
        events,
        jl.make_event(events, jl.EventType.GAP_IDENTIFIED, actor, FIXED_TIME, _gap(question)),
    )
    return events


def _write_ledger(path: Path, events) -> None:
    path.write_text(
        "\n".join(jl.encode_event(event) for event in events) + "\n",
        encoding="utf-8",
    )


@pytest.fixture()
def ledger_file(tmp_path: Path) -> Path:
    path = tmp_path / "judgment-ledger.jsonl"
    _write_ledger(path, _ledger_events())
    return path


def _invoke(ledger: Path, out: Path, *extra: str):
    return runner.invoke(
        cli.app,
        ["recognize", "reanalysis", str(ledger), "--out", str(out), *extra],
    )


def _mapped_policy(*types: rxc.AnalysisType):
    return rp.AdmissionPolicy(
        predicate_version="p3-admit-v1",
        mapping_version="p3d-test-mapping-v1",
        reason_mapping={"p3d-fixture-reason": tuple(types)},
        reduces_confidence_whitelist=frozenset(),
    )


# ---------------------------------------------------------------- 诚实空输出面


def test_default_policy_yields_empty_requests_and_receipt(ledger_file, tmp_path):
    out = tmp_path / "requests.jsonl"
    result = _invoke(ledger_file, out)
    assert result.exit_code == 0, result.output
    assert out.is_file() and out.read_bytes() == b""
    receipt = json.loads((tmp_path / "requests.jsonl.receipt.json").read_text("utf-8"))
    assert receipt["ledger_profile"] == "p3e2-v1"  # P3-E2 profile 演进
    assert receipt["questions_seen"] == 1
    assert receipt["gaps_seen"] == 1
    assert receipt["suppressed"]["unknown_reason"] == 1
    assert receipt["emitted"]["count"] == 0


def test_receipt_key_set_is_frozen(ledger_file, tmp_path):
    out = tmp_path / "requests.jsonl"
    assert _invoke(ledger_file, out).exit_code == 0
    receipt = json.loads((tmp_path / "requests.jsonl.receipt.json").read_text("utf-8"))
    assert set(receipt) == {
        "schema_version",
        "predicate_version",
        "mapping_version",
        "matrix_version",
        "ledger_profile",
        "questions_seen",
        "questions_planned",  # P3-E2 受控加键：实际进 planner 的 question 数
        "gaps_seen",
        "suppressed",
        "emitted",
        "ledger_sidecar",
    }
    assert set(receipt["suppressed"]) == {
        "not_open",
        "low_value",
        "unknown_reason",
        "over_ceiling",
    }
    assert receipt["ledger_sidecar"] is None  # 未给 --ledger-out


# ---------------------------------------------------------------- 非空产出与全序


def test_mapped_policy_emits_decodable_proposed_requests(ledger_file, tmp_path, monkeypatch):
    monkeypatch.setattr(
        reanalysis_cli,
        "DEFAULT_POLICY",
        _mapped_policy(rxc.AnalysisType.JADX_CALLPATH),
    )
    out = tmp_path / "requests.jsonl"
    result = _invoke(ledger_file, out)
    assert result.exit_code == 0, result.output
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    request = rxc.decode_reanalysis_request(json.loads(lines[0]))
    assert request.status is rxc.RequestStatus.PROPOSED
    assert request.analysis_type is rxc.AnalysisType.JADX_CALLPATH
    assert request.origin.input_digest == "sha256:" + HEX_SAMPLE


def test_output_is_totally_ordered(ledger_file, tmp_path, monkeypatch):
    monkeypatch.setattr(
        reanalysis_cli,
        "DEFAULT_POLICY",
        _mapped_policy(
            rxc.AnalysisType.JADX_CALLPATH,
            rxc.AnalysisType.JADX_STRUCTURAL_DIFF,
            rxc.AnalysisType.WEB_EVIDENCE,
        ),
    )
    out = tmp_path / "requests.jsonl"
    assert _invoke(ledger_file, out).exit_code == 0
    rows = [json.loads(line) for line in out.read_text("utf-8").splitlines()]
    assert len(rows) == 3
    rank = {"high": 0, "review": 1, "low": 2}
    keys = [
        (
            rank[row["priority"]["class"]],
            -row["priority"]["expected_information_gain"],
            row["dedupe_key"],
            row["request_id"],
        )
        for row in rows
    ]
    assert keys == sorted(keys)


# ---------------------------------------------------------------- 授权提示（stderr，不可抑制）


def test_above_offline_requests_warn_on_stderr(ledger_file, tmp_path, monkeypatch):
    monkeypatch.setattr(
        reanalysis_cli,
        "DEFAULT_POLICY",
        _mapped_policy(rxc.AnalysisType.PCAP_RUNTIME),
    )
    out = tmp_path / "requests.jsonl"
    result = _invoke(ledger_file, out)
    assert result.exit_code == 0
    stderr = result.stderr
    row = json.loads(out.read_text("utf-8").splitlines()[0])
    prefix = row["request_id"].split("sha256:")[-1][:12]
    assert prefix in stderr
    assert "pcap_runtime" in stderr
    assert "authorized_device" in stderr
    assert "proposed" in stderr and "未获授权" in stderr


def test_cli_has_no_quiet_escape_hatch():
    result = runner.invoke(cli.app, ["recognize", "reanalysis", "--help"])
    assert result.exit_code == 0
    assert "--quiet" not in result.output
    assert "空输出" in result.output  # help 明示「空输出≠无缺口」


# ---------------------------------------------------------------- 非法输入 fail-closed（与空结果严格可分）


@pytest.mark.parametrize("payload", [b"", b"\n\n", b"not json\n"])
def test_invalid_ledger_bytes_fail_closed(tmp_path, payload):
    ledger = tmp_path / "bad.jsonl"
    ledger.write_bytes(payload)
    out = tmp_path / "requests.jsonl"
    result = _invoke(ledger, out)
    assert result.exit_code != 0
    assert not out.exists()
    assert not (tmp_path / "requests.jsonl.receipt.json").exists()


def test_tampered_chain_fails_closed(tmp_path):
    events = _ledger_events()
    lines = [jl.encode_event(event) for event in events]
    lines[-1] = lines[-1].replace('"gap_identified"', '"gap_identifiee"')
    ledger = tmp_path / "tampered.jsonl"
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
    out = tmp_path / "requests.jsonl"
    result = _invoke(ledger, out)
    assert result.exit_code != 0
    assert not out.exists()


def test_multi_question_ledger_planned_per_question(tmp_path):
    """p3e2-v1 语义演进：多 question 合法，逐 question 分桶规划。

    此前 p2d2-v1 在此拒绝；P3-E2 起 visibility question 入账成为常态。
    exit 0 本身即分桶证明——validate_planning_context 对跨 question 混装
    fail-closed（gap_question_mismatch），不分桶到不了这里。
    """
    second = _question("p3e2-visibility-fixture")
    events = _ledger_events(extra_question=second)
    events = jl.append_event(
        events,
        jl.make_event(
            events,
            jl.EventType.GAP_IDENTIFIED,
            make_actor(),
            FIXED_TIME,
            _gap(second, reason="p3e2-vis-reason"),
        ),
    )
    ledger = tmp_path / "multi.jsonl"
    _write_ledger(ledger, events)
    out = tmp_path / "requests.jsonl"
    result = _invoke(ledger, out)
    assert result.exit_code == 0, result.output + result.stderr
    assert out.read_text(encoding="utf-8") == ""  # 默认空映射 → 诚实空
    receipt = json.loads((tmp_path / "requests.jsonl.receipt.json").read_text("utf-8"))
    assert receipt["ledger_profile"] == "p3e2-v1"
    assert receipt["questions_seen"] == 2
    assert receipt["gaps_seen"] == 2


def test_run_only_ledger_is_unsupported_profile(tmp_path):
    """零 question 仍拒：profile 演进只放宽上限，不放宽下限。"""
    run = codec.build_reasoning_run(
        execution_nonce="5" * 32,
        purpose="p3e2_run_only_fixture",
        subjects=(_SUBJECT,),
        input_anchors=(make_anchor(),),
        initial_coverage=(),
        policies=(make_policy(),),
        producers=(make_producer(),),
    )
    events = jl.append_event(
        (), jl.make_event((), jl.EventType.RUN_OPENED, make_actor(), FIXED_TIME, run)
    )
    ledger = tmp_path / "runonly.jsonl"
    _write_ledger(ledger, events)
    out = tmp_path / "requests.jsonl"
    result = _invoke(ledger, out)
    assert result.exit_code != 0
    assert "unsupported_ledger_profile" in result.output + result.stderr
    assert not out.exists()


# ---------------------------------------------------------------- 双文件 create-only


def test_existing_requests_target_refuses_before_work(ledger_file, tmp_path):
    out = tmp_path / "requests.jsonl"
    out.write_text("occupied", encoding="utf-8")
    result = _invoke(ledger_file, out)
    assert result.exit_code != 0
    assert out.read_text(encoding="utf-8") == "occupied"
    assert not (tmp_path / "requests.jsonl.receipt.json").exists()


def test_existing_receipt_target_refuses_and_leaves_no_requests(ledger_file, tmp_path):
    receipt = tmp_path / "requests.jsonl.receipt.json"
    receipt.write_text("occupied", encoding="utf-8")
    out = tmp_path / "requests.jsonl"
    result = _invoke(ledger_file, out)
    assert result.exit_code != 0
    assert not out.exists()
    assert receipt.read_text(encoding="utf-8") == "occupied"


# ---------------------------------------------------------------- 零副作用


def test_cli_spawns_no_subprocess_and_no_network(ledger_file, tmp_path, monkeypatch):
    import socket
    import subprocess

    def _boom(*_args, **_kwargs):
        raise AssertionError("CLI 不得触网/起子进程")

    for target in ("run", "Popen", "check_output", "check_call", "call"):
        monkeypatch.setattr(subprocess, target, _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    monkeypatch.setattr(socket.socket, "connect", _boom)

    out = tmp_path / "requests.jsonl"
    assert _invoke(ledger_file, out).exit_code == 0


# ---------------------------------------------------------------- --ledger-out：P3-C 的生产接线


def test_ledger_out_publishes_extended_chain(ledger_file, tmp_path, monkeypatch):
    monkeypatch.setattr(
        reanalysis_cli,
        "DEFAULT_POLICY",
        _mapped_policy(rxc.AnalysisType.JADX_CALLPATH),
    )
    sidecar_dir = tmp_path / "sidecars"
    out = tmp_path / "requests.jsonl"
    result = _invoke(ledger_file, out, "--ledger-out", str(sidecar_dir))
    assert result.exit_code == 0, result.output
    receipt = json.loads((tmp_path / "requests.jsonl.receipt.json").read_text("utf-8"))
    sidecar = receipt["ledger_sidecar"]
    assert sidecar["published"] is True and sidecar["replay_ok"] is True
    target = sidecar_dir / sidecar["locator"]
    events = tuple(jl.decode_event(line) for line in target.read_text("utf-8").splitlines())
    projection = jl.replay(events)
    assert len(projection.actions) == 1
    assert dict(projection.action_statuses)[projection.actions[0].action_id] is (
        jl.ActionStatus.PROPOSED
    )
    assert projection.authorizations == ()


def test_receipt_failure_rolls_back_requests(ledger_file, tmp_path, monkeypatch):
    # codex 复审：receipt 写入失败必须回滚 requests（不变量：receipt ⟺ requests）。
    real_create = reanalysis_cli.atomic_create_bytes
    calls = {"n": 0}

    def _second_fails(path, data):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("simulated receipt failure")
        return real_create(path, data)

    monkeypatch.setattr(reanalysis_cli, "atomic_create_bytes", _second_fails)
    out = tmp_path / "requests.jsonl"
    result = _invoke(ledger_file, out)
    assert result.exit_code != 0
    assert not out.exists()
    assert not (tmp_path / "requests.jsonl.receipt.json").exists()


def test_pair_failure_rolls_back_published_sidecar(ledger_file, tmp_path, monkeypatch):
    # codex 复审：--ledger-out 的 sidecar 先落盘，双文件失败时不得留孤儿。
    monkeypatch.setattr(
        reanalysis_cli,
        "DEFAULT_POLICY",
        _mapped_policy(rxc.AnalysisType.JADX_CALLPATH),
    )
    real_create = reanalysis_cli.atomic_create_bytes

    def _requests_fail(path, data):
        if str(path).endswith("requests.jsonl"):
            raise OSError("simulated requests failure")
        return real_create(path, data)

    monkeypatch.setattr(reanalysis_cli, "atomic_create_bytes", _requests_fail)
    sidecar_dir = tmp_path / "sidecars"
    out = tmp_path / "requests.jsonl"
    result = _invoke(ledger_file, out, "--ledger-out", str(sidecar_dir))
    assert result.exit_code != 0
    assert not out.exists()
    assert not sidecar_dir.exists() or not any(sidecar_dir.iterdir())


def test_ledger_out_without_proposals_publishes_nothing(ledger_file, tmp_path):
    sidecar_dir = tmp_path / "sidecars"
    out = tmp_path / "requests.jsonl"
    result = _invoke(ledger_file, out, "--ledger-out", str(sidecar_dir))
    assert result.exit_code == 0
    receipt = json.loads((tmp_path / "requests.jsonl.receipt.json").read_text("utf-8"))
    assert receipt["ledger_sidecar"] == {"published": False, "reason": "no_proposals"}
    assert not sidecar_dir.exists() or not any(sidecar_dir.iterdir())


def test_cross_question_dedupe_collision_fails_closed(tmp_path, monkeypatch):
    """C5（codex 复审 P1）：两 question 同 reason 同映射 → 同 dedupe_key。
    requests 双行而扩展账本静默跳一 = 三件套不一致——必须 fail-closed 拒发，
    不留任何输出文件。"""
    monkeypatch.setattr(
        reanalysis_cli,
        "DEFAULT_POLICY",
        _mapped_policy(rxc.AnalysisType.JADX_CALLPATH),
    )
    second = _question("p3e2-collision-fixture")
    events = _ledger_events(extra_question=second)
    events = jl.append_event(
        events,
        jl.make_event(events, jl.EventType.GAP_IDENTIFIED, make_actor(), FIXED_TIME, _gap(second)),
    )
    ledger = tmp_path / "collision.jsonl"
    _write_ledger(ledger, events)
    out = tmp_path / "requests.jsonl"
    sidecar_dir = tmp_path / "sidecar"
    sidecar_dir.mkdir()
    result = _invoke(ledger, out, "--ledger-out", str(sidecar_dir))
    assert result.exit_code != 0
    assert "ledger_projection_inconsistent" in result.output + result.stderr
    assert not out.exists()
    assert not (tmp_path / "requests.jsonl.receipt.json").exists()
    assert not list(sidecar_dir.iterdir())
