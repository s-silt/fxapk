"""Phase2 行为金标准。

三个合成场景只经 ``tests/phase2_fixtures.write_verified_package`` 落盘，值只用
``example.test`` 与 ``100.64.0.0/10``。每个场景依次跑
``build_inventory`` → ``build_triage`` → ``materialize_snapshot`` → ``run_gate``
→ ``classify_replay_change``。

``FXAPK_UPDATE_GOLDEN=1`` 重写 ``tests/golden/phase2/<场景>.json``，否则与规范化
输出逐字节比对。规范化：``sort_keys``、临时目录绝对路径换成 ``<tmp>``、ISO-8601
时间戳换成 ``<timestamp>``、``d2:`` 判决号按文档遍历顺序换成 ``<decision:N>``。
"""
from __future__ import annotations

import difflib
import json
import os
import re
from pathlib import Path
from typing import Any

import pytest

from apkscan.core.phase2.decision import (
    build_decision,
    classify_replay_change,
    materialize_snapshot,
    members_hash,
    run_gate,
    signals_hash,
)
from apkscan.core.phase2.inventory import build_inventory
from apkscan.core.phase2.triage import build_triage
from tests.phase2_fixtures import write_verified_package

# create_case_package 把 created_at 写进 package_id。不冻住这个时钟时，
# package_id / candidate_id / fingerprint / members_hash / decision_id 每次都变，
# 且 stale_decisions 按 decision_id 排序，两次运行无法逐字节相同。
FROZEN_NOW = "2020-01-01T00:00:00+00:00"
CASE_SINGLE = "CASE-GOLDEN-SINGLE"
CASE_PROP = "CASE-GOLDEN-PROP"
CASE_REPLAY = "CASE-GOLDEN-REPLAY"
GOLDEN_DIR = Path(__file__).parent / "golden" / "phase2"

_DECISION_ID = re.compile(r"d2:[0-9a-f]{32}(?![0-9a-f])")
_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"
)
_DRIVE = re.compile(r"[A-Za-z]:[\\/]")


def _freeze_package_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("apkscan.core.case_package._now", lambda: FROZEN_NOW)


def _runtime(omit: str | None = None, **overrides: Any) -> dict[str, Any]:
    state: dict[str, Any] = {
        "is_runtime_seen": False,
        "is_runtime_contact": False,
        "is_c2": False,
    }
    state.update(overrides)
    if omit is not None:
        state.pop(omit, None)
    return state


def _lead(
    value: str,
    advice: str,
    evidence_id: str,
    *,
    category: str = "IP",
    confidence: str | None = None,
    runtime: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "category": category,
        "value": value,
        "advice": advice,
        "source_refs": [{"evidence_id": evidence_id, "scope": "case_evidence"}],
    }
    if confidence is not None:
        body["confidence"] = confidence
    if runtime is not None:
        body.update(runtime)
    return body


def _endpoint(kind: str, value: str, evidence_id: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "value": value,
        "evidences": [{"evidence_id": evidence_id, "scope": "case_evidence"}],
    }


def _finding() -> dict[str, Any]:
    return {
        "id": "F-SYNTH-NOTE",
        "title": "synthetic finding",
        "description": "synthetic narrative",
        "severity": "LOW",
        "evidences": [{"evidence_id": "ev-finding", "scope": "case_evidence"}],
    }


def _parent_decision(
    *,
    case_id: str,
    proposal: Any,
    disposition: str,
    event_id: str,
    fingerprint: str,
    reason: str | None = None,
    accepts: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    return build_decision(
        case_id=case_id,
        decided_by="golden",
        scope="parent",
        parent_id=proposal.parent_id,
        candidate_id=None,
        disposition=disposition,
        reason=reason,
        next_action=None,
        accepts=[] if accepts is None else accepts,
        clue_id=None,
        supersedes=[],
        members_hash_value=members_hash(proposal.member_candidate_ids),
        decided_against={
            "inventory_fingerprint": fingerprint,
            "triage_bucket": proposal.bucket,
            "triage_tier": proposal.tier,
            "signals_hash": signals_hash(proposal.signals),
        },
        note="",
        event_id=event_id,
        decided_at=FROZEN_NOW,
    )


def _clue(case_id: str, clue_id: str, candidate: Any) -> dict[str, Any]:
    return {
        "clue_id": clue_id,
        "case_id": case_id,
        "origin": "phase1",
        "phase1_provenance": candidate.provenance_dict(),
    }


def _open(case_dir: Path, case_id: str) -> tuple[Any, Any]:
    inventory = build_inventory(case_dir)
    assert inventory.case_id == case_id
    assert not inventory.issues, [issue.code for issue in inventory.issues]
    return inventory, build_triage(inventory, case_dir)


def _view(
    inventory: Any,
    triage: Any,
    decisions: list[dict[str, Any]],
    clues: list[dict[str, Any]],
) -> dict[str, Any]:
    """inventory 与 triage 已由本场景算好；这里接上物化、门禁、replay。"""
    result = materialize_snapshot(
        inventory, triage, decisions, clues, case_id=inventory.case_id,
    )
    gate = run_gate(
        inventory, triage, decisions, clues, result.coverage, case_id=inventory.case_id,
    )
    replay = classify_replay_change(inventory, triage, decisions)
    return {
        "inventory": inventory.to_dict(),
        "triage": triage.to_dict(),
        "materialize": {"coverage": result.coverage, "report": result.report},
        "gate": {
            "ok": gate.ok,
            "blockers": list(gate.blockers),
            "warnings": list(gate.warnings),
            "declarations": list(gate.declarations),
        },
        "replay": {
            "old_fingerprint": replay.old_fingerprint,
            "new_fingerprint": replay.new_fingerprint,
            "summary": dict(replay.summary),
            "items": [
                {
                    "decision_id": item.decision_id,
                    "scope": item.scope,
                    "key": item.key,
                    "classification": item.classification,
                    "detail": item.detail,
                    "next_action": item.next_action,
                }
                for item in replay.items
            ],
        },
    }


def _single_package(case_dir: Path) -> dict[str, Any]:
    """单包。endpoint / finding 各一。

    lead 需要五条，R4 的 false / missing / null、T2 镜像目标、T1 runtime_seen
    才能同时出现。一条 lead 落不进这几种分层。
    """
    write_verified_package(
        case_dir,
        "pkg",
        case_id=CASE_SINGLE,
        leads=[
            _lead(
                "100.64.0.1:443/tcp", "待核", "ev-mirror",
                confidence="LOW", runtime=_runtime(),
            ),
            _lead(
                "ledger.example.test", "无需调证", "ev-ledger",
                category="DOMAIN", runtime=_runtime(),
            ),
            _lead(
                "missing.example.test", "无需调证", "ev-missing",
                category="DOMAIN", runtime=_runtime(omit="is_runtime_contact"),
            ),
            _lead(
                "nullstate.example.test", "无需调证", "ev-null",
                category="DOMAIN", runtime=_runtime(is_runtime_contact=None),
            ),
            _lead(
                "seen.example.test", "待核", "ev-seen",
                category="DOMAIN", runtime=_runtime(is_runtime_seen=True),
            ),
        ],
        endpoints=[_endpoint("ip", "100.64.0.1", "ev-endpoint")],
        findings=[_finding()],
    )
    inventory, triage = _open(case_dir, CASE_SINGLE)
    humans = sorted(
        (item for item in triage.parents if item.bucket == "human"),
        key=lambda item: item.parent_id,
    )
    decisions = [
        _parent_decision(
            case_id=inventory.case_id,
            proposal=item,
            disposition="report_only",
            reason="synthetic human review",
            event_id=f"evt-single-{index}",
            fingerprint=inventory.fingerprint,
        )
        for index, item in enumerate(humans)
    ]
    return _view(inventory, triage, decisions, [])


def _accepted_propagation(case_dir: Path) -> dict[str, Any]:
    """两包同一条 lead：parent 两个成员，accepted_clue 只点名其中一个。"""
    lead = _lead(
        "100.64.0.10", "建议调证", "ev-prop",
        runtime=_runtime(),
    )
    write_verified_package(case_dir, "pkg-1", case_id=CASE_PROP, leads=[lead])
    lead["source_refs"] = [{"evidence_id": "ev-prop-b", "scope": "case_evidence"}]
    write_verified_package(case_dir, "pkg-2", case_id=CASE_PROP, leads=[lead])
    inventory, triage = _open(case_dir, CASE_PROP)
    parents = [item for item in triage.parents if item.collection == "leads"]
    assert len(parents) == 1
    parent = parents[0]
    assert len(parent.member_candidate_ids) == 2
    chosen = sorted(parent.member_candidate_ids)[0]
    candidate = next(
        item for item in inventory.candidates if item.candidate_id == chosen
    )
    decisions = [
        _parent_decision(
            case_id=inventory.case_id,
            proposal=parent,
            disposition="accepted_clue",
            event_id="evt-prop-accept",
            fingerprint=inventory.fingerprint,
            accepts=[{"candidate_id": chosen, "clue_id": "CL-PROP-1"}],
        )
    ]
    clues = [_clue(inventory.case_id, "CL-PROP-1", candidate)]
    return _view(inventory, triage, decisions, clues)


def _replay_supplement(case_dir: Path) -> dict[str, Any]:
    """先对三个单成员 parent 判决，再补两个包，然后跑完整链路。

    补包不动 hold → unchanged；给 carry 增加同 lead 成员 → carry_with_note；
    给 block 增加带 runtime_contact 的同 lead 成员 → blocked_stale。
    判决列表顺序参与 decisions fingerprint，保持这条固定顺序。
    """
    write_verified_package(
        case_dir, "pkg-hold", case_id=CASE_REPLAY,
        leads=[_lead(
            "hold.example.test", "待核", "ev-hold",
            category="DOMAIN", confidence="LOW", runtime=_runtime(),
        )],
    )
    write_verified_package(
        case_dir, "pkg-carry", case_id=CASE_REPLAY,
        leads=[_lead("100.64.0.20", "建议调证", "ev-carry-a", runtime=_runtime())],
    )
    write_verified_package(
        case_dir, "pkg-block", case_id=CASE_REPLAY,
        leads=[_lead(
            "100.64.0.30", "待核", "ev-block-a",
            confidence="LOW", runtime=_runtime(),
        )],
    )
    base_inv, base_tri = _open(case_dir, CASE_REPLAY)
    by_display = {item.display: item for item in base_tri.parents}
    assert set(by_display) == {"hold.example.test", "100.64.0.20", "100.64.0.30"}
    for proposal in base_tri.parents:
        assert len(proposal.member_candidate_ids) == 1

    hold = by_display["hold.example.test"]
    carry = by_display["100.64.0.20"]
    blocked = by_display["100.64.0.30"]
    chosen = carry.member_candidate_ids[0]
    candidate = next(
        item for item in base_inv.candidates if item.candidate_id == chosen
    )
    decisions = [
        _parent_decision(
            case_id=base_inv.case_id,
            proposal=hold,
            disposition="report_only",
            reason="synthetic hold",
            event_id="evt-replay-unchanged",
            fingerprint=base_inv.fingerprint,
        ),
        _parent_decision(
            case_id=base_inv.case_id,
            proposal=carry,
            disposition="accepted_clue",
            event_id="evt-replay-carry",
            fingerprint=base_inv.fingerprint,
            accepts=[{"candidate_id": chosen, "clue_id": "CL-REPLAY-CARRY"}],
        ),
        _parent_decision(
            case_id=base_inv.case_id,
            proposal=blocked,
            disposition="excluded_with_reason",
            reason="synthetic static exclusion",
            event_id="evt-replay-blocked",
            fingerprint=base_inv.fingerprint,
        ),
    ]
    clues = [_clue(base_inv.case_id, "CL-REPLAY-CARRY", candidate)]

    write_verified_package(
        case_dir, "pkg-carry-extra", case_id=CASE_REPLAY,
        leads=[_lead("100.64.0.20", "建议调证", "ev-carry-b", runtime=_runtime())],
    )
    write_verified_package(
        case_dir, "pkg-block-extra", case_id=CASE_REPLAY,
        leads=[_lead(
            "100.64.0.30", "待核", "ev-block-b",
            confidence="LOW", runtime=_runtime(is_runtime_contact=True),
        )],
    )
    inventory, triage = _open(case_dir, CASE_REPLAY)
    return _view(inventory, triage, decisions, clues)


_SCENARIOS = {
    "single_package": _single_package,
    "accepted_propagation": _accepted_propagation,
    "replay_supplement": _replay_supplement,
}


def _diff(expected: bytes, actual: bytes) -> str:
    try:
        expected_text = expected.decode("utf-8")
        actual_text = actual.decode("utf-8")
    except UnicodeDecodeError:
        return f"byte length expected={len(expected)} actual={len(actual)}"
    lines = list(difflib.unified_diff(
        expected_text.splitlines(),
        actual_text.splitlines(),
        fromfile="expected",
        tofile="actual",
        lineterm="",
    ))
    if len(lines) > 160:
        lines = [*lines[:160], "..."]
    return "\n".join(lines)


def _path_roots(case_dir: Path) -> tuple[str, ...]:
    found: set[str] = set()
    for path in (case_dir, case_dir.resolve()):
        found.add(str(path))
        found.add(path.as_posix())
    return tuple(sorted((item for item in found if item), key=len, reverse=True))


def _reject_machine_paths(value: Any) -> None:
    if isinstance(value, str):
        if _DRIVE.search(value):
            raise AssertionError(f"absolute path survived canonicalization: {value!r}")
        folded = value.replace("\\", "/").lower()
        if "/temp/" in folded or "/tmp/" in folded or "/pytest-of-" in folded:
            raise AssertionError(f"temp path survived canonicalization: {value!r}")
        return
    if isinstance(value, dict):
        for item in value.values():
            _reject_machine_paths(item)
        return
    if isinstance(value, list):
        for item in value:
            _reject_machine_paths(item)


def canonicalize(payload: Any, case_dir: Path) -> bytes:
    """规范化成可逐字节比较的 UTF-8 JSON（末尾一个 LF）。"""
    roots = _path_roots(case_dir)
    placeholders: dict[str, str] = {}

    def scrub(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: scrub(value[key]) for key in sorted(value)}
        if isinstance(value, list):
            return [scrub(item) for item in value]
        if not isinstance(value, str):
            return value
        text = value
        for root in roots:
            if root in text:
                text = text.replace(root, "<tmp>")
        text = _TIMESTAMP.sub("<timestamp>", text)

        def replace_decision(match: re.Match[str]) -> str:
            token = match.group(0)
            placeholder = placeholders.get(token)
            if placeholder is None:
                placeholder = f"<decision:{len(placeholders) + 1}>"
                placeholders[token] = placeholder
            return placeholder

        return _DECISION_ID.sub(replace_decision, text)

    normalized = scrub(payload)
    _reject_machine_paths(normalized)
    rendered = json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
        allow_nan=False,
    )
    return (rendered + "\n").encode("utf-8")


def _raw_bytes(payload: Any) -> bytes:
    rendered = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
        allow_nan=False,
    )
    return (rendered + "\n").encode("utf-8")


def _assert_single(payload: dict[str, Any]) -> None:
    parents = payload["triage"]["parents"]
    counts: dict[str, int] = {}
    for item in parents:
        counts[item["collection"]] = counts.get(item["collection"], 0) + 1
    assert counts == {"endpoints": 1, "findings": 1, "leads": 5}
    by_display = {item["display"]: item for item in parents}
    assert by_display["100.64.0.1:443/tcp"]["tier"] == "T2:待核静态 IP conf=LOW"
    assert by_display["ledger.example.test"]["tier"] == "R4-LEDGER"
    assert by_display["ledger.example.test"]["bucket"] == "auto:excluded_with_reason"
    assert by_display["missing.example.test"]["tier"] == "T1:runtime字段不完整"
    assert by_display["nullstate.example.test"]["tier"] == "T1:runtime字段不完整"
    assert by_display["seen.example.test"]["tier"] == "T1:runtime_seen"
    endpoint = by_display["100.64.0.1"]
    assert endpoint["tier"] == "R1-MIRROR"
    assert endpoint["merged_into"] == [by_display["100.64.0.1:443/tcp"]["parent_id"]]
    assert by_display["synthetic finding"]["bucket"] == "auto:report_only"
    assert by_display["synthetic finding"]["tier"] == "finding:LOW"
    assert payload["inventory"]["stats"]["candidate_count"] == 7
    assert payload["gate"]["ok"] is True
    assert payload["replay"]["summary"] == {
        "unchanged": 4,
        "carry_with_note": 0,
        "blocked_stale": 0,
        "removed": 0,
    }
    assert payload["replay"]["items"] == []
    assert payload["replay"]["old_fingerprint"] == payload["replay"]["new_fingerprint"]


def _assert_propagation(payload: dict[str, Any]) -> None:
    parents = payload["triage"]["parents"]
    assert [item["collection"] for item in parents] == ["leads"]
    parent = parents[0]
    assert parent["packages"] == 2
    assert len(parent["member_candidate_ids"]) == 2
    entries = payload["materialize"]["coverage"]["entries"]
    accepted = [item for item in entries if item["disposition"] == "accepted_clue"]
    propagated = [
        item for item in entries
        if item.get("propagation") == "accepted_parent_unselected_member"
    ]
    assert len(entries) == 2
    assert len(accepted) == 1
    assert len(propagated) == 1
    assert propagated[0]["merged_into_candidate_id"] == accepted[0]["candidate_id"]
    assert "clue_id" not in propagated[0]
    assert accepted[0]["clue_id"] == "CL-PROP-1"
    assert {
        accepted[0]["candidate_id"],
        propagated[0]["candidate_id"],
    } == set(parent["member_candidate_ids"])
    assert payload["gate"]["ok"] is True
    assert payload["replay"]["summary"]["unchanged"] == 1
    assert payload["replay"]["items"] == []
    assert payload["replay"]["old_fingerprint"] == payload["replay"]["new_fingerprint"]


def _assert_replay(payload: dict[str, Any]) -> None:
    assert payload["inventory"]["stats"] == {
        "package_count": 5,
        "candidate_count": 5,
        "blocker_count": 0,
    }
    assert payload["replay"]["summary"] == {
        "unchanged": 1,
        "carry_with_note": 1,
        "blocked_stale": 1,
        "removed": 0,
    }
    by_class = {item["classification"]: item for item in payload["replay"]["items"]}
    assert set(by_class) == {"carry_with_note", "blocked_stale"}
    assert "点名" in by_class["carry_with_note"]["detail"]
    assert "runtime" in by_class["blocked_stale"]["detail"]
    stale = set(payload["materialize"]["report"]["stale_decisions"])
    assert stale == {item["decision_id"] for item in payload["replay"]["items"]}
    assert payload["materialize"]["report"]["warning_count"] == 2
    assert payload["gate"]["ok"] is False
    blockers = payload["gate"]["blockers"]
    assert any("数量为 4" in item for item in blockers)
    assert any(item.startswith("G5:") for item in blockers)
    assert not any(item.startswith("G8:") for item in blockers)
    assert payload["replay"]["new_fingerprint"] == payload["inventory"]["fingerprint"]
    assert payload["replay"]["old_fingerprint"] != payload["replay"]["new_fingerprint"]


_CONTRACTS = {
    "single_package": _assert_single,
    "accepted_propagation": _assert_propagation,
    "replay_supplement": _assert_replay,
}


def _updating() -> bool:
    return os.environ.get("FXAPK_UPDATE_GOLDEN") == "1"


@pytest.mark.parametrize("scenario", list(_SCENARIOS))
def test_phase2_golden_is_stable(
    scenario: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _freeze_package_clock(monkeypatch)
    left_dir = tmp_path / "run-a"
    right_dir = tmp_path / "run-b"
    left = _SCENARIOS[scenario](left_dir)
    right = _SCENARIOS[scenario](right_dir)
    _CONTRACTS[scenario](left)
    _CONTRACTS[scenario](right)
    raw_left = _raw_bytes(left)
    raw_right = _raw_bytes(right)
    if raw_left != raw_right:
        raise AssertionError(
            "two runs diverged before normalization\n" + _diff(raw_left, raw_right)
        )
    left_bytes = canonicalize(left, left_dir)
    right_bytes = canonicalize(right, right_dir)
    if left_bytes != right_bytes:
        raise AssertionError(
            "normalized runs diverged\n" + _diff(left_bytes, right_bytes)
        )
    assert b"d2:" not in left_bytes
    path = GOLDEN_DIR / f"{scenario}.json"
    if _updating():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(left_bytes)
        return
    if not path.is_file():
        raise AssertionError(
            f"missing {path.name}; set FXAPK_UPDATE_GOLDEN=1 to record"
        )
    expected = path.read_bytes()
    if expected != left_bytes:
        raise AssertionError(f"golden mismatch {path.name}\n" + _diff(expected, left_bytes))


def test_golden_files_match_scenarios() -> None:
    if _updating():
        return
    found = {path.name for path in GOLDEN_DIR.glob("*.json")}
    expected = {f"{name}.json" for name in _SCENARIOS}
    assert found == expected
