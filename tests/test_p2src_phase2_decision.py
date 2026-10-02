# -*- coding: utf-8 -*-
"""期2a 判决闭环红线测试：走真入口 build_inventory→build_triage→decision 库。

每条红线在注释给出"无修复即失败"的突变。合成值一律 100.64/example.test/CL-。
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path



import pytest  # noqa: E402

import apkscan.core.phase2.inventory as coverage
import apkscan.core.phase2.decision as pd
import apkscan.core.phase2.triage as pt
from tests.phase2_fixtures import write_verified_package


def _write_pkg(case_dir: Path, name: str, leads: list) -> None:
    write_verified_package(case_dir, name, leads=leads)


def _lead(value: str, advice: str) -> dict:
    return {"category": "IP", "value": value, "advice": advice,
            "is_runtime_seen": False, "is_runtime_contact": False, "is_c2": False,
            "source_refs": [{"evidence_id": f"ev-{value}", "scope": "case_evidence"}]}


def _da(inventory, proposal) -> dict:
    return {"inventory_fingerprint": inventory.fingerprint, "triage_bucket": proposal.bucket,
            "triage_tier": proposal.tier,
            "signals_hash": hashlib.sha256(
                "\n".join(sorted(proposal.signals)).encode("utf-8")).hexdigest()}


def _two_pkg_case(tmp_path: Path, value: str = "100.64.1.1", advice: str = "建议调证"):
    """两包同 lead → 该 case-parent 有 2 个成员 candidate。"""
    _write_pkg(tmp_path, "pkg-1", [_lead(value, advice)])
    _write_pkg(tmp_path, "pkg-2", [_lead(value, advice)])
    inv = coverage.build_inventory(tmp_path)
    assert not inv.issues
    triage = pt.build_triage(inv, tmp_path)
    lead = [p for p in triage.parents if p.collection == "leads"][0]
    assert len(lead.member_candidate_ids) == 2
    return inv, triage, lead


# ---------- 红线1/2：传播语义（accepted 点名 → 未点名 duplicate+propagation，过 audit） ----------
def test_传播语义_点名与未点名(tmp_path: Path) -> None:
    inv, triage, lead = _two_pkg_case(tmp_path)
    c1, c2 = lead.member_candidate_ids
    c1_cand = next(c for c in inv.candidates if c.candidate_id == c1)
    clue_records = [{"clue_id": "CL-1", "case_id": tmp_path.name, "origin": "phase1",
                     "phase1_provenance": c1_cand.provenance_dict()}]
    decision = pd.build_decision(
        case_id=tmp_path.name, decided_by="test", scope="parent", parent_id=lead.parent_id,
        candidate_id=None, disposition="accepted_clue", reason=None, next_action=None,
        accepts=[{"candidate_id": c1, "clue_id": "CL-1"}], clue_id=None, supersedes=[],
        members_hash_value=pd.members_hash(lead.member_candidate_ids),
        decided_against=_da(inv, lead))
    result = pd.materialize_snapshot(inv, triage, [decision], clue_records, case_id=tmp_path.name)
    entries = {e["candidate_id"]: e for e in result.coverage["entries"]}
    assert entries[c1]["disposition"] == "accepted_clue"
    assert entries[c1]["clue_id"] == "CL-1"
    assert entries[c2]["disposition"] == "duplicate_or_merged"
    assert entries[c2]["propagation"] == "accepted_parent_unselected_member"
    assert entries[c2]["merged_into_candidate_id"] == c1
    assert "clue_id" not in entries[c2]  # 突变：给未点名成员塞 clue_id → audit duplicate_accepted_mapping


def test_未点名塞clue_id触发audit红(tmp_path: Path) -> None:
    """直接构造违规 snapshot：未点名成员带同一 clue_id → audit 必红。"""
    inv, _, lead = _two_pkg_case(tmp_path)
    c1, c2 = lead.member_candidate_ids
    cands = {c.candidate_id: c for c in inv.candidates}
    entries = []
    for c in inv.candidates:
        if c.candidate_id in (c1, c2):
            entries.append({"candidate_id": c.candidate_id, "disposition": "accepted_clue",
                            "clue_id": "CL-1", "provenance": c.provenance_dict()})
        else:
            entries.append({"candidate_id": c.candidate_id, "disposition": "report_only",
                            "reason": "x"})
    snapshot = {"schema_version": coverage.SCHEMA_VERSION, "case_id": tmp_path.name,
                "inventory_fingerprint": inv.fingerprint, "entries": entries}
    clue_records = [{"clue_id": "CL-1", "case_id": tmp_path.name, "origin": "phase1",
                     "phase1_provenance": cands[c1].provenance_dict()}]
    audit = coverage.audit_coverage(inv, snapshot, clue_records)
    assert not audit.ok
    assert any("duplicate_accepted_mapping" in b.code for b in audit.blockers)


# ---------- 红线3/4/5：图校验（分叉 / 数组收敛 / 环 / 断链 / 跨单元） ----------
def _decision(tmp_path, lead, inv, disposition="excluded_with_reason", reason="噪声",
              supersedes=None, event_id=None):
    return pd.build_decision(
        case_id=tmp_path.name, decided_by="t", scope="parent", parent_id=lead.parent_id,
        candidate_id=None, disposition=disposition, reason=reason, next_action=None,
        accepts=[], clue_id=None, supersedes=supersedes or [],
        members_hash_value=pd.members_hash(lead.member_candidate_ids),
        decided_against=_da(inv, lead), event_id=event_id)


def test_分叉阻断与数组收敛(tmp_path: Path) -> None:
    inv, _, lead = _two_pkg_case(tmp_path)
    a = _decision(tmp_path, lead, inv, reason="A", event_id="ev-a")
    b = _decision(tmp_path, lead, inv, reason="B", event_id="ev-b")
    # 两条无 supersedes 同 parent → 分叉阻断
    with pytest.raises(pd.DecisionGraphError):
        pd.validate_decision_graph([a, b])
    # 一条 supersedes=[两末端] → 收敛
    c = _decision(tmp_path, lead, inv, reason="C", supersedes=[a["decision_id"], b["decision_id"]],
                  event_id="ev-c")
    state = pd.validate_decision_graph([a, b, c])
    active = state.active_by_unit[("parent", lead.parent_id)]
    assert active["decision_id"] == c["decision_id"]


def test_long_supersedes_chain_is_valid(tmp_path: Path) -> None:
    inv, _, lead = _two_pkg_case(tmp_path)
    decisions = []
    for index in range(4000):
        decisions.append(_decision(
            tmp_path, lead, inv, disposition="report_only", reason="合成复审更新",
            event_id=f"event-{index}",
            supersedes=[decisions[-1]["decision_id"]] if decisions else [],
        ))
    state = pd.validate_decision_graph(decisions)
    assert state.active_by_unit[("parent", lead.parent_id)]["decision_id"] == decisions[-1]["decision_id"]


def test_自环与断链阻断(tmp_path: Path) -> None:
    inv, _, lead = _two_pkg_case(tmp_path)
    a = _decision(tmp_path, lead, inv, event_id="ev-a")
    # 断链：supersedes 指向不存在
    b = _decision(tmp_path, lead, inv, supersedes=["d2:nonexistent"], event_id="ev-b")
    with pytest.raises(pd.DecisionGraphError):
        pd.validate_decision_graph([a, b])


# ---------- 红线6：schema 闭合（member/parent accepted） ----------
def test_schema_闭合(tmp_path: Path) -> None:
    inv, _, lead = _two_pkg_case(tmp_path)
    c1 = lead.member_candidate_ids[0]
    members = {lead.parent_id: lead.member_candidate_ids}
    # parent accepted 带顶层 clue_id → 拒（用 build 绕过则 decision_id 变，改手工构造）
    good = pd.build_decision(
        case_id=tmp_path.name, decided_by="t", scope="parent", parent_id=lead.parent_id,
        candidate_id=None, disposition="accepted_clue", reason=None, next_action=None,
        accepts=[{"candidate_id": c1, "clue_id": "CL-1"}], clue_id=None, supersedes=[],
        members_hash_value=pd.members_hash(lead.member_candidate_ids), decided_against=_da(inv, lead))
    pd.validate_decision_record(good, members_by_parent=members)  # 合法
    bad = dict(good)
    bad["clue_id"] = "CL-X"
    bad["decision_id"] = pd.decision_id_for_payload(bad)  # 重算 id 使其自洽
    with pytest.raises(pd.DecisionSchemaError):
        pd.validate_decision_record(bad, members_by_parent=members)


# ---------- 红线8/11：确定性 + decision_id 128bit + members_hash ----------
def test_确定性物化(tmp_path: Path) -> None:
    inv, triage, _ = _two_pkg_case(tmp_path, advice="待核")
    r1 = pd.materialize_snapshot(inv, triage, [], [], case_id=tmp_path.name)
    r2 = pd.materialize_snapshot(inv, triage, [], [], case_id=tmp_path.name)
    assert (json.dumps(r1.coverage, ensure_ascii=False, sort_keys=True)
            == json.dumps(r2.coverage, ensure_ascii=False, sort_keys=True))


def test_decision_id_128bit与members_hash(tmp_path: Path) -> None:
    inv, _, lead = _two_pkg_case(tmp_path)
    d = _decision(tmp_path, lead, inv, event_id="ev-a")
    assert d["decision_id"].startswith("d2:")
    assert len(d["decision_id"]) == len("d2:") + 32  # 128bit hex
    mh = pd.members_hash(["b", "a", "a"])
    assert mh == "mh:" + hashlib.sha256("a\nb".encode("utf-8")).hexdigest()


# ---------- 红线7/9/10：守恒 + 骨架兜底 + auto 推翻 ----------
def test_守恒与骨架兜底(tmp_path: Path) -> None:
    inv, triage, lead = _two_pkg_case(tmp_path, advice="待核")
    result = pd.materialize_snapshot(inv, triage, [], [], case_id=tmp_path.name)
    ids = sorted(e["candidate_id"] for e in result.coverage["entries"])
    assert ids == sorted(c.candidate_id for c in inv.candidates)
    # 待核+全 runtime False → T2/human → 无判决落 skeleton pending
    entries = {e["candidate_id"]: e for e in result.coverage["entries"]}
    for cid in lead.member_candidate_ids:
        assert entries[cid]["disposition"] == "pending_with_action"
        assert entries[cid]["materialized_from"] == "skeleton"


# ---------- 红线：写入侧防分叉（已有活动末端未给 supersedes → 拒） ----------
def test_写入侧防分叉(tmp_path: Path) -> None:
    inv, _, lead = _two_pkg_case(tmp_path)
    members = {lead.parent_id: lead.member_candidate_ids}
    cand_ids = {c.candidate_id for c in inv.candidates}
    a = _decision(tmp_path, lead, inv, event_id="ev-a")
    b = _decision(tmp_path, lead, inv, reason="B", event_id="ev-b")  # 无 supersedes
    # 精确锁写入侧第一道防线（错误消息来自写入侧，而非末尾图校验的兜底）
    with pytest.raises(pd.DecisionGraphError, match="必须提供 supersedes"):
        pd.validate_new_decision(b, [a], members_by_parent=members,
                                 inventory_candidate_ids=cand_ids, known_clue_ids=set(),
                                 case_id=tmp_path.name)


# ---------- 复审补测 P1#1：推翻反转不卡 self_check ----------
def test_推翻反转不卡self_check(tmp_path: Path) -> None:
    """d1 accept CL-1 → d2 excluded supersedes d1；旧 CL-1 不得进 self_check 令物化失败。
    突变：self_check 改回遍历全部 decisions → 旧 CL-1 触发 clue_not_accepted → materialize raise。"""
    inv, triage, lead = _two_pkg_case(tmp_path)
    c1 = lead.member_candidate_ids[0]
    c1_cand = next(c for c in inv.candidates if c.candidate_id == c1)
    clue_records = [{"clue_id": "CL-1", "case_id": tmp_path.name, "origin": "phase1",
                     "phase1_provenance": c1_cand.provenance_dict()}]
    d1 = pd.build_decision(
        case_id=tmp_path.name, decided_by="t", scope="parent", parent_id=lead.parent_id,
        candidate_id=None, disposition="accepted_clue", reason=None, next_action=None,
        accepts=[{"candidate_id": c1, "clue_id": "CL-1"}], clue_id=None, supersedes=[],
        members_hash_value=pd.members_hash(lead.member_candidate_ids),
        decided_against=_da(inv, lead), event_id="ev-1")
    d2 = pd.build_decision(
        case_id=tmp_path.name, decided_by="t", scope="parent", parent_id=lead.parent_id,
        candidate_id=None, disposition="excluded_with_reason", reason="撤销接受", next_action=None,
        accepts=[], clue_id=None, supersedes=[d1["decision_id"]],
        members_hash_value=pd.members_hash(lead.member_candidate_ids),
        decided_against=_da(inv, lead), event_id="ev-2")
    result = pd.materialize_snapshot(inv, triage, [d1, d2], clue_records, case_id=tmp_path.name)
    entries = {e["candidate_id"]: e for e in result.coverage["entries"]}
    assert entries[c1]["disposition"] == "excluded_with_reason"


# ---------- 复审补测 P1#2：members_hash 漂移进 stale、不静默传播 ----------
def test_members_hash漂移进stale(tmp_path: Path) -> None:
    inv, triage, lead = _two_pkg_case(tmp_path, advice="待核")
    bad = pd.build_decision(
        case_id=tmp_path.name, decided_by="t", scope="parent", parent_id=lead.parent_id,
        candidate_id=None, disposition="excluded_with_reason", reason="旧判决", next_action=None,
        accepts=[], clue_id=None, supersedes=[],
        members_hash_value="mh:" + "0" * 64,  # 故意与当前成员集不符
        decided_against=_da(inv, lead), event_id="ev-bad")
    result = pd.materialize_snapshot(inv, triage, [bad], [], case_id=tmp_path.name)
    assert bad["decision_id"] in result.report["stale_decisions"]
    entries = {e["candidate_id"]: e for e in result.coverage["entries"]}
    for cid in lead.member_candidate_ids:  # 漂移判决不传播，成员回落 skeleton
        assert entries[cid]["materialized_from"] == "skeleton"


# ---------- 复审补测：member accepted 路径 ----------
def test_member_accepted路径(tmp_path: Path) -> None:
    inv, triage, lead = _two_pkg_case(tmp_path)
    c1 = lead.member_candidate_ids[0]
    c1_cand = next(c for c in inv.candidates if c.candidate_id == c1)
    clue_records = [{"clue_id": "CL-1", "case_id": tmp_path.name, "origin": "phase1",
                     "phase1_provenance": c1_cand.provenance_dict()}]
    d = pd.build_decision(
        case_id=tmp_path.name, decided_by="t", scope="member", parent_id=lead.parent_id,
        candidate_id=c1, disposition="accepted_clue", reason=None, next_action=None,
        accepts=[], clue_id="CL-1", supersedes=[], members_hash_value=pd.members_hash([c1]),
        decided_against=_da(inv, lead))
    result = pd.materialize_snapshot(inv, triage, [d], clue_records, case_id=tmp_path.name)
    entries = {e["candidate_id"]: e for e in result.coverage["entries"]}
    assert entries[c1]["disposition"] == "accepted_clue"
    assert entries[c1]["clue_id"] == "CL-1"


# ---------- 期2b gate 红线 ----------
def test_gate_G10_honest_gap(tmp_path: Path) -> None:
    inv, triage, _ = _two_pkg_case(tmp_path, advice="待核")
    cov = pd.materialize_snapshot(inv, triage, [], [], case_id=tmp_path.name).coverage
    report = pd.run_gate(inv, triage, [], [], cov, case_id=tmp_path.name, allow_pending=True)
    assert any("HONEST_GAP" in d for d in report.declarations)  # 无 survey → 声明


def test_gate_G4_手改coverage阻断(tmp_path: Path) -> None:
    """突变：G4 的重物化比对若被删，手改 coverage 不会被抓。"""
    inv, triage, _ = _two_pkg_case(tmp_path, advice="待核")
    cov = pd.materialize_snapshot(inv, triage, [], [], case_id=tmp_path.name).coverage
    tampered = json.loads(json.dumps(cov))
    tampered["entries"][0]["disposition"] = "report_only"  # 手改一个 entry
    report = pd.run_gate(inv, triage, [], [], tampered, case_id=tmp_path.name, allow_pending=True)
    assert any(b.startswith("G4") for b in report.blockers)


def test_gate_G6_pending_allow(tmp_path: Path) -> None:
    inv, triage, _ = _two_pkg_case(tmp_path, advice="待核")
    cov = pd.materialize_snapshot(inv, triage, [], [], case_id=tmp_path.name).coverage
    r1 = pd.run_gate(inv, triage, [], [], cov, case_id=tmp_path.name, allow_pending=False)
    assert any(b.startswith("G6") for b in r1.blockers)
    r2 = pd.run_gate(inv, triage, [], [], cov, case_id=tmp_path.name, allow_pending=True)
    assert any(w.startswith("G6") for w in r2.warnings)


def test_gate_G8_excluded含runtime阻断(tmp_path: Path) -> None:
    """人判 excluded 的 parent 若 triage 含 runtime 信号 → G8 blocker。"""
    _write_pkg(tmp_path, "pkg-1", [{
        "category": "IP", "value": "100.64.8.1", "advice": "建议调证",
        "is_runtime_seen": True, "is_runtime_contact": True, "is_c2": False,
        "source_refs": [{"evidence_id": "ev1", "scope": "case_evidence"}]}])
    inv = coverage.build_inventory(tmp_path)
    triage = pt.build_triage(inv, tmp_path)
    lead = [p for p in triage.parents if p.collection == "leads"][0]
    assert "runtime_contact" in lead.signals
    d = pd.build_decision(
        case_id=tmp_path.name, decided_by="t", scope="parent", parent_id=lead.parent_id,
        candidate_id=None, disposition="excluded_with_reason", reason="强行排除", next_action=None,
        accepts=[], clue_id=None, supersedes=[],
        members_hash_value=pd.members_hash(lead.member_candidate_ids), decided_against=_da(inv, lead))
    cov = pd.materialize_snapshot(inv, triage, [d], [], case_id=tmp_path.name).coverage
    report = pd.run_gate(inv, triage, [d], [], cov, case_id=tmp_path.name, allow_pending=True)
    assert any(b.startswith("G8") for b in report.blockers)


def test_batch_expect不符抛错(tmp_path: Path) -> None:
    inv, triage, _ = _two_pkg_case(tmp_path, advice="待核")
    with pytest.raises(pd.DecisionError, match="预期"):
        pd.build_batch_decisions(
            triage, tier_prefix="T2:", disposition="excluded_with_reason", reason="x",
            decided_by="t", expect=999, existing_decisions=[],
            inventory_fingerprint=inv.fingerprint)


def test_batch_禁accepted_clue(tmp_path: Path) -> None:
    inv, triage, _ = _two_pkg_case(tmp_path, advice="待核")
    with pytest.raises(pd.DecisionError, match="accepted_clue"):
        pd.build_batch_decisions(
            triage, tier_prefix="T2:", disposition="accepted_clue", reason="x",
            decided_by="t", expect=1, existing_decisions=[],
            inventory_fingerprint=inv.fingerprint)


# 复审 P1#3：member-scope 判决不得让 parent 算"已判"
def test_batch_member判决不占parent(tmp_path: Path) -> None:
    inv, triage, lead = _two_pkg_case(tmp_path, advice="待核")
    c1 = lead.member_candidate_ids[0]
    member_d = pd.build_decision(
        case_id=tmp_path.name, decided_by="t", scope="member", parent_id=lead.parent_id,
        candidate_id=c1, disposition="excluded_with_reason", reason="成员例外", next_action=None,
        accepts=[], clue_id=None, supersedes=[], members_hash_value=pd.members_hash([c1]),
        decided_against=_da(inv, lead))
    # member 判决存在时，batch 仍应能覆盖该 parent（突变：scope 不过滤 → parent 被误占 → 抛错）
    batch = pd.build_batch_decisions(
        triage, tier_prefix="T2:", disposition="excluded_with_reason", reason="组批",
        decided_by="t", expect=1, existing_decisions=[member_d],
        inventory_fingerprint=inv.fingerprint)
    assert len(batch) == 1


# 复审 P1#4：batch 禁 pending_with_action
def test_batch_禁pending(tmp_path: Path) -> None:
    inv, triage, _ = _two_pkg_case(tmp_path, advice="待核")
    with pytest.raises(pd.DecisionError, match="pending_with_action"):
        pd.build_batch_decisions(
            triage, tier_prefix="T2:", disposition="pending_with_action", reason="x",
            decided_by="t", expect=1, existing_decisions=[],
            inventory_fingerprint=inv.fingerprint)


# ---------- 期3：survey 接入 gate G9 ----------
def test_extract_established_hosts() -> None:
    survey = {"endpoints": [
        {"ip": "100.64.1.1", "observations": [{"state": "established"}]},
        {"ip": "100.64.2.2", "observations": [{"state": "syn_only"}]},
        {"ip": "100.64.3.3:443", "observations": [{"state": "established_then_reset"}]},
    ]}
    hosts = pd.extract_established_hosts(survey)
    assert "100.64.1.1" in hosts
    assert "100.64.2.2" not in hosts  # syn_only 不算
    assert "100.64.3.3" in hosts  # established 前缀 + 端口剥离归一


def test_gate_url_host提取() -> None:
    """复审 P1#2：proposal display 为 URL 时必须提出 hostname（旧实现漏）。"""
    from types import SimpleNamespace
    proposal = SimpleNamespace(display="http://100.64.9.9:443/a", value=None,
                               collection="endpoints")
    assert "100.64.9.9" in pd._gate_proposal_hosts(proposal)


def test_gate_G9_excluded命中established(tmp_path: Path) -> None:
    inv, triage, lead = _two_pkg_case(tmp_path, advice="待核")
    d = pd.build_decision(
        case_id=tmp_path.name, decided_by="t", scope="parent", parent_id=lead.parent_id,
        candidate_id=None, disposition="excluded_with_reason", reason="判无需调证", next_action=None,
        accepts=[], clue_id=None, supersedes=[],
        members_hash_value=pd.members_hash(lead.member_candidate_ids), decided_against=_da(inv, lead))
    cov = pd.materialize_snapshot(inv, triage, [d], [], case_id=tmp_path.name).coverage
    report = pd.run_gate(inv, triage, [d], [], cov, case_id=tmp_path.name,
                         survey_established_hosts={"100.64.1.1"}, allow_pending=True)
    assert any(b.startswith("G9") for b in report.blockers)
    assert not any("HONEST_GAP" in dec for dec in report.declarations)  # survey 提供 → G10 消失


# ---------- 期2c replay 分类 ----------
def _parent_decision(tmp_path, inv, lead, disposition, *, accepts=(), members_hash=None,
                     reason="判决"):
    return pd.build_decision(
        case_id=tmp_path.name, decided_by="t", scope="parent", parent_id=lead.parent_id,
        candidate_id=None, disposition=disposition,
        reason=None if disposition == "accepted_clue" else reason, next_action=None,
        accepts=list(accepts), clue_id=None, supersedes=[],
        members_hash_value=members_hash if members_hash is not None
        else pd.members_hash(lead.member_candidate_ids),
        decided_against=_da(inv, lead))


def test_replay_补无关包全unchanged(tmp_path: Path) -> None:
    inv, triage, lead = _two_pkg_case(tmp_path, advice="待核")
    d = _parent_decision(tmp_path, inv, lead, "excluded_with_reason")
    report = pd.classify_replay_change(inv, triage, [d])
    assert report.summary["unchanged"] == 1
    assert report.items == ()


def test_replay_accepted新成员carry(tmp_path: Path) -> None:
    inv, triage, lead = _two_pkg_case(tmp_path)
    c1 = lead.member_candidate_ids[0]
    d = _parent_decision(tmp_path, inv, lead, "accepted_clue",
                         accepts=[{"candidate_id": c1, "clue_id": "CL-1"}],
                         members_hash=pd.members_hash([c1]))  # 旧只 c1，当前 c1+c2 → members 变、点名仍在
    report = pd.classify_replay_change(inv, triage, [d])
    assert report.summary["carry_with_note"] == 1


def test_replay_点名消失_blocked(tmp_path: Path) -> None:
    from types import SimpleNamespace
    inv, _, lead = _two_pkg_case(tmp_path)
    c1, c2 = lead.member_candidate_ids
    d = _parent_decision(tmp_path, inv, lead, "accepted_clue",
                         accepts=[{"candidate_id": c1, "clue_id": "CL-1"}],
                         members_hash=pd.members_hash([c1, c2]))
    new_p = SimpleNamespace(parent_id=lead.parent_id, bucket="human", tier=lead.tier,
                            signals=lead.signals, member_candidate_ids=(c2,))  # c1 消失
    new_triage = SimpleNamespace(parents=(new_p,), case_id=tmp_path.name)
    report = pd.classify_replay_change(inv, new_triage, [d])
    assert report.summary["blocked_stale"] == 1


def test_replay_excluded新runtime_blocked(tmp_path: Path) -> None:
    from types import SimpleNamespace
    inv, _, lead = _two_pkg_case(tmp_path, advice="待核")
    d = _parent_decision(tmp_path, inv, lead, "excluded_with_reason")  # signals_hash 记当前（无 runtime）
    new_p = SimpleNamespace(parent_id=lead.parent_id, bucket="human", tier="T1:runtime_contact",
                            signals=("runtime_contact",),
                            member_candidate_ids=lead.member_candidate_ids)  # members 同、signals 加 runtime
    new_triage = SimpleNamespace(parents=(new_p,), case_id=tmp_path.name)
    report = pd.classify_replay_change(inv, new_triage, [d])
    assert report.summary["blocked_stale"] == 1


def test_replay_excluded_members和runtime同变_blocked(tmp_path: Path) -> None:
    """复审 P1#3：members 变 + excluded + runtime 必须 blocked_stale，不被 members 分支遮蔽成 carry。
    突变：把 classify 的 runtime 优先判定挪回 members 分支之后 → 本测试变红。"""
    from types import SimpleNamespace
    inv, _, lead = _two_pkg_case(tmp_path, advice="待核")
    c1 = lead.member_candidate_ids[0]
    d = _parent_decision(tmp_path, inv, lead, "excluded_with_reason",
                         members_hash=pd.members_hash([c1]))  # 旧只 c1（members 会变）
    new_p = SimpleNamespace(parent_id=lead.parent_id, bucket="human", tier="T1:runtime_contact",
                            signals=("runtime_contact",),
                            member_candidate_ids=lead.member_candidate_ids)  # c1+c2（members 变）+ runtime
    new_triage = SimpleNamespace(parents=(new_p,), case_id=tmp_path.name)
    report = pd.classify_replay_change(inv, new_triage, [d])
    assert report.summary["blocked_stale"] == 1  # runtime 优先，不因 members 变被降 carry


# ---------- 耗时优化：判决批量（一次 build，杜绝逐条重算） ----------
def test_build_decisions_from_intents(tmp_path: Path) -> None:
    inv, triage, lead = _two_pkg_case(tmp_path, advice="待核")
    intents = [{"scope": "parent", "parent": lead.parent_id,
                "disposition": "excluded_with_reason", "reason": "批量排除"}]
    decisions = pd.build_decisions_from_intents(
        inv, triage, intents, case_id=tmp_path.name, decided_by="t")
    assert len(decisions) == 1
    assert decisions[0]["scope"] == "parent"
    assert decisions[0]["disposition"] == "excluded_with_reason"
    # 批量构造的判决能过 append 校验（与逐条 decide 等价、只是 build 一次）
    pd.validate_new_decision(
        decisions[0], [], members_by_parent={lead.parent_id: lead.member_candidate_ids},
        inventory_candidate_ids={c.candidate_id for c in inv.candidates},
        known_clue_ids=set(), case_id=tmp_path.name)


def test_intents_accepted点名(tmp_path: Path) -> None:
    inv, triage, lead = _two_pkg_case(tmp_path)  # 建议调证
    c1 = lead.member_candidate_ids[0]
    intents = [{"scope": "parent", "parent": lead.parent_id, "disposition": "accepted_clue",
                "accepts": [{"candidate": c1, "clue": "CL-1"}]}]
    decisions = pd.build_decisions_from_intents(
        inv, triage, intents, case_id=tmp_path.name, decided_by="t")
    assert decisions[0]["disposition"] == "accepted_clue"
    assert decisions[0]["accepts"] == [{"candidate_id": c1, "clue_id": "CL-1"}]


def test_intents_非对象行被拒(tmp_path: Path) -> None:
    """判决批量复审 P2#2：一行 JSON 是 null/数字/字符串/数组 → DecisionError，
    不漏成 AttributeError/TypeError（那不在 _cmd_decide_file 的捕获列表里，会 traceback）。"""
    inv, triage, _ = _two_pkg_case(tmp_path)
    for bad in (None, 42, "x", ["a"]):
        with pytest.raises(pd.DecisionError):
            pd.build_decisions_from_intents(
                inv, triage, [bad], case_id=tmp_path.name, decided_by="t")  # type: ignore[arg-type]  # 故意传坏值


def test_intents_accepts非法被拒(tmp_path: Path) -> None:
    """判决批量复审 P2#2：accepts 非数组、或元素非对象 → DecisionError。"""
    inv, triage, lead = _two_pkg_case(tmp_path)
    for bad_accepts in (None, "x", [123], ["notdict"]):
        with pytest.raises(pd.DecisionError):
            pd.build_decisions_from_intents(
                inv, triage,
                [{"scope": "parent", "parent": lead.parent_id,
                  "disposition": "accepted_clue", "accepts": bad_accepts}],
                case_id=tmp_path.name, decided_by="t")


def test_append_decisions_dry_run校验但不写盘(tmp_path: Path) -> None:
    """判决批量复审 P2#3：dry_run 走与真写**相同**的读台账+逐条校验，但不落盘——
    预检说「可提交」就必须真能提交（否则预检是假的）。"""
    inv, triage, lead = _two_pkg_case(tmp_path, advice="待核")
    intents = [{"scope": "parent", "parent": lead.parent_id,
                "disposition": "excluded_with_reason", "reason": "x"}]
    decisions = pd.build_decisions_from_intents(
        inv, triage, intents, case_id=tmp_path.name, decided_by="t")
    path = tmp_path / "phase2" / "decisions.jsonl"
    mbp = {lead.parent_id: lead.member_candidate_ids}
    cids = {c.candidate_id for c in inv.candidates}
    # 空 intents 构造 0 条（CLI 层据此不写盘）
    assert pd.build_decisions_from_intents(
        inv, triage, [], case_id=tmp_path.name, decided_by="t") == []
    # dry_run：校验通过但不落盘
    pd.append_decisions(path, decisions, members_by_parent=mbp,
                        inventory_candidate_ids=cids, known_clue_ids=set(),
                        case_id=tmp_path.name, dry_run=True)
    assert not path.exists()  # ★没写文件
    # dry_run 仍跑完整校验：先真写一条活动末端，再对同单元 dry_run 一条无 supersedes 的 → 被拒
    pd.append_decisions(path, decisions, members_by_parent=mbp,
                        inventory_candidate_ids=cids, known_clue_ids=set(), case_id=tmp_path.name)
    before = path.read_bytes()
    dup = pd.build_decisions_from_intents(
        inv, triage, intents, case_id=tmp_path.name, decided_by="t2")
    with pytest.raises(pd.DecisionGraphError):  # 已有活动末端、无 supersedes → 校验拒
        pd.append_decisions(path, dup, members_by_parent=mbp,
                            inventory_candidate_ids=cids, known_clue_ids=set(),
                            case_id=tmp_path.name, dry_run=True)
    assert path.read_bytes() == before  # dry_run 失败也没动盘
