# -*- coding: utf-8 -*-
"""Phase2 只读分层红线测试。

全部走真入口：真实小包 → build_inventory → build_triage（不 mock _stable_parent_id），
因此同时锁住与真实 phase1_coverage 的集成。每条红线在注释里给出"无修复即失败"的突变。
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest



import apkscan.commands.phase2 as cli
import apkscan.core.phase2.inventory as coverage
import apkscan.core.phase2.triage as pt
from tests.phase2_fixtures import write_verified_package


def _write_package(
    case_dir: Path,
    name: str,
    *,
    leads: list | None = None,
    endpoints: list | None = None,
    findings: list | None = None,
    package_id: str | None = None,
) -> None:
    """写一个经公开 verifier 可验的不可变包（package_id 由 manifest 规范哈希决定）。"""
    del package_id
    write_verified_package(
        case_dir, name, leads=leads, endpoints=endpoints, findings=findings
    )


def _lead(value: str, advice: str, *, category: str = "IP", **runtime: object) -> dict:
    lead = {
        "category": category,
        "value": value,
        "advice": advice,
        "source_refs": [{"evidence_id": f"ev-{value}", "scope": "case_evidence"}],
    }
    lead.update(runtime)
    return lead


def _endpoint(kind: str, value: str) -> dict:
    return {
        "kind": kind,
        "value": value,
        "evidences": [{"evidence_id": f"ev-{kind}-{value}", "scope": "case_evidence"}],
    }


def _triage_of(case_dir: Path):
    inventory = coverage.build_inventory(case_dir)
    assert not inventory.issues, [i.code for i in inventory.issues]
    return inventory, pt.build_triage(inventory, case_dir)


def _by_collection(triage, collection: str) -> list:
    return [p for p in triage.parents if p.collection == collection]


# ---------- 红线 1：覆盖守恒 ----------
def test_覆盖守恒(tmp_path: Path) -> None:
    """Σ member == 候选数 == totals.candidates。
    突变：把 _make_proposal 的 member_ids 改为 candidates[:-1] → build_triage raise → 本测试崩。"""
    _write_package(
        tmp_path, "pkg-a",
        leads=[_lead("100.64.1.1", "待核", is_runtime_seen=False,
                     is_runtime_contact=False, is_c2=False)],
        endpoints=[_endpoint("ip", "100.64.1.2")],
        findings=[{"id": "R-1", "title": "示例", "severity": "LOW",
                   "evidences": [{"evidence_id": "ev-f1", "scope": "case_evidence"}]}],
    )
    inventory, triage = _triage_of(tmp_path)
    total_members = sum(len(p.member_candidate_ids) for p in triage.parents)
    assert total_members == len(inventory.candidates)
    assert triage.totals["candidates"] == total_members


# ---------- 红线 2：三态·R4 缺失字段不得自动排除 ----------
def test_R4_runtime字段缺失必须T1(tmp_path: Path) -> None:
    """advice=无需调证 但 is_runtime_contact 字段缺失 → 禁止自动排除，进 T1。
    突变：_bool_state 把 missing 当 'false' → 会走 auto:excluded_with_reason → 断言失败。"""
    _write_package(
        tmp_path, "pkg-a",
        leads=[_lead("100.64.2.1", "无需调证", is_runtime_seen=False, is_c2=False)],
        # is_runtime_contact 故意缺失
    )
    _, triage = _triage_of(tmp_path)
    lead = _by_collection(triage, "leads")[0]
    assert lead.bucket == "human"
    assert lead.tier.startswith("T1")


def test_R4_runtime字段为null必须T1(tmp_path: Path) -> None:
    """null 与 False 三态分开：任一 runtime 字段为 null → 不得自动排除。"""
    _write_package(
        tmp_path, "pkg-a",
        leads=[_lead("100.64.2.9", "无需调证", is_runtime_seen=False,
                     is_runtime_contact=None, is_c2=False)],
    )
    _, triage = _triage_of(tmp_path)
    lead = _by_collection(triage, "leads")[0]
    assert lead.bucket == "human"
    assert lead.tier.startswith("T1")


def test_R4_三字段显式False才允许排除(tmp_path: Path) -> None:
    _write_package(
        tmp_path, "pkg-a",
        leads=[_lead("100.64.2.2", "无需调证", is_runtime_seen=False,
                     is_runtime_contact=False, is_c2=False)],
    )
    _, triage = _triage_of(tmp_path)
    lead = _by_collection(triage, "leads")[0]
    assert lead.bucket == "auto:excluded_with_reason"


# ---------- 红线 3：runtime_seen=True 升 T1，不进 T2 ----------
def test_runtime_seen升T1不进T2(tmp_path: Path) -> None:
    """突变：删掉 runtime_seen 的 T1 抬升 → 待核+seen 会落入 T2 → 断言失败。"""
    _write_package(
        tmp_path, "pkg-a",
        leads=[_lead("example.test", "待核", category="DOMAIN",
                     is_runtime_seen=True, is_runtime_contact=False, is_c2=False)],
    )
    _, triage = _triage_of(tmp_path)
    lead = _by_collection(triage, "leads")[0]
    assert lead.bucket == "human"
    assert lead.tier == "T1:runtime_seen"  # 精确 tier，不是兜底"字段不完整"
    assert "字段不完整" not in lead.tier


# ---------- 红线 4：R1 规范化合并 ----------
def test_R1规范化后endpoint挂lead(tmp_path: Path) -> None:
    """lead IP 值带 :443/tcp 后缀，endpoint 裸 host 同值 → 必须 merged。
    突变：normalize_host 不剥端口/路径 → 漏合并、endpoint 落 T1 → 断言失败。"""
    _write_package(
        tmp_path, "pkg-a",
        leads=[_lead("100.64.9.28:443/tcp", "待核", is_runtime_seen=False,
                     is_runtime_contact=False, is_c2=False)],
        endpoints=[_endpoint("ip", "100.64.9.28")],
    )
    _, triage = _triage_of(tmp_path)
    endpoint = _by_collection(triage, "endpoints")[0]
    assert endpoint.bucket == "auto:duplicate_or_merged"
    assert endpoint.tier == "R1-MIRROR"
    assert len(endpoint.merged_into) == 1


# ---------- 红线 5：R1 单向（runtime-only 无镜像 endpoint 必进 T1） ----------
@pytest.mark.parametrize("same_package", [True, False])
@pytest.mark.parametrize("runtime_signal", ["source", "enrichment"])
def test_runtime_endpoint_cannot_be_hidden_by_static_mirror(
    tmp_path: Path, same_package: bool, runtime_signal: str
) -> None:
    from apkscan.core.phase2.decision import (
        build_decisions_from_intents, materialize_snapshot, run_gate,
    )

    lead = _lead("api.example.test", "无需调证", category="DOMAIN",
                 is_runtime_seen=False, is_runtime_contact=False, is_c2=False)
    endpoint = _endpoint("domain", "api.example.test")
    if runtime_signal == "source":
        endpoint["evidences"][0]["source"] = "runtime-pcap"
    else:
        endpoint["enrichment"] = {"runtime": {"target_attributed": True, "has_payload": True}}
    _write_package(tmp_path, "static", leads=[lead],
                   endpoints=[endpoint] if same_package else [])
    if not same_package:
        _write_package(tmp_path, "dynamic", endpoints=[endpoint])
    inventory, triage = _triage_of(tmp_path)
    proposal = _by_collection(triage, "endpoints")[0]
    assert proposal.bucket == "human"
    materialized = materialize_snapshot(inventory, triage, [], [], case_id=inventory.case_id)
    gate = run_gate(inventory, triage, [], [], materialized.coverage, case_id=inventory.case_id)
    assert not gate.ok
    decisions = build_decisions_from_intents(
        inventory, triage, [{"parent": proposal.parent_id,
                            "disposition": "excluded_with_reason", "reason": "合成排除"}],
        case_id=inventory.case_id, decided_by="synthetic-reviewer",
    )
    excluded = materialize_snapshot(inventory, triage, decisions, [], case_id=inventory.case_id)
    gate = run_gate(inventory, triage, decisions, [], excluded.coverage, case_id=inventory.case_id)
    assert any(blocker.startswith("G8:") for blocker in gate.blockers)


def test_R1单向_无镜像endpoint必须T1(tmp_path: Path) -> None:
    """突变：R1 改双向吞并 → 无 lead 的 endpoint 被误 merged → 断言失败。"""
    _write_package(
        tmp_path, "pkg-a",
        endpoints=[_endpoint("ip", "100.64.9.29")],
    )
    _, triage = _triage_of(tmp_path)
    endpoint = _by_collection(triage, "endpoints")[0]
    assert endpoint.bucket == "human"
    assert endpoint.tier == "T1:endpoint无lead镜像"
    assert endpoint.merged_into == ()


# ---------- 红线 6：确定性 ----------
def test_确定性两次逐字节相同(tmp_path: Path) -> None:
    _write_package(
        tmp_path, "pkg-a",
        leads=[_lead("100.64.4.1", "待核", is_runtime_seen=False,
                     is_runtime_contact=False, is_c2=False, confidence="HIGH"),
               _lead("100.64.4.2", "建议调证", is_runtime_seen=True,
                     is_runtime_contact=True, is_c2=True)],
        endpoints=[_endpoint("domain", "a.example.test"),
                   _endpoint("path", "/api/v1/login")],
    )
    inventory = coverage.build_inventory(tmp_path)
    first = pt.build_triage(inventory, tmp_path).to_dict()
    second = pt.build_triage(inventory, tmp_path).to_dict()
    assert json.dumps(first, ensure_ascii=False, sort_keys=True) == json.dumps(
        second, ensure_ascii=False, sort_keys=True
    )


# ---------- 红线 7：单一真源（判据只在 phase2_triage，CLI 不含） ----------
def test_单一真源() -> None:
    pt_file, cli_file = pt.__file__, cli.__file__
    assert pt_file and cli_file
    src = Path(pt_file).read_text(encoding="utf-8")
    assert src.count("def normalize_host(") == 1
    cli_src = Path(cli_file).read_text(encoding="utf-8")
    for forbidden in ("normalize_host", "R1-MIRROR", "R4-LEDGER",
                      "is_runtime_seen", "_all_runtime_false"):
        assert forbidden not in cli_src, forbidden


# ---------- CLI 真入口落两文件 ----------
def test_cli_triage落两文件(tmp_path: Path) -> None:
    _write_package(
        tmp_path, "pkg-a",
        leads=[_lead("100.64.3.1", "待核", is_runtime_seen=False,
                     is_runtime_contact=False, is_c2=False)],
    )
    assert cli.main(["triage", "--case-dir", str(tmp_path)]) == 0
    assert (tmp_path / "phase2" / "triage.json").is_file()
    assert (tmp_path / "phase2" / "queue.md").is_file()
    payload = json.loads((tmp_path / "phase2" / "triage.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "phase2-triage/1.0"


# ---------- 复审补测：非法包不得污染判据（P1#2） ----------
def test_非法包不污染判据(tmp_path: Path) -> None:
    """被 inventory 拒绝的坏包，其 lead 不得进 lead_index 污染 R1。
    突变：_read_parent_versions 改回按目录 iterdir → 坏包 lead 误镜像合法 endpoint → 红。"""
    _write_package(tmp_path, "pkg-good", endpoints=[_endpoint("ip", "100.64.5.1")])
    bad = tmp_path / "pkg-bad"
    bad.mkdir()
    (bad / "report.json").write_text(
        json.dumps({
            "leads": [_lead("100.64.5.1", "待核", is_runtime_seen=False,
                            is_runtime_contact=False, is_c2=False)],
            "endpoints": [], "findings": [],
        }, ensure_ascii=False), encoding="utf-8")
    inventory = coverage.build_inventory(tmp_path)
    assert inventory.issues  # 坏包（缺 case-package.json）被拒绝
    triage = pt.build_triage(inventory, tmp_path)
    endpoints = [p for p in triage.parents if p.collection == "endpoints"]
    assert len(endpoints) == 1
    assert endpoints[0].tier == "T1:endpoint无lead镜像"  # 未被坏包 lead 误镜像


# ---------- 复审补测：守恒挡"一漏一重"（P1#3） ----------
def test_守恒拒绝重复candidate_id(tmp_path: Path) -> None:
    dup = SimpleNamespace(candidate_id="p1:dup", package_id="pkg",
                          collection="leads", parent_id="lead:x", display_value="x")
    inv = SimpleNamespace(case_id="c", fingerprint="f",
                          candidates=[dup, dup], issues=[], packages=[])
    with pytest.raises(ValueError, match="非唯一"):
        pt.build_triage(inv, tmp_path)


# ---------- 复审补测：CLI 对 blocker 默认阻断（P2#6） ----------
def test_cli_issues默认阻断(tmp_path: Path) -> None:
    _write_package(tmp_path, "pkg-good",
                   leads=[_lead("100.64.6.1", "待核", is_runtime_seen=False,
                                is_runtime_contact=False, is_c2=False)])
    bad = tmp_path / "pkg-bad"
    bad.mkdir()
    (bad / "report.json").write_text(
        json.dumps({"leads": [], "endpoints": [], "findings": []}), encoding="utf-8")
    assert cli.main(["triage", "--case-dir", str(tmp_path)]) == 1
    assert not (tmp_path / "phase2").exists()
    assert cli.main(["triage", "--case-dir", str(tmp_path), "--allow-inventory-issues"]) == 0
    assert (tmp_path / "phase2" / "triage.json").is_file()
