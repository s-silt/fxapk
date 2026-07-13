"""report 对比（fxapk diff）：core.diff.diff_reports 纯逻辑 + CLI 端到端。"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from apkscan import cli
from apkscan.core.diff import diff_reports


def _report(*, leads=None, endpoints=None, findings=None, meta=None) -> dict:  # type: ignore[no-untyped-def]
    return {
        "leads": leads or [],
        "endpoints": endpoints or [],
        "findings": findings or [],
        "meta": meta or {},
    }


# --- leads 增量（按 category+value 配对）------------------------------------


def test_diff_leads_added_removed() -> None:
    old = _report(leads=[
        {"category": "PAYMENT", "value": "pay.old.com"},
        {"category": "WALLET_SECRET", "value": "0xabc"},
    ])
    new = _report(leads=[
        {"category": "WALLET_SECRET", "value": "0xabc"},  # 保留
        {"category": "ADMIN_PANEL", "value": "admin.new.com"},  # 新增
    ])
    d = diff_reports(old, new)
    added = {(x["category"], x["value"]) for x in d["leads"]["added"]}
    removed = {(x["category"], x["value"]) for x in d["leads"]["removed"]}
    assert added == {("ADMIN_PANEL", "admin.new.com")}
    assert removed == {("PAYMENT", "pay.old.com")}
    assert d["summary"]["leads_added"] == 1 and d["summary"]["leads_removed"] == 1


def test_diff_same_category_different_value_is_both_add_and_remove() -> None:
    # 同类不同值（如换了后台域名）= 一删一增，而非"改"（lead 无稳定 id，靠 value 配对）。
    old = _report(leads=[{"category": "ADMIN_PANEL", "value": "a.old.com"}])
    new = _report(leads=[{"category": "ADMIN_PANEL", "value": "a.new.com"}])
    d = diff_reports(old, new)
    assert d["summary"]["leads_added"] == 1 and d["summary"]["leads_removed"] == 1


# --- endpoints 增量（按 value+kind）-----------------------------------------


def test_diff_endpoints_by_value_and_kind() -> None:
    old = _report(endpoints=[{"value": "x.com", "kind": "domain"}])
    new = _report(endpoints=[
        {"value": "x.com", "kind": "domain"},
        {"value": "1.2.3.4", "kind": "ip"},
    ])
    d = diff_reports(old, new)
    assert [e["value"] for e in d["endpoints"]["added"]] == ["1.2.3.4"]
    assert d["endpoints"]["removed"] == []


# --- findings 增量 + changed（同 id 但 severity/confidence/kind 变）---------


def test_diff_findings_added_removed_changed() -> None:
    old = _report(findings=[
        {"id": "F-KEEP", "severity": "LOW", "confidence": "MEDIUM", "kind": "inference"},
        {"id": "F-GONE", "severity": "HIGH"},
    ])
    new = _report(findings=[
        {"id": "F-KEEP", "severity": "HIGH", "confidence": "MEDIUM", "kind": "inference",
         "title": "升级了"},  # severity 变
        {"id": "F-NEW", "severity": "MEDIUM"},
    ])
    d = diff_reports(old, new)
    assert [f["id"] for f in d["findings"]["added"]] == ["F-NEW"]
    assert [f["id"] for f in d["findings"]["removed"]] == ["F-GONE"]
    changed = d["findings"]["changed"]
    assert len(changed) == 1
    assert changed[0]["id"] == "F-KEEP"
    assert changed[0]["changes"]["severity"] == {"old": "LOW", "new": "HIGH"}
    assert "confidence" not in changed[0]["changes"]  # 没变的不列


def test_diff_findings_same_id_multiple_not_collapsed() -> None:
    # ★复审修复：id 是**规则**标识，同规则多命中（如 jadx 每个硬编码密钥都共用常量
    #   JADX-HARDCODED-SECRET）不能因 id 相同塌缩，否则"新增密钥"这类核心增量被静默吞掉。
    #   靠 (id, description) 区分实例。
    old = _report(findings=[{"id": "JADX-HARDCODED-SECRET", "description": "secret in A.java"}])
    new = _report(findings=[
        {"id": "JADX-HARDCODED-SECRET", "description": "secret in A.java"},  # 保留
        {"id": "JADX-HARDCODED-SECRET", "description": "secret in B.java"},  # 新增（同 id）
        {"id": "JADX-HARDCODED-SECRET", "description": "secret in C.java"},  # 新增（同 id）
    ])
    d = diff_reports(old, new)
    assert len(d["findings"]["added"]) == 2  # 两条新增密钥不被塌缩吞掉
    assert {f["description"] for f in d["findings"]["added"]} == {
        "secret in B.java", "secret in C.java",
    }
    assert d["findings"]["removed"] == []


# --- meta 变化（身份/加固/分类）--------------------------------------------


def test_diff_meta_identity_hardening_classification() -> None:
    old = _report(meta={
        "version_name": "1.0", "packer": "none", "is_hardened": False,
        "app_classification": {"type": "unknown", "score": 10},
    })
    new = _report(meta={
        "version_name": "2.0", "packer": "梆梆", "is_hardened": True,
        "app_classification": {"type": "fraud", "score": 88},
    })
    d = diff_reports(old, new)["meta_changes"]
    assert d["version_name"] == {"old": "1.0", "new": "2.0"}
    assert d["is_hardened"] == {"old": False, "new": True}
    assert d["app_classification.type"] == {"old": "unknown", "new": "fraud"}
    assert d["app_classification.score"] == {"old": 10, "new": 88}


# --- 健壮性 ----------------------------------------------------------------


def test_diff_handles_non_dict_and_missing_keys() -> None:
    assert diff_reports(None, None)["summary"]["leads_added"] == 0
    assert diff_reports({}, {})["findings"]["changed"] == []
    # 报告缺 leads/endpoints/findings 键 → 空增量，不抛。
    assert diff_reports({"meta": {}}, {"meta": {}})["summary"]["endpoints_added"] == 0


# --- CLI 端到端 ------------------------------------------------------------


def test_cli_diff_two_json_reports(tmp_path: Path) -> None:
    old_p = tmp_path / "old.json"
    new_p = tmp_path / "new.json"
    old_p.write_text(json.dumps(_report(leads=[{"category": "PAYMENT", "value": "pay.old.com"}])), encoding="utf-8")
    new_p.write_text(json.dumps(_report(
        leads=[{"category": "WALLET_SECRET", "value": "0xnew"}],
        meta={"is_hardened": True},
    )), encoding="utf-8")

    res = CliRunner().invoke(cli.app, ["diff", str(old_p), str(new_p)])
    assert res.exit_code == 0
    out = json.loads(res.output)
    assert {(x["category"], x["value"]) for x in out["leads"]["added"]} == {("WALLET_SECRET", "0xnew")}
    assert {(x["category"], x["value"]) for x in out["leads"]["removed"]} == {("PAYMENT", "pay.old.com")}
    assert out["meta_changes"]["is_hardened"] == {"old": None, "new": True}


def test_cli_diff_bad_json_exits_3(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json", encoding="utf-8")
    good = tmp_path / "good.json"
    good.write_text(json.dumps(_report()), encoding="utf-8")
    res = CliRunner().invoke(cli.app, ["diff", str(bad), str(good)])
    assert res.exit_code == 3
