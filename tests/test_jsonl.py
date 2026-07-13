"""report → JSONL 事件流（fxapk jsonl）：core.jsonl.report_to_events + CLI 端到端。"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from apkscan import cli
from apkscan.core.jsonl import report_to_events

_REPORT = {
    "schema_version": "1.0",
    "analysis_status": "partial",
    "completeness": 0.5,
    "package_name": "com.fraud.app",
    "meta": {
        "package_name": "com.fraud.app",
        "sample_sha256": "abc123",
        "version_name": "2.0",
        "mode": "passive",
        "tool_version": "0.9.0",
        "ruleset_digest": "deadbeef",
    },
    "leads": [
        {"category": "WALLET_SECRET", "value": "0xdead", "confidence": "HIGH",
         "advice": "建议调证", "evidence_to_obtain": ["链上交易"]},
    ],
    "findings": [
        {"id": "NATIVE-OBFUSCATION-SUSPECTED", "title": "疑加密", "severity": "MEDIUM",
         "confidence": "LOW", "kind": "inference", "analyzer": "native_obfuscation",
         "category": "anti_analysis", "evidences": [{"source": "native", "location": "libx.so"}]},
    ],
}


def test_events_meta_header_first() -> None:
    events = report_to_events(_REPORT)
    assert events[0]["type"] == "meta"
    m = events[0]
    assert m["package"] == "com.fraud.app"
    assert m["analysis_status"] == "partial" and m["completeness"] == 0.5
    assert m["ruleset_digest"] == "deadbeef" and m["tool_version"] == "0.9.0"


def test_events_lead_and_finding() -> None:
    events = report_to_events(_REPORT)
    types = [e["type"] for e in events]
    assert types == ["meta", "lead", "finding"]  # meta 头 + 每条各一

    lead = next(e for e in events if e["type"] == "lead")
    assert lead["category"] == "WALLET_SECRET" and lead["confidence"] == "HIGH"
    assert lead["evidence_to_obtain"] == ["链上交易"]

    finding = next(e for e in events if e["type"] == "finding")
    # ★溯源字段随事件自解释,供 agent 加权/归因
    assert finding["id"] == "NATIVE-OBFUSCATION-SUSPECTED"
    assert finding["confidence"] == "LOW" and finding["kind"] == "inference"
    assert finding["analyzer"] == "native_obfuscation"
    assert finding["evidence"] == [{"source": "native", "location": "libx.so"}]


def test_events_robust_non_dict_and_empty() -> None:
    # 非 dict → 只 meta 头(全 None),不抛。
    assert report_to_events(None) == [report_to_events(None)[0]]
    assert report_to_events(None)[0]["type"] == "meta"
    # 缺 leads/findings 键 → 只 meta。
    assert [e["type"] for e in report_to_events({"meta": {}})] == ["meta"]


def test_cli_jsonl_one_json_per_line(tmp_path: Path) -> None:
    p = tmp_path / "r.json"
    p.write_text(json.dumps(_REPORT), encoding="utf-8")
    res = CliRunner().invoke(cli.app, ["jsonl", str(p)])
    assert res.exit_code == 0
    lines = [ln for ln in res.output.splitlines() if ln.strip()]
    parsed = [json.loads(ln) for ln in lines]  # 每行必须是合法 JSON
    assert [e["type"] for e in parsed] == ["meta", "lead", "finding"]


def test_cli_jsonl_bad_json_exits_3(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{oops", encoding="utf-8")
    res = CliRunner().invoke(cli.app, ["jsonl", str(bad)])
    assert res.exit_code == 3
