"""样本库（fxapk corpus）：core.corpus 纯逻辑 + CLI 端到端。"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest
from typer.testing import CliRunner

from apkscan import cli
from apkscan.core import corpus
from apkscan.core.models import (
    Confidence,
    Endpoint,
    Evidence,
    EvidenceScope,
    Lead,
    LeadCategory,
    Report,
)
from apkscan.report import json as report_json


def _evidence(scope: str = "case_evidence") -> dict:
    return {"source": "dex", "location": "classes.dex", "scope": scope}


def _runtime_dns_evidence(scope: str = "case_evidence") -> dict:
    return {"source": "runtime-pcap", "location": "pcap-dns", "scope": scope}


def _save_manifest_cas(root: Path, entries: list[dict], *, allow_shrink: bool = False) -> None:
    _current, revision = corpus.load_manifest_snapshot(root)
    corpus.save_manifest(
        root,
        entries,
        allow_shrink=allow_shrink,
        expected_revision=revision,
    )


def _write_manifest_fixture(root: Path, entries: list[dict]) -> None:
    """Test-only corruption/legacy fixture writer; production APIs must reject these edits."""
    root.mkdir(parents=True, exist_ok=True)
    payload = "".join(
        json.dumps(entry, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"
        for entry in entries
    )
    corpus.manifest_path(root).write_text(payload, encoding="utf-8")


def _add(root: Path, report: dict, *, case_id: str | None = None) -> dict:
    return corpus.add_report(root, report, json.dumps(report), case_id=case_id)


def test_exclusive_report_create_never_publishes_partial_bytes_after_hard_exit(
    tmp_path: Path,
) -> None:
    target = tmp_path / "reports" / "crash.report.json"
    payload = b'{"complete":"corpus evidence"}\n'
    script = """
import os
import sys
from pathlib import Path
from apkscan.core import corpus

real_write = os.write

def crash_after_prefix(descriptor, data):
    written = real_write(descriptor, data[:1])
    os.fsync(descriptor)
    os._exit(91)

os.write = crash_after_prefix
corpus._create_report_exclusive(Path(sys.argv[1]), b'{"complete":"corpus evidence"}\\n')
"""

    completed = subprocess.run(
        [sys.executable, "-c", script, str(target)],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
    )

    assert completed.returncode == 91
    assert not target.exists(), "a crash before publication left partial canonical evidence"
    assert corpus._create_report_exclusive(target, payload) is True
    assert target.read_bytes() == payload


def test_exclusive_report_create_preserves_preexisting_target(tmp_path: Path) -> None:
    target = tmp_path / "reports" / "existing.report.json"
    target.parent.mkdir(parents=True)
    original = b'{"owner":"first"}\n'
    target.write_bytes(original)

    assert corpus._create_report_exclusive(target, b'{"owner":"second"}\n') is False
    assert target.read_bytes() == original


def test_concurrent_exclusive_report_create_publishes_one_complete_payload(
    tmp_path: Path,
) -> None:
    target = tmp_path / "reports" / "race.report.json"
    payloads = (
        b'{"owner":"alpha","padding":"aaaaaaaa"}\n',
        b'{"owner":"bravo","padding":"bbbbbbbb"}\n',
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(
            pool.map(lambda data: corpus._create_report_exclusive(target, data), payloads)
        )

    assert sorted(outcomes) == [False, True]
    assert target.read_bytes() in payloads


def _report(
    *,
    sha: str | None = "abc123",
    tool_version: str = "0.9.0",
    digest: str = "deadbeef",
    package: str = "com.fraud.app",
    leads=None,
    findings=None,
) -> dict:
    meta = {
        "package_name": package,
        "version_name": "2.0",
        "version_code": 20,
        "packer": "packer-x",
        "is_hardened": True,
        "sign_sha256": "CERT-SHA",
        "mode": "passive",
        "tool_version": tool_version,
        "ruleset_digest": digest,
        "app_classification": {"type": "fraud", "score": 88},
    }
    if sha is not None:
        meta["sample_sha256"] = sha
    return {
        "schema_version": "1.2",
        "analysis_status": "complete",
        "completeness": 1.0,
        "package_name": package,
        "meta": meta,
        "leads": leads if leads is not None else [
            {
                "category": "PAYMENT", "value": "pay.x.com", "advice": "建议调证",  # leak-scan: allow 合成 leads 夹具，基线既有值
                "is_c2": False, "source_refs": [_evidence()],
            },
            {
                "category": "DOMAIN", "value": "c2.x.com", "advice": "建议调证",  # leak-scan: allow 合成 leads 夹具，基线既有值
                "is_c2": True,
                "source_refs": [_evidence()],
            },
            {
                "category": "OTHER", "value": "noise.x.com", "advice": "仅参考",  # leak-scan: allow 合成 leads 夹具，基线既有值
                "is_c2": False, "source_refs": [_evidence()],
            },
        ],
        "endpoints": [{"value": "x.com", "kind": "domain", "evidences": [_evidence()]}],  # leak-scan: allow 合成 leads 夹具，基线既有值
        "findings": findings if findings is not None else [
            {"id": "JADX-HARDCODED-SECRET", "description": "k in A"},
            {"id": "NATIVE-OBFUSCATION-SUSPECTED", "description": "libx.so"},
        ],
    }


# --- manifest_entry 提取 -----------------------------------------------------


def test_manifest_entry_extracts_key_fields() -> None:
    e = corpus.manifest_entry(_report(), case_id="case-1")
    assert e["sample_sha256"] == "abc123"
    assert e["sample_sha256_synthetic"] is False
    assert e["tool_version"] == "0.9.0" and e["ruleset_digest"] == "deadbeef"
    assert e["package_name"] == "com.fraud.app"
    assert e["sign_sha256"] == "CERT-SHA"  # 保留证书摘要供候选召回，不在此判家族/主体
    assert e["packer"] == "packer-x" and e["is_hardened"] is True
    assert e["app_type"] == "fraud" and e["app_score"] == 88
    assert e["mode"] == "passive" and e["analysis_status"] == "complete"
    assert e["case_id"] == "case-1"
    assert e["report_path"] == "reports/abc123/0.9.0_deadbeef.report.json"
    assert e["counts"] == {"leads": 3, "endpoints": 1, "findings": 2}
    assert e["finding_ids"] == ["JADX-HARDCODED-SECRET", "NATIVE-OBFUSCATION-SUSPECTED"]
    # key_iocs 只收 is_c2 或 advice=建议调证 的，噪声 lead 不收
    assert set(e["key_iocs"]) == {"pay.x.com", "c2.x.com"}


def test_manifest_entry_projects_only_bounded_repack_verdict() -> None:
    report = _report()
    report["meta"]["repack_identity"] = {
        "verdict": "repack_suspected",
        "signature": {"certificate_subject": "fixture-sensitive-detail"},
        "content_profile": {"vendor_name": "fixture-vendor-detail"},
    }

    entry = corpus.manifest_entry(report)

    assert entry["repack_identity_verdict"] == "repack_suspected"
    rendered = json.dumps(entry, ensure_ascii=True, sort_keys=True)
    assert "fixture-sensitive-detail" not in rendered
    assert "fixture-vendor-detail" not in rendered

    report["meta"]["repack_identity"] = {"verdict": "future-free-text"}
    assert "repack_identity_verdict" not in corpus.manifest_entry(report)
    assert "repack_identity_verdict" not in corpus.manifest_entry({})

    report["meta"]["repack_identity"] = {"verdict": "unknown"}
    assert corpus.manifest_entry(report)["repack_identity_verdict"] == "unknown"


def test_reindex_does_not_mark_unassessed_repack_identity_as_current(tmp_path: Path) -> None:
    report = _report(sha="a" * 64)
    assert "repack_identity" not in report["meta"]
    assert _add(tmp_path, report, case_id="case-1")["added"] is True

    rebuilt = corpus.reindex(tmp_path)

    assert len(rebuilt) == 1
    assert "repack_identity_verdict" not in rebuilt[0]
    from apkscan.core.linkage import rank_link_candidates

    result = rank_link_candidates(rebuilt)
    assert result["status"] == "partial"
    assert "re-analyze" in result["migration"]["next_action"]


def test_manifest_entry_indexes_domains_and_observed_cname_edges() -> None:
    rep = _report()
    rep["leads"] = []
    rep["endpoints"] = [{
        "value": "Entry.Example.Test.", "kind": "domain",
        "evidences": [_runtime_dns_evidence()],
        "enrichment": {"dns_runtime": {
            "cname_edges": [
                {"from": "Entry.Example.Test.", "to": "Route.Example.Test."},
                {"from": "route.example.test", "to": "Origin.Example.Test."},
            ],
        }},
    }]

    entry = corpus.manifest_entry(rep, case_id="case-dns")

    assert entry["domains"] == [
        "entry.example.test", "origin.example.test", "route.example.test"
    ]
    assert entry["cname_edges"] == [
        {"from": "entry.example.test", "to": "route.example.test"},
        {"from": "route.example.test", "to": "origin.example.test"},
    ]
    assert corpus.find_by_domain([entry], "ENTRY.EXAMPLE.TEST.") == [entry]
    assert corpus.find_by_cname([entry], "route.example.test->origin.example.test") == [entry]


@pytest.mark.parametrize(
    "status",
    ["failed", "no_record", "skipped", "disabled"],
)
def test_manifest_entry_ignores_stale_dns_payload_without_provider_hit(
    status: str,
) -> None:
    rep = _report(leads=[])
    rep["endpoints"] = [{
        "value": "entry.example.test",
        "kind": "domain",
        "evidences": [_evidence()],
        "enrichment": {
            "source_status": {"dns": {"status": status}},
            "dns": {
                "cname": ["stale.example.test"],
                "cname_edges": [{
                    "from": "entry.example.test",
                    "to": "stale.example.test",
                }],
            },
        },
    }]

    entry = corpus.manifest_entry(rep)

    assert entry["domains"] == ["entry.example.test"]
    assert entry["cname_edges"] == []


def test_manifest_entry_ignores_stale_dns_payload_when_status_map_omits_dns() -> None:
    rep = _report(leads=[])
    rep["endpoints"] = [{
        "value": "entry.example.test",
        "kind": "domain",
        "evidences": [_evidence()],
        "enrichment": {
            "source_status": {"rdap": {"status": "hit"}},
            "dns": {
                "cname": ["stale.example.test"],
                "cname_edges": [{
                    "from": "entry.example.test",
                    "to": "stale.example.test",
                }],
            },
        },
    }]

    entry = corpus.manifest_entry(rep)

    assert entry["domains"] == ["entry.example.test"]
    assert entry["cname_edges"] == []


@pytest.mark.parametrize("source_status", [None, {"dns": {"status": "hit"}}])
def test_manifest_entry_accepts_dns_payload_for_legacy_or_explicit_hit(
    source_status: dict | None,
) -> None:
    enrichment: dict = {
        "dns": {
            "cname": ["route.example.test"],
            "cname_edges": [{
                "from": "entry.example.test",
                "to": "route.example.test",
            }],
        },
    }
    if source_status is not None:
        enrichment["source_status"] = source_status
    rep = _report(leads=[])
    rep["endpoints"] = [{
        "value": "entry.example.test",
        "kind": "domain",
        "evidences": [_evidence()],
        "enrichment": enrichment,
    }]

    entry = corpus.manifest_entry(rep)

    assert entry["domains"] == ["entry.example.test", "route.example.test"]
    assert entry["cname_edges"] == [{
        "from": "entry.example.test",
        "to": "route.example.test",
    }]


def test_manifest_entry_keeps_runtime_dns_when_passive_dns_failed() -> None:
    rep = _report(leads=[])
    rep["endpoints"] = [{
        "value": "entry.example.test",
        "kind": "domain",
        "evidences": [_runtime_dns_evidence()],
        "enrichment": {
            "source_status": {"dns": {"status": "failed"}},
            "dns": {"cname": ["stale.example.test"]},
            "dns_runtime": {
                "cname_edges": [{
                    "from": "entry.example.test",
                    "to": "observed.example.test",
                }],
            },
        },
    }]

    entry = corpus.manifest_entry(rep)

    assert entry["domains"] == ["entry.example.test", "observed.example.test"]
    assert entry["cname_edges"] == [{
        "from": "entry.example.test",
        "to": "observed.example.test",
    }]


def test_manifest_entry_rejects_batch_runtime_dns_borrowed_by_dex_evidence() -> None:
    rep = _report(leads=[])
    rep["endpoints"] = [{
        "value": "entry.example.test",
        "kind": "domain",
        "evidences": [_evidence(), _runtime_dns_evidence("batch_reference")],
        "enrichment": {
            "dns_runtime": {
                "cname_edges": [{
                    "from": "entry.example.test",
                    "to": "foreign.example.test",
                }],
            },
        },
    }]

    entry = corpus.manifest_entry(rep)

    assert entry["domains"] == ["entry.example.test"]
    assert entry["cname_edges"] == []


def test_case_ioc_projection_requires_nested_case_evidence_scope() -> None:
    rep = _report(leads=[], findings=[])
    rep["meta"]["remote_config_artifacts"] = [
        {"source_url": "https://artifact.example.test/config.dat", "sha256": "a" * 64}
    ]
    rep["leads"] = [
        {
            "category": "DOMAIN", "value": "direct.example.test", "advice": "建议调证",
            "is_c2": True, "source_refs": [_evidence()],
        },
        {
            "category": "DOMAIN", "value": "batch.example.test", "advice": "建议调证",
            "is_c2": True, "source_refs": [_evidence("batch_reference")],
        },
        {
            "category": "DOMAIN", "value": "legacy.example.test", "advice": "建议调证",
            "is_c2": True, "source_refs": [],
        },
        {
            "category": "DOMAIN", "value": "forged-top.example.test", "advice": "建议调证",
            "is_c2": True, "scope": "case_evidence", "source_refs": [_evidence("batch_reference")],
        },
        {
            "category": "DOMAIN", "value": "shared.example.test", "advice": "建议调证",
            "is_c2": True, "source_refs": [_evidence("batch_reference")],
        },
        {
            "category": "DOMAIN", "value": "shared.example.test", "advice": "建议调证",
            "is_c2": True, "source_refs": [_evidence()],
        },
        {
            "category": "REMOTE_CONFIG", "value": "https://direct.example.test/cfg.dat",
            "source_refs": [_evidence()],
        },
        {
            "category": "REMOTE_CONFIG", "value": "https://batch.example.test/cfg.dat",
            "source_refs": [_evidence("batch_reference")],
        },
    ]
    rep["endpoints"] = [
        {
            "value": "direct.example.test", "kind": "domain",
            "evidences": [_runtime_dns_evidence()],
            "enrichment": {"dns_runtime": {"cname_edges": [
                {"from": "direct.example.test", "to": "origin.example.test"}
            ]}},
        },
        {
            "value": "batch-endpoint.example.test", "kind": "domain",
            "evidences": [_evidence("batch_reference")],
            "enrichment": {"dns_runtime": {"cname_edges": [
                {"from": "batch-endpoint.example.test", "to": "batch-origin.example.test"}
            ]}},
        },
        {
            "value": "legacy-endpoint.example.test", "kind": "domain", "evidences": [],
        },
    ]

    entry = corpus.manifest_entry(rep, case_id="case-scope")

    assert set(entry["key_iocs"]) == {"direct.example.test", "shared.example.test"}
    assert entry["domains"] == [
        "direct.example.test", "origin.example.test", "shared.example.test"
    ]
    assert entry["cname_edges"] == [
        {"from": "direct.example.test", "to": "origin.example.test"}
    ]
    by_url = {item["url"]: item for item in entry["remote_config_objects"]}
    assert set(by_url) == {
        "https://artifact.example.test/config.dat",
        "https://direct.example.test/cfg.dat",
    }
    assert by_url["https://artifact.example.test/config.dat"]["sha256"] == "a" * 64


def test_key_iocs_recomputes_is_c2_instead_of_trusting_cached_flag() -> None:
    report = _report(leads=[], findings=[])
    report["leads"] = [
        {
            "category": "CONTACT", "value": "forged-contact", "advice": "待核",
            "is_c2": True, "source_refs": [_evidence()],
        },
        {
            "category": "IP", "value": "192.0.2.10", "advice": "待核",
            "is_c2": True, "source_refs": [_evidence()],
        },
        {
            "category": "DOMAIN", "value": "valid.example.test", "advice": "建议调证",
            "is_c2": False, "source_refs": [_evidence()],
        },
    ]

    entry = corpus.manifest_entry(report)

    assert entry["key_iocs"] == ["valid.example.test"]


def test_real_serialized_report_keeps_current_case_iocs() -> None:
    evidence = Evidence(
        source="dex",
        location="classes.dex",
        scope=EvidenceScope.CASE_EVIDENCE,
    )
    report = Report(
        package_name="com.example.synthetic",
        meta={
            "sample_sha256": "serialized-sample",
            "tool_version": "1.5.4",
            "ruleset_digest": "rules-a",
        },
        leads=[
            Lead(
                category=LeadCategory.DOMAIN,
                value="serialized.example.test",
                confidence=Confidence.HIGH,
                advice="建议调证",
                source_refs=[evidence],
            )
        ],
        endpoints=[
            Endpoint(
                value="serialized.example.test",
                kind="domain",
                evidences=[evidence],
            )
        ],
        findings=[],
        analyzer_status=[],
    )

    entry = corpus.manifest_entry(report_json.to_dict(report))

    assert entry["key_iocs"] == ["serialized.example.test"]
    assert entry["domains"] == ["serialized.example.test"]


def test_legacy_manifest_case_ioc_projection_is_suppressed_until_reindex(
    tmp_path: Path,
) -> None:
    report = _report(sha="legacy-scope", leads=[], findings=[])
    report["schema_version"] = "1.1"
    report["leads"] = [
        {
            "category": "DOMAIN",
            "value": "poisoned.example.test",
            "advice": "建议调证",
            "is_c2": True,
            # Old report: no nested Evidence.scope.
            "source_refs": [{"source": "dex", "location": "classes.dex"}],
        }
    ]
    report["endpoints"] = [
        {
            "value": "poisoned.example.test",
            "kind": "domain",
            "evidences": [{"source": "dex", "location": "classes.dex"}],
        }
    ]
    raw = json.dumps(report, ensure_ascii=False)
    report_file = tmp_path / corpus.report_relpath(report)
    report_file.parent.mkdir(parents=True)
    report_file.write_text(raw, encoding="utf-8")
    poisoned = corpus.manifest_entry(report)
    poisoned.pop("case_ioc_scope_indexed", None)
    poisoned["key_iocs"] = ["poisoned.example.test"]
    poisoned["domains"] = ["poisoned.example.test"]
    poisoned["cname_edges"] = [
        {"from": "poisoned.example.test", "to": "origin.example.test"}
    ]
    poisoned["remote_config_objects"] = [
        {"url": "https://poisoned.example.test/config.dat", "sha256": None}
    ]
    poisoned["native_lib_hashes"] = [{"name": "libkeep.so", "sha256": "b" * 64}]
    poisoned["sign_sha256"] = "CERT-KEEP"
    poisoned["build_environments"] = [{"id": "BUILD-KEEP", "paths": ["/src/main.go"]}]
    corpus.manifest_path(tmp_path).write_text(
        json.dumps(poisoned, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report_before = report_file.read_bytes()

    [safe] = corpus.load_materialized_manifest(tmp_path)

    assert safe["key_iocs"] == []
    assert safe["domains"] == []
    assert safe["cname_edges"] == []
    assert safe["remote_config_objects"] == []
    assert safe["native_lib_hashes"] == poisoned["native_lib_hashes"]
    assert safe["sign_sha256"] == "CERT-KEEP"
    assert safe["build_environments"] == poisoned["build_environments"]
    domain = CliRunner().invoke(
        cli.app,
        [
            "corpus", "seen", "poisoned.example.test", "--by", "domain",
            "--corpus", str(tmp_path),
        ],
    )
    config = CliRunner().invoke(
        cli.app,
        [
            "corpus", "seen", "https://poisoned.example.test/config.dat",
            "--by", "config-object", "--corpus", str(tmp_path),
        ],
    )
    assert domain.exit_code == 0 and json.loads(domain.stdout)["seen"] is False
    assert config.exit_code == 0 and json.loads(config.stdout)["seen"] is False

    [rebuilt] = corpus.reindex(tmp_path)

    assert rebuilt["key_iocs"] == []
    assert rebuilt["domains"] == []
    assert rebuilt["cname_edges"] == []
    assert rebuilt["remote_config_objects"] == []
    assert report_file.read_bytes() == report_before


def test_manifest_does_not_promote_batch_reference_values_to_case_evidence() -> None:
    """整批附件即使挂在单案报告旁，也不得扩写进该案 domain/CNAME 索引。"""
    rep = _report()
    rep["attachments"] = [{
        "scope": "batch_reference",
        "case_evidence": False,
        "values": ["copied-from-another-case.example.test"],
        "cname_edges": [{
            "from": "copied.example.test", "to": "batch.example.test"
        }],
    }]

    entry = corpus.manifest_entry(rep, case_id="case-scope")

    assert "copied-from-another-case.example.test" not in entry["domains"]
    assert {"from": "copied.example.test", "to": "batch.example.test"} not in entry["cname_edges"]


def test_upsert_warns_on_same_key_different_dep_versions(caplog) -> None:
    """★codex P1：同主键但依赖版本不同 → 幂等跳过但告警（不静默丢 dep 变体报告）。"""
    import logging

    base = corpus.manifest_entry(_report(), case_id="c1")
    base = {**base, "dependency_versions": {"androguard": "4.1.4"}}
    other = corpus.manifest_entry(_report(), case_id="c2")
    other = {**other, "dependency_versions": {"androguard": "4.1.9"}}  # 同主键、不同 androguard
    with caplog.at_level(logging.WARNING):
        merged, added = corpus.upsert([base], other)
    assert added is False and len(merged) == 1  # 主键相同 → 幂等跳过
    assert any("依赖版本不同" in r.message for r in caplog.records), "同主键不同依赖版本未告警"


def test_upsert_same_key_same_deps_no_warning(caplog) -> None:
    """同主键同依赖版本 → 幂等跳过、无告警（正常重复入库）。"""
    import logging

    e = {**corpus.manifest_entry(_report()), "dependency_versions": {"androguard": "4.1.4"}}
    with caplog.at_level(logging.WARNING):
        _merged, added = corpus.upsert([e], dict(e))
    assert added is False
    assert not any("依赖版本不同" in r.message for r in caplog.records)


def test_manifest_entry_records_dependency_versions() -> None:
    """依赖版本登记进 manifest（复现锚点，供 upsert 冲突检测）。"""
    rep = _report()
    rep["meta"]["dependency_versions"] = {"androguard": "4.1.4", "requests": "2.32.0"}
    e = corpus.manifest_entry(rep)
    assert e["dependency_versions"] == {"androguard": "4.1.4", "requests": "2.32.0"}


def test_manifest_entry_robust_to_junk() -> None:
    # 坏输入容错、绝不抛。
    e = corpus.manifest_entry({}, case_id=None)
    assert e["case_id"] is None
    assert e["counts"] == {"leads": 0, "endpoints": 0, "findings": 0}
    assert corpus.manifest_entry(None)["package_name"] is None  # type: ignore[arg-type]
    assert e["visibility"] is None, "无可见性求值必须是 None，不能是空 dict（那等于断言无受限主张）"


# --- 证据可见性投影 ---------------------------------------------------------


def _vis_report(**over) -> dict:
    r = _report()
    r.setdefault("meta", {})["visibility"] = {
        "sources": {"dex": {"visibility": "stub_only", "why": ["加固桩"]},
                    "native": {"visibility": "complete", "why": []}},
        "blocked_claims": ["static_endpoint_exhaustive"],
        "remediation": "not_attempted",
        "notes": ["人读文案"],
        "next_actions": ["先脱壳"],
        "degraded": True,
        **over,
    }
    return r


def test_visibility_summary_projects_structured_fields_only() -> None:
    """指纹只收方向可判的结构化字段；notes/why 等人读文案不入（否则措辞一改全库都标"有变化"）。"""
    s = corpus.visibility_summary(_vis_report())
    assert s is not None
    assert s["blocked_claims"] == ["static_endpoint_exhaustive"]
    assert s["sources"]["dex"] == "stub_only"
    assert s["degraded"] is True
    assert s["remediation"] == "not_attempted"
    assert s["next_actions"] == 1, "next_actions 只记条数，不记文案"
    assert "notes" not in s and "why" not in json.dumps(s)


def test_visibility_summary_missing_is_none_not_empty() -> None:
    """★缺失 ≠ 无受限主张：没做求值必须返回 None，畸形值同样折到 None 而非静默吞成空。"""
    assert corpus.visibility_summary(_report()) is None
    assert corpus.visibility_summary({"meta": {"visibility": "坏值"}}) is None
    assert corpus.visibility_summary({"meta": {"visibility": ["坏值"]}}) is None
    assert corpus.visibility_summary(None) is None
    # 求过值、确实无受限主张 → dict（与上面的 None 严格区分）
    empty = corpus.visibility_summary(_vis_report(blocked_claims=[], degraded=False))
    assert empty is not None and empty["blocked_claims"] == []


def test_manifest_entry_carries_visibility() -> None:
    e = corpus.manifest_entry(_vis_report(), case_id="c1")
    assert e["visibility"]["blocked_claims"] == ["static_endpoint_exhaustive"]
    assert e["visibility"]["sources"]["dex"] == "stub_only"
    assert corpus.manifest_entry(_report())["visibility"] is None


# --- 样本身份（真哈希 vs 旧报告占位）----------------------------------------


def test_sample_identity_real_and_synthetic() -> None:
    sha, synthetic = corpus.sample_identity(_report(sha="deadc0de"))
    assert sha == "deadc0de" and synthetic is False

    # 旧报告无 sample_sha256 → 派生 nosha- 占位，确定且可复现
    old = _report(sha=None)
    s1, syn1 = corpus.sample_identity(old)
    s2, _ = corpus.sample_identity(_report(sha=None))
    assert syn1 is True and s1.startswith("nosha-") and s1 == s2


# --- add / upsert 幂等 -------------------------------------------------------


def test_add_report_idempotent(tmp_path: Path) -> None:
    r = _report()
    raw = json.dumps(r)
    first = corpus.add_report(tmp_path, r, raw, case_id="case-1")
    second = corpus.add_report(tmp_path, r, raw, case_id="case-1")
    assert first["added"] is True and second["added"] is False
    # 报告原样落盘 + manifest 只一条
    report_file = tmp_path / first["report_path"]
    assert report_file.exists() and report_file.read_text(encoding="utf-8") == raw
    assert len(corpus.load_manifest(tmp_path)) == 1


def test_add_same_sample_different_version_coexists(tmp_path: Path) -> None:
    # 同样本换 fxapk 版本 → 并存两份报告（回归对比的基线）
    _add(tmp_path, _report(tool_version="0.9.0"), case_id="c1")
    _add(tmp_path, _report(tool_version="1.0.0"), case_id="c1")
    assert len(corpus.load_manifest(tmp_path)) == 2


# --- 反查 / 过滤 -------------------------------------------------------------


def test_find_by_and_query(tmp_path: Path) -> None:
    _add(tmp_path, _report(sha="s1", package="com.a"), case_id="c1")
    _add(tmp_path, _report(sha="s2", package="com.b"), case_id="c2")
    entries = corpus.load_manifest(tmp_path)
    assert len(corpus.find_by(entries, "s1", by="sample_sha256")) == 1
    assert len(corpus.find_by(entries, "com.b", by="package_name")) == 1
    # 两样本共享同一签名证书 → 证书反查命中两条候选，不在查询层判家族/主体
    assert len(corpus.find_by(entries, "CERT-SHA", by="sign_sha256")) == 2
    assert corpus.find_by(entries, "nope", by="sample_sha256") == []
    assert corpus.find_by(entries, "x", by="unknown_field") == []  # 不支持字段 → 空
    assert len(corpus.query(entries, case_id="c1")) == 1


def test_find_by_hash_case_insensitive(tmp_path: Path) -> None:
    """★哈希（sample_sha256/sign_sha256）十六进制大小写等价：反查大写/小写都命中，避免传大写 SHA256 假阴性；
    package_name 保持大小写敏感（com.Foo ≠ com.foo）。"""
    _add(tmp_path, _report(sha="abc123def", package="com.Foo.Bar"), case_id="c1")
    entries = corpus.load_manifest(tmp_path)
    # sample_sha256：库内小写，大写/小写反查都命中
    assert len(corpus.find_by(entries, "ABC123DEF", by="sample_sha256")) == 1
    assert len(corpus.find_by(entries, "abc123def", by="sample_sha256")) == 1
    # sign_sha256：库内 "CERT-SHA"（含大写），小写反查也命中（双向归一）
    assert len(corpus.find_by(entries, "cert-sha", by="sign_sha256")) == 1
    # package_name：大小写敏感——变体不误命中，原样才命中
    assert corpus.find_by(entries, "com.foo.bar", by="package_name") == []
    assert len(corpus.find_by(entries, "com.Foo.Bar", by="package_name")) == 1


# --- reindex 重建 + 保 case_id ----------------------------------------------


def test_reindex_preserves_case_id_from_manifest(tmp_path: Path) -> None:
    corpus.add_report(tmp_path, _report(sha="s1"), json.dumps(_report(sha="s1")), case_id="case-9")
    # manifest 在场时 reindex 从报告重算，但从旧 manifest 继承人工 case_id（不因重建而丢）
    rebuilt = corpus.reindex(tmp_path)
    assert len(rebuilt) == 1 and rebuilt[0]["case_id"] == "case-9"


def test_reindex_rebuilds_from_reports_when_manifest_lost(tmp_path: Path) -> None:
    corpus.add_report(tmp_path, _report(sha="s1"), json.dumps(_report(sha="s1")), case_id="case-9")
    # 索引损坏/丢失：删掉 manifest，reindex 从 reports/ 重建派生字段，并从独立 catalog
    # 恢复人工案件关联。case 绑定不再只活在可重建的 manifest 里。
    corpus.manifest_path(tmp_path).unlink()
    rebuilt = corpus.reindex(tmp_path)
    assert len(rebuilt) == 1 and rebuilt[0]["sample_sha256"] == "s1"
    assert rebuilt[0]["case_id"] == "case-9"
    assert rebuilt[0]["case_ids"] == ["case-9"]


def test_reindex_uses_actual_path_for_legacy_misnamed_unpacked_report(tmp_path: Path) -> None:
    """重建索引时，report_path 必须指向本次实际扫描到的库内文件。

    旧版曾把 unpacked 内容写进没有 ``_unpacked`` 后缀的静态文件名。若 reindex 再按
    报告元数据推导规范文件名，manifest 会指向不存在的文件，同时把真实文件报成 orphan。
    """
    report = _unpacked_report(sha="legacy-unpacked")
    actual = (
        tmp_path
        / "reports"
        / "legacy-unpacked"
        / "0.9.0_deadbeef.report.json"
    )
    actual.parent.mkdir(parents=True)
    actual.write_text(json.dumps(report), encoding="utf-8")

    [rebuilt] = corpus.reindex(tmp_path)

    assert rebuilt["report_path"] == "reports/legacy-unpacked/0.9.0_deadbeef.report.json"
    verified = corpus.verify_reports(tmp_path)
    assert verified["counts"]["missing"] == 0
    assert verified["counts"]["orphan"] == 0


def test_reindex_rejects_duplicate_report_key_without_rewriting_manifest(
    tmp_path: Path,
) -> None:
    report = _report(sha="duplicate-key")
    result = corpus.add_report(tmp_path, report, json.dumps(report))
    original = tmp_path / str(result["report_path"])
    duplicate = tmp_path / corpus.REPORTS_DIR / "duplicate-copy" / "copy.report.json"
    duplicate.parent.mkdir(parents=True)
    duplicate.write_bytes(original.read_bytes())
    before = corpus.manifest_path(tmp_path).read_bytes()

    with pytest.raises(corpus.ManifestCorruptError, match="同一 manifest 主键"):
        corpus.reindex(tmp_path)

    assert corpus.manifest_path(tmp_path).read_bytes() == before


@pytest.mark.parametrize("old_file_state", ["deleted", "corrupt"])
def test_reindex_equal_count_cannot_replace_a_missing_old_key(
    tmp_path: Path,
    old_file_state: str,
) -> None:
    old = _report(sha="old-key")
    old_result = corpus.add_report(tmp_path, old, json.dumps(old), case_id="case-a")
    old_file = tmp_path / str(old_result["report_path"])
    if old_file_state == "deleted":
        old_file.unlink()
    else:
        old_file.write_text("{bad json}", encoding="utf-8")

    new = _report(sha="new-key")
    new_file = tmp_path / corpus.report_relpath(new)
    new_file.parent.mkdir(parents=True, exist_ok=True)
    new_file.write_text(json.dumps(new), encoding="utf-8")
    manifest = corpus.manifest_path(tmp_path)
    before = manifest.read_bytes()

    expected_error = (
        corpus.ManifestShrinkError
        if old_file_state == "deleted"
        else corpus.ManifestCorruptError
    )
    expected_message = "既有主键" if old_file_state == "deleted" else "入库哈希"
    with pytest.raises(expected_error, match=expected_message):
        corpus.reindex(tmp_path)

    assert manifest.read_bytes() == before


def test_reindex_pure_new_report_is_allowed_without_inventing_sequence(
    tmp_path: Path,
) -> None:
    old = _report(sha="old-key")
    corpus.add_report(tmp_path, old, json.dumps(old), case_id="case-a")
    new = _report(sha="new-key")
    new_file = tmp_path / corpus.report_relpath(new)
    new_file.parent.mkdir(parents=True, exist_ok=True)
    new_file.write_text(json.dumps(new), encoding="utf-8")

    rebuilt = corpus.reindex(tmp_path)

    assert {entry["sample_sha256"] for entry in rebuilt} == {"old-key", "new-key"}
    new_entry = next(entry for entry in rebuilt if entry["sample_sha256"] == "new-key")
    assert new_entry["ingest_sequence"] is None


def test_explicit_add_adopts_reindexed_orphan_without_inventing_sequence(
    tmp_path: Path,
) -> None:
    report = _report(sha="adopted-key")
    raw = json.dumps(report)
    report_file = tmp_path / corpus.report_relpath(report)
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(raw, encoding="utf-8")
    [orphan] = corpus.reindex(tmp_path)
    assert orphan["ingest_sequence"] is None
    assert not (tmp_path / "catalog.jsonl").exists()

    result = corpus.add_report(tmp_path, report, raw, case_id="case-a")

    assert result["added"] is False
    assert result["content_conflict"] is False
    [adopted] = corpus.load_materialized_manifest(tmp_path)
    assert adopted["ingest_sequence"] is None
    assert adopted["case_ids"] == ["case-a"]
    assert adopted["report_bytes_sha256_origin"] == corpus.HASH_ORIGIN_BACKFILL


def test_restore_rejects_snapshot_with_duplicate_primary_key(tmp_path: Path) -> None:
    report = _report(sha="duplicate-snapshot")
    corpus.add_report(tmp_path, report, json.dumps(report))
    [entry] = corpus.load_manifest(tmp_path)
    snapshots = corpus.snapshot_dir(tmp_path)
    snapshots.mkdir(parents=True, exist_ok=True)
    snapshot = snapshots / "manifest-duplicate.jsonl"
    line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
    snapshot.write_text(f"{line}\n{line}\n", encoding="utf-8")
    before = corpus.manifest_path(tmp_path).read_bytes()

    restored = corpus.restore_manifest(tmp_path, snapshot.name)

    assert restored["applied"] is False
    assert "主键重复" in str(restored["error"])
    assert corpus.manifest_path(tmp_path).read_bytes() == before


# --- CLI 端到端：add → seen → reindex 幂等闭环 ------------------------------


def test_cli_add_seen_reindex_closed_loop(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "corpus"
    report_file = tmp_path / "r.json"
    report_file.write_text(json.dumps(_report()), encoding="utf-8")
    runner = CliRunner()

    res = runner.invoke(cli.app, ["corpus", "add", str(report_file), "--case", "c1", "--corpus", str(corpus_dir)])
    assert res.exit_code == 0 and json.loads(res.output)["added"] == 1

    res = runner.invoke(cli.app, ["corpus", "seen", "abc123", "--corpus", str(corpus_dir)])
    assert res.exit_code == 0 and json.loads(res.stdout)["seen"] is True

    res = runner.invoke(cli.app, ["corpus", "reindex", "--corpus", str(corpus_dir)])
    assert res.exit_code == 0 and json.loads(res.output)["reindexed"] == 1

    # 再入库幂等跳过
    res = runner.invoke(cli.app, ["corpus", "add", str(report_file), "--case", "c1", "--corpus", str(corpus_dir)])
    assert json.loads(res.stdout)["skipped"] == 1


def test_cli_events_streams_jsonl(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "corpus"
    report_file = tmp_path / "r.json"
    report_file.write_text(json.dumps(_report()), encoding="utf-8")
    runner = CliRunner()
    runner.invoke(cli.app, ["corpus", "add", str(report_file), "--case", "c1", "--corpus", str(corpus_dir)])

    res = runner.invoke(cli.app, ["corpus", "events", "abc123", "--corpus", str(corpus_dir)])
    assert res.exit_code == 0
    lines = [ln for ln in res.stdout.splitlines() if ln.strip()]  # stdout：本命令往 stderr 打不脱敏提醒
    parsed = [json.loads(ln) for ln in lines]  # 每行合法 JSON
    assert parsed[0]["type"] == "meta"
    assert {e["type"] for e in parsed} == {"meta", "lead", "finding"}


def test_cli_events_uses_catalog_sequence_not_report_mtime(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "corpus"
    first = _report(sha="same-sample", tool_version="1.0.0")
    second = _report(sha="same-sample", tool_version="2.0.0")
    first_result = _add(corpus_dir, first, case_id="case-a")
    _add(corpus_dir, second, case_id="case-a")
    # Simulate a OneDrive copy/touch that makes the older evidence file look newer.
    (corpus_dir / str(first_result["report_path"])).touch()

    result = CliRunner().invoke(
        cli.app,
        ["corpus", "events", "same-sample", "--corpus", str(corpus_dir)],
    )

    assert result.exit_code == 0, result.output
    meta = json.loads(next(line for line in result.stdout.splitlines() if line.strip()))
    assert meta["tool_version"] == "2.0.0"


def test_cli_events_legacy_multiversion_requires_explicit_revision(
    tmp_path: Path,
) -> None:
    root = tmp_path / "legacy-corpus"
    entries: list[dict] = []
    for version in ("2.0.0", "1.0.0"):
        report = _report(sha="legacy-sample", tool_version=version)
        path = root / corpus.report_relpath(report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report), encoding="utf-8")
        entry = corpus.manifest_entry(report, case_id="legacy-case")
        entry["report_path"] = path.relative_to(root).as_posix()
        entries.append(entry)
    _write_manifest_fixture(root, entries)

    implicit = CliRunner().invoke(
        cli.app,
        ["corpus", "events", "legacy-sample", "--corpus", str(root)],
    )
    explicit = CliRunner().invoke(
        cli.app,
        [
            "corpus",
            "events",
            "legacy-sample",
            "--revision",
            "1.0.0@deadbeef",
            "--corpus",
            str(root),
        ],
    )

    assert implicit.exit_code == 2
    assert "不能按 manifest 行序或文件 mtime 猜测" in implicit.stderr
    assert explicit.exit_code == 0, explicit.output
    meta = json.loads(next(line for line in explicit.stdout.splitlines() if line.strip()))
    assert meta["tool_version"] == "1.0.0"


@pytest.mark.parametrize("token", ["NaN", "Infinity", "1e9999"])
def test_cli_events_rejects_nonfinite_stored_report(
    tmp_path: Path,
    token: str,
) -> None:
    root = tmp_path / "corpus"
    report = _report(sha="nonfinite-event")
    result = _add(root, report, case_id="case-a")
    stored = root / str(result["report_path"])
    raw = stored.read_text(encoding="utf-8")
    stored.write_text(raw[:-1] + f', "nonfinite": {token}}}', encoding="utf-8")
    # Exercise the strict parser itself through a legacy/unverifiable row;
    # modern hashed rows reject the byte mutation even earlier.
    [entry] = corpus.load_manifest(root)
    entry.pop("report_bytes_sha256", None)
    entry.pop("report_bytes_sha256_origin", None)
    _write_manifest_fixture(root, [entry])

    invoked = CliRunner().invoke(
        cli.app,
        ["corpus", "events", "nonfinite-event", "--corpus", str(root)],
    )

    assert invoked.exit_code == 1
    assert "non-finite JSON number" in invoked.stderr
    assert "Traceback" not in invoked.output


def test_cli_events_rejects_digest_mismatch_without_emitting_forged_lead(
    tmp_path: Path,
) -> None:
    root = tmp_path / "corpus"
    report = _report(sha="tampered-event")
    result = _add(root, report, case_id="case-a")
    stored = root / str(result["report_path"])
    payload = json.loads(stored.read_text(encoding="utf-8"))
    payload["leads"] = [
        {
            "category": "DOMAIN",
            "value": "forged.example.test",
            "advice": "建议调证",
            "source_refs": [_evidence()],
        }
    ]
    stored.write_text(json.dumps(payload), encoding="utf-8")

    invoked = CliRunner().invoke(
        cli.app,
        ["corpus", "events", "tampered-event", "--corpus", str(root)],
    )

    assert invoked.exit_code == 1
    assert "report_bytes_sha256" in invoked.stderr
    assert "forged.example.test" not in invoked.stdout
    assert "Traceback" not in invoked.output


def test_cli_nan_report_is_rejected_before_corpus_ingest(tmp_path: Path) -> None:
    # ★复审(codex 探查方向)：report 数值字段若为 NaN/Infinity（Python json 默认接受、但 RFC-8259
    #   非法），必须拒绝入库；归一化为 None 会改变原报告语义与后续主键/证据判断。
    corpus_dir = tmp_path / "corpus"
    report_file = tmp_path / "r.json"
    r = _report(sha="nan-sample")
    r["completeness"] = float("nan")
    r["meta"]["app_classification"]["score"] = float("inf")
    report_file.write_text(json.dumps(r), encoding="utf-8")  # 默认写出字面 NaN/Infinity
    runner = CliRunner()

    add = runner.invoke(cli.app, ["corpus", "add", str(report_file), "--case", "c1", "--corpus", str(corpus_dir)])
    assert add.exit_code == 1
    payload = json.loads(add.stdout)
    assert payload["added"] == 0 and payload["failed"] == 1
    assert "读取/解析失败" in add.stderr
    assert not corpus.manifest_path(corpus_dir).exists()


def test_cli_events_missing_sample_exits_1(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    res = CliRunner().invoke(cli.app, ["corpus", "events", "ghost", "--corpus", str(corpus_dir)])
    assert res.exit_code == 1


# --- PII 硬防线：缺库路径拒跑 -----------------------------------------------


def test_cli_refuses_without_corpus_dir(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("FXAPK_CORPUS", raising=False)
    report_file = tmp_path / "r.json"
    report_file.write_text(json.dumps(_report()), encoding="utf-8")
    res = CliRunner().invoke(cli.app, ["corpus", "add", str(report_file)])
    assert res.exit_code == 2  # 既无 --corpus 又无环境变量 → 拒跑，绝不默认 ./corpus


def test_cli_uses_env_corpus(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    corpus_dir = tmp_path / "corpus"
    monkeypatch.setenv("FXAPK_CORPUS", str(corpus_dir))
    report_file = tmp_path / "r.json"
    report_file.write_text(json.dumps(_report()), encoding="utf-8")
    res = CliRunner().invoke(cli.app, ["corpus", "add", str(report_file), "--case", "c1"])
    assert res.exit_code == 0 and json.loads(res.output)["added"] == 1


# --- 复审修复回归（Fable 对抗式复审确认的真问题）---------------------------


def test_add_report_collision_refuses_overwrite(tmp_path: Path) -> None:
    # #2/#3：不同主键净化后落同一路径（abc?123 / abc*123 → abc_123），第二次不得覆写第一份取证字节。
    r1 = _report(sha="abc?123")
    r2 = _report(sha="abc*123")
    raw1, raw2 = json.dumps(r1), json.dumps(r2) + " "  # 字节不同
    first = corpus.add_report(tmp_path, r1, raw1)
    second = corpus.add_report(tmp_path, r2, raw2)
    assert first["added"] is True
    assert second["added"] is False and second["collision"] is True
    # 第一份取证字节完好、未被销毁
    assert (tmp_path / first["report_path"]).read_bytes() == raw1.encode("utf-8")


def test_add_report_byte_fidelity_multiline(tmp_path: Path) -> None:
    # #4：多行(含 \n) raw 入库后逐字节等于原文，不被文本模式 CRLF 翻译污染。
    raw = json.dumps(_report(), indent=2)  # 多行
    res = corpus.add_report(tmp_path, _report(), raw)
    assert (tmp_path / res["report_path"]).read_bytes() == raw.encode("utf-8")


def test_sample_identity_rejects_forged_nosha_prefix() -> None:
    # #9：meta.sample_sha256 冒用保留前缀 nosha- → 不当真实身份，落派生分支置 synthetic。
    sha, synthetic = corpus.sample_identity(_report(sha="nosha-deadbeef"))
    assert synthetic is True and sha != "nosha-deadbeef"


def test_reindex_skips_non_utf8_report(tmp_path: Path) -> None:
    # #5：坏文件(非 UTF-8)不得让自愈工具崩，其它报告照常重建。
    corpus.add_report(tmp_path, _report(sha="good"), json.dumps(_report(sha="good")))
    bad = tmp_path / corpus.REPORTS_DIR / "bad" / "x.report.json"
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_bytes(b"\xff\xfe not utf8 \x00")
    rebuilt = corpus.reindex(tmp_path)  # 不抛
    assert len(rebuilt) == 1 and rebuilt[0]["sample_sha256"] == "good"


def test_cli_seen_invalid_by_exits_2(tmp_path: Path) -> None:
    # #8：拼错 --by 字段不能静默假阴性（seen=false exit 0），必须拒跑。
    cd = tmp_path / "corpus"
    cd.mkdir()
    res = CliRunner().invoke(cli.app, ["corpus", "seen", "x", "--by", "sign_sha", "--corpus", str(cd)])
    assert res.exit_code == 2


def test_cli_events_path_traversal_refused(tmp_path: Path) -> None:
    # #10：manifest 里 report_path 越界/缺失 → 拒绝读库外文件、不 traceback。
    cd = tmp_path / "corpus"
    cd.mkdir()
    _write_manifest_fixture(cd, [{
        "sample_sha256": "evil", "tool_version": "t", "ruleset_digest": "d",
        "report_path": "../../../etc/passwd",
    }])
    res = CliRunner().invoke(cli.app, ["corpus", "events", "evil", "--corpus", str(cd)])
    assert res.exit_code == 1


def test_cli_refuses_corpus_inside_git_worktree(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # #1 加固：语料库落在 git 工作树内 → 拒跑（防真实案件数据随 git add 混进公开仓库）。
    monkeypatch.delenv("FXAPK_CORPUS", raising=False)
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    report_file = tmp_path / "r.json"
    report_file.write_text(json.dumps(_report()), encoding="utf-8")
    res = CliRunner().invoke(
        cli.app, ["corpus", "add", str(report_file), "--corpus", str(repo / "corpus")]
    )
    assert res.exit_code == 2


# --- 证据面（脱壳前 / 脱壳后）入主键 -----------------------------------------


def _unpacked_report(**kw) -> dict:  # type: ignore[no-untyped-def]
    """同一样本、同一版本、同一套规则，但看的是**脱壳后**的证据面。"""
    rep = _report(**kw)
    rep["meta"]["unpacked"] = True
    rep["meta"]["unpacked_dex_count"] = 7
    return rep


def test_unpacked_and_static_reports_coexist(tmp_path: Path) -> None:
    """★脱壳前后不是同一批内容，两份报告必须并存。

    此前证据面不在主键里，两份的 (样本, 版本, 规则) 完全相同 → 后入库的被幂等跳过。
    而脱壳那份通常检出**更多**（真样本实测：静态 100 端点、脱壳后 239），
    被丢掉的恰恰是更完整的证据面。

    ★变异验证：把 "evidence_surface" 从 corpus.KEY_FIELDS 去掉，本测试必红。
    """
    static, unpacked = _report(), _unpacked_report()

    entries, added_1 = corpus.upsert([], corpus.manifest_entry(static))
    assert added_1 is True
    entries, added_2 = corpus.upsert(entries, corpus.manifest_entry(unpacked))
    assert added_2 is True, "脱壳报告被当成静态那份的重复，幂等跳过了"
    assert len(entries) == 2

    surfaces = sorted(e["evidence_surface"] for e in entries)
    assert surfaces == ["static", "unpacked"]

    # 两份落在不同文件，不会互相覆盖
    assert corpus.report_relpath(static) != corpus.report_relpath(unpacked)


def test_static_report_path_is_unchanged_by_the_new_dimension() -> None:
    """★向后兼容：static 不加后缀，存量记录不必搬家。

    这一维是后加的；若给 static 也加后缀，库里 40 余条存量记录的路径会全部失配。
    """
    assert corpus.report_relpath(_report()).endswith("/0.9.0_deadbeef.report.json")
    assert corpus.report_relpath(_unpacked_report()).endswith(
        "/0.9.0_deadbeef_unpacked.report.json"
    )


def test_legacy_manifest_row_without_the_field_keys_the_same_as_static() -> None:
    """★存量 manifest 行没有 evidence_surface 字段，主键必须与重算后的 static 对齐。

    不归一的话，同一份存量报告在 reindex 前算出 ""、reindex 后算出 "static"，
    会被当成两条记录——一次索引重建就把库里的记录数凭空翻倍。
    """
    fresh = corpus.manifest_entry(_report())
    legacy = {k: v for k, v in fresh.items() if k != "evidence_surface"}
    assert "evidence_surface" not in legacy

    _entries, added = corpus.upsert([legacy], fresh)
    assert added is False, "存量行与重算行主键不一致，reindex 会重复计数"


def test_unpacked_flag_absent_means_static() -> None:
    """没有 unpacked 标记就是 static——判据只认标记，不靠端点多寡之类的启发式。"""
    assert corpus.evidence_surface(_report()) == "static"
    assert corpus.evidence_surface({}) == "static"
    assert corpus.evidence_surface({"meta": {"unpacked": False}}) == "static"
    assert corpus.evidence_surface({"meta": {"unpacked": True}}) == "unpacked"


# --- 缩减护栏 + 写前快照（防"调用方算错 entries 一次调用抹掉整库"的不可逆损失）---


def test_save_manifest_refuses_shrink_by_default(tmp_path: Path) -> None:
    """Generic CAS cannot add/delete keys; named add/reindex paths own key changes.

    This prevents an equal-length replacement from bypassing a count-only
    shrink guard and prevents public save from fabricating a ghost record.
    """
    for i in range(3):
        _add(tmp_path, _report(sha=f"s{i}"))
    entries = corpus.load_manifest(tmp_path)
    before = corpus.manifest_path(tmp_path).read_bytes()

    with pytest.raises(corpus.ManifestShrinkError):
        _save_manifest_cas(tmp_path, entries[:1])
    assert corpus.manifest_path(tmp_path).read_bytes() == before

    # Same keys may rewrite genuinely derived extension fields.
    entries[0]["test_extension"] = "updated"
    _save_manifest_cas(tmp_path, entries)
    with pytest.raises(corpus.ManifestShrinkError):
        _save_manifest_cas(
            tmp_path,
            [*entries, corpus.manifest_entry(_report(sha="s9"))],
        )
    with pytest.raises(corpus.ManifestShrinkError):
        _save_manifest_cas(tmp_path, entries[:1], allow_shrink=True)


def test_save_manifest_rejects_nonfinite_extension_without_snapshot_or_rewrite(
    tmp_path: Path,
) -> None:
    report = _report(sha="finite-guard")
    corpus.add_report(tmp_path, report, json.dumps(report), case_id="case-a")
    entries, revision = corpus.load_manifest_snapshot(tmp_path)
    entries[0]["extension"] = float("nan")
    manifest = corpus.manifest_path(tmp_path)
    before = manifest.read_bytes()
    snapshots_before = [path.name for path in corpus.list_snapshots(tmp_path)]

    with pytest.raises(ValueError, match="JSON compliant"):
        corpus.save_manifest(tmp_path, entries, expected_revision=revision)

    assert manifest.read_bytes() == before
    assert [path.name for path in corpus.list_snapshots(tmp_path)] == snapshots_before


def test_manifest_reader_rejects_overflowed_json_float(tmp_path: Path) -> None:
    report = _report(sha="overflow-guard")
    corpus.add_report(tmp_path, report, json.dumps(report), case_id="case-a")
    manifest = corpus.manifest_path(tmp_path)
    [entry] = corpus.load_manifest_strict(tmp_path)
    encoded = json.dumps(entry, ensure_ascii=False)
    manifest.write_text(
        encoded[:-1] + ', "overflow": 1e9999}\n',
        encoding="utf-8",
    )

    with pytest.raises(corpus.ManifestCorruptError, match="non-finite"):
        corpus.load_manifest_strict(tmp_path)


def test_save_manifest_snapshots_previous_state_before_write(tmp_path: Path) -> None:
    """写前快照 = 写入前旧状态的逐字节副本，落 .snapshots/。

    ★变异验证：把 save_manifest 里的 snapshot_manifest 调用删掉，本测试必红。
    """
    _add(tmp_path, _report(sha="s1"))
    before = corpus.manifest_path(tmp_path).read_bytes()
    _add(tmp_path, _report(sha="s2"))

    snaps = corpus.list_snapshots(tmp_path)
    assert len(snaps) == 1, "首写无旧状态可拍，第二次写必须拍下第一次的状态"
    assert snaps[0].read_bytes() == before  # 逐字节保真


def test_snapshot_failure_warns_but_does_not_block_write(tmp_path: Path, caplog) -> None:  # type: ignore[no-untyped-def]
    """快照是保险：保险坏了不该让正事（入库）停下，但必须 warning——沉默会让人以为有保险。

    ★变异验证：把 snapshot_manifest 里的 try/except（吞异常转 warning）去掉，本测试必红。
    """
    import logging

    _add(tmp_path, _report(sha="s1"))
    # 用同名普通文件占住 .snapshots → 快照目录无法创建，快照必然失败
    (tmp_path / corpus.SNAPSHOT_DIR).write_text("occupied", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        res = _add(tmp_path, _report(sha="s2"))
    assert res["added"] is True and len(corpus.load_manifest(tmp_path)) == 2  # 主写入未被阻断
    assert any("快照失败" in r.message for r in caplog.records), "快照失败必须出声"


def test_snapshot_retention_and_dedup(tmp_path: Path) -> None:
    """保留窗口按时间淘汰到 SNAPSHOT_KEEP 份；同内容不重复建快照（窗口不被无变化重写刷穿）。

    ★变异验证：删掉 snapshot_manifest 的淘汰循环 → 第一段断言红；删掉去重分支 → 第二段断言红。
    """
    _add(tmp_path, _report(sha="snapshot-seed"))
    entries = corpus.load_manifest(tmp_path)
    for i in range(corpus.SNAPSHOT_KEEP + 5):
        entries[0]["test_revision"] = i
        _save_manifest_cas(tmp_path, entries)
    snaps = corpus.list_snapshots(tmp_path)
    # KEEP+5 次写：首写无快照 → 产出 KEEP+4 份，各份内容都不同，淘汰后剩 KEEP
    assert len(snaps) == corpus.SNAPSHOT_KEEP
    # 最新快照 = 最后一次写之前的 derived revision.
    assert corpus.load_manifest_file(snaps[0])[0]["test_revision"] == corpus.SNAPSHOT_KEEP + 3

    # 同内容重写：第一次把当前态拍进窗口，此后内容不变 → 复用最新快照、不再新建
    _save_manifest_cas(tmp_path, entries)
    names_after_first = [p.name for p in corpus.list_snapshots(tmp_path)]
    _save_manifest_cas(tmp_path, entries)
    assert [p.name for p in corpus.list_snapshots(tmp_path)] == names_after_first


def test_cli_reindex_refuses_shrink_without_flag(tmp_path: Path) -> None:
    """接线锁走真入口：删一份报告文件后 reindex 将少 1 条 → 默认拒绝（exit 1、manifest 未动），
    ``--allow-shrink`` 显式声明后才重建成功。

    ★变异验证：把 reindex（或 CLI 透传）的 allow_shrink 改成恒 True，本测试必红。
    """
    corpus_dir = tmp_path / "corpus"
    r1 = _add(corpus_dir, _report(sha="s1"))
    _add(corpus_dir, _report(sha="s2"))
    (corpus_dir / r1["report_path"]).unlink()  # 报告文件被删（或 OneDrive 占位符读不出的同形态）

    res = CliRunner().invoke(cli.app, ["corpus", "reindex", "--corpus", str(corpus_dir)])
    assert res.exit_code == 1
    assert len(corpus.load_manifest(corpus_dir)) == 2  # 拒写：manifest 分毫未动

    res = CliRunner().invoke(
        cli.app, ["corpus", "reindex", "--allow-shrink", "--corpus", str(corpus_dir)]
    )
    assert res.exit_code == 0
    assert json.loads(res.stdout)["reindexed"] == 1
    assert len(corpus.load_manifest(corpus_dir)) == 1


def test_cli_snapshot_and_restore_roundtrip(tmp_path: Path) -> None:
    """snapshot 手动拍 → 再入库 → restore 无参列表 / 默认 dry-run 不动磁盘 / --apply 恢复且
    恢复前先给当前状态拍快照（恢复错了还能再反悔）。

    ★变异验证：删掉 restore_manifest 里「恢复前先快照」那步，本测试必红
    （pre_restore_snapshot 为 None）。
    """
    corpus_dir = tmp_path / "corpus"
    runner = CliRunner()
    _add(corpus_dir, _report(sha="s1"), case_id="c1")
    _add(corpus_dir, _report(sha="s2"), case_id="c1")

    snap_res = runner.invoke(cli.app, ["corpus", "snapshot", "--corpus", str(corpus_dir)])
    assert snap_res.exit_code == 0
    snap_payload = json.loads(snap_res.stdout)
    assert snap_payload["entries"] == 2
    snap_name = Path(snap_payload["snapshot"]).name

    _add(corpus_dir, _report(sha="s3"), case_id="c1")
    assert len(corpus.load_manifest(corpus_dir)) == 3

    # 无参 = 列出可用快照 + 当前条数
    ls = runner.invoke(cli.app, ["corpus", "restore", "--corpus", str(corpus_dir)])
    assert ls.exit_code == 0
    listing = json.loads(ls.stdout)
    assert listing["current_entries"] == 3
    assert any(s["name"] == snap_name and s["entries"] == 2 for s in listing["snapshots"])

    # 默认 dry-run：打印将恢复几条/现有几条，不写入
    dry = runner.invoke(cli.app, ["corpus", "restore", snap_name, "--corpus", str(corpus_dir)])
    assert dry.exit_code == 0
    dry_payload = json.loads(dry.stdout)
    assert dry_payload["dry_run"] is True
    assert dry_payload["would_restore_entries"] == 2 and dry_payload["current_entries"] == 3
    assert len(corpus.load_manifest(corpus_dir)) == 3  # 磁盘没动

    # --apply 真恢复：回到 2 条；恢复前的 3 条状态被拍成新快照
    ap = runner.invoke(
        cli.app, ["corpus", "restore", snap_name, "--apply", "--corpus", str(corpus_dir)]
    )
    assert ap.exit_code == 0
    ap_payload = json.loads(ap.stdout)
    assert ap_payload["applied"] is True and ap_payload["restored_entries"] == 2
    assert ap_payload["previous_entries"] == 3
    assert len(corpus.load_manifest(corpus_dir)) == 2
    pre = Path(ap_payload["pre_restore_snapshot"])
    assert pre.is_file() and len(corpus.load_manifest_file(pre)) == 3


def test_cli_restore_rejects_missing_and_traversal_names(tmp_path: Path) -> None:
    """不存在的快照与路径穿越名同一出口拒绝——绝不据用户输入读快照目录外的文件。"""
    corpus_dir = tmp_path / "corpus"
    _add(corpus_dir, _report(sha="s1"))
    runner = CliRunner()

    res = runner.invoke(
        cli.app, ["corpus", "restore", "ghost.jsonl", "--apply", "--corpus", str(corpus_dir)]
    )
    assert res.exit_code == 1
    # ../manifest.jsonl 真实存在，但越出 .snapshots → 必须拒绝
    res = runner.invoke(
        cli.app,
        ["corpus", "restore", "../manifest.jsonl", "--apply", "--corpus", str(corpus_dir)],
    )
    assert res.exit_code == 1
    assert len(corpus.load_manifest(corpus_dir)) == 1  # 磁盘没动


def test_cli_restore_apply_without_name_exits_2(tmp_path: Path) -> None:
    """--apply 不指明恢复哪份 → 拒跑（不许"恢复个最新的"这种隐式破坏性默认）。"""
    corpus_dir = tmp_path / "corpus"
    _add(corpus_dir, _report(sha="s1"))
    res = CliRunner().invoke(
        cli.app, ["corpus", "restore", "--apply", "--corpus", str(corpus_dir)]
    )
    assert res.exit_code == 2


def test_cli_snapshot_without_manifest_exits_1(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    res = CliRunner().invoke(cli.app, ["corpus", "snapshot", "--corpus", str(corpus_dir)])
    assert res.exit_code == 1


# --- 存证自证未被篡改：入库哈希 / verify 三档严格分开 / 补录证据边界 ----------


def _sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _strip_hash(corpus_dir: Path, sample_sha: str) -> None:
    """把某条 manifest 记录的完整性哈希字段剥掉，模拟完整性功能之前入库的存量记录。"""
    entries = corpus.load_manifest(corpus_dir)
    for e in entries:
        if e["sample_sha256"] == sample_sha:
            e.pop("report_bytes_sha256", None)
            e.pop("report_bytes_sha256_origin", None)
    _write_manifest_fixture(corpus_dir, entries)


def test_add_report_records_ingest_hash_of_stored_bytes(tmp_path: Path) -> None:
    """入库时记下**存盘原样字节**的哈希（origin=ingest），且它 == 磁盘上那份文件的 sha256。

    ★变异验证：把 add_report 里写 report_bytes_sha256 的两行删掉，本测试必红。
    """
    r = _report()
    raw = json.dumps(r, indent=2)  # 多行，连带验证换行不被翻译（哈希对得上就说明字节保真）
    res = corpus.add_report(tmp_path, r, raw)
    [e] = corpus.load_manifest(tmp_path)
    stored = (tmp_path / res["report_path"]).read_bytes()
    assert e["report_bytes_sha256"] == _sha256(stored)
    assert e["report_bytes_sha256_origin"] == corpus.HASH_ORIGIN_INGEST
    # 与样本哈希是两个字段、两个值，绝不混同
    assert e["report_bytes_sha256"] != e["sample_sha256"]


def test_hash_fields_do_not_change_primary_key() -> None:
    """完整性字段不入主键：带哈希的新条目与不带哈希的存量行必须算同一条记录，
    否则一次 reindex/入库就把库内记录凭空翻倍。"""
    legacy = corpus.manifest_entry(_report())
    hashed = {
        **legacy,
        "report_bytes_sha256": "a" * 64,
        "report_bytes_sha256_origin": corpus.HASH_ORIGIN_INGEST,
    }
    _entries, added = corpus.upsert([legacy], hashed)
    assert added is False


def test_verify_ok_mismatch_unverifiable_strictly_separated(tmp_path: Path) -> None:
    """★核心价值观：三种"文件读得到"的情形严格分开——
    ok（有哈希且相符）/ mismatch（有哈希对不上=被改过）/ unverifiable（没哈希=没法验）。

    ★变异验证：把 verify_reports 里 recorded is None 分支改成归 ok，本测试必红（unverifiable
    计数）；把哈希比对改成恒真，本测试必红（mismatch 计数）。
    """
    r_ok = _report(sha="s-ok")
    corpus.add_report(tmp_path, r_ok, json.dumps(r_ok))

    r_bad = _report(sha="s-bad")
    res_bad = corpus.add_report(tmp_path, r_bad, json.dumps(r_bad))
    # 入库后绕过 API 改文件（追加一个空格：内容仍是合法 JSON，但字节已非原样）
    bad_file = tmp_path / res_bad["report_path"]
    bad_file.write_text(json.dumps(r_bad) + " ", encoding="utf-8")

    r_old = _report(sha="s-old")
    corpus.add_report(tmp_path, r_old, json.dumps(r_old))
    _strip_hash(tmp_path, "s-old")  # 模拟存量记录：没有入库哈希

    res = corpus.verify_reports(tmp_path)
    assert res["counts"] == {"ok": 1, "mismatch": 1, "unverifiable": 1, "missing": 0, "orphan": 0}
    by_sha = {row["sample_sha256"]: row for row in res["entries"]}
    assert by_sha["s-ok"]["status"] == "ok"
    assert by_sha["s-bad"]["status"] == "mismatch"
    # mismatch 行给出两侧哈希，够人去 .snapshots/ 与备份定位
    assert by_sha["s-bad"]["recorded_sha256"] == _sha256(json.dumps(r_bad).encode("utf-8"))
    assert by_sha["s-bad"]["actual_sha256"] == _sha256(bad_file.read_bytes())
    # ★没法验 ≠ 验过没问题：存量记录必须是 unverifiable，绝不能折进 ok
    assert by_sha["s-old"]["status"] == "unverifiable"
    assert by_sha["s-old"]["origin"] is None


def test_verify_missing_and_orphan(tmp_path: Path) -> None:
    """missing（有记录无文件）与 orphan（有文件无记录）都要报出来。"""
    r1 = _add(tmp_path, _report(sha="s-gone"))
    (tmp_path / r1["report_path"]).unlink()
    stray = tmp_path / corpus.REPORTS_DIR / "stray" / "x.report.json"
    stray.parent.mkdir(parents=True)
    stray.write_text("{}", encoding="utf-8")

    res = corpus.verify_reports(tmp_path)
    assert res["counts"] == {"ok": 0, "mismatch": 0, "unverifiable": 0, "missing": 1, "orphan": 1}
    assert res["orphans"] == ["reports/stray/x.report.json"]


def test_verify_path_traversal_counted_missing_not_read(tmp_path: Path) -> None:
    """manifest 的 report_path 越出库根 → 归 missing、绝不出库读文件、不抛。"""
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    cd = tmp_path / "corpus"
    cd.mkdir()
    _write_manifest_fixture(cd, [{
        "sample_sha256": "evil", "tool_version": "t", "ruleset_digest": "d",
        "report_path": "../outside.txt",
        "report_bytes_sha256": _sha256(b"secret"),  # 哪怕哈希"能对上"也不许出库比对
        "report_bytes_sha256_origin": "ingest",
    }])
    with pytest.raises(corpus.ManifestCorruptError):
        corpus.verify_reports(cd)


def test_backfill_marks_backfill_origin_and_never_overwrites(tmp_path: Path) -> None:
    """补录打 origin=backfill、与入库哈希在输出里长得不一样；已有哈希绝不重算覆盖；幂等。

    ★变异验证：把 backfill_report_hashes 里的 HASH_ORIGIN_BACKFILL 换成 HASH_ORIGIN_INGEST，
    本测试必红——那正是"给来历不明的哈希发合格证"的形态。
    """
    r_new = _report(sha="s-ingest")
    corpus.add_report(tmp_path, r_new, json.dumps(r_new))
    r_old = _report(sha="s-legacy")
    corpus.add_report(tmp_path, r_old, json.dumps(r_old))
    _strip_hash(tmp_path, "s-legacy")

    result = corpus.backfill_report_hashes(tmp_path)
    assert result["backfilled"] == 1 and result["already_hashed"] == 1
    assert result["written"] is True and result["error"] is None

    by_sha = {e["sample_sha256"]: e for e in corpus.load_manifest(tmp_path)}
    assert by_sha["s-legacy"]["report_bytes_sha256"] == _sha256(json.dumps(r_old).encode("utf-8"))
    assert by_sha["s-legacy"]["report_bytes_sha256_origin"] == corpus.HASH_ORIGIN_BACKFILL
    # 入库哈希原样未动（补录绝不碰已有基准）
    assert by_sha["s-ingest"]["report_bytes_sha256_origin"] == corpus.HASH_ORIGIN_INGEST

    # verify 的 ok 按来源分开呈现：一条 ingest、一条 backfill，不混同
    v = corpus.verify_reports(tmp_path)
    assert v["counts"]["ok"] == 2 and v["counts"]["unverifiable"] == 0
    assert v["ok_by_origin"] == {"ingest": 1, "backfill": 1}

    # 幂等：再补一次无事发生
    again = corpus.backfill_report_hashes(tmp_path)
    assert again["backfilled"] == 0 and again["already_hashed"] == 2 and again["written"] is False


def test_backfill_cannot_retroactively_certify_pre_backfill_tampering(tmp_path: Path) -> None:
    """★证据边界的如实呈现：补录**前**已被篡改的文件，补录后 verify 恒 ok——机制本身证明不了
    补录之前的历史，唯一诚实的做法是 origin=backfill 标记让读的人知道这份 ok 只覆盖补录之后。
    本测试同时锁住"边界存在"这个事实与"标记在场"这个补救。"""
    r = _report(sha="s-pre-tamper")
    res = corpus.add_report(tmp_path, r, json.dumps(r))
    _strip_hash(tmp_path, "s-pre-tamper")  # 存量：无哈希
    tampered = json.dumps(r) + "  "
    (tmp_path / res["report_path"]).write_text(tampered, encoding="utf-8")  # 补录前被篡改

    corpus.backfill_report_hashes(tmp_path)
    v = corpus.verify_reports(tmp_path)
    # 篡改被钉成基准：ok 而非 mismatch——这正是补录证明不了的部分
    assert v["counts"]["ok"] == 1 and v["counts"]["mismatch"] == 0
    [row] = v["entries"]
    assert row["origin"] == corpus.HASH_ORIGIN_BACKFILL, "没有 backfill 标记，这份 ok 就成了伪证"


def test_backfill_skips_unreadable_and_snapshots_before_write(tmp_path: Path) -> None:
    """文件取不到的记录补不了、逐条报出；补录写 manifest 条数不变（缩减护栏放行）且写前拍快照。"""
    r1 = _report(sha="s-a")
    corpus.add_report(tmp_path, r1, json.dumps(r1))
    r2 = _report(sha="s-b")
    res2 = corpus.add_report(tmp_path, r2, json.dumps(r2))
    _strip_hash(tmp_path, "s-a")
    _strip_hash(tmp_path, "s-b")
    (tmp_path / res2["report_path"]).unlink()  # s-b 的文件没了 → 补不了

    before_bytes = corpus.manifest_path(tmp_path).read_bytes()
    snaps_before = len(corpus.list_snapshots(tmp_path))
    result = corpus.backfill_report_hashes(tmp_path)
    assert result["backfilled"] == 1
    assert result["unreadable"] == [{"sample_sha256": "s-b", "report_path": res2["report_path"]}]
    assert len(corpus.load_manifest(tmp_path)) == 2  # 条数不变
    snaps = corpus.list_snapshots(tmp_path)
    assert len(snaps) == snaps_before + 1  # 写前快照触发
    assert snaps[0].read_bytes() == before_bytes  # 快照 = 补录前的状态，可回滚


def test_reindex_carries_hash_and_does_not_launder_tampering(tmp_path: Path) -> None:
    """reindex 拒绝已篡改的同主键报告，绝不刷新派生索引或重算哈希。

    只照抄旧哈希仍不够：若继续解析篡改报告，key_iocs/domains 等派生索引会被污染。
    """
    r = _report(sha="s-1")
    raw = json.dumps(r)
    res = corpus.add_report(tmp_path, r, raw, case_id="c1")
    # 篡改文件：内容仍解析出同一主键（只加尾随空白），reindex 才能按主键对上旧记录
    (tmp_path / res["report_path"]).write_text(raw + "   ", encoding="utf-8")
    manifest_before = corpus.manifest_path(tmp_path).read_bytes()

    with pytest.raises(corpus.ManifestCorruptError, match="入库哈希"):
        corpus.reindex(tmp_path)

    assert corpus.manifest_path(tmp_path).read_bytes() == manifest_before
    v = corpus.verify_reports(tmp_path)
    assert v["counts"]["mismatch"] == 1, "被拒后篡改仍必须可检出"


def test_reindex_rejects_changed_key_even_with_allow_shrink(tmp_path: Path) -> None:
    report = _report(sha="original-key")
    result = _add(tmp_path, report, case_id="case-a")
    manifest_before = corpus.manifest_path(tmp_path).read_bytes()
    path = tmp_path / str(result["report_path"])
    changed = json.loads(path.read_text(encoding="utf-8"))
    changed["meta"]["sample_sha256"] = "forged-new-key"
    path.write_text(json.dumps(changed), encoding="utf-8")

    with pytest.raises(corpus.ManifestCorruptError, match="入库哈希"):
        corpus.reindex(tmp_path, allow_shrink=True)

    assert corpus.manifest_path(tmp_path).read_bytes() == manifest_before


@pytest.mark.skipif(os.name != "nt", reason="Windows backslash manifest compatibility")
def test_reindex_hash_gate_normalizes_legacy_backslash_report_path(
    tmp_path: Path,
) -> None:
    report = _report(sha="legacy-windows-path")
    result = _add(tmp_path, report, case_id="case-a")
    [entry] = corpus.load_manifest(tmp_path)
    entry["report_path"] = str(entry["report_path"]).replace("/", "\\")
    _write_manifest_fixture(tmp_path, [entry])
    manifest_before = corpus.manifest_path(tmp_path).read_bytes()
    path = tmp_path / str(result["report_path"])
    changed = json.loads(path.read_text(encoding="utf-8"))
    changed["meta"]["sample_sha256"] = "forged-new-key"
    path.write_text(json.dumps(changed), encoding="utf-8")

    with pytest.raises(corpus.ManifestCorruptError, match="入库哈希"):
        corpus.reindex(tmp_path, allow_shrink=True)

    assert corpus.manifest_path(tmp_path).read_bytes() == manifest_before


def test_add_report_refuses_parent_symlink_escape_without_external_write(
    tmp_path: Path,
) -> None:
    root = tmp_path / "corpus"
    outside = tmp_path / "outside"
    outside.mkdir()
    report = _report(sha="symlink-escape")
    rel = Path(corpus.report_relpath(report))
    link = root / rel.parent
    link.parent.mkdir(parents=True)
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")

    result = _add(root, report, case_id="case-a")

    assert result["content_conflict"] is True
    assert result["conflict_reason"] == "target_report_path_outside_corpus"
    assert list(outside.iterdir()) == []
    assert not corpus.manifest_path(root).exists()
    assert not (root / "catalog.jsonl").exists()


def test_reindex_rejects_report_file_symlink_escape_without_manifest_change(
    tmp_path: Path,
) -> None:
    root = tmp_path / "corpus"
    _add(root, _report(sha="safe"), case_id="case-a")
    before = corpus.manifest_path(root).read_bytes()
    outside = tmp_path / "outside.report.json"
    outside.write_text(json.dumps(_report(sha="outside")), encoding="utf-8")
    link = root / "reports" / "linked" / "outside.report.json"
    link.parent.mkdir(parents=True)
    try:
        link.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"file symlink unavailable: {exc}")

    with pytest.raises(corpus.ManifestCorruptError, match="越出 corpus"):
        corpus.reindex(root)

    assert corpus.manifest_path(root).read_bytes() == before


def test_reindex_does_not_invent_hashes_for_legacy_rows(tmp_path: Path) -> None:
    """旧记录没哈希 → reindex 后也没有（补录是 backfill-hash 的显式职责，reindex 不发明基准）。"""
    r = _report(sha="s-legacy")
    corpus.add_report(tmp_path, r, json.dumps(r))
    _strip_hash(tmp_path, "s-legacy")
    [e] = corpus.reindex(tmp_path)
    assert "report_bytes_sha256" not in e
    assert corpus.verify_reports(tmp_path)["counts"]["unverifiable"] == 1


def test_cli_verify_exit_codes_and_prominent_hints(tmp_path: Path) -> None:
    """CLI 三种局面：全 ok → 0；仅 unverifiable → 0 但 stderr 醒目提示；mismatch → 1。

    ★变异验证：把 corpus_verify 末尾的 raise typer.Exit(1) 删掉，本测试必红（mismatch 段）。
    """
    corpus_dir = tmp_path / "corpus"
    runner = CliRunner()
    r = _report(sha="s-1")
    res_add = corpus.add_report(corpus_dir, r, json.dumps(r))

    ok = runner.invoke(cli.app, ["corpus", "verify", "--corpus", str(corpus_dir)])
    assert ok.exit_code == 0
    payload = json.loads(ok.stdout)
    assert payload["counts"]["ok"] == 1 and payload["ok_by_origin"] == {"ingest": 1}

    # 仅 unverifiable：退出码 0，但 stderr 必须把"还有多少条没法验"说出来
    _strip_hash(corpus_dir, "s-1")
    unver = runner.invoke(cli.app, ["corpus", "verify", "--corpus", str(corpus_dir)])
    assert unver.exit_code == 0
    assert json.loads(unver.stdout)["counts"]["unverifiable"] == 1
    assert "没法验" in unver.stderr and "backfill-hash" in unver.stderr

    # mismatch：补录回哈希后篡改文件 → 非零退出
    runner.invoke(cli.app, ["corpus", "backfill-hash", "--apply", "--corpus", str(corpus_dir)])
    (corpus_dir / res_add["report_path"]).write_text(json.dumps(r) + " ", encoding="utf-8")
    bad = runner.invoke(cli.app, ["corpus", "verify", "--corpus", str(corpus_dir)])
    assert bad.exit_code == 1
    assert json.loads(bad.stdout)["counts"]["mismatch"] == 1
    assert "改过" in bad.stderr


def test_cli_verify_missing_exits_1(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "corpus"
    r = _add(corpus_dir, _report(sha="s-1"))
    (corpus_dir / r["report_path"]).unlink()
    res = CliRunner().invoke(cli.app, ["corpus", "verify", "--corpus", str(corpus_dir)])
    assert res.exit_code == 1
    assert json.loads(res.stdout)["counts"]["missing"] == 1


def test_cli_backfill_dry_run_default_then_apply(tmp_path: Path) -> None:
    """backfill-hash 默认 dry-run（不动磁盘）、--apply 才写；两种输出都写明证据边界。

    ★变异验证：把 corpus_backfill_hash 的 dry-run 分支删掉（不带 --apply 也真写），本测试必红。
    """
    corpus_dir = tmp_path / "corpus"
    runner = CliRunner()
    r = _report(sha="s-1")
    corpus.add_report(corpus_dir, r, json.dumps(r))
    _strip_hash(corpus_dir, "s-1")

    dry = runner.invoke(cli.app, ["corpus", "backfill-hash", "--corpus", str(corpus_dir)])
    assert dry.exit_code == 0
    dry_payload = json.loads(dry.stdout)
    assert dry_payload["dry_run"] is True and dry_payload["would_backfill"] == 1
    assert "不能追溯" in dry_payload["evidence_boundary"]
    [e] = corpus.load_manifest(corpus_dir)
    assert "report_bytes_sha256" not in e  # dry-run 没动磁盘

    ap = runner.invoke(cli.app, ["corpus", "backfill-hash", "--apply", "--corpus", str(corpus_dir)])
    assert ap.exit_code == 0
    ap_payload = json.loads(ap.stdout)
    assert ap_payload["backfilled"] == 1
    assert "不能追溯" in ap_payload["evidence_boundary"]
    [e] = corpus.load_manifest(corpus_dir)
    assert e["report_bytes_sha256_origin"] == corpus.HASH_ORIGIN_BACKFILL
