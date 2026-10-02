"""Exercise real offline stages with synthetic evidence and fake provider I/O."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from apkscan.analyzers.endpoints import EndpointsAnalyzer
from apkscan.core.case_package import create_case_package
from apkscan.core.enrichment import _run_enrichment
from apkscan.core.models import (
    AnalysisConfig, Confidence, Endpoint, EnrichmentResult, Evidence, EvidenceScope,
    Lead, LeadCategory, Report,
)
from apkscan.core.phase2.inventory import build_coverage_skeleton, build_inventory
from apkscan.core.phase2.preparation import prepare_case_materials
from apkscan.core.registry import BaseEnricher
from apkscan.core.report_io import write_report
from apkscan.core.webctx import load_web_evidence
from apkscan.dynamic.merge import merge_runtime_endpoints


class SyntheticSource(BaseEnricher):
    applies_to = ["domain", "ip"]
    phase = "attribution"
    active = False

    def __init__(self, name: str, fail: bool = False):
        self.name, self.fail = name, fail

    def enrich(self, endpoint: Endpoint) -> EnrichmentResult:
        if self.fail:
            return EnrichmentResult(provider=self.name, ok=False, data={})
        return EnrichmentResult(provider=self.name, ok=True, data={
            "org": "Synthetic Holder", "netname": "SYNTHETIC-NET", "country": "ZZ",
            "cidr": "192.0.2.0/24", "handle": "SYNTHETIC",
        })


def make_chain_case(root: Path, *, samples: int = 2, targets: int = 3) -> Path:
    case = root / "case"
    for number in range(samples):
        package = case / f"sample-{number:03d}"
        package.mkdir(parents=True)
        web = root / f"web-{number}"
        web.mkdir()
        hosts = [f"api-{i}.example.test" for i in range(targets)]
        (web / "page.body").write_text(
            "<html>" + "".join(f'<a href="https://{host}/v1">synthetic</a>' for host in hosts) + "</html>")
        context = load_web_evidence(web, AnalysisConfig(online=False))
        web_result = EndpointsAnalyzer().analyze(context)  # type: ignore[arg-type]
        assert not web_result.error
        web_domains = [ep for ep in web_result.endpoints if ep.kind == "domain"]
        assert {ep.value for ep in web_domains} >= set(hosts)
        # Keep original web coordinates; record web stage explicitly when
        # assembling these material types into a mixed Android report.
        for ep in web_domains:
            for evidence in ep.evidences:
                evidence.source = "web"
        static = [Endpoint(kind="domain", value=host, evidences=[
            Evidence(source="dex", location="synthetic/Config", scope=EvidenceScope.CASE_EVIDENCE)])
                  for host in hosts]
        report = Report(package_name="com.example.synthetic", leads=[], endpoints=static,
                        findings=[], analyzer_status=[], meta={
                            "sample_sha256": hashlib.sha256(f"sample-{number}".encode()).hexdigest(),
                            "tool_version": "1.15.0", "ruleset_digest": "b" * 16,
                            "build_provenance": {"status": "synthetic"},
                            "capture_quality": {"target_attributed_count": targets,
                                                "business_candidate_count": targets,
                                                "bidirectional_target_count": targets},
                        })
        # Existing dedup path must retain static and runtime observations.
        runtime = [Endpoint(kind="domain", value=host, evidences=[
            Evidence(source="runtime", location="synthetic/flow", observed_at=1700000000.0)])
                   for host in hosts]
        merge_runtime_endpoints(report, runtime)
        from apkscan.core.pipeline import _dedup_endpoints
        report.endpoints = _dedup_endpoints(report.endpoints + web_domains)
        for ep in report.endpoints:
            report.leads.append(Lead(category=LeadCategory.DOMAIN, value=ep.value,
                                     confidence=Confidence.HIGH, advice="建议调证",
                                     source_refs=list(ep.evidences)))
        _run_enrichment(report.endpoints, [SyntheticSource("ip_rdap"), SyntheticSource("ripestat_bgp", fail=True)])
        write_report(report, package / "report.json", render_existing_html=False)
        create_case_package(package / "report.json", package / "case-package.json",
                            case_id="CASE-SYNTHETIC", producer="synthetic-chain")
    return case


def test_web_static_dynamic_enrichment_package_coverage_to_pre_report(tmp_path: Path):
    case = make_chain_case(tmp_path)
    inventory = build_inventory(case)
    assert not inventory.issues
    coverage = build_coverage_skeleton(inventory)
    before = {str(p): p.read_bytes() for p in case.rglob("*") if p.is_file()}
    result = prepare_case_materials(case, coverage=coverage, clue_records=[])
    assert result["state"] == "review_required"
    assert result["formal_report_generated"] is False
    assert result["family_review"]["kind"] == "linkage_review_groups"
    assert len(result["packages"]) == 2
    for package in result["packages"]:
        assert package["stage_observations"]["dynamic"]["status"] == "complete"
        plan = package["provider_review"]
        assert plan["selected_target_count"] == 3
        assert plan["evidence_linkage"]["unlinked_network_candidate_count"] == 0
        for target in plan["targets"]:
            evidence = target["phase1_evidence"]
            stages = {s for ref in evidence["candidate_refs"] for s in ref["stages"]}
            assert stages == {"static", "dynamic", "web"}
            assert evidence["scope_counts"]["case_evidence"] == 6
            assert evidence["provider_identity_verified"] is False
            actions = [a for role in target["roles"] for a in role["next_actions"]]
            assert any(a.get("provider") == "ripestat_bgp" and a["status"] == "failed" for a in actions)
    assert before == {str(p): p.read_bytes() for p in case.rglob("*") if p.is_file()}
    assert "api-0.example.test" not in json.dumps(result)
    assert not list(case.rglob("*.html")) and not list(case.rglob("*.pdf"))


def test_target_cap_keeps_unlinked_material_visible(tmp_path: Path):
    case = make_chain_case(tmp_path, samples=1, targets=5)
    result = prepare_case_materials(case, max_targets=2)
    plan = result["packages"][0]["provider_review"]
    assert plan["truncated"] is True
    assert plan["selected_target_count"] == 2
    assert plan["evidence_linkage"]["unlinked_network_candidate_count"] > 0


def test_query_budget_is_case_wide_not_reset_per_package(tmp_path: Path):
    case = make_chain_case(tmp_path, samples=3, targets=4)
    result = prepare_case_materials(case)
    work = result["source_worklist"]
    assert work["proposed_query_count"] == work["query_budget"] == 32
    assert work["deferred_query_count"] > 0
    assert all("source_worklist" not in p["provider_review"] for p in result["packages"])
    assert all(row["target_ref"].startswith("package-") for row in work["items"])
