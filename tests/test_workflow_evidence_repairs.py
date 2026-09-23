from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

from typer.testing import CliRunner

from apkscan.cli import app
from apkscan.core.batch_enrich import Target
from apkscan.core.closure.layers import _hosting_layer, _request_layer
from apkscan.core.enrichment_coverage import build_coverage
from apkscan.core.response_evidence import capture_responses
from apkscan.enrichers._http import _cap_body


def test_network_label_and_banner_do_not_establish_hosting() -> None:
    rows = [["https://api.example.test", "100.64.0.1", 443, "https", "Welcome", "nginx", "", "", "", 64500, "Network A"]]
    e = {"fofa": {"records": rows}, "source_status": {"fofa": {"status": "hit"}}}
    hosting = _hosting_layer(e)
    assert hosting["status"] == "partial"
    assert _request_layer(hosting, {"required": False})["status"] == "partial"
    rows.append([*rows[0][:-1], "Network B"])
    first = _hosting_layer(e)
    rows.reverse()
    second = _hosting_layer(e)
    assert first["status"] == second["status"] == "partial"
    assert first["evidence"].get("provider") == second["evidence"].get("provider")


def test_full_denominator_includes_disabled_deferred_and_not_applicable() -> None:
    targets = [Target("a.example", "domain"), Target("100.64.0.1", "ip")]
    providers = [SimpleNamespace(name="fofa", applies_to=["domain", "ip"], required_env=("UNUSED",)),
                 SimpleNamespace(name="basic", applies_to=["ip"], required_env=())]
    r = build_coverage(targets, providers, [], {}, case_id="fixture")
    assert r["target_count"] == 2
    assert r["targets"][0]["source_status"]["fofa"]["status"] == "disabled"
    assert r["targets"][0]["source_status"]["basic"]["reason"] == "not_applicable"
    assert r["targets"][1]["source_status"]["basic"]["status"] == "skipped"
    assert r["unresolved_cells"] == 3 and not r["coverage_complete"]


def test_disabled_batch_emits_case_bound_coverage_without_network(tmp_path, monkeypatch) -> None:
    from apkscan.core import registry
    monkeypatch.setattr(registry, "discover_enrichers", lambda: [SimpleNamespace(
        name="fofa", active=False, applies_to=["domain"], required_env=("UNUSED",))])
    monkeypatch.delenv("UNUSED", raising=False)
    targets = tmp_path / "targets.txt"
    targets.write_text("a.example\nb.example\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["enrich", "batch", "--targets", str(targets), "--out", str(tmp_path / "out"),
                                    "--no-dry-run", "--case-id", "fixture", "--providers", "fofa"])
    assert result.exit_code == 0, result.output
    summary = json.loads(result.stdout)
    from pathlib import Path
    coverage = json.loads(Path(summary["coverage"]).read_text(encoding="utf-8"))
    assert coverage["case_id"] == "fixture" and len(coverage["targets"]) == 2
    assert summary["completed_with_gaps"]
    assert all(r["source_status"]["fofa"]["status"] == "disabled" for r in coverage["targets"])
    mismatch = CliRunner().invoke(app, ["enrich", "batch", "--targets", str(targets), "--out", str(tmp_path / "out"),
        "--no-dry-run", "--case-id", "another-case", "--providers", "fofa"])
    assert mismatch.exit_code == 2 and "身份不符" in mismatch.output
    assert len(list((tmp_path / "out").glob("coverage-*.json"))) == 1
    (tmp_path / "out" / "enrich.ndjson").write_text("not-json\n", encoding="utf-8")
    corrupt = CliRunner().invoke(app, ["enrich", "batch", "--targets", str(targets), "--out", str(tmp_path / "out"),
        "--no-dry-run", "--case-id", "fixture", "--providers", "fofa"])
    assert corrupt.exit_code == 0, corrupt.output
    corrupt_summary = json.loads(corrupt.stdout)
    corrupt_coverage = json.loads(Path(corrupt_summary["coverage"]).read_text(encoding="utf-8"))
    assert corrupt_coverage["ledger_bad_lines"] == 1
    assert not corrupt_coverage["ledger_complete"] and not corrupt_coverage["coverage_complete"]


def test_hit_with_truncated_payload_is_not_complete_coverage() -> None:
    providers = [SimpleNamespace(name="synthetic", applies_to=["ip"], required_env=())]
    records = [{"target": "100.64.0.1", "source_status": {"synthetic": {"status": "hit"}},
                "enrichment": {"synthetic": {"records_truncated": True}}}]
    coverage = build_coverage([Target("100.64.0.1", "ip")], providers, records, {}, case_id="fixture")
    assert coverage["source_outcomes"] == {"hit": 1}
    assert not coverage["coverage_complete"] and coverage["unresolved_cells"] == 1


def test_retained_entity_is_exact_and_request_secrets_are_not_in_metadata(tmp_path) -> None:
    body = b'{"result": [1, 2]}'
    response = SimpleNamespace(url="https://user:password@api.example/private-key?key=secret", status_code=403,
                               iter_content=lambda _: iter([body]), close=lambda: None)
    # requests.Response exposes content from _content after bounded consumption.
    class FakeResponse:
        url = response.url
        status_code = response.status_code
        iter_content = staticmethod(response.iter_content)
        close = staticmethod(response.close)
        @property
        def content(self):
            return self._content
    with capture_responses(tmp_path / "raw-responses") as records:
        _cap_body(FakeResponse(), 1000)
    assert len(records) == 1
    record = records[0]
    assert (tmp_path / record["relpath"]).read_bytes() == body
    assert record["sha256"] == hashlib.sha256(body).hexdigest()
    assert record["source_origin"] == "https://api.example"
    assert not any(x in json.dumps(record) for x in ("password", "secret", "private-key"))


def test_raw_write_failure_is_visible_and_does_not_fake_retention(tmp_path) -> None:
    from apkscan.core.response_evidence import retain_response
    invalid = tmp_path / "file"
    invalid.write_text("exists")
    with capture_responses(invalid) as records:
        retain_response(SimpleNamespace(content=b"{}", status_code=200, url="https://api.example"))
    assert records[0]["status"] == "failed" and "relpath" not in records[0]


def test_esa_product_is_separate_from_carrier_and_headers_do_not_confirm_origin() -> None:
    from apkscan.core.attribution import build_ip_attribution, build_endpoint_attribution, score_edge_provider
    headers = {"Server": "ESA", "EagleId": "synthetic-request-id", "Via": "ens-cache1.example[1,0]"}
    edge = score_edge_provider({"response_headers": headers})
    assert edge and edge["name"] == "阿里云 ESA" and edge["tier"] == "probable"
    single = score_edge_provider({"response_headers": {"Server": "ESA"}})
    assert single and single["tier"] == "possible"
    view = build_ip_attribution("100.64.0.1", {"asn": {"asn": 64500, "org": "China Telecom"},
        "response_headers": headers})
    assert view["origin_network"]["organization"] == "China Telecom"
    assert view["edge_provider"]["name"] == "阿里云 ESA"
    assert view["hosting_provider"]["name"] is None and view["service_operator"]["name"] is None
    enrichment = {"response_headers": headers, "source_status": {"response_headers": {"status": "hit"}}}
    endpoint_view = build_endpoint_attribution("ip", "100.64.0.1", enrichment)
    assert endpoint_view and endpoint_view["ips"][0]["edge_provider"]["name"] == "阿里云 ESA"
    enrichment["source_status"]["response_headers"]["status"] = "failed"
    assert build_endpoint_attribution("ip", "100.64.0.1", enrichment) is None


def test_resume_verifies_retained_response_bytes(tmp_path, monkeypatch):
    from pathlib import Path
    from apkscan.core import registry
    from apkscan.core.models import EnrichmentResult
    from apkscan.core.response_evidence import retain_response
    calls = []
    class Provider:
        name = "synthetic"
        active = False
        applies_to = ["domain"]
        required_env = ()
        def enrich(self, endpoint):
            calls.append(endpoint.value)
            retain_response(SimpleNamespace(content=b"fixture", status_code=200, url="https://api.example"))
            return EnrichmentResult(provider=self.name, ok=True, data={"record": "fixture"})
    monkeypatch.setattr(registry, "discover_enrichers", lambda: [Provider()])
    targets = tmp_path / "targets.txt"
    targets.write_text("a.example\n", encoding="utf-8")
    out = tmp_path / "out"
    args = ["enrich", "batch", "--targets", str(targets), "--out", str(out),
            "--no-dry-run", "--case-id", "fixture", "--providers", "synthetic", "--retain-responses"]
    first = CliRunner().invoke(app, args)
    assert first.exit_code == 0, first.output
    assert json.loads(first.stdout)["response_archive_complete"] is True
    artifact = next((out / "raw-responses").glob("*.body"))
    artifact.write_bytes(b"corrupt")
    second = CliRunner().invoke(app, args)
    assert second.exit_code == 0, second.output
    summary = json.loads(second.stdout)
    assert summary["response_archive_complete"] is False
    assert summary["completed_with_gaps"] is True
    coverage = json.loads(Path(summary["coverage"]).read_text(encoding="utf-8"))
    state = coverage["targets"][0]["source_status"]["synthetic"]
    assert state["raw_response_evidence"]["status"] == "invalid"
    assert calls == ["a.example"]
