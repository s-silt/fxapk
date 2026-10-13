"""E4：失败、无记录和预算跳过必须留下旧观察，且旧观察不再是当前 hit。"""

from __future__ import annotations

import copy

import pytest

from apkscan.core.enrichment import enrich_selected_targets
from apkscan.core.enrichment_budget import EnrichmentBudget
from apkscan.core.models import Endpoint, EnrichmentResult, Report
from apkscan.core.report_io import load_report
from apkscan.core.source_status import canonicalize_report_source_status, provider_payload_if_hit
from apkscan.report.json import dump


class _Synthetic:
    name = "fofa"
    applies_to = ["domain"]
    configured = True
    active = False
    case_close_only = False

    def __init__(self) -> None:
        self.payload: dict = {}
        self.calls = 0
        self.raise_on_call = False

    def enrich(self, endpoint: Endpoint) -> EnrichmentResult:
        self.calls += 1
        if self.raise_on_call:
            raise RuntimeError("synthetic provider failure")
        payload = copy.deepcopy(self.payload)
        failed = payload.get("_source_status") == "failed"
        return EnrichmentResult(
            self.name, not failed, payload, "synthetic_failure" if failed else None,
        )


def _payload(token: str, status: str) -> dict:
    if status != "hit":
        return {"_source_status": status, "source": "synthetic-fofa"}
    return {
        "observation_token": token,
        "source": "synthetic-fofa",
        "_source_status": status,
        "source_identity": {"provider": "fofa", "capture_id": token},
        "org": "SYNTHETIC-" + token,
    }


def _history_payloads(endpoint: Endpoint) -> list[dict]:
    raw = endpoint.enrichment.get("enrichment_history")
    if not isinstance(raw, list):
        return []
    found: list[dict] = []
    for item in raw:
        if isinstance(item, dict) and isinstance(item.get("payload"), dict):
            found.append(item)
    return found


def _roundtrip(endpoint: Endpoint, path) -> Endpoint:
    report = Report(
        package_name="example.invalid",
        meta={"sample_sha256": "ab" * 32, "closure": {"status": "partial", "gaps": ["keep"]}},
        endpoints=[endpoint],
        leads=[],
        findings=[],
        analyzer_status=[],
    )
    dump(report, path)
    loaded = load_report(path)
    canonicalize_report_source_status(loaded)
    return loaded.endpoints[0]


def test_repeat_failure_archives_once_and_unknown_time_is_not_invented(tmp_path) -> None:
    endpoint = Endpoint(value="endpoint.example.invalid", kind="domain")
    endpoint.enrichment["raw_response_evidence"] = {
        "fofa": {"artifacts": [{"sha256": "ab" * 32, "status": "retained"}]},
    }
    provider = _Synthetic()
    provider.payload = _payload("A", "hit")
    enrich_selected_targets([endpoint], [provider], include_case_close=True)
    provider.payload = _payload("A", "failed")
    enrich_selected_targets([endpoint], [provider], include_case_close=True)
    provider.payload = _payload("A", "failed")
    enrich_selected_targets([endpoint], [provider], include_case_close=True)
    endpoint.enrichment["raw_response_evidence"] = {
        "fofa": {"artifacts": [{"sha256": "cd" * 32, "status": "retained"}]},
    }
    endpoint = _roundtrip(endpoint, tmp_path / "repeat.json")

    archived = _history_payloads(endpoint)
    tokens = [item["payload"].get("observation_token") for item in archived]
    assert tokens == ["A"]
    assert archived[0]["observed_at"] == "unknown"
    assert archived[0]["source_outcome"]["status"] == "hit"
    assert archived[0]["raw_response_evidence"]["artifacts"][0]["sha256"] == "ab" * 32
    assert "fofa" not in endpoint.enrichment
    assert endpoint.enrichment["source_status"]["fofa"]["status"] == "failed"
    assert provider_payload_if_hit(endpoint.enrichment, "fofa") == {}


def test_hit_failure_hit_then_second_failure_keeps_both_generations(tmp_path) -> None:
    endpoint = Endpoint(value="endpoint.example.invalid", kind="domain")
    provider = _Synthetic()
    for token, status in (("A", "hit"), ("A", "failed"), ("B", "hit")):
        provider.payload = _payload(token, status)
        enrich_selected_targets([endpoint], [provider], include_case_close=True)
    endpoint = _roundtrip(endpoint, tmp_path / "fresh.json")
    assert provider_payload_if_hit(endpoint.enrichment, "fofa")["observation_token"] == "B"
    assert [item["payload"].get("observation_token") for item in _history_payloads(endpoint)] == ["A"]

    provider.payload = _payload("B", "failed")
    enrich_selected_targets([endpoint], [provider], include_case_close=True)
    endpoint = _roundtrip(endpoint, tmp_path / "fresh-failed.json")
    assert [item["payload"].get("observation_token") for item in _history_payloads(endpoint)] == ["A", "B"]
    assert provider_payload_if_hit(endpoint.enrichment, "fofa") == {}
    assert endpoint.enrichment.get("fofa") is None


def test_no_record_budget_and_exception_do_not_keep_stale_hit(tmp_path) -> None:
    endpoint = Endpoint(value="endpoint.example.invalid", kind="domain")
    provider = _Synthetic()
    provider.payload = _payload("A", "hit")
    enrich_selected_targets([endpoint], [provider], include_case_close=True)
    provider.payload = _payload("A", "no_record")
    enrich_selected_targets([endpoint], [provider], include_case_close=True)
    endpoint = _roundtrip(endpoint, tmp_path / "norecord.json")
    assert endpoint.enrichment["source_status"]["fofa"]["status"] == "no_record"
    assert provider_payload_if_hit(endpoint.enrichment, "fofa") == {}
    assert [item["payload"].get("observation_token") for item in _history_payloads(endpoint)] == ["A"]

    budget_endpoint = Endpoint(value="budget.example.invalid", kind="domain")
    budget_provider = _Synthetic()
    budget_provider.payload = _payload("A", "hit")
    enrich_selected_targets([budget_endpoint], [budget_provider], include_case_close=True)
    calls = budget_provider.calls
    enrich_selected_targets(
        [budget_endpoint], [budget_provider], include_case_close=True, budget=EnrichmentBudget(total=0),
    )
    assert budget_provider.calls == calls
    budget_endpoint = _roundtrip(budget_endpoint, tmp_path / "budget.json")
    assert budget_endpoint.enrichment["source_status"]["fofa"]["status"] == "skipped"
    assert provider_payload_if_hit(budget_endpoint.enrichment, "fofa") == {}
    assert [item["payload"].get("observation_token") for item in _history_payloads(budget_endpoint)] == ["A"]

    broken_endpoint = Endpoint(value="broken.example.invalid", kind="domain")
    broken = _Synthetic()
    broken.payload = _payload("A", "hit")
    enrich_selected_targets([broken_endpoint], [broken], include_case_close=True)
    broken.raise_on_call = True
    enrich_selected_targets([broken_endpoint], [broken], include_case_close=True)
    broken_endpoint = _roundtrip(broken_endpoint, tmp_path / "broken.json")
    assert broken_endpoint.enrichment["source_status"]["fofa"]["status"] == "failed"
    assert provider_payload_if_hit(broken_endpoint.enrichment, "fofa") == {}
    assert [item["payload"].get("observation_token") for item in _history_payloads(broken_endpoint)] == ["A"]


@pytest.mark.parametrize("status", ["skipped", "disabled"])
def test_non_hit_result_retires_previous_payload(tmp_path, status: str) -> None:
    endpoint = Endpoint(value="endpoint.example.invalid", kind="domain")
    provider = _Synthetic()
    provider.payload = _payload("A", "hit")
    enrich_selected_targets([endpoint], [provider], include_case_close=True)
    provider.payload = _payload("A", status)
    enrich_selected_targets([endpoint], [provider], include_case_close=True)
    endpoint = _roundtrip(endpoint, tmp_path / f"{status}.json")
    assert endpoint.enrichment["source_status"]["fofa"]["status"] == status
    assert provider_payload_if_hit(endpoint.enrichment, "fofa") == {}
    assert [item["payload"].get("observation_token") for item in _history_payloads(endpoint)] == ["A"]
