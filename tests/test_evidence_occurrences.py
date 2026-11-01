from __future__ import annotations

import hashlib
import json

import pytest

from apkscan.analyzers._common import EndpointCollector
from apkscan.analyzers.endpoints import EndpointsAnalyzer
from apkscan.analyzers.js_bundle import JsBundleAnalyzer
from apkscan.core.context import iter_dex_records
from apkscan.core.integrity import evidence_id
from apkscan.core.models import Endpoint, Evidence, Lead, LeadCategory, Report
from apkscan.core.observations import DexStringRecord, occurrence_id
from apkscan.core.report_io import report_from_dict
from apkscan.core.snapshot import SnapshotContext, build_snapshot
from apkscan.core.stage_preservation import merge_carried_evidence
from apkscan.core.web_supplement_report import _evidence_list
from apkscan.report.json import to_dict
from tests.conftest import FakeContext


def _evidence(offset: int, *, source: str = "dex", suspicion: str = "unknown") -> Evidence:
    return Evidence(
        source=source,
        location="classes.dex",
        snippet="https://backend.example",
        provenance={"extractor": "test-v1", "member_path": "classes.dex"},
        locator={"char_offset": offset, "offset_unit": "unicode-codepoint"},
        suspicions=[{"kind": suspicion}],
    )


def test_same_value_different_offsets_survive_endpoint_collection() -> None:
    collector = EndpointCollector()
    collector.add("backend.example", "domain", _evidence(1))
    collector.add("backend.example", "domain", _evidence(42))
    assert len(collector.by_value["backend.example"].evidences) == 2


def test_real_and_suspicious_facts_survive_in_either_insertion_order() -> None:
    real = _evidence(1, source="dex", suspicion="none")
    real.structure_status = "verified"
    real.reachability = "reachable"
    suspicious = _evidence(1, source="resource", suspicion="comment_only")
    suspicious.structure_status = "unknown"
    suspicious.reachability = "unreachable"

    def collected(items: tuple[Evidence, Evidence]) -> dict[str, tuple[str, str, str]]:
        collector = EndpointCollector()
        for evidence in items:
            collector.add("backend.example", "domain", evidence)
        return {
            evidence.source: (
                evidence.structure_status,
                evidence.reachability,
                evidence.suspicions[0]["kind"],
            )
            for evidence in collector.by_value["backend.example"].evidences
        }

    expected = {
        "dex": ("verified", "reachable", "none"),
        "resource": ("unknown", "unreachable", "comment_only"),
    }
    assert collected((real, suspicious)) == expected
    assert collected((suspicious, real)) == expected


def test_occurrence_id_is_stable_and_legacy_id_is_unchanged() -> None:
    first = _evidence(3)
    second = _evidence(3)
    assert occurrence_id(first) == occurrence_id(second)
    payload = to_dict(Report("x", {}, [
        Lead(LeadCategory.DOMAIN, "backend.example", source_refs=[first])
    ], [], [], []))
    assert payload["leads"][0]["source_refs"][0]["evidence_id"] == evidence_id(first.source, first.location)
    assert payload["leads"][0]["source_refs"][0]["occurrence_id"] == occurrence_id(first)


@pytest.mark.parametrize("provenance,locator", [
    ([], {"byte_offset": 1}),
    ("classes.dex", {"byte_offset": 1}),
    ({"member_path": "classes.dex"}, []),
    ({"member_path": "classes.dex"}, "offset"),
    ({}, {"byte_offset": 1}),
    ({"member_path": "classes.dex"}, {}),
])
def test_occurrence_id_requires_nonempty_mapping_facts(provenance, locator):
    assert occurrence_id({
        "source": "dex",
        "location": "classes.dex",
        "provenance": provenance,
        "locator": locator,
    }) is None


def test_typed_fields_roundtrip_and_legacy_report_has_no_coordinates() -> None:
    raw = {
        "schema_version": "1.2", "package_name": "x", "meta": {},
        "leads": [{"category": "DOMAIN", "value": "backend.example",
                   "source_refs": [{"source": "dex", "location": "classes.dex",
                                    "scope": "case_evidence"}]}],
        "endpoints": [], "findings": [], "analyzer_status": [],
    }
    report = report_from_dict(raw)
    ev = report.leads[0].source_refs[0]
    assert ev.provenance == {} and ev.locator == {} and ev.reachability == "unknown"
    rich_raw = json.loads(json.dumps(raw))
    rich_raw["schema_version"] = "1.3"
    rich_raw["leads"][0]["source_refs"][0].update(
        provenance={"extractor": "x"}, locator={"char_offset": 2},
        structure_status="verified", reference_status="observed",
        reachability="reachable", suspicions=[{"kind": "demo"}],
    )
    rich = report_from_dict(rich_raw)
    rich_ev = rich.leads[0].source_refs[0]
    assert rich_ev.provenance == {"extractor": "x"}
    assert rich_ev.locator == {"char_offset": 2}
    assert rich_ev.structure_status == "verified"
    assert rich_ev.suspicions == [{"kind": "demo"}]
    malformed = json.loads(json.dumps(rich_raw))
    malformed["leads"][0]["source_refs"][0].update(
        provenance="bad", locator=[], structure_status=1,
        reference_status=None, reachability={}, suspicions=[{"kind": "ok"}, "bad"],
    )
    malformed_ev = report_from_dict(malformed).leads[0].source_refs[0]
    assert malformed_ev.provenance == {} and malformed_ev.locator == {}
    assert malformed_ev.structure_status == "unknown"
    assert malformed_ev.reference_status == malformed_ev.reachability == "unknown"
    assert {"kind": "ok"} in malformed_ev.suspicions
    assert {"kind": "malformed_suspicion"} in malformed_ev.suspicions
    assert {
        "kind": "malformed_evidence_fact", "field": "provenance",
    } in malformed_ev.suspicions
    assert {
        "kind": "malformed_evidence_fact", "field": "locator",
    } in malformed_ev.suspicions
    wrong_container = json.loads(json.dumps(rich_raw))
    wrong_container["leads"][0]["source_refs"][0]["suspicions"] = "malformed"
    wrong_container_ev = report_from_dict(wrong_container).leads[0].source_refs[0]
    assert {"kind": "malformed_suspicion"} in wrong_container_ev.suspicions


def test_web_supplement_reader_reuses_typed_fields_and_keeps_float_timestamp() -> None:
    evidence = _evidence_list([{
        "source": "web", "location": "capture.json", "observed_at": 12,
        "provenance": {"extractor": "web-test"},
        "locator": {"char_offset": 5},
        "suspicions": [{"kind": "query_parameter"}],
    }])[0]
    assert evidence.observed_at == 12.0
    assert type(evidence.observed_at) is float
    assert evidence.provenance == {"extractor": "web-test"}
    assert evidence.suspicions == [{"kind": "query_parameter"}]


def test_snapshot_and_legacy_context_use_same_dex_records() -> None:
    records = (DexStringRecord("one", {"extractor": "x"}, {"char_offset": 7}),)

    class Ctx:
        def dex_string_records(self):
            return iter(records)

        def dex_strings(self):
            raise AssertionError("records path must not call legacy projection")

    assert tuple(iter_dex_records(Ctx())) == records
    snapshot = SnapshotContext(
        package_name="x", manifest_xml="", platform="android", config=object(),
        apk_path="", extra_dex_paths=[], jadx_cache_root=None, jadx_baseline_index=None,
        permissions=[], components=object(), dex_strings=("one",), records=records,
        file_list=[], native_libs=[], certificates=[], files={},
    )
    assert tuple(snapshot.dex_string_records()) == records
    assert tuple(snapshot.dex_strings()) == ("one",)


def test_original_and_snapshot_context_produce_matching_occurrences() -> None:
    url = "https://snapshot.example.test/api"
    record = DexStringRecord(
        url,
        {"extractor": "dex-test-v1", "member_path": "classes.dex"},
        {"string_index": 2, "index_unit": "dex-string-pool"},
    )

    class RecordContext(FakeContext):
        def dex_string_records(self):
            return iter((record,))

    original = RecordContext(dex_strings=[url])
    snapshot = build_snapshot(original)

    def emitted(context) -> str:
        result = EndpointsAnalyzer().analyze(context)
        endpoint = next(item for item in result.endpoints if item.value == url)
        return occurrence_id(next(item for item in endpoint.evidences if item.source == "dex"))

    assert emitted(original) == emitted(snapshot)


def test_dex_byte_locator_keeps_its_unit_and_adds_string_offset() -> None:
    url = "https://record.example.test/api"
    record = DexStringRecord(
        f"x {url}",
        {"extractor": "dex-test-v1", "member_path": "classes.dex"},
        {"byte_offset": 123, "offset_unit": "dex-bytes"},
    )

    class RecordContext(FakeContext):
        def dex_string_records(self):
            return iter((record,))

    result = EndpointsAnalyzer().analyze(RecordContext(dex_strings=[record.value]))
    endpoint = next(item for item in result.endpoints if item.value == url)
    evidence = next(item for item in endpoint.evidences if item.source == "dex")
    assert evidence.locator == {
        "byte_offset": 123,
        "offset_unit": "dex-bytes",
        "char_offset": 2,
        "char_offset_unit": "decoded-text-codepoint",
    }


def test_fallback_record_has_no_claimed_coordinates() -> None:
    class Legacy:
        def dex_strings(self):
            return iter(("https://backend.example",))

    record = next(iter_dex_records(Legacy()))
    assert record.provenance == {} and record.locator == {}


def test_js_producer_keeps_repeated_offsets_and_dedupes_chunk_overlap() -> None:
    from apkscan.analyzers.js_bundle import _SCAN_CHUNK_BYTES, _SCAN_OVERLAP_CHARS

    url = "https://boundary-c2.example.test/path"
    first = f"var a='{url}';".encode()
    repeated = f"var b='{url}';".encode()
    repeat_offset = _SCAN_CHUNK_BYTES - _SCAN_OVERLAP_CHARS // 2
    payload = bytearray(b"x" * (_SCAN_CHUNK_BYTES + 100_000))
    payload[:len(first)] = first
    payload[repeat_offset:repeat_offset + len(repeated)] = repeated
    path = "assets/apps/__UNI__X/www/app-service.js"
    result = JsBundleAnalyzer().analyze(FakeContext(files={path: bytes(payload)}))
    endpoint = next(item for item in result.endpoints if item.value == url)
    evidence = [item for item in endpoint.evidences if item.source == "js"]
    offsets = sorted(item.locator["char_offset"] for item in evidence)
    assert offsets == sorted((payload.find(url.encode()), payload.find(url.encode(), len(first))))
    assert len(offsets) == 2
    assert all(item.locator["offset_unit"] == "decoded-text-codepoint" for item in evidence)
    assert all(item.provenance["extractor"] == "js-bundle-v1" for item in evidence)


def test_stage_merge_preserves_occurrence_fields() -> None:
    carried = _evidence(33, source="resource", suspicion="wasm_comment")
    carried.structure_status = "verified"
    previous = Report(
        "x", {}, [], [Endpoint("backend.example", "domain", evidences=[carried])], [], [],
    )
    active = Report(
        "x", {}, [], [Endpoint("backend.example", "domain", evidences=[_evidence(8)])], [], [],
    )
    merge_carried_evidence(active, previous)
    merged = active.endpoints[0].evidences
    restored = next(item for item in merged if item.source == "resource")
    assert restored.locator == carried.locator
    assert restored.provenance == carried.provenance
    assert restored.structure_status == "verified"
    assert restored.suspicions == carried.suspicions


def test_duplicate_resource_paths_keep_provenance_but_not_coordinates() -> None:
    url = "https://duplicate.example.test/api"
    path = "assets/config.json"

    class DuplicatePathContext(FakeContext):
        def list_files(self):
            return [path, path]

    raw = f'{{"url":"{url}"}}'.encode()
    result = EndpointsAnalyzer().analyze(DuplicatePathContext(files={path: raw}))
    endpoint = next(item for item in result.endpoints if item.value == url)
    evidence = next(item for item in endpoint.evidences if item.source == "resource")
    assert evidence.locator == {}
    assert evidence.provenance == {
        "extractor": "endpoints-v1",
        "member_path": path,
        "member_sha256": hashlib.sha256(raw).hexdigest(),
    }


def test_resource_locator_retains_byte_offset_unit() -> None:
    url = "https://resource.example.test/api"
    path = "assets/config.json"
    raw = f'{{"url":"{url}"}}'.encode()
    result = EndpointsAnalyzer().analyze(FakeContext(files={path: raw}))
    endpoint = next(item for item in result.endpoints if item.value == url)
    evidence = next(item for item in endpoint.evidences if item.source == "resource")
    assert evidence.locator == {
        "byte_offset": raw.index(url.encode()),
        "offset_unit": "byte",
    }
