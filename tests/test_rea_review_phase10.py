"""Historical derived projection files stay byte-for-byte on later attaches."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from tests.test_rea_review_phase6 import _marker, _plugin, _to_legacy
from tests.test_rea_trace_extended import _call, _ctx, _envelope, _parsed, _request, _source

_SAMPLE = "ab" * 32


@pytest.fixture
def plugin_src(monkeypatch: pytest.MonkeyPatch) -> Path:
    src = Path(__file__).parents[1] / "plugins" / "fxapk-rea" / "src"
    monkeypatch.syspath_prepend(str(src))
    return src
_SIX = {
    "schema_version",
    "base_schema_version",
    "coverage_status",
    "certification_upgraded",
    "gap_reordered",
    "added_paths",
}


def _raw(frame: str) -> bytes:
    raw = _envelope(
        [
            _ctx(1, "u1", "FRAME-A", 1),
            _ctx(2, "u2", "FRAME-B", 2),
            _parsed("9", 2, 3),
            _request(
                "req",
                frame,
                4,
                {"callFrames": [], "parent": {"callFrames": [_call("9", 0, 0, "parent")]}},
                loader="LOAD-A",
            ),
        ],
        [_source("9", 3, 2, "function parent(){return 1}\n")],
        actions=[{
            "kind": "navigate",
            "url": "http://127.0.0.1:8765/next",
            "ack": True,
            "timestamp": "2026-10-12T00:00:01Z",
            "round": 1,
        }],
    )
    payload = json.loads(raw)
    payload["capture"]["startup_interventions"] = [{"kind": "synthetic"}]
    return json.dumps(payload).encode()


def _case(path: Path) -> None:
    path.write_text(json.dumps({
        "package_name": "com.example.synthetic",
        "meta": {
            "sample_sha256": _SAMPLE,
            "web_supplement": {"status": "not_applicable", "reason": "mode_off", "mode": "off"},
        },
        "endpoints": [],
        "leads": [],
        "findings": [],
        "analyzer_status": [],
    }), encoding="utf-8")


def _context(path: Path) -> None:
    path.write_text(json.dumps({
        "schema_version": "fxapk-web-context/1",
        "sample_sha256": _SAMPLE,
        "target_id": "TARGET-1",
        "origin": "http://127.0.0.1:8765",
        "package_name": "com.example.synthetic",
    }), encoding="utf-8")


def _bundle(trace, tmp_path: Path, raw: bytes, name: str) -> tuple[Path, dict]:  # noqa: ANN001
    from fxapk_rea.evidence import claim_output

    fresh, files = trace.project_trace(raw)
    bundle = tmp_path / name
    claim_output(bundle)
    body = trace._publish(bundle, raw, fresh, files)
    _marker(bundle)
    return bundle, body


def _write_observation(bundle: Path, saved: dict) -> None:
    encoded = (json.dumps(saved, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()
    (bundle / "observation.json").write_bytes(encoded)


def _files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    }


def _rewrite_manifest(attachment, report: Path, sha: str) -> None:  # noqa: ANN001
    root = report.parent / "external_observations" / sha
    manifest = attachment._manifest(sha, _files(root))
    (root / "manifest.json").write_bytes(manifest)
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["meta"]["web_observations"][0]["manifest_sha256"] = hashlib.sha256(manifest).hexdigest()
    report.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _downgrade_record(root: Path) -> bytes:
    record = json.loads((root / "projection-record.json").read_text(encoding="utf-8"))
    record.pop("legacy_frame_paths", None)
    record.pop("compatibility_gap", None)
    assert set(record) == _SIX
    blob = (json.dumps(record, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()
    (root / "projection-record.json").write_bytes(blob)
    return blob


def _next_raw(raw: bytes, capture_id: str) -> bytes:
    payload = json.loads(raw)
    payload["capture"]["id"] = capture_id
    return json.dumps(payload).encode()


def _fresh_bundle(trace, tmp_path: Path, raw: bytes, name: str) -> Path:  # noqa: ANN001
    bundle, _body = _bundle(trace, tmp_path, raw, name)
    return bundle


def _historical(
    plugin_src: Path, tmp_path: Path, mode: str,
) -> tuple[Any, Path, str, dict[str, bytes]]:
    trace, attachment = _plugin(plugin_src)
    frame = "FRAME-A" if mode == "cross" else "FRAME-B"
    raw = _raw(frame)
    bundle, fresh = _bundle(trace, tmp_path, raw, f"bundle-{mode}")
    saved = json.loads(json.dumps(fresh))
    if mode == "cross":
        _to_legacy(saved)
    if mode in {"gap", "cross"}:
        saved["coverage"]["gaps"].reverse()
    if mode in {"missing", "cross"}:
        for key in ("actions", "startup_interventions", "related_targets"):
            saved.pop(key, None)
    _write_observation(bundle, saved)
    report = tmp_path / f"report-{mode}.json"
    _case(report)
    context = tmp_path / f"context-{mode}.json"
    _context(context)
    summary = attachment.attach(bundle, report, tmp_path / f"first-{mode}", context_record=context)
    sha = summary["source_sha256"]
    root = tmp_path / f"first-{mode}" / "external_observations" / sha
    _downgrade_record(root)
    if mode == "cross":
        legacy = json.loads(json.dumps(fresh))
        _to_legacy(legacy)
        encoded = (json.dumps(legacy, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()
        (root / "observation-reprojected.json").write_bytes(encoded)
    stored_report = tmp_path / f"first-{mode}" / "report.json"
    _rewrite_manifest(attachment, stored_report, sha)
    before = _files(root)
    before["manifest.json"] = (root / "manifest.json").read_bytes()
    return attachment, stored_report, sha, before


@pytest.mark.parametrize("mode", ["gap", "missing", "cross"])
def test_historical_six_key_derivatives_are_preserved(
    plugin_src: Path, tmp_path: Path, mode: str,
) -> None:
    attachment, report, sha, before = _historical(plugin_src, tmp_path, mode)
    source_report = report.read_bytes()
    trace, _attachment = _plugin(plugin_src)
    raw = _raw("FRAME-B")
    nxt = _fresh_bundle(trace, tmp_path, _next_raw(raw, f"CAP-{mode}-1"), f"next-{mode}")
    out = tmp_path / f"continued-{mode}"
    summary = attachment.attach(nxt, report, out)
    assert report.read_bytes() == source_report
    carried = out / "external_observations" / sha
    for name, blob in before.items():
        assert (carried / name).read_bytes() == blob
    record = json.loads((carried / "projection-record.json").read_text(encoding="utf-8"))
    assert set(record) == _SIX
    assert record["certification_upgraded"] is False
    assert record["coverage_status"] == "partial"
    published = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert published["meta"]["web_supplement"]["mode"] == "off"
    assert [row["source_sha256"] for row in published["meta"]["web_observations"]][0] == sha
    assert summary["source_sha256"] != sha
    third = _fresh_bundle(trace, tmp_path, _next_raw(raw, f"CAP-{mode}-2"), f"third-{mode}")
    again = tmp_path / f"again-{mode}"
    attachment.attach(third, out / "report.json", again)
    carried_again = again / "external_observations" / sha
    for name, blob in before.items():
        assert (carried_again / name).read_bytes() == blob
    assert (again / "report.json").read_text(encoding="utf-8").count(sha) >= 1


def test_current_projection_record_still_attaches(plugin_src: Path, tmp_path: Path) -> None:
    trace, attachment = _plugin(plugin_src)
    raw = _raw("FRAME-B")
    bundle, fresh = _bundle(trace, tmp_path, raw, "current-bundle")
    saved = json.loads(json.dumps(fresh))
    saved["coverage"]["gaps"].reverse()
    _write_observation(bundle, saved)
    report = tmp_path / "current-report.json"
    _case(report)
    first = attachment.attach(bundle, report, tmp_path / "current-first")
    root = tmp_path / "current-first" / "external_observations" / first["source_sha256"]
    record = json.loads((root / "projection-record.json").read_text(encoding="utf-8"))
    assert "legacy_frame_paths" in record
    assert "compatibility_gap" in record
    nxt = _fresh_bundle(trace, tmp_path, _next_raw(raw, "CAP-CURRENT"), "current-next")
    attachment.attach(nxt, tmp_path / "current-first" / "report.json", tmp_path / "current-second")
    kept = tmp_path / "current-second" / "external_observations" / first["source_sha256"]
    assert (kept / "projection-record.json").read_bytes() == (root / "projection-record.json").read_bytes()


def test_malicious_historical_derivatives_and_originals_rejected(
    plugin_src: Path, tmp_path: Path,
) -> None:
    attachment, report, sha, _before = _historical(plugin_src, tmp_path, "cross")
    source = report.read_bytes()
    root = report.parent / "external_observations" / sha
    trace, _attachment = _plugin(plugin_src)
    raw = _raw("FRAME-B")
    nxt = _fresh_bundle(trace, tmp_path, _next_raw(raw, "CAP-REJECT"), "reject-next")

    def reject(name: str) -> None:
        destination = tmp_path / f"rejected-{name}"
        with pytest.raises(attachment.AttachError):
            attachment.attach(nxt, report, destination)
        assert not destination.exists()
        assert report.read_bytes() == source

    record = json.loads((root / "projection-record.json").read_text(encoding="utf-8"))
    record["certification_upgraded"] = True
    (root / "projection-record.json").write_bytes(
        (json.dumps(record, ensure_ascii=False, indent=2) + "\n").encode()
    )
    _rewrite_manifest(attachment, report, sha)
    source = report.read_bytes()
    reject("certification")

    payload = json.loads(report.read_text(encoding="utf-8"))
    record["certification_upgraded"] = False
    record["coverage_status"] = "complete"
    (root / "projection-record.json").write_bytes(
        (json.dumps(record, ensure_ascii=False, indent=2) + "\n").encode()
    )
    _rewrite_manifest(attachment, report, sha)
    source = report.read_bytes()
    reject("coverage")

    record["coverage_status"] = "partial"
    record["operator"] = "silent-cert"
    (root / "projection-record.json").write_bytes(
        (json.dumps(record, ensure_ascii=False, indent=2) + "\n").encode()
    )
    _rewrite_manifest(attachment, report, sha)
    source = report.read_bytes()
    reject("unknown-field")

    record.pop("operator")
    (root / "projection-record.json").write_bytes(
        (json.dumps(record, ensure_ascii=False, indent=2) + "\n").encode()
    )
    projected = json.loads((root / "observation-reprojected.json").read_text(encoding="utf-8"))
    projected["source"]["sha256"] = "cd" * 32
    (root / "observation-reprojected.json").write_bytes(
        (json.dumps(projected, ensure_ascii=False, indent=2) + "\n").encode()
    )
    _rewrite_manifest(attachment, report, sha)
    source = report.read_bytes()
    reject("source")

    projected["source"]["sha256"] = sha
    (root / "observation-reprojected.json").write_bytes(
        (json.dumps(projected, ensure_ascii=False, indent=2) + "\n").encode()
    )
    script = next((root / "scripts").glob("*.js"))
    script.write_bytes(script.read_bytes() + b" ")
    _rewrite_manifest(attachment, report, sha)
    source = report.read_bytes()
    reject("script")

    script.write_bytes(script.read_bytes()[:-1])
    context = root / "context-record.json"
    context.write_text(context.read_text(encoding="utf-8").replace(_SAMPLE, "cd" * 32), encoding="utf-8")
    _rewrite_manifest(attachment, report, sha)
    source = report.read_bytes()
    reject("context")

    context.write_text(context.read_text(encoding="utf-8").replace("cd" * 32, _SAMPLE), encoding="utf-8")
    observation = json.loads((root / "observation.json").read_text(encoding="utf-8"))
    observation["provenance_authenticated"] = True
    (root / "observation.json").write_bytes(
        (json.dumps(observation, ensure_ascii=False, indent=2) + "\n").encode()
    )
    _rewrite_manifest(attachment, report, sha)
    source = report.read_bytes()
    reject("flag")
    assert payload["meta"]["web_observations"][0]["source_sha256"] == sha


def test_disk_derivative_must_match_manifest_even_if_regenerated_does(
    plugin_src: Path, tmp_path: Path,
) -> None:
    trace, attachment = _plugin(plugin_src)
    raw = _raw("FRAME-B")
    bundle, fresh = _bundle(trace, tmp_path, raw, "disk-bundle")
    saved = json.loads(json.dumps(fresh))
    saved["coverage"]["gaps"].reverse()
    _write_observation(bundle, saved)
    report = tmp_path / "disk-report.json"
    _case(report)
    first = attachment.attach(bundle, report, tmp_path / "disk-first")
    stored = tmp_path / "disk-first"
    sha = first["source_sha256"]
    root = stored / "external_observations" / sha
    source_report = (stored / "report.json").read_bytes()
    record_bytes = (root / "projection-record.json").read_bytes()
    projected_bytes = (root / "observation-reprojected.json").read_bytes()
    nxt = _fresh_bundle(trace, tmp_path, _next_raw(raw, "CAP-DISK"), "disk-next")

    def refuse(name: str, blob: bytes) -> None:
        path = root / name
        original = path.read_bytes()
        path.write_bytes(blob)
        destination = tmp_path / f"disk-rejected-{name}"
        with pytest.raises(attachment.AttachError, match="existing_observation_mismatch"):
            attachment.attach(nxt, stored / "report.json", destination)
        assert not destination.exists()
        assert (stored / "report.json").read_bytes() == source_report
        path.write_bytes(original)

    refuse(
        "projection-record.json",
        record_bytes.replace(b'"certification_upgraded": false', b'"certification_upgraded": true ', 1),
    )
    refuse(
        "observation-reprojected.json",
        projected_bytes.replace(b'"provenance_authenticated": false', b'"provenance_authenticated": true ', 1),
    )
    kept = tmp_path / "disk-kept"
    attachment.attach(nxt, stored / "report.json", kept)
    carried = kept / "external_observations" / sha
    assert (carried / "projection-record.json").read_bytes() == record_bytes
    assert (carried / "observation-reprojected.json").read_bytes() == projected_bytes


def test_duplicate_json_keys_cannot_hide_certification(
    plugin_src: Path, tmp_path: Path,
) -> None:
    attachment, report, sha, _before = _historical(plugin_src, tmp_path, "gap")
    root = report.parent / "external_observations" / sha
    trace, _attachment = _plugin(plugin_src)
    nxt = _fresh_bundle(trace, tmp_path, _next_raw(_raw("FRAME-B"), "CAP-DUP"), "dup-next")

    def plant(name: str, old: str, new: str) -> None:
        path = root / name
        text = path.read_text(encoding="utf-8").replace(old, new, 1)
        assert text != path.read_text(encoding="utf-8")
        path.write_text(text, encoding="utf-8")
        _rewrite_manifest(attachment, report, sha)
        source = report.read_bytes()
        destination = tmp_path / f"rejected-{name}"
        with pytest.raises(attachment.AttachError, match="duplicate_json_key"):
            attachment.attach(nxt, report, destination)
        assert not destination.exists()
        assert report.read_bytes() == source

    plant(
        "projection-record.json",
        '"certification_upgraded": false',
        '"certification_upgraded": true, "certification_upgraded": false',
    )
    record = root / "projection-record.json"
    record.write_text(
        record.read_text(encoding="utf-8").replace(
            '"certification_upgraded": true, "certification_upgraded": false',
            '"certification_upgraded": false',
            1,
        ),
        encoding="utf-8",
    )
    plant(
        "observation-reprojected.json",
        '"provenance_authenticated": false',
        '"provenance_authenticated": true, "provenance_authenticated": false',
    )


def test_large_historical_derivative_survives_second_attach(
    plugin_src: Path, tmp_path: Path,
) -> None:
    from tests.test_rea_review_phase6 import _publish_legacy
    from tests.test_rea_review_phase8 import _many

    trace, attachment = _plugin(plugin_src)
    raw = _many(350, 3)
    bundle, indented = _publish_legacy(plugin_src, tmp_path, raw, "large-legacy")
    compact = (json.dumps(json.loads(indented), separators=(",", ":")) + "\n").encode()
    assert len(compact) <= 2 * 1024 * 1024
    (bundle / "observation.json").write_bytes(compact)
    report = tmp_path / "input.json"
    _case(report)
    first = attachment.attach(bundle, report, tmp_path / "large-first")
    root = tmp_path / "large-first" / "external_observations" / first["source_sha256"]
    derived = (root / "observation-reprojected.json").read_bytes()
    assert len(derived) > 2 * 1024 * 1024
    before = derived
    record = (root / "projection-record.json").read_bytes()
    other = _fresh_bundle(trace, tmp_path, _next_raw(_raw("FRAME-B"), "CAP-LARGE"), "large-next")
    source = (tmp_path / "large-first" / "report.json").read_bytes()
    attachment.attach(other, tmp_path / "large-first" / "report.json", tmp_path / "large-second")
    assert (tmp_path / "large-first" / "report.json").read_bytes() == source
    carried = tmp_path / "large-second" / "external_observations" / first["source_sha256"]
    assert (carried / "observation-reprojected.json").read_bytes() == before
    assert (carried / "projection-record.json").read_bytes() == record
    forged = record.replace(b'"certification_upgraded": false', b'"certification_upgraded": true', 1)
    (carried / "projection-record.json").write_bytes(forged)
    _rewrite_manifest(attachment, tmp_path / "large-second" / "report.json", first["source_sha256"])
    rejected = tmp_path / "large-rejected"
    with pytest.raises(attachment.AttachError, match="existing_observation_mismatch"):
        attachment.attach(other, tmp_path / "large-second" / "report.json", rejected)
    assert not rejected.exists()
    assert (carried / "observation-reprojected.json").read_bytes() == before
