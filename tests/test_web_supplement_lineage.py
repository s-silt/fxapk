"""Prior input-report lineage is verified before any output or plugin work."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from apkscan.core.web_supplement_report import SupplementRefusal, supplement_report

_MAX_CHAIN = 32


def _payload(pointer: dict[str, Any] | None = None) -> dict[str, Any]:
    meta: dict[str, Any] = {"platform": "android"}
    if pointer is not None:
        meta["supplement_web_input"] = pointer
    return {
        "schema_version": "1.2",
        "package_name": "app.example.test",
        "analysis_status": "complete",
        "meta": meta,
        "endpoints": [],
        "leads": [{
            "category": "DOMAIN",
            "value": "old.example.test",
            "advice": "待核",
            "base_advice": "待核",
            "confidence": "LOW",
            "notes": "original-note",
            "source_refs": [{
                "source": "runtime-pcap",
                "location": "captures/floor.pcap",
                "snippet": "old.example.test",
                "scope": "case_evidence",
            }],
        }],
        "findings": [],
    }


def _config(path: Path) -> Path:
    path.write_text(json.dumps({
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "auto",
        "source": "bundle",
        "path": str(path.parent / "missing-bundle"),
    }), encoding="utf-8")
    return path


def _off_config(path: Path) -> Path:
    unused = path.parent / "unused.json"
    unused.write_text("{}", encoding="utf-8")
    path.write_text(json.dumps({
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "off",
        "source": "rea-json",
        "path": str(unused),
    }), encoding="utf-8")
    return path


def _dump(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _pointer(blob: bytes) -> dict[str, Any]:
    digest = hashlib.sha256(blob).hexdigest()
    return {
        "relative_path": f"input_report/{digest}/report.json",
        "sha256": digest,
        "byte_length": len(blob),
    }


def _write_snapshot(base: Path, blob: bytes) -> dict[str, Any]:
    pointer = _pointer(blob)
    digest = pointer["sha256"]
    path = base / "input_report" / digest / "report.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)
    return pointer


def _chain(base: Path, count: int) -> tuple[Path, dict[str, bytes]]:
    """Write ``count`` prior snapshots and a current report that points at the newest."""
    previous: dict[str, Any] | None = None
    stored: dict[str, bytes] = {}
    for _ in range(count):
        blob = _dump(_payload(previous))
        previous = _write_snapshot(base, blob)
        stored[str(previous["sha256"])] = blob
    current = base / "report.json"
    current.write_bytes(_dump(_payload(previous)))
    return current, stored


def _forbid_stages(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    called: list[str] = []

    def forbid(*_args: object, **_kwargs: object) -> None:
        called.append("called")
        raise AssertionError("lineage failure reached a later stage")

    monkeypatch.setattr("apkscan.core.web_supplement_report._reverify_trees", forbid)
    monkeypatch.setattr("apkscan.core.web_supplement_report.apply_static", forbid)
    return called


def test_missing_snapshot_hash_and_overlong_chain_stop_before_plugin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = _forbid_stages(monkeypatch)
    config = _config(tmp_path / "config.json")
    cases = {
        "missing": 1,
        "hash_missing": 1,
        "too_many": _MAX_CHAIN + 1,
    }
    for name, count in cases.items():
        base = tmp_path / name
        report, _stored = _chain(base, count)
        if name == "missing":
            next(base.rglob("input_report/*/report.json")).unlink()
        elif name == "hash_missing":
            payload = json.loads(report.read_text(encoding="utf-8"))
            del payload["meta"]["supplement_web_input"]["sha256"]
            report.write_bytes(_dump(payload))
        out = tmp_path / f"{name}-out"
        with pytest.raises(SupplementRefusal):
            supplement_report(report, config, out)
        assert not out.exists(), name
    assert called == []


def test_valid_32_chain_is_copied_with_command_provenance(tmp_path: Path) -> None:
    base = tmp_path / "case"
    report, stored = _chain(base, _MAX_CHAIN)
    out = tmp_path / "out"
    result = supplement_report(report, _off_config(tmp_path / "off.json"), out)
    assert result["exit_code"] == 3
    for digest, blob in stored.items():
        assert (out / "input_report" / digest / "report.json").read_bytes() == blob
    pointer = json.loads((out / "report.json").read_text(encoding="utf-8"))
    fresh = pointer["meta"]["supplement_web_input"]
    assert fresh["source_report_absolute"] == str(report.resolve())
    assert fresh["source_artifact_base"] == str(base.resolve())
    assert (out / fresh["relative_path"]).read_bytes() == report.read_bytes()
    assert not (out / "captures").exists()


def test_repeated_chain_keeps_bytes_and_source_bases(tmp_path: Path) -> None:
    original = tmp_path / "case" / "report.json"
    original.parent.mkdir()
    original.write_bytes(_dump(_payload()))
    config = _off_config(tmp_path / "off.json")
    first = tmp_path / "first"
    second = tmp_path / "second"
    assert supplement_report(original, config, first)["exit_code"] == 3
    assert supplement_report(first / "report.json", config, second)["exit_code"] == 3
    first_report = json.loads((first / "report.json").read_text(encoding="utf-8"))
    second_report = json.loads((second / "report.json").read_text(encoding="utf-8"))
    old = first_report["meta"]["supplement_web_input"]
    fresh = second_report["meta"]["supplement_web_input"]
    assert (second / old["relative_path"]).read_bytes() == (first / old["relative_path"]).read_bytes()
    stored = json.loads((second / fresh["relative_path"]).read_bytes())
    assert stored["meta"]["supplement_web_input"] == old
    assert old["source_report_absolute"] == str(original.resolve())
    assert old["source_artifact_base"] == str(original.parent.resolve())
    assert fresh["source_report_absolute"] == str((first / "report.json").resolve())
    assert fresh["source_artifact_base"] == str(first.resolve())
    assert stored["leads"][0]["source_refs"][0]["location"] == "captures/floor.pcap"
    assert second_report["leads"][0]["source_refs"][0]["location"] == "captures/floor.pcap"
    assert not (second / "captures" / "floor.pcap").exists()


@pytest.mark.parametrize("relative", [
    "../outside/secret.json",
    "input_report/../secret.json",
    "/input_report/secret.json",
    "C:/outside/secret.json",
    "input_report/" + ("ab" * 32) + "/report.json:Zone.Identifier",
    "\\\\server\\share\\report.json",
])
def test_snapshot_path_escape_does_not_read_outside(tmp_path: Path, relative: str) -> None:
    outside = tmp_path / "outside" / "secret.json"
    outside.parent.mkdir()
    outside.write_bytes(b"OUTSIDE-SECRET")
    report = tmp_path / "case" / "report.json"
    report.parent.mkdir()
    payload = _payload({
        "relative_path": relative,
        "sha256": "ab" * 32,
        "byte_length": 1,
    })
    report.write_bytes(_dump(payload))
    out = tmp_path / "out"
    with pytest.raises(SupplementRefusal):
        supplement_report(report, _off_config(tmp_path / "off.json"), out)
    assert not out.exists()
    assert outside.read_bytes() == b"OUTSIDE-SECRET"


def test_windows_snapshot_junction_is_not_followed(tmp_path: Path) -> None:
    if sys.platform != "win32":
        pytest.skip("directory junction is Windows-only")
    outside = tmp_path / "outside"
    blob = _dump(_payload())
    pointer = _pointer(blob)
    target = outside / str(pointer["sha256"])
    target.mkdir(parents=True)
    (target / "report.json").write_bytes(blob)
    case = tmp_path / "case"
    case.mkdir()
    link = case / "input_report"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(outside)],
        capture_output=True,
    )
    if created.returncode != 0:
        pytest.skip("directory junction is not available")
    try:
        report = case / "report.json"
        report.write_bytes(_dump(_payload(pointer)))
        out = tmp_path / "out"
        with pytest.raises(SupplementRefusal) as refused:
            supplement_report(report, _off_config(tmp_path / "off.json"), out)
        assert refused.value.reason == "link_escape"
        assert not out.exists()
        assert (target / "report.json").read_bytes() == blob
    finally:
        if link.exists():
            link.rmdir()


@pytest.mark.parametrize("record", [[], "bad", 1, {"relative_path": "input_report/" + ("ab" * 32) + "/report.json"}])
def test_malformed_or_cyclic_snapshot_record_refuses(tmp_path: Path, record: object) -> None:
    report = tmp_path / "case" / "report.json"
    report.parent.mkdir()
    report.write_bytes(_dump(_payload(record if isinstance(record, dict) else None)))
    if not isinstance(record, dict):
        payload = json.loads(report.read_text(encoding="utf-8"))
        payload["meta"]["supplement_web_input"] = record
        report.write_bytes(_dump(payload))
    out = tmp_path / "out"
    with pytest.raises(SupplementRefusal):
        supplement_report(report, _off_config(tmp_path / "off.json"), out)
    assert not out.exists()


def test_cyclic_snapshot_pointers_refuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two consistent links that name each other. Hashes are pinned in-test."""
    left_digest = "11" * 32
    right_digest = "22" * 32
    left_blob = _dump(_payload({
        "relative_path": f"input_report/{right_digest}/report.json",
        "sha256": right_digest,
    }))
    right_blob = _dump(_payload({
        "relative_path": f"input_report/{left_digest}/report.json",
        "sha256": left_digest,
    }))
    pinned = {left_blob: left_digest, right_blob: right_digest}
    real_sha256 = hashlib.sha256

    def pinned_sha256(blob: bytes) -> Any:
        if blob in pinned:
            class _Pinned:
                def hexdigest(self) -> str:
                    return pinned[blob]
            return _Pinned()
        return real_sha256(blob)

    monkeypatch.setattr("apkscan.core.web_supplement_report.hashlib.sha256", pinned_sha256)
    base = tmp_path / "case"
    for digest, blob in ((left_digest, left_blob), (right_digest, right_blob)):
        path = base / "input_report" / digest / "report.json"
        path.parent.mkdir(parents=True)
        path.write_bytes(blob)
    report = base / "report.json"
    report.write_bytes(_dump(_payload({
        "relative_path": f"input_report/{left_digest}/report.json",
        "sha256": left_digest,
        "byte_length": len(left_blob),
    })))
    out = tmp_path / "out"
    with pytest.raises(SupplementRefusal) as refused:
        supplement_report(report, _off_config(tmp_path / "off.json"), out)
    assert refused.value.reason == "invalid_report"
    assert not out.exists()


def test_aggregate_history_bytes_refuse_without_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = _forbid_stages(monkeypatch)
    base = tmp_path / "case"
    report, stored = _chain(base, 2)
    monkeypatch.setattr(
        "apkscan.core.web_supplement_report._MAX_BYTES",
        sum(len(blob) for blob in stored.values()) - 1,
    )
    out = tmp_path / "out"
    with pytest.raises(SupplementRefusal) as refused:
        supplement_report(report, _config(tmp_path / "config.json"), out)
    assert refused.value.reason == "oversize"
    assert not out.exists()
    assert called == []


def test_bool_byte_length_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    called = _forbid_stages(monkeypatch)
    base = tmp_path / "case"
    report, _stored = _chain(base, 1)
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["meta"]["supplement_web_input"]["byte_length"] = True
    report.write_bytes(_dump(payload))
    out = tmp_path / "out"
    with pytest.raises(SupplementRefusal) as refused:
        supplement_report(report, _config(tmp_path / "config.json"), out)
    assert refused.value.reason == "invalid_report"
    assert not out.exists()
    assert called == []
