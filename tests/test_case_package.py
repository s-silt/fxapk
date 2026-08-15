from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

import pytest

from apkscan.core import atomic, case_package
from apkscan.core.case_package import (
    CasePackageError,
    create_case_package,
    create_case_review,
    project_case_status,
    verify_case_package,
)
from apkscan.core.models import Report
from apkscan.core.report_io import write_report


def _write_report(root, *, analysis: str = "complete", closure: str = "partial"):  # noqa: ANN001, ANN202
    path = root / "report.json"
    report = Report(
        package_name="com.example.synthetic",
        meta={
            "sample_sha256": "a" * 64,
            "tool_version": "1.5.4",
            "ruleset_digest": "b" * 16,
            "closure": {"schema_version": "1.0", "status": closure},
        },
        leads=[],
        endpoints=[],
        findings=[],
        analyzer_status=[],
        analysis_status=analysis,
    )
    write_report(report, path, render_existing_html=False)
    return path


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sample_sha256", None),
        ("sample_sha256", "a" * 63),
        ("sample_sha256", "g" * 64),
        ("ruleset_digest", None),
        ("ruleset_digest", "unknown"),
        ("ruleset_digest", "b" * 15),
        ("tool_version", None),
        ("tool_version", " dev-local "),
        ("tool_version", "de\u0301v-local"),
        ("tool_version", "dev\nlocal"),
        ("tool_version", "dev\u200blocal"),
        ("tool_version", "v" * 121),
    ],
)
def test_phase1_package_requires_valid_reproducibility_anchors_before_writing(
    tmp_path, field, value  # noqa: ANN001
) -> None:
    report = _write_report(tmp_path)
    payload = json.loads(report.read_text(encoding="utf-8"))
    if value is None:
        payload["meta"].pop(field)
    else:
        payload["meta"][field] = value
    report.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    manifest = tmp_path / "case-package.json"

    with pytest.raises(CasePackageError, match=field):
        create_case_package(
            report,
            manifest,
            case_id="case-001",
            producer="analyst-a",
        )

    assert not manifest.exists()


def test_phase1_package_pins_normalized_reproducibility_anchors(tmp_path) -> None:  # noqa: ANN001
    report = _write_report(tmp_path)
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["meta"]["sample_sha256"] = "A" * 64
    payload["meta"]["ruleset_digest"] = "B" * 16
    payload["meta"]["tool_version"] = "1.5.4+local"
    report.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    manifest = tmp_path / "case-package.json"

    created = create_case_package(
        report,
        manifest,
        case_id="case-001",
        producer="analyst-a",
    )

    assert created["sample_sha256"] == "a" * 64
    assert created["ruleset_digest"] == "b" * 16
    assert created["tool_version"] == "1.5.4+local"
    assert verify_case_package(manifest)["status"] == "verified"


@pytest.mark.parametrize("field", ["sample_sha256", "tool_version", "ruleset_digest"])
def test_verifier_rejects_forged_or_missing_reproducibility_anchor(
    tmp_path, field  # noqa: ANN001
) -> None:
    report = _write_report(tmp_path)
    manifest = tmp_path / "case-package.json"
    create_case_package(report, manifest, case_id="case-001", producer="analyst-a")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload.pop(field)
    body = {key: value for key, value in payload.items() if key != "package_id"}
    payload["package_id"] = hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    manifest.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    result = verify_case_package(manifest)

    assert result["status"] == "failed"
    assert any(field in issue for issue in result["issues"])


def test_phase1_package_projects_four_independent_statuses(tmp_path) -> None:  # noqa: ANN001
    report = _write_report(tmp_path, analysis="complete", closure="partial")
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"pcap")
    batch = tmp_path / "batch.csv"
    batch.write_text("reference", encoding="utf-8")
    manifest = tmp_path / "case-package.json"

    create_case_package(
        report,
        manifest,
        case_id="case-001",
        producer="analyst-a",
        case_evidence=[pcap],
        batch_reference=[batch],
    )
    status = project_case_status(manifest)
    payload = json.loads(manifest.read_text(encoding="utf-8"))

    assert status == {
        "package_integrity": "verified",
        "analysis": "complete",
        "closure": "partial",
        "review": "not_reviewed",
    }
    assert {item["scope"] for item in payload["artifacts"]} == {
        "case_evidence",
        "batch_reference",
    }


def test_package_integrity_detects_modified_artifact(tmp_path) -> None:  # noqa: ANN001
    report = _write_report(tmp_path)
    manifest = tmp_path / "case-package.json"
    create_case_package(report, manifest, case_id="case-001", producer="analyst-a")

    report.write_text(report.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    result = verify_case_package(manifest)
    assert result["status"] == "failed"
    assert result["issues"]


def test_package_integrity_detects_missing_artifact(tmp_path) -> None:  # noqa: ANN001
    report = _write_report(tmp_path)
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"pcap")
    manifest = tmp_path / "case-package.json"
    create_case_package(
        report,
        manifest,
        case_id="case-001",
        producer="analyst-a",
        case_evidence=[pcap],
    )

    pcap.unlink()

    result = verify_case_package(manifest)
    assert result["status"] == "failed"
    assert any("missing" in issue for issue in result["issues"])


def test_package_integrity_projects_unreadable_artifact_as_failed(
    tmp_path, monkeypatch: pytest.MonkeyPatch  # noqa: ANN001
) -> None:
    report = _write_report(tmp_path)
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"pcap")
    manifest = tmp_path / "case-package.json"
    create_case_package(
        report,
        manifest,
        case_id="case-001",
        producer="analyst-a",
        case_evidence=[pcap],
    )
    original_sha256 = case_package._sha256

    def unreadable_artifact(path: Path) -> str:
        if path.resolve() == pcap.resolve():
            raise PermissionError("simulated unreadable evidence")
        return original_sha256(path)

    monkeypatch.setattr(case_package, "_sha256", unreadable_artifact)

    verified = verify_case_package(manifest)
    status = project_case_status(manifest)

    assert verified["status"] == "failed"
    assert any("artifact unreadable" in issue for issue in verified["issues"])
    assert status["package_integrity"] == "failed"


def test_phase_record_never_overwrites_preexisting_target(tmp_path) -> None:  # noqa: ANN001
    report = _write_report(tmp_path)
    manifest = tmp_path / "case-package.json"
    original = b"preexisting-record"
    manifest.write_bytes(original)

    with pytest.raises(CasePackageError, match="already exists"):
        create_case_package(report, manifest, case_id="case-001", producer="analyst-a")

    assert manifest.read_bytes() == original


def test_manifest_temp_name_cannot_destroy_a_packaged_attachment(tmp_path) -> None:  # noqa: ANN001
    report = _write_report(tmp_path)
    manifest = tmp_path / "case-package.json"
    attachment = manifest.with_suffix(manifest.suffix + ".tmp")
    original = b"original-evidence"
    attachment.write_bytes(original)

    create_case_package(
        report,
        manifest,
        case_id="case-001",
        producer="analyst-a",
        case_evidence=[attachment],
    )

    assert attachment.read_bytes() == original
    assert verify_case_package(manifest)["status"] == "verified"


def test_constructor_rejects_same_attachment_in_case_and_batch_scopes(tmp_path) -> None:  # noqa: ANN001
    report = _write_report(tmp_path)
    attachment = tmp_path / "shared.bin"
    attachment.write_bytes(b"evidence")
    manifest = tmp_path / "case-package.json"

    with pytest.raises(CasePackageError, match="conflicting artifact kind/scope"):
        create_case_package(
            report,
            manifest,
            case_id="case-001",
            producer="analyst-a",
            case_evidence=[attachment],
            batch_reference=[attachment],
        )

    assert not manifest.exists()


def test_constructor_deduplicates_exact_same_artifact_classification(tmp_path) -> None:  # noqa: ANN001
    report = _write_report(tmp_path)
    attachment = tmp_path / "capture.pcap"
    attachment.write_bytes(b"pcap")
    manifest = tmp_path / "case-package.json"

    payload = create_case_package(
        report,
        manifest,
        case_id="case-001",
        producer="analyst-a",
        case_evidence=[attachment, attachment],
    )

    assert [item["path"] for item in payload["artifacts"]].count("capture.pcap") == 1


def test_concurrent_phase_record_creation_has_exactly_one_winner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    report = _write_report(tmp_path)
    manifest = tmp_path / "case-package.json"
    barrier = threading.Barrier(2)
    original_exists = Path.exists

    # Force the historical ``exists() -> fixed .tmp -> replace()`` implementation
    # through its TOCTOU window.  The corrected implementation does not consult
    # ``exists()`` and relies on an atomic create-if-absent operation instead.
    def synchronized_exists(path: Path) -> bool:
        if path == manifest:
            barrier.wait(timeout=5)
            return False
        return original_exists(path)

    monkeypatch.setattr(Path, "exists", synchronized_exists)

    def produce(actor: str) -> str:
        try:
            create_case_package(
                report,
                manifest,
                case_id="case-001",
                producer=actor,
            )
        except Exception as exc:  # noqa: BLE001 - assert the public failure type below
            return type(exc).__name__
        return "ok"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(produce, ("analyst-a", "analyst-b")))

    assert outcomes == ["CasePackageError", "ok"]
    assert verify_case_package(manifest)["status"] == "verified"


def test_immutable_write_falls_back_when_hard_links_are_unsupported(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    report = _write_report(tmp_path)
    manifest = tmp_path / "case-package.json"

    def unsupported_link(_source: object, _target: object) -> None:
        raise OSError(errno.EPERM, "hard links unsupported")

    monkeypatch.setattr(atomic.os, "link", unsupported_link)

    if os.name != "nt":
        with pytest.raises(atomic.AtomicCreateUnsupportedError):
            create_case_package(
                report,
                manifest,
                case_id="case-001",
                producer="analyst-a",
            )
        assert not manifest.exists()
        return

    create_case_package(report, manifest, case_id="case-001", producer="analyst-a")

    assert verify_case_package(manifest)["status"] == "verified"

    original = manifest.read_bytes()
    with pytest.raises(CasePackageError, match="already exists"):
        create_case_package(report, manifest, case_id="case-001", producer="analyst-b")
    assert manifest.read_bytes() == original


def test_hard_link_unavailable_concurrent_publish_never_overwrites(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "immutable.json"
    payloads = (b'{"owner":"alpha"}\n', b'{"owner":"bravo"}\n')

    def unsupported_link(_source: object, _target: object) -> None:
        raise OSError(errno.EPERM, "hard links unsupported")

    monkeypatch.setattr(atomic.os, "link", unsupported_link)

    def publish(payload: bytes) -> bool | str:
        try:
            return atomic.atomic_create_bytes(target, payload)
        except atomic.AtomicCreateUnsupportedError:
            return "unsupported"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(publish, payloads))

    if os.name == "nt":
        assert sorted(outcomes) == [False, True]
        assert target.read_bytes() in payloads
    else:
        assert outcomes == ["unsupported", "unsupported"]
        assert not target.exists()


def test_hard_link_fallback_never_publishes_partial_record_after_hard_exit(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "case-package.json"
    payload = {"payload": "complete phase record"}
    script = """
import errno
import os
import sys
from pathlib import Path
from apkscan.core import case_package

real_fdopen = os.fdopen
real_write = os.write
fdopen_calls = 0

def unsupported_link(_source, _target):
    raise OSError(errno.EPERM, "hard links unsupported")

def crash_write(descriptor, data):
    written = real_write(descriptor, data[:1])
    os.fsync(descriptor)
    os._exit(92)

def crash_on_legacy_target(descriptor, *args, **kwargs):
    global fdopen_calls
    fdopen_calls += 1
    if fdopen_calls == 1:
        return real_fdopen(descriptor, *args, **kwargs)
    real_write(descriptor, b"{")
    os.fsync(descriptor)
    os._exit(92)

os.link = unsupported_link
os.write = crash_write
os.fdopen = crash_on_legacy_target
case_package._write_new_json(
    Path(sys.argv[1]),
    {"payload": "complete phase record"},
)
"""

    completed = subprocess.run(
        [sys.executable, "-c", script, str(manifest)],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
    )

    assert completed.returncode == 92
    assert not manifest.exists(), "a crash before publication left a partial immutable record"
    case_package._write_new_json(manifest, payload)
    assert json.loads(manifest.read_text(encoding="utf-8")) == payload


def test_atomic_create_failure_removes_only_its_own_temporary_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    report = _write_report(tmp_path)
    manifest = tmp_path / "case-package.json"
    real_fsync = atomic.os.fsync

    def unsupported_link(_source: object, _target: object) -> None:
        raise OSError(errno.EPERM, "hard links unsupported")

    def fail_temporary_fsync(descriptor: int) -> None:
        real_fsync(descriptor)
        raise OSError(errno.EIO, "simulated temporary fsync failure")

    monkeypatch.setattr(atomic.os, "link", unsupported_link)
    monkeypatch.setattr(atomic.os, "fsync", fail_temporary_fsync)

    with pytest.raises(OSError, match="temporary fsync failure"):
        create_case_package(report, manifest, case_id="case-001", producer="analyst-a")

    assert not manifest.exists()
    assert list(tmp_path.glob(f".{manifest.name}.*.tmp")) == []


def test_package_verifier_rejects_recomputed_path_escape(tmp_path) -> None:  # noqa: ANN001
    package_root = tmp_path / "package"
    package_root.mkdir()
    report = _write_report(package_root)
    manifest = package_root / "case-package.json"
    create_case_package(report, manifest, case_id="case-001", producer="analyst-a")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["artifacts"][0]["path"] = "../outside.json"
    body = {key: value for key, value in payload.items() if key != "package_id"}
    canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    payload["package_id"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    manifest.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    result = verify_case_package(manifest)

    assert result["status"] == "failed"
    assert any("escapes package root" in issue for issue in result["issues"])


def test_review_is_bound_to_exact_package_and_becomes_stale_after_change(tmp_path) -> None:  # noqa: ANN001
    report = _write_report(tmp_path, closure="partial")
    manifest = tmp_path / "case-package.json"
    review = tmp_path / "case-review.json"
    create_case_package(report, manifest, case_id="case-001", producer="same-analyst")
    create_case_review(
        manifest,
        review,
        reviewer="same-analyst",
        status="accepted",
        findings=["reviewed"],
    )

    before = project_case_status(manifest, review)
    report.write_text(report.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    after = project_case_status(manifest, review)

    assert before["review"] == "accepted"
    assert before["closure"] == "partial"
    assert after["package_integrity"] == "failed"
    assert after["review"] == "stale"


def test_package_rejects_artifact_outside_manifest_root(tmp_path) -> None:  # noqa: ANN001
    package_root = tmp_path / "package"
    package_root.mkdir()
    outside = tmp_path / "report.json"
    _write_report(tmp_path)

    with pytest.raises(CasePackageError, match="outside package root"):
        create_case_package(
            outside,
            package_root / "case-package.json",
            case_id="case-001",
            producer="analyst-a",
        )


def test_case_package_uses_shared_nfc_case_identity(tmp_path) -> None:  # noqa: ANN001
    report = _write_report(tmp_path)
    manifest = tmp_path / "case-package.json"

    payload = create_case_package(
        report,
        manifest,
        case_id="Cafe\u0301",
        producer="analyst-a",
    )

    assert payload["case_id"] == "Caf\u00e9"


def test_case_package_rejects_control_character_case_identity(tmp_path) -> None:  # noqa: ANN001
    report = _write_report(tmp_path)

    with pytest.raises(ValueError, match="控制字符"):
        create_case_package(
            report,
            tmp_path / "case-package.json",
            case_id="case\n001",
            producer="analyst-a",
        )


def test_phase1_refuses_report_with_invalid_analysis_status(tmp_path) -> None:  # noqa: ANN001
    report = _write_report(tmp_path)
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["analysis_status"] = "bogus"
    report.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(CasePackageError, match="analysis status"):
        create_case_package(
            report,
            tmp_path / "case-package.json",
            case_id="case-001",
            producer="analyst-a",
        )

    assert not (tmp_path / "case-package.json").exists()


def test_report_without_manifest_is_explicitly_unverified(tmp_path) -> None:  # noqa: ANN001
    report = _write_report(tmp_path, analysis="partial", closure="failed")

    status = project_case_status(report)

    assert status == {
        "package_integrity": "unverified",
        "analysis": "partial",
        "closure": "failed",
        "review": "not_reviewed",
    }


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("case_id", ""),
        ("producer", ""),
        ("analysis_snapshot", "bogus"),
        ("closure_snapshot", "accepted"),
        ("created_at", "not-a-time"),
        ("created_at", "2026-08-11T12:00:00"),
    ],
)
def test_semantically_invalid_manifest_fails_even_with_recomputed_package_id(
    tmp_path, field, bad_value  # noqa: ANN001
) -> None:
    report = _write_report(tmp_path)
    manifest = tmp_path / "case-package.json"
    create_case_package(report, manifest, case_id="case-001", producer="analyst-a")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload[field] = bad_value
    body = {key: value for key, value in payload.items() if key != "package_id"}
    canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    payload["package_id"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    manifest.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    result = verify_case_package(manifest)

    assert result["status"] == "failed"
    assert any(field in issue for issue in result["issues"])


@pytest.mark.parametrize(
    ("field", "forged"),
    [
        ("analysis_snapshot", "failed"),
        ("closure_snapshot", "complete"),
        ("report_schema_version", "1.1"),
    ],
)
def test_manifest_status_snapshot_must_match_hashed_report(
    tmp_path, field, forged  # noqa: ANN001
) -> None:
    report = _write_report(tmp_path, analysis="complete", closure="partial")
    manifest = tmp_path / "case-package.json"
    create_case_package(report, manifest, case_id="case-001", producer="analyst-a")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload[field] = forged
    body = {key: value for key, value in payload.items() if key != "package_id"}
    canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    payload["package_id"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    manifest.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    result = verify_case_package(manifest)

    assert result["status"] == "failed"
    assert any(field in issue for issue in result["issues"])


def test_verifier_rejects_invalid_report_closure_status_even_when_snapshot_is_not_run(
    tmp_path,
) -> None:  # noqa: ANN001
    report = _write_report(tmp_path, closure="partial")
    manifest = tmp_path / "case-package.json"
    create_case_package(report, manifest, case_id="case-001", producer="analyst-a")

    report_payload = json.loads(report.read_text(encoding="utf-8"))
    report_payload["meta"]["closure"]["status"] = "bogus"
    report.write_text(json.dumps(report_payload, ensure_ascii=False), encoding="utf-8")

    payload = json.loads(manifest.read_text(encoding="utf-8"))
    artifact = next(item for item in payload["artifacts"] if item["kind"] == "report")
    artifact["size"] = report.stat().st_size
    artifact["sha256"] = hashlib.sha256(report.read_bytes()).hexdigest()
    payload["closure_snapshot"] = "not_run"
    body = {key: value for key, value in payload.items() if key != "package_id"}
    payload["package_id"] = hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    manifest.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    result = verify_case_package(manifest)

    assert result["status"] == "failed"
    assert any("invalid closure status" in issue for issue in result["issues"])


def test_report_artifact_cannot_be_relabelled_as_batch_reference(tmp_path) -> None:  # noqa: ANN001
    report = _write_report(tmp_path)
    manifest = tmp_path / "case-package.json"
    create_case_package(report, manifest, case_id="case-001", producer="analyst-a")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    report_artifact = next(item for item in payload["artifacts"] if item["kind"] == "report")
    report_artifact["scope"] = "batch_reference"
    body = {key: value for key, value in payload.items() if key != "package_id"}
    payload["package_id"] = hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    manifest.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    result = verify_case_package(manifest)

    assert result["status"] == "failed"
    assert any("report artifact" in issue and "scope" in issue for issue in result["issues"])


def test_same_artifact_cannot_claim_case_and_batch_scopes(tmp_path) -> None:  # noqa: ANN001
    report = _write_report(tmp_path)
    manifest = tmp_path / "case-package.json"
    create_case_package(report, manifest, case_id="case-001", producer="analyst-a")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    duplicate = dict(payload["artifacts"][0])
    duplicate.update({"kind": "reference", "scope": "batch_reference"})
    payload["artifacts"].append(duplicate)
    body = {key: value for key, value in payload.items() if key != "package_id"}
    payload["package_id"] = hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    manifest.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    result = verify_case_package(manifest)

    assert result["status"] == "failed"
    assert any("duplicate artifact path" in issue for issue in result["issues"])


def test_batch_or_legacy_only_report_cannot_snapshot_complete_closure(tmp_path) -> None:  # noqa: ANN001
    for scope in ("batch_reference", "legacy_unspecified"):
        root = tmp_path / scope
        root.mkdir()
        report = _write_report(root, closure="complete")
        payload = json.loads(report.read_text(encoding="utf-8"))
        evidence = {"source": "runtime-pcap", "location": "capture.pcap", "scope": scope}
        payload["meta"]["closure"]["targets"] = [
            {"kind": "domain", "value": "backend.example"}
        ]
        payload["endpoints"] = [
            {
                "value": "backend.example",
                "kind": "domain",
                "evidences": [evidence],
            }
        ]
        payload["leads"] = [
            {
                "category": "DOMAIN",
                "value": "backend.example",
                "advice": "建议调证",
                "base_advice": "建议调证",
                "confidence": "HIGH",
                "source_refs": [evidence],
            }
        ]
        report.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

        with pytest.raises(CasePackageError, match="direct case evidence"):
            create_case_package(
                report,
                root / "case-package.json",
                case_id="case-001",
                producer="analyst-a",
            )


def test_case_plus_batch_evidence_can_snapshot_complete_closure(tmp_path) -> None:  # noqa: ANN001
    report = _write_report(tmp_path, closure="complete")
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["meta"]["closure"]["targets"] = [
        {"kind": "domain", "value": "backend.example"}
    ]
    payload["endpoints"] = [
        {
            "value": "backend.example",
            "kind": "domain",
            "evidences": [
                {
                    "source": "runtime-pcap",
                    "location": "capture.pcap",
                    "scope": "case_evidence",
                },
                {
                    "source": "batch",
                    "location": "batch.csv",
                    "scope": "batch_reference",
                },
            ],
        }
    ]
    report.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    manifest = tmp_path / "case-package.json"

    create_case_package(
        report,
        manifest,
        case_id="case-001",
        producer="analyst-a",
    )

    assert verify_case_package(manifest)["status"] == "verified"


def test_complete_closure_requires_direct_evidence_for_every_target(tmp_path) -> None:  # noqa: ANN001
    report = _write_report(tmp_path, closure="complete")
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["meta"]["closure"]["targets"] = [
        {"kind": "domain", "value": "direct.example"},
        {"kind": "domain", "value": "batch-only.example"},
    ]
    payload["endpoints"] = [
        {
            "value": "direct.example",
            "kind": "domain",
            "evidences": [
                {
                    "source": "runtime-pcap",
                    "location": "capture.pcap",
                    "scope": "case_evidence",
                }
            ],
        },
        {
            "value": "batch-only.example",
            "kind": "domain",
            "evidences": [
                {
                    "source": "batch",
                    "location": "batch.csv",
                    "scope": "batch_reference",
                }
            ],
        },
    ]
    report.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    with pytest.raises(CasePackageError, match="batch-only.example"):
        create_case_package(
            report,
            tmp_path / "case-package.json",
            case_id="case-001",
            producer="analyst-a",
        )


def test_unrelated_direct_endpoint_cannot_license_batch_only_closure_target(
    tmp_path,
) -> None:  # noqa: ANN001
    report = _write_report(tmp_path, closure="complete")
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["meta"]["closure"]["targets"] = [
        {"kind": "domain", "value": "batch-only.example"}
    ]
    payload["endpoints"] = [
        {
            "value": "unrelated.example",
            "kind": "domain",
            "evidences": [
                {
                    "source": "runtime-pcap",
                    "location": "capture.pcap",
                    "scope": "case_evidence",
                }
            ],
        },
        {
            "value": "batch-only.example",
            "kind": "domain",
            "evidences": [
                {
                    "source": "batch",
                    "location": "batch.csv",
                    "scope": "batch_reference",
                }
            ],
        },
    ]
    report.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    with pytest.raises(CasePackageError, match="batch-only.example"):
        create_case_package(
            report,
            tmp_path / "case-package.json",
            case_id="case-001",
            producer="analyst-a",
        )


def test_complete_closure_without_target_inventory_is_rejected(tmp_path) -> None:  # noqa: ANN001
    report = _write_report(tmp_path, closure="complete")
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["endpoints"] = [
        {
            "value": "direct.example",
            "kind": "domain",
            "evidences": [
                {
                    "source": "runtime-pcap",
                    "location": "capture.pcap",
                    "scope": "case_evidence",
                }
            ],
        }
    ]
    report.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    with pytest.raises(CasePackageError, match="closure targets"):
        create_case_package(
            report,
            tmp_path / "case-package.json",
            case_id="case-001",
            producer="analyst-a",
        )


@pytest.mark.parametrize(
    ("analysis_snapshot", "closure_snapshot", "expected_analysis", "expected_closure"),
    [
        ("bogus", "partial", "failed", "partial"),
        ("complete", "accepted", "complete", "not_run"),
        ("bogus", "accepted", "failed", "not_run"),
    ],
)
def test_failed_manifest_status_projection_never_exposes_out_of_contract_enums(
    tmp_path,
    analysis_snapshot,
    closure_snapshot,
    expected_analysis,
    expected_closure,
) -> None:  # noqa: ANN001
    report = _write_report(tmp_path)
    manifest = tmp_path / "case-package.json"
    create_case_package(report, manifest, case_id="case-001", producer="analyst-a")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["analysis_snapshot"] = analysis_snapshot
    payload["closure_snapshot"] = closure_snapshot
    body = {key: value for key, value in payload.items() if key != "package_id"}
    payload["package_id"] = hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    manifest.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    status = project_case_status(manifest)

    assert status == {
        "package_integrity": "failed",
        "analysis": expected_analysis,
        "closure": expected_closure,
        "review": "not_reviewed",
    }


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("reviewer", ""),
        ("reviewed_at", ""),
        ("reviewed_at", "not-a-time"),
        ("reviewed_at", "2026-08-11T12:00:00"),
        ("findings", "not-a-list"),
        ("findings", ["valid", 7]),
    ],
)
def test_review_required_fields_are_validated_before_projecting_status(
    tmp_path, field, bad_value  # noqa: ANN001
) -> None:
    report = _write_report(tmp_path)
    manifest = tmp_path / "case-package.json"
    review = tmp_path / "case-review.json"
    create_case_package(report, manifest, case_id="case-001", producer="analyst-a")
    create_case_review(
        manifest,
        review,
        reviewer="reviewer-a",
        status="accepted",
        findings=["checked"],
    )
    payload = json.loads(review.read_text(encoding="utf-8"))
    payload[field] = bad_value
    review.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    status = project_case_status(manifest, review)

    assert status["review"] == "stale"
