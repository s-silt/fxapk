"""P1 explicit Phase-1 inventory to corpus reconciliation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

from apkscan import cli
from apkscan.core import corpus
from apkscan.core import corpus_catalog as catalog
from apkscan.core.case_package import create_case_package


runner = CliRunner()


def _write_report(path: Path, *, sha: str = "a" * 64) -> None:
    payload = {
        "schema_version": "1.1",
        "package_name": "com.example.synthetic",
        "analysis_status": "complete",
        "completeness": 1.0,
        "leads": [],
        "endpoints": [],
        "findings": [],
        "meta": {
            "sample_sha256": sha,
            "tool_version": "1.5.4",
            "ruleset_digest": "b" * 16,
        },
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _write_inventory(path: Path, report_path: str, *, case_id: str = "case-a") -> None:
    path.write_text(
        json.dumps({"case_id": case_id, "report_path": report_path}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _rewrite_package_id(payload: dict) -> None:
    body = {key: value for key, value in payload.items() if key != "package_id"}
    canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    payload["package_id"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def test_reconcile_defaults_to_read_only_then_apply_ingests(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    inventory = tmp_path / "inventory.jsonl"
    corpus_root = tmp_path / "external-corpus"
    _write_report(report)
    _write_inventory(inventory, "report.json")

    dry = corpus.reconcile_inventory(corpus_root, inventory, apply=False)
    assert dry["counts"]["missing_record"] == 1
    assert dry["applied"] is False
    assert not (corpus_root / "manifest.jsonl").exists()

    applied = corpus.reconcile_inventory(corpus_root, inventory, apply=True)
    assert applied["counts"]["in_sync"] == 1
    assert applied["added"] == 1
    [entry] = corpus.load_manifest(corpus_root)
    assert entry["case_ids"] == ["case-a"]


def test_reconcile_never_infers_case_id_from_parent_directory(tmp_path: Path) -> None:
    report = tmp_path / "case-from-directory" / "report.json"
    report.parent.mkdir()
    inventory = tmp_path / "inventory.jsonl"
    _write_report(report)
    inventory.write_text(
        json.dumps({"report_path": str(report)}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    result = corpus.reconcile_inventory(tmp_path / "corpus", inventory, apply=True)

    assert result["counts"]["invalid_report"] == 1
    assert not (tmp_path / "corpus" / "manifest.jsonl").exists()


def test_reconcile_rejects_non_string_case_id(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    inventory = tmp_path / "inventory.jsonl"
    _write_report(report)
    inventory.write_text(
        json.dumps({"case_id": 123, "report_path": str(report)}) + "\n",
        encoding="utf-8",
    )

    result = corpus.reconcile_inventory(tmp_path / "corpus", inventory, apply=True)

    assert result["counts"]["invalid_report"] == 1
    assert "字符串" in str(result["items"][0]["reason"])
    assert not corpus.manifest_path(tmp_path / "corpus").exists()


def test_reconcile_rejects_nonstandard_json_constants(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    inventory = tmp_path / "inventory.jsonl"
    corpus_root = tmp_path / "external-corpus"
    _write_report(report)
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["meta"]["nonstandard"] = float("nan")
    report.write_text(json.dumps(payload, allow_nan=True), encoding="utf-8")
    _write_inventory(inventory, str(report))

    result = corpus.reconcile_inventory(corpus_root, inventory, apply=True)

    assert result["counts"]["invalid_report"] == 1
    assert "non-finite JSON number" in str(result["items"][0]["reason"])
    assert not corpus.manifest_path(corpus_root).exists()


def test_reconcile_cli_is_dry_run_unless_apply_is_explicit(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    inventory = tmp_path / "inventory.jsonl"
    corpus_root = tmp_path / "external-corpus"
    _write_report(report)
    _write_inventory(inventory, str(report))

    result = runner.invoke(
        cli.app,
        ["corpus", "reconcile", str(inventory), "--corpus", str(corpus_root)],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["applied"] is False
    assert payload["counts"]["missing_record"] == 1
    assert not (corpus_root / "manifest.jsonl").exists()


def test_reconcile_detects_tampered_corpus_bytes_even_when_manifest_hash_matches(
    tmp_path: Path,
) -> None:
    report = tmp_path / "report.json"
    inventory = tmp_path / "inventory.jsonl"
    corpus_root = tmp_path / "external-corpus"
    _write_report(report)
    _write_inventory(inventory, str(report))
    corpus.reconcile_inventory(corpus_root, inventory, apply=True)
    [entry] = corpus.load_manifest(corpus_root)
    (corpus_root / str(entry["report_path"])).write_text("{}", encoding="utf-8")

    result = corpus.reconcile_inventory(corpus_root, inventory, apply=False)

    assert result["counts"]["content_conflict"] == 1
    assert "case_conflict" not in result["counts"]


def test_reconcile_apply_reports_path_collision_as_content_conflict(
    tmp_path: Path,
) -> None:
    corpus_root = tmp_path / "external-corpus"
    original = tmp_path / "original.json"
    incoming = tmp_path / "incoming.json"
    inventory = tmp_path / "inventory.jsonl"
    _write_report(original, sha="same?path")
    _write_report(incoming, sha="same*path")
    original_payload = json.loads(original.read_text(encoding="utf-8"))
    corpus.add_report(
        corpus_root,
        original_payload,
        original.read_text(encoding="utf-8"),
        case_id="case-a",
    )
    _write_inventory(inventory, str(incoming), case_id="case-b")

    result = corpus.reconcile_inventory(corpus_root, inventory, apply=True)

    assert result["counts"]["content_conflict"] == 1
    assert result["counts"]["missing_record"] == 0
    assert result["added"] == 0
    assert result["case_bound"] == 0


def test_reconcile_apply_reloads_final_quarantine_state(
    tmp_path: Path,
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    report = tmp_path / "report.json"
    inventory = tmp_path / "inventory.jsonl"
    corpus_root = tmp_path / "external-corpus"
    _write_report(report)
    payload = json.loads(report.read_text(encoding="utf-8"))
    seeded = corpus.add_report(
        corpus_root,
        payload,
        report.read_text(encoding="utf-8"),
    )
    key = tuple(seeded["key"])
    _write_inventory(inventory, str(report), case_id="case-a")
    original_add = corpus.add_report

    def quarantine_then_bind(*args, **kwargs):  # type: ignore[no-untyped-def]
        catalog.set_record_state(
            corpus_root,
            key,
            state=catalog.RECORD_QUARANTINED,
            reason="concurrent review quarantine",
        )
        return original_add(*args, **kwargs)

    monkeypatch.setattr(corpus, "add_report", quarantine_then_bind)

    result = corpus.reconcile_inventory(corpus_root, inventory, apply=True)

    assert result["counts"]["quarantined"] == 1
    assert result["counts"]["in_sync"] == 0
    assert result["case_bound"] == 1


def test_reconcile_accepts_verified_case_package_directly(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    package = tmp_path / "case-package.json"
    corpus_root = tmp_path / "external-corpus"
    _write_report(report)
    create_case_package(
        report,
        package,
        case_id="case-from-package",
        producer="phase1",
    )

    dry = corpus.reconcile_inventory(corpus_root, package, apply=False)
    applied = corpus.reconcile_inventory(corpus_root, package, apply=True)

    assert dry["input_kind"] == "case_package"
    assert dry["counts"]["missing_record"] == 1
    assert isinstance(dry["items"][0]["package_id"], str)
    assert applied["counts"]["in_sync"] == 1
    [entry] = corpus.load_manifest(corpus_root)
    assert entry["case_ids"] == ["case-from-package"]


def test_reconcile_rejects_case_package_with_tampered_report(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    package = tmp_path / "case-package.json"
    corpus_root = tmp_path / "external-corpus"
    _write_report(report)
    create_case_package(report, package, case_id="case-a", producer="phase1")
    report.write_text(report.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    result = corpus.reconcile_inventory(corpus_root, package, apply=True)

    assert result["input_kind"] == "case_package"
    assert result["counts"]["invalid_report"] == 1
    assert not corpus.manifest_path(corpus_root).exists()


def test_reconcile_cli_tampered_case_package_exits_nonzero_with_json_result(
    tmp_path: Path,
) -> None:
    report = tmp_path / "report.json"
    package = tmp_path / "case-package.json"
    corpus_root = tmp_path / "external-corpus"
    _write_report(report)
    create_case_package(report, package, case_id="case-a", producer="phase1")
    report.write_text(report.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    result = runner.invoke(
        cli.app,
        ["corpus", "reconcile", str(package), "--apply", "--corpus", str(corpus_root)],
    )

    assert result.exit_code == 1
    assert json.loads(result.stdout)["counts"]["invalid_report"] == 1
    assert "未被安全接收" in result.stderr


def test_reconcile_rejects_stale_case_package_snapshot(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    package = tmp_path / "case-package.json"
    _write_report(report)
    create_case_package(report, package, case_id="case-a", producer="phase1")
    report_payload = json.loads(report.read_text(encoding="utf-8"))
    report_payload["analysis_status"] = "failed"
    report.write_text(json.dumps(report_payload, ensure_ascii=False), encoding="utf-8")
    package_payload = json.loads(package.read_text(encoding="utf-8"))
    artifact = next(item for item in package_payload["artifacts"] if item["kind"] == "report")
    raw = report.read_bytes()
    artifact["sha256"] = hashlib.sha256(raw).hexdigest()
    artifact["size"] = len(raw)
    _rewrite_package_id(package_payload)
    package.write_text(json.dumps(package_payload, ensure_ascii=False), encoding="utf-8")

    result = corpus.reconcile_inventory(tmp_path / "corpus", package, apply=True)

    assert result["counts"]["invalid_report"] == 1
    assert "analysis_snapshot" in str(result["items"][0]["reason"])


def test_reconcile_rejects_case_package_report_path_escape(tmp_path: Path) -> None:
    package_root = tmp_path / "package"
    package_root.mkdir()
    report = package_root / "report.json"
    outside = tmp_path / "outside.json"
    package = package_root / "case-package.json"
    _write_report(report)
    outside.write_bytes(report.read_bytes())
    create_case_package(report, package, case_id="case-a", producer="phase1")
    payload = json.loads(package.read_text(encoding="utf-8"))
    artifact = next(item for item in payload["artifacts"] if item["kind"] == "report")
    artifact["path"] = "../outside.json"
    artifact["sha256"] = hashlib.sha256(outside.read_bytes()).hexdigest()
    artifact["size"] = outside.stat().st_size
    _rewrite_package_id(payload)
    package.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    result = corpus.reconcile_inventory(tmp_path / "corpus", package, apply=True)

    assert result["counts"]["invalid_report"] == 1
    assert "escapes package root" in str(result["items"][0]["reason"])
