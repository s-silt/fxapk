"""证据链与 stale 的唯一定义。合成夹具，不碰金标准对象。"""
from __future__ import annotations

import json
from pathlib import Path

from apkscan.core.phase2.chain import (
    CHAIN_LINKS,
    ENVELOPE_LINKS,
    chain_link,
    file_sha256,
    is_stale,
    replay_stale,
    review_stale,
    schema_document,
)


def test_stale_is_only_a_previous_hash_mismatch() -> None:
    current = "ab" * 32
    assert is_stale(current, current) is False
    assert is_stale("cd" * 32, current) is True
    assert is_stale(None, current) is True
    assert is_stale("not-a-hash", current) is True


def test_replay_and_review_use_the_same_stale_definition() -> None:
    current = "ab" * 32
    decision = {"decided_against": {"inventory_fingerprint": current}}
    assert replay_stale(decision, current) is False
    assert replay_stale({"decided_against": {"inventory_fingerprint": "cd" * 32}}, current) is True

    review = {"manifest_sha256": current, "phase2_gate": {"receipt_sha256": "ef" * 32}}
    assert review_stale(review, current_manifest_sha256=current) is False
    assert review_stale(review, current_manifest_sha256="cd" * 32) is True
    assert review_stale(
        review, current_manifest_sha256=current, current_receipt_sha256="ef" * 32,
    ) is False
    assert review_stale(
        review, current_manifest_sha256=current, current_receipt_sha256="11" * 32,
    ) is True


def test_chain_link_records_previous_without_replacing_payload() -> None:
    body = {"schema_version": "phase2-triage/1.0", "case_id": "CASE-SYNTH"}
    linked = chain_link("triage", body, previous_sha256="ab" * 32)
    assert linked["previous_link"] == "inventory"
    assert linked["previous_sha256"] == "ab" * 32
    assert linked["case_id"] == "CASE-SYNTH"
    assert "previous_sha256" not in body


def test_each_link_schema_names_its_previous_link() -> None:
    assert schema_document("report")["required"] == ["schema_version"]
    for link in CHAIN_LINKS:
        if link not in ENVELOPE_LINKS:
            continue
        document = schema_document(link)
        assert document["properties"]["previous_sha256"]["pattern"] == "^[0-9a-f]{64}$"
        assert "previous_sha256" in document["required"]
    for link in ("decision", "coverage", "review"):
        assert "previous_sha256" not in schema_document(link)["required"]


def test_written_inventory_records_manifest_bytes(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    import apkscan.cli as cli
    from tests.phase2_fixtures import write_verified_package

    case_dir = tmp_path / "case"
    write_verified_package(case_dir, "pkg", case_id="CASE-CHAIN")
    manifest = case_dir / "pkg" / "case-package.json"
    out = tmp_path / "inventory.json"
    result = CliRunner().invoke(cli.app, [
        "phase2", "inventory-phase1", "--case-dir", str(case_dir), "--out", str(out),
    ])
    assert result.exit_code == 0, result.output
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["previous_link"] == "package"
    assert payload["previous_sha256"] == file_sha256(manifest)


def test_triage_previous_hash_is_inventory_file_bytes(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    import apkscan.cli as cli
    from tests.phase2_fixtures import write_verified_package

    case_dir = tmp_path / "case"
    write_verified_package(case_dir, "pkg", case_id="CASE-CHAIN")
    inventory_out = case_dir / "phase2" / "inventory.json"
    inventory_out.parent.mkdir()
    listed = CliRunner().invoke(cli.app, [
        "phase2", "inventory-phase1", "--case-dir", str(case_dir), "--out", str(inventory_out),
    ])
    assert listed.exit_code == 0, listed.output
    triaged = CliRunner().invoke(cli.app, ["phase2", "triage", "--case-dir", str(case_dir)])
    assert triaged.exit_code == 0, triaged.output
    payload = json.loads((case_dir / "phase2" / "triage.json").read_text(encoding="utf-8"))
    assert payload["previous_link"] == "inventory"
    assert payload["previous_sha256"] == file_sha256(inventory_out)
    assert payload["previous_sha256"] != json.loads(inventory_out.read_text(encoding="utf-8"))["fingerprint"]


def test_multi_package_previous_hash_is_manifest_bytes_not_a_new_fingerprint(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    import apkscan.cli as cli
    from apkscan.core.integrity import sha256_hex
    from tests.phase2_fixtures import write_verified_package

    case_dir = tmp_path / "case"
    first = write_verified_package(case_dir, "b-pkg", case_id="CASE-CHAIN")
    second = write_verified_package(case_dir, "a-pkg", case_id="CASE-CHAIN")
    out = tmp_path / "inventory.json"
    result = CliRunner().invoke(cli.app, [
        "phase2", "inventory-phase1", "--case-dir", str(case_dir), "--out", str(out),
    ])
    assert result.exit_code == 0, result.output
    payload = json.loads(out.read_text(encoding="utf-8"))
    ordered = sorted((first, second), key=lambda path: path.name)
    expected = sha256_hex(b"".join(
        (path / "case-package.json").read_bytes() for path in ordered
    ))
    assert payload["previous_sha256"] == expected
    assert payload["previous_sha256"] != payload["fingerprint"]


def test_triage_refuses_partial_inventory_file(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    import apkscan.cli as cli
    from tests.phase2_fixtures import write_verified_package

    case_dir = tmp_path / "case"
    write_verified_package(case_dir, "pkg", case_id="CASE-CHAIN")
    inventory_out = case_dir / "phase2" / "inventory.json"
    inventory_out.parent.mkdir()
    inventory_out.write_text("{", encoding="utf-8")
    before = inventory_out.read_bytes()

    result = CliRunner().invoke(cli.app, ["phase2", "triage", "--case-dir", str(case_dir)])
    assert result.exit_code != 0
    assert inventory_out.read_bytes() == before
    assert not (case_dir / "phase2" / "triage.json").exists()


def test_triage_writes_inventory_file_when_missing(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    import apkscan.cli as cli
    from tests.phase2_fixtures import write_verified_package

    case_dir = tmp_path / "case"
    write_verified_package(case_dir, "pkg", case_id="CASE-CHAIN")
    result = CliRunner().invoke(cli.app, ["phase2", "triage", "--case-dir", str(case_dir)])
    assert result.exit_code == 0, result.output
    inventory_out = case_dir / "phase2" / "inventory.json"
    payload = json.loads((case_dir / "phase2" / "triage.json").read_text(encoding="utf-8"))
    assert payload["previous_sha256"] == file_sha256(inventory_out)


def test_missing_coverage_is_not_hashed_as_empty_bytes(tmp_path: Path) -> None:
    from apkscan.core.phase2.link import build_gate_receipt

    class _Package:
        package_id = "ab" * 32
        manifest_sha256 = "cd" * 32
        directory_name = "pkg"

    class _Inventory:
        packages = (_Package(),)
        case_id = "CASE-CHAIN"
        fingerprint = "ef" * 32

    class _Report:
        ok = True
        blockers: tuple[str, ...] = ()
        warnings: tuple[str, ...] = ()

    try:
        build_gate_receipt(
            _Inventory(),
            _Report(),
            coverage_path=tmp_path / "missing-coverage.json",
            decisions_path=tmp_path / "missing-decisions.jsonl",
            decisions_ledger="absent",
        )
    except OSError:
        return
    raise AssertionError("缺 coverage 不应得到回执")


def test_human_queue_without_ledger_is_not_auto_closed(tmp_path: Path) -> None:
    """有人判队列且从未落账本时，gate 也不能把缺失读成空账本。"""
    from typer.testing import CliRunner

    import apkscan.cli as cli
    from tests.phase2_fixtures import write_verified_package

    case_dir = tmp_path / "case"
    write_verified_package(
        case_dir, "pkg", case_id="CASE-CHAIN",
        leads=[{
            "category": "DOMAIN", "value": "api.example.test", "advice": "建议调证",
            "source_refs": [{"evidence_id": "ev-api", "scope": "case_evidence"}],
        }],
    )
    runner = CliRunner()
    assert runner.invoke(cli.app, ["phase2", "triage", "--case-dir", str(case_dir)]).exit_code == 0
    # 物化会落显式空账本。删掉它才是「有人判队列、账本被删」。
    assert runner.invoke(cli.app, ["phase2", "materialize", "--case-dir", str(case_dir)]).exit_code == 0
    ledger = case_dir / "phase2" / "decisions.jsonl"
    ledger.unlink()
    gated = runner.invoke(cli.app, ["phase2", "gate", "--case-dir", str(case_dir)])
    assert gated.exit_code != 0, gated.output
    assert not ledger.exists()
    assert not (case_dir / "phase2" / "gate-receipt.json").exists()


def test_deleted_decision_ledger_is_not_an_empty_ledger(tmp_path: Path) -> None:
    """物化已落空账本后，删掉它不能再被 gate 补成同一份 PASS。"""
    from typer.testing import CliRunner

    import apkscan.cli as cli
    from apkscan.core.integrity import sha256_hex
    from apkscan.core.phase2.chain import file_sha256
    from tests.phase2_fixtures import write_verified_package

    case_dir = tmp_path / "case"
    write_verified_package(
        case_dir, "pkg", case_id="CASE-CHAIN",
        leads=[{
            "category": "DOMAIN", "value": "sdk.example.test", "advice": "无需调证",
            "is_runtime_seen": False, "is_runtime_contact": False, "is_c2": False,
            "source_refs": [{"evidence_id": "ev-sdk", "scope": "case_evidence"}],
        }],
    )
    runner = CliRunner()
    assert runner.invoke(cli.app, ["phase2", "triage", "--case-dir", str(case_dir)]).exit_code == 0
    materialized = runner.invoke(cli.app, ["phase2", "materialize", "--case-dir", str(case_dir)])
    assert materialized.exit_code == 0, materialized.output
    ledger = case_dir / "phase2" / "decisions.jsonl"
    coverage = json.loads((case_dir / "phase2" / "coverage.json").read_text(encoding="utf-8"))
    assert ledger.is_file()
    assert coverage["decisions_sha256"] == file_sha256(ledger)
    ledger.unlink()

    gated = runner.invoke(cli.app, ["phase2", "gate", "--case-dir", str(case_dir)])
    receipt_path = case_dir / "phase2" / "gate-receipt.json"
    assert gated.exit_code != 0, gated.output
    assert not ledger.exists()
    assert not receipt_path.exists()
    assert coverage["decisions_sha256"] == sha256_hex(b"")
