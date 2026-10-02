"""Phase1 五元组由工具从已验包生成。夹具只用 example.test 与合成哈希。"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from apkscan.core.corpus import add_report
from apkscan.core.linkage import collapse_manifest_entries, rank_link_candidates
from apkscan.core.phase2.provenance import (
    HANDOFF_ROOT_ENV,
    Phase1Provenance,
    ProvenanceError,
    handoff_root,
    provenance_for_evidence,
)
from tests.phase2_fixtures import write_verified_package


def test_provenance_is_generated_from_verified_package(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "handoff"
    case_dir = root / "cases" / "synthetic"
    package = write_verified_package(
        case_dir, "pkg", case_id="CASE-SYN",
        leads=[{
            "category": "DOMAIN", "value": "api.example.test",
            "source_refs": [{"evidence_id": "ab" * 8, "scope": "case_evidence"}],
        }],
    )
    monkeypatch.setenv(HANDOFF_ROOT_ENV, str(root))
    assert handoff_root() == root.resolve()

    item = provenance_for_evidence(package / "case-package.json", "ab" * 8)
    payload = item.to_dict()
    assert payload["evidence_id"] == "ab" * 8
    assert payload["manifest_relpath"].endswith("case-package.json")
    assert not Path(payload["manifest_relpath"]).is_absolute()
    assert payload["report_relpath"] == "report.json"
    assert len(payload["package_id"]) == 64
    assert payload["package_id"] == json.loads(
        (package / "case-package.json").read_text(encoding="utf-8")
    )["package_id"]


def test_provenance_refuses_unconfigured_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case_dir = tmp_path / "case"
    package = write_verified_package(case_dir, "pkg", case_id="CASE-SYN")
    monkeypatch.delenv(HANDOFF_ROOT_ENV, raising=False)
    with pytest.raises(ProvenanceError):
        handoff_root()
    with pytest.raises(ProvenanceError):
        provenance_for_evidence(package / "case-package.json", "ab" * 8)


@pytest.mark.parametrize("relpath", ["/foo", "\\\\server\\share", "C:foo", "foo\\bar", "../x"])
def test_from_dict_rejects_windows_pseudo_relative_paths(relpath: str) -> None:
    with pytest.raises(ProvenanceError):
        Phase1Provenance.from_dict({
            "manifest_relpath": relpath,
            "package_id": "ab" * 32,
            "manifest_sha256": "cd" * 32,
            "report_relpath": "report.json",
            "evidence_id": "ab" * 8,
        })


def test_provenance_refuses_unknown_evidence_and_tampered_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "handoff"
    case_dir = root / "cases" / "synthetic"
    package = write_verified_package(
        case_dir, "pkg", case_id="CASE-SYN",
        leads=[{
            "category": "DOMAIN", "value": "api.example.test",
            "source_refs": [{"evidence_id": "ab" * 8, "scope": "case_evidence"}],
        }],
    )
    monkeypatch.setenv(HANDOFF_ROOT_ENV, str(root))
    with pytest.raises(ProvenanceError):
        provenance_for_evidence(package / "case-package.json", "cd" * 8)
    report = package / "report.json"
    report.write_text(report.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(ProvenanceError):
        provenance_for_evidence(package / "case-package.json", "ab" * 8)


def test_provenance_ignores_unregistered_report_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "handoff"
    case_dir = root / "cases" / "synthetic"
    package = write_verified_package(
        case_dir, "pkg", case_id="CASE-SYN", report_name="named-report.json",
        leads=[{
            "category": "DOMAIN", "value": "api.example.test",
            "source_refs": [{"evidence_id": "ab" * 8, "scope": "case_evidence"}],
        }],
    )
    monkeypatch.setenv(HANDOFF_ROOT_ENV, str(root))
    (package / "report.json").write_text('{"leads":[]}', encoding="utf-8")
    item = provenance_for_evidence(package / "case-package.json", "ab" * 8)
    assert item.report_relpath == "named-report.json"


def test_corpus_add_cites_package_without_manual_case(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    package = write_verified_package(
        case_dir, "pkg", case_id="CASE-SYN",
        leads=[{"category": "DOMAIN", "value": "api.example.test"}],
    )
    manifest = json.loads((package / "case-package.json").read_text(encoding="utf-8"))
    report = json.loads((package / "report.json").read_text(encoding="utf-8"))
    raw = (package / "report.json").read_text(encoding="utf-8")
    corpus = tmp_path / "corpus"

    result = add_report(
        corpus, report, raw, case_id=manifest["case_id"], package_id=manifest["package_id"]
    )
    assert result["case_id"] == "CASE-SYN"
    assert result["package_ids"] == [manifest["package_id"]]

    from apkscan.core.corpus import load_materialized_manifest

    rows = load_materialized_manifest(corpus)
    assert rows[0]["case_id"] == "CASE-SYN"
    assert rows[0]["package_ids"] == [manifest["package_id"]]
    collapsed = collapse_manifest_entries(rows)
    assert collapsed[0].case_ids == ("CASE-SYN",)
    assert collapsed[0].revisions[0].package_ids == (manifest["package_id"],)
    ranked = rank_link_candidates(rows)
    assert ranked["same_sample_case_links"] == []
    assert ranked["candidates"] == []


def test_second_ingest_merges_package_id_instead_of_replacing(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    package = write_verified_package(
        case_dir, "pkg", case_id="CASE-SYN",
        leads=[{"category": "DOMAIN", "value": "api.example.test"}],
    )
    manifest = json.loads((package / "case-package.json").read_text(encoding="utf-8"))
    report = json.loads((package / "report.json").read_text(encoding="utf-8"))
    raw = (package / "report.json").read_text(encoding="utf-8")
    corpus = tmp_path / "corpus"
    first = "a" * 64
    second = manifest["package_id"]

    added = add_report(corpus, report, raw, case_id="CASE-SYN", package_id=first)
    again = add_report(corpus, report, raw, case_id="CASE-SYN", package_id=second)

    assert added["added"] is True
    assert again["added"] is False
    assert again["package_ids"] == sorted({first, second})
    from apkscan.core.corpus import load_materialized_manifest, reindex

    assert load_materialized_manifest(corpus)[0]["package_ids"] == sorted({first, second})
    assert reindex(corpus)[0]["package_ids"] == sorted({first, second})


def test_second_ingest_drops_illegal_historical_package_ids(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    package = write_verified_package(
        case_dir, "pkg", case_id="CASE-SYN",
        leads=[{"category": "DOMAIN", "value": "api.example.test"}],
    )
    manifest = json.loads((package / "case-package.json").read_text(encoding="utf-8"))
    report = json.loads((package / "report.json").read_text(encoding="utf-8"))
    raw = (package / "report.json").read_text(encoding="utf-8")
    corpus = tmp_path / "corpus"
    legal = "a" * 64
    add_report(corpus, report, raw, case_id="CASE-SYN", package_id=legal)

    from apkscan.core.corpus import load_materialized_manifest

    rows = load_materialized_manifest(corpus)
    rows[0]["package_ids"] = ["NOT-A-SHA", "AB" * 32, "abc", legal]
    manifest_path = corpus / "manifest.json"
    manifest_path.write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")

    again = add_report(corpus, report, raw, case_id="CASE-SYN", package_id=manifest["package_id"])
    expected = sorted({legal, manifest["package_id"]})
    assert again["package_ids"] == expected
    assert load_materialized_manifest(corpus)[0]["package_ids"] == expected


def test_inventory_uses_manifest_report_even_with_unregistered_legacy_file(tmp_path: Path) -> None:
    from apkscan.core.phase2.inventory import build_inventory
    case_dir = tmp_path / "case"
    package = write_verified_package(
        case_dir, "pkg", case_id="CASE-SYN", report_name="named-report.json",
        leads=[{"category": "DOMAIN", "value": "registered.example.test",
                "source_refs": [{"evidence_id": "ab" * 8, "scope": "case_evidence"}]}])
    (package / "report.json").write_text(json.dumps({
        "leads": [{"category": "DOMAIN", "value": "unregistered.example.test",
                   "source_refs": [{"evidence_id": "cd" * 8, "scope": "case_evidence"}]}],
        "endpoints": [], "findings": []}), encoding="utf-8")
    inventory = build_inventory(case_dir)
    assert not inventory.issues
    assert {c.report_relpath for c in inventory.candidates} == {"named-report.json"}
    assert {c.display_value for c in inventory.candidates} == {"registered.example.test"}


def test_inventory_binds_loaded_report_bytes_to_verified_manifest(tmp_path: Path, monkeypatch) -> None:
    from apkscan.core.phase2 import inventory as module
    case_dir = tmp_path / "case"
    write_verified_package(case_dir, "pkg", case_id="CASE-SYN", leads=[
        {"category": "DOMAIN", "value": "registered.example.test",
         "source_refs": [{"evidence_id": "ab" * 8, "scope": "case_evidence"}]}])
    original = module._read_json_bounded
    def read_snapshot(path, *args):
        payload, raw = original(path, *args)
        if path.name == "report.json":
            payload["leads"][0]["value"] = "changed.example.test"
            raw = json.dumps(payload).encode()
        return payload, raw
    monkeypatch.setattr(module, "_read_json_bounded", read_snapshot)
    inventory = module.build_inventory(case_dir)
    assert "report_snapshot_hash_mismatch" in {issue.code for issue in inventory.issues}
    assert not inventory.packages and not inventory.candidates
