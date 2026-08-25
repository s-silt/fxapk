"""P1 corpus catalog: stable case ids, many-to-many binding and quarantine."""

from __future__ import annotations

import json
import multiprocessing
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkscan import cli
from apkscan.core import corpus
from apkscan.core import corpus_catalog as catalog


runner = CliRunner()


def _concurrent_bind_worker(
    corpus_root: str,
    report: dict,
    raw: str,
    case_id: str,
    start: object,
) -> None:
    start.wait()  # type: ignore[attr-defined]
    corpus.add_report(corpus_root, report, raw, case_id=case_id)


def _report(*, sha: str = "sample-a", note: str = "") -> dict:
    return {
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
            "ruleset_digest": "rules-a",
            "note": note,
        },
    }


def _report_version(version: str, *, sha: str) -> dict:
    report = _report(sha=sha)
    report["meta"]["tool_version"] = version
    return report


def _raw(report: dict) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2)


def _write_manifest_fixture(root: Path, entries: list[dict]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    corpus.manifest_path(root).write_text(
        "".join(
            json.dumps(entry, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"
            for entry in entries
        ),
        encoding="utf-8",
    )


def _downgrade_to_true_legacy_manifest(root: Path, case_id: str) -> None:
    [entry] = corpus.load_manifest(root)
    entry["case_id"] = case_id
    for field in (
        "case_ids",
        "record_state",
        "record_state_reason",
        "catalog_authority_materialized",
        "ingest_sequence",
    ):
        entry.pop(field, None)
    _write_manifest_fixture(root, [entry])
    path = catalog.catalog_path(root)
    if path.exists():
        path.unlink()


def test_normalize_case_id_is_explicit_and_stable() -> None:
    assert catalog.normalize_case_id("  case-2026-001  ") == "case-2026-001"
    assert catalog.normalize_case_id("\u3000case-e\u0301\u3000") == "case-é"
    with pytest.raises(ValueError, match="不能为空"):
        catalog.normalize_case_id("   ")
    with pytest.raises(ValueError, match="控制字符"):
        catalog.normalize_case_id("case\nother")
    for deceptive in (
        "case\u0085other",
        "case\u202eother",
        "case\u200bother",
        "case\ud800other",
    ):
        with pytest.raises(ValueError, match="控制字符|不可见格式字符|代理码位"):
            catalog.normalize_case_id(deceptive)


def test_same_report_can_bind_multiple_cases_without_losing_first(tmp_path: Path) -> None:
    report = _report()
    raw = _raw(report)

    first = corpus.add_report(tmp_path, report, raw, case_id="case-a")
    second = corpus.add_report(tmp_path, report, raw, case_id="case-b")

    assert first["added"] is True
    assert second["added"] is False
    assert second["case_bound"] is True
    [entry] = corpus.load_manifest(tmp_path)
    assert entry["case_ids"] == ["case-a", "case-b"]
    [catalog_entry] = catalog.load_catalog(tmp_path)
    assert catalog_entry["case_ids"] == ["case-a", "case-b"]


def test_add_rejects_report_dict_raw_text_mismatch_before_any_write(
    tmp_path: Path,
) -> None:
    root = tmp_path / "corpus-does-not-exist"
    report = _report(note="indexed-object")
    different_raw = _raw(_report(note="stored-object"))

    with pytest.raises(ValueError, match="raw_text.*不一致"):
        corpus.add_report(root, report, different_raw, case_id="case-a")

    assert not root.exists()


@pytest.mark.parametrize("token", ["NaN", "Infinity", "1e9999"])
def test_add_rejects_nonfinite_raw_json_before_any_write(
    tmp_path: Path,
    token: str,
) -> None:
    root = tmp_path / "corpus-does-not-exist"
    report = _report()
    raw = _raw(report)[:-1] + f', "nonfinite": {token}}}'

    with pytest.raises(ValueError, match="JSON|浮点"):
        corpus.add_report(root, report, raw, case_id="case-a")

    assert not root.exists()


def test_new_reports_get_unique_catalog_ingest_sequences_without_case_binding(
    tmp_path: Path,
) -> None:
    first = _report(sha="sample-a")
    second = _report(sha="sample-b")

    corpus.add_report(tmp_path, first, _raw(first))
    corpus.add_report(tmp_path, second, _raw(second))

    rows = catalog.load_catalog_strict(tmp_path)
    assert sorted(row["ingest_sequence"] for row in rows) == [1, 2]
    projected = corpus.load_materialized_manifest(tmp_path)
    assert {
        row["sample_sha256"]: row["ingest_sequence"] for row in projected
    } == {"sample-a": 1, "sample-b": 2}


def test_duplicate_catalog_ingest_sequence_is_corruption_and_refuses_write(
    tmp_path: Path,
) -> None:
    first = _report(sha="sample-a")
    second = _report(sha="sample-b")
    corpus.add_report(tmp_path, first, _raw(first))
    corpus.add_report(tmp_path, second, _raw(second))
    path = catalog.catalog_path(tmp_path)
    rows = catalog.load_catalog_strict(tmp_path)
    rows[1]["ingest_sequence"] = rows[0]["ingest_sequence"]
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    before = path.read_bytes()

    with pytest.raises(catalog.CatalogCorruptError, match="ingest_sequence"):
        catalog.load_catalog_strict(tmp_path)
    with pytest.raises(catalog.CatalogCorruptError, match="ingest_sequence"):
        corpus.add_report(tmp_path, _report(sha="sample-c"), _raw(_report(sha="sample-c")))

    assert path.read_bytes() == before


def test_catalog_save_rejects_nonfinite_extension_without_rewriting(
    tmp_path: Path,
) -> None:
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report), case_id="case-a")
    rows, revision = catalog.load_catalog_snapshot(tmp_path)
    path = catalog.catalog_path(tmp_path)
    before = path.read_bytes()
    rows[0]["extension"] = float("nan")

    with pytest.raises(ValueError, match="JSON compliant"):
        catalog.save_catalog(tmp_path, rows, expected_revision=revision)

    assert path.read_bytes() == before


def test_catalog_read_rejects_overflowed_json_float(tmp_path: Path) -> None:
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report), case_id="case-a")
    path = catalog.catalog_path(tmp_path)
    [row] = catalog.load_catalog_strict(tmp_path)
    encoded = json.dumps(row, ensure_ascii=False)
    path.write_text(encoded[:-1] + ', "overflow": 1e9999}\n', encoding="utf-8")

    valid, diagnostics = catalog.read_catalog(tmp_path)

    assert valid == []
    assert diagnostics and "non-finite" in str(diagnostics[0]["reason"])
    with pytest.raises(catalog.CatalogCorruptError):
        catalog.load_catalog_strict(tmp_path)


def test_second_case_binding_preserves_legacy_manifest_case_id(tmp_path: Path) -> None:
    report = _report()
    raw = _raw(report)
    corpus.add_report(tmp_path, report, raw)
    _downgrade_to_true_legacy_manifest(tmp_path, "legacy-case")

    result = corpus.add_report(tmp_path, report, raw, case_id="case-b")

    assert result["case_bound"] is True
    [stored] = catalog.load_catalog(tmp_path)
    assert stored["case_ids"] == ["case-b", "legacy-case"]
    rebuilt = corpus.reindex(tmp_path)
    assert rebuilt[0]["case_ids"] == ["case-b", "legacy-case"]


def test_same_key_different_report_bytes_is_content_conflict(tmp_path: Path) -> None:
    original = _report(note="first")
    changed = _report(note="changed")
    corpus.add_report(tmp_path, original, _raw(original), case_id="case-a")

    result = corpus.add_report(tmp_path, changed, _raw(changed), case_id="case-b")

    assert result["added"] is False
    assert result["content_conflict"] is True
    [entry] = corpus.load_manifest(tmp_path)
    assert entry["case_ids"] == ["case-a"]


def test_new_key_target_path_unreadable_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report = _report()
    raw = _raw(report)
    target = tmp_path / str(corpus.manifest_entry(report)["report_path"])
    target.parent.mkdir(parents=True)
    original_bytes = b"pre-existing-evidence"
    target.write_bytes(original_bytes)
    original_read_bytes = Path.read_bytes

    def guarded_read_bytes(path: Path) -> bytes:
        if path.resolve() == target.resolve():
            raise OSError("simulated OneDrive placeholder")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)

    result = corpus.add_report(tmp_path, report, raw, case_id="case-a")

    assert result["added"] is False
    assert result["collision"] is True
    assert result["content_conflict"] is True
    assert result["conflict_reason"] == "target_report_unreadable"
    with target.open("rb") as stream:
        assert stream.read() == original_bytes
    assert not corpus.manifest_path(tmp_path).exists()


def test_preexisting_identical_report_is_adopted_without_rewrite(tmp_path: Path) -> None:
    report = _report()
    raw = _raw(report)
    target = tmp_path / str(corpus.manifest_entry(report)["report_path"])
    target.parent.mkdir(parents=True)
    target.write_bytes(raw.encode("utf-8"))
    before = target.stat()

    result = corpus.add_report(tmp_path, report, raw, case_id="case-a")

    after = target.stat()
    assert result["added"] is True
    assert target.read_bytes() == raw.encode("utf-8")
    assert after.st_mtime_ns == before.st_mtime_ns
    assert after.st_ino == before.st_ino


def test_exclusive_create_race_never_overwrites_different_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report = _report()
    raw = _raw(report)
    target = tmp_path / str(corpus.manifest_entry(report)["report_path"])
    competing = b"competing-evidence"

    def competing_create(path: Path, _data: bytes) -> bool:
        assert path == target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(competing)
        return False

    monkeypatch.setattr(corpus, "_create_report_exclusive", competing_create)

    result = corpus.add_report(tmp_path, report, raw, case_id="case-a")

    assert result["added"] is False
    assert result["content_conflict"] is True
    assert result["conflict_reason"] == "target_report_bytes_differ"
    assert target.read_bytes() == competing
    assert not corpus.manifest_path(tmp_path).exists()
    assert not catalog.catalog_path(tmp_path).exists()


def test_missing_revision_anchors_are_rejected_before_any_corpus_write(
    tmp_path: Path,
) -> None:
    root = tmp_path / "must-remain-absent"
    report = _report()
    report["meta"].pop("tool_version")
    report["meta"].pop("ruleset_digest")

    with pytest.raises(ValueError, match="tool_version/ruleset_digest"):
        corpus.add_report(root, report, _raw(report), case_id="case-a")

    assert not root.exists()


def test_duplicate_binding_fails_closed_when_stored_report_was_tampered(tmp_path: Path) -> None:
    report = _report()
    raw = _raw(report)
    first = corpus.add_report(tmp_path, report, raw, case_id="case-a")
    stored = tmp_path / str(first["report_path"])
    stored.write_text("{}", encoding="utf-8")

    result = corpus.add_report(tmp_path, report, raw, case_id="case-b")

    assert result["content_conflict"] is True
    assert result["conflict_reason"] == "stored_report_hash_mismatch"
    [entry] = corpus.load_manifest(tmp_path)
    assert entry["case_ids"] == ["case-a"]


def test_duplicate_binding_fails_closed_when_stored_report_is_missing(tmp_path: Path) -> None:
    report = _report()
    raw = _raw(report)
    first = corpus.add_report(tmp_path, report, raw, case_id="case-a")
    (tmp_path / str(first["report_path"])).unlink()

    result = corpus.add_report(tmp_path, report, raw, case_id="case-b")

    assert result["content_conflict"] is True
    assert result["conflict_reason"] == "stored_report_missing_or_unreadable"
    [entry] = corpus.load_manifest(tmp_path)
    assert entry["case_ids"] == ["case-a"]


def test_duplicate_binding_fails_closed_when_recorded_hash_is_missing(tmp_path: Path) -> None:
    report = _report()
    raw = _raw(report)
    corpus.add_report(tmp_path, report, raw, case_id="case-a")
    [entry] = corpus.load_manifest(tmp_path)
    entry.pop("report_bytes_sha256", None)
    _write_manifest_fixture(tmp_path, [entry])

    result = corpus.add_report(tmp_path, report, raw, case_id="case-b")

    assert result["content_conflict"] is True
    assert result["conflict_reason"] == "stored_report_hash_missing"
    [catalog_entry] = catalog.load_catalog(tmp_path)
    assert catalog_entry["case_ids"] == ["case-a"]


def test_legacy_manifest_case_id_migration_is_dry_run_by_default(tmp_path: Path) -> None:
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report), case_id=None)
    _downgrade_to_true_legacy_manifest(tmp_path, "legacy-case")

    planned = catalog.migrate_legacy_case_ids(tmp_path, apply=False)
    assert planned["would_migrate"] == 1
    assert not catalog.catalog_path(tmp_path).exists()

    applied = catalog.migrate_legacy_case_ids(tmp_path, apply=True)
    assert applied["migrated"] == 1
    [stored] = catalog.load_catalog(tmp_path)
    assert stored["case_ids"] == ["legacy-case"]


def _run_cli(*args: str) -> str:
    result = runner.invoke(cli.app, list(args))
    assert result.exit_code == 0, result.output
    return result.output


def test_migrate_catalog_always_states_it_cannot_be_undone(tmp_path: Path) -> None:
    """★ 不可逆声明必须同时出现在 dry-run 与真写两处输出里。

    2026-08-12 在语料库副本上演练发现：迁移后 ``corpus restore`` 撤不掉它——catalog 是
    案件绑定真源、manifest 只是派生索引，恢复旧快照会被立刻重新物化；删 catalog.jsonl
    则整库 fail-closed。唯一有效的回滚是整目录备份。决定要不要 ``--apply`` 的人必须在
    同一屏看到这件事，所以 dry-run 那次尤其不能省。
    """
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report), case_id=None)
    _downgrade_to_true_legacy_manifest(tmp_path, "legacy-case")

    preview = _run_cli("corpus", "migrate-catalog", "--corpus", str(tmp_path))
    assert "整目录备份" in preview
    assert "corpus restore" in preview

    applied = _run_cli("corpus", "migrate-catalog", "--corpus", str(tmp_path), "--apply")
    assert "整目录备份" in applied


def test_restore_warns_when_snapshot_predates_the_catalog(tmp_path: Path) -> None:
    """★ 跨 catalog 边界的回滚会「报成功却没生效」，必须出警告。

    restore 在这种情形下照常回 ``applied/restored_entries``，读的人据此以为已退回旧状态；
    实际 catalog 仍在，manifest 转头被重新物化回去。**报成功却没生效比明确失败更危险**。
    """
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report), case_id=None)
    _downgrade_to_true_legacy_manifest(tmp_path, "legacy-case")
    catalog.migrate_legacy_case_ids(tmp_path, apply=True)

    pre_catalog = [
        path
        for path in corpus.list_snapshots(tmp_path)
        if not any(
            catalog.has_catalog_era_projection(entry)
            for entry in corpus.load_manifest_file(path)
        )
    ]
    assert pre_catalog, "迁移应当留下一份 catalog 之前的快照"

    preview = _run_cli(
        "corpus", "restore", pre_catalog[0].name, "--corpus", str(tmp_path)
    )
    assert "catalog_boundary" in preview
    assert "整目录还原备份" in preview

    applied = _run_cli(
        "corpus", "restore", pre_catalog[0].name, "--corpus", str(tmp_path), "--apply"
    )
    assert "catalog_boundary" in applied


def test_restore_stays_quiet_when_no_catalog_boundary_is_crossed(tmp_path: Path) -> None:
    """反向：库还没进 catalog 时代，这条警告不得出现——否则它会退化成人人略过的噪音。"""
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report), case_id=None)
    _downgrade_to_true_legacy_manifest(tmp_path, "legacy-case")
    corpus.snapshot_manifest(tmp_path)

    [snapshot] = corpus.list_snapshots(tmp_path)
    preview = _run_cli("corpus", "restore", snapshot.name, "--corpus", str(tmp_path))
    assert "catalog_boundary" not in preview


def test_quarantined_records_are_hidden_by_default(tmp_path: Path) -> None:
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report), case_id="case-a")
    key = corpus.manifest_key(corpus.load_manifest(tmp_path)[0])
    catalog.set_record_state(
        tmp_path,
        key,
        state=catalog.RECORD_QUARANTINED,
        reason="shadowed development build",
    )
    corpus.refresh_catalog_fields(tmp_path)

    entries = corpus.load_manifest(tmp_path)
    assert corpus.visible_entries(entries) == []
    assert len(corpus.visible_entries(entries, include_quarantined=True)) == 1
    assert entries[0]["record_state_reason"] == "shadowed development build"


def test_strict_query_joins_catalog_after_quarantine_refresh_crash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report), case_id="case-a")
    [manifest_before] = corpus.load_manifest(tmp_path)
    assert manifest_before["record_state"] == catalog.RECORD_ACTIVE
    def crash_refresh(_root: object) -> list[dict]:
        raise OSError("simulated refresh crash")

    monkeypatch.setattr(corpus, "refresh_catalog_fields", crash_refresh)
    # The named state API commits catalog truth before refreshing the derived
    # manifest.  Simulate a crash in that second phase.
    with pytest.raises(OSError, match="simulated refresh crash"):
        catalog.set_record_state(
            tmp_path,
            corpus.manifest_key(manifest_before),
            state=catalog.RECORD_QUARANTINED,
            reason="committed before derived refresh",
        )
    assert corpus.load_manifest(tmp_path)[0]["record_state"] == catalog.RECORD_ACTIVE

    materialized = corpus.load_materialized_manifest(tmp_path)
    assert materialized[0]["record_state"] == catalog.RECORD_QUARANTINED
    assert corpus.visible_entries(materialized) == []
    assert len(corpus.visible_entries(materialized, include_quarantined=True)) == 1

    hidden = runner.invoke(cli.app, ["corpus", "ls", "--corpus", str(tmp_path)])
    shown = runner.invoke(
        cli.app,
        ["corpus", "ls", "--include-quarantined", "--corpus", str(tmp_path)],
    )
    assert hidden.exit_code == 0 and json.loads(hidden.stdout)["count"] == 0
    assert shown.exit_code == 0 and json.loads(shown.stdout)["count"] == 1


def test_catalog_annotation_rejects_forged_legacy_manifest_alias(tmp_path: Path) -> None:
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report), case_id="real-case")
    [tampered] = corpus.load_manifest(tmp_path)
    tampered["case_id"] = "forged-case"
    tampered["case_ids"] = ["forged-case"]
    corpus.manifest_path(tmp_path).write_text(
        json.dumps(tampered, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    [materialized] = corpus.load_materialized_manifest(tmp_path)

    assert materialized["case_ids"] == ["real-case"]
    assert materialized["case_id"] == "real-case"


def test_missing_catalog_with_projected_case_facts_fails_closed(tmp_path: Path) -> None:
    report = _report()
    raw = _raw(report)
    corpus.add_report(tmp_path, report, raw, case_id="case-a")
    catalog.catalog_path(tmp_path).unlink()

    with pytest.raises(catalog.CatalogCorruptError, match="catalog"):
        corpus.load_materialized_manifest(tmp_path)
    with pytest.raises(catalog.CatalogCorruptError, match="catalog"):
        corpus.add_report(tmp_path, report, raw, case_id="case-b")

    result = runner.invoke(cli.app, ["corpus", "ls", "--corpus", str(tmp_path)])
    assert result.exit_code == 1
    assert "CatalogCorruptError" in result.stderr


def test_deleted_catalog_never_reactivates_quarantined_manifest_row(tmp_path: Path) -> None:
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report))
    key = corpus.manifest_key(corpus.load_manifest(tmp_path)[0])
    catalog.set_record_state(
        tmp_path,
        key,
        state=catalog.RECORD_QUARANTINED,
        reason="obsolete run",
    )
    assert corpus.load_manifest(tmp_path)[0]["record_state"] == catalog.RECORD_QUARANTINED
    catalog.catalog_path(tmp_path).unlink()

    result = runner.invoke(cli.app, ["corpus", "ls", "--corpus", str(tmp_path)])

    assert result.exit_code == 1
    assert "CatalogCorruptError" in result.stderr
    assert '"count"' not in result.stdout


def test_missing_catalog_row_for_one_key_fails_query_and_write_closed(tmp_path: Path) -> None:
    first = _report(sha="sample-a")
    second = _report(sha="sample-b")
    corpus.add_report(tmp_path, first, _raw(first), case_id="case-a")
    corpus.add_report(tmp_path, second, _raw(second), case_id="case-b")
    rows = catalog.load_catalog(tmp_path)
    surviving = [row for row in rows if row["sample_sha256"] == "sample-b"]
    catalog.catalog_path(tmp_path).write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            for row in surviving
        ),
        encoding="utf-8",
    )

    with pytest.raises(catalog.CatalogCorruptError, match="主键缺失"):
        corpus.load_materialized_manifest(tmp_path)
    with pytest.raises(catalog.CatalogCorruptError, match="主键缺失"):
        corpus.add_report(tmp_path, first, _raw(first), case_id="case-c")


def test_bad_manifest_line_refuses_add_and_refresh_without_rewrite(tmp_path: Path) -> None:
    report = _report(sha="sample-a")
    corpus.add_report(tmp_path, report, _raw(report), case_id="case-a")
    manifest = corpus.manifest_path(tmp_path)
    with manifest.open("ab") as stream:
        stream.write(b"not-json\n")
    before = manifest.read_bytes()
    catalog_before = catalog.catalog_path(tmp_path).read_bytes()
    other = _report(sha="sample-b")

    with pytest.raises(corpus.ManifestCorruptError, match="manifest"):
        corpus.add_report(tmp_path, other, _raw(other), case_id="case-b")
    with pytest.raises(corpus.ManifestCorruptError, match="manifest"):
        corpus.refresh_catalog_fields(tmp_path)

    assert manifest.read_bytes() == before
    assert catalog.catalog_path(tmp_path).read_bytes() == catalog_before
    assert not (tmp_path / str(corpus.manifest_entry(other)["report_path"])).exists()


def test_verify_manifest_corruption_is_structured_and_nonzero(tmp_path: Path) -> None:
    corpus.manifest_path(tmp_path).write_text("{bad json}\n", encoding="utf-8")

    with pytest.raises(corpus.ManifestCorruptError):
        corpus.verify_reports(tmp_path)
    result = runner.invoke(cli.app, ["corpus", "verify", "--corpus", str(tmp_path)])

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["counts"]["manifest_corrupt"] == 1


def test_semantically_invalid_manifest_fails_all_strict_cli_paths(tmp_path: Path) -> None:
    entry = corpus.manifest_entry(_report())
    entry["case_id"] = "case\u0000forged"
    _write_manifest_fixture(tmp_path, [entry])

    with pytest.raises(corpus.ManifestCorruptError):
        corpus.load_materialized_manifest(tmp_path)
    with pytest.raises(corpus.ManifestCorruptError):
        corpus.verify_reports(tmp_path)
    with pytest.raises(corpus.ManifestCorruptError):
        corpus.reindex(tmp_path)

    for command in (
        ["corpus", "ls", "--corpus", str(tmp_path)],
        ["corpus", "verify", "--corpus", str(tmp_path)],
        ["corpus", "reindex", "--corpus", str(tmp_path)],
        ["corpus", "backfill-hash", "--corpus", str(tmp_path)],
    ):
        result = runner.invoke(cli.app, command)
        assert result.exit_code == 1, result.output
        assert "Traceback" not in result.output


def test_empty_object_manifest_is_corrupt_not_an_active_ghost(tmp_path: Path) -> None:
    corpus.manifest_path(tmp_path).write_text("{}\n", encoding="utf-8")

    with pytest.raises(corpus.ManifestCorruptError, match="sample_sha256"):
        corpus.load_materialized_manifest(tmp_path)


def test_verify_fails_when_catalog_authority_is_missing(tmp_path: Path) -> None:
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report), case_id="case-a")
    catalog.catalog_path(tmp_path).unlink()

    result = runner.invoke(cli.app, ["corpus", "verify", "--corpus", str(tmp_path)])

    assert result.exit_code == 1
    assert json.loads(result.stdout)["counts"]["catalog_corrupt"] == 1


def test_public_manifest_save_requires_revision_and_rejects_stale_snapshot(
    tmp_path: Path,
) -> None:
    first = _report(sha="sample-a")
    second = _report(sha="sample-b")
    corpus.add_report(tmp_path, first, _raw(first), case_id="case-a")
    stale_rows, stale_revision = corpus.load_manifest_snapshot(tmp_path)

    with pytest.raises(corpus.ManifestStaleError, match="expected_revision"):
        corpus.save_manifest(tmp_path, stale_rows)

    corpus.add_report(tmp_path, second, _raw(second), case_id="case-b")
    before = corpus.manifest_path(tmp_path).read_bytes()
    with pytest.raises(corpus.ManifestStaleError, match="changed since snapshot"):
        corpus.save_manifest(
            tmp_path,
            stale_rows,
            expected_revision=stale_revision,
        )
    assert corpus.manifest_path(tmp_path).read_bytes() == before


def test_corrupt_catalog_query_never_falls_back_to_active_manifest(tmp_path: Path) -> None:
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report), case_id="case-a")
    catalog.catalog_path(tmp_path).write_text("not-json\n", encoding="utf-8")

    result = runner.invoke(cli.app, ["corpus", "ls", "--corpus", str(tmp_path)])

    assert result.exit_code == 1
    assert "CatalogCorruptError" in result.stderr
    assert '"count"' not in result.stdout


def test_corpus_ls_requires_opt_in_to_show_quarantined(tmp_path: Path) -> None:
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report), case_id="case-a")
    key = corpus.manifest_key(corpus.load_manifest(tmp_path)[0])
    catalog.set_record_state(
        tmp_path,
        key,
        state=catalog.RECORD_QUARANTINED,
        reason="obsolete development run",
    )
    corpus.refresh_catalog_fields(tmp_path)

    hidden = runner.invoke(cli.app, ["corpus", "ls", "--corpus", str(tmp_path)])
    shown = runner.invoke(
        cli.app,
        ["corpus", "ls", "--include-quarantined", "--corpus", str(tmp_path)],
    )

    assert json.loads(hidden.stdout)["count"] == 0
    assert json.loads(shown.stdout)["count"] == 1


def test_corpus_add_cli_reports_case_binding_separately_from_skip(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(_raw(_report()), encoding="utf-8")
    corpus_root = tmp_path / "external-corpus"
    first = runner.invoke(
        cli.app,
        ["corpus", "add", str(report_path), "--case", "case-a", "--corpus", str(corpus_root)],
    )
    second = runner.invoke(
        cli.app,
        ["corpus", "add", str(report_path), "--case", "case-b", "--corpus", str(corpus_root)],
    )

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    payload = json.loads(second.stdout)
    assert payload["added"] == 0
    assert payload["case_bound"] == 1
    assert payload["skipped"] == 0


def test_corpus_add_cli_reports_content_conflict_not_benign_skip(tmp_path: Path) -> None:
    original_path = tmp_path / "original.json"
    changed_path = tmp_path / "changed.json"
    original_path.write_text(_raw(_report(note="first")), encoding="utf-8")
    changed_path.write_text(_raw(_report(note="changed")), encoding="utf-8")
    corpus_root = tmp_path / "external-corpus"
    runner.invoke(
        cli.app,
        ["corpus", "add", str(original_path), "--case", "case-a", "--corpus", str(corpus_root)],
    )

    result = runner.invoke(
        cli.app,
        ["corpus", "add", str(changed_path), "--case", "case-b", "--corpus", str(corpus_root)],
    )

    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["conflicts"] == 1
    assert payload["failed"] == 1
    assert payload["skipped"] == 0
    assert "同主键内容冲突" in result.stderr


def test_corpus_add_cli_rejects_nonstandard_json_constants(tmp_path: Path) -> None:
    report_path = tmp_path / "nan-report.json"
    report_path.write_text(_raw(_report())[:-1] + ', "nonstandard": NaN}', encoding="utf-8")
    corpus_root = tmp_path / "external-corpus"

    result = runner.invoke(
        cli.app,
        ["corpus", "add", str(report_path), "--case", "case-a", "--corpus", str(corpus_root)],
    )

    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["failed"] == 1
    assert payload["added"] == 0
    assert not corpus.manifest_path(corpus_root).exists()


def test_corpus_add_cli_mixed_batch_returns_nonzero_but_keeps_valid_add(
    tmp_path: Path,
) -> None:
    good = tmp_path / "good.json"
    bad = tmp_path / "bad.json"
    good.write_text(_raw(_report()), encoding="utf-8")
    bad.write_text("{bad json}", encoding="utf-8")
    corpus_root = tmp_path / "external-corpus"

    result = runner.invoke(
        cli.app,
        [
            "corpus", "add", str(good), str(bad),
            "--case", "case-a", "--corpus", str(corpus_root),
        ],
    )

    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["added"] == 1
    assert payload["failed"] == 1
    assert len(corpus.load_materialized_manifest(corpus_root)) == 1


def test_corpus_add_cli_idempotent_skip_remains_success(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(_raw(_report()), encoding="utf-8")
    corpus_root = tmp_path / "external-corpus"
    args = ["corpus", "add", str(report_path), "--corpus", str(corpus_root)]

    assert runner.invoke(cli.app, args).exit_code == 0
    duplicate = runner.invoke(cli.app, args)

    assert duplicate.exit_code == 0, duplicate.output
    payload = json.loads(duplicate.stdout)
    assert payload["skipped"] == 1 and payload["failed"] == 0


def test_version_audit_and_quarantine_are_explicit_and_non_destructive(tmp_path: Path) -> None:
    dev = _report_version("0.10.0.dev0", sha="sample-dev")
    legacy = _report_version("1.4.0", sha="sample-legacy")
    stable = _report_version("1.5.4", sha="sample-stable")
    unknown = _report_version("not-a-version", sha="sample-unknown")
    corpus.add_report(tmp_path, dev, _raw(dev), case_id="case-a")
    corpus.add_report(tmp_path, legacy, _raw(legacy), case_id="case-a")
    corpus.add_report(tmp_path, stable, _raw(stable), case_id="case-a")
    corpus.add_report(tmp_path, unknown, _raw(unknown), case_id="case-a")

    audit = corpus.audit_versions(corpus.load_manifest(tmp_path))
    assert audit["0.10.0.dev0"]["development"] is True
    assert audit["1.5.4"]["development"] is False
    assert audit["0.10.0.dev0"]["version_state"] == "development"
    assert audit["1.4.0"]["version_state"] == "legacy_release"
    assert audit["1.5.4"]["version_state"] == "current_release"
    assert audit["not-a-version"]["version_state"] == "unknown"
    assert audit["1.5.4"]["version_state_basis"] == "highest_stable_release_in_corpus"

    dry = catalog.quarantine_tool_versions(
        tmp_path,
        ["0.10.0.dev0"],
        reason="shadowed development build",
        apply=False,
    )
    assert dry["would_quarantine"] == 1
    assert all(entry.get("record_state") != "quarantined" for entry in corpus.load_manifest(tmp_path))

    applied = catalog.quarantine_tool_versions(
        tmp_path,
        ["0.10.0.dev0"],
        reason="shadowed development build",
        apply=True,
    )
    assert applied["quarantined"] == 1
    entries = corpus.load_manifest(tmp_path)
    dev_entry = next(entry for entry in entries if entry["tool_version"] == "0.10.0.dev0")
    assert (tmp_path / dev_entry["report_path"]).is_file()
    assert len(corpus.visible_entries(entries)) == 3


def test_catalog_bad_line_is_auditable(caplog: pytest.LogCaptureFixture, tmp_path: Path) -> None:
    catalog.catalog_path(tmp_path).write_text("not-json\n", encoding="utf-8")

    assert catalog.load_catalog(tmp_path) == []
    assert "第 1 行损坏：不是合法 JSON" in caplog.text


def test_version_audit_and_quarantine_cli_require_explicit_apply(tmp_path: Path) -> None:
    dev = _report_version("0.10.0.dev0", sha="sample-dev")
    corpus.add_report(tmp_path, dev, _raw(dev), case_id="case-a")

    audit = runner.invoke(cli.app, ["corpus", "versions", "--corpus", str(tmp_path)])
    dry = runner.invoke(
        cli.app,
        [
            "corpus", "quarantine-version", "0.10.0.dev0",
            "--reason", "shadowed development build", "--corpus", str(tmp_path),
        ],
    )

    assert audit.exit_code == 0, audit.output
    audit_payload = json.loads(audit.stdout)
    assert audit_payload["versions"]["0.10.0.dev0"]["development"] is True
    assert audit_payload["version_state_basis"] == "highest_stable_release_in_corpus"
    assert dry.exit_code == 0, dry.output
    assert json.loads(dry.stdout)["applied"] is False
    assert corpus.load_manifest(tmp_path)[0]["record_state"] == "active"

    applied = runner.invoke(
        cli.app,
        [
            "corpus", "quarantine-version", "0.10.0.dev0",
            "--reason", "shadowed development build", "--apply",
            "--corpus", str(tmp_path),
        ],
    )
    assert applied.exit_code == 0, applied.output
    assert json.loads(applied.stdout)["quarantined"] == 1


def test_corrupt_catalog_refuses_bind_and_direct_save_without_changing_bytes(
    tmp_path: Path,
) -> None:
    path = catalog.catalog_path(tmp_path)
    path.write_bytes(b"not-json\n")
    before = path.read_bytes()
    key = ("sample-a", "1.5.4", "rules-a", "static")

    with pytest.raises(catalog.CatalogCorruptError):
        catalog.bind_case(tmp_path, key, "case-b")
    assert path.read_bytes() == before

    with pytest.raises(catalog.CatalogCorruptError):
        catalog.save_catalog(tmp_path, [])
    assert path.read_bytes() == before

    with pytest.raises(catalog.CatalogCorruptError):
        catalog.migrate_legacy_case_ids(tmp_path, apply=True)
    assert path.read_bytes() == before


def test_corrupt_catalog_refuses_quarantine_without_changing_bytes(tmp_path: Path) -> None:
    report = _report_version("0.10.0.dev0", sha="sample-dev")
    corpus.add_report(tmp_path, report, _raw(report), case_id="case-a")
    path = catalog.catalog_path(tmp_path)
    path.write_bytes(b"not-json\n")
    before = path.read_bytes()

    with pytest.raises(catalog.CatalogCorruptError):
        catalog.quarantine_tool_versions(
            tmp_path,
            ["0.10.0.dev0"],
            reason="shadowed development build",
            apply=True,
        )

    assert path.read_bytes() == before


def test_corpus_mutation_clis_report_corrupt_catalog_without_traceback(tmp_path: Path) -> None:
    corpus_root = tmp_path / "external-corpus"
    corpus_root.mkdir()
    catalog.catalog_path(corpus_root).write_bytes(b"not-json\n")
    report_path = tmp_path / "report.json"
    report_path.write_text(_raw(_report()), encoding="utf-8")
    inventory = tmp_path / "inventory.jsonl"
    inventory.write_text(
        json.dumps({"case_id": "case-a", "report_path": str(report_path)}) + "\n",
        encoding="utf-8",
    )
    commands = [
        ["corpus", "reindex", "--corpus", str(corpus_root)],
        ["corpus", "reconcile", str(inventory), "--corpus", str(corpus_root)],
        [
            "corpus", "quarantine-version", "1.5.4", "--reason", "audit",
            "--corpus", str(corpus_root),
        ],
        ["corpus", "migrate-catalog", "--corpus", str(corpus_root)],
    ]

    for command in commands:
        result = runner.invoke(cli.app, command)
        assert result.exit_code == 1, result.output
        # 断言异常**类型名**而非旧的 str(exc) 文案：错误串已按脱敏规则收敛成
        # 「<操作>失败：<路径>（<类型名>）」，异常消息不再外泄。
        assert "CatalogCorruptError" in result.stderr
        assert "not-json" not in result.stderr
        assert result.exception is not None
        assert result.exception.__class__.__name__ == "SystemExit"


def test_reindex_refuses_corrupt_catalog_without_rewriting_manifest(tmp_path: Path) -> None:
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report), case_id="case-a")
    manifest = corpus.manifest_path(tmp_path)
    manifest_before = manifest.read_bytes()
    catalog.catalog_path(tmp_path).write_bytes(b"not-json\n")

    with pytest.raises(catalog.CatalogCorruptError):
        corpus.reindex(tmp_path)

    assert manifest.read_bytes() == manifest_before


def test_manifest_restore_keeps_catalog_as_case_binding_authority(tmp_path: Path) -> None:
    report = _report()
    raw = _raw(report)
    corpus.add_report(tmp_path, report, raw, case_id="case-a")
    snapshot = corpus.snapshot_manifest(tmp_path)
    assert snapshot is not None
    corpus.add_report(tmp_path, report, raw, case_id="case-b")

    restored = corpus.restore_manifest(tmp_path, snapshot.name)

    assert restored["applied"] is True
    [entry] = corpus.load_manifest(tmp_path)
    assert entry["case_ids"] == ["case-a", "case-b"]
    assert entry["case_id"] is None


def test_manifest_restore_refuses_corrupt_catalog_before_writing(tmp_path: Path) -> None:
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report), case_id="case-a")
    snapshot = corpus.snapshot_manifest(tmp_path)
    assert snapshot is not None
    manifest_before = corpus.manifest_path(tmp_path).read_bytes()
    catalog.catalog_path(tmp_path).write_bytes(b"not-json\n")

    restored = corpus.restore_manifest(tmp_path, snapshot.name)

    assert restored["applied"] is False
    # 错误字段已收敛成异常类型名（脱敏规则：不外泄异常消息）。
    assert str(restored["error"]) == "CatalogCorruptError"
    assert corpus.manifest_path(tmp_path).read_bytes() == manifest_before


def test_concurrent_case_bindings_union_catalog_and_manifest(tmp_path: Path) -> None:
    report = _report()
    raw = _raw(report)
    corpus.add_report(tmp_path, report, raw, case_id="case-a")
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    processes = [
        context.Process(
            target=_concurrent_bind_worker,
            args=(str(tmp_path), report, raw, case_id, start),
        )
        for case_id in ("case-b", "case-c")
    ]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(15)
        assert process.exitcode == 0

    [catalog_entry] = catalog.load_catalog(tmp_path)
    assert catalog_entry["case_ids"] == ["case-a", "case-b", "case-c"]
    [manifest_entry] = corpus.load_manifest(tmp_path)
    assert manifest_entry["case_ids"] == ["case-a", "case-b", "case-c"]


def test_stale_catalog_save_cannot_erase_new_case_binding(tmp_path: Path) -> None:
    report = _report()
    raw = _raw(report)
    corpus.add_report(tmp_path, report, raw, case_id="case-a")
    stale_rows, stale_revision = catalog.load_catalog_snapshot(tmp_path)
    corpus.add_report(tmp_path, report, raw, case_id="case-b")

    with pytest.raises(catalog.CatalogStaleError):
        catalog.save_catalog(
            tmp_path,
            stale_rows,
            expected_revision=stale_revision,
        )

    [entry] = catalog.load_catalog(tmp_path)
    assert entry["case_ids"] == ["case-a", "case-b"]


def test_safe_bind_rejects_nonexistent_tampered_and_unhashed_records(
    tmp_path: Path,
) -> None:
    report = _report()
    result = corpus.add_report(tmp_path, report, _raw(report), case_id="case-a")
    key = tuple(result["key"])
    path = catalog.catalog_path(tmp_path)

    before = path.read_bytes()
    with pytest.raises(catalog.CatalogBindingError, match="不存在"):
        catalog.bind_case(tmp_path, ("missing", *key[1:]), "case-b")
    assert path.read_bytes() == before

    stored = tmp_path / str(result["report_path"])
    stored.write_text(_raw(report) + " ", encoding="utf-8")
    with pytest.raises(catalog.CatalogBindingError, match="哈希不一致"):
        catalog.bind_case(tmp_path, key, "case-b")
    assert path.read_bytes() == before

    stored.write_text(_raw(report), encoding="utf-8")
    [entry] = corpus.load_manifest(tmp_path)
    entry.pop("report_bytes_sha256", None)
    entry.pop("report_bytes_sha256_origin", None)
    _write_manifest_fixture(tmp_path, [entry])
    with pytest.raises(catalog.CatalogBindingError, match="记录哈希缺失"):
        catalog.bind_case(tmp_path, key, "case-b")
    assert path.read_bytes() == before


def test_safe_bind_and_state_preserve_true_legacy_case_without_sequence(
    tmp_path: Path,
) -> None:
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report))
    _downgrade_to_true_legacy_manifest(tmp_path, "legacy-case")
    key = corpus.manifest_key(corpus.load_manifest(tmp_path)[0])

    assert catalog.bind_case(tmp_path, key, "case-b") is True
    [bound] = corpus.load_materialized_manifest(tmp_path)
    assert bound["case_ids"] == ["case-b", "legacy-case"]
    assert bound["ingest_sequence"] is None

    catalog.set_record_state(
        tmp_path,
        key,
        state=catalog.RECORD_QUARANTINED,
        reason="explicit legacy quarantine",
    )
    [quarantined] = corpus.load_materialized_manifest(tmp_path)
    assert quarantined["case_ids"] == ["case-b", "legacy-case"]
    assert quarantined["record_state"] == catalog.RECORD_QUARANTINED


def test_quarantine_version_preserves_true_legacy_case(tmp_path: Path) -> None:
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report))
    _downgrade_to_true_legacy_manifest(tmp_path, "legacy-case")

    applied = catalog.quarantine_tool_versions(
        tmp_path,
        ["1.5.4"],
        reason="legacy release",
        apply=True,
    )

    assert applied["quarantined"] == 1
    [entry] = corpus.load_materialized_manifest(tmp_path)
    assert entry["case_ids"] == ["legacy-case"]
    assert entry["ingest_sequence"] is None


def test_state_api_rejects_nonexistent_and_tampered_reactivation(tmp_path: Path) -> None:
    report = _report()
    result = corpus.add_report(tmp_path, report, _raw(report), case_id="case-a")
    key = tuple(result["key"])
    catalog.set_record_state(
        tmp_path,
        key,
        state=catalog.RECORD_QUARANTINED,
        reason="initial quarantine",
    )
    path = catalog.catalog_path(tmp_path)
    before = path.read_bytes()

    with pytest.raises(catalog.CatalogBindingError, match="不存在"):
        catalog.set_record_state(
            tmp_path,
            ("missing", *key[1:]),
            state=catalog.RECORD_QUARANTINED,
            reason="must not preseed",
        )
    assert path.read_bytes() == before

    stored = tmp_path / str(result["report_path"])
    stored.write_text(_raw(report) + " ", encoding="utf-8")
    with pytest.raises(catalog.CatalogBindingError, match="哈希不一致"):
        catalog.set_record_state(
            tmp_path,
            key,
            state=catalog.RECORD_ACTIVE,
            reason="reviewed for reactivation",
        )
    assert path.read_bytes() == before


def test_public_catalog_save_cannot_roll_back_non_derived_facts(tmp_path: Path) -> None:
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report), case_id="case-a")
    key = corpus.manifest_key(corpus.load_manifest(tmp_path)[0])
    catalog.set_record_state(
        tmp_path,
        key,
        state=catalog.RECORD_QUARANTINED,
        reason="explicit quarantine",
    )
    path = catalog.catalog_path(tmp_path)

    for mutation in ("case", "state", "sequence", "delete"):
        rows, revision = catalog.load_catalog_snapshot(tmp_path)
        before = path.read_bytes()
        if mutation == "case":
            rows[0]["case_ids"] = []
        elif mutation == "state":
            rows[0]["record_state"] = catalog.RECORD_ACTIVE
            rows[0]["record_state_reason"] = None
        elif mutation == "sequence":
            rows[0]["ingest_sequence"] = int(rows[0]["ingest_sequence"]) + 1
        else:
            rows = []

        with pytest.raises(catalog.CatalogFactRegressionError):
            catalog.save_catalog(tmp_path, rows, expected_revision=revision)

        assert path.read_bytes() == before


def test_public_catalog_save_cannot_append_case_or_preseed_key(tmp_path: Path) -> None:
    report = _report()
    result = corpus.add_report(tmp_path, report, _raw(report), case_id="case-a")
    stored = tmp_path / str(result["report_path"])
    stored.write_text(_raw(report) + " ", encoding="utf-8")
    path = catalog.catalog_path(tmp_path)

    rows, revision = catalog.load_catalog_snapshot(tmp_path)
    before = path.read_bytes()
    rows[0]["case_ids"].append("case-b")
    with pytest.raises(catalog.CatalogFactRegressionError, match="bind_case"):
        catalog.save_catalog(tmp_path, rows, expected_revision=revision)
    assert path.read_bytes() == before

    rows, revision = catalog.load_catalog_snapshot(tmp_path)
    rows.append(
        {
            **rows[0],
            "sample_sha256": "preseeded-sample",
            "case_ids": ["future-case"],
            "ingest_sequence": None,
        }
    )
    with pytest.raises(catalog.CatalogFactRegressionError, match="预埋"):
        catalog.save_catalog(tmp_path, rows, expected_revision=revision)
    assert path.read_bytes() == before


def test_public_manifest_save_cannot_launder_tampered_report_hash(
    tmp_path: Path,
) -> None:
    report = _report(note="original")
    result = corpus.add_report(tmp_path, report, _raw(report), case_id="case-a")
    stored = tmp_path / str(result["report_path"])
    tampered = _raw(_report(note="tampered"))
    stored.write_text(tampered, encoding="utf-8")
    assert corpus.verify_reports(tmp_path)["counts"]["mismatch"] == 1

    rows, revision = corpus.load_manifest_snapshot(tmp_path)
    before = corpus.manifest_path(tmp_path).read_bytes()
    import hashlib

    rows[0]["report_bytes_sha256"] = hashlib.sha256(
        tampered.encode("utf-8")
    ).hexdigest()
    rows[0]["report_bytes_sha256_origin"] = corpus.HASH_ORIGIN_INGEST
    with pytest.raises(corpus.ManifestIntegrityMutationError, match="report_bytes_sha256"):
        corpus.save_manifest(tmp_path, rows, expected_revision=revision)

    assert corpus.manifest_path(tmp_path).read_bytes() == before
    assert corpus.verify_reports(tmp_path)["counts"]["mismatch"] == 1


def test_public_manifest_save_cannot_strip_catalog_authority_projection(
    tmp_path: Path,
) -> None:
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report), case_id="case-a")
    rows, revision = corpus.load_manifest_snapshot(tmp_path)
    before = corpus.manifest_path(tmp_path).read_bytes()
    rows[0]["case_ids"] = []
    rows[0]["case_id"] = None
    rows[0]["catalog_authority_materialized"] = False
    rows[0]["ingest_sequence"] = None

    with pytest.raises(corpus.ManifestAuthorityMutationError):
        corpus.save_manifest(tmp_path, rows, expected_revision=revision)

    assert corpus.manifest_path(tmp_path).read_bytes() == before
    catalog.catalog_path(tmp_path).unlink()
    with pytest.raises(catalog.CatalogCorruptError):
        corpus.load_materialized_manifest(tmp_path)


def test_public_manifest_save_cannot_forge_scope_marker_and_ioc_projection(
    tmp_path: Path,
) -> None:
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report), case_id="case-a")
    [legacy_projection] = corpus.load_manifest(tmp_path)
    legacy_projection.pop("case_ioc_scope_indexed", None)
    legacy_projection["key_iocs"] = []
    _write_manifest_fixture(tmp_path, [legacy_projection])
    rows, revision = corpus.load_manifest_snapshot(tmp_path)
    before = corpus.manifest_path(tmp_path).read_bytes()
    rows[0]["case_ioc_scope_indexed"] = True
    rows[0]["key_iocs"] = ["forged.example.test"]

    with pytest.raises(corpus.ManifestAuthorityMutationError, match="派生索引字段"):
        corpus.save_manifest(tmp_path, rows, expected_revision=revision)

    assert corpus.manifest_path(tmp_path).read_bytes() == before


@pytest.mark.parametrize(
    ("field", "forged"),
    [
        ("key_iocs", ["forged.example.test"]),
        ("sign_sha256", "forged-signature"),
        ("counts", {"leads": 999, "endpoints": 0, "findings": 0}),
    ],
)
def test_public_manifest_save_cannot_rewrite_known_report_projections(
    tmp_path: Path,
    field: str,
    forged: object,
) -> None:
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report), case_id="case-a")
    rows, revision = corpus.load_manifest_snapshot(tmp_path)
    before = corpus.manifest_path(tmp_path).read_bytes()
    rows[0][field] = forged

    with pytest.raises(corpus.ManifestAuthorityMutationError, match="派生索引字段"):
        corpus.save_manifest(tmp_path, rows, expected_revision=revision)

    assert corpus.manifest_path(tmp_path).read_bytes() == before


@pytest.mark.parametrize("replacement", [None, "other-case"])
def test_public_manifest_save_cannot_change_true_legacy_case_id(
    tmp_path: Path,
    replacement: str | None,
) -> None:
    report = _report()
    corpus.add_report(tmp_path, report, _raw(report))
    _downgrade_to_true_legacy_manifest(tmp_path, "legacy-case")
    rows, revision = corpus.load_manifest_snapshot(tmp_path)
    before = corpus.manifest_path(tmp_path).read_bytes()
    rows[0]["case_id"] = replacement

    with pytest.raises(corpus.ManifestAuthorityMutationError, match="legacy case_id"):
        corpus.save_manifest(tmp_path, rows, expected_revision=revision)

    assert corpus.manifest_path(tmp_path).read_bytes() == before


def test_report_resolver_returns_canonical_resolved_path(tmp_path: Path) -> None:
    report = _report()
    result = corpus.add_report(tmp_path, report, _raw(report))
    unresolved = tmp_path / "." / str(result["report_path"])

    resolved = corpus.resolve_report_file(tmp_path, str(unresolved.relative_to(tmp_path)))

    assert resolved == unresolved.resolve()
    assert resolved is not None and resolved.is_absolute()


def test_catalog_dry_runs_do_not_create_missing_root(tmp_path: Path) -> None:
    root = tmp_path / "does-not-exist"

    quarantine = catalog.quarantine_tool_versions(
        root,
        ["1.0.0"],
        reason="audit only",
        apply=False,
    )
    migration = catalog.migrate_legacy_case_ids(root, apply=False)

    assert quarantine["applied"] is False
    assert migration["applied"] is False
    assert not root.exists()


def test_catalog_dry_runs_leave_existing_bytes_unchanged(tmp_path: Path) -> None:
    report = _report_version("0.10.0.dev0", sha="sample-dev")
    corpus.add_report(tmp_path, report, _raw(report), case_id="case-a")
    catalog_before = catalog.catalog_path(tmp_path).read_bytes()
    manifest_before = corpus.manifest_path(tmp_path).read_bytes()

    catalog.quarantine_tool_versions(
        tmp_path,
        ["0.10.0.dev0"],
        reason="audit only",
        apply=False,
    )
    catalog.migrate_legacy_case_ids(tmp_path, apply=False)

    assert catalog.catalog_path(tmp_path).read_bytes() == catalog_before
    assert corpus.manifest_path(tmp_path).read_bytes() == manifest_before


def test_backfill_materializes_latest_case_bindings_before_equal_length_write(
    tmp_path: Path,
) -> None:
    report = _report()
    raw = _raw(report)
    corpus.add_report(tmp_path, report, raw, case_id="case-a")
    corpus.add_report(tmp_path, report, raw, case_id="case-b")
    [stale] = corpus.load_manifest(tmp_path)
    stale.pop("report_bytes_sha256", None)
    stale.pop("report_bytes_sha256_origin", None)
    stale["case_ids"] = ["case-a"]
    stale["case_id"] = "case-a"
    _write_manifest_fixture(tmp_path, [stale])

    result = corpus.backfill_report_hashes(tmp_path)

    assert result["written"] is True
    [entry] = corpus.load_manifest(tmp_path)
    assert entry["case_ids"] == ["case-a", "case-b"]
    assert entry["case_id"] is None
    assert entry["report_bytes_sha256_origin"] == corpus.HASH_ORIGIN_BACKFILL
