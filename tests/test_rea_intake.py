"""H1：可识别的未验证 REA 观察不得进入直接案件证据。"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from apkscan.core import case_package as case_package_module
from apkscan.core.case_package import (
    CasePackageError,
    create_case_package,
    verify_case_package,
)
from apkscan.core.integrity import sha256_canonical_json
from apkscan.core.models import AnalysisConfig, Report
from apkscan.core.redact import safe_exception_text
from apkscan.core.report_io import write_report
import apkscan.core.rea_intake as rea_intake
from apkscan.core.webctx import load_web_evidence
from fxapk_rea.evidence import claim_output

_DIAGNOSTIC = "unverified REA observation cannot be admitted as direct case evidence"


def _envelope() -> dict[str, object]:
    return {
        "ok": True,
        "data": {
            "operation": "inspect_web_page",
            "predicate_type": "rea.web-page-inspection",
            "provider": {"id": "rea-cdp-browser", "version": "2"},
        },
    }


def _receipt() -> dict[str, object]:
    return {
        "schema_version": "rea-web-observation/1",
        "producer": "rea",
        "status": "ok",
        "provenance_authenticated": True,
    }


def _marker() -> dict[str, object]:
    return {
        "schema_version": "fxapk-rea-bundle-marker/1",
        "producer": "rea",
        "kind": "unverified_external_observation_bundle",
    }


def _write_report(root: Path) -> Path:
    path = root / "report.json"
    write_report(
        Report(
            package_name="com.example.synthetic",
            meta={
                "sample_sha256": "a" * 64,
                "tool_version": "synthetic-review",
                "ruleset_digest": "b" * 16,
            },
            leads=[],
            endpoints=[],
            findings=[],
            analyzer_status=[],
        ),
        path,
        render_existing_html=False,
    )
    return path


def _assert_web_refused(root: Path) -> None:
    with pytest.raises(ValueError) as excinfo:
        load_web_evidence(root, AnalysisConfig(online=False))
    message = safe_exception_text(excinfo.value)
    assert message == _DIAGNOSTIC
    assert "example.test" not in message
    assert "http" not in message


def test_renamed_envelope_utf8_utf16_and_gzip_are_refused(tmp_path: Path) -> None:
    raw = json.dumps(_envelope()).encode("utf-8")
    (tmp_path / "utf8").mkdir()
    (tmp_path / "utf8" / "ordinary-looking.body").write_bytes(raw)
    (tmp_path / "utf16").mkdir()
    (tmp_path / "utf16" / "ordinary-looking.body").write_bytes(raw.decode("utf-8").encode("utf-16"))
    (tmp_path / "gzip").mkdir()
    (tmp_path / "gzip" / "ordinary-looking.body").write_bytes(gzip.compress(raw))
    for name in ("utf8", "utf16", "gzip"):
        _assert_web_refused(tmp_path / name)


def test_receipt_and_legacy_schema_are_refused_by_contract(tmp_path: Path) -> None:
    (tmp_path / "current.json").write_text(json.dumps(_receipt()), encoding="utf-8")
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    (legacy / "notes.json").write_text(
        json.dumps({"schema_version": "rea-web-observation/0", "producer": "rea"}),
        encoding="utf-8",
    )
    _assert_web_refused(tmp_path)


def test_marker_and_ancestor_guard_scripts_and_execution(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    claim_output(bundle)
    (bundle / "script.js").write_text('fetch("https://example.test/api")\n', encoding="utf-8")
    (bundle / "execution").mkdir()
    (bundle / "execution" / "stdout.bin").write_bytes(b"not-json")
    _assert_web_refused(bundle)
    _assert_web_refused(bundle / "execution")
    _assert_web_refused(tmp_path)


def test_legacy_observation_above_scripts_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "legacy"
    (root / "scripts").mkdir(parents=True)
    (root / "observation.json").write_text(json.dumps(_receipt()), encoding="utf-8")
    (root / "scripts" / "app.js").write_text("console.log(1)\n", encoding="utf-8")
    _assert_web_refused(root / "scripts")


def test_hand_written_marker_guards_nested_script(tmp_path: Path) -> None:
    bundle = tmp_path / "nested" / "bundle"
    (bundle / "a" / "b").mkdir(parents=True)
    (bundle / "fxapk-rea-bundle.json").write_text(json.dumps(_marker()), encoding="utf-8")
    (bundle / "a" / "b" / "app.js").write_text("console.log(1)\n", encoding="utf-8")
    _assert_web_refused(bundle / "a" / "b")


def test_ordinary_observation_json_and_bare_js_stay_web_evidence(tmp_path: Path) -> None:
    (tmp_path / "observation.json").write_text(
        '{"ordinary":"https://example.test/api"}', encoding="utf-8"
    )
    (tmp_path / "app.js").write_text('fetch("https://example.test/api")\n', encoding="utf-8")
    ctx = load_web_evidence(tmp_path, AnalysisConfig(online=False))
    assert len(ctx.list_files()) == 2


def test_case_package_create_and_verify_reject_direct_rea_evidence(tmp_path: Path) -> None:
    report = _write_report(tmp_path)
    receipt = tmp_path / "renamed-evidence.json"
    receipt.write_text(json.dumps(_receipt()), encoding="utf-8")
    manifest = tmp_path / "case-package.json"
    with pytest.raises(CasePackageError) as excinfo:
        create_case_package(
            report,
            manifest,
            case_id="synthetic-review",
            producer="acceptance",
            case_evidence=[receipt],
        )
    assert excinfo.value.diagnostic_code == "unverified_rea_direct_intake"
    assert safe_exception_text(excinfo.value) == _DIAGNOSTIC
    assert not manifest.exists()

    created = create_case_package(
        report, manifest, case_id="synthetic-review", producer="acceptance"
    )
    assert verify_case_package(manifest)["status"] == "verified"
    raw = receipt.read_bytes()
    created["artifacts"].append(
        {
            "path": receipt.name,
            "kind": "evidence",
            "scope": "case_evidence",
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    )
    created["package_id"] = sha256_canonical_json(
        {key: value for key, value in created.items() if key != "package_id"}
    )
    manifest.write_text(json.dumps(created), encoding="utf-8")
    verified = verify_case_package(manifest)
    assert verified["status"] == "failed"
    assert any(_DIAGNOSTIC in issue for issue in verified["issues"])
    assert "example.test" not in " ".join(str(issue) for issue in verified["issues"])


def test_case_package_rejects_script_under_bundle_but_allows_explicit_reference(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "bundle"
    (bundle / "scripts").mkdir(parents=True)
    (bundle / "fxapk-rea-bundle.json").write_text(json.dumps(_marker()), encoding="utf-8")
    script = bundle / "scripts" / "app.js"
    script.write_text("console.log(1)\n", encoding="utf-8")
    report = _write_report(tmp_path)
    with pytest.raises(CasePackageError):
        create_case_package(
            report,
            tmp_path / "blocked.json",
            case_id="synthetic-review",
            producer="acceptance",
            case_evidence=[script],
        )
    assert not (tmp_path / "blocked.json").exists()
    manifest = tmp_path / "case-package.json"
    create_case_package(
        report,
        manifest,
        case_id="synthetic-review",
        producer="acceptance",
        batch_reference=[script],
    )
    packaged = verify_case_package(manifest)
    assert packaged["status"] == "verified"
    reference = [
        item
        for item in json.loads(manifest.read_text(encoding="utf-8"))["artifacts"]
        if item["kind"] == "reference"
    ]
    assert reference and reference[0]["scope"] == "batch_reference"


def test_ordinary_observation_can_be_direct_case_evidence(tmp_path: Path) -> None:
    note = tmp_path / "observation.json"
    note.write_text('{"ordinary":"https://example.test/api"}', encoding="utf-8")
    report = _write_report(tmp_path)
    manifest = tmp_path / "case-package.json"
    create_case_package(
        report,
        manifest,
        case_id="synthetic-review",
        producer="acceptance",
        case_evidence=[note],
    )
    assert verify_case_package(manifest)["status"] == "verified"


def test_nonregular_marker_does_not_grant_case_scope(tmp_path: Path) -> None:
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (blocked / "fxapk-rea-bundle.json").mkdir()
    (blocked / "app.js").write_text("console.log(1)\n", encoding="utf-8")
    _assert_web_refused(blocked)


def test_link_marker_does_not_grant_case_scope(tmp_path: Path) -> None:
    linked = tmp_path / "linked"
    linked.mkdir()
    marker = linked / "fxapk-rea-bundle.json"
    benign = tmp_path / "benign.json"
    benign.write_text('{"note":"benign"}', encoding="utf-8")
    created = False
    try:
        marker.symlink_to(benign)
        created = True
    except OSError:
        target = tmp_path / "benign-dir"
        target.mkdir()
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(marker), str(target)],
            capture_output=True,
            check=False,
        )
        created = completed.returncode == 0
    if not created:
        pytest.skip("symlink and directory junction are not permitted")
    (linked / "app.js").write_text("console.log(1)\n", encoding="utf-8")
    _assert_web_refused(linked)


def _hold_unshared(path: Path) -> int | None:
    """Hold a non-shared read so a second open fails. Windows-only; None if unavailable."""
    if os.name != "nt":
        return None
    import ctypes

    handle = ctypes.windll.kernel32.CreateFileW(
        str(path), 0x80000000, 0, None, 3, 0x80, None
    )
    if handle in (0, ctypes.c_void_p(-1).value):
        return None
    return int(handle)


def test_unreadable_marker_fails_closed(tmp_path: Path) -> None:
    blocked = tmp_path / "locked"
    blocked.mkdir()
    marker = blocked / "fxapk-rea-bundle.json"
    marker.write_bytes(b'{"note":"benign"}\n')
    (blocked / "app.js").write_text("console.log(1)\n", encoding="utf-8")
    handle = _hold_unshared(marker)
    if handle is None and os.name != "nt":
        os.chmod(marker, 0)
        try:
            _assert_web_refused(blocked)
        finally:
            os.chmod(marker, stat.S_IRUSR | stat.S_IWUSR)
        return
    if handle is None:
        pytest.skip("cannot hold an unshared read on the marker")
    import ctypes

    try:
        _assert_web_refused(blocked)
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def test_deep_entry_keeps_bundle_ancestor_and_ordinary_deep_tree_loads(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    claim_output(root)
    nested = root.joinpath(*["child" for _ in range(12)])
    nested.mkdir(parents=True)
    (nested / "script.js").write_text('fetch("https://example.test/api")\n', encoding="utf-8")
    _assert_web_refused(nested)

    deep = tmp_path.joinpath("plain", *["child" for _ in range(12)])
    deep.mkdir(parents=True)
    (deep / "app.js").write_text("console.log(1)\n", encoding="utf-8")
    assert len(load_web_evidence(deep, AnalysisConfig(online=False)).list_files()) == 1


def test_exhausted_ancestor_bound_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("apkscan.core.rea_intake._MAX_ANCESTORS", 2)
    (tmp_path / "app.js").write_text("console.log(1)\n", encoding="utf-8")
    _assert_web_refused(tmp_path)


def test_utf32_be_raw_envelope_is_recognized(tmp_path: Path) -> None:
    import codecs

    payload = codecs.BOM_UTF32_BE + json.dumps(_envelope()).encode("utf-32-be")
    (tmp_path / "renamed.body").write_bytes(payload)
    _assert_web_refused(tmp_path)


def test_contract_after_8mib_padding_is_recognized(tmp_path: Path) -> None:
    raw = json.dumps({"padding": "x" * (8 * 1024 * 1024), **_envelope()}).encode()
    assert len(raw) <= 16 * 1024 * 1024
    (tmp_path / "renamed.body").write_bytes(raw)
    _assert_web_refused(tmp_path)


def test_corrupt_marker_refuses_but_invalid_observation_json_does_not(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    claim_output(bundle)
    (bundle / "fxapk-rea-bundle.json").write_bytes(b"{")
    (bundle / "script.js").write_text('fetch("https://example.test/api")\n', encoding="utf-8")
    _assert_web_refused(bundle)

    ordinary = tmp_path / "ordinary"
    ordinary.mkdir()
    (ordinary / "observation.json").write_bytes(b"{")
    (ordinary / "app.js").write_text("console.log(1)\n", encoding="utf-8")
    names = load_web_evidence(ordinary, AnalysisConfig(online=False)).list_files()
    assert any(name.endswith("app.js") for name in names)


def test_marker_metadata_read_failure_is_not_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "bundle"
    claim_output(root)
    (root / "script.js").write_text('fetch("https://example.test/api")\n', encoding="utf-8")
    marker = root / "fxapk-rea-bundle.json"
    original = Path.lstat

    def fail_marker(path: Path, *args: object, **kwargs: object) -> os.stat_result:
        if path == marker:
            raise PermissionError("synthetic metadata failure")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", fail_marker)
    _assert_web_refused(root)


def _make_directory_alias(alias: Path, target: Path) -> None:
    if os.name == "nt":
        made = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(alias), str(target)],
            capture_output=True,
            check=False,
        )
        assert made.returncode == 0, made.stderr.decode("utf-8", errors="replace")
        return
    alias.symlink_to(target, target_is_directory=True)


def _remove_directory_alias(alias: Path) -> None:
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "rmdir", str(alias)], capture_output=True, check=False)
        return
    if alias.is_symlink():
        alias.unlink()


def test_directory_alias_cannot_hide_bundle_ancestor(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    claim_output(root)
    scripts = root / "scripts"
    scripts.mkdir()
    script = scripts / "script.js"
    script.write_text('fetch("https://example.test/api")\n', encoding="utf-8")
    alias = tmp_path / "outside-alias"
    _make_directory_alias(alias, scripts)
    try:
        _assert_web_refused(alias)
        report = _write_report(tmp_path)
        with pytest.raises(CasePackageError) as excinfo:
            create_case_package(
                report,
                tmp_path / "blocked.json",
                case_id="synthetic-review",
                producer="acceptance",
                case_evidence=[alias / "script.js"],
            )
        assert excinfo.value.diagnostic_code == "unverified_rea_direct_intake"
        assert not (tmp_path / "blocked.json").exists()

        manifest = tmp_path / "case-package.json"
        created = create_case_package(
            report, manifest, case_id="synthetic-review", producer="acceptance"
        )
        raw = script.read_bytes()
        created["artifacts"].append(
            {
                "path": "outside-alias/script.js",
                "kind": "evidence",
                "scope": "case_evidence",
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
        created["package_id"] = sha256_canonical_json(
            {key: value for key, value in created.items() if key != "package_id"}
        )
        manifest.write_text(json.dumps(created), encoding="utf-8")
        verified = verify_case_package(manifest)
        assert verified["status"] == "failed"
        assert any(_DIAGNOSTIC in str(issue) for issue in verified["issues"])
    finally:
        _remove_directory_alias(alias)


def test_recursive_json_document_has_stable_diagnostic(tmp_path: Path) -> None:
    (tmp_path / "observation.json").write_text("[" * 5000 + "0" + "]" * 5000, encoding="utf-8")
    (tmp_path / "app.js").write_text("console.log(1)\n", encoding="utf-8")
    _assert_web_refused(tmp_path)


def test_sixty_deep_json_document_is_refused_on_every_platform(tmp_path: Path) -> None:
    (tmp_path / "observation.json").write_text("[" * 60 + "0" + "]" * 60, encoding="utf-8")
    (tmp_path / "app.js").write_text("console.log(1)\n", encoding="utf-8")
    _assert_web_refused(tmp_path)


def test_shallow_json_list_stays_ordinary_web_evidence(tmp_path: Path) -> None:
    (tmp_path / "observation.json").write_text("[" * 10 + "0" + "]" * 10, encoding="utf-8")
    (tmp_path / "app.js").write_text("console.log(1)\n", encoding="utf-8")
    ctx = load_web_evidence(tmp_path, AnalysisConfig(online=False))
    assert len(ctx.list_files()) == 2


def test_multimember_gzip_envelope_is_recognized(tmp_path: Path) -> None:
    raw = json.dumps(_envelope()).encode()
    middle = len(raw) // 2
    (tmp_path / "renamed.body").write_bytes(gzip.compress(raw[:middle]) + gzip.compress(raw[middle:]))
    _assert_web_refused(tmp_path)


def test_leading_whitespace_does_not_hide_contract(tmp_path: Path) -> None:
    (tmp_path / "renamed.body").write_bytes(b" " * 128 + json.dumps(_envelope()).encode())
    _assert_web_refused(tmp_path)


def test_manifest_verification_keeps_lexical_bundle_provenance(tmp_path: Path) -> None:
    report = _write_report(tmp_path)
    manifest = tmp_path / "case-package.json"
    package = create_case_package(
        report, manifest, case_id="synthetic-review", producer="acceptance"
    )
    bundle = tmp_path / "bundle"
    claim_output(bundle)
    ordinary = tmp_path / "ordinary"
    ordinary.mkdir()
    artifact = ordinary / "script.js"
    raw = b'fetch("https://example.test/api")'
    artifact.write_bytes(raw)
    alias = bundle / "alias"
    _make_directory_alias(alias, ordinary)
    try:
        package["artifacts"].append(
            {
                "path": "bundle/alias/script.js",
                "kind": "evidence",
                "scope": "case_evidence",
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
        package["package_id"] = sha256_canonical_json(
            {key: value for key, value in package.items() if key != "package_id"}
        )
        manifest.write_text(json.dumps(package), encoding="utf-8")
        verified = verify_case_package(manifest)
        assert verified["status"] == "failed"
        assert any(_DIAGNOSTIC in str(issue) for issue in verified["issues"])
    finally:
        _remove_directory_alias(alias)


_BUDGET_DIAGNOSTIC = "unverified REA recognition exceeded the intake read budget"


def test_marker_only_nonregular_root_is_refused(tmp_path: Path) -> None:
    (tmp_path / "fxapk-rea-bundle.json").mkdir()
    _assert_web_refused(tmp_path)


def test_file_link_to_renamed_receipt_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = _write_report(tmp_path)
    raw = json.dumps(_receipt()).encode()
    target = tmp_path / "renamed-evidence.body"
    target.write_bytes(raw)
    alias = tmp_path / "file-link.json"
    alias.write_bytes(raw)
    original_resolve = Path.resolve
    original_is_symlink = Path.is_symlink

    def resolve(path: Path, *args: object, **kwargs: object) -> Path:
        return target if path == alias else original_resolve(path, *args, **kwargs)

    def is_symlink(path: Path) -> bool:
        return True if path == alias else original_is_symlink(path)

    monkeypatch.setattr(Path, "resolve", resolve)
    monkeypatch.setattr(Path, "is_symlink", is_symlink)
    manifest = tmp_path / "case-package.json"
    with pytest.raises(CasePackageError) as excinfo:
        create_case_package(
            report,
            manifest,
            case_id="synthetic-review",
            producer="acceptance",
            case_evidence=[alias],
        )
    assert excinfo.value.diagnostic_code == "unverified_rea_direct_intake"
    package = create_case_package(
        report, manifest, case_id="synthetic-review", producer="acceptance"
    )
    package["artifacts"].append(
        {
            "path": alias.name,
            "kind": "evidence",
            "scope": "case_evidence",
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    )
    package["package_id"] = sha256_canonical_json(
        {key: value for key, value in package.items() if key != "package_id"}
    )
    manifest.write_text(json.dumps(package), encoding="utf-8")
    verified = verify_case_package(manifest)
    assert verified["status"] == "failed"
    assert any(_DIAGNOSTIC in str(issue) for issue in verified["issues"])


def test_ordinary_file_link_can_remain_case_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = _write_report(tmp_path)
    raw = b'{"ordinary":"https://example.test/api"}'
    target = tmp_path / "note.json"
    target.write_bytes(raw)
    alias = tmp_path / "alias.json"
    alias.write_bytes(raw)
    original_resolve = Path.resolve
    original_is_symlink = Path.is_symlink

    def resolve(path: Path, *args: object, **kwargs: object) -> Path:
        return target if path == alias else original_resolve(path, *args, **kwargs)

    def is_symlink(path: Path) -> bool:
        return True if path == alias else original_is_symlink(path)

    monkeypatch.setattr(Path, "resolve", resolve)
    monkeypatch.setattr(Path, "is_symlink", is_symlink)
    manifest = tmp_path / "case-package.json"
    create_case_package(
        report,
        manifest,
        case_id="synthetic-review",
        producer="acceptance",
        case_evidence=[alias],
    )
    assert verify_case_package(manifest)["status"] == "verified"


def test_web_recognition_budget_is_shared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rea_intake, "INTAKE_READ_BUDGET_BYTES", 80)
    body = b'{"padding":"' + (b"x" * 60) + b'"}'
    (tmp_path / "a.json").write_bytes(body)
    (tmp_path / "b.json").write_bytes(body)
    with pytest.raises(ValueError) as excinfo:
        load_web_evidence(tmp_path, AnalysisConfig(online=False))
    assert safe_exception_text(excinfo.value) == _BUDGET_DIAGNOSTIC


def test_case_package_recognition_budget_is_shared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = _write_report(tmp_path)
    body = b'{"padding":"' + (b"y" * 70) + b'"}'
    # 报告本身的识别读取之后，还够一份普通 JSON，不够第二份。
    monkeypatch.setattr(
        rea_intake, "INTAKE_READ_BUDGET_BYTES", report.stat().st_size + len(body) + 8
    )
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    first.write_bytes(body)
    second.write_bytes(body)
    with pytest.raises(CasePackageError) as excinfo:
        create_case_package(
            report,
            tmp_path / "case-package.json",
            case_id="synthetic-review",
            producer="acceptance",
            case_evidence=[first, second],
        )
    assert excinfo.value.diagnostic_code == "rea_recognition_budget_exhausted"
    assert safe_exception_text(excinfo.value) == _BUDGET_DIAGNOSTIC


def test_verify_stops_when_recognition_budget_is_exhausted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = _write_report(tmp_path)
    (tmp_path / "observation.json").write_text(
        json.dumps({"ordinary": "x" * 512}), encoding="utf-8"
    )
    evidence = []
    for index in range(4):
        item = tmp_path / f"ordinary-{index}.txt"
        item.write_text("ordinary", encoding="utf-8")
        evidence.append(item)
    manifest = tmp_path / "case-package.json"
    create_case_package(
        report,
        manifest,
        case_id="synthetic-review",
        producer="acceptance",
        case_evidence=evidence,
    )
    monkeypatch.setattr(rea_intake, "INTAKE_READ_BUDGET_BYTES", 1)
    opens: list[Path] = []
    hashes: list[Path] = []
    original_open = Path.open
    original_hash = case_package_module._sha256

    def counted_open(path: Path, *args: object, **kwargs: object):
        if path == tmp_path / "observation.json":
            opens.append(path)
        return original_open(path, *args, **kwargs)

    def counted_hash(path: Path) -> str:
        hashes.append(path)
        return original_hash(path)

    monkeypatch.setattr(Path, "open", counted_open)
    monkeypatch.setattr(case_package_module, "_sha256", counted_hash)
    result = verify_case_package(manifest)
    assert result["status"] == "failed"
    assert len(opens) <= 1
    assert hashes == []
    assert any(_BUDGET_DIAGNOSTIC in str(issue) for issue in result["issues"])


def test_crc_failure_on_first_chunk_reserves_output_allowance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rea_intake, "INTAKE_READ_BUDGET_BYTES", 32768)
    body = bytearray(gzip.compress(b"x" * 60000))
    body[-8] ^= 1
    (tmp_path / "invalid.body").write_bytes(body)
    with pytest.raises(ValueError) as excinfo:
        load_web_evidence(tmp_path, AnalysisConfig(online=False))
    assert safe_exception_text(excinfo.value) == _BUDGET_DIAGNOSTIC


@pytest.mark.parametrize("mode", ["crc", "trailing"])
def test_failed_gzip_output_counts_toward_recognition_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    raw = b'{"padding":"' + (b"z" * (80 * 1024)) + b'"}'
    stored = gzip.compress(raw)
    if mode == "crc":
        damaged = bytearray(stored)
        damaged[-8] ^= 1
        stored = bytes(damaged)
    else:
        stored += b"invalid-tail"
    monkeypatch.setattr(rea_intake, "INTAKE_READ_BUDGET_BYTES", 100_000)
    (tmp_path / "a.json").write_bytes(stored)
    (tmp_path / "b.json").write_bytes(stored)
    with pytest.raises(ValueError) as excinfo:
        load_web_evidence(tmp_path, AnalysisConfig(online=False))
    assert safe_exception_text(excinfo.value) == _BUDGET_DIAGNOSTIC
