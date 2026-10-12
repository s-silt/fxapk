"""Portable regressions for native attachment and validation defects.

Synthetic fixtures only. No out/ directories, devices, or live engines.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.test_rea_attach import _rea_bundle
from tests.test_rea_native import (
    _hidden_file,
    _inspect_bundle,
    _report,
    _sha,
)

PLUGIN_SRC = Path(__file__).parents[1] / "plugins" / "fxapk-rea" / "src"
_MIB = 1024 * 1024


@pytest.fixture
def native(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.syspath_prepend(str(PLUGIN_SRC))
    return importlib.import_module("fxapk_rea.native")


def _recover(native, monkeypatch, tmp_path: Path) -> tuple[Path, bytes]:  # noqa: ANN001
    body, recipe = _hidden_file()
    bundle = _inspect_bundle(native, monkeypatch, tmp_path, body)
    recipe["evidence_sha256"] = _sha((bundle / "execution" / "stdout.bin").read_bytes())
    recipe_path = tmp_path / "recipe.json"
    recipe_path.write_text(json.dumps(recipe), encoding="utf-8")
    out = tmp_path / "recover"
    native.recover(bundle, recipe_path, out)
    return out, body


def _attach_report(native, recovery: Path, tmp_path: Path, body: bytes) -> Path:  # noqa: ANN001
    report = tmp_path / "input.json"
    report.write_text(json.dumps(_report(_sha(body))), encoding="utf-8")
    out = tmp_path / "attached"
    native.attach(recovery, report, out)
    return out


def _retarget_hashes(native, recovery: Path, *, digest_query: str) -> None:  # noqa: ANN001
    """Recompute file hashes the way a forged bundle keeps local digest checks green."""
    recipe_bytes = (recovery / "recipe.json").read_bytes()
    result = json.loads((recovery / "result.json").read_text(encoding="utf-8"))
    result["recipe_sha256"] = _sha(recipe_bytes)
    digest = native._content_digest(
        result["binary_sha256"],
        result["evidence_sha256"],
        result["recipe_sha256"],
        result["candidate"]["kind"],
        result["candidate"]["value"],
        digest_query,
    )
    result["content_digest"] = digest
    result_bytes = (json.dumps(result, indent=2) + "\n").encode()
    (recovery / "result.json").write_bytes(result_bytes)
    manifest = json.loads((recovery / "manifest.json").read_text(encoding="utf-8"))
    manifest["content_digest"] = digest
    for name, blob in {
        "recipe.json": recipe_bytes,
        "result.json": result_bytes,
    }.items():
        manifest["files"][name] = {"sha256": _sha(blob), "size": len(blob)}
    (recovery / "manifest.json").write_bytes((json.dumps(manifest, indent=2) + "\n").encode())


def test_r1_rehashed_anchor_cannot_disagree_with_dossier(native, monkeypatch, tmp_path) -> None:  # noqa: ANN001
    recovery, body = _recover(native, monkeypatch, tmp_path)
    inspect_manifest = json.loads((recovery / "dossier" / "inspect-manifest.json").read_text(encoding="utf-8"))
    recipe = json.loads((recovery / "recipe.json").read_text(encoding="utf-8"))
    recipe["anchor"] = {"operation": "overview", "query": "different_function"}
    (recovery / "recipe.json").write_bytes((json.dumps(recipe, indent=2) + "\n").encode())
    _retarget_hashes(native, recovery, digest_query=inspect_manifest["query"])
    report = tmp_path / "input.json"
    report.write_text(json.dumps(_report(_sha(body))), encoding="utf-8")
    before = report.read_bytes()
    out = tmp_path / "forged-attach"

    with pytest.raises(native.NativeError, match="function_dossier_mismatch"):
        native.attach(recovery, report, out)

    assert not out.exists()
    assert report.read_bytes() == before


def test_r2_forged_history_flags_are_rejected_without_touching_input(native, monkeypatch, tmp_path) -> None:  # noqa: ANN001
    recovery, body = _recover(native, monkeypatch, tmp_path)
    attached = _attach_report(native, recovery, tmp_path, body)
    report = attached / "report.json"
    payload = json.loads(report.read_text(encoding="utf-8"))
    history = payload["meta"]["native_recovery"][0]
    history["relation_verified"] = True
    history["runtime_observed"] = True
    history["closure_evaluated"] = True
    history["label"] = "runtime_observation"
    report.write_text(json.dumps(payload), encoding="utf-8")
    before = report.read_bytes()
    out = tmp_path / "second"

    with pytest.raises(native.NativeError, match="result_mismatch"):
        native.attach(recovery, report, out)

    assert not out.exists()
    assert report.read_bytes() == before
    assert json.loads(before)["meta"]["native_recovery"][0]["relation_verified"] is True


def test_r2_missing_history_flags_are_reconstructed_only_on_output(native, monkeypatch, tmp_path) -> None:  # noqa: ANN001
    recovery, body = _recover(native, monkeypatch, tmp_path)
    attached = _attach_report(native, recovery, tmp_path, body)
    report = attached / "report.json"
    payload = json.loads(report.read_text(encoding="utf-8"))
    history = payload["meta"]["native_recovery"][0]
    for key in ("relation_verified", "runtime_observed", "closure_evaluated", "label"):
        history.pop(key)
    report.write_text(json.dumps(payload), encoding="utf-8")
    before = report.read_bytes()
    out = tmp_path / "reconstructed"
    native.attach(recovery, report, out)
    written = json.loads((out / "report.json").read_text(encoding="utf-8"))
    item = written["meta"]["native_recovery"][0]

    assert report.read_bytes() == before
    assert "relation_verified" not in json.loads(before)["meta"]["native_recovery"][0]
    assert item["relation_verified"] is False
    assert item["runtime_observed"] is False
    assert item["closure_evaluated"] is False
    assert item["label"] == "analyst_reconstruction"


def test_r4_web_attach_keeps_native_closure_and_web_receipts(native, monkeypatch, tmp_path) -> None:  # noqa: ANN001
    recovery, body = _recover(native, monkeypatch, tmp_path)
    attached = _attach_report(native, recovery, tmp_path, body)
    bundle = tmp_path / "bundle"
    _rea_bundle(PLUGIN_SRC, bundle)
    attachment = importlib.import_module("fxapk_rea.attachment")
    web_out = tmp_path / "web-attached"
    attachment.attach(bundle, attached / "report.json", web_out)
    published = json.loads((web_out / "report.json").read_text(encoding="utf-8"))
    native_ref = published["meta"]["native_recovery"][0]["files"][0]["path"]
    snapshot = published["meta"]["native_recovery_input"]["relative_path"]

    assert (web_out / native_ref).read_bytes() == (attached / native_ref).read_bytes()
    assert (web_out / snapshot).read_bytes() == (attached / snapshot).read_bytes()
    for item in published["meta"]["native_recovery"]:
        for entry in item["files"]:
            relative = entry["path"]
            assert (web_out / relative).read_bytes() == (attached / relative).read_bytes()
    assert any((web_out / "external_observations").glob("*/fxapk-rea-bundle.json"))
    again = tmp_path / "native-again"
    native.attach(recovery, web_out / "report.json", again)
    kept = json.loads((again / "report.json").read_text(encoding="utf-8"))
    assert kept["meta"]["web_observations"]
    kept_snapshot = kept["meta"]["native_recovery_input"]["relative_path"]
    assert (again / kept_snapshot).read_bytes() == (web_out / "report.json").read_bytes()
    assert (again / snapshot).read_bytes() == (web_out / snapshot).read_bytes()
    for item in kept["meta"]["native_recovery"]:
        for entry in item["files"]:
            assert (again / entry["path"]).is_file()
    assert (again / "external_observations").is_dir()


def test_b2_snapshot_alias_is_rejected_and_canonical_path_is_copied(native, monkeypatch, tmp_path) -> None:  # noqa: ANN001
    recovery, body = _recover(native, monkeypatch, tmp_path)
    attached = _attach_report(native, recovery, tmp_path, body)
    report = attached / "report.json"
    payload = json.loads(report.read_text(encoding="utf-8"))
    record = payload["meta"]["native_recovery_input"]
    canonical = attached / record["relative_path"]
    alias = str(record["relative_path"]).replace("report.json", "report_json")
    alias_path = attached / alias
    alias_path.write_bytes(canonical.read_bytes())
    record["relative_path"] = alias
    report.write_text(json.dumps(payload), encoding="utf-8")
    out = tmp_path / "alias-out"

    with pytest.raises(native.NativeError, match="history_snapshot_mismatch"):
        native.attach(recovery, report, out)

    assert not out.exists()
    assert canonical.is_file()
    assert not (attached / "input_report").joinpath(record["sha256"], "report_json").samefile(canonical)


def test_b3_corrupt_zip_crc_is_a_structured_native_error(native, monkeypatch, tmp_path) -> None:  # noqa: ANN001
    del native, monkeypatch
    member = "lib/x86_64/libsample.so"
    archive_path = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(member, b"synthetic-native-bytes")
    raw = bytearray(archive_path.read_bytes())
    if raw[:4] != b"PK\x03\x04":
        raise AssertionError("expected a local zip header")
    raw[14] ^= 0xFF
    central = raw.find(b"PK\x01\x02")
    raw[central + 16] ^= 0xFF
    archive_path.write_bytes(raw)
    with zipfile.ZipFile(archive_path) as archive:
        assert archive.namelist() == [member]
    cli = importlib.import_module("fxapk_rea.native_cli")
    out = tmp_path / "extracted"
    result = CliRunner().invoke(cli.native_app, [
        "extract", str(archive_path), "--member", member, "--out", str(out),
    ])
    assert result.exit_code == 1
    assert result.stdout.strip(), (result.stdout, result.stderr, repr(result.exception))
    payload = json.loads(result.stdout)
    assert payload == {"status": "failed", "reason": "invalid_zip"}
    assert not out.exists()


def test_b4_reparse_without_is_junction(native, monkeypatch, tmp_path) -> None:  # noqa: ANN001
    monkeypatch.delattr(Path, "is_junction", raising=False)
    link = tmp_path / "linksim"
    link.mkdir()
    real_lstat = os.lstat

    def lstat(path):  # noqa: ANN001
        if Path(path).name == "linksim":
            return type("Stat", (), {
                "st_mode": stat.S_IFDIR,
                "st_reparse_tag": 0xA0000003,
                "st_file_attributes": 0x400,
            })()
        return real_lstat(path)

    monkeypatch.setattr(native.os, "lstat", lstat)
    with pytest.raises(native.NativeError, match="reparse_forbidden"):
        native._ancestors(link)

    def lstat_symlink(path):  # noqa: ANN001
        if Path(path).name == "symlink":
            return type("Stat", (), {
                "st_mode": stat.S_IFLNK,
                "st_reparse_tag": 0,
                "st_file_attributes": 0,
            })()
        return real_lstat(path)

    monkeypatch.setattr(native.os, "lstat", lstat_symlink)
    with pytest.raises(native.NativeError, match="reparse_forbidden"):
        native._ancestors(tmp_path / "symlink")


def test_b4_symlink_and_windows_junction_rejected(native, tmp_path) -> None:  # noqa: ANN001
    target = tmp_path / "target"
    target.mkdir()
    symlink = tmp_path / "symlink"
    try:
        os.symlink(target, symlink, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(native.NativeError, match="reparse_forbidden"):
        native._ancestors(symlink / "child.txt")


def test_b4_windows_junction_rejected(native, tmp_path) -> None:  # noqa: ANN001
    if sys.platform != "win32":
        pytest.skip("directory junction requires Windows")
    target = tmp_path / "target"
    target.mkdir()
    junction = tmp_path / "junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True,
        check=False,
    )
    if created.returncode != 0 or not junction.exists():
        pytest.skip("directory junction could not be created")
    with pytest.raises(native.NativeError, match="reparse_forbidden"):
        native._read_file(junction / "child.txt", 16)


def test_b1_native_budget_accepts_40mib_and_preflights_cumulative(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from apkscan.core.web_supplement_report import (
        SupplementRefusal,
        _prepare_native_history,
        supplement_report,
    )
    import apkscan.core.web_supplement_report as web

    digest = "ab" * 32
    root = tmp_path / "case" / "native_recovery" / digest
    root.mkdir(parents=True)
    blobs = {
        "manifest.json": b'{"schema_version":"synthetic"}\n',
        "recipe.json": b"{}\n",
        "result.json": b"{}\n",
        "binary.bin": b"MZ" + b"\x00" * (40 * _MIB - 2),
        "dossier/stdout.bin": b"out",
        "dossier/stderr.bin": b"err",
        "dossier/inspect-manifest.json": b"{}\n",
        "dossier/execution.json": b"{}\n",
        "dossier/provenance.json": b"{}\n",
    }
    files = []
    for name, blob in blobs.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
        files.append({
            "path": f"native_recovery/{digest}/{name}",
            "sha256": hashlib.sha256(blob).hexdigest(),
            "size": len(blob),
        })
    report = tmp_path / "case" / "report.json"
    report.write_text(json.dumps({
        "schema_version": "1.2",
        "package_name": "com.example.synthetic",
        "analysis_status": "complete",
        "meta": {
            "sample_sha256": "c" * 64,
            "tool_version": "1.5.4",
            "native_recovery": [{
                "content_digest": digest,
                "files": files,
            }],
        },
        "endpoints": [],
        "leads": [],
        "findings": [],
    }), encoding="utf-8")
    config = tmp_path / "off.json"
    config.write_text(json.dumps({
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "off",
        "source": "bundle",
        "path": str(tmp_path / "unused"),
    }), encoding="utf-8")
    out = tmp_path / "supplemented"
    result = supplement_report(report, config, out)
    copied = out / "native_recovery" / digest / "binary.bin"

    assert result["exit_code"] == 3
    assert copied.read_bytes() == blobs["binary.bin"]
    assert copied.stat().st_size == 40 * _MIB

    huge = "cd" * 32
    payload = {"meta": {"native_recovery": [{
        "content_digest": huge,
        "files": [
            {
                "path": f"native_recovery/{huge}/{name}",
                "sha256": "11" * 32,
                "size": 40 * _MIB,
            }
            for name in blobs
        ],
    }]}}

    def fail_open(*_args, **_kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("preflight read a file")

    monkeypatch.setattr(web.Path, "open", fail_open)
    with pytest.raises(SupplementRefusal, match="oversize"):
        _prepare_native_history(tmp_path / "missing-report.json", payload)
