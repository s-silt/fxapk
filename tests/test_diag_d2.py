"""D2：失败轮的 runtime 报告要登记，诊断可并入，但不能升成成功采集。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from apkscan.core.models import Report
from apkscan.dynamic import auto, capture
from apkscan.dynamic.capture_sequence import complement_decryption, run_rounds

_SAMPLE = "ab" * 32


def _report() -> Report:
    return Report(
        package_name="example.invalid",
        meta={
            "sample_sha256": _SAMPLE,
            "closure": {"status": "partial", "gaps": ["keep"]},
            "capture_apk_identity": {
                "which": "original",
                "original": {"sha256": _SAMPLE},
            },
        },
        leads=[],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )


def _write_failed(directory: Path, *, window: str, with_endpoint: bool = False) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    payload = {
        "package_name": "example.invalid",
        "source": "runtime",
        "capture_complete": False,
        "runtime_variant": "original-runtime",
        "endpoints": (
            [{"value": "https://failed.example.invalid/", "kind": "url"}] if with_endpoint else []
        ),
        "process_observations": [{
            "event": "early_exit",
            "window_id": window,
            "runtime_variant": "original-runtime",
        }],
    }
    path = directory / "runtime_report.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_error_capture_indexes_report_without_upgrading(monkeypatch, tmp_path: Path) -> None:
    failed = _write_failed(tmp_path, window="failed", with_endpoint=True)
    report = _report()

    def fake_run(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            "status": "error",
            "reason": "synthetic_failure",
            "report_paths": [str(failed)],
            "artifacts": [],
            "playbook": [],
        }

    monkeypatch.setattr(capture, "run", fake_run)
    step, path = auto._run_capture(
        "example.invalid",
        out_dir=str(tmp_path),
        has_device=True,
        duration=1,
        on_progress=None,
        confirm=None,
        report=report,
    )
    assert step["status"] == "error"
    assert step["detail"] == "synthetic_failure"
    assert path == str(failed.resolve())
    assert report.endpoints == []
    assert report.meta["closure"] == {"status": "partial", "gaps": ["keep"]}
    events = [item["event"] for item in report.meta["runtime_diagnostics"]["items"]]
    assert "early_exit_unattributed" in events
    assert "https://failed.example.invalid/" not in json.dumps(report.endpoints)


def test_error_capture_rejects_missing_and_outside_paths(monkeypatch, tmp_path: Path) -> None:
    outside = _write_failed(tmp_path / "outside", window="outside")
    bounded = tmp_path / "round"

    def fake_run(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            "status": "error",
            "reason": "synthetic_failure",
            "report_paths": [str(outside)],
            "artifacts": [],
            "playbook": [],
        }

    monkeypatch.setattr(capture, "run", fake_run)
    step, path = auto._run_capture(
        "example.invalid",
        out_dir=str(bounded),
        has_device=True,
        duration=1,
        on_progress=None,
        confirm=None,
        report=_report(),
    )
    assert step["status"] == "error"
    assert path == ""

    missing = tmp_path / "missing"

    def no_file(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            "status": "error",
            "reason": "synthetic_failure",
            "report_paths": [str(missing / "runtime_report.json")],
            "artifacts": [],
            "playbook": [],
        }

    monkeypatch.setattr(capture, "run", no_file)
    step, path = auto._run_capture(
        "example.invalid",
        out_dir=str(missing),
        has_device=True,
        duration=1,
        on_progress=None,
        confirm=None,
        report=_report(),
    )
    assert step["status"] == "error"
    assert path == ""


def test_error_rounds_index_inside_file_and_ignore_outside(tmp_path: Path) -> None:
    report = _report()
    outside = _write_failed(tmp_path / "outside", window="outside", with_endpoint=True)

    def runner(package: str, **kwargs: object) -> dict[str, object]:
        out = Path(str(kwargs["out"]))
        tag = str(kwargs["pass_tag"])
        if tag == "round1":
            path = _write_failed(out, window=tag, with_endpoint=True)
            return {
                "status": "error",
                "reason": "synthetic_failure",
                "report_paths": [str(path)],
            }
        if tag == "round2":
            return {
                "status": "error",
                "reason": "synthetic_failure",
                "report_paths": [str(outside)],
            }
        return {"status": "skipped", "reason": "not_this_test", "report_paths": []}

    rows = run_rounds(
        "example.invalid",
        report=report,
        unpacked=False,
        out_dir=str(tmp_path / "rounds"),
        duration=1,
        sample_sha256=_SAMPLE,
        runner=runner,
    )
    failed = rows[0]
    assert failed["status"] == "error"
    indexed = Path(str(failed["runtime_report_path"]))
    assert indexed.is_file()
    assert indexed.parent == Path(str(failed["output_dir"]))
    digest = hashlib.sha256(indexed.read_bytes()).hexdigest()
    assert failed["runtime_report_sha256"] == digest
    assert rows[1]["status"] == "error"
    assert "runtime_report_path" not in rows[1]
    assert report.endpoints == []
    assert report.meta["closure"]["status"] == "partial"
    events = [item["event"] for item in report.meta["runtime_diagnostics"]["items"]]
    assert events.count("early_exit_unattributed") == 1


def test_error_round_symlink_is_not_indexed(tmp_path: Path) -> None:
    real = _write_failed(tmp_path / "real", window="real")
    out = tmp_path / "round1-pcap"
    out.mkdir()
    link = out / "runtime_report.json"
    try:
        link.symlink_to(real)
    except OSError as exc:
        pytest.skip(f"symlink_unavailable:{type(exc).__name__}")

    def runner(package: str, **kwargs: object) -> dict[str, object]:
        return {"status": "error", "reason": "synthetic_failure", "report_paths": [str(link)]}

    rows = run_rounds(
        "example.invalid",
        report=_report(),
        unpacked=False,
        out_dir=str(tmp_path),
        duration=1,
        sample_sha256=_SAMPLE,
        runner=runner,
    )
    assert rows[0]["status"] == "error"
    assert "runtime_report_path" not in rows[0]


def test_error_round_is_not_a_decryption_source(tmp_path: Path) -> None:
    from tests.test_merge import _C5B_KEY, _c5b_encrypt_fixed_iv

    key, iv = _C5B_KEY, "abcdefghijklmnop"
    plain = '{"url":"https://api.example.test/v1"}'
    cipher = _c5b_encrypt_fixed_iv(plain, key, iv)
    events = [{
        "src": "cipher",
        "event": "init",
        "transformation": "AES/CFB/PKCS5Padding",
        "key_hex": key.encode().hex(),
        "iv_hex": iv.encode().hex(),
    }] * 2
    report = _report()
    report.package_name = "com.example.synthetic"
    rows = []
    for number, (messages, crypto) in enumerate((
        ([{
            "url": "https://api.example.test/config",
            "response_body": json.dumps({"data": cipher, "timestamp": 1700000000000}),
        }], []),
        ([], events),
    )):
        path = tmp_path / f"round-{number}.json"
        raw = json.dumps({
            "package_name": report.package_name,
            "runtime_variant": "original-runtime",
            "messages": messages,
            "crypto_events": crypto,
        }).encode()
        path.write_bytes(raw)
        rows.append({
            "status": "error",
            "runtime_report_path": str(path),
            "runtime_report_sha256": hashlib.sha256(raw).hexdigest(),
            "sample_sha256": _SAMPLE,
        })
    result = complement_decryption(report, rows)
    assert result["decrypted"] == 0
    assert result["plaintext_endpoints"] == 0
    assert report.endpoints == []
    assert "error_round_not_a_payload_source" in result["gaps"]
