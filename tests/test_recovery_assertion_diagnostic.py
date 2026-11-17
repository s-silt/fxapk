"""Exercise the real assertion wiring with dictionaries, never a native worker."""
from __future__ import annotations

import json

import pytest

from tests import test_recovery_pipeline as pipeline


@pytest.mark.parametrize("failure", [None, "positive", "negative", "algorithm", "missing", "empty", "opaque"])
def test_arithmetic_receipt_assertions_are_bounded(monkeypatch, tmp_path, request, capsys, failure):
    class Opaque:
        def __repr__(self):
            raise AssertionError("diagnostic must not render payload")
        __str__ = __repr__

    good = {"state": "ok", "vectors": [{"returned": True}], "independent_algorithm": False,
            "reason_codes": [], "worker_error": Opaque(), "registers": Opaque()}
    bad = {"state": "failed", "reason_codes": ["emulation_output_mismatch"]}
    if failure in {"positive", "missing", "empty", "opaque"}:
        good["state"] = "failed"
        good["reason_codes"] = ["review_worker_timeout", "synthetic-private-value"]
        if failure == "missing":
            del good["reason_codes"]
        elif failure == "empty":
            good["reason_codes"] = []
        elif failure == "opaque":
            good["reason_codes"] = [Opaque(), "review_worker_exit"]
    elif failure == "negative":
        bad["reason_codes"] = ["review_worker_receipt_invalid", "synthetic-private-value"]
    elif failure == "algorithm":
        good["independent_algorithm"] = True

    calls = []

    def execute(code, options, output):
        assert code == bytes.fromhex("0000018bc0035fd6")  # Existing add/return fixture, not executed.
        assert output == tmp_path
        calls.append(options)
        return good if len(calls) == 1 else bad

    monkeypatch.setattr(pipeline, "execute", execute)
    monkeypatch.setattr(pipeline.pytest, "importorskip", lambda name: None)
    if failure:
        with pytest.raises(AssertionError):
            pipeline.test_real_unicorn_calls_and_negative_vectors(tmp_path, request)
    else:
        pipeline.test_real_unicorn_calls_and_negative_vectors(tmp_path, request)
    out, err = capsys.readouterr()
    assert out == ""
    assert len(calls) == (1 if failure in {"positive", "missing", "empty", "opaque"} else 2)
    if failure is None:
        assert err == ""
        return
    assert err.count("first-failure: ") == 1
    payload = json.loads(err.removeprefix("first-failure: "))
    assert payload["test"] == "recovery_unicorn"
    assert payload["stage"] == ("negative_result" if failure == "negative" else "positive_result")
    assert payload["ownership"] == payload["read_error"] == "unknown"
    assert payload["reasons"] == {
        "positive": ["review_worker_timeout", "unknown"],
        "negative": ["review_worker_receipt_invalid", "unknown"],
        "algorithm": [], "missing": ["unknown"], "empty": [],
        "opaque": ["review_worker_exit", "unknown"],
    }[failure]
    assert set(payload) == {"test", "worker", "stage", "ownership", "read_error", "reasons"}
    assert "synthetic-private-value" not in err


def test_pytest_failure_output_does_not_expand_receipt(tmp_path):
    import os
    from pathlib import Path
    import subprocess
    import sys

    test = tmp_path / "test_synthetic_failure.py"
    test.write_text(
        "from tests import test_recovery_pipeline as pipeline\n"
        "def test_failure(monkeypatch, tmp_path, request):\n"
        "    value = dict(state='failed', reason_codes=['review_worker_exit', 'private-sentinel-opaque'])\n"
        "    monkeypatch.setattr(pipeline, 'execute', lambda *args: value)\n"
        "    monkeypatch.setattr(pipeline.pytest, 'importorskip', lambda name: None)\n"
        "    pipeline.test_real_unicorn_calls_and_negative_vectors(tmp_path, request)\n",
        encoding="utf-8",
    )
    env = {name: value for name, value in os.environ.items() if name.upper() in {
        "PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL",
        "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH",
    }}
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    env["PYTHONIOENCODING"] = "utf-8"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--tb=short", str(test)],
        env=env, capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    assert result.returncode == 1
    output = result.stdout + result.stderr
    assert '"reasons": ["review_worker_exit", "unknown"]' in output
    assert "private-sentinel-opaque" not in output
    assert output.count("first-failure: ") == 1
