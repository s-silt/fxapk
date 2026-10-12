from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest


@pytest.fixture
def runtime(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "plugins/fxapk-rea/src"))
    return importlib.import_module("fxapk_rea.runtime")


def test_bounded_runner_preserves_exact_bytes(runtime, tmp_path):
    code = "import sys;sys.stdout.buffer.write(b'\\xff\\r\\n');sys.stderr.buffer.write(b'private-diagnostic')"
    result = runtime.run_bounded(
        [sys.executable, "-c", code], tmp_path / "run", timeout=5, max_stdout=1024
    )
    assert result["ok"] is True
    assert (tmp_path / "run/stdout.bin").read_bytes() == b"\xff\r\n"
    assert (tmp_path / "run/stderr.bin").read_bytes() == b"private-diagnostic"
    assert "private-diagnostic" not in json.dumps(result)


def test_output_overflow_is_failure_not_truncated_success(runtime, tmp_path):
    result = runtime.run_bounded(
        [sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'x'*1000000)"],
        tmp_path / "run",
        timeout=5,
        max_stdout=1024,
    )
    assert result["ok"] is False
    assert result["streams"]["stdout"]["truncated"] is True
    assert (tmp_path / "run/stdout.bin").stat().st_size == 1024


def test_timeout_is_failure_with_process_tree_receipt(runtime, tmp_path):
    result = runtime.run_bounded(
        [sys.executable, "-c", "import time;time.sleep(30)"],
        tmp_path / "run",
        timeout=0.5,
        max_stdout=1024,
    )
    assert result["ok"] is False
    assert result["process_tree"]["timed_out"] is True
    assert result["process_tree"]["termination_complete"] is True


def test_nonzero_exit_cannot_pass(runtime, tmp_path):
    result = runtime.run_bounded(
        [sys.executable, "-c", "raise SystemExit(7)"], tmp_path / "run", timeout=5, max_stdout=1024
    )
    assert result["ok"] is False
    assert result["exit_code"] == 7


@pytest.mark.parametrize(
    "version,available", [("6.4.0", True), ("6.5.0", False), ("nonsense", False)]
)
def test_runtime_requires_verified_version(runtime, tmp_path, monkeypatch, version, available):
    executable = tmp_path / "rea"
    executable.write_text("synthetic")

    def execute(argv, out, **kwargs):
        out.mkdir()
        (out / "stdout.bin").write_text(version)
        return {"ok": True}

    monkeypatch.setattr(runtime, "run_bounded", execute)
    result = runtime.ReaRuntime(str(executable)).capabilities()
    assert (result["capabilities"]["inspect"] == "available") is available
    assert result["capabilities"]["import"] == "available"


def test_unverified_tree_does_not_credit_child_payload(runtime, tmp_path, monkeypatch):
    from apkscan.core.proctree import OwnedRun

    monkeypatch.setattr(
        runtime,
        "run_owned",
        lambda *a, **kw: OwnedRun(
            0, '{"exit_code":0}', "", False, False, False, False, ("internal_error",)
        ),
    )
    result = runtime.run_bounded(
        [sys.executable, "-c", "pass"], tmp_path / "run", timeout=5, max_stdout=1024
    )
    assert result["ok"] is False


def test_inspect_origin_option_is_one_plain_array_element(runtime, tmp_path, monkeypatch):
    executable = tmp_path / "rea"
    executable.write_text("synthetic")
    seen = []

    def execute(argv, *args, **kwargs):
        seen.extend(argv)
        return {"ok": True}

    monkeypatch.setattr(runtime, "run_bounded", execute)
    runtime.ReaRuntime(str(executable)).inspect(
        "http://127.0.0.1:9222",
        "synthetic",
        "https://example.test",
        tmp_path / "out",
        observation_ms=1000,
    )
    assert seen[seen.index("--allowed-origins") + 1] == "https://example.test"
