from __future__ import annotations

import importlib
import json
import logging
import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from tests.first_failure_diagnostic import FirstFailureDiagnostic, observe_posix_verification_stage


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


def test_timeout_is_failure_with_process_tree_receipt(
    runtime: ModuleType | SimpleNamespace, tmp_path: Path,
) -> None:
    details: dict[str, str] = {}
    with FirstFailureDiagnostic("rea_runtime_timeout", os.environ.get("PYTEST_XDIST_WORKER", "master")) as diagnostic:
        with observe_posix_verification_stage(details=details) as observed:
            result = runtime.run_bounded(
                [sys.executable, "-c", "import time;time.sleep(30)"],
                tmp_path / "run",
                timeout=0.5,
                max_stdout=1024,
            )
        tree = result["process_tree"]
        diagnostic.observe(
            stage="termination_check",
            ownership=tree.get("ownership_complete"),
            reasons=tree.get("reason_codes"),
            posix_verification_stage=observed(),
            **details,
        )
        assert result["ok"] is False
        assert tree["timed_out"] is True
        assert tree["termination_complete"] is True


@pytest.mark.parametrize(("reasons", "details"), [
    (["tree_state_unverified"], {"posix_verification_stage": "unknown"}),
    (["tree_state_unverified"], {
        "posix_verification_stage": "ownership_scan",
        "posix_probe": "getpgid",
        "posix_error": "PermissionError",
    }),
    (["survivors_after_kill", "process_exit_unverified"], {}),
])
def test_timeout_failure_emits_allowlisted_diagnostic(
    reasons: list[str], details: dict[str, str], tmp_path: Path,
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw1")
    tree = {
        "timed_out": True,
        "ownership_complete": True,
        "termination_complete": False,
        "reason_codes": ["timeout", *reasons, "synthetic-private-marker"],
        "pids": [1234],
    }

    def run_bounded(*_args: object, **_kwargs: object) -> dict[str, object]:
        if details.get("posix_verification_stage") == "ownership_scan":
            logging.getLogger("fxapk.core.proctree").debug(
                "POSIX tree verification unavailable: stage=%s", "ownership_scan",
                extra={"posix_probe": "getpgid", "posix_error": "PermissionError"},
            )
        return {"ok": False, "process_tree": tree}

    fake = SimpleNamespace(run_bounded=run_bounded)
    with pytest.raises(AssertionError):
        test_timeout_is_failure_with_process_tree_receipt(fake, tmp_path)
    out, err = capsys.readouterr()
    assert out == ""
    assert err.count("first-failure: ") == 1
    payload = json.loads(err.removeprefix("first-failure: "))
    assert payload == {
        "test": "rea_runtime_timeout", "worker": "gw1", "stage": "termination_check",
        "ownership": "confirmed", "read_error": "unknown",
        "reasons": sorted(["timeout", *reasons, "unknown"]),
        **details,
    }


def test_timeout_success_keeps_diagnostic_quiet(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    tree = {"timed_out": True, "ownership_complete": True, "termination_complete": True,
            "reason_codes": ["timeout"]}

    def run_bounded(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {"ok": False, "process_tree": tree}

    fake = SimpleNamespace(run_bounded=run_bounded)
    test_timeout_is_failure_with_process_tree_receipt(fake, tmp_path)
    assert capsys.readouterr() == ("", "")


def test_nonzero_exit_cannot_pass(runtime, tmp_path):
    result = runtime.run_bounded(
        [sys.executable, "-c", "raise SystemExit(7)"], tmp_path / "run", timeout=5, max_stdout=1024
    )
    assert result["ok"] is False
    assert result["exit_code"] == 7


@pytest.mark.parametrize(
    "version,available", [("6.4.0", True), ("6.7.0", True), ("6.5.0", False), ("nonsense", False)]
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
    from fxapk.core.proctree import OwnedRun

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


def test_rea_runtime_uses_safe_which_not_bare_path(runtime, monkeypatch):
    """★安全回归：rea/node 查找必须走 safe_which（防 Windows 当前目录二进制投放）。"""
    seen: list[str] = []

    def _safe(name: str):
        seen.append(name)
        return None

    monkeypatch.setattr(runtime, "safe_which", _safe)
    runtime.ReaRuntime()
    assert seen == ["rea", "node"]
