"""Contracts for bounded, local-only first observation diagnostics."""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tests.first_failure_diagnostic import FirstFailureDiagnostic, observe_posix_verification_stage


def _payload(capsys):
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err.count("first-failure: ") == 1
    return json.loads(output.err.removeprefix("first-failure: "))


def test_first_observation_survives_cleanup(capsys):
    diagnostic = FirstFailureDiagnostic("diagnostic_contract", "gw2")
    reasons = ["tree_state_unverified"]
    with pytest.raises(AssertionError, match="original assertion"):
        with diagnostic:
            try:
                diagnostic.observe(stage="ownership_read", read_error="AccessDenied", reasons=reasons)
                assert False, "original assertion"
            finally:
                reasons[:] = ["subprocess_timeout"]
                diagnostic.observe(stage="cleanup", ownership=True)
    assert _payload(capsys) == {
        "test": "diagnostic_contract", "worker": "gw2", "stage": "ownership_read",
        "ownership": "unknown", "read_error": "AccessDenied", "reasons": ["tree_state_unverified"],
    }


@pytest.mark.parametrize("ownership,expected", [(True, "confirmed"), (False, "false"), (None, "unknown")])
def test_ownership_requires_exact_observation(capsys, ownership, expected):
    with pytest.raises(AssertionError):
        with FirstFailureDiagnostic("diagnostic_contract") as diagnostic:
            diagnostic.observe(stage="reanalyze", ownership=ownership, reasons=["tree_state_unverified"])
            assert False
    payload = _payload(capsys)
    assert payload["ownership"] == expected
    assert payload["read_error"] == "unknown"


def test_arbitrary_data_never_serialized(capsys):
    class Opaque:
        def __str__(self):
            raise AssertionError("must not stringify payload")
        __repr__ = __str__
    with pytest.raises(AssertionError, match="unchanged"):
        with FirstFailureDiagnostic(Opaque(), "private-worker-99999") as diagnostic:
            diagnostic.observe(stage=Opaque(), ownership=1, read_error=Opaque(),
                               reasons=[Opaque(), "private-reason", "tree_state_unverified"] + ["private"] * 100)
            assert False, "unchanged"
    payload = _payload(capsys)
    assert payload == {
        "test": "unknown", "worker": "unknown", "stage": "unknown", "ownership": "unknown",
        "read_error": "unknown", "reasons": ["tree_state_unverified", "unknown"],
    }


def test_success_is_quiet_even_with_observed_read_error(capsys):
    with FirstFailureDiagnostic("diagnostic_contract") as diagnostic:
        diagnostic.observe(stage="ownership_read", read_error="AccessDenied")
        assert True
    assert capsys.readouterr() == ("", "")


def test_unobserved_failure_is_unknown_and_preserves_exception(capsys):
    error = AssertionError("unchanged")
    with pytest.raises(AssertionError) as caught:
        with FirstFailureDiagnostic("diagnostic_contract"):
            raise error
    assert caught.value is error
    payload = _payload(capsys)
    assert payload["stage"] == payload["ownership"] == payload["read_error"] == "unknown"
    assert payload["reasons"] == ["unknown"]


_DELIBERATE_FAILURE = "fxapk-first-failure-sentinel"


def _probe_source(assertion: str) -> str:
    helper = Path(__file__).with_name("first_failure_diagnostic.py")
    return (
        "import runpy\n"
        f"Diagnostic = runpy.run_path({str(helper)!r})['FirstFailureDiagnostic']\n"
        "def test_probe():\n"
        "    with Diagnostic('diagnostic_contract', 'master') as diagnostic:\n"
        "        diagnostic.observe(stage='reanalyze')\n"
        f"        {assertion}\n"
    )


def _run_diagnostic_probe(tmp_path: Path, source: str) -> subprocess.CompletedProcess[str]:
    test = tmp_path / "test_deliberate.py"
    test.write_text(source, encoding="utf-8")
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    # The child tests one generated file, independently of the outer runner.
    env = os.environ.copy()
    env.pop("PYTEST_ADDOPTS", None)
    env.pop("PYTEST_PLUGINS", None)
    env.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONIOENCODING="utf-8")
    try:
        # Show captured output for passing children so the silence check can see it.
        return subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-rP", "-c", "pytest.ini", "--noconftest",
             "--tb=short", "--color=no", "-p", "no:cacheprovider", test.name],
            cwd=tmp_path, env=env, capture_output=True, text=True, encoding="utf-8", timeout=30,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("nested pytest: timeout", pytrace=False)
    except (OSError, UnicodeError) as exc:
        problem = "start_failed" if isinstance(exc, OSError) else "invalid_output_encoding"
        pytest.fail(f"nested pytest: {problem}", pytrace=False)


def _check_diagnostic_probe(result: subprocess.CompletedProcess[str], *, deliberate_failure: bool) -> None:
    lines = result.stdout.splitlines() + result.stderr.splitlines()
    assertion = re.compile(rf"E[ \t]+AssertionError: {re.escape(_DELIBERATE_FAILURE)}")
    sentinel = any(assertion.fullmatch(line) for line in lines)
    diagnostics = [line for line in lines if line.startswith("first-failure: ")]
    expected = "first-failure: " + json.dumps({
        "test": "diagnostic_contract", "worker": "master", "stage": "reanalyze",
        "ownership": "unknown", "read_error": "unknown", "reasons": ["unknown"],
    }, sort_keys=True)
    if deliberate_failure:
        accepted = result.returncode == 1 and sentinel and diagnostics == [expected]
    else:
        child_passed = any(re.fullmatch(r"1 passed in [0-9.]+s", line) for line in lines)
        accepted = result.returncode == 0 and child_passed and not sentinel and not diagnostics
    if not accepted:
        # Preserve only a fixed exception label. Paths and arbitrary output can
        # appear in either stream, so do not include excerpts in the failure.
        error = re.search(
            r"(?m)^E[ \t]+(AssertionError|FileNotFoundError|ImportError|ModuleNotFoundError|"
            r"OSError|PermissionError|SyntaxError):",
            result.stdout[-8192:] + "\n" + result.stderr[-8192:],
        )
        kind = error[1] if error else "unknown"
        pytest.fail(f"nested pytest: exit={result.returncode}, sentinel={sentinel}, "
                    f"expected_diagnostic={diagnostics == [expected]}, error_type={kind}", pytrace=False)


def test_deliberate_pytest_failure_stays_nonzero(tmp_path: Path) -> None:
    result = _run_diagnostic_probe(tmp_path, _probe_source(f"assert False, {_DELIBERATE_FAILURE!r}"))
    _check_diagnostic_probe(result, deliberate_failure=True)


def test_deliberate_pytest_success_is_quiet(tmp_path: Path) -> None:
    result = _run_diagnostic_probe(tmp_path, _probe_source("assert True"))
    _check_diagnostic_probe(result, deliberate_failure=False)


def test_deliberate_pytest_rejects_diagnostic_from_passing_child(tmp_path: Path) -> None:
    source = (
        "import sys\n\n"
        "def test_probe() -> None:\n"
        "    print('first-failure: synthetic unexpected diagnostic', file=sys.stderr)\n"
    )
    result = _run_diagnostic_probe(tmp_path, source)
    assert result.returncode == 0
    with pytest.raises(pytest.fail.Exception, match=r"^nested pytest: exit=0, sentinel=False,"):
        _check_diagnostic_probe(result, deliberate_failure=False)
    assert "first-failure: synthetic unexpected diagnostic" in (
        result.stdout.splitlines() + result.stderr.splitlines()
    )


def test_deliberate_pytest_skip_is_not_a_successful_control(tmp_path: Path) -> None:
    source = "import pytest\n\ndef test_probe():\n    pytest.skip('synthetic-private-context')\n"
    result = _run_diagnostic_probe(tmp_path, source)
    with pytest.raises(pytest.fail.Exception) as caught:
        _check_diagnostic_probe(result, deliberate_failure=False)
    assert str(caught.value) == (
        "nested pytest: exit=0, sentinel=False, expected_diagnostic=False, error_type=unknown"
    )


@pytest.mark.parametrize(("source", "status", "kind", "diagnostic"), [
    ("raise ModuleNotFoundError('synthetic-private-context')\n", 2, "ModuleNotFoundError", False),
    (_probe_source("assert False, 'synthetic-private-context'"), 1, "AssertionError", True),
])
def test_deliberate_pytest_rejects_unexpected_failure(
    tmp_path: Path,
    source: str,
    status: int,
    kind: str,
    diagnostic: bool,
) -> None:
    result = _run_diagnostic_probe(tmp_path, source)
    with pytest.raises(pytest.fail.Exception) as caught:
        _check_diagnostic_probe(result, deliberate_failure=True)
    assert str(caught.value) == (f"nested pytest: exit={status}, sentinel=False, "
                                 f"expected_diagnostic={diagnostic}, error_type={kind}")


def test_unobserved_reasons_differ_from_observed_empty(capsys):
    for reasons, expected in [(None, ["unknown"]), ([], [])]:
        with pytest.raises(AssertionError):
            with FirstFailureDiagnostic("diagnostic_contract") as diagnostic:
                diagnostic.observe(stage="ownership_read", reasons=reasons)
                assert False
        assert _payload(capsys)["reasons"] == expected


@pytest.mark.parametrize("failure", [None, "reason", "report"])
def test_reanalysis_late_assertions_emit_filtered_diagnostic(monkeypatch, tmp_path, request, capsys, failure):
    from contextlib import nullcontext

    from tests import test_recovery_pipeline as pipeline

    original_run = pipeline.recovery.run
    reached = []

    def synthetic_run(plan, output):
        value = original_run(plan, output)
        stage = next(row for row in value["stages"] if row["id"] == "reanalyze")
        assert stage["state"] == "partial"  # The first assertion will pass.
        reached.append(True)
        stage["reason_codes"].append("synthetic-private-path-or-command")
        if failure == "reason":
            stage["reason_codes"].remove("reanalyzed_report_partial")
        elif failure == "report":
            (output / "reviewed/report.json").write_text("synthetic altered report", encoding="utf-8")
        return value

    monkeypatch.setattr(pipeline.recovery, "run", synthetic_run)
    with pytest.raises(AssertionError) if failure else nullcontext():
        pipeline.test_reanalysis_status_reaches_recovery_and_report(
            monkeypatch, tmp_path, "partial", False, True, request,
        )
    assert reached == [True]
    if failure:
        payload = _payload(capsys)
        assert payload["test"] == "recovery_reanalysis"
        assert payload["stage"] == "reanalyze"
        assert payload["reasons"] == (["unknown"] if failure == "reason"
                                      else ["reanalyzed_report_partial", "unknown"])
        assert "synthetic-private-path-or-command" not in json.dumps(payload)
    else:
        assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(("first", "later"), [
    ("ownership_scan", "individual_signal"),
    ("individual_signal", "ownership_scan"),
])
def test_posix_stage_observer_filters_records_and_preserves_first(
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
    first: str,
    later: str,
) -> None:
    class Opaque:
        def __str__(self) -> str:
            raise AssertionError("unreviewed argument must not be formatted")

    logger = logging.getLogger("fxapk.core.proctree")
    template = "POSIX tree verification unavailable: stage=%s"
    with caplog.at_level(logging.INFO, logger=logger.name):
        with observe_posix_verification_stage() as observed:
            foreign = logging.LogRecord("another.logger", logging.DEBUG, "", 0, template, (later,), None)
            other_thread = logging.LogRecord(logger.name, logging.DEBUG, "", 0, template, (later,), None)
            other_thread.thread = -1
            logger.handle(foreign)
            logger.handle(other_thread)
            logger.debug(f"POSIX tree verification unavailable: stage={later}")
            logger.debug(template, "unreviewed-private-stage")
            logger.debug(template, Opaque())
            logger.debug(template, later, "extra")
            assert observed() == "unknown"

            logger.debug(template, first)
            logger.debug(template, later)
            logger.info("preexisting logging remains visible")
            assert observed() == first
        assert observed() == first and logger.level == logging.INFO

    assert [record.getMessage() for record in caplog.records if record.name == logger.name] == [
        "preexisting logging remains visible",
    ]
    assert capsys.readouterr() == ("", "")


def test_posix_stage_observer_restores_inherited_level_and_filters_on_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger = logging.getLogger("fxapk.core.proctree")
    inherited_from = "fxapk.core"
    existing = logging.Filter()
    sentinel = RuntimeError("original exception")
    with caplog.at_level(logging.INFO, logger=inherited_from):
        with caplog.at_level(logging.NOTSET, logger=logger.name):
            logger.addFilter(existing)
            try:
                original_filters = tuple(logger.filters)
                with pytest.raises(RuntimeError) as caught:
                    with observe_posix_verification_stage():
                        assert logger.isEnabledFor(logging.DEBUG)
                        raise sentinel
                assert caught.value is sentinel
                assert logger.level == logging.NOTSET
                assert logger.getEffectiveLevel() == logging.INFO
                assert tuple(logger.filters) == original_filters
            finally:
                logger.removeFilter(existing)
