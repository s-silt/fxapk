"""Contracts for bounded, local-only first observation diagnostics."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.first_failure_diagnostic import FirstFailureDiagnostic


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


def test_deliberate_pytest_failure_stays_nonzero(tmp_path):
    helper = Path(__file__).with_name("first_failure_diagnostic.py")
    test = tmp_path / "test_deliberate.py"
    test.write_text(
        "import runpy\n"
        f"Diagnostic = runpy.run_path({str(helper)!r})['FirstFailureDiagnostic']\n"
        "def test_failure():\n"
        "    with Diagnostic('diagnostic_contract', 'master') as diagnostic:\n"
        "        diagnostic.observe(stage='reanalyze')\n"
        "        assert False\n", encoding="utf-8",
    )
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", "--tb=short", str(test)],
                            capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert result.returncode == 1
    assert "1 failed" in result.stdout
    assert result.stdout.count("first-failure: ") == 1


def test_unobserved_reasons_differ_from_observed_empty(capsys):
    for reasons, expected in [(None, ["unknown"]), ([], [])]:
        with pytest.raises(AssertionError):
            with FirstFailureDiagnostic("diagnostic_contract") as diagnostic:
                diagnostic.observe(stage="ownership_read", reasons=reasons)
                assert False
        assert _payload(capsys)["reasons"] == expected
