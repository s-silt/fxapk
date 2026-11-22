"""Pure controls for the isolated native fixture receipt and coverage insertion."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools import ci_descendant_fixture as gate


def fixture_receipt() -> dict[str, object]:
    return dict(schema="fxapk.container_fixture.v1", nonce="fresh", head="head", tree="tree",
                dep_wait=0, pytest_wait=0, setup=True, source_verified=True, pins_verified=True,
                cleanup_before_exit=True, ordinary_phases=True, junit="one_passed", status="fixture_passed",
                coverage_lines={"fxapk/core/proctree.py": [1]})


@pytest.mark.parametrize("change", [
    {"nonce": "stale"},
    {"cleanup_before_exit": False},
    {"junit": "nonpass"},
    {"ordinary_phases": False},
    {"pytest_wait": False},
    {"tree": "stale"},
])
def test_isolated_receipt_retains_strict_predicates(change: dict[str, object]) -> None:
    state = fixture_receipt()
    encoded = json.dumps(state).encode()
    assert gate.receipt(encoded, "fresh", "head", "tree", 0, b"0") == state["coverage_lines"]
    state.update(change)
    with pytest.raises(gate.IsolationFailure):
        gate.receipt(json.dumps(state).encode(), "fresh", "head", "tree", 0, b"0")


def test_isolated_receipt_checks_outer_result() -> None:
    with pytest.raises(gate.IsolationFailure, match="container_result_unverified"):
        gate.receipt(json.dumps(fixture_receipt()).encode(), "fresh", "head", "tree", 0, b"1")


@pytest.mark.parametrize(("bad_path", "bad_lines"), [
    ("/src/fxapk/core/proctree.py", [1]),
    ("fxapk/../else.py", [1]),
    ("fxapk/core/proctree.py", [False]),
    ("fxapk/core/proctree.py", [4]),
    ("fxapk/core/proctree.py", [1, 1]),
])
def test_isolated_coverage_rejects_unverified_paths_and_lines(
    tmp_path: Path, bad_path: str, bad_lines: list[int],
) -> None:
    source = tmp_path / "fxapk/core/proctree.py"
    source.parent.mkdir(parents=True)
    source.write_text("one\nsecond\nthird\n", encoding="utf-8")
    normal = {"fxapk/core/proctree.py": [1, 3]}
    assert gate.normalized_lines(tmp_path, normal) == {str(source): [1, 3]}
    with pytest.raises(gate.IsolationFailure):
        gate.normalized_lines(tmp_path, {**normal, bad_path: bad_lines})


def test_isolated_coverage_appends_host_lines(tmp_path: Path) -> None:
    coverage = pytest.importorskip("coverage")
    source = tmp_path / "fxapk/core/proctree.py"
    source.parent.mkdir(parents=True)
    source.write_text("one\nsecond\nthird\n", encoding="utf-8")
    existing = coverage.CoverageData(basename=str(tmp_path / ".coverage"))
    existing.add_lines({str(source): [1]})
    existing.write()
    gate.merge_coverage(tmp_path, {"fxapk/core/proctree.py": [2, 3]})
    combined = coverage.CoverageData(basename=str(tmp_path / ".coverage"))
    combined.read()
    assert combined.measured_files() == {str(source)}
    assert sorted(combined.lines(str(source))) == [1, 2, 3]


def test_isolated_fixture_junit_matches_only_the_non_skipped_selector(tmp_path: Path) -> None:
    xml = tmp_path / "junit.xml"
    tag = '<testcase classname="tests.test_proctree" name="test_descendants_after_root_exit_force_killed" />'
    def normal(body: str, tests: int, skips: int) -> str:
        return ('<testsuites><testsuite errors="0" failures="0" '
                f'tests="{tests}" skipped="{skips}">{body}</testsuite></testsuites>')
    for data, expected in ((normal(tag, 1, 0), "one_passed"),
                           (normal(tag + tag, 2, 0), "invalid"),
                           (normal(tag.replace(" />", "><skipped /></testcase>"), 1, 1), "nonpass"),
                           (normal(tag.replace("tests.test_proctree", "wrong"), 1, 0), "invalid")):
        xml.write_text(data, encoding="utf-8")
        assert gate.junit(xml) == expected



def known_diagnostic() -> dict[str, object]:
    return {
        "test": "ownership_descendants", "worker": "master", "stage": "termination_check",
        "ownership": "confirmed", "read_error": "unknown",
        "reasons": ["descendants_after_root_exit", "tree_state_unverified"],
        "posix_verification_stage": "ownership_scan", "posix_probe": "environ", "posix_error": "AccessDenied",
    }


@pytest.mark.parametrize("variant", ["normal", "xpass", "failure", "opaque"])
def test_real_pytest_observation_distinguishes_xpass_and_filters_failures(tmp_path: Path, variant: str) -> None:
    import xml.etree.ElementTree as ET

    private = "do-not-export-synthetic-pid-or-argv"
    event = known_diagnostic()
    record = dict(event, argv=[private], pid=424242) if variant == "opaque" else event
    content = "def test_target():\n    assert True\n"
    if variant == "xpass":
        content = "import pytest\n@pytest.mark.xfail(strict=False)\n" + content
    elif variant in ("failure", "opaque"):
        content = ("import sys\n"
                   "def test_target():\n"
                   f"    print({('first-failure: ' + json.dumps(record))!r}, file=sys.stderr)\n"
                   f"    print({private!r}, file=sys.stderr)\n"
                   f"    assert False, {private!r}\n")
    name = f"test_control_{variant}.py"
    (tmp_path / name).write_text(content, encoding="utf-8")
    result = tmp_path / "result.xml"
    witness = tmp_path / "witness.json"
    helper = Path(__file__).resolve().parents[1] / "tools/ci_descendant_fixture.py"
    driver = (
        "import json, runpy, sys; from pathlib import Path; "
        "gate = runpy.run_path(sys.argv[1]); "
        "code, plain, diagnostic = gate['run_pytest'](sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4])); "
        "Path(sys.argv[5]).write_text(json.dumps([plain, diagnostic]), encoding='utf-8'); "
        "raise SystemExit(code)"
    )
    env = {key: value for key, value in os.environ.items()
           if key not in {"PYTEST_PLUGINS", "PYTEST_ADDOPTS", "PYTHONPATH", "PYTHONHOME"}}
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    child = subprocess.run([sys.executable, "-IB", "-c", driver, str(helper), f"{name}::test_target",
                            str(result), str(tmp_path / "temp"), str(witness)],
                           cwd=tmp_path, env=env, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=20, check=False)
    code = child.returncode
    plain, diagnostic = json.loads(witness.read_text(encoding="utf-8"))
    assert code == (1 if variant in ("failure", "opaque") else 0)
    assert plain is (variant == "normal")
    assert diagnostic == (event if variant == "failure" else None)
    assert private not in json.dumps(diagnostic)
    if variant == "xpass":
        [case] = ET.parse(result).getroot().iter("testcase")
        assert not len(case), "JUnit looks green; only the separate pytest hook rejects XPASS"


@pytest.mark.parametrize("malicious", [False, True])
def test_host_failure_keeps_only_matching_allowlisted_diagnostic(malicious: bool) -> None:
    receipt = fixture_receipt()
    event = known_diagnostic()
    sent = {**event, "posix_probe": "do-not-export-synthetic-path"} if malicious else event
    receipt.update(status="fixture_failed", pytest_wait=1, junit="one_failed", ordinary_phases=False,
                   diagnostic=sent)
    with pytest.raises(gate.IsolationFailure, match="^fixture_failed$") as result:
        gate.receipt(json.dumps(receipt).encode(), "fresh", "head", "tree", 1, b"1")
    assert result.value.diagnostic == (None if malicious else event)
