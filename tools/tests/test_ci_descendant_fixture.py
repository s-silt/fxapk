"""Pure controls for the isolated native fixture receipt and coverage insertion."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools import ci_descendant_fixture as gate


def fixture_receipt():
    return dict(schema="fxapk.container_fixture.v1", nonce="fresh", head="head", tree="tree",
                dep_wait=0, pytest_wait=0, setup=True, source_verified=True, pins_verified=True,
                cleanup_before_exit=True, junit="one_passed", status="fixture_passed",
                coverage_lines={"fxapk/core/proctree.py": [1]})


@pytest.mark.parametrize("change", [
    {"nonce": "stale"},
    {"cleanup_before_exit": False},
    {"junit": "nonpass"},
    {"pytest_wait": False},
    {"tree": "stale"},
])
def test_isolated_receipt_retains_strict_predicates(change):
    state = fixture_receipt()
    encoded = json.dumps(state).encode()
    assert gate.receipt(encoded, "fresh", "head", "tree", 0, b"0") == state["coverage_lines"]
    state.update(change)
    with pytest.raises(gate.IsolationFailure):
        gate.receipt(json.dumps(state).encode(), "fresh", "head", "tree", 0, b"0")


def test_isolated_receipt_checks_outer_result():
    with pytest.raises(gate.IsolationFailure, match="container_result_unverified"):
        gate.receipt(json.dumps(fixture_receipt()).encode(), "fresh", "head", "tree", 0, b"1")


@pytest.mark.parametrize(("bad_path", "bad_lines"), [
    ("/src/fxapk/core/proctree.py", [1]),
    ("fxapk/../else.py", [1]),
    ("fxapk/core/proctree.py", [False]),
    ("fxapk/core/proctree.py", [4]),
    ("fxapk/core/proctree.py", [1, 1]),
])
def test_isolated_coverage_rejects_unverified_paths_and_lines(tmp_path, bad_path, bad_lines):
    source = tmp_path / "fxapk/core/proctree.py"
    source.parent.mkdir(parents=True)
    source.write_text("one\nsecond\nthird\n", encoding="utf-8")
    normal = {"fxapk/core/proctree.py": [1, 3]}
    assert gate.normalized_lines(tmp_path, normal) == {str(source): [1, 3]}
    with pytest.raises(gate.IsolationFailure):
        gate.normalized_lines(tmp_path, {**normal, bad_path: bad_lines})


def test_isolated_coverage_appends_host_lines(tmp_path):
    import coverage
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


def test_isolated_fixture_junit_matches_only_the_non_skipped_selector(tmp_path: Path):
    xml = tmp_path / "junit.xml"
    tag = '<testcase classname="tests.test_proctree" name="test_descendants_after_root_exit_force_killed" />'
    def normal(body, tests, skips):
        return ('<testsuites><testsuite errors="0" failures="0" '
                f'tests="{tests}" skipped="{skips}">{body}</testsuite></testsuites>')
    for data, expected in ((normal(tag, 1, 0), "one_passed"),
                           (normal(tag + tag, 2, 0), "invalid"),
                           (normal(tag.replace(" />", "><skipped /></testcase>"), 1, 1), "nonpass"),
                           (normal(tag.replace("tests.test_proctree", "wrong"), 1, 0), "invalid")):
        xml.write_text(data, encoding="utf-8")
        assert gate.junit(xml) == expected
