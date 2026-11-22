"""Exercise the versioned Bot entry with a synthetic Git repository."""

from __future__ import annotations

import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
from typing import Any
from xml.etree import ElementTree

import pytest

GATE = Path(__file__).resolve().parents[1] / "tools" / "fixed_jadx_gate.py"
GATE_API = runpy.run_path(str(GATE))
NODES = GATE_API["NODES"]
AUDIT = GATE_API["audit"]
MODES = ("full", "limited", "empty", "legacy", "at_byte_limit", "over_byte_limit")
VIEWS = ("json", "html", "digest")
NORMAL = [("setup", "passed"), ("call", "passed"), ("teardown", "passed")]


def junit_key(node: str) -> tuple[str, str]:
    module, name = node.split("::", 1)
    return module[:-3].replace("/", "."), name


def normal_phases() -> dict[str, list[tuple[str, str]]]:
    return {node: list(NORMAL) for node in NODES}


def write_junit(path: Path, cases: list[tuple[str, str]]) -> Path:
    suite = ElementTree.Element("testsuite")
    for classname, name in cases:
        ElementTree.SubElement(suite, "testcase", classname=classname, name=name)
    ElementTree.ElementTree(suite).write(path)
    return path


class ToyRepo:
    def __init__(self, tmp_path: Path) -> None:
        self.path = tmp_path / "repo"
        self.path.mkdir()
        self.scratch = tmp_path / "scratch"
        self.scratch.mkdir()
        home = tmp_path / "home"
        home.mkdir()
        self.env = {
            "PATH": os.environ.get("PATH", os.defpath), "HOME": str(home),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "Synthetic", "GIT_COMMITTER_NAME": "Synthetic",
            "GIT_AUTHOR_EMAIL": "synthetic@example.invalid",
            "GIT_COMMITTER_EMAIL": "synthetic@example.invalid",
        }
        if "SystemRoot" in os.environ:
            self.env["SystemRoot"] = os.environ["SystemRoot"]
        self.git("init", "--quiet", "--template=")
        self.write("tools/fixed_jadx_gate.py", GATE.read_text(encoding="utf-8"))
        self.write("fxapk/__init__.py", "")
        self.write("tests/__init__.py", "")
        self.write(".gitattributes", "fxapk/sample_value.py export-ignore\n")
        self.write("fxapk/sample_value.py", "value = 1\n")
        self.write_tests()
        self.write_visibility()
        self.git("add", ".")
        tree = self.git("write-tree")
        commit = self.git("commit-tree", tree, "-m", "synthetic fixture")
        self.git("update-ref", "HEAD", commit)

    def git(self, *args: str) -> str:
        return subprocess.check_output(
            ["git", *args], cwd=self.path, env=self.env, text=True,
        ).strip()

    def write(self, relative: str, content: str) -> None:
        target = self.path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")

    def write_tests(self, variant: str = "") -> None:
        source = ["import pytest", "from fxapk.sample_value import value"]
        for view in VIEWS:
            modes = MODES[:-1] if variant == "missing" and view == "html" else MODES
            source.append(f'@pytest.mark.parametrize("mode", {modes!r})')
            if variant == "xpass" and view == "html":
                source.append("@pytest.mark.xfail(strict=False)")
            source.append(f"def test_jadx_coverage_report_{view}(mode):")
            if variant == "skip" and view == "html":
                source.append('    if mode == "limited": pytest.skip("synthetic")')
            source.append("    assert value == 1")
        self.write("tests/test_jadx.py", "\n".join(source) + "\n")

    def write_visibility(self) -> None:
        self.write(
            "tests/test_visibility.py",
            "from fxapk.sample_value import value\n\n\n"
            "def test_java_truncated_full_count_in_html():\n"
            "    assert value == 1\n",
        )

    def leave_old_junit(self) -> None:
        suite = ElementTree.Element("testsuite")
        for view in VIEWS:
            for mode in MODES:
                ElementTree.SubElement(
                    suite, "testcase", classname="tests.test_jadx",
                    name=f"test_jadx_coverage_report_{view}[{mode}]",
                )
        ElementTree.SubElement(
            suite, "testcase", classname="tests.test_visibility",
            name="test_java_truncated_full_count_in_html",
        )
        ElementTree.ElementTree(suite).write(self.path / "result.xml")

    def gate(self) -> tuple[int, dict[str, Any]]:
        completed = subprocess.run(
            [sys.executable, "-I", "tools/fixed_jadx_gate.py", "--scratch", str(self.scratch)],
            cwd=self.path, env=self.env, capture_output=True, text=True, check=False,
        )
        return completed.returncode, json.loads(completed.stdout)


def test_gate_reads_staged_blobs_instead_of_worktree(tmp_path: Path) -> None:
    repo = ToyRepo(tmp_path)
    repo.write("fxapk/sample_value.py", "value = 0\n")
    repo.git("add", "fxapk/sample_value.py")
    bad_tree = repo.git("write-tree")
    repo.write("fxapk/sample_value.py", "value = 1\n")
    assert repo.git("show", ":fxapk/sample_value.py") == "value = 0"
    code, receipt = repo.gate()
    assert code == 1 and receipt["accepted"] is False
    assert receipt["index_tree"] == bad_tree
    assert any("JUnit failure" in problem for problem in receipt["problems"])

    repo.git("add", "fxapk/sample_value.py")
    good_tree = repo.git("write-tree")
    repo.write("fxapk/sample_value.py", "value = 0\n")
    code, receipt = repo.gate()
    assert code == 0 and receipt["accepted"] is True
    assert receipt["index_tree"] == good_tree != bad_tree
    assert receipt["version"] == "jadx-report-v3"
    assert receipt["cases"][-1] == "tests/test_visibility.py::test_java_truncated_full_count_in_html"
    assert len(receipt["cases"]) == 19


@pytest.mark.parametrize(("variant", "diagnostic"), [
    ("skip", "JUnit skipped"),
    ("xpass", "xfail/xpass"),
    ("missing", "expected one JUnit case"),
])
def test_gate_rejects_nonclean_results_even_with_prior_junit(
    tmp_path: Path, variant: str, diagnostic: str,
) -> None:
    repo = ToyRepo(tmp_path)
    repo.leave_old_junit()
    repo.write_tests(variant)
    repo.git("add", "tests/test_jadx.py")
    code, receipt = repo.gate()
    assert code == 1 and receipt["accepted"] is False
    assert any(diagnostic in problem for problem in receipt["problems"])
    if variant in {"skip", "xpass"}:
        assert receipt["pytest_exit"] == 0


@pytest.mark.parametrize(("mutation", "diagnostic"), [
    ("missing", "expected one JUnit case"),
    ("duplicate", "expected one JUnit case, got 2"),
    ("wrong_classname", "unexpected JUnit case"),
])
def test_audit_rejects_bad_new_visibility_case(
    tmp_path: Path, mutation: str, diagnostic: str,
) -> None:
    cases = [junit_key(node) for node in NODES]
    if mutation == "missing":
        cases.pop()
    elif mutation == "duplicate":
        cases.append(junit_key(NODES[-1]))
    else:
        cases[-1] = ("tests.test_jadx", NODES[-1].split("::", 1)[1])
    problems = AUDIT(write_junit(tmp_path / "result.xml", cases), normal_phases(), 0)
    assert any(diagnostic in problem for problem in problems)
    if mutation == "missing":
        assert any(NODES[-1] in problem for problem in problems)


@pytest.mark.parametrize("child", ["skipped", "failure", "error"])
def test_audit_rejects_new_visibility_child(tmp_path: Path, child: str) -> None:
    cases = [junit_key(node) for node in NODES]
    suite = ElementTree.Element("testsuite")
    for classname, name in cases:
        case = ElementTree.SubElement(suite, "testcase", classname=classname, name=name)
        if (classname, name) == cases[-1]:
            ElementTree.SubElement(case, child)
    report = tmp_path / "result.xml"
    ElementTree.ElementTree(suite).write(report)
    problems = AUDIT(report, normal_phases(), 0)
    assert any(f"{NODES[-1]}: JUnit {child}" in problem for problem in problems)


def test_audit_rejects_new_visibility_xpass_phase(tmp_path: Path) -> None:
    report = write_junit(tmp_path / "result.xml", [junit_key(node) for node in NODES])
    phases = normal_phases()
    phases[NODES[-1]] = [("setup", "passed"), ("call", "xfail/xpass"), ("teardown", "passed")]
    problems = AUDIT(report, phases, 0)
    assert any("xfail/xpass" in problem for problem in problems)


def test_gate_rejects_missing_new_visibility_node(tmp_path: Path) -> None:
    repo = ToyRepo(tmp_path)
    repo.write("tests/test_visibility.py", "from fxapk.sample_value import value\n")
    repo.git("add", "tests/test_visibility.py")
    code, receipt = repo.gate()
    assert code == 1 and receipt["accepted"] is False
    assert receipt["pytest_exit"] != 0


def test_gate_ignores_stale_junit_for_new_visibility_node(tmp_path: Path) -> None:
    repo = ToyRepo(tmp_path)
    repo.leave_old_junit()
    repo.write("tests/test_visibility.py", "from fxapk.sample_value import value\n")
    repo.git("add", "tests/test_visibility.py")
    code, receipt = repo.gate()
    assert code == 1 and receipt["accepted"] is False


def test_gate_does_not_take_new_visibility_node_from_worktree(tmp_path: Path) -> None:
    repo = ToyRepo(tmp_path)
    repo.write("tests/test_visibility.py", "from fxapk.sample_value import value\n")
    repo.git("add", "tests/test_visibility.py")
    repo.write_visibility()
    code, receipt = repo.gate()
    assert code == 1 and receipt["accepted"] is False


@pytest.mark.parametrize(("version", "case_count"), [
    ("jadx-report-v2", 19),
    ("jadx-report-v3", 18),
])
def test_dispatcher_rejects_old_or_incomplete_receipt(version: str, case_count: int) -> None:
    dispatcher = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "tools" / "local_candidate_commit.py")
    )
    receipt = {
        "version": version,
        "base_head": "0" * 40,
        "index_tree": "1" * 40,
        "accepted": True,
        "cases": list(NODES)[:case_count],
        "problems": [],
        "pytest_exit": 0,
    }
    with pytest.raises(dispatcher["Rejected"]):
        dispatcher["validate_gate"](json.dumps(receipt).encode(), "0" * 40, "1" * 40)


def test_gate_scripts_keep_lf_in_autocrlf_checkout(tmp_path: Path) -> None:
    repo = ToyRepo(tmp_path)
    source = GATE.parents[1]
    scripts = (".githooks/pre-commit", "tools/fixed_jadx_gate.py")
    for relative in (".gitattributes", *scripts):
        path = repo.path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((source / relative).read_bytes())
    repo.git("add", "--", ".gitattributes", *scripts)
    tree = repo.git("write-tree")
    commit = repo.git("commit-tree", tree, "-m", "synthetic source tree")
    repo.git("update-ref", "HEAD", commit)

    checkout = tmp_path / "checkout"
    repo.git("clone", "--quiet", "-c", "core.autocrlf=true", "--", str(repo.path), str(checkout))
    assert repo.git("-C", str(checkout), "status", "--porcelain") == ""
    for relative in scripts:
        checked_out = (checkout / relative).read_bytes()
        assert b"\r\n" not in checked_out, relative
        assert checked_out == (source / relative).read_bytes(), relative
