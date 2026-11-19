"""Exercise the versioned Bot entry with a synthetic Git repository."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any
from xml.etree import ElementTree

import pytest

GATE = Path(__file__).resolve().parents[1] / "tools" / "fixed_jadx_gate.py"
MODES = ("full", "limited", "empty", "legacy", "at_byte_limit", "over_byte_limit")
VIEWS = ("json", "html", "digest")


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

    def leave_old_junit(self) -> None:
        suite = ElementTree.Element("testsuite")
        for view in VIEWS:
            for mode in MODES:
                ElementTree.SubElement(
                    suite, "testcase", classname="tests.test_jadx",
                    name=f"test_jadx_coverage_report_{view}[{mode}]",
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
    assert len(receipt["cases"]) == 18


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
