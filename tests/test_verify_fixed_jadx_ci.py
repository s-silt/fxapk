"""Synthetic controls for the hosted staged-snapshot receipt."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

import pytest
import yaml

from tools.fixed_jadx_gate import NODES, VERSION
from tools.verify_fixed_jadx_ci import accepts_receipt


HEAD = "a" * 40
TREE = "b" * 40
NO_PRINT = "synthetic receipt text not for the log"
ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")


@pytest.fixture
def receipt() -> dict[str, object]:
    return {
        "version": VERSION, "base_head": HEAD, "index_tree": TREE, "cases": list(NODES),
        "pytest_exit": 0, "accepted": True, "problems": [],
    }


def test_exact_receipt(receipt: dict[str, object]) -> None:
    assert len(NODES) == 19
    assert accepts_receipt(receipt, HEAD, TREE)


@pytest.mark.parametrize(("field", "value"), [
    ("version", "jadx-report-v2"),
    ("base_head", "c" * 40),
    ("index_tree", "d" * 40),
    ("cases", list(NODES[:-1])),
    ("cases", [*NODES[:-1], NODES[0]]),
    ("cases", list(reversed(NODES))),
    ("pytest_exit", 1),
    ("pytest_exit", False),
    ("pytest_exit", 0.0),
    ("accepted", 1),
    ("accepted", False),
    ("problems", [NO_PRINT]),
])
def test_rejects_nonmatching_receipt(
    receipt: dict[str, object], field: str, value: object,
) -> None:
    receipt[field] = value
    assert not accepts_receipt(receipt, HEAD, TREE)
    del receipt[field]
    assert not accepts_receipt(receipt, HEAD, TREE)


def test_receipt_cli_rejects_missing_or_malformed_input(
    tmp_path: Path, receipt: dict[str, object],
) -> None:
    path = tmp_path / "receipt.json"
    command = [sys.executable, "-m", "tools.verify_fixed_jadx_ci", str(path), HEAD, TREE]
    canonical = json.dumps(receipt)
    for payload in (
        None, b"{", b"\xff", b"[]", b" " * 16_384 + canonical.encode(),
        json.dumps({**receipt, "unexpected": NO_PRINT}).encode(),
        ('{"accepted": false,' + canonical[1:]).encode(),
    ):
        if payload is not None:
            path.write_bytes(payload)
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        assert result.returncode == 1
        assert result.stdout == ""
        assert result.stderr.strip() == "fixed JADX: receipt validation failed"
    path.write_text(canonical, encoding="utf-8")
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout.splitlines() == [json.dumps(receipt, sort_keys=True)]


def _workflow() -> dict[str | bool, Any]:
    return yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))


def test_hosted_trigger_and_default_checkout_scope() -> None:
    workflow = _workflow()
    triggers = workflow.get("on", workflow.get(True))
    assert isinstance(triggers, dict)
    assert "pull_request_target" not in triggers
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["fixed-jadx-snapshot"]
    assert "permissions" not in job
    assert "continue-on-error" not in job
    assert job["runs-on"] == "ubuntu-latest"
    assert job["if"] == (
        "(github.event_name == 'push' && github.ref == 'refs/heads/master' && "
        "github.ref_protected && !github.event.deleted) || "
        "(github.event_name == 'pull_request' && github.base_ref == 'master' && "
        "github.event.pull_request.head.repo['id'] && "
        "github.event.pull_request.head.repo['id'] == github.event.repository['id'])"
    )
    assert job["steps"][0]["with"] == {"persist-credentials": False}
    assert job["steps"][-1]["id"] == "fixed-jadx-receipt"


@pytest.mark.skipif(BASH is None, reason="Hosted step control requires Bash")
@pytest.mark.parametrize(("scenario", "expected_exit", "stage"), [
    ("valid", 0, ""),
    ("wrong_tree", 1, "receipt validation failed"),
    ("extra_field", 1, "receipt validation failed"),
    ("duplicate_key", 1, "receipt validation failed"),
    ("gate_rejected", 2, "outer gate failed (exit 2)"),
    ("checkout_mismatch", 1, "initial checkout verification failed"),
    ("dirty_index", 1, "initial checkout verification failed"),
    ("dirty_worktree", 1, "initial checkout verification failed"),
    ("dirty_after_gate", 1, "final checkout verification failed"),
])
def test_hosted_step_requires_exact_checkout_and_successful_gate(
    tmp_path: Path, receipt: dict[str, object], scenario: str, expected_exit: int, stage: str,
) -> None:
    assert BASH is not None
    script = _workflow()["jobs"]["fixed-jadx-snapshot"]["steps"][-1]["run"]
    repo = tmp_path / "checkout"
    repo.mkdir()
    runner_temp = tmp_path / "runner"
    runner_temp.mkdir()

    def git(*args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()

    git("init", "-q")
    git("config", "user.name", "Synthetic Fixture")
    git("config", "user.email", "fixture@example.test")
    (repo / "tools").mkdir()
    for name in ("fixed_jadx_gate.py", "verify_fixed_jadx_ci.py"):
        shutil.copyfile(ROOT / "tools" / name, repo / "tools" / name)
    (repo / ".githooks").mkdir()
    marker = repo / "tracked.txt"
    marker.write_text("unchanged\n", encoding="utf-8")
    # This control substitutes only the outer hook; the real gate has its own tests.
    (repo / ".githooks/pre-commit").write_text(
        "#!/bin/sh\n"
        "test \"$1\" = --fixed-jadx && test \"$2\" = --scratch && test -d \"$3\" || exit 90\n"
        "printf '%s\\n' \"$FIXTURE_STDERR\" >&2\n"
        "if [ \"$FIXTURE_MUTATE\" = yes ]; then printf '%s\\n' changed >tracked.txt; fi\n"
        "printf '%s\\n' \"$FIXTURE_RECEIPT\"\n"
        "exit \"$FIXTURE_EXIT\"\n",
        encoding="utf-8", newline="\n",
    )
    git("add", ".")
    git("config", "core.hooksPath", ".git/hooks")
    git("commit", "-qm", "synthetic runner fixture")
    head = git("rev-parse", "HEAD")
    receipt["base_head"] = head
    receipt["index_tree"] = "0" * 40 if scenario == "wrong_tree" else git("write-tree")
    if scenario in {"dirty_index", "dirty_worktree"}:
        marker.write_text("changed\n", encoding="utf-8")
        if scenario == "dirty_index":
            git("add", "tracked.txt")
    raw = json.dumps(receipt)
    if scenario == "extra_field":
        raw = json.dumps({**receipt, "unexpected": NO_PRINT})
    elif scenario == "duplicate_key":
        raw = '{"accepted": false,' + raw[1:]
    elif scenario == "gate_rejected":
        raw = NO_PRINT
    env = {
        **os.environ,
        "PATH": os.pathsep.join((str(Path(sys.executable).parent), os.environ["PATH"])),
        "GITHUB_SHA": "0" * 40 if scenario == "checkout_mismatch" else head,
        "RUNNER_TEMP": runner_temp.as_posix(),
        "FIXTURE_RECEIPT": raw,
        "FIXTURE_STDERR": NO_PRINT,
        "FIXTURE_MUTATE": "yes" if scenario == "dirty_after_gate" else "no",
        "FIXTURE_EXIT": "2" if scenario == "gate_rejected" else "0",
    }
    result = subprocess.run(
        [BASH, "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
        cwd=repo, env=env, check=False, capture_output=True, text=True,
    )
    assert result.returncode == expected_exit, result.stderr
    assert NO_PRINT not in result.stdout + result.stderr
    assert not list(runner_temp.iterdir())
    if expected_exit == 0:
        assert result.stdout.splitlines() == [json.dumps(receipt, sort_keys=True)]
        assert result.stderr == ""
    else:
        assert result.stdout == ""
        assert result.stderr.strip() == f"fixed JADX: {stage}"
