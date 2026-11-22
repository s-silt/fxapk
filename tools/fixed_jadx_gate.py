"""Run the fixed JADX report contracts against a frozen Git index."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import sysconfig
from tempfile import TemporaryDirectory, gettempdir
from typing import Any
from xml.etree import ElementTree

VERSION = "jadx-report-v3"
SCRIPT = "tools/fixed_jadx_gate.py"
LOCAL_GIT = ("git", "--no-replace-objects", "-c", "protocol.allow=never")
NODES = tuple(
    f"tests/test_jadx.py::test_jadx_coverage_report_{output}[{mode}]"
    for output in ("json", "html", "digest")
    for mode in ("full", "limited", "empty", "legacy", "at_byte_limit", "over_byte_limit")
) + (
    "tests/test_visibility.py::test_java_truncated_full_count_in_html",
)
Phases = dict[str, list[tuple[str, str]]]


class GateError(RuntimeError):
    """A diagnostic safe to include in the gate receipt."""


class Observe:
    """Keep the pytest outcomes that JUnit omits for a non-strict XPASS."""

    def __init__(self) -> None:
        self.phases: Phases = defaultdict(list)

    def pytest_runtest_logreport(self, report: Any) -> None:
        outcome = "xfail/xpass" if hasattr(report, "wasxfail") else report.outcome
        self.phases[report.nodeid].append((report.when, outcome))


def audit(report: Path, phases: Phases, pytest_exit: int) -> list[str]:
    problems = [f"pytest exit {pytest_exit}"] if pytest_exit else []
    if not report.is_file() or report.is_symlink():
        return problems + ["this invocation produced no JUnit file"]
    try:
        xml = ElementTree.parse(report).getroot()
    except (ElementTree.ParseError, OSError):
        return problems + ["unreadable or malformed JUnit from this invocation"]

    expected = {
        (node.split("::", 1)[0][:-3].replace("/", "."), node.split("::", 1)[1]): node
        for node in NODES
    }
    counts: Counter[tuple[str, str]] = Counter()
    for case in xml.iter("testcase"):
        key = case.get("classname", ""), case.get("name", "")
        counts[key] += 1
        if key in expected and len(case):
            kinds = sorted({e.tag for e in case} & {"error", "failure", "skipped"})
            problems.append(f"{expected[key]}: JUnit {','.join(kinds) or 'unexpected child'}")
    if not counts:
        problems.append("JUnit contains no cases")
    if set(counts) - expected.keys() or set(phases) - set(NODES):
        problems.append("unexpected JUnit case or pytest node ID")
    normal = [("setup", "passed"), ("call", "passed"), ("teardown", "passed")]
    for key, node in expected.items():
        if counts[key] != 1:
            problems.append(f"{node}: expected one JUnit case, got {counts[key]}")
        actual = phases.get(node, [])
        if actual != normal:
            compact = ",".join(f"{step}={state}" for step, state in actual) or "none"
            problems.append(f"{node}: pytest phases {compact}")
    return problems


def git_env(index: Path | None = None) -> dict[str, str]:
    env = {**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": ""}
    if index is not None:
        env["GIT_INDEX_FILE"] = str(index)
    return env


def git(repo: Path, *args: str, index: Path | None = None) -> bytes:
    return subprocess.check_output(
        [*LOCAL_GIT, "-C", str(repo), *args],
        env=git_env(index), stderr=subprocess.PIPE,
    )


def frozen_tree(repo: Path, copy: Path) -> str:
    index = Path(os.fsdecode(git(repo, "rev-parse", "--path-format=absolute", "--git-path", "index").rstrip(b"\n")))
    shutil.copyfile(index, copy)
    try:
        return git(repo, "write-tree", index=copy).decode("ascii").strip()
    except subprocess.CalledProcessError as exc:
        raise GateError("cannot freeze the Git index") from exc


def materialize(repo: Path, tree: str, snapshot: Path) -> None:
    """Use raw Git blobs, independent of checkout filters and archive attributes."""
    entries = git(repo, "ls-tree", "-rz", "--full-tree", tree).split(b"\0")
    with subprocess.Popen(
        [*LOCAL_GIT, "-C", str(repo), "cat-file", "--batch"],
        env=git_env(),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    ) as reader:
        assert reader.stdin is not None and reader.stdout is not None
        try:
            for entry in entries[:-1]:
                metadata, raw_path = entry.split(b"\t", 1)
                mode, kind, oid = metadata.split()
                parts = os.fsdecode(raw_path).split("/")
                if kind != b"blob" or mode not in {b"100644", b"100755"} or any(
                    part.casefold() in {"", ".", "..", ".git"} or "\\" in part or ":" in part
                    for part in parts
                ):
                    raise GateError("unsupported path or mode in the staged tree")
                reader.stdin.write(oid + b"\n")
                reader.stdin.flush()
                reported, object_type, size = reader.stdout.readline().split()
                if (reported, object_type) != (oid, b"blob"):
                    raise GateError("staged blob lookup failed")
                target = snapshot.joinpath(*parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as dest:
                    remaining = int(size)
                    while remaining:
                        data = reader.stdout.read(min(remaining, 1024 * 1024))
                        if not data:
                            raise GateError("staged blob ended early")
                        dest.write(data)
                        remaining -= len(data)
                if reader.stdout.read(1) != b"\n":
                    raise GateError("invalid staged blob framing")
                target.chmod(0o700 if mode == b"100755" else 0o600)
            reader.stdin.close()
            if reader.wait():
                raise GateError("staged blob lookup failed")
        finally:
            if reader.poll() is None:
                reader.kill()


def run_pytest(scratch: Path, site_dirs: list[str]) -> dict[str, Any]:
    # The worker starts with -I -S: add installed dependencies without processing .pth
    # or loading an editable mapping to a different fxapk checkout.
    sys.path.extend(site_dirs)
    import pytest

    checkout = Path.cwd()
    sys.path.insert(0, str(checkout))
    result = scratch / "result.xml"
    if result.exists() or result.is_symlink():
        raise GateError("JUnit path already existed before pytest")
    watch = Observe()
    args = [
        "-q", "-o", "addopts=", "-o", "junit_family=xunit2", "-o", "junit_logging=no",
        "-o", "xfail_strict=true", "-p", "no:cacheprovider",
        f"--basetemp={scratch / 'pytest'}", f"--junitxml={result}", *NODES,
    ]
    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        code = int(pytest.main(args, plugins=[watch]))
    problems = audit(result, watch.phases, code)
    return {"pytest_exit": code, "accepted": not problems, "cases": list(NODES), "problems": problems}


def from_index(scratch_dir: Path) -> dict[str, Any]:
    repo = Path.cwd()
    root = Path(os.fsdecode(git(repo, "rev-parse", "--show-toplevel").rstrip(b"\n"))).resolve()
    if repo != root:
        raise GateError("run this gate from the repository root")
    scratch_dir = scratch_dir.resolve(strict=True)
    if any((p / ".git").exists() or (p / ".git").is_symlink() for p in (scratch_dir, *scratch_dir.parents)):
        raise GateError("scratch directory must have no Git ancestor")

    with TemporaryDirectory(prefix="fxapk-jadx-gate-", dir=scratch_dir) as temp:
        scratch = Path(temp)
        head = git(repo, "rev-parse", "--verify", "HEAD").decode("ascii").strip()
        tree = frozen_tree(repo, scratch / "initial.index")
        snapshot = scratch / "checkout"
        snapshot.mkdir()
        materialize(repo, tree, snapshot)
        for name in (
            "fxapk/__init__.py", "tests/__init__.py", "tests/test_jadx.py",
            "tests/test_visibility.py", SCRIPT,
        ):
            if not (snapshot / name).is_file():
                raise GateError("required staged source or test file is missing")
        if (snapshot / SCRIPT).read_bytes() != Path(__file__).read_bytes():
            raise GateError("running gate differs from the staged gate")

        for name in ("home", "tmp"):
            (scratch / name).mkdir()
        env = {
            "HOME": str(scratch / "home"), "PATH": os.defpath, "LANG": "C.UTF-8",
            "TMPDIR": str(scratch / "tmp"), "TEMP": str(scratch / "tmp"),
            "TMP": str(scratch / "tmp"), "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        }
        # Windows subprocess creation requires SystemRoot when env is explicit.
        if "SystemRoot" in os.environ:
            env["SystemRoot"] = os.environ["SystemRoot"]
        site_dirs = sorted({sysconfig.get_path("purelib"), sysconfig.get_path("platlib")})
        worker = subprocess.run(
            [sys.executable, "-I", "-S", str(snapshot / SCRIPT), "--worker", str(scratch), *site_dirs],
            cwd=snapshot, env=env, capture_output=True, check=False,
        )
        if worker.returncode not in {0, 1}:
            raise GateError("snapshot worker could not run; verify pytest and checkout dependencies")
        result = json.loads(worker.stdout)
        if (
            not isinstance(result, dict)
            or result.get("accepted") is not (worker.returncode == 0)
            or result.get("cases") != list(NODES)
            or type(result.get("pytest_exit")) is not int
            or not isinstance(result.get("problems"), list)
        ):
            raise GateError("invalid snapshot worker receipt")
        latest_tree = frozen_tree(repo, scratch / "final.index")
        latest_head = git(repo, "rev-parse", "--verify", "HEAD").decode("ascii").strip()
        if (latest_head, latest_tree) != (head, tree):
            result["accepted"] = False
            result["problems"].append("HEAD or staged tree changed during the gate")
        return {"base_head": head, "index_tree": tree, **result}


def main() -> int:
    try:
        if sys.flags.isolated and sys.flags.no_site and len(sys.argv) >= 4 and sys.argv[1] == "--worker":
            result = run_pytest(Path(sys.argv[2]), sys.argv[3:])
        else:
            parser = argparse.ArgumentParser(description=__doc__)
            parser.add_argument("--scratch", type=Path, default=Path(gettempdir()))
            args = parser.parse_args()
            if not sys.flags.isolated:
                raise GateError("invoke this gate with Python isolated mode (-I)")
            result = from_index(args.scratch)
    except (GateError, ImportError, OSError, ValueError, subprocess.SubprocessError) as exc:
        message = str(exc) if isinstance(exc, GateError) else "gate setup or snapshot verification failed"
        print(json.dumps({"version": VERSION, "accepted": False, "problems": [message]}))
        return 2
    print(json.dumps({"version": VERSION, **result}, sort_keys=True))
    return 0 if result["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
