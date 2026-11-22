"""Required Linux CI isolation for one synthetic process-ownership test."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import secrets
import runpy
import tempfile
import stat
import subprocess
import sys
from xml.etree import ElementTree as ET

IMAGE = "docker.io/library/python@sha256:0f086103b026048cc50cb5da25ec435c023c5241a83fc44daea593377abc61c4"  # leak-scan: allow public Docker Official Image pinned to its linux/amd64 manifest.
LOCK = "tools/ci_descendant_wheels.txt"
SCRIPT = "tools/ci_descendant_fixture.py"
NODE = "tests/test_proctree.py::test_descendants_after_root_exit_force_killed"
VERSIONS = {
    "backports-zstd": "1.8.0", "certifi": "2026.11.20", "coverage": "7.17.4", "charset-normalizer": "3.5.2",
    "idna": "3.20", "iniconfig": "2.3.1", "packaging": "26.3", "pluggy": "1.7.0",
    "psutil": "7.2.2", "pygments": "2.21.0", "pytest": "9.2.0",
    "requests": "2.34.2", "urllib3": "2.8.0",
}


def git_tree(root):
    """Hash raw exported regular blobs by Git mode and bytes, not checkout metadata."""
    def walk(directory):
        rows = []
        with os.scandir(directory) as entries:
            for entry in entries:
                name = os.fsencode(entry.name)
                if name.lower() in (b".git", b".", b"..") or b"\\" in name or b":" in name:
                    raise ValueError("unsafe export")
                st = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(st.st_mode):
                    mode, oid, key = b"40000", walk(entry.path), name + b"/"
                elif stat.S_ISREG(st.st_mode):
                    mode, key = (b"100755" if st.st_mode & 0o111 else b"100644"), name
                    h = hashlib.sha1(b"blob " + str(st.st_size).encode() + b"\0")
                    with open(entry.path, "rb") as stream:
                        for block in iter(lambda: stream.read(1 << 20), b""):
                            h.update(block)
                    oid = h.digest()
                else:
                    raise ValueError("unsupported export entry")
                rows.append((key, mode + b" " + name + b"\0" + oid))
        body = b"".join(value for _, value in sorted(rows))
        return hashlib.sha1(b"tree " + str(len(body)).encode() + b"\0" + body).digest()
    return walk(root).hex()


def ns(path):
    st = os.stat(path)
    return f"{st.st_dev}:{st.st_ino}"


def setup_ok(outside_pid, outside_net, uid):
    if os.getpid() != 1 or os.geteuid() == 0 or str(os.getuid()) != uid or os.getuid() != os.geteuid():
        return False
    current_pid = ns("/proc/self/ns/pid")
    if current_pid == outside_pid or current_pid != ns("/proc/1/ns/pid"):
        return False
    if ns("/proc/self/ns/net") == outside_net or {name for _, name in socket.if_nameindex()} != {"lo"}:
        return False
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    return status["NoNewPrivs"].strip() == "1" and all(
        int(status[field], 16) == 0 for field in ("CapEff", "CapPrm", "CapBnd")
    )


def manifest(path, want):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != want:
        return False
    names = {}
    for line in data.decode("ascii").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([0-9.]+)[ \t]+--hash=sha256:[0-9a-f]{64}", line)
        if not match:
            return False
        name = re.sub(r"[-_.]+", "-", match[1].lower())
        if name in names:
            return False
        names[name] = match[2]
    return names == VERSIONS


def junit(path):
    try:
        with path.open("rb") as stream:
            raw = stream.read(65_537)
        if len(raw) > 65_536:
            return "invalid"
        xml = ET.fromstring(raw)
        if xml.tag != "testsuites" or len(xml) != 1 or xml[0].tag != "testsuite":
            return "invalid"
        suite = xml[0]
        cases = list(suite.iter("testcase"))
        if len(cases) != 1 or suite.get("tests") != "1":
            return "invalid"
        [case] = cases
        if case.get("classname") != "tests.test_proctree" or case.get("name") != NODE.split("::")[1]:
            return "invalid"
        status = [x.tag for x in case if x.tag in {"failure", "error", "skipped"}]
        if not status and all(suite.get(k) == "0" for k in ("failures", "errors", "skipped")):
            return "one_passed"
        if status == ["failure"] and suite.get("failures") == "1" and all(suite.get(k) == "0" for k in ("errors", "skipped")):
            return "one_failed"
        return "nonpass"
    except (ET.ParseError, OSError):
        return "invalid"


def no_owned_left():
    # Only after PID1 / private proc verification. Never signal the remaining processes.
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if not pid:
            return False
    with os.scandir("/proc") as table:
        return not any(entry.name.isdecimal() and entry.name != "1" for entry in table)


def observer(nonce, outside_pid, outside_net, uid, requirements_sha, head, tree):
    r = dict(schema="fxapk.container_fixture.v1", nonce=nonce, head=head, tree=tree,
             setup=False, source_verified=False, pins_verified=False, dep_wait=None,
             pytest_wait=None, junit="not_run", cleanup_before_exit=None)
    def emit(status, code):
        print(json.dumps(dict(r, status=status), sort_keys=True))
        return code
    try:
        r["setup"] = setup_ok(outside_pid, outside_net, uid)
        if not r["setup"]:
            return emit("isolation_unverified", 3)
        r["source_verified"] = git_tree("/src") == tree
        if not r["source_verified"]:
            return emit("candidate_unverified", 3)
        pins = Path("/src") / LOCK
        r["pins_verified"] = manifest(pins, requirements_sha) and sys.version_info[:3] == (3, 12, 16) and os.uname().machine == "x86_64"
        if not r["pins_verified"]:
            return emit("prerequisite_missing", 3)
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "TMPDIR": "/tmp",
               "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
               "PIP_CONFIG_FILE": "/dev/null", "LC_ALL": "C"}
        def child(args, limit):
            return subprocess.run([sys.executable, "-B", *args], cwd="/src", env=env, timeout=limit,
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, check=False).returncode
        r["dep_wait"] = child(
            ["-m", "pip", "--isolated", "--disable-pip-version-check", "--no-cache-dir", "install",
             "--no-index", "--only-binary", ":all:", "--require-hashes", "--no-deps", "--find-links",
             "/wheels", "--target", "/fixture-deps", "-r", str(pins)], 15)
        if r["dep_wait"] != 0:
            r["cleanup_before_exit"] = no_owned_left()
            return emit("dependency_setup_failed", 3)
        env["PYTHONPATH"] = "/fixture-deps"
        env["COVERAGE_FILE"] = "/tmp/.coverage"
        r["pytest_wait"] = child(
            ["-m", "coverage", "run", "--source=fxapk", "-m", "pytest", "-q", "-p", "no:cacheprovider",
             "--tb=no", "--basetemp=/tmp/pytest",
             "--junitxml=/tmp/result.xml", NODE], 38)
        r["junit"] = junit(Path("/tmp/result.xml"))
        r["cleanup_before_exit"] = no_owned_left()
        if not r["cleanup_before_exit"]:
            return emit("cleanup_unverified", 3)
        if (r["pytest_wait"], r["junit"]) == (0, "one_passed"):
            r["coverage_lines"] = observed_lines()
            return emit("fixture_passed", 0)
        if (r["pytest_wait"], r["junit"]) == (1, "one_failed"):
            return emit("fixture_failed", 1)
        return emit("fixture_unverified", 3)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        return emit("observation_unverified", 3)


class IsolationFailure(RuntimeError):
    """An allowlisted failure without raw device or process data."""


def observed_lines():
    from importlib.metadata import version

    sys.path.insert(0, "/fixture-deps")
    if version("coverage") != VERSIONS["coverage"]:
        raise IsolationFailure("coverage_dependency_mismatch")
    from coverage import CoverageData

    data = CoverageData(basename="/tmp/.coverage")
    data.read()
    if data.has_arcs():
        raise IsolationFailure("coverage_arcs_unexpected")
    report = {}
    for name in sorted(data.measured_files()):
        lines = data.lines(name)
        if lines:
            report[PurePosixPath(name).relative_to("/src").as_posix()] = sorted(set(lines))
    return report


def normalized_lines(repo, raw):
    if type(raw) is not dict or not raw.get("fxapk/core/proctree.py"):
        raise IsolationFailure("coverage_proctree_missing")
    out = {}
    for name, lines in raw.items():
        if type(name) is not str:
            raise IsolationFailure("coverage_path_invalid")
        rel = PurePosixPath(name)
        path = repo.joinpath(*rel.parts)
        if (rel.as_posix() != name or rel.is_absolute() or ".." in rel.parts
                or rel.parts[:1] != ("fxapk",) or rel.suffix != ".py"
                or not path.is_file() or not path.resolve().is_relative_to(repo / "fxapk")):
            raise IsolationFailure("coverage_path_invalid")
        if (type(lines) is not list or not lines or any(type(n) is not int or n < 1 for n in lines)
                or lines != sorted(set(lines))):
            raise IsolationFailure("coverage_lines_invalid")
        with path.open("rb") as stream:
            if lines[-1] > sum(1 for _ in stream):
                raise IsolationFailure("coverage_lines_invalid")
        out[str(path.resolve())] = lines
    return out


def merge_coverage(repo, raw):
    from coverage import CoverageData

    file = repo / ".coverage"
    if not file.is_file() or file.is_symlink():
        raise IsolationFailure("host_coverage_missing")
    host = CoverageData(basename=str(file))
    host.read()
    if host.has_arcs() or not host.measured_files():
        raise IsolationFailure("host_coverage_unverified")
    host.add_lines(normalized_lines(repo, raw))
    host.write()


def unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate receipt field")
        out[key] = value
    return out


def receipt(raw, nonce, head, tree, attach, wait):
    if len(raw) > 512_000:
        raise IsolationFailure("observer_receipt_too_large")
    state = json.loads(raw, object_pairs_hook=unique)
    if type(state) is not dict or (state.get("schema"), state.get("nonce"), state.get("head"), state.get("tree")) != (
        "fxapk.container_fixture.v1", nonce, head, tree,
    ):
        raise IsolationFailure("observer_identity_unverified")
    if attach != 0 or wait != b"0":
        status = state.get("status")
        allowed = ("fixture_failed", "fixture_unverified", "isolation_unverified", "candidate_unverified",
                   "prerequisite_missing", "dependency_setup_failed", "cleanup_unverified", "observation_unverified")
        raise IsolationFailure(status if type(status) is str and status in allowed else "container_result_unverified")
    if (any(state.get(k) is not True for k in ("setup", "source_verified", "pins_verified", "cleanup_before_exit"))
            or any(type(state.get(k)) is not int or state[k] != 0 for k in ("dep_wait", "pytest_wait"))
            or state.get("junit") != "one_passed" or state.get("status") != "fixture_passed"):
        raise IsolationFailure("observer_nonpass")
    return state["coverage_lines"]


def host(expected):
    repo = Path.cwd().resolve()
    git = ("git", "--no-replace-objects", "-c", "protocol.allow=never")
    def read_git(*args):
        return subprocess.check_output((*git, *args), text=True, stderr=subprocess.DEVNULL).strip()

    head = read_git("rev-parse", "HEAD")
    if (head != expected or not re.fullmatch(r"[a-f0-9]{40}", head) or os.geteuid() == 0
            or read_git("rev-parse", "--show-toplevel") != str(repo)):
        raise IsolationFailure("checkout_unverified")
    subprocess.run((*git, "diff", "--quiet", "HEAD", "--"), check=True)
    tree = read_git("rev-parse", "HEAD^{tree}")
    materialize = runpy.run_path(str(repo / "tools/fixed_jadx_gate.py"))["materialize"]
    nonce = secrets.token_hex(16)
    name = "fxapk-descendant-fixture-" + nonce
    label = "org.s-silt.fxapk.private-fixture"
    with tempfile.TemporaryDirectory(prefix="fxapk-descendant-ci-", dir=os.environ.get("RUNNER_TEMP")) as raw:
        tmp = Path(raw)
        export = tmp / "source"
        wheels = tmp / "wheels"
        export.mkdir()
        wheels.mkdir()
        materialize(repo, tree, export)
        if git_tree(export) != tree or "," in str(tmp):
            raise IsolationFailure("raw_checkout_unverified")
        digest = hashlib.sha256((export / LOCK).read_bytes()).hexdigest()
        if not manifest(export / LOCK, digest):
            raise IsolationFailure("wheel_manifest_unverified")

        docker_env = {k: v for k, v in os.environ.items()
                      if k not in {"DOCKER_CONTEXT", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_TLS",
                                   "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"}}
        docker = ("docker", "--config", str(tmp / "docker-config"), "--host", "unix:///var/run/docker.sock")
        def dock(*args, limit=10):
            return subprocess.run((*docker, *args), timeout=limit, env=docker_env, check=False,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

        def prepare(args, limit, reason):
            result = subprocess.run(args, timeout=limit, check=False,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode != 0:
                raise IsolationFailure(reason)

        if dock("version", "--format", "{{.Server.Version}}", limit=5).returncode:
            raise IsolationFailure("docker_unavailable")
        if dock("pull", "--platform", "linux/amd64", IMAGE, limit=120).returncode:
            raise IsolationFailure("image_unavailable")
        if dock("image", "inspect", "--format", "{{.Os}}/{{.Architecture}} {{json .Config.Volumes}}", IMAGE).stdout.strip() != b"linux/amd64 null":
            raise IsolationFailure("image_configuration_unverified")
        prepare((sys.executable, "-IB", "-m", "pip", "--isolated", "--disable-pip-version-check", "download",
                 "--index-url", "https://pypi.org/simple", "--only-binary", ":all:", "--require-hashes",
                 "--no-deps", "--dest", str(wheels), "--requirement", str(export / LOCK)),
                90, "wheel_staging_failed")
        cid = ""
        removed = False
        try:
            created = dock(
                "container", "create", "--pull=never", "--platform", "linux/amd64", "--name", name,
                "--label", f"{label}={nonce}", "--user", f"{os.getuid()}:{os.getgid()}", "--network=none",
                "--cap-drop=ALL", "--security-opt=no-new-privileges=true", "--read-only", "--no-healthcheck",
                "--pids-limit=64", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=32m",
                "--tmpfs", "/fixture-deps:rw,nosuid,nodev,exec,mode=1777,size=64m",
                "--mount", f"type=bind,src={export},dst=/src,readonly,bind-recursive=disabled",
                "--mount", f"type=bind,src={wheels},dst=/wheels,readonly,bind-recursive=disabled",
                "--workdir", "/src", "--entrypoint", "/usr/local/bin/python", IMAGE,
                "-IB", f"/src/{SCRIPT}", "--inside", nonce, ns("/proc/self/ns/pid"),
                ns("/proc/self/ns/net"), str(os.getuid()), digest, head, tree,
            )
            ident = created.stdout.strip()
            if created.returncode != 0 or not re.fullmatch(rb"[a-f0-9]{64}", ident):
                raise IsolationFailure("container_create_unverified")
            cid = ident.decode("ascii")
            attach = dock("container", "start", "--attach", cid, limit=70)
            wait = dock("container", "wait", cid, limit=6)
            if wait.returncode != 0:
                raise IsolationFailure("container_wait_unverified")
            stopped = dock("container", "rm", cid, limit=8)
            removed = stopped.returncode == 0 and stopped.stdout.strip() == ident
            if not removed:
                raise IsolationFailure("container_cleanup_unverified")
            coverage_lines = receipt(attach.stdout, nonce, head, tree, attach.returncode, wait.stdout.strip())
        finally:
            if not removed:
                owner = dock("container", "inspect", "--format", f'{{{{index .Config.Labels "{label}"}}}}', name, limit=5)
                if owner.returncode == 0 and owner.stdout.strip() == nonce.encode("ascii"):
                    dock("container", "rm", "-f", cid or name, limit=8)
        if read_git("rev-parse", "HEAD") != head or read_git("rev-parse", "HEAD^{tree}") != tree:
            raise IsolationFailure("checkout_changed")
        subprocess.run((*git, "diff", "--quiet", "HEAD", "--"), check=True)
        merge_coverage(repo, coverage_lines)
    print(json.dumps(dict(status="strict_native_pass", head=head, tree=tree, image=IMAGE,
                          junit="one_passed", cleanup_before_exit=True, exact_container_removed=True,
                          coverage_files=len(coverage_lines)), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        if sys.argv[1:2] == ["--inside"] and len(sys.argv) == 9:
            raise SystemExit(observer(*sys.argv[2:]))
        if len(sys.argv) != 2:
            raise IsolationFailure("usage")
        raise SystemExit(host(sys.argv[1]))
    except IsolationFailure as error:
        print(json.dumps({"status": str(error)}))
        raise SystemExit(3)
    except (KeyError, OSError, ValueError, subprocess.SubprocessError, ImportError):
        print(json.dumps({"status": "isolated_fixture_unverified"}))
        raise SystemExit(3)
