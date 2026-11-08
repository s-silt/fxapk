"""Prepared Docker backend, verified content cache and per-APK receipts."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import uuid

from apkscan.core.proctree import run_owned

from . import __version__
from .detect import inspect_pair
from .evidence import SCHEMA, FlutterError, digest, extract, inventory, load, reject_overlapping_paths, save, validate_bundle
from .index import INDEX_VERSION, build
from apkscan.core import tools


def config_path(path: Path | None = None) -> Path:
    return path or Path(os.environ.get("FXAPK_FLUTTER_TOOLCHAIN", str(Path.home() / ".fxapk/flutter/toolchain.json")))


def configuration(path: Path | None = None) -> dict:
    file = config_path(path)
    if not file.is_file():
        raise FlutterError("toolchain_not_configured")
    data = load(file, 1024 * 1024)
    if not isinstance(data, dict) or data.get("schema_version") != "fxapk-flutter-toolchain/1":
        raise FlutterError("invalid_toolchain")
    if not isinstance(data.get("entries"), list):
        raise FlutterError("invalid_toolchain")
    return data


def select(data: dict, compatibility: dict) -> dict:
    keys = ("dart_version", "snapshot", "abi", "compressed_pointers", "snapshot_flags")
    matches = [entry for entry in data["entries"] if isinstance(entry, dict) and all(entry.get(k) == compatibility.get(k) for k in keys)]
    if len(matches) != 1:
        raise FlutterError("toolchain_ambiguous" if matches else "unsupported_snapshot")
    entry = dict(matches[0])
    binary = Path(entry.get("binary", ""))
    if not binary.is_absolute() or not binary.is_file() or digest(binary) != entry.get("binary_sha256"):
        raise FlutterError("toolchain_binary_mismatch")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(entry.get("image_id", ""))):
        raise FlutterError("image_digest_required")
    if not isinstance(entry.get("blutter_revision"), str) or not entry["blutter_revision"]:
        raise FlutterError("toolchain_revision_required")
    return entry


def docker_check(docker: str, image: str) -> None:
    result = run_owned([docker, "image", "inspect", image, "--format", "{{.Id}}"], timeout=20, max_stdout_bytes=65536, max_stderr_bytes=65536)
    if result.returncode != 0 or result.stdout.strip() != image:
        raise FlutterError("docker_or_image_unavailable")


def execute(root: Path, entry: dict, docker: str, timeout: int) -> None:
    name = "fxapk-flutter-" + uuid.uuid4().hex
    output = root / "generated"
    output.mkdir()
    runner = Path(__file__).with_name("container_runner.py").resolve()
    mount_paths = (root / "input", Path(entry["binary"]), runner, output)
    if any("," in str(p) for p in mount_paths):
        raise FlutterError("unsupported_mount_path")
    argv = [docker, "run", "--name", name, "--pull", "never", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "6g",
            "--memory-swap", "6g", "--cpus", "2", "--pids-limit", "64",
            "--user", str(getattr(os, "getuid", lambda: 1000)()),
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
            "--mount", f"type=bind,src={mount_paths[0].resolve()},dst=/input,readonly",
            "--mount", f"type=bind,src={mount_paths[1].resolve()},dst=/tool/blutter,readonly",
            "--mount", f"type=bind,src={runner},dst=/runner.py,readonly",
            "--mount", f"type=bind,src={output.resolve()},dst=/output",
            "--entrypoint", "python3", entry["image_id"], "/runner.py"]
    result = None
    cleanup_ok = False
    try:
        result = run_owned(argv, timeout=timeout, max_stdout_bytes=1024 * 1024, max_stderr_bytes=1024 * 1024)
    finally:
        cleanup = run_owned([docker, "rm", "-f", name], timeout=20, max_stdout_bytes=65536, max_stderr_bytes=65536)
        cleanup_ok = cleanup.returncode == 0
        save(root / "execution.json", {"returncode": result.returncode if result else None,
             "timed_out": result.timed_out if result else False, "cleanup_complete": cleanup_ok,
             "reason_codes": list(result.reason_codes) if result else ["interrupted"], "network": "none"})
    if not cleanup_ok:
        raise FlutterError("container_cleanup_failed")
    if result is None or result.timed_out:
        raise FlutterError("analysis_timeout")
    if result.reason_codes or not result.termination_complete or not result.ownership_complete:
        raise FlutterError("process_execution_incomplete")
    if result.returncode != 0:
        raise FlutterError("output_limit" if result.returncode == 75 else "blutter_failed")
    inventory(output)
    if not (output / "raw").is_dir():
        raise FlutterError("required_output_missing")
    os.replace(output / "raw", root / "raw")
    output.rmdir()


@contextmanager
def serial_lock(cache: Path):
    cache.mkdir(parents=True, exist_ok=True)
    lock = cache / "analysis.lock"
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise FlutterError("analysis_busy") from exc
    try:
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        yield
    finally:
        lock.unlink(missing_ok=True)


def analyze(apk: Path, out: Path, toolchain: Path | None = None, *, timeout: int = 300,
            use_cache: bool = True, expected_apk_sha256: str | None = None) -> dict:
    if not 1 <= timeout <= 1800:
        raise FlutterError("invalid_timeout")
    if out.exists():
        raise FileExistsError(out)
    data = configuration(toolchain)
    cache = Path(data.get("cache_dir", str(Path.home() / ".fxapk/flutter/cache"))).resolve()
    reject_overlapping_paths(out, cache)
    out.mkdir(parents=True, exist_ok=False)
    try:
        source = extract(apk, out / "input")
        if expected_apk_sha256 is not None and source["apk_sha256"] != expected_apk_sha256:
            raise FlutterError("apk_identity_mismatch")
        compatibility = inspect_pair(out / "input/libapp.so", out / "input/libflutter.so")
        entry = select(data, compatibility)
        docker = tools.safe_which(str(data.get("docker", "docker")))
        if not docker:
            raise FlutterError("docker_unavailable")
        identity = {"libapp": source["libapp"]["sha256"], "libflutter": source["libflutter"]["sha256"],
                    "compatibility": compatibility, "tool": entry, "plugin_version": __version__, "index_version": INDEX_VERSION}
        key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        cached = cache / key
        cache_hit = False
        cache_reason = "miss"
        with serial_lock(cache):
            if use_cache and cached.exists():
                try:
                    prior = validate_bundle(cached)
                    if prior.get("cache_key") != key or prior.get("identity") != identity:
                        raise FlutterError("cache_identity_mismatch")
                    for child in cached.iterdir():
                        if child.name in {"manifest.json", "input"}:
                            continue
                        if child.is_dir():
                            shutil.copytree(child, out / child.name)
                        else:
                            shutil.copy2(child, out / child.name)
                    coverage = prior["coverage"]
                    cache_hit = True
                    cache_reason = "verified_hit"
                except FlutterError:
                    cache_reason = "invalid_cache_recomputed"
                    os.replace(cached, cache / ("invalid-" + uuid.uuid4().hex))
            if not cache_hit:
                docker_check(docker, entry["image_id"])
                execute(out, entry, docker, timeout)
                inventory(out)
                coverage = build(out)
            if digest(out / "input/libapp.so") != source["libapp"]["sha256"] or digest(out / "input/libflutter.so") != source["libflutter"]["sha256"]:
                raise FlutterError("extracted_input_changed")
            if digest(apk) != source["apk_sha256"]:
                raise FlutterError("input_changed")
            manifest = {"schema_version": SCHEMA, "status": "ok", "source": source, "compatibility": compatibility,
                        "identity": identity, "cache_key": key, "cache_hit": cache_hit, "cache_reason": cache_reason,
                        "coverage": coverage, "files": inventory(out), "runtime_observed": False}
            save(out / "manifest.json", manifest)
            validate_bundle(out)
            if not cached.exists():
                with tempfile.TemporaryDirectory(prefix="publish-", dir=cache) as temp:
                    staged = Path(temp) / "bundle"
                    shutil.copytree(out, staged)
                    validate_bundle(staged)
                    os.replace(staged, cached)
        return manifest
    except Exception as exc:
        reason = str(exc) if isinstance(exc, FlutterError) else "analysis_io_or_parser_failed"
        save(out / "failure.json", {"schema_version": SCHEMA, "status": "failed", "reason": reason})
        raise FlutterError(reason) from exc


def capabilities(apk: Path | None, toolchain: Path | None = None) -> dict:
    try:
        data = configuration(toolchain)
        if apk is None:
            return {"status": "configured", "entries": len(data["entries"]), "execution_verified": False}
        with tempfile.TemporaryDirectory(prefix="fxapk-flutter-inspect-") as temp:
            root = Path(temp)
            source = extract(apk, root)
            compatibility = inspect_pair(root / "libapp.so", root / "libflutter.so")
        entry = select(data, compatibility)
        docker = tools.safe_which(str(data.get("docker", "docker")))
        if not docker:
            raise FlutterError("docker_unavailable")
        docker_check(docker, entry["image_id"])
        return {"status": "ready", "compatibility": compatibility, "source": source, "execution_verified": False}
    except (FlutterError, OSError) as exc:
        return {"status": "unavailable", "reason": str(exc) if isinstance(exc, FlutterError) else "io_failed", "execution_verified": False}
