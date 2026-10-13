"""Local native REA inspect and declarative byte recovery. No target execution."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import stat
import struct
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path
from typing import Any

from apkscan.core.atomic import atomic_create_bytes

from .evidence import EvidenceError
from .runtime import ReaRuntime, run_bounded

SUPPORTED_PROVIDERS = frozenset({"ghidra", "ida", "hopper"})
OPERATIONS = {
    "overview": "analyze",
    "function": "function",
    "xrefs": "xrefs",
    "instructions": "instructions",
    "search": "search",
    "address-to-file-offset": "address-to-file-offset",
    "read-bytes": "read-bytes",
}
_ENVELOPE_OPERATION = {
    "overview": "analyze",
    "function": "analyze_function",
    "xrefs": "xrefs",
    "instructions": "instructions",
    "search": "search",
    "address-to-file-offset": "address_to_file_offset",
    "read-bytes": "read_bytes",
}
MAX_BINARY_BYTES = 64 * 1024 * 1024
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_APK_BYTES = 256 * 1024 * 1024
MAX_BUNDLE_BYTES = 80 * 1024 * 1024
MAX_HISTORY_BYTES = 256 * 1024 * 1024
MAX_SNAPSHOT_LINKS = 32
MAX_RANGES = 8
MAX_RANGE_BYTES = 4096
MAX_STEPS = 8
MAX_CONCAT_IDS = 32
MAX_EXPANDED_BYTES = 8 * 1024 * 1024
MAX_READ_LENGTH = 4096
MAX_JSON_DEPTH = 48
_SHA = re.compile(r"[0-9a-f]{64}")
_MEMBER = re.compile(r"lib/(armeabi-v7a|arm64-v8a|x86|x86_64)/[A-Za-z0-9._-]{1,80}\.so")
_ABI_ARCH = {
    "armeabi-v7a": "arm",
    "arm64-v8a": "arm64",
    "x86": "x86",
    "x86_64": "x86_64",
}
_SNAPSHOT = re.compile(r"input_report/([0-9a-f]{64})/report\.json\Z")
BUNDLE_FILES = (
    "recipe.json",
    "result.json",
    "binary.bin",
    "dossier/stdout.bin",
    "dossier/stderr.bin",
    "dossier/inspect-manifest.json",
    "dossier/execution.json",
    "dossier/provenance.json",
)
_RECIPE_FIELDS = frozenset({"schema_version", "binary_sha256", "evidence_sha256", "anchor", "ranges", "steps"})
_ANCHOR_FIELDS = frozenset({"operation", "query"})
_RANGE_FIELDS = frozenset({"id", "offset", "length", "expected_hex"})
_STEP_FIELDS = {
    "concat": frozenset({"op", "ids"}),
    "xor-byte": frozenset({"op", "key"}),
    "ascii-domain": frozenset({"op"}),
    "ascii-ip": frozenset({"op"}),
    "u32-ipv4": frozenset({"op", "endian"}),
}
_TERMINALS = frozenset({"ascii-domain", "ascii-ip", "u32-ipv4"})
_DOC_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
_HOST = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
)


class NativeError(EvidenceError):
    """Stable reason code. The message is the code and nothing else."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NativeError("duplicate_json_key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise NativeError("invalid_json")


def _depth_gate(text: str) -> None:
    depth = 0
    inside = False
    escaped = False
    for char in text:
        if inside:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                inside = False
            continue
        if char == '"':
            inside = True
        elif char in "{[":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise NativeError("invalid_json")
        elif char in "}]":
            depth -= 1
            if depth < 0:
                raise NativeError("invalid_json")


def _finite(value: object, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise NativeError("invalid_json")
    if isinstance(value, float) and not math.isfinite(value):
        raise NativeError("invalid_json")
    if isinstance(value, dict):
        for item in value.values():
            _finite(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _finite(item, depth + 1)


def _loads(raw: bytes, limit: int = MAX_JSON_BYTES) -> Any:
    if len(raw) > limit:
        raise NativeError("oversize")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise NativeError("invalid_json") from None
    _depth_gate(text)
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_reject_constant)
    except NativeError:
        raise
    except (ValueError, RecursionError):
        raise NativeError("invalid_json") from None
    _finite(value)
    return value


def _is_reparse(path: Path) -> bool:
    """Reject symlinks and Windows junctions without requiring Path.is_junction.

    Python 3.11 has no ``Path.is_junction``. ``st_reparse_tag`` and
    ``FILE_ATTRIBUTE_REPARSE_POINT`` (0x400) cover that interpreter. A present
    ``is_junction`` remains a fallback when the stat result has no tag.
    """
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(getattr(info, "st_mode", 0)):
        return True
    if getattr(info, "st_reparse_tag", 0):
        return True
    attributes = getattr(info, "st_file_attributes", 0) or 0
    if attributes & 0x400:
        return True
    probe = getattr(path, "is_junction", None)
    if not callable(probe):
        return False
    try:
        return bool(probe())
    except OSError:
        return False


def _ancestors(path: Path) -> None:
    current = path
    for _ in range(64):
        if _is_reparse(current):
            raise NativeError("reparse_forbidden")
        if current.parent == current:
            return
        current = current.parent
    raise NativeError("reparse_forbidden")


def _write(path: Path, data: bytes) -> None:
    _ancestors(path)
    _ancestors(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    _ancestors(path.parent)
    if not atomic_create_bytes(path, data):
        raise NativeError("output_exists")


def _claim(out: Path) -> None:
    _ancestors(out)
    if out.exists() or _is_reparse(out):
        raise NativeError("output_exists")
    out.mkdir(parents=True, exist_ok=False)
    _ancestors(out)


def _read_file(path: Path, limit: int) -> bytes:
    if type(limit) is not int or limit < 0:
        raise NativeError("oversize")
    _ancestors(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise NativeError("not_a_regular_file") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise NativeError("not_a_regular_file")
        data = os.read(fd, limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise NativeError("oversize")
    return data


def _hash_file(path: Path, limit: int) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    _ancestors(path)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise NativeError("not_a_regular_file") from None
    total = 0
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise NativeError("not_a_regular_file")
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > limit:
                raise NativeError("oversize")
            digest.update(block)
    finally:
        os.close(fd)
    return digest.hexdigest()


def classify_binary(data: bytes) -> dict[str, Any]:
    """PE/ELF header only. Does not execute the file."""
    if data.startswith(b"\x7fELF") and len(data) >= 20:
        if data[4] not in {1, 2} or data[5] != 1:
            raise NativeError("unsupported_target")
        machine = struct.unpack_from("<H", data, 18)[0]
        arch = {3: "x86", 62: "x86_64", 40: "arm", 183: "arm64"}.get(machine, "unknown")
        return {"format": "elf", "architecture": arch, "executable_role": "unknown", "managed": None}
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise NativeError("unsupported_target")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew < 0x40 or e_lfanew > 1024 or e_lfanew + 24 > len(data):
        raise NativeError("unsupported_target")
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise NativeError("unsupported_target")
    machine, _, _, _, _, size_opt, chars = struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
    arch = {0x14C: "x86", 0x8664: "x86_64"}.get(machine, "other")
    role = "shared-library" if chars & 0x2000 else "application"
    return {
        "format": "pe",
        "architecture": arch,
        "executable_role": role,
        "managed": _clr_managed(data, e_lfanew, size_opt),
    }


def _clr_managed(data: bytes, e_lfanew: int, size_opt: int) -> bool | None:
    start = e_lfanew + 24
    if start + 2 > len(data):
        return None
    magic = struct.unpack_from("<H", data, start)[0]
    if magic == 0x10B:
        num_off, dir_off = 92, 96
    elif magic == 0x20B:
        num_off, dir_off = 108, 112
    else:
        return None
    if size_opt < dir_off + 15 * 8 or start + size_opt > len(data):
        return None
    count = struct.unpack_from("<I", data, start + num_off)[0]
    if count < 15:
        return None
    clr_size = struct.unpack_from("<I", data, start + dir_off + 14 * 8 + 4)[0]
    return clr_size != 0


def _host_limits() -> dict[str, Any]:
    windows = sys.platform == "win32"
    return {
        "host_platform": sys.platform,
        "windows_ghidra_p0": "x86_x64_native_pe_only",
        "android_elf": "unsupported_on_this_host" if windows else "ghidra_structural_only_live_unverified",
        "ida_hopper_target_support": "not_claimed",
        "linux_ghidra_elf_live_run": "unverified",
        "live_target_verified": False,
        "engine_executed_for_target": False,
        "binary_read_limit_bytes": MAX_BINARY_BYTES,
        "supported_rea_versions": ["6.4.0"],
        "supported_providers": sorted(SUPPORTED_PROVIDERS),
        "read_only_operations": sorted(OPERATIONS),
    }


def _target_gate(header: dict[str, Any], provider: str) -> str | None:
    """Provider-specific structural gate. IDA/Hopper are not claimed from this host table."""
    if provider != "ghidra":
        return "provider_target_unclaimed"
    if header["format"] == "elf":
        if sys.platform == "win32":
            return "unsupported_on_this_host"
        if sys.platform in {"linux", "darwin"}:
            return None
        return "elf_not_claimed"
    if header["format"] != "pe" or header["architecture"] not in {"x86", "x86_64"}:
        return "target_format_unsupported"
    if header["managed"] is not False:
        return "managed_target_unsupported"
    return None


def _toolchain_env(path: Path | None) -> dict[str, str] | None:
    if path is None:
        return None
    raw = _loads(_read_file(path, 65536), 65536)
    if not isinstance(raw, dict) or set(raw) - {"node", "ghidra", "java"}:
        raise NativeError("invalid_toolchain")
    overlay: dict[str, str] = {}
    ghidra = raw.get("ghidra")
    java = raw.get("java")
    if ghidra is not None:
        if not isinstance(ghidra, str) or not ghidra or "\n" in ghidra:
            raise NativeError("invalid_toolchain")
        overlay["GHIDRA_INSTALL_DIR"] = ghidra
    if java is not None:
        if not isinstance(java, str) or not java or "\n" in java:
            raise NativeError("invalid_toolchain")
        overlay["JAVA_HOME"] = java
    return overlay or None


def _provider_rows(data: object) -> list[dict[str, Any]] | None:
    if not isinstance(data, dict):
        return None
    rows = data.get("analysis_provider_candidates")
    if not isinstance(rows, list):
        return None
    parsed: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            return None
        provider = row.get("provider")
        availability = row.get("availability")
        if not isinstance(provider, dict) or not isinstance(availability, dict):
            return None
        ident = provider.get("id")
        status = availability.get("status")
        if not isinstance(ident, str) or status not in {"available", "unavailable"}:
            return None
        support = row.get("target_support")
        support_status = support.get("status") if isinstance(support, dict) else "unknown"
        if not isinstance(support_status, str):
            return None
        parsed.append({"id": ident, "availability": status, "target_support": support_status})
    return parsed


def capabilities(
    *,
    provider: str | None = None,
    executable: str | None = None,
    node: str | None = None,
    binary: Path | None = None,
    toolchain: Path | None = None,
) -> dict[str, Any]:
    """Probe version and provider readiness. A present CLI is not a live target."""
    info: dict[str, Any] = {
        "status": "unavailable",
        "reason": "",
        "provider": provider,
        "rea_version": None,
        "target": None,
        **_host_limits(),
    }
    if provider is not None and provider not in SUPPORTED_PROVIDERS:
        info["reason"] = "invalid_provider"
        return info
    if binary is not None:
        header = classify_binary(_read_file(binary, MAX_BINARY_BYTES))
        reason = _target_gate(header, provider or "ghidra")
        info["target"] = {**header, "header_supported": reason is None, "reason": reason or ""}
        if reason is not None:
            info["status"] = "unsupported"
            info["reason"] = reason
            return info
    runtime = ReaRuntime(executable, node)
    probed = runtime.capabilities()
    info["rea_version"] = probed.get("rea_version")
    if probed.get("status") != "ok":
        info["reason"] = str(probed.get("reason") or "rea_missing")
        return info
    env = _toolchain_env(toolchain)
    with tempfile.TemporaryDirectory(prefix="fxapk-native-probe-") as directory:
        probe = run_bounded(
            [*runtime.command(), "providers", "--format", "json", "--full-output"],
            Path(directory) / "probe",
            timeout=30,
            max_stdout=MAX_JSON_BYTES,
            env=env,
        )
        raw = _read_file(Path(directory) / "probe" / "stdout.bin", MAX_JSON_BYTES) if probe.get("ok") else b""
    if not probe.get("ok"):
        info["reason"] = "provider_probe_failed"
        info["provider_probe"] = {"command": "providers", "parsed": "unresolved"}
        return info
    try:
        envelope = _loads(raw, MAX_JSON_BYTES)
    except NativeError:
        info["reason"] = "provider_probe_failed"
        info["provider_probe"] = {"command": "providers", "parsed": "unresolved"}
        return info
    rows = _provider_rows(envelope.get("data")) if isinstance(envelope, dict) and envelope.get("ok") is True else None
    if rows is None:
        info["reason"] = "provider_probe_failed"
        info["provider_probe"] = {"command": "providers", "parsed": "unresolved"}
        return info
    info["provider_availability"] = rows
    info["provider_probe"] = {"command": "providers", "parsed": "listed"}
    info["live_target_verified"] = False
    if provider is None:
        info["status"] = "listed"
        info["reason"] = ""
        return info
    selected = next((row for row in rows if row["id"] == provider), None)
    if selected is None or selected["availability"] != "available":
        info["reason"] = "provider_unavailable" if selected else "provider_probe_unresolved"
        info["provider_probe"] = {
            "command": "providers",
            "parsed": "unavailable" if selected else "unresolved",
        }
        return info
    info["status"] = "ok"
    info["provider_probe"] = {"command": "providers", "parsed": "available", "target_support": selected["target_support"]}
    return info


def _query_ok(operation: str, query: str | None, length: int | None) -> None:
    if operation not in OPERATIONS:
        raise NativeError("invalid_operation")
    if operation == "overview":
        if query is not None or length is not None:
            raise NativeError("invalid_query")
        return
    if length is not None and operation != "read-bytes":
        raise NativeError("invalid_query")
    if not isinstance(query, str) or not query or query.startswith("-") or len(query) > 256:
        raise NativeError("invalid_query")
    if any(ord(char) < 32 or char in "\r\n" for char in query):
        raise NativeError("invalid_query")
    if operation == "read-bytes":
        if type(length) is not int or not 1 <= length <= MAX_READ_LENGTH:
            raise NativeError("invalid_query")


def _argv(
    runtime: ReaRuntime,
    operation: str,
    copy: Path,
    provider: str,
    query: str | None,
    length: int | None,
) -> list[str]:
    argv = [*runtime.command(), OPERATIONS[operation], str(copy.resolve())]
    if operation != "overview":
        argv.append(query or "")
    if operation == "read-bytes":
        argv.extend(["--length", str(length)])
    argv.extend(["--provider", provider, "--format", "json", "--full-output"])
    if operation == "search":
        argv.extend(["--kind", "strings", "--mode", "literal"])
    return argv


def _dict(value: object, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NativeError(code)
    return value


def _native_provider_identity(data: dict[str, Any], operation: str) -> dict[str, Any]:
    identity = _dict(data.get("provider"), "envelope_not_complete")
    if operation == "overview" and identity.get("id") == "rea-workflow":
        profile = _dict(data.get("analysis_profile"), "envelope_not_complete")
        parameters = _dict(profile.get("parameters"), "envelope_not_complete")
        if profile.get("provider") != identity or parameters.get("workflow_revision") != 2:
            raise NativeError("envelope_not_complete")
        upstream = _dict(parameters.get("upstream_analysis_profile"), "envelope_not_complete")
        if data.get("operation") != "binary_overview" or not data.get("normalized_result"):
            raise NativeError("envelope_not_complete")
        return _dict(upstream.get("provider"), "envelope_not_complete")
    return identity


def _envelope(raw: bytes, *, binary_sha: str, provider: str, operation: str, query: str | None) -> dict[str, Any]:
    value = _loads(raw)
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise NativeError("envelope_not_complete")
    data = _dict(value.get("data"), "envelope_not_complete")
    if not data or data.get("status") in {"failed", "unresolved", "error"}:
        raise NativeError("envelope_not_complete")
    meta = _dict(value.get("meta"), "envelope_not_complete")
    if meta.get("command") != OPERATIONS[operation]:
        raise NativeError("envelope_not_complete")
    subject = _dict(data.get("subject"), "envelope_not_complete")
    digest = _dict(subject.get("digest"), "envelope_not_complete")
    if digest.get("sha256") != binary_sha or _SHA.fullmatch(binary_sha) is None:
        raise NativeError("envelope_not_complete")
    identity = _native_provider_identity(data, operation)
    version = identity.get("version")
    if identity.get("id") != provider or not isinstance(version, str) or not version:
        raise NativeError("envelope_not_complete")
    expected_operation = (
        "binary_overview" if operation == "overview" and data["provider"].get("id") == "rea-workflow"
        else _ENVELOPE_OPERATION[operation]
    )
    if data.get("operation") != expected_operation:
        raise NativeError("envelope_not_complete")
    parameters = data.get("parameters")
    if operation == "function":
        params = _dict(parameters, "envelope_not_complete")
        if params.get("procedure") != query:
            raise NativeError("function_dossier_mismatch")
        raw_result = _dict(data.get("raw_result"), "envelope_not_complete")
        body = _dict(raw_result.get("value"), "envelope_not_complete")
        procedure = _dict(body.get("procedure"), "envelope_not_complete")
        if procedure.get("name") != query or not isinstance(procedure.get("address"), str):
            raise NativeError("function_dossier_mismatch")
        if not isinstance(body.get("pseudocode"), str) or not isinstance(body.get("assembly"), list):
            raise NativeError("envelope_not_complete")
        if any(not isinstance(item, str) for item in body["assembly"]):
            raise NativeError("envelope_not_complete")
    elif operation == "address-to-file-offset":
        params = _dict(parameters, "envelope_not_complete")
        raw_result = _dict(data.get("raw_result"), "envelope_not_complete")
        if params.get("address") != query or raw_result.get("address") != query:
            raise NativeError("envelope_not_complete")
        offset = raw_result.get("file_offset")
        if type(offset) is not int or offset < 0:
            raise NativeError("envelope_not_complete")
    elif operation == "read-bytes":
        params = _dict(parameters, "envelope_not_complete")
        if params.get("address") != query:
            raise NativeError("envelope_not_complete")
        if not isinstance(data.get("raw_result"), dict) or not data["raw_result"]:
            raise NativeError("envelope_not_complete")
    elif operation != "overview" and not isinstance(parameters, dict):
        raise NativeError("envelope_not_complete")
    return value


def inspect(
    binary: Path,
    out: Path,
    *,
    provider: str,
    operation: str = "overview",
    query: str | None = None,
    length: int | None = None,
    executable: str | None = None,
    node: str | None = None,
    toolchain: Path | None = None,
) -> dict[str, Any]:
    """Run one read-only REA operation on an immutable copy. No endpoint regex."""
    if provider not in SUPPORTED_PROVIDERS:
        raise NativeError("invalid_provider")
    _query_ok(operation, query, length)
    before = _read_file(binary, MAX_BINARY_BYTES)
    header = classify_binary(before)
    reason = _target_gate(header, provider)
    if reason is not None:
        raise NativeError(reason)
    runtime = ReaRuntime(executable, node)
    probed = runtime.capabilities()
    if probed.get("status") != "ok":
        raise NativeError(str(probed.get("reason") or "rea_missing"))
    env = _toolchain_env(toolchain)
    binary_sha = _sha(before)
    _claim(out)
    try:
        _write(out / "binary.bin", before)
        after = _read_file(binary, MAX_BINARY_BYTES)
        if after != before or _sha(_read_file(out / "binary.bin", MAX_BINARY_BYTES)) != binary_sha:
            raise NativeError("source_changed")
        provenance = json.dumps(
            {
                "caller_path": str(binary.resolve()),
                "sha256_before": binary_sha,
                "sha256_after": _sha(after),
                "size": len(before),
            }
        ).encode()
        _write(out / "provenance.json", provenance)
        execution = run_bounded(
            _argv(runtime, operation, out / "binary.bin", provider, query, length),
            out / "execution",
            timeout=180,
            env=env,
        )
        execution_bytes = (json.dumps(execution) + "\n").encode()
        _write(out / "execution.json", execution_bytes)
        if not execution.get("ok"):
            raise NativeError("rea_execution_failed")
        stdout = _read_file(out / "execution" / "stdout.bin", MAX_JSON_BYTES)
        stderr = _read_file(out / "execution" / "stderr.bin", MAX_JSON_BYTES)
        envelope = _envelope(stdout, binary_sha=binary_sha, provider=provider, operation=operation, query=query)
        later = _read_file(binary, MAX_BINARY_BYTES)
        if later != before:
            raise NativeError("source_changed")
        data = envelope["data"]
        manifest: dict[str, Any] = {
            "schema_version": "fxapk-native-inspect/1",
            "status": "captured",
            "provider": provider,
            "provider_version": _native_provider_identity(data, operation)["version"],
            "operation": operation,
            "rea_command": OPERATIONS[operation],
            "query": query,
            "binary_sha256": binary_sha,
            "size": len(before),
            "format": header["format"],
            "architecture": header["architecture"],
            "evidence_sha256": _sha(stdout),
            "stderr_sha256": _sha(stderr),
            "rea_version": probed.get("rea_version"),
            "endpoints_derived": False,
            "relation_verified": False,
            "envelope": {
                "ok": True,
                "command": envelope["meta"]["command"],
                "operation": data.get("operation"),
                "provider_id": data["provider"]["id"],
                "subject_sha256": data["subject"]["digest"]["sha256"],
                "endpoints_derived": False,
            },
        }
        if operation == "address-to-file-offset":
            manifest["address_observation"] = {
                "address": data["raw_result"]["address"],
                "file_offset": data["raw_result"]["file_offset"],
                "virtual_address_is_file_offset": False,
                "recovered": False,
            }
        if operation == "read-bytes":
            manifest["read_bytes_observation"] = {"address": query, "length": length, "recovered": False}
        _write(out / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
    except NativeError as exc:
        _write(out / "failure.json", json.dumps({"status": "failed", "reason": str(exc)}).encode())
        raise
    return manifest


def _int(value: object, lo: int, hi: int) -> int:
    if type(value) is not int or not lo <= value <= hi:
        raise NativeError("invalid_recipe")
    return value


def _exact_fields(value: dict[str, Any], allowed: frozenset[str]) -> None:
    if set(value) != allowed:
        raise NativeError("invalid_recipe")


def _walk_strings(value: object, found: list[str], depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise NativeError("invalid_json")
    if isinstance(value, str):
        found.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            found.append(str(key))
            _walk_strings(item, found, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _walk_strings(item, found, depth + 1)


def _valid_domain(value: str) -> bool:
    if len(value) > 253 or _HOST.fullmatch(value) is None:
        return False
    tld = value.rsplit(".", 1)[-1]
    return tld.isalpha() and len(tld) >= 2


def _valid_ip(value: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    if any(addr in network for network in _DOC_NETS):
        return str(addr) == value
    return bool(addr.is_global) and str(addr) == value


def _apply(body: bytes, recipe: dict[str, Any]) -> tuple[str, str]:
    if set(recipe) != _RECIPE_FIELDS:
        raise NativeError("invalid_recipe")
    ranges = recipe.get("ranges")
    steps = recipe.get("steps")
    if not isinstance(ranges, list) or not isinstance(steps, list):
        raise NativeError("invalid_recipe")
    if not 1 <= len(ranges) <= MAX_RANGES or not 1 <= len(steps) <= MAX_STEPS:
        raise NativeError("invalid_recipe")
    if not isinstance(steps[0], dict):
        raise NativeError("invalid_recipe")
    pieces: dict[str, bytes] = {}
    total = 0
    for item in ranges:
        if not isinstance(item, dict):
            raise NativeError("invalid_recipe")
        _exact_fields(item, _RANGE_FIELDS)
        ident = item.get("id")
        if not isinstance(ident, str) or not ident or ident in pieces:
            raise NativeError("invalid_recipe")
        offset_value = item.get("offset")
        if type(offset_value) is not int or offset_value < 0:
            raise NativeError("invalid_recipe")
        length = _int(item.get("length"), 1, MAX_RANGE_BYTES)
        if offset_value > len(body) or length > len(body) - offset_value:
            raise NativeError("range_out_of_bounds")
        offset = offset_value
        total += length
        if total > MAX_RANGE_BYTES * MAX_RANGES:
            raise NativeError("invalid_recipe")
        expected = item.get("expected_hex")
        if not isinstance(expected, str) or len(expected) != length * 2:
            raise NativeError("invalid_recipe")
        try:
            raw_expected = bytes.fromhex(expected)
        except ValueError:
            raise NativeError("invalid_recipe") from None
        actual = body[offset : offset + length]
        if actual != raw_expected:
            raise NativeError("expected_bytes_mismatch")
        pieces[ident] = actual
    first = steps[0]
    _exact_fields(first, _STEP_FIELDS["concat"])
    if first.get("op") != "concat":
        raise NativeError("invalid_recipe")
    ids = first.get("ids")
    if not isinstance(ids, list) or not 1 <= len(ids) <= MAX_CONCAT_IDS:
        raise NativeError("invalid_recipe")
    if any(not isinstance(ident, str) or ident not in pieces for ident in ids):
        raise NativeError("invalid_recipe")
    expanded = sum(len(pieces[ident]) for ident in ids)
    if expanded > MAX_EXPANDED_BYTES:
        raise NativeError("invalid_recipe")
    current = b"".join(pieces[ident] for ident in ids)
    kind = ""
    text = ""
    terminals = 0
    for index, step in enumerate(steps[1:], start=1):
        if not isinstance(step, dict):
            raise NativeError("invalid_recipe")
        op = step.get("op")
        if not isinstance(op, str) or op not in _STEP_FIELDS:
            raise NativeError("invalid_recipe")
        _exact_fields(step, _STEP_FIELDS[op])
        if op in _TERMINALS:
            terminals += 1
            if terminals > 1 or index != len(steps) - 1:
                raise NativeError("invalid_recipe")
        elif terminals:
            raise NativeError("invalid_recipe")
        if op == "xor-byte":
            key = _int(step.get("key"), 0, 255)
            current = bytes(item ^ key for item in current)
        elif op == "ascii-domain":
            try:
                text = current.decode("ascii")
            except UnicodeError:
                raise NativeError("invalid_hostname") from None
            if not _valid_domain(text):
                raise NativeError("invalid_hostname")
            kind = "domain"
        elif op == "ascii-ip":
            try:
                text = current.decode("ascii")
            except UnicodeError:
                raise NativeError("invalid_ip") from None
            if not _valid_ip(text):
                raise NativeError("invalid_ip")
            kind = "ip"
        elif op == "u32-ipv4":
            if len(current) != 4 or step.get("endian") not in {"big", "little"}:
                raise NativeError("invalid_recipe")
            number = int.from_bytes(current, step["endian"])
            text = str(ipaddress.IPv4Address(number))
            if not _valid_ip(text):
                raise NativeError("invalid_ip")
            kind = "ip"
    if kind not in {"domain", "ip"} or terminals != 1:
        raise NativeError("invalid_recipe")
    strings: list[str] = []
    _walk_strings(recipe, strings)
    if any(item == text for item in strings):
        raise NativeError("hardcoded_endpoint")
    return kind, text


def _content_digest(binary_sha: str, evidence_sha: str, recipe_sha: str, kind: str, value: str, query: object) -> str:
    content = json.dumps(
        {
            "binary_sha256": binary_sha,
            "evidence_sha256": evidence_sha,
            "recipe_sha256": recipe_sha,
            "kind": kind,
            "value": value,
            "query": query,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return _sha(content)


def _inspect_files(bundle: Path) -> dict[str, bytes]:
    names = {
        "dossier/stdout.bin": bundle / "execution" / "stdout.bin",
        "dossier/stderr.bin": bundle / "execution" / "stderr.bin",
        "dossier/inspect-manifest.json": bundle / "manifest.json",
        "dossier/execution.json": bundle / "execution.json",
        "dossier/provenance.json": bundle / "provenance.json",
        "binary.bin": bundle / "binary.bin",
    }
    return {name: _read_file(path, MAX_BINARY_BYTES if name == "binary.bin" else MAX_JSON_BYTES) for name, path in names.items()}


def _recipe_for(bundle: Path, recipe_path: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    files = _inspect_files(bundle)
    manifest = _loads(files["dossier/inspect-manifest.json"])
    if not isinstance(manifest, dict) or manifest.get("schema_version") != "fxapk-native-inspect/1":
        raise NativeError("invalid_bundle")
    if manifest.get("operation") != "function" or manifest.get("status") != "captured":
        raise NativeError("not_function_dossier")
    binary = files["binary.bin"]
    stdout = files["dossier/stdout.bin"]
    binary_sha = _sha(binary)
    evidence_sha = _sha(stdout)
    if binary_sha != manifest.get("binary_sha256") or evidence_sha != manifest.get("evidence_sha256"):
        raise NativeError("bundle_hash_mismatch")
    if _sha(files["dossier/stderr.bin"]) != manifest.get("stderr_sha256"):
        raise NativeError("bundle_hash_mismatch")
    _envelope(
        stdout,
        binary_sha=binary_sha,
        provider=str(manifest.get("provider")),
        operation="function",
        query=manifest.get("query") if isinstance(manifest.get("query"), str) else None,
    )
    recipe_bytes = _read_file(recipe_path, MAX_JSON_BYTES)
    recipe = _loads(recipe_bytes)
    if not isinstance(recipe, dict) or recipe.get("schema_version") != "fxapk-native-recipe/1":
        raise NativeError("invalid_recipe")
    anchor = recipe.get("anchor")
    if not isinstance(anchor, dict) or set(anchor) != _ANCHOR_FIELDS:
        raise NativeError("invalid_recipe")
    if anchor.get("operation") != "function" or anchor.get("query") != manifest.get("query"):
        raise NativeError("function_dossier_mismatch")
    if recipe.get("binary_sha256") != binary_sha:
        raise NativeError("binary_sha256_mismatch")
    if recipe.get("evidence_sha256") != evidence_sha:
        raise NativeError("evidence_sha256_mismatch")
    files["recipe.json"] = recipe_bytes
    return recipe, files


def recover(bundle: Path, recipe_path: Path, out: Path) -> dict[str, Any]:
    """Recompute a declared transform. Byte match is not semantic linkage."""
    recipe, files = _recipe_for(bundle, recipe_path)
    kind, value = _apply(files["binary.bin"], recipe)
    recipe_bytes = files["recipe.json"]
    binary_sha = _sha(files["binary.bin"])
    evidence_sha = _sha(files["dossier/stdout.bin"])
    recipe_sha = _sha(recipe_bytes)
    candidate = {
        "label": "analyst_reconstruction",
        "kind": kind,
        "value": value,
        "confidence": "LOW",
        "advice": "待核",
        "source": "derived-native",
        "relation_verified": False,
        "runtime_observed": False,
        "closure_evaluated": False,
    }
    result = {
        "schema_version": "fxapk-native-recovery/1",
        "candidate": candidate,
        "binary_sha256": binary_sha,
        "evidence_sha256": evidence_sha,
        "recipe_sha256": recipe_sha,
        "anchor": recipe["anchor"],
        "relation_verified": False,
        "runtime_observed": False,
        "closure_evaluated": False,
        "verified_ranges": recipe["ranges"],
        "gaps": [
            "byte_transform_only",
            "relation_verified_false",
            "runtime_observed_false",
            "closure_not_evaluated",
        ],
    }
    digest = _content_digest(binary_sha, evidence_sha, recipe_sha, kind, value, recipe["anchor"]["query"])
    result["content_digest"] = digest
    files["result.json"] = (json.dumps(result, indent=2) + "\n").encode()
    listing = {name: {"sha256": _sha(files[name]), "size": len(files[name])} for name in BUNDLE_FILES}
    recovery_manifest = {
        "schema_version": "fxapk-native-recovery/1",
        "content_digest": digest,
        "files": listing,
        "endpoints_derived_by_regex": False,
    }
    manifest_bytes = (json.dumps(recovery_manifest, indent=2) + "\n").encode()
    _claim(out)
    _write(out / "manifest.json", manifest_bytes)
    for name in BUNDLE_FILES:
        _write(out / name, files[name])
    return {
        "status": "ok",
        "schema_version": "fxapk-native-recovery/1",
        "content_digest": digest,
        "candidate_sha256": _sha(value.encode()),
        "kind": kind,
        "relation_verified": False,
        "runtime_observed": False,
        "closure_evaluated": False,
    }


def _typed_size(value: object) -> int:
    if type(value) is not int or value < 0:
        raise NativeError("invalid_bundle")
    return value


def _load_recovery(bundle: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    manifest_path = bundle / "manifest.json"
    if manifest_path.name != "manifest.json":
        raise NativeError("invalid_bundle")
    manifest_bytes = _read_file(manifest_path, MAX_JSON_BYTES)
    manifest = _loads(manifest_bytes)
    if not isinstance(manifest, dict) or manifest.get("schema_version") != "fxapk-native-recovery/1":
        raise NativeError("invalid_bundle")
    files_meta = manifest.get("files")
    if not isinstance(files_meta, dict) or set(files_meta) != set(BUNDLE_FILES):
        raise NativeError("invalid_bundle")
    claimed_total = 0
    for name in BUNDLE_FILES:
        meta = files_meta.get(name)
        if not isinstance(name, str) or not isinstance(meta, dict) or set(meta) - {"sha256", "size"}:
            raise NativeError("invalid_bundle")
        digest = meta.get("sha256")
        if not isinstance(digest, str) or _SHA.fullmatch(digest) is None:
            raise NativeError("invalid_bundle")
        claimed_total += _typed_size(meta.get("size"))
        if name != "binary.bin" and meta["size"] > MAX_JSON_BYTES:
            raise NativeError("oversize")
        if name == "binary.bin" and meta["size"] > MAX_BINARY_BYTES:
            raise NativeError("oversize")
    if claimed_total > MAX_BUNDLE_BYTES:
        raise NativeError("oversize")
    loaded: dict[str, bytes] = {"manifest.json": manifest_bytes}
    actual_total = len(manifest_bytes)
    for name in BUNDLE_FILES:
        limit = MAX_BINARY_BYTES if name == "binary.bin" else MAX_JSON_BYTES
        blob = _read_file(bundle / name, limit)
        meta = files_meta[name]
        if _sha(blob) != meta["sha256"] or len(blob) != meta["size"]:
            raise NativeError("bundle_hash_mismatch")
        actual_total += len(blob)
        if actual_total > MAX_BUNDLE_BYTES:
            raise NativeError("oversize")
        loaded[name] = blob
    result = _loads(loaded["result.json"])
    recipe = _loads(loaded["recipe.json"])
    inspect_manifest = _loads(loaded["dossier/inspect-manifest.json"])
    if not isinstance(result, dict) or not isinstance(recipe, dict) or not isinstance(inspect_manifest, dict):
        raise NativeError("invalid_bundle")
    binary_sha = _sha(loaded["binary.bin"])
    evidence_sha = _sha(loaded["dossier/stdout.bin"])
    recipe_sha = _sha(loaded["recipe.json"])
    if result.get("binary_sha256") != binary_sha or recipe.get("binary_sha256") != binary_sha:
        raise NativeError("result_mismatch")
    if result.get("evidence_sha256") != evidence_sha or recipe.get("evidence_sha256") != evidence_sha:
        raise NativeError("result_mismatch")
    if inspect_manifest.get("binary_sha256") != binary_sha or inspect_manifest.get("evidence_sha256") != evidence_sha:
        raise NativeError("bundle_hash_mismatch")
    provider = inspect_manifest.get("provider")
    query = inspect_manifest.get("query")
    if not isinstance(provider, str) or not isinstance(query, str):
        raise NativeError("invalid_bundle")
    anchor = recipe.get("anchor")
    if (
        inspect_manifest.get("operation") != "function"
        or not isinstance(anchor, dict)
        or set(anchor) != _ANCHOR_FIELDS
        or anchor.get("operation") != "function"
        or anchor.get("query") != query
        or result.get("anchor") != anchor
    ):
        raise NativeError("function_dossier_mismatch")
    _envelope(loaded["dossier/stdout.bin"], binary_sha=binary_sha, provider=provider, operation="function", query=query)
    kind, value = _apply(loaded["binary.bin"], recipe)
    digest = _content_digest(binary_sha, evidence_sha, recipe_sha, kind, value, query)
    if result.get("content_digest") != digest or manifest.get("content_digest") != digest:
        raise NativeError("result_mismatch")
    if result.get("recipe_sha256") != recipe_sha:
        raise NativeError("result_mismatch")
    if result.get("verified_ranges") != recipe.get("ranges"):
        raise NativeError("result_mismatch")
    candidate = result.get("candidate")
    if not isinstance(candidate, dict) or candidate.get("kind") != kind or candidate.get("value") != value:
        raise NativeError("result_mismatch")
    if candidate.get("label") != "analyst_reconstruction":
        raise NativeError("result_mismatch")
    if "label" in result and result.get("label") != "analyst_reconstruction":
        raise NativeError("result_mismatch")
    if result.get("relation_verified") is not False or candidate.get("relation_verified") is not False:
        raise NativeError("result_mismatch")
    if result.get("runtime_observed") is not False or candidate.get("runtime_observed") is not False:
        raise NativeError("result_mismatch")
    if candidate.get("closure_evaluated") is not False or result.get("closure_evaluated") is not False:
        raise NativeError("result_mismatch")
    if candidate.get("confidence") != "LOW" or candidate.get("advice") != "待核":
        raise NativeError("result_mismatch")
    if candidate.get("source") != "derived-native":
        raise NativeError("result_mismatch")
    loaded["content_digest"] = digest.encode()
    return result, loaded


def _bind(report: dict[str, Any], binary_sha: str) -> str:
    meta = report.get("meta")
    if not isinstance(meta, dict):
        raise NativeError("sample_binding_mismatch")
    if meta.get("sample_sha256") == binary_sha:
        return "sample_sha256"
    hashes = meta.get("native_lib_hashes")
    if isinstance(hashes, list):
        for item in hashes:
            if isinstance(item, dict) and item.get("sha256") == binary_sha and isinstance(item.get("name"), str):
                size = item.get("size")
                if type(size) is int and size >= 0:
                    return "native_lib_hashes"
    raise NativeError("sample_binding_mismatch")


def _history_groups(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    meta = report.get("meta")
    if not isinstance(meta, dict):
        raise NativeError("invalid_report")
    history = meta.get("native_recovery")
    if history is None:
        return {}
    if not isinstance(history, list) or len(history) > MAX_SNAPSHOT_LINKS:
        raise NativeError("history_snapshot_mismatch")
    groups: dict[str, dict[str, Any]] = {}
    seen_paths: set[str] = set()
    for item in history:
        if not isinstance(item, dict):
            raise NativeError("history_snapshot_mismatch")
        digest = item.get("content_digest")
        files = item.get("files")
        binary_sha = item.get("binary_sha256")
        binding = item.get("binding")
        if not isinstance(digest, str) or _SHA.fullmatch(digest) is None or not isinstance(files, list):
            raise NativeError("history_snapshot_mismatch")
        if not isinstance(binary_sha, str) or _SHA.fullmatch(binary_sha) is None:
            raise NativeError("history_snapshot_mismatch")
        if binding not in {"sample_sha256", "native_lib_hashes"}:
            raise NativeError("history_snapshot_mismatch")
        names: list[tuple[str, str, str, int]] = []
        for entry in files:
            if not isinstance(entry, dict):
                raise NativeError("history_snapshot_mismatch")
            relative = entry.get("path")
            if (
                not isinstance(relative, str)
                or "\\" in relative
                or ":" in relative
                or relative.startswith("/")
                or ".." in relative.split("/")
            ):
                raise NativeError("history_snapshot_mismatch")
            parts = relative.split("/")
            if len(parts) < 3 or parts[0] != "native_recovery" or parts[1] != digest:
                raise NativeError("history_snapshot_mismatch")
            name = "/".join(parts[2:])
            if name not in BUNDLE_FILES and name != "manifest.json":
                raise NativeError("history_snapshot_mismatch")
            claimed = entry.get("sha256")
            size = entry.get("size")
            if not isinstance(claimed, str) or _SHA.fullmatch(claimed) is None:
                raise NativeError("history_snapshot_mismatch")
            if type(size) is not int or size < 0:
                raise NativeError("history_snapshot_mismatch")
            if relative in seen_paths or any(existing == name for existing, *_rest in names):
                raise NativeError("history_snapshot_mismatch")
            seen_paths.add(relative)
            names.append((name, relative, claimed, size))
        expected = {"manifest.json", *BUNDLE_FILES}
        if len(names) != len(expected) or {name for name, *_rest in names} != expected or digest in groups:
            raise NativeError("history_snapshot_mismatch")
        groups[digest] = {"names": names, "binary_sha256": binary_sha, "binding": binding}
    return groups


def _read_history(report_path: Path, report: dict[str, Any]) -> list[tuple[str, bytes]]:
    groups = _history_groups(report)
    copied: list[tuple[str, bytes]] = []
    total = 0
    for digest, group in groups.items():
        root = report_path.parent / "native_recovery" / digest
        blob_map: dict[str, bytes] = {}
        for name, relative, claimed, size in group["names"]:
            blob = _read_file(report_path.parent / relative, MAX_BINARY_BYTES if name == "binary.bin" else MAX_JSON_BYTES)
            if _sha(blob) != claimed or len(blob) != size:
                raise NativeError("history_snapshot_mismatch")
            total += len(blob)
            if total > MAX_HISTORY_BYTES:
                raise NativeError("oversize")
            blob_map[name] = blob
            copied.append((relative, blob))
        if _sha(blob_map["binary.bin"]) != group["binary_sha256"]:
            raise NativeError("history_snapshot_mismatch")
        if _bind(report, group["binary_sha256"]) != group["binding"]:
            raise NativeError("history_snapshot_mismatch")
        result, loaded = _load_recovery(root)
        if result.get("content_digest") != digest or loaded["manifest.json"] != blob_map["manifest.json"]:
            raise NativeError("history_snapshot_mismatch")
        if result.get("binary_sha256") != group["binary_sha256"]:
            raise NativeError("history_snapshot_mismatch")
    return copied


def _snapshot_chain(report_path: Path, report: dict[str, Any]) -> list[tuple[str, bytes]]:
    meta = report.get("meta")
    if not isinstance(meta, dict):
        raise NativeError("invalid_report")
    prepared: list[tuple[str, bytes]] = []
    sizes: dict[str, int] = {}
    stack: set[str] = set()
    total = 0

    def visit(record: object) -> None:
        nonlocal total
        if record is None:
            return
        if len(prepared) > MAX_SNAPSHOT_LINKS:
            raise NativeError("oversize")
        if not isinstance(record, dict):
            raise NativeError("history_snapshot_mismatch")
        relative = record.get("relative_path")
        if not isinstance(relative, str):
            raise NativeError("history_snapshot_mismatch")
        match = _SNAPSHOT.fullmatch(relative)
        if match is None or "\\" in relative or ":" in relative:
            raise NativeError("history_snapshot_mismatch")
        digest = match.group(1)
        if record.get("sha256") != digest:
            raise NativeError("history_snapshot_mismatch")
        if digest in stack:
            raise NativeError("history_snapshot_mismatch")
        if digest in sizes:
            if "byte_length" in record and _typed_size(record.get("byte_length")) != sizes[digest]:
                raise NativeError("history_snapshot_mismatch")
            return
        if len(prepared) >= MAX_SNAPSHOT_LINKS:
            raise NativeError("oversize")
        remaining = MAX_HISTORY_BYTES - total
        blob = _read_file(report_path.parent / relative, remaining)
        if _sha(blob) != digest:
            raise NativeError("history_snapshot_mismatch")
        if "byte_length" in record and _typed_size(record.get("byte_length")) != len(blob):
            raise NativeError("history_snapshot_mismatch")
        sizes[digest] = len(blob)
        total += len(blob)
        prepared.append((relative, blob))
        nested = _loads(blob, MAX_HISTORY_BYTES)
        nested_meta = nested.get("meta") if isinstance(nested, dict) else None
        if not isinstance(nested, dict):
            raise NativeError("history_snapshot_mismatch")
        stack.add(digest)
        try:
            if isinstance(nested_meta, dict):
                visit(nested_meta.get("native_recovery_input"))
                visit(nested_meta.get("supplement_web_input"))
            elif nested_meta is not None:
                raise NativeError("history_snapshot_mismatch")
        finally:
            stack.remove(digest)

    visit(meta.get("native_recovery_input"))
    visit(meta.get("supplement_web_input"))
    return prepared


def _require_lists(report: dict[str, Any]) -> None:
    for key in ("endpoints", "leads"):
        if key in report and not isinstance(report[key], list):
            raise NativeError("invalid_report")
    for collection in ("endpoints", "leads"):
        rows = report.get(collection)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                raise NativeError("invalid_report")
            refs_key = "evidences" if collection == "endpoints" else "source_refs"
            if refs_key in row and not isinstance(row[refs_key], list):
                raise NativeError("invalid_report")


def _web_observation_bytes(report_path: Path, report: dict[str, Any]) -> list[tuple[str, dict[str, bytes]]]:
    """Read-only reuse of the core bundle verifier. No path walk of our own."""
    from apkscan.core.web_supplement_report import (
        SupplementRefusal,
        _referenced_trees,
        _reverify_trees,
        _verify_attachment_claims,
    )

    try:
        _verify_attachment_claims(report, report_path.parent)
        trees = _referenced_trees(report, report_path.parent)
        return _reverify_trees(trees)
    except SupplementRefusal as exc:
        raise NativeError("history_snapshot_mismatch") from exc


def _place_web_observations(out: Path, trees: list[tuple[str, dict[str, bytes]]]) -> None:
    from apkscan.core.web_supplement_report import SupplementRefusal, _place_trees

    try:
        _place_trees(out, trees)
    except SupplementRefusal as exc:
        raise NativeError("history_snapshot_mismatch") from exc


def _bind_extract(
    report: dict[str, Any], apk_sha: str, member: str, member_sha: str, size: int,
) -> None:
    meta = report.get("meta")
    if not isinstance(meta, dict) or meta.get("sample_sha256") != apk_sha:
        raise NativeError("sample_binding_mismatch")
    hashes = meta.get("native_lib_hashes")
    if not isinstance(hashes, list):
        raise NativeError("sample_binding_mismatch")
    basename = member.rsplit("/", 1)[-1]
    for item in hashes:
        if not isinstance(item, dict) or item.get("sha256") != member_sha:
            continue
        recorded = item.get("name")
        recorded_size = item.get("size")
        if recorded in {basename, member} and type(recorded_size) is int and recorded_size == size:
            return
    raise NativeError("sample_binding_mismatch")


def _history_flags(report: dict[str, Any]) -> None:
    """Reject history flags that contradict the immutable false recovery result.

    Missing flags are filled only on this in-memory copy. The caller writes a new
    directory and does not rewrite the input report.
    """
    meta = report.get("meta")
    if not isinstance(meta, dict):
        return
    history = meta.get("native_recovery")
    if not isinstance(history, list):
        return
    for item in history:
        if not isinstance(item, dict):
            continue
        for key in ("relation_verified", "runtime_observed", "closure_evaluated"):
            if key not in item:
                item[key] = False
            elif item[key] is not False:
                raise NativeError("result_mismatch")
        if "label" not in item:
            item["label"] = "analyst_reconstruction"
        elif item.get("label") != "analyst_reconstruction":
            raise NativeError("result_mismatch")


def attach(bundle: Path, report_path: Path, out: Path) -> dict[str, Any]:
    """Append one candidate. Existing grades, closure and unknown fields stay."""
    result, loaded = _load_recovery(bundle)
    original = _read_file(report_path, 32 * 1024 * 1024)
    report = _loads(original, 32 * 1024 * 1024)
    if not isinstance(report, dict) or not isinstance(report.get("meta"), dict):
        raise NativeError("invalid_report")
    _require_lists(report)
    _history_flags(report)
    binary_sha = _sha(loaded["binary.bin"])
    bound = _bind(report, binary_sha)
    prior_files = _read_history(report_path, report)
    snapshots = _snapshot_chain(report_path, report)
    meta = report["meta"]
    history = meta.get("native_recovery")
    if history is None:
        history = []
        meta["native_recovery"] = history
    if not isinstance(history, list):
        raise NativeError("history_snapshot_mismatch")
    digest = result["content_digest"]
    if not isinstance(digest, str):
        raise NativeError("result_mismatch")
    fresh = not any(isinstance(item, dict) and item.get("content_digest") == digest for item in history)
    candidate = result["candidate"]
    if not isinstance(candidate, dict) or not isinstance(candidate.get("value"), str):
        raise NativeError("result_mismatch")
    evidence = {
        "source": "derived-native",
        "location": f"native-recovery:{binary_sha[:12]}",
        "snippet": candidate["value"],
        "scope": "case_evidence",
    }
    if fresh:
        endpoints = report.get("endpoints")
        if endpoints is None:
            endpoints = []
            report["endpoints"] = endpoints
        if not isinstance(endpoints, list):
            raise NativeError("invalid_report")
        endpoint = next(
            (
                item
                for item in endpoints
                if isinstance(item, dict) and item.get("kind") == candidate.get("kind") and item.get("value") == candidate["value"]
            ),
            None,
        )
        if endpoint is None:
            endpoints.append(
                {"value": candidate["value"], "kind": candidate["kind"], "evidences": [evidence], "enrichment": {}}
            )
        else:
            refs = endpoint.get("evidences")
            if refs is None:
                refs = []
                endpoint["evidences"] = refs
            if not isinstance(refs, list):
                raise NativeError("invalid_report")
            if evidence not in refs:
                refs.append(evidence)
        leads = report.get("leads")
        if leads is None:
            leads = []
            report["leads"] = leads
        if not isinstance(leads, list):
            raise NativeError("invalid_report")
        lead = next(
            (
                item
                for item in leads
                if isinstance(item, dict)
                and str(item.get("category", "")).upper() == str(candidate.get("kind", "")).upper()
                and item.get("value") == candidate["value"]
            ),
            None,
        )
        if lead is None:
            leads.append(
                {
                    "category": str(candidate["kind"]).upper(),
                    "value": candidate["value"],
                    "confidence": "LOW",
                    "advice": "待核",
                    "base_advice": "待核",
                    "notes": "analyst_reconstruction; relation_verified=false; runtime_observed=false; closure_evaluated=false",
                    "source_refs": [evidence],
                    "evidence_to_obtain": ["核对 native 字节变换与函数锚点；运行时未观察"],
                }
            )
        else:
            refs = lead.get("source_refs")
            if refs is None:
                refs = []
                lead["source_refs"] = refs
            if not isinstance(refs, list):
                raise NativeError("invalid_report")
            if evidence not in refs:
                refs.append(evidence)
        relative_files = []
        root = f"native_recovery/{digest}"
        names = ("manifest.json", *BUNDLE_FILES)
        for name in names:
            blob = loaded["manifest.json"] if name == "manifest.json" else loaded[name]
            relative_files.append({"path": f"{root}/{name}", "sha256": _sha(blob), "size": len(blob)})
        history.append(
            {
                "schema_version": "fxapk-native-recovery-history/1",
                "content_digest": digest,
                "binary_sha256": binary_sha,
                "binding": bound,
                "label": "analyst_reconstruction",
                "relation_verified": False,
                "runtime_observed": False,
                "closure_evaluated": False,
                "files": relative_files,
            }
        )
    snapshot = f"input_report/{_sha(original)}/report.json"
    meta["native_recovery_input"] = {
        "sha256": _sha(original),
        "relative_path": snapshot,
        "byte_length": len(original),
        "source_report_absolute": str(report_path.resolve()),
        "source_artifact_base": str(report_path.parent.resolve()),
    }
    preserved = _web_observation_bytes(report_path, report)
    from apkscan.core.dex_query import DexQueryError, collect_receipt_files

    try:
        dex_receipts = collect_receipt_files(report_path.parent, meta)
    except DexQueryError as exc:
        raise NativeError(exc.reason) from None
    _claim(out)
    _place_web_observations(out, preserved)
    _write(out / snapshot, original)
    for relative, blob in snapshots:
        _write(out / relative, blob)
    for relative, blob in prior_files:
        _write(out / relative, blob)
    for relative, blob in dex_receipts.items():
        _write(out / relative, blob)
    if fresh:
        root = out / "native_recovery" / digest
        _write(root / "manifest.json", loaded["manifest.json"])
        for name in BUNDLE_FILES:
            _write(root / name, loaded[name])
    _write(out / "report.json", (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode())
    return {
        "status": "ok",
        "content_digest": digest,
        "history_count": len(history),
        "closure_evaluated": False,
        "candidate_sha256": _sha(str(candidate["value"]).encode()),
    }


def extract_native(apk: Path, member: str, out: Path, report: Path | None = None) -> dict[str, Any]:
    """Copy one exact lib/<abi>/<name>.so into binary.bin. No bulk unzip and no engine."""
    if not isinstance(member, str) or _MEMBER.fullmatch(member) is None or "\\" in member:
        raise NativeError("invalid_member")
    abi = member.split("/")[1]
    apk_sha = _hash_file(apk, MAX_APK_BYTES)
    _ancestors(apk)
    try:
        archive = zipfile.ZipFile(apk)
    except (zipfile.BadZipFile, OSError):
        raise NativeError("invalid_zip") from None
    try:
        infos = [info for info in archive.infolist() if info.filename == member]
        if len(infos) != 1:
            raise NativeError("invalid_member")
        info = infos[0]
        if info.flag_bits & 0x1 or info.file_size > MAX_BINARY_BYTES or info.file_size <= 0:
            raise NativeError("oversize" if info.file_size > MAX_BINARY_BYTES else "invalid_member")
        try:
            with archive.open(info, "r") as handle:
                blob = handle.read(MAX_BINARY_BYTES + 1)
        except (zipfile.BadZipFile, zlib.error):
            raise NativeError("invalid_zip") from None
    finally:
        archive.close()
    if len(blob) != info.file_size:
        raise NativeError("invalid_zip")
    header = classify_binary(blob)
    if header["format"] != "elf":
        raise NativeError("unsupported_target")
    member_sha = _sha(blob)
    if header["architecture"] != _ABI_ARCH.get(abi):
        raise NativeError("abi_mismatch")
    if report is not None:
        payload = _loads(_read_file(report, 32 * 1024 * 1024), 32 * 1024 * 1024)
        if not isinstance(payload, dict):
            raise NativeError("invalid_report")
        _bind_extract(payload, apk_sha, member, member_sha, len(blob))
    manifest = {
        "schema_version": "fxapk-native-extract/1",
        "apk_sha256": apk_sha,
        "member": member,
        "abi": abi,
        "member_sha256": member_sha,
        "size": len(blob),
        "format": header["format"],
        "architecture": header["architecture"],
        "engine_required": False,
    }
    _claim(out)
    _write(out / "binary.bin", blob)
    _write(out / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
    return {"status": "ok", **manifest}
