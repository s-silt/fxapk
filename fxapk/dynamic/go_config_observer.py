"""Opt-in, offline support for hash-bound AArch64 Go boundary observations.

Compiles regular uprobes only: no return-address replacement or Go trampolines.
The caller owns device setup, isolated trace instance, loss accounting and APK /
PID identity verification. A boundary snapshot is NOT a field-consumption proof.
No device, network, or default capture behavior is changed by this module.
"""

from __future__ import annotations

import hashlib
import re
import struct
from typing import Any

_ROLES = {
    "fetch_enter",
    "body_return",
    "decode_enter",
    "decode_return",
    "json_enter",
    "json_return",
    "field_read",
    "dial_enter",
    "dial_return",
    "stage_enter",
}
_REG = r"%(?:x(?:[0-9]|[12][0-9]|30)|sp)"
_EXPR = re.compile(
    rf"(?:{_REG}|\+[0-9]{{1,4}}\({_REG}\)|\+[0-9]{{1,4}}\(\+[0-9]{{1,4}}\({_REG}\)\))"
)
_LINE = re.compile(
    r"^\s*.+-(\d+)\s+\(\s*(\d+|-----)\)\s+\[\d+\]\s+\S+\s+(\d+)\.(\d+):\s+(\w+):\s+\([^)]*\)\s+(.*)$"
)
_LIMIT = 5 * 1024 * 1024


def _sites(profile: dict) -> list[dict]:
    sites = profile.get("sites")
    if (
        profile.get("schema") != "fxapk-go-config-profile-1"
        or profile.get("architecture") != "arm64"
        or not re.fullmatch(r"[0-9a-f]{64}", str(profile.get("module_sha256")))
        or not isinstance(sites, list)
        or not 1 <= len(sites) <= 24
    ):
        raise ValueError("invalid_go_profile")
    seen = set()
    for site in sites:
        if not isinstance(site, dict):
            raise ValueError("invalid_go_site")
        name, offset, size = site.get("name"), site.get("file_offset"), site.get("max_bytes")
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", name)
            or name in seen
            or site.get("role") not in _ROLES
            or type(offset) is not int
            or offset < 0
            or offset % 4
            or not re.fullmatch(r"[0-9a-f]{8}", str(site.get("instruction_hex")))
            or type(size) is not int
            or not 0 <= size <= 768
            or size % 8
            or not _EXPR.fullmatch(str(site.get("pointer")))
            or not _EXPR.fullmatch(str(site.get("length")))
        ):
            raise ValueError("invalid_go_site")
        scalars = site.get("scalars", {})
        if not isinstance(scalars, dict) or len(scalars) > 8:
            raise ValueError("invalid_go_scalars")
        for key, expr in scalars.items():
            if not re.fullmatch(r"s_[a-z_]{1,24}", str(key)) or not _EXPR.fullmatch(str(expr)):
                raise ValueError("invalid_go_scalar")
        seen.add(name)
    return sorted(sites, key=lambda s: s["name"])


def compile_profile(profile: dict, module: bytes, *, remote_path: str, group: str) -> list[str]:
    """Validate bytes/ELF offsets before producing narrowly quoted trace commands.

    Append these definitions to uprobe_events; never truncate its global file.
    Enable only the caller's isolated instance and remove only its own events.
    """
    sites = _sites(profile)
    if (
        not re.fullmatch(r"/[A-Za-z0-9_./+=@~-]+", remote_path)
        or ".." in remote_path.split("/")
        or not re.fullmatch(r"fxapk_go_[a-z0-9_]{1,32}", group)
    ):
        raise ValueError("invalid_go_trace_scope")
    if hashlib.sha256(module).hexdigest() != profile["module_sha256"]:
        raise ValueError("native_module_hash_mismatch")
    try:
        if module[:7] != b"\x7fELF\x02\x01\x01" or struct.unpack_from("<H", module, 18)[0] != 183:
            raise ValueError("unsupported_go_elf")
        phoff = struct.unpack_from("<Q", module, 32)[0]
        phsize, count = struct.unpack_from("<HH", module, 54)
        if phsize != 56 or not 1 <= count <= 256:
            raise ValueError("invalid_go_elf_segments")
        segments = [
            struct.unpack_from("<IIQQQQQQ", module, phoff + i * phsize) for i in range(count)
        ]
        for site in sites:
            offset = site["file_offset"]
            if (
                not any(
                    s[0] == 1
                    and s[1] & 1
                    and s[2] <= offset
                    and offset + 4 <= s[2] + s[5] <= len(module)
                    for s in segments
                )
                or module[offset : offset + 4].hex() != site["instruction_hex"]
            ):
                raise ValueError("native_probe_instruction_mismatch")
    except struct.error as exc:
        raise ValueError("invalid_go_elf") from exc
    lines = []
    for site in sites:
        pointer = site["pointer"]
        fields = ["g=%x28:u64", "lr=%x30:u64", f"ptr={pointer}:u64", f"len={site['length']}:u64"]
        fields.extend(f"{key}={expr}:u64" for key, expr in sorted(site.get("scalars", {}).items()))
        fields.extend(f"w{i:03}=+{i * 8}({pointer}):x64" for i in range(site["max_bytes"] // 8))
        lines.append(
            f"p:{group}/{site['name']} {remote_path}:{site['file_offset']:#x} " + " ".join(fields)
        )
    return lines


def project_trace(profile: dict, trace: str, *, lost_events: int | None) -> dict[str, Any]:
    """Decode retained trace text conservatively; never invent Go object identity.

    Scalar tracefs fetches use zero on read faults on some supported kernels.
    Zero words are retained, but cannot certify complete material. Even a complete
    snapshot does not certify HTTP completeness, process identity or causality.
    """
    sites = {s["name"]: s for s in _sites(profile)}
    gaps = {"field_to_network_origin_unbound", "native_capture_scope_requires_verification"}
    if lost_events is None:
        gaps.add("native_loss_status_unknown")
    elif type(lost_events) is not int or lost_events < 0:
        raise ValueError("invalid_native_loss_count")
    elif lost_events:
        gaps.add("native_events_lost")
    rows = []
    if len(trace.encode()) > _LIMIT:
        gaps.add("native_trace_budget_exceeded")
        trace = ""
    for line_no, line in enumerate(trace.splitlines()):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _LINE.fullmatch(line)
        if not match or match[5] not in sites or len(rows) >= 20000:
            gaps.add("native_trace_malformed")
            continue
        site = sites[match[5]]
        parts = match[6].split()
        values = dict(part.split("=", 1) for part in parts if "=" in part)
        local: set[str] = set()
        try:
            if len(values) != len(parts):
                raise ValueError("duplicate_or_missing_trace_field")
            numbers = {k: int(values[k], 0) for k in ("g", "lr", "ptr", "len")}
            if (
                any(v < 0 or v >= 2**64 for v in numbers.values())
                or not numbers["g"]
                or not numbers["ptr"]
            ):
                raise ValueError("invalid_go_coordinate")
            length = numbers["len"]
            if site["max_bytes"] and length > site["max_bytes"]:
                local.add("native_snapshot_truncated")
            size = min(length, site["max_bytes"])
            words = []
            for i in range((size + 7) // 8):
                value = values.get(f"w{i:03}", "(fault)")
                if value == "(fault)":
                    local.add("native_memory_read_failed")
                    break
                word = int(value, 0)
                if word == 0:
                    local.add("native_memory_read_status_unknown")
                words.append(word.to_bytes(8, "little"))
            body = b"".join(words)[:size]
            tgid = int(match[2]) if match[2] != "-----" else None
            if tgid is None:
                local.add("native_process_binding_missing")
            scalars = {key: int(values[key], 0) for key in sorted(site.get("scalars", {}))}
            rows.append(
                {
                    "site": site["name"],
                    "role": site["role"],
                    "tid": int(match[1]),
                    "tgid": tgid,
                    "timestamp_ns": int(match[3]) * 10**9 + int(match[4].ljust(9, "0")),
                    "line": line_no,
                    **numbers,
                    "scalars": scalars,
                    "body_hex": body.hex(),
                    "snapshot_complete": not local
                    and 0 < length <= site["max_bytes"]
                    and lost_events == 0,
                    "consumption": "candidate",
                    "gaps": sorted(local),
                }
            )
            gaps.update(local)
        except (KeyError, ValueError, OverflowError):
            gaps.add("native_trace_malformed")
    if not rows:
        gaps.add("native_no_observations")
    if {"native_trace_malformed", "native_events_lost", "native_loss_status_unknown"} & gaps:
        for row in rows:
            row["snapshot_complete"] = False
    return {
        "schema": "fxapk-go-config-observation-1",
        "module_sha256": profile["module_sha256"],
        "events": sorted(rows, key=lambda r: (r["timestamp_ns"], r["line"])),
        "gaps": sorted(gaps),
    }
