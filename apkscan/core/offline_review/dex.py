"""Recovered DEX header, method-body and real JADX checks on immutable bytes."""
from __future__ import annotations

import hashlib
import os
import re
import struct
import zlib
from pathlib import Path

from .common import result, sha256


def review(data: bytes, options: dict) -> dict:
    if data[:4] == b"cdex" or data[4:7] not in {b"035", b"037", b"038", b"039", b"040"}:
        return result("unsupported", ["unsupported_dex_format"])
    if len(data) < 112 or data[:4] != b"dex\n" or data[7] != 0:
        raise ValueError("invalid_dex_header")
    size, header, endian = struct.unpack_from("<III", data, 32)
    checks = {"size": size == len(data), "header": header == 112, "endian": endian == 0x12345678,
              "sha1": data[12:32] == hashlib.sha1(data[32:]).digest(),
              "adler32": struct.unpack_from("<I", data, 8)[0] == zlib.adler32(data[12:]) & 0xffffffff}
    if not all(checks.values()):
        return result("failed", ["dex_header_integrity_failed"], header_checks=checks,
                      repair_performed=False, method_coverage="not_run")
    # Bound every fixed-size table before handing bytes to the third-party parser.
    for offset, width in ((56, 4), (64, 4), (72, 12), (80, 8), (88, 8), (96, 32)):
        count, position = struct.unpack_from("<II", data, offset)
        if count > 200000 or position + count * width > len(data):
            raise ValueError("dex_table_budget_or_bounds")
    targets = options.get("targets")
    if not isinstance(targets, list) or not 1 <= len(targets) <= 64 or not all(isinstance(t, str) and "->" in t for t in targets):
        raise ValueError("explicit_dex_method_targets_required")
    from androguard.core.dex import DEX
    parsed = DEX(data)
    methods = {}
    for cls in parsed.get_classes():
        for method in cls.get_methods():
            key = method.get_class_name() + "->" + method.get_name() + method.get_descriptor().replace(" ", "")
            if key in targets:
                methods.setdefault(key, []).append(method)
    rows, reasons = [], set()
    for target in targets:
        found = methods.get(target, [])
        row = {"target": target, "state": "missing", "instructions": 0, "code_sha256": None}
        if len(found) == 1:
            method = found[0]
            code = method.get_code()
            if code is None:
                row["state"] = "native_or_abstract" if method.get_access_flags() & 0x500 else "body_missing"
            else:
                bytecode = code.get_bc().get_raw()
                instructions = list(code.get_bc().get_instructions())
                valid = (bytecode and sum(i.get_length() for i in instructions) == len(bytecode)
                         and not any(i.get_name().startswith(("unused", "invalid")) for i in instructions))
                row.update(state="decoded" if valid else "decode_failed", instructions=len(instructions),
                           code_sha256=sha256(bytecode), code_offset=method.get_code_off(),
                           byte_count=len(bytecode))
        elif len(found) > 1:
            row["state"] = "ambiguous"
        if row["state"] != "decoded":
            reasons.add("dex_target_" + row["state"])
        rows.append(row)
    jadx = {"state": "not_requested", "reason_codes": []}
    if options.get("jadx") is True:
        from apkscan.core import tools
        from apkscan.core.proctree import run_owned
        resolved = tools.resolve_jadx()
        if not resolved:
            jadx = {"state": "unsupported", "reason_codes": ["jadx_unavailable"]}
        else:
            folder = Path(options["_artifact_dir"])
            folder.mkdir(exist_ok=True)
            source = folder / "recovered.dex"
            source.write_bytes(data)
            command, extra_env = resolved
            run = run_owned([*command, "--no-res", "--deobf", "--comments-level", "error", "-j", "1",
                             "-d", str(folder / "jadx"), str(source)], timeout=120,
                            env={**os.environ, **extra_env}, memory_bytes=2 * 1024**3,
                            max_stdout_bytes=1024**2, max_stderr_bytes=1024**2)
            (folder / "jadx.stdout.log").write_text(run.stdout, encoding="utf-8")
            (folder / "jadx.stderr.log").write_text(run.stderr, encoding="utf-8")
            codes = list(run.reason_codes)
            if run.returncode != 0:
                codes.append("jadx_nonzero_exit")
            if run.timed_out:
                codes.append("jadx_timeout")
            if not run.ownership_complete or not run.termination_complete or run.forced_tree_kill:
                codes.append("jadx_process_tree_incomplete")
            source_rows, total = [], 0
            # Generated names are not used as exact DEX descriptor proof.
            for path in sorted((folder / "jadx").rglob("*.java")):
                total += path.stat().st_size
                if len(source_rows) >= 10000 or total > 32 * 1024**2:
                    codes.append("jadx_output_budget")
                    break
                text = path.read_text(encoding="utf-8", errors="strict")
                bad = bool(re.search(r"JADX (?:ERROR|WARN)|Method not decompiled|throw new UnsupportedOperationException", text))
                source_rows.append({"path": str(path.relative_to(folder)), "sha256": sha256(path.read_bytes()),
                                    "decompilation_gap": bad})
                if bad:
                    codes.append("jadx_decompilation_gap")
            if not source_rows:
                codes.append("jadx_no_sources")
            jadx = {"state": "partial" if codes else "ok", "reason_codes": sorted(set(codes)),
                    "source_files": source_rows, "returncode": run.returncode,
                    "descriptor_coverage_source": "dex_parser", "semantic_equivalence": "not_proven"}
        reasons.update(jadx["reason_codes"])
    else:
        reasons.add("jadx_not_requested")
    return result("partial" if reasons else "ok", sorted(reasons), header_checks=checks,
                  targets=rows, jadx=jadx, repair_performed=False, method_coverage="explicit_targets_only",
                  all_dex_recovered="unknown", semantic_completeness="not_proven")
