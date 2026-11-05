"""Bounded AArch64 function execution; no host syscalls or implicit import stubs."""
from __future__ import annotations

import json

from .common import hex_bytes, integer, result, sha256
from .native import review as elf_review


def review(data: bytes, options: dict) -> dict:
    import unicorn as uc
    from unicorn import arm64_const as reg

    vectors = options.get("vectors")
    if not isinstance(vectors, list) or not 1 <= len(vectors) <= 16:
        raise ValueError("emulation_vectors_required")
    budget = integer(options.get("instruction_limit", 100000), 1, 1000000)
    timeout = integer(options.get("timeout_ms", 1000), 1, 5000)
    base = integer(options.get("base", 0x100000), 4096, 2**48 - 1)
    entry = integer(options.get("entry"), 0, 2**48 - 1)
    segments = []
    if options.get("format") == "raw_aarch64":
        if not data or len(data) % 4 or base % 4096:
            raise ValueError("emulation_code_alignment")
        segments = [{"elf_va": 0, "file_offset": 0, "file_size": len(data),
                     "memory_size": len(data), "flags": 5}]
    elif options.get("format") == "elf":
        info = elf_review(data, {"query": "info"})
        if info["state"] != "ok" or info["machine"] != "EM_AARCH64" or not info["little_endian"]:
            return result("unsupported", ["emulation_requires_aarch64_le"])
        # Dynamic relocations/TLS are not silently treated as zeros or valid pointers.
        import io
        from elftools.elf.elffile import ELFFile
        elf = ELFFile(io.BytesIO(data))
        if any(s["p_type"] in {"PT_DYNAMIC", "PT_TLS"} for s in elf.iter_segments()):
            return result("unsupported", ["dynamic_linker_or_tls_required"])
        segments = info["segments"]
    else:
        raise ValueError("explicit_emulation_format_required")
    if entry % 4 or not any(s["flags"] & 1 and s["elf_va"] <= entry < s["elf_va"] + s["file_size"] for s in segments):
        raise ValueError("entry_not_file_backed_executable")
    mapped_size = sum((s["memory_size"] + 8191) // 4096 * 4096 for s in segments)
    if mapped_size > 32 * 1024**2:
        raise ValueError("emulation_memory_budget")
    stack, arena, sentinel = 0x7000000000, 0x7100000000, 0x7200000000
    rows = []
    stubs = options.get("stubs", [])
    if not isinstance(stubs, list) or len(stubs) > 32:
        raise ValueError("emulation_stub_budget")
    stub_map = {}
    for stub in stubs:
        if not isinstance(stub, dict) or not isinstance(stub.get("reason"), str) or not stub["reason"].strip():
            raise ValueError("explicit_stub_reason_required")
        address = base + integer(stub.get("address"))
        if address in stub_map:
            raise ValueError("duplicate_stub_address")
        stub_map[address] = integer(stub.get("return_value"))
    for index, vector in enumerate(vectors):
        machine = uc.Uc(uc.UC_ARCH_ARM64, uc.UC_MODE_ARM)  # pyright: ignore[reportPrivateImportUsage]
        pages: dict[int, int] = {}
        for segment in segments:
            start = base + segment["elf_va"]
            end = start + segment["memory_size"]
            if end > 2**48 or any(start < fixed + 1024**2 and end > fixed for fixed in (stack, arena, sentinel)):
                raise ValueError("emulation_mapping_overlap")
            for page in range(start & ~4095, (end + 4095) & ~4095, 4096):
                if page in pages:
                    raise ValueError("emulation_mapping_overlap")
                pages[page] = segment["flags"]
                machine.mem_map(page, 4096)
            machine.mem_write(start, data[segment["file_offset"]:segment["file_offset"] + segment["file_size"]])
        for page, flags in pages.items():
            machine.mem_protect(page, 4096, ((uc.UC_PROT_READ if flags & 4 else 0)
                                          | (uc.UC_PROT_WRITE if flags & 2 else 0)
                                          | (uc.UC_PROT_EXEC if flags & 1 else 0)))
        machine.mem_map(stack, 0x10000, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
        machine.mem_map(arena, 0x100000, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
        machine.mem_map(sentinel, 4096, uc.UC_PROT_READ | uc.UC_PROT_EXEC)
        machine.reg_write(reg.UC_ARM64_REG_SP, stack + 0xfff0)
        machine.reg_write(reg.UC_ARM64_REG_LR, sentinel)
        args = vector.get("args", [])
        if not isinstance(args, list) or len(args) > 8:
            raise ValueError("emulation_argument_budget")
        output_buffers = []
        offset = 0
        for number, arg in enumerate(args):
            if isinstance(arg, dict):
                initial = hex_bytes(arg.get("hex", ""), 65536)
                size = integer(arg.get("size", len(initial)), max(1, len(initial)), 65536)
                pointer = arena + offset
                offset += (size + 15) & ~15
                machine.mem_write(pointer, initial)
                if "expected_hex" in arg:
                    expected = hex_bytes(arg["expected_hex"], size)
                    if len(expected) != size:
                        raise ValueError("emulation_expected_buffer_size")
                    output_buffers.append((pointer, expected))
                value = pointer
            else:
                value = integer(arg)
            machine.reg_write(getattr(reg, f"UC_ARM64_REG_X{number}"), value)
        expected_return = integer(vector["expected_return"]) if "expected_return" in vector else None
        if expected_return is None and not output_buffers:
            raise ValueError("emulation_expected_output_required")
        counts = {"instructions": 0, "stub_calls": 0}
        reason = []

        def hook(engine, address, size, user):
            counts["instructions"] += 1
            instruction = bytes(engine.mem_read(address, 4))
            word = int.from_bytes(instruction, "little")
            if word & 0xff000000 == 0xd4000000:
                reason.append("system_instruction_unsupported")
                engine.emu_stop()
            if address in stub_map:
                counts["stub_calls"] += 1
                engine.reg_write(reg.UC_ARM64_REG_X0, stub_map[address])
                engine.reg_write(reg.UC_ARM64_REG_PC, engine.reg_read(reg.UC_ARM64_REG_LR))

        machine.hook_add(uc.UC_HOOK_CODE, hook)
        try:
            machine.emu_start(base + entry, sentinel, timeout=timeout * 1000, count=budget)
        except uc.UcError as error:  # pyright: ignore[reportPrivateImportUsage]
            reason.append("emulation_fault")
            fault = error.errno
        else:
            fault = None
        returned = machine.reg_read(reg.UC_ARM64_REG_PC) == sentinel
        if not returned and not reason:
            reason.append("emulation_budget_exhausted")
        actual_return = machine.reg_read(reg.UC_ARM64_REG_X0)
        matches = [(expected_return == actual_return)] if expected_return is not None else []
        buffers = []
        for pointer, expected in output_buffers:
            actual = bytes(machine.mem_read(pointer, len(expected)))
            matches.append(actual == expected)
            buffers.append({"size": len(actual), "sha256": sha256(actual), "matches": actual == expected})
        if returned and not all(matches):
            reason.append("emulation_output_mismatch")
        rows.append({"index": index, "returned": returned, "output_matches": all(matches),
                     "reason_codes": reason, "fault_code": fault, **counts, "outputs": buffers})
    reasons = sorted({code for row in rows for code in row["reason_codes"]})
    if stubs:
        reasons.append("declared_stubs_limit_equivalence")
    if len(vectors) < 2:
        reasons.append("single_vector_only")
    elif len({json.dumps(v.get("args", []), sort_keys=True) for v in vectors}) < 2:
        reasons.append("distinct_validation_inputs_required")
    failed = any(row["reason_codes"] for row in rows)
    return result("failed" if failed else "partial" if reasons else "ok", reasons,
                  vectors=rows, emulation_executed=True, independent_algorithm=False,
                  abi="aapcs64", instruction_limit=budget, timeout_ms=timeout,
                  stub_count=len(stubs), memory_limit_bytes=32 * 1024**2,
                  source_equivalence="not_proven", network_access="not_implemented")
