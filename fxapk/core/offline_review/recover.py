"""Evidence-backed AArch64 field and function-name candidates, never original names."""
from __future__ import annotations

from .common import integer, result
from .native import review as native_review


def review(data: bytes, options: dict) -> dict:
    import capstone
    from capstone.arm64 import ARM64_OP_MEM, ARM64_OP_REG, ARM64_OP_IMM

    info = native_review(data, {"query": "info"})
    if info["state"] != "ok" or info.get("machine") != "EM_AARCH64" or not info.get("little_endian"):
        return result("unsupported", ["recovery_requires_aarch64_le"])
    functions = options.get("functions")
    if not isinstance(functions, list) or not 1 <= len(functions) <= 32:
        raise ValueError("recovery_function_windows_required")
    symbols = native_review(data, {"query": "symbols", "limit": 1000})
    names = {row["elf_va"]: row["name"] for row in symbols.get("matches", []) if row.get("defined") and row.get("name")}
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    fields, suggestions, reasons = {}, [], set()
    if symbols["state"] != "ok":
        reasons.update(symbols.get("reason_codes", ["symbol_coverage_incomplete"]))
    for function in functions:
        address = integer(function.get("address"))
        size = integer(function.get("size"), 4, 16384)
        argument = integer(function.get("object_argument", 0), 0, 7)
        candidates = [s for s in info["segments"] if s["flags"] & 1 and s["elf_va"] <= address and address + size <= s["elf_va"] + s["file_size"]]
        if len(candidates) != 1 or address % 4 or size % 4:
            raise ValueError("recovery_window_unmapped")
        segment = candidates[0]
        offset = segment["file_offset"] + address - segment["elf_va"]
        code = data[offset:offset + size]
        aliases = {f"x{argument}": 0}
        decoded, callees = 0, []
        for ins in decoder.disasm(code, address):
            decoded += ins.size
            operands = ins.operands
            for op in operands:
                if op.type != ARM64_OP_MEM:
                    continue
                base = ins.reg_name(op.mem.base)
                if base not in aliases or op.mem.index:
                    continue
                field_offset = aliases[base] + op.mem.disp
                if not 0 <= field_offset <= 65536:
                    continue
                first = (ins.reg_name(operands[0].reg) or "") if operands[0].type == ARM64_OP_REG else ""
                width = 1 if ins.mnemonic.endswith("b") else 2 if ins.mnemonic.endswith("h") else 8 if first.startswith("x") else 4 if first.startswith("w") else None
                if width is None or ins.mnemonic not in {"ldr", "str", "ldrb", "strb", "ldrh", "strh", "ldur", "stur"}:
                    reasons.add("unsupported_field_access")
                    continue
                key = (field_offset, width)
                fields.setdefault(key, []).append({"function": address, "instruction": ins.address,
                                                   "access": "read" if ins.mnemonic.startswith("ld") else "write",
                                                   "object_argument": argument})
            new_alias = None
            if ins.mnemonic == "mov" and len(operands) == 2 and all(o.type == ARM64_OP_REG for o in operands):
                source = ins.reg_name(operands[1].reg)
                if source in aliases:
                    new_alias = (ins.reg_name(operands[0].reg) or "", aliases[source])
            if ins.mnemonic == "add" and len(operands) == 3 and operands[1].type == ARM64_OP_REG and operands[2].type == ARM64_OP_IMM:
                source = ins.reg_name(operands[1].reg)
                if source in aliases:
                    new_alias = (ins.reg_name(operands[0].reg) or "", aliases[source] + operands[2].imm)
            _, written = ins.regs_access()
            for register in written:
                name = ins.reg_name(register) or ""
                aliases.pop("x" + name[1:] if name.startswith("w") else name, None)
            if new_alias:
                aliases[new_alias[0]] = new_alias[1]
            if ins.mnemonic == "bl" and operands[0].type == ARM64_OP_IMM:
                target = operands[0].imm
                callees.append({"callsite": ins.address, "target": target, "symbol": names.get(target)})
            # Do not carry speculative register provenance across control flow or calls.
            if ins.mnemonic.startswith(("b", "ret", "cb", "tb")):
                aliases.clear()
        if decoded != len(code):
            reasons.add("recovery_decode_gap")
        suggestion = names.get(address)
        named_calls = [c["symbol"] for c in callees if c["symbol"]]
        suggestions.append({"address": address, "existing_name": suggestion,
                            "candidate_name": suggestion or ("calls_" + named_calls[0] if named_calls else f"sub_{address:x}"),
                            "basis": "symbol_table" if suggestion else "direct_callee" if named_calls else "address_only",
                            "confidence": "observed_symbol" if suggestion else "low", "callees": callees})
    field_rows = [{"offset": offset, "width": width, "type_candidate": f"uint{width * 8}_t",
                   "evidence": evidence, "distinct_functions": len({e["function"] for e in evidence})}
                  for (offset, width), evidence in sorted(fields.items())]
    reasons.add("recovered_names_and_types_are_candidates")
    return result("partial", sorted(reasons), symbols=suggestions, fields=field_rows,
                  minimum_observed_extent=max((f["offset"] + f["width"] for f in field_rows), default=0),
                  structure_size="unknown", original_names_recovered=False,
                  object_identity_across_functions="caller_supplied_hypothesis",
                  coverage="explicit_function_windows")
