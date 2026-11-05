"""Targeted ELF queries. Static candidates never imply execution or complete xrefs."""
from __future__ import annotations

import io
import re
import struct

from .common import integer, result


def review(data: bytes, options: dict) -> dict:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] not in {1, 2} or data[5] not in {1, 2}:
        raise ValueError("invalid_elf_header")
    endian = "<" if data[5] == 1 else ">"
    bits = 64 if data[4] == 2 else 32
    header = struct.unpack_from(endian + ("HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH"), data, 16)
    phoff, shoff, phsize, phnum, shsize, shnum = header[4], header[5], header[8], header[9], header[10], header[11]
    if phnum == 65535 or (shoff and shnum == 0) or phnum > 4096 or shnum > 4096:
        return result("unsupported", ["extended_or_excessive_elf_tables"])
    if (phnum and phsize != (56 if bits == 64 else 32)) or (shnum and shsize != (64 if bits == 64 else 40)):
        raise ValueError("invalid_elf_table_entry_size")
    if phoff + phsize * phnum > len(data) or shoff + shsize * shnum > len(data):
        raise ValueError("elf_table_outside_file")
    for index in range(shnum):
        section_header = struct.unpack_from(endian + ("IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII"), data, shoff + index * shsize)
        if section_header[2] & 0x800:
            return result("unsupported", ["compressed_elf_sections"])
        if section_header[1] != 8 and section_header[4] + section_header[5] > len(data):
            raise ValueError("elf_section_outside_file")
    elf = ELFFile(io.BytesIO(data))
    segments = []
    for seg in elf.iter_segments():
        if seg["p_type"] != "PT_LOAD":
            continue
        offset, address, filesz, memsz = (int(seg[key]) for key in ("p_offset", "p_vaddr", "p_filesz", "p_memsz"))
        if filesz > memsz or offset + filesz > len(data) or address + memsz > 2**bits:
            raise ValueError("invalid_load_segment")
        segments.append({"file_offset": offset, "elf_va": address, "file_size": filesz,
                         "memory_size": memsz, "flags": int(seg["p_flags"])})

    def mapped(value: int, kind: str) -> list[dict]:
        output = []
        for seg in segments:
            source = "file_offset" if kind == "file" else "elf_va"
            length = seg["file_size"] if kind == "file" else seg["memory_size"]
            delta = value - seg[source]
            if 0 <= delta < length:
                output.append({"elf_va": seg["elf_va"] + delta,
                               "file_offset": seg["file_offset"] + delta if delta < seg["file_size"] else None,
                               "file_backed": delta < seg["file_size"]})
        return output

    common = {"machine": elf["e_machine"], "bits": bits, "little_endian": elf.little_endian,
              "coverage": "static_file_only", "dynamic_jni_registration": "not_resolved",
              "runtime_base": "not_observed"}
    query = options.get("query", "info")
    limit = integer(options.get("limit", 200), 1, 1000)
    if query == "info":
        return result(**common, segments=segments, entry=int(elf["e_entry"]))
    if query == "map":
        kind = options.get("address_kind")
        if kind not in {"file", "elf_va"}:
            raise ValueError("explicit_address_kind_required")
        matches = mapped(integer(options.get("address")), kind)
        return result("ok" if len(matches) == 1 else "partial",
                      [] if len(matches) == 1 else ["unmapped_or_ambiguous_address"], **common, mappings=matches)
    matches: list[dict] = []
    truncated = False
    if query == "strings":
        needle = options.get("needle")
        if not isinstance(needle, str) or not 1 <= len(needle) <= 256 or not needle.isascii():
            raise ValueError("bounded_ascii_needle_required")
        for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
            if needle.encode("ascii") in match.group():
                if len(matches) >= limit:
                    truncated = True
                    break
                matches.append({"file_offset": match.start(), "mappings": mapped(match.start(), "file"),
                                "text": match.group()[:1024].decode("ascii"),
                                "text_truncated": len(match.group()) > 1024})
    elif query in {"symbols", "jni"}:
        inspected = 0
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            if int(section["sh_offset"]) + int(section["sh_size"]) > len(data):
                raise ValueError("symbol_table_outside_file")
            for symbol in section.iter_symbols():
                inspected += 1
                if inspected > 100_000:
                    truncated = True
                    break
                if query == "jni" and not symbol.name.startswith(("Java_", "JNI_OnLoad")):
                    continue
                if len(matches) >= limit:
                    truncated = True
                    break
                matches.append({"name": symbol.name[:1024], "name_truncated": len(symbol.name) > 1024,
                                "elf_va": int(symbol["st_value"]), "size": int(symbol["st_size"]),
                                "defined": symbol["st_shndx"] != "SHN_UNDEF"})
            if truncated:
                break
    elif query in {"disasm", "callers", "strrefs"}:
        if elf["e_machine"] != "EM_AARCH64" or not elf.little_endian:
            return result("unsupported", ["disassembly_requires_aarch64_little_endian"], **common)
        import capstone

        address = integer(options.get("address"))  # ELF VA, never a guessed runtime address
        window = integer(options.get("size", 256), 4, 4 * 1024 * 1024)
        if address % 4 or window % 4:
            raise ValueError("instruction_window_alignment")
        candidates = [seg for seg in segments if seg["flags"] & 1
                      and seg["elf_va"] <= address and address + window <= seg["elf_va"] + seg["file_size"]]
        if len(candidates) != 1:
            raise ValueError("instruction_window_not_uniquely_file_backed")
        segment = candidates[0]
        offset = segment["file_offset"] + address - segment["elf_va"]
        decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        decoder.detail = True
        target = integer(options.get("target")) if query != "disasm" else None
        decoded = invalid = 0
        prior = None
        # Decode fixed-width instructions independently so an invalid word does not hide the tail.
        for position in range(0, window, 4):
            instructions = list(decoder.disasm(data[offset + position:offset + position + 4], address + position))
            if not instructions:
                invalid += 1
                prior = None
                continue
            ins = instructions[0]
            decoded += 1
            operands = ins.operands
            found = query == "disasm"
            basis = "instruction"
            if query == "callers":
                found = ins.mnemonic == "bl" and operands and operands[0].type == capstone.arm64.ARM64_OP_IMM and operands[0].imm == target
                basis = "direct_bl_only"
            elif query == "strrefs":
                found = ins.mnemonic == "adr" and len(operands) == 2 and operands[1].imm == target
                basis = "adr_literal_candidate"
                if prior is not None and ins.mnemonic == "add" and len(operands) == 3 and operands[2].type == capstone.arm64.ARM64_OP_IMM:
                    previous_ops = prior.operands
                    if (prior.mnemonic == "adrp" and len(previous_ops) == 2
                            and operands[1].reg == previous_ops[0].reg and operands[2].shift.value == 0):
                        found = previous_ops[1].imm + operands[2].imm == target
                        basis = "adjacent_adrp_add_candidate"
            if found:
                if len(matches) >= limit:
                    truncated = True
                    break
                matches.append({"elf_va": ins.address, "mnemonic": ins.mnemonic,
                                "operands": ins.op_str, "basis": basis})
            prior = ins
        common.update(requested_bytes=window, decoded_bytes=decoded * 4, invalid_instruction_words=invalid,
                      indirect_references="not_resolved")
        if invalid:
            common["decode_gap"] = True
    else:
        return result("unsupported", ["native_query_unsupported"], **common)
    reasons = ["result_or_scan_budget"] if truncated else []
    if common.get("decode_gap"):
        reasons.append("invalid_instruction_words")
    return result("partial" if reasons else "ok", reasons, **common, matches=matches,
                  result_count=len(matches), search_result="hit" if matches else "no_hit_in_checked_scope")
