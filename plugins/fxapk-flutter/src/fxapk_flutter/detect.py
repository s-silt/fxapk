"""Offline snapshot/engine inspection; never use upstream network fallback."""

from __future__ import annotations

import io
from pathlib import Path
import re

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from .evidence import FlutterError, read


def address_offset(elf: ELFFile, address: int, length: int = 4) -> int:
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        start, size = segment["p_vaddr"], segment["p_filesz"]
        if start <= address and address + length <= start + size:
            return segment["p_offset"] + address - start
    raise FlutterError("address_not_file_backed")


def inspect_pair(app: Path, engine: Path) -> dict:
    try:
        raw = read(app)
        elf = ELFFile(io.BytesIO(raw))
        engine_elf = ELFFile(io.BytesIO(read(engine)))
        for obj in (elf, engine_elf):
            if obj.header["e_machine"] != "EM_AARCH64" or not obj.little_endian or obj.elfclass != 64:
                raise FlutterError("unsupported_abi")
        symbols = elf.get_section_by_name(".dynsym")
        matches = symbols.get_symbol_by_name("_kDartVmSnapshotData") if isinstance(symbols, SymbolTableSection) else None
        if not matches or len(matches) != 1:
            raise FlutterError("snapshot_symbol_missing")
        symbol = matches[0]
        offset = address_offset(elf, symbol["st_value"], 52)
        snapshot = raw[offset + 20:offset + 52].decode("ascii")
        if not re.fullmatch(r"[0-9a-f]{32}", snapshot):
            raise FlutterError("invalid_snapshot")
        flags_raw = raw[offset + 52:offset + min(symbol["st_size"], 1024)]
        if b"\0" not in flags_raw:
            raise FlutterError("snapshot_flags_missing")
        flags = flags_raw.split(b"\0", 1)[0].decode("ascii").split()
        rodata = engine_elf.get_section_by_name(".rodata")
        if rodata is None:
            raise FlutterError("engine_version_unknown")
        versions = set(re.findall(rb"\x00([\d\w.\-]{1,64}) \((?:stable|beta|dev)\)", rodata.data()))
        if len(versions) != 1:
            raise FlutterError("engine_version_unknown")
        return {"dart_version": next(iter(versions)).decode("ascii"), "snapshot": snapshot,
                "abi": "android_arm64", "compressed_pointers": "compressed-pointers" in flags,
                "snapshot_flags": sorted(flags)}
    except FlutterError:
        raise
    except Exception as exc:
        raise FlutterError("invalid_flutter_elf") from exc
