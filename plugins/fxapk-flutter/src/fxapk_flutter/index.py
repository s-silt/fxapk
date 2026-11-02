"""Deterministic SQLite index of Blutter text and raw-verified ARM64 BL edges."""

from __future__ import annotations

import io
from pathlib import Path
import re
import sqlite3
import struct
from urllib.parse import urlsplit

from elftools.elf.elffile import ELFFile

from .detect import address_offset
from .evidence import FlutterError, read

INDEX_VERSION = "4"
_ADDR = re.compile(r"^\s*// \*\* addr: (0x[0-9a-f]+), size: (0x[0-9a-f]+)\s*$")
_LINE = re.compile(r"^\s*//\s+(0x[0-9a-f]+):")
_BL = re.compile(r"^\s*//\s+(0x[0-9a-f]+):\s+bl\s+#(0x[0-9a-f]+)(?:\s|$)")
_INDIRECT = re.compile(r"^\s*//\s+0x[0-9a-f]+:\s+blr\b")
_STRING = re.compile(r'(?:String: |r\d+ = )("(?:[^"\\]|\\.)*")')


def decode_string(quoted: str) -> str:
    """Invert Blutter Util::UnescapeWithQuote, including C-style escaped '?'."""
    escapes = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v",
               "\\": "\\", "'": "'", '"': '"', "?": "?"}
    if not quoted.startswith('"') or not quoted.endswith('"'):
        raise FlutterError("unsupported_string_format")
    result = []
    value = quoted[1:-1]
    pos = 0
    while pos < len(value):
        char = value[pos]
        if char == "\\":
            pos += 1
            if pos == len(value) or value[pos] not in escapes:
                raise FlutterError("unsupported_string_escape")
            char = escapes[value[pos]]
        result.append(char)
        pos += 1
    return "".join(result)


def verified_bl(raw: bytes, elf: ELFFile, site: int, target: int) -> bool:
    try:
        word = struct.unpack_from("<I", raw, address_offset(elf, site))[0]
    except (FlutterError, struct.error):
        return False
    if word & 0xFC000000 != 0x94000000:
        return False
    immediate = word & 0x3FFFFFF
    if immediate & 0x2000000:
        immediate -= 0x4000000
    return site + immediate * 4 == target


def connect(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)


def build(root: Path) -> dict:
    asm = root / "raw/asm"
    if not asm.is_dir() or not (root / "raw/pp.txt").is_file() or not (root / "raw/objs.txt").is_file():
        raise FlutterError("required_output_missing")
    raw = read(root / "input/libapp.so")
    elf = ELFFile(io.BytesIO(raw))
    db = sqlite3.connect(root / "index.sqlite3")
    db.executescript("""
        CREATE TABLE functions(address INTEGER PRIMARY KEY, symbol TEXT, source TEXT, size INTEGER, line INTEGER);
        CREATE TABLE calls(caller INTEGER, site INTEGER, target INTEGER, verified INTEGER, source TEXT, line INTEGER);
        CREATE TABLE strings(function INTEGER, address INTEGER, value TEXT, source TEXT, line INTEGER, kind TEXT);
        CREATE INDEX call_target ON calls(target);
        CREATE INDEX call_caller ON calls(caller);
        CREATE INDEX string_function ON strings(function);
    """)
    functions = calls = indirect = strings = mismatches = decode_failures = oversized_strings = 0
    sources = []
    try:
        for path in sorted(asm.rglob("*.dart")):
            relative = path.relative_to(root).as_posix()
            text = read(path).decode("utf-8", errors="strict")
            lines = text.splitlines()
            if not lines or not lines[0].startswith("// lib:"):
                raise FlutterError("unsupported_assembly_format")
            sources.append(lines[0].split("url:", 1)[-1].strip())
            cls = ""
            signature = ""
            current = None
            current_address = None
            current_end = None
            for number, line in enumerate(lines, 1):
                if line.strip() == "}":
                    current = current_end = current_address = None
                class_match = re.match(r"^(?:(?:abstract|final|base|sealed|interface) )*class (\S+)", line)
                if class_match:
                    cls = class_match[1]
                if re.match(r"^  \S.*\{$", line):
                    signature = line.strip().rsplit("{", 1)[0].strip()
                match = _ADDR.search(line)
                if match:
                    current = int(match[1], 16)
                    current_end = current + int(match[2], 16)
                    current_address = None
                    # Keep readable constructor/getter/closure signatures, not guessed source code.
                    name_parts = signature.split("(", 1)[0].split()
                    method = name_parts[-1] if name_parts else f"closure@{current:x}"
                    symbol = cls + "." + method
                    db.execute("INSERT INTO functions VALUES(?,?,?,?,?)", (current, symbol, relative, int(match[2], 16), number))
                    functions += 1
                at = _LINE.match(line)
                if at:
                    address = int(at[1], 16)
                    current_address = address if (current is not None and current_end is not None
                                                  and current <= address and address + 4 <= current_end
                                                  and address % 4 == 0) else None
                call = _BL.search(line)
                if call and current is not None:
                    site, target = int(call[1], 16), int(call[2], 16)
                    verified = current_address == site and verified_bl(raw, elf, site, target)
                    db.execute("INSERT INTO calls VALUES(?,?,?,?,?,?)", (current, site, target, int(verified), relative, number))
                    calls += 1
                    mismatches += not verified
                if _INDIRECT.match(line):
                    indirect += 1
                value_match = _STRING.search(line) if at else None
                if value_match:
                    try:
                        value = decode_string(value_match[1])
                    except FlutterError:
                        decode_failures += 1
                        continue
                    if len(value) > 8192:
                        oversized_strings += 1
                        continue
                    kind = "string"
                    if value.startswith(("http://", "https://")) and not re.search(r"[\s\x00-\x1f]", value):
                        try:
                            url = urlsplit(value)
                            if url.hostname and not url.username and not url.password:
                                kind = "url_literal"
                        except ValueError:
                            pass
                    elif value.startswith("/"):
                        kind = "path_literal"
                    if re.match(r"^(?:[A-Za-z]:[\\/]|/(?:Users|home|opt|build|workspace)/)", value):
                        kind = "dependency_path" if any(s in value for s in (".pub-cache", "flutter/packages", "dart-sdk")) else "build_path_candidate"
                    db.execute("INSERT INTO strings VALUES(?,?,?,?,?,?)", (current if current_address is not None else None, current_address, value, relative, number, kind))
                    strings += 1
                if functions > 100000 or strings > 500000 or calls > 2000000:
                    raise FlutterError("index_limit")
        if not functions:
            raise FlutterError("empty_function_index")
        db.commit()
    finally:
        db.close()
    return {"index_version": INDEX_VERSION, "functions": functions, "direct_calls": calls,
            "raw_call_mismatches": mismatches, "unresolved_indirect_calls": indirect, "strings": strings,
            "string_decode_failures": decode_failures, "oversized_strings_omitted": oversized_strings,
            "source_namespaces": sorted(set(sources)), "callgraph_coverage": "direct_calls_only",
            "source_recovery": "annotated_assembly_not_original_dart", "runtime_observed": False}


def query(root: Path, symbol: str | None = None, text: str | None = None, limit: int = 30) -> dict:
    if not 1 <= limit <= 200 or bool(symbol) == bool(text):
        raise FlutterError("query_requires_symbol_or_text")
    with connect(root / "index.sqlite3") as db:
        db.row_factory = sqlite3.Row
        if symbol:
            rows = db.execute("SELECT * FROM functions WHERE instr(symbol,?)>0 ORDER BY address LIMIT ?", (symbol, limit + 1)).fetchall()
            records = []
            for row in rows[:limit]:
                item = dict(row)
                for name, sql in (
                    ("calls", "SELECT c.*,f.symbol AS target_symbol FROM calls c LEFT JOIN functions f ON f.address=c.target WHERE caller=? ORDER BY site LIMIT 201"),
                    ("callers", "SELECT c.*,f.symbol AS caller_symbol FROM calls c LEFT JOIN functions f ON f.address=c.caller WHERE target=? ORDER BY site LIMIT 201"),
                    ("strings", "SELECT * FROM strings WHERE function=? ORDER BY line LIMIT 201"),
                ):
                    found = db.execute(sql, (row["address"],)).fetchall()
                    item[name] = [dict(x) for x in found[:200]]
                    item[name + "_truncated"] = len(found) > 200
                records.append(item)
        else:
            rows = db.execute("SELECT s.*,f.symbol FROM strings s LEFT JOIN functions f ON f.address=s.function WHERE instr(value,?)>0 ORDER BY source,line LIMIT ?", (text, limit + 1)).fetchall()
            records = [dict(x) for x in rows[:limit]]
    return {"matches": records, "truncated": len(rows) > limit, "runtime_observed": False}


def url_candidates(root: Path) -> list[dict]:
    with connect(root / "index.sqlite3") as db:
        db.row_factory = sqlite3.Row
        rows = db.execute("SELECT * FROM strings WHERE kind='url_literal' ORDER BY value,source,line").fetchall()
    # No path/base concatenation; a literal never establishes business use or transmission.
    return [dict(row) for row in rows]
