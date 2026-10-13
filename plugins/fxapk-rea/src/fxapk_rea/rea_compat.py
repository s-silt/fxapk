"""Explicit, hash-pinned REA 6.4.0 script-lifetime compatibility repair.

Run ``python -m fxapk_rea.rea_compat --root <rea-agents> --apply``.
No downloads or implicit runtime mutations; unknown installations are refused.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from apkscan.core.atomic import atomic_write_bytes

PATCH_ID = "fxapk-rea-6.4.0-script-lifetime-1"
RELATIVE = "dist/browser/CdpPageCaptureScripts.js"
BEFORE_SHA256 = "f8fd2f45455450ec46319c27be749c1aae9ae605dfd901664483c75f6272cfed"
AFTER_SHA256 = "410967ab384e3425ad67a6dba345a278aea546d108c7af7bb143c2b549620233"
_OLD = '''    const content = requiredScriptSource(await context.connection.send("Debugger.getScriptSource", { scriptId: script.scriptId }, context.sessionId, context.signal), context.operation);
    return sourceResult(content);'''
_NEW = '''    // fxapk compatibility: a destroyed context must not discard other evidence.
    try {
        const content = requiredScriptSource(await context.connection.send("Debugger.getScriptSource", { scriptId: script.scriptId }, context.sessionId, context.signal), context.operation);
        return sourceResult(content);
    }
    catch (cause) {
        if (!(cause instanceof CdpCommandRejection) ||
            cause.command !== "Debugger.getScriptSource" ||
            cause.code !== -32000 ||
            typeof cause.reportedMessage !== "string" ||
            !/^(?:No script for id: .+|Could not find script with given id)$/.test(cause.reportedMessage))
            throw cause;
        state.events.completeness.exclude("script_sources", "provider_unavailable", 1);
        return sourceExcluded("script source unavailable: context or script no longer exists");
    }'''
_IMPORT = 'import { CdpCommandRejection } from "./CdpCommandRejection.js";\n'


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest()


def repair(root: Path, *, apply: bool = False) -> dict[str, object]:
    root = root.resolve(strict=True)
    package = json.loads((root / "package.json").read_text(encoding="utf-8"))
    if package.get("name") != "rea-agents" or package.get("version") != "6.4.0":
        raise ValueError("unsupported REA package")
    target = (root / RELATIVE).resolve(strict=True)
    if not target.is_relative_to(root):
        raise ValueError("REA source escapes package")
    raw = target.read_bytes()
    digest = _sha(raw)
    if digest not in (BEFORE_SHA256, AFTER_SHA256):
        raise ValueError("unrecognized REA source; refusing to overwrite local changes")
    changed = digest == BEFORE_SHA256
    patched = raw
    if changed:
        text = raw.decode("utf-8").replace("\r\n", "\n")
        if text.count(_OLD) != 1:
            raise ValueError("REA source anchor mismatch")
        patched = (_IMPORT + text.replace(_OLD, _NEW)).encode("utf-8")
        if _sha(patched) != AFTER_SHA256:
            raise ValueError("REA patched source checksum mismatch")
        if apply:
            atomic_write_bytes(target, patched)
    return {
        "patch_id": PATCH_ID,
        "upstream_version": "6.4.0",
        "path": RELATIVE,
        "before_sha256": digest,
        "after_sha256": _sha(patched),
        "changed": changed,
        "applied": apply,
    }


def provenance(executable: str | None) -> dict[str, str]:
    """Report actual source identity, never infer patch state from a marker file."""
    if not executable:
        return {"status": "not_detected"}
    root = Path(executable).resolve().parent.parent
    try:
        result = repair(root)
    except (OSError, ValueError):
        return {"status": "not_detected"}
    return {
        "status": "upstream" if result["changed"] else "patched",
        "patch_id": PATCH_ID if not result["changed"] else "",
        "source_sha256": str(result["before_sha256"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    print(json.dumps(repair(args.root, apply=args.apply), indent=2))


if __name__ == "__main__":
    main()
