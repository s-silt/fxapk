"""Validate and project an accepted fixed JADX receipt for the hosted job."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re

from tools.fixed_jadx_gate import NODES, VERSION


_MAX_RECEIPT_BYTES = 16 * 1024
# Independently pin v3's ordered IDs; an intentional contract change needs a version review.
_V3_NODES_SHA256 = "ebd41e5a20df61c77fb940b142fc11cc6934a77f0ca4e983b248a22fa38259ab"


def _nodes_fingerprint(nodes: tuple[str, ...]) -> str:
    encoded = json.dumps(nodes, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return sha256(encoded).hexdigest()


def _canonical_receipt(head: str, tree: str) -> dict[str, object]:
    return {
        "version": VERSION,
        "base_head": head,
        "index_tree": tree,
        "cases": list(NODES),
        "pytest_exit": 0,
        "accepted": True,
        "problems": [],
    }


def accepts_receipt(raw: object, head: str, tree: str) -> bool:
    return (
        VERSION == "jadx-report-v3"
        and len(NODES) == len(set(NODES)) == 19
        and _nodes_fingerprint(NODES) == _V3_NODES_SHA256
        and re.fullmatch(r"[0-9a-f]{40}", head) is not None
        and re.fullmatch(r"[0-9a-f]{40}", tree) is not None
        and isinstance(raw, dict)
        and raw.get("accepted") is True
        and type(raw.get("pytest_exit")) is int
        and raw == _canonical_receipt(head, tree)
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    fields: dict[str, object] = {}
    for name, value in pairs:
        if name in fields:
            raise ValueError("duplicate receipt field")
        fields[name] = value
    return fields


def _read_receipt(path: Path) -> object:
    with path.open("rb") as receipt:
        raw = receipt.read(_MAX_RECEIPT_BYTES + 1)
    if len(raw) > _MAX_RECEIPT_BYTES:
        raise ValueError("oversized receipt")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("head")
    parser.add_argument("tree")
    args = parser.parse_args()
    try:
        raw = _read_receipt(args.receipt)
    except (OSError, ValueError, RecursionError):
        raw = None
    if not accepts_receipt(raw, args.head, args.tree):
        parser.exit(1, "fixed JADX: receipt validation failed\n")
    # Write only known values; never print bytes or fields supplied by the gate.
    print(json.dumps(_canonical_receipt(args.head, args.tree), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
