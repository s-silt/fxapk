"""Bounded reads without reserving an entire maximum-size buffer."""
from __future__ import annotations

from typing import BinaryIO


def read_limited(stream: BinaryIO, max_bytes: int) -> bytes:
    """Read at most limit+1 bytes in 64 KiB chunks for the caller's size check.

    The extra byte distinguishes an exact-size file from an oversized or growing
    file. A small input never incurs a 128/256 MiB speculative read allocation.
    """
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        raise ValueError("invalid_read_limit")
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    while remaining:
        part = stream.read(min(65536, remaining))
        if not part:
            break
        if len(part) > remaining:
            raise ValueError("reader_exceeded_requested_limit")
        chunks.append(part)
        remaining -= len(part)
    return b"".join(chunks)
