"""Owned trace subprocess. The parent kills this process at the capture deadline.

It does not launch or close a browser. Ready is written by the trace provider.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def _load(path: str) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("config_rejected")
    return payload


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2 or args[0] != "--request":
        return 2
    try:
        request = _load(args[1])
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return 2
    if request.get("authorized") is not True or request.get("source") != "cdp":
        return 2
    provider = request.get("provider") or "trace"
    if provider not in {"trace", "fxapk-cdp-trace"}:
        return 2
    endpoint = request.get("endpoint")
    target = request.get("target")
    origins = request.get("exact_origins")
    observation_ms = request.get("observation_ms")
    out = request.get("out_dir")
    if (
        not isinstance(endpoint, str) or not isinstance(target, str)
        or not isinstance(origins, list) or not origins
        or not isinstance(out, str) or not out
        or isinstance(observation_ms, bool) or not isinstance(observation_ms, int)
    ):
        return 2
    clean: list[str] = []
    for item in origins:
        if not isinstance(item, str) or not item:
            return 2
        clean.append(item)
    if len(clean) > 9:
        return 2
    if any(key in request for key in ("navigate", "click_selector", "pause_related_start")):
        return 2
    related_targets: bool | None = None
    if "related_targets" in request:
        flag = request.get("related_targets")
        if not isinstance(flag, bool):
            return 2
        related_targets = flag
    from .supplement import _invoke_trace

    if related_targets is None:
        _invoke_trace(endpoint, target, clean, observation_ms, Path(out))
    else:
        _invoke_trace(
            endpoint, target, clean, observation_ms, Path(out),
            related_targets=related_targets,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        raise SystemExit(1) from None
