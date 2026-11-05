"""Owned-process boundary for native execution and recovered-code parsers."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from .common import json_value, read_bytes, result


def main() -> None:
    source, config, destination = map(Path, sys.argv[1:4])
    try:
        from loguru import logger
        logger.disable("androguard")
        task = json_value(read_bytes(config, 1024**2))
        from .runner import REVIEWERS
        review = REVIEWERS[task["kind"]]
        detail = review(read_bytes(source), task)
    except ImportError:
        detail = result("unsupported", ["optional_dependency_unavailable"])
    except Exception as error:
        code = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]{1,80}", str(error)) else "review_worker_failed"
        detail = result("failed", [code], exception_type=type(error).__name__)
    destination.write_text(json.dumps(detail, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()
