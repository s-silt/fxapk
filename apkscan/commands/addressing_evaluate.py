"""Read-only evaluation of explicitly selected local evidence bundles."""
from pathlib import Path
import json
from typing import Annotated

import typer

from apkscan.config.evaluation import evaluate_real_suite
from apkscan.core.atomic import atomic_create_bytes
from apkscan.core.json_io import load_json_file


def addressing_evaluate(
    manifest: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    out: Annotated[Path, typer.Option("--out")],
) -> None:
    """离线复核原 APK/报告/运行时材料哈希；独立标签缺失保持 unknown。"""
    try:
        data = load_json_file(manifest, limit=1024 * 1024)
        if not isinstance(data, dict) or data.get("schema") != "fxapk-addressing-evaluation-1" or not isinstance(data.get("cases"), list):
            raise ValueError("invalid_evaluation_manifest")
        result = evaluate_real_suite(data["cases"])
        if not atomic_create_bytes(out, json.dumps(result, sort_keys=True, ensure_ascii=False, indent=2).encode()):
            raise ValueError("evaluation_output_exists")
        typer.echo(json.dumps({"report": str(out), "cases": result["real_case_count"],
                               "independently_labeled": result["independently_labeled_case_count"]}))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        typer.echo(f"addressing-evaluate failed: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(code=2) from exc
