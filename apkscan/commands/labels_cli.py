"""只读的识别标签校验命令。"""

from __future__ import annotations

from pathlib import Path

import typer

from apkscan.core import recognition_labels as rlabels

labels_app = typer.Typer(
    help="只读校验识别标签文件，不联网、不启动子进程且不写入文件。",
    no_args_is_help=True,
)


def _print_counts(
    name: str,
    counts: tuple[tuple[str, int], ...],
) -> None:
    """按稳定的字典序输出一组计数。"""
    for key, count in sorted(counts, key=lambda item: item[0]):
        typer.echo(f"{name} {key}={count}")


@labels_app.command("validate")
def validate(
    labels: Path = typer.Option(
        ...,
        "--labels",
        help="待校验的识别标签 JSONL 文件路径。",
    ),
) -> None:
    """只读校验识别标签文件并输出 kind/status/layer 计数摘要。"""
    try:
        label_set = rlabels.load_recognition_labels(labels)
    except rlabels.RecognitionLabelValidationError as exc:
        typer.echo(f"error: {exc.code} at line {exc.line}", err=True)
        raise typer.Exit(code=2) from None
    except Exception:
        # 文件级错误（缺失/权限/解码）统一稳定形式：行号约定 0=文件级，
        # 绝不回显路径或异常文本（codex 复审 P1）。
        typer.echo("error: labels_unreadable at line 0", err=True)
        raise typer.Exit(code=2) from None

    _print_counts("kind", label_set.kind_counts)
    _print_counts("status", label_set.status_counts)
    _print_counts("layer", label_set.layer_counts)
    typer.echo(f"total {label_set.record_count}")
