"""CLI entry points for deterministic case closure."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Mapping

import typer

from apkscan.core.closure import ClosureConfig, close_report
from apkscan.core.models import ANALYSIS_MODE_PASSIVE, ANALYSIS_MODES
from apkscan.core.report_io import load_report, write_report

logger = logging.getLogger(__name__)

case_app = typer.Typer(
    add_completion=False,
    help="案件闭环：运行时端点再富化、多源覆盖、五层归因和严格验收。",
)


def closure_exit_code(status: object) -> int:
    """Map closure status to the stable strict-mode CLI contract."""
    if status == "complete":
        return 0
    if status == "partial":
        return 5
    return 6


def _execution_failure_exit_code(*, strict: bool) -> int:
    return closure_exit_code("failed") if strict else 1


def _strings(value: object) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


def _print_closure_summary(closure: Mapping[str, object]) -> None:
    targets = closure.get("targets")
    target_count = len(targets) if isinstance(targets, list) else 0
    typer.echo(f"闭环状态：{closure.get('status', 'failed')}")
    typer.echo(f"主目标：{target_count}")
    gaps = _strings(closure.get("gaps"))
    if gaps:
        typer.echo("未闭环项：")
        for gap in gaps:
            typer.echo(f"  - {gap}")
    actions = _strings(closure.get("next_actions"))
    if actions:
        typer.echo("下一步：")
        for action in actions:
            typer.echo(f"  - {action}")


@case_app.command("close")
def close_command(
    report_json: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="要闭环的 fxapk report.json。",
    ),
    online: bool = typer.Option(True, "--online/--offline", help="是否执行被动联网富化。"),
    mode: str = typer.Option(
        ANALYSIS_MODE_PASSIVE,
        "--mode",
        help=f"联网模式：{' | '.join(ANALYSIS_MODES)}。",
    ),
    max_targets: int = typer.Option(6, "--max-targets", min=1, max=50, help="最多闭环主目标数。"),
    strict: bool = typer.Option(True, "--strict/--no-strict", help="未闭环时返回非零退出码。"),
    refresh: bool = typer.Option(False, "--refresh", help="忽略成功来源状态，重新执行联网查询。"),
) -> None:
    """Close an existing report in place and refresh a sibling HTML report when present."""
    try:
        report = load_report(report_json)
    except (OSError, ValueError, UnicodeError) as exc:
        typer.echo(f"错误：报告读取失败：{report_json}（{type(exc).__name__}）", err=True)
        raise typer.Exit(code=_execution_failure_exit_code(strict=strict)) from exc

    try:
        config = ClosureConfig(
            online=online,
            mode=mode,
            max_targets=max_targets,
            refresh=refresh,
        )
    except ValueError as exc:
        typer.echo(f"错误：闭环参数无效：{exc}", err=True)
        raise typer.Exit(code=2) from exc

    try:
        closure = close_report(report, config)
        write_report(report, report_json)
    except Exception as exc:  # noqa: BLE001 - command boundary prints a safe summary
        logger.error("[case close] closure failed (%s)", type(exc).__name__)
        typer.echo(f"错误：案件闭环执行失败（{type(exc).__name__}）", err=True)
        raise typer.Exit(code=_execution_failure_exit_code(strict=strict)) from exc

    _print_closure_summary(closure)
    code = closure_exit_code(closure.get("status"))
    if strict and code:
        raise typer.Exit(code=code)


__all__ = ["case_app", "close_command", "closure_exit_code"]
