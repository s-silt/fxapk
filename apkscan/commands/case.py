"""CLI entry points for deterministic case closure."""

from __future__ import annotations

import logging
import os
import json
import traceback
from pathlib import Path
from typing import Mapping

import typer

from apkscan.core.redact import safe_exception_text
from apkscan.core.closure import ClosureConfig, close_report
from apkscan.core.case_package import (
    CasePackageError,
    create_case_package,
    create_case_review,
    project_case_status,
)
from apkscan.core.models import ANALYSIS_MODE_PASSIVE, ANALYSIS_MODES
from apkscan.core.report_compat import report_revision_warnings
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

    for warning in report_revision_warnings(report.meta):
        typer.echo(warning, err=True)

    try:
        config = ClosureConfig(
            online=online,
            mode=mode,
            max_targets=max_targets,
            refresh=refresh,
        )
    except ValueError as exc:
        typer.echo(f"错误：闭环参数无效：{safe_exception_text(exc)}", err=True)
        raise typer.Exit(code=2) from exc

    try:
        closure = close_report(report, config)
        write_report(report, report_json)
    except Exception as exc:  # noqa: BLE001 - command boundary prints a safe summary
        # 记异常**调用栈位置**（文件:行:函数，末 5 帧），但**不含异常消息/源码行**——闭环会处理
        # provider 响应，异常消息可能夹带敏感响应片段/带 key 的 URL，``logger.exception`` 会把它
        # 连同 traceback 写进日志（有专门测试守此不外泄）。只记帧位置：既恢复「在哪一行、经什么
        # 调用路径失败」的排障线索，又不泄露载荷。用户可见串仍只给类型名。
        frames = traceback.extract_tb(exc.__traceback__)[-5:]
        where = " <- ".join(f"{os.path.basename(f.filename)}:{f.lineno}:{f.name}" for f in frames)
        logger.error("[case close] closure failed (%s) at %s", type(exc).__name__, where)
        typer.echo(f"错误：案件闭环执行失败（{type(exc).__name__}）", err=True)
        raise typer.Exit(code=_execution_failure_exit_code(strict=strict)) from exc

    _print_closure_summary(closure)
    code = closure_exit_code(closure.get("status"))
    if strict and code:
        raise typer.Exit(code=code)


@case_app.command("package")
def package_command(
    report_json: Path = typer.Argument(
        ..., exists=True, dir_okay=False, readable=True, help="Phase-1 fxapk report.json。"
    ),
    case_id: str = typer.Option(..., "--case-id", help="稳定案件标识。"),
    producer: str = typer.Option(..., "--producer", help="Phase-1 执行者标识；不限定具体人员或 AI。"),
    out: Path = typer.Option(..., "--out", help="不可变 case-package.json 输出路径。"),
    case_evidence: list[Path] = typer.Option(
        [], "--case-evidence", help="当前案件直接证据附件，可重复。"
    ),
    batch_reference: list[Path] = typer.Option(
        [], "--batch-reference", help="批量/跨案参考附件，可重复；不能独立支撑闭环。"
    ),
) -> None:
    """固化 Phase-1 证据包；路径/角色与 OneDrive 或具体执行者无关。"""
    try:
        payload = create_case_package(
            report_json,
            out,
            case_id=case_id,
            producer=producer,
            case_evidence=case_evidence,
            batch_reference=batch_reference,
        )
    except (CasePackageError, OSError, ValueError, UnicodeError) as exc:
        typer.echo(f"错误：Phase-1 证据包生成失败（{type(exc).__name__}）：{safe_exception_text(exc)}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"Phase-1 证据包：{out}")
    typer.echo(f"package_id：{payload.get('package_id')}")


@case_app.command("review")
def review_command(
    package_json: Path = typer.Argument(
        ..., exists=True, dir_okay=False, readable=True, help="Phase-1 case-package.json。"
    ),
    reviewer: str = typer.Option(..., "--reviewer", help="Phase-2 执行者标识；可与 producer 相同。"),
    status: str = typer.Option(..., "--status", help="accepted | changes_requested。"),
    out: Path = typer.Option(..., "--out", help="不可变 case-review.json 输出路径。"),
    finding: list[str] = typer.Option([], "--finding", help="复核发现，可重复。"),
) -> None:
    """对精确 package 哈希出具独立 Phase-2 复核记录，不修改 Phase-1 证据。"""
    try:
        payload = create_case_review(
            package_json,
            out,
            reviewer=reviewer,
            status=status,
            findings=finding,
        )
    except (CasePackageError, OSError, ValueError, UnicodeError) as exc:
        typer.echo(f"错误：Phase-2 复核记录生成失败（{type(exc).__name__}）：{safe_exception_text(exc)}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"Phase-2 复核记录：{out}")
    typer.echo(f"复核状态：{payload.get('status')}")


@case_app.command("status")
def status_command(
    target_json: Path = typer.Argument(
        ..., exists=True, dir_okay=False, readable=True, help="case-package.json 或裸 report.json。"
    ),
    review: Path | None = typer.Option(
        None, "--review", exists=True, dir_okay=False, readable=True, help="可选 case-review.json。"
    ),
    as_json: bool = typer.Option(False, "--json", help="输出稳定 JSON。"),
) -> None:
    """并列显示 package/analysis/closure/review 四个不可互推的状态。"""
    status = project_case_status(target_json, review)
    if as_json:
        typer.echo(json.dumps(status, ensure_ascii=False, sort_keys=True))
        return
    typer.echo(f"包完整性：{status['package_integrity']}")
    typer.echo(f"分析状态：{status['analysis']}")
    typer.echo(f"闭环状态：{status['closure']}")
    typer.echo(f"复核状态：{status['review']}")


__all__ = [
    "case_app",
    "close_command",
    "closure_exit_code",
    "package_command",
    "review_command",
    "status_command",
]
