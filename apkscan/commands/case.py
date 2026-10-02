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
from apkscan.commands.phase2 import build_phase2_typer
from apkscan.core.report_compat import report_revision_warnings
from apkscan.core.report_io import load_report, write_report

logger = logging.getLogger(__name__)

case_app = typer.Typer(
    add_completion=False,
    help="案件闭环：运行时端点再富化、多源覆盖、五层归因和严格验收。",
)
case_app.add_typer(
    build_phase2_typer(deprecated_alias=False),
    name="phase2",
    help="Phase2 独立复核。旧入口 fxapk phase2 本版仍可用，下一版删除。",
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
    max_source_calls: int | None = typer.Option(None, "--max-source-calls", min=0, help="本次闭环及解析 IP 共用的富化器调用上限；不等于积分/金额上限。"),
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
            max_source_calls=max_source_calls,
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
    gate_receipt: Path = typer.Option(
        ..., "--gate-receipt", exists=True, dir_okay=False, readable=True,
        help="`fxapk case phase2 gate` 产出的 gate-receipt.json；必填，必须 PASS 且覆盖本包。",
    ),
) -> None:
    """对精确 package 哈希出具独立 Phase-2 复核记录，不修改 Phase-1 证据。"""
    try:
        payload = create_case_review(
            package_json,
            out,
            reviewer=reviewer,
            status=status,
            findings=finding,
            gate_receipt=gate_receipt,
        )
    except (CasePackageError, OSError, ValueError, UnicodeError) as exc:
        typer.echo(f"错误：Phase-2 复核记录生成失败（{type(exc).__name__}）：{safe_exception_text(exc)}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"Phase-2 复核记录：{out}")
    typer.echo(f"复核状态：{payload.get('status')}")
    typer.echo(f"Phase2 门禁绑定：{'已绑定' if 'phase2_gate' in payload else '未绑定'}")


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


@case_app.command("provider-plan")
def provider_plan_command(
    report_json: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    out: Path | None = typer.Option(None, "--out", help="新建 JSON 核验工作清单；拒绝覆盖。"),
    max_targets: int = typer.Option(200, "--max-targets", min=1, max=200),
    evidence_values: str = typer.Option("omit", "--evidence-values", help="omit 或 raw；raw 含私有对象原值。"),
) -> None:
    """离线准备服务商角色核验清单；不查询、不改原报告、不表示服务商已落实。"""
    from apkscan.core.atomic import atomic_create_bytes
    from apkscan.core.closure.layers import assemble_target_closure
    from apkscan.core.closure.targets import _select_targets_with_stats
    from apkscan.core.integrity import sha256_hex
    from apkscan.core.json_io import read_json_bounded
    from apkscan.core.provider_review import build_provider_review_plan
    from apkscan.core.report_io import report_from_dict

    if evidence_values not in {"omit", "raw"}:
        typer.echo("错误：evidence-values 必须是 omit 或 raw", err=True)
        raise typer.Exit(code=2)
    if evidence_values == "raw":
        typer.echo("警告：raw 清单含未脱敏的目标与服务商原值，仅供本地授权复核。", err=True)
    try:
        payload, raw = read_json_bounded(report_json, 128 * 1024 * 1024, 64)
        if not isinstance(payload, dict):
            raise ValueError("report root must be an object")
        report = report_from_dict(payload)
        targets, selection = _select_targets_with_stats(report, max_targets)
        plan = build_provider_review_plan(
            [assemble_target_closure(endpoint) for endpoint in targets],
            evidence_values=evidence_values, max_targets=max_targets,
        )
        # Keep identity binding, but not the source filename or excluded target
        # values, in the default projection. Hashes are references, not proof
        # that the case material has been comprehensively anonymized.
        plan["source_report_sha256"] = sha256_hex(raw)
        plan["target_selection"] = {
            key: value for key, value in selection.items()
            if isinstance(value, int) and not isinstance(value, bool)
        }
        plan["truncated"] = bool(plan["truncated"] or selection.get("truncated"))
        encoded = (json.dumps(plan, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
        if out is not None:
            if not atomic_create_bytes(out, encoded):
                typer.echo("错误：输出已存在，拒绝覆盖", err=True)
                raise typer.Exit(code=2)
            typer.echo("服务商核验工作清单已生成；仍需复核，不是正式报告或身份确认。")
        else:
            typer.echo(encoded.decode("utf-8"), nl=False)
    except (OSError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        typer.echo(f"错误：无法准备核验清单（{type(exc).__name__}）", err=True)
        raise typer.Exit(code=2) from exc


@case_app.command("prepare-materials")
def prepare_materials_command(
    case_dir: Path = typer.Argument(..., exists=True, file_okay=False, readable=True),
    out: Path = typer.Option(..., "--out", help="新建报告前材料 JSON，不覆盖原件。"),
    coverage: Path | None = typer.Option(None, "--coverage", exists=True, dir_okay=False),
    clues: Path | None = typer.Option(None, "--clues", exists=True, dir_okay=False),
    runs: Path | None = typer.Option(None, "--runs", exists=True, dir_okay=False, help="可选 RunRecord JSONL；只保留声明及逐次状态，不冒充运行证明。"),
    max_targets: int = typer.Option(200, "--max-targets", min=1, max=200),
    evidence_values: str = typer.Option("omit", "--evidence-values"),
) -> None:
    """离线串联已验包、阶段二覆盖、运行历史及服务商核验队列；停在正式报告前。"""
    from apkscan.core.atomic import atomic_create_bytes
    from apkscan.core.phase2.inventory import load_clue_records, load_coverage_snapshot
    from apkscan.core.phase2.preparation import prepare_case_materials

    if (coverage is None) != (clues is None) or evidence_values not in {"omit", "raw"}:
        typer.echo("错误：coverage/clues 必须配对；evidence-values 必须是 omit 或 raw", err=True)
        raise typer.Exit(code=2)
    if evidence_values == "raw":
        typer.echo("警告：raw 材料含未脱敏对象，仅供本地授权复核。", err=True)
    try:
        payload = prepare_case_materials(
            case_dir, coverage=load_coverage_snapshot(coverage) if coverage else None,
            clue_records=load_clue_records(clues) if clues else None,
            runs=load_clue_records(runs) if runs else (),
            evidence_values=evidence_values, max_targets=max_targets,
        )
        encoded = (json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
        if not atomic_create_bytes(out, encoded):
            typer.echo("错误：输出已存在，拒绝覆盖", err=True)
            raise typer.Exit(code=2)
    except (OSError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        typer.echo(f"错误：准备材料失败（{type(exc).__name__}）", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"报告前材料已生成：{payload['state']}；尚未出具正式报告或服务商确认。")
    if payload["state"] == "blocked":
        raise typer.Exit(code=1)


@case_app.command("source-catalog")
def source_catalog_command(
    category: str = typer.Option("all", "--category", help="all / free / registered / paid"),
) -> None:
    """查看有日期和官方来源的富化产品目录，不读取密钥或调用外部 API。"""
    from apkscan.core.source_catalog import source_catalog
    try:
        payload = source_catalog(category=category)
    except ValueError as exc:
        typer.echo(f"错误：来源目录参数或数据无效（{type(exc).__name__}）", err=True)
        raise typer.Exit(2) from exc
    typer.echo(json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False))
