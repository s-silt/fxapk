"""``supplement-web``：对已有规范报告追加一次网页补采，不重跑分析流水线。"""

from __future__ import annotations

import logging
from pathlib import Path

import typer

from apkscan.core.redact import safe_exception_text
from apkscan.core.web_supplement_report import SupplementRefusal, supplement_report

logger = logging.getLogger(__name__)


def supplement_web(
    report_json: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="已有的 web 或 Android 规范 report.json。",
    ),
    web_supplement: Path = typer.Option(
        ...,
        "--web-supplement",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="网页补采配置 JSON。bundle、rea-json，或已授权的 CDP。",
    ),
    out: Path = typer.Option(
        ...,
        "--out",
        help="新的输出目录。目录必须不存在，且不能落在输入报告或观察材料里面。",
    ),
) -> None:
    """把一份已验证的网页观察并进已有报告，写出新的 JSON、脱敏 digest 和 HTML。

    不调用 analyze、auto、adb、富化或 case close。退出码 0 只表示本次执行得到了
    有效结果（含重复原料）。配置或输入输出拒绝为 2。提供方或解析失败为 1。
    mode off 或其他未执行的跳过为 3。
    """
    try:
        result = supplement_report(report_json, web_supplement, out)
    except SupplementRefusal as exc:
        typer.echo(f"supplement-web: refused reason={exc.reason}", err=True)
        raise typer.Exit(code=2) from exc
    except Exception as exc:
        logger.exception("[supplement-web] failed")
        typer.echo(f"supplement-web: failed ({safe_exception_text(exc)})", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(
        "supplement-web: "
        f"status={result['status']} reason={result['reason']} "
        f"endpoints_added={result['endpoints_added']} leads_added={result['leads_added']} "
        f"live_cdp={str(result['live_cdp']).lower()}"
    )
    typer.echo(f"report={result['report']}")
    raise typer.Exit(code=int(result["exit_code"]))
