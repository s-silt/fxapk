"""``fxapk dex``：capabilities / query / import。

缺可选插件时帮助和 capabilities 仍可用。本模块不导入 ASC。
stdout 只输出安全投影，查询原文留在本地回执文件里。
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from apkscan.core import dex_query

dex_app = typer.Typer(
    add_completion=False,
    help="可选 DEX 定点查询。缺插件时返回 provider_unavailable，不改 jadx 查询。",
)


def _public_receipt(receipt: dict[str, object]) -> dict[str, object]:
    projected = dict(receipt)
    projected.pop("query_values", None)
    return projected


def _fail(reason: str) -> None:
    typer.echo(json.dumps({"reason": reason, "engine_executed": False}, ensure_ascii=False))
    raise typer.Exit(1)


@dex_app.command("capabilities")
def capabilities_command() -> None:
    """探测 ASC 插件是否安装且版本匹配。不打开 APK，不声称引擎已执行。"""
    typer.echo(json.dumps(dex_query.capabilities(), ensure_ascii=False, indent=2))


@dex_app.command("query")
def query_command(
    apk: Path,
    value: list[str] = typer.Option(..., "--value", help="要查询的字符串。可重复。stdout 不回显原文。"),
    out: Path | None = typer.Option(None, "--out", help="create-only 的原始回执路径。"),
) -> None:
    """清点 APK 内 DEX 并经隔离 worker 查询。原件不改写。"""
    try:
        receipt = dex_query.query_apk(apk, value, out=out)
    except dex_query.DexQueryError as exc:
        _fail(exc.reason)
    typer.echo(json.dumps(_public_receipt(receipt), ensure_ascii=False, indent=2))


@dex_app.command("import")
def import_command(
    receipt: Path = typer.Option(..., "--receipt"),
    report: Path = typer.Option(..., "--report"),
    out: Path = typer.Option(..., "--out"),
    apk: Path | None = typer.Option(None, "--apk"),
) -> None:
    """把已核验回执导入新报告目录。不升级运行时观察，也不改闭环状态。"""
    try:
        result = dex_query.import_receipt(receipt, report, out, apk=apk)
    except dex_query.DexQueryError as exc:
        _fail(exc.reason)
    except OSError:
        _fail("evidence_io_failed")
    typer.echo(json.dumps(result, ensure_ascii=False, indent=2))
