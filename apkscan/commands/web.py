"""``analyze-web`` 子命令：把**已落盘**的网页证据目录当一级输入走同一条分析流水线。

为什么需要它：实测有的样本压根没有 APK、只有 URL 与落盘的网页证据（``.body`` / ``.headers.txt`` /
``.html`` / ``.js``），``analyze`` 吃不进去 —— 那些证据里的分发链、内联配置、跳转跳板全靠人工挖。

本命令与 ``analyze`` 共用出口：同一个 :func:`apkscan.core.pipeline.run`、同一套 Lead/Finding/
report.json、同一个 ``_write_reports``（含 ``.sha256`` 旁文件契约），**不另建并行管线**。

★ 纯离线读证据：证据只从磁盘读，本命令绝不抓取任何 URL（主动获取一律不在此实现，见 AGENTS.md
  主被动硬隔离）。``--online`` 只影响**归属富化**（对 IP/域名做被动 OSINT 查询），不会去碰目标站点；
  且与 ``analyze`` 相反**默认关**：网页证据常是"先看看这份证据里有什么"，不该默认就发外部查询。

逻辑分层同 1b：本层只做 IO / 打印 / 退出码，证据读取在 :mod:`apkscan.core.webctx`、
判据在 :mod:`apkscan.analyzers.web_evidence`。
"""

from __future__ import annotations

import logging
from pathlib import Path

import typer

from apkscan.core.models import AnalysisConfig
from apkscan.core.webctx import load_web_evidence

logger = logging.getLogger(__name__)

META_WRITE_OWNER = "commands.web"
META_WRITE_KEYS = frozenset({"online", "web_evidence"})

#: 报告文件名兜底 base（证据目录名不可用时）。
_FALLBACK_BASE = "web_evidence"


def _sanitize_base(name: str) -> str:
    """把证据目录名/origin 收敛成安全文件名 base。

    ★不可信输入：``origin`` 可能来自证据里的 URL。只保留字母数字与 ``-_.``，其余换 ``_``，
    并**剥掉**路径分隔符与前导点 —— 否则 ``--origin ../../x`` 会把报告写到证据目录之外。
    """
    cleaned = "".join(ch if (ch.isalnum() or ch in "-_.") else "_" for ch in name.strip())
    cleaned = cleaned.lstrip(".")[:80].strip("_")
    return cleaned or _FALLBACK_BASE


def analyze_web(
    evidence_dir: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="已落盘的网页证据目录（递归读 .html/.body/.js/.headers 等文本证据）。",
    ),
    out: str | None = typer.Option(None, "--out", help="报告输出目录（默认：证据目录下的 out/）。"),
    fmt: str = typer.Option("html,json", "--fmt", help="输出格式，逗号分隔：html,json,pdf。"),
    origin: str = typer.Option(
        "", "--origin", help="证据来源标注（URL 或自定义标识），只写进报告，不参与任何请求。"
    ),
    online: bool = typer.Option(
        False,
        "--online/--offline",
        help="是否对抽出的 IP/域名做被动归属富化（默认关）。绝不抓取证据里的 URL。",
    ),
) -> None:
    """分析已落盘的网页证据目录，产出与 ``analyze`` 同构的报告。"""
    # 复用 analyze 的报告写出与摘要打印：report 文件名/格式/`.sha256` 旁文件是**同一份契约**，
    # 各写一份必然漂移。函数体内惰性 import：cli.py 在模块级注册本命令，顶层反向 import 会成环。
    from apkscan.cli import _parse_formats, _print_summary, _write_reports
    from apkscan.core import pipeline

    formats = _parse_formats(fmt)
    out_dir = Path(out) if out else Path(evidence_dir) / "out"

    # ★输出目录**不得**等于证据根：``exclude_dirs`` 只能剪掉 root 的**子**目录，
    #   os.walk 从 root 自身开始，剪不掉 root —— 于是上次写在证据根下的 report.html /
    #   report.json 会在下一次运行时被当作新证据读回去，形成自污染反馈（报告里的域名/端点
    #   变成"证据"，越跑越像有线索）。这里在 CLI 层直接拒绝，比在读取层做"精确排除"更稳：
    #   排除单个文件名会连用户真实叫 report.html 的证据一起吞掉。
    if out_dir.resolve(strict=False) == Path(evidence_dir).resolve(strict=False):
        typer.echo(
            "错误：--out 不能等于证据目录本身"
            f"（{out_dir}）——上次生成的报告会被当作新证据读回去，形成自污染。"
            "请指定证据目录之外或其下的子目录，例如 --out "
            f"{Path(evidence_dir) / 'out'}。",
            err=True,
        )
        raise typer.Exit(code=2)

    try:
        # 默认输出就在证据根下；重跑时必须排除它，否则上次生成的 report.html/json 会被
        # 当作新证据递归吃回去，形成自污染反馈。自定义输出若位于证据树内也同样排除。
        ctx = load_web_evidence(
            evidence_dir,
            AnalysisConfig(online=online),
            origin=origin,
            exclude_dirs=(out_dir,),
        )
    except FileNotFoundError as exc:
        typer.echo(f"错误：{exc}", err=True)
        raise typer.Exit(code=2)
    except Exception as exc:
        logger.exception("[analyze-web] 读取网页证据失败：%s", evidence_dir)
        typer.echo(f"错误：读取网页证据失败：{evidence_dir}（{exc}）", err=True)
        raise typer.Exit(code=1)

    file_count = len(ctx.list_files())
    typer.echo(f"已读入网页证据 {file_count} 份（来源：{origin or evidence_dir}）")

    # ★读失败必须当场可见，不能只躺在 report 里：静默跳过时"扫了 1 份"与"扫全了"在数据上
    #   完全一样，报告就会以"网页证据已穷尽"签发一份漏读了关键证据的分析。
    for message in ctx.load_errors:
        typer.echo(f"警告：{message}", err=True)

    if not file_count:
        # 不是崩溃，但也绝不能当成"分析完毕、无线索"：零证据的空报告与"真的没有线索"不可区分。
        typer.echo(
            "错误：该目录下没有可读的文本网页证据（支持 .html/.htm/.body/.js/.json/.headers 等）。",
            err=True,
        )
        raise typer.Exit(code=2)

    typer.echo("运行分析流水线 ...")
    report = pipeline.run(ctx, ctx.config)  # type: ignore[arg-type]
    report.meta["online"] = online
    report.meta["web_evidence"] = {
        "source_dir": ctx.source_dir,
        "origin": origin,
        "file_count": file_count,
        # 如实带出读取缺口：completeness / 人工复核据此知道"这份分析看了多少"。
        "load_errors": list(ctx.load_errors),
    }

    base = _sanitize_base(origin or Path(ctx.source_dir or str(evidence_dir)).name)
    out_dir.mkdir(parents=True, exist_ok=True)
    _write_reports(report, out_dir, formats, base)
    _print_summary(report)


__all__ = ["analyze_web"]
