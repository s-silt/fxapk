"""apkscan CLI（typer）。

analyze: load_apk → pipeline.run → report.html.render + report.json.dump，写到 out 目录，
并打印线索数量摘要。

report.html / report.json 由其它 agent 实现；本文件惰性导入它们，
缺失时记 warning 并跳过对应格式，不影响其余流程。
"""

from __future__ import annotations

import logging
from pathlib import Path

import typer

from apkscan.core import device, pipeline
from apkscan.core.apk import ApkParseError, load_apk
from apkscan.core.models import AnalysisConfig, LeadCategory, Report

logger = logging.getLogger(__name__)

app = typer.Typer(
    add_completion=False,
    help="涉诈 APK 调证分析 CLI：静态分析 + 端点/服务归属提取，产出调证线索清单。",
)


@app.command()
def analyze(
    apk: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="待分析的 APK 文件路径。",
    ),
    online: bool = typer.Option(
        True,
        "--online/--offline",
        help="是否联网富化归属信息（WHOIS/ICP/ASN）。",
    ),
    out: str = typer.Option("out", "--out", help="报告输出目录。"),
    fmt: str = typer.Option(
        "html,json",
        "--fmt",
        help="输出格式，逗号分隔：html,json,pdf。pdf 需本机有 Chrome/Edge/Chromium（无头打印）。",
    ),
    extra_dex: str = typer.Option(
        "",
        "--extra-dex",
        help="额外 DEX（脱壳 dump 的 .dex 文件或含 .dex 的目录），逗号分隔；并入静态分析。",
    ),
    dynamic: bool = typer.Option(
        False,
        "--dynamic",
        help="静态分析后，若探测到在线设备则自动执行真机 unpack + capture（需设备/工具）。",
    ),
) -> None:
    """分析一个 APK 并产出报告。"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    formats = [f.strip().lower() for f in fmt.split(",") if f.strip()]
    config = AnalysisConfig(online=online, out_dir=out, formats=formats)

    extra_dex_files = _resolve_extra_dex(extra_dex)
    if extra_dex_files:
        typer.echo(f"额外 DEX：{len(extra_dex_files)} 个并入静态分析")

    typer.echo(f"加载 APK：{apk}")
    try:
        ctx = load_apk(str(apk), config, extra_dex=extra_dex_files or None)
    except ApkParseError as exc:
        typer.echo(f"错误：{exc}", err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(f"包名：{ctx.package_name or '(未知)'}  联网富化：{'是' if online else '否'}")
    typer.echo("运行分析流水线 ...")
    # ApkContext 用 @cached_property 暴露 package_name/manifest_xml，运行期满足
    # AnalysisContext 协议（324 测试+真机已证）；pyright 对 cached_property→property
    # 的协议匹配有已知局限，故此处显式忽略。
    report = pipeline.run(ctx, config)  # type: ignore[arg-type]

    # 设备探测：有在线设备则提示并写入 meta，便于报告/后续动态补全感知。
    device_detected = device.has_device()
    if device_detected:
        report.meta["device_detected"] = True
        typer.echo("检测到在线 adb 设备：可用 --dynamic 做真机脱壳/抓包补全静态盲区。")

    out_dir = Path(out)
    out_dir.mkdir(parents=True, exist_ok=True)
    _write_reports(report, out_dir, formats)

    _print_summary(report)

    # --dynamic：静态完成后，若有设备则自动 unpack + capture（实现由 dynamic 模块 agent 完成）。
    if dynamic:
        if not device_detected:
            typer.echo("未检测到在线设备，跳过 --dynamic（动态脱壳/抓包需真机）。")
        else:
            _run_dynamic_after_static(str(apk), ctx.package_name or "", out)


@app.command()
def unpack(
    apk: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="待脱壳的 APK 文件路径。",
    ),
    out: str = typer.Option("out", "--out", help="产物 / 报告输出目录。"),
    reanalyze: bool = typer.Option(
        True,
        "--reanalyze/--no-reanalyze",
        help="脱壳得到额外 DEX 后是否自动重新静态分析。",
    ),
) -> None:
    """真机脱壳：dump 隐藏 DEX 并（可选）重新静态分析。

    实现由 apkscan.dynamic.unpack 提供；未安装时打印提示并退出，不崩。
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        from apkscan.dynamic import unpack as _unpack
    except ImportError:
        typer.echo("该功能未安装：apkscan.dynamic.unpack 不可用（动态脱壳模块尚未就绪）。")
        raise typer.Exit(code=1) from None

    result = _unpack.run(str(apk), out=out, reanalyze=reanalyze)
    _print_dynamic_result("脱壳", result)


@app.command()
def capture(
    package: str = typer.Argument(..., help="目标应用包名（在设备上运行/抓包）。"),
    out: str = typer.Option("out", "--out", help="产物 / 报告输出目录。"),
    duration: int = typer.Option(60, "--duration", help="抓包时长（秒）。"),
) -> None:
    """真机抓包：对运行中的目标应用做流量抓取，提取动态端点。

    实现由 apkscan.dynamic.capture 提供；未安装时打印提示并退出，不崩。
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        from apkscan.dynamic import capture as _capture
    except ImportError:
        typer.echo("该功能未安装：apkscan.dynamic.capture 不可用（动态抓包模块尚未就绪）。")
        raise typer.Exit(code=1) from None

    result = _capture.run(package, out=out, duration=duration)
    _print_dynamic_result("抓包", result)


def _resolve_extra_dex(spec: str) -> list[str]:
    """解析 --extra-dex（逗号分隔的 .dex 路径或目录）为 .dex 文件路径列表。

    - 目录：收集其下所有 .dex 文件。
    - 文件：原样保留。
    - 不存在的条目记 warning 跳过（不静默吞错），交由 load_apk 对单个失败再降级。
    """
    files: list[str] = []
    for raw in spec.split(","):
        item = raw.strip()
        if not item:
            continue
        p = Path(item)
        if p.is_dir():
            dexes = sorted(p.glob("*.dex"))
            if not dexes:
                logger.warning("--extra-dex 目录内无 .dex 文件：%s", p)
            files.extend(str(d) for d in dexes)
        elif p.is_file():
            files.append(str(p))
        else:
            logger.warning("--extra-dex 路径不存在，跳过：%s", item)
    return files


def _run_dynamic_after_static(apk_path: str, package: str, out: str) -> None:
    """--dynamic：静态完成且有设备时，顺序执行 unpack + capture。

    两个动态模块均惰性导入，缺失时打印"该功能未安装"并跳过，绝不崩主流程。
    """
    typer.echo("")
    typer.echo("===== 动态补全（真机） =====")

    try:
        from apkscan.dynamic import unpack as _unpack
    except ImportError:
        typer.echo("该功能未安装：apkscan.dynamic.unpack 不可用，跳过脱壳。")
    else:
        try:
            _print_dynamic_result("脱壳", _unpack.run(apk_path, out=out, reanalyze=True))
        except Exception:
            logger.exception("动态脱壳执行异常（不影响已产出的静态报告）")
            typer.echo("脱壳执行异常（详见日志），已跳过。")

    if not package:
        typer.echo("未知包名，跳过抓包（capture 需目标包名）。")
        return

    try:
        from apkscan.dynamic import capture as _capture
    except ImportError:
        typer.echo("该功能未安装：apkscan.dynamic.capture 不可用，跳过抓包。")
    else:
        try:
            _print_dynamic_result("抓包", _capture.run(package, out=out))
        except Exception:
            logger.exception("动态抓包执行异常（不影响已产出的静态报告）")
            typer.echo("抓包执行异常（详见日志），已跳过。")


def _print_dynamic_result(label: str, result: object) -> None:
    """打印 DynamicResult（dict 契约）摘要；容错非 dict 返回。"""
    if not isinstance(result, dict):
        typer.echo(f"{label}：返回值非预期格式，已忽略。")
        return
    status = result.get("status", "?")
    reason = result.get("reason", "")
    typer.echo(f"{label}：status={status}{('  ' + reason) if reason else ''}")
    for key, title in (("artifacts", "产物"), ("report_paths", "报告"), ("playbook", "操作步骤")):
        items = result.get(key) or []
        if items:
            typer.echo(f"  {title}（{len(items)}）：")
            for it in items:
                typer.echo(f"    - {it}")


def _write_reports(report: Report, out_dir: Path, formats: list[str]) -> None:
    """按 formats 写出报告。report.html / report.json 由其它 agent 实现。"""
    if "json" in formats:
        try:
            from apkscan.report import json as report_json

            path = out_dir / "report.json"
            report_json.dump(report, str(path))
            typer.echo(f"已写出 JSON 报告：{path}")
        except Exception:
            logger.exception("写出 JSON 报告失败（report.json 模块可能尚未就绪）")

    html_path = out_dir / "report.html"
    if "html" in formats:
        try:
            from apkscan.report import html as report_html

            report_html.render(report, str(html_path))
            typer.echo(f"已写出 HTML 报告：{html_path}")
        except Exception:
            logger.exception("写出 HTML 报告失败（report.html 模块可能尚未就绪）")

    if "pdf" in formats:
        # PDF 派生自 HTML：html 已写则复用，否则 pdf.render 内部渲临时 HTML 再转。
        try:
            from apkscan.report import pdf as report_pdf

            path = out_dir / "report.pdf"
            html_source = str(html_path) if ("html" in formats and html_path.is_file()) else None
            if report_pdf.render(report, str(path), html_source=html_source):
                typer.echo(f"已写出 PDF 报告：{path}")
            else:
                typer.echo(
                    "PDF 导出跳过：未找到 Chrome/Edge/Chromium 或转换失败（详见日志）；"
                    "HTML/JSON 不受影响。"
                )
        except Exception:
            logger.exception("写出 PDF 报告失败")


def _print_summary(report: Report) -> None:
    """打印线索数量摘要。"""
    typer.echo("")
    typer.echo("===== 线索摘要 =====")
    typer.echo(f"端点总数：{len(report.endpoints)}")
    typer.echo(f"技术发现：{len(report.findings)}")
    typer.echo(f"线索总数：{len(report.leads)}")

    by_cat: dict[str, int] = {}
    for lead in report.leads:
        cat = lead.category.value if isinstance(lead.category, LeadCategory) else str(lead.category)
        by_cat[cat] = by_cat.get(cat, 0) + 1
    for cat in sorted(by_cat):
        typer.echo(f"  {cat}: {by_cat[cat]}")

    ran = sum(1 for s in report.analyzer_status if s.get("status") == "ran")
    skipped = sum(1 for s in report.analyzer_status if s.get("status") == "skipped")
    errored = sum(1 for s in report.analyzer_status if s.get("status") == "error")
    typer.echo(f"分析器：ran={ran} skipped={skipped} error={errored}")


def main() -> None:
    """[project.scripts] 入口。"""
    app()


if __name__ == "__main__":
    main()
