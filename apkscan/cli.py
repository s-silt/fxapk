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

    # 把真实联网状态落到 meta：merge 生成运行时线索时据此决定 online 分级标注，
    # 离线扫描（--no-online）下运行时端点才不会被默认 online=True 当成已联网核实
    # （否则拿不到静态侧"离线扫描，归属未查询"标注，偏乐观、轻微假成功）。
    report.meta["online"] = config.online

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
            _run_dynamic_after_static(
                str(apk), ctx.package_name or "", out, report, formats
            )


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


@app.command()
def doctor(
    serial: str = typer.Option(
        "", "--serial", help="目标设备序列号（默认 adb 当前设备）。"
    ),
    auto_fix: bool = typer.Option(
        True,
        "--fix/--no-fix",
        help="对 frida-server / CA 等可自动修的项调 provision 自动修复（--no-fix 仅体检不动设备）。",
    ),
) -> None:
    """动态抓包/脱壳前置环境体检：设备/root/ABI/frida/mitmproxy/CA，逐项给出状态与可复制命令。

    实现由 apkscan.dynamic.doctor 提供（纯结构化返回）；本命令是唯一打印体检结果的薄包装。
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        from apkscan.dynamic import doctor as _doctor
    except ImportError:
        typer.echo("该功能未安装：apkscan.dynamic.doctor 不可用（环境体检模块尚未就绪）。")
        raise typer.Exit(code=1) from None

    typer.echo("===== 动态环境体检 =====")
    result = _doctor.run(
        serial=serial or None,
        auto_fix=auto_fix,
        on_progress=lambda m: typer.echo(f"... {m}"),
    )
    _print_doctor_result(result)
    if not result.get("ok", False):
        raise typer.Exit(code=1)


def _print_doctor_result(result: object) -> None:
    """打印 doctor.run 的结构化结果：逐项 [OK]/[FAIL] + 缩进列出 fix_cmd。"""
    if not isinstance(result, dict):
        typer.echo("体检：返回值非预期格式，已忽略。")
        return
    items = result.get("items") or []
    typer.echo("")
    for item in items:
        if not isinstance(item, dict):
            continue
        ok = bool(item.get("ok"))
        name = str(item.get("name", "?"))
        detail = str(item.get("detail", ""))
        tag = "[OK]  " if ok else "[FAIL]"
        typer.echo(f"{tag} {name}{('：' + detail) if detail else ''}")
        if not ok:
            fix_cmd = item.get("fix_cmd") or []
            if isinstance(fix_cmd, list) and fix_cmd:
                typer.echo("       建议命令：")
                for cmd in fix_cmd:
                    typer.echo(f"         {cmd}")
    typer.echo("")
    overall = "全部关键项通过" if result.get("ok", False) else "存在未通过的关键项（详见上方 [FAIL]）"
    typer.echo(f"体检结论：{overall}")


def _resolve_extra_dex(spec: str) -> list[str]:
    """解析 --extra-dex（逗号分隔的 .dex 路径或目录）为 .dex 文件路径列表。

    - 目录：递归收集其下所有 .dex 文件（frida-dexdump 常把 dump 放子目录，
      与 unpack._collect_dex 的 rglob 行为对齐，避免子目录 dex 静默漏掉）。
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
            dexes = sorted(p.rglob("*.dex"))
            if not dexes:
                logger.warning("--extra-dex 目录内无 .dex 文件：%s", p)
            files.extend(str(d) for d in dexes)
        elif p.is_file():
            files.append(str(p))
        else:
            logger.warning("--extra-dex 路径不存在，跳过：%s", item)
    return files


def _run_dynamic_after_static(
    apk_path: str, package: str, out: str, report: Report, formats: list[str]
) -> None:
    """--dynamic：静态完成且有设备时，顺序执行 unpack + capture，并把运行时端点并回主报告。

    两个动态模块均惰性导入，缺失时打印"该功能未安装"并跳过，绝不崩主流程。
    capture status==done 后，惰性 import merge，从 out/runtime_report.json 读回运行时端点，
    去重并入静态 report.endpoints、按 infra 分级生成线索、重渲 report.html/json，
    让真·C2 进入主线索清单而非游离在 runtime_report.json。合并失败不影响已产出静态报告。
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
        return

    try:
        capture_result = _capture.run(package, out=out)
    except Exception:
        logger.exception("动态抓包执行异常（不影响已产出的静态报告）")
        typer.echo("抓包执行异常（详见日志），已跳过。")
        return

    _print_dynamic_result("抓包", capture_result)

    # 抓包成功（done）才把运行时端点并回主报告并重渲；skipped/error 不调 merge。
    status = capture_result.get("status") if isinstance(capture_result, dict) else None
    from apkscan.dynamic import STATUS_DONE

    if status != STATUS_DONE:
        return

    _merge_runtime_into_report(capture_result, out, report, formats)


def _merge_runtime_into_report(
    capture_result: object, out: str, report: Report, formats: list[str]
) -> None:
    """把 capture 抓到的运行时端点并回主报告并重渲；任何失败不破坏已产出的静态报告。"""
    try:
        from apkscan.dynamic import merge as _merge
    except ImportError:
        typer.echo("该功能未安装：apkscan.dynamic.merge 不可用，跳过运行时端点并入。")
        return

    try:
        # 运行时端点来源（不动 capture 契约）：优先 report_paths 里的 runtime_report.json，
        # 否则回退到约定路径 out/runtime_report.json。
        runtime_path = _resolve_runtime_report_path(capture_result, out)
        endpoints = _merge.load_runtime_endpoints(runtime_path)
        stats = _merge.merge_and_rerender(
            report,
            endpoints,
            out,
            formats=formats,
            on_progress=lambda m: typer.echo(f"... {m}"),
        )
        merged = stats.get("merged", 0)
        new_leads = stats.get("new_leads", 0)
        report_paths = stats.get("report_paths") or []
        typer.echo(
            f"运行时端点并入：新增端点 {merged}，新增线索 {new_leads}；"
            f"重渲报告 {len(report_paths)} 份"
        )
        for p in report_paths:
            typer.echo(f"  - {p}")
    except Exception:
        logger.exception("运行时端点并入/重渲异常（不影响已产出的静态报告）")
        typer.echo("运行时端点并入异常（详见日志），静态报告不受影响。")


def _resolve_runtime_report_path(capture_result: object, out: str) -> str:
    """从 capture 返回的 report_paths 里找 runtime_report.json，否则回退 out/runtime_report.json。"""
    if isinstance(capture_result, dict):
        for p in capture_result.get("report_paths") or []:
            if isinstance(p, str) and Path(p).name == "runtime_report.json":
                return p
    return str(Path(out) / "runtime_report.json")


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
