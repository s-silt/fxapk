"""apkscan CLI（typer）。

analyze: load_apk → pipeline.run → report.html.render + report.json.dump，写到 out 目录，
并打印线索数量摘要。

report.html / report.json 由其它 agent 实现；本文件惰性导入它们，
缺失时记 warning 并跳过对应格式，不影响其余流程。
"""

from __future__ import annotations

import logging
from pathlib import Path

import click
import typer

from apkscan.core import device
from apkscan.core.apk import ApkParseError
from apkscan.core.loader import load_app
from apkscan.core.models import AnalysisConfig, LeadCategory, Report
from apkscan.core.report_naming import report_base

logger = logging.getLogger(__name__)

app = typer.Typer(
    add_completion=False,
    help="涉诈 APK / iOS IPA 调证分析 CLI：静态分析 + 端点/服务归属提取，产出调证线索清单。",
)

# 合法输出格式（--fmt）。全非法时回退而非静默产出零报告。
_VALID_FORMATS = ("html", "json", "pdf")


def _version_callback(value: bool) -> None:
    if value:
        from apkscan import __version__

        typer.echo(f"fxapk {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(  # noqa: ARG001 - eager callback 内即退出，形参仅供 typer 注册
        False,
        "--version",
        help="显示版本号并退出。",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """涉诈 APK / iOS IPA 调证分析 CLI。"""


def _parse_formats(fmt: str) -> list[str]:
    """解析 ``--fmt`` 逗号串为合法格式列表。

    无法识别的格式会告警并忽略；**全部非法 → 回退 ['html','json'] 并告警**，绝不让"格式参数
    全填错"静默产出零报告却 exit 0（调证场景最怕"以为出了报告其实没有"）。
    """
    requested = [f.strip().lower() for f in fmt.split(",") if f.strip()]
    formats = [f for f in requested if f in _VALID_FORMATS]
    invalid = [f for f in requested if f not in _VALID_FORMATS]
    if invalid:
        typer.echo(
            f"忽略无法识别的输出格式：{'、'.join(invalid)}（合法：{', '.join(_VALID_FORMATS)}）",
            err=True,
        )
    if not formats:
        typer.echo("未指定任何合法输出格式，回退为 html,json。", err=True)
        formats = ["html", "json"]
    return formats


def _close_ctx_quiet(ctx: object) -> None:
    """关闭分析上下文的底层资源（IPA 的 ZipFile 句柄）；ApkContext 无 close 则 no-op。绝不抛。"""
    close = getattr(ctx, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            logger.exception("[cli] 关闭分析上下文失败（已忽略）")


def _cleanup_adb_quiet() -> None:
    """命令收尾：收掉本次进程自起的 adb server（惰性 import tools，绝不抛）。

    adb server 是 adb 全局单例：analyze 的设备探测（device.has_device）、doctor/auto/
    capture 的动态动作都会经 adb 起一个常驻 adb server。GUI 分析走子进程，子进程跑的就是
    这些 CLI 命令——退出时若不收，adb.exe 残留、下次重打 exe 被锁。每个 dynamic 命令体外
    包 ``try/finally`` 调本函数，收掉子进程自己起的那个 server。kill-server 幂等、对未起
    server 零副作用、且仅在 adb 可用时执行（见 tools.kill_adb_server），不会反而起 server。
    """
    try:
        from apkscan.core import tools

        tools.kill_adb_server()
    except Exception:
        logger.exception("[cli] 收尾清理 adb server 失败（已忽略）")


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

    # 无条件 finally 收 adb server：analyze 的 device.has_device() 设备探测每次都会经
    # adb 起一个常驻 adb server（即便纯静态/离线），不收则 adb.exe 残留（GUI 子进程尤甚）。
    ctx: object = None  # 供 finally 关闭 IPA 句柄（IpaContext 持有打开的 ZipFile）
    try:
        formats = _parse_formats(fmt)
        config = AnalysisConfig(online=online, out_dir=out, formats=formats)

        extra_dex_files = _resolve_extra_dex(extra_dex)
        if extra_dex_files:
            typer.echo(f"额外 DEX：{len(extra_dex_files)} 个并入静态分析")

        typer.echo(f"加载：{apk}")
        try:
            # load_app 按文件类型分流：.ipa / 含 Payload 的 ZIP → IPA（纯静态），否则 → APK。
            ctx = load_app(str(apk), config, extra_dex=extra_dex_files or None)
        except ApkParseError as exc:  # IpaParseError 继承 ApkParseError，一并兜住
            typer.echo(f"错误：{exc}", err=True)
            raise typer.Exit(code=2) from exc

        is_ios = getattr(ctx, "platform", "android") == "ios"
        if is_ios and extra_dex_files:
            typer.echo("IPA 无 DEX，已忽略 --extra-dex。")
        kind = "IPA(iOS)" if is_ios else "APK(Android)"
        typer.echo(f"类型：{kind}  包名：{ctx.package_name or '(未知)'}  联网富化：{'是' if online else '否'}")
        typer.echo("运行分析流水线 ...")
        # 启动提速：pipeline（→registry）延迟到真正分析时才 import；--version/doctor/gui
        # 等不分析的命令不再付这份导入开销。
        from apkscan.core import pipeline

        # ApkContext 用 @cached_property 暴露 package_name/manifest_xml，运行期满足
        # AnalysisContext 协议（324 测试+真机已证）；pyright 对 cached_property→property
        # 的协议匹配有已知局限，故此处显式忽略。
        report = pipeline.run(ctx, config)  # type: ignore[arg-type]

        # 把真实联网状态落到 meta：merge 生成运行时线索时据此决定 online 分级标注，
        # 离线扫描（--no-online）下运行时端点才不会被默认 online=True 当成已联网核实
        # （否则拿不到静态侧"离线扫描，归属未查询"标注，偏乐观、轻微假成功）。
        report.meta["online"] = config.online

        # 设备探测：有在线设备则提示并写入 meta，便于报告/后续动态补全感知。
        # IPA 无 Android 动态（adb/frida 不适用），跳过设备探测。
        device_detected = False if is_ios else device.has_device()
        if device_detected:
            report.meta["device_detected"] = True
            typer.echo("检测到在线 adb 设备：可用 --dynamic 做真机脱壳/抓包补全静态盲区。")

        # 报告文件名 base：用 APK 文件名去后缀（清理非法字符），空/异常回退包名再回退 report。
        base = report_base(str(apk), ctx.package_name or "")

        out_dir = Path(out)
        out_dir.mkdir(parents=True, exist_ok=True)
        _write_reports(report, out_dir, formats, base)

        _print_summary(report)

        # --dynamic：静态完成后，若有设备则自动 unpack + capture（实现由 dynamic 模块 agent 完成）。
        if dynamic and is_ios:
            typer.echo("IPA 仅静态分析（iOS 动态需越狱设备 + frida-iOS，本工具不支持），跳过 --dynamic。")
        elif dynamic:
            if not device_detected:
                typer.echo("未检测到在线设备，跳过 --dynamic（动态脱壳/抓包需真机）。")
            else:
                # base 透传：merge 重渲必须用与静态写出同一 base，否则静态写 <apk>.* 而
                # 重渲写 report.* 产两套报告。
                _run_dynamic_after_static(
                    str(apk), ctx.package_name or "", out, report, formats, base
                )
    finally:
        _close_ctx_quiet(ctx)  # IPA 的 ZipFile 句柄必须关（ApkContext 无 close 则 no-op）
        _cleanup_adb_quiet()


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
    # 抓包必经 adb（frida -U / mitmproxy 走设备），finally 收掉自起的 adb server。
    try:
        try:
            from apkscan.dynamic import capture as _capture
        except ImportError:
            typer.echo("该功能未安装：apkscan.dynamic.capture 不可用（动态抓包模块尚未就绪）。")
            raise typer.Exit(code=1) from None

        result = _capture.run(package, out=out, duration=duration)
        _print_dynamic_result("抓包", result)
    finally:
        _cleanup_adb_quiet()


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
    # doctor 体检会经 adb 探测设备/起 server，finally 收掉自起的 adb server。
    # 注意：doctor 给用户的 "adb kill-server && adb start-server" 是可复制的修复命令字符串
    # （结构化结果里的 fix_cmd），不是程序执行路径——本收尾不触碰它，语义不破坏。
    try:
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
    finally:
        _cleanup_adb_quiet()


@app.command()
def auto(
    apk: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="待分析的 APK 文件路径。",
    ),
    out: str = typer.Option("out", "--out", help="报告 / 产物输出目录。"),
    online: bool = typer.Option(
        True,
        "--online/--offline",
        help="静态分析是否联网富化归属（WHOIS/ICP/ASN）。默认联网（与 analyze 一致）；"
        "网络受限/不想等富化可加 --offline。",
    ),
    auto_fix: bool = typer.Option(
        True,
        "--fix/--no-fix",
        help="体检时对 frida-server / CA 等可自动修的项调 provision 自动修复（--no-fix 仅体检不动设备）。",
    ),
    duration: int = typer.Option(60, "--duration", help="抓包时长（秒）。"),
    fmt: str = typer.Option(
        "html,json",
        "--fmt",
        help="输出格式，逗号分隔：html,json,pdf。",
    ),
) -> None:
    """一键全自动：体检 → 静态分析 → 脱壳 → 抓包 → 合并，串成确定性流水线产出总报告。

    无设备时优雅跳过脱壳/抓包，仍产出静态报告。实现由 apkscan.dynamic.auto 提供
    （纯结构化返回 + 回调）；本命令是唯一打印 / 交互（提示操作 app）的薄包装。
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # auto 流水线含体检/脱壳/抓包，全经 adb；finally 收掉自起的 adb server。
    try:
        try:
            from apkscan.dynamic import auto as _auto
        except ImportError:
            typer.echo("该功能未安装：apkscan.dynamic.auto 不可用（一键全自动模块尚未就绪）。")
            raise typer.Exit(code=1) from None

        formats = _parse_formats(fmt)

        def _confirm(msg: str) -> None:
            """抓包前提示用户操作 app 触发网络，并等回车（CLI 落点；GUI 用弹窗）。

            确认提示只是「准备好就继续」的暂停闸（返回值本就不使用）。无 stdin / EOF /
            Ctrl-C 时 click.confirm 抛 Abort —— 这不是错误，直接继续抓包，不刷 ERROR+traceback。
            """
            typer.echo("")
            typer.echo(f">>> {msg}")
            try:
                typer.confirm("已准备好，开始抓包？", default=True)
            except (click.Abort, EOFError):
                typer.echo("（未读到输入，直接继续抓包）")

        typer.echo(f"===== 一键全自动：{apk} =====")
        result = _auto.run(
            str(apk),
            out_dir=out,
            online=online,
            auto_fix=auto_fix,
            capture_duration=duration,
            formats=formats,
            on_progress=lambda m: typer.echo(f"... {m}"),
            confirm=_confirm,
        )
        _print_auto_result(result)
    finally:
        _cleanup_adb_quiet()


@app.command()
def batch(
    folder: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="待扫描的文件夹：逐个分析其中**没分析过**的 APK（顶层 *.apk，不递归）。",
    ),
    out: str = typer.Option(
        "out_batch", "--out", help="批量输出根目录；每个 APK 落到 <out>/<名>__<sha8>/。"
    ),
    online: bool = typer.Option(
        True,
        "--online/--offline",
        help="静态分析是否联网富化归属（WHOIS/ICP/ASN）。默认联网（与 auto 一致）。",
    ),
    duration: int = typer.Option(30, "--duration", help="launch-only 抓包时长（秒）。"),
    fmt: str = typer.Option(
        "html,json", "--fmt", help="输出格式，逗号分隔：html,json,pdf。"
    ),
    force: bool = typer.Option(
        False, "--force", help="无视去重台账、文件夹内全部重跑。"
    ),
) -> None:
    """批量分析文件夹：扫描没分析过的 APK，逐个「静态 + launch-only 动态」产出报告。

    launch-only = 只启动 app 抓冷启动流量、不等人操作（需登录才出流量的 app 请在场时手动
    单跑 ``auto``）。有设备时每个 app 跑完自动 ``adb uninstall`` 收尾，保持设备干净。去重按
    APK 内容 sha256：同一样本改名也跳过；``--force`` 强制重跑。实现由 apkscan.dynamic.batch
    提供（纯结构化返回 + 回调），本命令是打印薄包装。
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # 批量逐个走 auto（含体检/脱壳/抓包），全经 adb；finally 收掉自起的 adb server。
    try:
        try:
            from apkscan.dynamic import batch as _batch
        except ImportError:
            typer.echo("该功能未安装：apkscan.dynamic.batch 不可用（批量分析模块尚未就绪）。")
            raise typer.Exit(code=1) from None

        formats = _parse_formats(fmt)
        typer.echo(f"===== 批量分析文件夹：{folder} =====")
        result = _batch.run_folder(
            str(folder),
            out_dir=out,
            online=online,
            capture_duration=duration,
            formats=formats,
            force=force,
            on_progress=lambda m: typer.echo(f"... {m}"),
        )
        _print_batch_result(result)
    finally:
        _cleanup_adb_quiet()


@app.command()
def export(
    report_json: Path = typer.Argument(
        ...,
        help="已产出的 report.json 路径（analyze/auto/batch 写出的 JSON 报告）。",
    ),
    out: str = typer.Option(
        "",
        "--out",
        help="导出的 CSV 路径。默认 = 与 report.json 同目录的 <base>.ioc.csv。",
    ),
    only_investigate: bool = typer.Option(
        False,
        "--only-investigate",
        help="只导 advice=建议调证 的线索（默认全导，但带 advice 列让下游自行过滤）。",
    ),
) -> None:
    """把 report.json 的线索导成扁平 IOC CSV，便于进 MISP/i2/Maltego 做跨案碰撞。

    薄包装：读 report.json → leads_to_ioc_rows → write_csv。绝不抛——读不到文件 / 坏 JSON
    都打印友好提示并退出码 1。CSV 为 UTF-8 with BOM（Excel 打开中文不乱码）。
    """
    import json as _json

    try:
        try:
            raw = report_json.read_text(encoding="utf-8")
        except FileNotFoundError:
            typer.echo(f"错误：找不到报告文件：{report_json}", err=True)
            raise typer.Exit(code=1) from None
        except OSError as exc:
            typer.echo(f"错误：读取报告文件失败：{report_json}（{exc}）", err=True)
            raise typer.Exit(code=1) from exc

        try:
            report = _json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            typer.echo(f"错误：报告 JSON 解析失败：{report_json}（{exc}）", err=True)
            raise typer.Exit(code=1) from exc

        from apkscan.report import ioc

        rows = ioc.leads_to_ioc_rows(report, only_investigate=only_investigate)

        # 默认 out = 与 report.json 同目录的 <base>.ioc.csv（base = 去掉 .json 后缀的名）。
        out_path = Path(out) if out else report_json.with_suffix("").with_suffix(".ioc.csv")
        if out_path.parent and not out_path.parent.exists():
            out_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            ioc.write_csv(rows, str(out_path))
        except OSError as exc:
            typer.echo(f"错误：写出 CSV 失败：{out_path}（{exc}）", err=True)
            raise typer.Exit(code=1) from exc

        scope = "（仅 建议调证）" if only_investigate else ""
        typer.echo(f"已导出 IOC CSV：{out_path}（{len(rows)} 行{scope}）")
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - 兜底任何意外，转友好提示而非 traceback
        logger.exception("[cli] export 导出 IOC CSV 异常")
        typer.echo(f"错误：导出失败：{exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command()
def gui() -> None:
    """启动新手友好的图形界面（tkinter 单窗口：环境体检 / 静态分析 / 一键全自动）。

    GUI 只是前端壳，复用同一套程序化核心（auto/doctor）。tkinter 不可用（极少数无
    GUI 的 Python）时打印提示并退出，不崩。
    """
    try:
        from apkscan.gui import main as _gui_main
    except Exception as exc:  # noqa: BLE001 - tkinter 缺失 / 导入异常都转友好提示
        logger.exception("启动 GUI 失败（tkinter 可能不可用）")
        typer.echo(f"无法启动图形界面（tkinter 可能不可用）：{exc}", err=True)
        raise typer.Exit(code=1) from exc
    _gui_main()


def _print_auto_result(result: object) -> None:
    """打印 auto.run 的结构化结果：逐步状态 + 报告路径。"""
    if not isinstance(result, dict):
        typer.echo("一键全自动：返回值非预期格式，已忽略。")
        return
    typer.echo("")
    typer.echo("===== 步骤摘要 =====")
    steps = result.get("steps") or []
    _tags = {"done": "[OK]  ", "skipped": "[SKIP]", "error": "[ERR] "}
    for step in steps:
        if not isinstance(step, dict):
            continue
        status = str(step.get("status", "?"))
        name = str(step.get("name", "?"))
        detail = str(step.get("detail", ""))
        tag = _tags.get(status, "[?]   ")
        typer.echo(f"{tag} {name}{('：' + detail) if detail else ''}")

    pkg = str(result.get("package_name") or "(未知)")
    out_dir = str(result.get("out_dir") or "")
    typer.echo("")
    typer.echo(f"包名：{pkg}  输出目录：{out_dir}")

    report_paths = result.get("report_paths") or []
    if report_paths:
        typer.echo(f"报告（{len(report_paths)}）：")
        for p in report_paths:
            typer.echo(f"  - {p}")
    else:
        typer.echo("未产出报告（详见步骤摘要）。")


def _print_batch_result(result: object) -> None:
    """打印 batch.run_folder 的结构化汇总：计数行 + 逐个 [OK]/[ERR]/[SKIP]。"""
    if not isinstance(result, dict):
        typer.echo("批量分析：返回值非预期格式，已忽略。")
        return
    summary = result.get("summary") or {}
    typer.echo("")
    typer.echo("===== 批量汇总 =====")
    had = "有" if summary.get("had_device") else "无（仅静态）"
    typer.echo(
        f"共 {summary.get('total', 0)} 个 · 分析 {summary.get('analyzed', 0)}"
        f" · 跳过 {summary.get('skipped', 0)} · 失败 {summary.get('failed', 0)} · 设备：{had}"
    )
    clusters = result.get("clusters") or []
    if clusters:
        typer.echo(f"团伙簇：{len(clusters)} 个（共享强指纹串并，详见 case_correlation.json）")
        for c in clusters:
            if not isinstance(c, dict):
                continue
            members = c.get("members") or []
            shared = c.get("shared") or []
            keys = "、".join(
                f"{s.get('kind')}={s.get('value')}" for s in shared[:3] if isinstance(s, dict)
            )
            typer.echo(f"  簇#{c.get('cluster_id')}：{len(members)} 个样本，并案依据：{keys}")
    for item in result.get("analyzed") or []:
        if isinstance(item, dict):
            typer.echo(f"[OK]   {item.get('apk')} → {item.get('out_dir')}")
    for item in result.get("failed") or []:
        if isinstance(item, dict):
            typer.echo(f"[ERR]  {item.get('apk')}：{item.get('detail')}")
    for item in result.get("skipped") or []:
        if isinstance(item, dict):
            typer.echo(f"[SKIP] {item.get('apk')}（已分析过）")


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
    apk_path: str, package: str, out: str, report: Report, formats: list[str], base: str
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

    _merge_runtime_into_report(capture_result, out, report, formats, base)


def _merge_runtime_into_report(
    capture_result: object, out: str, report: Report, formats: list[str], base: str
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
            base,
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


def _write_reports(report: Report, out_dir: Path, formats: list[str], base: str) -> None:
    """按 formats 写出报告，文件名用 ``base``（APK 名去后缀）：``<base>.{json,html,pdf}``。

    report.html / report.json 由其它 agent 实现。``runtime_report.json`` 不在此处写
    （那是 capture 的独立契约名）。
    """
    if "json" in formats:
        try:
            from apkscan.report import json as report_json

            path = out_dir / f"{base}.json"
            report_json.dump(report, str(path))
            typer.echo(f"已写出 JSON 报告：{path}")
        except Exception:
            logger.exception("写出 JSON 报告失败（report.json 模块可能尚未就绪）")

    html_path = out_dir / f"{base}.html"
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

            path = out_dir / f"{base}.pdf"
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
    # 入口先开 UTF-8 环境：修控制台中文乱码 + 让后续 adb/frida 子进程自动带 UTF-8
    # （Windows 默认 GBK，否则读子进程输出遇非 GBK 字节会崩）。
    from apkscan.core.logsetup import setup_logging
    from apkscan.core.utf8 import enable_utf8_runtime

    enable_utf8_runtime()
    # 装「错误定位标识」日志格式器（WARNING+ 末尾带 [@模块.函数:行号]，便于按日志反馈定位）。
    setup_logging()
    app()


if __name__ == "__main__":
    main()
