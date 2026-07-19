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
from apkscan.core.apk import load_apk
from apkscan.core.models import (
    ANALYSIS_MODE_PASSIVE,
    ANALYSIS_MODES,
    ANALYSIS_STATUS_COMPLETE,
    AnalysisConfig,
    LeadCategory,
    Report,
)
from apkscan.core.report_naming import report_base

# 图谱串案 / 追踪台账 / 样本库子命令已物理拆到 apkscan/commands/（纯搬移）；add_typer 留此处以引用主 app。
from apkscan.commands.corpus import corpus_app
from apkscan.commands.case import case_app, closure_exit_code
from apkscan.commands.graph import graph_app
from apkscan.commands.track import track_app

logger = logging.getLogger(__name__)

app = typer.Typer(
    add_completion=False,
    help="涉诈 APK 调证分析 CLI：静态分析 + 端点/服务归属提取，产出调证线索清单。",
)
app.add_typer(graph_app, name="graph")
app.add_typer(track_app, name="track")
app.add_typer(corpus_app, name="corpus")
app.add_typer(case_app, name="case")

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
    """涉诈 APK 调证分析 CLI。"""


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


def _adb_owned_at_start() -> bool:
    """命令**起手**判本次 adb server 是否归本进程收：起手时无 server 在跑 → 本次动态动作会起
    一个、归我们收（True）；起手时已有 server（外部 / 先前已在跑，可能仍要用于 pull）→ 不归我们、
    收尾不杀（False）。惰性 import、绝不抛（探测失败保守视作外部、不杀）。
    """
    try:
        from apkscan.core import tools

        return not tools.adb_server_running()
    except Exception:
        logger.exception("[cli] 判定 adb server 归属失败（保守：收尾不杀）")
        return False


def _cleanup_adb_quiet(owned: bool = True) -> None:
    """命令收尾：**仅当本次进程自起**的 adb server（owned=True）才收掉（惰性 import tools，绝不抛）。

    adb server 是 adb 全局单例：analyze 的设备探测、doctor/auto/capture 的动态动作都会经 adb 起
    一个常驻 server。GUI 分析走子进程，退出时若不收、adb.exe 残留下次重打 exe 被锁——故收尾要收。
    但 ★P0-5：``owned=False``（命令起手时已有外部 / 先前 server 在跑，可能仍要用于 pull）时**绝不杀**，
    避免误杀外部或仍在 pull 落盘 floor.pcap 的 adb。kill-server 幂等、仅在 adb 可用时执行。
    """
    if not owned:
        logger.info("[cli] adb server 起手时已存在（外部/先前），收尾不杀（避免误杀外部或正在 pull 的 adb）")
        return
    try:
        from apkscan.core import tools

        tools.kill_adb_server()
    except Exception:
        logger.exception("[cli] 收尾清理 adb server 失败（已忽略）")


def _resolve_out(out: str | None, apk: Path) -> str:
    """输出目录解析：显式 --out 原样用（相对则相对 cwd）；未给 --out 时默认落到 **APK 同目录**
    下的 ``out/``。

    动机：旧默认是相对当前工作目录的 ``"out"``——从哪个目录跑就把 out/ 建在哪、GUI/auto 下 cwd
    还不可预测，产物散落（"建在错的位置"）。默认跟着样本走最可预测。
    """
    if out is not None:
        return out
    return str(apk.resolve().parent / "out")


def _resolve_out_cwd(out: str | None) -> str:
    """无样本文件命令（capture）的输出目录解析：统一绝对化到 **当前工作目录** 基准。

    动机：capture 只有包名、没有样本文件路径，无法像 analyze/unpack 那样落到「样本同目录」。
    旧默认是相对 cwd 的裸字符串 ``"out"``——从哪跑就散在哪、GUI/auto 下 cwd 不可预测。这里把
    未给 / 相对的 out 都解析成绝对路径（口径确定、可预测），与 analyze/unpack「产物落点确定」
    的精神一致，只是基准是 cwd（capture 无样本可依）。
    """
    return str((Path(out) if out else Path("out")).resolve())


def _raise_exit_for_status(status: object) -> None:
    """按 DynamicResult 的 status 决定命令退出码：

    - ``STATUS_ERROR`` → ``typer.Exit(1)``（执行出错）；
    - ``STATUS_SKIPPED`` → ``typer.Exit(2)``（缺 frida/mitmproxy/root 等前置 → 零产出高发场景，
      与 error 分开，便于调用方/脚本区分「跑错了」与「没跑起来」）；
    - ``STATUS_DEGRADED`` → ``typer.Exit(3)``（抓包跑完但无任何证据路径：代理未起/MITM 0 字节/
      floor 未拉回/端点 0 → 脚本调用方不能当成功，独立码便于区分「降级无产出」）；
    - 其它（done/未知）→ 不抛，正常返回 0。
    """
    from apkscan.dynamic import STATUS_DEGRADED, STATUS_ERROR, STATUS_SKIPPED

    if status == STATUS_ERROR:
        raise typer.Exit(code=1)
    if status == STATUS_SKIPPED:
        raise typer.Exit(code=2)
    if status == STATUS_DEGRADED:
        raise typer.Exit(code=3)


def _strict_exit_code(report: Report) -> int | None:
    """analyze --strict 的退出码判定（与 capture 的 _raise_exit_for_status 是不同命令、各自命名空间）：

    - 关键分析器失败（report.critical_failures 非空）→ 4（报告核心不可信）；
    - 其它不完整（analysis_status != complete，即 partial/failed）→ 3；
    - 完整 → None（调用方退 0）。

    纯函数，便于单测；analyze 仅在 --strict 时消费其结果。
    """
    if report.critical_failures:
        return 4
    if report.analysis_status != ANALYSIS_STATUS_COMPLETE:
        return 3
    return None


def _validate_mode(mode: str) -> None:
    """校验 --mode 值合法（analyze / auto / batch 共用）；非法值 → typer.Exit(2)。"""
    if mode not in ANALYSIS_MODES:
        typer.echo(
            f"错误：--mode 只能是 {' | '.join(ANALYSIS_MODES)}（收到 {mode!r}）", err=True
        )
        raise typer.Exit(code=2)


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
    out: str | None = typer.Option(None, "--out", help="报告输出目录（默认：APK 同目录下的 out/）。"),
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
    track: bool = typer.Option(
        True,
        "--track/--no-track",
        help="写报告后自动把线索入追踪台账（+喂案件图谱）。默认开；--no-track 关闭。",
    ),
    mode: str = typer.Option(
        ANALYSIS_MODE_PASSIVE,
        "--mode",
        help=(
            "网络模式：passive（默认，只跑被动 OSINT 富化、对目标零流量）| "
            "authorized-active（显式授权下才放行会向目标 / 其基础设施发起请求的动作："
            "下载样本引用的远程配置对象、Telegram getMe 在线核验等）。"
        ),
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help=(
            "严格模式：分析不完整时非零退出（关键分析器失败=退出码 4，其它分析器报错=3）。"
            "默认关（尽力而为、退出码 0），适合 CI / 批量 / Agent 判定。"
        ),
    ),
) -> None:
    """分析一个 APK 并产出报告。"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # 无条件 finally 收 adb server：analyze 的 device.has_device() 设备探测每次都会经
    # adb 起一个常驻 adb server（即便纯静态/离线），不收则 adb.exe 残留（GUI 子进程尤甚）。
    _adb_owned = _adb_owned_at_start()  # ★P0-5：起手判 adb server 归属（外部/先前存在则收尾不杀）
    try:
        formats = _parse_formats(fmt)
        _validate_mode(mode)
        out = _resolve_out(out, apk)  # 未给 --out → 默认落到 APK 同目录下的 out/
        config = AnalysisConfig(online=online, out_dir=out, formats=formats, mode=mode)

        extra_dex_files = _resolve_extra_dex(extra_dex)
        if extra_dex_files:
            typer.echo(f"额外 DEX：{len(extra_dex_files)} 个并入静态分析")

        typer.echo(f"加载：{apk}")
        try:
            ctx = load_apk(str(apk), config, extra_dex=extra_dex_files or None)
        except ApkParseError as exc:
            typer.echo(f"错误：{exc}", err=True)
            raise typer.Exit(code=2) from exc

        typer.echo(f"包名：{ctx.package_name or '(未知)'}  联网富化：{'是' if online else '否'}")
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

        # 取证完整性背书：检材指纹（多算法 + 分析环境）落 meta["evidence_manifest"]，
        # 并把 sha256 提到顶层快捷键 meta["sample_sha256"]（CSV 导出 / 团伙聚类已预留引用）。
        # 纯函数容错、绝不抛；外层仍包 try 兜底任何意外，失败只 logging 不炸 analyze。
        try:
            from apkscan import __version__
            from apkscan.core.integrity import sample_fingerprint

            manifest = sample_fingerprint(str(apk), tool_version=__version__)
            report.meta["evidence_manifest"] = manifest
            report.meta["sample_sha256"] = manifest.get("sha256", "")
        except Exception:
            logger.exception("[cli] 写入取证完整性元数据失败（已忽略，不影响报告产出）")

        # 设备探测：有在线设备则提示并写入 meta，便于报告/后续动态补全感知。
        device_detected = device.has_device()
        if device_detected:
            report.meta["device_detected"] = True
            typer.echo("检测到在线 adb 设备：可用 --dynamic 做真机脱壳/抓包补全静态盲区。")

        # 报告文件名 base：用 APK 文件名去后缀（清理非法字符），空/异常回退包名再回退 report。
        base = report_base(str(apk), ctx.package_name or "")

        out_dir = Path(out)
        out_dir.mkdir(parents=True, exist_ok=True)
        _write_reports(report, out_dir, formats, base)

        _print_summary(report)

        # 自动入账 + 喂图谱（best-effort 旁路，绝不影响已产出报告）。默认开，--no-track 关。
        # 报告路径用主 JSON 报告（<base>.json，溯源用）；台账主键是 sha256，路径仅展示。
        _auto_track(report, str(out_dir / f"{base}.json"), track=track)

        # --dynamic：静态完成后，若有设备则自动 unpack + capture（实现由 dynamic 模块 agent 完成）。
        if dynamic:
            if not device_detected:
                typer.echo("未检测到在线设备，跳过 --dynamic（动态脱壳/抓包需真机）。")
            else:
                # base 透传：merge 重渲必须用与静态写出同一 base，否则静态写 <apk>.* 而
                # 重渲写 report.* 产两套报告。
                _run_dynamic_after_static(
                    str(apk), ctx.package_name or "", out, report, formats, base, track=track
                )

        # --strict：所有工作（写报告 / 入账 / 动态）完成后，据完整度决定退出码，供 CI / Agent 判定。
        # 非严格默认退 0（尽力而为，向后兼容）。退出穿过 finally 正常收尾（与 capture 同范式）。
        if strict:
            code = _strict_exit_code(report)
            if code is not None:
                typer.echo(
                    f"[strict] 分析不完整：status={report.analysis_status}"
                    f"，completeness={report.completeness}"
                    f"，critical_failures={report.critical_failures}",
                    err=True,
                )
                raise typer.Exit(code=code)
    finally:
        _cleanup_adb_quiet(_adb_owned)


def _report_dict_for(path: Path, *, online: bool) -> dict:
    """把 diff 的一个参数解析成 report dict：``.json`` → 直接读；否则当 APK → 现分析成报告 dict。

    JSON 读取 / APK 解析失败 → 友好报错 + 非零退出（3=坏输入 JSON，2=APK 解析失败），不打 traceback。
    """
    import json as _json

    if path.suffix.lower() == ".json":
        try:
            # parse_constant：把 NaN/Infinity（json.loads 默认接受、但非 RFC-8259 合法）归一化为
            # None，保证 diff/jsonl 后续 dumps 出的每行都是严格合法 JSON（jq / JSON.parse 不炸）。
            data = _json.loads(path.read_text(encoding="utf-8"), parse_constant=lambda _c: None)
        except Exception as exc:  # noqa: BLE001 — 坏 JSON → 友好报错而非 traceback
            typer.echo(f"错误：无法读取报告 JSON：{path}（{exc}）", err=True)
            raise typer.Exit(code=3) from exc
        return data if isinstance(data, dict) else {}

    # 非 .json → 当 APK 现分析（离线默认：diff 通常不需联网富化，也让结果确定/快）。
    from apkscan.core import pipeline
    from apkscan.report import json as report_json

    config = AnalysisConfig(online=online, out_dir=str(path.parent), formats=[])
    try:
        ctx = load_apk(str(path), config)
    except ApkParseError as exc:
        typer.echo(f"错误：{exc}", err=True)
        raise typer.Exit(code=2) from exc
    report = pipeline.run(ctx, config)  # type: ignore[arg-type]
    data = report_json.to_dict(report)
    # ★现算 sample_sha256 填回 meta：pipeline.run 不算它（只 analyze 的证据 manifest 步骤算），
    #   否则 `diff old.json new.apk` 会报虚假的 sample_sha256 变化（旧有哈希、新为 None）。
    meta = data.get("meta")
    if isinstance(meta, dict) and not meta.get("sample_sha256"):
        digest = _file_sha256(path)
        if digest:
            meta["sample_sha256"] = digest
    return data


def _file_sha256(path: Path) -> str:
    """流式算文件 sha256（大文件不占内存）。读失败 → 空串（不抛，diff 不因哈希失败中断）。"""
    import hashlib

    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        logger.warning("[cli] 算 sample_sha256 失败（已忽略）：%s", path, exc_info=True)
        return ""


@app.command()
def diff(
    old: Path = typer.Argument(..., exists=True, help="旧版：report.json 或 APK。"),
    new: Path = typer.Argument(..., exists=True, help="新版：report.json 或 APK。"),
    online: bool = typer.Option(
        False,
        "--online/--offline",
        help="参数是 APK 时是否联网富化（默认离线：diff 通常只看结构变化、更快更确定）。",
    ),
) -> None:
    """对比两份分析结果，输出**调证增量**的稳定 JSON：新增 / 删除的线索、端点、发现，加身份 /
    加固 / 分类变化。每个参数可是 report.json（直接读）或 APK（现分析）——适合追踪同一 App 跨版本
    新增了哪些支付通道 / 钱包 / 后台入口、加固是否升级、SDK 是否变了。
    """
    import json as _json

    from apkscan.core.diff import diff_reports

    old_dict = _report_dict_for(old, online=online)
    new_dict = _report_dict_for(new, online=online)
    typer.echo(_json.dumps(diff_reports(old_dict, new_dict), ensure_ascii=False, indent=2))


@app.command()
def jsonl(
    report: Path = typer.Argument(..., exists=True, dir_okay=False, help="report.json 路径。"),
) -> None:
    """把 report.json 摊成 **JSONL 事件流**（每行一个 JSON：1 条 meta 头 + 每条线索 / 发现一个事件），
    供 AI agent / 脚本逐条流式消费——据 finding 的 confidence/kind/analyzer 加权、逐条串案、生成文书，
    无需先解析整份嵌套报告。坏 JSON → 退出码 3。
    """
    import json as _json

    from apkscan.core.jsonl import report_to_events

    try:
        # parse_constant：NaN/Infinity → None，保证每行输出严格合法 JSON（见 _report_dict_for）。
        data = _json.loads(report.read_text(encoding="utf-8"), parse_constant=lambda _c: None)
    except Exception as exc:  # noqa: BLE001 — 坏 JSON → 友好报错而非 traceback
        typer.echo(f"错误：无法读取报告 JSON：{report}（{exc}）", err=True)
        raise typer.Exit(code=3) from exc
    for event in report_to_events(data):
        typer.echo(_json.dumps(event, ensure_ascii=False))


@app.command()
def unpack(
    apk: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="待脱壳的 APK 文件路径。",
    ),
    out: str | None = typer.Option(None, "--out", help="产物 / 报告输出目录（默认：APK 同目录下的 out/）。"),
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

    out = _resolve_out(out, apk)  # 未给 --out → 默认落到 APK 同目录下的 out/
    result = _unpack.run(str(apk), out=out, reanalyze=reanalyze)
    _print_dynamic_result("脱壳", result)
    # 业务失败返回非零退出码：error→1 / skipped（缺 root/frida 等前置）→2，正常→0。
    _raise_exit_for_status(result.get("status") if isinstance(result, dict) else None)


@app.command()
def repackage(
    apk: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="原 APK 路径（以它为基底替换脱壳 DEX 重打包）。",
    ),
    out: str | None = typer.Option(None, "--out", help="产物目录（脱壳 DEX 取自 <out>/dump；默认 APK 同目录 out/）。"),
) -> None:
    """脱壳后重打包出去壳 APK 并装回设备，使其能被重新动态抓包（绕加固壳反 frida）。

    前置：先 unpack 出脱壳 DEX（落 <out>/dump）+ apksigner/zipalign + 在线设备。需 unpack
    先成功；缺工具/设备则 skipped 给手册。实现由 apkscan.dynamic.repackage 提供，未安装优雅退出。
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        from apkscan.dynamic import repackage as _repackage
    except ImportError:
        typer.echo("该功能未安装：apkscan.dynamic.repackage 不可用。")
        raise typer.Exit(code=1) from None

    out = _resolve_out(out, apk)  # 未给 --out → 默认落到 APK 同目录下的 out/
    result = _repackage.run(str(apk), out=out)
    _print_dynamic_result("去壳重打包", result)
    # 业务失败返回非零退出码：error→1 / skipped（缺 unpack 产物/apksigner/设备）→2，正常→0。
    _raise_exit_for_status(result.get("status") if isinstance(result, dict) else None)


@app.command()
def capture(
    package: str = typer.Argument(..., help="目标应用包名（在设备上运行/抓包）。"),
    out: str | None = typer.Option(
        None, "--out", help="产物 / 报告输出目录（默认：当前目录下的 out/，绝对化）。"
    ),
    duration: int = typer.Option(60, "--duration", min=1, help="抓包时长（秒，下限 1）。"),
    serial: str | None = typer.Option(
        None, "--serial", help="目标设备 serial（多设备/一机多 transport 时钉定那台；不给则 -U/自动）。"
    ),
    mode: str = typer.Option(
        "both",
        "--mode",
        help="抓包模式：both（默认，mitm 明文 + 带外 pcap）/ floor-only（不设代理、只带外抓，加固 IM/反 frida 更稳）/ mitm-only（不起 floor）。",
    ),
) -> None:
    """真机抓包：对运行中的目标应用做流量抓取，提取动态端点。

    实现由 apkscan.dynamic.capture 提供；未安装时打印提示并退出，不崩。业务失败按 status
    返回非零退出码（error→1 / skipped→2），便于脚本区分「跑错了」与「缺前置没跑起来」。
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # 抓包必经 adb（frida -U / mitmproxy 走设备），finally 收掉自起的 adb server。
    _adb_owned = _adb_owned_at_start()  # ★P0-5：起手判 adb server 归属（外部/仍在 pull 则收尾不杀）
    try:
        try:
            from apkscan.dynamic import capture as _capture
        except ImportError:
            typer.echo("该功能未安装：apkscan.dynamic.capture 不可用（动态抓包模块尚未就绪）。")
            raise typer.Exit(code=1) from None

        if mode not in ("both", "floor-only", "mitm-only", "no-proxy"):
            typer.echo(f"--mode 取值非法：{mode!r}（可选 both / floor-only / mitm-only）")
            raise typer.Exit(code=2)
        out = _resolve_out_cwd(out)  # 未给 / 相对 → 绝对化到 cwd 下的 out/（口径确定）
        result = _capture.run(package, out=out, duration=duration, serial=serial, mode=mode)
        _print_dynamic_result("抓包", result)
        # 业务失败返回非零退出码（在 adb 清理 finally 之前抛，仍会穿过 finally 收 server）。
        _raise_exit_for_status(result.get("status") if isinstance(result, dict) else None)
    finally:
        _cleanup_adb_quiet(_adb_owned)


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
    profile: str = typer.Option(
        "full",
        "--profile",
        help="体检 profile：full（默认，完整抓包栈）| floor-only（只体检 floor pcap 底座 设备+root+tcpdump，"
        "缺 frida/mitmproxy/CA 仍体检但不判环境失败——PCAP-first 只想 tcpdump 抓包时用）。",
    ),
) -> None:
    """动态抓包/脱壳前置环境体检：设备/root/ABI/frida/mitmproxy/CA，逐项给出状态与可复制命令。

    实现由 apkscan.dynamic.doctor 提供（纯结构化返回）；本命令是唯一打印体检结果的薄包装。
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # doctor 体检会经 adb 探测设备/起 server，finally 收掉自起的 adb server。
    # 注意：doctor 给用户的 "adb kill-server && adb start-server" 是可复制的修复命令字符串
    # （结构化结果里的 fix_cmd），不是程序执行路径——本收尾不触碰它，语义不破坏。
    _adb_owned = _adb_owned_at_start()  # ★P0-5：起手判 adb server 归属（外部/先前存在则收尾不杀）
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
            profile=profile,
            on_progress=lambda m: typer.echo(f"... {m}"),
        )
        _print_doctor_result(result)
        if not result.get("ok", False):
            raise typer.Exit(code=1)
    finally:
        _cleanup_adb_quiet(_adb_owned)


@app.command()
def auto(
    apk: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="待分析的 APK 文件路径。",
    ),
    out: str | None = typer.Option(None, "--out", help="报告 / 产物输出目录（默认：APK 同目录下的 out/）。"),
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
    duration: int = typer.Option(60, "--duration", min=1, help="抓包时长（秒，下限 1）。"),
    fmt: str = typer.Option(
        "html,json",
        "--fmt",
        help="输出格式，逗号分隔：html,json,pdf。",
    ),
    track: bool = typer.Option(
        True,
        "--track/--no-track",
        help="静态分析写报告后自动把线索入追踪台账（+喂案件图谱）。默认开；--no-track 关闭。",
    ),
    repackage: bool = typer.Option(
        True,
        "--repackage/--no-repackage",
        help="脱壳后把去壳版重打包装回设备供 capture 抓（绕壳反 frida）。默认开；"
        "--no-repackage 关（重签必卸原包会清 app 数据/登录态）。",
    ),
    strict_case: bool = typer.Option(
        False,
        "--strict-case/--no-strict-case",
        help="按案件闭环状态返回退出码：complete=0、partial=5、failed=6。默认只报告状态。",
    ),
    mode: str = typer.Option(
        ANALYSIS_MODE_PASSIVE,
        "--mode",
        help="网络模式：passive（默认，静态富化只跑被动 OSINT）| authorized-active（显式授权下才放行会向目标发起请求的动作，如远程配置对象下载、Telegram getMe 核验）。",
    ),
) -> None:
    """一键全自动：体检 → 静态分析 → 脱壳 → 抓包 → 合并 → 案件闭环。

    无设备时优雅跳过脱壳/抓包，仍产出静态报告。实现由 apkscan.dynamic.auto 提供
    （纯结构化返回 + 回调）；本命令是唯一打印 / 交互（提示操作 app）的薄包装。
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # auto 流水线含体检/脱壳/抓包，全经 adb；finally 收掉自起的 adb server。
    _adb_owned = _adb_owned_at_start()  # ★P0-5：起手判 adb server 归属（外部/先前存在则收尾不杀）
    try:
        try:
            from apkscan.dynamic import auto as _auto
        except ImportError:
            typer.echo("该功能未安装：apkscan.dynamic.auto 不可用（一键全自动模块尚未就绪）。")
            raise typer.Exit(code=1) from None

        formats = _parse_formats(fmt)
        _validate_mode(mode)

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

        out = _resolve_out(out, apk)  # 未给 --out → 默认落到 APK 同目录下的 out/
        typer.echo(f"===== 一键全自动：{apk} =====")
        result = _auto.run(
            str(apk),
            out_dir=out,
            online=online,
            auto_fix=auto_fix,
            capture_duration=duration,
            formats=formats,
            track=track,
            mode=mode,
            repackage=repackage,
            strict_case=strict_case,
            on_progress=lambda m: typer.echo(f"... {m}"),
            confirm=_confirm,
        )
        _print_auto_result(result)
        if strict_case:
            status = result.get("status") if isinstance(result, dict) else "failed"
            code = closure_exit_code(status)
            if code:
                raise typer.Exit(code=code)
    finally:
        _cleanup_adb_quiet(_adb_owned)


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
    duration: int = typer.Option(30, "--duration", min=1, help="launch-only 抓包时长（秒，下限 1）。"),
    fmt: str = typer.Option(
        "html,json", "--fmt", help="输出格式，逗号分隔：html,json,pdf。"
    ),
    force: bool = typer.Option(
        False, "--force", help="无视去重台账、文件夹内全部重跑。"
    ),
    mode: str = typer.Option(
        ANALYSIS_MODE_PASSIVE,
        "--mode",
        help="网络模式：passive（默认，静态富化只跑被动 OSINT）| authorized-active（显式授权下才放行会向目标发起请求的动作，如远程配置对象下载、Telegram getMe 核验）。",
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
    _adb_owned = _adb_owned_at_start()  # ★P0-5：起手判 adb server 归属（外部/先前存在则收尾不杀）
    try:
        try:
            from apkscan.dynamic import batch as _batch
        except ImportError:
            typer.echo("该功能未安装：apkscan.dynamic.batch 不可用（批量分析模块尚未就绪）。")
            raise typer.Exit(code=1) from None

        formats = _parse_formats(fmt)
        _validate_mode(mode)
        typer.echo(f"===== 批量分析文件夹：{folder} =====")
        result = _batch.run_folder(
            str(folder),
            out_dir=out,
            online=online,
            capture_duration=duration,
            formats=formats,
            force=force,
            mode=mode,
            on_progress=lambda m: typer.echo(f"... {m}"),
        )
        _print_batch_result(result)
    finally:
        _cleanup_adb_quiet(_adb_owned)


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
def digest(
    report_json: Path = typer.Argument(
        ...,
        help="已产出的 report.json 路径（analyze/auto/batch 写出的 JSON 报告）。",
    ),
    redact: bool = typer.Option(
        False,
        "--redact",
        help="脱敏高敏值（钱包私钥/助记词、后端凭据、受害人 PII、加密配方）——喂云端 agent 时用；默认明文，便于取证查看。",
    ),
) -> None:
    """把 report.json 压成**紧凑调证摘要 JSON** 打印到 stdout（供任意 AI agent（Codex/Claude 等）/ 脚本低 token 消费）。

    线索按优先级排序（建议调证 > 待核 > 无需调证；同档高可信、C2 在前），只保留可办案化的扁平
    字段 + 计数摘要，去掉端点全表 / 技术附录 / 富化原始数据等冗长内容。绝不抛——读不到 / 坏 JSON
    打印友好错误并退出码 1。
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

        from apkscan.report.digest import build_digest

        typer.echo(_json.dumps(build_digest(report, redact=redact), ensure_ascii=False, indent=2))
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - 兜底任何意外，转友好提示而非 traceback
        logger.exception("[cli] digest 生成摘要异常")
        typer.echo(f"错误：生成摘要失败：{exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command()
def selfcheck(
    online: bool = typer.Option(
        True, "--online/--offline", help="是否探测联网富化就绪度。"
    ),
    probe: bool = typer.Option(
        True, "--probe/--no-probe", help="是否实际发起网络探测；--no-probe 只看配置。"
    ),
) -> None:
    """自检诊断：逐项报告**哪个能力通 / 不通 / 怎么修**，输出稳定 JSON（供任意 AI agent 驱动前自检）。

    覆盖：核心、可选依赖（图谱 kuzu / 解密）、外部工具（jadx/adb）、动态（frida/mitmproxy/设备）、
    联网富化。每项给 status（ok/missing/disabled/unreachable）+ 一句话修复指引。绝不抛。
    """
    import json as _json

    from apkscan.selfcheck import run_selfcheck

    typer.echo(
        _json.dumps(run_selfcheck(online=online, probe_network=probe), ensure_ascii=False, indent=2)
    )


@app.command()
def letters(
    report_json: Path = typer.Argument(
        ...,
        help="已产出的 report.json 路径（analyze/auto/batch 写出的 JSON 报告）。",
    ),
    out: str = typer.Option(
        "",
        "--out",
        help="文书输出目录（其下生成 letters/ 子目录）。默认 = report.json 同目录。",
    ),
) -> None:
    """把 report.json 的可办案化线索套打成「调证函 / 协查文书」草稿（markdown）。

    薄包装：读 report.json → build_letters → write_letters。只对建议调证、有可调取证据、
    且 where_to_request 为真实受文机关的线索成文（证书指纹/解密配方等占位 Lead 自动跳过）。
    绝不抛——读不到文件 / 坏 JSON 都打印友好提示并退出码 1。每份文书顶部带免责声明草稿标注。
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

        from apkscan.report import letters as letters_mod

        drafts = letters_mod.build_letters(report)

        # 默认 out = report.json 同目录（其下再建 letters/ 子目录）。
        out_dir = out or str(report_json.parent)
        try:
            paths = letters_mod.write_letters(drafts, out_dir)
        except OSError as exc:
            typer.echo(f"错误：写出文书失败：{out_dir}（{exc}）", err=True)
            raise typer.Exit(code=1) from exc

        letters_dir = Path(out_dir) / "letters"
        typer.echo(f"已生成 {len(drafts)} 份调证 / 协查文书草稿：{letters_dir}（含 index.md）")
        if not drafts:
            typer.echo("提示：本样本无可套打的调证线索（仅生成空索引 index.md）。")
        else:
            logger.info("[cli] letters 写出 %d 个文件", len(paths))
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - 兜底任何意外，转友好提示而非 traceback
        logger.exception("[cli] letters 套打调证文书异常")
        typer.echo(f"错误：套打失败：{exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command(name="probe-leads")
def probe_leads(
    log: Path = typer.Argument(..., help="frida 探针日志（`frida -o probe.log` 的 console 输出）。"),
    md: str = typer.Option("", "--md", help="台账 markdown 输出路径（默认打到终端）。"),
    json_out: str = typer.Option("", "--json", help="台账 JSON 输出路径（程序化消费/入图）。"),
    into: str = typer.Option("", "--into", help="把线索追加进已有 report.json 的 leads（去重）。"),
) -> None:
    """把 46 个独立探针(`-l` 注入)散落的 `[LEAD]` 输出聚成**调证台账**，并可回灌进 report.json。

    薄包装：读探针日志 → parse_probe_log（按 LeadCategory 分类+where_to_request）→ 去重 →
    build_ledger_md / to_ledger_dict / merge_into_report_json。绝不抛——读不到 / 坏文件打印
    友好提示并退出码 1。线索带合规提示（含高敏个人信息按办案合规留存处置）。
    """
    import json as _json

    try:
        try:
            text = log.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            typer.echo(f"错误：找不到探针日志：{log}", err=True)
            raise typer.Exit(code=1) from None
        except OSError as exc:
            typer.echo(f"错误：读取探针日志失败：{log}（{exc}）", err=True)
            raise typer.Exit(code=1) from exc

        from apkscan.dynamic import probe_ingest

        leads = probe_ingest.dedup(probe_ingest.parse_probe_log(text))
        typer.echo(f"解析出 {len(leads)} 条去重调证线索。")

        ledger_md = probe_ingest.build_ledger_md(leads)
        if md:
            try:
                Path(md).write_text(ledger_md, encoding="utf-8")
                typer.echo(f"台账(markdown) → {md}")
            except OSError as exc:
                typer.echo(f"错误：写台账失败：{md}（{exc}）", err=True)
                raise typer.Exit(code=1) from exc
        if json_out:
            try:
                Path(json_out).write_text(
                    _json.dumps(probe_ingest.to_ledger_dict(leads), ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                typer.echo(f"台账(JSON) → {json_out}")
            except OSError as exc:
                typer.echo(f"错误：写台账 JSON 失败：{json_out}（{exc}）", err=True)
                raise typer.Exit(code=1) from exc
        if into:
            added = probe_ingest.merge_into_report_json(into, leads)
            typer.echo(f"已追加 {added} 条探针线索进 {into}（去重）。")
            # report.json 被改后，若同目录有 report.html 则重渲，让人读报告随台账更新。
            rerendered = _rerender_html_if_present(into)
            if rerendered:
                typer.echo(f"已重渲 HTML 报告：{rerendered}")
        if not (md or json_out or into):
            typer.echo("")
            typer.echo(ledger_md)
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - 兜底任何意外，转友好提示而非 traceback
        logger.exception("[cli] probe-leads 聚合台账异常")
        typer.echo(f"错误：聚合台账失败：{exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command(name="pcap-leads")
def pcap_leads(
    pcap: Path = typer.Argument(..., help="带外抓的 pcap/pcapng（网关 tcpdump / PCAPdroid 免 root 导出 / Wireshark）。"),
    md: str = typer.Option("", "--md", help="台账 markdown 输出路径（默认打到终端）。"),
    json_out: str = typer.Option("", "--json", help="台账 JSON 输出路径（程序化消费）。"),
    into: str = typer.Option("", "--into", help="把线索追加进已有 report.json 的 leads（去重）。"),
) -> None:
    """从**带外 pcap** 抽接入节点 IP:port + TLS SNI + DNS + JA3 → 调证台账，可回灌 report.json。

    针对反分析涉诈 App：即便 TLS 解不开、走 MTProto/native 自建协议（普通抓包 endpoint=0），
    带外抓的 pcap 里仍有真实接入节点 IP/SNI——这就是穿透真源站的调证锚点。纯标准库解析，绝不抛。
    """
    import json as _json

    try:
        from apkscan.core.models import LeadCategory
        from apkscan.dynamic import pcap_ingest

        summary = pcap_ingest.parse_pcap(str(pcap))
        leads = pcap_ingest.to_report_leads(summary)
        n_ip = sum(1 for lead in leads if lead.category == LeadCategory.IP)
        n_dom = sum(1 for lead in leads if lead.category == LeadCategory.DOMAIN)
        typer.echo(
            f"解析出 {len(summary.flows)} 条流、{n_ip} 个公网接入节点、{n_dom} 个域名、"
            f"{len(summary.dns_queries)} 条 DNS 查询。"
        )
        if getattr(summary, "parse_status", "ok") != "ok":
            typer.echo(
                f"警告：pcap 解析未成功（{summary.parse_status}：{summary.error}）——"
                "空结果**不代表零流量**，请核对文件完整性/格式后重抓。",
                err=True,
            )
        elif not summary.flows and not summary.dns_queries:
            typer.echo("提示：没解析出流量——确认是 pcap/pcapng、且为 Ethernet/RAW/Linux-SLL 链路（pcapng 也支持）。")

        ledger = pcap_ingest.build_ledger_md(summary)
        if md:
            try:
                Path(md).write_text(ledger, encoding="utf-8")
                typer.echo(f"台账(markdown) → {md}")
            except OSError as exc:
                typer.echo(f"错误：写台账失败：{md}（{exc}）", err=True)
                raise typer.Exit(code=1) from exc
        if json_out:
            try:
                Path(json_out).write_text(
                    _json.dumps(pcap_ingest.to_ledger_dict(summary), ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                typer.echo(f"台账(JSON) → {json_out}")
            except OSError as exc:
                typer.echo(f"错误：写台账 JSON 失败：{json_out}（{exc}）", err=True)
                raise typer.Exit(code=1) from exc
        if into:
            added = pcap_ingest.merge_into_report_json(into, summary)
            typer.echo(f"已追加 {added} 条带外线索进 {into}（去重）。")
            # report.json 被改后，若同目录有 report.html 则重渲，让人读报告随台账更新。
            rerendered = _rerender_html_if_present(into)
            if rerendered:
                typer.echo(f"已重渲 HTML 报告：{rerendered}")
        if not (md or json_out or into):
            typer.echo("")
            typer.echo(ledger)
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - 兜底任何意外，转友好提示而非 traceback
        logger.exception("[cli] pcap-leads 聚合台账异常")
        typer.echo(f"错误：聚合台账失败：{exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command(name="capture-plan")
def capture_plan_cmd(
    report_json: Path = typer.Argument(..., help="已产出的 report.json（analyze/auto 写出）。"),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="输出机器可读的结构化决策（CaptureDecision：floor 优先 / 秒退阈值 / 总预算 / 信号），供引擎或 Codex 消费，而非人读文本步骤。",
    ),
) -> None:
    """据静态报告的规避信号（加固/endpoint数/加密配方/自建IM），输出**针对该样本的抓包打法**。

    薄包装：读 report.json → capture_plan.plan_capture → 打印有序步骤（起手式带外 pcap 保底 → 按
    规避类型选 frida unpinning / 静态去 pin / pcap-leads / 专项探针）。绝不抛——读不到/坏 JSON
    打印友好提示并退出码 1。供办案人/Codex 决定"这个样本该怎么抓"。``--json`` 则改出与文本同源的
    结构化决策（decide_capture），供自动编排读。
    """
    import json as _json

    try:
        try:
            raw = report_json.read_text(encoding="utf-8")
        except FileNotFoundError:
            typer.echo(f"错误：找不到报告文件：{report_json}", err=True)
            raise typer.Exit(code=1) from None
        except OSError as exc:
            typer.echo(f"错误：读取报告失败：{report_json}（{exc}）", err=True)
            raise typer.Exit(code=1) from exc
        try:
            report = _json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            typer.echo(f"错误：报告 JSON 解析失败：{report_json}（{exc}）", err=True)
            raise typer.Exit(code=1) from exc

        from apkscan.dynamic import capture_plan

        if as_json:
            import dataclasses

            decision = capture_plan.decide_capture(report)
            typer.echo(_json.dumps(dataclasses.asdict(decision), ensure_ascii=False, indent=2))
            return

        steps = capture_plan.plan_capture(report)
        typer.echo("# 抓包打法（据静态报告规避信号 + 方法目录决策树）\n")
        for i, step in enumerate(steps, 1):
            typer.echo(f"{i}. {step}\n")
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - 兜底任何意外，转友好提示而非 traceback
        logger.exception("[cli] capture-plan 生成打法异常")
        typer.echo(f"错误：生成打法失败：{exc}", err=True)
        raise typer.Exit(code=1) from exc


# ===== track 子命令：线索追踪 / 办案进度（裸 track → 起网页；track ingest → 回填台账） =====
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

    closure = result.get("closure")
    if isinstance(closure, dict):
        typer.echo("")
        typer.echo(f"案件闭环：{closure.get('status', 'failed')}")
        gaps = closure.get("gaps")
        if isinstance(gaps, list) and gaps:
            typer.echo(f"未闭环项（{len(gaps)}）：")
            for gap in gaps[:6]:
                typer.echo(f"  - {gap}")


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
    apk_path: str, package: str, out: str, report: Report, formats: list[str], base: str,
    *, track: bool = True,
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

    _merge_runtime_into_report(capture_result, out, report, formats, base, track=track)


def _merge_runtime_into_report(
    capture_result: object, out: str, report: Report, formats: list[str], base: str,
    *, track: bool = True,
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
            runtime_report_path=runtime_path,
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
        # 动态富化后 report 已就地并入运行时线索 → 重新入账：upsert 合并安全（新增运行时线索、
        # 保留人工改过的进度）。报告路径用主 JSON（与静态入账同口径）。best-effort，绝不抛。
        _auto_track(report, str(Path(out) / f"{base}.json"), track=track)
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


def _report_from_json_dict(payload: dict) -> Report:
    """Backward-compatible wrapper around the shared report loader."""
    from apkscan.core.report_io import report_from_dict

    return report_from_dict(payload)


def _rerender_html_if_present(report_json_path: str) -> str:
    """``--into`` 回灌改了 report.json 后：若**同目录同名** ``<base>.html`` 存在，则据改后的
    report.json 复用 report.html 渲染入口重渲该 html，让台账新增线索同步进人读报告。

    返回重渲的 html 路径；同目录无对应 html 则不重渲、不新建（返回空串）。绝不抛——读/解析/
    渲染失败只 logging 并返回空串，不影响已回灌的 report.json（--into 主产物）。
    """
    import json as _json

    rp = Path(report_json_path)
    html_path = rp.with_suffix(".html")
    if not html_path.is_file():
        return ""  # 无对应 report.html：不主动生成（尊重用户只要 JSON 的场景）
    try:
        payload = _json.loads(rp.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            logger.warning("[cli] --into 重渲跳过：report.json 顶层非对象：%s", rp)
            return ""
        report = _report_from_json_dict(payload)
        from apkscan.report import html as report_html

        report_html.render(report, str(html_path))
        return str(html_path)
    except Exception:
        logger.exception("[cli] --into 后重渲 report.html 失败（已忽略，不影响 report.json）：%s", html_path)
        return ""


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

    写完后对每个产物算 sha256，落 ``<base>.sha256`` 旁文件（对标 sha256sum 格式），作为
    报告自证完整性的可复现校验锚点（工具产物自证，不替代司法鉴定机构的证据保全）。
    """
    written: list[Path] = []  # 实际落盘成功的产物，供生成 .sha256 旁文件

    if "json" in formats:
        try:
            from apkscan.report import json as report_json

            path = out_dir / f"{base}.json"
            report_json.dump(report, str(path))
            written.append(path)
            typer.echo(f"已写出 JSON 报告：{path}")
        except Exception:
            logger.exception("写出 JSON 报告失败（report.json 模块可能尚未就绪）")

    html_path = out_dir / f"{base}.html"
    if "html" in formats:
        try:
            from apkscan.report import html as report_html

            report_html.render(report, str(html_path))
            written.append(html_path)
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
                written.append(path)
                typer.echo(f"已写出 PDF 报告：{path}")
            else:
                typer.echo(
                    "PDF 导出跳过：未找到 Chrome/Edge/Chromium 或转换失败（详见日志）；"
                    "HTML/JSON 不受影响。"
                )
        except Exception:
            logger.exception("写出 PDF 报告失败")

    _write_sha256_sidecar(out_dir, base, written)


def _write_sha256_sidecar(out_dir: Path, base: str, products: list[Path]) -> None:
    """对每个报告产物算 sha256，落 ``<base>.sha256`` 旁文件（sha256sum 风格：``<hash>  <文件名>``）。

    工具产物自证：供调证人员 / 复核方用 sha256sum 校验报告未被篡改，**不替代司法鉴定机构的
    证据保全**。算 hash / 写旁文件全包 try/except——失败只 logging，绝不影响已产出的报告。
    """
    if not products:
        return
    try:
        import hashlib

        lines: list[str] = []
        for path in products:
            if not path.is_file():
                continue
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda f=f: f.read(1 << 20), b""):
                    h.update(chunk)
            # sha256sum 风格：哈希 + 两个空格 + 文件名（旁文件与产物同目录，用 name 即可）。
            lines.append(f"{h.hexdigest()}  {path.name}")
        if not lines:
            return
        sidecar = out_dir / f"{base}.sha256"
        sidecar.write_text("\n".join(lines) + "\n", encoding="utf-8")
        typer.echo(f"已写出完整性校验旁文件：{sidecar}")
    except Exception:
        logger.exception("[cli] 写出 .sha256 旁文件失败（已忽略，不影响报告产出）")


def _auto_track(report: Report, report_path: str, *, track: bool) -> None:
    """写报告后自动入账 + 喂图谱（best-effort 旁路）。绝不抛——失败只 logging，不影响报告。

    薄包装：委托 :func:`apkscan.track.autoingest.auto_track_and_ingest`（never-throw）。
    --no-track 时 ``track=False``，整体跳过。
    """
    try:
        from apkscan.track.autoingest import auto_track_and_ingest

        auto_track_and_ingest(report, report_path, track=track)
    except Exception:  # noqa: BLE001 — 入账旁路绝不抛：连 import 异常也吞，不影响报告产出
        logger.warning("[track] 自动入账/喂图谱调用异常（已忽略，不影响报告产出）", exc_info=True)


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
    from apkscan.core.dotenv import load_dotenv
    from apkscan.core.logsetup import setup_logging
    from apkscan.core.utf8 import enable_utf8_runtime

    enable_utf8_runtime()
    # 装「错误定位标识」日志格式器（WARNING+ 末尾带 [@模块.函数:行号]，便于按日志反馈定位）。
    setup_logging()
    # 从项目根 .env 兜底加载密钥（FXAPK_SHODAN_KEY 等）；真实环境变量优先，绝不抛。
    load_dotenv()
    app()


if __name__ == "__main__":
    main()
