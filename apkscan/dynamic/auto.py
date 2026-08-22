"""apkscan.dynamic.auto — 一键全自动流水线（零 AI，确定性编排）。

取证用途：对取证样本自身在分析机上做运行时观测，产出端点/密钥/独特串等线索，不面向任何第三方基础设施。

把已有的离散能力串成一条「按下即跑」的确定性流水线，供 CLI ``fxapk auto`` 与
将来的 GUI 单按钮直接程序化调用：

    1. doctor.run    —— 动态前置环境自检 + 自修（设备/root/frida/mitmproxy/CA）。
    2. 静态分析      —— load_apk → pipeline.run → 写 report.{html,json}，得包名。
    3. 脱壳 unpack   —— 有设备才跑（frida-dexdump dump 隐藏 DEX 并自动回灌重分析）。
    4. 抓包 capture  —— 有设备 + 有包名才跑；先经 confirm 回调提示用户操作 app 触发网络。
    5. 合并 merge    —— 抓包成功则把运行时端点并回主报告并重渲，真·C2 进主线索清单。
    6. 案件闭环      —— 多源再富化 + 五层归因 + 动态证据质量验收，写回主报告。

设计铁律（与 dynamic.__init__ / doctor / unpack / capture / merge 一致，GUI-ready / exe-ready）：

- **核心模块禁 print / typer.* / sys.exit / input()**；仅 logging + 可选 on_progress/confirm
  回调 + 结构化返回。CLI ``auto`` 命令是唯一可 typer.echo / 交互的薄包装。
- ``run`` **绝不把异常抛给调用方**：每一步独立 try/except，单步失败记 status="error"
  但**不中断后续步骤**（失败不中断）；整体再有外层兜底转结构化结果。
- 每个 except 必 logging（warning/exception），不裸 pass、不静默吞错。
- 分阶段前 on_progress 上报进度；回调异常吞掉 + logging，防 GUI 回调炸内核。
- 全量 type hints；Callable 从 collections.abc 导入。

返回结构::

    {
        "steps": [
            {"name": str, "status": "done"|"skipped"|"error", "detail": str},
            ...
        ],
        "report_paths": list[str],   # 产出/重渲的报告路径（去重，保持顺序）
        "package_name": str,         # 静态分析解析出的包名（未知则空串）
        "out_dir": str,              # 报告输出目录
    }
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from apkscan.core import device
from apkscan.core.models import ANALYSIS_MODE_PASSIVE, AnalysisConfig, Report
from apkscan.core.report_naming import report_base

META_WRITE_OWNER = "dynamic.auto"
META_WRITE_CATEGORIES = {
    'artifact_lineage': 'signal',
    'capture_apk_identity': 'record',
    'online': 'signal',
    'target_serial': 'record',
}
META_WRITE_KEYS = frozenset(META_WRITE_CATEGORIES)

logger = logging.getLogger(__name__)

# 步骤名常量（避免裸字符串漂移；CLI / 测试以此识别步骤）。
_STEP_DOCTOR = "环境体检"
_STEP_STATIC = "静态分析"
_STEP_INSTALL = "安装到设备"
_STEP_UNPACK = "脱壳"
_STEP_REPACKAGE = "去壳重打包"
_STEP_CAPTURE = "抓包"
# ★P0-c 第二遍（旁路）专用步骤名：与第一遍分开命名，否则同名步骤在 steps 里出现两次、
#   消费方（CLI 展示 / 批量汇总）分不清哪条属于哪一遍，"重打包 skipped" 也会被误读成第一遍出了问题。
_STEP_BYPASS = "旁路轮（行为修改）"
_STEP_BYPASS_REPACKAGE = "旁路轮·去壳重打包"
_STEP_BYPASS_CAPTURE = "旁路轮·抓包"
_STEP_MERGE = "合并运行时端点"
_STEP_CLOSE = "案件闭环"

# 步骤状态常量（与 DynamicResult 的 status 取值口径一致）。
_DONE = "done"
_SKIPPED = "skipped"
_ERROR = "error"
# 抓包跑完但无可用证据路径（与 dynamic.STATUS_DEGRADED 同值）。第一遍即便 degraded 也算「跑出了基线」，
# 可据以判断要不要旁路——它与「压根没跑起来」（skipped/error）是两回事。
_DEGRADED = "degraded"

# 默认报告格式（与 merge / cli 口径一致）。
_DEFAULT_FORMATS = ["html", "json"]


def _emit(on_progress: Callable[[str], None] | None, msg: str) -> None:
    """安全调用进度回调：None 跳过；回调抛异常吞掉 + logging，防 GUI 回调炸内核。"""
    logger.info("[auto] %s", msg)
    if on_progress is None:
        return
    try:
        on_progress(msg)
    except Exception:
        logger.exception("[auto] on_progress 回调异常（已忽略）")


def _confirm(confirm: Callable[[str], None] | None, msg: str) -> None:
    """安全调用确认回调（抓包前提示用户操作 app）：None 不等待直接继续；异常吞 + logging。"""
    if confirm is None:
        logger.info("[auto] confirm 回调为空，跳过抓包前用户确认，直接继续")
        return
    try:
        confirm(msg)
    except Exception:
        logger.exception("[auto] confirm 回调异常（已忽略，继续抓包）")


def _step(name: str, status: str, detail: str) -> dict:
    """构造单步结果。"""
    return {"name": name, "status": status, "detail": detail}


def run(
    apk_path: str,
    *,
    out_dir: str = "out",
    online: bool = True,
    auto_fix: bool = True,
    capture_duration: int = 60,
    formats: list[str] | None = None,
    mode: str = ANALYSIS_MODE_PASSIVE,
    repackage: bool = True,
    strict_case: bool = False,
    on_progress: Callable[[str], None] | None = None,
    confirm: Callable[[str], None] | None = None,
    allow_behavior_modification: bool = False,
    antidetect: str = "off",
) -> dict:
    """一键全自动：体检 → 静态 → 脱壳 → 抓包 → 合并，回一份结构化总报告。绝不抛。

    每一步独立 try/except、失败不中断后续、必 logging；全程仅 on_progress/confirm
    回调 + 结构化返回（GUI-ready）。

    Args:
        apk_path: 待分析的 APK 文件路径。
        out_dir: 报告 / 产物输出目录。
        online: 静态分析是否联网富化归属（WHOIS/ICP/ASN）。默认 True（联网，与 cli analyze 一致）。
        auto_fix: 体检时是否对 frida-server / CA 等调 provision 自动修复。
        capture_duration: 抓包时长（秒）。
        formats: 报告格式，默认 ``["html", "json"]``。
        strict_case: 标记调用方要求严格闭环；核心仍结构化返回，不抛出或退出进程。
        on_progress: 可选进度回调（GUI 弹窗 / CLI echo；None → no-op）。
        confirm: 抓包前的「提示用户操作 app」钩子（GUI 弹窗 / CLI 等回车）；
                 None 则不等待直接继续。

    Returns:
        dict：{status, closure, steps, report_paths, package_name, out_dir}。绝不抛异常给调用方。
    """
    fmts = list(formats) if formats else list(_DEFAULT_FORMATS)
    steps: list[dict] = []
    report_paths: list[str] = []
    package_name = ""
    # 静态分析得到的 Report，供抓包后 merge 就地补全；任意类型（避免顶层 import pipeline/Report）。
    report: object | None = None
    closure: dict[str, object] = {
        "schema_version": "1.0",
        "status": "failed",
        "checks": [],
        "targets": [],
        "source_summary": {},
        "gaps": ["case closure did not run"],
        "next_actions": ["rerun case closure after static analysis succeeds"],
    }

    try:
        # 0) 设备探测 + **钉定单台 serial**：必须在体检之前选定。多设备/一机多 transport
        #    （模拟器常被列成多条目，尤其 adb root 触发重连后）下，下游 adb/frida 命令必须
        #    带 -s/-D，否则 "more than one device" → 体检装 CA/代理/reverse/getprop/frida
        #    部署一连串失败。这里先钉定一个（emulator-* 优先），has_device 由它是否为 None 推出，
        #    并贯穿进体检与之后每一步（体检/装 CA 同样需要 serial，否则多设备下照样炸）。
        try:
            target_serial = device.select_target_serial()
        except Exception:
            logger.exception("[auto] 设备探测/选定异常，按无设备处理")
            target_serial = None
        has_device = target_serial is not None
        if target_serial is not None:
            logger.info(
                "[auto] 已钉定目标设备 serial=%s（下游 adb -s / frida -D）", target_serial
            )

        # 1) 环境体检（自检 + 自修）。带 serial：体检/装 CA 全程钉定同一台。失败不中断后续静态分析。
        steps.append(
            _run_doctor(serial=target_serial, auto_fix=auto_fix, on_progress=on_progress)
        )

        # 2) 静态分析（load_apk → pipeline.run → 写报告）。
        static_step, report, package_name, static_paths, base = _run_static(
            apk_path, out_dir=out_dir, online=online, formats=fmts, mode=mode,
            on_progress=on_progress,
        )
        steps.append(static_step)
        _extend_unique(report_paths, static_paths)

        # 2.5) 把选定 serial 记入静态报告 meta，便于排查（report 此时才有，可能为 None：静态失败时）。
        if target_serial is not None and report is not None:
            meta = getattr(report, "meta", None)
            if isinstance(meta, dict):
                meta["target_serial"] = target_serial

        # 3.4) 确保 frida-server 在跑且是 **root**（脱壳/抓包 spawn 注入必须 root，否则 jailed）。
        #      自愈逻辑在 ensure_frida_server，但 doctor「看见在跑就 OK」不会调它 → 非 root 实例
        #      不会被换掉。这里显式调一次，触发「非 root → 杀掉以 root 重启」自愈。失败不阻断。
        if has_device:
            _ensure_root_frida_server(serial=target_serial, on_progress=on_progress)

        # 3.5) 安装 APK 到设备（脱壳/抓包 spawn 前置）：frida -f <包名> 要 spawn 的是**已安装**
        #      的 app；只分析 APK 文件而设备上没装 → "unable to find application"。仅有设备才做。
        install_ok = True
        if has_device:
            install_step = _run_install_app(apk_path, serial=target_serial, on_progress=on_progress)
            steps.append(install_step)
            # ★身份可信性前提：装原包失败（最常见是上一次旁路轮留下的 wrapper 仍在设备上、签名不同
            #   → UPDATE_INCOMPATIBLE），此时设备上跑的**不是**本次要分析的原版 APK。流水线仍继续
            #   （抓到什么算什么），但绝不能把那一轮的证据标成 original-runtime——见下方 apk_identity。
            install_ok = install_step.get("status") == _DONE

        # 3) 脱壳：仅有设备才做（产出 dex 由 unpack 内部 reanalyze 回灌）。
        unpack_step, unpack_paths, unpacked_report = _run_unpack(
            apk_path,
            out_dir=out_dir,
            has_device=has_device,
            serial=target_serial,
            on_progress=on_progress,
        )
        steps.append(unpack_step)
        _extend_unique(report_paths, unpack_paths)

        # 3.5) ★把后续全程切到脱壳版报告。
        #      脱壳的**全部价值**在于隐藏 DEX 里的端点/配置能进最终报告与闭环；若这里不换，
        #      capture/merge/closure 与最终写出的报告全都还在壳桩上跑，脱壳等于白做——
        #      结果是「步骤显示脱壳成功、报告里却一条隐藏端点都没有」。
        if unpacked_report is not None:
            report = _adopt_unpacked_report(report, unpacked_report, apk_path=apk_path)
            package_name = report.package_name or package_name

        # 4) 第一遍（original 基线）：★始终跑原版 APK + floor PCAP，绝不重打包、绝不注入行为修改
        #    shim。主报告**只采信这一遍**——它是「样本自发行为」的干净观测，是后续一切对照的基准。
        #    产物落 out/pass1-original/，与第二遍物理隔离（两遍都会写 runtime_report.json/flows/pcap）。
        pass1_out = str(Path(out_dir) / "pass1-original")
        capture_step, runtime_report_path = _run_capture(
            package_name,
            out_dir=pass1_out,
            has_device=has_device,
            serial=target_serial,
            duration=capture_duration,
            on_progress=on_progress,
            confirm=confirm,
            report=report,
            # ★设备侧 floor pcap 的远端路径按 pass 区分：pull 失败时 capture 会**特意保留**远端那份
            #   供手动重拉，两遍共用固定路径的话第二遍起手的 rm -f 会把它删掉（不可恢复的证据丢失）。
            pass_tag="pass1",
        )
        steps.append(capture_step)

        # 本次实际抓的 APK 身份。第一遍恒 original；第二遍成功启动才补 wrapper。
        # ★路径可同名、可被覆盖，哈希才是身份——报告里必须能回答「这份证据采自哪个 APK」。
        # ★``which`` 必须反映**设备上实际在跑什么**，不能想当然标 original：安装原包失败时（典型是
        #   上一次旁路轮的 wrapper 仍在设备上、签名不同装不上），第一遍 spawn 到的是那个遗留 wrapper，
        #   把它的流量标成 original-runtime 就是伪造证据身份——不可判定时标 unknown 并说明原因。
        apk_identity: dict[str, Any] = {
            "which": "original" if (install_ok or not has_device) else "unknown",
            "original": {"path": apk_path, "sha256": _apk_sha256(apk_path)},
            "wrapper": None,
        }
        if not (install_ok or not has_device):
            apk_identity["identity_warning"] = (
                "原包安装失败（可能是此前旁路轮的去壳重打包版仍在设备上），"
                "本轮实际运行的 APK 身份不可确认；证据不得按 original-runtime 采信"
            )
        pass2_runtime_report: str | None = None
        pass2_variant: str = ""  # 旁路轮实测 variant（由 capture 按是否真注入 shim 算出，不由本层假定）

        # 4.5) 旁路轮（第二遍，modified-runtime）：仅当①第一遍确有基线产物、②判据建议、③取得显式
        #      行为修改授权，三者同时成立才跑。任一不满足 → 结构化 skipped + 写明原因，绝不自动提权。
        pass1_payload = _read_runtime_payload(runtime_report_path)
        pass1_status = str(capture_step.get("status") or "")
        if not (pass1_status in (_DONE, _DEGRADED) and runtime_report_path and pass1_payload):
            # ★硬前置：没有 original 基线就绝不允许跑 modified——否则唯一的运行时证据将全部来自
            #   被我方诱导的那一轮，且无从对照。这条比"判据建议与否"更优先。
            steps.append(
                _step(_STEP_BYPASS, _SKIPPED, "无第一遍 original 基线产物，拒绝执行旁路轮（先修环境/重抓）")
            )
        else:
            suggests, reason = _pass1_suggests_bypass(pass1_status, pass1_payload)
            if not suggests:
                # 第一遍健康：不跑旁路是正常路径，记一条 skipped 让"为什么没跑"可查（非降级）。
                steps.append(_step(_STEP_BYPASS, _SKIPPED, reason))
            elif not (allow_behavior_modification is True and antidetect == "java"):
                # ★判据是弱代理（见 _pass1_suggests_bypass 的诚实边界），故绝不自动提权：
                #   只把建议摆出来，由人决定是否授权重跑。假阳的代价止于一次确认。
                steps.append(
                    _step(
                        _STEP_BYPASS,
                        _SKIPPED,
                        f"判据建议旁路，但未取得行为修改授权（--allow-behavior-modification --antidetect java）：{reason}",
                    )
                )
            elif not repackage:
                steps.append(
                    _step(_STEP_BYPASS, _SKIPPED, f"判据建议旁路且已授权，但调用方已禁用去壳重打包：{reason}")
                )
            else:
                _emit(on_progress, f"旁路轮：{reason}（已授权，去壳重打包 + 行为修改 shim 重抓一遍）")
                pass2_out = str(Path(out_dir) / "pass2-modified")
                # ★恰好尝试一次、绝不重试；且全程不得影响第一遍已产出的主报告（旁路失败即退回 PCAP 主链）。
                repack_step, wrapper_apk_path = _run_repackage(
                    apk_path,
                    package_name,
                    # ★必须传主 out_dir，不能传 pass2_out：repackage 固定从 <out_dir>/dump 取脱壳 DEX，
                    #   而脱壳产物落在主 out/dump（第 3 步产出）。传 pass2 子目录会让它找不到 DEX、
                    #   旁路轮恒报"无料可重打包"；更糟的是若 pass2/dump 有旧残留还会用错 DEX。
                    #   repack 自身产物落 <out_dir>/repack/，与两遍的 capture 产物目录不冲突。
                    out_dir=out_dir,
                    has_device=has_device,
                    serial=target_serial,
                    on_progress=on_progress,
                )
                repack_step = dict(repack_step, name=_STEP_BYPASS_REPACKAGE)
                steps.append(repack_step)
                if repack_step.get("status") == _DONE and wrapper_apk_path:
                    apk_identity["wrapper"] = {
                        "path": wrapper_apk_path,
                        "sha256": _apk_sha256(wrapper_apk_path),
                    }
                    pass2_step, pass2_path = _run_capture(
                        package_name,
                        out_dir=pass2_out,
                        has_device=has_device,
                        serial=target_serial,
                        duration=capture_duration,
                        on_progress=on_progress,
                        confirm=confirm,
                        # ★不把静态 report 传进旁路轮：第二遍只产独立 runtime_report.json，
                        #   不并入任何 Report、不跑第二份 closure（保 S2 的报告级 variant 单值不破）。
                        report=None,
                        allow_behavior_modification=True,
                        antidetect="java",
                        pass_tag="pass2",  # 设备侧 floor pcap 与第一遍分开，绝不覆盖 original 基线
                    )
                    pass2_step = dict(pass2_step, name=_STEP_BYPASS_CAPTURE)
                    steps.append(pass2_step)
                    if pass2_step.get("status") in (_DONE, _DEGRADED) and pass2_path:
                        pass2_runtime_report = pass2_path
                        # ★不假定旁路轮一定是 modified-runtime：capture 按**实际是否注入了 shim**
                        #   计算 variant（frida 会话失败回退 subprocess 时它诚实写 original-runtime）。
                        #   这里必须读回它的结论，否则主报告会宣称"诱导轮"而实际那轮根本没注入。
                        pass2_variant = str(
                            _read_runtime_payload(pass2_path).get("runtime_variant") or ""
                        ) or "unknown"
                else:
                    steps.append(
                        _step(_STEP_BYPASS_CAPTURE, _SKIPPED, "去壳重打包未产出 wrapper APK，旁路轮未执行")
                    )

        # 4.9) 落 APK 身份：★必须在合并**之前**写进 meta，否则 merge 重渲出的报告里没有这一栏——
        #      「这份运行时证据采自哪个 APK（原版还是去壳重打包版）、哈希多少」是取证溯源的硬要求。
        #      旁路轮若产出了独立 runtime_report，指针一并挂上（该份是 modified-runtime，不并入主报告）。
        if report is not None:
            if pass2_runtime_report:
                apk_identity["pass2_runtime_report"] = pass2_runtime_report
                # 旁路轮的**实测** variant（可能是 original-runtime——授权了但 frida 会话失败回退
                # subprocess 时 shim 根本没进去）。据实记录，报告据此渲染，不替它宣称"诱导轮"。
                apk_identity["pass2_runtime_variant"] = pass2_variant or "unknown"
            report.meta["capture_apk_identity"] = apk_identity

        # 5) 合并：抓包成功且静态有 report 才把运行时端点并回主报告并重渲。
        if capture_step["status"] == _DONE and report is not None and runtime_report_path:
            merge_step, merge_paths = _run_merge(
                report,
                runtime_report_path,
                out_dir=out_dir,
                base=base,
                formats=fmts,
                on_progress=on_progress,
            )
            steps.append(merge_step)
            _extend_unique(report_paths, merge_paths)
        else:
            steps.append(
                _step(
                    _STEP_MERGE,
                    _SKIPPED,
                    "抓包未成功或无静态报告，无运行时端点可并入",
                )
            )

        # 6) 案件闭环：无论动态是否完整，只要静态报告存在都执行并把缺口显式写入报告。
        if report is not None:
            close_step, closure, close_paths = _run_closure(
                report,
                out_dir=out_dir,
                base=base,
                online=online,
                mode=mode,
                require_dynamic=has_device,
                on_progress=on_progress,
            )
            steps.append(close_step)
            _extend_unique(report_paths, close_paths)
        else:
            steps.append(_step(_STEP_CLOSE, _SKIPPED, "无有效静态报告，案件闭环失败"))
    except Exception:
        # 顶层兜底：任何未预期异常都转成结构化结果，绝不抛给调用方（GUI 单按钮要稳）。
        logger.exception("[auto] run 未预期异常（已转结构化结果）")
        steps.append(_step("一键全自动", _ERROR, "流水线发生未预期异常（详见日志）"))

    return {
        "status": str(closure.get("status") or "failed"),
        "closure": closure,
        "strict_case": bool(strict_case),
        "steps": steps,
        "report_paths": report_paths,
        "package_name": package_name,
        "out_dir": out_dir,
    }


def analyze_static(
    apk_path: str,
    *,
    out_dir: str = "out",
    online: bool = True,
    formats: list[str] | None = None,
    mode: str = ANALYSIS_MODE_PASSIVE,
    on_progress: Callable[[str], None] | None = None,
) -> dict:
    """仅静态分析（无 doctor / 无设备 / 无动态）：load_apk → pipeline.run → 写报告。绝不抛。

    供 GUI「静态分析」按钮与任何只想跑纯静态的程序化调用直接使用——
    复用与 ``run`` 第 2 步完全相同的 ``_run_static`` / ``_write_reports``，
    **不复制任何分析器逻辑**，与 ``run`` 的静态步骤口径严格一致。

    与 ``run`` 同样的设计铁律：禁 print/typer/input；异常被吞成结构化结果；
    on_progress 回调安全调用（None → no-op；回调抛异常吞 + logging）。

    Args:
        apk_path: 待分析的 APK 文件路径。
        out_dir: 报告输出目录。
        online: 是否联网富化归属（WHOIS/ICP/ASN）。默认 True（联网，与 cli analyze 一致）。
        formats: 报告格式，默认 ``["html", "json"]``。
        on_progress: 可选进度回调（GUI 弹窗 / None → no-op）。

    Returns:
        dict：{steps, report_paths, package_name, out_dir}，结构与 ``run`` 一致
        （steps 仅含一个「静态分析」步骤），便于 GUI 复用同一套结果解析。绝不抛。
    """
    fmts = list(formats) if formats else list(_DEFAULT_FORMATS)
    try:
        static_step, _report, package_name, static_paths, _base = _run_static(
            apk_path, out_dir=out_dir, online=online, formats=fmts, mode=mode,
            on_progress=on_progress,
        )
        return {
            "steps": [static_step],
            "report_paths": list(static_paths),
            "package_name": package_name,
            "out_dir": out_dir,
        }
    except Exception:
        # _run_static 自身已吞异常；此处为外层兜底，确保任何意外都转结构化结果，绝不抛。
        logger.exception("[auto] analyze_static 未预期异常（已转结构化结果）：%s", apk_path)
        return {
            "steps": [_step(_STEP_STATIC, _ERROR, "静态分析发生未预期异常（详见日志）")],
            "report_paths": [],
            "package_name": "",
            "out_dir": out_dir,
        }


# ---------------------------------------------------------------------------
# 各步骤（每步独立 try/except，失败不中断后续、绝不抛）
# ---------------------------------------------------------------------------


def _run_doctor(
    *, serial: str | None = None, auto_fix: bool, on_progress: Callable[[str], None] | None
) -> dict:
    """步骤 1：动态前置环境体检 + 自修。失败转 error step，不中断后续。

    serial 透传给 doctor.run（多设备消歧：体检/装 CA 全程钉定同一台）；None 时退回旧行为。
    """
    _emit(on_progress, "步骤 1/5：环境体检（设备/root/frida/mitmproxy/CA）")
    try:
        from apkscan.dynamic import doctor

        result = doctor.run(serial=serial, auto_fix=auto_fix, on_progress=on_progress)
        items = result.get("items") or [] if isinstance(result, dict) else []
        ok = bool(result.get("ok")) if isinstance(result, dict) else False
        n_ok = sum(1 for it in items if isinstance(it, dict) and it.get("ok"))
        detail = (
            f"体检{'通过' if ok else '存在未通过的关键项'}："
            f"{n_ok}/{len(items)} 项 OK"
        )
        # 体检本身跑完即 done（结论是否 ok 写进 detail，不阻断后续：无设备时静态仍要跑）。
        return _step(_STEP_DOCTOR, _DONE, detail)
    except Exception as exc:  # noqa: BLE001 - 体检失败不中断流水线
        logger.exception("[auto] 环境体检步骤异常")
        return _step(_STEP_DOCTOR, _ERROR, f"环境体检异常：{exc}")


def _run_static(
    apk_path: str,
    *,
    out_dir: str,
    online: bool,
    formats: list[str],
    mode: str = ANALYSIS_MODE_PASSIVE,
    on_progress: Callable[[str], None] | None,
) -> tuple[dict, Report | None, str, list[str], str]:
    """步骤 2：静态分析 load_apk → pipeline.run → 写报告。

    Returns:
        (step, report, package_name, report_paths, base)。失败时 report=None、包名空串、
        路径空列表、base 回退到 APK 名（仍合法，供 merge 同 base 重渲），step.status=error，
        但不抛（后续脱壳/抓包仍可在有设备时进行）。
    """
    _emit(on_progress, "步骤 2/5：静态分析（load_apk → pipeline → 写报告）")
    # base 在 try 外先算：即便 load_apk/pipeline 失败，merge 步骤也用同一 base（保持一致）。
    base = report_base(apk_path, "")
    try:
        # 惰性 import：避免顶层加载 androguard / pipeline / report（慢、且 GUI 冷启动友好）。
        from apkscan.core import pipeline
        from apkscan.core.apk import load_apk

        config = AnalysisConfig(online=online, out_dir=out_dir, formats=list(formats), mode=mode)
        ctx = load_apk(apk_path, config)
        package_name = ctx.package_name or ""
        # base 升级：拿到包名后用「APK 名→包名」回退链重算，覆盖 apk 名清理后为空的边界。
        base = report_base(apk_path, package_name)
        # ApkContext 运行期满足 AnalysisContext 协议；pyright 对 cached_property→property
        # 协议匹配有已知局限，显式忽略（见 cli.analyze / unpack._reanalyze 同处说明）。
        report = pipeline.run(ctx, config)  # type: ignore[arg-type]
        # 把真实联网状态落到 meta：merge 生成运行时线索时据此决定 online 分级标注
        # （与 cli.analyze 一致，离线扫描下运行时端点不被当成已联网核实）。
        report.meta["online"] = config.online

        report_paths = _write_reports(report, out_dir=out_dir, formats=formats, base=base)

        detail = (
            f"静态分析完成：包名 {package_name or '(未知)'}，"
            f"端点 {len(report.endpoints)}，线索 {len(report.leads)}"
        )
        return _step(_STEP_STATIC, _DONE, detail), report, package_name, report_paths, base
    except Exception as exc:  # noqa: BLE001 - load_apk(ApkParseError 等)/pipeline 失败不中断流水线
        logger.exception("[auto] 静态分析步骤异常：%s", apk_path)
        return _step(_STEP_STATIC, _ERROR, f"静态分析失败：{exc}"), None, "", [], base


def _write_reports(report: object, *, out_dir: str, formats: list[str], base: str) -> list[str]:
    """写出静态报告（``<base>.json`` / ``<base>.html``）。单格式失败不致命，记 logging 跳过。

    不依赖 cli 私有函数：直接惰性 import report.{json,html}，与 merge 重渲口径一致。
    文件名用 ``base``（APK 名去后缀），与 cli.analyze / merge 重渲严格同 base。
    返回成功写出的报告路径列表。
    """
    out_path = Path(out_dir)
    try:
        out_path.mkdir(parents=True, exist_ok=True)
    except OSError:
        logger.exception("[auto] 创建输出目录失败：%s", out_dir)

    paths: list[str] = []
    if "json" in formats:
        target = out_path / f"{base}.json"
        try:
            from apkscan.report import json as report_json

            report_json.dump(report, str(target))  # type: ignore[arg-type]
            paths.append(str(target))
        except Exception:
            logger.exception("[auto] 写出 %s 失败：%s", target.name, target)
    if "html" in formats:
        target = out_path / f"{base}.html"
        try:
            from apkscan.report import html as report_html

            report_html.render(report, str(target))  # type: ignore[arg-type]
            paths.append(str(target))
        except Exception:
            logger.exception("[auto] 写出 %s 失败：%s", target.name, target)
    return paths


def _ensure_root_frida_server(
    *, serial: str | None = None, on_progress: Callable[[str], None] | None
) -> None:
    """脱壳/抓包前确保 frida-server 在跑且是 root（触发非 root → root 自愈）。绝不抛、不阻断。

    不产 step（仅作前置保障，结果体现在后续 spawn 成败上）；失败只 logging。
    serial 透传给 provision（多设备消歧）；None 时退回旧行为。
    """
    _emit(on_progress, "确保 frida-server 以 root 运行（spawn 注入前置）")
    try:
        from apkscan.dynamic import provision

        res = provision.ensure_frida_server(serial=serial)
        action = res.get("action")
        if action == "restarted_as_root":
            _emit(on_progress, "检测到 frida-server 非 root，已以 root 重启")
        logger.info("[auto] ensure_frida_server: ok=%s action=%s", res.get("ok"), action)
    except Exception:  # noqa: BLE001 — 前置保障失败不中断流水线
        logger.exception("[auto] ensure_frida_server 异常（继续，spawn 若失败会有提示）")


def _run_install_app(
    apk_path: str, *, serial: str | None = None, on_progress: Callable[[str], None] | None
) -> dict:
    """安装 APK 到设备（脱壳/抓包 spawn 前置）。失败不阻断流水线（设备或已装兼容版本）。

    成功 → done；失败 → error（带原因，如签名冲突需先 uninstall），但后续步骤仍尝试
    （unpack/capture 会以 "unable to find application" 给出明确提示）。绝不抛。
    serial 透传给 provision（多设备消歧）；None 时退回旧行为。
    """
    _emit(on_progress, "安装 APK 到设备（frida spawn 前置：需 app 已安装）")
    try:
        from apkscan.dynamic import provision

        res = provision.install_apk(apk_path, serial=serial)
    except Exception as exc:  # noqa: BLE001 — 安装异常不中断流水线
        logger.exception("[auto] 安装 APK 异常：%s", apk_path)
        return _step(_STEP_INSTALL, _ERROR, f"安装 APK 异常：{exc}")
    detail = str(res.get("detail") or "")
    if res.get("ok"):
        return _step(_STEP_INSTALL, _DONE, detail or "APK 已安装到设备")
    return _step(_STEP_INSTALL, _ERROR, detail or "APK 安装失败（设备上若无此 app，spawn 会失败）")


def _run_unpack(
    apk_path: str,
    *,
    out_dir: str,
    has_device: bool,
    serial: str | None = None,
    on_progress: Callable[[str], None] | None,
) -> tuple[dict, list[str], Report | None]:
    """步骤 3：脱壳（仅有设备才做）。无设备 → skipped；失败 → error，均不中断。

    serial 透传给 unpack.run（多设备消歧）；None 时退回旧行为（-FU）。

    Returns:
        ``(step, report_paths, 回灌后的 Report 或 None)``。第三项非空表示脱壳 DEX 已重分析完成，
        调用方**必须**把后续流程切到它——否则 capture/merge/closure 仍在壳桩报告上跑。
    """
    if not has_device:
        _emit(on_progress, "步骤 3/5：脱壳（无设备，优雅跳过）")
        return _step(_STEP_UNPACK, _SKIPPED, "未检测到在线设备，跳过真机脱壳"), [], None

    _emit(on_progress, "步骤 3/5：脱壳（frida-dexdump dump 隐藏 DEX 并回灌重分析）")
    holder: list[Report] = []
    try:
        from apkscan.dynamic import unpack

        result = unpack.run(
            apk_path, out=out_dir, reanalyze=True, serial=serial,
            on_reanalyzed=holder.append,
        )
        step, paths = _fold_dynamic_step(_STEP_UNPACK, result)
        return step, paths, holder[0] if holder else None
    except Exception as exc:  # noqa: BLE001 - 脱壳失败不中断流水线
        logger.exception("[auto] 脱壳步骤异常：%s", apk_path)
        return _step(_STEP_UNPACK, _ERROR, f"脱壳异常：{exc}"), [], None


#: 描述**本次运行**而非样本内容的 meta 键。脱壳回灌报告由 unpack 自己跑一遍 pipeline 产出，
#: 拿不到这些，必须从被它取代的静态报告继承过来。
#:
#: ★为什么是白名单而不是整体 merge：其余 meta 键（is_hardened / packed / dex_* …）描述的是**样本**，
#: 脱壳后本就该重新计算，照搬会把壳桩的结论糊到去壳报告上。
#:
#: ★``online`` 漏继承的后果是方向性的：``_reanalyze`` 固定以 ``AnalysisConfig(online=False)`` 跑
#: （回灌只做静态重解，富化留给后续 closure），产出的报告里根本没有这个键；而 ``merge`` 读
#: ``meta.get("online", True)`` 决定运行时线索要不要标「离线扫描，归属未查询」。于是一次 ``--offline``
#: 运行在脱壳成功后，会把「压根没查」渲染成「查过」——正是这个字段存在的意义所反。
_RUN_SCOPED_META_KEYS = ("online", "mode", "target_serial")


def _adopt_unpacked_report(
    static_report: Report | None, unpacked: Report, *, apk_path: str
) -> Report:
    """把脱壳回灌后的报告立为后续流程的**当前报告**，继承运行上下文，并留下可核查的血缘。

    ★「脱壳成功」与「脱壳结果已成为当前报告的输入」是两件事，必须分开记录：前者只说 DEX dump
    出来了，后者才说明最终报告/闭环看到了那些 DEX。二者混为一谈时，「步骤显示脱壳成功、报告却
    还是壳桩」这种情况从数据上根本看不出来。
    """
    meta = unpacked.meta if isinstance(unpacked.meta, dict) else {}
    prior = static_report.meta if static_report is not None and isinstance(
        static_report.meta, dict
    ) else {}
    inherited = [k for k in _RUN_SCOPED_META_KEYS if k in prior and k not in meta]
    for key in inherited:
        meta[key] = prior[key]
    meta["artifact_lineage"] = {
        "active_input": "unpacked",           # 当前报告基于脱壳回灌的 DEX
        "apk_path": apk_path,
        "unpacked_dex_count": meta.get("unpacked_dex_count", 0),
        "superseded_static_hardened": bool(prior.get("is_hardened")),
        "superseded_static_packed": prior.get("packed"),
        "inherited_run_context": inherited,   # 哪些运行上下文是从被取代的静态报告接过来的
    }
    logger.info(
        "[auto] 后续流程切换到脱壳回灌报告（%s 个 DEX，继承运行上下文 %s）：%s",
        meta.get("unpacked_dex_count", 0), inherited or "无", apk_path,
    )
    return unpacked


def _apk_sha256(path: str | None) -> str | None:
    """算 APK 文件的 sha256（分块读，不整文件进内存）。路径缺失/不可读 → None（best-effort，绝不抛）。

    ★P0-c：报告里必须写明「这一遍实际抓的是哪个 APK」——路径可以同名、可以被覆盖，哈希才是身份。
    repackage 侧不产哈希（通读确认无 hashlib），故由本层新算。
    """
    if not path:
        return None
    try:
        file_path = Path(path)
        if not file_path.is_file():
            return None
        digest = hashlib.sha256()
        with file_path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except Exception:  # noqa: BLE001 - 算不出哈希不该中断流水线，缺身份好过崩
        logger.exception("[auto] 计算 APK sha256 失败（记为缺失，不中断）：%s", path)
        return None


def _run_repackage(
    apk_path: str,
    package_name: str,
    *,
    out_dir: str,
    has_device: bool,
    serial: str | None = None,
    on_progress: Callable[[str], None] | None,
) -> tuple[dict, str | None]:
    """步骤 3.6：去壳重打包（仅有设备才做）。无设备 → skipped；异常 → error，均不中断流水线。

    去壳成功 → done（去壳版已装回，capture 将抓此版）；无料/判定不过 → repackage 内部降级 skipped
    （重装原包，capture 仍跑原版）。serial 透传（多设备消歧）。

    ★P0-c：第二元素返回 **wrapper APK 路径**（仅 status==done 时非 None），供编排层把「设备上实际
    在跑哪个 APK」的身份贯穿进报告。此前这里返回的是 ``_fold_dynamic_step`` 折出的 ``report_paths``——
    而 ``repackage.run`` 只设 ``artifacts``、从不设 ``report_paths``，故那个返回值**恒为空列表**、
    wrapper 路径从没被任何人读到过（不是「有值但被丢弃」，是压根没取对字段）。
    """
    if not has_device:
        _emit(on_progress, "步骤 3.6：去壳重打包（无设备，优雅跳过）")
        return _step(_STEP_REPACKAGE, _SKIPPED, "未检测到在线设备，跳过去壳重打包"), None

    _emit(on_progress, "步骤 3.6：去壳重打包（脱壳 DEX 装回 → 重签 → 装去壳版供 capture 抓）")
    try:
        from apkscan.dynamic import repackage

        result = repackage.run(apk_path, out=out_dir, serial=serial, package_name=package_name)
        step, _ = _fold_dynamic_step(_STEP_REPACKAGE, result)
        # ★只有 done 才代表「去壳版真的装上了、设备在跑它」；skipped 是 repackage 内部降级重装原包
        #   （四联判定不过/无料），error 是异常——两者设备上跑的都是原版，绝不能标成 wrapper。
        wrapper_path: str | None = None
        if step.get("status") == _DONE and isinstance(result, dict):
            artifacts = result.get("artifacts") or []
            if isinstance(artifacts, list) and artifacts:
                wrapper_path = str(artifacts[0])
        return step, wrapper_path
    except Exception as exc:  # noqa: BLE001 - 去壳重打包失败不中断流水线
        logger.exception("[auto] 去壳重打包步骤异常：%s", apk_path)
        return _step(_STEP_REPACKAGE, _ERROR, f"去壳重打包异常：{exc}"), None


def _pass1_suggests_bypass(capture_status: str, rr_payload: dict) -> tuple[bool, str]:
    """据第一遍（original 基线）的产出，判断是否**建议**跑第二遍旁路。纯函数，绝不抛。

    Returns:
        ``(建议与否, 理由)``。理由恒为人可读的中文串——即便判"不建议"也给出原因，
        调用方要拿它写进 skipped 步骤的 detail，说明"为什么没跑第二遍"。

    ★判据的诚实边界（写死在这里，防后人把弱代理当强证据）：
      - "业务端点为零" 与 "hook 未就绪" 都**区分不了**「样本装死/反检测顶回来了」与
        「这个样本本来就没有业务流量」——两者在当前信号下形态相同。
      - 第一遍不注入 shim，因此**没有**任何 antidetect 观测可用，"明确反检测"没有强信号。
      → 故本函数只产出「建议」，第二遍必须另有显式授权才会真跑（见调用方）。弱代理的假阳
        只会多花一次授权确认，不会自动把诱导观测灌进证据链。
    """
    if capture_status not in (_DONE, _DEGRADED):
        return False, "第一遍未产出 original 基线（先修环境/重抓），不进第二遍"
    signals = rr_payload.get("capture_signals")
    signals = signals if isinstance(signals, dict) else {}
    # ★字段缺失 ≠ 零。缺 endpoint_total 说明这份 payload 本身不可信（旧格式/写坏），此时既不能说
    #   「端点为零」（那是替它下结论、并据以推荐一次会污染证据的旁路），也不该放行——按「基线不可判定」
    #   拒绝，遵「不可判定不得返回正常值」。有合法 endpoints 数组时可退而求其次按其长度判。
    total = rr_payload.get("endpoint_total")
    if not isinstance(total, int) or isinstance(total, bool) or total < 0:
        # 负数同样是坏值（计数不可能为负），退回按 endpoints 数组长度判，再不行就是不可判定。
        eps = rr_payload.get("endpoints")
        total = len(eps) if isinstance(eps, list) else None
    if total is None:
        return False, "第一遍基线不可判定（runtime_report 缺 endpoint_total/endpoints），拒绝据以推荐旁路"

    reasons: list[str] = []
    if total == 0:
        reasons.append("业务端点为零")
    if signals.get("frida_retreated") is True:
        reasons.append(f"frida 秒退熔断（{signals.get('frida_retreat_count') or 0} 次）")
    hook_status = signals.get("hook_ready_status")
    if hook_status in ("unconfirmed", "none"):
        reasons.append(f"frida hook 未就绪（{hook_status}，疑反 frida）")
    if capture_status == _DEGRADED:
        # `_fold_dynamic_step` 会把 DynamicResult 的 degraded 折成 error（全局既有行为，不在本片动），
        # 但 `_run_capture` 局部还原了该状态——degraded＝「跑完了、只是没有可用证据路径」，与「压根没
        # 跑起来」的 error 语义完全不同，正是判断要不要旁路的关键信号，故本分支在生产链路可达。
        reasons.append("抓包降级（无证据路径）")
    if not reasons:
        # ★措辞不得替信号下结论：hook_ready_status 缺失时我们只是"没看到触发信号"，不等于"hook 就绪"
        #   （那是在报告一个我们并不知道的事实）。只陈述已知：没有任何一条旁路判据被触发。
        return False, "第一遍未出现旁路触发信号（业务端点非零、未秒退、无降级），无需旁路"
    return True, "；".join(reasons)


def _read_runtime_payload(runtime_report_path: str) -> dict:
    """读回 runtime_report.json（供判据用）。缺失 / 坏 JSON → ``{}``（不抛，但记日志）。"""
    if not runtime_report_path:
        return {}
    try:
        payload = json.loads(Path(runtime_report_path).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - 读不回第一遍产物只影响"要不要建议旁路"，不该中断流水线
        logger.exception("[auto] 读取第一遍 runtime_report.json 失败：%s", runtime_report_path)
        return {}
    return payload if isinstance(payload, dict) else {}


def _run_capture(
    package_name: str,
    *,
    out_dir: str,
    has_device: bool,
    serial: str | None = None,
    duration: int,
    on_progress: Callable[[str], None] | None,
    confirm: Callable[[str], None] | None,
    report: object = None,
    allow_behavior_modification: bool = False,
    antidetect: str = "off",
    pass_tag: str = "",
) -> tuple[dict, str]:
    """步骤 4：抓包（有设备 + 有包名才做）。先 confirm 提示用户操作 app 触发网络。

    serial 透传给 capture.run（多设备消歧）；None 时退回旧行为（-U）。
    report（静态分析报告）透传给 capture.run，让 ``decide_capture`` 的四律决策
    （floor 优先 / 秒退熔断阈值 / 总预算时间盒 / native 预判）真正驱动抓包引擎。

    Returns:
        (step, runtime_report_path)。runtime_report_path：抓包成功时 runtime_report.json
        的路径（供 merge 读回），否则空串。
    """
    if not has_device:
        _emit(on_progress, "步骤 4/5：抓包（无设备，优雅跳过）")
        return _step(_STEP_CAPTURE, _SKIPPED, "未检测到在线设备，跳过真机抓包"), ""
    if not package_name:
        _emit(on_progress, "步骤 4/5：抓包（包名未知，跳过）")
        return _step(_STEP_CAPTURE, _SKIPPED, "包名未知（静态分析失败？），跳过抓包"), ""

    # 抓包前提示用户操作 app 触发网络（GUI 弹窗 / CLI 等回车）；confirm 为 None 则不等待。
    _confirm(
        confirm,
        f"即将抓包约 {duration} 秒，请在模拟器/设备上操作 app"
        "（登录/支付/拉配置）触发网络；准备好后继续",
    )

    _emit(on_progress, f"步骤 4/5：抓包（{package_name}，约 {duration} 秒）")
    try:
        from apkscan.dynamic import capture

        result = capture.run(
            package_name,
            out=out_dir,
            duration=duration,
            serial=serial,
            report=report,
            allow_behavior_modification=allow_behavior_modification,
            antidetect=antidetect,
            pass_tag=pass_tag,
        )
        step, _ = _fold_dynamic_step(_STEP_CAPTURE, result)
        # ★局部保留 degraded：`_fold_dynamic_step` 把它折成 error（全局既有行为，不在本片动），但抓包
        #   的 degraded 语义是「跑完了、只是没有可用证据路径」——与「压根没跑起来」的 error 完全不同，
        #   且它正是判断要不要跑旁路轮的关键信号之一。只在本函数还原该状态并照常解析报告路径，
        #   使 degraded 判据在生产链路真正可达（否则那条分支只有纯函数测试能触发）。
        raw_status = str(result.get("status") or "") if isinstance(result, dict) else ""
        if raw_status == _DEGRADED and step["status"] == _ERROR:
            step = dict(step, status=_DEGRADED)
        runtime_path = ""
        if step["status"] in (_DONE, _DEGRADED):
            runtime_path = _resolve_runtime_report_path(result, out_dir)
        return step, runtime_path
    except Exception as exc:  # noqa: BLE001 - 抓包失败不中断流水线
        logger.exception("[auto] 抓包步骤异常：%s", package_name)
        return _step(_STEP_CAPTURE, _ERROR, f"抓包异常：{exc}"), ""


def _run_merge(
    report: object,
    runtime_report_path: str,
    *,
    out_dir: str,
    base: str,
    formats: list[str],
    on_progress: Callable[[str], None] | None,
) -> tuple[dict, list[str]]:
    """步骤 5：把运行时端点并回主报告并重渲。失败 → error，但不破坏已产出静态报告。

    ``base`` 必须与静态首次写出同一 base，否则重渲会写到 report.* 而静态在 <apk>.*，产两套。

    Returns:
        (step, report_paths)。report_paths 为重渲后的报告路径。
    """
    _emit(on_progress, "步骤 5/5：合并运行时端点并重渲报告")
    try:
        from apkscan.core.models import Report
        from apkscan.dynamic import merge

        if not isinstance(report, Report):
            logger.warning("[auto] 合并步骤收到非 Report 对象，跳过：%r", type(report).__name__)
            return _step(_STEP_MERGE, _SKIPPED, "无有效静态报告，跳过合并"), []

        endpoints = merge.load_runtime_endpoints(runtime_report_path)
        stats = merge.merge_and_rerender(
            report,
            endpoints,
            out_dir,
            base,
            formats=list(formats),
            on_progress=on_progress,
            runtime_report_path=runtime_report_path,
        )
        merged = stats.get("merged", 0)
        new_leads = stats.get("new_leads", 0)
        report_paths = stats.get("report_paths") or []
        if not isinstance(report_paths, list):
            report_paths = []
        detail = (
            f"运行时端点并入：新增端点 {merged}，新增线索 {new_leads}；"
            f"重渲报告 {len(report_paths)} 份"
        )
        return _step(_STEP_MERGE, _DONE, detail), [str(p) for p in report_paths]
    except Exception as exc:  # noqa: BLE001 - 合并失败不破坏已产出静态报告
        logger.exception("[auto] 合并运行时端点步骤异常")
        return _step(_STEP_MERGE, _ERROR, f"合并运行时端点失败：{exc}"), []


def _run_closure(
    report: object,
    *,
    out_dir: str,
    base: str,
    online: bool,
    mode: str,
    require_dynamic: bool,
    on_progress: Callable[[str], None] | None,
) -> tuple[dict, dict[str, object], list[str]]:
    """Run deterministic case gates and persist them without raising to callers."""
    _emit(on_progress, "步骤 6/6：多源富化、五层归因与案件闭环验收")
    try:
        from apkscan.core import report_io
        from apkscan.core.closure import ClosureConfig, close_report
        from apkscan.core.models import Report

        if not isinstance(report, Report):
            closure = {
                "schema_version": "1.0",
                "status": "failed",
                "targets": [],
                "gaps": ["invalid static report"],
                "next_actions": ["rerun static analysis"],
            }
            return _step(_STEP_CLOSE, _SKIPPED, "无有效静态报告，案件闭环失败"), closure, []

        closure = close_report(
            report,
            ClosureConfig(
                online=online,
                mode=mode,
                require_dynamic=require_dynamic,
            ),
        )
        paths = report_io.write_report(report, Path(out_dir) / f"{base}.json")
        targets = closure.get("targets")
        gaps = closure.get("gaps")
        target_count = len(targets) if isinstance(targets, list) else 0
        gap_count = len(gaps) if isinstance(gaps, list) else 0
        detail = (
            f"闭环状态 {closure.get('status', 'failed')}；"
            f"主目标 {target_count}；未闭环项 {gap_count}"
        )
        return _step(_STEP_CLOSE, _DONE, detail), closure, paths
    except Exception as exc:  # noqa: BLE001 - auto core always returns structured failure
        logger.exception("[auto] 案件闭环步骤异常")
        reason = f"case closure execution failed ({type(exc).__name__})"
        closure = {
            "schema_version": "1.0",
            "status": "failed",
            "targets": [],
            "gaps": [reason],
            "next_actions": ["rerun fxapk case close against the static report"],
        }
        return _step(_STEP_CLOSE, _ERROR, reason), closure, []


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------


def _fold_dynamic_step(name: str, result: object) -> tuple[dict, list[str]]:
    """把 DynamicResult（unpack/capture 返回）折叠成一个 step + 其 report_paths。

    status 直接沿用 DynamicResult 的 done/skipped/error；detail 用 reason。
    """
    if not isinstance(result, dict):
        logger.warning("[auto] %s 返回非 dict，按 error 处理：%r", name, type(result).__name__)
        return _step(name, _ERROR, "返回值非预期格式"), []
    status = str(result.get("status") or _ERROR)
    if status not in (_DONE, _SKIPPED, _ERROR):
        status = _ERROR
    reason = str(result.get("reason") or "")
    raw_paths = result.get("report_paths") or []
    report_paths = [str(p) for p in raw_paths] if isinstance(raw_paths, list) else []
    return _step(name, status, reason), report_paths


def _resolve_runtime_report_path(capture_result: object, out_dir: str) -> str:
    """从 capture 的 report_paths 找 runtime_report.json，否则回退 out/runtime_report.json。

    与 cli._resolve_runtime_report_path 同口径（不动 capture 契约）。
    """
    if isinstance(capture_result, dict):
        for p in capture_result.get("report_paths") or []:
            if isinstance(p, str) and Path(p).name == "runtime_report.json":
                return p
    return str(Path(out_dir) / "runtime_report.json")


def _extend_unique(acc: list[str], new: list[str]) -> None:
    """把 new 中尚未出现的路径就地追加进 acc（去重、保持首现顺序）。"""
    for p in new:
        if p and p not in acc:
            acc.append(p)


__all__ = ["analyze_static", "run"]
