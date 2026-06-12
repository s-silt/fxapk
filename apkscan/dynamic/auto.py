"""apkscan.dynamic.auto — 一键全自动流水线（零 AI，确定性编排）。

把已有的离散能力串成一条「按下即跑」的确定性流水线，供 CLI ``fxapk auto`` 与
将来的 GUI 单按钮直接程序化调用：

    1. doctor.run    —— 动态前置环境自检 + 自修（设备/root/frida/mitmproxy/CA）。
    2. 静态分析      —— load_apk → pipeline.run → 写 report.{html,json}，得包名。
    3. 脱壳 unpack   —— 有设备才跑（frida-dexdump dump 隐藏 DEX 并自动回灌重分析）。
    4. 抓包 capture  —— 有设备 + 有包名才跑；先经 confirm 回调提示用户操作 app 触发网络。
    5. 合并 merge    —— 抓包成功则把运行时端点并回主报告并重渲，真·C2 进主线索清单。

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

import logging
from collections.abc import Callable
from pathlib import Path

from apkscan.core import device
from apkscan.core.models import AnalysisConfig
from apkscan.core.report_naming import report_base

logger = logging.getLogger(__name__)

# 步骤名常量（避免裸字符串漂移；CLI / 测试以此识别步骤）。
_STEP_DOCTOR = "环境体检"
_STEP_STATIC = "静态分析"
_STEP_INSTALL = "安装到设备"
_STEP_UNPACK = "脱壳"
_STEP_CAPTURE = "抓包"
_STEP_MERGE = "合并运行时端点"

# 步骤状态常量（与 DynamicResult 的 status 取值口径一致）。
_DONE = "done"
_SKIPPED = "skipped"
_ERROR = "error"

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
    on_progress: Callable[[str], None] | None = None,
    confirm: Callable[[str], None] | None = None,
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
        on_progress: 可选进度回调（GUI 弹窗 / CLI echo；None → no-op）。
        confirm: 抓包前的「提示用户操作 app」钩子（GUI 弹窗 / CLI 等回车）；
                 None 则不等待直接继续。

    Returns:
        dict：{steps, report_paths, package_name, out_dir}。绝不抛异常给调用方。
    """
    fmts = list(formats) if formats else list(_DEFAULT_FORMATS)
    steps: list[dict] = []
    report_paths: list[str] = []
    package_name = ""
    # 静态分析得到的 Report，供抓包后 merge 就地补全；任意类型（避免顶层 import pipeline/Report）。
    report: object | None = None

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
            apk_path, out_dir=out_dir, online=online, formats=fmts, on_progress=on_progress
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
        if has_device:
            steps.append(
                _run_install_app(apk_path, serial=target_serial, on_progress=on_progress)
            )

        # 3) 脱壳：仅有设备才做（产出 dex 由 unpack 内部 reanalyze 回灌）。
        unpack_step, unpack_paths = _run_unpack(
            apk_path,
            out_dir=out_dir,
            has_device=has_device,
            serial=target_serial,
            on_progress=on_progress,
        )
        steps.append(unpack_step)
        _extend_unique(report_paths, unpack_paths)

        # 4) 抓包：有设备且有包名才做；先 confirm 提示用户操作 app 触发网络。
        capture_step, runtime_report_path = _run_capture(
            package_name,
            out_dir=out_dir,
            has_device=has_device,
            serial=target_serial,
            duration=capture_duration,
            on_progress=on_progress,
            confirm=confirm,
        )
        steps.append(capture_step)

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
    except Exception:
        # 顶层兜底：任何未预期异常都转成结构化结果，绝不抛给调用方（GUI 单按钮要稳）。
        logger.exception("[auto] run 未预期异常（已转结构化结果）")
        steps.append(_step("一键全自动", _ERROR, "流水线发生未预期异常（详见日志）"))

    return {
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
            apk_path, out_dir=out_dir, online=online, formats=fmts, on_progress=on_progress
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
    on_progress: Callable[[str], None] | None,
) -> tuple[dict, object | None, str, list[str], str]:
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

        config = AnalysisConfig(online=online, out_dir=out_dir, formats=list(formats))
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
) -> tuple[dict, list[str]]:
    """步骤 3：脱壳（仅有设备才做）。无设备 → skipped；失败 → error，均不中断。

    serial 透传给 unpack.run（多设备消歧）；None 时退回旧行为（-FU）。

    Returns:
        (step, report_paths)。脱壳内部 reanalyze 默认回灌，report_paths 来自其产出。
    """
    if not has_device:
        _emit(on_progress, "步骤 3/5：脱壳（无设备，优雅跳过）")
        return _step(_STEP_UNPACK, _SKIPPED, "未检测到在线设备，跳过真机脱壳"), []

    _emit(on_progress, "步骤 3/5：脱壳（frida-dexdump dump 隐藏 DEX 并回灌重分析）")
    try:
        from apkscan.dynamic import unpack

        result = unpack.run(apk_path, out=out_dir, reanalyze=True, serial=serial)
        return _fold_dynamic_step(_STEP_UNPACK, result)
    except Exception as exc:  # noqa: BLE001 - 脱壳失败不中断流水线
        logger.exception("[auto] 脱壳步骤异常：%s", apk_path)
        return _step(_STEP_UNPACK, _ERROR, f"脱壳异常：{exc}"), []


def _run_capture(
    package_name: str,
    *,
    out_dir: str,
    has_device: bool,
    serial: str | None = None,
    duration: int,
    on_progress: Callable[[str], None] | None,
    confirm: Callable[[str], None] | None,
) -> tuple[dict, str]:
    """步骤 4：抓包（有设备 + 有包名才做）。先 confirm 提示用户操作 app 触发网络。

    serial 透传给 capture.run（多设备消歧）；None 时退回旧行为（-U）。

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

        result = capture.run(package_name, out=out_dir, duration=duration, serial=serial)
        step, _ = _fold_dynamic_step(_STEP_CAPTURE, result)
        runtime_path = ""
        if step["status"] == _DONE:
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
