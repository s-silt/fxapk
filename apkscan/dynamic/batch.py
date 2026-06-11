"""apkscan.dynamic.batch — 文件夹批量分析引擎（零 AI，确定性编排）。

把一个文件夹里**没分析过**的 APK 逐个跑完：扫描 → sha256 去重 → 调 :func:`auto.run`
（launch-only：``confirm=None``，只启动 app 抓冷启动流量、不等人操作）→ 有设备则
``adb uninstall`` 收尾 → 记台账 → 汇总。供 CLI ``fxapk batch`` 与 GUI 批量栏目调用。

设计铁律（与 dynamic.auto 一致，GUI-ready / exe-ready）：

- **核心禁 print/typer/sys.exit/input**；仅 logging + 可选 ``on_progress`` 回调 + 结构化返回。
- **绝不把异常抛给调用方**：单个 APK 处理独立 try/except，单个失败记 ``failed`` 但
  **不中断整批**；最外层再兜底。
- **去重靠内容 sha256**（见 :mod:`apkscan.dynamic.ledger`）：同 APK 改名也跳过。
- **失败的不入台账** → 下次重跑会重试（不被瞬时失败永久跳过）；只有产出了报告才记。
- **逐个卸载**：每个 app 跑完 ``adb uninstall``（仅有设备时），保持设备干净、避免堆包 /
  同包名不同 APK 冲突。只动当前分析的这个包，绝不碰设备上其它 app。

返回结构::

    {
        "analyzed": [{"apk", "sha256", "package_name", "report_paths", "out_dir", "status"}],
        "skipped":  [{"apk", "sha256"}],                  # 台账命中、本轮没跑
        "failed":   [{"apk", "sha256", "detail"}],        # 异常 / 无报告产出（未入台账）
        "summary":  {"total", "analyzed", "skipped", "failed", "had_device"},
        "out_dir": str,
        "ledger_path": str,
    }
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from apkscan.core import device
from apkscan.dynamic import auto, provision
from apkscan.dynamic.ledger import AnalyzedLedger, apk_sha256

logger = logging.getLogger(__name__)

# launch-only 批量默认抓包时长（秒）：只抓冷启动流量，逐个都短一点省时间。
_DEFAULT_DURATION = 30


def _emit(on_progress: Callable[[str], None] | None, msg: str) -> None:
    """安全调用进度回调：None 跳过；回调抛异常吞掉 + logging，防 GUI 回调炸内核。"""
    logger.info("[batch] %s", msg)
    if on_progress is None:
        return
    try:
        on_progress(msg)
    except Exception:
        logger.exception("[batch] on_progress 回调异常（已忽略）")


def run_folder(
    folder: str,
    *,
    out_dir: str = "out_batch",
    online: bool = True,
    capture_duration: int = _DEFAULT_DURATION,
    formats: list[str] | None = None,
    force: bool = False,
    ledger_path: str | Path | None = None,
    on_progress: Callable[[str], None] | None = None,
) -> dict:
    """扫描 ``folder`` 下的 APK，逐个分析没分析过的。绝不抛，返回结构化汇总（见模块 docstring）。

    Args:
        folder: 待扫描的文件夹（只取顶层 ``*.apk``，不递归子目录）。
        out_dir: 批量输出根目录；每个 APK 落到 ``<out_dir>/<文件名>__<sha8>/``。
        online: 静态分析是否联网富化归属。默认 True（与 auto/analyze 一致）。
        capture_duration: launch-only 抓包时长（秒）。默认 30。
        formats: 报告格式，默认 auto 的默认（html,json）。
        force: True 则无视台账、全部重跑。
        ledger_path: 去重台账路径；None → ``<out_dir>/.apkscan_cache/analyzed.json``。
        on_progress: 可选进度回调（GUI/CLI；None → 仅 logging）。
    """
    analyzed: list[dict] = []
    skipped: list[dict] = []
    failed: list[dict] = []

    led_path = Path(ledger_path) if ledger_path else Path(out_dir) / ".apkscan_cache" / "analyzed.json"
    ledger = AnalyzedLedger(led_path)

    try:
        had_device = device.has_device()
    except Exception:
        logger.exception("[batch] 设备探测异常，按无设备处理")
        had_device = False

    apks = sorted(Path(folder).glob("*.apk")) if Path(folder).is_dir() else []
    total = len(apks)
    _emit(on_progress, f"扫描到 {total} 个 APK；设备：{'有' if had_device else '无（仅静态）'}")

    for idx, apk in enumerate(apks, start=1):
        name = apk.name
        try:
            sha = apk_sha256(str(apk))
        except OSError:
            logger.exception("[batch] 读取 APK 失败，跳过：%s", apk)
            failed.append({"apk": name, "sha256": "", "detail": "读取 APK 失败（详见日志）"})
            continue

        if not force and ledger.is_analyzed(sha):
            _emit(on_progress, f"[{idx}/{total}] 跳过（已分析过）：{name}")
            skipped.append({"apk": name, "sha256": sha})
            continue

        per_app_out = str(Path(out_dir) / f"{apk.stem}__{sha[:8]}")
        _emit(on_progress, f"[{idx}/{total}] 分析：{name}")
        try:
            result = auto.run(
                str(apk),
                out_dir=per_app_out,
                online=online,
                capture_duration=capture_duration,
                formats=formats,
                on_progress=on_progress,
                confirm=None,  # launch-only：只启动 app，不等人操作
            )
            reports = list(result.get("report_paths") or [])
            pkg = result.get("package_name") or ""

            # 逐个卸载：有设备 + 有包名才卸（auto.run 装的就是这个包）。失败无害，只记日志。
            if had_device and pkg:
                u = provision.uninstall_app(pkg)
                if not u.get("ok"):
                    logger.warning("[batch] 卸载失败（忽略）：%s — %s", pkg, u.get("detail"))

            if reports:
                ledger.record(sha, apk_name=name, report_dir=per_app_out, status="done")
                analyzed.append({
                    "apk": name,
                    "sha256": sha,
                    "package_name": pkg,
                    "report_paths": reports,
                    "out_dir": per_app_out,
                    "status": "done",
                })
            else:
                # 跑了但没出任何报告（静态都失败）→ 记 failed、**不入台账**，下次重试。
                failed.append({"apk": name, "sha256": sha, "detail": "无报告产出（静态分析失败？）"})
        except Exception:
            logger.exception("[batch] 处理 APK 异常（已隔离，继续下一个）：%s", apk)
            failed.append({"apk": name, "sha256": sha, "detail": "处理异常（详见日志）"})

    summary = {
        "total": total,
        "analyzed": len(analyzed),
        "skipped": len(skipped),
        "failed": len(failed),
        "had_device": had_device,
    }
    _emit(
        on_progress,
        f"批量完成：分析 {summary['analyzed']} / 跳过 {summary['skipped']} / 失败 {summary['failed']}",
    )
    return {
        "analyzed": analyzed,
        "skipped": skipped,
        "failed": failed,
        "summary": summary,
        "out_dir": out_dir,
        "ledger_path": str(led_path),
    }
