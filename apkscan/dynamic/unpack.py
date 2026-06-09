"""真机脱壳（unpack）：root 设备 + frida + frida-dexdump 自动 dump 解密 DEX 并回灌重分析。

工作流::

    1. 探测能力：device.has_device / has_frida / has_frida_dexdump / frida_server_running，
       任一缺失 → status="skipped" + 精确手册（playbook 给可复制的命令），reason 写缺啥。
    2. 满足条件：load_apk 取包名 → subprocess 跑 ``frida-dexdump -FU -f <package>``
       到 ``out_dir/dump`` → 收集 *.dex 到 artifacts。
    3. reanalyze → load_apk(extra_dex=dumped) + pipeline.run + 写
       ``out_dir/unpacked_report.{json,html}`` → report_paths。
    4. status="done"。

错误处理铁律：任何失败 → status="error" + reason（不抛、不静默吞错；全程 logging）。
设备/工具探测一律走 apkscan.core.device（纯 subprocess、不抛）。

返回值见 apkscan.dynamic.DynamicResult 契约。
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from apkscan.core import device, tools
from apkscan.core.models import AnalysisConfig
from apkscan.dynamic import (
    STATUS_DONE,
    STATUS_ERROR,
    STATUS_SKIPPED,
    DynamicResult,
    empty_result,
)

logger = logging.getLogger(__name__)

# frida-dexdump 在加固应用上要等壳解密、脱完所有 DEX，给足超时（秒）。
_DEXDUMP_TIMEOUT = 300.0

# subprocess 输出尾部保留多少字符记到 reason / 日志（防止刷屏）。
_STDOUT_TAIL = 2000


def run(
    apk_path: str,
    out_dir: str = "out",
    reanalyze: bool = True,
    *,
    out: str | None = None,
) -> DynamicResult:
    """真机脱壳主入口（见模块 docstring）。

    Args:
        apk_path: 待脱壳的 APK 文件路径。
        out_dir: 产物 / 报告输出目录（dump 落到 ``out_dir/dump``）。
        reanalyze: 脱壳得到额外 DEX 后是否自动 load_apk(extra_dex=...) 重新静态分析。
        out: ``out_dir`` 的关键字别名（CLI 以 ``out=`` 调用，二者取其一，out 优先）。

    Returns:
        DynamicResult（status=done|skipped|error，字段齐全，绝不抛异常）。
    """
    if out is not None:
        out_dir = out

    # 1) 能力探测：任一缺失 → skipped + 精确手册。
    skipped = _check_capabilities()
    if skipped is not None:
        return skipped

    # 2) 取包名（脱壳/重分析都要）。load_apk 失败 → error，不抛。
    try:
        package_name = _resolve_package_name(apk_path)
    except Exception as exc:  # noqa: BLE001 - 转成 DynamicResult，不抛给 CLI
        logger.exception("load_apk 取包名失败：%s", apk_path)
        result = empty_result(STATUS_ERROR, f"加载 APK 取包名失败：{exc}")
        return result

    if not package_name:
        logger.error("APK 包名为空，无法用 frida-dexdump 定位目标：%s", apk_path)
        return empty_result(
            STATUS_ERROR,
            "无法从 APK 解析包名（frida-dexdump 需 -f <package> 定位目标进程）。",
        )

    # 3) 跑 frida-dexdump dump 到 out_dir/dump。
    dump_dir = Path(out_dir) / "dump"
    playbook: list[str] = []
    try:
        dumped = _dexdump(package_name, dump_dir, playbook)
    except Exception as exc:  # noqa: BLE001 - dump 任何异常都转 error
        logger.exception("frida-dexdump 脱壳异常：package=%s", package_name)
        result = empty_result(STATUS_ERROR, f"frida-dexdump 执行异常：{exc}")
        result["playbook"] = playbook
        return result

    if isinstance(dumped, str):
        # _dexdump 以字符串返回失败原因（非零退出 / 超时 / 无产物）。
        logger.error("frida-dexdump 脱壳失败：%s", dumped)
        result = empty_result(STATUS_ERROR, dumped)
        result["playbook"] = playbook
        return result

    artifacts = [str(p) for p in dumped]
    logger.info("frida-dexdump 脱壳成功：dump 出 %d 个 DEX", len(artifacts))

    report_paths: list[str] = []
    if reanalyze:
        # 4) 回灌：load_apk(extra_dex=dumped) + pipeline.run + 写报告。失败不致命，
        #    脱壳产物已在 artifacts，仅在 reason 标注重分析失败。
        try:
            report_paths = _reanalyze(apk_path, artifacts, out_dir)
            playbook.append(
                f"apkscan analyze {apk_path} --extra-dex {dump_dir} "
                "（脱壳产物已自动回灌重分析）"
            )
        except Exception as exc:  # noqa: BLE001 - 重分析失败不丢脱壳产物
            logger.exception("脱壳后重分析失败：%s", apk_path)
            result = empty_result(
                STATUS_DONE,
                f"脱壳成功（{len(artifacts)} 个 DEX），但重分析失败：{exc}",
            )
            result["artifacts"] = artifacts
            result["playbook"] = playbook
            return result
    else:
        playbook.append(
            f"apkscan analyze {apk_path} --extra-dex {dump_dir} "
            "（手动回灌：把脱壳 DEX 并入静态分析）"
        )

    result = empty_result(STATUS_DONE, f"脱壳成功，dump 出 {len(artifacts)} 个 DEX。")
    result["artifacts"] = artifacts
    result["playbook"] = playbook
    result["report_paths"] = report_paths
    return result


def _check_capabilities() -> DynamicResult | None:
    """探测脱壳所需能力。全部满足返回 None；任一缺失返回 status=skipped 的 DynamicResult。

    缺什么写进 reason，并在 playbook 给出可直接复制的精确补全命令。
    """
    missing: list[str] = []
    if not device.has_device():
        missing.append("在线 root 设备（adb devices 无在线设备）")
    if not device.has_frida():
        missing.append("frida CLI（PATH 无 frida）")
    if not device.has_frida_dexdump():
        missing.append("frida-dexdump（PATH 无 frida-dexdump）")
    # frida-server 仅在有设备时判定才有意义；无设备时上面已记，避免误导。
    if device.has_device() and not device.frida_server_running():
        missing.append("设备上运行中的 frida-server")

    if not missing:
        return None

    reason = "缺少：" + "；".join(missing)
    logger.info("脱壳前置条件不满足，跳过：%s", reason)
    result = empty_result(STATUS_SKIPPED, reason)
    result["playbook"] = _manual_playbook()
    return result


def _manual_playbook() -> list[str]:
    """无设备 / 缺工具时的精确手册（每条都是可直接复制的命令或动作）。"""
    return [
        "# 1) 准备 root 设备（真机或模拟器），确认 adb 连接：",
        "adb devices  # 状态应为 device（非 offline/unauthorized）",
        "",
        "# 2) 查设备 ABI，按 ABI 下载匹配的 frida-server：",
        "adb shell getprop ro.product.cpu.abi  # 如 arm64-v8a / armeabi-v7a / x86_64",
        "#    去 https://github.com/frida/frida/releases 下载对应 frida-server"
        "（如 frida-server-<版本>-android-arm64.xz），解压：",
        "xz -d frida-server-<版本>-android-arm64.xz",
        "",
        "# 3) push 到设备并赋可执行、后台运行：",
        "adb push frida-server-<版本>-android-arm64 /data/local/tmp/frida-server",
        "adb shell su -c 'chmod 755 /data/local/tmp/frida-server'",
        "adb shell su -c '/data/local/tmp/frida-server &'  # 后台启动 frida-server",
        "",
        "# 4) 安装 PC 端 frida 工具链（版本需与 frida-server 一致）：",
        "pip install frida-tools frida-dexdump",
        "frida-ps -U  # 验证 PC 能连到设备上的 frida-server",
        "",
        "# 5) 启动目标 app 并自动 dump 解密后的 DEX（-FU=USB前台应用, -f=按包名spawn）：",
        "frida-dexdump -FU -f <package>  # <package> 换成目标应用包名",
        "",
        "# 6) 把 dump 出的 DEX 目录回灌静态分析：",
        "apkscan analyze <apk> --extra-dex <dump_dir>",
    ]


def _resolve_package_name(apk_path: str) -> str:
    """load_apk 后取 ctx.package_name。androguard 解析失败由 load_apk 抛，调用方转 error。"""
    from apkscan.core.apk import load_apk

    ctx = load_apk(apk_path, AnalysisConfig(online=False))
    return ctx.package_name or ""


def _dexdump(
    package_name: str, dump_dir: Path, playbook: list[str]
) -> list[Path] | str:
    """跑 ``frida-dexdump -FU -f <package> -o <dump_dir>`` 脱壳。

    返回 dump 出的 .dex 文件路径列表；失败（非零退出 / 超时 / 无产物）返回字符串原因。
    超时 / 异常由调用方 try/except 兜底（本函数超时返回字符串、不抛）。
    """
    dump_dir.mkdir(parents=True, exist_ok=True)
    # frozen 时经 tools.frida_invocation 自调用内置 frida-dexdump；源码时用 PATH。
    inv = tools.frida_invocation("frida-dexdump")
    if not inv:
        logger.error("frida-dexdump 不可用（frozen 内置缺失 / PATH 无 frida-dexdump）")
        return "frida-dexdump 不可用"
    # -F=attach 前台应用, -U=USB 设备, -f=按包名 spawn, -o=输出目录。
    cmd = [*inv, "-FU", "-f", package_name, "-o", str(dump_dir)]
    # playbook 记**人类可读命令**（不暴露 sys.executable frida-dexdump），与实际 argv 解耦。
    playbook.append(f"frida-dexdump -FU -f {package_name} -o {dump_dir}")
    logger.info("执行 frida-dexdump：%s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_DEXDUMP_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("frida-dexdump 超时（%ss）：package=%s", _DEXDUMP_TIMEOUT, package_name)
        return f"frida-dexdump 超时（{_DEXDUMP_TIMEOUT}s 未完成），目标可能未启动或壳脱不出。"

    tail = (proc.stdout or "")[-_STDOUT_TAIL:]
    # frida-dexdump 的真实错误（连不上 frida-server / 版本不匹配 / spawn 失败 / 权限）
    # 绝大多数走 stderr，必须一并纳入诊断，否则失败原因被静默丢弃、排障无据。
    tail_err = (proc.stderr or "")[-_STDOUT_TAIL:]
    if proc.returncode != 0:
        logger.error(
            "frida-dexdump 非零退出（%s）：package=%s\nstdout尾部：%s\nstderr尾部：%s",
            proc.returncode,
            package_name,
            tail,
            tail_err,
        )
        return (
            f"frida-dexdump 非零退出（returncode={proc.returncode}）。"
            f"stdout 尾部：{tail.strip()} | stderr 尾部：{tail_err.strip()}"
            f"{device.frida_spawn_hint(tail + tail_err)}"
        )

    dumped = _collect_dex(dump_dir)
    if not dumped:
        logger.error(
            "frida-dexdump 退出 0 但未产出 .dex：package=%s\nstdout尾部：%s\nstderr尾部：%s",
            package_name,
            tail,
            tail_err,
        )
        return (
            f"frida-dexdump 未 dump 出任何 .dex（目录 {dump_dir} 为空）。"
            f"stdout 尾部：{tail.strip()} | stderr 尾部：{tail_err.strip()}"
        )

    logger.debug("frida-dexdump stdout 尾部：%s", tail)
    return dumped


def _collect_dex(dump_dir: Path) -> list[Path]:
    """收集 dump_dir 下所有 *.dex（递归，frida-dexdump 可能分子目录）。排序保证稳定。

    注意：不在此吞 IO 异常——若 rglob 因权限/路径异常失败，让异常上抛由 run() 的
    try 转成带真实原因的 STATUS_ERROR；空目录自然返回 []，从而把"收集失败"与
    "确实没脱出 dex"区分开（否则真实 IO 错误会被误报成"壳没脱出来"）。
    """
    return sorted(dump_dir.rglob("*.dex"))


def _reanalyze(apk_path: str, extra_dex: list[str], out_dir: str) -> list[str]:
    """load_apk(extra_dex=dumped) + pipeline.run + 写 unpacked_report.{json,html}。

    返回写出的报告路径列表。任何异常向上抛，由调用方转 DynamicResult（不在此吞错）。
    """
    # 惰性导入：重分析才需要 androguard / pipeline / report，避免无谓加载。
    from apkscan.core import pipeline
    from apkscan.core.apk import load_apk
    from apkscan.report import html as html_report
    from apkscan.report import json as json_report

    config = AnalysisConfig(online=False, out_dir=out_dir)
    ctx = load_apk(apk_path, config, extra_dex=extra_dex)
    # ApkContext 运行期满足 AnalysisContext 协议；pyright 对 cached_property→property
    # 协议匹配有已知局限，显式忽略（见 cli.analyze 同处说明）。
    report = pipeline.run(ctx, config)  # type: ignore[arg-type]
    # 标注本报告来自脱壳回灌，便于报告消费方区分。
    report.meta["unpacked"] = True
    report.meta["unpacked_dex_count"] = len(extra_dex)

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    json_path = out_path / "unpacked_report.json"
    html_path = out_path / "unpacked_report.html"

    json_report.dump(report, str(json_path))
    html_report.render(report, str(html_path))
    logger.info("脱壳后重分析报告已写出：%s / %s", json_path, html_path)
    return [str(json_path), str(html_path)]


__all__ = ["run"]
