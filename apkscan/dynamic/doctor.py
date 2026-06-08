"""apkscan.dynamic.doctor — 动态抓包/脱壳前置环境结构化体检 + 自动修。

逐项检查接上设备一键体检需要的环境，能自动修的调用 provision，修不了给出
可逐条复制的 fix_cmd::

    (1) 在线设备                       device.has_device / adb_devices
    (2) 设备 root                      adb shell su -c id（uid=0）
    (3) 设备 ABI                       provision.device_abi
    (4) 主机 frida 版本                provision.host_frida_version
    (5) 设备 frida-server 运行且版本匹配  device.frida_server_running + best-effort 版本比对，
                                       auto_fix → provision.ensure_frida_server
    (6) mitmproxy 已安装               device.has_mitmproxy
    (7) CA 已信任                      auto_fix → provision.ensure_mitm_ca（否则只读 best-effort）

设计铁律（与 provision / device / capture 一致，GUI-ready / exe-ready）::

- **核心模块禁 print / typer.* / sys.exit / input()**；只 logging + 结构化返回。
  cli doctor 命令是唯一可 typer.echo 的薄包装（由集成单元做，不在本模块）。
- ``run`` **绝不把异常抛给调用方**：每项检查独立 try/except 转成 item，
  单点异常不中断其它项；整体再有外层兜底转结构化结果。
- 每个 except 必 logging（warning/exception），不裸 pass、不静默吞错。
- 耗时/分阶段（调 provision 自动修）前 on_progress 上报进度；回调异常吞 + logging。
- 全量 type hints；Callable 从 collections.abc 导入。

返回结构::

    {
        "ok": bool,                  # 所有关键项（_CRITICAL）均 ok
        "items": [
            {"name": str, "ok": bool, "detail": str, "fix_cmd": list[str]},
            ...
        ],
    }
"""

from __future__ import annotations

import logging
import re
import subprocess
from collections.abc import Callable

from apkscan.core import device, tools
from apkscan.dynamic import provision

logger = logging.getLogger(__name__)

# 检查项名称（常量，避免裸字符串漂移；cli / 测试以此识别项）。
_NAME_DEVICE = "在线设备"
_NAME_ROOT = "设备 root"
_NAME_ABI = "设备 ABI"
_NAME_HOST_FRIDA = "主机 frida 版本"
_NAME_FRIDA_SERVER = "设备 frida-server 运行且版本匹配"
_NAME_MITMPROXY = "mitmproxy 已安装"
_NAME_CA = "CA 已信任"

# 关键项：任一不 ok → 整体 ok=False。设备/ABI/frida/mitmproxy/CA 是抓包脱壳命门；
# root 单列为非关键（部分形态可不 root 抓 HTTP），但 CA / frida-server 多依赖它，
# 失败会通过这些关键项体现。
_CRITICAL: frozenset[str] = frozenset(
    {
        _NAME_DEVICE,
        _NAME_ABI,
        _NAME_HOST_FRIDA,
        _NAME_FRIDA_SERVER,
        _NAME_MITMPROXY,
        _NAME_CA,
    }
)


def _emit(on_progress: Callable[[str], None] | None, msg: str) -> None:
    """安全调用进度回调：None 跳过；回调抛异常吞掉 + logging，防 GUI 回调炸内核。"""
    logger.debug("[doctor] %s", msg)
    if on_progress is None:
        return
    try:
        on_progress(msg)
    except Exception:
        logger.exception("[doctor] on_progress 回调异常（已忽略）")


def _item(name: str, ok: bool, detail: str, fix_cmd: list[str] | None = None) -> dict:
    """构造单个检查项结果。"""
    return {"name": name, "ok": ok, "detail": detail, "fix_cmd": list(fix_cmd or [])}


def _uid0_in(proc: object) -> bool:
    """proc 成功退出且输出含 uid=0 → True；否则 False（不抛）。"""
    if proc is None:
        return False
    if getattr(proc, "returncode", 1) != 0:
        return False
    try:
        out = (getattr(proc, "stdout", "") or "") + " " + (getattr(proc, "stderr", "") or "")
    except Exception:
        logger.exception("[doctor] 解析 id 输出失败")
        return False
    return "uid=0" in out


def _device_is_rooted(serial: str | None = None) -> bool:
    """best-effort 判断设备是否 root，兼容两类 root 形态（不抛）：

    1. **su 型**（Magisk / 夜神 / 雷电 / MuMu 等）：``adb shell su -c id`` → uid=0。
    2. **adb root 型**（AVD Google APIs 镜像、雷电部分形态）：设备没有 su 二进制，
       但 adbd 本身已 root，``adb shell id`` 直接就是 uid=0。仅查 su 会把这类设备
       误判为未 root（无设备开发者最先接的 AVD 正属此类）。

    adb 缺失 / 无设备 / 两路皆非 uid=0 / 异常一律 False。
    """
    # 1) su 型。
    if _uid0_in(provision._adb(["shell", "su", "-c", "id"], serial)):
        return True
    # 2) adb root 型：su 不存在但 adbd 已 root（先 best-effort adb root 再查 id）。
    provision._adb_ok(["root"], serial)  # best-effort，失败不阻断
    if _uid0_in(provision._adb(["shell", "id"], serial)):
        return True
    logger.debug("[doctor] 两类 root 探测均未见 uid=0（su 型 + adb root 型）")
    return False


def _device_frida_version(serial: str | None = None) -> str:
    """best-effort 取设备端 frida-server 版本（``/data/local/tmp/frida-server --version``）。

    取不到 / 解析失败 → ''（不抛）。部分设备拿不到属正常，调用方据此只 warning 不阻断。
    """
    proc = provision._adb(
        ["shell", f"{provision._FRIDA_SERVER_REMOTE} --version"], serial
    )
    if proc is None or proc.returncode != 0:
        if proc is not None:
            logger.debug("[doctor] 设备 frida-server --version 非零退出：%s", proc.returncode)
        return ""
    try:
        text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except Exception:
        logger.exception("[doctor] 解析设备 frida-server 版本失败")
        return ""
    match = re.search(r"(\d+\.\d+\.\d+)", text)
    if match is None:
        logger.debug("[doctor] 无法从设备 frida-server 输出解析版本：%r", text.strip())
        return ""
    return match.group(1)


def _frida_ps_reachable(serial: str | None = None) -> bool:
    """``frida-ps -U`` 能连上设备 frida-server（exit 0）→ 确认 server 在跑且可达。

    比 ``adb shell ps | grep frida-server`` 的进程名启发式更可靠（进程名可能被截断/改名
    导致漏判，正是 --no-fix 误报"未运行"的根因）。frozen 时经 tools.frida_invocation
    自调用内置 frida-ps；缺工具 / 异常 → False（不抛）。
    """
    inv = tools.frida_invocation("frida-ps")
    if not inv:
        return False
    # 指定了 serial 用 -D <serial>（多设备精确）；否则 -U（单 USB/远程设备）。
    args = [*inv, "-D", serial] if serial else [*inv, "-U"]
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=device._DEFAULT_TIMEOUT,
            check=False,
        )
    except Exception:
        logger.debug("[doctor] frida-ps -U 探测异常（按未连接处理）", exc_info=True)
        return False
    return proc.returncode == 0


# ---------------------------------------------------------------------------
# 各检查项（每项内部 try/except 转 item，单点异常不中断 run）
# ---------------------------------------------------------------------------


def _check_device(serial: str | None) -> dict:
    """(1) 是否有在线 adb 设备。"""
    try:
        if not tools.has_adb():
            return _item(
                _NAME_DEVICE,
                False,
                "adb 不可用（frozen 同目录无 adb.exe / PATH 无 adb；请安装 platform-tools 并加入 PATH）",
                ["adb devices"],
            )
        serials = device.adb_devices()
        if not serials:
            return _item(
                _NAME_DEVICE,
                False,
                "未检测到在线设备（adb devices 无 device 状态条目）",
                ["adb devices", "adb kill-server && adb start-server"],
            )
        if serial and serial not in serials:
            return _item(
                _NAME_DEVICE,
                False,
                f"指定序列号 {serial} 不在在线设备列表：{serials}",
                ["adb devices"],
            )
        target = serial or serials[0]
        return _item(_NAME_DEVICE, True, f"在线设备：{target}（共 {len(serials)} 台）")
    except Exception:
        logger.exception("[doctor] 检查在线设备异常")
        return _item(_NAME_DEVICE, False, "检查在线设备时发生异常（详见日志）", ["adb devices"])


def _check_root(serial: str | None) -> dict:
    """(2) 设备是否 root（非关键项；CA / frida-server 多依赖它）。"""
    try:
        if _device_is_rooted(serial):
            return _item(_NAME_ROOT, True, "设备已 root（su -c id → uid=0）")
        return _item(
            _NAME_ROOT,
            False,
            "设备未 root 或无 su（无法装系统 CA / 起 frida-server；HTTPS 可能只抓密文）",
            ["adb root", "adb shell su -c id  # 期望 uid=0"],
        )
    except Exception:
        logger.exception("[doctor] 检查设备 root 异常")
        return _item(_NAME_ROOT, False, "检查设备 root 时发生异常（详见日志）", ["adb shell su -c id"])


def _check_abi(serial: str | None) -> dict:
    """(3) 设备首选 ABI（供 frida-server 选包）。"""
    try:
        abi = provision.device_abi(serial)
        if abi:
            return _item(_NAME_ABI, True, f"设备 ABI：{abi}")
        return _item(
            _NAME_ABI,
            False,
            "无法读取设备 ABI（无设备 / adb 不可用 / getprop 失败）",
            ["adb devices", "adb shell getprop ro.product.cpu.abi"],
        )
    except Exception:
        logger.exception("[doctor] 检查设备 ABI 异常")
        return _item(
            _NAME_ABI,
            False,
            "检查设备 ABI 时发生异常（详见日志）",
            ["adb shell getprop ro.product.cpu.abi"],
        )


def _check_host_frida() -> tuple[dict, str]:
    """(4) 主机 frida CLI 版本。返回 (item, host_ver)；host_ver 供 frida-server 项比对。"""
    try:
        ver = provision.host_frida_version()
        if ver:
            return _item(_NAME_HOST_FRIDA, True, f"主机 frida CLI 版本：{ver}"), ver
        return (
            _item(
                _NAME_HOST_FRIDA,
                False,
                "主机未安装 frida CLI（无法确定 frida-server 版本，也无法注入）",
                ["pip install frida-tools"],
            ),
            "",
        )
    except Exception:
        logger.exception("[doctor] 检查主机 frida 版本异常")
        return (
            _item(
                _NAME_HOST_FRIDA,
                False,
                "检查主机 frida 版本时发生异常（详见日志）",
                ["pip install frida-tools"],
            ),
            "",
        )


def _check_frida_server(
    serial: str | None,
    host_ver: str,
    *,
    auto_fix: bool,
    on_progress: Callable[[str], None] | None,
) -> dict:
    """(5) 设备 frida-server 在跑且版本与主机匹配；auto_fix 时调 ensure_frida_server。"""
    try:
        running = False
        try:
            running = device.frida_server_running(serial)
        except Exception:
            logger.exception("[doctor] frida_server_running 探测异常（按未运行处理）")
        if not running:
            # ps 进程名启发式可能漏判（名字被截断/改名）→ 用 frida-ps -U 权威探测：
            # 能连上设备 frida-server 即确认在跑。修 --no-fix 对已在跑的 server 误报未运行。
            running = _frida_ps_reachable(serial)

        if running:
            # best-effort 版本比对：拿不到设备端版本只 warning，不判失败。
            dev_ver = _device_frida_version(serial)
            if host_ver and dev_ver and host_ver != dev_ver:
                if auto_fix:
                    _emit(on_progress, "frida-server 版本与主机不一致，尝试重新部署匹配版本")
                    fix = provision.ensure_frida_server(
                        serial, download=True, on_progress=on_progress
                    )
                    return _fold_frida_fix(fix, host_ver)
                return _item(
                    _NAME_FRIDA_SERVER,
                    False,
                    f"frida-server 在跑但版本不匹配（设备 {dev_ver} ≠ 主机 {host_ver}），注入可能失败",
                    ["adb shell su -c 'pkill frida-server'", "pip install frida-tools"],
                )
            if host_ver and dev_ver and host_ver == dev_ver:
                return _item(
                    _NAME_FRIDA_SERVER, True, f"frida-server 在跑且版本匹配（{dev_ver}）"
                )
            # 拿不到设备端版本：在跑即视作 ok，附带说明无法核实版本。
            return _item(
                _NAME_FRIDA_SERVER,
                True,
                "frida-server 在跑（设备端版本无法核实，best-effort 视作匹配）",
            )

        # 未在跑。
        if auto_fix:
            _emit(on_progress, "frida-server 未运行，尝试自动部署/启动")
            fix = provision.ensure_frida_server(serial, download=True, on_progress=on_progress)
            return _fold_frida_fix(fix, host_ver)
        return _item(
            _NAME_FRIDA_SERVER,
            False,
            "设备 frida-server 未运行（--no-fix 未自动部署）",
            ["frida-ps -U  # 验证；或开启 --fix 自动部署"],
        )
    except Exception:
        logger.exception("[doctor] 检查 frida-server 异常")
        return _item(
            _NAME_FRIDA_SERVER,
            False,
            "检查 frida-server 时发生异常（详见日志）",
            ["frida-ps -U"],
        )


def _fold_frida_fix(fix: dict, host_ver: str) -> dict:
    """把 provision.ensure_frida_server 的结果折叠成 frida-server 检查项。"""
    ok = bool(fix.get("ok"))
    action = str(fix.get("action", ""))
    detail = str(fix.get("detail", ""))
    fix_cmd = fix.get("fix_cmd") or []
    if not isinstance(fix_cmd, list):
        fix_cmd = []
    if ok and action == "already_running":
        detail = detail or "frida-server 已在运行"
    elif ok and action == "deployed":
        ver = str(fix.get("version", "")) or host_ver
        detail = detail or f"已自动部署并启动 frida-server {ver}"
    return _item(_NAME_FRIDA_SERVER, ok, detail, list(fix_cmd))


def _check_mitmproxy() -> dict:
    """(6) mitmproxy / mitmdump 是否在 PATH。"""
    try:
        if device.has_mitmproxy():
            return _item(_NAME_MITMPROXY, True, "mitmproxy/mitmdump 已安装")
        return _item(
            _NAME_MITMPROXY,
            False,
            "mitmproxy/mitmdump 不在 PATH（无法抓包）",
            ["pip install mitmproxy"],
        )
    except Exception:
        logger.exception("[doctor] 检查 mitmproxy 异常")
        return _item(
            _NAME_MITMPROXY,
            False,
            "检查 mitmproxy 时发生异常（详见日志）",
            ["pip install mitmproxy"],
        )


def _check_ca(
    serial: str | None,
    *,
    auto_fix: bool,
    on_progress: Callable[[str], None] | None,
) -> dict:
    """(7) mitmproxy CA 是否装入设备信任库；auto_fix 时调 ensure_mitm_ca。

    HTTPS 抓明文命门：失败必须讲清、不假成功。
    """
    try:
        if auto_fix:
            _emit(on_progress, "检查/安装 mitmproxy CA 到设备信任库")
            ca = provision.ensure_mitm_ca(serial, on_progress=on_progress)
            ok = bool(ca.get("ok"))
            detail = str(ca.get("detail", ""))
            fix_cmd = ca.get("fix_cmd") or []
            if not isinstance(fix_cmd, list):
                fix_cmd = []
            action = str(ca.get("action", ""))
            if ok and not detail:
                detail = f"CA 已信任（{action or 'installed'}）"
            return _item(_NAME_CA, ok, detail, list(fix_cmd))

        # --no-fix：只读 best-effort，不做安装。
        installed = _ca_already_trusted(serial)
        if installed:
            return _item(_NAME_CA, True, "CA 已在设备系统信任库（best-effort 探测）")
        return _item(
            _NAME_CA,
            False,
            "CA 未确认装入设备信任库（--no-fix 未自动安装；HTTPS 可能只抓密文）",
            ["# 开启 --fix 自动安装，或参考 docs/dynamic-setup.md 手动装 CA"],
        )
    except Exception:
        logger.exception("[doctor] 检查 CA 异常")
        return _item(
            _NAME_CA,
            False,
            "检查 CA 时发生异常（详见日志）",
            ["# 参考 docs/dynamic-setup.md 手动装 CA"],
        )


def _ca_already_trusted(serial: str | None) -> bool:
    """best-effort 只读探测：mitmproxy CA 是否已在系统信任库（不安装、不抛）。

    复用 provision 算 subject_hash_old，再 ``adb shell ls`` 系统库目标文件。
    任何环节缺失 / 失败 → False。
    """
    try:
        ca_path = provision._mitm_ca_path()
        if not ca_path.exists():
            return False
        hash_hex = provision._subject_hash_old(ca_path)
        if not hash_hex:
            return False
        target = f"{provision._SYSTEM_CACERTS}/{hash_hex}.0"
        return provision._adb_ok(["shell", "ls", target], serial)
    except Exception:
        logger.exception("[doctor] best-effort 探测 CA 信任状态异常")
        return False


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------


def run(
    *,
    serial: str | None = None,
    auto_fix: bool = True,
    on_progress: Callable[[str], None] | None = None,
) -> dict:
    """逐项体检动态抓包/脱壳前置环境，能自动修的调 provision，修不了给 fix_cmd。绝不抛。

    Args:
        serial: 目标设备序列号（None → adb 默认设备）。
        auto_fix: True 时对 frida-server / CA 调用 provision 自动修复。
        on_progress: 可选进度回调（GUI-ready；None → no-op）。

    Returns:
        dict：{ok: bool, items: list[{name, ok, detail, fix_cmd}]}。
        ok = 所有关键项（_CRITICAL）均 ok。
    """
    try:
        return _run_impl(serial=serial, auto_fix=auto_fix, on_progress=on_progress)
    except Exception:
        logger.exception("[doctor] run 未预期异常（已转结构化结果）")
        return {
            "ok": False,
            "items": [
                _item(
                    "体检",
                    False,
                    "体检过程发生未预期异常（详见日志）",
                    ["adb devices"],
                )
            ],
        }


def _run_impl(
    *,
    serial: str | None,
    auto_fix: bool,
    on_progress: Callable[[str], None] | None,
) -> dict:
    """run 的实际逻辑（异常由外层 run 兜底转结构化）。"""
    items: list[dict] = []

    _emit(on_progress, "检查在线设备")
    items.append(_check_device(serial))

    _emit(on_progress, "检查设备 root")
    items.append(_check_root(serial))

    _emit(on_progress, "检查设备 ABI")
    items.append(_check_abi(serial))

    _emit(on_progress, "检查主机 frida 版本")
    host_item, host_ver = _check_host_frida()
    items.append(host_item)

    _emit(on_progress, "检查设备 frida-server")
    items.append(
        _check_frida_server(serial, host_ver, auto_fix=auto_fix, on_progress=on_progress)
    )

    _emit(on_progress, "检查 mitmproxy")
    items.append(_check_mitmproxy())

    _emit(on_progress, "检查 CA 信任")
    items.append(_check_ca(serial, auto_fix=auto_fix, on_progress=on_progress))

    ok = all(it["ok"] for it in items if it["name"] in _CRITICAL)
    return {"ok": ok, "items": items}


__all__ = ["run"]
