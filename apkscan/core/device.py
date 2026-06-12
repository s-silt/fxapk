"""动态能力探测助手：设备 / Frida / mitmproxy 是否可用。

设计铁律：
- 纯 subprocess + shutil.which，全部 try/except + logging + 超时，**绝不抛异常**，
  探测不到一律返回安全默认值（False / 空列表）。
- 本模块**不得 import apkscan.core.registry**（registry 反过来 import 本模块，避免循环导入）。

供 registry.detect_capabilities 与 apkscan.dynamic（unpack/capture）模块共用。
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess

from apkscan.core import tools

logger = logging.getLogger(__name__)

# adb / frida 子命令的默认超时（秒）。设备无响应时不应卡死主流程。
_DEFAULT_TIMEOUT = 5.0
# `adb start-server` 冷启 / 版本不匹配重启较慢，给足超时（无设备也只是起 server，不卡等）。
_START_SERVER_TIMEOUT = 20.0
# `adb devices` 枚举超时：略宽于默认，吸收 server 刚就绪后的 USB 扫描尾延迟。
_DEVICES_TIMEOUT = 10.0
# `adb connect` 单端口超时（秒）：localhost 关闭端口 TCP RST 瞬间拒绝，给个小上界兜底。
_CONNECT_TIMEOUT = 3.0

# 常见 Android 模拟器的 adb 端口（adb server 重启后不在标准 5555-5585 扫描范围的需显式
# connect，否则设备掉线、命令 exit 1）。MuMu 12=16384 是最常见的坑。best-effort 连接：
# 已连/关闭端口都瞬间返回，不显著拖慢。
_EMULATOR_ADB_ENDPOINTS: tuple[str, ...] = (
    "127.0.0.1:16384",  # MuMu 12
    "127.0.0.1:7555",   # MuMu 6 / X
    "127.0.0.1:5555",   # 通用模拟器 / LDPlayer / MuMu Pro(macOS)
    "127.0.0.1:62001",  # 夜神 Nox
    "127.0.0.1:21503",  # 逍遥 Memu
)

# 合法 Android 包名形态：仅字母/数字/下划线/点。
_PACKAGE_RE = re.compile(r"^[A-Za-z0-9_.]+$")


def is_valid_package(package: str) -> bool:
    """包名是否形态合法（仅字母/数字/下划线/点）。

    防御性校验：包名源自样本 manifest（attacker 可控输入）。下发 frida/adb 全走 argv 列表
    （无 shell、无经典注入），但仍校验形态以挡住异常字符（空格 / ``;&$`/`` 等），符合
    "样本输入不可信"的威胁模型——畸形包名直接拒绝，不下发到设备。
    """
    return bool(package) and _PACKAGE_RE.match(package) is not None


def _run(args: list[str], timeout: float = _DEFAULT_TIMEOUT) -> subprocess.CompletedProcess | None:
    """运行外部命令并捕获输出。任何失败（缺命令/超时/非零退出/异常）返回 None，绝不抛。

    ``adb`` 走 tools.adb_path()（frozen 用同目录随包 adb.exe，源码用 PATH）；
    其它命令仍走 shutil.which。
    """
    if not args:
        exe = None
    elif args[0] == "adb":
        exe = tools.adb_path() or None
    else:
        exe = shutil.which(args[0])
    if exe is None:
        logger.debug("命令不在 PATH，跳过：%s", args[0] if args else "(空)")
        return None
    try:
        return subprocess.run(
            [exe, *args[1:]],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("命令超时（%ss）：%s", timeout, " ".join(args))
        return None
    except Exception:
        logger.exception("命令执行异常：%s", " ".join(args))
        return None


# ---------------------------------------------------------------------------
# 设备（adb）
# ---------------------------------------------------------------------------


def ensure_adb_server() -> None:
    """同步确保 adb server 已启动并就绪（绝不抛）。

    为什么需要（真机实测 bug）：本工具结束时 ``kill-server`` 不留残留 → 每次 adb 操作
    多遇**冷 server**；且系统若另有不同版本 adb，会触发 server 版本不匹配的 kill+重启。
    这些都让紧接着的 ``adb devices`` 赶上 server 冷启/重启 → **空表，误判「无设备」**
    （而 ``adb shell`` 等后续命令因 server 已被前一条拉热而正常 → 出现「root/ABI/frida
    全 OK 但『在线设备』FAIL」的矛盾）。先同步 ``adb start-server``（给足超时）把 server
    拉起 / 版本重启完成，后续枚举才可靠。无设备时 start-server 也只是起 server，不卡等设备。

    并对常见模拟器 adb 端口做 best-effort ``adb connect``：MuMu 12（端口 16384）等模拟器
    挂在标准 5555-5585 扫描范围外，server 重启后不会被自动重连 → 设备掉线、命令 exit 1
    （MuMu 实测：手动 ``adb connect 127.0.0.1:16384`` 后一切恢复）。连一遍把它们拉回来
    （已连/关闭端口都瞬间返回，不显著拖慢）。
    """
    _run(["adb", "start-server"], timeout=_START_SERVER_TIMEOUT)
    # 已能看到在线设备 → 不再 connect：对已可见的 MuMu 重复 connect 会加一条重复 transport，
    # 导致后续无 -s 命令报 "more than one device" → getprop/push/ps 一连串 exit 1（实测坑）。
    # 仅在看不到设备时（server 重启后 MuMu 16384 掉线）才逐个 best-effort connect，**一连上即停**
    # （避免多端口同时连同一设备造成重复入口）。
    if _online_serials_quiet():
        return
    for endpoint in _EMULATOR_ADB_ENDPOINTS:
        _run(["adb", "connect", endpoint], timeout=_CONNECT_TIMEOUT)
        if _online_serials_quiet():
            return


def _parse_online_serials(stdout: str) -> list[str]:
    """从 `adb devices` 输出解析 **device 状态** 的序列号（忽略 offline/unauthorized）。不抛。"""
    serials: list[str] = []
    try:
        for raw in stdout.splitlines()[1:]:  # 首行是 "List of devices attached"
            line = raw.strip()
            if not line or "\t" not in line:
                continue
            serial, state = line.split("\t", 1)
            if serial.strip() and state.strip() == "device":
                serials.append(serial.strip())
    except Exception:
        logger.exception("解析 adb devices 输出失败")
        return []
    return serials


def _online_serials_quiet() -> list[str]:
    """跑一次 `adb devices` 解析在线序列号（**不经 ensure_adb_server，避免递归**）。失败 → []。"""
    proc = _run(["adb", "devices"], timeout=_DEVICES_TIMEOUT)
    if proc is None or proc.returncode != 0:
        return []
    return _parse_online_serials(proc.stdout)


def adb_devices() -> list[str]:
    """解析 `adb devices`，返回**在线**设备序列号列表（状态为 device 的行）。

    先 :func:`ensure_adb_server` 把 server 拉热 / 把掉线模拟器 connect 回来，避免冷启竞态空表。
    adb 缺失 / 未启动 / 解析失败 → 返回空列表（不抛）。
    """
    ensure_adb_server()
    proc = _run(["adb", "devices"], timeout=_DEVICES_TIMEOUT)
    if proc is None or proc.returncode != 0:
        if proc is not None:
            logger.debug("adb devices 非零退出：%s", proc.returncode)
        return []
    return _parse_online_serials(proc.stdout)


def has_device() -> bool:
    """是否有至少一台在线 adb 设备。"""
    return bool(adb_devices())


def _is_localhost_serial(serial: str) -> bool:
    """serial 是否为 localhost tcp transport（127.0.0.1:* / localhost:*）。"""
    s = serial.strip().lower()
    return s.startswith("127.0.0.1") or s.startswith("localhost")


def select_target_serial() -> str | None:
    """从在线设备里**钉定单台**目标 serial，下游一律带 ``-s <serial>`` / frida ``-D <serial>``。

    真机实测 P0 根因：模拟器（MuMu/夜神/雷电）常被 adb 列成**多条 transport**（如
    ``emulator-5554`` + ``127.0.0.1:7555`` 实为同一台），尤其 ``adb root`` 触发重连后。
    若下游 adb/frida 命令不指定设备 → ``more than one device/emulator`` → 代理/CA/reverse/
    getprop/frida 部署一连串 exit 1 → 脱壳/抓包全挂。本函数据此钉定一个 serial（**单设备
    假设**：fxapk 一次只调证一台），消解歧义。

    选择优先级（同一台的多条目里挑最稳的那条；多台真机里挑一台）：
      1. ``emulator-*`` 开头：模拟器原生 transport，比 tcp ``connect`` 上来的条目更稳。
      2. 非 ``127.0.0.1``/``localhost`` 的 USB 真机 serial。
      3. 兜底：排序后第一个（确定性，避免每次跑选到不同条目）。

    Returns:
        0 个在线 → None（下游 serial=None：照旧不带 -s、frida 用 -U，**完全向后兼容**）；
        1 个 → 它（不告警，单设备本就是常态）；
        多个 → 按上述优先级选定一个并 **log warning**（提示其余被忽略）。绝不抛。
    """
    serials = adb_devices()
    if not serials:
        return None
    if len(serials) == 1:
        return serials[0]

    ordered = sorted(serials)  # 确定性排序，作为兜底与组内稳定次序
    emulators = [s for s in ordered if s.startswith("emulator-")]
    usb_reals = [s for s in ordered if not s.startswith("emulator-") and not _is_localhost_serial(s)]
    if emulators:
        chosen = emulators[0]
    elif usb_reals:
        chosen = usb_reals[0]
    else:
        chosen = ordered[0]

    logger.warning(
        "检测到多个 adb 设备/transport（可能是同一模拟器的多条目）：%s；"
        "已钉定 %s，其余忽略（fxapk 单设备假设）",
        ", ".join(serials),
        chosen,
    )
    return chosen


def frida_spawn_hint(output: str) -> str:
    """frida spawn 失败输出 → 按具体特征返回可操作中文提示（区分两类常见根因）；无匹配 → 空串。

    - ``unable to find application``：目标 app **未安装**在设备上（``frida -f <包名>`` 要 spawn
      的是已安装的 app）。auto 会自动 ``adb install``；手动则装好再试。
    - ``need Gadget`` / ``jailed``：**frida-server 未以 root 运行**（su 型设备上非 root 实例
      先占了端口）；frida-ps 能列进程（故 doctor 误判 OK），但 spawn 注入必须 root。

    注意：不匹配过宽的 "failed to spawn"（它对上述两类都出现，无法区分根因）。
    """
    if not output:
        return ""
    low = output.lower()
    if "unable to find application" in low:
        return (
            "（目标 app 未安装在设备上：frida -f <包名> 要 spawn 的是已安装的 app。"
            "fxapk auto 现会自动 adb install；手动则 `adb install -r <apk>` 装好后重试）"
        )
    if "need gadget" in low or "jailed" in low:
        return (
            "（疑似 frida-server 未以 root 运行：spawn 注入必须 root frida-server。"
            "请先 `adb shell su -c 'pkill frida-server'` 杀掉非 root 实例再重跑"
            "（fxapk 会以 root 重启），或手动 "
            "`adb shell su -c '/data/local/tmp/frida-server >/dev/null 2>&1 &'`）"
        )
    return ""


# ---------------------------------------------------------------------------
# 工具是否安装（PATH 探测）
# ---------------------------------------------------------------------------


def has_frida() -> bool:
    """frida CLI 是否可用（frozen 看内置 frida_tools；源码看 PATH）。"""
    return tools.has_frida()


def has_frida_dexdump() -> bool:
    """frida-dexdump 是否可用（frozen 看内置 frida_dexdump；源码看 PATH）。"""
    return tools.has_frida_dexdump()


def has_mitmproxy() -> bool:
    """mitmproxy（或 mitmdump）是否可用（frozen 看内置 mitmproxy；源码看 PATH）。"""
    return tools.has_mitmproxy()


# ---------------------------------------------------------------------------
# frida-server 运行状态（best-effort）
# ---------------------------------------------------------------------------


def frida_ps_reachable(serial: str | None = None) -> bool:
    """``frida-ps -U``/``-D <serial>`` 能连上设备 frida-server（exit 0）→ 确认在跑且可达。

    比 ``adb shell ps`` 的进程名启发式**更可靠**：进程名可能被截断/改名导致 ps 漏判
    （正是 doctor --no-fix 曾误报「未运行」、以及 unpack/capture 误判「缺 frida-server」
    的根因）。frozen 时经 ``tools.frida_invocation`` 自调用内置 frida-ps；缺工具/异常 → False。
    """
    inv = tools.frida_invocation("frida-ps")
    if not inv:
        return False
    args = [*inv, "-D", serial] if serial else [*inv, "-U"]
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_DEFAULT_TIMEOUT,
            check=False,
        )
    except Exception:
        logger.debug("frida-ps 探测异常（按未连接处理）", exc_info=True)
        return False
    return proc.returncode == 0


def frida_server_is_root(serial: str | None = None) -> bool:
    """frida-server 是否**确认**以 root 运行（spawn 注入必须 root，否则 frida 判设备 jailed）。

    解析 ``adb shell ps`` 里 frida-server 行的 USER 列。**严格**：仅当明确解析到 root 属主
    才返回 True；ps 失败 / 找不到 frida-server 行（进程名被截断改名、MuMu 等 ps 格式不认）/
    非 root 属主 / 解析异常 —— 一律返回 **False**（= 未确认 root）。

    为什么严格而非保守：调用方（ensure_frida_server）据此决定「是否需要以 root 重启」。
    若保守判 True，MuMu 上 ps 看不到 frida-server 行就会误判已 root、跳过重启 → 非 root 实例
    一直 spawn 失败（jailed）。严格判 False 则触发 su -c 重启；用 su -c 起的即 root，重启后
    用 ``frida_server_running``（frida-ps 可达）验证即可——代价仅是「确认不了 root 时多重启
    一次」，对 su 可用的设备无害。
    """
    args = ["adb"]
    if serial:
        args += ["-s", serial]
    args += ["shell", "ps", "-A"]
    proc = _run(args)
    if proc is None or proc.returncode != 0:
        fallback = ["adb"]
        if serial:
            fallback += ["-s", serial]
        fallback += ["shell", "ps"]
        proc = _run(fallback)
    if proc is None or proc.returncode != 0:
        return False  # 探测不到 → 未确认 root
    try:
        for line in proc.stdout.splitlines():
            if "frida-server" not in line and "frida_server" not in line:
                continue
            parts = line.split()
            if not parts:
                continue
            # ps -A（toybox）首列为 USER；明确 root → True，其它属主 → False。
            return parts[0].strip().lower() == "root"
    except Exception:
        logger.exception("解析 ps 判定 frida-server 属主失败")
        return False
    return False  # 没找到 frida-server 行（进程改名/ps 不认）→ 未确认 root → 触发以 root 重启


def frida_server_running(serial: str | None = None) -> bool:
    """判断目标设备上 frida-server 是否在跑（best-effort，绝不抛）。

    两段式（与 doctor 一致，避免 unpack/capture 漏判）：
      1. ``adb [-s serial] shell ps`` 进程名启发式（快）；命中即 True。
      2. ps 没命中（含探测失败 / 进程名被截断改名）→ 用 :func:`frida_ps_reachable`
         （``frida-ps -U``）权威兜底确认。两者都不确认才返回 False。
    """
    args = ["adb"]
    if serial:
        args += ["-s", serial]
    args += ["shell", "ps", "-A"]

    proc = _run(args)
    if proc is None or proc.returncode != 0:
        # 部分 Android 版本 `ps -A` 不支持，回退到 `ps`。
        fallback = ["adb"]
        if serial:
            fallback += ["-s", serial]
        fallback += ["shell", "ps"]
        proc = _run(fallback)

    if proc is not None and proc.returncode == 0:
        try:
            if "frida-server" in proc.stdout or "frida_server" in proc.stdout:
                return True
        except Exception:
            logger.exception("解析 ps 输出查找 frida-server 失败")

    # ps 没命中 / 探测失败 → frida-ps 权威兜底（进程名截断改名场景，或 adb shell ps 不可用）。
    return frida_ps_reachable(serial)
