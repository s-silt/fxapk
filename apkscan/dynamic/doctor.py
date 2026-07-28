"""apkscan.dynamic.doctor — 动态抓包/脱壳前置环境结构化体检 + 自动修。

取证用途：为取证样本自身在分析机上的运行时观测准备环境（设备/root/frida/mitmproxy/CA），不面向任何第三方基础设施。

逐项检查接上设备一键体检需要的环境，能自动修的调用 provision，修不了给出
可逐条复制的 fix_cmd::

    (1) 在线设备                       device.has_device / adb_devices
    (2) 设备 root                      adb shell su -c id（uid=0）
    (3) 设备 ABI                       provision.device_abi
    (4) 主机 frida 版本                provision.host_frida_version
    (5) 设备 frida-server 可真实注入        /proc 进程路径 + root UID + 版本 + attach smoke，
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
_NAME_DEVICE_TCPDUMP = "设备 tcpdump（floor pcap 底座）"
_NAME_DEVICE_NETWORK = "设备联网基线"
# PCAP-first 深度能力（信息性、非关键——不进 _CRITICAL、不影响整体 ok）。
_NAME_QUIC_META = "QUIC 元数据解析"
_NAME_QUIC_DECRYPT = "QUIC Initial 解密（cryptography）"
_NAME_TSHARK = "tshark 深度后端"

# ★floor-only profile 的关键项：只看 **floor pcap 底座**（设备 + root + 设备 tcpdump），**不含**
# frida/mitmproxy/CA——PCAP-first 下只想 tcpdump 抓 pcap 的用户，不该被"主机没装 frida"判成环境不完整
# （这正是外部评价 #1 点的问题）。缺 frida/mitm 时对应项仍体检、仅信息性，不拉整体 ok。
# ★设备联网基线并入两个 profile 的关键项：设备不通公网时抓不到有效业务流量，
#   floor-only 也一样。判不出来时该项按通过处理（见 _check_device_network），
#   所以不会在不支持 dumpsys 的设备上假失败。
_FLOOR_CRITICAL: frozenset[str] = frozenset(
    {_NAME_DEVICE, _NAME_ROOT, _NAME_DEVICE_TCPDUMP, _NAME_DEVICE_NETWORK}
)

# 关键项（full profile）= floor pcap 底座 ∪ 完整明文栈（ABI/frida/mitmproxy/CA）。任一不 ok → 整体 ok=False。
# ★须并入 _FLOOR_CRITICAL（codex 复审 P1-1）：能力矩阵规定 both/full 的 PCAP 底座同样需要
# adb+device+root+device_tcpdump，缺 root/tcpdump 时 full 也抓不到 floor.pcap——不能因 _CRITICAL 漏了
# root/device_tcpdump 而在缺 floor 底座时误报"完整环境可用"（frida/mitm/CA 全 ok 也不行）。
_CRITICAL: frozenset[str] = _FLOOR_CRITICAL | frozenset(
    {
        _NAME_ABI,
        _NAME_HOST_FRIDA,
        _NAME_FRIDA_SERVER,
        _NAME_MITMPROXY,
        _NAME_CA,
    }
)

#: 支持的体检 profile。
DOCTOR_PROFILES: tuple[str, ...] = ("full", "floor-only")


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
            encoding="utf-8",
            errors="replace",
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


#: 网络归因的四种结局。写成常量是为了让 doctor 的 detail 文案与测试断言同一口径。
_ATTR_BASELINE_BAD = "基线异常"
_ATTR_DEGRADED = "验收后退化"
_ATTR_STABLE = "前后正常"
_ATTR_UNKNOWN = "无法判定"


def _attribute_network(
    before: "device.DeviceNetworkState", after: "device.DeviceNetworkState"
) -> tuple[str, str]:
    """据前后快照判断网络问题该不该算到 Frida 头上。返回 ``(结局, 说明)``。

    ★这一层存在的全部意义是挡住一类误判：真机上「脱壳后全机断网」曾被记成样本反 Frida，
    实测根因是 Wi-Fi 静态地址导致 Android 网络验证失败并临时拉黑 BSSID —— 与 Frida 无关。
    基线本来就坏的，事后再坏也不能归因于 Frida。
    """
    b, a = before.healthy, after.healthy
    if b is False:
        return _ATTR_BASELINE_BAD, (
            "Frida 验收**之前**网络已异常，本次网络问题不得归因于 Frida 或样本反 Frida；"
            f"请先修设备网络（基线：{before.detail}）"
        )
    if b is True and a is False:
        return _ATTR_DEGRADED, (
            "Frida 验收后网络退化（验收前正常）；建议停 frida-server 并人工恢复网络后复测，"
            f"再判断是否与注入相关（验收后：{after.detail}）"
        )
    if b is True and a is True:
        return _ATTR_STABLE, "Frida 验收前后设备网络均正常"
    return _ATTR_UNKNOWN, (
        "无法可靠判定设备网络状态（设备不支持 dumpsys / 解析失败）；"
        "不将其计为 Frida 导致的问题"
    )


def _check_device_network(
    before: "device.DeviceNetworkState", after: "device.DeviceNetworkState", outcome: str
) -> dict:
    """独立的「设备联网基线」检查项。unknown 判通过但带警告——不在不支持的设备上假失败。"""
    if outcome == _ATTR_BASELINE_BAD:
        return _item(
            _NAME_DEVICE_NETWORK, False,
            f"动态采集前设备网络已异常：{before.detail}",
            [
                "在设备 Wi-Fi 设置里改用 DHCP（勿手工静态地址）",
                "确认无 VPN / 代理 / 策略路由干扰",
                "adb shell ip route show table all  # 应有 default via",
            ],
        )
    if outcome == _ATTR_DEGRADED:
        return _item(
            _NAME_DEVICE_NETWORK, False,
            f"动态采集后设备网络退化：采集前 {before.detail}；采集后 {after.detail}",
            [
                "adb shell su -c 'pkill -f frida-server'",
                "在设备上手工重连 Wi-Fi 后复测（工具不会自动改网络设置）",
            ],
        )
    if outcome == _ATTR_STABLE:
        return _item(_NAME_DEVICE_NETWORK, True, f"设备网络正常：{after.detail}")
    return _item(
        _NAME_DEVICE_NETWORK, True,
        f"设备网络状态未知（不判失败）：{after.detail or before.detail or '无可用信息'}",
        ["adb shell dumpsys connectivity | head -40"],
    )


def _check_frida_server(
    serial: str | None,
    host_ver: str,
    *,
    auto_fix: bool,
    on_progress: Callable[[str], None] | None,
) -> tuple[dict, dict]:
    """(5) 严格验收 root frida-server、版本与真实 attach；auto_fix 时自愈。

    返回 ``(frida 项, 设备联网基线项)``：验收前后各采一次网络状态，把「网络本来就坏」
    与「验收后才坏」分开——否则前者会被记成样本反 Frida。
    """
    before = device.read_network_state(serial)
    try:
        probe = device.frida_server_probe(serial, expected_version=host_ver)
        if probe.ok:
            frida_item = _item(_NAME_FRIDA_SERVER, True, probe.detail)
        elif auto_fix:
            _emit(on_progress, f"frida-server 动态注入验收未通过，尝试自愈：{probe.detail}")
            fix = provision.ensure_frida_server(serial, download=True, on_progress=on_progress)
            frida_item = _fold_frida_fix(fix, host_ver)
        else:
            frida_item = _item(
                _NAME_FRIDA_SERVER,
                False,
                f"frida-server 动态注入未就绪：{probe.detail}（--no-fix 未自动修复）",
                ["fxapk doctor --fix", "adb shell su -c 'pkill -f frida-server'"],
            )
    except Exception:
        logger.exception("[doctor] 检查 frida-server 异常")
        frida_item = _item(
            _NAME_FRIDA_SERVER,
            False,
            "检查 frida-server 时发生异常（详见日志）",
            ["frida-ps -U"],
        )

    # ★以哪个 UID 跑着，与"跑没跑着"是两件事。实测踩过：Windows 侧启动命令的引号被 adb 拆开，
    #   frida-server 以 UID=2000（shell）起来了——进程在、frida-ps 能枚举，但 spawn/attach 目标
    #   一概失败，现象酷似样本反 Frida，实则权限不足。判据取 /proc/<pid>/status 的真实 UID。
    frida_item = _annotate_frida_uid(frida_item, serial)

    after = device.read_network_state(serial)
    outcome, note = _attribute_network(before, after)
    frida_item["detail"] = f"{frida_item['detail']}　[网络归因：{outcome}] {note}"
    # 基线异常时不让 Frida 项背锅：它的失败可能只是网络不通的结果。
    if outcome == _ATTR_BASELINE_BAD and not frida_item["ok"]:
        frida_item["detail"] += "　★该失败可能由基线网络问题导致，先修网络再判 Frida。"
    return frida_item, _check_device_network(before, after, outcome)


def _annotate_frida_uid(item: dict, serial: str | None) -> dict:
    """核 frida-server 的真实运行 UID；非 0 即判不就绪（就地改写检查项）。绝不抛。

    ★判不出来时**不**改判：``None`` 表示这台设备读不到 ``/proc/<pid>/status``（无 root shell、
      pidof 不可用等），那是"不知道"，不是"以非 root 跑着"——把读不到当成坏了，正是本仓库
      反复要避免的那类误读。
    """
    try:
        uid = device.frida_server_uid(serial)
    except Exception:
        logger.exception("[doctor] 读取 frida-server UID 异常")
        return item
    if uid is None:
        item["detail"] += "　[运行 UID：判不出来，未据此改判]"
        return item
    if uid == 0:
        item["detail"] += "　[运行 UID：0（root）✓]"
        return item
    item["ok"] = False
    item["detail"] += (
        f"　★frida-server 实际以 UID={uid} 运行（非 root）——进程在、frida-ps 也枚举得到，"
        "但 spawn/attach 目标应用会失败，现象酷似样本反 Frida。"
        "常见成因：启动命令经 adb 传递时引号被拆开，su -c 后半段丢失。"
    )
    fixes = item.setdefault("fix_cmd", [])
    if isinstance(fixes, list):
        fixes.append("adb shell su -c 'pkill -f frida-server'")
        fixes.append("fxapk doctor --fix")
    return item


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
            ["# 开启 --fix 自动安装，或手动把 CA 装入设备系统信任库"],
        )
    except Exception:
        logger.exception("[doctor] 检查 CA 异常")
        return _item(
            _NAME_CA,
            False,
            "检查 CA 时发生异常（详见日志）",
            ["# 手动把 CA 装入设备系统信任库"],
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
    profile: str = "full",
    on_progress: Callable[[str], None] | None = None,
) -> dict:
    """逐项体检动态抓包/脱壳前置环境，能自动修的调 provision，修不了给 fix_cmd。绝不抛。

    Args:
        serial: 目标设备序列号（None → adb 默认设备）。
        auto_fix: True 时对 frida-server / CA 调用 provision 自动修复。
        profile: ``full``（默认，完整抓包栈：设备/ABI/frida/mitm/CA 都当关键项）| ``floor-only``
            （只把 floor pcap 底座 设备/root/tcpdump 当关键项，缺 frida/mitm/CA 仍体检但不判整体失败）。
        on_progress: 可选进度回调（GUI-ready；None → no-op）。

    Returns:
        dict：{ok: bool, profile, items: list[{name, ok, detail, fix_cmd}]}。
        ok = 该 profile 的关键项均 ok。
    """
    profile = profile if profile in DOCTOR_PROFILES else "full"
    try:
        return _run_impl(serial=serial, auto_fix=auto_fix, profile=profile, on_progress=on_progress)
    except Exception:
        logger.exception("[doctor] run 未预期异常（已转结构化结果）")
        return {
            "ok": False,
            "profile": profile,
            "items": [
                _item(
                    "体检",
                    False,
                    "体检过程发生未预期异常（详见日志）",
                    ["adb devices"],
                )
            ],
        }


def _check_pcap_capabilities() -> list[dict]:
    """PCAP-first 深度能力可用性（信息性、非关键）——让用户知道『pcap 里没抓到 SNI』是样本没发，还是本机
    缺依赖导致解不出（★外部复审：不要静默降级，否则易把"缺依赖"误读为"样本无此流量"）。

    - QUIC 元数据解析：纯 stdlib，恒可用。
    - QUIC Initial 解密：需 cryptography（androguard 已传递引入，但缺失时降级为仅元数据 → 缺 SNI/ALPN）。
    - tshark 深度后端：PATH 有 tshark 才能抽明文 HTTP + 用 keylog 解密 TLS。
    均非关键项（不进 _CRITICAL、不影响整体 ok），仅报告可用状态。
    """
    import shutil

    items: list[dict] = [
        _item(_NAME_QUIC_META, True, "可用（纯 stdlib：QUIC 长包头 / 版本 / DCID / SCID 解析）"),
    ]
    # ★复审 #3：查**实际用到的 AEAD 子模块**是否可用（复用 QUIC 解密同一探测），而非只 import 顶层
    #   cryptography——部分损坏安装/后端加载失败时顶层能 import 但 aead 子模块不可用、会误报可用。
    from apkscan.dynamic import pcap_ingest

    if pcap_ingest._quic_crypto_available():
        items.append(_item(_NAME_QUIC_DECRYPT, True, "可用（cryptography AEAD 就绪 → QUIC Initial 解密恢复 SNI/ALPN）"))
    else:
        items.append(
            _item(
                _NAME_QUIC_DECRYPT, False,
                "不可用：cryptography AEAD 子模块不可用 → QUIC 仅解析元数据（无 SNI/ALPN）；"
                "`pip install fxapk[pcap]` 启用解密",
                ["pip install fxapk[pcap]"],
            )
        )
    if shutil.which("tshark"):
        items.append(_item(_NAME_TSHARK, True, "可用（tshark 在 PATH → 明文 HTTP 抽取 + TLS Key Log 解密）"))
    else:
        items.append(
            _item(_NAME_TSHARK, False, "不可用：PATH 无 tshark（可选深度后端；装 Wireshark/tshark 启用明文 HTTP/解密）")
        )
    return items


def _check_device_tcpdump(serial: str | None = None) -> dict:
    """floor pcap 底座：设备侧 tcpdump 可用（已装 command -v，或配了 FXAPK_TCPDUMP_BIN 可 push）。

    ★floor-only 模式的核心前置——无 tcpdump 则 floor pcap 抓不了；与 frida/mitmproxy 无关。
    """
    try:
        from apkscan.dynamic import capabilities as _caps
        from apkscan.dynamic.capability_probe import _probe_device_side

        # 无在线设备时不探 adb（否则 provision 会刷"root 命令失败"假告警）——直接判无法体检。
        if not device.has_device():
            return _item(_NAME_DEVICE_TCPDUMP, False, "无在线设备，无法体检 floor pcap 底座（先接设备）")
        ok = _caps.CAP_DEVICE_TCPDUMP in _probe_device_side(serial)
    except Exception:
        logger.exception("[doctor] 检查设备 tcpdump 异常")
        ok = False
    if ok:
        return _item(_NAME_DEVICE_TCPDUMP, True, "设备侧 tcpdump 可用（floor pcap 底座就绪）")
    return _item(
        _NAME_DEVICE_TCPDUMP,
        False,
        "设备无 tcpdump 且未配可 push 的二进制 → floor pcap 抓不了；请在设备装 tcpdump 或设 FXAPK_TCPDUMP_BIN",
    )


def _run_impl(
    *,
    serial: str | None,
    auto_fix: bool,
    profile: str,
    on_progress: Callable[[str], None] | None,
) -> dict:
    """run 的实际逻辑（异常由外层 run 兜底转结构化）。profile=floor-only 时只把 floor 底座当关键项。"""
    items: list[dict] = []

    # ★floor-only profile 只要求 PCAP 底座——对增强项（frida-server / CA）只做只读体检，绝不因默认
    #   --fix 就下载部署 frida-server、往设备系统信任库装 CA（codex 复审 P1-3：floor-only 抓 pcap
    #   不该有 frida/CA 的写副作用；full profile 现状不变，仍自动修）。
    enhancement_fix = auto_fix and profile != "floor-only"

    _emit(on_progress, "检查在线设备")
    items.append(_check_device(serial))

    _emit(on_progress, "检查设备 root")
    items.append(_check_root(serial))

    _emit(on_progress, "检查设备 tcpdump（floor pcap 底座）")
    items.append(_check_device_tcpdump(serial))

    _emit(on_progress, "检查设备 ABI")
    items.append(_check_abi(serial))

    _emit(on_progress, "检查主机 frida 版本")
    host_item, host_ver = _check_host_frida()
    items.append(host_item)

    _emit(on_progress, "检查设备 frida-server（含前后网络归因）")
    frida_item, network_item = _check_frida_server(
        serial, host_ver, auto_fix=enhancement_fix, on_progress=on_progress
    )
    items.append(frida_item)
    items.append(network_item)

    _emit(on_progress, "检查 mitmproxy")
    items.append(_check_mitmproxy())

    _emit(on_progress, "检查 CA 信任")
    items.append(_check_ca(serial, auto_fix=enhancement_fix, on_progress=on_progress))
    items.extend(_check_pcap_capabilities())  # PCAP 深度能力可用性（信息性、非关键）

    # ★按 profile 选关键项集：floor-only 只看 floor pcap 底座（缺 frida/mitm/CA 不拉整体 ok）。
    critical = _FLOOR_CRITICAL if profile == "floor-only" else _CRITICAL
    ok = all(it["ok"] for it in items if it["name"] in critical)
    return {"ok": ok, "items": items, "profile": profile}


__all__ = ["run"]
