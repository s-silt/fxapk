"""apkscan.dynamic.provision — 纯 stdlib + adb 的设备/工具自动配置层。

职责（动态抓包/脱壳的"环境自动配齐"）::

    device_abi          查设备首选 ABI（getprop ro.product.cpu.abi）
    host_frida_version  查主机 frida CLI 版本（确保主机 / 设备 frida-server 版本一致）
    ensure_frida_server 设备没跑 frida-server 时按 ABI + 主机版本拼 GitHub releases URL，
                        urllib 下载、lzma 解压、adb push、chmod、后台起、验证
    ensure_mitm_ca      定位 ~/.mitmproxy CA，算 subject_hash_old，root 推系统信任库
                        （/system/etc/security/cacerts/<hash>.0），退路用户信任库

设计铁律（与 device / capture 一致，GUI-ready / exe-ready）::

- **核心模块禁 print / typer.* / sys.exit / input()**；只 logging + 结构化返回。
- 所有对外函数返回结构化 dict，**绝不把异常抛给调用方**（失败 → ok=False + fix_cmd）。
- 每个 except 必 logging（warning/exception），不裸 pass、不静默吞错。
- 可选依赖（cryptography）惰性 import 且容缺；外部工具（adb/frida/openssl/mitmdump）
  一律 shutil.which 先探，缺则结构化降级 + fix_cmd。
- 下载用 requests（自带 certifi，避免 macOS/Homebrew Python 的 urllib 默认 SSL 上下文
  缺 CA → SSLCertVerificationError）+ lzma + tempfile + hashlib。requests 已是运行期依赖。
- 所有 requests / subprocess 调用必带 timeout；临时文件 finally 清理（ignore errors）。
- 耗时/分阶段函数接受可选 on_progress 回调上报进度（None → no-op；回调异常吞 + logging）。
- 全量 type hints；Callable 从 collections.abc 导入。
"""

from __future__ import annotations

import hashlib
import logging
import lzma
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from apkscan.core import device, tools

logger = logging.getLogger(__name__)

# 设备 getprop ro.product.cpu.abi → frida 发行包 abi 串。
_FRIDA_ABI_MAP: dict[str, str] = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "armeabi": "arm",
    "x86_64": "x86_64",
    "x86": "x86",
}

# frida releases 下载地址模板。
_FRIDA_RELEASE_URL = (
    "https://github.com/frida/frida/releases/download/"
    "{ver}/frida-server-{ver}-android-{abi}.xz"
)

# frida-server 在设备上的部署路径。
_FRIDA_SERVER_REMOTE = "/data/local/tmp/frida-server"

# adb install 超时（秒）：大 APK / 加固包安装可能较慢。
_INSTALL_TIMEOUT = 180.0

# urllib 下载超时（秒）。GitHub releases 大文件，给足时间但仍有上限。
_DOWNLOAD_TIMEOUT = 60.0

# frida-server 起来后的验证轮询参数（次数 × 间隔秒）。
_VERIFY_RETRIES = 10
_VERIFY_INTERVAL = 1.0

# 等待 mitmdump 生成 CA 的轮询参数。
_CA_GEN_RETRIES = 20
_CA_GEN_INTERVAL = 0.5

# Android 系统 / 用户信任库目录。
_SYSTEM_CACERTS = "/system/etc/security/cacerts"
_USER_CACERTS = "/data/misc/user/0/cacerts-added"


# ---------------------------------------------------------------------------
# 进度上报（GUI-ready）：on_progress 为 None 时 no-op，回调异常吞 + logging。
# ---------------------------------------------------------------------------


def _emit(on_progress: Callable[[str], None] | None, msg: str) -> None:
    """安全调用进度回调：None 跳过；回调抛异常吞掉 + logging，防 GUI 回调炸内核。"""
    logger.debug("[provision] %s", msg)
    if on_progress is None:
        return
    try:
        on_progress(msg)
    except Exception:
        logger.exception("[provision] on_progress 回调异常（已忽略）")


# ---------------------------------------------------------------------------
# 私有 adb / subprocess 帮助器（仿 capture._adb：which 先探，超时，不抛）。
# ---------------------------------------------------------------------------


def _adb(extra: list[str], serial: str | None = None) -> subprocess.CompletedProcess[str] | None:
    """运行 adb 子命令，返回 CompletedProcess。缺 adb / 超时 / 异常 → None（不抛）。

    adb 走 tools.adb_path()（frozen 用同目录随包 adb.exe，源码用 PATH）。
    """
    exe = tools.adb_path()
    if not exe:
        logger.warning("[provision] adb 不可用，跳过：%s", " ".join(extra))
        return None
    args = [exe]
    if serial:
        args += ["-s", serial]
    args += extra
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=device._DEFAULT_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("[provision] adb 命令超时：%s", " ".join(extra))
        return None
    except OSError:
        logger.exception("[provision] adb 命令 OSError：%s", " ".join(extra))
        return None
    except Exception:
        logger.exception("[provision] adb 命令异常：%s", " ".join(extra))
        return None


def _adb_ok(extra: list[str], serial: str | None = None) -> bool:
    """运行 adb 子命令，returncode==0 → True；否则 False（含命令缺失/超时/异常）。"""
    proc = _adb(extra, serial)
    if proc is None:
        return False
    if proc.returncode != 0:
        # 带上 stderr 尾部：排障需要看到真因（如 "more than one device" / "device offline"
        # / "read-only file system"），否则只看到「非零退出」无从判断。
        err = (proc.stderr or "").strip()
        logger.warning(
            "[provision] adb 非零退出（%s）：%s%s",
            proc.returncode,
            " ".join(extra),
            f"（{err[-200:]}）" if err else "",
        )
        return False
    return True


def _shq(cmd: str) -> str:
    """POSIX 单引号包裹整条命令，使其经 adb shell 重拼+设备 shell 再分词后，作为**单个参数**
    传给 ``su -c``。

    实测血泪坑（Superuser.apk/KingUser 型 su）：``_adb(["shell","su","-c",cmd])`` 里 cmd 即便是
    单个 argv 元素，adb.exe 也会把 ``shell`` 之后的 argv **用空格重拼**成一条命令串下发，设备
    shell 再分词 → ``su -c pkill -f frida-server`` 中的 ``-f frida-server`` 被 su 当成**自己的
    选项**（打印 usage 退 2），``su -c cp a b && chmod ...`` 里的路径被 su 当成**用户名**（Unknown
    id）。单引号包裹后设备 shell 把整条当一个参数交给 su -c，flags/重定向/`&&`/`&` 才不外泄。
    """
    return "'" + cmd.replace("'", "'\\''") + "'"


def _su_ok(cmd: str, serial: str | None = None) -> bool:
    """以 root 跑 cmd，尝试多种 su 调用形态（兼容 Magisk / Superuser.apk / KingUser）。

    每条都把 cmd 单引号包裹成**单个** adb shell 参数（见 :func:`_shq`）。任一形态
    returncode==0 → True。全失败 → False（含无 su / 设备已锁）。
    """
    q = _shq(cmd)
    for form in (f"su -c {q}", f"su 0 -c {q}", f"su root -c {q}"):
        if _adb_ok(["shell", form], serial):
            return True
    return False


def _su_uid0(serial: str | None = None) -> bool:
    """设备 su 是否真能拿到 uid=0（权威 root 能力判定，不只是 returncode）。"""
    for form in ("su -c id", "su 0 -c id", "su root -c id"):
        proc = _adb(["shell", form], serial)
        if proc is not None and proc.returncode == 0 and "uid=0" in (proc.stdout or ""):
            return True
    return False


def _adbd_is_root(serial: str | None = None) -> bool:
    """adbd 当前是否 uid=0（AOSP rootful 镜像 ``adb root`` 后为真；此时 adb shell 直执即 root）。"""
    proc = _adb(["shell", "id"], serial)
    return proc is not None and proc.returncode == 0 and "uid=0" in (proc.stdout or "")


def _adb_root_shell(cmd: str, serial: str | None = None) -> bool:
    """以 root 跑一条设备 shell 命令：优先直接 ``adb shell``（``adb root`` 后 adbd 即
    uid0，AOSP rootful 镜像上最稳），失败再回退 ``adb shell su -c '<cmd>'``（Magisk/su 型设备）。

    实测教训：AOSP/模拟器 rootful 镜像上 ``su -c`` 行为不稳，而 ``adb root`` 后 adb shell
    本身就是 root，根本不必 su；而 Superuser.apk/KingUser 型设备 ``adb root`` 不支持、必须 su。
    两条都试以兼容两类 root。su 路径经 :func:`_su_ok` 正确单引号包裹（否则 cmd 的选项/`&&`
    会外泄给 su 本身）。
    """
    return _adb_ok(["shell", cmd], serial) or _su_ok(cmd, serial)


# ---------------------------------------------------------------------------
# device_abi / host_frida_version
# ---------------------------------------------------------------------------


def device_abi(serial: str | None = None) -> str:
    """返回设备首选 ABI（如 'arm64-v8a'）。adb 缺失/无设备/解析失败 → ''（不抛）。

    本模块自实现 subprocess（device 无 getprop 函数，不用其私有 _run）。
    """
    proc = _adb(["shell", "getprop", "ro.product.cpu.abi"], serial)
    if proc is None:
        return ""
    if proc.returncode != 0:
        logger.warning("[provision] getprop ro.product.cpu.abi 非零退出：%s", proc.returncode)
        return ""
    try:
        abi = (proc.stdout or "").strip()
    except Exception:
        logger.exception("[provision] 解析 getprop 输出失败")
        return ""
    if not abi:
        logger.warning("[provision] getprop ro.product.cpu.abi 返回空")
    return abi


def host_frida_version() -> str:
    """返回主机 frida CLI 版本（规范化 'x.y.z'）。frida 不可用 / 解析失败 → ''（不抛）。

    frozen 时经 tools.frida_invocation 自调用内置 frida；源码时用 PATH。
    """
    inv = tools.frida_invocation("frida")
    if not inv:
        logger.debug("[provision] frida CLI 不可用")
        return ""
    try:
        proc = subprocess.run(
            [*inv, "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=device._DEFAULT_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("[provision] frida --version 超时")
        return ""
    except Exception:
        logger.exception("[provision] frida --version 执行异常")
        return ""
    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    match = re.search(r"(\d+\.\d+\.\d+)", text)
    if match is None:
        logger.warning("[provision] 无法从 frida --version 解析版本：%r", text.strip())
        return ""
    return match.group(1)


# ---------------------------------------------------------------------------
# ensure_frida_server
# ---------------------------------------------------------------------------


def _download_and_extract(url: str, dest: Path, on_progress: Callable[[str], None] | None) -> str:
    """下载 .xz 并 lzma 解压到 dest。成功 → ''；失败 → 错误说明字符串（不抛）。

    用 requests 下载（自带 certifi CA bundle）——macOS/Homebrew Python 的 urllib 默认
    SSL 上下文常没接系统 CA，会 ``SSLCertVerificationError: unable to get local issuer
    certificate`` 下不动 GitHub。requests 已是本项目运行期依赖，零新增。
    """
    _emit(on_progress, f"下载 frida-server：{url}")
    try:
        import requests

        resp = requests.get(url, timeout=_DOWNLOAD_TIMEOUT)
        resp.raise_for_status()
        compressed = resp.content
    except requests.exceptions.HTTPError as exc:
        code = getattr(exc.response, "status_code", "?")
        logger.exception("[provision] frida-server 下载 HTTP 错误（%s）：%s", code, url)
        if code == 404:
            return f"该 frida 版本/ABI 不存在（HTTP 404）：{url}"
        return f"下载失败 HTTP {code}：{url}"
    except requests.exceptions.SSLError as exc:
        logger.exception("[provision] frida-server 下载 SSL 校验失败：%s", url)
        return f"SSL 证书校验失败（certifi 仍不通？）：{exc}"
    except requests.exceptions.Timeout:
        logger.exception("[provision] frida-server 下载超时：%s", url)
        return f"下载超时（>{_DOWNLOAD_TIMEOUT}s）：{url}"
    except requests.exceptions.RequestException as exc:
        logger.exception("[provision] frida-server 下载失败：%s", url)
        return f"无网络或无法访问 GitHub（{exc}）：{url}"
    except Exception:
        logger.exception("[provision] frida-server 下载异常：%s", url)
        return f"下载异常：{url}"

    _emit(on_progress, "lzma 解压 frida-server")
    try:
        raw = lzma.decompress(compressed)
    except lzma.LZMAError:
        logger.exception("[provision] frida-server lzma 解压失败")
        return "下载内容不是有效的 .xz（lzma 解压失败）"
    except Exception:
        logger.exception("[provision] frida-server 解压异常")
        return "解压异常"

    try:
        dest.write_bytes(raw)
    except OSError:
        logger.exception("[provision] 写出解压后的 frida-server 失败：%s", dest)
        return f"写出临时文件失败：{dest}"
    return ""


# frida-server 后台启动命令模板：把 std{out,err} 重定向、用 setsid/nohup 脱离 adb
# 会话，否则 adb shell 会一直挂在长驻进程的管道上直到 subprocess 超时（误判失败）。
_FRIDA_START_CMDS: tuple[str, ...] = (
    f"setsid {_FRIDA_SERVER_REMOTE} >/dev/null 2>&1 < /dev/null &",
    f"nohup {_FRIDA_SERVER_REMOTE} >/dev/null 2>&1 < /dev/null &",
)


def _start_frida_server_background(serial: str | None) -> bool:
    """后台拉起 frida-server，脱离 adb 会话（setsid→nohup 兜底）。不抛。

    长驻进程必须重定向 std{in,out,err} 并 setsid/nohup，否则 adb shell 会被进程的
    管道阻塞到 subprocess 超时，误把"已启动"判成失败。本函数负责把它拉起来，是否真在跑
    由调用方随后轮询 ``device.frida_server_running`` 判定。

    Returns:
        ``root_started``：拉起的 frida-server 是否以 **root** 运行——以**权威 root 能力**为准
        （adbd 本身 uid=0[AOSP rootful]，或 su 能拿 uid=0[su 型设备]），**与长驻启动命令那条
        不可靠的 returncode 解耦**（含 ``&`` 的后台命令会被管道阻塞到超时，returncode 不可信，
        故不能据它判 root）。ps 在 MuMu 上又看不到 frida-server 行、无法靠 ps 判 root。
    """
    # 先杀掉可能已在跑的**非 root** frida-server：su 型设备（adb root 不可用）上若先有非 root
    # 实例占着端口，root 实例就起不来 → frida-ps 能列进程但 spawn 注入失败（"need Gadget /
    # jailed Android"）。杀掉后再以 root 重起，确保 spawn 可用。失败无害（本就没在跑）。
    _su_ok("pkill -f frida-server", serial)
    _adb_ok(["shell", "pkill", "-f", "frida-server"], serial)

    # 权威 root 能力：adbd 已 root（AOSP rootful）则直执即 root；否则看 su 能否拿 uid=0。
    adb_root = _adbd_is_root(serial)
    su_root = False if adb_root else _su_uid0(serial)
    for cmd in _FRIDA_START_CMDS:
        # **root 优先**：spawn 注入必须 root frida-server。su 型设备先 su -c（正确单引号包裹）把
        # 端口占住；直执（adbd 为 root 则 root、否则非 root 兜底）。两条 setsid/nohup 都试。
        if su_root:
            _su_ok(cmd, serial)
        _adb_ok(["shell", cmd], serial)
    return adb_root or su_root


def _manual_frida_steps(ver: str, abi: str, fabi: str) -> list[str]:
    """无法自动部署时给可逐条复制的手动命令。"""
    url = _FRIDA_RELEASE_URL.format(ver=ver or "<ver>", abi=fabi or "<abi>")
    return [
        "adb devices",
        "adb shell getprop ro.product.cpu.abi",
        f"# 浏览器下载（设备 ABI={abi or '?'} → frida abi={fabi or '?'}，需与主机 frida 版本一致）：",
        url,
        "xz -d frida-server-*.xz",
        f"adb push frida-server {_FRIDA_SERVER_REMOTE}",
        f"adb shell su -c 'chmod 755 {_FRIDA_SERVER_REMOTE}'",
        # 后台启动务必重定向 + setsid/nohup，否则 adb shell 会挂住（长驻进程占管道）。
        f"adb shell su -c 'setsid {_FRIDA_SERVER_REMOTE} >/dev/null 2>&1 &'",
        "frida-ps -U  # 验证 frida-server 在跑",
    ]


def install_apk(apk_path: str, serial: str | None = None) -> dict:
    """把 APK 安装到设备（dynamic spawn 前置：``frida -f <pkg>`` 要 spawn 的是**已安装**的 app）。

    用 ``adb install -r -t -g``（-r 覆盖安装、-t 允许 test 包、-g 自动授运行时权限）。
    绝不抛，返回 ``{ok, detail}``：
    - 成功（输出含 Success）→ ok=True。
    - 已装同包但签名不同（INSTALL_FAILED_UPDATE_INCOMPATIBLE / signatures）→ ok=False，
      detail 提示先 ``adb uninstall <pkg>``（不自动卸载，避免误删用户设备上的同名 app 数据）。
    - adb 不可用 / apk 不存在 / 超时 / 非零 → ok=False + detail。
    """
    exe = tools.adb_path()
    if not exe:
        return {"ok": False, "detail": "adb 不可用，无法安装 APK 到设备"}
    if not apk_path or not Path(apk_path).is_file():
        return {"ok": False, "detail": f"APK 文件不存在，无法安装：{apk_path}"}

    args = [exe, *(["-s", serial] if serial else []), "install", "-r", "-t", "-g", apk_path]
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_INSTALL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("[provision] adb install 超时（%ss）：%s", _INSTALL_TIMEOUT, apk_path)
        return {"ok": False, "detail": f"adb install 超时（{_INSTALL_TIMEOUT:.0f}s）"}
    except Exception:
        logger.exception("[provision] adb install 异常：%s", apk_path)
        return {"ok": False, "detail": "adb install 异常（详见日志）"}

    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and "Success" in out:
        return {"ok": True, "detail": "APK 已安装到设备"}
    low = out.lower()
    if "signatures do not match" in low or "update_incompatible" in low:
        return {
            "ok": False,
            "detail": "设备上已装同包名但签名不同的 app；请先 `adb uninstall <包名>` 再重试",
        }
    return {"ok": False, "detail": f"adb install 失败：{out[-300:]}"}


def ensure_frida_server(
    serial: str | None = None,
    *,
    download: bool = True,
    on_progress: Callable[[str], None] | None = None,
) -> dict:
    """确保目标设备上 frida-server 在跑（必要时自动下载部署）。绝不抛。

    Returns:
        dict：{ok, action('already_running'|'deployed'|'skipped'|'error'),
              detail, version, abi, fix_cmd}。
    """
    # 外层兜底：任何内部未预期异常一律转结构化 error（契约红线"绝不抛"）。
    try:
        return _ensure_frida_server_impl(serial, download=download, on_progress=on_progress)
    except Exception:
        logger.exception("[provision] ensure_frida_server 未预期异常（已转结构化 error）")
        return {
            "ok": False,
            "action": "error",
            "detail": "部署 frida-server 过程发生未预期异常（详见日志）",
            "version": "",
            "abi": "",
            "fix_cmd": ["adb devices"],
        }


def _ensure_frida_server_impl(
    serial: str | None,
    *,
    download: bool,
    on_progress: Callable[[str], None] | None,
) -> dict:
    """ensure_frida_server 的实际逻辑（异常由外层 ensure_frida_server 兜底转结构化）。"""
    result: dict = {
        "ok": False,
        "action": "error",
        "detail": "",
        "version": "",
        "abi": "",
        "fix_cmd": [],
    }

    # 1) 已在跑 → 进一步确认是 **root**（spawn 注入必须 root frida-server；非 root 会被
    #    frida 判为 jailed、要求 Gadget 注入 → 脱壳/抓包 spawn 全失败）。非 root 则杀掉
    #    以 root 重启（自愈，无需用户手动 pkill）。
    try:
        if device.frida_server_running(serial):
            if device.frida_server_is_root(serial):
                result.update(
                    ok=True, action="already_running", detail="设备上 frida-server 已在运行（root）"
                )
                return result
            # 未确认 root（含 ps 看不到 frida-server 行的 MuMu 等）→ 杀掉以 root 重启。
            # **权威 root 信号 = _start_frida_server_background 是否经 su 把它真起起来**
            # （返回 root_started）：ps 在 MuMu 上看不到 frida-server 行，无法靠 is_root 判；
            # 而"running" 对非 root 实例同样为真，**只验 running 会把 jailed 误报成 root**
            # （实测：Superuser.apk 型 su 拒收旧的未加引号命令 → 旧非 root 实例还在跑 → 误判
            # restarted_as_root → 脱壳/抓包全 jailed 却显示成功）。故 root_started 为准。
            _emit(on_progress, "frida-server 未确认 root，杀掉以 root 重启（spawn 注入需 root）")
            logger.warning(
                "[provision] frida-server 未确认以 root 运行（spawn 会 jailed）；杀掉以 root 重启"
            )
            root_started = _start_frida_server_background(serial)
            for _ in range(_VERIFY_RETRIES):
                try:
                    running = device.frida_server_running(serial)
                except Exception:
                    logger.exception("[provision] root 重启后验证轮询异常")
                    running = False
                if running and root_started:
                    result.update(
                        ok=True,
                        action="restarted_as_root",
                        detail="未确认 root，已杀掉并以 root（su -c）重启 frida-server",
                    )
                    return result
                if running and not root_started:
                    # 在跑但 su 没把它起起来（设备 su 不接受 -c 形态 / 已锁）→ 仍是非 root，
                    # spawn 会 jailed。如实报告 + 给手动命令，不假成功（避免下游白走 spawn）。
                    su_uid0 = _su_uid0(serial)
                    detail = (
                        "frida-server 在跑但未能以 root 重启（设备 su 不接受标准 `su -c` 形态）："
                        + ("su 可拿 uid=0 但未起成功，请手动起" if su_uid0 else "su 不可用/已锁，无法获取 root")
                        + "；spawn 注入将被判 jailed，脱壳/运行时 hook 不可用。"
                    )
                    logger.warning("[provision] %s", detail)
                    result.update(ok=False, action="running_not_root", detail=detail)
                    result["fix_cmd"] = [
                        "adb shell su -c 'pkill -f frida-server'",
                        f"adb shell su -c 'setsid {_FRIDA_SERVER_REMOTE} >/dev/null 2>&1 &'",
                        "frida-ps -U  # 应能列出进程；spawn 仍 jailed 则 su 未给 root",
                    ]
                    return result
                time.sleep(_VERIFY_INTERVAL)
            # 重启后仍未见运行（su 受限 / 二进制架构不符？）→ 继续走下方部署流程兜底。
            logger.warning("[provision] 以 root 重启 frida-server 后仍未见运行；继续走部署流程兜底")
    except Exception:
        logger.exception("[provision] frida_server_running 探测异常（按未运行处理）")

    # 2) 取设备 ABI。
    abi = device_abi(serial)
    result["abi"] = abi
    if not abi:
        result["detail"] = "无法读取设备 ABI（无设备 / adb 不可用 / getprop 失败）"
        result["fix_cmd"] = ["adb devices", "adb shell getprop ro.product.cpu.abi"]
        return result

    # 3) 取主机 frida 版本（保证主机/设备版本一致）。
    ver = host_frida_version()
    result["version"] = ver
    if not ver:
        result["detail"] = "主机未安装 frida CLI，无法确定要部署的 frida-server 版本"
        result["fix_cmd"] = ["pip install frida-tools"]
        return result

    # 4) ABI 映射。
    fabi = _FRIDA_ABI_MAP.get(abi, "")
    if not fabi:
        result["detail"] = f"未知设备 ABI：{abi}（无对应 frida 发行包，请手动部署）"
        result["fix_cmd"] = _manual_frida_steps(ver, abi, fabi)
        return result

    # 5) download=False → 跳过自动部署，给完整手动命令。
    if not download:
        result.update(
            action="skipped",
            detail=f"未启用自动下载（download=False）；frida {ver} / abi {fabi} 请按命令手动部署",
        )
        result["fix_cmd"] = _manual_frida_steps(ver, abi, fabi)
        return result

    # 6) 下载 + 解压（requests[certifi] + lzma），写临时文件。
    url = _FRIDA_RELEASE_URL.format(ver=ver, abi=fabi)
    tmp_path: str | None = None
    try:
        fd, tmp_name = tempfile.mkstemp(prefix="frida-server-", suffix=".bin")
        os.close(fd)
        tmp_path = tmp_name
        err = _download_and_extract(url, Path(tmp_path), on_progress)
        if err:
            result["detail"] = err
            result["fix_cmd"] = _manual_frida_steps(ver, abi, fabi)
            return result

        # 7) adb root → push / chmod / 后台启动（chmod 优先直执、su 兜底，与 CA 安装一致）。
        _adb_ok(["root"], serial)  # best-effort：AOSP rootful 镜像后续 adb shell 即 uid0
        _emit(on_progress, f"adb push frida-server → {_FRIDA_SERVER_REMOTE}")
        if not _adb_ok(["push", tmp_path, _FRIDA_SERVER_REMOTE], serial):
            result["detail"] = "adb push frida-server 失败（设备离线 / 路径不可写？）"
            result["fix_cmd"] = _manual_frida_steps(ver, abi, fabi)
            return result

        _emit(on_progress, "chmod 755 frida-server（需 root）")
        if not _adb_root_shell(f"chmod 755 {_FRIDA_SERVER_REMOTE}", serial):
            result["detail"] = "chmod 755 失败：设备可能未 root（adb root 与 su 均不可用）"
            result["fix_cmd"] = _manual_frida_steps(ver, abi, fabi)
            return result

        _emit(on_progress, "后台启动 frida-server（需 root）")
        # frida-server 是长驻进程；若用 `su -c '... &'` 而不重定向 stdout/stderr，
        # 子进程会继承 adb shell 的管道 fd，adb shell 不会立即返回 → subprocess.run
        # 会吃满 timeout 被判失败，即便 frida-server 真起来了（frida-server 部署经典坑）。
        # 因此用 setsid/nohup 彻底脱离会话并把 std{in,out,err} 重定向掉，adb shell 才会
        # 立即返回。且**不以这一步的 returncode 判成败**——以第 8 步轮询 frida_server_running
        # 成功为准（命令本身超时/非零都不直接判失败）。
        root_started = _start_frida_server_background(serial)

        # 8) 轮询验证（启动成败以此为准，不看上一步 returncode）。
        _emit(on_progress, "验证 frida-server 是否在跑")
        for _ in range(_VERIFY_RETRIES):
            try:
                running = device.frida_server_running(serial)
            except Exception:
                logger.exception("[provision] frida_server_running 验证轮询异常")
                running = False
            if running and root_started:
                result.update(
                    ok=True,
                    action="deployed",
                    detail=f"已部署并以 root 启动 frida-server {ver}（abi {fabi}）",
                )
                return result
            if running and not root_started:
                # 部署成功且在跑，但 su 没把它起成 root（spawn 会 jailed）→ 如实报告、不假成功。
                detail = (
                    f"已部署 frida-server {ver}（abi {fabi}）且在跑，但未能以 root 启动"
                    "（设备 su 不接受标准 `su -c` 形态 / 已锁）；spawn 注入将 jailed，"
                    "脱壳/运行时 hook 不可用。"
                )
                logger.warning("[provision] %s", detail)
                result.update(ok=False, action="running_not_root", detail=detail)
                result["fix_cmd"] = _manual_frida_steps(ver, abi, fabi)
                return result
            time.sleep(_VERIFY_INTERVAL)

        result["detail"] = (
            f"已 push/启动 frida-server {ver}，但 {_VERIFY_RETRIES} 次验证仍未见进程在跑"
            "（设备可能未 root / su 不可用 / 启动被拒）"
        )
        result["fix_cmd"] = _manual_frida_steps(ver, abi, fabi)
        return result
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                logger.debug("[provision] 清理临时文件失败（忽略）：%s", tmp_path)


# ---------------------------------------------------------------------------
# ensure_mitm_ca
# ---------------------------------------------------------------------------


def _mitm_ca_path() -> Path:
    """mitmproxy CA 证书 PEM 的标准位置。"""
    return Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"


def _generate_ca(ca_path: Path, on_progress: Callable[[str], None] | None) -> bool:
    """跑一次 mitmdump 触发生成 CA：Popen → 轮询 pem 出现 → terminate。成功 → True（不抛）。

    frozen 时经 tools.frida_invocation 自调用内置 mitmdump；源码时用 PATH。
    """
    inv = tools.frida_invocation("mitmdump")
    if not inv:
        logger.warning("[provision] mitmdump/mitmproxy 不可用，无法生成 CA")
        return False
    _emit(on_progress, "运行一次 mitmdump 以生成 CA")
    proc: subprocess.Popen[bytes] | None = None
    try:
        proc = subprocess.Popen(
            [*inv, "--listen-port", "0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for _ in range(_CA_GEN_RETRIES):
            if ca_path.exists():
                return True
            time.sleep(_CA_GEN_INTERVAL)
        logger.warning("[provision] mitmdump 未在预期时间内生成 CA：%s", ca_path)
        return ca_path.exists()
    except Exception:
        logger.exception("[provision] 生成 mitmproxy CA 异常")
        return False
    finally:
        if proc is not None:
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5.0)
                    except subprocess.TimeoutExpired:
                        logger.warning("[provision] mitmdump 未及时退出，强杀")
                        proc.kill()
            except Exception:
                logger.exception("[provision] 停止 mitmdump 异常")


def _hash_via_openssl(pem_path: Path) -> str:
    """用 openssl CLI 算 subject_hash_old。openssl 缺失/失败 → ''（不抛）。"""
    exe = shutil.which("openssl")
    if exe is None:
        logger.debug("[provision] openssl 不在 PATH，跳过 openssl 算 hash")
        return ""
    try:
        proc = subprocess.run(
            [exe, "x509", "-inform", "PEM", "-subject_hash_old", "-in", str(pem_path), "-noout"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=device._DEFAULT_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("[provision] openssl subject_hash_old 超时")
        return ""
    except Exception:
        logger.exception("[provision] openssl subject_hash_old 执行异常")
        return ""
    if proc.returncode != 0:
        logger.warning("[provision] openssl subject_hash_old 非零退出：%s", proc.returncode)
        return ""
    out = (proc.stdout or "").strip().splitlines()
    first = out[0].strip() if out else ""
    if not re.fullmatch(r"[0-9a-fA-F]{8}", first):
        logger.warning("[provision] openssl subject_hash_old 输出非预期：%r", first)
        return ""
    return first.lower()


def _hash_via_cryptography(pem_path: Path) -> str:
    """退路：惰性 import cryptography 算 subject_hash_old。

    算法 = openssl X509_subject_name_hash_old：MD5(canonical DER subject) 前 4 字节小端 hex。
    cryptography 缺失 / 旧版无 public_bytes / 解析失败 → ''（不抛）。
    """
    try:
        from cryptography import x509
    except ImportError:
        logger.warning("[provision] cryptography 未安装，无法退路算 subject_hash_old")
        return ""
    except Exception:
        logger.exception("[provision] 导入 cryptography 异常")
        return ""
    try:
        pem_bytes = pem_path.read_bytes()
        cert = x509.load_pem_x509_certificate(pem_bytes)
        name_der = cert.subject.public_bytes()
    except AttributeError:
        logger.exception("[provision] cryptography 版本过旧（subject.public_bytes 不可用）")
        return ""
    except Exception:
        logger.exception("[provision] cryptography 解析证书 / 取 subject DER 失败")
        return ""
    digest = hashlib.md5(name_der).digest()  # noqa: S324  非安全用途，仅复刻 openssl 旧 hash
    val = digest[0] | digest[1] << 8 | digest[2] << 16 | digest[3] << 24
    return "%08x" % val


def _subject_hash_old(pem_path: Path) -> str:
    """算 CA 的 subject_hash_old：优先 openssl，退回 cryptography。皆不可用 → ''。"""
    h = _hash_via_openssl(pem_path)
    if h:
        return h
    return _hash_via_cryptography(pem_path)


def ensure_mitm_ca(
    serial: str | None = None,
    *,
    on_progress: Callable[[str], None] | None = None,
) -> dict:
    """把 mitmproxy CA 装入设备系统信任库（HTTPS 抓明文的命门）。绝不抛、不假成功。

    Returns:
        dict：{ok, action('already_trusted'|'installed_system'|'installed_user_store'|
              'skipped'|'error'), verified, detail, ca_path, subject_hash, store_path,
              fix_cmd}。

        ``verified``=True 仅当 CA 确证已被设备信任（系统库已装/已存在）；``ok`` 与
        ``verified`` 在本函数始终同值——``installed_user_store`` 路径只是把文件写进了
        用户库，Android 10+ 默认不生效（需 magisk 模块 + 重启），故 ok=verified=False，
        避免 doctor 把"已写入待生效"误判为"CA 已信任"。
    """
    # 外层兜底：任何内部未预期异常一律转结构化 error（契约红线"绝不抛"）。
    try:
        return _ensure_mitm_ca_impl(serial, on_progress=on_progress)
    except Exception:
        logger.exception("[provision] ensure_mitm_ca 未预期异常（已转结构化 error）")
        return {
            "ok": False,
            "action": "error",
            "verified": False,
            "detail": "安装 mitmproxy CA 过程发生未预期异常（详见日志）",
            "ca_path": "",
            "subject_hash": "",
            "store_path": "",
            "fix_cmd": ["adb devices"],
        }


def _ensure_mitm_ca_impl(
    serial: str | None,
    *,
    on_progress: Callable[[str], None] | None,
) -> dict:
    """ensure_mitm_ca 的实际逻辑（异常由外层 ensure_mitm_ca 兜底转结构化）。"""
    result: dict = {
        "ok": False,
        "action": "error",
        # verified：CA 是否**确证已被设备信任**（系统库已装/已存在）。区别于
        # installed_user_store——写入了但 Android 10+ 默认不生效，verified=False。
        # doctor 的 CA 关键项以 ok（=verified）为准，不把"已写入待生效"判为绿。
        "verified": False,
        "detail": "",
        "ca_path": "",
        "subject_hash": "",
        "store_path": "",
        "fix_cmd": [],
    }

    # 1) 定位 / 生成 CA。
    ca_path = _mitm_ca_path()
    if not ca_path.exists():
        _emit(on_progress, "未找到 mitmproxy CA，尝试生成")
        if not _generate_ca(ca_path, on_progress) or not ca_path.exists():
            result["detail"] = "未找到 mitmproxy CA 且无法自动生成（mitmproxy 未安装？）"
            result["fix_cmd"] = ["pip install mitmproxy", "mitmdump  # 运行一次生成 CA"]
            return result
    result["ca_path"] = str(ca_path)

    # 2) 算 subject_hash_old。
    _emit(on_progress, "计算 CA 的 subject_hash_old")
    hash_hex = _subject_hash_old(ca_path)
    if not hash_hex:
        result["detail"] = "无法计算 subject_hash_old（openssl 与 cryptography 均不可用）"
        result["fix_cmd"] = ["pip install cryptography"]
        return result
    result["subject_hash"] = hash_hex
    target_name = f"{hash_hex}.0"
    system_target = f"{_SYSTEM_CACERTS}/{target_name}"
    user_target = f"{_USER_CACERTS}/{target_name}"

    fix_cmd = _manual_ca_steps(str(ca_path), hash_hex)

    # 3) 幂等：系统库已存在同名证书 → already_trusted。
    if _adb_ok(["shell", "ls", system_target], serial):
        result.update(
            ok=True,
            action="already_trusted",
            verified=True,
            detail=f"系统信任库已存在 {target_name}",
            store_path=system_target,
        )
        return result

    # 中转路径：先 push 到可写的 /data/local/tmp，再在 root 上下文 cp 到目标分区。
    # 直接 `adb push` 到 /system 即便 remount 成功也常被 adbd（SELinux）拒绝——push 中转
    # + root shell cp 两步法（与 docs §6.2 一致）。
    staging = f"/data/local/tmp/{target_name}"

    # 4) 主路：adb root → remount → push 中转 → 直接 adb shell cp/chmod（su 兜底）。
    #    实测教训：`adb root` 后 adb shell 即 uid0，AOSP rootful 镜像直执比 `su -c` 稳；
    #    remount 也优先 `adb remount`，再直 mount，最后 su mount。
    _emit(on_progress, "尝试 adb root + remount /system 并推入系统信任库")
    _adb_ok(["root"], serial)  # best-effort，失败不阻断（部分设备 adbd 本就 root）
    remounted = (
        _adb_ok(["remount"], serial)
        or _adb_root_shell("mount -o rw,remount /system", serial)
        or _adb_root_shell("mount -o rw,remount /", serial)
    )
    if remounted and _adb_ok(["push", str(ca_path), staging], serial):
        if _adb_root_shell(
            f"cp {staging} {system_target} && chmod 644 {system_target}", serial
        ):
            result.update(
                ok=True,
                action="installed_system",
                verified=True,
                detail=f"已装入系统信任库：{system_target}",
                store_path=system_target,
            )
            return result
        logger.warning("[provision] 系统库中转 push 成功但 cp/chmod 失败（直执与 su 均不行）")

    # 5) 退路：用户信任库（Android 10+ /system 只读 / magisk）。**不报 ok=True**：
    #    仅把文件 cp 到 /data/misc/user/0/cacerts-added 在 Android 10+ 默认并不生效，
    #    需配套 magisk 模块（MoveCert/AlwaysTrustUserCerts）且通常需重启，否则 App 仍
    #    不信任该 CA、HTTPS 照样只抓密文。报 ok=True 会让 doctor 把"CA 已信任"误判为
    #    通过 → 与"CA 是 HTTPS 命门、务必不假成功"红线相冲突。故此路 ok=False、
    #    verified=False，由 doctor/调用方提示"已写入但待 magisk/重启后复检"。
    _emit(on_progress, "系统库不可写，写入用户信任库（需 magisk/重启生效，不算已信任）")
    _adb_root_shell(f"mkdir -p {_USER_CACERTS}", serial)  # best-effort
    if _adb_ok(["push", str(ca_path), staging], serial) and _adb_root_shell(
        f"cp {staging} {user_target} && chmod 644 {user_target} "
        f"&& chown system:system {user_target}",
        serial,
    ):
        result.update(
            ok=False,
            action="installed_user_store",
            verified=False,
            detail=(
                f"已写入用户信任库 {user_target}，但 Android 10+ 默认不生效，"
                "需配套 magisk 模块（MoveCert/AlwaysTrustUserCerts）并重启后才被 App 信任；"
                "未生效前 HTTPS 仍只抓密文"
            ),
            store_path=user_target,
            fix_cmd=fix_cmd,
        )
        return result

    # 6) 两路皆败 → 明确无 root，HTTPS 只能抓密文。
    result["detail"] = (
        "无法把 CA 装入系统信任库（设备无 root / /system 只读且无 magisk）；"
        "HTTPS 将只抓到密文（证书不被应用信任）"
    )
    result["fix_cmd"] = fix_cmd
    return result


def _manual_ca_steps(ca_path: str, hash_hex: str) -> list[str]:
    """无法自动装 CA 时给可逐条复制的完整手动命令（与 docs §6.2 一致）。

    采用 push 到中转目录 + ``su -c cp`` 两步法：直接 ``adb push`` 到 /system 即便
    remount 成功也常被 adbd（非 root 上下文 / SELinux）拒绝，须用 su 在 root 上下文写。
    """
    name = f"{hash_hex}.0"
    staging = f"/data/local/tmp/{name}"
    return [
        f"openssl x509 -inform PEM -subject_hash_old -in {ca_path} -noout  # → {hash_hex}",
        "adb root",
        "adb remount   # 或：adb shell su -c 'mount -o rw,remount /system'（夜神/雷电常需）",
        # 推到中转目录再 su cp 到系统库（不直推 /system，避开 adbd 限制）。
        f"adb push {ca_path} {staging}",
        f"adb shell su -c 'cp {staging} {_SYSTEM_CACERTS}/{name} && chmod 644 {_SYSTEM_CACERTS}/{name}'",
        "# Android 10+ /system 只读时退路（需 magisk 模块 + 重启才生效，否则仍抓密文）：",
        f"adb shell su -c 'mkdir -p {_USER_CACERTS}'",
        f"adb push {ca_path} {staging}",
        f"adb shell su -c 'cp {staging} {_USER_CACERTS}/{name} && chmod 644 {_USER_CACERTS}/{name}'",
    ]


__all__ = [
    "device_abi",
    "host_frida_version",
    "ensure_frida_server",
    "ensure_mitm_ca",
]
