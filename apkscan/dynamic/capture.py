"""apkscan.dynamic.capture — 真·抓包：mitmproxy + frida SSL unpinning + adb 代理。

目标：在**有真机 + frida + mitmproxy** 时，对运行中的目标应用做真实流量抓取，
绕过证书绑定（cert pinning），从流量里提取运行时网络端点（source="runtime"），
汇总写出 ``out/runtime_report.json``；缺任一前置条件时返回 status="skipped" + 手册
（playbook，给出可手动复现的完整取证步骤），reason 写明缺什么。

编排流程（前置满足时）::

    1. 起 mitmdump 子进程：mitmdump -w <out>/flows.mitm（监听 8080）。
    2. adb 设全局代理 + adb reverse（让设备流量回流到主机 mitmproxy）。
    3. frida 注入内置通用 SSL unpinning 脚本并 spawn 目标 app。
    4. 抓 duration 秒后停止，清理代理 / frida / mitmdump 子进程。
    5. 解析 flows.mitm（mitmproxy python 包可用则读出 host/url，否则只记原始路径），
       命中的 → Endpoint(source="runtime")，写 out/runtime_report.json。

设计铁律（与 dynamic.__init__ / device 一致）：
- 设备/工具探测一律走 apkscan.core.device（纯 subprocess、不抛）。
- try/except 必须 logging，不裸 pass、不静默吞错；finally 清理所有子进程。
- 返回值严格遵守 DynamicResult 契约；任何失败 → status="error"，不抛给 CLI。
- 全程 type hints。
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from apkscan.core import device
from apkscan.core.models import Endpoint, Evidence
from apkscan.dynamic import (
    STATUS_DONE,
    STATUS_ERROR,
    STATUS_SKIPPED,
    DynamicResult,
    empty_result,
)
from apkscan.report import json as report_json

logger = logging.getLogger(__name__)

# 抓包用的本机代理监听端口（mitmproxy 默认 8080）。
_PROXY_HOST = "127.0.0.1"
_PROXY_PORT = 8080

# mitmdump 子进程在 duration 到点后额外等待的缓冲（秒），给落盘 flow 文件留时间。
_STOP_BUFFER = 10.0

# 子进程优雅退出的等待上限（秒），超时则强杀。
_TERMINATE_TIMEOUT = 5.0

# 子进程 stderr 尾部保留字符数（记日志 / reason，防刷屏）。
_STDERR_TAIL = 2000


class _MitmStartupError(RuntimeError):
    """mitmdump 启动后立即退出（端口占用/证书目录不可写/参数不支持等）。"""

# 内置通用 frida SSL unpinning 脚本：覆盖 OkHttp3 CertificatePinner、
# javax.net.ssl.X509TrustManager（自定义 TrustManager 全放行）、TrustManagerImpl
# （Android N+ 系统校验入口）。best-effort：单个 hook 失败不影响其它。
FRIDA_UNPINNING_JS: str = r"""
// apkscan 内置通用 SSL unpinning（best-effort，覆盖最常见的 pinning 路径）。
Java.perform(function () {
    // 1) 自定义 TrustManager：替换为全放行的 X509TrustManager。
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            name: 'org.apkscan.TrustAllManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var TrustManagers = [TrustManager.$new()];
        var SSLContextInit = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        );
        SSLContextInit.implementation = function (km, tm, sr) {
            SSLContextInit.call(this, km, TrustManagers, sr);
        };
        console.log('[apkscan] SSLContext TrustManager hooked');
    } catch (e) {
        console.log('[apkscan] SSLContext hook skip: ' + e);
    }

    // 2) OkHttp3 CertificatePinner.check：直接返回（放行）。
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List')
            .implementation = function (host, peerCertificates) {
                console.log('[apkscan] OkHttp3 CertificatePinner.check bypass: ' + host);
                return;
            };
        console.log('[apkscan] OkHttp3 CertificatePinner hooked');
    } catch (e) {
        console.log('[apkscan] OkHttp3 hook skip: ' + e);
    }

    // 3) Android N+ TrustManagerImpl.verifyChain：返回原始链（跳过 pin 校验）。
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (
            untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData
        ) {
            console.log('[apkscan] TrustManagerImpl.verifyChain bypass: ' + host);
            return untrustedChain;
        };
        console.log('[apkscan] TrustManagerImpl hooked');
    } catch (e) {
        console.log('[apkscan] TrustManagerImpl hook skip: ' + e);
    }
});
"""


def run(
    package: str,
    out_dir: str = "out",
    duration: int = 60,
    *,
    out: str | None = None,
) -> DynamicResult:
    """对运行中的目标应用做真机抓包，提取运行时端点。

    Args:
        package: 目标应用包名（设备上运行/抓包）。
        out_dir: 产物 / 报告输出目录。
        duration: 抓包时长（秒）。
        out: ``out_dir`` 的关键字别名（CLI 以 ``out=`` 调用，与 unpack.run 一致；
             二者取其一，out 优先）。

    Returns:
        DynamicResult 契约 dict。前置不满足 → status="skipped" + playbook；
        满足并完成 → status="done"（artifacts/report_paths 填充）；
        过程异常 → status="error"。绝不抛异常给调用方。
    """
    if out is not None:
        out_dir = out

    out_path = Path(out_dir)
    try:
        out_path.mkdir(parents=True, exist_ok=True)
    except Exception:
        logger.exception("创建输出目录失败：%s", out_dir)
        result = empty_result(STATUS_ERROR, f"无法创建输出目录 {out_dir}")
        return result

    # --- 前置能力探测：缺任一 → skipped + 手册 ---------------------------
    missing = _detect_missing()
    if missing:
        reason = "缺少前置条件：" + "、".join(missing)
        logger.info("[capture] %s；返回手册（playbook）", reason)
        result = empty_result(STATUS_SKIPPED, reason)
        result["playbook"] = _build_playbook(package, out_dir, duration)
        return result

    # --- 前置满足：真·抓包编排 ------------------------------------------
    logger.info("[capture] 前置满足，开始真机抓包：package=%s duration=%ds", package, duration)
    return _capture(package, out_path, duration)


# ---------------------------------------------------------------------------
# 能力探测
# ---------------------------------------------------------------------------


def _detect_missing() -> list[str]:
    """返回缺失的前置条件名列表（空 = 全部就绪）。

    顺序：设备 / frida / mitmproxy。每项探测均走 device 模块（不抛）。
    """
    missing: list[str] = []
    try:
        if not device.has_device():
            missing.append("在线 adb 设备")
    except Exception:
        logger.exception("[capture] 设备探测异常，视为无设备")
        missing.append("在线 adb 设备")

    try:
        if not device.has_frida():
            missing.append("frida")
    except Exception:
        logger.exception("[capture] frida 探测异常，视为缺失")
        missing.append("frida")

    try:
        if not device.has_mitmproxy():
            missing.append("mitmproxy")
    except Exception:
        logger.exception("[capture] mitmproxy 探测异常，视为缺失")
        missing.append("mitmproxy")

    # 设备上 frida-server 是否在跑（与 unpack 口径一致）：host 有 frida CLI 但设备
    # frida-server 没起来时，注入会失败、抓包绕不过证书绑定，应提前判为缺失。
    try:
        if device.has_device() and not device.frida_server_running():
            missing.append("设备上运行中的 frida-server")
    except Exception:
        logger.exception("[capture] frida-server 运行状态探测异常")
        missing.append("设备上运行中的 frida-server")

    return missing


# ---------------------------------------------------------------------------
# 手册（skipped 时给出可手动复现的完整取证步骤）
# ---------------------------------------------------------------------------


def _build_playbook(package: str, out_dir: str, duration: int) -> list[str]:
    """生成手动抓包 playbook（缺前置条件时给操作员照做即可复现）。"""
    flows = str(Path(out_dir) / "flows.mitm")
    return [
        "# 前置：连接已 root 真机/模拟器，安装 frida-server 并启动，主机装 mitmproxy + frida-tools。",
        f"1. 启动抓包代理：mitmdump -w {flows}（监听 {_PROXY_HOST}:{_PROXY_PORT}）。",
        f"2. 让设备走主机代理：adb shell settings put global http_proxy {_PROXY_HOST}:{_PROXY_PORT}",
        f"   （或 USB 反向端口：adb reverse tcp:{_PROXY_PORT} tcp:{_PROXY_PORT}，再把设备代理设为 {_PROXY_HOST}:{_PROXY_PORT}）。",
        "3. 信任 mitmproxy CA：浏览器访问 http://mitm.it 下载 CA，"
        "推为系统级信任证书（Android 7+ 用户证书默认不被 app 信任，需 root 推到 /system/etc/security/cacerts/ "
        "并 chmod 644，按 subject_hash_old 命名 <hash>.0）。",
        "4. 绕过证书绑定（cert pinning）：frida 注入通用 SSL unpinning 脚本并启动 app："
        f"frida -U -f {package} -l unpinning.js --no-pause"
        "（unpinning.js 内容见本模块 FRIDA_UNPINNING_JS：覆盖 OkHttp3 CertificatePinner / "
        "X509TrustManager / TrustManagerImpl）。",
        f"5. 操作 app（登录/支付/拉配置等触发网络），持续约 {duration} 秒采集流量。",
        f"6. 停止 mitmdump，得到 {flows}；用 mitmproxy python 包读取流提取 host/url，"
        "归为运行时端点（source=runtime）写入 runtime_report.json。",
        "7. 还原设备：adb shell settings delete global http_proxy；"
        f"adb reverse --remove tcp:{_PROXY_PORT}。",
    ]


# ---------------------------------------------------------------------------
# 真·抓包编排
# ---------------------------------------------------------------------------


def _capture(package: str, out_path: Path, duration: int) -> DynamicResult:
    """编排 mitmdump + adb 代理 + frida unpinning + 启 app，到时停并解析流量。

    所有子进程在 finally 中清理（terminate→kill），proxy/reverse 在 finally 还原。
    """
    result = empty_result(STATUS_DONE, "")
    playbook: list[str] = []
    flows_file = out_path / "flows.mitm"

    mitm_proc: subprocess.Popen[bytes] | None = None
    frida_proc: subprocess.Popen[bytes] | None = None
    proxy_set = False
    reverse_set = False

    try:
        # 1) 起 mitmdump（-w flows.mitm）。超时 = duration + 缓冲。
        mitm_proc = _start_mitmdump(flows_file)
        playbook.append(f"启动 mitmdump -w {flows_file}（监听 {_PROXY_HOST}:{_PROXY_PORT}）")
        # 存活确认：mitmdump 若因端口被占用 / 证书目录不可写 / 参数不支持而当场退出，
        # Popen 本身不抛——必须主动检测，否则会照常 sleep 满 duration 并以"成功 0 端点"
        # 收尾，把"代理根本没起来"静默成"真的没抓到"。
        if mitm_proc is not None and mitm_proc.poll() is not None:
            err = _read_proc_stderr(mitm_proc)
            msg = (
                f"mitmdump 启动后立即退出（端口 {_PROXY_PORT} 被占用 / 证书目录不可写 / "
                f"参数不支持？）stderr 尾部：{err}"
            )
            logger.error("[capture] %s", msg)
            result["status"] = STATUS_ERROR
            result["reason"] = msg
            raise _MitmStartupError(msg)

        # 2) adb 代理 + reverse，把设备流量回流到主机 mitmproxy。
        reverse_set = _adb_reverse()
        if reverse_set:
            playbook.append(f"adb reverse tcp:{_PROXY_PORT} tcp:{_PROXY_PORT}")
        proxy_set = _adb_set_proxy()
        if proxy_set:
            playbook.append(f"adb 设全局代理 {_PROXY_HOST}:{_PROXY_PORT}")

        # 3) frida 注入通用 SSL unpinning 并 spawn 目标 app。
        frida_proc = _start_frida_unpinning(package, out_path)
        if frida_proc is not None:
            playbook.append(f"frida 注入 SSL unpinning 并启动 {package}")

        # 4) 抓 duration 秒。
        playbook.append(f"采集流量约 {duration} 秒")
        _wait(duration)

    except _MitmStartupError:
        # status/reason 已在抛出点设好；跳到 finally 清理（mitmdump 已死，其它子进程未起）。
        pass
    except Exception:
        logger.exception("[capture] 抓包编排过程异常")
        result["status"] = STATUS_ERROR
        result["reason"] = "抓包编排过程异常（详见日志）"
    finally:
        # 5) 清理：先停 frida（让 app 网络收尾），再撤代理/reverse，最后停 mitmdump（落盘）。
        _terminate(frida_proc, "frida")
        if proxy_set:
            _adb_clear_proxy()
            playbook.append("还原：清除设备全局代理")
        if reverse_set:
            _adb_remove_reverse()
            playbook.append(f"还原：adb reverse --remove tcp:{_PROXY_PORT}")
        _terminate(mitm_proc, "mitmdump")

    # 6) 解析 flows，提运行时端点，写 runtime_report.json。
    artifacts: list[str] = []
    if flows_file.exists():
        artifacts.append(str(flows_file))

    endpoints = _parse_flows(flows_file)
    # 抓包失败（mitmdump 没起来 / 编排异常）时，产出的 runtime_report 基于不完整/未抓全
    # 的流量，必须在报告里标明，避免它伪装成正常结果被下游误用。
    capture_ok = result["status"] != STATUS_ERROR
    report_path = _write_runtime_report(package, out_path, endpoints, complete=capture_ok)
    report_paths = [report_path] if report_path else []

    if capture_ok:
        playbook.append(
            f"解析 {flows_file.name} 提取运行时端点 {len(endpoints)} 个 → {Path(report_path).name if report_path else 'runtime_report.json'}"
        )
        result["reason"] = f"抓包完成，提取运行时端点 {len(endpoints)} 个"

    result["artifacts"] = artifacts
    result["report_paths"] = report_paths
    result["playbook"] = playbook
    return result


def _start_mitmdump(flows_file: Path) -> subprocess.Popen[bytes]:
    """启动 mitmdump 子进程（-w flows_file）。失败抛异常由上层 finally 兜底清理。"""
    exe = shutil.which("mitmdump") or shutil.which("mitmproxy")
    if exe is None:  # _detect_missing 已确认存在，此处防御
        raise RuntimeError("mitmdump/mitmproxy 不在 PATH")
    args = [
        exe,
        "-w",
        str(flows_file),
        "--listen-host",
        _PROXY_HOST,
        "--listen-port",
        str(_PROXY_PORT),
    ]
    logger.info("[capture] 启动 mitmdump：%s", " ".join(args))
    return subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _start_frida_unpinning(package: str, out_path: Path) -> subprocess.Popen[bytes] | None:
    """写出内置 unpinning 脚本，frida -U -f <package> -l <js> --no-pause 注入并 spawn。

    frida 缺失/启动失败 → 记 warning 返回 None（不抛，抓包仍可在无 unpinning 下进行）。
    """
    exe = shutil.which("frida")
    if exe is None:
        logger.warning("[capture] frida 不在 PATH，跳过 unpinning 注入")
        return None

    js_path = out_path / "unpinning.js"
    try:
        js_path.write_text(FRIDA_UNPINNING_JS, encoding="utf-8")
    except Exception:
        logger.exception("[capture] 写出 frida unpinning 脚本失败，跳过注入")
        return None

    args = [exe, "-U", "-f", package, "-l", str(js_path), "--no-pause", "-q"]
    logger.info("[capture] frida 注入 unpinning 并启动 app：%s", " ".join(args))
    try:
        return subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception:
        logger.exception("[capture] 启动 frida 失败，跳过注入")
        return None


# ---------------------------------------------------------------------------
# adb 代理 / reverse（best-effort，单步失败记 warning 不阻断）
# ---------------------------------------------------------------------------


def _adb_set_proxy() -> bool:
    """adb shell settings put global http_proxy 127.0.0.1:8080。成功返回 True。"""
    ok = _adb(
        ["shell", "settings", "put", "global", "http_proxy", f"{_PROXY_HOST}:{_PROXY_PORT}"]
    )
    if not ok:
        logger.warning("[capture] 设置设备全局代理失败（不阻断抓包）")
    return ok


def _adb_clear_proxy() -> None:
    """还原设备全局代理：settings delete global http_proxy。"""
    if not _adb(["shell", "settings", "delete", "global", "http_proxy"]):
        logger.warning("[capture] 清除设备全局代理失败（请手动还原）")


def _adb_reverse() -> bool:
    """adb reverse tcp:8080 tcp:8080，让设备 localhost 回流到主机 mitmproxy。"""
    ok = _adb(["reverse", f"tcp:{_PROXY_PORT}", f"tcp:{_PROXY_PORT}"])
    if not ok:
        logger.warning("[capture] adb reverse 失败（不阻断抓包）")
    return ok


def _adb_remove_reverse() -> None:
    """还原 adb reverse。"""
    if not _adb(["reverse", "--remove", f"tcp:{_PROXY_PORT}"]):
        logger.warning("[capture] adb reverse --remove 失败（请手动还原）")


def _adb(extra: list[str]) -> bool:
    """运行 adb 子命令，成功（returncode==0）返回 True。缺 adb / 失败 / 异常 → False。"""
    exe = shutil.which("adb")
    if exe is None:
        logger.warning("[capture] adb 不在 PATH，跳过：%s", " ".join(extra))
        return False
    try:
        proc = subprocess.run(
            [exe, *extra],
            capture_output=True,
            text=True,
            timeout=device._DEFAULT_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("[capture] adb 命令超时：%s", " ".join(extra))
        return False
    except Exception:
        logger.exception("[capture] adb 命令异常：%s", " ".join(extra))
        return False
    if proc.returncode != 0:
        logger.warning("[capture] adb 命令非零退出（%s）：%s", proc.returncode, " ".join(extra))
        return False
    return True


# ---------------------------------------------------------------------------
# 计时 / 子进程清理
# ---------------------------------------------------------------------------


def _wait(duration: int) -> None:
    """采集等待。隔离为函数便于测试 monkeypatch（避免真睡 duration 秒）。"""
    time.sleep(max(0, duration))


def _terminate(proc: subprocess.Popen[bytes] | None, label: str) -> None:
    """优雅停子进程：terminate → wait(超时) → kill。任何异常记日志，不抛。"""
    if proc is None:
        return
    try:
        if proc.poll() is not None:
            return  # 已退出
        proc.terminate()
        try:
            proc.wait(timeout=_TERMINATE_TIMEOUT)
        except subprocess.TimeoutExpired:
            logger.warning("[capture] %s 未在 %ss 内退出，强杀", label, _TERMINATE_TIMEOUT)
            proc.kill()
            proc.wait(timeout=_TERMINATE_TIMEOUT)
    except Exception:
        logger.exception("[capture] 停止子进程 %s 异常", label)


# ---------------------------------------------------------------------------
# flows 解析 → 运行时端点
# ---------------------------------------------------------------------------


def _parse_flows(flows_file: Path) -> list[Endpoint]:
    """解析 mitmproxy 流文件，提取 host/url → Endpoint(source="runtime")。

    优先用 mitmproxy python 包（io.FlowReader）读出每条 HTTP 流的 url/host；
    包不可用 / 文件缺失 / 解析失败 → 只记原始路径（返回空端点，不抛）。
    """
    if not flows_file.exists():
        logger.info("[capture] 未生成流文件 %s，无运行时端点", flows_file)
        return []

    try:
        # 用 importlib.import_module 而非 `from mitmproxy import io`：前者直接认 sys.modules
        # 中已注册的子模块（测试用 monkeypatch 注入 fake io/http 时父包是裸对象、无 __path__，
        # `from ... import ...` 的子模块回退不生效），对真实 mitmproxy 安装亦等价。
        import importlib

        mitm_io = importlib.import_module("mitmproxy.io")  # type: ignore[import-not-found]
        mitm_http = importlib.import_module("mitmproxy.http")  # type: ignore[import-not-found]
    except ImportError:
        logger.warning(
            "[capture] mitmproxy python 包不可用，无法解析流；仅记原始路径 %s", flows_file
        )
        return []

    collector: dict[str, Endpoint] = {}
    try:
        with flows_file.open("rb") as fh:
            reader = mitm_io.FlowReader(fh)
            for flow in reader.stream():
                if not isinstance(flow, mitm_http.HTTPFlow):
                    continue
                req = getattr(flow, "request", None)
                if req is None:
                    continue
                _collect_flow_endpoints(req, str(flows_file), collector)
    except Exception:
        logger.exception("[capture] 解析流文件失败：%s（仅记原始路径）", flows_file)
        return list(collector.values())

    endpoints = list(collector.values())
    logger.info("[capture] 从流文件提取运行时端点 %d 个", len(endpoints))
    return endpoints


def _collect_flow_endpoints(
    request: object, location: str, collector: dict[str, Endpoint]
) -> None:
    """从单条 mitmproxy 请求对象提取 url + host，去重累积进 collector。"""
    url = getattr(request, "pretty_url", None) or getattr(request, "url", None)
    host = getattr(request, "pretty_host", None) or getattr(request, "host", None)
    scheme = getattr(request, "scheme", "") or ""

    if isinstance(url, str) and url:
        ep = collector.get(url)
        if ep is None:
            collector[url] = Endpoint(
                value=url,
                kind="url",
                evidences=[Evidence(source="runtime", location=location, snippet=url)],
                is_cleartext=str(scheme).lower() == "http" or url.lower().startswith("http://"),
            )
    if isinstance(host, str) and host and "." in host:
        if host not in collector:
            collector[host] = Endpoint(
                value=host,
                kind="domain",
                evidences=[Evidence(source="runtime", location=location, snippet=host)],
            )


def _read_proc_stderr(proc: object) -> str:
    """读取已退出子进程的 stderr 尾部（用于诊断 mitmdump/frida 立即退出原因）。

    真实 Popen 才有 communicate；测试替身无则降级。任何异常不抛。
    """
    communicate: Any = getattr(proc, "communicate", None)
    # 用 is None 守卫而非 callable()：后者会把 Any 收窄成 Callable[..., object]，
    # 导致返回值被当 object 无法解包。
    if communicate is None:
        return f"exit code {getattr(proc, 'returncode', '?')}"
    try:
        out, err = communicate(timeout=2.0)
    except Exception:
        logger.exception("[capture] 读取子进程 stderr 失败")
        return f"exit code {getattr(proc, 'returncode', '?')}"
    data = err or out or b""
    if isinstance(data, (bytes, bytearray)):
        data = bytes(data).decode("utf-8", errors="ignore")
    text = str(data)[-_STDERR_TAIL:].strip()
    return text or f"exit code {getattr(proc, 'returncode', '?')}"


def _write_runtime_report(
    package: str, out_path: Path, endpoints: list[Endpoint], *, complete: bool = True
) -> str:
    """把运行时端点写成 out/runtime_report.json（复用 report.json 的序列化）。

    complete=False（抓包失败/中断）时在 payload 标 capture_complete=False + note，
    使报告自身能表明它产自一次不完整的抓包，而非静默以正常结果示人。
    返回报告路径；写出失败记日志返回空串（不抛）。
    """
    report_file = out_path / "runtime_report.json"
    payload = {
        "package_name": package,
        "source": "runtime",
        "capture_complete": complete,
        "endpoint_total": len(endpoints),
        "endpoints": [report_json._to_jsonable(ep) for ep in endpoints],
    }
    if not complete:
        payload["note"] = "抓包未完整（代理未起或编排中断），运行时端点可能不全。"
    try:
        import json as _json

        report_file.write_text(
            _json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except Exception:
        logger.exception("[capture] 写出 runtime_report.json 失败：%s", report_file)
        return ""
    logger.info("[capture] 已写出运行时报告：%s", report_file)
    return str(report_file)
