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
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from apkscan.core import device, tools
from apkscan.core.models import Endpoint, Evidence
from apkscan.dynamic import (
    STATUS_DONE,
    STATUS_ERROR,
    STATUS_SKIPPED,
    DynamicResult,
    empty_result,
)
from apkscan.dynamic import cryptohook, provision
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

# frida 注入后短暂等待，用于检测进程是否秒退（版本不匹配/包名不存在/spawn 失败）。
# 用 _wait 走同一计时入口，测试可 monkeypatch 避免真睡。
_FRIDA_GRACE = 2


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

    # 防御：包名源自样本 manifest（不可信）。畸形包名直接拒绝，不下发到 frida/adb。
    if not device.is_valid_package(package):
        logger.error("[capture] 包名形态非法，拒绝抓包：%r", package)
        return empty_result(STATUS_ERROR, f"包名形态非法，拒绝抓包：{package!r}")

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
        f"frida -U -f {package} -l unpinning.js -q  （老版 frida-tools<14 才加 --no-pause）"
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
    # P0 运行时密钥 hook：frida-core 会话（带 crypto 回传）+ 其收集到的活体 crypto 事件。
    # frida-core 不可用/注入失败时 frida_session 保持 None、回退 subprocess（无 key 回传）。
    frida_session: Any = None
    frida_script: Any = None
    crypto_events: list[dict[str, Any]] = []
    jsbridge_events: list[dict[str, Any]] = []  # P1：运行时 JS-bridge 暴露面/调用
    sensitive_api_events: list[dict[str, Any]] = []  # P1：运行时敏感 API 调用
    antidetect_events: list[dict[str, Any]] = []  # P3：反检测探测（root/模拟器/frida）
    proxy_set = False
    reverse_set = False
    # 抓包加固产生的告警（CA 未装系统库 / frida 版本不一致），收尾并入 reason，
    # 不假成功——但都不阻断抓包（HTTP 仍可抓；frida 不匹配仍尝试注入）。
    warnings: list[str] = []

    try:
        # 0) HTTPS 命门：把 mitmproxy CA 装入设备系统信任库。失败不中止抓包
        #    （HTTP 仍可抓），但把降级原因写进 playbook + reason，确保不假成功。
        ca = provision.ensure_mitm_ca(on_progress=None)
        if ca.get("ok"):
            playbook.append(f"mitmproxy CA 已就绪（{ca.get('action', '')}）")
        else:
            ca_detail = str(ca.get("detail") or "CA 未装入系统信任库")
            warn = f"CA 未装入系统信任库：{ca_detail}，HTTPS 可能仅密文"
            logger.warning("[capture] %s", warn)
            playbook.append(warn)
            warnings.append(warn)

        # 0.5) frida 主机/设备版本一致性校验。不一致不阻断（仍注入），但写入告警。
        match_ok, match_msg = _check_frida_version_match()
        if not match_ok:
            logger.warning("[capture] %s", match_msg)
            playbook.append(match_msg)
            warnings.append(match_msg)

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

        # 3) frida 注入：优先 frida-core 通道（SSL unpinning + 运行时密钥 hook，可回传活体 key）；
        #    frida-core 不可用 / attach 失败 → 回退现有 subprocess 路径（仅 unpinning，无 key 回传）。
        #    两路都 best-effort、失败不阻断抓包（HTTP 仍可抓）。
        frida_session, frida_script = _start_frida_session(
            package, crypto_events, jsbridge_events, sensitive_api_events, antidetect_events
        )
        if frida_session is not None:
            playbook.append(
                f"frida-core 注入 SSL unpinning + 运行时密钥 hook 并启动 {package}（活体 key 回传）"
            )
            logger.info("[capture] frida-core 会话已建立，运行时密钥 hook 生效")
        else:
            frida_proc = _start_frida_unpinning(package, out_path)
        if frida_session is None and frida_proc is None:
            # 未起 frida（缺 frida / 写脚本失败）→ 无 unpinning，HTTPS 可能仅密文。
            warn = "frida 未启动（缺 frida / 脚本写出失败），无 SSL unpinning，HTTPS 可能仅密文"
            logger.warning("[capture] %s", warn)
            playbook.append(warn)
            warnings.append(warn)
        elif frida_proc is not None:
            # 存活检测：frida 若因 frida-server 版本不匹配 / 包名不存在 / spawn 失败而
            # 瞬间退出，Popen 不抛——必须主动检测，否则会照常 sleep 满 duration 并以
            # "成功"收尾，把"unpinning 根本没生效（HTTPS 仅密文）"静默成假成功。
            # 与 CA 失败路径一致：不阻断（HTTP 仍可抓），但如实降级写入 reason/playbook。
            playbook.append(f"frida 注入 SSL unpinning 并启动 {package}")
            _wait(_FRIDA_GRACE)
            if frida_proc.poll() is not None:
                err = _read_proc_stderr(frida_proc)
                warn = (
                    f"frida 注入失败/秒退（frida-server 版本不匹配 / 包名不存在 / "
                    f"spawn 失败？）stderr 尾部：{err}；HTTPS 可能仅密文"
                    f"{device.frida_spawn_hint(err)}"
                )
                logger.warning("[capture] %s", warn)
                playbook.append(warn)
                warnings.append(warn)

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
        _teardown_frida_session(frida_session, frida_script)
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
    # C5b：额外抽出报文体（请求/响应），供 merge 阶段对 {data,timestamp} 信封解密。
    # 失败/缺 mitmproxy 包 → 空列表（不影响端点提取与报告写出）。
    messages = _parse_messages(flows_file)
    # 抓包失败（mitmdump 没起来 / 编排异常）时，产出的 runtime_report 基于不完整/未抓全
    # 的流量，必须在报告里标明，避免它伪装成正常结果被下游误用。
    capture_ok = result["status"] != STATUS_ERROR
    # P0/P1：把活体事件（去掉 sink 上限触发的 _capped 占位）一并写进 runtime_report.json。
    def _clean(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [e for e in events if not e.get("_capped")]

    report_path = _write_runtime_report(
        package,
        out_path,
        endpoints,
        complete=capture_ok,
        messages=messages,
        crypto_events=_clean(crypto_events),
        jsbridge_events=_clean(jsbridge_events),
        sensitive_api_events=_clean(sensitive_api_events),
        antidetect_events=_clean(antidetect_events),
    )
    report_paths = [report_path] if report_path else []

    if capture_ok:
        playbook.append(
            f"解析 {flows_file.name} 提取运行时端点 {len(endpoints)} 个 → {Path(report_path).name if report_path else 'runtime_report.json'}"
        )
        result["reason"] = f"抓包完成，提取运行时端点 {len(endpoints)} 个"

    # 把加固告警（CA 降级 / frida 版本不一致）追加进 reason，确保不假成功——
    # 即便抓包 done，调用方也能从 reason 看到 HTTPS/注入可能不可靠。done 与 error
    # 两路都追加（error 时已有 reason，告警作为补充上下文）。
    if warnings:
        suffix = "；".join(warnings)
        result["reason"] = f"{result['reason']}；{suffix}" if result["reason"] else suffix

    result["artifacts"] = artifacts
    result["report_paths"] = report_paths
    result["playbook"] = playbook
    return result


def _spawn_logged(args: list[str], log_path: Path) -> subprocess.Popen[bytes]:
    """起长驻子进程：stdout 丢弃、stderr 重定向到 ``log_path`` 文件（**而非 PIPE**）。

    长驻子进程（mitmdump/frida）若用 ``PIPE`` 且在抓包窗口内无人读，输出写满 OS 管道缓冲
    （~64KB）会阻塞其主循环 → 代理停转、后续真·C2 流量静默丢失，而 capture 仍 sleep 满
    duration 并以"成功 N 端点"收尾（"假成功"）。改用文件重定向：既不会阻塞，又把 stderr
    完整留盘供秒退诊断（``_read_proc_stderr`` 优先读该文件）。stdout 用 ``DEVNULL``（flows 已
    落 ``-w`` 文件、frida ``-q`` 本就安静）。
    """
    log_f = open(log_path, "wb")  # noqa: SIM115 - 句柄交 subprocess 继承，父进程随即关闭副本
    try:
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=log_f)
    finally:
        log_f.close()  # 父进程关副本；子进程已继承自己的 fd，照常写入
    proc._fxapk_stderr_log = log_path  # type: ignore[attr-defined]  # 供 _read_proc_stderr 读取
    return proc


def _start_mitmdump(flows_file: Path) -> subprocess.Popen[bytes]:
    """启动 mitmdump 子进程（-w flows_file）。失败抛异常由上层 finally 兜底清理。

    frozen 时经 tools.frida_invocation 自调用内置 mitmdump；源码时用 PATH。
    """
    inv = tools.frida_invocation("mitmdump")
    if not inv:  # _detect_missing 已确认存在，此处防御
        raise RuntimeError("mitmdump/mitmproxy 不可用")
    args = [
        *inv,
        "-w",
        str(flows_file),
        "--listen-host",
        _PROXY_HOST,
        "--listen-port",
        str(_PROXY_PORT),
    ]
    logger.info("[capture] 启动 mitmdump：%s", " ".join(args))
    return _spawn_logged(args, flows_file.parent / "mitmdump.stderr.log")


def _start_frida_unpinning(package: str, out_path: Path) -> subprocess.Popen[bytes] | None:
    """写出内置 unpinning 脚本，frida -U -f <package> -l <js> 注入并 spawn 目标 app。

    frida 缺失/启动失败 → 记 warning 返回 None（不抛，抓包仍可在无 unpinning 下进行）。
    frozen 时经 tools.frida_invocation 自调用内置 frida；源码时用 PATH。

    注意：frida-tools ≥14 删除了 ``--no-pause``（不暂停已是默认，传它会
    ``unrecognized arguments`` 让 frida 秒退、unpinning 永不注入）；故只对老版本(<14)
    才补 ``--no-pause``，版本拿不到则按新版处理（不加）。
    """
    inv = tools.frida_invocation("frida")
    if not inv:
        logger.warning("[capture] frida 不可用，跳过 unpinning 注入")
        return None

    js_path = out_path / "unpinning.js"
    try:
        js_path.write_text(FRIDA_UNPINNING_JS, encoding="utf-8")
    except Exception:
        logger.exception("[capture] 写出 frida unpinning 脚本失败，跳过注入")
        return None

    args = [*inv, "-U", "-f", package, "-l", str(js_path), "-q"]
    host_major = re.match(r"(\d+)\.", provision.host_frida_version())
    if host_major is not None and int(host_major.group(1)) < 14:
        args.append("--no-pause")  # 仅老版 frida-tools(<14) 需要；新版默认不暂停
    logger.info("[capture] frida 注入 unpinning 并启动 app：%s", " ".join(args))
    try:
        return _spawn_logged(args, out_path / "frida.stderr.log")
    except Exception:
        logger.exception("[capture] 启动 frida 失败，跳过注入")
        return None


# ---------------------------------------------------------------------------
# P0：frida-core 会话（SSL unpinning + 运行时密钥 hook，可回传活体 key）
# ---------------------------------------------------------------------------

# frida.get_usb_device 连接设备的超时（秒）。_detect_missing 已确认设备+frida-server，
# 此处只是防御性上限，避免无设备时阻塞。
_FRIDA_USB_TIMEOUT = 10


def _start_frida_session(
    package: str,
    sink: list[dict[str, Any]],
    jsbridge_sink: list[dict[str, Any]] | None = None,
    api_sink: list[dict[str, Any]] | None = None,
    antidetect_sink: list[dict[str, Any]] | None = None,
) -> tuple[Any, Any]:
    """用 frida-core（``import frida``）spawn 目标 app 并注入 unpinning + 运行时 hook 套件。

    与 subprocess 路径（``_start_frida_unpinning``）的关键差异：frida-core 提供
    ``send()``/``on_message`` 双向通道，能把活体 AES key/iv/明文（P0）+ JS-bridge 暴露面/
    敏感 API 调用（P1）**结构化回传** Python，这是 subprocess 单向 console.log 做不到的。

    Args:
        package: 目标应用包名（spawn）。
        sink: 收集 crypto 事件的共享列表（``make_message_handler`` 写入）。
        jsbridge_sink: 收集 JS-bridge 事件（None 则不注册该通道）。
        api_sink: 收集敏感 API 调用事件（None 则不注册该通道）。

    Returns:
        ``(session, script)``：成功 → 两者非 None（脚本已 load、app 已 resume）；
        frida-core 不可用 / spawn / attach / load 任一失败 → ``(None, None)`` + warning，
        由调用方回退 subprocess 路径。**绝不抛**：失败必清理已 spawn 的进程，避免回退路径
        二次 spawn 冲突（同包名 already running）。
    """
    try:
        import frida  # type: ignore[import-not-found]  # lazy：缺库时回退 subprocess
    except Exception as exc:  # noqa: BLE001 — 缺 frida-core 不阻断，回退 subprocess
        logger.warning(
            "[capture] frida-core（import frida）不可用，回退 subprocess unpinning"
            "（无运行时密钥回传）：%s",
            exc,
        )
        return None, None

    source = (
        FRIDA_UNPINNING_JS
        + "\n"
        + cryptohook.FRIDA_CRYPTO_HOOK_JS
        + "\n"
        + cryptohook.FRIDA_JSBRIDGE_HOOK_JS
        + "\n"
        + cryptohook.FRIDA_SENSITIVE_API_HOOK_JS
        + "\n"
        + cryptohook.FRIDA_ANTIDETECT_JS
    )
    device_handle: Any = None
    pid: Any = None
    session: Any = None
    try:
        device_handle = frida.get_usb_device(timeout=_FRIDA_USB_TIMEOUT)
        pid = device_handle.spawn([package])
        session = device_handle.attach(pid)
        script = session.create_script(source)
        # 三通道：crypto（含 error 诊断）/ jsbridge / 敏感 API，各自规范化进对应 sink。
        script.on("message", cryptohook.make_message_handler(sink))
        if jsbridge_sink is not None:
            script.on(
                "message",
                cryptohook.make_typed_handler(
                    jsbridge_sink, cryptohook.JSBRIDGE_MSG_TYPE, cryptohook.normalize_jsbridge_event
                ),
            )
        if api_sink is not None:
            script.on(
                "message",
                cryptohook.make_typed_handler(
                    api_sink, cryptohook.SENSITIVE_API_MSG_TYPE, cryptohook.normalize_sensitive_api_event
                ),
            )
        if antidetect_sink is not None:
            script.on(
                "message",
                cryptohook.make_typed_handler(
                    antidetect_sink, cryptohook.ANTIDETECT_MSG_TYPE, cryptohook.normalize_antidetect_event
                ),
            )
        script.load()
        device_handle.resume(pid)
        logger.info("[capture] frida-core spawn+attach 成功：pid=%s package=%s", pid, package)
        return session, script
    except Exception as exc:  # noqa: BLE001 — frida-core 任一环节失败 → 回退 subprocess
        logger.warning(
            "[capture] frida-core 注入失败，回退 subprocess unpinning：%s%s",
            exc,
            device.frida_spawn_hint(str(exc)),
        )
        # 清理已 spawn 的进程/会话，避免 subprocess 回退 `-f` 二次 spawn 冲突。
        if session is not None:
            try:
                session.detach()
            except Exception:
                logger.debug("[capture] 清理 frida-core 会话失败（忽略）", exc_info=True)
        if pid is not None and device_handle is not None:
            try:
                device_handle.kill(pid)
            except Exception:
                logger.debug("[capture] 清理 frida-core spawned 进程失败（忽略）", exc_info=True)
        return None, None


def _teardown_frida_session(session: Any, script: Any) -> None:
    """best-effort 收尾 frida-core 会话：unload → detach → kill spawned app。异常记日志不抛。

    收尾还会 kill 掉 spawn 出来的目标 app（与失败路径对称）：否则反复跑 auto 会在设备上堆叠同
    包名进程，下次 spawn 可能 ``already running``。pid 在 detach 前取（detach 后可能失效）。
    """
    pid = getattr(session, "pid", None) if session is not None else None
    if script is not None:
        try:
            script.unload()
        except Exception:
            logger.debug("[capture] frida-core script.unload 失败（忽略）", exc_info=True)
    if session is not None:
        try:
            session.detach()
        except Exception:
            logger.debug("[capture] frida-core session.detach 失败（忽略）", exc_info=True)
    # 仅当拿到真实 int pid 才 kill（测试替身的 object() 会话无 pid → 跳过，不触真 frida）。
    if isinstance(pid, int):
        _kill_spawned_app(pid)


def _kill_spawned_app(pid: int) -> None:
    """best-effort kill frida spawn 出来的目标 app 进程（重新取设备句柄）。绝不抛。"""
    try:
        import frida  # type: ignore[import-not-found]

        frida.get_usb_device(timeout=_FRIDA_USB_TIMEOUT).kill(pid)
        logger.debug("[capture] 收尾已 kill spawned app：pid=%s", pid)
    except Exception:
        logger.debug("[capture] 收尾 kill spawned app 失败（忽略）：pid=%s", pid, exc_info=True)


# ---------------------------------------------------------------------------
# frida 主机/设备版本一致性校验（best-effort，不阻断）
# ---------------------------------------------------------------------------

# frida-server 在设备上的常驻路径（与 provision 部署口径一致）。
_FRIDA_SERVER_REMOTE = "/data/local/tmp/frida-server"


def _device_frida_version(serial: str | None = None) -> str:
    """best-effort 取设备端 frida-server 版本。

    尝试 ``adb shell <frida-server> --version`` 解析 semver；缺 adb / 设备拿不到
    （非常见，frida-server 路径不定 / 无 root / 不支持 --version）→ ''（不抛）。
    设计为"拿不到只校在跑、不阻断"，故空串由调用方按"无法比对"处理。
    """
    exe = tools.adb_path()
    if not exe:
        logger.debug("[capture] adb 不可用，无法取设备 frida-server 版本")
        return ""
    args = [exe]
    if serial:
        args += ["-s", serial]
    args += ["shell", _FRIDA_SERVER_REMOTE, "--version"]
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
    except subprocess.TimeoutExpired:
        logger.warning("[capture] 取设备 frida-server 版本超时")
        return ""
    except Exception:
        logger.exception("[capture] 取设备 frida-server 版本异常")
        return ""

    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    match = re.search(r"(\d+\.\d+\.\d+)", text)
    if match is None:
        logger.debug("[capture] 无法从设备解析 frida-server 版本：%r", text.strip())
        return ""
    return match.group(1)


def _check_frida_version_match(serial: str | None = None) -> tuple[bool, str]:
    """校验主机 frida 与设备 frida-server 版本是否一致（best-effort，不阻断注入）。

    Returns:
        (ok, msg)。一致 / 无法比对（任一版本取不到）→ (True, '')；
        明确不一致 → (False, 警告文案)。版本不一致时注入可能失败，但 capture 设计为
        仍尝试注入，仅把告警写入 playbook/reason，由 _capture 决定如何呈现。
    """
    host_ver = provision.host_frida_version()
    dev_ver = _device_frida_version(serial)
    # 任一取不到 → 无法比对，按"通过"处理（只校在跑，不阻断）。
    if not host_ver or not dev_ver:
        logger.debug(
            "[capture] frida 版本无法比对（主机=%r 设备=%r），跳过版本校验",
            host_ver,
            dev_ver,
        )
        return True, ""
    if host_ver != dev_ver:
        msg = (
            f"主机 frida {host_ver} 与设备 frida-server {dev_ver} 版本不一致，"
            "注入可能失败"
        )
        logger.warning("[capture] %s", msg)
        return False, msg
    return True, ""


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
    exe = tools.adb_path()
    if not exe:
        logger.warning("[capture] adb 不可用，跳过：%s", " ".join(extra))
        return False
    try:
        proc = subprocess.run(
            [exe, *extra],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
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
# 噪音过滤：模拟器/系统自身流量（连通性检测/时间同步/GMS 传输/模拟器遥测）
# ---------------------------------------------------------------------------
#
# adb 全局代理把**整机**流量（不止目标 app）都回流到 mitmproxy，模拟器/系统自身会发连通性
# 探测（generate_204）、NTP 授时、GMS 传输、模拟器厂商遥测等——这些不是涉诈线索，混进运行时
# 端点里是噪音。按 host 精确/后缀名单过滤掉整条流。**保守**：只列 OS/连通性/模拟器自身的 host，
# 绝不含 maps/firebase/fcm 等 app 也会用的 Google SDK（那些由 infra 分级标"无需调证"，不误杀）。
_FALLBACK_NOISE_HOSTS: tuple[str, ...] = (
    # 连通性 / captive portal 检测
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "clients3.google.com",
    "clients4.google.com",
    "clients.l.google.com",
    "captive.apple.com",
    "www.msftconnecttest.com",
    ".msftncsi.com",
    # 时间同步
    "time.android.com",
    "time.google.com",
    ".pool.ntp.org",
    ".ntp.org",
    # GMS / Play 传输层（OS 级，非 app SDK）
    "mtalk.google.com",
    "alt1-mtalk.google.com",
    "alt2-mtalk.google.com",
    "android.clients.google.com",
    "play.googleapis.com",
    ".gvt1.com",
    ".gvt2.com",
    "update.googleapis.com",
    "dl.google.com",
    # 模拟器自身遥测 / 更新（MuMu/网易、Nox、LDPlayer、逍遥、VMOS 等）
    ".mumu.com",
    ".nemu.com",
    ".bignox.com",
    ".ldmnq.com",
    ".ldrescdn.com",
    ".yeshen.com",
    ".vmos.cloud",
)

# 进程内缓存（一次抓包解析内复用，避免每条流都 load_rules）。
_NOISE_PATTERNS_CACHE: tuple[str, ...] | None = None


def _load_noise_patterns() -> tuple[str, ...]:
    """加载噪音 host 名单（rules/capture_noise.yaml 覆盖/扩展内置兜底）。规则缺失/异常 → 兜底。"""
    global _NOISE_PATTERNS_CACHE
    if _NOISE_PATTERNS_CACHE is not None:
        return _NOISE_PATTERNS_CACHE
    patterns: list[str] = list(_FALLBACK_NOISE_HOSTS)
    try:
        from apkscan.core.registry import load_rules

        data = load_rules("capture_noise")
        if isinstance(data, dict):
            extra = data.get("noise_hosts")
            if isinstance(extra, list):
                cleaned = [str(h).strip().lower() for h in extra if str(h).strip()]
                if cleaned:
                    patterns = cleaned  # 规则给了就以规则为准（含内置常见项即可整体覆盖）
    except Exception:  # noqa: BLE001 — 规则不可用不影响抓包，用兜底
        logger.debug("[capture] 加载 capture_noise 规则失败，用内置兜底", exc_info=True)
    _NOISE_PATTERNS_CACHE = tuple(dict.fromkeys(p for p in patterns if p))
    return _NOISE_PATTERNS_CACHE


def _is_noise_host(host: str, patterns: tuple[str, ...]) -> bool:
    """host 是否命中噪音名单：``.suffix`` 做后缀匹配（含自身），其余做精确匹配（大小写不敏感）。"""
    if not host:
        return False
    h = host.strip().lower().rstrip(".")
    for p in patterns:
        if not p:
            continue
        if p.startswith("."):
            if h == p[1:] or h.endswith(p):
                return True
        elif h == p:
            return True
    return False


def _flow_host(flow: object) -> str:
    """从流取 host（pretty_host 优先），用于噪音判定。取不到 → 空串。"""
    request = getattr(flow, "request", None)
    if request is None:
        return ""
    host = getattr(request, "pretty_host", None) or getattr(request, "host", None)
    return host if isinstance(host, str) else ""


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

    noise_patterns = _load_noise_patterns()
    collector: dict[str, Endpoint] = {}
    filtered = 0
    try:
        with flows_file.open("rb") as fh:
            reader = mitm_io.FlowReader(fh)
            for flow in reader.stream():
                if not isinstance(flow, mitm_http.HTTPFlow):
                    continue
                # 模拟器/系统自身流量（连通性检测/授时/GMS/模拟器遥测）→ 整条跳过，不入端点。
                if _is_noise_host(_flow_host(flow), noise_patterns):
                    filtered += 1
                    continue
                _collect_flow_endpoints(flow, str(flows_file), collector)
    except Exception:
        logger.exception("[capture] 解析流文件失败：%s（仅记原始路径）", flows_file)
        return list(collector.values())

    endpoints = list(collector.values())
    if filtered:
        logger.info(
            "[capture] 从流文件提取运行时端点 %d 个（已过滤模拟器/系统自身噪音流 %d 条）",
            len(endpoints),
            filtered,
        )
    else:
        logger.info("[capture] 从流文件提取运行时端点 %d 个", len(endpoints))
    return endpoints


def _collect_flow_endpoints(
    flow: object, location: str, collector: dict[str, Endpoint]
) -> None:
    """从单条 mitmproxy 流提取 url + host(域名) + **服务器实连 IP**，去重累积进 collector。

    ``flow.server_conn.peername`` 是经 mitmproxy 中转后**实际连到的上游服务器 IP**——即 C2
    域名在抓包当时真实解析到的落点 IP（连去哪个机房/IDC），比仅有域名更直接可调取（可凭 IP
    向 IDC/云厂商调取租用主体）。故除 url/域名外，把实连 IP 也作为运行时端点产出。
    """
    request = getattr(flow, "request", None)
    host: str | None = None
    if request is not None:
        url = getattr(request, "pretty_url", None) or getattr(request, "url", None)
        host = getattr(request, "pretty_host", None) or getattr(request, "host", None)
        scheme = getattr(request, "scheme", "") or ""
        if isinstance(url, str) and url and url not in collector:
            collector[url] = Endpoint(
                value=url,
                kind="url",
                evidences=[Evidence(source="runtime", location=location, snippet=url)],
                is_cleartext=str(scheme).lower() == "http" or url.lower().startswith("http://"),
            )
        if isinstance(host, str) and host and "." in host and host not in collector:
            collector[host] = Endpoint(
                value=host,
                kind="domain",
                evidences=[Evidence(source="runtime", location=location, snippet=host)],
            )

    # 服务器实连 IP（C2 真实落点）：mitmproxy 上游连接的 peername=(ip, port)。
    server_conn = getattr(flow, "server_conn", None)
    peername = getattr(server_conn, "peername", None) if server_conn is not None else None
    if isinstance(peername, (tuple, list)) and len(peername) >= 1:
        ip = peername[0]
        if isinstance(ip, str) and ip and ip not in collector:
            note = f"{ip}（{host} 实连服务器 IP）" if isinstance(host, str) and host else f"{ip}（实连服务器 IP）"
            collector[ip] = Endpoint(
                value=ip,
                kind="ip",
                evidences=[Evidence(source="runtime", location=location, snippet=note)],
            )


# ---------------------------------------------------------------------------
# 报文体提取（C5b：供 merge 对 {data,timestamp} 信封解密）
# ---------------------------------------------------------------------------

# 单条报文体保留上限（字节）：信封 data 是 base64 密文，通常不大；超大体多为上传/下载，跳过。
_MAX_BODY_BYTES = 256 * 1024


def _parse_messages(flows_file: Path) -> list[dict[str, Any]]:
    """解析流文件，提取每条 HTTP 流的请求/响应体（文本），供解密信封用。

    只保留**像 JSON 信封**（文本含 "data" 且含 "timestamp"）的报文体，避免把全部流量
    体塞进 runtime_report.json。mitmproxy 包不可用 / 文件缺失 / 解析失败 → []（不抛）。

    返回 ``[{"url": str, "request_body": str, "response_body": str}]``。
    """
    if not flows_file.exists():
        return []

    try:
        import importlib

        mitm_io = importlib.import_module("mitmproxy.io")  # type: ignore[import-not-found]
        mitm_http = importlib.import_module("mitmproxy.http")  # type: ignore[import-not-found]
    except ImportError:
        logger.warning("[capture] mitmproxy 包不可用，无法提取报文体（信封解密将跳过）")
        return []

    noise_patterns = _load_noise_patterns()
    messages: list[dict[str, Any]] = []
    try:
        with flows_file.open("rb") as fh:
            reader = mitm_io.FlowReader(fh)
            for flow in reader.stream():
                if not isinstance(flow, mitm_http.HTTPFlow):
                    continue
                if _is_noise_host(_flow_host(flow), noise_patterns):
                    continue  # 模拟器/系统自身流量不参与信封解密
                msg = _message_from_flow(flow)
                if msg is not None:
                    messages.append(msg)
    except Exception:
        logger.exception("[capture] 提取报文体失败：%s（信封解密将跳过）", flows_file)
        return messages

    logger.info("[capture] 从流文件提取信封报文 %d 条", len(messages))
    return messages


def _message_from_flow(flow: object) -> dict[str, Any] | None:
    """从单条 HTTPFlow 提取 url + 请求/响应体（仅保留 JSON 信封形态）。无信封 → None。"""
    req = getattr(flow, "request", None)
    resp = getattr(flow, "response", None)
    url = ""
    if req is not None:
        url = getattr(req, "pretty_url", None) or getattr(req, "url", None) or ""

    req_body = _body_text(req)
    resp_body = _body_text(resp)

    # 只在请求或响应体像信封（含 data 且含 timestamp）时才保留。
    if not _looks_like_envelope(req_body) and not _looks_like_envelope(resp_body):
        return None

    return {
        "url": str(url),
        "request_body": req_body,
        "response_body": resp_body,
    }


def _body_text(msg: object) -> str:
    """安全取出 mitmproxy 请求/响应的文本体（超限截断；取不到 → 空串）。"""
    if msg is None:
        return ""
    # 优先 .text（mitmproxy 已按 content-type 解码）；回退 .content（bytes）。
    text = getattr(msg, "text", None)
    if isinstance(text, str) and text:
        return text[:_MAX_BODY_BYTES]
    content = getattr(msg, "content", None)
    if isinstance(content, (bytes, bytearray)):
        if len(content) > _MAX_BODY_BYTES:
            content = bytes(content[:_MAX_BODY_BYTES])
        try:
            return bytes(content).decode("utf-8", errors="ignore")
        except Exception:  # noqa: BLE001 — errors=ignore 几乎不抛，仅防御
            logger.exception("[capture] 报文体解码失败")
            return ""
    return ""


def _looks_like_envelope(body: str) -> bool:
    """文本体是否像 {data,timestamp} 信封（粗判：含 data 与 timestamp 两词）。"""
    if not body:
        return False
    return '"data"' in body and '"timestamp"' in body


def _read_proc_stderr(proc: object) -> str:
    """读取已退出子进程的 stderr 尾部（用于诊断 mitmdump/frida 立即退出原因）。

    优先读 ``_spawn_logged`` 重定向的 stderr 日志文件（真实进程）；测试替身无该属性时降级走
    ``communicate``。任何异常不抛。
    """
    log_path = getattr(proc, "_fxapk_stderr_log", None)
    if log_path is not None:
        try:
            text = Path(log_path).read_bytes().decode("utf-8", errors="ignore")
            text = text[-_STDERR_TAIL:].strip()
            return text or f"exit code {getattr(proc, 'returncode', '?')}"
        except OSError:
            logger.exception("[capture] 读取子进程 stderr 日志失败：%s", log_path)
            return f"exit code {getattr(proc, 'returncode', '?')}"

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
    package: str,
    out_path: Path,
    endpoints: list[Endpoint],
    *,
    complete: bool = True,
    messages: list[dict[str, Any]] | None = None,
    crypto_events: list[dict[str, Any]] | None = None,
    jsbridge_events: list[dict[str, Any]] | None = None,
    sensitive_api_events: list[dict[str, Any]] | None = None,
    antidetect_events: list[dict[str, Any]] | None = None,
) -> str:
    """把运行时端点写成 out/runtime_report.json（复用 report.json 的序列化）。

    complete=False（抓包失败/中断）时在 payload 标 capture_complete=False + note，
    使报告自身能表明它产自一次不完整的抓包，而非静默以正常结果示人。

    C5b：``messages`` 为抽出的 {data,timestamp} 信封报文体（请求/响应），供 merge 阶段
    据静态配方自动解密；默认空数组（向后兼容，旧消费方忽略即可）。

    P0：``crypto_events`` 为运行时密钥 hook 抓到的活体 crypto 事件（key/iv/明文等），供
    merge 阶段反推「实测配方」优先解密信封；默认空数组（向后兼容）。
    返回报告路径；写出失败记日志返回空串（不抛）。
    """
    report_file = out_path / "runtime_report.json"
    payload = {
        "package_name": package,
        "source": "runtime",
        "capture_complete": complete,
        "endpoint_total": len(endpoints),
        "endpoints": [report_json._to_jsonable(ep) for ep in endpoints],
        "messages": list(messages or []),
        "crypto_events": list(crypto_events or []),
        "jsbridge_events": list(jsbridge_events or []),
        "sensitive_api_events": list(sensitive_api_events or []),
        "antidetect_events": list(antidetect_events or []),
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
