"""apkscan.dynamic.capture — 真·抓包：mitmproxy + frida SSL unpinning + adb 代理。

取证用途：对取证样本自身在分析机上做运行时观测，产出端点/密钥/独特串等线索，不面向任何第三方基础设施。

目标：在**有真机 + frida + mitmproxy** 时，对运行中的样本自身做真实流量抓取，
解除样本自身的证书绑定（cert pinning，SSL unpinning）以观测其加密流量，从流量里提取运行时
网络端点（source="runtime"），汇总写出 ``out/runtime_report.json``；缺任一前置条件时返回
status="skipped" + 手册（playbook，给出可手动复现的完整取证步骤），reason 写明缺什么。

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

import ipaddress
import json
import logging
import math
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from apkscan.core import device, infra, tools
from apkscan.core.closure import evaluate_capture_quality
from apkscan.core.models import Endpoint, Evidence
from apkscan.dynamic import (
    STATUS_DEGRADED,
    STATUS_DONE,
    STATUS_ERROR,
    STATUS_SKIPPED,
    DynamicResult,
    empty_result,
)
from apkscan.dynamic import capabilities, capability_probe, cryptohook, pcap_ingest, provision
from apkscan.dynamic.capture_plan import CaptureDecision, decide_capture
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

# ① floor 带外 pcap（设备侧 tcpdump）保底相关常量。
_FLOOR_FLUSH_GRACE = 1.5  # SIGINT tcpdump 后给它 flush + 落盘的等待秒数（走 _wait，测试可 patch）。
_FLOOR_REMOTE_PCAP = "/data/local/tmp/fxapk_floor.pcap"  # 设备上 tcpdump 落盘路径。
_FLOOR_PID_PATH = "/data/local/tmp/fxapk_floor.pid"  # 记录 tcpdump PID 的文件（收尾按 PID 精确 SIGINT）。
_FLOOR_LOCAL_NAME = "floor.pcap"  # adb pull 回本地 out/ 的文件名。
_TCPDUMP_REMOTE = "/data/local/tmp/tcpdump"  # 设备无 tcpdump 时 push 上去的目标路径。
_TCPDUMP_ENV = "FXAPK_TCPDUMP_BIN"  # 用户提供的、与设备 ABI 匹配的 tcpdump 二进制路径（可 push）。
# tcpdump 常见路径（command -v 找不到时逐个探）：多数生产机型无自带 tcpdump。
_TCPDUMP_KNOWN_PATHS = ("/system/xbin/tcpdump", "/system/bin/tcpdump", _TCPDUMP_REMOTE)

# 抓包窗口内按 UID 周期采样 socket，补窗口末单次快照会漏掉的短连接。
_SOCKET_SAMPLE_INTERVAL = 0.25
_TLS_KEYLOG_NAME = "tls.keys"  # P2：授权插桩落下的 NSS TLS Key Log 约定路径（out/tls.keys）→ 解密 floor.pcap。
_SOCKET_MAX_OBSERVATIONS = 20_000
_SOCKET_TIMELINE_NAME = "socket_timeline.jsonl"


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

# ★#8 合法抓包模式（both=mitm+floor；floor-only/no-proxy=不设代理只带外抓；mitm-only=不起 floor）。
_CAPTURE_MODES = frozenset({"both", "floor-only", "mitm-only", "no-proxy"})


def _build_capture_quality(
    floor_summary: pcap_ingest.PcapSummary | None,
    mitm_endpoints: list[Endpoint],
    pcap_app_attr: dict[str, Any],
    *,
    channel_ready: bool,
) -> dict[str, object]:
    """Build strict business-evidence quality without changing capture step semantics."""
    raw_flows = getattr(floor_summary, "flows", []) if floor_summary is not None else []
    flows = raw_flows if isinstance(raw_flows, list) else []
    packet_count = sum(max(0, int(getattr(flow, "packets", 0) or 0)) for flow in flows)
    business_keys: set[str] = set()
    intercept_observed = False
    if floor_summary is not None:
        try:
            remotes = pcap_ingest.remote_endpoints(floor_summary)
        except Exception:  # noqa: BLE001 - quality must not break capture on a degraded parser result
            logger.exception("[capture] 无法从 floor 摘要计算业务流量质量")
            remotes = []
        for remote in remotes:
            if pcap_ingest.is_known_intercept_ip(remote.ip):
                intercept_observed = True
                continue
            if bool(getattr(remote, "has_payload", False)) or bool(getattr(remote, "sni", set())):
                # A2：键含 proto 族，对齐 pcap_app_attr 的 "proto/ip:port"——否则 target_count 恒 0
                #   （落盘 runtime_report.json 的 pre-merge quality 块误判 partial；Fable 复审 LOW-MED）。
                business_keys.add(f"{remote.proto}/{remote.ip}:{remote.port}")

    target_count = sum(
        1
        for key in business_keys
        if isinstance(pcap_app_attr.get(key), dict)
        and pcap_app_attr[key].get("is_target_app") is True
    )
    raw = {
        "channel_ready": channel_ready,
        "pcap_valid": packet_count > 0,
        "packet_count": packet_count,
        "business_candidate_count": max(
            len(business_keys),
            0 if intercept_observed and not business_keys else len(mitm_endpoints),
        ),
        "target_attributed_count": target_count,
    }
    return evaluate_capture_quality(raw)


def _annotate_runtime_endpoints(
    endpoints: list[Endpoint],
    floor_summary: pcap_ingest.PcapSummary | None,
    pcap_app_attr: dict[str, Any],
) -> None:
    """Attach per-endpoint PCAP payload and UID attribution for five-layer closure."""
    if floor_summary is None:
        return
    try:
        remotes = pcap_ingest.remote_endpoints(floor_summary)
    except Exception:  # noqa: BLE001 - annotation is evidence metadata, never a capture blocker
        logger.exception("[capture] 无法把 floor UID 归因写回运行时端点")
        return

    for endpoint in endpoints:
        if endpoint.kind == "ip":
            matched = [remote for remote in remotes if remote.ip == endpoint.value]
        elif endpoint.kind == "domain":
            value = endpoint.value.lower().rstrip(".")
            matched = [
                remote
                for remote in remotes
                if value in {str(sni).lower().rstrip(".") for sni in getattr(remote, "sni", set())}
            ]
        else:
            continue
        if not matched:
            continue

        # A2：查归因用含 proto 族的键（"proto/ip:port"，对齐 pcap_app_attribution，避免 tcp/udp 同 ip:port
        #   覆盖）；但写回 remote_endpoints 仍用 "ip:port"——下游 assemble 的 tls_sni/network_flow 边（域名→落地
        #   IP，最强运行时真值信号）按 "ip:port" 解析该列表，不能改其契约（Fable 复审 HIGH：否则真值边被静默丢）。
        attr_keys = [f"{remote.proto}/{remote.ip}:{remote.port}" for remote in matched]
        attributed = [pcap_app_attr[k] for k in attr_keys if isinstance(pcap_app_attr.get(k), dict)]
        endpoint_keys = sorted({f"{remote.ip}:{remote.port}" for remote in matched})
        # A2 时序穿透（供 network_attribution 的 SUBSEQUENT_OVERSEAS 时序关联）：该端点最早被接触的时刻。
        #   0.0 视作未知（pcap_ingest first_ts 默认 0.0）→ 过滤；只收有限正值（防 NaN/inf 让下游 max() 顺序敏感
        #   或垃圾值恒产信号）；全未知则 None。不改 remote_endpoints 契约。
        _contact_ts = [
            remote.first_ts for remote in matched
            if isinstance(getattr(remote, "first_ts", None), (int, float))
            and math.isfinite(remote.first_ts) and remote.first_ts > 0
        ]
        runtime = endpoint.enrichment.setdefault("runtime", {})
        if not isinstance(runtime, dict):
            runtime = {}
            endpoint.enrichment["runtime"] = runtime
        runtime.update(
            {
                "has_payload": any(bool(getattr(remote, "has_payload", False)) for remote in matched),
                "target_attributed": any(item.get("is_target_app") is True for item in attributed),
                "remote_endpoints": endpoint_keys,
                "first_contact_ts": min(_contact_ts) if _contact_ts else None,
                "sni": sorted(
                    {
                        str(sni)
                        for remote in matched
                        for sni in getattr(remote, "sni", set())
                        if str(sni)
                    }
                ),
            }
        )
        if attributed:
            runtime["attribution"] = sorted(
                {str(item.get("attribution", "unknown")) for item in attributed}
            )
            # A2：某流 confirmed 到非目标 UID 但"目标 app 也连过该远端"时，透出提示——避免这条目标线索
            #   在 target_attributed（仅按 is_target_app）里被当背景噪音整段丢掉（供人工/报告复核）。
            if any(item.get("target_uid_among_candidates") is True for item in attributed):
                runtime["target_among_candidates"] = True


def run(
    package: str,
    out_dir: str = "out",
    duration: int = 60,
    *,
    out: str | None = None,
    serial: str | None = None,
    report: Any = None,
    mode: str = "both",
) -> DynamicResult:
    """对运行中的目标应用做真机抓包，提取运行时端点。

    Args:
        package: 目标应用包名（设备上运行/抓包）。
        out_dir: 产物 / 报告输出目录。
        duration: 抓包时长（秒）。
        out: ``out_dir`` 的关键字别名（CLI 以 ``out=`` 调用，与 unpack.run 一致；
             二者取其一，out 优先）。
        serial: 目标设备 serial（多设备/一机多 transport 下钉定那台，由 auto 选定后传入）。
                所有 adb 命令带 ``-s <serial>``、frida 用 ``-D <serial>``；None 时不带 -s、
                frida 用 ``-U``（向后兼容无设备选择的旧路径/测试）。
        report: 静态分析报告（dict / Report / None）。据其规避信号经
                ``capture_plan.decide_capture`` 产出 :class:`CaptureDecision`，
                四条铁律（floor 优先 / 秒退熔断阈值 / 总预算时间盒 / native 预判）真正
                驱动本引擎的行为——治『几小时零产出』。None → 用默认决策（floor 优先、
                秒退阈值 3、预算 60min），向后兼容无 report 的旧路径/测试。

    Returns:
        DynamicResult 契约 dict。前置不满足 → status="skipped" + playbook；
        满足并完成 → status="done"（artifacts/report_paths 填充）；
        过程异常 → status="error"。绝不抛异常给调用方。
    """
    if out is not None:
        out_dir = out

    # 消费 decide_capture：把静态报告的规避信号落成引擎可读决策（绝不抛，坏 report→默认决策）。
    decision = decide_capture(report)

    # ★#8 抓包模式 → mitm/floor 门控（both=默认；floor-only/no-proxy=不设代理只带外抓；mitm-only=不起
    #    floor）。★须在能力探测之前算：floor-only 不该因缺 mitmproxy 被判缺前置。
    if mode not in _CAPTURE_MODES:
        logger.error("[capture] mode 取值非法：%r（可选 %s）", mode, "/".join(sorted(_CAPTURE_MODES)))
        return empty_result(STATUS_ERROR, f"mode 取值非法：{mode!r}（可选 {'/'.join(sorted(_CAPTURE_MODES))}）")
    use_mitm = mode not in ("floor-only", "no-proxy")
    use_floor = mode != "mitm-only"
    # ★floor-only=纯带外 pcap（反 frida/加固场景）→ 不需要也不注入 frida；其余模式靠 frida 做 SSL unpinning +
    #   运行时 hook。据此条件化前置：floor-only 只要 adb+设备+tcpdump 就能跑，不因缺 frida 被判缺前置而跳过。
    use_frida = mode != "floor-only"

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

    # --- A1-3：起手用能力矩阵解析本次抓包的能力计划（机器可读的抓包能力快照）----------------
    # 探本次实际可用能力（主机 adb/frida/mitm/tshark + 设备 root/tcpdump）→ resolve(mode) → CapabilityPlan，
    # 序列化后随 runtime_report.json 落进 report.meta['capture_capabilities']。让"floor 底座就绪没有 /
    # 明文最强可达层 / 为何没明文（缺哪些增强）"从散落日志变机器可读。★纯可见性：门控降级仍由下面
    # _detect_missing 兜底（保守、不改既有 skip 语义）；能力探测碰 adb IO，best-effort、异常记空计划、绝不挡抓包。
    plan_dict: dict[str, Any] | None = None
    try:
        available = capability_probe.probe_available(serial)
        plan_dict = capabilities.plan_as_dict(capabilities.resolve(mode, available))
    except Exception:
        logger.exception("[capture] 能力计划解析异常（不影响抓包，记为空计划）")

    # --- 前置能力探测：缺任一 → skipped + 手册（floor-only 不要求 mitmproxy）------
    missing = _detect_missing(serial, require_mitm=use_mitm, require_frida=use_frida)
    if missing:
        reason = "缺少前置条件：" + "、".join(missing)
        logger.info("[capture] %s；返回手册（playbook）", reason)
        result = empty_result(STATUS_SKIPPED, reason)
        result["playbook"] = _build_playbook(package, out_dir, duration)
        return result

    # --- 前置满足：真·抓包编排 ------------------------------------------
    logger.info(
        "[capture] 前置满足，开始真机抓包：package=%s duration=%ds serial=%s "
        "decision(floor_first=%s, retreat_threshold=%d, budget=%ds)",
        package, duration, serial or "(未指定/-U)",
        decision.floor_first, decision.frida_retreat_threshold, decision.total_budget_sec,
    )
    return _capture(
        package, out_path, duration, serial, decision=decision, mitm=use_mitm, floor=use_floor,
        frida=use_frida, capabilities_plan=plan_dict,
    )


# ---------------------------------------------------------------------------
# 能力探测
# ---------------------------------------------------------------------------


def _detect_missing(
    serial: str | None = None, require_mitm: bool = True, require_frida: bool = True
) -> list[str]:
    """返回缺失的前置条件名列表（空 = 全部就绪）。

    顺序：设备 / frida / mitmproxy。每项探测均走 device 模块（不抛）。
    serial 非空时 frida-server 运行探测钉定那台（多设备消歧）；None 退回旧行为。
    ★#8：``require_mitm=False``（floor-only/no-proxy）时不把 mitmproxy 计入缺失。
    ★floor-only：``require_frida=False`` 时不把 frida / 设备 frida-server 计入缺失——floor-only 是纯带外
    tcpdump（反 frida/加固场景），只要 adb+设备+tcpdump 就能跑，不该因缺 frida 被判缺前置而整体跳过。
    """
    missing: list[str] = []
    try:
        if not device.has_device():
            missing.append("在线 adb 设备")
    except Exception:
        logger.exception("[capture] 设备探测异常，视为无设备")
        missing.append("在线 adb 设备")

    try:
        if require_frida and not device.has_frida():
            missing.append("frida")
    except Exception:
        logger.exception("[capture] frida 探测异常，视为缺失")
        if require_frida:
            missing.append("frida")

    try:
        if require_mitm and not device.has_mitmproxy():
            missing.append("mitmproxy")
    except Exception:
        logger.exception("[capture] mitmproxy 探测异常，视为缺失")
        if require_mitm:
            missing.append("mitmproxy")

    # 设备上 frida-server 是否在跑（与 unpack 口径一致）：host 有 frida CLI 但设备
    # frida-server 没起来时，注入会失败、抓包绕不过证书绑定，应提前判为缺失。floor-only 不注入 frida → 不查。
    if require_frida:
        try:
            if device.has_device() and not device.frida_server_running(serial):
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
        "4. 解除证书绑定（cert pinning）：frida 注入通用 SSL unpinning 脚本并启动 app："
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


def _capture(
    package: str,
    out_path: Path,
    duration: int,
    serial: str | None = None,
    *,
    decision: CaptureDecision | None = None,
    mitm: bool = True,
    floor: bool = True,
    frida: bool = True,
    capabilities_plan: dict[str, Any] | None = None,
) -> DynamicResult:
    """编排 mitmdump + adb 代理 + frida unpinning + 启 app，到时停并解析流量。

    ★#8 抓包模式：``mitm``=False（floor-only）跳过 mitmdump+全局代理、只靠带外 pcap（加固 IM /
    反 frida 场景不设代理更稳）；``floor``=False（mitm-only）不起 floor。默认两者都开（both）。

    所有子进程在 finally 中清理（terminate→kill），proxy/reverse 在 finally 还原。
    serial 一路传给所有 adb 调用（reverse/proxy/CA/收尾 pull）与 frida 注入（-D 设备选择）；
    None 时全部退回旧行为（不带 -s、frida 用 -U），向后兼容。

    ``decision``（:class:`CaptureDecision`）把 capture_plan 四律落到引擎行为：
    ① floor_first → 起手先起带外 pcap 保底（``_start_floor_pcap``），收尾停之；
    ② frida_retreat_threshold → frida 秒退累计达阈值即弃 frida、退 floor（不死磕明文）；
    ③ total_budget_sec → 采集总耗时超预算即交付已捕获部分（budget_exceeded 标记）；
    None → 用 ``decide_capture(None)`` 默认决策（floor 优先、阈值 3、预算 60min）。
    """
    # TODO(real-device): 需真机验证后方可依赖——floor pcap 起停、frida 会话 liveness、
    # 秒退熔断、预算超时交付部分，均在真机上才有真实副作用；单测一律 mock 这些接口。
    if decision is None:
        decision = decide_capture(None)
    result = empty_result(STATUS_DONE, "")
    playbook: list[str] = []
    flows_file = out_path / "flows.mitm"
    # ③ 时间盒：采集起点（_monotonic 可 monkeypatch）。超 decision.total_budget_sec 交付部分。
    capture_started_at = _monotonic()
    budget_exceeded = False
    # ① floor：带外 pcap 保底 runner 句柄（floor_first 时起手启动，finally 收尾停）。
    floor_handle: Any = None
    floor_pcap: Path | None = None  # 收尾 adb pull 落盘的本地 floor.pcap（供 artifacts / 后续 pcap-leads）。
    uid_snapshot: Path | None = None  # ★P1(#10)：抓包窗口末抓的目标 UID socket 快照（供把 pcap 接入节点绑 app）。
    socket_sampler: _SocketSampler | None = None
    socket_timeline: Path | None = None  # 抓包窗口内持续采样，补 uid_snapshot 漏掉的短连接。

    mitm_proc: subprocess.Popen[bytes] | None = None
    frida_proc: subprocess.Popen[bytes] | None = None
    # P0 运行时密钥 hook：frida-core 会话（带 crypto 回传）+ 其收集到的活体 crypto 事件。
    # frida-core 不可用/注入失败时 frida_session 保持 None、回退 subprocess（无 key 回传）。
    frida_session: Any = None
    frida_script: Any = None
    crypto_events: list[dict[str, Any]] = []
    jsbridge_events: list[dict[str, Any]] = []  # P1：运行时 JS-bridge 暴露面/调用
    sensitive_api_events: list[dict[str, Any]] = []  # P1：运行时敏感 API 调用
    antidetect_events: list[dict[str, Any]] = []  # P3：样本自我检测（root/模拟器/frida）
    # P2：运行时凭据（OkHttp 加密前明文 token/手机号 + 收尾 adb pull shared_prefs 落地凭据）。
    credential_events: list[dict[str, Any]] = []
    # P2：运行时落地库导出（SQLCipher hook 导明文 .plain.db + 收尾 adb pull databases 回 dump_db/）。
    sqlcipher_events: list[dict[str, Any]] = []
    # 第二波：运行时剪贴板链上地址（受害人复制转账入口）。★ 隐私护栏：normalize 抽地址丢全文，
    # 此 sink 只存抽出的链上地址，剪贴板全文绝不入此 sink/落盘。
    clipboard_events: list[dict[str, Any]] = []
    # 第二波（最后）：无障碍远控（被劫持目标银行/支付包名清单 + 远控手势/全局动作 + 屏幕录制）。
    # ★ launch-only 抓不到，多数需引导式人工动态——多数情况下此 sink 为空，属预期。
    remote_control_events: list[dict[str, Any]] = []
    proxy_set = False
    proxy_attempted = False  # 是否尝试过写设备代理（读回未确认也要在 finally 清理，避免遗留死代理）
    reverse_set = False
    # 抓包加固产生的告警（CA 未装系统库 / frida 版本不一致），收尾并入 reason，
    # 不假成功——但都不阻断抓包（HTTP 仍可抓；frida 不匹配仍尝试注入）。
    warnings: list[str] = []

    try:
        # 0) HTTPS 命门：把 mitmproxy CA 装入设备系统信任库。失败不中止抓包
        #    （HTTP 仍可抓），但把降级原因写进 playbook + reason，确保不假成功。
        if mitm:  # ★#8：floor-only 不走 mitm，就不该往设备系统信任库装 mitmproxy CA。
            ca = provision.ensure_mitm_ca(serial, on_progress=None)
            if ca.get("ok"):
                playbook.append(f"mitmproxy CA 已就绪（{ca.get('action', '')}）")
            else:
                ca_detail = str(ca.get("detail") or "CA 未装入系统信任库")
                warn = f"CA 未装入系统信任库：{ca_detail}，HTTPS 可能仅密文"
                logger.warning("[capture] %s", warn)
                playbook.append(warn)
                warnings.append(warn)

        # 0.5) frida 主机/设备版本一致性校验。不一致不阻断（仍注入），但写入告警。
        match_ok, match_msg = _check_frida_version_match(serial)
        if not match_ok:
            logger.warning("[capture] %s", match_msg)
            playbook.append(match_msg)
            warnings.append(match_msg)

        # 1) 起 mitmdump（-w flows.mitm）。超时 = duration + 缓冲。★#8：floor-only 模式跳过 mitm+代理，
        #    只靠带外 pcap（加固 IM / 反 frida 场景常用：不设代理、直连流量交 floor 抓）。
        if mitm:
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
        else:
            playbook.append("floor-only 模式：跳过 mitmdump + 全局代理，仅靠带外 pcap")

        # 2) ① floor 优先（**起手先起，必须在设全局代理之前**）：不碰 App 本体先起带外 pcap 保底。
        #    为何在代理前：设全局代理后，遵守代理的 app 连的是 127.0.0.1:8080（代理腿），设备侧
        #    tcpdump 只会抓到 loopback、抓不到真实后端 IP（pcap-leads 又过滤 loopback → floor 白抓）。
        #    起手先起 → 捕获 app 的**直连**流量（反 frida/pinning/native、绕过代理的 app 正是 floor
        #    的目标场景）。遵守代理的 app 其真实后端 IP 另由 mitm 的 server_conn.peername 在
        #    _parse_flows 取得——两者互补，不重复。真机依赖封成可注入 runner，单测 mock。
        # TODO(real-device): -i any 接口名 / tcpdump AF_PACKET 权限需真机对齐。
        if floor and decision.floor_first:  # ★#8：mitm-only 模式不起 floor
            floor_handle = _start_floor_pcap(package, out_path, serial)
            if floor_handle is not None:
                playbook.append("① floor 保底：已起带外 pcap（代理前起手，抓直连后端 IP；零产出不可接受）")
                logger.info("[capture] floor 带外 pcap 已启动（保底，代理前起手）")
            else:
                logger.info("[capture] floor 带外 pcap 未起（无设备侧 runner），仅靠主抓包链")

        # 3) adb 代理 + reverse，把设备流量回流到主机 mitmproxy。★#8：floor-only 模式跳过（无代理）。
        if mitm:
            reverse_set = _adb_reverse(serial)
            if reverse_set:
                playbook.append(f"adb reverse tcp:{_PROXY_PORT} tcp:{_PROXY_PORT}")
            else:
                # 无 reverse：设备代理指向本机 loopback 却无反向端口 → MITM 通道不可用（floor 兜底）。
                warnings.append(
                    f"adb reverse tcp:{_PROXY_PORT} 失败——设备代理指向 loopback 但无反向端口，MITM 通道可能不可用"
                )
            proxy_attempted = True
            proxy_set = _adb_set_proxy(serial)
            if proxy_set:
                playbook.append(f"adb 设全局代理 {_PROXY_HOST}:{_PROXY_PORT}")

        # 4) frida 注入：优先 frida-core 通道（SSL unpinning + 运行时密钥 hook，可回传活体 key）；
        #    frida-core 不可用 / attach 失败 → 回退现有 subprocess 路径（仅 unpinning，无 key 回传）。
        #    两路都 best-effort、失败不阻断抓包（HTTP 仍可抓）。
        #    ② 秒退熔断：会话建立后做 liveness（resume 后进程是否秒退）；秒退累计达
        #    decision.frida_retreat_threshold 即弃 frida、退 floor（不死磕明文）。
        # TODO(real-device): 需真机验证后方可依赖——liveness/秒退计数只有真机才有真实副作用。
        if not frida:  # ★floor-only：纯带外 pcap，不注入 frida（契合反 frida/加固场景、不触发样本自检）。
            playbook.append("floor-only 模式：跳过 frida 注入（仅带外 pcap，不触发反 frida 检测）")
        retreat_count = 0
        retreated = False  # 达秒退阈值主动退 floor（区别于 frida-core 本就不可用→仍试 subprocess）
        while frida:  # floor-only（frida=False）跳过整段注入；其余模式等价 while True（靠内部 break 退出）
            frida_session, frida_script = _start_frida_session(
                package,
                crypto_events,
                jsbridge_events,
                sensitive_api_events,
                antidetect_events,
                credential_events,
                sqlcipher_events,
                clipboard_events,
                remote_control_events,
                serial=serial,
            )
            if frida_session is None:
                break  # frida-core 不可用/注入失败 → 回退 subprocess（下方处理）。
            # frida-core liveness（治默认路径假成功）：resume 后短暂等待再验进程存活；
            # 死了就像 subprocess 秒退一样降级，绝不再报假成功。
            _wait(_FRIDA_GRACE)
            if _frida_session_alive(frida_session):
                playbook.append(
                    f"frida-core 注入 SSL unpinning + 运行时密钥 hook 并启动 {package}"
                    "（hook 就绪与活体 key 回传待收尾按 hook_ready_status 确认）"
                )
                # ★codex 真机 BUG2：此处仅"会话存活"，hook 是否真装上要到收尾 _frida_hook_status 才知；
                #   不预断"hook 生效"，以免日志与最终 hook_ready_status=unconfirmed 自相矛盾、误导使用者。
                logger.info(
                    "[capture] frida-core 会话已建立且存活；运行时密钥 hook 就绪状态待收尾确认"
                    "（见 capture_signals.hook_ready_status）"
                )
                break
            # 会话秒退：清理这次的死会话，计一次秒退。
            _teardown_frida_session(frida_session, frida_script)
            frida_session, frida_script = None, None
            retreat_count += 1
            warn = (
                f"frida-core 会话秒退（第 {retreat_count}/{decision.frida_retreat_threshold} 次，"
                "版本不匹配 / 样本自我检测 / spawn 失败？）；HTTPS 可能仅密文"
            )
            logger.warning("[capture] %s", warn)
            playbook.append(warn)
            warnings.append(warn)
            if retreat_count >= decision.frida_retreat_threshold:
                # ② 达秒退阈值：弃 frida，退 floor（带外 pcap 已保底，别再死磕明文）。
                fell = (
                    "② 秒退熔断：frida 秒退累计达阈值，弃 frida、退 floor 带外 pcap 保底"
                    "（接入节点已够调证，明文是上限不是底线）"
                )
                logger.warning("[capture] %s", fell)
                playbook.append(fell)
                warnings.append(fell)
                retreated = True
                break

        # 退 floor 后不回退 subprocess frida——但**仅当 floor 真起来了**(floor_handle 非 None)。
        # floor 是桩 / 设备侧不可用时(handle=None)并没真退成 floor,subprocess frida 仍是唯一的
        # unpinning 兜底,不能连它一起丢,否则 pinned HTTPS 只剩密文(codex review 复核 P2)。
        if frida and frida_session is None and not (retreated and floor_handle is not None):
            frida_proc = _start_frida_unpinning(package, out_path, serial)
        if frida and frida_session is None and frida_proc is None:
            # 未起 frida（缺 frida / 写脚本失败 / 秒退熔断退 floor）→ 无 unpinning，HTTPS 可能仅密文。
            # ★floor-only（frida=False）本就不注入 frida、不该刷此告警——已由上方"跳过 frida 注入"说明覆盖。
            warn = "frida 未启动（缺 frida / 脚本写出失败 / 秒退退 floor），无 SSL unpinning，HTTPS 可能仅密文"
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

        # 4) 抓 duration 秒——③ 时间盒：受 decision.total_budget_sec 约束，超预算交付已捕获部分。
        playbook.append(f"采集流量约 {duration} 秒")
        budget_left = _budget_remaining(capture_started_at, decision.total_budget_sec)
        if budget_left <= 0:
            # 前置步骤（CA/frida 重试）已耗尽预算 → 不再采集，直接交付已捕获部分。
            budget_exceeded = True
            warn = (
                f"③ 时间盒：抓包总预算 {decision.total_budget_sec}s 已耗尽，"
                "交付已捕获部分（不无限磨）"
            )
            logger.warning("[capture] %s", warn)
            playbook.append(warn)
            warnings.append(warn)
        else:
            wait_for = min(duration, budget_left)
            if wait_for < duration:
                budget_exceeded = True
                warn = (
                    f"③ 时间盒：剩余预算 {int(budget_left)}s 不足 {duration}s，"
                    "采集缩短并交付已捕获部分（不无限磨）"
                )
                logger.warning("[capture] %s", warn)
                playbook.append(warn)
                warnings.append(warn)
            try:
                socket_sampler = _SocketSampler(package, out_path, serial)
                socket_sampler.start()
            except Exception:
                logger.exception("[capture] 初始化 socket 时间线采样失败（忽略）")
                socket_sampler = None
            _wait(wait_for)
            if socket_sampler is not None:
                socket_timeline = socket_sampler.stop()
                socket_sampler = None
        # ★P1(#10)：抓包窗口末、app 仍活、连接仍在时抓目标 UID 的 socket 快照——供把带外整机
        #   pcap 的接入节点绑定到【本 app】的连接（整机 pcap 未绑 UID 时的锚）。best-effort、不阻断。
        uid_snapshot = _capture_uid_socket_snapshot(package, out_path, serial)

    except _MitmStartupError:
        # status/reason 已在抛出点设好；跳到 finally 清理（mitmdump 已死，其它子进程未起）。
        pass
    except Exception:
        logger.exception("[capture] 抓包编排过程异常")
        result["status"] = STATUS_ERROR
        result["reason"] = "抓包编排过程异常（详见日志）"
    finally:
        # 5) 清理：先停 frida（让 app 网络收尾），再撤代理/reverse，最后停 mitmdump（落盘）。
        # 先停 socket 采样：异常/中断也要交付已经观察到的短连接，且此时 app 仍活。
        if socket_sampler is not None:
            try:
                socket_timeline = socket_sampler.stop()
            except Exception:
                logger.exception("[capture] 清理 socket 时间线采样失败（忽略）")
            socket_sampler = None
        # P2：收尾在 kill app 前 adb pull shared_prefs（app 活着时 prefs 多已 flush 到磁盘），
        #     抠登录态/凭据进 credential_events（best-effort，失败不影响抓包/其它事件）。
        _pull_shared_prefs_credentials(package, out_path, credential_events, serial)
        # P2：把 SQLCipher hook 导出的 *.plain.db（及普通 SQLite databases/*）adb pull 回
        #     out/dump_db/，并把回拉后的本地路径回填 sqlcipher_events.plain_path（供 merge 只读抠值）。
        _pull_exported_databases(package, out_path, sqlcipher_events, serial)
        _terminate(frida_proc, "frida")
        _teardown_frida_session(frida_session, frida_script)
        # ① floor：收尾停带外 pcap（起手起过才停；handle=None 说明没起、无需停）。
        if floor_handle is not None:
            floor_pcap = _stop_floor_pcap(floor_handle, out_path)
            if floor_pcap is not None:
                playbook.append(f"① floor 保底：带外 pcap 已停并落盘 {floor_pcap.name}")
            else:
                playbook.append("① floor 保底：带外 pcap 收尾未取到（降级，见日志）")
        if proxy_attempted:
            # ★P1：只要尝试过写代理就清理——即便读回未确认（settings put 可能已生效），
            # 也避免把设备全局代理遗留成死的 127.0.0.1:8080。
            _adb_clear_proxy(serial)
            playbook.append("还原：清除设备全局代理")
        if reverse_set:
            _adb_remove_reverse(serial)
            playbook.append(f"还原：adb reverse --remove tcp:{_PROXY_PORT}")
        _terminate(mitm_proc, "mitmdump")

    # 6) 解析 flows，提运行时端点，写 runtime_report.json。
    artifacts: list[str] = []
    if flows_file.exists():
        artifacts.append(str(flows_file))
    if floor_pcap is not None and floor_pcap.is_file():
        # ① floor 带外 pcap 作产物（mitm 明文之外的接入节点兜底：反 frida/pinning/native 时的穿透锚点）。
        artifacts.append(str(floor_pcap))
    if uid_snapshot is not None and uid_snapshot.is_file():
        # ★P1(#10)：UID socket 快照作产物，供人工把 floor.pcap 接入节点绑定到本 app 的连接。
        artifacts.append(str(uid_snapshot))
        playbook.append(f"UID socket 快照：{uid_snapshot.name}（把带外 pcap 接入节点绑定到 app 连接）")
    if socket_timeline is not None and socket_timeline.is_file():
        artifacts.append(str(socket_timeline))
        playbook.append(
            f"UID socket 时间线：{socket_timeline.name}（周期采样，补窗口末快照漏掉的短连接）"
        )

    endpoints = _parse_flows(flows_file)
    mitm_endpoints = list(endpoints)
    # ① floor 自动并入：带外 pcap 的接入节点作 runtime 端点并进 endpoints（mitm 0 端点时靠它兜底，
    #    治零产出）。IP 侧不在此判噪音——交下游 asn 富化 + infra 归属分级（Google/云 IP 自动判第三方
    #    基础设施并在报告折叠）；域名侧（SNI/DNS）按 OS/GMS/连通性 host 名单折叠明显噪音。绝不因
    #    floor 解析失败影响主报告（pcap 仍作产物留档）。
    floor_summary = None  # 解析一次，供并入端点与 UID 归因复用（复审 #5：避免重复全量解析大 pcap）
    if floor_pcap is not None and floor_pcap.is_file():
        try:
            noise_patterns = _load_noise_patterns()
            floor_summary = pcap_ingest.parse_pcap(str(floor_pcap))
            floor_eps = pcap_ingest.to_runtime_endpoints(floor_summary)
            seen_vals = {ep.value for ep in endpoints}
            added = [
                ep
                for ep in floor_eps
                if ep.value not in seen_vals
                and not (ep.kind == "domain" and _is_noise_host(ep.value, noise_patterns))
            ]
            if added:
                endpoints.extend(added)
                playbook.append(
                    f"① floor：带外 pcap 自动并入接入节点 {len(added)} 个"
                    f"（走 asn/infra 分级，Google/云 IP 自动折叠为第三方基础设施；原始 {floor_pcap.name} 留档）"
                )
        except Exception:
            logger.exception("[capture] floor：解析/并入 floor.pcap 失败（忽略，pcap 仍作产物）")
    # tshark 可选深度后端：明文 HTTP（Host/URL）——pcap_ingest 只抽 IP/SNI/DNS、不解 HTTP，涉诈 App 常用
    # 明文 HTTP 下发配置/上报；tshark 在 PATH 时深抽接入域名并入端点。tshark 缺/失败静默降级、绝不影响主流程。
    if floor_pcap is not None and floor_pcap.is_file():
        try:
            from apkscan.dynamic import tshark_backend

            if tshark_backend.has_tshark():
                http_eps = tshark_backend.to_endpoints(tshark_backend.extract_http(str(floor_pcap)))
                seen_http = {ep.value for ep in endpoints}
                http_noise = _load_noise_patterns()  # tshark 路径同样过噪音名单（复审 #1：captive-portal/遥测污染）
                http_added = [
                    ep for ep in http_eps
                    if ep.value not in seen_http and not _is_noise_host(ep.value, http_noise)
                ]
                if http_added:
                    endpoints.extend(http_added)
                    mitm_endpoints.extend(http_added)
                    playbook.append(
                        f"tshark 深度后端：明文 HTTP 抽出接入域名 {len(http_added)} 个（pcap_ingest 不解 HTTP）"
                    )
        except Exception:
            logger.exception("[capture] tshark 明文 HTTP 抽取失败（忽略，不影响主流程）")
    # P2：NSS TLS Key Log 解密——若 floor.pcap 旁存在授权插桩落下的 tls.keys（native agent / Frida SSL
    # keylog / PCAPdroid / 分析者 SSLKEYLOGFILE），用它解密 TLS，抽出加密应用层 HTTP/2 端点：pcap_ingest 只
    # 到 SNI、tshark 明文路径只到明文 HTTP，解密后才见 :authority/:path 的真实业务后端。★门控：仅当 keylog
    # 文件显式存在且确是 NSS Key Log 时才解密——密钥出自授权设备/App 插桩，其存在即授权信号。缺/失败静默降级。
    if floor_pcap is not None and floor_pcap.is_file():
        keylog = out_path / _TLS_KEYLOG_NAME
        if keylog.is_file():
            try:
                from apkscan.dynamic import tshark_backend

                if tshark_backend.has_tshark():
                    dec_eps = tshark_backend.decrypted_to_endpoints(
                        tshark_backend.extract_decrypted_http(str(floor_pcap), str(keylog))
                    )
                    seen_dec = {ep.value for ep in endpoints}
                    dec_noise = _load_noise_patterns()
                    dec_added = [
                        ep for ep in dec_eps
                        if ep.value not in seen_dec and not _is_noise_host(ep.value, dec_noise)
                    ]
                    if dec_added:
                        endpoints.extend(dec_added)
                        mitm_endpoints.extend(dec_added)
                        artifacts.append(str(keylog))
                        playbook.append(
                            f"P2 NSS TLS Key Log 解密：还原 TLS 应用层接入域名 {len(dec_added)} 个"
                            "（加密流量解密后才可见的真实业务后端）"
                        )
                    # P2 续：抠解密 HTTP 请求的凭据头（Authorization/Cookie=登录态/token）→ credential_events。
                    #   ★脱敏：每条经 cryptohook.normalize_credential_event（高敏头整值截断），绝不把明文 token 落报告。
                    cred_added = 0
                    for raw_cred in tshark_backend.extract_decrypted_credentials(str(floor_pcap), str(keylog)):
                        ev = cryptohook.normalize_credential_event(raw_cred)
                        if ev:
                            credential_events.append(ev)
                            cred_added += 1
                    if cred_added:
                        if str(keylog) not in artifacts:
                            artifacts.append(str(keylog))
                        playbook.append(
                            f"P2 NSS TLS Key Log 解密：抠出 TLS 请求的登录态/token 头 {cred_added} 条（已脱敏）"
                        )
            except Exception:
                logger.exception("[capture] TLS keylog 解密抽取失败（忽略，不影响主流程）")
    # floor pcap 接入节点【绑定到目标 app】：消费 uid_sockets.txt 快照，按远端 IP:port 关联出该连接属
    # 哪个 UID/进程、是否 == 目标 app——自动区分真后端 vs 背景噪音（此前 uid_sockets.txt 只供人工比对）。
    # best-effort、绝不影响主流程（floor pcap 与 uid 快照都在才做；失败忽略）。
    pcap_app_attr: dict[str, Any] = {}
    if floor_summary is not None and (
        (socket_timeline is not None and socket_timeline.is_file())
        or (uid_snapshot is not None and uid_snapshot.is_file())
    ):
        try:
            from apkscan.dynamic import socket_attr

            parsed: list = []
            names: list[str] = []
            if socket_timeline is not None and socket_timeline.is_file():
                tl = socket_attr.parse_socket_timeline(
                    socket_timeline.read_text(encoding="utf-8", errors="replace")
                )
                if tl.entries:
                    parsed.append(tl)
                    names.append(socket_timeline.name)
            if uid_snapshot is not None and uid_snapshot.is_file():
                snap = socket_attr.parse_uid_sockets(
                    uid_snapshot.read_text(encoding="utf-8", errors="replace")
                )
                if snap.entries:
                    parsed.append(snap)
                    names.append(uid_snapshot.name)
            if not parsed:
                raise ValueError("socket 时间线与窗口末快照均无可解析记录")
            # ★codex 复审 P0：合并【时间线】（_SocketSampler 只采目标 UID、补短连）+【窗口末快照】（含全 UID，
            #   是歧义判定必需的竞争视图）——不能只用 target-only 时间线，否则同远端多 UID 时会误判 confident。
            table = parsed[0] if len(parsed) == 1 else socket_attr.merge_uid_sockets(*parsed)
            attribution_source = "+".join(names)
            res = pcap_ingest.remote_endpoints(floor_summary)  # 复用已解析的 summary，不重复解析
            # A2：把每个远端接入节点连同其本机连接明细（本地端口 + pcap 流时间窗）喂给五元组归因引擎——
            #   同远端多 UID（CDN/网关）时用本地端口/时间窗消歧到 confirmed/probable，四级评分。键含 proto 族。
            eps = [
                socket_attr.PcapEndpoint(
                    remote_ip=r.ip,
                    remote_port=r.port,
                    proto=r.proto,
                    conns=[socket_attr.PcapConn(c.local_port, c.first_ts, c.last_ts) for c in r.connections],
                )
                for r in res
            ]
            attr = socket_attr.attribute_connections(eps, table)
            pcap_app_attr = {f"{proto}/{ip}:{port}": v for (proto, ip, port), v in attr.items()}
            if pcap_app_attr:
                # ★A2 四级计数：confirmed/probable/ambiguous/unattributed；is_target_app=None（歧义/未归因）
                #   不能被当 falsy 归入"背景噪音"（承 codex 复审 P1 三类不塌缩纪律）。
                vals = list(pcap_app_attr.values())
                n_target = sum(1 for v in vals if v.get("is_target_app") is True)

                def _n(kind: str) -> int:
                    return sum(1 for v in vals if v.get("attribution") == kind)

                playbook.append(
                    f"UID 归因（五元组+时间窗）：floor pcap 接入节点绑到 app——{len(vals)} 个已归因："
                    f"confirmed {_n('confirmed')} / probable {_n('probable')} / ambiguous {_n('ambiguous')} / "
                    f"unattributed {_n('unattributed')}；其中 {n_target} 属目标 app（uid={table.target_uid}）"
                    f"（来源 {attribution_source}）"
                )
        except Exception:
            logger.exception("[capture] floor：pcap↔app UID 归因失败（忽略，不影响主流程）")
    # C5b：额外抽出报文体（请求/响应），供 merge 阶段对 {data,timestamp} 信封解密。
    # 失败/缺 mitmproxy 包 → 空列表（不影响端点提取与报告写出）。
    messages = _parse_messages(flows_file)
    # P0-4：结构化采集信号——判这次抓包哪路成了。没有 error 但也没取到任何可用证据
    # （代理未起 / MITM 0 字节 / floor 未拉回 / 端点 0）时降为 degraded，杜绝"假成功"。
    try:
        mitm_bytes = flows_file.stat().st_size if flows_file.exists() else 0
    except OSError:
        mitm_bytes = 0
    # ★#7：hook 就绪三态——只有收到显式 fxapk_hook_ready:true 才算 confirmed；未确认/Java 不可用
    #   附告警，不把"未确认"上报成"已确认"掩盖 hook 没装上。
    hook_status = _frida_hook_status(frida_session)
    if hook_status in ("java-unavailable", "unconfirmed"):
        warnings.append(
            f"frida hook 未确认就绪（{hook_status}）——注入可能未生效（反检测样本常见），运行时事件可能不全，靠 floor/pcap 兜底"
        )
    capture_signals: dict[str, Any] = {
        "proxy_set": bool(proxy_set),
        "reverse_set": bool(reverse_set),
        "floor_started": floor_handle is not None,
        "floor_pulled": floor_pcap is not None,
        "hook_ready": hook_status == "confirmed",  # ★#7：仅收到显式 fxapk_hook_ready:true 才算已确认
        "hook_ready_status": hook_status,  # confirmed / java-unavailable / unconfirmed / none
        "mitm_bytes": mitm_bytes,
        "endpoint_total": len(endpoints),
        "warnings": list(warnings),
    }
    if pcap_app_attr:  # floor pcap 接入节点→app UID/进程 归因（真后端 vs 背景噪音）
        capture_signals["pcap_app_attribution"] = pcap_app_attr
    # 降级判定：仅当**没有任何证据路径成立**——代理未起 且 无 floor pcap 且 MITM 0 字节 且 端点 0
    # ——才降为 degraded（总失败组合）。只要代理起了 / floor 拉回了 / 抓到端点，即便 app 安静
    # （0 flows）仍算 done（不阻断，降级细节走 reason/warnings，保持既有契约）。
    # ★P0：MITM 通道需 代理【且】reverse 都成——只 proxy_set 不够（reverse 失败时设备代理
    # 指向死的本机 loopback、MITM 不可用，等价无证据路径）。
    mitm_channel_ok = proxy_set and reverse_set
    capture_signals["mitm_channel_ok"] = mitm_channel_ok
    _annotate_runtime_endpoints(endpoints, floor_summary, pcap_app_attr)
    capture_signals["quality"] = _build_capture_quality(
        floor_summary,
        mitm_endpoints,
        pcap_app_attr,
        channel_ready=mitm_channel_ok or floor_handle is not None,
    )
    evidence_path_ok = mitm_channel_ok or floor_pcap is not None or len(endpoints) > 0 or mitm_bytes > 0
    if result["status"] == STATUS_DONE and not evidence_path_ok:
        result["status"] = STATUS_DEGRADED
        result["reason"] = "抓包降级：无任何证据路径（MITM 通道未通[代理/reverse]、无 floor pcap、MITM 0 字节、端点 0）"
        capture_signals["degraded"] = True
    # 抓包失败/降级时，产出的 runtime_report 基于不完整/未抓全的流量，必须标明，避免伪装成正常结果。
    capture_ok = result["status"] == STATUS_DONE
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
        credential_events=_clean(credential_events),
        sqlcipher_events=_clean(sqlcipher_events),
        clipboard_events=_clean(clipboard_events),
        remote_control_events=_clean(remote_control_events),
        budget_exceeded=budget_exceeded,
        capture_signals=capture_signals,
        capture_capabilities=capabilities_plan,
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
    _cleanup_diag(out_path)  # 清掉 .diag/ 下空的 mitmdump/frida stderr 日志（成功时纯杂物）
    return result


def _spawn_logged(args: list[str], log_path: Path) -> subprocess.Popen[bytes]:
    """起长驻子进程：stdout 丢弃、stderr 重定向到 ``log_path`` 文件（**而非 PIPE**）。

    长驻子进程（mitmdump/frida）若用 ``PIPE`` 且在抓包窗口内无人读，输出写满 OS 管道缓冲
    （~64KB）会阻塞其主循环 → 代理停转、后续真·C2 流量静默丢失，而 capture 仍 sleep 满
    duration 并以"成功 N 端点"收尾（"假成功"）。改用文件重定向：既不会阻塞，又把 stderr
    完整留盘供秒退诊断（``_read_proc_stderr`` 优先读该文件）。stdout 用 ``DEVNULL``（flows 已
    落 ``-w`` 文件、frida ``-q`` 本就安静）。日志写进 ``out/.diag/``（不与报告混在主输出目录），
    成功（空文件）由 :func:`_cleanup_diag` 收尾清掉。
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)  # .diag 子目录
    log_f = open(log_path, "wb")  # noqa: SIM115 - 句柄交 subprocess 继承，父进程随即关闭副本
    try:
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=log_f)
    finally:
        log_f.close()  # 父进程关副本；子进程已继承自己的 fd，照常写入
    proc._fxapk_stderr_log = log_path  # type: ignore[attr-defined]  # 供 _read_proc_stderr 读取
    return proc


def _cleanup_diag(out_path: Path) -> None:
    """收尾清理 ``out/.diag/`` 下的**空**诊断日志（成功时 stderr 为空、纯杂物，别和报告混在
    主输出目录）；非空的保留供排障。目录清空后连 ``.diag`` 一并删。绝不抛。"""
    diag = out_path / ".diag"
    if not diag.is_dir():
        return
    try:
        for f in diag.iterdir():
            try:
                if f.is_file() and f.stat().st_size == 0:
                    f.unlink()
            except OSError:
                logger.debug("[capture] 清理空诊断日志失败（忽略）：%s", f, exc_info=True)
        if not any(diag.iterdir()):
            diag.rmdir()
    except OSError:
        logger.debug("[capture] 清理 .diag 目录失败（忽略）", exc_info=True)


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
    return _spawn_logged(args, flows_file.parent / ".diag" / "mitmdump.stderr.log")


def _start_frida_unpinning(
    package: str, out_path: Path, serial: str | None = None
) -> subprocess.Popen[bytes] | None:
    """写出内置 unpinning 脚本，frida 注入并 spawn 目标 app。

    设备选择：serial 非空时用 ``-D <serial>`` 钉定那台（多设备/一机多 transport 下，
    ``-U`` 会因有多个可达设备而 ambiguous）；serial=None 退回 ``-U``（向后兼容无设备
    选择的旧路径/测试）。

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

    device_flags = ["-D", serial] if serial else ["-U"]
    args = [*inv, *device_flags, "-f", package, "-l", str(js_path), "-q"]
    host_major = re.match(r"(\d+)\.", provision.host_frida_version())
    if host_major is not None and int(host_major.group(1)) < 14:
        args.append("--no-pause")  # 仅老版 frida-tools(<14) 需要；新版默认不暂停
    logger.info("[capture] frida 注入 unpinning 并启动 app：%s", " ".join(args))
    try:
        return _spawn_logged(args, out_path / ".diag" / "frida.stderr.log")
    except Exception:
        logger.exception("[capture] 启动 frida 失败，跳过注入")
        return None


# ---------------------------------------------------------------------------
# P0：frida-core 会话（SSL unpinning + 运行时密钥 hook，可回传活体 key）
# ---------------------------------------------------------------------------

# frida.get_usb_device 连接设备的超时（秒）。_detect_missing 已确认设备+frida-server，
# 此处只是防御性上限，避免无设备时阻塞。
_FRIDA_USB_TIMEOUT = 10


# 表驱动的运行时事件通道：(name, msg_type, normalize)。crypto 主通道单独走
# make_message_handler（含 error 诊断），其余 7 路统一用 make_typed_handler 注册，避免 8 段
# 近乎相同的 script.on 复制粘贴（改一处即全通道生效）。sink 由调用方按 name 顺序传入。
CHANNELS: tuple[tuple[str, str, Any], ...] = (
    ("jsbridge", cryptohook.JSBRIDGE_MSG_TYPE, cryptohook.normalize_jsbridge_event),
    ("sensitive_api", cryptohook.SENSITIVE_API_MSG_TYPE, cryptohook.normalize_sensitive_api_event),
    ("antidetect", cryptohook.ANTIDETECT_MSG_TYPE, cryptohook.normalize_antidetect_event),
    ("credential", cryptohook.CREDENTIAL_MSG_TYPE, cryptohook.normalize_credential_event),
    ("sqlcipher", cryptohook.SQLCIPHER_MSG_TYPE, cryptohook.normalize_sqlcipher_event),
    # ★ 隐私护栏：normalize_clipboard_event 抽地址丢全文，sink 只留链上地址、绝不落剪贴板原文。
    ("clipboard", cryptohook.CLIPBOARD_MSG_TYPE, cryptohook.normalize_clipboard_event),
    # 无障碍远控：多数需引导式人工动态，launch-only 常为空——属预期。
    ("remote_control", cryptohook.ACCESSIBILITY_MSG_TYPE, cryptohook.normalize_remote_control_event),
)

# ★#7 hook readiness：所有 hook 装完后由 JS 显式回传 fxapk_hook_ready——在 Java.perform 内确认 ART
# 可用（catch 反检测样本下 script.load 成功但实际 "Java is not defined"/hook 没装上的假就绪）。
_FRIDA_HOOK_READY_JS = (
    ";(function () {"
    "  try {"
    "    if (typeof Java !== 'undefined' && Java.available) {"
    "      Java.perform(function () { send({ fxapk_hook_ready: true }); });"
    "    } else {"
    "      send({ fxapk_hook_ready: false, reason: 'java-unavailable' });"
    "    }"
    "  } catch (e) { send({ fxapk_hook_ready: false, reason: String(e) }); }"
    "})();"
)


def _start_frida_session(
    package: str,
    sink: list[dict[str, Any]],
    jsbridge_sink: list[dict[str, Any]] | None = None,
    api_sink: list[dict[str, Any]] | None = None,
    antidetect_sink: list[dict[str, Any]] | None = None,
    credential_sink: list[dict[str, Any]] | None = None,
    sqlcipher_sink: list[dict[str, Any]] | None = None,
    clipboard_sink: list[dict[str, Any]] | None = None,
    remote_control_sink: list[dict[str, Any]] | None = None,
    serial: str | None = None,
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
        serial: 目标设备 serial。非空时经 ``frida.get_device(serial)`` 钉定那台（多设备/
                一机多 transport 下 ``get_usb_device`` 会因多个可达设备 ambiguous）；
                None 退回 ``get_usb_device``（向后兼容无设备选择的旧路径/测试）。

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
        + "\n"
        + cryptohook.FRIDA_OKHTTP_HOOK_JS
        + "\n"
        + cryptohook.FRIDA_SQLCIPHER_HOOK_JS
        + "\n"
        + cryptohook.FRIDA_CLIPBOARD_HOOK_JS
        + "\n"
        + cryptohook.FRIDA_ACCESSIBILITY_HOOK_JS
        + "\n"
        + _FRIDA_HOOK_READY_JS  # ★#7：所有 hook 装完后显式 send hook_ready（在 Java.perform 内确认 ART 可用）
    )
    device_handle: Any = None
    pid: Any = None
    session: Any = None
    try:
        # serial 钉定那台（-D 等价）；None 退回 USB（向后兼容）。
        if serial:
            device_handle = frida.get_device(serial, timeout=_FRIDA_USB_TIMEOUT)
        else:
            device_handle = frida.get_usb_device(timeout=_FRIDA_USB_TIMEOUT)
        pid = device_handle.spawn([package])
        session = device_handle.attach(pid)
        # 在会话上寄存 device 句柄，供 _frida_session_alive 用 enumerate_processes 复验 pid 存活。
        try:
            session._fxapk_device = device_handle  # type: ignore[attr-defined]
        except Exception:
            logger.debug("[capture] 无法在会话上寄存 device 句柄（忽略，liveness 退化为仅看 detached）", exc_info=True)
        script = session.create_script(source)
        # ★#7：hook readiness 通道——JS 装完 hook 后 send fxapk_hook_ready，异步落进标志容器，
        #   供收尾时读（capture_signals["hook_ready"]），把"会话建立"细化为"hook 真装上"。
        hook_ready: dict[str, Any] = {"ready": None}

        def _hook_ready_handler(message: Any, _data: Any) -> None:
            try:
                if isinstance(message, dict) and message.get("type") == "send":
                    payload = message.get("payload")
                    if isinstance(payload, dict) and "fxapk_hook_ready" in payload:
                        hook_ready["ready"] = bool(payload.get("fxapk_hook_ready"))
            except Exception:
                logger.debug("[capture] hook_ready 消息处理异常（忽略）", exc_info=True)

        script.on("message", _hook_ready_handler)
        try:
            session._fxapk_hook_ready = hook_ready  # type: ignore[attr-defined]
        except Exception:
            logger.debug("[capture] 无法在会话寄存 hook_ready 标志（忽略）", exc_info=True)
        # crypto 主通道（含 error 诊断）单独走 make_message_handler。
        script.on("message", cryptohook.make_message_handler(sink))
        # 其余 7 路运行时事件通道表驱动注册（sink 顺序与 CHANNELS 严格对齐；None 则跳过该通道）。
        channel_sinks = (
            jsbridge_sink,
            api_sink,
            antidetect_sink,
            credential_sink,
            sqlcipher_sink,
            clipboard_sink,
            remote_control_sink,
        )
        for (name, msg_type, normalize), chan_sink in zip(CHANNELS, channel_sinks):
            if chan_sink is None:
                continue
            script.on(
                "message",
                cryptohook.make_typed_handler(chan_sink, msg_type, normalize),
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


def _frida_device_reachable(serial: str | None = None) -> bool | None:
    """用 frida-core（``import frida``）连设备并 ``enumerate_processes()`` 实测验收 frida 是否真可用。

    Returns: ``True``=可枚举进程（frida 就绪）/ ``False``=连上设备但枚举失败（frida-server 未起/
    版本不配）/ ``None``=frida-core 不可用或连不上设备（无法判定）。best-effort、绝不抛。
    """
    try:
        import frida  # type: ignore[import-not-found]  # lazy：缺库时无法验收
    except Exception:
        return None
    try:
        dev = (
            frida.get_device(serial, timeout=_FRIDA_USB_TIMEOUT)
            if serial
            else frida.get_usb_device(timeout=_FRIDA_USB_TIMEOUT)
        )
    except Exception:
        logger.debug("[capture] frida 连设备失败，无法枚举验收", exc_info=True)
        return None
    try:
        dev.enumerate_processes()
        return True
    except Exception:
        logger.debug("[capture] frida enumerate_processes 失败（frida-server 未起/版本不配）", exc_info=True)
        return False


def _check_frida_version_match(serial: str | None = None) -> tuple[bool, str]:
    """校验主机 frida 与设备 frida-server 版本是否一致（best-effort，不阻断注入）。

    Returns:
        (ok, msg)。一致 → (True, '')；明确不一致 → (False, 警告文案)。
        ★P1(#6)：任一版本取不到时不再静默按通过（PATH 混用/frida-server 未起会掩盖真不配），
        改用 ``_frida_device_reachable`` 实测 ``enumerate_processes`` 验收：可枚举→静默通过；
        连上但枚举失败→(False, 警告)；无法验收(缺 frida-core/连不上)→不阻断但只 debug。
    """
    host_ver = provision.host_frida_version()
    dev_ver = _device_frida_version(serial)
    # 任一取不到 → 版本不可比对：用 frida 实测枚举验收，而非静默通过。
    if not host_ver or not dev_ver:
        reachable = _frida_device_reachable(serial)
        if reachable is False:
            msg = (
                "frida 版本无法比对，且设备进程枚举验收失败"
                "（frida-server 可能未起或与主机版本不配），注入可能失败"
            )
            logger.warning("[capture] %s", msg)
            return False, msg
        logger.debug(
            "[capture] frida 版本无法比对（主机=%r 设备=%r），枚举验收=%r，不阻断",
            host_ver,
            dev_ver,
            reachable,
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


def _proxy_readback(serial: str | None = None) -> str:
    """读回设备全局 HTTP 代理值（``settings get global http_proxy``，去空白）；取不到/未设返回空串。"""
    out = _adb_capture(["shell", "settings", "get", "global", "http_proxy"], serial)
    val = (out or "").strip()
    return "" if val in ("", "null") else val


def _adb_set_proxy(serial: str | None = None) -> bool:
    """设设备全局 HTTP 代理并**读回确认**；普通 ``settings put`` 未生效则 root 兜底再读回。

    ★P1：只有读回确认代理值 == 目标才返回 True——``settings put`` 返回 0 不代表真生效
    （部分设备被策略拦 / 需 root）。返回 False 即明确降级，供 P0-4 capture_signals 如实标注，
    不谎称 MITM 就绪。best-effort、不阻断抓包（floor pcap 仍可保底）。
    """
    target = f"{_PROXY_HOST}:{_PROXY_PORT}"
    _adb(["shell", "settings", "put", "global", "http_proxy", target], serial)
    if _proxy_readback(serial) == target:
        return True
    # 普通 put 未读回生效 → root 兜底（部分设备 settings 需 root / 或被策略限制）。
    provision._adb_root_shell(f"settings put global http_proxy {target}", serial)
    if _proxy_readback(serial) == target:
        logger.info("[capture] 设备全局代理经 root 兜底设置成功（读回确认 %s）", target)
        return True
    logger.warning("[capture] 设置设备全局代理失败/读回未确认（降级：MITM 可能不可用）")
    return False


def _adb_clear_proxy(serial: str | None = None) -> None:
    """还原设备全局代理：settings delete global http_proxy。"""
    if not _adb(["shell", "settings", "delete", "global", "http_proxy"], serial):
        logger.warning("[capture] 清除设备全局代理失败（请手动还原）")


def _adb_reverse(serial: str | None = None) -> bool:
    """adb reverse tcp:8080 tcp:8080，让设备 localhost 回流到主机 mitmproxy。"""
    ok = _adb(["reverse", f"tcp:{_PROXY_PORT}", f"tcp:{_PROXY_PORT}"], serial)
    if not ok:
        logger.warning("[capture] adb reverse 失败（不阻断抓包）")
    return ok


def _adb_remove_reverse(serial: str | None = None) -> None:
    """还原 adb reverse。"""
    if not _adb(["reverse", "--remove", f"tcp:{_PROXY_PORT}"], serial):
        logger.warning("[capture] adb reverse --remove 失败（请手动还原）")


def _adb(extra: list[str], serial: str | None = None) -> bool:
    """运行 adb 子命令，成功（returncode==0）返回 True。缺 adb / 失败 / 异常 → False。

    serial 非空时插入 ``-s <serial>``（多设备/一机多 transport 下消解 ``more than one
    device`` 歧义）；serial=None 时不带 -s（向后兼容无设备选择的旧路径/测试）。
    """
    exe = tools.adb_path()
    if not exe:
        logger.warning("[capture] adb 不可用，跳过：%s", " ".join(extra))
        return False
    args = [exe, *(["-s", serial] if serial else []), *extra]
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
        logger.warning("[capture] adb 命令超时：%s", " ".join(extra))
        return False
    except Exception:
        logger.exception("[capture] adb 命令异常：%s", " ".join(extra))
        return False
    if proc.returncode != 0:
        logger.warning("[capture] adb 命令非零退出（%s）：%s", proc.returncode, " ".join(extra))
        return False
    return True


def _path_is_ascii(p: Path) -> bool:
    """本地路径是否纯 ASCII。Windows 下 adb.exe 对含中文/非 ASCII 的本地目标路径 pull 会失败（argv 编码）。"""
    try:
        str(p).encode("ascii")
    except UnicodeEncodeError:
        return False
    return True


def _short_path_if_ascii(p: Path) -> Path | None:
    """Windows 上取 ``p`` 的 8.3 短路径；短路径纯 ASCII 才返回，否则 None（非 Windows/取不到/仍非 ASCII → None）。

    系统卷默认启用 8.3 短名，中文/非 ASCII 目录段会呈 ``XXXXXX~1`` 纯 ASCII 形式——用它做 adb pull 的
    本地目标即可绕开非 ASCII 路径失败。指向的仍是同一物理目录（清理不受影响）。
    """
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        fn = ctypes.windll.kernel32.GetShortPathNameW  # type: ignore[attr-defined]
        fn.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        fn.restype = wintypes.DWORD
        buf = ctypes.create_unicode_buffer(512)
        if fn(str(p), buf, 512) and buf.value:
            short = Path(buf.value)
            if _path_is_ascii(short):
                return short
    except Exception:
        logger.debug("[capture] GetShortPathNameW 取 8.3 短路径失败（忽略）", exc_info=True)
    return None


def _ascii_staging_dir() -> Path:
    """建一个**尽量 ASCII** 的临时暂存目录（供 _adb_pull_to 中转，规避 adb 对非 ASCII 本地路径失败）。

    ★codex 真机 BUG3 复审加固：``tempfile.mkdtemp`` 跟随 ``%TEMP%``，而中文 Windows 账户下 ``%TEMP%``
    （位于 ``%USERPROFILE%`` 内）本身非 ASCII——只靠它中转对**非 ASCII 用户名**机器仍失败。故 mkdtemp 后
    若路径非 ASCII，用 8.3 短路径兜底（:func:`_short_path_if_ascii`，同一物理目录）；仍不可得（卷禁用 8.3）
    则记一次告警后回落原路径（不抛、不比修复前更差）。
    """
    d = Path(tempfile.mkdtemp(prefix="fxapk_pull_"))
    if _path_is_ascii(d):
        return d
    short = _short_path_if_ascii(d)
    if short is not None:
        return short
    logger.warning(
        "[capture] 临时暂存目录含非 ASCII 且无 8.3 短路径可用，adb pull 中转可能仍失败；"
        "可设环境变量 TMP 指向纯 ASCII 目录规避。路径=%s",
        d,
    )
    return d


def _adb_pull_to(remote: str, dest: Path, serial: str | None = None) -> bool:
    """adb pull 设备文件 ``remote`` → 本地 ``dest``（已含最终文件名）；成功 True，任何失败 → False（不抛）。

    ★codex 真机 BUG3（Windows 中文/OneDrive 路径 adb pull 失败）：adb.exe 在 Windows 上对含非 ASCII
    的本地目标路径 pull 会失败。故 ``dest`` 路径非 ASCII 时，先 pull 到**尽量 ASCII** 的临时暂存目录
    （:func:`_ascii_staging_dir`，用 ASCII 占位文件名规避文件名本身非 ASCII），校验拉到后再 ``shutil.move``
    到 ``dest``（Python 处理 Unicode 路径无碍）；``dest`` 纯 ASCII 时直接 pull。``dest`` 父目录按需创建。
    """
    if _path_is_ascii(dest):
        return _adb(["pull", remote, str(dest)], serial)
    staging = _ascii_staging_dir()
    staged = staging / "pulled.bin"  # ASCII 占位名：暂存目录与文件名全 ASCII，adb 才拉得动
    try:
        if not (_adb(["pull", remote, str(staged)], serial) and staged.exists()):
            return False
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            logger.exception("[capture] adb pull：创建目标目录失败 %s", dest.parent)
            return False
        shutil.move(str(staged), str(dest))
        return True
    except Exception:
        logger.exception("[capture] adb pull 经 ASCII 暂存中转失败：%s → %s", remote, dest)
        return False
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _adb_capture(extra: list[str], serial: str | None = None) -> str | None:
    """运行 adb 子命令并返回 stdout 文本；缺 adb / 非零退出 / 异常 → None（不抛）。

    serial 非空时插入 ``-s <serial>``（同 :func:`_adb`）；None 时不带 -s（向后兼容）。
    """
    exe = tools.adb_path()
    if not exe:
        logger.debug("[capture] adb 不可用，跳过取数：%s", " ".join(extra))
        return None
    args = [exe, *(["-s", serial] if serial else []), *extra]
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
        logger.warning("[capture] adb 取数超时：%s", " ".join(extra))
        return None
    except Exception:
        logger.exception("[capture] adb 取数异常：%s", " ".join(extra))
        return None
    if proc.returncode != 0:
        logger.debug("[capture] adb 取数非零退出（%s）：%s", proc.returncode, " ".join(extra))
        return None
    return proc.stdout or ""


def _app_uid(package: str, serial: str | None = None) -> str:
    """取目标 app 的 UID（``dumpsys package <pkg>`` 的 ``userId=``）。取不到返回空串。绝不抛。"""
    out = _adb_capture(["shell", "dumpsys", "package", package], serial) or ""
    m = re.search(r"userId=(\d+)", out)
    return m.group(1) if m else ""


def _capture_uid_socket_snapshot(package: str, out_path: Path, serial: str | None = None) -> Path | None:
    """★P1(#10)：抓目标 app（按 UID）的 socket 快照存 ``out/uid_sockets.txt``——供把带外整机
    pcap 的接入节点【绑定到本 app 的连接】（进程/UID→远端 IP:port），区分真后端 vs 背景噪音。

    抓 ``ss -tunp``（需 root 才显进程/UID）+ ``/proc/net/tcp``、``/proc/net/tcp6``（含 uid 列、
    地址端口十六进制）。任一取到即写文件；全空返回 None。best-effort、绝不抛。
    """
    try:
        uid = _app_uid(package, serial)
        parts = [f"# package={package} uid={uid or '(未取到)'}"]
        got = False
        ss = _adb_capture(["shell", "ss", "-tunp"], serial)
        if ss and ss.strip():
            parts.append("## ss -tunp（需 root 显进程/UID）\n" + ss.rstrip())
            got = True
        # tcp{,6}=长连后端；udp{,6}=QUIC/HTTP3 的 socket（UDP/443），补上才能给 QUIC 流做 UID 归因。
        for procfs in ("/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"):
            raw = _adb_capture(["shell", "cat", procfs], serial)
            if raw and raw.strip():
                parts.append(f"## {procfs}（uid 在第 8 列，地址/端口十六进制）\n" + raw.rstrip())
                got = True
        if not got:
            logger.debug("[capture] UID socket 快照：ss / /proc/net 均未取到（无 root / 无 adb）")
            return None
        dest = out_path / "uid_sockets.txt"
        dest.write_text("\n\n".join(parts) + "\n", encoding="utf-8")
        logger.info("[capture] UID socket 快照已存 %s（uid=%s）", dest, uid or "?")
        return dest
    except Exception:
        logger.exception("[capture] 抓 UID socket 快照失败（忽略）")
        return None


class _SocketSampler:
    """抓包窗口内周期采集目标 UID 的 socket，落盘为有界 JSONL 时间线。"""

    def __init__(
        self,
        package: str,
        out_path: Path,
        serial: str | None = None,
        *,
        interval: float = _SOCKET_SAMPLE_INTERVAL,
        max_observations: int = _SOCKET_MAX_OBSERVATIONS,
    ) -> None:
        self.package = package
        self.out_path = out_path
        self.serial = serial
        uid_text = _app_uid(package, serial)
        self.target_uid = int(uid_text) if uid_text.isdigit() else None
        self.interval = max(0.05, float(interval))
        self.max_observations = max(1, int(max_observations))
        self._observations: list[dict[str, Any]] = []
        # 键=5 元组(proto,uid,本地,远端)，值=该 socket 的观测 dict（含就地更新的 last_ts）——
        # 不含 state，稳定态长连接才能跨轮扩成时间区间，而非只留首次观测的点。
        self._seen: dict[tuple[Any, ...], dict[str, Any]] = {}
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._written: Path | None = None
        self._lock = threading.Lock()

    def start(self) -> None:
        """同步抓首帧后起 daemon 线程；取不到 UID 时静默降级。"""
        if self.target_uid is None or self._thread is not None:
            return
        try:
            self._sample_once()
            self._thread = threading.Thread(
                target=self._run,
                name="fxapk-socket-sampler",
                daemon=True,
            )
            self._thread.start()
        except Exception:
            logger.exception("[capture] 启动 socket 时间线采样失败（忽略）")

    def _run(self) -> None:
        while not self._stop_event.wait(self.interval):
            try:
                self._sample_once()
            except Exception:
                logger.exception("[capture] socket 时间线单次采样失败（忽略）")
            if len(self._observations) >= self.max_observations:
                logger.warning(
                    "[capture] socket 时间线达到上限 %s，停止继续累积",
                    self.max_observations,
                )
                return

    @staticmethod
    def _endpoint(ip: str, port: int) -> str:
        return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"

    def _sample_once(self) -> None:
        """采一轮 /proc/net/tcp{,6}；同一 socket（5 元组，不含 state）首见记 first ts、重现就地扩 last_ts，形成观测区间。"""
        if self.target_uid is None:
            return
        from apkscan.dynamic import socket_attr

        ts = time.time()
        for procfs, proto in (
            ("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6"),
            ("/proc/net/udp", "udp"), ("/proc/net/udp6", "udp6"),  # QUIC/HTTP3 = UDP，补归因
        ):
            raw = _adb_capture(["shell", "cat", procfs], self.serial) or ""
            for line in raw.splitlines():
                entry = socket_attr._parse_proc_line(line, proto)
                if entry is None or entry.uid != self.target_uid:
                    continue
                key = (
                    entry.proto,
                    entry.uid,
                    entry.local_ip,
                    entry.local_port,
                    entry.remote_ip,
                    entry.remote_port,
                )
                with self._lock:
                    existing = self._seen.get(key)
                    if existing is not None:
                        existing["last_ts"] = ts  # 就地扩展观测区间，不新增列表项（仍受 max_observations 约束）
                        continue
                    if len(self._observations) >= self.max_observations:
                        continue
                    observation = {
                        "ts": ts,
                        "last_ts": ts,
                        "proto": entry.proto,
                        "uid": entry.uid,
                        "local": self._endpoint(entry.local_ip, entry.local_port),
                        "remote": self._endpoint(entry.remote_ip, entry.remote_port),
                        "state": entry.state,
                    }
                    self._seen[key] = observation
                    self._observations.append(observation)

    def stop(self) -> Path | None:
        """停止采样并原子写 JSONL；无有效观测或失败返回 None。"""
        try:
            if self._written is not None:
                return self._written
            self._stop_event.set()
            if self._thread is not None:
                timeout = max(1.0, float(device._DEFAULT_TIMEOUT) * 2 + 1)
                self._thread.join(timeout=timeout)
                if self._thread.is_alive():
                    logger.warning("[capture] socket 时间线采样线程未及时退出，放弃本次落盘")
                    return None
            with self._lock:
                observations = list(self._observations)
            if not observations or self.target_uid is None:
                return None
            self.out_path.mkdir(parents=True, exist_ok=True)
            dest = self.out_path / _SOCKET_TIMELINE_NAME
            temp = self.out_path / f".{_SOCKET_TIMELINE_NAME}.tmp"
            def _interval_rows(obs: dict[str, Any]) -> list[dict[str, Any]]:
                # 落盘不含内部 last_ts 字段；last_ts>first 时补一行末观测，parse_socket_timeline 按 ts min/max 重建区间。
                first = {k: v for k, v in obs.items() if k != "last_ts"}
                last_ts = obs.get("last_ts")
                if isinstance(last_ts, (int, float)) and not isinstance(last_ts, bool) and last_ts > first["ts"]:
                    return [first, {**first, "ts": last_ts}]
                return [first]

            rows = [
                {"type": "meta", "package": self.package, "target_uid": self.target_uid},
                *(row for obs in observations for row in _interval_rows(obs)),
            ]
            temp.write_text(
                "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
                encoding="utf-8",
            )
            temp.replace(dest)
            self._written = dest
            logger.info(
                "[capture] socket 时间线已存 %s（目标 UID=%s，唯一观测=%s）",
                dest,
                self.target_uid,
                len(observations),
            )
            return dest
        except Exception:
            logger.exception("[capture] 停止/写出 socket 时间线失败（忽略）")
            return None


# ---------------------------------------------------------------------------
# P2：收尾 adb pull shared_prefs，抠落地凭据（登录态/token/商户号/邀请码）
# ---------------------------------------------------------------------------
#
# 机制：debuggable app 可 `run-as <pkg>` 以 app 身份读自己私有目录；非 debuggable 则需 root
# （`su -c`）。两条通道都 best-effort 试一遍，任一成功即抠 xml。失败（无 root / 非 debuggable /
# 无 adb）只记 debug、不影响抓包与其它事件——这正是反诈样本常见的封堵，属预期降级。
# 拉回的 xml 走 cryptohook.extract_sharedprefs_credentials（脱敏/形态闸/截断），不落全文。

#: shared_prefs 私有目录（<pkg> 占位）。
_SHARED_PREFS_DIR = "/data/data/{pkg}/shared_prefs"


def _pull_shared_prefs_credentials(
    package: str, out_path: Path, sink: list[dict[str, Any]], serial: str | None = None
) -> None:
    """adb 读取 ``/data/data/<pkg>/shared_prefs/*.xml``，抠登录态/凭据进 ``sink``。绝不抛。

    通道（依次尝试，任一成功即用）：``run-as <pkg>``（debuggable）/ ``su -c``（root）。
    抠出的凭据经 ``extract_sharedprefs_credentials`` 脱敏/形态闸/截断；高敏，不落全文。
    serial 透传给底层 adb（多设备消歧）；None 时不带 -s（向后兼容）。
    """
    try:
        prefs_dir = _SHARED_PREFS_DIR.format(pkg=package)
        xml_files = _list_shared_prefs_files(package, prefs_dir, serial)
        if not xml_files:
            logger.debug("[capture] 未列到 shared_prefs xml（无 root/非 debuggable/无凭据），跳过")
            return
        total = 0
        for fname in xml_files:
            xml_text = _read_shared_prefs_file(package, prefs_dir, fname, serial)
            if not xml_text:
                continue
            creds = cryptohook.extract_sharedprefs_credentials(xml_text, fname)
            for c in creds:
                sink.append(c)
            total += len(creds)
        if total:
            logger.info(
                "[capture] shared_prefs 抠出落地凭据 %d 条（含高敏个人信息，已脱敏截断，"
                "按办案合规留存处置）",
                total,
            )
    except Exception:  # noqa: BLE001 — 收尾凭据抽取绝不影响抓包/报告写出
        logger.exception("[capture] adb pull shared_prefs 抽凭据异常（已忽略）")


def _list_shared_prefs_files(
    package: str, prefs_dir: str, serial: str | None = None
) -> list[str]:
    """列出 shared_prefs 目录下的 *.xml 文件名（run-as 优先，回退 su）。失败 → []。"""
    for cmd in (
        ["shell", "run-as", package, "ls", prefs_dir],
        ["shell", "su", "-c", f"ls {prefs_dir}"],
    ):
        out = _adb_capture(cmd, serial)
        if out:
            names = [
                line.strip().rsplit("/", 1)[-1]
                for line in out.splitlines()
                if line.strip().lower().endswith(".xml")
            ]
            if names:
                return names
    return []


def _read_shared_prefs_file(
    package: str, prefs_dir: str, fname: str, serial: str | None = None
) -> str:
    """读取单个 shared_prefs xml 文本（run-as 优先，回退 su）。失败 → 空串。"""
    # 防御：文件名取自设备 ls 输出，钉死只接受简单文件名，杜绝路径穿越/命令注入。
    if not re.fullmatch(r"[A-Za-z0-9_.\-]+\.xml", fname):
        logger.debug("[capture] 跳过形态可疑的 prefs 文件名：%r", fname)
        return ""
    path = f"{prefs_dir}/{fname}"
    for cmd in (
        ["shell", "run-as", package, "cat", path],
        ["shell", "su", "-c", f"cat {path}"],
    ):
        out = _adb_capture(cmd, serial)
        if out and "<map" in out:
            return out
    return ""


# ---------------------------------------------------------------------------
# P2：收尾 adb pull 落地库（SQLCipher 导出的 *.plain.db + 普通 SQLite databases/*）
# ---------------------------------------------------------------------------
#
# 机制：SQLCipher hook 在设备 /data/local/tmp/apkscan_db/ 导出明文 *.plain.db（sqlcipher_events
# 记其设备路径）；收尾把这些 .plain.db **adb pull** 回 out/dump_db/，并把回拉后的本地路径回填进
# 事件的 plain_path（供 merge 用标准库 sqlite3 只读抠值）。同时尽力 pull 普通 SQLite 库
# （/data/data/<pkg>/databases/*.db）作为补充物证。pull 限大小/超时，失败只记日志、不影响抓包。
# 拉回的 .plain.db 是受害人高敏明文——SHA256 留存由 merge 落盘时算（取证完整性）。

#: app 私有 databases 目录（<pkg> 占位）。
_DATABASES_DIR = "/data/data/{pkg}/databases"
#: SQLCipher hook 在设备上导出明文库的临时目录（与 FRIDA_SQLCIPHER_HOOK_JS 的 _TMP_DIR 一致）。
_EXPORTED_DB_TMP = "/data/local/tmp/apkscan_db"
#: 单个 db 文件 adb pull 的大小上限（字节）：超大库多为缓存/媒体，跳过避免拖垮收尾。
_DB_PULL_MAX_BYTES = 200 * 1024 * 1024


def _pull_exported_databases(
    package: str,
    out_path: Path,
    sqlcipher_events: list[dict[str, Any]],
    serial: str | None = None,
) -> None:
    """adb pull SQLCipher 导出的 ``*.plain.db``（及普通 SQLite ``databases/*``）回 ``out/dump_db/``。

    回填每条 exported 事件的 ``plain_path`` 为回拉后的**本地**路径（供 merge 只读抠值）；
    设备上回拉不到的事件保持原样（merge 端按缺文件跳过）。绝不抛——单库失败/无 root/无 adb
    只记日志，不影响抓包与其它事件。serial 透传给底层 adb（多设备消歧）；None 不带 -s。
    """
    try:
        dump_dir = out_path / "dump_db"
        # 1) 回拉 SQLCipher hook 导出的明文 .plain.db（事件里记了设备路径）。
        pulled_any = False
        for ev in sqlcipher_events:
            if not isinstance(ev, dict):
                continue
            dev_plain = str(ev.get("plain_path") or "")
            if not dev_plain or not dev_plain.endswith(".plain.db"):
                continue
            local = _adb_pull_db(dev_plain, dump_dir, serial)
            if local:
                ev["plain_path"] = str(local)  # 回填本地路径供 merge
                pulled_any = True
        # 2) 补充：尽力把 app 私有 databases/*.db（普通 SQLite）一并拉回（best-effort）。
        _pull_plain_sqlite_databases(package, dump_dir, serial)
        # 3) 兜底：把导出临时目录里所有 .plain.db 拉回（事件可能漏记某些库）。
        _pull_exported_tmp_dir(dump_dir, serial)
        if pulled_any:
            logger.info(
                "[capture] 落地库已回拉至 %s（含受害人高敏明文，按办案合规留存处置）", dump_dir
            )
    except Exception:  # noqa: BLE001 — 收尾落地库回拉绝不影响抓包/报告写出
        logger.exception("[capture] adb pull 落地库异常（已忽略）")


def _adb_pull_db(device_path: str, dump_dir: Path, serial: str | None = None) -> Path | None:
    """把设备上单个 db 文件 adb pull 到 ``dump_dir``；超大/失败/无 adb → None（不抛）。

    防御：device_path 来自 Frida 事件（不完全可信），钉死只接受 .db/.plain.db 结尾的
    绝对路径，杜绝把任意设备文件拉回。pull 前用 ``ls -l`` 估大小，超 _DB_PULL_MAX_BYTES 跳过。
    serial 透传（多设备消歧）；None 不带 -s（向后兼容）。
    """
    if not re.fullmatch(r"/[A-Za-z0-9_./\-]+\.db", device_path):
        logger.debug("[capture] 跳过形态可疑的 db 设备路径：%r", device_path)
        return None
    # 大小闸（best-effort）：ls -l 第 5 列为字节数；拿不到不阻断（仍尝试 pull）。
    size = _adb_db_size(device_path, serial)
    if size is not None and size > _DB_PULL_MAX_BYTES:
        logger.info("[capture] 落地库超大（%d 字节）跳过回拉：%s", size, device_path)
        return None
    if not tools.adb_path():
        return None
    try:
        dump_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        logger.exception("[capture] 创建 dump_db 目录失败：%s", dump_dir)
        return None
    local = dump_dir / device_path.rsplit("/", 1)[-1]
    # ★codex 真机 BUG3：dump_dir 可能落在中文/OneDrive 目录，经 _adb_pull_to 的 ASCII 暂存中转规避
    #   Windows 下 adb 对非 ASCII 本地路径 pull 失败（超时/异常/非零退出均由 _adb 吞并记日志）。
    if not (_adb_pull_to(device_path, local, serial) and local.exists()):
        logger.debug("[capture] adb pull 落地库失败（无 root/不存在）：%s", device_path)
        return None
    return local


def _adb_db_size(device_path: str, serial: str | None = None) -> int | None:
    """best-effort 取设备上 db 文件字节数（ls -l 第 5 列）；拿不到 → None（不阻断 pull）。"""
    out = _adb_capture(["shell", "ls", "-l", device_path], serial)
    if not out:
        return None
    parts = out.split()
    for token in parts:
        if token.isdigit() and int(token) > 0:
            return int(token)
    return None


def _pull_plain_sqlite_databases(
    package: str, dump_dir: Path, serial: str | None = None
) -> None:
    """尽力把 app 私有 ``databases/*.db`` 普通 SQLite 库拉回（run-as 优先、回退 su）。

    普通（未加密）SQLite 库直接含可读物证；命中 run-as/su 通道即逐个 pull。无 root/非
    debuggable → 列不到、跳过（预期降级）。绝不抛。
    """
    db_dir = _DATABASES_DIR.format(pkg=package)
    names: list[str] = []
    for cmd in (
        ["shell", "run-as", package, "ls", db_dir],
        ["shell", "su", "-c", f"ls {db_dir}"],
    ):
        out = _adb_capture(cmd, serial)
        if out:
            names = [
                line.strip().rsplit("/", 1)[-1]
                for line in out.splitlines()
                if line.strip().lower().endswith(".db")
            ]
            if names:
                break
    for fname in names:
        if not re.fullmatch(r"[A-Za-z0-9_.\-]+\.db", fname):
            continue
        _adb_pull_db(f"{db_dir}/{fname}", dump_dir, serial)


def _pull_exported_tmp_dir(dump_dir: Path, serial: str | None = None) -> None:
    """兜底：把 SQLCipher 导出临时目录里所有 ``*.plain.db`` 拉回（事件漏记时的补网）。绝不抛。"""
    out = _adb_capture(["shell", "ls", _EXPORTED_DB_TMP], serial)
    if not out:
        return
    for line in out.splitlines():
        name = line.strip().rsplit("/", 1)[-1]
        if name.endswith(".plain.db") and re.fullmatch(r"[A-Za-z0-9_.\-]+\.plain\.db", name):
            _adb_pull_db(f"{_EXPORTED_DB_TMP}/{name}", dump_dir, serial)


# ---------------------------------------------------------------------------
# 计时 / 子进程清理
# ---------------------------------------------------------------------------


def _wait(duration: float) -> None:
    """采集等待。隔离为函数便于测试 monkeypatch（避免真睡 duration 秒）。"""
    time.sleep(max(0.0, duration))


def _monotonic() -> float:
    """单调时钟读数（秒）。隔离为函数便于测试 monkeypatch 预算超时，而无需真流逝时间。"""
    return time.monotonic()


def _budget_remaining(started_at: float, total_budget_sec: int) -> float:
    """据采集起点与总预算算剩余可用秒数（≤0 表示预算已耗尽）。用 _monotonic 便于测试。"""
    elapsed = _monotonic() - started_at
    return float(total_budget_sec) - elapsed


# ---------------------------------------------------------------------------
# ② frida-core 会话 liveness（治默认路径假成功：resume 后进程秒退却报成功）
# ---------------------------------------------------------------------------


def _frida_hook_status(session: Any) -> str:
    """frida hook 就绪状态（★#7，三态不混淆"已确认"与"未确认"）。JS 装完 hook 在 Java.perform
    内 send fxapk_hook_ready，落进 ``session._fxapk_hook_ready``：

    - ``"confirmed"``        收到 True —— hook 真装上；
    - ``"java-unavailable"`` 收到 False —— ART/Java 不可用或异常（反检测样本假就绪，据此诚实降级）；
    - ``"unconfirmed"``      会话存活但未收到信号 —— 抓包窗内 JS 没跑到/时序未到（不当已确认）；
    - ``"none"``             无会话。

    绝不抛。``hook_ready`` 布尔只在 ``"confirmed"`` 为真；``unconfirmed``/``java-unavailable`` 由
    调用方附告警，避免把"未确认"上报成"已确认"掩盖 hook 没装上。
    """
    if session is None:
        return "none"
    try:
        flag = getattr(session, "_fxapk_hook_ready", None)
        if isinstance(flag, dict):
            ready = flag.get("ready")
            if ready is True:
                return "confirmed"
            if ready is False:
                return "java-unavailable"
    except Exception:
        logger.debug("[capture] 读 hook_ready 标志异常", exc_info=True)
    return "unconfirmed"


def _frida_session_alive(session: Any) -> bool:
    """判定 frida-core 会话对应的 spawned 进程是否仍存活（resume 后未秒退）。

    优先看 ``session.is_detached``（frida 在目标进程退出/崩溃时把会话标 detached）；
    再尽力用会话的 device+pid 重新 ``enumerate_processes`` 确认 pid 仍在。任一确凿判死 →
    False；拿不到判据（测试替身/接口缺失）→ 保守判 True（不误降级正常会话）。绝不抛。

    真机上 detached / 进程消失才是"秒退"的确证；单测 monkeypatch 本函数直接给期望结果。
    """
    # TODO(real-device): 需真机验证后方可依赖——is_detached / enumerate_processes 只有真机可信。
    if session is None:
        return False
    # 1) 会话是否已 detached（进程崩溃/退出时 frida 置位）。
    is_detached = getattr(session, "is_detached", None)
    try:
        detached = is_detached() if callable(is_detached) else bool(is_detached)
    except Exception:
        logger.debug("[capture] 读取 session.is_detached 失败（忽略）", exc_info=True)
        detached = False
    if detached:
        logger.warning("[capture] frida-core 会话已 detached（spawned 进程疑似秒退）")
        return False
    # 2) 重新 enumerate 确认 spawned pid 仍在（拿不到设备/pid → 不据此判死）。
    pid = getattr(session, "pid", None)
    device_handle = getattr(session, "_fxapk_device", None)
    if isinstance(pid, int) and device_handle is not None:
        enum = getattr(device_handle, "enumerate_processes", None)
        if callable(enum):
            try:
                procs: Any = enum()
                live_pids = {getattr(p, "pid", None) for p in procs}
            except Exception:
                logger.debug("[capture] enumerate_processes 失败（忽略，不据此判死）", exc_info=True)
                return True
            if pid not in live_pids:
                logger.warning("[capture] spawned pid=%s 不在设备进程表（秒退）", pid)
                return False
    return True


# ---------------------------------------------------------------------------
# ① floor 自动化：设备侧带外 pcap 保底 runner（可注入/可 mock，真机部分封在此）
# ---------------------------------------------------------------------------
#
# floor_first 决策恒 True：反 frida / pinning / native 协议对带外 pcap 全无效化，起手先起、
# 收尾停，保证接入节点这条产出永远有——治"几小时零产出"。真机依赖（设备侧 tcpdump / PCAPdroid
# 或旁路抓包）封在 _start_floor_pcap/_stop_floor_pcap，单测一律 mock，不触真机/真子进程。


@dataclass
class _FloorPcap:
    """floor 带外 pcap 句柄：设备上 tcpdump 落盘路径 + 记录其 PID 的文件 + serial。

    tcpdump 以 ``nohup ... &`` 在设备后台运行（脱离 adb-shell 会话存活），PID 写进 ``pid_path``，
    收尾按 PID 精确 SIGINT（root）——比 ``pkill -INT tcpdump`` 更可靠（真机实测：非 root 的
    ``adb shell pkill`` 杀不动 root 的 tcpdump，报 Operation not permitted；且按名杀有误伤/漏杀风险）。
    """

    remote_path: str
    pid_path: str
    serial: str | None
    net_start: dict[str, str] | None = None  # 开抓时的出站网络态快照（漂移检测基线）。


# 网络态漂移检测（Codex fengzhixin 案抓包交接 §5.1）：开抓/停抓各快照一次出站网络态，跨网络/接口
# 漂移则本轮带外 pcap 掺入非目标网络流量、接入节点须按污染核。比对字段（两端都采到才参与判定）。
_NET_FIELDS = ("iface", "src", "gateway", "ssid")
_FLOOR_NETSTATE_NAME = "floor.netstate.json"  # 网络态留痕 + 漂移判定 sidecar（与 floor.pcap 同目录）。


def _snapshot_netstate(serial: str | None = None) -> dict[str, str]:
    """快照设备出站网络态：默认路由 iface/src/gateway（``ip route get``）+ 当前 SSID（best-effort）。

    非 root 即可取；取不到的字段留空。绝不抛（失败返回已采到的部分/空 dict，调用方据空判"未采集"）。
    """
    state: dict[str, str] = {}
    try:
        route = _adb_capture(["shell", "ip", "route", "get", "8.8.8.8"], serial) or ""
        for name, pat in (
            ("iface", r"\bdev\s+(\S+)"),
            ("src", r"\bsrc\s+(\S+)"),
            ("gateway", r"\bvia\s+(\S+)"),
        ):
            m = re.search(pat, route)
            if m:
                state[name] = m.group(1)
    except Exception:  # noqa: BLE001 - 网络态快照失败不影响抓包
        logger.debug("[capture] floor：ip route 网络态快照失败（忽略）", exc_info=True)
    try:
        wifi = _adb_capture(["shell", "dumpsys", "wifi"], serial) or ""
        m = re.search(r'SSID:\s*"?([^",\r\n]+)', wifi)
        if m:
            ssid = m.group(1).strip()
            if ssid and ssid.lower() not in ("<unknown ssid>", "unknown ssid", "none", "null"):
                state["ssid"] = ssid
    except Exception:  # noqa: BLE001 - SSID 取不到（新版 Android 限制）属预期降级
        logger.debug("[capture] floor：SSID 快照失败（忽略）", exc_info=True)
    return state


def _write_floor_netstate(
    out_path: Path, net_start: dict[str, str] | None, net_end: dict[str, str]
) -> bool:
    """写 floor 网络态留痕 + 漂移检测 sidecar（``floor.netstate.json``）；漂移则 WARNING。返回是否漂移。

    只比对两端**都采到**的字段（避免"未采集"误报漂移）。绝不抛。
    """
    import json

    from apkscan.core.atomic import atomic_write_text

    start = net_start or {}
    end = net_end or {}
    changed = (
        sorted(f for f in _NET_FIELDS if f in start and f in end and start[f] != end[f])
        if start and end
        else []
    )
    drifted = bool(changed)
    if not (start and end):
        note = "网络态未完整采集（设备/命令不支持时留空），本轮不做漂移判定。"
    elif drifted:
        note = (
            "开抓与停抓的出站网络态不一致（默认路由/源IP/SSID 变化）——本轮 floor pcap 可能跨网络/"
            "接口、掺入非目标网络流量；接入节点须按『网络漂移污染』核，勿直接当目标 App 真实链路。"
        )
    else:
        note = "开抓与停抓出站网络态一致（未见漂移）。"
    payload = {
        "drifted": drifted,
        "changed_fields": changed,
        "start": start,
        "end": end,
        "note": note,
    }
    try:
        atomic_write_text(
            out_path / _FLOOR_NETSTATE_NAME,
            json.dumps(payload, ensure_ascii=False, indent=2),
        )
    except OSError:
        logger.warning("[capture] floor：写网络态 sidecar 失败（忽略）", exc_info=True)
    if drifted:
        logger.warning(
            "[capture] floor：★网络漂移（%s）——开抓 %s → 停抓 %s；本轮带外 pcap 可能掺入其它网络流量，"
            "接入节点须按污染核（见 %s）。",
            changed, start, end, _FLOOR_NETSTATE_NAME,
        )
    return drifted


def _find_device_tcpdump(serial: str | None) -> str | None:
    """在设备上找可执行 tcpdump（root 上下文）；PATH 里有 → ``"tcpdump"``，已装的 → 其路径；无 → None。

    经 ``provision._adb_root_shell``（adbd-root 直执 / 多形态 su 兜底），不再用天真 ``su -c``。绝不抛。
    """
    if provision._adb_root_shell("command -v tcpdump >/dev/null 2>&1", serial):
        return "tcpdump"
    for p in _TCPDUMP_KNOWN_PATHS:
        if provision._adb_root_shell(f"test -x {p}", serial):
            return p
    return None


def _push_tcpdump(serial: str | None) -> str | None:
    """设备无 tcpdump 时，push 用户经 ``FXAPK_TCPDUMP_BIN`` 指定的二进制（须与设备 ABI 匹配）+ chmod。

    返回设备上可执行路径或 None（未配置 env / 文件不存在 / push / chmod 失败 → None，优雅降级）。绝不抛。
    仿 ``provision`` 的 frida-server 部署：``adb push`` + ``_adb_root_shell chmod 755``。
    """
    try:
        src = os.environ.get(_TCPDUMP_ENV)
        if not src or not Path(src).is_file():
            return None
        if not _adb(["push", src, _TCPDUMP_REMOTE], serial):
            logger.warning("[capture] floor：push tcpdump 失败（设备离线 / 路径不可写？）")
            return None
        if not provision._adb_root_shell(f"chmod 755 {_TCPDUMP_REMOTE}", serial):
            logger.warning("[capture] floor：chmod tcpdump 失败（设备未 root？）")
            return None
        logger.info("[capture] floor：已 push tcpdump → %s（来源 %s）", _TCPDUMP_REMOTE, src)
        return _TCPDUMP_REMOTE
    except Exception:
        logger.exception("[capture] floor：push tcpdump 异常（降级）")
        return None


def _start_floor_pcap(
    package: str, out_path: Path, serial: str | None = None
) -> _FloorPcap | None:
    """起设备侧带外 pcap 保底（tcpdump -w 到设备 tmp）。返回句柄；起不来 → None，绝不阻断抓包。

    带外 pcap 对反 frida / TLS pinning / native 自建协议全无效化——加固样本 frida/mitm 零产出
    时它仍拿得到接入节点 IP:port（穿透锚点）。真机依赖封在此，单测 mock 掉 provision/adb/spawn。
    root 与 su 语法复用 ``provision`` 的健壮处理（adbd-root / 多形态 su / 单引号包裹）。
    """
    # TODO(real-device): 接口名(-i any) 与部分机型 tcpdump/AF_PACKET 权限仍需真机对齐；无 tcpdump/root → 降级。
    try:
        if not tools.adb_path():
            return None
        tcpdump = _find_device_tcpdump(serial) or _push_tcpdump(serial)
        if not tcpdump:
            logger.info(
                "[capture] floor：设备无 tcpdump 且未提供可 push 的二进制（设 %s），带外 pcap 不可用（降级）",
                _TCPDUMP_ENV,
            )
            return None
        # 后台起 tcpdump（nohup + &，脱离 adb-shell 会话存活），PID 写文件供收尾精确 SIGINT。
        # -U 每包即刷盘（中断不丢缓冲）；-i any 抓全部接口；-s 0 抓全长。经 provision._adb_root_shell
        # 以 root 起（adbd-root 直执 / 多形态 su / 单引号包裹）。两处防"非 root 假成功"（codex review P1）:
        #   ① `[ "$(id -u)" = 0 ] || exit 1`：非 root 的 adb shell 路径直接失败退出，逼 _adb_root_shell
        #      改走 su（否则非 root shell 里 tcpdump 因无抓包权限秒退，但末尾 echo $! 仍 exit 0 → 假成功、
        #      floor 报已起却产出空 pcap）。
        #   ② 起后台后 `sleep 1; kill -0 <pid>`：验 tcpdump 仍活；死了（无 AF_PACKET/坏接口/无权限）→ 命令
        #      非零 → floor 判失败降级，绝不假成功。
        launch = (
            '[ "$(id -u)" = 0 ] || exit 1; '
            f"rm -f {_FLOOR_REMOTE_PCAP} {_FLOOR_PID_PATH}; "
            f"nohup {tcpdump} -i any -s 0 -U -w {_FLOOR_REMOTE_PCAP} >/dev/null 2>&1 & "
            f"echo $! > {_FLOOR_PID_PATH}; "
            f"sleep 1; kill -0 $(cat {_FLOOR_PID_PATH} 2>/dev/null) 2>/dev/null"
        )
        if not provision._adb_root_shell(launch, serial):
            logger.info("[capture] floor：tcpdump 未能以 root 起或起后即退（无 root / 无抓包权限），带外 pcap 不可用（降级）")
            return None
        logger.info("[capture] floor：设备侧 tcpdump 已起（%s → %s，后台+pidfile）", tcpdump, _FLOOR_REMOTE_PCAP)
        return _FloorPcap(
            remote_path=_FLOOR_REMOTE_PCAP,
            pid_path=_FLOOR_PID_PATH,
            serial=serial,
            net_start=_snapshot_netstate(serial),  # 开抓网络态基线（漂移检测）
        )
    except Exception:
        logger.exception("[capture] floor：起设备侧 tcpdump 失败（降级，不阻断）")
        return None


# 有效 pcap/pcapng 文件的起始 magic（判本地 floor.pcap 是否真拉回、可解析）。
_PCAP_MAGICS = (
    b"\xa1\xb2\xc3\xd4",
    b"\xa1\xb2\x3c\x4d",
    b"\xd4\xc3\xb2\xa1",
    b"\x4d\x3c\xb2\xa1",
    b"\x0a\x0d\x0d\x0a",
)


def _floor_pcap_valid(local: Path) -> bool:
    """本地 floor.pcap 是否有效——size ≥ pcap 头 + 起始 magic 认得（拉回 0 字节/半截不算数）。"""
    try:
        if not local.is_file() or local.stat().st_size < 24:
            return False
        with local.open("rb") as fh:
            return fh.read(4) in _PCAP_MAGICS
    except OSError:
        return False


def _stop_floor_pcap(handle: _FloorPcap, out_path: Path) -> Path | None:
    """停设备侧 tcpdump、adb pull 落盘 ``out/floor.pcap``、**仅在本地有效后**才清设备残留。绝不抛。

    ★证据防丢（P0-3）：pull 失败 / 本地为空 / magic 不认（不可解析）时【绝不删除远端 pcap】——
    保留在设备侧供手动重拉，只有本地文件 size 有效且 magic 认得后才 rm 远端 pcap。
    """
    try:
        serial = handle.serial
        # 1) 按 PID 精确 SIGINT（root）令 tcpdump flush 落盘并退出（-INT 留全 pcap 尾）；拿不到
        #    PID 再退 pkill 兜底。前置 `[ "$(id -u)" = 0 ] || exit 1` 守卫：非 root 的 adb shell 路径
        #    直接退出，逼 _adb_root_shell 走 su。
        provision._adb_root_shell(
            '[ "$(id -u)" = 0 ] || exit 1; '
            f"kill -INT $(cat {handle.pid_path} 2>/dev/null) 2>/dev/null || pkill -INT tcpdump",
            serial,
        )
        _wait(_FLOOR_FLUSH_GRACE)  # 给 flush + 落盘一点时间
        # 停抓后再快照网络态，与开抓基线比对 → 漂移则本轮 pcap 可能掺入非目标网络流量（落 sidecar）。
        _write_floor_netstate(out_path, handle.net_start, _snapshot_netstate(serial))
        # 2) adb pull 到**唯一临时文件**：要求 _adb 返回成功【且】临时文件 magic/size 有效——
        #    ★防旧证据误判（P0-3 复审）：若直接拉到固定 floor.pcap，本轮 pull 失败不覆盖旧文件时，
        #    旧 floor.pcap 会被当本轮成功、随后误删本轮远端证据。临时文件+校验通过才原子替换。
        local = out_path / _FLOOR_LOCAL_NAME
        tmp = out_path / (_FLOOR_LOCAL_NAME + ".tmp")
        try:
            tmp.unlink(missing_ok=True)  # 清掉上一轮可能残留的临时文件
        except OSError:
            logger.debug("[capture] floor：清临时文件失败（忽略）", exc_info=True)
        pulled_ok = _adb_pull_to(handle.remote_path, tmp, serial) and _floor_pcap_valid(tmp)
        if not pulled_ok:  # 首拉失败/无效 → chmod 644 兜底再拉（root tcpdump 写的文件常 0600 拉不动）
            provision._adb_root_shell(f"chmod 644 {handle.remote_path} 2>/dev/null", serial)
            pulled_ok = _adb_pull_to(handle.remote_path, tmp, serial) and _floor_pcap_valid(tmp)
        # 3) 本轮确实拉到有效文件才原子替换 floor.pcap + 清远端；否则保留远端供手动重拉（绝不删证据）。
        if pulled_ok:
            try:
                os.replace(tmp, local)
            except OSError:
                logger.exception("[capture] floor：替换 floor.pcap 失败（保留远端 pcap）")
                provision._adb_root_shell(f"rm -f {handle.pid_path}", serial)
                return None
            logger.info("[capture] floor：带外 pcap 已拉回 %s（%d 字节）", local, local.stat().st_size)
            provision._adb_root_shell(f"rm -f {handle.remote_path} {handle.pid_path}", serial)
            return local
        try:
            tmp.unlink(missing_ok=True)  # 失败的临时文件不留
        except OSError:
            logger.debug("[capture] floor：清失败临时文件失败（忽略）", exc_info=True)
        logger.warning(
            "[capture] floor：带外 pcap 拉回失败/为空/不可解析——【已保留设备侧 %s 未删除】，"
            "可手动 `adb -s %s pull %s`；仅清 pidfile。",
            handle.remote_path,
            serial,
            handle.remote_path,
        )
        provision._adb_root_shell(f"rm -f {handle.pid_path}", serial)  # 只清 pidfile，保留远端 pcap
        return None
    except Exception:
        logger.exception("[capture] floor：收尾设备侧 tcpdump 异常（忽略）")
        return None


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


# 运行时请求路径分类（供 network_attribution 的 origin_candidate：BUSINESS_API / LOGIN_ENDPOINT 信号）。
#   只认业务/登录两类、别的路径不采；源自运行时 mitm 请求（守"静态不产 eligible"不变量：静态报告无此数据）。
#   终结符含 `.`（接 /login.do、/api.php 动态脚本）+ `;`（Java ;jsessionid 路径参数）；不含 `?`（urlsplit path 无 query）。
#   词表含 REST 复数（users?/orders?）与常见登录别名（signup/sign_in/passport/oauth2）。
_RUNTIME_LOGIN_PATH_RE = re.compile(
    r"/(?:login|logon|signin|sign-in|sign_in|signup|sign-up|sign_up|auth|oauth2?|sso|passport|register)(?:[/.;]|$)",
    re.IGNORECASE)
_RUNTIME_BIZ_PATH_RE = re.compile(
    r"/(?:api|app|gateway|service|interface|mobile|client|users?|members?|accounts?|orders?|"
    r"pay(?:ments?)?|wallets?|recharge|withdraw(?:al)?|trade|funds?)(?:[/.;]|$)", re.IGNORECASE)
_MAX_RUNTIME_PATHS = 8  # 每 IP 每类保留的路径样本上限（证据用，防无限累积）
#: 静态资源扩展名——末段是这些的路径是前端资源（app.js/login.png/app.apk），不是业务/登录 API。
#: ★防落地页拉 SPA 包把防红/共享前端误判成 origin_candidate 源站（app/auth/sso/login 恰是最高频前端命名）。
_STATIC_ASSET_EXT = frozenset({
    "js", "mjs", "css", "map", "html", "htm", "png", "jpg", "jpeg", "gif", "webp", "ico", "svg",
    "woff", "woff2", "ttf", "otf", "eot", "apk", "ipa", "zip", "gz", "wasm", "mp4", "mp3", "avi",
    "mov", "webm", "pdf",
})


def _runtime_path_categories(url: object) -> tuple[str | None, str | None]:
    """从运行时请求 URL 的**路径部分**分类：返回 (业务路径样本, 登录路径样本)，命中该类才非 None。绝不抛。
    只看 path（urlsplit 已剥 host/query）；无 scheme 致 host 混入 path（不以 / 开头）→ 不采；
    末段是静态资源文件名 → 整条不采（防前端资源误判）。样本从命中处起截 80 字符（保证证据含命中段）。"""
    if not isinstance(url, str) or not url:
        return None, None
    try:
        from urllib.parse import urlsplit
        path = urlsplit(url).path or ""
    except (ValueError, TypeError):
        return None, None
    if not path.startswith("/"):  # 无 scheme → urlsplit 把 host 并进 path，非真路径
        return None, None
    last = path.rsplit("/", 1)[-1]
    if "." in last and last.rsplit(".", 1)[-1].lower() in _STATIC_ASSET_EXT:
        return None, None  # 静态资源（app.js/login.png/app.apk…）不是业务/登录 API
    def _sample(m: "re.Match[str] | None") -> str | None:
        # 正常留全路径前 80 字符；仅当命中段超出 80（超长路径）才以命中处开窗，保证样本含命中段。
        return None if m is None else (path[:80] if m.end() <= 80 else path[m.start():m.start() + 80])

    return _sample(_RUNTIME_BIZ_PATH_RE.search(path)), _sample(_RUNTIME_LOGIN_PATH_RE.search(path))


def _accum_runtime_path(runtime: dict, key: str, value: str) -> None:
    """把观测到的业务/登录路径样本去重累积进 runtime[key]（有序、去重、截上限）。绝不抛。"""
    lst = runtime.setdefault(key, [])
    if isinstance(lst, list) and value not in lst and len(lst) < _MAX_RUNTIME_PATHS:
        lst.append(value)


_MAX_EDGE_HOSTS = 32  # 每 IP 记录边缘行为的请求 host 上限（防共享边缘上无限累积）


def _accum_edge_host(runtime: dict, host: str, redirect: bool, cookie_challenge: bool) -> None:
    """按**请求 host** 记录边缘行为（重定向/挑战 cookie）进 runtime['edge_hosts'][host]={r,c}。★per-host 而非 per-IP：
    edge/cloaking 须**同一 host 同时**重定向+挑战才算（共享边缘上不同租户各出一个信号不得凑成 cloaking）。绝不抛。"""
    hosts = runtime.setdefault("edge_hosts", {})
    if not isinstance(hosts, dict):
        return
    key = str(host or "")[:120]
    if key not in hosts and len(hosts) >= _MAX_EDGE_HOSTS:
        return
    entry = hosts.setdefault(key, {"r": False, "c": False})
    if isinstance(entry, dict):
        if redirect:
            entry["r"] = True
        if cookie_challenge:
            entry["c"] = True


def _is_ip_literal(host: str) -> bool:
    """host 是否为 IP 字面量（IPv4/IPv6）。绝不抛。"""
    try:
        ipaddress.ip_address(host.strip())
        return True
    except (ValueError, TypeError):
        return False


_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})
#: 挑战**通过/清算**类 Cookie 名——只在 bot/WAF **挑战被解出后**经 Set-Cookie 下发（=确有挑战），
#: 是服务端主动挑战的行为证据（供 COOKIE_CHALLENGE）。★严格只取清算类：
#: - cf_clearance（Cloudflare 挑战通过）/ __jsl_clearance*（加速乐挑战通过）确经 Set-Cookie 下发；
#: - acw_sc__v2/v3（阿里挑战）由客户端 JS 算出、**不走 Set-Cookie**，头部检测见不到，保留仅为语义完整（近死条目）。
#: ★绝不取"每会话/每请求常设"的存在性 cookie（__cf_bm / acw_tc / aliyungf_tc / srv_id 等）——那只标"有该 WAF/LB"、
#: 非挑战，混入会把合法阿里云/CF 前置的普通流量误判成 cloaking（复审 P0，本工具目标生态大量在阿里云）。
_CHALLENGE_COOKIE_NAMES = frozenset({
    "cf_clearance", "__jsl_clearance", "__jsl_clearance_s", "__jsl_clearance_ss",
    "acw_sc__v2", "acw_sc__v3",
})


def _header_first(headers: object, name: str) -> str:
    """从 mitm/dict 响应头取单值（大小写不敏感）。缺/坏 → ""。绝不抛。"""
    try:
        get = getattr(headers, "get", None)
        if callable(get):
            v = get(name) or get(name.title()) or get(name.upper())
            return str(v) if v else ""
    except Exception:  # noqa: BLE001
        return ""
    return ""


def _header_all(headers: object, name: str) -> list[str]:
    """从 mitm/dict 响应头取多值（如多条 Set-Cookie）。缺/坏 → []。绝不抛。"""
    try:
        get_all = getattr(headers, "get_all", None)
        if callable(get_all):
            result = get_all(name)
            return [str(x) for x in result] if isinstance(result, (list, tuple)) else []
        v = _header_first(headers, name)
        return [v] if v else []
    except Exception:  # noqa: BLE001
        return []


def _response_edge_signals(flow: object, request_host: object) -> tuple[bool, bool]:
    """从运行时响应抽边缘行为信号：(跨 host 重定向, 挑战 cookie 下发)。供 edge_candidate / cloaking_edge_node。
    REDIRECT=3xx 且 Location 指向与请求 host 不同的 host；COOKIE_CHALLENGE=Set-Cookie 命中挑战/清算 cookie 名。绝不抛。"""
    resp = getattr(flow, "response", None)
    if resp is None:
        return False, False
    headers = getattr(resp, "headers", None)
    redirect = False
    status = getattr(resp, "status_code", None)
    if isinstance(status, int) and status in _REDIRECT_STATUS and headers is not None:
        loc_host = ""
        try:
            from urllib.parse import urlsplit
            loc = _header_first(headers, "location")
            # schemeless "Location: other.com/x"（不合规但浏览器接受）→ 补 // 再解析，否则 hostname=None 漏报跨 host。
            if loc and "://" not in loc and not loc.startswith(("/", "?", "#")):
                loc = "//" + loc
            loc_host = urlsplit(loc).hostname or ""
        except (ValueError, TypeError):
            loc_host = ""
        lh, rh = loc_host.lower(), str(request_host or "").lower()
        # ★同注册域（父子标签边界）豁免：www.foo.com↔foo.com、x.com→m.x.com 是良性规范化/移动版分流、非跨站前置；
        #   evil-foo.com→foo.com（'-'边界非'.'边界）仍算跨站。避免把良性 canonical 重定向误当 cloaking 行为。
        redirect = bool(lh) and lh != rh and not lh.endswith("." + rh) and not rh.endswith("." + lh)
    cookie_challenge = False
    if headers is not None:
        for sc in _header_all(headers, "set-cookie"):
            if sc.split("=", 1)[0].strip().lower() in _CHALLENGE_COOKIE_NAMES:
                cookie_challenge = True
                break
    return redirect, cookie_challenge


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
    url: object = None
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
        # ★裸 IP host（app 直连某 IP 无域名）不建 domain 端点——否则占用 IP 键、peername 分支复用它、
        #   永不建 kind="ip" 端点，路径/信号落到 domain 上被编译器(_ip_signal_features 只读 kind=="ip")丢弃。
        #   交下面 peername 分支按 ip kind 收录。
        if isinstance(host, str) and host and "." in host and host not in collector and not _is_ip_literal(host):
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
        if isinstance(ip, str) and ip:
            ep = collector.get(ip)
            if ep is None:
                note = f"{ip}（{host} 实连服务器 IP）" if isinstance(host, str) and host else f"{ip}（实连服务器 IP）"
                ep = Endpoint(
                    value=ip,
                    kind="ip",
                    evidences=[Evidence(source="runtime", location=location, snippet=note)],
                )
                collector[ip] = ep
            # 该 IP 观测到的业务/登录路径类别（跨同 IP 多条流累积）——供 origin_candidate 的 BUSINESS_API/LOGIN_ENDPOINT。
            biz, login = _runtime_path_categories(url)
            # 该 IP 的响应边缘行为（跨 host 重定向 / 挑战 cookie 下发）——按请求 host 记，供 edge/cloaking 判同 host 共现。
            redirect, cookie_challenge = _response_edge_signals(flow, host)
            if biz or login or redirect or cookie_challenge:
                rt = ep.enrichment.setdefault("runtime", {})
                if isinstance(rt, dict):
                    if biz:
                        _accum_runtime_path(rt, "business_api_paths", biz)
                    if login:
                        _accum_runtime_path(rt, "login_paths", login)
                    if redirect or cookie_challenge:
                        _accum_edge_host(rt, host or ip, redirect, cookie_challenge)


# ---------------------------------------------------------------------------
# 报文体提取（C5b：供 merge 对 {data,timestamp} 信封解密）
# ---------------------------------------------------------------------------

# 单条报文体保留上限（字节）：信封 data 是 base64 密文，通常不大；超大体多为上传/下载，跳过。
_MAX_BODY_BYTES = 256 * 1024

# ---------------------------------------------------------------------------
# Dead-Drop：明文配置响应保留通道（白名单 + 限大小 + 剔噪声 host）
# ---------------------------------------------------------------------------
#
# 二段式 dead-drop：app 先打伪装的「命令域名」（甚至像合规备案域名），回包**明文 JSON 配置**
# 里才带真实交易/后台域名（rest.apizza.net→acedealex.xyz 模式）。现有信封保留通道只留
# {data,timestamp} 密文，会把这类明文配置回包丢弃 → merge 层无米下锅。故新增**独立**的明文
# 响应保留通道：当请求 URL 命中 config 类路径**或**响应体里出现与请求 host 不同的新域名时，
# 保留该明文响应体（标 kind="config"，供 merge.resolve_dead_drop_c2 做回包关系分析浮出二级 C2）。
#
# 护栏：① **限大小**（≤_MAX_CONFIG_BODY_BYTES，避免大段明文落盘——隐私）；② **剔噪声 host**
# （请求 host 命中已知基础设施/CDN → 不留，避免把 CDN/SDK 配置回调当 dead-drop）；③ 不动现有
# 信封保留逻辑（信封流照旧保留、不带 kind 标记，向后兼容）。
#
# ★ 诚实标注：本通道依赖抓包窗口真触发了命令域名的回包（需人工操作 app 登录/拉配置）；
# launch-only 抓不到登录后接口 → 二级 C2 需配合人工操作触发命令域名回包（见 merge 模块标注）。

# 明文配置响应单独的保留上限（字节，32KB）：比信封更克制——明文配置含可读字段，限小防隐私外泄。
_MAX_CONFIG_BODY_BYTES = 32 * 1024

# 请求 URL 命中即视为「疑似配置下发接口」的路径关键词（小写子串匹配）。
_CONFIG_PATH_KEYWORDS: tuple[str, ...] = (
    "config", "webconfig", "geth5", "home", "init", "appconfig",
)

# 从明文响应体里抽 host 的正则（http(s) URL 的 host 段）；用于「回包出现新域名」判定。
_RESP_HOST_RE = re.compile(r"""https?://([A-Za-z0-9.\-]+)""", re.IGNORECASE)


def _url_hits_config_keyword(url: str) -> bool:
    """请求 URL（路径）是否命中 config 类白名单关键词（小写子串）。"""
    low = (url or "").lower()
    return any(kw in low for kw in _CONFIG_PATH_KEYWORDS)


def _response_new_domains(resp_body: str, request_host: str) -> list[str]:
    """从明文响应体抽出与请求 host 不同的新域名（http(s) URL 的 host）。

    用于 dead-drop 判定：命令域名回包里若带与自身不同的新域名 → 疑似二级下发。
    剔掉与请求 host 相同的自引用；其余去重保序返回（不在此判 infra，留给 merge 兜底）。
    """
    if not resp_body:
        return []
    req = (request_host or "").strip().lower().rstrip(".")
    found: list[str] = []
    seen: set[str] = set()
    for m in _RESP_HOST_RE.finditer(resp_body):
        host = m.group(1).strip().lower().rstrip(".")
        if not host or "." not in host or host == req:
            continue
        if host in seen:
            continue
        seen.add(host)
        found.append(host)
    return found


def _config_message_from_flow(flow: object) -> dict[str, Any] | None:
    """Dead-Drop 明文配置保留通道：命中条件时保留响应体（限大小 + 剔噪声 host）。

    保留条件（任一）：① 请求 URL 命中 config 类白名单路径；② 明文响应体里出现与请求 host
    不同的新域名。护栏：请求 host 命中已知基础设施/CDN → 不留；响应体超
    ``_MAX_CONFIG_BODY_BYTES`` → 不留。命中 → ``{"url","request_body","response_body",
    "kind":"config"}``；否则 None。**不在此判加密信封**（信封走原通道，避免与本通道重复保留）。
    """
    req = getattr(flow, "request", None)
    resp = getattr(flow, "response", None)
    url = ""
    request_host = ""
    if req is not None:
        url = getattr(req, "pretty_url", None) or getattr(req, "url", None) or ""
        request_host = getattr(req, "pretty_host", None) or getattr(req, "host", None) or ""

    resp_body = _body_text(resp)
    if not resp_body:
        return None

    # 护栏①：剔噪声 host——请求 host 是已知基础设施/CDN（infra），其配置回调非 dead-drop。
    if request_host and infra.is_known_infra(str(request_host)):
        return None

    hit_keyword = _url_hits_config_keyword(str(url))
    new_domains = _response_new_domains(resp_body, str(request_host))
    if not hit_keyword and not new_domains:
        return None

    # 护栏②：限大小——明文配置含可读字段，超 32KB 不留（隐私 + 防大段明文落盘）。
    if len(resp_body.encode("utf-8", errors="ignore")) > _MAX_CONFIG_BODY_BYTES:
        logger.info("[capture] 明文配置响应超 %d 字节，跳过保留：%s", _MAX_CONFIG_BODY_BYTES, url)
        return None

    flow_id, ts = _flow_meta(flow)
    return {
        "url": str(url),
        "request_body": _body_text(req),
        "response_body": resp_body,
        "kind": "config",
        "flow_id": flow_id,
        "ts": ts,
    }


def _parse_messages(flows_file: Path) -> list[dict[str, Any]]:
    """解析流文件，提取每条 HTTP 流的请求/响应体（文本），供解密信封 + dead-drop 浮出用。

    两条**独立**保留通道：① 现有信封通道——保留像 JSON 信封（文本含 "data" 且含
    "timestamp"）的报文体（供 merge 解密）；② 新增 dead-drop 明文配置通道——保留命中 config
    类路径**或**回包出现新域名的明文响应体（标 kind="config"，供 merge 浮出二级真实 C2）。
    避免把全部流量塞进 runtime_report.json。mitmproxy 包不可用 / 文件缺失 / 解析失败 → []（不抛）。

    返回 ``[{"url": str, "request_body": str, "response_body": str[, "kind": "config"]}]``。
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
                    continue  # 模拟器/系统自身流量不参与信封解密 / dead-drop
                # 通道①：现有信封保留（{data,timestamp} 密文）——优先，沿用旧契约不带 kind。
                msg = _message_from_flow(flow)
                if msg is not None:
                    messages.append(msg)
                    continue
                # 通道②：dead-drop 明文配置保留（config 路径 / 回包新域名；限大小 + 剔噪声 host）。
                cfg = _config_message_from_flow(flow)
                if cfg is not None:
                    messages.append(cfg)
    except Exception:
        logger.exception("[capture] 提取报文体失败：%s（信封解密将跳过）", flows_file)
        return messages

    logger.info("[capture] 从流文件提取信封报文 %d 条", len(messages))
    return messages


def _flow_meta(flow: object) -> tuple[str, float | None]:
    """取 mitmproxy flow 的 flow_id 与请求起始时间戳（epoch 秒），供通信会话时序重建。

    取不到 → ("", None)。flow_id=flow.id（mitmproxy 每条流唯一）；ts=request.timestamp_start。
    """
    flow_id = str(getattr(flow, "id", "") or "")
    ts: float | None = None
    req = getattr(flow, "request", None)
    raw = getattr(req, "timestamp_start", None) if req is not None else None
    if isinstance(raw, (int, float)):
        ts = float(raw)
    return flow_id, ts


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

    flow_id, ts = _flow_meta(flow)
    return {
        "url": str(url),
        "request_body": req_body,
        "response_body": resp_body,
        "flow_id": flow_id,
        "ts": ts,
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
    credential_events: list[dict[str, Any]] | None = None,
    sqlcipher_events: list[dict[str, Any]] | None = None,
    clipboard_events: list[dict[str, Any]] | None = None,
    remote_control_events: list[dict[str, Any]] | None = None,
    budget_exceeded: bool = False,
    capture_signals: dict[str, Any] | None = None,
    capture_capabilities: dict[str, Any] | None = None,
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
        # P0-4：结构化采集信号（proxy_set/floor_started/floor_pulled/hook_ready/mitm_bytes/
        # endpoint_total/degraded），供下游/人工判这次抓包哪路成了、哪路降级，杜绝"假成功"。
        "capture_signals": dict(capture_signals or {}),
        # A1-3：抓包能力计划快照（mode / floor 底座就绪否 / 缺哪些增强 / 明文最强可达层），
        # 供 merge 拷进 report.meta['capture_capabilities']——机器可读的"这次抓包能到哪、为何没明文"。
        "capture_capabilities": dict(capture_capabilities or {}),
        # ③ 时间盒：采集因超总预算被缩短/中止 → True（下游据此知端点/事件可能不全）。
        "budget_exceeded": budget_exceeded,
        "endpoint_total": len(endpoints),
        "endpoints": [report_json._to_jsonable(ep) for ep in endpoints],
        "messages": list(messages or []),
        "crypto_events": list(crypto_events or []),
        "jsbridge_events": list(jsbridge_events or []),
        "sensitive_api_events": list(sensitive_api_events or []),
        "antidetect_events": list(antidetect_events or []),
        "credential_events": list(credential_events or []),
        "sqlcipher_events": list(sqlcipher_events or []),
        # 第二波：剪贴板链上地址（★ 隐私护栏：只含抽出的地址，绝不含剪贴板全文）。
        "clipboard_events": list(clipboard_events or []),
        # 第二波（最后）：无障碍远控（目标银行/支付包名清单 + 远控手势 + 屏幕录制）。
        # ★ launch-only 抓不到，多数需引导式人工动态——多数情况下为空数组，属预期。
        "remote_control_events": list(remote_control_events or []),
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
