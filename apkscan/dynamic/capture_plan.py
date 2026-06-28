"""apkscan.dynamic.capture_plan — 据静态报告给"针对该样本的抓包打法"（探针之外的方法决策树）。

读 ``report.json`` 的规避信号（加固 / endpoint 数 / 应用层加密配方 / 自建 IM / Telegram 改包），
按《反分析涉诈 App —— frida 探针之外的抓包/取证方法目录》的决策树，输出一串**有序、可执行**的
抓包步骤建议（起手式带外 pcap 保底 → 按规避类型选 frida unpinning / 静态去 pin / pcap-leads /
专项探针）。纯逻辑、**绝不抛**（坏 report 退化为只给起手式）。
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_BASELINE = (
    "【起手式·保底】不碰 App 本体先带外抓一份 pcap：设备端 PCAPdroid（免 root VpnService、按 UID 只抓目标 App）"
    "或 网关/旁路由 tcpdump → `fxapk pcap-leads capture.pcap --into report.json`，保底拿 接入节点 IP:port + SNI + DNS"
    "（解不开密文也能办案，穿透真源站锚点）。反 frida / pinning / native 协议对它都无效化。"
)
_PINNING = (
    "【TLS pinning】mitm 起了但证书指纹告警 / 0 流量：系统级 CA（Magisk MagiskTrustUserCerts 把 user CA 提到系统层）"
    "或 静态去 pin（`apk-mitm app.apk` 或 apktool 改 network_security_config 加 user trust-anchors 重签）；"
    "都解不开就退回旁路 pcap 拿 IP/SNI。"
)
_MERGE = (
    "【回灌串案】所有路线产出统一回灌：`fxapk probe-leads probe.log --into report.json`（探针）/ "
    "`fxapk pcap-leads capture.pcap --into report.json`（pcap），合并进同一 report.leads 串案，"
    "并按台账末尾「取证完备性」诊断（定人/穿透/固证）补抓缺的轴。"
)


def _as_list(v: Any) -> list:
    return v if isinstance(v, list) else []


def _as_dict(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def _is_packed(findings: list, leads: list) -> bool:
    for f in findings:
        if isinstance(f, dict) and str(f.get("id")) == "PACK-DETECTED":
            return True
    for lead in leads:
        if isinstance(lead, dict) and str(lead.get("category")) == "PACKER":
            return True
    return False


def _has_lead_category(leads: list, category: str) -> bool:
    return any(isinstance(lead, dict) and str(lead.get("category")) == category for lead in leads)


def _telegram_hint(leads: list, findings: list) -> bool:
    needles = ("telegram", "mtproto", "tgnet", "tlrpc")
    for item in (*leads, *findings):
        if not isinstance(item, dict):
            continue
        blob = " ".join(
            str(item.get(k, "")) for k in ("value", "notes", "title", "description", "subject")
        ).lower()
        if any(n in blob for n in needles):
            return True
    return False


def plan_capture(report: Any) -> list[str]:
    """据 report（dict）规避信号产出抓包打法步骤（有序）。绝不抛；坏输入只给起手式。"""
    steps: list[str] = [_BASELINE]
    try:
        rep = _as_dict(report)
        findings = _as_list(rep.get("findings"))
        leads = _as_list(rep.get("leads"))
        endpoints = _as_list(rep.get("endpoints"))
        meta = _as_dict(rep.get("meta"))

        ep_count = sum(1 for e in endpoints if isinstance(e, dict))
        packed = _is_packed(findings, leads)
        zero_ep = ep_count == 0
        has_recipe = bool(meta.get("crypto_recipe") or meta.get("runtime_crypto_recipe"))
        telegram = _telegram_hint(leads, findings) or _has_lead_category(leads, "SELF_HOSTED_IM")

        if packed:
            steps.append(
                "【加固壳】静态端点不完整：先 `fxapk auto` / `fxapk repackage` 脱壳去壳重打包（对真实 DEX 抓包）；"
                "frida 易被反检测秒退 → 必配 anti-detection-hook(+native)，仍秒退则换注入面（LSPosed + TrustMeAlready）"
                "或改名/改端口的 strongR-frida / Florida。"
            )
        if zero_ep:
            steps.append(
                "【endpoint=0】普通 HTTP/OkHttp 抓不到端点：多半 native 直发 / 自建协议（MTProto）/ QUIC。"
                "① 旁路 pcap + `fxapk pcap-leads` 拿接入节点 IP（首选、最稳）；"
                "② tls-keylog 探针导主密钥 → Wireshark 离线解 TLS/QUIC；"
                "③ native-ssl / socket / netstat 探针抓 native 发包与接入节点。"
            )
        if telegram:
            steps.append(
                "【自建 IM / Telegram 改包】走 telegram-mtproto-hook（TLRPC 登录/聊天/接入节点）+ netstat-hook（/proc/net/tcp）"
                "+ native-ssl；接入节点 IP:port 也可由旁路 pcap 兜底（pcap-leads）。"
            )
        if has_recipe:
            steps.append(
                "【应用层加密配方已抠到】report.meta.crypto_recipe 含算法/key/iv：抓到的密文流量可**离线解密**；"
                "运行期配 cipher-hook 校验，objstore/coldstart 下发配置正文用它还原真后端。"
            )

        steps.append(_PINNING)
        steps.append(_MERGE)
    except Exception:  # noqa: BLE001 - 出打法不该抛，坏 report 也至少给起手式
        logger.exception("[capture-plan] 生成打法异常，仅返回起手式")
    return steps
