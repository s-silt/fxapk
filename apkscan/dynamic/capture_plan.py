"""apkscan.dynamic.capture_plan — 据静态报告给"针对该样本的抓包打法"（探针之外的方法决策树）。

读 ``report.json`` 的规避信号（加固 / endpoint 数 / 应用层加密配方 / 自建 IM / Telegram 改包），
按《反分析涉诈 App —— frida 探针之外的抓包/取证方法目录》的决策树，输出一串**有序、可执行、带
时间盒与停止门**的抓包步骤。核心约束（治"几小时零产出"）：

  ① floor 优先：先带外 pcap 保底拿接入节点，再谈明文——"零产出"不可接受；
  ② 每步带时间盒（≤Nmin）；
  ③ frida 秒退 fail-fast：秒退累计 ≤2~3 次就弃明文、退 floor，别死磕；
  ④ 明确停止门："够了就停"，不追求"全都要"。

授权/取证口径：个人安全研究 / 测试取证，仅对自有 / 授权样本；用"去 pin / 流量解析 / 离线解密
自有抓包"等取证措辞，不用攻击性表述。纯逻辑、**绝不抛**（坏 report 退化为只给铁律 + 起手式）。
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# 铁律永远第一条——这是治"几小时零产出"的行为约束。
_DIRECTIVES = (
    "【铁律·先读】抓包总预算 ≤60min，到点就交已有结果——『零产出』不可接受（带外 pcap 起手必有接入节点）。"
    "四条：① floor 优先（先带外保底再谈明文）；② 每步带时间盒；③ frida 秒退 fail-fast（累计 ≤2~3 次就弃明文、退 floor、别死磕）；"
    "④ 达停止门即停（见末条），不追求『全都要』。口径：个人安全研究 / 授权取证，措辞用『去 pin / 流量解析 / 离线解密自有抓包』。"
)
_BASELINE = (
    "【第0步·保底·≤15min】不碰 App 本体先带外抓一份 pcap：设备端 PCAPdroid（免 root VpnService、按 UID 只抓目标 App）"
    "或 网关 / 旁路由 tcpdump → `fxapk pcap-leads capture.pcap --into report.json`。"
    "✅停止门：拿到 ≥1 个接入节点 IP:port + SNI + DNS = 案子已有可调证产出（穿透真源站锚点）。"
    "反 frida / pinning / native 协议对带外 pcap 全无效化——所以它永远先跑、永远有结果。"
)
_PINNING = (
    "【TLS pinning·≤30min·达不到就退】mitm 起了但证书告警 / 0 流量：按存活率从高到低试，任一成即停："
    "① LSPosed + JustTrustMe / TrustMeAlready（**很多样本只测 frida、不测 Xposed，先试这个**）→ "
    "② 系统级 CA（Magisk 把 user CA 提到系统层）→ ③ 静态去 pin（`apk-mitm app.apk` 或改 network_security_config 重签）→ "
    "④ Florida frida unpin。全失败 → 退第0步带外 pcap 拿 IP / SNI，别再磕明文。"
)
_STOP = (
    "【停止门·够了就停，别空耗】任一达成即停，不追求『全都要』：① 接入节点 ≥1 → floor 达成、案子可调证；"
    "② 明文经 crypto_recipe 离线解 或 tls-keylog 解出 → 明文达成；③ frida 秒退累计 ≥3 或总时长超 60min → 弃明文、"
    "把 floor 结果回灌交活。**记住：带外 pcap 已保证你不会『零产出』，明文是上限不是底线。**"
)
_MERGE = (
    "【回灌串案】所有路线产出统一 `--into` 同一 report.json：`fxapk probe-leads probe.log --into report.json`（探针）/ "
    "`fxapk pcap-leads capture.pcap --into report.json`（pcap），合并进同一 report.leads 串案，"
    "并按台账末尾「取证完备性」诊断（定人 / 穿透 / 固证）补抓缺的轴。"
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
    """据 report（dict）规避信号产出抓包打法步骤（有序、带时间盒/停止门）。

    绝不抛；坏输入也至少给『铁律 + 起手式』。第一条恒为铁律、第二条恒为带外 pcap 保底。
    """
    steps: list[str] = [_DIRECTIVES, _BASELINE]
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

        # 零注入明文优先：配方已抠到 → 离线解，先于一切 frida 注入。
        if has_recipe:
            steps.append(
                "【应用层加密配方已抠到·零注入明文·首选】report.meta.crypto_recipe 含算法 / key / iv（配方）："
                "带外抓到的密文 body 直接**离线解密**（cipher-hook 校验 / 手动 AES）——这条不碰 frida、反检测无效化，"
                "对『明文 HTTP + 应用层加密』的涉诈 App 是最稳的明文路径，**优先于任何注入**。"
            )
        if packed:
            steps.append(
                "【加固壳·≤20min】静态端点不完整：先 `fxapk auto` / `fxapk repackage` 脱壳去壳重打包（对真实 DEX 抓包）。"
                "frida 易被反检测秒退 → 必配 anti-detection-hook(+native)；**秒退 ≤2 次就停 frida，换注入面一次**"
                "（LSPosed + TrustMeAlready 或 改名 / 改端口的 strongR-frida / Florida），还不行 → 弃明文、交第0步 floor。"
            )
        if zero_ep:
            steps.append(
                "【endpoint=0·≤20min】普通 HTTP / OkHttp 抓不到端点：多半 native 直发 / 自建协议（MTProto）/ QUIC。"
                "① 旁路 pcap + `fxapk pcap-leads` 拿接入节点 IP（首选、最稳，见第0步）；"
                "② tls-keylog 探针导主密钥 → Wireshark 离线解 TLS / QUIC；③ native-ssl / socket / netstat 探针抓 native 发包。"
                "明文拿不到不强求——接入节点 IP 已够调证。"
            )
        if telegram:
            steps.append(
                "【自建 IM / Telegram 改包】telegram-mtproto-hook（TLRPC 登录 / 聊天 / 接入节点）+ netstat-hook（/proc/net/tcp）"
                "+ native-ssl；需注入，秒退就退接入节点级——接入节点 IP:port 由旁路 pcap 兜底（pcap-leads）。"
            )

        steps.append(_PINNING)
        steps.append(_STOP)
        steps.append(_MERGE)
    except Exception:  # noqa: BLE001 - 出打法不该抛，坏 report 也至少给铁律 + 起手式
        logger.exception("[capture-plan] 生成打法异常，仅返回铁律 + 起手式")
    return steps
