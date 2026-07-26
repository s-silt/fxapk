"""自带域名解析（DoH / HTTPDNS）检测——**取证可见性信号**，不是罪状。

为什么需要：App 若自己走 DoH（DNS over HTTPS）或 HTTPDNS，域名解析就**不经过系统 DNS**。
后果对动态取证是直接的：

  - PCAP 里只看得到一条到解析器的 TLS 连接，**看不到它查了哪些域名**；
  - 设备/网关的 DNS 日志同样为空；
  - 于是「DNS 日志里没有 X 域名」不能推出「该 App 没访问过 X」——又一个「抓不到≠没有」。

本模块只回答「这个 App 的域名解析我们还看不看得见」，**不指名工具、不产端点、不作可疑判定**。
实测语料 24 个样本中 9 个含 DoH 线格式标记（``application/dns-message``），属常见能力而非异常，
故命中只作**取证方法提示**，严重度不拔高。

分档（按证据硬度，不是按可疑度）：
  - protocol：RFC 8484 的线格式 MIME / 标准 ``/dns-query`` 路径 —— App **自己实现 DoH 客户端**；
  - sdk：商用 HTTPDNS SDK（合法且常见，但同样绕开系统 DNS）；
  - resolver-hint：仅出现公共解析器主机名 —— 最弱，单独不作判据（可能只是配置默认值）。

纯静态、有界、绝不抛。
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from apkscan.analyzers._common import collect_dex_strings, collect_so_paths
from apkscan.core.models import AnalyzerResult, Confidence, Evidence, Finding, Severity
from apkscan.core.registry import BaseAnalyzer

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_MAX_DEX_STRINGS = 200_000

#: 单个 .so 读入上限 / 全部 .so 累计上限（有界读，防超大库或多库累计撑爆内存）。
_MAX_SO_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_SO_BYTES = 256 * 1024 * 1024

#: 档位一：DoH 协议自身的标记——命中即说明 App 内含 DoH 客户端实现（RFC 8484）。
_PROTOCOL_MARKERS: tuple[str, ...] = (
    "application/dns-message",   # RFC 8484 线格式 MIME，最硬的一条
    "application/dns-json",      # Google/Cloudflare 的 JSON 变体
    "/dns-query",                # RFC 8484 规定的标准路径
)

#: 档位二：商用 HTTPDNS SDK（合法常见，但绕开系统 DNS，对取证可见性影响相同）。
_SDK_MARKERS: tuple[str, ...] = (
    "httpdns.aliyuncs.com",
    "resolvers-cn.httpdns.aliyuncs.com",
    "httpdns.c.163.com",
    "sdk.httpdns.qq.com",
)

#: 档位三：公共 DoH 解析器主机名——最弱，**不单独触发**（仅作佐证与展示）。
_RESOLVER_MARKERS: tuple[str, ...] = (
    "dns.alidns.com", "doh.pub", "doh.360.cn", "dns.google",
    "cloudflare-dns.com", "dns.quad9.net", "doh.opendns.com",
)

_MAX_EVIDENCE = 5


def assess_markers(haystack: str) -> dict[str, list[str]]:
    """在一坨小写文本里找各档标记（纯函数，便于单测）。"""
    low = haystack.lower()
    return {
        "protocol": [m for m in _PROTOCOL_MARKERS if m in low],
        "sdk": [m for m in _SDK_MARKERS if m in low],
        "resolver": [m for m in _RESOLVER_MARKERS if m in low],
    }


class DnsBypassAnalyzer(BaseAnalyzer):
    """检出 App 自带 DoH / HTTPDNS 解析 → 提示 DNS 层抓包看不到其域名解析。"""

    name: str = "dns_bypass"
    requires: list[str] = ["apk"]  # Android 专属（需扫 .so）

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        parts: list[str] = []
        try:
            _ok, dex_strings = collect_dex_strings(ctx, self.name, max_strings=_MAX_DEX_STRINGS)
            parts.append(" ".join(dex_strings))
        except Exception:
            logger.exception("[%s] 收集 dex 字符串失败，仅据 .so 判定", self.name)
        so_hits = self._scan_native(ctx)

        hits = assess_markers(" ".join(parts))
        for tier, found in so_hits.items():          # 合并 native 侧命中（去重保序）
            for m in found:
                if m not in hits[tier]:
                    hits[tier].append(m)
        result.meta["dns_bypass"] = hits
        if not (hits["protocol"] or hits["sdk"]):
            # 仅解析器主机名不作判据：可能只是配置里的默认值，单独命中不足以说明自带解析。
            logger.info("[%s] 未见自带 DoH/HTTPDNS 解析证据", self.name)
            return result

        result.findings.append(self._build_finding(hits))
        return result

    def _scan_native(self, ctx: "AnalysisContext") -> dict[str, list[str]]:
        """在 App 自有 ``.so`` 里**全量**搜这批固定标记（有界读，逐库直接按字节找）。

        ★为什么不用共享的 ``collect_app_so_string_blobs``：它按头/中/尾窗口**采样**，30MB 的 .so
        里位于中段的标记会漏。而本模块产出的是**可见性信号**——漏检等于错误地告诉办案人
        「DNS 是可见的」，比误报更糟。标记都是固定 ASCII 串，直接按字节子串搜即可，
        既不必抽 ASCII 串也更省：单库读入受 ``_MAX_SO_BYTES`` 限、累计受 ``_MAX_TOTAL_SO_BYTES`` 限，
        且读前先查声明大小（不把超大库膨胀进内存）。绝不抛。
        """
        out: dict[str, list[str]] = {"protocol": [], "sdk": [], "resolver": []}
        needles = {
            "protocol": [(m, m.encode()) for m in _PROTOCOL_MARKERS],
            "sdk": [(m, m.encode()) for m in _SDK_MARKERS],
            "resolver": [(m, m.encode()) for m in _RESOLVER_MARKERS],
        }
        budget = _MAX_TOTAL_SO_BYTES
        try:
            paths = collect_so_paths(ctx, self.name)
        except Exception:
            logger.exception("[%s] 枚举 .so 失败，仅据 dex 判定", self.name)
            return out
        for path in paths:
            if budget <= 0:
                logger.info("[%s] .so 扫描累计达上限，剩余库未扫——本次未命中不等于样本无此能力", self.name)
                break
            try:
                declared = ctx.declared_size(path)
            except Exception:
                logger.debug("[%s] 查声明大小失败：%s", self.name, path, exc_info=True)
                declared = None
            if declared is not None and declared > _MAX_SO_BYTES:
                continue                      # 超大库跳过：不读、不膨胀
            try:
                data = ctx.read_file(path)
            except Exception:
                logger.debug("[%s] 读 .so 失败，跳过：%s", self.name, path, exc_info=True)
                continue
            if not data or len(data) > _MAX_SO_BYTES:
                continue
            budget -= len(data)
            low = data.lower()
            for tier, items in needles.items():
                for text, raw in items:
                    if raw in low and text not in out[tier]:
                        out[tier].append(text)
        return out

    def _build_finding(self, hits: dict[str, list[str]]) -> Finding:
        kind = "自实现 DoH 客户端" if hits["protocol"] else "商用 HTTPDNS SDK"
        shown = "、".join((hits["protocol"] + hits["sdk"] + hits["resolver"])[:6])
        return Finding(
            id="APP-MANAGED-DNS-RESOLUTION",
            title=f"App 自带域名解析（{kind}）——DNS 层抓包看不到其解析",
            severity=Severity.LOW,      # 能力/可见性信号，非可疑度；语料 24 样本中 9 个具备
            confidence=Confidence.MEDIUM,
            category="anti_analysis",
            description=(
                f"样本内含自带域名解析的证据（{shown}）。这类实现把 DNS 查询封进 HTTPS 发给指定解析器，"
                "**不经过系统 DNS**。\n"
                "★ 对取证的直接后果：PCAP 里只看得到一条到解析器的 TLS 连接，**看不到它查了哪些域名**；"
                "设备/网关的 DNS 日志同样为空。因此「DNS 日志里没有某域名」**不能**推出「该 App 没访问过它」。\n"
                "★ 这是能力信号不是罪状：商用 HTTPDNS SDK 合法且常见（用于防劫持/加速），"
                "实测语料中约三分之一样本具备该能力。"
            ),
            recommendation=(
                "别据 DNS 日志判定该 App 的访问范围。真实访问域名改从这些地方取："
                "① TLS ClientHello 的 SNI（DoH 只隐藏解析、不隐藏后续连接的 SNI）；"
                "② 应用层明文（TLS keylog 解密后的 HTTP Host 头）；"
                "③ 直接看它连了哪些 IP，再对 IP 做被动归属。"
            ),
            evidences=[
                Evidence(source="dex", location="dns-resolution", snippet=m)
                for m in (hits["protocol"] + hits["sdk"])[:_MAX_EVIDENCE]
            ],
        )
