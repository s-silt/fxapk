"""self_hosted_im 分析器：识别**自建 IM / C2 控制信道**线索（MQTT/WebSocket/XMPP/原生 socket）。

自建即时通讯 / 命令控制信道（自架 MQTT broker、WebSocket 网关、XMPP 服务器、裸 TCP socket
服务端）是诈骗团伙的「落地强连边」——成员之间、后台与端之间的实时指挥就走这条信道，服务器
归属与会话日志一旦调取即可还原团伙组织关系与指挥链。本分析器从 dex 字符串与文本资源里抽
**带 host 的控制信道 URL**，并扫 dex 里的 **IM 库包名指纹**，按两类特征识别：

  - 强证据：硬编码 ``ws:// / wss:// / mqtt:// / mqtts:// / xmpp:// / tcp:// / ssl://`` 服务器地址，
    host 经 ``infra.classify_domain`` 研判为「建议调证」（非公共 / 非 SDK / 非私网）→ HIGH·建议调证。
  - 弱证据：仅命中 IM 库包名指纹（``org.jivesoftware.smack`` [XMPP] / ``org.eclipse.paho`` [MQTT] /
    ``io.netty`` [自建 socket] / matrix sdk 等）而无硬编码非白名单地址 → MEDIUM·待核。

FP 收敛（**关键，宁缺毋滥**）：正常 App 大量使用 MQTT / WebSocket 做推送 / 客服 / 实时刷新，
故必须排除公共 IM / 推送 / MQTT 基础设施（getui / jpush / umeng / firebase /
mqtt.eclipseprojects.io / hivemq public / 阿里云 mqtt 等）——这部分由 ``infra.classify_domain``
统一排除；私网 / 内网 host 直接跳过。仅当「硬编码非白名单服务器地址」才升 HIGH·建议调证；
仅有库指纹（无地址）只给「待核」，绝不轻易升「建议调证」。

约束（与 admin_panel 一致）：只用 AnalysisContext 公开接口（dex_strings / list_files /
read_file），规则数据化（rules/self_hosted_im.yaml + load_rules），URL / 信道正则字符类有界
（无灾难性回溯），库指纹按 token 词边界匹配，单点异常 try/except + logging，不静默 pass、
不炸 analyze，全程 type hints。
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from apkscan.analyzers._common import (
    TEXT_RESOURCE_PREFIXES,
    TEXT_RESOURCE_SUFFIXES,
    collect_dex_strings,
    is_text_resource,
    str_or_empty,
    truncate,
)
from apkscan.core import infra
from apkscan.core.models import AnalyzerResult, Confidence, Evidence, Lead, LeadCategory
from apkscan.core.registry import BaseAnalyzer, load_rules
from apkscan.core.textutil import as_str_list, host_from_url, host_is_private, strip_url_tail

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_RULES_NAME = "self_hosted_im"
_MAX_DEX_STRINGS = 200_000
# 单个文本资源读取上限（避免极端大文件拖慢 / 撑内存）。
_MAX_RESOURCE_BYTES = 4_000_000
# 文本资源扫描总字节预算（超出即停，防大样本拖慢）。
_MAX_TOTAL_RESOURCE_BYTES = 64_000_000

# 有界控制信道 URL 提取正则（字符类、无嵌套量词 → 线性、无 ReDoS）。
# 仅匹配非 http(s) 的实时信道协议；http(s) 已由 admin_panel / endpoints 覆盖。
_CHANNEL_RE = re.compile(
    r"(?:wss?|mqtts?|xmpp|stomp|amqp|tcp|ssl|tls)://[^\s\"'<>)\]}\\]+",
    re.IGNORECASE,
)

_DEFAULT_WHERE = "服务器云厂商 / IDC"


@dataclass
class _Fingerprint:
    """单条 IM 库包名指纹（dex token 词边界匹配，弱证据）。"""

    id: str
    title: str
    tokens: list[str] = field(default_factory=list)


@dataclass
class _Hit:
    """单个控制信道 host 的命中累积（强证据：硬编码非白名单服务器地址）。"""

    host: str
    host_advice: str
    scheme: str
    sample_url: str = ""
    sample_source: str = "dex"
    sample_location: str = ""


def _is_ident_char(c: str) -> bool:
    return c.isalnum() or c == "_"


def _token_match(token: str, s: str) -> bool:
    """token 是否在 s 里按标识符边界出现（前后字符非 [A-Za-z0-9_]）。

    与 sensitive_api._token_match 同口径：避免 ``io.netty`` 误命中
    ``io.nettyextra``，同时仍命中包名前缀 / 类描述符里的真实引用。token 自身含非标识符
    字符（如 ``org.eclipse.paho``）时点号天然提供边界。线性扫描，无 ReDoS。
    """
    n = len(token)
    if not n:
        return False
    start = 0
    while True:
        idx = s.find(token, start)
        if idx < 0:
            return False
        before = s[idx - 1] if idx > 0 else ""
        after = s[idx + n] if idx + n < len(s) else ""
        if not _is_ident_char(before) and not _is_ident_char(after):
            return True
        start = idx + 1


class SelfHostedImAnalyzer(BaseAnalyzer):
    """识别自建 IM / C2 控制信道，产出 category=SELF_HOSTED_IM 的调证线索。"""

    name: str = "self_hosted_im"
    # 信道 URL 走文本（dex/H5/资源），库指纹走 dex 字符串：APK/IPA 皆可，缺数据自然空跑。
    requires: list[str] = []

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        fingerprints, evidence_to_obtain, where_to_request = self._load_rules()

        hits: dict[str, _Hit] = {}

        # 1) DEX 字符串：硬编码控制信道 URL + IM 库包名指纹。
        _ok, dex_strings = collect_dex_strings(ctx, self.name, max_strings=_MAX_DEX_STRINGS)
        for s in dex_strings:
            self._scan_channel(s, "dex", "dex_strings", hits)

        # 2) 文本资源（H5/JS/json/xml 里的信道地址）。
        self._scan_resources(ctx, hits)

        # 3) IM 库指纹（弱证据，仅 dex 包名）。
        matched_fps = self._match_fingerprints(fingerprints, dex_strings)

        # 强证据：每个非白名单信道 host 一条 HIGH/待核 线索。
        for _host, hit in sorted(hits.items()):
            result.leads.append(
                self._build_channel_lead(hit, evidence_to_obtain, where_to_request)
            )

        # 弱证据：仅当**无任何**硬编码强证据 host 时，才把库指纹作为「待核」线索产出
        # （有硬编码地址时，地址才是落点；库指纹仅佐证，不再单独出弱线索，避免重复噪音）。
        if not hits and matched_fps:
            result.leads.append(
                self._build_fingerprint_lead(matched_fps, evidence_to_obtain, where_to_request)
            )

        result.meta["self_hosted_im_channel_count"] = len(hits)
        result.meta["self_hosted_im_fingerprints"] = [fp.id for fp in matched_fps]
        if result.leads:
            logger.info(
                "[%s] 识别自建 IM/C2 信道线索 %d 条（信道 host：%s；库指纹：%s）",
                self.name,
                len(result.leads),
                "、".join(sorted(hits)) or "无",
                "、".join(fp.id for fp in matched_fps) or "无",
            )
        return result

    # ------------------------------------------------------------------
    # 扫描：硬编码控制信道 URL（强证据）
    # ------------------------------------------------------------------

    def _scan_channel(
        self,
        text: str,
        source: str,
        location: str,
        hits: dict[str, _Hit],
    ) -> None:
        """从一段文本抽控制信道 URL → 命中非白名单 host 则累积（按 host 去重）。绝不抛。"""
        if not text or "://" not in text:
            return
        try:
            for m in _CHANNEL_RE.finditer(text):
                raw = strip_url_tail(m.group(0))
                scheme = raw.split("://", 1)[0].lower()
                host = host_from_url(raw)
                if not host or host_is_private(host):
                    continue  # 私网 / 内网信道无对外调证落点
                advice, _reason = infra.classify_domain(host)
                if advice == infra.ADVICE_SKIP:
                    continue  # 公共 IM/推送/MQTT 基础设施（getui/firebase/eclipse 等），非落点
                hit = hits.get(host)
                if hit is None:
                    hits[host] = _Hit(
                        host=host,
                        host_advice=advice,
                        scheme=scheme,
                        sample_url=raw,
                        sample_source=source,
                        sample_location=location,
                    )
        except Exception:
            logger.exception("[%s] 扫描控制信道 URL 失败：%s", self.name, location)

    def _scan_resources(self, ctx: "AnalysisContext", hits: dict[str, _Hit]) -> None:
        """扫描 APK 内文本资源（H5/JS/json/xml）里的控制信道 URL。绝不抛。"""
        try:
            files = [p for p in ctx.list_files() if isinstance(p, str)]
        except Exception:
            logger.exception("[%s] 读取 list_files 失败", self.name)
            return

        total = 0
        for path in files:
            if total >= _MAX_TOTAL_RESOURCE_BYTES:
                logger.warning("[%s] 文本资源扫描达总预算，停止", self.name)
                break
            if not is_text_resource(
                path, suffixes=TEXT_RESOURCE_SUFFIXES, prefixes=TEXT_RESOURCE_PREFIXES
            ):
                continue
            try:
                data = ctx.read_file(path)
            except Exception:
                logger.exception("[%s] 读取资源失败：%s", self.name, path)
                continue
            if not data or len(data) > _MAX_RESOURCE_BYTES:
                continue
            total += len(data)
            text = (
                data.decode("utf-8", errors="replace")
                if isinstance(data, (bytes, bytearray))
                else str(data)
            )
            self._scan_channel(text, "resource", path, hits)

    # ------------------------------------------------------------------
    # 扫描：IM 库包名指纹（弱证据）
    # ------------------------------------------------------------------

    def _match_fingerprints(
        self, fingerprints: list[_Fingerprint], dex_strings: list[str]
    ) -> list[_Fingerprint]:
        """返回命中的库指纹（任一 token 按词边界出现在任一 dex 字符串）。绝不抛。"""
        matched: list[_Fingerprint] = []
        for fp in fingerprints:
            try:
                if any(
                    _token_match(tok, s) for tok in fp.tokens for s in dex_strings
                ):
                    matched.append(fp)
            except Exception:
                logger.exception("[%s] 库指纹匹配失败，跳过：%s", self.name, fp.id)
        return matched

    # ------------------------------------------------------------------
    # 出线索
    # ------------------------------------------------------------------

    def _build_channel_lead(
        self, hit: _Hit, evidence_to_obtain: list[str], where_to_request: str
    ) -> Lead:
        """强证据线索：硬编码非白名单信道 host。host 研判为建议调证 → HIGH·建议调证。"""
        if hit.host_advice == infra.ADVICE_INVESTIGATE:
            confidence = Confidence.HIGH
            advice = infra.ADVICE_INVESTIGATE
        else:
            confidence = Confidence.MEDIUM
            advice = infra.ADVICE_REVIEW
        ev = Evidence(
            source=hit.sample_source,
            location=hit.sample_location,
            snippet=truncate(hit.sample_url, 160),
        )
        return Lead(
            category=LeadCategory.SELF_HOSTED_IM,
            value=hit.host,
            subject=None,
            where_to_request=where_to_request,
            evidence_to_obtain=list(evidence_to_obtain),
            confidence=confidence,
            source_refs=[ev],
            notes=f"自建控制信道：硬编码 {hit.scheme}:// 服务器地址",
            advice=advice,
        )

    def _build_fingerprint_lead(
        self,
        matched: list[_Fingerprint],
        evidence_to_obtain: list[str],
        where_to_request: str,
    ) -> Lead:
        """弱证据线索：仅命中 IM 库指纹、无硬编码非白名单地址 → MEDIUM·待核（FP 风险高，绝不升建议调证）。"""
        titles = sorted({fp.title for fp in matched})
        ev = Evidence(
            source="dex",
            location="dex_strings",
            snippet="IM 库指纹：" + "、".join(titles),
        )
        return Lead(
            category=LeadCategory.SELF_HOSTED_IM,
            value="自建 IM / C2 信道（库指纹，待核服务器地址）",
            subject=None,
            where_to_request=where_to_request,
            evidence_to_obtain=list(evidence_to_obtain),
            confidence=Confidence.MEDIUM,
            source_refs=[ev],
            notes=(
                "仅命中 IM / 消息库指纹（" + "、".join(titles) + "），"
                "未抽到硬编码非白名单服务器地址；需 jadx / runtime 复核是否自建信道"
            ),
            advice=infra.ADVICE_REVIEW,
        )

    # ------------------------------------------------------------------
    # 规则加载
    # ------------------------------------------------------------------

    def _load_rules(self) -> tuple[list[_Fingerprint], list[str], str]:
        data = load_rules(_RULES_NAME)
        if not isinstance(data, dict):
            if data:
                logger.warning("[%s] 规则顶层应为 dict，实际 %s", self.name, type(data).__name__)
            return [], [], _DEFAULT_WHERE

        evidence_to_obtain = as_str_list(data.get("evidence_to_obtain"))
        where_to_request = str_or_empty(data.get("where_to_request")) or _DEFAULT_WHERE

        fingerprints: list[_Fingerprint] = []
        raw = data.get("fingerprints")
        if raw is not None and not isinstance(raw, list):
            logger.warning(
                "[%s] fingerprints 字段应为 list，实际 %s", self.name, type(raw).__name__
            )
            raw = []
        for entry in raw or []:
            if not isinstance(entry, dict):
                continue
            fid = entry.get("id")
            if not isinstance(fid, str) or not fid.strip():
                logger.warning("[%s] 跳过缺 id 的库指纹条目：%r", self.name, entry)
                continue
            tokens = as_str_list(entry.get("tokens"))
            if not tokens:
                logger.warning("[%s] 跳过无 tokens 的库指纹条目：%s", self.name, fid)
                continue
            fingerprints.append(
                _Fingerprint(
                    id=fid.strip(),
                    title=str_or_empty(entry.get("title")) or fid.strip(),
                    tokens=tokens,
                )
            )
        return fingerprints, evidence_to_obtain, where_to_request
