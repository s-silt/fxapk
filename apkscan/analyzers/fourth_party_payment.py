"""fourth_party_payment 分析器：识别**四方支付 / 跑分 / 代收代付 / 二清聚合支付平台**线索。

payment.py 只覆盖约 20 家主流第三方支付 SDK / 资金关键字；而四方支付（聚合在三方之上、
为商户做"代收代付 / 跑分 / D0-T0 结算"的灰产收单平台）往往没有标准 SDK 指纹，只在代码 /
H5 里露出**支付网关 URL + 中文跑分黑话**。本分析器补这块盲区：从 dex 字符串与文本资源里
抽**带 host 的支付网关 URL**，再叠加"跑分 / 代收代付 / 聚合支付 / 商户进件 / D0 结算"等
中文强关键词，按 host 聚合产出 FOURTH_PARTY_PAYMENT 线索，直击资金流重建。

判定（宁缺毋滥，FP 风险高的弱信号默认只「待核」）：
  - **强档**：同一 host 上既命中支付网关 URL（``/pay/notify``、``/api/pay``、含
    ``mch_id`` / ``merchantNo`` / ``payKey`` 配对的网关地址），又出现明确跑分 / 代收代付 /
    聚合支付中文关键词，且该 host 经 ``infra.classify_domain`` 研判为「建议调证」
    → HIGH·建议调证。
  - **弱档**：仅命中支付端点、或仅命中中文关键词（缺另一半）→ MEDIUM·待核。
  - **FP 收敛**：排除已知正规支付 SDK / 网关（支付宝 alipay、微信支付 wechat/tenpay、
    银联 unionpay、Stripe、PayPal、Adyen 等）——这些不是四方 / 跑分；中文关键词用组合 +
    词边界，避免"支付"单字泛滥。host 命中 ``infra`` 已知基础设施 / 私网亦排除。

约束：只用 AnalysisContext 公开接口（dex_strings / list_files / read_file），规则数据化
（rules/fourth_party_payment.yaml + load_rules），正则一律字符类 / 定长替换、无嵌套量词
（线性、无 ReDoS），单点异常 try/except + logging，不静默 pass、不炸 analyze，全程 type hints。
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

_RULES_NAME = "fourth_party_payment"
_MAX_DEX_STRINGS = 200_000
# 单个文本资源读取上限（避免极端大文件拖慢 / 撑内存；H5 bundle 通常远小于此）。
_MAX_RESOURCE_BYTES = 4_000_000
# 文本资源扫描总字节预算（dex 已覆盖代码内 URL；超出即停，防大样本拖慢）。
_MAX_TOTAL_RESOURCE_BYTES = 64_000_000
# snippet 截断长度。
_SNIPPET_MAX = 200
# 「就近共现」窗口：取 URL 出现位置前后各 ~200 字符内的文本来判该 host 的关键词，
# 避免整文件（H5/JS 单段）任意处一个关键词污染文件内所有 host → 误升强档。
_KEYWORD_WINDOW = 200

# 有界 URL 提取正则（字符类、无嵌套量词 → 线性、无 ReDoS）。
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]}\\]+", re.IGNORECASE)

# 已知正规支付 SDK / 网关品牌关键字（host 子串命中即不视为四方 / 跑分）。这些是合规
# 三方支付，调证落点是机构本身（payment.py 已覆盖），不属于本分析器的灰产收单范畴。
_LEGIT_PAYMENT_HOST_MARKERS: tuple[str, ...] = (
    "alipay", "alipayobjects", "mypay",  # 支付宝
    "wechat", "weixin", "tenpay", "wxpay", "tenpayapp",  # 微信支付
    "unionpay", "95516", "chinapay",  # 银联 / 中国银联
    "stripe", "paypal", "adyen", "braintree", "checkout.com",  # 海外
    "square", "razorpay", "payu", "worldpay",
    "applepay", "googlepay",
    "qcloud", "aliyun", "myqcloud", "aliyuncs",  # 云厂商（网关托管基础设施）
)

_DEFAULT_WHERE = "第四方 / 聚合支付平台 / 收单机构 / 支付公司"


@dataclass
class _EndpointPattern:
    """单条支付网关 URL 识别规则（host_regex 命中 host，path_regex 命中 path，
    param_regex 命中整段 URL 里的支付参数如 mch_id / payKey）。"""

    id: str
    title: str
    path_re: re.Pattern[str] | None = None
    host_re: re.Pattern[str] | None = None
    param_re: re.Pattern[str] | None = None


@dataclass
class _Hit:
    """单个支付网关 host 的命中累积。"""

    host: str
    host_advice: str
    endpoint_titles: set[str] = field(default_factory=set)
    keyword_titles: set[str] = field(default_factory=set)
    sample_url: str = ""
    sample_source: str = "dex"
    sample_location: str = ""

    @property
    def has_endpoint(self) -> bool:
        return bool(self.endpoint_titles)

    @property
    def has_keyword(self) -> bool:
        return bool(self.keyword_titles)


class FourthPartyPaymentAnalyzer(BaseAnalyzer):
    """识别四方支付 / 跑分平台，产出 category=FOURTH_PARTY_PAYMENT 的调证线索。"""

    name: str = "fourth_party_payment"
    requires: list[str] = []  # URL / 文本通用（dex/H5），缺数据自然空跑

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        endpoints, keywords, evidence_to_obtain, where_to_request = self._load_rules()
        if not endpoints and not keywords:
            logger.info("[%s] 无可用四方支付识别规则，跳过", self.name)
            result.meta["fourth_party_payment_count"] = 0
            return result

        hits: dict[str, _Hit] = {}

        # 1) DEX 字符串（代码内硬编码网关 URL / 中文黑话）。
        _ok, dex_strings = collect_dex_strings(ctx, self.name, max_strings=_MAX_DEX_STRINGS)
        for s in dex_strings:
            self._scan_text(s, "dex", "dex_strings", endpoints, keywords, hits)

        # 2) 文本资源（H5 / JS / json / xml 里的接口地址与文案）。
        self._scan_resources(ctx, endpoints, keywords, hits)

        for host, hit in sorted(hits.items()):
            try:
                lead = self._build_lead(hit, evidence_to_obtain, where_to_request)
            except Exception:
                # 单条 lead 构造异常不应炸整个 analyze：跳过本条，保其余与整体返回。
                logger.exception("[%s] 构造四方支付线索失败，跳过：%s", self.name, host)
                continue
            if lead is not None:
                result.leads.append(lead)

        result.meta["fourth_party_payment_count"] = len(result.leads)
        if result.leads:
            logger.info(
                "[%s] 识别四方 / 跑分支付平台 %d 个：%s",
                self.name,
                len(result.leads),
                "、".join(sorted(lead.value for lead in result.leads)),
            )
        return result

    # ------------------------------------------------------------------
    # 扫描
    # ------------------------------------------------------------------

    def _scan_text(
        self,
        text: str,
        source: str,
        location: str,
        endpoints: list[_EndpointPattern],
        keywords: list[re.Pattern[str]],
        hits: dict[str, _Hit],
    ) -> None:
        """从一段文本里抽支付网关 URL → 命中累积到 hits（按 host 去重）；
        关键词按「就近共现」判定——只取该 URL 出现位置前后 ~``_KEYWORD_WINDOW`` 字符
        （即同一行 / 相邻文本）内的跑分 / 代收代付中文关键词叠加给该 host，避免整文件
        （H5/JS 单段）任意处一个关键词污染文件内所有 host 而误升强档。绝不抛。

        dex 字符串通常一行一 URL，整段即窗口内，行为与逐行扫描一致。"""
        if not text or "://" not in text:
            return
        try:
            for m in _URL_RE.finditer(text):
                url = strip_url_tail(m.group(0))
                host = host_from_url(url)
                if not host or host_is_private(host):
                    continue
                if self._is_legit_payment_host(host):
                    continue  # 已知正规支付 SDK / 网关，非四方 / 跑分
                matched = self._match_endpoint(url, host, endpoints)
                keyword_titles = self._keywords_near(text, m.start(), m.end(), keywords)
                if matched is None and not keyword_titles:
                    continue
                advice, _reason = infra.classify_domain(host)
                if advice == infra.ADVICE_SKIP:
                    continue  # 已知第三方基础设施 / 库内置站点，非调证落点
                hit = hits.get(host)
                if hit is None:
                    hit = _Hit(
                        host=host,
                        host_advice=advice,
                        sample_url=url,
                        sample_source=source,
                        sample_location=location,
                    )
                    hits[host] = hit
                if matched is not None:
                    if not hit.has_endpoint:  # 升级为带端点证据的样本
                        hit.sample_url, hit.sample_source, hit.sample_location = url, source, location
                    hit.endpoint_titles.add(matched)
                hit.keyword_titles.update(keyword_titles)
        except Exception:
            logger.exception("[%s] 扫描文本支付网关失败：%s", self.name, location)

    def _scan_resources(
        self,
        ctx: "AnalysisContext",
        endpoints: list[_EndpointPattern],
        keywords: list[re.Pattern[str]],
        hits: dict[str, _Hit],
    ) -> None:
        """扫描 APK 内文本资源（H5/JS/json/xml）里的支付网关 URL 与中文黑话。绝不抛。"""
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
            self._scan_text(text, "resource", path, endpoints, keywords, hits)

    @staticmethod
    def _is_legit_payment_host(host: str) -> bool:
        """host 是否命中已知正规支付 SDK / 网关品牌关键字（合规三方，非四方 / 跑分）。"""
        h = host.lower()
        return any(marker in h for marker in _LEGIT_PAYMENT_HOST_MARKERS)

    @staticmethod
    def _match_keywords(text: str, keywords: list[re.Pattern[str]]) -> set[str]:
        """返回 text 命中的跑分 / 代收代付中文关键词正则名集合（pattern 文档串作标题）。"""
        titles: set[str] = set()
        for kw in keywords:
            if kw.search(text):
                titles.add(kw.pattern)
        return titles

    @classmethod
    def _keywords_near(
        cls,
        text: str,
        url_start: int,
        url_end: int,
        keywords: list[re.Pattern[str]],
    ) -> set[str]:
        """「就近共现」：只在 URL 命中区间前后各 ``_KEYWORD_WINDOW`` 字符的窗口内匹配关键词。

        多 host 的整文件（H5/JS）里，仅靠文件别处存在某关键词不再能把本 host 升强档；
        dex 字符串一行一 URL，窗口覆盖整行，行为不变。"""
        lo = max(0, url_start - _KEYWORD_WINDOW)
        hi = min(len(text), url_end + _KEYWORD_WINDOW)
        return cls._match_keywords(text[lo:hi], keywords)

    @staticmethod
    def _path_of(url: str) -> str:
        """取 URL 中 host 之后的 path（含起始 ``/``）；无 path → 空串。"""
        after = url.split("://", 1)[-1]
        slash = after.find("/")
        return after[slash:] if slash >= 0 else ""

    def _match_endpoint(
        self, url: str, host: str, endpoints: list[_EndpointPattern]
    ) -> str | None:
        """返回首条命中的支付网关 URL 规则标题；都不命中 → None。"""
        path = self._path_of(url)
        for p in endpoints:
            if p.host_re is not None and p.host_re.search(host):
                return p.title
            if p.path_re is not None and path and p.path_re.search(path):
                return p.title
            if p.param_re is not None and p.param_re.search(url):
                return p.title
        return None

    # ------------------------------------------------------------------
    # 出线索
    # ------------------------------------------------------------------

    def _build_lead(
        self, hit: _Hit, evidence_to_obtain: list[str], where_to_request: str
    ) -> Lead | None:
        """强档（端点 + 关键字 + host 建议调证）→ HIGH·建议调证；其余 → MEDIUM·待核。

        仅在同段文本里既无端点又无关键词时不会进到这里（_scan_text 已过滤）；
        防御性兜底：两类信号皆空 → 不出线索。
        """
        if not hit.has_endpoint and not hit.has_keyword:
            return None
        strong = hit.has_endpoint and hit.has_keyword and hit.host_advice == infra.ADVICE_INVESTIGATE
        if strong:
            confidence = Confidence.HIGH
            advice = infra.ADVICE_INVESTIGATE
        else:
            confidence = Confidence.MEDIUM
            advice = infra.ADVICE_REVIEW
        ev = Evidence(
            source=hit.sample_source,
            location=hit.sample_location,
            snippet=truncate(hit.sample_url, _SNIPPET_MAX),
        )
        return Lead(
            category=LeadCategory.FOURTH_PARTY_PAYMENT,
            value=hit.host,
            subject=None,
            where_to_request=where_to_request,
            evidence_to_obtain=list(evidence_to_obtain),
            confidence=confidence,
            source_refs=[ev],
            notes=self._notes(hit),
            advice=advice,
        )

    @staticmethod
    def _notes(hit: _Hit) -> str:
        parts: list[str] = []
        if hit.endpoint_titles:
            parts.append("支付网关特征：" + "、".join(sorted(hit.endpoint_titles)))
        if hit.keyword_titles:
            parts.append("跑分 / 代收代付关键词：" + "、".join(sorted(hit.keyword_titles)))
        if hit.has_endpoint and hit.has_keyword:
            parts.append("网关 URL 与跑分黑话共现，疑似四方 / 聚合收单平台。")
        else:
            parts.append("仅单类信号（端点或关键词），需人工核四方 / 跑分属性。")
        return "；".join(parts)

    # ------------------------------------------------------------------
    # 规则加载
    # ------------------------------------------------------------------

    def _load_rules(
        self,
    ) -> tuple[list[_EndpointPattern], list[re.Pattern[str]], list[str], str]:
        data = load_rules(_RULES_NAME)
        if not isinstance(data, dict):
            if data:
                logger.warning("[%s] 规则顶层应为 dict，实际 %s", self.name, type(data).__name__)
            return [], [], [], _DEFAULT_WHERE

        evidence_to_obtain = as_str_list(data.get("evidence_to_obtain"))
        where_to_request = str_or_empty(data.get("where_to_request")) or _DEFAULT_WHERE

        endpoints = self._parse_endpoints(data.get("endpoint_patterns"))
        keywords = self._parse_keywords(data.get("keyword_patterns"))
        return endpoints, keywords, evidence_to_obtain, where_to_request

    def _parse_endpoints(self, raw: object) -> list[_EndpointPattern]:
        if not isinstance(raw, list):
            if raw is not None:
                logger.warning(
                    "[%s] endpoint_patterns 字段应为 list，实际 %s", self.name, type(raw).__name__
                )
            return []
        out: list[_EndpointPattern] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            pid = entry.get("id")
            if not isinstance(pid, str) or not pid.strip():
                logger.warning("[%s] 跳过缺 id 的支付端点规则：%r", self.name, entry)
                continue
            path_re = self._compile(entry.get("path_regex"), pid)
            host_re = self._compile(entry.get("host_regex"), pid)
            param_re = self._compile(entry.get("param_regex"), pid)
            if path_re is None and host_re is None and param_re is None:
                logger.warning(
                    "[%s] 跳过无 path/host/param_regex 的支付端点规则：%s", self.name, pid
                )
                continue
            out.append(
                _EndpointPattern(
                    id=pid.strip(),
                    title=str_or_empty(entry.get("title")) or pid.strip(),
                    path_re=path_re,
                    host_re=host_re,
                    param_re=param_re,
                )
            )
        return out

    def _parse_keywords(self, raw: object) -> list[re.Pattern[str]]:
        if not isinstance(raw, list):
            if raw is not None:
                logger.warning(
                    "[%s] keyword_patterns 字段应为 list，实际 %s", self.name, type(raw).__name__
                )
            return []
        out: list[re.Pattern[str]] = []
        for entry in raw:
            pat = entry if isinstance(entry, str) else None
            if pat is None and isinstance(entry, dict):
                pat = entry.get("regex") if isinstance(entry.get("regex"), str) else None
            if not isinstance(pat, str) or not pat.strip():
                logger.warning("[%s] 跳过无效关键词规则：%r", self.name, entry)
                continue
            compiled = self._compile(pat, pat)
            if compiled is not None:
                out.append(compiled)
        return out

    def _compile(self, pattern: object, pid: str) -> re.Pattern[str] | None:
        if not isinstance(pattern, str) or not pattern.strip():
            return None
        try:
            return re.compile(pattern, re.IGNORECASE)
        except re.error:
            logger.warning("[%s] 规则正则编译失败，跳过：%s", self.name, pid)
            return None
