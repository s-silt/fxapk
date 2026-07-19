"""card_merchant 分析器：从 dex 字符串与文本资源里识别**卡商 / 料商 / 开户供应链**线索。

卡商（贩卡 / 收 U / 承兑）、料商（贩卖"料"，即公民个人信息四件套 / U盾料 / 身份证料 /
对公料）是洗钱与开户供应链的上游节点。这类关键词在样本里命中率低、且单字（"卡""料"）
极易误报，故本分析器**定位为情报研判线索，不自动建议调证**：

判定与置信（recon 明确：此类信号 FP 高 → 宁缺毋滥、默认只"待核"）：
  - 默认：命中任一高区分关键词 → MEDIUM·待核（advice=待核），category=CARD_MERCHANT。
  - 命中**多个不同**高区分关键词 → notes 标「重点」，但**仍待核**（不升 advice / 不升置信）。
  - 绝不自动升「建议调证」——本类无直接调证对象，属线索研判用。

FP 收敛（硬性）：
  - 关键词务必高区分：用完整词 / 多字组合（"银行卡料""四件套""收U承兑"），
    绝不用"料""卡"单字这类泛词。
  - 文本资源命中前，先用 ``infra.classify_domain`` 把整段里出现的已知正规基础设施 host
    所在的命中排除（避免正规厂商域名 / SDK 文档误触发）。
  - 已知正规厂商 / 基础设施关键字（白名单）出现在同一命中行上下文时跳过该命中。

where_to_request 写「无直接调证对象（线索研判用）」——letters 据此跳过（这是预期）。
约束：只用 AnalysisContext 公开接口（dex_strings / list_files / read_file），规则数据化
（rules/card_merchant.yaml + load_rules），关键词为定长字面子串匹配（无正则、无 ReDoS），
单点异常 try/except + logging，不静默 pass、不炸 analyze，全程 type hints。
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from apkscan.analyzers._common import (
    TEXT_RESOURCE_PREFIXES,
    TEXT_RESOURCE_SUFFIXES,
    as_str_list,
    collect_dex_strings,
    is_text_resource,
    str_or_empty,
    truncate,
)
from apkscan.core import infra
from apkscan.core.models import AnalyzerResult, Confidence, Evidence, Lead, LeadCategory
from apkscan.core.registry import BaseAnalyzer, load_rules
from apkscan.core.textutil import host_from_url

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_RULES_NAME = "card_merchant"
_MAX_DEX_STRINGS = 200_000
# 单个文本资源读取上限（避免极端大文件拖慢 / 撑内存）。
_MAX_RESOURCE_BYTES = 4_000_000
# 文本资源扫描总字节预算（超出即停，防大样本拖慢）。
_MAX_TOTAL_RESOURCE_BYTES = 64_000_000
# 单条命中文本截取做证据的半径上限（够人工复核即可）。
_SNIPPET_LIMIT = 160

# 本类无直接调证对象 → letters 据此占位文案跳过（这是预期）。
_DEFAULT_WHERE = "无直接调证对象（线索研判用）"

# 关键词白名单：这些字面出现在命中行时，判为正规语境 / 误报，跳过该命中。
# （宁缺毋滥：例如"承兑"在正规票据/会计语境也用，但与卡商高区分词共现时仍可疑——
#  本白名单仅排除明显正规厂商 / 通用功能描述，不覆盖卡商组合词。）
_DEFAULT_WHITELIST: tuple[str, ...] = (
    "承兑汇票",  # 正规票据业务，非卡商"承兑"
    "银行卡管理",  # App 正规卡包 / 卡片管理功能
    "银行卡绑定",
    "银行卡号",
    "添加银行卡",
)


@dataclass
class _Keyword:
    """单条卡商 / 料商关键词（定长字面子串，无正则）。

    weak: 弱区分泛词（"跑分"），单独出现不计入，须与某个**高区分**词在同段文本共现。
    boundary: 英文混排 2 字组合（"收U""出U"），要求 ASCII 字母前后非字母数字（词边界），
              或与高区分词共现——避免英文长串里误拼。
    """

    text: str
    title: str
    weak: bool = False
    boundary: bool = False

    @property
    def strong(self) -> bool:
        """高区分词：既非弱区分、又无词边界限制 → 单独出现即可计入。"""
        return not self.weak and not self.boundary


@dataclass
class _Hit:
    """一次扫描累积的命中集合（整样本级，按关键词去重）。"""

    titles: set[str] = field(default_factory=set)
    keywords: set[str] = field(default_factory=set)
    sample_keyword: str = ""
    sample_source: str = "dex"
    sample_location: str = ""
    sample_snippet: str = ""


class CardMerchantAnalyzer(BaseAnalyzer):
    """识别卡商 / 料商 / 开户供应链关键词，产出 category=CARD_MERCHANT 的研判线索。"""

    name: str = "card_merchant"
    requires: list[str] = []  # 关键词文本通用（dex/H5），缺数据自然空跑

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        keywords, whitelist, evidence_to_obtain, where_to_request = self._load_rules()
        if not keywords:
            logger.info("[%s] 无可用卡商 / 料商关键词规则，跳过", self.name)
            result.meta["card_merchant_count"] = 0
            return result

        hit = _Hit()
        # 性能：合并关键词正则预筛——整段无任一关键词子串即跳过昂贵的逐词 find+白名单窗口判定。
        # 预筛是详细逻辑的超集（详细逻辑也以关键词子串为前置），跳过的串本就不会命中，行为不变。
        prefilter = re.compile("|".join(re.escape(k.text) for k in keywords))

        # 1) DEX 字符串（代码内硬编码文案）。
        _ok, dex_strings = collect_dex_strings(ctx, self.name, max_strings=_MAX_DEX_STRINGS)
        for s in dex_strings:
            if prefilter.search(s):
                self._scan_text(s, "dex", "dex_strings", keywords, whitelist, hit)

        # 2) 文本资源（H5 / JS / json / xml 里的文案）。
        self._scan_resources(ctx, keywords, whitelist, hit)

        if hit.keywords:
            result.leads.append(self._build_lead(hit, evidence_to_obtain, where_to_request))

        result.meta["card_merchant_count"] = len(result.leads)
        if result.leads:
            logger.info(
                "[%s] 命中卡商 / 料商关键词 %d 个：%s",
                self.name,
                len(hit.keywords),
                "、".join(sorted(hit.keywords)),
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
        keywords: list[_Keyword],
        whitelist: tuple[str, ...],
        hit: _Hit,
    ) -> None:
        """在一段文本里找卡商 / 料商关键词；命中累积到 hit（按关键词去重）。绝不抛。

        判定顺序（FP 收敛）：
          - 含已知正规基础设施 host 的 URL → 整段视为正规语境，跳过。
          - 每个关键词命中位置都要过**近邻窗口白名单**（命中词 snippet 半径内含白名单
            字面才算被白名单吞，而非整段 in——长文本里别处的"银行卡管理"不再吞真命中）。
          - **高区分**词单独命中即计入；**弱区分 / 词边界**词须满足下列其一才计入：
            (a) 同段文本里存在任一高区分词命中（共现）；
            (b) 词边界词自身满足词边界（U 前后非 ASCII 字母数字）。
        """
        if not text:
            return
        try:
            if self._has_known_infra_host(text):
                return

            # 第一遍：收集每个关键词在本段的"有效命中位置"（已过近邻窗口白名单）。
            valid: dict[str, _Keyword] = {}
            positions: dict[str, int] = {}
            has_strong = False
            for kw in keywords:
                idx = self._first_valid_index(text, kw, whitelist)
                if idx < 0:
                    continue
                valid[kw.text] = kw
                positions[kw.text] = idx
                if kw.strong:
                    has_strong = True

            # 第二遍：按规则决定哪些计入。
            for text_kw, kw in valid.items():
                if kw.strong:
                    accept = True
                elif kw.boundary:
                    # 词边界词：满足词边界 → 计入；否则须与高区分词共现。
                    accept = self._boundary_ok(text, kw.text, positions[text_kw]) or has_strong
                else:  # weak
                    accept = has_strong
                if not accept:
                    continue
                hit.keywords.add(kw.text)
                hit.titles.add(kw.title)
                if not hit.sample_keyword:
                    hit.sample_keyword = kw.text
                    hit.sample_source = source
                    hit.sample_location = location
                    hit.sample_snippet = truncate(text.strip(), _SNIPPET_LIMIT)
        except Exception:
            logger.exception("[%s] 扫描文本失败：%s", self.name, location)

    def _first_valid_index(
        self, text: str, kw: _Keyword, whitelist: tuple[str, ...]
    ) -> int:
        """返回 kw.text 在 text 中第一个**未被近邻窗口白名单吞掉**的命中下标；无则 -1。

        近邻窗口：以命中位置为中心、_SNIPPET_LIMIT 半径的子串；窗口内含任一白名单字面
        即认为该命中处于正规语境，继续找下一个命中位置（避免整段 in 误吞别处真命中）。
        """
        start = 0
        while True:
            idx = text.find(kw.text, start)
            if idx < 0:
                return -1
            if not self._is_whitelisted_context(
                text, idx, idx + len(kw.text), whitelist
            ):
                return idx
            start = idx + 1

    def _scan_resources(
        self,
        ctx: "AnalysisContext",
        keywords: list[_Keyword],
        whitelist: tuple[str, ...],
        hit: _Hit,
    ) -> None:
        """扫描 APK 内文本资源（H5/JS/json/xml）里的关键词。绝不抛。"""
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
            self._scan_text(text, "resource", path, keywords, whitelist, hit)

    @staticmethod
    def _is_whitelisted_context(
        text: str, start: int, end: int, whitelist: tuple[str, ...]
    ) -> bool:
        """命中位置 [start, end) 的**近邻窗口**内是否含白名单字面 → 判为正规语境。

        窗口 = 命中位置左右各 _SNIPPET_LIMIT 半径的子串。限定近邻而非整段：长文本
        （H5 整文件）里别处出现"银行卡管理"不应吞掉此处的"卡商一手"真命中。
        """
        lo = max(0, start - _SNIPPET_LIMIT)
        hi = min(len(text), end + _SNIPPET_LIMIT)
        window = text[lo:hi]
        return any(w and w in window for w in whitelist)

    @staticmethod
    def _boundary_ok(text: str, kw_text: str, idx: int) -> bool:
        """词边界判定（英文混排 2 字组合，如 "收U""出U"）：命中片段紧邻字符若是
        ASCII 字母 / 数字 → 视为英文长串里的误拼（如 ...callbackUrl...），不算词边界。

        仅检查命中片段两端的相邻单字符；中文字符 / 标点 / 空白 / 串首尾均算边界 OK。
        """
        prev_ch = text[idx - 1] if idx > 0 else ""
        nxt_i = idx + len(kw_text)
        next_ch = text[nxt_i] if nxt_i < len(text) else ""
        if prev_ch.isascii() and prev_ch.isalnum():
            return False
        if next_ch.isascii() and next_ch.isalnum():
            return False
        return True

    @staticmethod
    def _has_known_infra_host(text: str) -> bool:
        """文本里若含已知正规基础设施 host 的 URL → 视为正规语境，跳过该命中。

        仅当文本带 ``://`` 时尝试取 host，避免对纯文案误判；命中 infra → 跳过。
        """
        if "://" not in text:
            return False
        host = host_from_url(text)
        if not host:
            return False
        return infra.is_known_infra(host)

    # ------------------------------------------------------------------
    # 出线索
    # ------------------------------------------------------------------

    def _build_lead(
        self, hit: _Hit, evidence_to_obtain: list[str], where_to_request: str
    ) -> Lead:
        """卡商 / 料商线索：默认 MEDIUM·待核（FP 高、无直接调证对象，绝不自动建议调证）。

        命中多个不同高区分关键词 → notes 标「重点」，但置信 / advice 不变（仍待核）。
        """
        confidence = Confidence.MEDIUM
        advice = infra.ADVICE_REVIEW

        notes = "卡商 / 料商关键词：" + "、".join(sorted(hit.keywords))
        if len(hit.keywords) >= 2:
            notes = "【重点】" + notes + "（命中多个高区分关键词，建议结合资金 / 通联研判）"

        ev = Evidence(
            source=hit.sample_source,
            location=hit.sample_location,
            snippet=hit.sample_snippet or truncate(hit.sample_keyword, _SNIPPET_LIMIT),
        )
        return Lead(
            category=LeadCategory.CARD_MERCHANT,
            value="、".join(sorted(hit.keywords)),
            subject=None,
            where_to_request=where_to_request,
            evidence_to_obtain=list(evidence_to_obtain),
            confidence=confidence,
            source_refs=[ev],
            notes=notes,
            advice=advice,
        )

    # ------------------------------------------------------------------
    # 规则加载
    # ------------------------------------------------------------------

    def _load_rules(self) -> tuple[list[_Keyword], tuple[str, ...], list[str], str]:
        data = load_rules(_RULES_NAME)
        if not isinstance(data, dict):
            if data:
                logger.warning("[%s] 规则顶层应为 dict，实际 %s", self.name, type(data).__name__)
            return [], _DEFAULT_WHITELIST, [], _DEFAULT_WHERE

        evidence_to_obtain = as_str_list(data.get("evidence_to_obtain"))
        where_to_request = str_or_empty(data.get("where_to_request")) or _DEFAULT_WHERE

        wl = as_str_list(data.get("whitelist"))
        whitelist = tuple(wl) if wl else _DEFAULT_WHITELIST

        keywords: list[_Keyword] = []
        raw = data.get("patterns")
        if not isinstance(raw, list):
            logger.warning("[%s] patterns 字段应为 list，实际 %s", self.name, type(raw).__name__)
            return [], whitelist, evidence_to_obtain, where_to_request

        seen: set[str] = set()
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            text = str_or_empty(entry.get("keyword"))
            # 高区分硬性下限：长度 < 2 的泛词（"料""卡"）一律拒收，避免 FP 爆炸。
            if len(text) < 2:
                if text:
                    logger.warning("[%s] 跳过过短（易误报）关键词：%r", self.name, text)
                continue
            if text in seen:
                continue
            seen.add(text)
            keywords.append(
                _Keyword(
                    text=text,
                    title=str_or_empty(entry.get("title")) or text,
                    weak=bool(entry.get("weak")),
                    boundary=bool(entry.get("boundary")),
                )
            )
        return keywords, whitelist, evidence_to_obtain, where_to_request
