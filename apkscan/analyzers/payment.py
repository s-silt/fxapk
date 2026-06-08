"""支付 / 资金线索分析器 — 涉诈调证核心（资金流）。

职责（见设计文档 §4 payment 行 + rules/payment.yaml 头注释）：
- 读 apkscan/rules/payment.yaml，分两类匹配：
    * sdks     ：第三方 / 聚合支付 SDK 指纹（dex 类前缀 / so 库名 / 资源文件三路），
                 命中 → 支付机构作为资金流调证目标。
    * keywords ：收款 / 资金相关字符串特征（商户号 mch_id / 收款码 / 提现 / USDT /
                 钱包地址 等，正则或子串），命中 → 资金线索。
- 每条命中 → Lead(category=PAYMENT, subject=支付机构/待核, where_to_request,
  evidence_to_obtain=可调取证据, confidence, source_refs=Evidence)。
- meta["payment_sdks"] / meta["payment_keywords"] 记录命中清单，供报告/调试。

置信度：
- sdk     ：rule.confidence 显式指定优先；否则命中 so/资源/≥2 类特征 → HIGH，仅单 dex → MEDIUM。
- keyword ：strong=true → HIGH；否则 MEDIUM。

约束：
- 只依赖 AnalysisContext 公开接口，禁止 import androguard。
- 单点解析异常 try/except + logging，不让单条规则 / 单个数据源炸掉整个 analyze；不静默 pass。
- 全程 type hints。
"""

from __future__ import annotations

import logging
import posixpath
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypeGuard

from apkscan.core.models import (
    AnalyzerResult,
    Confidence,
    Evidence,
    Lead,
    LeadCategory,
)
from apkscan.core.registry import BaseAnalyzer, load_rules

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_RULES_NAME = "payment"

# 命中后 Lead 默认可调取证据（规则 meta 缺失时兜底）。
_DEFAULT_EVIDENCE_TO_OBTAIN: tuple[str, ...] = (
    "商户号实名主体（营业执照 / 法人 / 联系人）",
    "交易流水 / 收款对账单",
    "结算银行账户（开户行 / 账号 / 户名）",
    "提现记录 / 资金划转记录",
)
_DEFAULT_WHERE = "对应第三方支付 / 清算机构与结算开户银行"
_DEFAULT_SUBJECT = "待核（疑似收款主体）"

# DEX 字符串扫描上限：样本字符串池可能很大，避免极端情况扫描过久。
_MAX_DEX_STRINGS = 200_000
# 文本资源扫描：限制读取的文件数与单文件大小，避免大体积资源拖慢。
_MAX_RESOURCE_FILES = 2_000
_MAX_RESOURCE_BYTES = 512 * 1024
# 单条 Lead 最多保留的证据条数（防止刷屏）。
_MAX_EVIDENCES = 6
_SNIPPET_MAX = 160

# 视为文本、值得做关键字扫描的资源后缀 / 路径前缀。
_TEXT_SUFFIXES: tuple[str, ...] = (
    ".json", ".xml", ".txt", ".properties", ".js", ".html", ".htm",
    ".cfg", ".conf", ".ini", ".csv", ".kv", ".plist",
)
_TEXT_PREFIXES: tuple[str, ...] = ("assets/", "res/raw/", "res/xml/")


@dataclass
class _SdkRule:
    name: str
    vendor: str
    category: str = ""
    where_to_request: str = ""
    dex_prefixes: list[str] = field(default_factory=list)
    so_names: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    evidence_to_obtain: list[str] = field(default_factory=list)
    confidence: str = ""  # 显式强制 high/medium/low；空=按命中强度判定
    note: str = ""


@dataclass
class _KeywordRule:
    name: str
    category: str = ""
    strong: bool = False
    patterns: list[str] = field(default_factory=list)
    subject: str = ""
    where_to_request: str = ""
    evidence_to_obtain: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class _SdkHit:
    rule: _SdkRule
    evidences: list[Evidence] = field(default_factory=list)
    matched_features: list[str] = field(default_factory=list)
    matched_kinds: set[str] = field(default_factory=set)

    def confidence(self) -> Confidence:
        forced = _parse_confidence(self.rule.confidence)
        if forced is not None:
            return forced
        if "so" in self.matched_kinds or "file" in self.matched_kinds:
            return Confidence.HIGH
        if len(self.matched_kinds) >= 2:
            return Confidence.HIGH
        return Confidence.MEDIUM


@dataclass
class _KeywordHit:
    rule: _KeywordRule
    evidences: list[Evidence] = field(default_factory=list)
    matched_patterns: list[str] = field(default_factory=list)

    def confidence(self) -> Confidence:
        return Confidence.HIGH if self.rule.strong else Confidence.MEDIUM


class PaymentAnalyzer(BaseAnalyzer):
    """识别第三方/聚合支付 SDK 与收款/资金特征，产出 PAYMENT 调证线索。"""

    name: str = "payment"
    requires: list[str] = []  # 纯静态，永远可用

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        sdk_rules, kw_rules, defaults = self._load_rules()
        if not sdk_rules and not kw_rules:
            logger.info("[%s] 无可用支付规则，跳过识别", self.name)
            result.meta["payment_sdks"] = []
            result.meta["payment_keywords"] = []
            return result

        # 数据源（各自 try/except，单源失败不影响其余）。
        so_basenames = self._collect_so_basenames(ctx)
        file_paths = self._collect_file_paths(ctx)
        dex_ok, dex_strings = self._collect_dex_strings(ctx)
        result.meta["dex_scanned"] = dex_ok
        # 关键字匹配的语料：dex 字符串 + 文本资源（带来源标注）。
        corpus = self._build_corpus(ctx, dex_strings, file_paths)

        # 1) 支付 SDK 指纹
        sdk_hits: list[_SdkHit] = []
        for rule in sdk_rules:
            try:
                hit = self._match_sdk(rule, so_basenames, file_paths, dex_strings)
            except Exception:
                logger.exception("[%s] 支付 SDK 规则匹配失败，跳过：%s", self.name, rule.name)
                continue
            if hit.evidences:
                sdk_hits.append(hit)

        # 2) 资金关键字
        kw_hits: list[_KeywordHit] = []
        for rule in kw_rules:
            try:
                hit = self._match_keyword(rule, corpus)
            except Exception:
                logger.exception("[%s] 资金关键字规则匹配失败，跳过：%s", self.name, rule.name)
                continue
            if hit.evidences:
                kw_hits.append(hit)

        for hit in sdk_hits:
            result.leads.append(self._sdk_lead(hit, defaults))
        for hit in kw_hits:
            result.leads.append(self._keyword_lead(hit, defaults))

        result.meta["payment_sdks"] = [h.rule.name for h in sdk_hits]
        result.meta["payment_keywords"] = [h.rule.name for h in kw_hits]

        if sdk_hits or kw_hits:
            logger.info(
                "[%s] 命中支付线索：SDK=%d 关键字=%d",
                self.name,
                len(sdk_hits),
                len(kw_hits),
            )
        else:
            logger.info("[%s] 未识别到支付 / 资金特征", self.name)
        return result

    # ------------------------------------------------------------------
    # 数据源采集
    # ------------------------------------------------------------------

    def _collect_so_basenames(self, ctx: "AnalysisContext") -> dict[str, str]:
        result: dict[str, str] = {}
        try:
            libs = list(ctx.native_libs())
        except Exception:
            logger.exception("[%s] 读取 native_libs 失败", self.name)
            libs = []
        try:
            files = list(ctx.list_files())
        except Exception:
            logger.exception("[%s] 读取 list_files 失败（用于 .so 采集）", self.name)
            files = []
        for path in libs + files:
            if not isinstance(path, str):
                continue
            base = posixpath.basename(path.replace("\\", "/"))
            if base.lower().endswith(".so"):
                result.setdefault(base.lower(), path)
        return result

    def _collect_file_paths(self, ctx: "AnalysisContext") -> list[str]:
        try:
            return [p for p in ctx.list_files() if isinstance(p, str)]
        except Exception:
            logger.exception("[%s] 读取 list_files 失败", self.name)
            return []

    def _collect_dex_strings(self, ctx: "AnalysisContext") -> tuple[bool, list[str]]:
        strings: list[str] = []
        try:
            for idx, s in enumerate(ctx.dex_strings()):
                if idx >= _MAX_DEX_STRINGS:
                    logger.warning(
                        "[%s] DEX 字符串超过上限 %d，截断扫描", self.name, _MAX_DEX_STRINGS
                    )
                    break
                if isinstance(s, str) and s:
                    strings.append(s)
        except Exception:
            logger.exception("[%s] 遍历 dex_strings 失败", self.name)
            return False, strings
        return True, strings

    def _build_corpus(
        self,
        ctx: "AnalysisContext",
        dex_strings: list[str],
        file_paths: list[str],
    ) -> list[tuple[str, str, str]]:
        """构造关键字匹配语料：[(source, location, text)]。

        - dex 字符串：source="dex"，location 用截断后的串本身。
        - 文本资源：source="resource"，location=文件路径。
        """
        corpus: list[tuple[str, str, str]] = [
            ("dex", _truncate(s), s) for s in dex_strings
        ]

        scanned = 0
        for path in file_paths:
            if scanned >= _MAX_RESOURCE_FILES:
                logger.warning("[%s] 文本资源数超过上限 %d，截断扫描", self.name, _MAX_RESOURCE_FILES)
                break
            if not self._is_text_resource(path):
                continue
            try:
                raw = ctx.read_file(path)
            except Exception:
                logger.exception("[%s] 读取资源失败，跳过：%s", self.name, path)
                continue
            if not raw:
                continue
            scanned += 1
            text = raw[:_MAX_RESOURCE_BYTES].decode("utf-8", errors="replace")
            corpus.append(("resource", path, text))
        return corpus

    @staticmethod
    def _is_text_resource(path: str) -> bool:
        low = path.lower()
        if low.endswith(_TEXT_SUFFIXES):
            return True
        return low.startswith(_TEXT_PREFIXES)

    # ------------------------------------------------------------------
    # 匹配
    # ------------------------------------------------------------------

    def _match_sdk(
        self,
        rule: _SdkRule,
        so_basenames: dict[str, str],
        file_paths: list[str],
        dex_strings: list[str],
    ) -> _SdkHit:
        hit = _SdkHit(rule=rule)

        for so in rule.so_names:
            key = so.lower()
            if key in so_basenames:
                hit.evidences.append(
                    Evidence(source="native", location=so_basenames[key], snippet=f"so={so}")
                )
                hit.matched_features.append(f"so:{so}")
                hit.matched_kinds.add("so")
                continue
            if not key.endswith(".so"):
                for base, path in so_basenames.items():
                    if base.startswith(key):
                        hit.evidences.append(
                            Evidence(source="native", location=path, snippet=f"so~={so}")
                        )
                        hit.matched_features.append(f"so:{so}")
                        hit.matched_kinds.add("so")
                        break

        lowered_files = [(p, p.lower()) for p in file_paths]
        for feat in rule.files:
            needle = feat.lower()
            for orig, low in lowered_files:
                if needle in low:
                    hit.evidences.append(
                        Evidence(source="resource", location=orig, snippet=f"file~={feat}")
                    )
                    hit.matched_features.append(f"file:{feat}")
                    hit.matched_kinds.add("file")
                    break

        for prefix in rule.dex_prefixes:
            for s in dex_strings:
                if prefix in s:
                    hit.evidences.append(
                        Evidence(source="dex", location=prefix, snippet=_truncate(s))
                    )
                    hit.matched_features.append(f"dex:{prefix}")
                    hit.matched_kinds.add("dex")
                    break

        _trim_evidences(hit.evidences)
        return hit

    def _match_keyword(
        self, rule: _KeywordRule, corpus: list[tuple[str, str, str]]
    ) -> _KeywordHit:
        hit = _KeywordHit(rule=rule)
        for pattern in rule.patterns:
            matcher = _compile_matcher(pattern)
            for source, location, text in corpus:
                m = matcher(text)
                if m is None:
                    continue
                snippet = _snippet_around(text, m)
                hit.evidences.append(
                    Evidence(source=source, location=location, snippet=snippet)
                )
                hit.matched_patterns.append(pattern)
                break  # 同一 pattern 命中一次即可
            if len(hit.evidences) >= _MAX_EVIDENCES:
                break
        _trim_evidences(hit.evidences)
        return hit

    # ------------------------------------------------------------------
    # Lead 构造
    # ------------------------------------------------------------------

    def _sdk_lead(self, hit: _SdkHit, defaults: dict[str, object]) -> Lead:
        rule = hit.rule
        evidence_to_obtain = (
            list(rule.evidence_to_obtain)
            if rule.evidence_to_obtain
            else list(defaults["evidence_to_obtain"])  # type: ignore[arg-type]
        )
        where = rule.where_to_request or rule.vendor
        return Lead(
            category=LeadCategory.PAYMENT,
            value=rule.name,
            subject=rule.vendor,
            where_to_request=where,
            evidence_to_obtain=evidence_to_obtain,
            confidence=hit.confidence(),
            source_refs=list(hit.evidences),
            notes=self._sdk_notes(hit),
        )

    def _keyword_lead(self, hit: _KeywordHit, defaults: dict[str, object]) -> Lead:
        rule = hit.rule
        evidence_to_obtain = (
            list(rule.evidence_to_obtain)
            if rule.evidence_to_obtain
            else list(defaults["evidence_to_obtain"])  # type: ignore[arg-type]
        )
        subject = rule.subject or str(defaults["default_subject"])
        where = rule.where_to_request or str(defaults["default_where_to_request"])
        return Lead(
            category=LeadCategory.PAYMENT,
            value=rule.name,
            subject=subject,
            where_to_request=where,
            evidence_to_obtain=evidence_to_obtain,
            confidence=hit.confidence(),
            source_refs=list(hit.evidences),
            notes=self._keyword_notes(hit),
        )

    @staticmethod
    def _sdk_notes(hit: _SdkHit) -> str:
        parts: list[str] = []
        if hit.rule.category:
            parts.append(f"分类：{hit.rule.category}。")
        if hit.rule.note:
            parts.append(hit.rule.note)
        if hit.matched_features:
            parts.append("命中特征：" + "、".join(hit.matched_features) + "。")
        return " ".join(parts)

    @staticmethod
    def _keyword_notes(hit: _KeywordHit) -> str:
        parts: list[str] = []
        if hit.rule.category:
            parts.append(f"分类：{hit.rule.category}。")
        if hit.rule.strong:
            parts.append("强资金线索。")
        if hit.rule.note:
            parts.append(hit.rule.note)
        if hit.matched_patterns:
            parts.append("命中：" + "、".join(dict.fromkeys(hit.matched_patterns)) + "。")
        return " ".join(parts)

    # ------------------------------------------------------------------
    # 规则加载
    # ------------------------------------------------------------------

    def _load_rules(
        self,
    ) -> tuple[list[_SdkRule], list[_KeywordRule], dict[str, object]]:
        data = load_rules(_RULES_NAME)

        defaults: dict[str, object] = {
            "evidence_to_obtain": list(_DEFAULT_EVIDENCE_TO_OBTAIN),
            "default_where_to_request": _DEFAULT_WHERE,
            "default_subject": _DEFAULT_SUBJECT,
        }

        if not isinstance(data, dict):
            logger.warning(
                "[%s] 规则顶层应为 dict，实际 %s；无规则可用",
                self.name,
                type(data).__name__,
            )
            return [], [], defaults

        meta = data.get("meta")
        if isinstance(meta, dict):
            ev = _as_str_list(meta.get("evidence_to_obtain"))
            if ev:
                defaults["evidence_to_obtain"] = ev
            if isinstance(meta.get("default_where_to_request"), str):
                defaults["default_where_to_request"] = meta["default_where_to_request"].strip()
            if isinstance(meta.get("default_subject"), str):
                defaults["default_subject"] = meta["default_subject"].strip()

        sdk_rules = self._parse_sdks(data.get("sdks"))
        kw_rules = self._parse_keywords(data.get("keywords"))
        return sdk_rules, kw_rules, defaults

    def _parse_sdks(self, raw: object) -> list[_SdkRule]:
        if not isinstance(raw, list):
            if raw is not None:
                logger.warning("[%s] sdks 字段应为 list，实际 %s", self.name, type(raw).__name__)
            return []
        rules: list[_SdkRule] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            vendor = entry.get("vendor")
            if not _nonempty_str(name) or not _nonempty_str(vendor):
                logger.warning("[%s] 跳过缺少 name/vendor 的支付 SDK 规则：%r", self.name, entry)
                continue
            rule = _SdkRule(
                name=name.strip(),
                vendor=vendor.strip(),
                category=_str_or_empty(entry.get("category")),
                where_to_request=_str_or_empty(entry.get("where_to_request")),
                dex_prefixes=_as_str_list(entry.get("dex_prefixes")),
                so_names=_as_str_list(entry.get("so_names")),
                files=_as_str_list(entry.get("files")),
                evidence_to_obtain=_as_str_list(entry.get("evidence_to_obtain")),
                confidence=_str_or_empty(entry.get("confidence")),
                note=_str_or_empty(entry.get("note")),
            )
            if not (rule.dex_prefixes or rule.so_names or rule.files):
                logger.warning("[%s] 跳过无匹配特征的支付 SDK 规则：%s", self.name, rule.name)
                continue
            rules.append(rule)
        return rules

    def _parse_keywords(self, raw: object) -> list[_KeywordRule]:
        if not isinstance(raw, list):
            if raw is not None:
                logger.warning("[%s] keywords 字段应为 list，实际 %s", self.name, type(raw).__name__)
            return []
        rules: list[_KeywordRule] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            patterns = _as_str_list(entry.get("patterns"))
            if not _nonempty_str(name) or not patterns:
                logger.warning("[%s] 跳过缺少 name/patterns 的资金关键字规则：%r", self.name, entry)
                continue
            rules.append(
                _KeywordRule(
                    name=name.strip(),
                    category=_str_or_empty(entry.get("category")),
                    strong=bool(entry.get("strong", False)),
                    patterns=patterns,
                    subject=_str_or_empty(entry.get("subject")),
                    where_to_request=_str_or_empty(entry.get("where_to_request")),
                    evidence_to_obtain=_as_str_list(entry.get("evidence_to_obtain")),
                    note=_str_or_empty(entry.get("note")),
                )
            )
        return rules


# ---------------------------------------------------------------------------
# 模块级工具
# ---------------------------------------------------------------------------


def _compile_matcher(pattern: str):
    """把规则 pattern 编成匹配函数 text -> re.Match|None。

    优先按正则编译（大小写不敏感）；编译失败回退为大小写不敏感子串匹配。
    """
    try:
        rx = re.compile(pattern, re.IGNORECASE)
    except re.error:
        logger.debug("支付关键字非合法正则，按子串匹配：%r", pattern)
        needle = pattern.lower()

        def _sub(text: str) -> re.Match | None:
            idx = text.lower().find(needle)
            if idx < 0:
                return None
            return _Span(idx, idx + len(needle))  # type: ignore[return-value]

        return _sub

    def _rx(text: str) -> re.Match | None:
        return rx.search(text)

    return _rx


class _Span:
    """子串匹配的轻量 Match 替身，提供 start()/end()。"""

    __slots__ = ("_s", "_e")

    def __init__(self, start: int, end: int) -> None:
        self._s = start
        self._e = end

    def start(self) -> int:
        return self._s

    def end(self) -> int:
        return self._e


def _snippet_around(text: str, m: object, radius: int = 60) -> str:
    """截取命中位置周边片段，便于人工复核。"""
    try:
        start = max(0, m.start() - radius)  # type: ignore[attr-defined]
        end = min(len(text), m.end() + radius)  # type: ignore[attr-defined]
    except Exception:
        return _truncate(text)
    seg = text[start:end].replace("\n", " ").strip()
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{seg}{suffix}"


def _trim_evidences(evidences: list[Evidence]) -> None:
    if len(evidences) > _MAX_EVIDENCES:
        del evidences[_MAX_EVIDENCES:]


def _parse_confidence(value: str) -> Confidence | None:
    if not value:
        return None
    key = value.strip().upper()
    try:
        return Confidence[key]
    except KeyError:
        return None


def _nonempty_str(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and bool(value.strip())


def _str_or_empty(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _as_str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _truncate(text: str, limit: int = _SNIPPET_MAX) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "…"
