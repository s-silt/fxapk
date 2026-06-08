"""联系方式分析器 — QQ / 微信 / Telegram / 邮箱 / 手机号 → CONTACT 调证线索。

职责（见设计文档 §4 contacts 行）：
- 从 ctx.dex_strings() + 文本资源 + manifest_xml 用正则抽取联系方式。
- 规则来自 apkscan/rules/contacts.yaml（每类含 patterns / blacklist / 归属 / 可调取证据）。
- 每个**去重后的联系方式值** → Lead(category=CONTACT, value=联系方式, subject=平台,
  where_to_request, evidence_to_obtain, confidence, source_refs=Evidence)。
- meta["contacts"] 记录按类型计数，供报告/调试。

误报控制：手机号用前后非数字边界；QQ/微信要求上下文关键字（写在正则里）；
邮箱黑名单排除 @drawable/@string 等资源引用。

约束：
- 只依赖 AnalysisContext 公开接口，禁止 import androguard。
- 单点解析异常 try/except + logging，不让单条规则/单个数据源炸掉整个 analyze；不静默 pass。
- 全程 type hints。
"""

from __future__ import annotations

import logging
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

_RULES_NAME = "contacts"

_DEFAULT_EVIDENCE_TO_OBTAIN: tuple[str, ...] = (
    "账号实名注册信息",
    "绑定手机号 / 邮箱",
    "登录 IP 与设备信息",
)

_MAX_DEX_STRINGS = 200_000
_MAX_RESOURCE_FILES = 2_000
_MAX_RESOURCE_BYTES = 512 * 1024
# 每个类型最多产出的联系方式 Lead 数（防止极端样本刷屏）。
_MAX_LEADS_PER_TYPE = 200
_MAX_EVIDENCES = 5
_SNIPPET_MAX = 160

_TEXT_SUFFIXES: tuple[str, ...] = (
    ".json", ".xml", ".txt", ".properties", ".js", ".html", ".htm",
    ".cfg", ".conf", ".ini", ".csv", ".kv", ".plist",
)
_TEXT_PREFIXES: tuple[str, ...] = ("assets/", "res/raw/", "res/xml/")


@dataclass
class _ContactType:
    name: str
    kind: str
    subject: str = ""
    where_to_request: str = ""
    confidence: Confidence = Confidence.MEDIUM
    patterns: list[re.Pattern] = field(default_factory=list)
    blacklist: list[str] = field(default_factory=list)
    evidence_to_obtain: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class _ContactHit:
    value: str
    evidences: list[Evidence] = field(default_factory=list)


class ContactsAnalyzer(BaseAnalyzer):
    """提取 QQ/微信/Telegram/邮箱/手机号，产出 CONTACT 调证线索。"""

    name: str = "contacts"
    requires: list[str] = []  # 纯静态，永远可用

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        types, default_evidence = self._load_rules()
        if not types:
            logger.info("[%s] 无可用联系方式规则，跳过识别", self.name)
            result.meta["contacts"] = {}
            return result

        corpus = self._build_corpus(ctx)
        counts: dict[str, int] = {}

        for ctype in types:
            try:
                hits = self._match_type(ctype, corpus)
            except Exception:
                logger.exception("[%s] 联系方式类型匹配失败，跳过：%s", self.name, ctype.name)
                continue
            if not hits:
                continue
            counts[ctype.kind] = len(hits)
            for hit in hits:
                result.leads.append(self._lead(ctype, hit, default_evidence))

        result.meta["contacts"] = counts
        total = sum(counts.values())
        if total:
            logger.info("[%s] 提取到 %d 条联系方式线索：%s", self.name, total, counts)
        else:
            logger.info("[%s] 未提取到联系方式线索", self.name)
        return result

    # ------------------------------------------------------------------
    # 语料
    # ------------------------------------------------------------------

    def _build_corpus(self, ctx: "AnalysisContext") -> list[tuple[str, str, str]]:
        """[(source, location, text)]：dex 字符串 + manifest + 文本资源。"""
        corpus: list[tuple[str, str, str]] = []

        # dex 字符串
        try:
            for idx, s in enumerate(ctx.dex_strings()):
                if idx >= _MAX_DEX_STRINGS:
                    logger.warning("[%s] DEX 字符串超过上限 %d，截断扫描", self.name, _MAX_DEX_STRINGS)
                    break
                if isinstance(s, str) and s:
                    corpus.append(("dex", _truncate(s), s))
        except Exception:
            logger.exception("[%s] 遍历 dex_strings 失败", self.name)

        # manifest
        try:
            mf = ctx.manifest_xml
            if isinstance(mf, str) and mf:
                corpus.append(("manifest", "AndroidManifest.xml", mf))
        except Exception:
            logger.exception("[%s] 读取 manifest_xml 失败", self.name)

        # 文本资源
        try:
            files = [p for p in ctx.list_files() if isinstance(p, str)]
        except Exception:
            logger.exception("[%s] 读取 list_files 失败", self.name)
            files = []
        scanned = 0
        for path in files:
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
            corpus.append(("resource", path, raw[:_MAX_RESOURCE_BYTES].decode("utf-8", errors="replace")))
        return corpus

    @staticmethod
    def _is_text_resource(path: str) -> bool:
        low = path.lower()
        return low.endswith(_TEXT_SUFFIXES) or low.startswith(_TEXT_PREFIXES)

    # ------------------------------------------------------------------
    # 匹配
    # ------------------------------------------------------------------

    def _match_type(
        self, ctype: _ContactType, corpus: list[tuple[str, str, str]]
    ) -> list[_ContactHit]:
        """对一个类型扫全语料，按线索值去重聚合证据。"""
        by_value: dict[str, _ContactHit] = {}
        for rx in ctype.patterns:
            for source, location, text in corpus:
                for m in rx.finditer(text):
                    value = _match_value(m)
                    if not value:
                        continue
                    if _is_blacklisted(value, ctype.blacklist) or _is_blacklisted(
                        m.group(0), ctype.blacklist
                    ):
                        continue
                    if not _valid_for_kind(ctype.kind, value):
                        continue
                    hit = by_value.get(value)
                    if hit is None:
                        if len(by_value) >= _MAX_LEADS_PER_TYPE:
                            logger.warning(
                                "[%s] 类型 %s 命中超过上限 %d，截断",
                                self.name,
                                ctype.kind,
                                _MAX_LEADS_PER_TYPE,
                            )
                            return list(by_value.values())
                        hit = _ContactHit(value=value)
                        by_value[value] = hit
                    if len(hit.evidences) < _MAX_EVIDENCES:
                        hit.evidences.append(
                            Evidence(
                                source=source,
                                location=location,
                                snippet=_snippet_around(text, m),
                            )
                        )
        return list(by_value.values())

    def _lead(
        self, ctype: _ContactType, hit: _ContactHit, default_evidence: list[str]
    ) -> Lead:
        evidence_to_obtain = (
            list(ctype.evidence_to_obtain) if ctype.evidence_to_obtain else list(default_evidence)
        )
        note = f"类型：{ctype.name}。" + (ctype.note or "")
        return Lead(
            category=LeadCategory.CONTACT,
            value=f"{ctype.name}：{hit.value}",
            subject=ctype.subject or None,
            where_to_request=ctype.where_to_request or None,
            evidence_to_obtain=evidence_to_obtain,
            confidence=ctype.confidence,
            source_refs=list(hit.evidences),
            notes=note.strip(),
        )

    # ------------------------------------------------------------------
    # 规则加载
    # ------------------------------------------------------------------

    def _load_rules(self) -> tuple[list[_ContactType], list[str]]:
        data = load_rules(_RULES_NAME)
        default_evidence = list(_DEFAULT_EVIDENCE_TO_OBTAIN)

        if not isinstance(data, dict):
            logger.warning(
                "[%s] 规则顶层应为 dict，实际 %s；无规则可用", self.name, type(data).__name__
            )
            return [], default_evidence

        meta = data.get("meta")
        if isinstance(meta, dict):
            ev = _as_str_list(meta.get("evidence_to_obtain"))
            if ev:
                default_evidence = ev

        raw_types = data.get("types")
        if not isinstance(raw_types, list):
            logger.warning("[%s] types 字段应为 list，实际 %s", self.name, type(raw_types).__name__)
            return [], default_evidence

        types: list[_ContactType] = []
        for entry in raw_types:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            kind = entry.get("kind")
            if not _nonempty_str(name) or not _nonempty_str(kind):
                logger.warning("[%s] 跳过缺少 name/kind 的联系方式规则：%r", self.name, entry)
                continue
            patterns = self._compile_patterns(_as_str_list(entry.get("patterns")), name)
            if not patterns:
                logger.warning("[%s] 跳过无有效正则的联系方式规则：%s", self.name, name)
                continue
            types.append(
                _ContactType(
                    name=name.strip(),
                    kind=kind.strip(),
                    subject=_str_or_empty(entry.get("subject")),
                    where_to_request=_str_or_empty(entry.get("where_to_request")),
                    confidence=_parse_confidence(entry.get("confidence")) or Confidence.MEDIUM,
                    patterns=patterns,
                    blacklist=[b.lower() for b in _as_str_list(entry.get("blacklist"))],
                    evidence_to_obtain=_as_str_list(entry.get("evidence_to_obtain")),
                    note=_str_or_empty(entry.get("note")),
                )
            )
        return types, default_evidence

    def _compile_patterns(self, patterns: list[str], type_name: str) -> list[re.Pattern]:
        compiled: list[re.Pattern] = []
        for pat in patterns:
            try:
                compiled.append(re.compile(pat, re.IGNORECASE))
            except re.error:
                logger.warning("[%s] 类型 %s 的正则非法，跳过：%r", self.name, type_name, pat)
        return compiled


# ---------------------------------------------------------------------------
# 模块级工具
# ---------------------------------------------------------------------------


def _match_value(m: re.Match) -> str:
    """取线索值：有捕获组用首个非空组，否则用整段匹配。"""
    if m.groups():
        for g in m.groups():
            if g:
                return g.strip()
    return m.group(0).strip()


def _is_blacklisted(text: str, blacklist: list[str]) -> bool:
    if not blacklist:
        return False
    low = text.lower()
    return any(b in low for b in blacklist)


# 邮箱后缀白名单：邮箱必须以真实 TLD 结尾，否则多为代码误报
# （如 Kotlin `this@AbstractTypeConstructor.builtIns` / `x@y.type` / `@a.parameters`）。
_EMAIL_TLDS: frozenset[str] = frozenset(
    {
        "com", "cn", "net", "org", "gov", "edu", "io", "co", "me", "info",
        "biz", "vip", "top", "xyz", "club", "shop", "site", "cc", "tv",
        "hk", "tw", "mo", "jp", "kr", "sg", "us", "uk", "ru", "de", "fr",
        "qq", "163", "126", "gmail", "outlook", "hotmail", "foxmail",
        "mobi", "pro", "live", "icloud", "yeah", "sina", "sohu", "aliyun",
    }
)


def _valid_for_kind(kind: str, value: str) -> bool:
    """按类型做额外有效性校验，剔除代码误报。

    email：取 @ 后域名的末段（TLD），必须是真实 TLD（小写、在白名单）。
           这能杀掉 Kotlin `this@Class.prop` / `x@y.type` 这类被邮箱正则误命中的代码。
    其它类型：不额外限制。
    """
    if kind != "email":
        return True
    at = value.rfind("@")
    if at < 0:
        return False
    domain = value[at + 1:]
    if "." not in domain:
        return False
    tld = domain.rsplit(".", 1)[-1]
    return tld.isalpha() and tld.lower() in _EMAIL_TLDS


def _snippet_around(text: str, m: re.Match, radius: int = 40) -> str:
    start = max(0, m.start() - radius)
    end = min(len(text), m.end() + radius)
    seg = text[start:end].replace("\n", " ").strip()
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{seg}{suffix}"


def _parse_confidence(value: object) -> Confidence | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return Confidence[value.strip().upper()]
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
