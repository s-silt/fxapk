"""第三方服务 / SDK 指纹分析器 — SDK → 厂商映射，产出 SDK_SERVICE 调证线索。

职责（见设计文档 §4 sdk_fingerprint 行 + §SDK 指纹库）：
- 用 ctx.dex_strings()（类名包前缀）+ ctx.list_files()（资源/特征文件）+
  ctx.native_libs()（.so 库名）三路匹配 SDK 特征。
- 规则来自 apkscan/rules/sdks.yaml，覆盖国内主流：支付（支付宝/微信支付/银联）、
  短信（阿里云/腾讯云/容联云/Mob）、推送（极光/个推/友盟/华为/小米/OPPO/vivo/魅族）、
  云存储 CDN（阿里云 OSS/腾讯云 COS/七牛/又拍云/华为云）、IM 客服（融云/环信/网易云信/
  容联七陌/美洽）、统计（友盟/TalkingData/神策/GrowingIO）、地图（高德/百度/腾讯）。
- 每命中一个 SDK →
    * Lead(category=SDK_SERVICE, value=name, subject=vendor, where_to_request=vendor,
           evidence_to_obtain=规则里的可调证据, source_refs=Evidence,
           confidence=按匹配强度 HIGH / MEDIUM)
    * meta["sdks"] 记录命中的 SDK 名列表；meta["sdk_categories"] 记录命中分类计数。

置信度判定（按匹配强度）：
- 命中 so / 资源文件，或命中 >= 2 类特征（dex/so/file）→ Confidence.HIGH
- 仅命中单一 dex 类前缀特征                          → Confidence.MEDIUM

约束：
- 只依赖 AnalysisContext 公开接口，禁止 import androguard。
- 单点解析异常 try/except + logging，不让单条规则 / 单个数据源炸掉整个 analyze；
  不静默 pass。
- 全程 type hints。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from apkscan.analyzers._common import (
    as_str_list as _as_str_list,
)
from apkscan.analyzers._common import (
    collect_dex_strings as _collect_dex_strings_shared,
)
from apkscan.analyzers._common import (
    collect_file_paths as _collect_file_paths_shared,
)
from apkscan.analyzers._common import (
    collect_so_basenames as _collect_so_basenames_shared,
)
from apkscan.analyzers._common import (
    str_or_empty as _str_or_empty,
)
from apkscan.analyzers._common import (
    truncate as _truncate_shared,
)
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

_RULES_NAME = "sdks"

# 命中后 Lead 默认可调取证据（规则 meta / 条目缺失时兜底，确保离线/规则缺失仍合规）。
_DEFAULT_EVIDENCE_TO_OBTAIN: tuple[str, ...] = (
    "开发者账号实名信息（注册主体/联系人/手机号/邮箱）",
    "应用绑定的 appid / appkey / 商户号注册主体",
    "服务调用日志（调用 IP / 时间 / 频次）",
)

# DEX 字符串扫描上限：样本字符串池可能很大，避免极端情况下扫描过久。
_MAX_DEX_STRINGS = 200_000

# dex_strings 命中后用于证据片段的截断长度。
_SNIPPET_MAX = 200


@dataclass
class _SdkRule:
    """单条 SDK 指纹规则（从 YAML 规整而来）。"""

    name: str
    vendor: str
    category: str = ""
    dex_prefixes: list[str] = field(default_factory=list)
    so_names: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    evidence_to_obtain: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class _Hit:
    """一条规则的命中证据集合。"""

    rule: _SdkRule
    evidences: list[Evidence] = field(default_factory=list)
    matched_features: list[str] = field(default_factory=list)
    # 命中的特征类别集合（"dex" / "so" / "file"），用于置信度判定。
    matched_kinds: set[str] = field(default_factory=set)

    def confidence(self) -> Confidence:
        """按匹配强度判定置信度。

        - 命中 so 或资源文件（强特征），或命中 >= 2 类特征 → HIGH
        - 仅命中单一 dex 类前缀                          → MEDIUM
        """
        if "so" in self.matched_kinds or "file" in self.matched_kinds:
            return Confidence.HIGH
        if len(self.matched_kinds) >= 2:
            return Confidence.HIGH
        return Confidence.MEDIUM


class SdkFingerprintAnalyzer(BaseAnalyzer):
    """识别第三方 SDK / 服务，产出 SDK_SERVICE 调证线索（每 SDK 绑定一家可调证厂商）。"""

    name: str = "sdk_fingerprint"
    requires: list[str] = ["apk"]  # Android 专属；IPA 上 pipeline 自动 skipped

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        rules, default_evidence = self._load_rules()
        if not rules:
            logger.info("[%s] 无可用 SDK 指纹规则，跳过识别", self.name)
            result.meta["sdks"] = []
            return result

        # 三路数据源各自 try/except，单源失败不影响其余。
        so_basenames = self._collect_so_basenames(ctx)
        file_paths = self._collect_file_paths(ctx)
        dex_iter_ok, dex_strings = self._collect_dex_strings(ctx)
        result.meta["dex_scanned"] = dex_iter_ok

        hits: list[_Hit] = []
        for rule in rules:
            try:
                hit = self._match_rule(rule, so_basenames, file_paths, dex_strings)
            except Exception:
                logger.exception("[%s] 规则匹配失败，跳过：%s", self.name, rule.name)
                continue
            if hit.evidences:
                hits.append(hit)

        if not hits:
            logger.info("[%s] 未识别到已知第三方 SDK 特征", self.name)
            result.meta["sdks"] = []
            return result

        # 命中：每 SDK 一条 Lead。
        for hit in hits:
            rule = hit.rule
            evidence_to_obtain = (
                list(rule.evidence_to_obtain)
                if rule.evidence_to_obtain
                else list(default_evidence)
            )
            result.leads.append(
                Lead(
                    category=LeadCategory.SDK_SERVICE,
                    value=rule.name,
                    subject=rule.vendor,
                    where_to_request=rule.vendor,
                    evidence_to_obtain=evidence_to_obtain,
                    confidence=hit.confidence(),
                    source_refs=list(hit.evidences),
                    notes=self._lead_notes(hit),
                )
            )

        # meta 汇总，便于报告概览/调试。
        result.meta["sdks"] = [hit.rule.name for hit in hits]
        category_counts: dict[str, int] = {}
        for hit in hits:
            cat = hit.rule.category or "other"
            category_counts[cat] = category_counts.get(cat, 0) + 1
        result.meta["sdk_categories"] = category_counts

        logger.info(
            "[%s] 识别到 %d 个第三方 SDK：%s",
            self.name,
            len(hits),
            "、".join(h.rule.name for h in hits),
        )
        return result

    # ------------------------------------------------------------------
    # 数据源采集（各自 try/except）
    # ------------------------------------------------------------------

    def _collect_so_basenames(self, ctx: "AnalysisContext") -> dict[str, str]:
        """返回 {小写 basename: 原始路径}。包含 native_libs 与 list_files 中的 .so。"""
        return _collect_so_basenames_shared(ctx, self.name)

    def _collect_file_paths(self, ctx: "AnalysisContext") -> list[str]:
        """APK 内全部文件路径。"""
        return _collect_file_paths_shared(ctx, self.name)

    def _collect_dex_strings(self, ctx: "AnalysisContext") -> tuple[bool, list[str]]:
        """收集 DEX 字符串（带上限）。返回 (是否成功遍历, 字符串列表)。"""
        return _collect_dex_strings_shared(ctx, self.name, max_strings=_MAX_DEX_STRINGS)

    # ------------------------------------------------------------------
    # 单规则匹配
    # ------------------------------------------------------------------

    def _match_rule(
        self,
        rule: _SdkRule,
        so_basenames: dict[str, str],
        file_paths: list[str],
        dex_strings: list[str],
    ) -> _Hit:
        hit = _Hit(rule=rule)

        # 1) .so 库名（basename 命中，大小写不敏感；容忍规则不带 .so 后缀 / 写库名前缀）
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

        # 2) 特征文件（路径子串匹配，大小写不敏感）
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

        # 3) DEX 类前缀 / 字符串特征（子串匹配，大小写敏感保留原样）
        for prefix in rule.dex_prefixes:
            for s in dex_strings:
                if prefix in s:
                    hit.evidences.append(
                        Evidence(source="dex", location=prefix, snippet=_truncate(s))
                    )
                    hit.matched_features.append(f"dex:{prefix}")
                    hit.matched_kinds.add("dex")
                    break

        return hit

    # ------------------------------------------------------------------
    # 规则加载 / 规整
    # ------------------------------------------------------------------

    def _load_rules(self) -> tuple[list[_SdkRule], list[str]]:
        """加载并规整规则，返回 (规则列表, 默认可调证据)。"""
        data = load_rules(_RULES_NAME)

        raw_sdks: object
        evidence: list[str] = list(_DEFAULT_EVIDENCE_TO_OBTAIN)

        if isinstance(data, dict):
            raw_sdks = data.get("sdks", [])
            meta = data.get("meta")
            if isinstance(meta, dict):
                ev = _as_str_list(meta.get("evidence_to_obtain"))
                if ev:
                    evidence = ev
        elif isinstance(data, list):
            # 容忍顶层直接是 list[规则] 的写法
            raw_sdks = data
        else:
            logger.warning(
                "[%s] 规则顶层应为 dict/list，实际 %s；无规则可用",
                self.name,
                type(data).__name__,
            )
            raw_sdks = []

        rules = self._parse_rules(raw_sdks)
        return rules, evidence

    def _parse_rules(self, raw: object) -> list[_SdkRule]:
        if not isinstance(raw, list):
            logger.warning("[%s] sdks 字段应为 list，实际 %s", self.name, type(raw).__name__)
            return []
        rules: list[_SdkRule] = []
        for entry in raw:
            if not isinstance(entry, dict):
                logger.warning("[%s] 跳过非 dict 规则条目：%r", self.name, entry)
                continue
            name = entry.get("name")
            vendor = entry.get("vendor")
            if not isinstance(name, str) or not name.strip():
                logger.warning("[%s] 跳过缺少 name 的规则条目：%r", self.name, entry)
                continue
            if not isinstance(vendor, str) or not vendor.strip():
                logger.warning("[%s] 跳过缺少 vendor 的规则条目：%s", self.name, name)
                continue
            rule = _SdkRule(
                name=name.strip(),
                vendor=vendor.strip(),
                category=_str_or_empty(entry.get("category")),
                dex_prefixes=_as_str_list(entry.get("dex_prefixes")),
                so_names=_as_str_list(entry.get("so_names")),
                files=_as_str_list(entry.get("files")),
                evidence_to_obtain=_as_str_list(entry.get("evidence_to_obtain")),
                note=_str_or_empty(entry.get("note")),
            )
            if not (rule.dex_prefixes or rule.so_names or rule.files):
                logger.warning(
                    "[%s] 跳过无任何匹配特征的规则条目：%s", self.name, rule.name
                )
                continue
            rules.append(rule)
        return rules

    @staticmethod
    def _lead_notes(hit: _Hit) -> str:
        parts: list[str] = []
        if hit.rule.category:
            parts.append(f"分类：{hit.rule.category}。")
        if hit.rule.note:
            parts.append(hit.rule.note)
        if hit.matched_features:
            parts.append("命中特征：" + "、".join(hit.matched_features) + "。")
        return " ".join(parts)


# ---------------------------------------------------------------------------
# 模块级工具函数
# ---------------------------------------------------------------------------


def _truncate(text: str, limit: int = _SNIPPET_MAX) -> str:
    return _truncate_shared(text, limit)
