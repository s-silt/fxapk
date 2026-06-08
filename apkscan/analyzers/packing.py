"""加固/加壳识别分析器 — 识别国内主流加固厂商 → 调证线索 + 静态不完整告警。

职责（见设计文档 §4 packing 行）：
- 用 ctx.native_libs() + ctx.list_files() + ctx.dex_strings() 三路匹配加固特征。
- 规则来自 apkscan/rules/packers.yaml（梆梆/爱加密/360/腾讯乐固/娜迦/百度/网易易盾/
  阿里聚安全/几维等），每条含 so 名 / 特征文件 / dex 类前缀。
- 命中（任一厂商）→
    * Finding(HIGH, "已加固，静态端点不完整，建议脱壳或真机动态补全")
    * Lead(category=PACKER, subject=加固厂商, where_to_request=加固厂商,
           evidence_to_obtain=["未加固原始安装包","开发者实名注册信息","加固/打包账号与操作日志"],
           confidence=HIGH)
    * meta["packed"] = vendor（多厂商命中时取首个；meta["packers"] 记全部）

约束：
- 只依赖 AnalysisContext 公开接口，禁止 import androguard。
- 单点解析异常 try/except + logging，不让单条规则/单个数据源炸掉整个 analyze；不静默 pass。
- 全程 type hints。
"""

from __future__ import annotations

import logging
import posixpath
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from apkscan.core.models import (
    AnalyzerResult,
    Confidence,
    Evidence,
    Finding,
    Lead,
    LeadCategory,
    Severity,
)
from apkscan.core.registry import BaseAnalyzer, load_rules

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_RULES_NAME = "packers"

# 命中后 Lead 默认可调取证据（规则文件 meta 缺失时的兜底，确保离线/规则缺失仍合规）。
_DEFAULT_EVIDENCE_TO_OBTAIN: tuple[str, ...] = (
    "未加固原始安装包",
    "开发者实名注册信息",
    "加固/打包账号与操作日志",
)

_FINDING_TITLE = "已加固，静态端点不完整，建议脱壳或真机动态补全"

# DEX 字符串扫描上限：加固样本字符串池可能很大，避免极端情况下扫描过久。
_MAX_DEX_STRINGS = 200_000

# dex_strings 命中后用于证据片段的截断长度。
_SNIPPET_MAX = 200


@dataclass
class _PackerRule:
    """单条加固厂商规则（从 YAML 规整而来）。"""

    name: str
    vendor: str
    so_names: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    dex_prefixes: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class _Hit:
    """一条规则的命中证据集合。"""

    rule: _PackerRule
    evidences: list[Evidence] = field(default_factory=list)
    matched_features: list[str] = field(default_factory=list)

    def matched_summary(self) -> str:
        """命中摘要：'产品名[特征1、特征2]'，用于 Finding 描述拼接。"""
        feats = "、".join(self.matched_features) if self.matched_features else "(无)"
        return f"{self.rule.name}[{feats}]"


class PackingAnalyzer(BaseAnalyzer):
    """识别加固厂商，产出 PACKER 线索 + 静态端点不完整 Finding。"""

    name: str = "packing"
    requires: list[str] = []  # 纯静态，永远可用

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        rules, default_evidence, where_suffix = self._load_rules()
        if not rules:
            logger.info("[%s] 无可用加固规则，跳过识别", self.name)
            result.meta["packed"] = None
            result.meta["packer"] = None
            result.meta["is_hardened"] = False
            return result

        # 三路数据源各自 try/except，单源失败不影响其余。
        so_basenames = self._collect_so_basenames(ctx)
        file_paths = self._collect_file_paths(ctx)
        dex_iter_ok, dex_strings = self._collect_dex_strings(ctx)

        hits: list[_Hit] = []
        for rule in rules:
            try:
                hit = self._match_rule(rule, so_basenames, file_paths, dex_strings)
            except Exception:
                logger.exception("[%s] 规则匹配失败，跳过：%s", self.name, rule.name)
                continue
            if hit.evidences:
                hits.append(hit)

        result.meta["dex_scanned"] = dex_iter_ok
        if not hits:
            logger.info("[%s] 未识别到已知加固特征", self.name)
            result.meta["packed"] = None
            result.meta["packer"] = None
            result.meta["is_hardened"] = False
            return result

        # 命中：产出 Finding + 每厂商一条 Lead。
        vendors = [hit.rule.vendor for hit in hits]
        result.meta["packed"] = vendors[0]
        result.meta["packers"] = vendors
        # 报告概览加固 banner 消费的键。
        result.meta["packer"] = vendors[0]
        result.meta["is_hardened"] = True

        all_evidences: list[Evidence] = []
        for hit in hits:
            all_evidences.extend(hit.evidences)

        product_names = "、".join(hit.rule.name for hit in hits)
        result.findings.append(
            Finding(
                id="PACK-DETECTED",
                title=_FINDING_TITLE,
                severity=Severity.HIGH,
                category="packing",
                description=(
                    f"检测到应用已使用加固/加壳保护（识别厂商：{product_names}）。"
                    "加固会对真实 DEX 加密/隐藏并在运行时还原，"
                    "静态分析无法获取完整的 DEX 字符串、网络端点、第三方 SDK 与支付线索，"
                    "本次静态产出的端点/SDK/支付清单可能严重不完整。"
                    f"命中特征：{'; '.join(h.matched_summary() for h in hits)}。"
                ),
                recommendation=(
                    "建议脱壳后重新静态分析，或在真机/沙箱动态运行抓包补全端点与资金流线索；"
                    "同时将加固厂商作为调证目标，调取未加固原始安装包与打包账号信息。"
                ),
                evidences=all_evidences,
                references=[
                    "https://developer.android.com/topic/security",
                ],
            )
        )

        for hit in hits:
            rule = hit.rule
            where = rule.vendor + where_suffix
            result.leads.append(
                Lead(
                    category=LeadCategory.PACKER,
                    value=rule.name,
                    subject=rule.vendor,
                    where_to_request=where,
                    evidence_to_obtain=list(default_evidence),
                    confidence=Confidence.HIGH,
                    source_refs=list(hit.evidences),
                    notes=self._lead_notes(hit),
                )
            )

        return result

    # ------------------------------------------------------------------
    # 数据源采集（各自 try/except）
    # ------------------------------------------------------------------

    def _collect_so_basenames(self, ctx: "AnalysisContext") -> dict[str, str]:
        """返回 {小写 basename: 原始路径}。包含 native_libs 与 list_files 中的 .so。"""
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
        """APK 内全部文件路径（小写副本用于匹配时另算）。"""
        try:
            return [p for p in ctx.list_files() if isinstance(p, str)]
        except Exception:
            logger.exception("[%s] 读取 list_files 失败", self.name)
            return []

    def _collect_dex_strings(self, ctx: "AnalysisContext") -> tuple[bool, list[str]]:
        """收集 DEX 字符串（带上限）。返回 (是否成功遍历, 字符串列表)。"""
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

    # ------------------------------------------------------------------
    # 单规则匹配
    # ------------------------------------------------------------------

    def _match_rule(
        self,
        rule: _PackerRule,
        so_basenames: dict[str, str],
        file_paths: list[str],
        dex_strings: list[str],
    ) -> _Hit:
        hit = _Hit(rule=rule)

        # 1) .so 库名（basename 精确匹配，大小写不敏感）
        for so in rule.so_names:
            key = so.lower()
            # 精确 basename 命中
            if key in so_basenames:
                hit.evidences.append(
                    Evidence(source="native", location=so_basenames[key], snippet=f"so={so}")
                )
                hit.matched_features.append(f"so:{so}")
                continue
            # 容忍规则写不带 .so 后缀 / 库名为前缀（如 libnllvm* / libsgmainso*）的情况
            if not key.endswith(".so"):
                for base, path in so_basenames.items():
                    if base.startswith(key):
                        hit.evidences.append(
                            Evidence(source="native", location=path, snippet=f"so~={so}")
                        )
                        hit.matched_features.append(f"so:{so}")
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
                    break

        # 3) DEX 类前缀/字符串特征（子串匹配，大小写敏感保留原样）
        for prefix in rule.dex_prefixes:
            for s in dex_strings:
                if prefix in s:
                    hit.evidences.append(
                        Evidence(
                            source="dex",
                            location=prefix,
                            snippet=_truncate(s),
                        )
                    )
                    hit.matched_features.append(f"dex:{prefix}")
                    break

        return hit

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------

    def _load_rules(self) -> tuple[list[_PackerRule], list[str], str]:
        """加载并规整规则，返回 (规则列表, 默认可调证据, where 后缀)。"""
        data = load_rules(_RULES_NAME)

        raw_packers: object
        evidence: list[str] = list(_DEFAULT_EVIDENCE_TO_OBTAIN)
        where_suffix = "（加固厂商）"

        if isinstance(data, dict):
            raw_packers = data.get("packers", [])
            meta = data.get("meta")
            if isinstance(meta, dict):
                ev = _as_str_list(meta.get("evidence_to_obtain"))
                if ev:
                    evidence = ev
                suffix = meta.get("where_to_request_suffix")
                if isinstance(suffix, str):
                    where_suffix = suffix
        elif isinstance(data, list):
            # 容忍顶层直接是 list[规则] 的写法
            raw_packers = data
        else:
            logger.warning(
                "[%s] 规则顶层应为 dict/list，实际 %s；无规则可用",
                self.name,
                type(data).__name__,
            )
            raw_packers = []

        rules = self._parse_rules(raw_packers)
        return rules, evidence, where_suffix

    def _parse_rules(self, raw: object) -> list[_PackerRule]:
        if not isinstance(raw, list):
            logger.warning("[%s] packers 字段应为 list，实际 %s", self.name, type(raw).__name__)
            return []
        rules: list[_PackerRule] = []
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
            rules.append(
                _PackerRule(
                    name=name.strip(),
                    vendor=vendor.strip(),
                    so_names=_as_str_list(entry.get("so_names")),
                    files=_as_str_list(entry.get("files")),
                    dex_prefixes=_as_str_list(entry.get("dex_prefixes")),
                    note=_str_or_empty(entry.get("note")),
                )
            )
        return rules

    @staticmethod
    def _lead_notes(hit: _Hit) -> str:
        parts: list[str] = []
        if hit.rule.note:
            parts.append(hit.rule.note)
        if hit.matched_features:
            parts.append("命中特征：" + "、".join(hit.matched_features))
        parts.append(
            "加固导致真实 DEX 不可见，静态端点/SDK/支付线索可能不完整；"
            "建议脱壳或真机动态补全后再次分析。"
        )
        return " ".join(parts)


# ---------------------------------------------------------------------------
# 模块级工具函数
# ---------------------------------------------------------------------------


def _str_or_empty(value: object) -> str:
    """规则字段取 str（去空白），非 str / None → 空串。"""
    return value.strip() if isinstance(value, str) else ""


def _as_str_list(value: object) -> list[str]:
    """把规则字段规整为 str 列表（容忍 None / 非 list / 含非 str 元素）。"""
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _truncate(text: str, limit: int = _SNIPPET_MAX) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "…"
