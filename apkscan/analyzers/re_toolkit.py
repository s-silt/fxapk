"""逆向 / Hook / 反检测工具链识别分析器 —— 识别样本内置的 RE/hook/反分析能力。

职责：
- 用 ctx.native_libs() + ctx.list_files() + ctx.dex_strings() 三路匹配 hook 框架 / 反检测工具特征。
- 规则来自 apkscan/rules/re_toolkit.yaml（ShadowHook/ByteHook/GlossHook/LSPlant/pine/xDL/Dobby、
  LibcoreSyscall/HiddenApiBypass/Frida Gadget 等），每条含 so 名 / 特征文件 / dex 包前缀 + category + anti_frida。
- 命中产出：
    * Finding(category="anti_analysis", id="RE-TOOLKIT-DETECTED")——列出识别到的工具与能力；
    * meta["re_toolkit"] = [{name, category, capability, strong}]（供 digest/串案）；
    * meta["hook_frameworks"] = [名]（结合无障碍权限研判运行时劫持）；
    * meta["anti_frida"] = bool（命中 anti_frida 工具 → 供 capture_plan 预判 frida 抓包会被击败、换打法）。

★ 定位与边界：本分析器是**防御性威胁情报**——识别样本内置了哪些 hook/反检测工具以研判其能力、
  预判动态抓包可行性、并作团伙工具链指纹串案。只识别、不利用。

约束：
- 只依赖 AnalysisContext 公开接口，禁止 import androguard。
- 单点解析异常 try/except + logging，不让单条规则/单个数据源炸掉整个 analyze；不静默 pass。
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
    Evidence,
    Finding,
    Severity,
)
from apkscan.core.registry import BaseAnalyzer, load_rules

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_RULES_NAME = "re_toolkit"

# DEX 字符串扫描上限（与 packing 一致，避免极端样本扫描过久）。
_MAX_DEX_STRINGS = 200_000
_SNIPPET_MAX = 200

# category → 人读分组名。
_CATEGORY_LABELS: dict[str, str] = {
    "hook_framework": "Hook 框架（运行时劫持能力）",
    "evasion": "反检测 / 反分析",
    "instrumentation": "插桩 / 注入",
}


@dataclass
class _ToolRule:
    """单条工具指纹规则（从 YAML 规整而来）。"""

    name: str
    category: str
    capability: str = ""
    so_names: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    dex_prefixes: list[str] = field(default_factory=list)
    anti_frida: bool = False
    note: str = ""


@dataclass
class _Hit:
    """一条规则的命中证据集合。

    strong：so 名 / 特征文件命中（工具运行时实证）；否则仅 dex 包名命中（中证据）。
    """

    rule: _ToolRule
    evidences: list[Evidence] = field(default_factory=list)
    matched_features: list[str] = field(default_factory=list)
    strong: bool = False


class ReToolkitAnalyzer(BaseAnalyzer):
    """识别样本内置的 hook 框架 / 反检测工具，产 anti_analysis Finding + 抓包预判 meta。"""

    name: str = "re_toolkit"
    requires: list[str] = ["apk"]  # Android 专属；IPA 上 pipeline 自动 skipped

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        rules = self._load_rules()
        if not rules:
            logger.info("[%s] 无可用工具指纹规则，跳过识别", self.name)
            self._set_empty_meta(result)
            return result

        # 三路数据源各自 try/except，单源失败不影响其余。
        so_basenames = _collect_so_basenames_shared(ctx, self.name)
        file_paths = _collect_file_paths_shared(ctx, self.name)
        _dex_ok, dex_strings = _collect_dex_strings_shared(
            ctx, self.name, max_strings=_MAX_DEX_STRINGS
        )

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
            logger.info("[%s] 未识别到已知 hook/反检测工具特征", self.name)
            self._set_empty_meta(result)
            return result

        anti_frida = any(h.rule.anti_frida for h in hits)
        result.meta["re_toolkit"] = [
            {
                "name": h.rule.name,
                "category": h.rule.category,
                "capability": h.rule.capability,
                "strong": h.strong,
            }
            for h in hits
        ]
        result.meta["hook_frameworks"] = [
            h.rule.name for h in hits if h.rule.category == "hook_framework"
        ]
        result.meta["anti_frida"] = anti_frida
        result.findings.append(self._build_finding(hits, anti_frida))
        return result

    @staticmethod
    def _set_empty_meta(result: AnalyzerResult) -> None:
        result.meta["re_toolkit"] = []
        result.meta["hook_frameworks"] = []
        result.meta["anti_frida"] = False

    # ------------------------------------------------------------------
    # 单规则匹配
    # ------------------------------------------------------------------

    def _match_rule(
        self,
        rule: _ToolRule,
        so_basenames: dict[str, str],
        file_paths: list[str],
        dex_strings: list[str],
    ) -> _Hit:
        hit = _Hit(rule=rule)

        # 1) .so 库名（basename 精确匹配，大小写不敏感）→ 强证据
        for so in rule.so_names:
            key = so.lower()
            if key in so_basenames:
                ev = Evidence(source="native", location=so_basenames[key], snippet=f"so={so}")
                hit.evidences.append(ev)
                hit.matched_features.append(f"so:{so}")
                hit.strong = True

        # 2) 特征文件（路径子串匹配，大小写不敏感）→ 强证据
        lowered_files = [(p, p.lower()) for p in file_paths]
        for feat in rule.files:
            needle = feat.lower()
            for orig, low in lowered_files:
                if needle in low:
                    ev = Evidence(source="resource", location=orig, snippet=f"file~={feat}")
                    hit.evidences.append(ev)
                    hit.matched_features.append(f"file:{feat}")
                    hit.strong = True
                    break

        # 3) DEX 类包前缀（子串匹配，大小写敏感保留原样）→ 中证据
        for prefix in rule.dex_prefixes:
            for s in dex_strings:
                if prefix in s:
                    ev = Evidence(source="dex", location=prefix, snippet=_truncate(s))
                    hit.evidences.append(ev)
                    hit.matched_features.append(f"dex:{prefix}")
                    break

        return hit

    # ------------------------------------------------------------------
    # Finding 组装
    # ------------------------------------------------------------------

    def _build_finding(self, hits: list[_Hit], anti_frida: bool) -> Finding:
        """据命中工具组一条 Finding：按 category 分组列出工具 + 能力 + 抓包/劫持研判。"""
        has_hook = any(h.rule.category == "hook_framework" for h in hits)
        has_instrumentation = any(h.rule.category == "instrumentation" for h in hits)
        # 反 frida（直 syscall 等，罕见于正常 app）或内嵌 frida gadget → HIGH；
        # 仅 hook 框架（bytehook/shadowhook 亦广泛用于合法 APM/崩溃监控，dual-use）→ MEDIUM，勿单凭此定性。
        severity = Severity.HIGH if (anti_frida or has_instrumentation) else Severity.MEDIUM

        # 按 category 分组列工具。
        grouped: dict[str, list[str]] = {}
        for h in hits:
            label = _CATEGORY_LABELS.get(h.rule.category, h.rule.category)
            cap = f"（{h.rule.capability}）" if h.rule.capability else ""
            grouped.setdefault(label, []).append(f"{h.rule.name}{cap}")
        group_lines = [f"  · {label}：{'、'.join(items)}" for label, items in grouped.items()]

        desc_parts = [
            "检测到样本内置逆向 / hook / 反检测工具链：\n" + "\n".join(group_lines) + "。",
        ]
        if has_hook:
            desc_parts.append(
                "内置 hook 框架 = 具备运行时 hook 能力（★ 亦广泛用于合法 APM / 崩溃监控，勿单凭此定性）；"
                "若样本同时申请无障碍/辅助功能权限、或与反检测工具共现，则高度疑似无障碍远控 / "
                "劫持银行·支付 app（结合 REMOTE_CONTROL 线索研判）。"
            )
        if anti_frida:
            anti_names = "、".join(h.rule.name for h in hits if h.rule.anti_frida)
            desc_parts.append(
                f"★ 命中反 frida 工具（{anti_names}）：这类走直 syscall / 内存加载等手段绕过 libc/Java hook 层，"
                "fxapk 的 frida 动态抓包可能**静默失效**（抓不到≠没有）。"
            )

        recommendation_parts = [
            "把内置的 hook/反检测工具链作为团伙工具链指纹并簇串案（同套自研工具疑同团伙）。",
        ]
        if anti_frida:
            recommendation_parts.append(
                "动态抓包别只靠 frida：改走旁路 pcap（PCAPdroid / 网关 tcpdump）拿接入节点、"
                "tls-keylog 离线解 TLS、或内核层抓包；frida 秒退/无产出优先怀疑被反检测击败而非样本干净。"
            )
        if has_hook:
            recommendation_parts.append(
                "核查无障碍/辅助功能、投影录屏权限与 AccessibilityService，研判是否劫持第三方 app。"
            )

        return Finding(
            id="RE-TOOLKIT-DETECTED",
            title="样本内置逆向/Hook/反检测工具链（疑运行时劫持 / 反抓包能力）",
            severity=severity,
            category="anti_analysis",
            description=" ".join(desc_parts),
            recommendation=" ".join(recommendation_parts),
            evidences=[ev for h in hits for ev in h.evidences],
            references=["https://developer.android.com/topic/security"],
        )

    # ------------------------------------------------------------------
    # 规则加载
    # ------------------------------------------------------------------

    def _load_rules(self) -> list[_ToolRule]:
        data = load_rules(_RULES_NAME)
        if isinstance(data, dict):
            raw = data.get("tools", [])
        elif isinstance(data, list):
            raw = data
        else:
            logger.warning(
                "[%s] 规则顶层应为 dict/list，实际 %s；无规则可用",
                self.name,
                type(data).__name__,
            )
            return []
        return self._parse_rules(raw)

    def _parse_rules(self, raw: object) -> list[_ToolRule]:
        if not isinstance(raw, list):
            logger.warning("[%s] tools 字段应为 list，实际 %s", self.name, type(raw).__name__)
            return []
        rules: list[_ToolRule] = []
        for entry in raw:
            if not isinstance(entry, dict):
                logger.warning("[%s] 跳过非 dict 规则条目：%r", self.name, entry)
                continue
            name = entry.get("name")
            category = entry.get("category")
            if not isinstance(name, str) or not name.strip():
                logger.warning("[%s] 跳过缺少 name 的规则条目：%r", self.name, entry)
                continue
            if not isinstance(category, str) or not category.strip():
                logger.warning("[%s] 跳过缺少 category 的规则条目：%s", self.name, name)
                continue
            rules.append(
                _ToolRule(
                    name=name.strip(),
                    category=category.strip(),
                    capability=_str_or_empty(entry.get("capability")),
                    so_names=_as_str_list(entry.get("so_names")),
                    files=_as_str_list(entry.get("files")),
                    dex_prefixes=_as_str_list(entry.get("dex_prefixes")),
                    anti_frida=bool(entry.get("anti_frida", False)),
                    note=_str_or_empty(entry.get("note")),
                )
            )
        return rules


def _truncate(text: str, limit: int = _SNIPPET_MAX) -> str:
    return _truncate_shared(text, limit)
