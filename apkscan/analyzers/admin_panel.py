"""admin_panel 分析器：从 URL 里识别诈骗 App 的**后台管理系统 / 控制台**。

后台是团伙运营控制中心（聊天 / 交易 / 成员 / 受害人数据都在此），是「提取服务器日志」诉求里
最高价值的调证落点。本分析器从 dex 字符串与文本资源里抽**带 host 的完整 URL**，按两类特征识别：
  - host 子域名指纹（admin. / manage. / houtai. 等）
  - URL path 后台特征（/wp-admin、/api/admin/、/admin、/dashboard 等）
并用 ``infra.classify_domain`` 排除第三方 SDK / CDN / 公共基础设施的管理控制台（如
console.firebase.google.com）；每个 App 自有后端 host 产一条 ADMIN_PANEL 线索，
``evidence_to_obtain`` 直接给出"向云厂商 / IDC 调后台服务器与运营 / 登录日志"的调证落点。

置信分级（宁缺毋滥）：
  - 强档特征 + host 研判为「建议调证」→ HIGH·建议调证
  - 泛 /admin 路径或 host 研判不确定 → MEDIUM·待核
  - 私网 / 内网 host、已知基础设施 host → 跳过（无对外调证落点）

约束：只用 AnalysisContext 公开接口（dex_strings / list_files / read_file），规则数据化
（rules/admin_panels.yaml + load_rules），URL 正则字符类有界（无灾难性回溯），
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

_RULES_NAME = "admin_panels"
_MAX_DEX_STRINGS = 200_000
# 单个文本资源读取上限（避免极端大文件拖慢 / 撑内存；H5 bundle 通常远小于此）。
_MAX_RESOURCE_BYTES = 4_000_000
# 文本资源扫描总字节预算（dex 已覆盖代码内 URL；超出即停，防大样本拖慢）。
_MAX_TOTAL_RESOURCE_BYTES = 64_000_000

# 有界 URL 提取正则（字符类、无嵌套量词 → 线性、无 ReDoS）。
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]}\\]+", re.IGNORECASE)

_DEFAULT_WHERE = "域名注册商 / 云服务商（IDC）"


@dataclass
class _Pattern:
    """单条后台识别规则（host_regex 命中 host，path_regex 命中 path）。"""

    id: str
    title: str
    tier: str  # "high" | "review"
    path_re: re.Pattern[str] | None = None
    host_re: re.Pattern[str] | None = None


@dataclass
class _Hit:
    """单个后端 host 的后台命中累积。"""

    host: str
    host_advice: str
    best_tier: str = "review"
    titles: set[str] = field(default_factory=set)
    sample_url: str = ""
    sample_source: str = "dex"
    sample_location: str = ""


class AdminPanelAnalyzer(BaseAnalyzer):
    """识别后台管理系统入口，产出 category=ADMIN_PANEL 的调证线索。"""

    name: str = "admin_panel"
    requires: list[str] = []  # URL 文本通用（dex/H5），缺数据自然空跑

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        patterns, evidence_to_obtain, where_to_request = self._load_rules()
        if not patterns:
            logger.info("[%s] 无可用后台识别规则，跳过", self.name)
            result.meta["admin_panel_count"] = 0
            return result

        hits: dict[str, _Hit] = {}

        # 1) DEX 字符串（代码内硬编码 URL）。
        _ok, dex_strings = collect_dex_strings(ctx, self.name, max_strings=_MAX_DEX_STRINGS)
        for s in dex_strings:
            self._scan_text(s, "dex", "dex_strings", patterns, hits)

        # 2) 文本资源（H5 / JS / json / xml 里的接口地址）。
        self._scan_resources(ctx, patterns, hits)

        for _host, hit in sorted(hits.items()):
            result.leads.append(self._build_lead(hit, evidence_to_obtain, where_to_request))

        result.meta["admin_panel_count"] = len(result.leads)
        if result.leads:
            logger.info(
                "[%s] 识别后台管理入口 %d 个：%s",
                self.name,
                len(result.leads),
                "、".join(sorted(hits)),
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
        patterns: list[_Pattern],
        hits: dict[str, _Hit],
    ) -> None:
        """从一段文本里抽 URL → 命中后台特征则累积到 hits（按 host 去重）。绝不抛。"""
        if not text or "://" not in text:
            return
        try:
            for m in _URL_RE.finditer(text):
                url = strip_url_tail(m.group(0))
                host = host_from_url(url)
                if not host or host_is_private(host):
                    continue
                matched = self._match(url, host, patterns)
                if matched is None:
                    continue
                advice, _reason = infra.classify_domain(host)
                if advice == infra.ADVICE_SKIP:
                    continue  # 已知 SDK/CDN/公共基础设施的管理控制台，非调证落点
                tier, title = matched
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
                hit.titles.add(title)
                if tier == "high":
                    if hit.best_tier != "high":  # 升 high 时换更有力的样本 URL 作证据
                        hit.sample_url, hit.sample_source, hit.sample_location = url, source, location
                    hit.best_tier = "high"
        except Exception:
            logger.exception("[%s] 扫描文本 URL 失败：%s", self.name, location)

    def _scan_resources(
        self, ctx: "AnalysisContext", patterns: list[_Pattern], hits: dict[str, _Hit]
    ) -> None:
        """扫描 APK 内文本资源（H5/JS/json/xml）里的 URL。绝不抛。"""
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
            self._scan_text(text, "resource", path, patterns, hits)

    @staticmethod
    def _path_of(url: str) -> str:
        """取 URL 中 host 之后的 path（含起始 ``/``）；无 path → 空串。"""
        after = url.split("://", 1)[-1]
        slash = after.find("/")
        return after[slash:] if slash >= 0 else ""

    def _match(self, url: str, host: str, patterns: list[_Pattern]) -> tuple[str, str] | None:
        """返回 (tier, title)；high 优先短路；都不命中 → None。"""
        path = self._path_of(url)
        best: tuple[str, str] | None = None
        for p in patterns:
            hit = False
            if p.host_re is not None and p.host_re.search(host):
                hit = True
            elif p.path_re is not None and path and p.path_re.search(path):
                hit = True
            if not hit:
                continue
            if p.tier == "high":
                return ("high", p.title)
            best = best or ("review", p.title)
        return best

    # ------------------------------------------------------------------
    # 出线索
    # ------------------------------------------------------------------

    def _build_lead(
        self, hit: _Hit, evidence_to_obtain: list[str], where_to_request: str
    ) -> Lead:
        if hit.best_tier == "high" and hit.host_advice == infra.ADVICE_INVESTIGATE:
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
            category=LeadCategory.ADMIN_PANEL,
            value=hit.host,
            subject=None,
            where_to_request=where_to_request,
            evidence_to_obtain=list(evidence_to_obtain),
            confidence=confidence,
            source_refs=[ev],
            notes="后台特征：" + "、".join(sorted(hit.titles)),
            advice=advice,
        )

    # ------------------------------------------------------------------
    # 规则加载
    # ------------------------------------------------------------------

    def _load_rules(self) -> tuple[list[_Pattern], list[str], str]:
        data = load_rules(_RULES_NAME)
        if not isinstance(data, dict):
            if data:
                logger.warning("[%s] 规则顶层应为 dict，实际 %s", self.name, type(data).__name__)
            return [], [], _DEFAULT_WHERE

        evidence_to_obtain = as_str_list(data.get("evidence_to_obtain"))
        where_to_request = str_or_empty(data.get("where_to_request")) or _DEFAULT_WHERE

        patterns: list[_Pattern] = []
        raw = data.get("patterns")
        if not isinstance(raw, list):
            logger.warning("[%s] patterns 字段应为 list，实际 %s", self.name, type(raw).__name__)
            return [], evidence_to_obtain, where_to_request

        for entry in raw:
            if not isinstance(entry, dict):
                continue
            pid = entry.get("id")
            if not isinstance(pid, str) or not pid.strip():
                logger.warning("[%s] 跳过缺 id 的规则条目：%r", self.name, entry)
                continue
            tier = "high" if str_or_empty(entry.get("tier")).lower() == "high" else "review"
            path_re = self._compile(entry.get("path_regex"), pid)
            host_re = self._compile(entry.get("host_regex"), pid)
            if path_re is None and host_re is None:
                logger.warning("[%s] 跳过无 path_regex/host_regex 的规则：%s", self.name, pid)
                continue
            patterns.append(
                _Pattern(
                    id=pid.strip(),
                    title=str_or_empty(entry.get("title")) or pid.strip(),
                    tier=tier,
                    path_re=path_re,
                    host_re=host_re,
                )
            )
        return patterns, evidence_to_obtain, where_to_request

    def _compile(self, pattern: object, pid: str) -> re.Pattern[str] | None:
        if not isinstance(pattern, str) or not pattern.strip():
            return None
        try:
            return re.compile(pattern, re.IGNORECASE)
        except re.error:
            logger.warning("[%s] 规则正则编译失败，跳过：%s", self.name, pid)
            return None
