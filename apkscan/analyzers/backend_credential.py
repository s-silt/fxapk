"""backend_credential 分析器：从已扣押 APK 静态抠**后端 / 管理凭据**（取证分析，非主动攻击）。

诈骗 App 常把后台 / 数据库 / 云凭据硬编码进包——Basic-Auth、DB 连接串（含 user:pass）、
JDBC password、云 AccessKey。提取它们 = 对证物做取证分析，是「弱口令 / 已知凭据」的**合规
版本**：不去猜、不主动爆破远程服务器，只抠 App 自己带着的凭据，供**有权机关依法**登录取证 /
据归属向云厂商调服务器镜像与日志。**严禁未授权使用**（写进 Lead.notes）。

约束：只用 AnalysisContext 公开接口、规则数据化（rules/backend_credentials.yaml）、正则字符类
有界无 ReDoS、资源扫描带上限、never-throw try/except + logging、全 type hints、宁缺毋滥
（只取高精度结构化凭据形态，误报近零）。
"""

from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from apkscan.analyzers._common import (
    TEXT_RESOURCE_PREFIXES,
    TEXT_RESOURCE_SUFFIXES,
    collect_dex_strings,
    is_text_resource,
    str_or_empty,
    truncate,
)
from apkscan.core.models import AnalyzerResult, Confidence, Evidence, Lead, LeadCategory
from apkscan.core.registry import BaseAnalyzer, load_rules

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_RULES_NAME = "backend_credentials"
_MAX_DEX_STRINGS = 200_000
_MAX_RESOURCE_BYTES = 4_000_000
_MAX_TOTAL_RESOURCE_BYTES = 64_000_000

_DECODE_BASIC = "base64_userpass"
_DEFAULT_WHERE = "无直接调证对象（凭据供有权机关依法登录取证 / 据服务器归属向云厂商调镜像与日志）"
_COMPLIANCE = "高敏：硬编码后端/管理凭据，仅供有权机关依法登录取证 / 调服务器镜像与日志，严禁未授权使用"


@dataclass
class _Pattern:
    id: str
    title: str
    regex: re.Pattern[str]
    decode: str = ""


class BackendCredentialAnalyzer(BaseAnalyzer):
    """抠 APK 内硬编码后端 / 管理凭据，产出 category=BACKEND_CREDENTIAL 的高敏取证线索。"""

    name: str = "backend_credential"
    requires: list[str] = []

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        patterns, where, evidence = self._load_rules()
        if not patterns:
            logger.info("[%s] 无可用后端凭据规则，跳过", self.name)
            return result

        # value -> (title, source, location)
        hits: dict[str, tuple[str, str, str]] = {}
        _ok, dex_strings = collect_dex_strings(ctx, self.name, max_strings=_MAX_DEX_STRINGS)
        for s in dex_strings:
            self._scan_text(s, "dex", "dex_strings", patterns, hits)
        self._scan_resources(ctx, patterns, hits)

        for value, (title, source, location) in sorted(hits.items()):
            try:
                result.leads.append(self._build_lead(value, title, source, location, where, evidence))
            except Exception:
                logger.exception("[%s] 构建线索失败（已跳过）", self.name)

        result.meta["backend_credential_count"] = len(result.leads)
        if result.leads:
            logger.info("[%s] 抠出硬编码后端/管理凭据 %d 条（高敏）", self.name, len(result.leads))
        return result

    def _scan_text(
        self,
        text: str,
        source: str,
        location: str,
        patterns: list[_Pattern],
        hits: dict[str, tuple[str, str, str]],
    ) -> None:
        """从一段文本抽硬编码凭据，去重累积。绝不抛。"""
        if not text:
            return
        try:
            for p in patterns:
                for m in p.regex.finditer(text):
                    value = self._extract_value(p, m)
                    if value:
                        hits.setdefault(value, (p.title, source, location))
        except Exception:
            logger.exception("[%s] 扫描文本失败：%s", self.name, location)

    @staticmethod
    def _extract_value(p: _Pattern, m: re.Match[str]) -> str:
        """从命中提取凭据值。Basic-Auth：base64 解码捕获组、要求解出 user:pass。其余取整段命中。"""
        if p.decode == _DECODE_BASIC:
            try:
                raw = base64.b64decode(m.group(1), validate=True)
                decoded = raw.decode("utf-8")
            except Exception:  # noqa: BLE001 — 非合法 base64 / 非 utf-8 → 非 Basic 凭据，跳过
                return ""
            # 要求解出 user:pass（含冒号、可打印），否则不是凭据。
            if ":" not in decoded or not decoded.isprintable():
                return ""
            return f"Basic {decoded}"
        return m.group(0)

    def _scan_resources(
        self, ctx: "AnalysisContext", patterns: list[_Pattern], hits: dict[str, tuple[str, str, str]]
    ) -> None:
        """扫描 APK 内文本资源（H5/JS/json/配置里的硬编码凭据）。绝不抛。"""
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

    def _build_lead(
        self,
        value: str,
        title: str,
        source: str,
        location: str,
        where: str,
        evidence: list[str],
    ) -> Lead:
        ev = Evidence(source=source, location=location, snippet=truncate(value, 120))
        return Lead(
            category=LeadCategory.BACKEND_CREDENTIAL,
            value=value,
            subject=None,
            where_to_request=where,
            evidence_to_obtain=list(evidence),
            confidence=Confidence.HIGH,
            source_refs=[ev],
            notes=f"{_COMPLIANCE}（{title}）",
            advice="建议调证",
        )

    def _load_rules(self) -> tuple[list[_Pattern], str, list[str]]:
        from apkscan.core.textutil import as_str_list

        data = load_rules(_RULES_NAME)
        if not isinstance(data, dict):
            if data:
                logger.warning("[%s] 规则顶层应为 dict，实际 %s", self.name, type(data).__name__)
            return [], _DEFAULT_WHERE, []
        where = str_or_empty(data.get("where_to_request")) or _DEFAULT_WHERE
        evidence = as_str_list(data.get("evidence_to_obtain"))
        patterns: list[_Pattern] = []
        for entry in data.get("patterns") or []:
            if not isinstance(entry, dict):
                continue
            pid = entry.get("id")
            raw = entry.get("regex")
            if not isinstance(pid, str) or not pid.strip() or not isinstance(raw, str):
                logger.warning("[%s] 跳过缺 id/regex 的规则：%r", self.name, entry)
                continue
            try:
                compiled = re.compile(raw)
            except re.error:
                logger.warning("[%s] 规则正则编译失败，跳过：%s", self.name, pid)
                continue
            patterns.append(
                _Pattern(
                    id=pid.strip(),
                    title=str_or_empty(entry.get("title")) or pid.strip(),
                    regex=compiled,
                    decode=str_or_empty(entry.get("decode")),
                )
            )
        return patterns, where, evidence
