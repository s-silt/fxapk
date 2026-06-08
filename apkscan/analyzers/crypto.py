"""crypto 分析器：弱加密 / 硬编码密钥检测 → Finding（风险佐证 / 取证意义）。

职责（见设计文档 §4 "crypto" 行）：
  - 扫 ctx.dex_strings() + 文本资源（assets/res/raw 等），匹配明确出现的弱加密特征：
    MD5 / SHA-1、DES / 3DES、AES/ECB、"AES/ECB/" transformation、RC4、默认 ECB 等。
  - 启发式识别硬编码密钥 / IV（密钥相关命名 + 定长十六进制 / Base64 常量同现）。
  - 识别内嵌的大块 Base64 常量（疑似内嵌密钥 / 证书 / 加密载荷 / 隐藏配置）。
  - 命中 → Finding(category="crypto", severity 多为 MEDIUM, references 含 "CWE-327")。
  - 统计写入 AnalyzerResult.meta，供报告"技术附录·crypto"区使用。

设计取向：**低误报**——只报“算法名明确出现”的字面量（getInstance 参数串 / 算法常量），
硬编码 / Base64 走带阈值的启发式并在 description 提示人工复核。

约束：
  - 只依赖 AnalysisContext 公开接口（dex_strings / list_files / read_file），禁止 import androguard。
  - 规则经 registry.load_rules("crypto") 读取。
  - 单点解析异常 try/except + logging，不让单条规则 / 单个数据源炸掉整个 analyze；不静默 pass。
  - 全程 type hints。
"""

from __future__ import annotations

import logging
import posixpath
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

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

_RULES_NAME = "crypto"

_SEVERITY_BY_NAME = {s.name: s for s in Severity}

# DEX / 资源字符串扫描上限：样本字符串池可能很大，避免极端情况扫描过久。
_MAX_STRINGS = 300_000

# 证据片段截断长度。
_SNIPPET_MAX = 200

# 文本资源后缀（仅扫这些，避免对图片 / so 等二进制误判与浪费）。
_TEXT_SUFFIXES: tuple[str, ...] = (
    ".json",
    ".xml",
    ".txt",
    ".js",
    ".html",
    ".htm",
    ".properties",
    ".cfg",
    ".conf",
    ".ini",
    ".yaml",
    ".yml",
    ".smali",
    ".java",
    ".kt",
    ".csv",
    ".sql",
    ".gradle",
)

# 资源扫描时单文件读取上限（字节），防止超大文件拖慢。
_MAX_RESOURCE_BYTES = 2_000_000

# 资源文件总扫描数上限。
_MAX_RESOURCE_FILES = 2_000

# Base64 blob 识别正则：>= min_length 的连续 Base64 字符块（允许内部换行）。
# 实际阈值由规则 min_length 控制，这里先抓候选再按长度过滤。
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# 硬编码常量候选：引号内的十六进制 / Base64 风格常量。
_HEX_CONST = re.compile(r"\b[0-9a-fA-F]{16,}\b")
_QUOTED_CONST = re.compile(r"[\"']([A-Za-z0-9+/=]{12,})[\"']")

# 默认硬编码密钥相关命名提示（规则缺失时兜底）。
_DEFAULT_NAME_HINTS: tuple[str, ...] = (
    "secretkey",
    "aeskey",
    "deskey",
    "encryptkey",
    "iv=",
    "ivspec",
    "secretkeyspec",
    "ivparameterspec",
)

_DEFAULT_KEY_LENGTHS: tuple[int, ...] = (16, 24, 32, 44, 64)


# ---------------------------------------------------------------------------
# 规则模型
# ---------------------------------------------------------------------------


@dataclass
class _PatternRule:
    """单条弱算法 / 不安全模式规则。"""

    id: str
    title: str
    severity: Severity
    needles: list[str]
    description: str = ""
    recommendation: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class _KeyRule:
    """硬编码密钥 / IV 启发式规则。"""

    id: str = "CRYPTO-HARDCODED-KEY"
    title: str = "疑似硬编码密钥 / IV"
    severity: Severity = Severity.MEDIUM
    name_hints: list[str] = field(default_factory=lambda: list(_DEFAULT_NAME_HINTS))
    candidate_lengths: list[int] = field(default_factory=lambda: list(_DEFAULT_KEY_LENGTHS))
    description: str = ""
    recommendation: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class _Base64Rule:
    """大块 Base64 常量规则。"""

    id: str = "CRYPTO-BASE64-BLOB"
    title: str = "内嵌大块 Base64 常量"
    severity: Severity = Severity.LOW
    min_length: int = 256
    max_reports: int = 20
    description: str = ""
    recommendation: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class _CryptoRules:
    patterns: list[_PatternRule] = field(default_factory=list)
    keys: _KeyRule | None = None
    base64: _Base64Rule | None = None


class CryptoAnalyzer(BaseAnalyzer):
    """检测弱加密 / 硬编码密钥，产出 category=\"crypto\" 的 Finding。"""

    name: str = "crypto"
    requires: list[str] = []  # 纯静态扫描，永远可用

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        rules = self._load_rules()
        if not rules.patterns and rules.keys is None and rules.base64 is None:
            logger.info("[%s] 无可用 crypto 规则，跳过检测", self.name)
            result.meta = {"strings_scanned": 0, "resources_scanned": 0, "findings": 0}
            return result

        # 收集待扫描的 (来源标签, location, 文本) 三元组。各数据源各自 try/except。
        dex_items, dex_count = self._collect_dex_strings(ctx)
        res_items, res_count = self._collect_resource_texts(ctx)
        scan_items = dex_items + res_items

        # 1) 弱算法 / 不安全模式（明确字面量匹配）。
        try:
            self._scan_patterns(rules.patterns, scan_items, result)
        except Exception:  # noqa: BLE001 — 单点失败不应炸掉整个 analyze
            logger.exception("[%s] 弱算法模式扫描失败", self.name)
            self._record_error(result, "弱算法模式扫描失败（详见日志）")

        # 2) 硬编码密钥 / IV 启发式。
        if rules.keys is not None:
            try:
                self._scan_hardcoded_keys(rules.keys, scan_items, result)
            except Exception:  # noqa: BLE001
                logger.exception("[%s] 硬编码密钥启发式扫描失败", self.name)
                self._record_error(result, "硬编码密钥启发式扫描失败（详见日志）")

        # 3) 大块 Base64 常量。
        if rules.base64 is not None:
            try:
                self._scan_base64_blobs(rules.base64, scan_items, result)
            except Exception:  # noqa: BLE001
                logger.exception("[%s] Base64 大块常量扫描失败", self.name)
                self._record_error(result, "Base64 大块常量扫描失败（详见日志）")

        result.meta = {
            "strings_scanned": dex_count,
            "resources_scanned": res_count,
            "findings": len(result.findings),
            "finding_ids": sorted({f.id for f in result.findings}),
        }
        return result

    # ------------------------------------------------------------------
    # 数据源采集（各自 try/except）
    # ------------------------------------------------------------------

    def _collect_dex_strings(
        self, ctx: "AnalysisContext"
    ) -> tuple[list[tuple[str, str, str]], int]:
        """收集 DEX 字符串。返回 ([(source, location, text)], 扫描计数)。"""
        items: list[tuple[str, str, str]] = []
        count = 0
        try:
            for s in ctx.dex_strings():
                if count >= _MAX_STRINGS:
                    logger.warning(
                        "[%s] DEX 字符串超过上限 %d，截断扫描", self.name, _MAX_STRINGS
                    )
                    break
                if isinstance(s, str) and s:
                    items.append(("dex", "dex_strings", s))
                    count += 1
        except Exception:  # noqa: BLE001
            logger.exception("[%s] 遍历 dex_strings 失败", self.name)
        return items, count

    def _collect_resource_texts(
        self, ctx: "AnalysisContext"
    ) -> tuple[list[tuple[str, str, str]], int]:
        """收集文本资源内容。返回 ([(source, location, text)], 扫描文件数)。"""
        items: list[tuple[str, str, str]] = []
        try:
            paths = list(ctx.list_files())
        except Exception:  # noqa: BLE001
            logger.exception("[%s] 读取 list_files 失败", self.name)
            return items, 0

        scanned = 0
        for path in paths:
            if not isinstance(path, str):
                continue
            if not self._is_text_resource(path):
                continue
            if scanned >= _MAX_RESOURCE_FILES:
                logger.warning(
                    "[%s] 文本资源数超过上限 %d，截断扫描", self.name, _MAX_RESOURCE_FILES
                )
                break
            text = self._read_text(ctx, path)
            if text is None:
                continue
            items.append(("resource", path, text))
            scanned += 1
        return items, scanned

    def _is_text_resource(self, path: str) -> bool:
        base = posixpath.basename(path.replace("\\", "/")).lower()
        return base.endswith(_TEXT_SUFFIXES)

    def _read_text(self, ctx: "AnalysisContext", path: str) -> str | None:
        """读取并解码文本资源；失败 / 非文本返回 None，记 debug 不抛出。"""
        try:
            raw = ctx.read_file(path)
        except Exception:  # noqa: BLE001 — 单文件读取失败不影响其余
            logger.exception("[%s] 读取资源失败：%s", self.name, path)
            return None
        if not raw:
            return None
        if len(raw) > _MAX_RESOURCE_BYTES:
            raw = raw[:_MAX_RESOURCE_BYTES]
        try:
            return raw.decode("utf-8", errors="ignore")
        except Exception:  # noqa: BLE001
            logger.debug("[%s] 资源解码失败，跳过：%s", self.name, path, exc_info=True)
            return None

    # ------------------------------------------------------------------
    # 1) 弱算法 / 不安全模式
    # ------------------------------------------------------------------

    def _scan_patterns(
        self,
        patterns: list[_PatternRule],
        scan_items: list[tuple[str, str, str]],
        result: AnalyzerResult,
    ) -> None:
        """逐规则匹配 needles；每条规则至多产一个 Finding（聚合多处证据）。"""
        for rule in patterns:
            try:
                evidences = self._match_pattern(rule, scan_items)
            except Exception:  # noqa: BLE001 — 单条规则失败不影响其余
                logger.exception("[%s] 规则匹配失败，跳过：%s", self.name, rule.id)
                continue
            if not evidences:
                continue
            result.findings.append(
                Finding(
                    id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    category="crypto",
                    description=rule.description,
                    recommendation=rule.recommendation,
                    evidences=evidences,
                    references=_ensure_cwe327(rule.references),
                )
            )

    def _match_pattern(
        self, rule: _PatternRule, scan_items: list[tuple[str, str, str]]
    ) -> list[Evidence]:
        """对单条规则匹配所有数据源；同一 needle 命中一次即停（避免刷屏）。"""
        evidences: list[Evidence] = []
        # 需求大小写不敏感子串匹配：预先小写化 needle。
        lowered_needles = [(n, n.lower()) for n in rule.needles if n]
        matched_needles: set[str] = set()
        for source, location, text in scan_items:
            low = text.lower()
            for orig, needle_low in lowered_needles:
                if orig in matched_needles:
                    continue
                if needle_low in low:
                    evidences.append(
                        Evidence(
                            source=source,
                            location=location,
                            snippet=_focus_snippet(text, orig),
                        )
                    )
                    matched_needles.add(orig)
            if len(matched_needles) == len(lowered_needles):
                break
        return evidences

    # ------------------------------------------------------------------
    # 2) 硬编码密钥 / IV 启发式
    # ------------------------------------------------------------------

    def _scan_hardcoded_keys(
        self,
        rule: _KeyRule,
        scan_items: list[tuple[str, str, str]],
        result: AnalyzerResult,
    ) -> None:
        """命名提示 + 定长常量同现 → 可疑硬编码密钥 / IV Finding（去重聚合）。"""
        lengths = set(rule.candidate_lengths)
        hints = [h.lower() for h in rule.name_hints if h]
        if not hints:
            return

        evidences: list[Evidence] = []
        seen: set[tuple[str, str]] = set()
        for source, location, text in scan_items:
            low = text.lower()
            if not any(h in low for h in hints):
                continue
            const = self._find_keyish_constant(text, lengths)
            if const is None:
                continue
            snippet = _truncate(text)
            key = (location, snippet)
            if key in seen:
                continue
            seen.add(key)
            evidences.append(
                Evidence(source=source, location=location, snippet=snippet)
            )

        if not evidences:
            return
        result.findings.append(
            Finding(
                id=rule.id,
                title=rule.title,
                severity=rule.severity,
                category="crypto",
                description=rule.description,
                recommendation=rule.recommendation,
                evidences=evidences,
                references=_ensure_cwe327(rule.references),
            )
        )

    @staticmethod
    def _find_keyish_constant(text: str, lengths: set[int]) -> str | None:
        """在文本里找一个定长十六进制 / Base64 常量；找不到返回 None。

        优先匹配引号内常量；其次裸十六进制串。长度需落在 candidate_lengths 内
        （为减误报，只接受这些密钥 / IV 的典型长度）。
        """
        if not lengths:
            lengths = set(_DEFAULT_KEY_LENGTHS)
        for m in _QUOTED_CONST.finditer(text):
            val = m.group(1)
            if len(val) in lengths and _looks_keyish(val):
                return val
        for m in _HEX_CONST.finditer(text):
            val = m.group(0)
            if len(val) in lengths:
                return val
        return None

    # ------------------------------------------------------------------
    # 3) 大块 Base64 常量
    # ------------------------------------------------------------------

    def _scan_base64_blobs(
        self,
        rule: _Base64Rule,
        scan_items: list[tuple[str, str, str]],
        result: AnalyzerResult,
    ) -> None:
        """识别 >= min_length 的连续 Base64 块，至多报 max_reports 个。"""
        min_len = max(int(rule.min_length), 1)
        max_reports = max(int(rule.max_reports), 1)

        evidences: list[Evidence] = []
        seen: set[str] = set()
        for source, location, text in scan_items:
            for m in _BASE64_RUN.finditer(text):
                blob = m.group(0)
                if len(blob) < min_len:
                    continue
                head = blob[:48]
                dedup_key = f"{location}:{head}:{len(blob)}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                evidences.append(
                    Evidence(
                        source=source,
                        location=location,
                        snippet=f"base64[len={len(blob)}] {head}…",
                    )
                )
                if len(evidences) >= max_reports:
                    break
            if len(evidences) >= max_reports:
                break

        if not evidences:
            return
        result.findings.append(
            Finding(
                id=rule.id,
                title=rule.title,
                severity=rule.severity,
                category="crypto",
                description=rule.description,
                recommendation=rule.recommendation,
                evidences=evidences,
                references=_ensure_cwe327(rule.references),
            )
        )

    # ------------------------------------------------------------------
    # 规则加载
    # ------------------------------------------------------------------

    def _load_rules(self) -> _CryptoRules:
        data = load_rules(_RULES_NAME)
        rules = _CryptoRules()

        if isinstance(data, list):
            # 容忍顶层直接是 patterns 列表的写法。
            rules.patterns = self._parse_patterns(data)
            return rules
        if not isinstance(data, dict):
            logger.warning(
                "[%s] 规则顶层应为 dict/list，实际 %s；无规则可用",
                self.name,
                type(data).__name__,
            )
            return rules

        rules.patterns = self._parse_patterns(data.get("patterns"))
        rules.keys = self._parse_key_rule(data.get("keys"))
        rules.base64 = self._parse_base64_rule(data.get("base64"))
        return rules

    def _parse_patterns(self, raw: Any) -> list[_PatternRule]:
        if raw is None:
            return []
        if not isinstance(raw, list):
            logger.warning(
                "[%s] patterns 字段应为 list，实际 %s", self.name, type(raw).__name__
            )
            return []
        out: list[_PatternRule] = []
        for entry in raw:
            if not isinstance(entry, dict):
                logger.warning("[%s] 跳过非 dict 的 pattern 条目：%r", self.name, entry)
                continue
            needles = _as_str_list(entry.get("needles"))
            if not needles:
                logger.warning(
                    "[%s] 跳过缺少 needles 的 pattern：%s", self.name, entry.get("id")
                )
                continue
            rid = entry.get("id")
            if not isinstance(rid, str) or not rid.strip():
                logger.warning("[%s] 跳过缺少 id 的 pattern：%r", self.name, entry)
                continue
            out.append(
                _PatternRule(
                    id=rid.strip(),
                    title=str(entry.get("title", rid)).strip(),
                    severity=_severity_from(entry.get("severity"), Severity.MEDIUM),
                    needles=needles,
                    description=str(entry.get("description", "")).strip(),
                    recommendation=str(entry.get("recommendation", "")).strip(),
                    references=_as_str_list(entry.get("references")),
                )
            )
        return out

    def _parse_key_rule(self, raw: Any) -> _KeyRule | None:
        if raw is None:
            return None
        if not isinstance(raw, dict):
            logger.warning(
                "[%s] keys 字段应为 dict，实际 %s；忽略", self.name, type(raw).__name__
            )
            return None
        name_hints = _as_str_list(raw.get("name_hints")) or list(_DEFAULT_NAME_HINTS)
        lengths = _as_int_list(raw.get("candidate_lengths")) or list(_DEFAULT_KEY_LENGTHS)
        return _KeyRule(
            id=str(raw.get("id", "CRYPTO-HARDCODED-KEY")).strip(),
            title=str(raw.get("title", "疑似硬编码密钥 / IV")).strip(),
            severity=_severity_from(raw.get("severity"), Severity.MEDIUM),
            name_hints=name_hints,
            candidate_lengths=lengths,
            description=str(raw.get("description", "")).strip(),
            recommendation=str(raw.get("recommendation", "")).strip(),
            references=_as_str_list(raw.get("references")),
        )

    def _parse_base64_rule(self, raw: Any) -> _Base64Rule | None:
        if raw is None:
            return None
        if not isinstance(raw, dict):
            logger.warning(
                "[%s] base64 字段应为 dict，实际 %s；忽略", self.name, type(raw).__name__
            )
            return None
        return _Base64Rule(
            id=str(raw.get("id", "CRYPTO-BASE64-BLOB")).strip(),
            title=str(raw.get("title", "内嵌大块 Base64 常量")).strip(),
            severity=_severity_from(raw.get("severity"), Severity.LOW),
            min_length=_as_int(raw.get("min_length"), 256),
            max_reports=_as_int(raw.get("max_reports"), 20),
            description=str(raw.get("description", "")).strip(),
            recommendation=str(raw.get("recommendation", "")).strip(),
            references=_as_str_list(raw.get("references")),
        )

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------

    @staticmethod
    def _record_error(result: AnalyzerResult, message: str) -> None:
        if not result.error:
            result.error = message


# ---------------------------------------------------------------------------
# 模块级工具函数
# ---------------------------------------------------------------------------


def _severity_from(value: Any, fallback: Severity) -> Severity:
    """把规则里的 severity 字符串解析为 Severity，无法判定回退。"""
    name = str(value).strip().upper()
    return _SEVERITY_BY_NAME.get(name, fallback)


def _as_str_list(value: Any) -> list[str]:
    """把规则字段规整为 str 列表（容忍 None / 非 list / 含非 str 元素）。"""
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _as_int_list(value: Any) -> list[int]:
    """把规则字段规整为 int 列表（容忍 None / 非 list / 不可转元素）。"""
    if not isinstance(value, list):
        return []
    out: list[int] = []
    for item in value:
        try:
            out.append(int(item))
        except (TypeError, ValueError):
            logger.debug("跳过不可转为 int 的元素：%r", item)
    return out


def _as_int(value: Any, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _ensure_cwe327(refs: list[str]) -> list[str]:
    """确保 references 含 CWE-327（弱加密 Finding 的统一引用）。"""
    out = list(refs)
    if not any("CWE-327" in r for r in out):
        out.insert(0, "CWE-327")
    return out


def _looks_keyish(value: str) -> bool:
    """引号内常量是否“像密钥”：纯十六进制，或含 Base64 特征字符（+/=）。

    纯字母（如普通英文词）不算，以降低误报。
    """
    if re.fullmatch(r"[0-9a-fA-F]+", value):
        return True
    if any(c in value for c in "+/="):
        return True
    # 混合大小写字母+数字（典型 key 形态），且含数字。
    if any(c.isdigit() for c in value) and any(c.isalpha() for c in value):
        return True
    return False


def _truncate(text: str, limit: int = _SNIPPET_MAX) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "…"


def _focus_snippet(text: str, needle: str, limit: int = _SNIPPET_MAX) -> str:
    """围绕命中 needle 截取一段上下文片段（大小写不敏感定位）。"""
    low = text.lower()
    idx = low.find(needle.lower())
    if idx < 0:
        return _truncate(text, limit)
    start = max(0, idx - 40)
    end = min(len(text), idx + len(needle) + 80)
    snippet = text[start:end]
    if start > 0:
        snippet = "…" + snippet
    if end < len(text):
        snippet = snippet + "…"
    return snippet
