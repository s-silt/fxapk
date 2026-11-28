"""backend_credential 分析器：从已扣押 APK 静态抠**后端 / 管理凭据**（取证分析，非主动攻击）。

诈骗 App 常把后台 / 数据库 / 云凭据硬编码进包——Basic-Auth、DB 连接串（含 user:pass）、
JDBC password、云 AccessKey。提取它们 = 对证物做取证分析，是「弱口令 / 已知凭据」的**合规
版本**：不去猜、不主动爆破远程服务器，只抠 App 自己带着的凭据，供**有权机关依法**登录取证 /
据归属向云厂商调服务器镜像与日志。**严禁未授权使用**（写进 Lead.notes）。

约束：只用 AnalysisContext 公开接口、规则数据化（rules/backend_credentials.yaml）、正则字符类
有界无 ReDoS、资源扫描带上限、never-throw try/except + logging、全 type hints、宁缺毋滥
（只取高精度结构化凭据形态，误报近零）。

Stage 2 待衔接缺口（本阶段不改动 config_keys / leads / tests / digest）：
- cross_analyzer_dedup: config_keys 分析器对同名配置键的 CONFIG_KEY 线索与本分析器脱敏云凭据线索的跨分析器去重协调。
- downstream_presentation: leads.py / digest.py 对未验证云厂商归属（verification_status=unverified）与脱敏摘要的分面展示。
- synthetic_placeholder_tests: 针对 7 家云/SaaS 厂商上下文配置键的合成无效占位符回归测试。
"""

from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from fxapk.analyzers._common import (
    TEXT_RESOURCE_PREFIXES,
    TEXT_RESOURCE_SUFFIXES,
    collect_dex_strings,
    is_text_resource,
    str_or_empty,
    truncate,
)
from fxapk.core.leads import APPROVED_CLOUD_CREDENTIAL_PREFIXES, cloud_credential_provider_routing
from fxapk.core.models import AnalyzerResult, Confidence, Evidence, Lead, LeadCategory
from fxapk.core.registry import BaseAnalyzer, load_rules

if TYPE_CHECKING:
    from fxapk.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_RULES_NAME = "backend_credentials"
_MAX_DEX_STRINGS = 200_000
_MAX_RESOURCE_BYTES = 4_000_000
_MAX_TOTAL_RESOURCE_BYTES = 64_000_000

# 性能预筛：5 类凭据必含下列锚点之一（DSN/JDBC→"://"、Basic→"Authorization"、云 AK→AKIA/LTAI）；
# 整段无锚点即跳过昂贵的 5 条正则 finditer。是详细规则的超集，跳过的串本就不会命中，行为不变。
_ANCHOR_RE = re.compile(r"://|AKIA|LTAI|Authorization")

_DECODE_BASIC = "base64_userpass"
_DEFAULT_WHERE = "无直接调证对象（凭据供有权机关依法登录取证 / 据服务器归属向云厂商调镜像与日志）"
_COMPLIANCE = "高敏：硬编码后端/管理凭据，仅供有权机关依法登录取证 / 调服务器镜像与日志，严禁未授权使用"

_CLOUD_PROVIDER_RULES_NAME = "cloud_credential_providers"
_FORBIDDEN_GENERIC_KEYS: frozenset[str] = frozenset(
    {
        "key",
        "api_key",
        "apikey",
        "secret",
        "secret_key",
        "secretkey",
        "token",
        "access_token",
        "auth_token",
        "password",
        "passwd",
        "pwd",
        "private_key",
        "client_secret",
        "app_key",
        "app_secret",
        "credential",
        "credentials",
        "access_key",
        "access_key_id",
    }
)
_CONFIG_KEY_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{6,96}$")
_MAX_CONFIG_KEYS_PER_PROVIDER = 16
_MAX_CLOUD_SCAN_CHARS = 4_000_000
_CLOUD_VALUE_RE = re.compile(r"^[A-Za-z0-9._+/=-]{16,128}$")
_REDACTED_MARKER = "[REDACTED]"
_NON_CREDENTIAL_LITERALS: frozenset[str] = frozenset(
    {"true", "false", "null", "none", "undefined"}
)
_CLOUD_COMPLIANCE = (
    "高敏：静态候选云/SaaS凭据配置（精确上下文键名，未验证厂商归属与有效性，"
    "仅供有权机关结合主体依法核实归属与调取服务访问日志，禁止直接使用该候选凭据或作自动登录验证）"
)
STAGE2_INTEGRATION_GAPS: tuple[str, ...] = (
    "config_keys_cross_analyzer_dedup",
    "digest_redact_value_double_masks_fixed_redacted_marker",
)

@dataclass
class _Pattern:
    id: str
    title: str
    regex: re.Pattern[str]
    decode: str = ""



@dataclass(frozen=True)
class CloudProviderRule:
    """本地防御性云/SaaS凭据上下文规则（仅静态匹配，不作在线验证或归属背书）。"""

    provider_id: str
    label: str
    service_category: str
    verification_status: str
    config_keys: tuple[str, ...]
    value_regex: re.Pattern[str]
    kv_regex: re.Pattern[str]
    xml_regex: re.Pattern[str]
    where_to_request: str
    evidence_to_obtain: tuple[str, ...]


def is_contextual_config_key(key: str) -> bool:
    """校验配置键名是否含显式厂商/服务上下文，拒绝通用键名。"""
    if not isinstance(key, str):
        return False
    cleaned = key.strip()
    if not _CONFIG_KEY_NAME_RE.fullmatch(cleaned):
        return False
    lowered = cleaned.lower()
    if lowered in _FORBIDDEN_GENERIC_KEYS:
        return False
    parts = [p for p in re.split(r"[_.-]+", lowered) if p]
    return len(parts) >= 2


def redact_credential_value(raw_value: str) -> str:
    """返回固定脱敏标记，不泄露原始值的任何前缀或长度。"""
    del raw_value
    return _REDACTED_MARKER


def format_cloud_provider_hit(provider_id: str, config_key: str, raw_value: str) -> str:
    """格式化云/SaaS上下文凭据命中值（provider_id:config_key=脱敏摘要）。"""
    return f"{provider_id.strip().lower()}:{config_key.strip().lower()}={redact_credential_value(raw_value)}"



def is_cloud_provider_hit_value(value: object) -> bool:
    """判断线索值是否为固定脱敏云/SaaS凭据标记（provider_id:config_key=[REDACTED]）。"""
    if not isinstance(value, str) or ":" not in value or not value.endswith(f"={_REDACTED_MARKER}"):
        return False
    provider_id, rest = value.split(":", 1)
    if provider_id not in APPROVED_CLOUD_CREDENTIAL_PREFIXES or "=" not in rest:
        return False
    config_key, marker = rest.split("=", 1)
    return (
        marker == _REDACTED_MARKER
        and is_contextual_config_key(config_key)
        and config_key.startswith(APPROVED_CLOUD_CREDENTIAL_PREFIXES[provider_id])
    )

def load_cloud_credential_providers(data: object = None) -> list[CloudProviderRule]:
    """加载并校验 cloud_credential_providers.yaml 中的 7 家云/SaaS 厂商精确上下文规则。"""
    from fxapk.core.textutil import as_str_list

    if data is None:
        try:
            data = load_rules(_CLOUD_PROVIDER_RULES_NAME)
        except Exception:
            logger.warning("[backend_credential] 读取云凭据提供方规则失败，跳过")
            return []
    if not isinstance(data, dict):
        return []
    rules: list[CloudProviderRule] = []
    for entry in data.get("providers") or []:
        if not isinstance(entry, dict):
            continue
        provider_id = str_or_empty(entry.get("provider_id")).lower()
        if provider_id not in APPROVED_CLOUD_CREDENTIAL_PREFIXES:
            continue
        label = str_or_empty(entry.get("label")) or provider_id
        service_category = str_or_empty(entry.get("service_category")) or "cloud_saas"
        raw_keys = as_str_list(entry.get("config_keys"))
        valid_keys = tuple(
            dict.fromkeys(
                k.strip()
                for k in raw_keys[:_MAX_CONFIG_KEYS_PER_PROVIDER]
                if is_contextual_config_key(k)
                and k.strip().lower().startswith(APPROVED_CLOUD_CREDENTIAL_PREFIXES[provider_id])
            )
        )
        if not valid_keys:
            continue
        try:
            keys_alt = "|".join(re.escape(k) for k in valid_keys)
            kv_regex = re.compile(
                rf'(?i)(?<![A-Za-z0-9_.-])(?P<key>{keys_alt})["\']?\s{{0,8}}[:=]\s{{0,8}}["\']?(?P<val>[A-Za-z0-9._~+/=:-]{{12,160}})["\']?'
            )
            xml_regex = re.compile(
                rf'(?i)<string\s{{1,8}}name=["\'](?P<key>{keys_alt})["\']\s{{0,8}}>\s{{0,8}}(?P<val>[A-Za-z0-9._~+/=:-]{{12,160}})\s{{0,8}}</string>'
            )
        except re.error:
            logger.warning("[backend_credential] 云凭据规则正则编译失败，跳过：%s", provider_id)
            continue
        # 路由按注册表标签区分候选服务方；仅条目级显式覆盖优先（顶层通用文案不再压过厂商路由）。
        routed_where, routed_evidence = cloud_credential_provider_routing(label)
        provider_where = str_or_empty(entry.get("where_to_request")) or routed_where
        provider_evidence = tuple(as_str_list(entry.get("evidence_to_obtain"))) or routed_evidence
        rules.append(
            CloudProviderRule(
                provider_id=provider_id,
                label=label,
                service_category=service_category,
                verification_status="unverified",
                config_keys=valid_keys,
                value_regex=_CLOUD_VALUE_RE,
                kv_regex=kv_regex,
                xml_regex=xml_regex,
                where_to_request=provider_where,
                evidence_to_obtain=provider_evidence,
            )
        )
    return rules

class BackendCredentialAnalyzer(BaseAnalyzer):
    """抠 APK 内硬编码后端 / 管理凭据，产出 category=BACKEND_CREDENTIAL 的高敏取证线索。"""

    name: str = "backend_credential"
    meta_key_categories = {
        'backend_credential_count': 'record',
        'dex_strings_truncated': 'coverage',
        # 资源面覆盖缺口：让 count=0 能区分「确实没有」与「没扫全」。
        'backend_credential_list_failed': 'coverage',
        'backend_credential_read_failed': 'coverage',
        'backend_credential_oversize_skipped': 'coverage',
        'backend_credential_budget_exhausted': 'coverage',
    }
    meta_keys = frozenset(meta_key_categories)
    requires: list[str] = []

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        patterns, where, evidence = self._load_rules()
        provider_rules = self._load_cloud_provider_rules()
        if not patterns and not provider_rules:
            logger.info("[%s] 无可用后端凭据规则，跳过", self.name)
            return result
        provider_rule_map = {r.provider_id: r for r in provider_rules}
        # value -> (title, source, location)
        hits: dict[str, tuple[str, str, str]] = {}
        _ok, dex_strings = collect_dex_strings(ctx, self.name, max_strings=_MAX_DEX_STRINGS, result=result)
        for s in dex_strings:
            self._scan_text(s, "dex", "dex_strings", patterns, hits, provider_rules=provider_rules)
        resource_coverage = self._scan_resources(ctx, patterns, hits, provider_rules=provider_rules)
        # 只写实际发生的覆盖缺口；缺失键即「没发生过这类缺口」（见 core/coverage.py 的约定）。
        # ★键名写成字面量而非 coverage_meta_key(self.name, ...) 动态拼：meta_scan 契约要求
        #   「声明的键」与「代码里静态可见的写入」双向对齐，动态拼键会让扫描器只看到 <dynamic>、
        #   等于绕过整套契约。字面量虽啰嗦，但护栏能核。
        for suffix, value in resource_coverage.items():
            if suffix == "list_failed":
                result.meta["backend_credential_list_failed"] = value
            elif suffix == "read_failed":
                result.meta["backend_credential_read_failed"] = value
            elif suffix == "oversize_skipped":
                result.meta["backend_credential_oversize_skipped"] = value
            elif suffix == "budget_exhausted":
                result.meta["backend_credential_budget_exhausted"] = value

        for value, (title, source, location) in sorted(hits.items()):
            try:
                hit_where = where
                hit_evidence = evidence
                hit_compliance = _COMPLIANCE
                hit_confidence = Confidence.HIGH
                if is_cloud_provider_hit_value(value):
                    pid = value.split(":", 1)[0]
                    prule = provider_rule_map.get(pid)
                    if prule:
                        hit_where, cloud_evidence = prule.where_to_request, prule.evidence_to_obtain
                    else:
                        hit_where, cloud_evidence = cloud_credential_provider_routing(pid)
                    hit_evidence = list(cloud_evidence)
                    hit_compliance = _CLOUD_COMPLIANCE
                    # 仅精确键名 + 固定标记，归属与有效性未核：不与结构化 legacy 凭据同档。
                    hit_confidence = Confidence.MEDIUM
                result.leads.append(
                    self._build_lead(
                        value,
                        title,
                        source,
                        location,
                        hit_where,
                        hit_evidence,
                        compliance=hit_compliance,
                        confidence=hit_confidence,
                    )
                )
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
        provider_rules: list[CloudProviderRule] | None = None,
    ) -> None:
        """从一段文本抽硬编码凭据，去重累积。绝不抛。"""
        if not text:
            return
        if _ANCHOR_RE.search(text):
            try:
                for p in patterns:
                    for m in p.regex.finditer(text):
                        value = self._extract_value(p, m)
                        if value:
                            hits.setdefault(value, (p.title, source, location))
            except Exception:
                logger.exception("[%s] 扫描文本失败：%s", self.name, location)
        if provider_rules:
            self._scan_cloud_provider_text(text, source, location, provider_rules, hits)

    def _scan_cloud_provider_text(
        self,
        text: str,
        source: str,
        location: str,
        provider_rules: list[CloudProviderRule],
        hits: dict[str, tuple[str, str, str]],
    ) -> None:
        """按精确厂商前缀上下文配置键名提取固定脱敏云/SaaS凭据标记。绝不抛。"""
        try:
            if len(text) > _MAX_CLOUD_SCAN_CHARS:
                text = text[:_MAX_CLOUD_SCAN_CHARS]
            lowered_text = text.lower()
            for rule in provider_rules:
                if not any(k.lower() in lowered_text for k in rule.config_keys):
                    continue
                for regex in (rule.kv_regex, rule.xml_regex):
                    for m in regex.finditer(text):
                        matched_key = m.group("key")
                        raw_val = m.group("val").strip()
                        if (
                            not raw_val
                            or raw_val.lower() in _NON_CREDENTIAL_LITERALS
                            or raw_val.startswith(("${", "{{"))
                            or not rule.value_regex.fullmatch(raw_val)
                        ):
                            continue
                        redacted_hit = format_cloud_provider_hit(rule.provider_id, matched_key, raw_val)
                        title = f"{rule.label}（精确上下文配置键，未验证归属）"
                        hits.setdefault(redacted_hit, (title, source, location))
        except Exception:
            logger.exception("[%s] 扫描云凭据配置失败：%s", self.name, location)
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
        self,
        ctx: "AnalysisContext",
        patterns: list[_Pattern],
        hits: dict[str, tuple[str, str, str]],
        provider_rules: list[CloudProviderRule] | None = None,
    ) -> dict[str, int]:
        """扫描 APK 内文本资源（H5/JS/json/配置里的硬编码凭据）。绝不抛。"""
        try:
            files = [p for p in ctx.list_files() if isinstance(p, str)]
        except Exception:
            logger.exception("[%s] 读取 list_files 失败", self.name)
            return {"list_failed": 1}
        total = 0
        read_failed = 0
        oversize = 0
        budget_hit = False
        for path in files:
            if total >= _MAX_TOTAL_RESOURCE_BYTES:
                # 达到总预算＝剩余资源根本没看，必须向下游暴露这个缺口。
                budget_hit = True
                logger.warning("[%s] 文本资源扫描达总预算，停止", self.name)
                break
            if not is_text_resource(
                path, suffixes=TEXT_RESOURCE_SUFFIXES, prefixes=TEXT_RESOURCE_PREFIXES
            ):
                continue
            try:
                data = ctx.read_file(path)
            except Exception:
                # 单个资源读失败不中断扫描，但要计数——读不到 ≠ 里面没有。
                read_failed += 1
                logger.exception("[%s] 读取资源失败：%s", self.name, path)
                continue
            if not data:
                continue  # 空文件不是覆盖缺口，静默跳过
            if len(data) > _MAX_RESOURCE_BYTES:
                # 超大资源被整个跳过，是覆盖缺口而非「未命中」。
                oversize += 1
                continue
            total += len(data)
            text = (
                data.decode("utf-8", errors="replace")
                if isinstance(data, (bytes, bytearray))
                else str(data)
            )
            self._scan_text(text, "resource", path, patterns, hits, provider_rules=provider_rules)

        return {
            key: value
            for key, value in {
                "read_failed": read_failed,
                "oversize_skipped": oversize,
                "budget_exhausted": int(budget_hit),
            }.items()
            if value
        }

    def _build_lead(
        self,
        value: str,
        title: str,
        source: str,
        location: str,
        where: str,
        evidence: list[str],
        *,
        compliance: str = _COMPLIANCE,
        confidence: Confidence = Confidence.HIGH,
    ) -> Lead:
        ev = Evidence(source=source, location=location, snippet=truncate(value, 120))
        return Lead(
            category=LeadCategory.BACKEND_CREDENTIAL,
            value=value,
            subject=None,
            where_to_request=where,
            evidence_to_obtain=list(evidence),
            confidence=confidence,
            source_refs=[ev],
            notes=f"{compliance}（{title}）",
            advice="建议调证",
        )

    def _load_rules(self) -> tuple[list[_Pattern], str, list[str]]:
        from fxapk.core.textutil import as_str_list

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

    def _load_cloud_provider_rules(self) -> list[CloudProviderRule]:
        return load_cloud_credential_providers()
