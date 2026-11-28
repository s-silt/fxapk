"""backend_credential 分析器：从已扣押 APK 静态抠**后端 / 管理凭据**（取证分析，非主动攻击）。

诈骗 App 常把后台 / 数据库 / 云凭据硬编码进包——Basic-Auth、DB 连接串（含 user:pass）、
JDBC password、云 AccessKey。提取它们 = 对证物做取证分析，是「弱口令 / 已知凭据」的**合规
版本**：不去猜、不主动爆破远程服务器，只抠 App 自己带着的凭据，供**有权机关依法**登录取证 /
据归属向云厂商调服务器镜像与日志。**严禁未授权使用**（写进 Lead.notes）。

约束：只用 AnalysisContext 公开接口、规则数据化（rules/backend_credentials.yaml）、正则字符类
有界无 ReDoS、资源扫描带上限、never-throw try/except + logging、全 type hints、宁缺毋滥
（只取高精度结构化凭据形态，误报近零）。

云/SaaS 精确上下文检测器（rules/cloud_credential_providers.yaml）覆盖范围与限制：
- 只扫 DEX 字符串池与 APK 内**打包明文**资源（assets/、res/raw/ 等）。不解析 resources.arsc；
  res/ 下除 res/raw/ 外的编译资源（res/values 字符串已编入 ARSC，res/xml 等为二进制 AXML）与
  AndroidManifest.xml 一律跳过，故 res/values/strings.xml 中的厂商键不在覆盖范围内。
- 只认完整语法：JSON 经 json.loads 取完整键 + 字符串标量（畸形 JSON 不回退正则）；.xml 只认完整
  ``<string name="键">值</string>``；其余文本只认整行 ``键 = "值"`` 完整引号字面量。JS 属性读取、
  表达式、非字面量与不支持语法一律不判。输出只含固定脱敏标记，不含原值、前缀或长度。
- 命中按 provider:key 分组为一条线索，每处出现以 (source, location, 序号) 记入 source_refs；
  backend_credential_count 是分组线索数，不是不同凭据数。尚余缺口见 STAGE2_INTEGRATION_GAPS。
"""

from __future__ import annotations

import base64
import json
import logging
import re
from dataclasses import dataclass
import xml.parsers.expat as expat
from typing import TYPE_CHECKING

from fxapk.analyzers._common import (
    BINARY_RESOURCE_SUFFIXES,
    TEXT_RESOURCE_PREFIXES,
    TEXT_RESOURCE_SUFFIXES,
    collect_dex_strings,
    is_text_resource,
    str_or_empty,
    truncate,
)
from fxapk.core.leads import APPROVED_CLOUD_CREDENTIAL_PREFIXES, cloud_credential_provider_routing
from fxapk.core.json_contract import reject_nonfinite_json_constant
from fxapk.core.models import AnalyzerResult, Confidence, Evidence, Lead, LeadCategory
from fxapk.core.registry import BaseAnalyzer, load_rules
from fxapk.core.xmlutil import UnsafeXmlError, safe_fromstring

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
_MAX_CLOUD_CANDIDATES_PER_TEXT = 256
_MAX_CLOUD_JSON_NODES = 100_000
_MAX_CLOUD_REFS_PER_HIT = 64
_CLOUD_VALUE_CHARS = r"[A-Za-z0-9._+/=-]{16,128}"
_CLOUD_VALUE_RE = re.compile(rf"^{_CLOUD_VALUE_CHARS}$")
_REDACTED_MARKER = "[REDACTED]"
_NON_CREDENTIAL_LITERALS: frozenset[str] = frozenset(
    {"true", "false", "null", "none", "undefined"}
)
_PLAIN_CLOUD_SUFFIXES: tuple[str, ...] = (
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".txt",
    ".kv",
    ".env",
    ".yaml",
    ".yml",
    ".csv",
    ".js",
    ".html",
    ".htm",
)
_XML_ASCII_WS = " \t\r\n"
_RES_RAW_DIR_RE = re.compile(r"^raw(?:-[a-z0-9]+(?:\+[a-z0-9]+)*)*$")
_CLOUD_COMPLIANCE = (
    "高敏：静态候选云/SaaS凭据配置（精确上下文键名，未验证厂商归属与有效性，"
    "仅供有权机关结合主体依法核实归属与调取服务访问日志，禁止直接使用该候选凭据或作自动登录验证）"
)
STAGE2_INTEGRATION_GAPS: tuple[str, ...] = (
    "config_keys_cross_analyzer_dedup",
    "digest_redact_value_double_masks_fixed_redacted_marker",
)
# 脱敏分组值 -> (title, 保留的 (source, location, 同位置序号) 引用, 每位置已见次数)
_CloudHits = dict[str, tuple[str, list[tuple[str, str, int]], dict[tuple[str, str], int]]]
_CloudCandidates = list[tuple["CloudProviderRule", str, str]]

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
            # 整行完整键值：键前后只允许同种引号，值必须是闭合的同种引号字面量，行尾只允许 , 或 ;。
            kv_regex = re.compile(
                rf'(?im)^[ \t]{{0,8}}(?P<kq>["\']?)(?P<key>{keys_alt})(?P=kq)[ \t]{{0,8}}[:=][ \t]{{0,8}}'
                rf'(?P<vq>["\'])(?P<val>{_CLOUD_VALUE_CHARS})(?P=vq)[ \t]{{0,8}}[,;]?[ \t]{{0,8}}\r?$'
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
                where_to_request=provider_where,
                evidence_to_obtain=provider_evidence,
            )
        )
    return rules

def _is_res_raw_resource(low_path: str) -> bool:
    """匹配精确 Android res/raw/ 或 res/raw-<valid-qualifier>/ 目录边界下的文件。"""
    parts = low_path.split("/")
    return (
        len(parts) >= 3
        and parts[0] == "res"
        and bool(_RES_RAW_DIR_RE.fullmatch(parts[1]))
        and all(seg and seg not in (".", "..") for seg in parts[2:])
    )


def _is_plaintext_cloud_resource(low_path: str) -> bool:
    """云检测器只扫打包明文：排除清单 AXML、二进制 ARSC 及 res/ 下非 res/raw[-qualifier]/ 的编译资源。"""
    if low_path == "androidmanifest.xml" or low_path.endswith(".arsc"):
        return False
    if low_path.startswith("res/"):
        return _is_res_raw_resource(low_path)
    return True


def _is_cloud_only_resource(low_path: str) -> bool:
    """仅云检测器新增的明文资源（res/raw-<qualifier>/、.toml）；不扩展 legacy 过滤器。"""
    return (
        (_is_res_raw_resource(low_path) or low_path.endswith(".toml"))
        and not low_path.endswith(BINARY_RESOURCE_SUFFIXES)
        and _is_plaintext_cloud_resource(low_path)
    )


def _is_cloud_literal(rule: CloudProviderRule, raw_val: str) -> bool:
    """完整字面量须符合厂商值形态且非布尔/空值字面量；须在占用候选上限前判定。"""
    return raw_val.lower() not in _NON_CREDENTIAL_LITERALS and bool(rule.value_regex.fullmatch(raw_val))


def _json_cloud_candidates(text: str, rules: list[CloudProviderRule]) -> tuple[_CloudCandidates, bool]:
    """JSON 完整键 + 字符串标量候选；允许单个前导 UTF-8 BOM，超限或畸形 JSON 直接放弃，不回退正则。

    返回 (候选, 是否因节点/候选上限遗漏证据)。
    """
    if len(text) > _MAX_CLOUD_SCAN_CHARS:
        return [], False
    if text.startswith("\ufeff"):
        text = text[1:]
    try:
        tree = json.loads(text, parse_constant=reject_nonfinite_json_constant)
    except (ValueError, RecursionError):
        return [], False
    key_rules = {k.lower(): r for r in rules for k in r.config_keys}
    out: _CloudCandidates = []
    pending: list[object] = [tree]
    visited = 0
    while pending:
        if visited >= _MAX_CLOUD_JSON_NODES:
            return out, True
        node = pending.pop()
        visited += 1
        if isinstance(node, dict):
            children: list[object] = []
            for key, item in node.items():
                if isinstance(item, str):
                    rule = key_rules.get(key.lower())
                    if rule is not None and _is_cloud_literal(rule, item):
                        if len(out) >= _MAX_CLOUD_CANDIDATES_PER_TEXT:
                            return out, True
                        out.append((rule, key, item))
                elif isinstance(item, (dict, list)):
                    children.append(item)
            pending.extend(reversed(children))
        elif isinstance(node, list):
            pending.extend(reversed([item for item in node if isinstance(item, (dict, list))]))
    return out, False


def _xml_cloud_candidates(text: str, rules: list[CloudProviderRule]) -> tuple[_CloudCandidates, bool]:
    """明文 .xml 候选：经 safe_fromstring 安全解析，只取无嵌套子节点的完整 <string name="精确键">字面量</string>。"""
    if len(text) > _MAX_CLOUD_SCAN_CHARS:
        return [], False
    try:
        root = safe_fromstring(text)
    except (UnsafeXmlError, expat.ExpatError):
        return [], False
    key_rules = {k.lower(): r for r in rules for k in r.config_keys}
    out: _CloudCandidates = []
    for elem in root.iter():
        tag = elem.tag.rsplit("}", 1)[-1] if isinstance(elem.tag, str) else ""
        if tag.lower() != "string" or len(elem) > 0:
            continue
        raw_name = elem.attrib.get("name")
        if not isinstance(raw_name, str):
            continue
        rule = key_rules.get(raw_name.lower())
        if rule is None or not isinstance(elem.text, str):
            continue
        val = elem.text.strip(_XML_ASCII_WS)
        if not _is_cloud_literal(rule, val):
            continue
        if len(out) >= _MAX_CLOUD_CANDIDATES_PER_TEXT:
            return out, True
        out.append((rule, raw_name, val))
    return out, False


def _regex_cloud_candidates(text: str, rules: list[CloudProviderRule]) -> tuple[_CloudCandidates, bool]:
    """明文锚定字面量候选：仅匹配整行完整键值与闭合引号字面量。"""
    lowered_text = text.lower()
    active_rules = [r for r in rules if any(k.lower() in lowered_text for k in r.config_keys)]
    out: _CloudCandidates = []
    for rule in active_rules:
        for m in rule.kv_regex.finditer(text):
            val = m.group("val")
            if not _is_cloud_literal(rule, val):
                continue
            if len(out) >= _MAX_CLOUD_CANDIDATES_PER_TEXT:
                return out, True
            out.append((rule, m.group("key"), val))
    return out, False


def _select_cloud_candidates(
    text: str,
    source: str,
    low_loc: str,
    provider_rules: list[CloudProviderRule],
) -> tuple[_CloudCandidates, bool]:
    """按已知文件后缀优先路由，仅对未知后缀资源或 DEX 片段使用内容形态启发式。"""
    if source == "resource":
        if low_loc.endswith(".json"):
            return _json_cloud_candidates(text, provider_rules)
        if low_loc.endswith(".xml"):
            return _xml_cloud_candidates(text, provider_rules)
        if low_loc.endswith(_PLAIN_CLOUD_SUFFIXES):
            return _regex_cloud_candidates(text, provider_rules)
    body = text[1:] if text.startswith("\ufeff") else text
    stripped = body.strip()
    if stripped.startswith(("{", "[")) and stripped.endswith(("}", "]")):
        return _json_cloud_candidates(text, provider_rules)
    if stripped.startswith("<") and stripped.endswith(">"):
        return _xml_cloud_candidates(text, provider_rules)
    return _regex_cloud_candidates(text, provider_rules)

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
        # legacy: value -> (title, source, location)，保首条（行为不变）
        hits: dict[str, tuple[str, str, str]] = {}
        # 云/SaaS：脱敏分组值 -> 有上限的确定性出现引用
        cloud_hits: _CloudHits = {}
        _ok, dex_strings = collect_dex_strings(ctx, self.name, max_strings=_MAX_DEX_STRINGS, result=result)
        cloud_dex_truncated = False
        cloud_dex_budget = False
        for s in dex_strings:
            truncated, budget = self._scan_text(
                s, "dex", "dex_strings", patterns, hits, provider_rules=provider_rules, cloud_hits=cloud_hits
            )
            cloud_dex_truncated = cloud_dex_truncated or truncated
            cloud_dex_budget = cloud_dex_budget or budget
        if cloud_dex_truncated:
            result.meta["dex_strings_truncated"] = True
        resource_coverage = self._scan_resources(
            ctx, patterns, hits, provider_rules=provider_rules, cloud_hits=cloud_hits
        )
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
        if cloud_dex_budget:
            # DEX 云候选/引用上限遗漏证据：与资源预算缺口取或，绝不清除已置位标记。
            result.meta["backend_credential_budget_exhausted"] = 1

        for value in sorted(hits.keys() | cloud_hits.keys()):
            try:
                if value not in cloud_hits:
                    title, source, location = hits[value]
                    result.leads.append(self._build_lead(value, title, source, location, where, evidence))
                    continue
                title, occurrences, _counts = cloud_hits[value]
                pid = value.split(":", 1)[0]
                prule = provider_rule_map.get(pid)
                if prule:
                    hit_where, cloud_evidence = prule.where_to_request, prule.evidence_to_obtain
                else:
                    hit_where, cloud_evidence = cloud_credential_provider_routing(pid)
                # 仅精确键名 + 固定标记，归属与有效性未核：不与结构化 legacy 凭据同档。
                refs = self._cloud_source_refs(value, occurrences)
                result.leads.append(
                    self._build_lead(
                        value,
                        title,
                        refs[0].source,
                        refs[0].location,
                        hit_where,
                        list(cloud_evidence),
                        compliance=_CLOUD_COMPLIANCE,
                        confidence=Confidence.MEDIUM,
                        source_refs=refs,
                    )
                )
            except Exception:
                logger.exception("[%s] 构建线索失败（已跳过）", self.name)

        # 分组线索数（云候选按 provider:key 分组），不是不同凭据数。
        result.meta["backend_credential_count"] = len(result.leads)
        if result.leads:
            logger.info("[%s] 硬编码后端/管理凭据线索 %d 条（分组计数，高敏）", self.name, len(result.leads))
        return result

    def _scan_text(
        self,
        text: str,
        source: str,
        location: str,
        patterns: list[_Pattern],
        hits: dict[str, tuple[str, str, str]],
        provider_rules: list[CloudProviderRule] | None = None,
        cloud_hits: _CloudHits | None = None,
    ) -> tuple[bool, bool]:
        """从一段文本抽硬编码凭据，去重累积。返回 (超云扫描字符预算而跳过云检测, 云候选/引用上限遗漏证据)。绝不抛。"""
        if not text:
            return False, False
        if _ANCHOR_RE.search(text):
            try:
                for p in patterns:
                    for m in p.regex.finditer(text):
                        value = self._extract_value(p, m)
                        if value:
                            hits.setdefault(value, (p.title, source, location))
            except Exception:
                logger.exception("[%s] 扫描文本失败：%s", self.name, location)
        if provider_rules and cloud_hits is not None:
            return self._scan_cloud_provider_text(text, source, location, provider_rules, cloud_hits)
        return False, False

    def _scan_cloud_provider_text(
        self,
        text: str,
        source: str,
        location: str,
        provider_rules: list[CloudProviderRule],
        cloud_hits: _CloudHits,
    ) -> tuple[bool, bool]:
        """按精确厂商前缀上下文配置键名提取固定脱敏云/SaaS凭据标记，保留有上限的确定性出现引用。绝不抛。

        返回 (DEX 超字符预算跳过, 候选/节点/引用上限遗漏证据)。
        """
        try:
            low_loc = location.lower()
            if source == "resource" and not _is_plaintext_cloud_resource(low_loc):
                return False, False
            if len(text) > _MAX_CLOUD_SCAN_CHARS:
                return source == "dex", False
            candidates, exhausted = _select_cloud_candidates(text, source, low_loc, provider_rules)
            for rule, matched_key, raw_val in candidates:
                canonical_key = matched_key.strip().lower()
                redacted_hit = format_cloud_provider_hit(rule.provider_id, canonical_key, raw_val)
                title = f"{rule.label}（精确上下文配置键：{canonical_key}，未验证归属）"
                _title, occurrences, counts = cloud_hits.setdefault(redacted_hit, (title, [], {}))
                # 序号只依赖 (source, location) 内出现次序，与原值及 APK 成员列举顺序无关。
                n = counts.get((source, location), 0) + 1
                counts[(source, location)] = n
                ref = (source, location, n)
                if len(occurrences) < _MAX_CLOUD_REFS_PER_HIT:
                    occurrences.append(ref)
                    continue
                # 超上限：保留排序最小的 N 条，任何新出现都记覆盖缺口（即便替换了已留引用）。
                exhausted = True
                worst = max(occurrences)
                if ref < worst:
                    occurrences[occurrences.index(worst)] = ref
            return False, exhausted
        except Exception:
            logger.exception("[%s] 扫描云凭据配置失败：%s", self.name, location)
            return False, False

    @staticmethod
    def _cloud_source_refs(value: str, occurrences: list[tuple[str, str, int]]) -> list[Evidence]:
        """每条保留引用一条证据：(source, location, 同位置序号)，与原值无关、排序确定。"""
        snippet = truncate(value, 120)
        return [Evidence(source=s, location=loc, snippet=f"{snippet} #{n}") for s, loc, n in sorted(occurrences)]

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
        cloud_hits: _CloudHits | None = None,
    ) -> dict[str, int]:
        """扫描 APK 内文本资源（H5/JS/json/配置里的硬编码凭据）。绝不抛。

        先按既有 legacy 过滤器与顺序扫描（预算不变），再用剩余预算扫仅云检测器新增的明文资源。
        """
        try:
            files = [p for p in ctx.list_files() if isinstance(p, str)]
        except Exception:
            logger.exception("[%s] 读取 list_files 失败", self.name)
            return {"list_failed": 1}
        cloud_rules = provider_rules if provider_rules and cloud_hits is not None else None
        legacy_files: list[str] = []
        cloud_only_files: list[str] = []
        for path in files:
            if is_text_resource(path, suffixes=TEXT_RESOURCE_SUFFIXES, prefixes=TEXT_RESOURCE_PREFIXES):
                legacy_files.append(path)
            elif cloud_rules and _is_cloud_only_resource(path.lower()):
                cloud_only_files.append(path)
        total = 0
        read_failed = 0
        oversize = 0
        budget_hit = False
        for legacy, path in [(True, p) for p in legacy_files] + [(False, p) for p in cloud_only_files]:
            if total >= _MAX_TOTAL_RESOURCE_BYTES:
                # 达到总预算＝剩余资源根本没看，必须向下游暴露这个缺口。
                budget_hit = True
                logger.warning("[%s] 文本资源扫描达总预算，停止", self.name)
                break
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
            if legacy:
                _truncated, exhausted = self._scan_text(
                    text, "resource", path, patterns, hits, provider_rules=provider_rules, cloud_hits=cloud_hits
                )
            elif cloud_rules and cloud_hits is not None:
                # 仅云：不跑 legacy 规则，避免扩展 legacy 扫描面。
                _truncated, exhausted = self._scan_cloud_provider_text(
                    text, "resource", path, cloud_rules, cloud_hits
                )
            else:
                exhausted = False
            budget_hit = budget_hit or exhausted

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
        source_refs: list[Evidence] | None = None,
    ) -> Lead:
        refs = source_refs or [Evidence(source=source, location=location, snippet=truncate(value, 120))]
        return Lead(
            category=LeadCategory.BACKEND_CREDENTIAL,
            value=value,
            subject=None,
            where_to_request=where,
            evidence_to_obtain=list(evidence),
            confidence=confidence,
            source_refs=refs,
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
