"""配置键值分析器 —— 把 App 里**真实配置的 key=value** 抠出来并归属到调证主体。

★ 最高价值模块：报告必须显示 'GETUI_APPID=DVRqpR8NztAJAfq8f4dbv3' 这种**具体值**，
  而不是只说"检测到个推 SDK"。每抠到一个 key=value → 一条 CONFIG_KEY 调证线索，
  并按 rules/config_keys.yaml 把它绑定到一家可调证公司（个推 / DCloud / 腾讯 …）。

职责（见任务说明）：
- 数据源（都走 AnalysisContext 公开接口，禁止 import androguard）：
    1. ctx.manifest_xml 里所有 <meta-data> 的 android:name / android:value
       （resource 引用 @xxx 记为 value="@资源引用"）。安全解析防 XXE。
    2. uni-app：assets/apps/*/www/manifest.json —— 提 id(__UNI__*)/name/version/
       description/developer；含 'confusion' 字段 → Finding(MEDIUM, 代码加密)。
    3. assets/data/dcloud_control.xml、dcloud_uniplugins.json、res/values/strings.xml
       里疑似配置键值（name=value）。
- 每个 key=value → Lead(category=CONFIG_KEY, value="name=value", subject=厂商,
  where_to_request=厂商, evidence_to_obtain=规则兜底, confidence=HIGH, advice="建议调证")。
- 敏感凭据（名字含 SECRET/APPKEY/APP_SECRET/PRIVATE/KEY/TOKEN）额外产 Finding(HIGH, secret)。
- meta：config_key_count / uni_appid / uni_app_name / uni_encrypted。

约束：
- 只依赖 AnalysisContext 公开接口；用 xml.etree 安全解析（防 XXE）。
- 逐源 try/except + logging，单源失败不影响其余；无配置 → 干净返回 error=None。
- 全程 type hints。
"""

from __future__ import annotations

import json
import logging
import re
import xml.parsers.expat as expat
from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import TYPE_CHECKING, Any

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
from apkscan.core.secrets import SecretRules, is_real_secret, load_secret_rules
from apkscan.core.xmlutil import UnsafeXmlError as _UnsafeXmlError
from apkscan.core.xmlutil import android_attr as _android_attr
from apkscan.core.xmlutil import safe_fromstring as _safe_fromstring

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_RULES_NAME = "config_keys"

# value 片段截断长度（写入 Evidence.snippet）。
_SNIPPET_MAX = 200

# uni-app manifest.json 路径模式（assets/apps/<__UNI__xxx>/www/manifest.json）。
_UNI_MANIFEST_GLOB = "assets/apps/*/www/manifest.json"

# 额外探查的疑似配置文件（路径子串，大小写不敏感）。
_EXTRA_CONFIG_FILES: tuple[str, ...] = (
    "assets/data/dcloud_control.xml",
    "assets/data/dcloud_uniplugins.json",
    "res/values/strings.xml",
)

# 敏感凭据 key 名特征（命中 → 额外 Finding(HIGH, secret)）。
_SECRET_TOKENS: tuple[str, ...] = (
    "SECRET",
    "APPKEY",
    "APP_SECRET",
    "PRIVATE",
    "KEY",
    "TOKEN",
)

# 默认兜底证据（规则 meta 缺失时使用）。
_DEFAULT_EVIDENCE_TO_OBTAIN: tuple[str, ...] = (
    "凭该 AppID/AppKey/渠道号向厂商调取：开发者账号实名、应用注册主体、调用/下发日志",
)

_DEFAULT_UNKNOWN_SUBJECT = "待核（应用配置）"

# 调证研判建议三态。
_ADVICE_NEED = "建议调证"
_ADVICE_SKIP = "无需调证"
_ADVICE_REVIEW = "待核"

# 框架 / 系统样板 meta-data:这些不是调证线索(平台初始化/显示配置/版本号),
# 命中(前缀或子串)→"无需调证",避免淹没真正的 AppID/AppKey/渠道等凭据线索。
_BOILERPLATE_PREFIXES: tuple[str, ...] = (
    "androidx.",
    "android.",
    "com.google.",
    "com.facebook.soloader",
    "com.android.",
    "flutterembedding",
    "io.flutter",
)
_BOILERPLATE_SUBSTRINGS: tuple[str, ...] = (
    "notch",
    "soloader",
    "input_mode",
    "default_language",
    "lazy_init",
    "sdk_version",
    "max_aspect",
    "file_provider",
    "splashscreen",
    "statusbar",
    "screenorientation",
    "version_code",
    "build_version",
    "glide",
    "workmanager",
    "lifecycle",
    "profileinstaller",
    "emoji",
    "startup",
)
# 强凭据 / 调证线索特征(命中 → 建议调证,即便未匹配到具体厂商)。
_CREDENTIAL_MARKERS: tuple[str, ...] = (
    "appid", "app_id", "appkey", "app_key", "appsecret", "app_secret",
    "secret", "token", "channel", "__uni__", "mch", "partner",
    "access_key", "accesskey", "api_key", "apikey", "client_id", "client_secret",
    "push_app", "getui", "umeng", "jpush", "wx", "qq_", "alipay", "miid", "mi_app",
)


def _truncate(text: str, limit: int = _SNIPPET_MAX) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "…"


# ---------------------------------------------------------------------------
# 规则
# ---------------------------------------------------------------------------


@dataclass
class _Pattern:
    """单条 key → 厂商映射规则（从 YAML 规整而来）。"""

    sdk: str
    subject: str
    prefixes: list[str] = field(default_factory=list)
    exact: list[str] = field(default_factory=list)
    contains: list[str] = field(default_factory=list)


@dataclass
class _ConfigKey:
    """抠出的一条配置键值及其来源。"""

    name: str
    value: str
    source: str  # manifest|resource
    location: str  # meta-data 名 / 文件路径


class ConfigKeysAnalyzer(BaseAnalyzer):
    """抠出 App 真实配置 key=value，归属到调证主体，产出 CONFIG_KEY 线索。"""

    name: str = "config_keys"
    requires: list[str] = []  # 纯静态解析，永远可用

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        patterns, default_evidence, unknown_subject = self._load_rules()
        secret_rules = load_secret_rules()

        keys: list[_ConfigKey] = []

        # 1) manifest <meta-data>（逐源 try/except）。
        try:
            keys.extend(self._from_manifest(ctx))
        except Exception:
            logger.exception("[%s] 解析 manifest <meta-data> 失败", self.name)

        # 2) uni-app manifest.json（顺带提取 id/name/version/confusion 等 meta + Finding）。
        try:
            keys.extend(self._from_uni_app(ctx, result))
        except Exception:
            logger.exception("[%s] 解析 uni-app manifest.json 失败", self.name)

        # 3) 额外配置文件（dcloud_control.xml / dcloud_uniplugins.json / strings.xml）。
        try:
            keys.extend(self._from_extra_files(ctx))
        except Exception:
            logger.exception("[%s] 解析额外配置文件失败", self.name)

        # 去重（同 name+value+location 只保留一条）。
        keys = self._dedup(keys)

        # 每个 key=value → 一条 CONFIG_KEY Lead；敏感凭据额外 Finding。
        for ck in keys:
            try:
                lead = self._build_lead(ck, patterns, default_evidence, unknown_subject)
                result.leads.append(lead)
                secret_finding = self._maybe_secret_finding(ck, secret_rules)
                if secret_finding is not None:
                    result.findings.append(secret_finding)
            except Exception:
                logger.exception("[%s] 构造 Lead/Finding 失败：%s", self.name, ck.name)

        result.meta["config_key_count"] = len(keys)
        logger.info("[%s] 抠出 %d 条配置键值", self.name, len(keys))
        return result

    # ------------------------------------------------------------------
    # 数据源 1：manifest <meta-data>
    # ------------------------------------------------------------------

    def _from_manifest(self, ctx: "AnalysisContext") -> list[_ConfigKey]:
        xml_text = ctx.manifest_xml
        if not xml_text or not xml_text.strip():
            logger.debug("[%s] manifest_xml 为空，跳过 meta-data 提取", self.name)
            return []

        try:
            root = _safe_fromstring(xml_text)
        except _UnsafeXmlError:
            logger.warning("[%s] manifest 含 DTD/实体声明，已拒绝解析（疑似 XXE）", self.name)
            return []
        except expat.ExpatError:
            logger.exception("[%s] manifest XML 解析失败", self.name)
            return []

        keys: list[_ConfigKey] = []
        # <meta-data> 可出现在 application / activity / service 等下，统一全树遍历。
        for elem in root.iter():
            tag = elem.tag
            # 兼容带命名空间的 tag（理论上 meta-data 无前缀）。
            local = tag.rsplit("}", 1)[-1] if "}" in tag else tag
            if local != "meta-data":
                continue
            name = _android_attr(elem, "name")
            if not name:
                continue
            value = _android_attr(elem, "value")
            resource = _android_attr(elem, "resource")
            display = self._normalize_value(value, resource)
            keys.append(
                _ConfigKey(
                    name=name.strip(),
                    value=display,
                    source="manifest",
                    location=f"meta-data[{name.strip()}]",
                )
            )
        return keys

    @staticmethod
    def _normalize_value(value: str | None, resource: str | None) -> str:
        """meta-data value 规整：resource 引用 / @xxx 引用 → "@资源引用"。"""
        raw = value if value is not None else resource
        if raw is None:
            return ""
        raw = raw.strip()
        if raw.startswith("@"):
            return "@资源引用"
        return raw

    # ------------------------------------------------------------------
    # 数据源 2：uni-app manifest.json
    # ------------------------------------------------------------------

    def _from_uni_app(
        self, ctx: "AnalysisContext", result: AnalyzerResult
    ) -> list[_ConfigKey]:
        try:
            paths = [
                p
                for p in ctx.list_files()
                if isinstance(p, str)
                and fnmatch(p.replace("\\", "/"), _UNI_MANIFEST_GLOB)
            ]
        except Exception:
            logger.exception("[%s] 枚举 uni-app manifest.json 失败", self.name)
            return []

        keys: list[_ConfigKey] = []
        for path in paths:
            try:
                raw = ctx.read_file(path)
            except Exception:
                logger.exception("[%s] 读取 uni-app manifest 失败：%s", self.name, path)
                continue
            if not raw:
                continue
            try:
                data = json.loads(raw.decode("utf-8", errors="replace"))
            except (ValueError, UnicodeError):
                logger.exception("[%s] uni-app manifest JSON 解析失败：%s", self.name, path)
                continue
            if not isinstance(data, dict):
                logger.warning("[%s] uni-app manifest 顶层非 dict：%s", self.name, path)
                continue
            keys.extend(self._extract_uni_fields(data, path, result))
        return keys

    def _extract_uni_fields(
        self, data: dict[str, Any], path: str, result: AnalyzerResult
    ) -> list[_ConfigKey]:
        """从 uni-app manifest.json dict 提取 id/name/version/description/developer。

        同时写入 result.meta（uni_appid/uni_app_name/uni_encrypted）；
        若含 confusion（代码加密标志）→ Finding(MEDIUM)。
        """
        keys: list[_ConfigKey] = []

        uni_id = data.get("id")
        if isinstance(uni_id, str) and uni_id.strip():
            result.meta.setdefault("uni_appid", uni_id.strip())
            keys.append(_ConfigKey("__UNI__", uni_id.strip(), "resource", path))

        name = data.get("name")
        if isinstance(name, str) and name.strip():
            result.meta.setdefault("uni_app_name", name.strip())
            keys.append(_ConfigKey("uni_app_name", name.strip(), "resource", path))

        for field_name in ("version", "versionName", "description", "developer"):
            val = data.get(field_name)
            if isinstance(val, dict):
                # version 可能是 {"name": "1.0.0", "code": "100"}。
                val = val.get("name") or val.get("code")
            if isinstance(val, str) and val.strip():
                keys.append(_ConfigKey(f"uni_{field_name}", val.strip(), "resource", path))

        # confusion（代码加密）标志：可能在顶层或 plus/app-plus 下。
        encrypted = self._detect_confusion(data)
        if encrypted:
            result.meta["uni_encrypted"] = True
            result.findings.append(
                Finding(
                    id="CONFIG-UNIAPP-ENCRYPTED",
                    title="uni-app 代码加密（confusion）",
                    severity=Severity.MEDIUM,
                    category="config",
                    description=(
                        "uni-app 代码加密，真实业务JS/接口需脱壳解密。"
                        "检出 manifest.json 含 confusion 字段，业务逻辑/接口被加密混淆，"
                        "静态分析无法直接获取真实接口，需运行期脱壳或解密后复核。"
                    ),
                    recommendation="运行期 hook / 脱壳后解密 app-service.js 复核真实接口与业务逻辑。",
                    evidences=[
                        Evidence(
                            source="resource",
                            location=path,
                            snippet="confusion",
                        )
                    ],
                )
            )
        else:
            result.meta.setdefault("uni_encrypted", False)

        return keys

    @staticmethod
    def _detect_confusion(data: dict[str, Any]) -> bool:
        """递归探测 uni-app manifest 中是否含 confusion（代码加密）标志。"""
        if "confusion" in data:
            return True
        for val in data.values():
            if isinstance(val, dict) and ConfigKeysAnalyzer._detect_confusion(val):
                return True
        return False

    # ------------------------------------------------------------------
    # 数据源 3：额外配置文件
    # ------------------------------------------------------------------

    def _from_extra_files(self, ctx: "AnalysisContext") -> list[_ConfigKey]:
        try:
            all_files = [p for p in ctx.list_files() if isinstance(p, str)]
        except Exception:
            logger.exception("[%s] 枚举额外配置文件失败", self.name)
            return []

        keys: list[_ConfigKey] = []
        for path in all_files:
            low = path.replace("\\", "/").lower()
            if not any(target in low for target in _EXTRA_CONFIG_FILES):
                continue
            try:
                raw = ctx.read_file(path)
            except Exception:
                logger.exception("[%s] 读取配置文件失败：%s", self.name, path)
                continue
            if not raw:
                continue
            text = raw.decode("utf-8", errors="replace")
            try:
                if low.endswith(".json"):
                    keys.extend(self._parse_json_kvs(text, path))
                else:
                    keys.extend(self._parse_xml_kvs(text, path))
            except Exception:
                logger.exception("[%s] 解析配置文件键值失败：%s", self.name, path)
        return keys

    def _parse_xml_kvs(self, text: str, path: str) -> list[_ConfigKey]:
        """从 strings.xml / dcloud_control.xml 等抠 name=value 键值。

        strings.xml：<string name="X">value</string>
        其它 XML：取带 name 属性的元素，value 取其 text 或 value/android:value 属性。
        """
        if not text.strip():
            return []
        try:
            root = _safe_fromstring(text)
        except _UnsafeXmlError:
            logger.warning("[%s] 配置 XML 含 DTD/实体声明，已拒绝解析：%s", self.name, path)
            return []
        except expat.ExpatError:
            logger.exception("[%s] 配置 XML 解析失败：%s", self.name, path)
            return []

        keys: list[_ConfigKey] = []
        for elem in root.iter():
            name = elem.get("name") or _android_attr(elem, "name")
            if not name or not name.strip():
                continue
            value = elem.text.strip() if elem.text and elem.text.strip() else None
            if value is None:
                value = elem.get("value") or _android_attr(elem, "value")
            if value is None or not str(value).strip():
                continue
            keys.append(
                _ConfigKey(
                    name=name.strip(),
                    value=str(value).strip(),
                    source="resource",
                    location=path,
                )
            )
        return keys

    def _parse_json_kvs(self, text: str, path: str) -> list[_ConfigKey]:
        """从 dcloud_uniplugins.json 等抠顶层标量键值（name=value）。"""
        if not text.strip():
            return []
        try:
            data = json.loads(text)
        except ValueError:
            logger.exception("[%s] 配置 JSON 解析失败：%s", self.name, path)
            return []
        keys: list[_ConfigKey] = []
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(k, str) and isinstance(v, (str, int, float, bool)):
                    keys.append(_ConfigKey(k.strip(), str(v).strip(), "resource", path))
        return keys

    # ------------------------------------------------------------------
    # Lead / Finding 构造
    # ------------------------------------------------------------------

    def _build_lead(
        self,
        ck: _ConfigKey,
        patterns: list[_Pattern],
        default_evidence: list[str],
        unknown_subject: str,
    ) -> Lead:
        match = self._match_pattern(ck.name, patterns)
        if match is not None:
            subject = match.subject
            notes = f"配置对应：{match.sdk}。"
        else:
            subject = unknown_subject
            notes = "未匹配已知 SDK 配置键，归属待核。"

        return Lead(
            category=LeadCategory.CONFIG_KEY,
            value=f"{ck.name}={ck.value}",
            subject=subject,
            where_to_request=subject,
            evidence_to_obtain=list(default_evidence),
            confidence=Confidence.HIGH,
            advice=self._advice_for(ck.name, match),
            source_refs=[
                Evidence(
                    source=ck.source,
                    location=ck.location,
                    snippet=_truncate(ck.value),
                )
            ],
            notes=notes,
        )

    @staticmethod
    def _advice_for(name: str, match: "_Pattern | None") -> str:
        """配置键的调证研判建议。

        - 框架/系统样板(androidx.*/notch/版本号/初始化等)→ 无需调证(降噪)。
        - 含凭据/AppID/AppKey/Secret/渠道/__UNI__ 特征,或匹配到已知 SDK 厂商 → 建议调证。
        - 其余(应用自有但非凭据的配置,如 uni_app_name/description)→ 待核。
        """
        low = name.lower()
        if low.startswith(_BOILERPLATE_PREFIXES) or any(
            s in low for s in _BOILERPLATE_SUBSTRINGS
        ):
            return _ADVICE_SKIP
        if any(m in low for m in _CREDENTIAL_MARKERS):
            return _ADVICE_NEED
        if match is not None:
            return _ADVICE_NEED
        return _ADVICE_REVIEW

    @staticmethod
    def _match_pattern(key_name: str, patterns: list[_Pattern]) -> _Pattern | None:
        """把 key 名匹配到规则。优先级：exact > 最长 prefix > contains。"""
        low = key_name.lower()

        # 1) 精确匹配。
        for pat in patterns:
            if any(low == e.lower() for e in pat.exact):
                return pat

        # 2) 前缀匹配（更长前缀优先，避免 ZX_ 抢走 ZX_APPID_GETUI）。
        best: _Pattern | None = None
        best_len = -1
        for pat in patterns:
            for pre in pat.prefixes:
                if low.startswith(pre.lower()) and len(pre) > best_len:
                    best = pat
                    best_len = len(pre)
        if best is not None:
            return best

        # 3) 子串匹配。
        for pat in patterns:
            if any(c.lower() in low for c in pat.contains):
                return pat

        return None

    def _maybe_secret_finding(
        self, ck: _ConfigKey, secret_rules: SecretRules
    ) -> Finding | None:
        """名字含 SECRET/APPKEY/APP_SECRET/PRIVATE/KEY/TOKEN + 值像真凭据 → Finding(HIGH, secret)。

        C2 旁路修复：原仅看 key 名即产 HIGH，导致 manifest 里任何 *_APPKEY meta-data
        （哪怕 value 是常量名，如 OPPOPUSH_APPKEY=OPPOPUSH_APPKEY）都误报 HIGH。现增 value
        形态判定（value==key / 已知 SDK 常量 / looks_keyish），不像真凭据则不产 Finding。
        注意：CONFIG_KEY lead 仍照常产出 key=value（无信息损失），符合"宁标低勿误杀"。
        """
        upper = ck.name.upper()
        if not any(tok in upper for tok in _SECRET_TOKENS):
            return None
        # value 形态闸：value==key / 已知 SDK 常量名值 / 不像凭据形态 → 不产 Finding。
        if not is_real_secret(ck.name, ck.value, secret_rules):
            logger.debug(
                "[%s] %s 的值不像真凭据（疑似 SDK 常量名/占位），不产 secret Finding",
                self.name,
                ck.name,
            )
            return None
        return Finding(
            id=f"CONFIG-SECRET-{re.sub(r'[^A-Z0-9]+', '-', upper).strip('-')}",
            title=f"硬编码敏感凭据：{ck.name}",
            severity=Severity.HIGH,
            category="secret",
            description=(
                f"配置项 {ck.name} 疑似敏感凭据（AppSecret / AppKey / Token / 私钥），"
                f"明文硬编码在应用配置中，可被逆向直接读取并冒用调用对应云服务。"
            ),
            recommendation="凭该凭据向对应 SDK 厂商调取注册主体与调用日志；提示厂商该凭据已泄露应吊销。",
            evidences=[
                Evidence(
                    source=ck.source,
                    location=ck.location,
                    snippet=f"{ck.name}={_truncate(ck.value)}",
                )
            ],
        )

    # ------------------------------------------------------------------
    # 去重 / 规则加载
    # ------------------------------------------------------------------

    @staticmethod
    def _dedup(keys: list[_ConfigKey]) -> list[_ConfigKey]:
        seen: set[tuple[str, str, str]] = set()
        out: list[_ConfigKey] = []
        for ck in keys:
            sig = (ck.name, ck.value, ck.location)
            if sig in seen:
                continue
            seen.add(sig)
            out.append(ck)
        return out

    def _load_rules(self) -> tuple[list[_Pattern], list[str], str]:
        """加载并规整规则，返回 (规则列表, 默认证据, 未知主体)。"""
        data = load_rules(_RULES_NAME)

        evidence: list[str] = list(_DEFAULT_EVIDENCE_TO_OBTAIN)
        unknown_subject = _DEFAULT_UNKNOWN_SUBJECT
        raw_patterns: object = []

        if isinstance(data, dict):
            raw_patterns = data.get("patterns", [])
            meta = data.get("meta")
            if isinstance(meta, dict):
                ev = _as_str_list(meta.get("evidence_to_obtain"))
                if ev:
                    evidence = ev
                us = meta.get("unknown_subject")
                if isinstance(us, str) and us.strip():
                    unknown_subject = us.strip()
        elif isinstance(data, list):
            raw_patterns = data
        else:
            logger.warning(
                "[%s] 规则顶层应为 dict/list，实际 %s；无规则可用",
                self.name,
                type(data).__name__,
            )

        return self._parse_patterns(raw_patterns), evidence, unknown_subject

    def _parse_patterns(self, raw: object) -> list[_Pattern]:
        if not isinstance(raw, list):
            logger.warning("[%s] patterns 字段应为 list，实际 %s", self.name, type(raw).__name__)
            return []
        patterns: list[_Pattern] = []
        for entry in raw:
            if not isinstance(entry, dict):
                logger.warning("[%s] 跳过非 dict 规则条目：%r", self.name, entry)
                continue
            subject = entry.get("subject")
            if not isinstance(subject, str) or not subject.strip():
                logger.warning("[%s] 跳过缺少 subject 的规则条目：%r", self.name, entry)
                continue
            sdk = entry.get("sdk")
            pat = _Pattern(
                sdk=sdk.strip() if isinstance(sdk, str) and sdk.strip() else subject.strip(),
                subject=subject.strip(),
                prefixes=_as_str_list(entry.get("prefixes")),
                exact=_as_str_list(entry.get("exact")),
                contains=_as_str_list(entry.get("contains")),
            )
            if not (pat.prefixes or pat.exact or pat.contains):
                logger.warning("[%s] 跳过无任何匹配特征的规则：%s", self.name, pat.subject)
                continue
            patterns.append(pat)
        return patterns


# ---------------------------------------------------------------------------
# 模块级工具函数
# ---------------------------------------------------------------------------


def _as_str_list(value: object) -> list[str]:
    """把规则字段规整为 str 列表（容忍 None / 非 list / 含非 str 元素）。"""
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]
