"""Firebase / google-services.json 后端归属解析器。

★ 价值：国内涉诈 RAT/盘子大量用 Firebase 做 C2 / 数据回传，归属确定性高——
  凭 project_id 可向 Google（GCP）调取项目实名 / 账单 / 付款主体，databaseURL 即
  数据回传后端（RTDB endpoint）。fxapk 的核心产出是「调证线索清单」，本分析器把
  Firebase 配置转成可落地的调证线索。

职责（纯静态、永远可用，靠 registry 自动发现注册）：
- 两类数据源（都走 AnalysisContext 公开接口，禁止 import androguard）：
    1. res/values/strings.xml 里 google-services 插件注入的键：
       firebase_database_url / google_api_key / project_id（或 gcm_defaultSenderId /
       google_storage_bucket）。安全解析（拒 XXE/DTD，用 core.xmlutil）。
    2. assets/ 下打包的 google-services.json：project_info.project_id /
       project_info.firebase_url / project_info.storage_bucket /
       project_info.project_number、client[].api_key.current_key。JSON 用 json.loads
       包 try/except。
- 产出：
    * databaseURL → Endpoint(kind="domain")（host 形态），让 pipeline 统一富化 +
      build_endpoint_leads 建 DOMAIN Lead（遵循 endpoints 分析器约定：只产 Endpoint）。
      ★ firebaseio.com / firebaseapp.com 不在 core/infra 的 KNOWN_INFRA 里，故会被判
      「建议调证」而非当 Google 公共服务降为「无需调证」——这正是涉诈调证最该盯的落点。
    * project_id → Lead(category=CONFIG_KEY, value="firebase_project_id=<id>")，
      subject/where_to_request/evidence_to_obtain 取自 rules/firebase.yaml 的调证模板。
    * meta["firebase_project_id"]（字符串）：供跨样本团伙聚类当并簇键。
    * meta["firebase"]（dict）：记录 database_url / project_id / storage_bucket /
      api_key / sender_id（有哪个记哪个）。

约束（项目铁律）：
- 绝不抛异常给调用方：每个数据源 try/except + logging，单源失败不炸 analyze。
- 绝不 print / 不用 typer（analyzer 是核心层）。
- 全量 type hints；规则数据进 rules/firebase.yaml，本模块读它（参照 config_keys）。
"""

from __future__ import annotations

import json
import logging
import xml.parsers.expat as expat
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from apkscan.analyzers._common import as_str_list as _as_str_list
from apkscan.analyzers._common import truncate as _truncate
from apkscan.core.models import (
    AnalyzerResult,
    Confidence,
    Endpoint,
    Evidence,
    Lead,
    LeadCategory,
)
from apkscan.core.registry import BaseAnalyzer, load_rules
from apkscan.core.xmlutil import UnsafeXmlError as _UnsafeXmlError
from apkscan.core.xmlutil import safe_fromstring as _safe_fromstring

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_RULES_NAME = "firebase"

# snippet 截断长度（写入 Evidence.snippet）。
_SNIPPET_MAX = 200

# google-services.json 路径特征（子串、大小写不敏感）。打包位置通常在 assets/ 下。
_GOOGLE_SERVICES_BASENAME = "google-services.json"

# strings.xml 路径特征（子串、大小写不敏感）。
_STRINGS_XML_SUFFIX = "res/values/strings.xml"

# project_id 产 CONFIG_KEY Lead 时的 value 前缀（同时是 meta/聚类约定键名）。
_PROJECT_ID_VALUE_PREFIX = "firebase_project_id"

# 规则缺失时的调证模板兜底（离线 / 规则缺失不崩）。
_FALLBACK_SUBJECT = "Google / GCP 项目所有者"
_FALLBACK_WHERE = "向 Google（境内常经第三方代理）调 GCP 项目实名 / 账单 / 付款主体"
_FALLBACK_EVIDENCE: tuple[str, ...] = (
    "GCP 项目注册实名与付款主体",
    "RTDB 数据库读写访问日志",
    "项目关联的其它 app",
)
_FALLBACK_NOTES = (
    "Firebase/GCP 项目归属确定性高；但 Firebase 亦正规 App 常用（推送/分析），"
    "需结合敏感行为研判。"
)

# strings.xml google-services 注入键 → firebase 逻辑字段名的兜底映射（全小写匹配）。
_FALLBACK_STRINGS_KEYS: dict[str, tuple[str, ...]] = {
    "database_url": ("firebase_database_url",),
    "api_key": ("google_api_key",),
    "project_id": ("project_id",),
    "sender_id": ("gcm_defaultsenderid",),
    "storage_bucket": ("google_storage_bucket",),
}

# 研判建议（与 infra / Lead.advice 取值约定一致）。
_ADVICE_NEED = "建议调证"


@dataclass
class _ProjectLeadTemplate:
    """project_id → CONFIG_KEY Lead 的调证模板（从 YAML 规整，缺失走兜底）。"""

    subject: str = _FALLBACK_SUBJECT
    where_to_request: str = _FALLBACK_WHERE
    evidence_to_obtain: list[str] = field(
        default_factory=lambda: list(_FALLBACK_EVIDENCE)
    )
    notes: str = _FALLBACK_NOTES


@dataclass
class _FirebaseConfig:
    """从一个数据源抠出的 Firebase 配置（有哪个记哪个；空字段为 None）。"""

    project_id: str | None = None
    database_url: str | None = None
    storage_bucket: str | None = None
    api_key: str | None = None
    sender_id: str | None = None
    project_number: str | None = None
    # 证据来源（首个非空源），用于 Lead/Endpoint 的 Evidence。
    source: str = "resource"
    location: str = ""

    def merge_from(self, other: "_FirebaseConfig") -> None:
        """用 other 的非空字段补齐本配置（先到先得，不覆盖已有）。"""
        for attr in (
            "project_id",
            "database_url",
            "storage_bucket",
            "api_key",
            "sender_id",
            "project_number",
        ):
            if getattr(self, attr) is None:
                val = getattr(other, attr)
                if val is not None:
                    setattr(self, attr, val)
        if not self.location and other.location:
            self.source = other.source
            self.location = other.location

    def is_empty(self) -> bool:
        return not any(
            (
                self.project_id,
                self.database_url,
                self.storage_bucket,
                self.api_key,
                self.sender_id,
                self.project_number,
            )
        )


class FirebaseAnalyzer(BaseAnalyzer):
    """从 strings.xml / google-services.json 抠 Firebase 配置，归属 Google/GCP 项目所有者。"""

    name: str = "firebase"
    requires: list[str] = []  # 纯静态解析，永远可用

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        strings_keys, template = self._load_rules()

        config = _FirebaseConfig()

        # 1) res/values/strings.xml（google-services 插件注入键）。
        try:
            config.merge_from(self._from_strings_xml(ctx, strings_keys))
        except Exception:
            logger.exception("[%s] 解析 strings.xml Firebase 键失败", self.name)

        # 2) assets/ 下的 google-services.json。
        try:
            config.merge_from(self._from_google_services(ctx))
        except Exception:
            logger.exception("[%s] 解析 google-services.json 失败", self.name)

        if config.is_empty():
            logger.debug("[%s] 未发现任何 Firebase 配置", self.name)
            return result

        # 产出：databaseURL → domain Endpoint；project_id → CONFIG_KEY Lead；写 meta。
        try:
            self._emit_database_endpoint(config, result)
        except Exception:
            logger.exception("[%s] 构造 databaseURL Endpoint 失败", self.name)

        try:
            self._emit_project_lead(config, template, result)
        except Exception:
            logger.exception("[%s] 构造 project_id Lead 失败", self.name)

        self._write_meta(config, result)

        logger.info(
            "[%s] Firebase 配置：project_id=%s database_url=%s",
            self.name,
            config.project_id,
            config.database_url,
        )
        return result

    # ------------------------------------------------------------------
    # 数据源 1：res/values/strings.xml
    # ------------------------------------------------------------------

    def _from_strings_xml(
        self, ctx: "AnalysisContext", strings_keys: dict[str, tuple[str, ...]]
    ) -> _FirebaseConfig:
        config = _FirebaseConfig()
        try:
            files = [p for p in ctx.list_files() if isinstance(p, str)]
        except Exception:
            logger.exception("[%s] 枚举文件失败（strings.xml）", self.name)
            return config

        # 反查表：注入键名（小写）→ firebase 逻辑字段名。
        key_to_field: dict[str, str] = {}
        for field_name, key_names in strings_keys.items():
            for key_name in key_names:
                key_to_field[key_name.lower()] = field_name

        for path in files:
            low = path.replace("\\", "/").lower()
            if not low.endswith(_STRINGS_XML_SUFFIX):
                continue
            try:
                raw = ctx.read_file(path)
            except Exception:
                logger.exception("[%s] 读取 strings.xml 失败：%s", self.name, path)
                continue
            if not raw:
                continue
            pairs = self._parse_strings_xml(raw.decode("utf-8", errors="replace"), path)
            for name, value in pairs:
                field_name = key_to_field.get(name.lower())
                if field_name is None:
                    continue
                if getattr(config, field_name, None) is None:
                    setattr(config, field_name, value)
                    if not config.location:
                        config.source = "resource"
                        config.location = path
        return config

    def _parse_strings_xml(self, text: str, path: str) -> list[tuple[str, str]]:
        """安全解析 strings.xml，抠 <string name="X">value</string> 键值。"""
        if not text.strip():
            return []
        try:
            root = _safe_fromstring(text)
        except _UnsafeXmlError:
            logger.warning(
                "[%s] strings.xml 含 DTD/实体声明，已拒绝解析（疑似 XXE）：%s",
                self.name,
                path,
            )
            return []
        except expat.ExpatError:
            logger.exception("[%s] strings.xml 解析失败：%s", self.name, path)
            return []

        pairs: list[tuple[str, str]] = []
        for elem in root.iter():
            name = elem.get("name")
            if not name or not name.strip():
                continue
            value = elem.text.strip() if elem.text and elem.text.strip() else ""
            if not value:
                continue
            pairs.append((name.strip(), value))
        return pairs

    # ------------------------------------------------------------------
    # 数据源 2：assets/ 下的 google-services.json
    # ------------------------------------------------------------------

    def _from_google_services(self, ctx: "AnalysisContext") -> _FirebaseConfig:
        config = _FirebaseConfig()
        try:
            files = [p for p in ctx.list_files() if isinstance(p, str)]
        except Exception:
            logger.exception("[%s] 枚举文件失败（google-services.json）", self.name)
            return config

        for path in files:
            low = path.replace("\\", "/").lower()
            if not low.endswith(_GOOGLE_SERVICES_BASENAME):
                continue
            try:
                raw = ctx.read_file(path)
            except Exception:
                logger.exception(
                    "[%s] 读取 google-services.json 失败：%s", self.name, path
                )
                continue
            if not raw:
                continue
            parsed = self._parse_google_services(
                raw.decode("utf-8", errors="replace"), path
            )
            if parsed is not None:
                config.merge_from(parsed)
        return config

    def _parse_google_services(self, text: str, path: str) -> _FirebaseConfig | None:
        """解析 google-services.json 的 project_info / client[].api_key.current_key。"""
        if not text.strip():
            return None
        try:
            data = json.loads(text)
        except ValueError:
            logger.exception("[%s] google-services.json 解析失败：%s", self.name, path)
            return None
        if not isinstance(data, dict):
            logger.warning("[%s] google-services.json 顶层非 dict：%s", self.name, path)
            return None

        config = _FirebaseConfig(source="resource", location=path)

        project_info = data.get("project_info")
        if isinstance(project_info, dict):
            config.project_id = _clean_str(project_info.get("project_id"))
            config.database_url = _clean_str(project_info.get("firebase_url"))
            config.storage_bucket = _clean_str(project_info.get("storage_bucket"))
            config.project_number = _clean_str(project_info.get("project_number"))

        config.api_key = self._first_api_key(data.get("client"))
        return config

    @staticmethod
    def _first_api_key(client: Any) -> str | None:
        """从 client[].api_key[].current_key 取第一个非空 api key。"""
        if not isinstance(client, list):
            return None
        for entry in client:
            if not isinstance(entry, dict):
                continue
            api_key = entry.get("api_key")
            if not isinstance(api_key, list):
                continue
            for key_entry in api_key:
                if isinstance(key_entry, dict):
                    current = _clean_str(key_entry.get("current_key"))
                    if current:
                        return current
        return None

    # ------------------------------------------------------------------
    # 产出：Endpoint / Lead / meta
    # ------------------------------------------------------------------

    def _emit_database_endpoint(
        self, config: _FirebaseConfig, result: AnalyzerResult
    ) -> None:
        """databaseURL → host 形态的 domain Endpoint（pipeline 统一富化 + 建 DOMAIN Lead）。"""
        host = _host_from_database_url(config.database_url)
        if not host:
            return
        result.endpoints.append(
            Endpoint(
                value=host,
                kind="domain",
                evidences=[
                    Evidence(
                        source=config.source,
                        location=config.location,
                        snippet=_truncate(config.database_url or host, _SNIPPET_MAX),
                    )
                ],
            )
        )

    def _emit_project_lead(
        self,
        config: _FirebaseConfig,
        template: _ProjectLeadTemplate,
        result: AnalyzerResult,
    ) -> None:
        """project_id → CONFIG_KEY Lead（归属 Google/GCP 项目所有者）。"""
        project_id = config.project_id
        if not project_id:
            return
        result.leads.append(
            Lead(
                category=LeadCategory.CONFIG_KEY,
                value=f"{_PROJECT_ID_VALUE_PREFIX}={project_id}",
                subject=template.subject,
                where_to_request=template.where_to_request,
                evidence_to_obtain=list(template.evidence_to_obtain),
                confidence=Confidence.HIGH,
                advice=_ADVICE_NEED,
                source_refs=[
                    Evidence(
                        source=config.source,
                        location=config.location,
                        snippet=_truncate(
                            f"firebase project_id={project_id}", _SNIPPET_MAX
                        ),
                    )
                ],
                notes=template.notes,
            )
        )

    def _write_meta(self, config: _FirebaseConfig, result: AnalyzerResult) -> None:
        """写 meta["firebase_project_id"]（聚类并簇键）与 meta["firebase"]（有哪个记哪个）。"""
        if config.project_id:
            result.meta["firebase_project_id"] = config.project_id

        firebase: dict[str, str] = {}
        for key, val in (
            ("database_url", config.database_url),
            ("project_id", config.project_id),
            ("storage_bucket", config.storage_bucket),
            ("api_key", config.api_key),
            ("sender_id", config.sender_id),
            ("project_number", config.project_number),
        ):
            if val:
                firebase[key] = val
        if firebase:
            result.meta["firebase"] = firebase

    # ------------------------------------------------------------------
    # 规则加载
    # ------------------------------------------------------------------

    def _load_rules(
        self,
    ) -> tuple[dict[str, tuple[str, ...]], _ProjectLeadTemplate]:
        """加载并规整规则，返回 (strings_keys 映射, project_lead 模板)。缺失走兜底。"""
        strings_keys: dict[str, tuple[str, ...]] = {
            k: tuple(v) for k, v in _FALLBACK_STRINGS_KEYS.items()
        }
        template = _ProjectLeadTemplate()

        data = load_rules(_RULES_NAME)
        if not isinstance(data, dict):
            if data:
                logger.warning(
                    "[%s] 规则顶层应为 dict，实际 %s；使用内置兜底",
                    self.name,
                    type(data).__name__,
                )
            return strings_keys, template

        raw_keys = data.get("strings_keys")
        if isinstance(raw_keys, dict):
            parsed: dict[str, tuple[str, ...]] = {}
            for field_name, names in raw_keys.items():
                if not isinstance(field_name, str):
                    continue
                name_list = _as_str_list(names)
                if name_list:
                    parsed[field_name.strip()] = tuple(name_list)
            if parsed:
                strings_keys = parsed

        raw_lead = data.get("project_lead")
        if isinstance(raw_lead, dict):
            subject = raw_lead.get("subject")
            if isinstance(subject, str) and subject.strip():
                template.subject = subject.strip()
            where = raw_lead.get("where_to_request")
            if isinstance(where, str) and where.strip():
                template.where_to_request = where.strip()
            evidence = _as_str_list(raw_lead.get("evidence_to_obtain"))
            if evidence:
                template.evidence_to_obtain = evidence
            notes = raw_lead.get("notes")
            if isinstance(notes, str) and notes.strip():
                template.notes = notes.strip()

        return strings_keys, template


# ---------------------------------------------------------------------------
# 模块级工具函数
# ---------------------------------------------------------------------------


def _clean_str(value: object) -> str | None:
    """取非空 str（去空白）；非 str / 空 → None。"""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _host_from_database_url(url: str | None) -> str | None:
    """从 databaseURL（https://xxx.firebaseio.com 或 RTDB endpoint）抽 host。

    容错：已是裸 host（无 scheme）时原样返回；剥 scheme / 路径 / 端口 / 用户信息。
    """
    if not url:
        return None
    d = url.strip()
    if not d:
        return None
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0]
    if "@" in d:
        d = d.rsplit("@", 1)[1]
    d = d.split(":", 1)[0]
    d = d.strip().strip(".")
    return d or None
