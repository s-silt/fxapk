"""manifest 分析器：解析 AndroidManifest，提取基础指纹与安全风险。

职责（见设计文档 §3/§4 "manifest" 行）:
  - 解析 ctx.manifest_xml + ctx.package_name，提取:
      package / versionName / versionCode / minSdkVersion / targetSdkVersion
      / debuggable / allowBackup / usesCleartextTraffic
  - 这些写入 AnalyzerResult.meta（供 Report.meta，报告"概览/基础指纹"区使用）。
  - debuggable / allowBackup / 明文流量 → Finding(category="manifest")。
  - targetSdk 偏低 → Finding（涉诈马甲包常压低 targetSdk 规避新版管控）。

约束:
  - 只依赖 AnalysisContext 公开接口（manifest_xml/package_name），禁止 import androguard。
  - 用 xml.etree 解析；解析异常 try/except + logging，不让单点失败炸掉 analyze。
  - 规则经 registry.load_rules("manifest") 读取（apkscan/rules/manifest.yaml）。
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
import xml.parsers.expat as expat
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

# Android 资源命名空间；ElementTree 会把 android:foo 展开为 {NS}foo。
_ANDROID_NS = "http://schemas.android.com/apk/res/android"

_SEVERITY_BY_NAME = {s.name: s for s in Severity}


class _UnsafeXmlError(ValueError):
    """manifest 中出现 DTD/实体声明（XXE / billion-laughs 攻击面），拒绝解析。"""


def _safe_fromstring(manifest_xml: str) -> ET.Element:
    """用 stdlib expat + ElementTree.TreeBuilder 安全解析，封堵 XXE / billion-laughs。

    spec 要求用 xml.etree、且不得引入 defusedxml 等额外依赖。CPython 3.12 的
    ET.XMLParser 走 C 加速实现、不暴露可改的 expat 钩子，故这里直接用
    xml.parsers.expat 创建解析器并安装拒绝处理器：
      - 关闭参数实体解析（SetParamEntityParsing(NEVER)）→ 阻断外部 DTD 拉取（XXE）；
      - 任何 <!ENTITY> 定义（内部/外部/未解析）→ 直接抛错（封堵 billion-laughs）；
      - <!NOTATION>、外部实体引用 → 抛错。
    元素/文本/属性事件转发给 ET.TreeBuilder，产出标准 ET.Element。
    AndroidManifest 本身不含 DTD/实体，正常输入不受影响。
    """
    builder = ET.TreeBuilder()
    parser = expat.ParserCreate()

    def _reject(*_args: object, **_kwargs: object) -> None:
        raise _UnsafeXmlError("manifest 含 DTD/实体声明或外部引用，已拒绝解析")

    # 阻断外部 DTD / 参数实体（XXE 主路径）。
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    # 任何实体声明/记法/外部实体引用一律拒绝。
    parser.EntityDeclHandler = _reject
    parser.UnparsedEntityDeclHandler = _reject
    parser.NotationDeclHandler = _reject
    parser.ExternalEntityRefHandler = _reject  # type: ignore[assignment]

    # 转发解析事件到 ElementTree TreeBuilder。
    parser.StartElementHandler = builder.start
    parser.EndElementHandler = builder.end
    parser.CharacterDataHandler = builder.data

    parser.Parse(manifest_xml, True)
    return builder.close()


def _android_attr(elem: ET.Element, name: str) -> str | None:
    """读取 android:<name> 属性；兼容已展开命名空间与裸属性两种形态。"""
    val = elem.get(f"{{{_ANDROID_NS}}}{name}")
    if val is not None:
        return val
    # 部分上游（如 androguard 反编译出的字符串）可能不带命名空间前缀。
    return elem.get(f"android:{name}", elem.get(name))


def _parse_bool(value: str | None) -> bool | None:
    """把 Android manifest 的布尔属性字符串解析为 bool；无法判定返回 None。"""
    if value is None:
        return None
    v = value.strip().lower()
    if v in ("true", "1"):
        return True
    if v in ("false", "0"):
        return False
    return None


def _parse_int(value: str | None) -> int | None:
    """把 sdk 版本属性解析为 int；非数字（如 "S"/"Tiramisu" 代号）返回 None。"""
    if value is None:
        return None
    v = value.strip()
    try:
        return int(v)
    except (TypeError, ValueError):
        logger.debug("无法解析为整数的版本属性: %r", value)
        return None


def _finding_from_template(
    tpl: dict[str, Any],
    fallback_id: str,
    fallback_severity: Severity,
    evidences: list[Evidence],
    *,
    extra_desc: str = "",
) -> Finding:
    """根据规则模板构造 Finding；模板缺字段时回退到安全默认。"""
    sev_name = str(tpl.get("severity", fallback_severity.name)).upper()
    severity = _SEVERITY_BY_NAME.get(sev_name, fallback_severity)
    description = str(tpl.get("description", "")).strip()
    if extra_desc:
        description = f"{description}\n\n{extra_desc}".strip()
    references = tpl.get("references", [])
    if not isinstance(references, list):
        references = [str(references)]
    return Finding(
        id=str(tpl.get("id", fallback_id)),
        title=str(tpl.get("title", fallback_id)),
        severity=severity,
        category="manifest",
        description=description,
        recommendation=str(tpl.get("recommendation", "")).strip(),
        evidences=evidences,
        references=[str(r) for r in references],
    )


class ManifestAnalyzer(BaseAnalyzer):
    """解析 AndroidManifest，产出基础指纹 meta 与安全 Finding。"""

    name = "manifest"
    requires: list[str] = []  # 纯静态解析，永远可用

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        rules = load_rules("manifest")
        if not isinstance(rules, dict):
            logger.warning("manifest 规则顶层应为 dict，实际 %s；按空规则处理", type(rules).__name__)
            rules = {}

        meta: dict[str, Any] = {
            "package_name": ctx.package_name or None,
            "version_name": None,
            "version_code": None,
            "min_sdk": None,
            "target_sdk": None,
            "debuggable": None,
            "allow_backup": None,
            "uses_cleartext_traffic": None,
        }

        root = self._parse_manifest(ctx.manifest_xml, result, meta)
        if root is not None:
            try:
                self._extract(root, meta)
            except Exception:  # noqa: BLE001 — 单点失败不应炸掉整个 analyze
                logger.exception("manifest 字段提取失败")
                result.error = "manifest 字段提取失败（详见日志）"

        # package 优先用 manifest 内声明，回退到 ctx.package_name。
        if not meta.get("package_name"):
            meta["package_name"] = ctx.package_name or None

        try:
            self._emit_findings(meta, rules, result)
        except Exception:  # noqa: BLE001
            logger.exception("manifest Finding 生成失败")
            if not result.error:
                result.error = "manifest Finding 生成失败（详见日志）"

        # 研判提示（不阻断），写入 meta 供报告参考。
        self._annotate_suspicious(meta, rules)

        result.meta = meta
        return result

    # ------------------------------------------------------------------
    # 解析
    # ------------------------------------------------------------------

    def _parse_manifest(
        self,
        manifest_xml: str,
        result: AnalyzerResult,
        meta: dict[str, Any],
    ) -> ET.Element | None:
        """安全解析 manifest_xml；失败记 error，不抛出。"""
        if not manifest_xml or not manifest_xml.strip():
            logger.warning("manifest_xml 为空，跳过 manifest 解析")
            result.error = "manifest_xml 为空"
            return None
        try:
            return _safe_fromstring(manifest_xml)
        except _UnsafeXmlError:
            logger.exception("AndroidManifest 含 DTD/实体声明，已拒绝解析")
            result.error = "AndroidManifest 含 DTD/实体声明，已拒绝解析（疑似 XXE）"
            return None
        except expat.ExpatError:
            logger.exception("AndroidManifest XML 解析失败")
            result.error = "AndroidManifest XML 解析失败（详见日志）"
            return None
        except Exception:  # noqa: BLE001
            logger.exception("AndroidManifest 解析出现未预期异常")
            result.error = "AndroidManifest 解析异常（详见日志）"
            return None

    def _extract(self, root: ET.Element, meta: dict[str, Any]) -> None:
        """从已解析的 <manifest> 树提取基础指纹字段，写入 meta。"""
        # <manifest> 根节点属性
        pkg = root.get("package")
        if pkg:
            meta["package_name"] = pkg
        meta["version_name"] = _android_attr(root, "versionName")
        meta["version_code"] = _android_attr(root, "versionCode")

        # <uses-sdk>（旧式声明）
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            meta["min_sdk"] = _parse_int(_android_attr(uses_sdk, "minSdkVersion"))
            meta["target_sdk"] = _parse_int(_android_attr(uses_sdk, "targetSdkVersion"))

        # <application> 安全标志
        app = root.find("application")
        if app is not None:
            meta["debuggable"] = _parse_bool(_android_attr(app, "debuggable"))
            # allowBackup 默认（未声明）为 true（API<31），故 None 也按"允许"研判。
            meta["allow_backup"] = _parse_bool(_android_attr(app, "allowBackup"))
            meta["uses_cleartext_traffic"] = _parse_bool(
                _android_attr(app, "usesCleartextTraffic")
            )
            # networkSecurityConfig 存在即记录，提示可能放开明文。
            nsc = _android_attr(app, "networkSecurityConfig")
            if nsc:
                meta["network_security_config"] = nsc

    # ------------------------------------------------------------------
    # Finding 生成
    # ------------------------------------------------------------------

    def _emit_findings(
        self,
        meta: dict[str, Any],
        rules: dict[str, Any],
        result: AnalyzerResult,
    ) -> None:
        templates = rules.get("findings", {})
        if not isinstance(templates, dict):
            templates = {}

        # debuggable=true → MEDIUM
        if meta.get("debuggable") is True:
            ev = [
                Evidence(
                    source="manifest",
                    location="application[@android:debuggable]",
                    snippet="android:debuggable=\"true\"",
                )
            ]
            result.findings.append(
                _finding_from_template(
                    templates.get("debuggable", {}),
                    "MANIFEST-DEBUGGABLE",
                    Severity.MEDIUM,
                    ev,
                )
            )

        # allowBackup=true → LOW
        if meta.get("allow_backup") is True:
            ev = [
                Evidence(
                    source="manifest",
                    location="application[@android:allowBackup]",
                    snippet="android:allowBackup=\"true\"",
                )
            ]
            result.findings.append(
                _finding_from_template(
                    templates.get("allow_backup", {}),
                    "MANIFEST-ALLOWBACKUP",
                    Severity.LOW,
                    ev,
                )
            )

        # 明文流量：usesCleartextTraffic=true，或存在 networkSecurityConfig（可能放开）。
        cleartext = meta.get("uses_cleartext_traffic")
        nsc = meta.get("network_security_config")
        if cleartext is True or nsc:
            loc = (
                "application[@android:usesCleartextTraffic]"
                if cleartext is True
                else "application[@android:networkSecurityConfig]"
            )
            snippet = (
                'android:usesCleartextTraffic="true"'
                if cleartext is True
                else f'android:networkSecurityConfig="{nsc}"'
            )
            extra = (
                ""
                if cleartext is True
                else "（经 networkSecurityConfig 自定义，明文策略需人工核对该配置文件）"
            )
            ev = [Evidence(source="manifest", location=loc, snippet=snippet)]
            result.findings.append(
                _finding_from_template(
                    templates.get("cleartext_traffic", {}),
                    "MANIFEST-CLEARTEXT",
                    Severity.MEDIUM,
                    ev,
                    extra_desc=extra,
                )
            )

        # targetSdk 偏低 → LOW
        self._emit_low_target_sdk(meta, rules, templates, result)

    def _emit_low_target_sdk(
        self,
        meta: dict[str, Any],
        rules: dict[str, Any],
        templates: dict[str, Any],
        result: AnalyzerResult,
    ) -> None:
        target_sdk = meta.get("target_sdk")
        if not isinstance(target_sdk, int):
            return
        floor_cfg = rules.get("sdk_floor", {})
        floor = floor_cfg.get("target_sdk_min") if isinstance(floor_cfg, dict) else None
        if not isinstance(floor, int):
            return
        if target_sdk >= floor:
            return
        ev = [
            Evidence(
                source="manifest",
                location="uses-sdk[@android:targetSdkVersion]",
                snippet=f'android:targetSdkVersion="{target_sdk}"',
            )
        ]
        extra = f"检出 targetSdk={target_sdk}，低于合规下限 {floor}。"
        result.findings.append(
            _finding_from_template(
                templates.get("low_target_sdk", {}),
                "MANIFEST-LOW-TARGETSDK",
                Severity.LOW,
                ev,
                extra_desc=extra,
            )
        )

    # ------------------------------------------------------------------
    # 研判提示
    # ------------------------------------------------------------------

    def _annotate_suspicious(self, meta: dict[str, Any], rules: dict[str, Any]) -> None:
        """对可疑 versionName 等做研判标注，写入 meta["suspicious"]（不报 Finding）。"""
        try:
            cfg = rules.get("suspicious_versions", {})
            keywords = cfg.get("version_name_keywords", []) if isinstance(cfg, dict) else []
            if not isinstance(keywords, list):
                return
            vname = meta.get("version_name")
            if not vname:
                return
            low = str(vname).lower()
            hits = [kw for kw in keywords if kw and str(kw).lower() in low]
            if hits:
                meta["suspicious_version_name"] = True
                meta["suspicious_version_hits"] = hits
        except Exception:  # noqa: BLE001 — 研判提示失败不影响主流程
            logger.exception("manifest 可疑版本研判失败")
