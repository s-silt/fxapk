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
from apkscan.core.xmlutil import UnsafeXmlError as _UnsafeXmlError
from apkscan.core.xmlutil import android_attr as _android_attr
from apkscan.core.xmlutil import safe_fromstring as _safe_fromstring

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_SEVERITY_BY_NAME = {s.name: s for s in Severity}

# Xposed / LSPosed 模块的 <application> 内特征 meta-data name（小写比较）。
# 现代 LSPosed 模块可只用这些声明、不带 assets/xposed_init（re_toolkit 读不到 manifest，须在此覆盖）。
# ★低 FP：正常终端 app（含做反 Xposed 检测的 RASP）绝不会把自己声明为 Xposed 模块。
_XPOSED_META_NAMES = frozenset(
    {"xposedmodule", "xposedminversion", "xposeddescription", "xposedscope"}
)


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
    requires: list[str] = ["apk"]  # Android 专属；IPA 上 pipeline 自动 skipped

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

        # 清单投毒 / 解析不可靠信号：apk.py 对包名做 androguard × aapt 交叉校验（或无 aapt 时的
        # sanity）得出异常时，显式发一条 HIGH Finding + 落 meta，避免“错的核心事实（如包名）”被
        # 静默采信（治构造 AndroidManifest 让 androguard mis-parse 而 aapt/运行时正常的清单投毒）。
        anomaly = getattr(ctx, "manifest_anomaly", None)
        if anomaly:
            meta["manifest_anomaly"] = anomaly
            # 关键：把 meta 包名回正到已交叉校验的权威值 ctx.package_name。上面 _extract() 会用
            # manifest_xml 里（androguard 视角、可能被投毒的）package 覆盖 meta["package_name"]，
            # 而 digest / graph ingest 都优先取 meta["package_name"]（`meta.get(...) or report...`）——
            # 不回正则报告与图谱仍按诱饵包名归档，加固的主场景被绕过。
            meta["package_name"] = ctx.package_name or None
            result.findings.append(
                Finding(
                    id="MANIFEST-PARSE-ANOMALY",
                    title="清单解析异常（疑清单投毒）",
                    severity=Severity.HIGH,
                    category="manifest",
                    description=str(anomaly),
                    recommendation=(
                        "核心字段（包名等）可能被清单构造干扰；下游动态抓包/脱壳请以校验后的包名为准，必要时人工核实。"
                    ),
                )
            )

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

            # Xposed/LSPosed 模块身份：<application> 内的特征 meta-data。
            markers: list[str] = []
            for md in app.findall("meta-data"):
                nm = _android_attr(md, "name")
                if nm and nm.strip().lower() in _XPOSED_META_NAMES:
                    markers.append(nm.strip())
            if markers:
                meta["xposed_module"] = True
                meta["xposed_markers"] = sorted(set(markers))

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

        # Xposed/LSPosed 模块身份 → HIGH（anti_analysis）
        self._emit_xposed_module(meta, result)

    def _emit_xposed_module(self, meta: dict[str, Any], result: AnalyzerResult) -> None:
        """<application> 声明为 Xposed/LSPosed 模块 → HIGH anti_analysis Finding。

        直接构造（非 manifest 模板，因 category=anti_analysis 而非 manifest，与 re_toolkit 的
        hook/反检测工具链归为同类，供 digest / 串案统一消费）。
        """
        if not meta.get("xposed_module"):
            return
        markers = meta.get("xposed_markers") or []
        ev = [
            Evidence(
                source="manifest",
                location="application/meta-data[@android:name]",
                snippet="、".join(str(m) for m in markers)[:200],
            )
        ]
        result.findings.append(
            Finding(
                id="MANIFEST-XPOSED-MODULE",
                title="APK 声明为 Xposed/LSPosed 模块（疑用于 hook 其它 app）",
                severity=Severity.HIGH,
                category="anti_analysis",
                description=(
                    "AndroidManifest 的 <application> 内含 Xposed 模块声明 meta-data（"
                    + "、".join(str(m) for m in markers)
                    + "）——本 APK 是一个 Xposed/LSPosed 模块，设计用于在设备上 hook / 篡改其它 app。"
                    "★ 正常终端 app 绝不会把自己做成 Xposed 模块；常见于远控 / 虚拟摄像头刷脸 / "
                    "改包 / 劫持银行·支付类黑产工具。"
                ),
                recommendation=(
                    "研判其 hook 目标（xposedscope 指定的目标包名）与 AccessibilityService / 无障碍权限，"
                    "确认是否劫持第三方 app；把 Xposed 模块身份作为团伙工具链指纹并簇串案。"
                ),
                evidences=ev,
                references=["https://developer.android.com/topic/security"],
            )
        )

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
