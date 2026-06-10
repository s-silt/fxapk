"""ios_plist 分析器（IPA 专属）：解析 Info.plist → 冒充品牌 / URL scheme / ATS 明文 / 探测他 App / 权限用途。

iOS 涉诈包是 H5 壳，Info.plist 是它唯一的"清单"，相当于 Android 的 AndroidManifest，承载：
  - CFBundleIdentifier / CFBundleDisplayName：包标识 + **冒充品牌**（如显示名"XX证券"）
  - CFBundleURLTypes → CFBundleURLSchemes：**自定义 URL scheme**（外部可拉起的 deeplink 攻击面）
  - NSAppTransportSecurity（ATS）：是否放开**明文 HTTP**（NSAllowsArbitraryLoads / 例外域名）
  - LSApplicationQueriesSchemes：探测本机是否装了**支付宝/微信**等（资金诱导前置）
  - NS*UsageDescription：要相册/通讯录/定位/相机等的**权限用途文案**（数据窃取意图）

requires=["ipa"]：仅 IPA 上跑（APK 缺 ipa 能力 → pipeline 自动 skipped）。复用现有
Finding/Lead/CONFIG_KEY，不新增 LeadCategory。绝不抛、单点 try/except + logging、全程 type hints。
"""

from __future__ import annotations

import logging
import plistlib
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
from apkscan.core.registry import BaseAnalyzer

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

# 探测他 App 的高价值 scheme（资金/IM 诱导）→ 命中给提示。
_FINANCE_QUERY_SCHEMES: frozenset[str] = frozenset(
    {"alipay", "alipays", "weixin", "weixinapp", "wechat", "mqq", "mqqapi", "unionpay",
     "alipayqr", "weixinULAPI", "tenpay", "wxpay"}
)
# 敏感权限用途键（要这些 → 数据访问意图）。
_SENSITIVE_USAGE_KEYS: dict[str, str] = {
    "NSContactsUsageDescription": "通讯录",
    "NSCameraUsageDescription": "相机",
    "NSMicrophoneUsageDescription": "麦克风",
    "NSPhotoLibraryUsageDescription": "相册",
    "NSPhotoLibraryAddUsageDescription": "相册(写)",
    "NSLocationWhenInUseUsageDescription": "定位(使用时)",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "定位(始终)",
    "NSLocationAlwaysUsageDescription": "定位(始终,旧)",
    "NSFaceIDUsageDescription": "FaceID",
    "NSAppleMusicUsageDescription": "媒体库",
    "NSMotionUsageDescription": "运动",
    "NSCalendarsUsageDescription": "日历",
}


class IosPlistAnalyzer(BaseAnalyzer):
    """解析 IPA 的 Info.plist，产 iOS 攻击面 / 冒充品牌 / 数据访问意图线索。"""

    name: str = "ios_plist"
    requires: list[str] = ["ipa"]  # 仅 IPA 上跑

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        plist = self._load_plist(ctx, result)
        if plist is None:
            result.meta["ios_plist"] = "未找到/无法解析 Info.plist"
            return result

        bundle_id = _s(plist.get("CFBundleIdentifier"))
        display = _s(plist.get("CFBundleDisplayName")) or _s(plist.get("CFBundleName"))
        result.meta["ios_bundle_id"] = bundle_id
        result.meta["ios_display_name"] = display
        result.meta["ios_min_os"] = _s(plist.get("MinimumOSVersion"))

        try:
            self._emit_brand(bundle_id, display, result)
            self._emit_url_schemes(plist, result)
            self._emit_ats(plist, result)
            self._emit_query_schemes(plist, result)
            self._emit_usage(plist, result)
        except Exception:  # noqa: BLE001 — 单点失败不炸整体
            logger.exception("[%s] Info.plist 线索生成异常", self.name)
            if not result.error:
                result.error = "Info.plist 线索生成异常（详见日志）"
        return result

    # ------------------------------------------------------------------
    # 加载 Info.plist（经协议 read_file，FakeContext 也可测）
    # ------------------------------------------------------------------

    def _load_plist(self, ctx: "AnalysisContext", result: AnalyzerResult) -> dict[str, Any] | None:
        path = self._find_info_plist(ctx)
        if not path:
            return None
        try:
            raw = ctx.read_file(path)
        except Exception:  # noqa: BLE001
            logger.exception("[%s] 读取 Info.plist 失败：%s", self.name, path)
            result.error = "读取 Info.plist 失败"
            return None
        if not isinstance(raw, (bytes, bytearray)) or not raw:
            return None
        try:
            import io

            obj = plistlib.load(io.BytesIO(bytes(raw)))
        except Exception:  # noqa: BLE001
            logger.exception("[%s] plistlib 解析失败：%s", self.name, path)
            result.error = "Info.plist 解析失败"
            return None
        return obj if isinstance(obj, dict) else None

    def _find_info_plist(self, ctx: "AnalysisContext") -> str:
        """从 list_files 找 ``Payload/<App>.app/Info.plist``（取最浅的、直属 .app 的那个）。"""
        try:
            files = [f for f in ctx.list_files() if isinstance(f, str)]
        except Exception:  # noqa: BLE001
            logger.exception("[%s] list_files 失败", self.name)
            return ""
        candidates = [
            f for f in files
            if f.replace("\\", "/").endswith(".app/Info.plist")
        ]
        if not candidates:
            return ""
        # 取路径最短的（直属 .app 根，排除 framework/plugin 内嵌 Info.plist）。
        return min(candidates, key=lambda p: p.count("/"))

    # ------------------------------------------------------------------
    # 各类线索
    # ------------------------------------------------------------------

    def _emit_brand(self, bundle_id: str, display: str, result: AnalyzerResult) -> None:
        if not bundle_id and not display:
            return
        value = f"iOS:{bundle_id}" + (f"（{display}）" if display else "")
        result.leads.append(
            Lead(
                category=LeadCategory.CONFIG_KEY,
                value=value,
                subject=display or None,
                confidence=Confidence.MEDIUM,
                source_refs=[Evidence(source="resource", location="Info.plist", snippet=value)],
                notes=(
                    "iOS 应用标识 / 显示名（CFBundleDisplayName）。显示名常是**冒充品牌**"
                    "（如冒充某证券/银行）——结合 H5 端点研判冒充关系。"
                ),
            )
        )

    def _emit_url_schemes(self, plist: dict[str, Any], result: AnalyzerResult) -> None:
        schemes: list[str] = []
        url_types = plist.get("CFBundleURLTypes")
        if isinstance(url_types, list):
            for t in url_types:
                if isinstance(t, dict):
                    for s in _as_list(t.get("CFBundleURLSchemes")):
                        if s and s not in schemes:
                            schemes.append(s)
        if not schemes:
            return
        result.meta["ios_url_schemes"] = schemes
        result.findings.append(
            Finding(
                id="IOS-URL-SCHEME",
                title=f"自定义 URL scheme（外部可拉起）：{('、'.join(schemes))[:120]}",
                severity=Severity.MEDIUM,
                category="attack_surface",
                description=(
                    f"应用注册了自定义 URL scheme：{('、'.join(schemes))}。"
                    "可被网页 / 短信链接 / 其它 app 经 `<scheme>://` 从外部拉起并传入受控数据，"
                    "是 iOS 上对标 Android deeplink 的外部触发面（常用于拉起内置 WebView 加载可控内容）。"
                ),
                recommendation="研判：跟踪 scheme 处理逻辑是否把传入 URL 直接喂给 WKWebView。",
                evidences=[Evidence(source="resource", location="Info.plist/CFBundleURLTypes", snippet="；".join(schemes)[:200])],
                references=[],
            )
        )

    def _emit_ats(self, plist: dict[str, Any], result: AnalyzerResult) -> None:
        ats = plist.get("NSAppTransportSecurity")
        if not isinstance(ats, dict):
            return
        arbitrary = bool(ats.get("NSAllowsArbitraryLoads")) or bool(ats.get("NSAllowsArbitraryLoadsInWebContent"))
        exceptions = ats.get("NSExceptionDomains")
        has_exc = isinstance(exceptions, dict) and bool(exceptions)
        if not arbitrary and not has_exc:
            return
        detail = []
        if arbitrary:
            detail.append("NSAllowsArbitraryLoads=true（全局放开明文 HTTP）")
        if has_exc:
            doms = "、".join(list(exceptions.keys())[:8]) if isinstance(exceptions, dict) else ""
            detail.append(f"NSExceptionDomains 例外域名：{doms}")
        result.meta["ios_ats_cleartext"] = True
        result.findings.append(
            Finding(
                id="IOS-ATS-CLEARTEXT",
                title="ATS 放开明文 HTTP（App Transport Security）",
                severity=Severity.HIGH if arbitrary else Severity.MEDIUM,
                category="security",
                description=(
                    "Info.plist 的 NSAppTransportSecurity 放开了明文 HTTP：" + "；".join(detail) + "。"
                    "明文流量可被中间人嗅探/篡改；涉诈样本放开明文常为对接自家无 HTTPS 的 C2。"
                ),
                recommendation="研判：结合 H5/端点确认明文回传去向（可直接抓明文）。",
                evidences=[Evidence(source="resource", location="Info.plist/NSAppTransportSecurity", snippet="；".join(detail)[:200])],
                references=[],
            )
        )

    def _emit_query_schemes(self, plist: dict[str, Any], result: AnalyzerResult) -> None:
        queries = [s.lower() for s in _as_list(plist.get("LSApplicationQueriesSchemes")) if s]
        hits = sorted({s for s in queries if s in _FINANCE_QUERY_SCHEMES})
        if not hits:
            return
        result.meta["ios_finance_queries"] = hits
        result.findings.append(
            Finding(
                id="IOS-QUERY-PAYAPP",
                title=f"探测本机支付/IM 应用：{('、'.join(hits))}",
                severity=Severity.MEDIUM,
                category="ios",
                description=(
                    f"LSApplicationQueriesSchemes 声明要探测：{('、'.join(hits))}。"
                    "杀猪盘/投资盘常先探测被害人是否装了支付宝/微信，再诱导转账/拉起支付。"
                ),
                recommendation="研判：结合 H5 资金接口确认诱导支付链路。",
                evidences=[Evidence(source="resource", location="Info.plist/LSApplicationQueriesSchemes", snippet="、".join(hits)[:200])],
                references=[],
            )
        )

    def _emit_usage(self, plist: dict[str, Any], result: AnalyzerResult) -> None:
        hits: list[str] = []
        for key, label in _SENSITIVE_USAGE_KEYS.items():
            if key in plist:
                hits.append(label)
        if not hits:
            return
        result.meta["ios_sensitive_usage"] = hits
        result.findings.append(
            Finding(
                id="IOS-USAGE-DESC",
                title=f"申请敏感数据访问：{('、'.join(hits))}",
                severity=Severity.MEDIUM,
                category="permission",
                description=(
                    f"Info.plist 声明要访问：{('、'.join(hits))}（NS*UsageDescription）。"
                    "通讯录/相册/定位等是涉诈样本窃取个人信息的落点（对标 Android 危险权限）。"
                ),
                recommendation="研判：结合 H5/端点确认这些数据是否被外发。",
                evidences=[Evidence(source="resource", location="Info.plist", snippet="、".join(hits)[:200])],
                references=[],
            )
        )


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------


def _s(value: Any) -> str:
    return str(value).strip() if value not in (None, "") else ""


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if value not in (None, ""):
        return [str(value).strip()]
    return []
