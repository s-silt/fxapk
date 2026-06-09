"""deeplink_surface 分析器：枚举导出组件的 intent-filter / deeplink 外部入口攻击面。

与 components 分析器互补、不重复：
  - components 只标「组件 exported=true」（谁能被外部触发）；
  - 本分析器解析这些导出组件的 **intent-filter**，枚举可被外部（网页 / 其它 app）经
    自定义 scheme deeplink 拉起的入口（scheme://host/path + action + BROWSABLE），这是
    components 不覆盖的「具体可达入口面」。

反诈意义：涉诈 uni-app/H5 壳常注册自定义 scheme deeplink，被网页/短信链接拉起后打开
内置 WebView 加载服务端下发的 H5（可控内容），或直达支付/充值入口。BROWSABLE deeplink =
外部可控触发面，是 intent 注入 / scheme 劫持 / 诱导跳转的落点。

约束（与 manifest/components 一致）：
  - 只依赖 AnalysisContext 公开接口（manifest_xml），禁止 import androguard。
  - 用 xmlutil.safe_fromstring（拒 XXE）+ android_attr 解析；单点异常 try/except + logging。
  - 规则数据化（apkscan/rules/deeplink_surface.yaml）：高危组件名 hint → 升 severity。
  - 误报收敛：仅对**导出且带 intent-filter** 的组件产 Finding；普通无 scheme 的 filter 不产。
  - 全程 type hints。
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
import xml.parsers.expat as expat
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from apkscan.analyzers._common import as_str_list as _as_str_list
from apkscan.core.models import AnalyzerResult, Evidence, Finding, Severity
from apkscan.core.registry import BaseAnalyzer, load_rules
from apkscan.core.xmlutil import UnsafeXmlError as _UnsafeXmlError
from apkscan.core.xmlutil import android_attr as _android_attr
from apkscan.core.xmlutil import safe_fromstring as _safe_fromstring

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_RULES_NAME = "deeplink_surface"

# 组件类型（<application> 下）。
_COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")

# 内置高危组件名 hint（名字含这些词 → 升 HIGH：deeplink 直达 WebView/支付/跳转）。
_FALLBACK_HIGH_HINTS: tuple[str, ...] = (
    "webview", "web", "h5", "browser", "pay", "wallet", "recharge", "cashier",
    "jump", "redirect", "scheme", "deeplink", "router", "open", "external",
)


def _parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    v = value.strip().lower()
    if v in ("true", "1"):
        return True
    if v in ("false", "0"):
        return False
    return None


@dataclass
class _Deeplink:
    """一条枚举出的导出入口 deeplink。"""

    component: str
    kind: str
    scheme: str = ""
    host: str = ""
    path: str = ""
    actions: list[str] = field(default_factory=list)
    browsable: bool = False

    def uri(self) -> str:
        if not self.scheme:
            return ""
        base = f"{self.scheme}://{self.host}" if self.host else f"{self.scheme}://"
        return base + self.path


class DeeplinkSurfaceAnalyzer(BaseAnalyzer):
    """枚举导出组件的 deeplink 外部入口，产 category=\"attack_surface\" 的 Finding。"""

    name: str = "deeplink_surface"
    requires: list[str] = []  # 纯静态解析 manifest，永远可用

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        high_hints = self._load_rules()

        root = self._parse(ctx.manifest_xml, result)
        if root is None:
            result.meta["deeplinks"] = []
            return result

        try:
            deeplinks = self._enumerate(root)
        except Exception:  # noqa: BLE001 — 枚举失败不应炸 analyze
            logger.exception("[%s] deeplink 枚举失败", self.name)
            result.error = "deeplink 枚举失败（详见日志）"
            result.meta["deeplinks"] = []
            return result

        browsable = [d for d in deeplinks if d.browsable and d.scheme]
        for dl in browsable:
            try:
                result.findings.append(self._finding_for(dl, high_hints))
            except Exception:  # noqa: BLE001 — 单条失败不影响其余
                logger.exception("[%s] deeplink Finding 生成失败：%s", self.name, dl.component)

        result.meta["deeplinks"] = [
            {"component": d.component, "kind": d.kind, "uri": d.uri(), "browsable": d.browsable}
            for d in deeplinks
            if d.scheme
        ]
        result.meta["deeplink_count"] = len(result.meta["deeplinks"])
        result.meta["browsable_deeplink_count"] = len(browsable)
        if browsable:
            logger.info(
                "[%s] 枚举到外部可达 deeplink %d 条：%s",
                self.name,
                len(browsable),
                "、".join(sorted({d.uri() for d in browsable}))[:300],
            )
        return result

    # ------------------------------------------------------------------
    # 解析 / 枚举
    # ------------------------------------------------------------------

    def _parse(self, manifest_xml: str, result: AnalyzerResult) -> ET.Element | None:
        if not manifest_xml or not manifest_xml.strip():
            logger.info("[%s] manifest_xml 为空，跳过", self.name)
            return None
        try:
            return _safe_fromstring(manifest_xml)
        except _UnsafeXmlError:
            logger.warning("[%s] manifest 含 DTD/实体声明，拒绝解析（疑似 XXE）", self.name)
            result.error = "AndroidManifest 含 DTD/实体声明，已拒绝解析"
            return None
        except expat.ExpatError:
            logger.warning("[%s] manifest XML 解析失败", self.name)
            result.error = "AndroidManifest XML 解析失败"
            return None
        except Exception:  # noqa: BLE001
            logger.exception("[%s] manifest 解析未预期异常", self.name)
            result.error = "AndroidManifest 解析异常"
            return None

    def _enumerate(self, root: ET.Element) -> list[_Deeplink]:
        app = root.find("application")
        if app is None:
            return []
        out: list[_Deeplink] = []
        for tag in _COMPONENT_TAGS:
            for comp in app.findall(tag):
                filters = comp.findall("intent-filter")
                if not filters:
                    continue
                if not self._is_exported(comp, has_filter=True):
                    continue
                name = _android_attr(comp, "name") or "(anonymous)"
                for flt in filters:
                    out.extend(self._deeplinks_from_filter(flt, name, tag))
        return out

    @staticmethod
    def _is_exported(comp: ET.Element, *, has_filter: bool) -> bool:
        """导出判定：显式 exported=true；显式 false → 否；未声明 + 有 intent-filter → 隐式导出。

        （隐式导出是 Android 12 前的默认；保守起见对带 filter 的未声明组件按可被外部触发处理。）
        """
        explicit = _parse_bool(_android_attr(comp, "exported"))
        if explicit is True:
            return True
        if explicit is False:
            return False
        return has_filter

    def _deeplinks_from_filter(
        self, flt: ET.Element, component: str, kind: str
    ) -> list[_Deeplink]:
        actions = [
            a for a in (_android_attr(el, "name") for el in flt.findall("action")) if a
        ]
        categories = {
            c for c in (_android_attr(el, "name") for el in flt.findall("category")) if c
        }
        browsable = "android.intent.category.BROWSABLE" in categories

        out: list[_Deeplink] = []
        data_els = flt.findall("data")
        schemes = [s for s in (_android_attr(d, "scheme") for d in data_els) if s]
        hosts = [h for h in (_android_attr(d, "host") for d in data_els) if h]
        paths = [
            p
            for d in data_els
            for p in (
                _android_attr(d, "path"),
                _android_attr(d, "pathPrefix"),
                _android_attr(d, "pathPattern"),
            )
            if p
        ]
        if not schemes:
            return out
        # 每个 scheme 与首个 host/path 组合成一条 deeplink（host/path 仅作展示用途）。
        host = hosts[0] if hosts else ""
        path = paths[0] if paths else ""
        for scheme in schemes:
            # 跳过纯 http/https（那是 App Links，不是自定义 scheme deeplink 攻击面重点）。
            if scheme.lower() in ("http", "https") and not host:
                continue
            out.append(
                _Deeplink(
                    component=component,
                    kind=kind,
                    scheme=scheme,
                    host=host,
                    path=path,
                    actions=list(actions),
                    browsable=browsable,
                )
            )
        return out

    # ------------------------------------------------------------------
    # Finding
    # ------------------------------------------------------------------

    def _finding_for(self, dl: _Deeplink, high_hints: tuple[str, ...]) -> Finding:
        comp_low = dl.component.lower()
        is_high = any(h in comp_low for h in high_hints)
        severity = Severity.HIGH if is_high else Severity.MEDIUM
        uri = dl.uri()
        hint_note = (
            "组件名暗示直达 WebView/支付/跳转，外部可控触发风险更高。"
            if is_high
            else ""
        )
        description = (
            f"导出 {dl.kind} 「{dl.component}」注册了 BROWSABLE deeplink：{uri} 。"
            "可被网页 / 短信链接 / 其它 app 经该 scheme 从外部拉起并传入受控数据，"
            "是 intent 注入 / scheme 劫持 / 诱导跳转的入口。" + hint_note
        )
        return Finding(
            id=f"DEEPLINK-{dl.scheme}".upper()[:48],
            title=f"外部可达 deeplink 入口 ({dl.scheme}://)",
            severity=severity,
            category="attack_surface",
            description=description,
            recommendation=(
                "研判：jadx 跟踪该组件如何处理传入 URI（是否直接喂给 WebView.loadUrl / 拼接"
                "支付参数），评估服务端/外部是否可经此 deeplink 驱动内置 WebView 加载可控内容。"
            ),
            evidences=[
                Evidence(
                    source="manifest",
                    location=f"{dl.kind}[@android:name=\"{dl.component}\"]/intent-filter",
                    snippet=f'<data android:scheme="{dl.scheme}"'
                    + (f' android:host="{dl.host}"' if dl.host else "")
                    + "/>",
                )
            ],
            references=["https://developer.android.com/training/app-links/deep-linking"],
        )

    # ------------------------------------------------------------------
    # 规则
    # ------------------------------------------------------------------

    def _load_rules(self) -> tuple[str, ...]:
        data = load_rules(_RULES_NAME)
        if isinstance(data, dict):
            hints = _as_str_list(data.get("high_risk_component_hints"))
            if hints:
                return tuple(h.lower() for h in hints)
        elif data:
            logger.warning("[%s] 规则顶层应为 dict，实际 %s；用内置兜底", self.name, type(data).__name__)
        return _FALLBACK_HIGH_HINTS


__all__ = ["DeeplinkSurfaceAnalyzer"]
