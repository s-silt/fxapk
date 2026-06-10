"""components 分析器：枚举四大组件的导出情况，产出攻击面 Finding。

职责（见设计文档 §3/§4 "components" 行）：
  - 用 ctx.components() 获取 activity/service/receiver/provider 四类组件。
  - 对每个 exported=True 的组件产出 Finding(category="component")：
      * activity / service / receiver → 默认 MEDIUM
      * provider（ContentProvider，可读/可写数据）→ HIGH
  - description 说明该导出组件构成的攻击面与涉诈调证价值。
  - 汇总信息写入 AnalyzerResult.meta（导出/总数统计），供报告"概览/技术附录"使用。

约束：
  - 只依赖 AnalysisContext 公开接口（components()），禁止 import androguard。
  - 规则经 registry.load_rules("components") 读取（apkscan/rules/components.yaml）；
    规则缺失/异常时回退到内置安全默认，仍能正常产出 Finding。
  - 单点解析异常 try/except + logging，不让单条组件/单个数据源炸掉整个 analyze；
    不静默 pass。
  - 全程 type hints。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from apkscan.core.models import (
    AnalyzerResult,
    Component,
    ComponentSet,
    Evidence,
    Finding,
    Severity,
)
from apkscan.core.registry import BaseAnalyzer, load_rules

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_RULES_NAME = "components"

_SEVERITY_BY_NAME: dict[str, Severity] = {s.name: s for s in Severity}

# 组件类型 → (Finding 默认 id, 默认严重度)。provider 默认 HIGH（数据泄露面）。
_KIND_DEFAULTS: dict[str, tuple[str, Severity]] = {
    "activity": ("COMPONENT-EXPORTED-ACTIVITY", Severity.MEDIUM),
    "service": ("COMPONENT-EXPORTED-SERVICE", Severity.MEDIUM),
    "receiver": ("COMPONENT-EXPORTED-RECEIVER", Severity.MEDIUM),
    "provider": ("COMPONENT-EXPORTED-PROVIDER", Severity.HIGH),
}

# 组件类型的中文展示名（用于回退描述）。
_KIND_LABEL: dict[str, str] = {
    "activity": "Activity",
    "service": "Service",
    "receiver": "BroadcastReceiver",
    "provider": "ContentProvider",
}

# 内置回退描述（规则文件缺失/某类型模板缺失时使用，保证仍合规可用）。
_FALLBACK_DESC: dict[str, str] = {
    "activity": (
        "该 Activity 已导出，可被任意外部应用通过 Intent 拉起，"
        "可能绕过登录态直达内部界面或被注入参数。"
    ),
    "service": (
        "该 Service 已导出，可被外部应用 bind/start 触发，"
        "涉诈 App 常用于承载推送/远控/短信转发/后台保活逻辑。"
    ),
    "receiver": (
        "该 BroadcastReceiver 已导出，可被外部应用发送广播触发；"
        "若监听 SMS_RECEIVED/BOOT_COMPLETED 则疑似窃码或保活。"
    ),
    "provider": (
        "该 ContentProvider 已导出，外部应用可经 content:// URI 读写应用私有数据，"
        "构成直接数据泄露面（服务器地址/商户号/本地账本等）。"
    ),
}

_FALLBACK_RECOMMENDATION: dict[str, str] = {
    "activity": "研判：用 am start 拉起导出 Activity，观察是否绕过鉴权、是否回显接口域名。",
    "service": "研判：分析导出 Service 协议，必要时主动绑定触发，观察外联端点与远控行为。",
    "receiver": "研判：检查导出 Receiver 监听的 action，结合短信/通知权限研判窃码链路。",
    "provider": "研判：用 content query/insert 验证读写权限，提取本地落地的服务器地址与账本数据。",
}


@dataclass
class _Rules:
    """从 YAML 规整后的组件规则（含 Finding 模板与研判提示）。"""

    finding_templates: dict[str, dict[str, Any]] = field(default_factory=dict)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    provider_writable_hints: list[str] = field(default_factory=list)
    sensitive_name_hints: dict[str, list[str]] = field(default_factory=dict)


class ComponentsAnalyzer(BaseAnalyzer):
    """枚举导出组件，产出攻击面 Finding（provider 可读写 → HIGH）。"""

    name: str = "components"
    requires: list[str] = ["apk"]  # Android 专属；IPA 上 pipeline 自动 skipped

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        rules = self._load_rules()

        comp_set = self._read_components(ctx, result)
        if comp_set is None:
            return result

        # (组件列表, kind) —— kind 显式传入，不依赖 Component.kind 字段是否填写。
        groups: list[tuple[list[Component], str]] = [
            (comp_set.activities, "activity"),
            (comp_set.services, "service"),
            (comp_set.receivers, "receiver"),
            (comp_set.providers, "provider"),
        ]

        totals: dict[str, int] = {}
        exported_counts: dict[str, int] = {}
        exported_components: list[dict] = []  # 报告附录"导出组件"表消费

        for components, kind in groups:
            total = 0
            exported = 0
            for comp in components:
                try:
                    counted, was_exported = self._process_component(comp, kind, rules, result)
                except Exception:  # noqa: BLE001 — 单组件失败不应炸掉整个 analyze
                    logger.exception("[%s] 处理组件失败，跳过：%r", self.name, comp)
                    continue
                if counted:
                    total += 1
                    if was_exported:
                        exported += 1
                        name = (getattr(comp, "name", "") or "").strip()
                        if name:
                            exported_components.append(
                                {
                                    "name": name,
                                    "kind": (getattr(comp, "kind", "") or kind),
                                    "exported": True,
                                }
                            )
            totals[kind] = total
            exported_counts[kind] = exported

        result.meta["component_totals"] = totals
        result.meta["exported_counts"] = exported_counts
        result.meta["exported_total"] = sum(exported_counts.values())
        result.meta["components"] = exported_components
        return result

    # ------------------------------------------------------------------
    # 数据源采集
    # ------------------------------------------------------------------

    def _read_components(
        self, ctx: "AnalysisContext", result: AnalyzerResult
    ) -> ComponentSet | None:
        """读取 ctx.components()；失败记 error 返回 None，不抛出。"""
        try:
            comp_set = ctx.components()
        except Exception:  # noqa: BLE001
            logger.exception("[%s] 读取 components 失败", self.name)
            result.error = "读取组件集合失败（详见日志）"
            return None
        if comp_set is None:
            logger.warning("[%s] ctx.components() 返回 None，按空组件处理", self.name)
            return ComponentSet()
        return comp_set

    # ------------------------------------------------------------------
    # 单组件处理
    # ------------------------------------------------------------------

    def _process_component(
        self,
        comp: Component,
        kind: str,
        rules: _Rules,
        result: AnalyzerResult,
    ) -> tuple[bool, bool]:
        """处理单个组件。

        返回 (是否计入统计, 是否导出)。仅对 exported=True 的组件产 Finding。
        """
        name = getattr(comp, "name", None)
        if not isinstance(name, str) or not name.strip():
            logger.warning("[%s] 跳过缺少 name 的组件：%r", self.name, comp)
            return False, False
        name = name.strip()

        # 优先用组件自带 kind（若有效），否则用分组传入的 kind。
        comp_kind = getattr(comp, "kind", "") or ""
        effective_kind = comp_kind if comp_kind in _KIND_DEFAULTS else kind

        exported = bool(getattr(comp, "exported", False))
        if not exported:
            return True, False

        finding = self._build_finding(name, effective_kind, rules)
        result.findings.append(finding)
        return True, True

    def _build_finding(self, name: str, kind: str, rules: _Rules) -> Finding:
        """为一个导出组件构造 Finding，合并规则模板与内置回退。"""
        default_id, default_sev = _KIND_DEFAULTS.get(
            kind, ("COMPONENT-EXPORTED", Severity.MEDIUM)
        )
        tpl = rules.finding_templates.get(kind, {})

        severity = self._resolve_severity(kind, tpl, rules, default_sev)

        base_desc = str(tpl.get("description", "")).strip() or _FALLBACK_DESC.get(
            kind, "该组件已导出，可被外部应用访问，构成攻击面。"
        )
        label = _KIND_LABEL.get(kind, "组件")
        description = f"导出{label}：{name}\n\n{base_desc}"

        recommendation = str(tpl.get("recommendation", "")).strip() or (
            _FALLBACK_RECOMMENDATION.get(kind, "研判：主动触发该导出组件，观察其行为与外联端点。")
        )

        # provider 命中可写/敏感名提示 → 在描述追加研判标注（严重度已为 HIGH）。
        notes = self._sensitive_notes(name, kind, rules)
        if notes:
            description = f"{description}\n\n研判提示：{notes}"

        references = tpl.get("references", [])
        if not isinstance(references, list):
            references = [str(references)]

        ev = [
            Evidence(
                source="manifest",
                location=name,
                snippet=f'<{kind} android:name="{name}" android:exported="true"/>',
            )
        ]

        return Finding(
            id=str(tpl.get("id", default_id)),
            title=str(tpl.get("title", f"导出的{label}")),
            severity=severity,
            category="component",
            description=description,
            recommendation=recommendation,
            evidences=ev,
            references=[str(r) for r in references],
        )

    def _resolve_severity(
        self,
        kind: str,
        tpl: dict[str, Any],
        rules: _Rules,
        default_sev: Severity,
    ) -> Severity:
        """确定严重度：模板 severity > 规则 severity override > 内置默认。"""
        sev_name = tpl.get("severity")
        if isinstance(sev_name, str):
            sev = _SEVERITY_BY_NAME.get(sev_name.strip().upper())
            if sev is not None:
                return sev
        override = rules.severity_overrides.get(kind)
        if override is not None:
            return override
        return default_sev

    def _sensitive_notes(self, name: str, kind: str, rules: _Rules) -> str:
        """对组件名做研判标注：provider 可写命中、SMS/支付/远控等敏感关键字命中。"""
        low = name.lower()
        notes: list[str] = []

        if kind == "provider":
            hits = [h for h in rules.provider_writable_hints if h and h.lower() in low]
            if hits:
                notes.append(
                    "疑似可读/可写敏感数据 Provider（命中：" + "、".join(hits) + "），"
                    "外部可经 content:// 直接提取本地落地数据"
                )

        for tag, keywords in rules.sensitive_name_hints.items():
            hit = next((kw for kw in keywords if kw and kw.lower() in low), None)
            if hit:
                notes.append(f"涉诈高敏面[{tag}]（命中：{hit}）")

        return "；".join(notes)

    # ------------------------------------------------------------------
    # 规则加载
    # ------------------------------------------------------------------

    def _load_rules(self) -> _Rules:
        """加载并规整 components.yaml；缺失/异常回退到空规则（内置默认仍生效）。"""
        rules = _Rules()
        try:
            data = load_rules(_RULES_NAME)
        except Exception:  # noqa: BLE001 — 规则加载失败不应炸掉 analyze
            logger.exception("[%s] 加载规则失败，使用内置默认", self.name)
            return rules

        if not isinstance(data, dict):
            logger.warning(
                "[%s] 规则顶层应为 dict，实际 %s；使用内置默认",
                self.name,
                type(data).__name__,
            )
            return rules

        findings = data.get("findings")
        if isinstance(findings, dict):
            rules.finding_templates = {
                k: v for k, v in findings.items() if isinstance(v, dict)
            }

        sev = data.get("severity")
        if isinstance(sev, dict):
            for kind, val in sev.items():
                if isinstance(val, str):
                    parsed = _SEVERITY_BY_NAME.get(val.strip().upper())
                    if parsed is not None and isinstance(kind, str):
                        rules.severity_overrides[kind] = parsed

        rules.provider_writable_hints = _as_str_list(data.get("provider_writable_hints"))

        hints = data.get("sensitive_name_hints")
        if isinstance(hints, dict):
            rules.sensitive_name_hints = {
                str(tag): _as_str_list(kws)
                for tag, kws in hints.items()
                if _as_str_list(kws)
            }

        return rules


# ---------------------------------------------------------------------------
# 模块级工具函数
# ---------------------------------------------------------------------------


def _as_str_list(value: object) -> list[str]:
    """把规则字段规整为 str 列表（容忍 None / 非 list / 含非 str 元素）。"""
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]
