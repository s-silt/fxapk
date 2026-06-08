"""apkscan.report.html — 用 Jinja2 渲染单文件 HTML 报告。

提供按 LeadCategory 分组、按 confidence 排序的辅助函数，供模板使用。
渲染产物为自包含单文件（CSS 内联），可直接分享给调证人员。
"""

from __future__ import annotations

import importlib.resources
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from apkscan.core.models import (
    Confidence,
    Endpoint,
    Lead,
    LeadCategory,
    Report,
)

_TEMPLATE_NAME = "report.html.j2"

# LeadCategory → 中文标签（用于线索清单分组标题）。
CATEGORY_LABELS: dict[LeadCategory, str] = {
    LeadCategory.CONFIG_KEY: "调用插件 / 配置键值",
    LeadCategory.DOMAIN: "域名线索",
    LeadCategory.IP: "IP 线索",
    LeadCategory.SDK_SERVICE: "第三方 SDK / 服务",
    LeadCategory.PAYMENT: "支付 / 资金线索",
    LeadCategory.PACKER: "加固厂商线索",
    LeadCategory.CONTACT: "联系方式线索",
    LeadCategory.SIGNING: "签名 / 开发者线索",
    LeadCategory.CHANNEL: "分发渠道线索",
}

# 调证人员视角下的分组展示顺序（配置键值最高优先，其次资金/SDK/联系方式）。
CATEGORY_ORDER: list[LeadCategory] = [
    LeadCategory.CONFIG_KEY,
    LeadCategory.PAYMENT,
    LeadCategory.SDK_SERVICE,
    LeadCategory.CONTACT,
    LeadCategory.DOMAIN,
    LeadCategory.IP,
    LeadCategory.PACKER,
    LeadCategory.SIGNING,
    LeadCategory.CHANNEL,
]

# advice（调证研判建议）归一化：用于判断是否「建议调证」。
ADVICE_NEED = "建议调证"
ADVICE_SKIP = "无需调证"

# confidence 排序权重：HIGH 在前。
_CONFIDENCE_RANK: dict[Confidence, int] = {
    Confidence.HIGH: 0,
    Confidence.MEDIUM: 1,
    Confidence.LOW: 2,
}

CONFIDENCE_LABELS: dict[Confidence, str] = {
    Confidence.HIGH: "高",
    Confidence.MEDIUM: "中",
    Confidence.LOW: "低",
}


def _confidence_of(lead: Lead) -> Confidence:
    """容错取出 lead 的 confidence；非法值按 MEDIUM 处理。"""
    conf = lead.confidence
    return conf if isinstance(conf, Confidence) else Confidence.MEDIUM


def sort_leads_by_confidence(leads: list[Lead]) -> list[Lead]:
    """按 confidence 降序（HIGH→LOW）稳定排序。"""
    return sorted(leads, key=lambda lead: _CONFIDENCE_RANK.get(_confidence_of(lead), 1))


def group_leads_by_category(leads: list[Lead]) -> list[dict[str, Any]]:
    """按 LeadCategory 分组、组内按 confidence 排序。

    返回 [{category, label, leads}]，仅含非空分组，按 CATEGORY_ORDER 排列；
    未在 CATEGORY_ORDER 中的分类追加在末尾（保持稳定）。
    """
    buckets: dict[LeadCategory, list[Lead]] = {}
    extras: list[LeadCategory] = []
    for lead in leads:
        cat = lead.category if isinstance(lead.category, LeadCategory) else None
        if cat is None:
            continue
        if cat not in buckets:
            buckets[cat] = []
            if cat not in CATEGORY_ORDER:
                extras.append(cat)
        buckets[cat].append(lead)

    ordered = [c for c in CATEGORY_ORDER if c in buckets] + extras
    groups: list[dict[str, Any]] = []
    for cat in ordered:
        groups.append(
            {
                "category": cat,
                "label": CATEGORY_LABELS.get(cat, cat.value),
                "leads": sort_leads_by_confidence(buckets[cat]),
            }
        )
    return groups


def confidence_label(conf: Confidence | str | None) -> str:
    """confidence → 中文标签（高/中/低），供模板调用。"""
    if isinstance(conf, Confidence):
        return CONFIDENCE_LABELS.get(conf, conf.value)
    if isinstance(conf, str):
        try:
            return CONFIDENCE_LABELS[Confidence(conf)]
        except ValueError:
            return conf
    return ""


def confidence_class(conf: Confidence | str | None) -> str:
    """confidence → CSS 类名（用于上色 badge）。"""
    value = conf.value if isinstance(conf, Confidence) else str(conf or "")
    return f"conf-{value.lower()}" if value else "conf-medium"


def _endpoint_enrichment(ep: Endpoint) -> dict[str, Any]:
    """安全取出端点的富化字典（whois/icp/asn）。"""
    return ep.enrichment if isinstance(ep.enrichment, dict) else {}


def split_endpoints(endpoints: list[Endpoint]) -> dict[str, list[Endpoint]]:
    """把端点拆成 domain / ip / url 三类，便于全表分区展示。"""
    out: dict[str, list[Endpoint]] = {"domain": [], "ip": [], "url": []}
    for ep in endpoints:
        kind = (ep.kind or "").lower()
        out.setdefault(kind, [])
        out[kind].append(ep)
    return out


def _advice_of(lead: Lead) -> str:
    """容错取出 lead 的 advice（去空白）。"""
    advice = getattr(lead, "advice", "") or ""
    return advice.strip() if isinstance(advice, str) else ""


def advice_label(advice: str | None) -> str:
    """advice → 展示标签；空串显示「待核」。"""
    value = (advice or "").strip() if isinstance(advice, str) else ""
    return value or "待核"


def advice_class(advice: str | None) -> str:
    """advice → CSS 类名（建议调证=醒目红、无需调证=灰、其余=中性）。"""
    value = (advice or "").strip() if isinstance(advice, str) else ""
    if value == ADVICE_NEED:
        return "advice-need"
    if value == ADVICE_SKIP:
        return "advice-skip"
    return "advice-todo"


def split_leads_by_advice(leads: list[Lead]) -> dict[str, list[Lead]]:
    """按 advice 把线索分成「建议调证」/「无需调证」/「其它（待核）」三桶。

    返回 {"need": [...], "skip": [...], "other": [...]}，桶内保持稳定顺序。
    供模板把主控域名（建议调证）与通联域名/IP（无需调证）分区展示。
    """
    out: dict[str, list[Lead]] = {"need": [], "skip": [], "other": []}
    for lead in leads:
        advice = _advice_of(lead)
        if advice == ADVICE_NEED:
            out["need"].append(lead)
        elif advice == ADVICE_SKIP:
            out["skip"].append(lead)
        else:
            out["other"].append(lead)
    return out


def network_leads_by_advice(leads: list[Lead]) -> dict[str, list[Lead]]:
    """抽出 DOMAIN / IP 线索并按 advice 分组（建议调证 vs 无需调证）。

    主控域名章节用 need + other（待核默认归入需关注），
    通联域名/IP 章节用 skip（无需调证，弱化/可折叠）。
    """
    net = [
        lead
        for lead in leads
        if isinstance(lead.category, LeadCategory)
        and lead.category in (LeadCategory.DOMAIN, LeadCategory.IP)
    ]
    buckets = split_leads_by_advice(net)
    return {
        "need": sort_leads_by_confidence(buckets["need"] + buckets["other"]),
        "skip": sort_leads_by_confidence(buckets["skip"]),
    }


def _build_environment(template_dir: str) -> Environment:
    """用给定模板目录构造 Jinja2 Environment 并注册自定义 filter。

    template_dir 由 :func:`render_to_string` 经 ``importlib.resources.as_file`` 取得，
    使打包形态（PyInstaller onefile，资源不是真实目录）下仍能定位模板，且保持原有
    FileSystemLoader + autoescape/trim_blocks/lstrip_blocks 行为不变（最小化偏移）。
    """
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "htm", "xml", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["confidence_label"] = confidence_label
    env.filters["confidence_class"] = confidence_class
    env.filters["advice_label"] = advice_label
    env.filters["advice_class"] = advice_class
    return env


def render_to_string(report: Report) -> str:
    """渲染 Report 为 HTML 字符串。

    模板目录用 importlib.resources 锚顶层包 ``apkscan`` 定位（templates/ 是数据目录、
    非子包，故锚 'apkscan'），不依赖 ``Path(__file__)`` 相对路径（exe-ready）。
    ``as_file`` 取得的真实目录仅在 with 作用域内有效，故在作用域内完成 ``template.render``。
    """
    templates_res = importlib.resources.files("apkscan") / "report" / "templates"
    with ExitStack() as stack:
        template_dir = stack.enter_context(importlib.resources.as_file(templates_res))
        env = _build_environment(str(template_dir))
        template = env.get_template(_TEMPLATE_NAME)
        return _render_template(template, report)


def _render_template(template: Any, report: Report) -> str:
    """用已加载的模板对象渲染（提出来便于在 as_file 作用域内调用）。"""
    lead_groups = group_leads_by_category(report.leads)
    endpoints = split_endpoints(report.endpoints)
    enrichment_by_endpoint = {ep.value: _endpoint_enrichment(ep) for ep in report.endpoints}
    config_key_leads = sort_leads_by_confidence(
        [
            lead
            for lead in report.leads
            if isinstance(lead.category, LeadCategory)
            and lead.category is LeadCategory.CONFIG_KEY
        ]
    )
    network_leads = network_leads_by_advice(report.leads)
    return template.render(
        report=report,
        lead_groups=lead_groups,
        lead_total=len(report.leads),
        config_key_leads=config_key_leads,
        network_leads=network_leads,
        endpoints=endpoints,
        endpoint_total=len(report.endpoints),
        enrichment_by_endpoint=enrichment_by_endpoint,
        meta=report.meta or {},
        analyzer_status=report.analyzer_status or [],
        enricher_status=report.enricher_status or [],
        findings=report.findings or [],
    )


def render(report: Report, path: str) -> None:
    """渲染 Report 并写成 UTF-8 HTML 单文件。"""
    html = render_to_string(report)
    out_path = Path(path)
    if out_path.parent and not out_path.parent.exists():
        out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
