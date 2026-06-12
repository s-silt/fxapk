"""App 类型自动分类器（聚合函数，非普通 BaseAnalyzer）。

★ 设计要点
- **不是 BaseAnalyzer**：普通分析器彼此无依赖、顺序不定；而分类需要**聚合其它分析器
  已产出的 meta/leads/endpoints/findings**，故实现为聚合函数 ``classify_app(report)``，
  由 pipeline.run() 在「所有分析器跑完 + build_endpoint_leads 之后」调用一次。
- **铁律：明确出线索，而非检测告警**。只写 ``app_type`` 标签 = 不合格。本模块在定类后
  **据类型产出针对性调证 Lead**（带 where_to_request + evidence_to_obtain），把「一摞
  域名/SDK」翻译成「这是哪类盘 → 该向谁调什么证据」。
- **零重复抠取**：信号全部从 report 现成的 ``meta``（permissions/dangerous_matched、
  sdks、payment_keywords/crypto_addresses、contacts 等）、``leads``（is_c2）、
  ``endpoints``（路径特征）、``findings``（文案）里取，绝不重新扫 dex。
- **误判对冲**：加权累计过阈值才定类；多类竞争取最高分 + 保留 runner_up；证据不足显式
  标「未定」，绝不硬判（马甲包文案混淆 / 多业务混合是真实风险，宁标未定勿硬判）。
- **绝不抛 / 绝不 print**：整体 try/except 兜底，分类失败时 report 原样返回。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from apkscan.core.models import Lead, LeadCategory
from apkscan.core.registry import load_rules

if TYPE_CHECKING:
    from apkscan.core.models import Report

logger = logging.getLogger(__name__)

_RULES_NAME = "app_types"
# 兜底过线分（YAML 未给 threshold 时用）。
_DEFAULT_THRESHOLD = 3.0
# 写入 Lead.value 的前缀，便于报告/测试识别这是「分类研判」Lead。
_LEAD_VALUE_PREFIX = "涉诈类型研判"


@dataclass
class _Signal:
    """一条带权重的信号（数据化自 YAML）。一条信号只用一种匹配源。"""

    weight: float
    desc: str
    permission_all: list[str] = field(default_factory=list)
    permission_any: list[str] = field(default_factory=list)
    path_any: list[str] = field(default_factory=list)
    text_any: list[str] = field(default_factory=list)
    sdk_any: list[str] = field(default_factory=list)
    payment_kw_any: list[str] = field(default_factory=list)
    contact_any: list[str] = field(default_factory=list)
    crypto_present: bool = False
    c2_present: bool = False


@dataclass
class _Investigation:
    """某类型的调证指向（命中后写入新建 Lead）。"""

    where_to_request: str = ""
    evidence_to_obtain: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class _TypeRule:
    """一个 App 类型的规则：名称 + 调证指向 + 一组带权重信号。"""

    name: str
    investigation: _Investigation
    signals: list[_Signal] = field(default_factory=list)


@dataclass
class _Hit:
    """某信号命中：权重 + 描述 + 来源（便于追溯）。"""

    weight: float
    desc: str
    source: str


@dataclass
class _Score:
    """某类型的累计得分与命中信号清单。"""

    rule: _TypeRule
    score: float = 0.0
    hits: list[_Hit] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------


def classify_app(report: "Report") -> None:
    """聚合 report 现成信号定类，就地写 meta + 追加调证 Lead。绝不抛。

    流程：
    1) 加载 app_types.yaml；
    2) 把 report 现成信号归一成一个轻量「信号视图」（permissions/paths/text/...）；
    3) 逐类型逐信号加权累计；
    4) 取最高分；过阈值 → 该类型 + runner_up；不过 → 未定；
    5) 写 report.meta["app_classification"]；过阈值则追加该类型的针对性调证 Lead。
    """
    try:
        rules, threshold = _load_rules()
        if not rules:
            logger.info("[classify] 无可用类型规则，跳过分类")
            return

        view = _build_signal_view(report)
        scores = _score_types(rules, view)
        if not scores:
            _write_undetermined(report, reason="无任何类型规则命中信号")
            return

        # 取最高分；同分时保持 YAML 顺序（sorted 稳定）。
        scores.sort(key=lambda s: s.score, reverse=True)
        best = scores[0]
        runner = scores[1] if len(scores) > 1 and scores[1].score > 0 else None

        if best.score < threshold:
            _write_undetermined(
                report,
                reason=f"最高分 {best.score:.1f} 未过阈值 {threshold:.1f}",
                best=best,
                runner=runner,
            )
            return

        _write_classification(report, best, runner)
        _append_investigation_lead(report, best)
    except Exception:  # noqa: BLE001 — 分类失败绝不炸 pipeline，report 原样返回
        logger.exception("[classify] App 类型分类异常，report 原样返回（不影响其余结果）")


# ---------------------------------------------------------------------------
# 信号视图：把 report 现成产出归一成易匹配的小结构（零重复抠取）
# ---------------------------------------------------------------------------


@dataclass
class _SignalView:
    """report 现成信号的归一视图——所有匹配都基于它，绝不回头扫 dex。"""

    perms: set[str] = field(default_factory=set)  # 权限短名（大写）
    paths_text: str = ""  # endpoint.value 拼接（小写），供 path 子串匹配
    corpus: str = ""  # 文案语料（finding 标题+描述 / lead.value / version_name / contacts 文本）
    sdks_text: str = ""  # sdks 列表拼接（小写）
    payment_kw_text: str = ""  # payment_keywords 拼接（小写）
    contact_kinds: set[str] = field(default_factory=set)  # contacts 命中的 kind
    crypto_present: bool = False  # crypto_addresses 非空
    c2_present: bool = False  # report.leads 含 is_c2


def _build_signal_view(report: "Report") -> _SignalView:
    """从 report 抽取信号视图。每个子提取独立 try/except，单源坏不影响其余。"""
    view = _SignalView()
    meta = _safe_dict(getattr(report, "meta", None))

    # 1) 权限：短名集合（兼容 dangerous_matched 短名 与 permissions 全名）。
    try:
        view.perms = _collect_perms(meta)
    except Exception:
        logger.exception("[classify] 权限信号抽取失败，按空处理")

    # 2) 端点路径文本：endpoint.value 拼接（小写）。
    try:
        eps = getattr(report, "endpoints", None) or []
        view.paths_text = " ".join(
            str(getattr(ep, "value", "") or "") for ep in eps
        ).lower()
    except Exception:
        logger.exception("[classify] 端点路径信号抽取失败，按空处理")

    # 3) 文案语料：finding 标题/描述 + lead.value + version_name + 端点 value。
    try:
        view.corpus = _build_corpus(report, meta)
    except Exception:
        logger.exception("[classify] 文案语料抽取失败，按空处理")

    # 4) SDK 文本。
    try:
        sdks = _as_str_list(meta.get("sdks"))
        view.sdks_text = " ".join(sdks).lower()
    except Exception:
        logger.exception("[classify] SDK 信号抽取失败，按空处理")

    # 5) 支付关键字文本。
    try:
        kws = _as_str_list(meta.get("payment_keywords"))
        view.payment_kw_text = " ".join(kws).lower()
    except Exception:
        logger.exception("[classify] 支付关键字信号抽取失败，按空处理")

    # 6) contacts kind 集合（meta["contacts"] 是 dict[kind, count]）。
    try:
        contacts = meta.get("contacts")
        if isinstance(contacts, dict):
            view.contact_kinds = {
                str(k).lower() for k, v in contacts.items() if _truthy_count(v)
            }
    except Exception:
        logger.exception("[classify] contacts 信号抽取失败，按空处理")

    # 7) 链上收款地址是否存在。
    try:
        view.crypto_present = bool(_as_str_list(meta.get("crypto_addresses")))
    except Exception:
        logger.exception("[classify] crypto_addresses 信号抽取失败，按空处理")

    # 8) is_c2：report.leads 里有「建议调证的 DOMAIN/IP」即为 True。
    try:
        leads = getattr(report, "leads", None) or []
        view.c2_present = any(_lead_is_c2(lead) for lead in leads)
    except Exception:
        logger.exception("[classify] is_c2 信号抽取失败，按空处理")

    return view


def _collect_perms(meta: dict[str, Any]) -> set[str]:
    """归一权限为短名大写集合。

    优先用 ``dangerous_matched``（本就是短名）；同时把 ``permissions``（全名如
    android.permission.READ_SMS）取末段并入，兼容两种喂法。
    """
    perms: set[str] = set()
    for short in _as_str_list(meta.get("dangerous_matched")):
        perms.add(short.upper())
    for full in _as_str_list(meta.get("permissions")):
        # 取 . 后末段作短名（无 . 则整体）。
        short = full.rsplit(".", 1)[-1]
        if short:
            perms.add(short.upper())
    return perms


def _build_corpus(report: "Report", meta: dict[str, Any]) -> str:
    """拼文案语料（小写）：finding 标题/描述 + lead.value + version_name + 端点 value。

    全部来自 report 现成产出，绝不重新扫 dex。
    """
    parts: list[str] = []

    for finding in getattr(report, "findings", None) or []:
        parts.append(str(getattr(finding, "title", "") or ""))
        parts.append(str(getattr(finding, "description", "") or ""))

    for lead in getattr(report, "leads", None) or []:
        parts.append(str(getattr(lead, "value", "") or ""))
        parts.append(str(getattr(lead, "notes", "") or ""))

    vname = meta.get("version_name")
    if isinstance(vname, str):
        parts.append(vname)
    aname = meta.get("uni_app_name")
    if isinstance(aname, str):
        parts.append(aname)

    for ep in getattr(report, "endpoints", None) or []:
        parts.append(str(getattr(ep, "value", "") or ""))

    return " ".join(parts).lower()


# ---------------------------------------------------------------------------
# 打分
# ---------------------------------------------------------------------------


def _score_types(rules: list[_TypeRule], view: _SignalView) -> list[_Score]:
    """逐类型逐信号加权累计，返回每类型一个 _Score（含命中明细）。"""
    scores: list[_Score] = []
    for rule in rules:
        sc = _Score(rule=rule)
        for sig in rule.signals:
            hit = _match_signal(sig, view)
            if hit is not None:
                sc.score += hit.weight
                sc.hits.append(hit)
        scores.append(sc)
    return scores


def _match_signal(sig: _Signal, view: _SignalView) -> _Hit | None:
    """判断一条信号是否命中。命中返回 _Hit（带来源），否则 None。

    一条信号只用一种匹配源（YAML 约定），逐种检查，命中即返回。
    """
    if sig.permission_all:
        need = {p.upper() for p in sig.permission_all}
        if need and need.issubset(view.perms):
            return _Hit(sig.weight, sig.desc, source="permissions")
        return None
    if sig.permission_any:
        if any(p.upper() in view.perms for p in sig.permission_any):
            return _Hit(sig.weight, sig.desc, source="permissions")
        return None
    if sig.path_any:
        if _contains_any(view.paths_text, sig.path_any):
            return _Hit(sig.weight, sig.desc, source="endpoints")
        return None
    if sig.text_any:
        if _contains_any(view.corpus, sig.text_any):
            return _Hit(sig.weight, sig.desc, source="findings/leads")
        return None
    if sig.sdk_any:
        if _contains_any(view.sdks_text, sig.sdk_any):
            return _Hit(sig.weight, sig.desc, source="meta.sdks")
        return None
    if sig.payment_kw_any:
        if _contains_any(view.payment_kw_text, sig.payment_kw_any):
            return _Hit(sig.weight, sig.desc, source="meta.payment_keywords")
        return None
    if sig.contact_any:
        if any(k.lower() in view.contact_kinds for k in sig.contact_any):
            return _Hit(sig.weight, sig.desc, source="meta.contacts")
        return None
    if sig.crypto_present:
        if view.crypto_present:
            return _Hit(sig.weight, sig.desc, source="meta.crypto_addresses")
        return None
    if sig.c2_present:
        if view.c2_present:
            return _Hit(sig.weight, sig.desc, source="leads.is_c2")
        return None
    return None


# ---------------------------------------------------------------------------
# 写结果
# ---------------------------------------------------------------------------


def _write_classification(
    report: "Report", best: _Score, runner: _Score | None
) -> None:
    """写 report.meta["app_classification"]（type/score/signals/runner_up）。"""
    report.meta["app_classification"] = {
        "type": best.rule.name,
        "score": round(best.score, 2),
        "signals": [
            {"desc": h.desc, "weight": h.weight, "source": h.source} for h in best.hits
        ],
        "runner_up": _runner_up_brief(runner),
    }


def _write_undetermined(
    report: "Report",
    *,
    reason: str,
    best: _Score | None = None,
    runner: _Score | None = None,
) -> None:
    """证据不足 → 显式标「未定」，**不产硬判 Lead**。

    仍保留 best/runner 的命中信号（便于人工研判），但 type 固定为「未定」。
    """
    signals = (
        [{"desc": h.desc, "weight": h.weight, "source": h.source} for h in best.hits]
        if best is not None
        else []
    )
    report.meta["app_classification"] = {
        "type": "未定",
        "score": round(best.score, 2) if best is not None else 0.0,
        "signals": signals,
        "runner_up": _runner_up_brief(runner),
        "reason": reason,
        # 最有可能但未过线的类型（仅供人工参考，非定论）。
        "top_candidate": best.rule.name if best is not None else None,
    }


def _runner_up_brief(runner: _Score | None) -> dict[str, Any] | None:
    """次高分类型的简要（type + score），无则 None。"""
    if runner is None or runner.score <= 0:
        return None
    return {"type": runner.rule.name, "score": round(runner.score, 2)}


def _append_investigation_lead(report: "Report", best: _Score) -> None:
    """据类型追加针对性调证 Lead（CONFIG_KEY，带 where_to_request + evidence_to_obtain）。

    ★ 这是本模块的核心交付：不只打标签，而是产出「该向谁调什么证据」的可落地线索。
    category 复用现有最贴近的 CONFIG_KEY（不新增 LeadCategory 枚举，避免涟漪到渲染）。
    **只追加新 Lead，绝不改动已有 Lead。**
    """
    inv = best.rule.investigation
    hits_desc = "、".join(h.desc for h in best.hits)
    notes = inv.notes
    if hits_desc:
        notes = f"{notes}（命中信号：{hits_desc}）" if notes else f"命中信号：{hits_desc}"

    lead = Lead(
        category=LeadCategory.CONFIG_KEY,
        value=f"{_LEAD_VALUE_PREFIX}：{best.rule.name}",
        subject=f"涉诈 App 类型：{best.rule.name}",
        where_to_request=inv.where_to_request,
        evidence_to_obtain=list(inv.evidence_to_obtain),
        notes=notes,
        advice="建议调证",
    )
    report.leads.append(lead)


# ---------------------------------------------------------------------------
# 规则加载
# ---------------------------------------------------------------------------


def _load_rules() -> tuple[list[_TypeRule], float]:
    """读 app_types.yaml → (类型规则列表, 阈值)。解析失败返回 ([], 默认阈值)。"""
    data = load_rules(_RULES_NAME)
    if not isinstance(data, dict):
        logger.warning(
            "[classify] 规则顶层应为 dict，实际 %s；无规则可用", type(data).__name__
        )
        return [], _DEFAULT_THRESHOLD

    threshold = _DEFAULT_THRESHOLD
    raw_threshold = data.get("threshold")
    if isinstance(raw_threshold, (int, float)) and not isinstance(raw_threshold, bool):
        threshold = float(raw_threshold)

    rules = _parse_types(data.get("types"))
    return rules, threshold


def _parse_types(raw: object) -> list[_TypeRule]:
    """解析 types 段为 _TypeRule 列表，跳过非法条目（记 warning，不抛）。"""
    if not isinstance(raw, list):
        if raw is not None:
            logger.warning("[classify] types 字段应为 list，实际 %s", type(raw).__name__)
        return []
    rules: list[_TypeRule] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            logger.warning("[classify] 跳过缺少 name 的类型规则：%r", entry)
            continue
        inv = _parse_investigation(entry.get("investigation"))
        signals = _parse_signals(entry.get("signals"))
        if not signals:
            logger.warning("[classify] 类型 %s 无有效信号，跳过", name)
            continue
        rules.append(_TypeRule(name=name.strip(), investigation=inv, signals=signals))
    return rules


def _parse_investigation(raw: object) -> _Investigation:
    """解析调证指向；缺失则返回空 _Investigation（Lead 字段会为空但仍产出标签 Lead）。"""
    if not isinstance(raw, dict):
        return _Investigation()
    return _Investigation(
        where_to_request=_str_or_empty(raw.get("where_to_request")),
        evidence_to_obtain=_as_str_list(raw.get("evidence_to_obtain")),
        notes=_str_or_empty(raw.get("notes")),
    )


def _parse_signals(raw: object) -> list[_Signal]:
    """解析 signals 段为 _Signal 列表，跳过无权重/无匹配源的条目。"""
    if not isinstance(raw, list):
        if raw is not None:
            logger.warning("[classify] signals 字段应为 list，实际 %s", type(raw).__name__)
        return []
    signals: list[_Signal] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        weight = entry.get("weight")
        if not isinstance(weight, (int, float)) or isinstance(weight, bool):
            continue
        sig = _Signal(
            weight=float(weight),
            desc=_str_or_empty(entry.get("desc")),
            permission_all=_as_str_list(entry.get("permission_all")),
            permission_any=_as_str_list(entry.get("permission_any")),
            path_any=_as_str_list(entry.get("path_any")),
            text_any=_as_str_list(entry.get("text_any")),
            sdk_any=_as_str_list(entry.get("sdk_any")),
            payment_kw_any=_as_str_list(entry.get("payment_kw_any")),
            contact_any=_as_str_list(entry.get("contact_any")),
            crypto_present=bool(entry.get("crypto_present", False)),
            c2_present=bool(entry.get("c2_present", False)),
        )
        # 至少一种匹配源才算有效信号。
        if _signal_has_source(sig):
            signals.append(sig)
    return signals


def _signal_has_source(sig: _Signal) -> bool:
    """信号是否声明了至少一种匹配源。"""
    return bool(
        sig.permission_all
        or sig.permission_any
        or sig.path_any
        or sig.text_any
        or sig.sdk_any
        or sig.payment_kw_any
        or sig.contact_any
        or sig.crypto_present
        or sig.c2_present
    )


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------


def _safe_dict(obj: object) -> dict[str, Any]:
    """obj 是 dict 则返回之，否则返回空 dict（兼容坏 report）。"""
    return obj if isinstance(obj, dict) else {}


def _as_str_list(value: object) -> list[str]:
    """把 value 归一成非空字符串列表（None / 非 list / 非 str 元素安全跳过）。"""
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
    return out


def _str_or_empty(value: object) -> str:
    """value 是非空字符串则返回 strip 后的值，否则空串。"""
    return value.strip() if isinstance(value, str) else ""


def _contains_any(haystack: str, needles: list[str]) -> bool:
    """haystack（已小写）是否含 needles 任一（needle 转小写后子串匹配）。"""
    if not haystack:
        return False
    return any(n.lower() in haystack for n in needles if n)


def _truthy_count(value: object) -> bool:
    """contacts 计数是否为真（>0 的 int 或非空）。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value > 0
    return bool(value)


def _lead_is_c2(lead: object) -> bool:
    """安全读取 lead.is_c2（坏对象 / 无属性 → False）。"""
    try:
        return bool(getattr(lead, "is_c2", False))
    except Exception:
        return False
