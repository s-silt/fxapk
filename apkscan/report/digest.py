"""把 report.json 压成 **AI agent（agent-agnostic）/ 程序友好** 的紧凑摘要（compact digest）。

report.json 完整但冗长（端点全表 / 技术附录 / 富化原始数据），AI agent（Codex）逐字解析既费
token 又难抓重点。本模块抽出**可办案化的核心**：按优先级排序的调证线索 + 计数摘要，键名稳定、
结构扁平，供低 token 消费、直接决策。纯函数（report dict → digest dict），绝不抛。
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from apkscan.core.evidence_scope import (
    project_serialized_closure,
    project_serialized_leads,
)
from apkscan.core.models import (
    OBSERVED_CONTACT_SOURCES,
    EvidenceScope,
    display_lead_category,
)
from apkscan.core.redact import redact_value, scrub_pii
from apkscan.core.restore import restore_index, restored_sources_for

# 排序优先级：建议调证 > 待核 > 无需调证；同档高可信在前；C2 在前。
_ADVICE_RANK = {"建议调证": 0, "待核": 1, "无需调证": 2}
_CONF_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _lead_sort_key(lead: dict[str, Any]) -> tuple[int, int, int, str]:
    return (
        _ADVICE_RANK.get(str(lead.get("advice") or ""), 3),
        _CONF_RANK.get(str(lead.get("confidence") or ""), 3),
        0 if lead.get("is_c2") else 1,
        str(lead.get("category") or ""),
    )


def _scrub_field(text: object, flag: list[bool]) -> object:
    """redact 模式下对单个自由文本字段抹结构化 PII；命中即置 flag。None 保持 None（不改结构）。"""
    if text is None:
        return None
    scrubbed, hit = scrub_pii(text)
    if hit:
        flag[0] = True
    return scrubbed


def _runtime_flags(lead: dict[str, Any]) -> tuple[bool, bool]:
    refs = lead.get("source_refs")
    direct_sources: list[str] = []
    if isinstance(refs, list):
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            if (
                str(ref.get("scope", EvidenceScope.LEGACY_UNSPECIFIED.value))
                != EvidenceScope.CASE_EVIDENCE.value
            ):
                continue
            direct_sources.append(str(ref.get("source", "")))
    return (
        any(source.startswith("runtime") for source in direct_sources),
        any(source in OBSERVED_CONTACT_SOURCES for source in direct_sources),
    )


def _compact_lead(
    lead: dict[str, Any],
    redact: bool,
    pii_flag: list[bool],
    restored_sources: set[str] | None = None,
) -> dict[str, Any]:
    """单条线索压成扁平稳定字段（去掉 source_refs 等冗长内部结构）。

    ``redact=True``（``build_digest`` 的默认值，由调用方传入——本函数自己没有默认参数）：
    高敏类别（钱包私钥/凭据/个人隐私数据/加密配方）的 value 按类别脱敏；并对 subject / notes /
    where_to_request / evidence_to_obtain 等**本条 lead 自己的自由文本**兜底抹结构化 PII
    （不依赖类别标注是否正确，防个人手机号/证件号绕过脱敏进云端 agent）。

    ★覆盖面**仅限本函数处理的 lead 字段**：digest 里 findings 的 title、visibility 与 closure
      的说明文本、overseas_targets 都不经过这里，一律原样。别把「digest 默认脱敏」读成
      「digest 的输出已净化」——确切的保证范围写在 :mod:`apkscan.core.redact` 的模块说明里。
    """
    restored_sources = restored_sources or set()
    category = lead.get("category")
    value = lead.get("value")
    subject = lead.get("subject")
    where = lead.get("where_to_request")
    notes = lead.get("notes") or ""
    evidence = lead.get("evidence_to_obtain") or []
    raw_downgrades = lead.get("downgrades")
    downgrades = {
        str(k): str(v) for k, v in raw_downgrades.items()
    } if isinstance(raw_downgrades, dict) else {}
    if redact:
        value = redact_value(category, value)
        subject = _scrub_field(subject, pii_flag)
        where = _scrub_field(where, pii_flag)
        notes = _scrub_field(notes, pii_flag)
        evidence = [_scrub_field(item, pii_flag) for item in evidence]
        downgrades = {k: _scrub_field(v, pii_flag) or "" for k, v in downgrades.items()}
    runtime_seen, runtime_contact = _runtime_flags(lead)
    return {
        # 未识别类别显式标注（raw_category 见 Lead.raw_category）；已知类别原样。
        "category": display_lead_category(category, lead.get("raw_category")),
        "value": value,
        "subject": subject,
        "advice": lead.get("advice"),
        "confidence": lead.get("confidence"),
        "is_c2": bool(lead.get("is_c2")),
        # 宽口径「动态侧出现」；严一档的「observed-contact 真接触」另给 is_runtime_contact，
        # 供下游筛选/研判分层——勿把仅 is_runtime_seen（含手编 runtime-derived）当「实连/确认 C2」。
        "is_runtime_seen": runtime_seen,
        "is_runtime_contact": runtime_contact,
        "where_to_request": where,
        "evidence_to_obtain": evidence,
        "notes": notes,
        # ★档位的抑制来源（{来源 id: 原因}）。降档原因不再拼进 notes——digest 的主要读者按
        #   工作流是 AI，它要判断「这条为什么被压着、能不能放回」，靠的就是这个字段；漏了它，
        #   压档在 AI 眼里就成了无来由的档位。
        "downgrades": downgrades,
        # ★这条档位是不是**被人放行**过（而不是判据说它干净）。必须显式呈现：手改 advice 会被
        #   closure 的一致性守卫挡下，手塞一条墓碑则不会——不呈现就等于给绕过守卫留了一条更
        #   安静的路。墓碑不做真伪校验，可见性是这里唯一站得住的保证。
        "manually_restored": sorted(restored_sources),
    }


#: role display order for the network_attribution digest block (behavioral-deception
#: and origin findings first; edge last as it is closest to a mere resource fact).
_ROLE_RANK = {
    "cloaking_edge_node": 0,
    "origin_candidate": 1,
    "domestic_relay_candidate": 2,
    "edge_candidate": 3,
}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


#: 完整性红旗阈值（低于即在 digest 顶部告警）。取值是判断权衡：
#:  · 分析完整度 <0.8 = 超两成分析器报错，结论基础明显残缺；
#:  · 富化命中率 <0.5 = 过半富化尝试失败（限速/源没跑全），AGENTS.md 明言此时勿据残缺证据下结论。
_COMPLETENESS_WARN = 0.8
_ENRICH_WARN = 0.5


def _finite_num_or_none(value: object) -> float | None:
    """有限实数 → float；bool / 非数 / NaN / inf → None（codex P1：NaN 不得绕过阈值伪装可靠）。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    f = float(value)
    return f if math.isfinite(f) else None


def _nonneg_count(value: object) -> int | None:
    """非负有限整数计数；bool / 负 / 非有限 / 非整 / 脏类型（如 "bad"）→ None（跳过，绝不 int() 抛，codex P0）。"""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float):
        if not math.isfinite(value) or value < 0 or value != int(value):
            return None
        return int(value)
    return None  # 字符串等脏类型：跳过而非 int() 抛（守 build_digest「绝不抛」契约）


def _integrity(report: dict[str, Any]) -> dict[str, Any]:
    """run 级完整性红旗（codex #4）：聚合分析完整度 / 关键分析器失败 / 富化命中率，低于阈值即出 warnings。

    ★把此前只散在 analyzer_status/enricher_status 里、靠人肉判断的「本次结果是否可信」升为**工具级主动告警**——
    ``reliable=False`` + ``warnings`` 让消费方（Agent/研判）不再据残缺证据下结论。纯读既有 status，不新增采集。
    ★绝不抛（codex P0/P1）：脏报告（``attempted:"bad"`` / NaN completeness / ``ok>attempted``）降低可靠性并告警，
      而非崩溃或伪装可靠。
    """
    warnings: list[str] = []
    status = report.get("analysis_status")
    raw_completeness = report.get("completeness")
    completeness = _finite_num_or_none(raw_completeness)
    if completeness is not None:
        if not (0.0 <= completeness <= 1.0):
            warnings.append(f"分析完整度 {completeness} 越界（应在 [0,1]）：报告数据异常，结果不可信")
        elif completeness < _COMPLETENESS_WARN:
            warnings.append(f"分析完整度 {completeness} 低于 {_COMPLETENESS_WARN}：部分分析器失败，结论基础可能残缺")
    elif raw_completeness is not None:
        warnings.append("分析完整度字段异常（非有限数）：报告数据异常，结果不可信")
    crit = [str(c) for c in _list(report.get("critical_failures")) if str(c)]
    if crit:
        warnings.append(f"关键分析器失败：{'、'.join(crit)}")

    # ★analysis_status 必须被**消费**而不只是透传：报告自称 partial/failed 时，即使
    #   completeness=1.0 且无 critical_failures（如仅 pipeline 阶段崩溃降的档），摘要也不得
    #   自称 reliable——否则"部分完成"在唯一被下游读取的出口上消失。
    if isinstance(status, str) and status in ("partial", "failed"):
        # 存盘形状：stage_status 由 pipeline 写在 meta 下（pipeline._run_stage →
        # meta["stage_status"]）；根级仅容错手工/合成报告。缺失/坏形状只丢细节，不丢主告警。
        stages = report.get("stage_status")
        if not isinstance(stages, list):
            meta_block = report.get("meta")
            stages = meta_block.get("stage_status") if isinstance(meta_block, dict) else None
        bad = [str(s.get("name")) for s in (stages if isinstance(stages, list) else [])
               if isinstance(s, dict) and s.get("status") in ("error", "failed")]
        detail = f"（失败阶段：{'、'.join(bad)}）" if bad else ""
        warnings.append(f"分析状态为 {status}{detail}：结论基础不完整，勿据此下确定性结论")

    es = [s for s in _list(report.get("enricher_status")) if isinstance(s, dict)]
    attempted = ok = 0
    dirty = False
    for s in es:
        a, o = _nonneg_count(s.get("attempted")), _nonneg_count(s.get("ok"))
        if a is None or o is None or o > a:  # 脏条目 / ok>attempted 无意义 → 跳过并标数据质量问题
            dirty = True
            continue
        attempted += a
        ok += o
    enrich_rate = round(ok / attempted, 4) if attempted else None
    if dirty:
        warnings.append("富化统计含异常条目（计数非法/ok>attempted）：命中率仅据可解析条目，结果可能不可信")
    if enrich_rate is not None and enrich_rate < _ENRICH_WARN:
        warnings.append(
            f"富化命中率 {enrich_rate} 低于 {_ENRICH_WARN}：富化源可能未跑全（限速/密钥/网络），勿据残缺证据下结论"
        )
    return {
        "analysis_status": status,
        "completeness": completeness,
        "critical_failures": crit,
        "enrichment_ok_rate": enrich_rate,
        "reliable": not warnings,
        "warnings": warnings,
    }


def _neg_score(value: object) -> float:
    """Negated score for a descending sort. A non-numeric / bool score (only
    reachable from a hand-edited or version-skewed report.json) sorts as 0 so the
    digest degrades rather than raising on the one arithmetic use of the field."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    return -float(value)


def _compact_network_attribution(raw: Any) -> dict[str, Any] | None:
    """Low-token projection of meta['network_attribution']: graph counts + the
    ELIGIBLE role candidates only (ineligible are counted, not listed). Defensive
    — any malformed shape degrades to an empty block; never raises, never the raw graph."""
    if not isinstance(raw, dict):
        return None
    graph = raw.get("graph")
    graph = graph if isinstance(graph, dict) else {}

    candidates: list[dict[str, Any]] = []
    eligible = ineligible = 0
    by_role: Counter = Counter()
    for endpoint in _list(raw.get("endpoints")):
        if not isinstance(endpoint, dict):
            continue
        for ipv in _list(endpoint.get("ips")):
            if not isinstance(ipv, dict):
                continue
            for role in _list(ipv.get("roles")):
                if not isinstance(role, dict):
                    continue
                if role.get("eligible"):
                    eligible += 1
                    by_role[str(role.get("role"))] += 1
                    candidates.append({
                        "endpoint": endpoint.get("endpoint"),
                        "kind": endpoint.get("kind"),  # domain / ip（对齐设计 schema role_candidates 字段）
                        "ip": ipv.get("ip"),
                        "role": role.get("role"),
                        "score": role.get("score"),
                        "confidence": role.get("confidence"),
                    })
                else:
                    ineligible += 1
    candidates.sort(
        key=lambda c: (_ROLE_RANK.get(str(c.get("role")), 99), _neg_score(c.get("score")), str(c.get("ip")))
    )
    return {
        "counts": {
            "nodes": len(_list(graph.get("nodes"))),
            "edges": len(_list(graph.get("edges"))),
            "issues": len(_list(graph.get("issues"))),
            "eligible": eligible,
            "ineligible": ineligible,
            "by_role": dict(by_role),
        },
        "role_candidates": candidates[:10],
    }


def _claim_field(claims: dict, claim: str, key: str, fallback: Any) -> Any:
    """从 claims 表里取某条主张的字段；结构不合预期 → fallback（不抛）。"""
    entry = claims.get(claim)
    return entry.get(key, fallback) if isinstance(entry, dict) else fallback


#: 进 digest 的 Finding 严重度（按分析器实际使用的取值大小写不敏感匹配）。
#: LOW/INFO 不进——digest 的立身之本是低 token，几十条信息级条目会把它撑成第二份报告。
_DIGEST_FINDING_SEVERITIES = frozenset({"critical", "high", "medium"})

#: 省略条目最多列多少个 ID。有上限是因为 digest 的立身之本是低 token；
#: 但**必须有下限意义上的可见性**——超过上限时 counts.omitted 仍如实计数，
#: 两者一起读才知道「列出来的是不是全部」。
_OMITTED_ID_CAP = 40


def _compact_findings(report: dict) -> dict[str, Any]:
    """Finding → digest 紧凑段：只带 id / 严重度 / 标题，不带证据明细。

    ★为什么必须有这一段：digest 是喂 AI agent 的消费面，而 Finding 承载的是 **leads 不表达的
    事实判断**——"后端有通讯录窃取接口"「疑似正版重打包，接口不能直接作线索」「未知壳、DEX 只剩
    壳桩」。此前 digest 完全不透 findings，实测一个样本 31 条 Finding 对 AI 全部不可见，
    其中包括 HIGH 级结论。这就是"提取出来却在最后一环沉默"。

    ★省略必须说出来：只带 CRITICAL/HIGH/MEDIUM，但把省略数与分布写进 counts。静默丢弃会被
    读成"只有这些"——与本项目反复要防的"缺失被当不存在"是同一个错。
    """
    raw = report.get("findings")
    items = [f for f in raw if isinstance(f, dict)] if isinstance(raw, list) else []
    kept: list[dict[str, Any]] = []
    by_sev: Counter[str] = Counter()
    for f in items:
        sev = _severity_name(f.get("severity"))
        by_sev[sev] += 1
        if sev.lower() in _DIGEST_FINDING_SEVERITIES:
            kept.append({
                "id": str(f.get("id") or ""),
                "severity": sev,
                "title": str(f.get("title") or "")[:160],
            })
    kept.sort(key=lambda x: (x["severity"], x["id"]))
    kept_ids = {item["id"] for item in kept}
    # ★「省略必须说出来」不能只说**数量**：只给一个 omitted=3，读的人知道有东西被丢了，
    #   却不知道被丢的是什么、也无从去 report.json 里定位——等于知道自己瞎但不知道瞎在哪。
    #   带上 ID（不带标题/证据，token 仍然便宜）才能按图索骥。
    #   实证：本轮补的三条 LOW 出口（版本标记词、绝对路径条目的落盘解压风险、
    #   未知远控目标）在默认 digest 里只体现为 omitted 计数，操作提示对决策面完全消失。
    omitted_ids = sorted(
        {str(f.get("id") or "") for f in items} - kept_ids - {""}
    )[:_OMITTED_ID_CAP]
    return {
        "items": kept,
        "counts": {
            "total": len(items),
            "shown": len(kept),
            "omitted": len(items) - len(kept),
            "by_severity": dict(by_sev),
        },
        "omitted_ids": omitted_ids,
        "note": (
            "只列 CRITICAL/HIGH/MEDIUM 的条目；低于该档的仅列 ID（见 omitted_ids）。"
            "完整条目与证据见 report.json 的 findings"
        ),
    }


def _severity_name(value: object) -> str:
    """把 Severity 取出成字符串——报告可能是 Enum、dict（序列化后）或裸字符串。

    ★不能只 str()：Enum 经 json 往返后是 ``{"_name_": "HIGH", ...}`` 这类 dict，
    直接 str 会得到一大坨对象文本，既污染 digest 又让严重度筛选全部失效。
    """
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("_name_", "name", "_value_", "value"):
            got = value.get(key)
            if isinstance(got, str):
                return got
        return "UNKNOWN"
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name
    got = getattr(value, "value", None)
    return got if isinstance(got, str) else "UNKNOWN"


def _compact_control_chains(raw: object) -> list[dict[str, Any]]:
    """控制链 → digest 紧凑段：远程配置对象 → 解密配方 → 后端 → 落地归因。

    ★为什么必须有这个出口：``build_control_chains`` 的存在理由就是「报告输出的不再是孤立
      IOC，而是一条可读的控制链」（见 config/chain.py 模块头），可它只写进
      ``meta["control_chains"]``，没有任何出口呈现——**组成节点各自可见，不等于这条关系可见**。
      拿到报告的人看得到域名、看得到配方、看得到 IDC，却看不出它们是一条链上的。

    ★摘要必须保住**关系**：把 source_url / recipe / backends 拆成三个平铺列表就退回孤立 IOC
      了，等于没接。所以逐链成条，链内保留次序与归属。
    """
    if not isinstance(raw, list) or not raw:
        return []
    out: list[dict[str, Any]] = []
    for chain in raw:
        if not isinstance(chain, dict):
            continue
        backends = [
            {
                "kind": b.get("kind"),
                "value": b.get("value"),
                # 落地归因只取可读标签，链条视图不重复整份五层结构（那在 enrichment 里）。
                "landing": [
                    {
                        "ip": rec.get("ip"),
                        "country": rec.get("country"),
                        "hosting": rec.get("hosting_provider"),
                    }
                    for rec in (b.get("attribution") or [])
                    if isinstance(rec, dict)
                ],
            }
            for b in (chain.get("backends") or [])
            if isinstance(b, dict)
        ]
        out.append({
            "source_url": chain.get("source_url"),
            "decoded": bool(chain.get("decoded")),
            "decode_chain": [str(s) for s in (chain.get("decode_chain") or [])],
            # 配方只带形态摘要（算法/模式/编码），chain.py 已保证不含 key 明文。
            "crypto_recipe": chain.get("crypto_recipe"),
            "backends": backends,
        })
    return out


def _compact_visibility(raw: object) -> dict[str, Any]:
    """可见性求值 → digest 紧凑段。缺失（旧报告）→ unknown 而非"完整"。

    ★对旧报告的降级方向必须是 unknown：把"没有这个字段"当成"输入都看得见"，正是本段要防的
    那类误读——缺失被读成不存在。
    """
    if not isinstance(raw, dict):
        return {"available": False, "note": "本报告无可见性求值（旧版本产出）；输入完整性未知"}
    blocked = [c for c in (raw.get("blocked_claims") or []) if isinstance(c, str)]
    raw_claims = raw.get("claims")
    claims: dict = raw_claims if isinstance(raw_claims, dict) else {}
    return {
        "available": True,
        "degraded": bool(raw.get("degraded")),
        "sources": {
            k: (v.get("visibility") if isinstance(v, dict) else None)
            for k, v in (raw.get("sources") or {}).items()
        },
        "remediation": raw.get("remediation"),
        # 无资格下的结论：AI 读到这些名字时，不得把对应的"未发现"当成"不存在"
        "blocked_claims": [
            {
                "claim": c,
                "label": _claim_field(claims, c, "label", c),
                "missing_sources": _claim_field(claims, c, "missing_sources", []),
            }
            for c in blocked
        ],
        "notes": [str(n) for n in (raw.get("notes") or [])],
        # 只说"哪里瞎了"是半截活：消费方还需要知道怎么补，否则拿到 degraded 报告也只能干看着。
        "next_actions": [str(a) for a in (raw.get("next_actions") or [])],
    }


def build_digest(report: object, *, redact: bool = True) -> dict[str, Any]:
    """report.json 解析出的对象 → 紧凑摘要 dict（线索按优先级排序）。绝不抛。

    ``redact=True``（**默认**）：钱包私钥 / 助记词、后端凭据、个人隐私数据、加密配方等高敏类别的
    value 按类别脱敏，自由文本里的结构化 PII 一并抹掉。明文原值只留在本地完整报告里。

    ``redact=False``（`fxapk digest --no-redact`）：原样输出。

    ★默认值曾是 ``False``（明文），已翻转。理由是这个出口的实际用法：本工具的主推路径就是把
      digest 喂给 AI，默认明文等于「按最省事的方式用」就把高敏原值交了出去，而想要安全反倒得
      额外记得加参数。两类失误的后果也不对称——忘了关脱敏只是少看见几个值、回头补跑即可；
      忘了开脱敏则是原值已经出去了、收不回来。
    """
    if not isinstance(report, dict):
        return {"error": "report 非 dict", "leads": []}
    raw_meta = report.get("meta")
    meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
    # digest intentionally consumes raw JSON for tolerance.  Project scope
    # before *any* count/sort/render decision so stale or forged materialized
    # booleans/advice cannot let batch/legacy evidence outrank current-case
    # evidence.  The projection is copy-on-write and leaves report untouched.
    leads = project_serialized_leads(report)
    leads_sorted = sorted(leads, key=_lead_sort_key)
    pii_flag = [False]  # 单元素可变标记：任一 lead 自由文本抹掉 PII 即置 True（见 _compact_lead）
    # 人工放行凭据：让「这条是被人放行的」在 digest（AI 的主消费面）上直接可见。
    restored_index = restore_index(meta)

    by_advice = Counter(str(lead.get("advice") or "未研判") for lead in leads)
    by_category = Counter(str(lead.get("category") or "?") for lead in leads)

    # 结构化境外源站段（被动定位的海外后端/控制者：IP 归属/ASN/开放端口/服务 banner/技术栈/关联子域，
    # 按主机聚合，机器可读）。由 pipeline 写入 meta["overseas_targets"]，已做辖区门控（仅国外+未知）；
    # 此处原样透传供 agent 直查——纯被动 OSINT 定位，对目标零流量。
    overseas_targets = meta.get("overseas_targets")
    overseas_targets = overseas_targets if isinstance(overseas_targets, list) else []

    closure = project_serialized_closure(report)
    closure_targets = closure.get("targets")
    compact_closure = {
        "status": closure.get("status"),
        "target_count": len(closure_targets) if isinstance(closure_targets, list) else 0,
        "gaps": [str(item) for item in closure.get("gaps", [])]
        if isinstance(closure.get("gaps"), list)
        else [],
        "next_actions": [str(item) for item in closure.get("next_actions", [])]
        if isinstance(closure.get("next_actions"), list)
        else [],
        "source_summary": closure.get("source_summary")
        if isinstance(closure.get("source_summary"), dict)
        else {},
    }

    network_attribution = _compact_network_attribution(meta.get("network_attribution"))
    role_candidate_count = (
        network_attribution["counts"].get("eligible", 0)
        if isinstance(network_attribution, dict)
        else 0
    )

    digest: dict[str, Any] = {
        "package": meta.get("package_name") or report.get("package_name"),
        "sha256": meta.get("sample_sha256"),
        "app_classification": meta.get("app_classification"),
        "summary": {
            "total_leads": len(leads),
            "by_advice": dict(by_advice),
            "by_category": dict(by_category),
            "comm_sessions": len(meta.get("comm_sessions") or []),
            "overseas_target_hosts": len(overseas_targets),
            "attributed_role_candidates": role_candidate_count,
        },
        "integrity": _integrity(report),  # run 级完整性红旗（reliable=False 时结果可能不可信）
        # ★证据可见性放在 leads **之前**：消费方（尤其是 AI）必须先知道「哪些输入没看见」，
        #   否则会把一份壳桩样本的空线索列表读成「该样本干净」。见 core/visibility.py。
        "visibility": _compact_visibility(meta.get("visibility")),
        # ★控制链紧接 visibility：先知道哪里没看见，再看「看见的这些是怎么串起来的」。
        #   原先只写 meta、无出口——组成节点各自可见 ≠ 这条关系可见。
        "control_chains": _compact_control_chains(meta.get("control_chains")),
        # ★三段的顺序即研判次序：哪里没看见 → 看见了什么事实 → 该向谁调证。
        #   findings 承载 leads 不表达的判断（重打包警示、通讯录窃取接口、未知壳…），
        #   此前完全不透出，对 AI 等于不存在。
        "findings": _compact_findings(report),
        "leads": [
            _compact_lead(lead, redact, pii_flag, restored_sources_for(lead, restored_index))
            for lead in leads_sorted
        ],
        "overseas_targets": overseas_targets,
        "closure": compact_closure,
    }
    # jadx 持久索引状态透出（消费面之一：不透出等于没接）。兼容旧报告：只有 meta
    # 明确带 jadx_index_status 时才输出整段；key 按 hex64 语法校验后才带（绝非路径）。
    if "jadx_index_status" in meta:
        jadx_index: dict[str, Any] = {"status": meta.get("jadx_index_status")}
        index_key = meta.get("jadx_index_key")
        if isinstance(index_key, str) and re.fullmatch(r"[0-9a-f]{64}", index_key):
            jadx_index["key"] = index_key
        # ownership 比较小节（P2-C）：只有明确的 compared 摘要才投影——unavailable、
        # 缺失/未知状态一律不建 comparison（不许归零冒充合法结果）。不输出 ownership
        # 枚举值，带"非鉴真"caveat——INHERITED_OFFICIAL 绝不能被排版成鉴真结论。
        raw_summary = meta.get("jadx_ownership_summary")
        if isinstance(raw_summary, dict) and raw_summary.get("status") == "compared":

            def _nonnegative_int(value: object) -> int:
                # bool 是 int 的子类，但摘要计数不接受布尔值。
                if isinstance(value, bool):
                    return 0
                if isinstance(value, int) and value >= 0:
                    return value
                return 0

            matches = _nonnegative_int(raw_summary.get("matches"))
            modified = _nonnegative_int(raw_summary.get("modified"))
            absent = _nonnegative_int(raw_summary.get("absent"))
            unattributed = _nonnegative_int(raw_summary.get("unattributed"))
            jadx_index["comparison"] = {
                "matches": matches,
                "modified": modified,
                "absent": absent,
                # partial baseline 时 region 全落 unattributed——不透出它，三桶全 0
                # 会被读成"没有 region"。total 从校验后的四桶复算，不信任上游。
                "unattributed": unattributed,
                "total_regions": matches + modified + absent + unattributed,
                "authenticity_asserted": raw_summary.get("authenticity_asserted") is True,
                "caveat": (
                    "此处仅表示 JADX 结构匹配/差异，不是来源真实性或官方身份鉴真；"
                    "与调用方断言的 baseline 结构匹配不构成鉴真结论。"
                ),
            }
        # 查询账本 sidecar 引用锚（P2-D2）：只投影绑定所需四字段；sidecar 内容由
        # locator 指向，reason 保留在原始 meta 审计面。
        raw_ledger = meta.get("jadx_judgment_ledger")
        if isinstance(raw_ledger, dict):
            # 白名单透传、源字段存在才输出：失败锚的 attempted_*/reason/published 一并
            # 可见——digest 消费者必须能分清"已验证磁盘摘要"与"本次拟发布字节摘要"。
            jadx_index["ledger"] = {
                key: raw_ledger[key]
                for key in (
                    "locator", "digest", "attempted_digest", "event_count",
                    "attempted_event_count", "replay_ok", "reason", "published",
                )
                if key in raw_ledger
            }
        digest["jadx_index"] = jadx_index

    if network_attribution is not None:
        digest["network_attribution"] = network_attribution
    # ★告警（codex C1）：redact 模式下自由文本命中并抹掉了结构化 PII → 显式标记，不静默
    #   （提醒操作者上游把受害人 PII 写进了 subject/notes 等自由文本，脱敏虽已兜底但源头应修）。
    if redact and pii_flag[0]:
        digest["redaction_warning"] = "自由文本字段命中并抹除了结构化 PII（手机号/证件号/邮箱/卡号）；上游不应把受害人 PII 写入自由文本"
    return digest
