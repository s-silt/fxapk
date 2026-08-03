"""跨版本回归对比（corpus regress）：同一批真实样本，换版 fxapk 后**检出到底变好还是变坏**。

为什么需要：合成基线（``tests/synthetic``）防的是「改坏」——它只断言既有检出别丢，进 CI、零 PII。
但**发现问题**靠的是真样本：实测中六个真缺陷（整包被误拒、调证清单被基础设施污染、`.so` 里的 URL
残片被当域名、未知壳报「未加固」、DoH 采样漏检）**没有一个是合成测试发现的**，全部来自跑真样本。

corpus 的主键是 ``(sample_sha256, tool_version, ruleset_digest)``，换版本自动并存两份报告——
底座早就在了，缺的只是「拿它做对比」这一步，于是每次都靠手写一次性脚本，跑完即弃、数据不沉淀。
本模块补上这一步。

★判断「是不是正优化」的关键在**分方向**：检出变多不必然是好（可能是误报涨了），变少也不必然是坏
（可能是降噪）。故本模块只做**忠实呈现 + 分类**，把「建议调证条数」「载入失败→成功」「闭环状态翻转」
这些**方向明确**的维度单列，其余一律呈现原值交人判断，绝不自动给「优化/劣化」的总评分。

纯函数为主、可离线跑、绝不联网、绝不抛。
"""
from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from apkscan.core import corpus

logger = logging.getLogger(__name__)

#: advice 取值（与 core.infra 的三档一致）。回归里最关心「建议调证」的增减——它直接决定
#: 办案人拿到的调证清单长度与质量。
ADVICE_INVESTIGATE = "建议调证"
ADVICE_REVIEW = "待核"
ADVICE_SKIP = "无需调证"


@dataclass
class SampleDiff:
    """单个样本在两版之间的差异。"""

    sample_sha256: str
    package_name: str | None = None
    case_id: str | None = None
    # 状态类
    status_from: str | None = None
    status_to: str | None = None
    closure_from: str | None = None
    closure_to: str | None = None
    hardened_from: bool | None = None
    hardened_to: bool | None = None
    # 计数类（None 表示该版无此样本）
    counts_from: dict[str, int] = field(default_factory=dict)
    counts_to: dict[str, int] = field(default_factory=dict)
    #: None = 该版报告读不到（缺文件/坏 JSON），与「读到了但零线索」的 {} 严格区分。
    advice_from: dict[str, int] | None = None
    advice_to: dict[str, int] | None = None
    #: 证据可见性指纹（:func:`corpus.visibility_summary`）。None = 该版报告没有可见性求值——
    #: 与「求过值、无受限主张」的 dict 严格区分，否则「整个求值阶段丢了」的退化会静默通过。
    visibility_from: dict | None = None
    visibility_to: dict | None = None
    # 检出类
    findings_added: list[str] = field(default_factory=list)
    findings_removed: list[str] = field(default_factory=list)
    # 备注：方向明确的变化，供人一眼看到
    notes: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(
            self.findings_added or self.findings_removed or self.notes
            or self.counts_from != self.counts_to
            or self.advice_from != self.advice_to
            or self.visibility_from != self.visibility_to
            or self.status_from != self.status_to
            or self.closure_from != self.closure_to
            or self.hardened_from != self.hardened_to
        )


def _load_report(corpus_dir: Path, entry: dict) -> dict | None:
    """按 manifest 记录读回报告全文；缺文件 / 坏 JSON → None（绝不抛）。"""
    rel = entry.get("report_path")
    if not isinstance(rel, str) or not rel:
        return None
    path = Path(corpus_dir) / rel
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — 缺文件/坏 JSON 视为不可读，调用方按 None 处理
        logger.debug("回归对比读报告失败：%s", path, exc_info=True)
        return None


def advice_counts(report: dict | None) -> dict[str, int] | None:
    """报告里各 advice 档的线索条数；**报告不可读时返回 None**。★这是判断「降噪是否有效」的核心指标。

    manifest 只存线索总数，不分档；而「建议调证」条数才是办案人实际面对的清单长度——
    实测一次降噪把它从 89 压到 24，总数却只从 107 降到 87，只看总数完全看不出来。

    ★``None`` 与 ``{}`` 必须分开：前者是「这份报告读不到」，后者是「读到了，确实零线索」。曾把
    两者都折叠成 ``{}``，于是报告文件缺失会被渲染成「建议调证 24 → 0（降噪）」——凭空捏造一个
    并不存在的改进。本模块的立意就是别把缺失当不存在，不能在自己内部先犯这个错。
    """
    if not isinstance(report, dict):
        return None
    leads = report.get("leads")
    if not isinstance(leads, list):
        return None
    c: Counter[str] = Counter()
    for ld in leads:
        if isinstance(ld, dict):
            c[str(ld.get("advice") or "(空)")] += 1
    return dict(c)


def _closure_status(report: dict | None) -> str | None:
    if not isinstance(report, dict):
        return None
    clo = (report.get("meta") or {}).get("closure")
    return (clo or {}).get("status") if isinstance(clo, dict) else None


def revision_of(entry: dict) -> str:
    """一条 manifest 记录的「修订版」标识：``tool_version@完整 ruleset_digest``。

    ★为什么不只用 tool_version：实测语料里，**被重跑过的样本全部是同 tool_version、
    不同 ruleset_digest**——真实迭代节奏是「版本号不动、规则集天天在动」。只按版本号切版，
    一整轮规则改动的效果一份都量不出来。规则集变了检出就可能变，它必须进版本坐标。

    ★用**完整** digest 而不是前 8 位：corpus 主键用的是完整 digest，两份「完整值不同、前 8 位相同」
    的报告是合法共存的两条记录；按前缀切版会把它们压成同一版，于是两套不同规则集的结果被当成
    同一版互相对比。显示时才截断（见 :func:`short_revision`）。
    """
    tv = str(entry.get("tool_version") or "?")
    rd = str(entry.get("ruleset_digest") or "")
    return f"{tv}@{rd}" if rd else tv


def short_revision(revision: str, width: int = 8) -> str:
    """修订版的人读形态：规则摘要截断到前 ``width`` 位。仅供显示，不作为键。"""
    tv, sep, rd = revision.partition("@")
    return f"{tv}{sep}{rd[:width]}" if sep else tv


def _index_by_sample(entries: list[dict], revision: str) -> dict[str, dict]:
    """取某修订版的 ``{sample_sha256: entry}``；同键重复时取最后一条（确定性：按 report_path 排序）。"""
    out: dict[str, list[dict]] = {}
    for e in entries:
        if not isinstance(e, dict) or revision_of(e) != revision:
            continue
        sha = e.get("sample_sha256")
        if isinstance(sha, str) and sha:
            out.setdefault(sha, []).append(e)
    return {
        sha: sorted(items, key=lambda x: str(x.get("report_path") or ""))[-1]
        for sha, items in out.items()
    }


def available_versions(entries: list[dict]) -> list[str]:
    """库内出现过的修订版，**按入库顺序**（首次出现的先后）去重返回。

    ★不能按字符串排序：字典序里 ``1.10.0`` 排在 ``1.9.0`` 前面，取「最后一个」当最新会拿到 1.9；
    同版本下多个规则摘要之间的字典序更是毫无时间含义。manifest 无任何时间戳字段，而 ``upsert``
    是纯追加（见 ``corpus.upsert``），所以**行序即入库顺序**——这是库里唯一能代表新旧的信号。
    """
    seen: dict[str, None] = {}
    for e in entries:
        if isinstance(e, dict) and e.get("tool_version"):
            seen.setdefault(revision_of(e), None)
    return list(seen)


def resolve_revision(spec: str, revisions: list[str]) -> tuple[str | None, str]:
    """把用户输入解析成一个确切修订版。返回 ``(修订版 或 None, 出错说明)``。

    接受：完整 ``1.2.0@<摘要>``、摘要写前缀 ``1.2.0@8bcab574``、以及纯版本号 ``1.2.0``
    （该版本下只有一个规则集时）。**版本号下有多个规则集时拒绝猜**——猜错会把两次不同规则集的
    结果错当同一版对比。

    ★版本段按**精确相等**匹配、不做前缀：曾用整串 ``startswith``，于是库里只有 ``1.1.0-rc@…``
    时输入 ``1.1.0`` 会被静默解析成那个预发布版，报错文案还误称「对应多个规则集」。
    """
    spec = (spec or "").strip()
    if not spec:
        return None, "版本不能为空"
    if spec in revisions:
        return spec, ""

    want_ver, sep, want_digest = spec.partition("@")
    hits = [
        r for r in revisions
        if r.partition("@")[0] == want_ver
        and (not sep or r.partition("@")[2].startswith(want_digest))
    ]
    shown = [short_revision(r) for r in revisions]
    if len(hits) == 1:
        return hits[0], ""
    if not hits:
        return None, f"{spec!r} 不在库内。可选：{shown}"
    return None, (
        f"{spec!r} 对应多个规则集：{[short_revision(h) for h in hits]}。"
        f"规则集变了检出就可能变，请写全（如 {short_revision(hits[0])}）。"
    )


def diff_versions(
    corpus_dir: str | Path, entries: list[dict], version_from: str, version_to: str
) -> tuple[list[SampleDiff], dict[str, Any]]:
    """逐样本对比两版检出。返回 ``(差异列表, 汇总)``。绝不抛。

    只对比**两版都有**的样本；仅单版有的样本单列（新入库 / 旧版未跑），不当成检出变化。
    """
    root = Path(corpus_dir)
    idx_a = _index_by_sample(entries, version_from)
    idx_b = _index_by_sample(entries, version_to)
    both = sorted(set(idx_a) & set(idx_b))
    only_a = sorted(set(idx_a) - set(idx_b))
    only_b = sorted(set(idx_b) - set(idx_a))

    diffs: list[SampleDiff] = []
    for sha in both:
        ea, eb = idx_a[sha], idx_b[sha]
        ra, rb = _load_report(root, ea), _load_report(root, eb)
        d = SampleDiff(
            sample_sha256=sha,
            package_name=eb.get("package_name") or ea.get("package_name"),
            case_id=eb.get("case_id") or ea.get("case_id"),
            status_from=ea.get("analysis_status"),
            status_to=eb.get("analysis_status"),
            closure_from=_closure_status(ra),
            closure_to=_closure_status(rb),
            hardened_from=ea.get("is_hardened"),
            hardened_to=eb.get("is_hardened"),
            counts_from=_safe_counts(ea),
            counts_to=_safe_counts(eb),
            advice_from=advice_counts(ra),
            advice_to=advice_counts(rb),
            # ★读报告全文而非 manifest 投影：upsert 按主键幂等跳过，存量行在 reindex 前没有
            #   visibility 字段，信投影会把「老行没记」读成「没有受限主张」。与 advice_counts 同路径。
            visibility_from=corpus.visibility_summary(ra),
            visibility_to=corpus.visibility_summary(rb),
        )
        fa, fb = _safe_finding_ids(ea), _safe_finding_ids(eb)
        d.findings_added = sorted(fb - fa)
        d.findings_removed = sorted(fa - fb)
        d.notes = _direction_notes(d)
        diffs.append(d)

    summary = _summarize(diffs, only_a, only_b, version_from, version_to)
    return diffs, summary


def _safe_counts(entry: dict) -> dict[str, int]:
    """manifest 的 counts 取成 ``{str: int}``；畸形（字符串/列表/嵌套）→ 空 dict。

    ★不能直接 ``dict(entry["counts"])``：manifest 可能被手工编辑或来自旧 schema，畸形值会让
    ``dict()``/``set()`` 抛到调用方，违背本模块「绝不抛」的承诺。
    """
    raw = entry.get("counts")
    if not isinstance(raw, dict):
        return {}
    return {str(k): v for k, v in raw.items() if isinstance(v, int)}


def _safe_finding_ids(entry: dict) -> set[str]:
    """manifest 的 finding_ids 取成字符串集合；畸形元素（dict/list）跳过而非抛。"""
    raw = entry.get("finding_ids")
    if not isinstance(raw, list):
        return set()
    return {x for x in raw if isinstance(x, str)}


def _direction_notes(d: SampleDiff) -> list[str]:
    """只对**方向明确**的变化下判断；其余一律不评价（避免把降噪误判成劣化，反之亦然）。"""
    notes: list[str] = []
    # ★任一侧报告读不到 → 这两版之间的「线索/闭环」根本无从比较，只如实说读不到，绝不下结论。
    #   曾把读不到折叠成空值，于是缺一份报告就会渲染出「建议调证 24 → 0（降噪）」和
    #   「闭环 complete → None（降级）」——凭空捏造并不存在的改进与劣化。
    unreadable = [
        label for label, adv in (("旧版", d.advice_from), ("新版", d.advice_to)) if adv is None
    ]
    if unreadable:
        return [f"⚠ {'、'.join(unreadable)}报告读不到（缺文件或坏 JSON），线索与闭环无法对比"]

    # 载入失败 → 成功：方向明确的改善（实测两个样本正是从整包被拒变为可分析）
    if d.status_from in ("failed", "error") and d.status_to not in ("failed", "error", None):
        notes.append("★ 由分析失败转为可分析")
    if d.status_to in ("failed", "error") and d.status_from not in ("failed", "error", None):
        notes.append("⚠ 由可分析转为分析失败")
    # 加固判定翻转：方向明确（漏判→检出 = 改善）
    if not d.hardened_from and d.hardened_to:
        notes.append("★ 加固判定：未检出 → 已检出")
    if d.hardened_from and not d.hardened_to:
        notes.append("⚠ 加固判定：已检出 → 未检出")
    # 闭环状态翻转：complete→partial 需人核（可能是新加的可见性约束正确降级，也可能是误伤）
    if d.closure_from == "complete" and d.closure_to != "complete":
        notes.append(f"闭环 complete → {d.closure_to}（须人核：正确降级还是误伤）")
    if d.closure_from != "complete" and d.closure_to == "complete":
        notes.append(f"闭环 {d.closure_from} → complete（须人核：是否证据确实变足）")
    # 建议调证条数：只报变化幅度，不判好坏
    a = (d.advice_from or {}).get(ADVICE_INVESTIGATE, 0)
    b = (d.advice_to or {}).get(ADVICE_INVESTIGATE, 0)
    if a != b:
        notes.append(f"建议调证 {a} → {b}（{'降噪' if b < a else '新增'}，须抽样核对是否误杀/误报）")
    notes.extend(_visibility_notes(d))
    return notes


def _visibility_notes(d: SampleDiff) -> list[str]:
    """可见性维度的方向判断。★按取证代价不对称分档：**警示消失**比警示新增危险得多。

    多一条「此处看不见」最多让人白核一遍；少一条会让办案人把「未发现」当成「已穷尽」——这正是
    :mod:`apkscan.core.visibility` 存在的理由，所以它自己的退化必须被回归护网抓住。反过来，
    新增受限主张多半是新约束在正确降级，记中性备注、不告警。
    """
    va, vb = d.visibility_from, d.visibility_to
    if va is not None and vb is None:
        return ["⚠ 新版报告缺失可见性求值（求值阶段丢失？须人核）"]
    if va is None and vb is not None:
        # 换版首次对比时全库都会走这条：旧报告产于可见性求值上线之前，不是退化。
        return ["旧版报告无可见性求值（旧版本产物），可见性维度不作方向判断"]
    if va is None or vb is None:
        return []

    notes: list[str] = []
    blocked_a, blocked_b = set(va["blocked_claims"]), set(vb["blocked_claims"])
    cleared = sorted(blocked_a - blocked_b)
    added = sorted(blocked_b - blocked_a)
    if cleared:
        why = "（remediation=reanalyzed，可能是脱壳回灌生效）" if vb.get("remediation") == "reanalyzed" else ""
        notes.append(
            f"⚠ 可见性受限主张解除：{'、'.join(cleared)}{why}"
            "（须人核：输入真的变可见了，还是求值退化把信号弄丢了）"
        )
    if added:
        notes.append(f"可见性新增受限主张：{'、'.join(added)}（可能是新约束正确降级）")
    # 仍瞎着、却不再给补法建议：有过先例的缺陷形态（可见性求值排在补法预案之前 → 建议恒空）。
    if blocked_b and va["next_actions"] > 0 and vb["next_actions"] == 0:
        notes.append("⚠ 仍有受限主张但补法建议清零（历史缺陷形态，须人核阶段顺序）")
    notes.extend(_downgraded_gap_notes(va, vb))
    return notes


def _downgraded_gap_notes(va: dict, vb: dict) -> list[str]:
    """同一条主张仍被阻断，但阻断理由从「确证盲区」退成了「未评估」。

    两者对 closure 的分量不同：确证盲区是本次分析实测到的缺口，记 gap、把闭环封顶 partial；
    未评估只 warn、不封顶。于是这种迁移会让 blocked_claims / 各源档位 / degraded / 补法条数
    全部纹丝不动，而报告上的警示实际弱了一档——正是本模块盯的「警示悄悄消失」那一类。
    """
    ca = va.get("claims") or {}
    cb = vb.get("claims") or {}
    if not (isinstance(ca, dict) and isinstance(cb, dict)):
        return []
    weakened = sorted(
        claim
        for claim, before in ca.items()
        if isinstance(before, dict) and isinstance(after := cb.get(claim), dict)
        and before.get("missing_sources") and not after.get("missing_sources")
        and after.get("unassessed_sources")
    )
    if not weakened:
        return []
    return [
        f"⚠ 受限理由由「确证盲区」退为「仅未评估」：{'、'.join(weakened)}"
        "（closure 封顶随之松开，须人核是分档语义变了还是输入丢了）"
    ]


def _summarize(
    diffs: list[SampleDiff], only_a: list[str], only_b: list[str],
    version_from: str, version_to: str,
) -> dict[str, Any]:
    changed = [d for d in diffs if d.changed]
    added = Counter(f for d in diffs for f in d.findings_added)
    removed = Counter(f for d in diffs for f in d.findings_removed)
    # ★只统计**两侧都读得到**的样本：把读不到当 0 会凭空做出一份「降噪」战绩。
    comparable = [d for d in diffs if d.advice_from is not None and d.advice_to is not None]
    unreadable = len(diffs) - len(comparable)
    inv_from = sum((d.advice_from or {}).get(ADVICE_INVESTIGATE, 0) for d in comparable)
    inv_to = sum((d.advice_to or {}).get(ADVICE_INVESTIGATE, 0) for d in comparable)
    return {
        "version_from": version_from,
        "version_to": version_to,
        "version_from_short": short_revision(version_from),
        "version_to_short": short_revision(version_to),
        "compared": len(diffs),
        "changed": len(changed),
        "only_in_from": len(only_a),
        "only_in_to": len(only_b),
        "only_in_from_samples": list(only_a),
        "only_in_to_samples": list(only_b),
        "findings_added_total": dict(added.most_common()),
        "findings_removed_total": dict(removed.most_common()),
        # 建议调证合计的分母：仅两侧报告都可读的样本数（其余样本不参与合计）
        "advice_comparable": len(comparable),
        "advice_unreadable": unreadable,
        "advice_investigate_from": inv_from,
        "advice_investigate_to": inv_to,
        "became_analyzable": sum(1 for d in diffs if any("由分析失败转为可分析" in n for n in d.notes)),
        "became_unanalyzable": sum(1 for d in diffs if any("由可分析转为分析失败" in n for n in d.notes)),
        # 闭环状态取自报告全文，读不到时 closure_* 恒为 None，不得计入降级
        "closure_downgraded": sum(
            1 for d in diffs
            if d.advice_from is not None and d.advice_to is not None
            and d.closure_from == "complete" and d.closure_to != "complete"
        ),
        "hardening_newly_detected": sum(1 for d in diffs if not d.hardened_from and d.hardened_to),
        # ---- 证据可见性（中性计数，不给总评）----
        "visibility_comparable": sum(
            1 for d in diffs if d.visibility_from is not None and d.visibility_to is not None
        ),
        # 受限主张解除 = 须人核重点（警示消失即漏报放大）
        "visibility_blocked_cleared": sum(
            1 for d in diffs
            if d.visibility_from is not None and d.visibility_to is not None
            and set(d.visibility_from["blocked_claims"]) - set(d.visibility_to["blocked_claims"])
        ),
        "visibility_blocked_added": sum(
            1 for d in diffs
            if d.visibility_from is not None and d.visibility_to is not None
            and set(d.visibility_to["blocked_claims"]) - set(d.visibility_from["blocked_claims"])
        ),
        # ★只数「新版报告读得到、却没有可见性求值」；报告根本读不到走 advice_unreadable 口径，
        #   不折进来。反方向（旧版无求值 → 新版有）是旧 schema 升级，绝不与本计数合并。
        "visibility_assessment_lost": sum(
            1 for d in diffs
            if d.visibility_from is not None and d.visibility_to is None and d.advice_to is not None
        ),
    }


def load_and_diff(
    corpus_dir: str | Path, version_from: str, version_to: str
) -> tuple[list[SampleDiff], dict[str, Any]]:
    """读 manifest 并对比两版（供 CLI 调用）。绝不抛。"""
    entries = corpus.load_manifest(corpus_dir)
    return diff_versions(corpus_dir, entries, version_from, version_to)


__all__ = [
    "SampleDiff",
    "advice_counts",
    "available_versions",
    "diff_versions",
    "load_and_diff",
    "resolve_revision",
    "revision_of",
    "short_revision",
]
