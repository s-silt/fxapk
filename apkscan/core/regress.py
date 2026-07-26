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
    advice_from: dict[str, int] = field(default_factory=dict)
    advice_to: dict[str, int] = field(default_factory=dict)
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


def advice_counts(report: dict | None) -> dict[str, int]:
    """报告里各 advice 档的线索条数。★这是判断「降噪是否有效」的核心指标。

    manifest 只存线索总数，不分档；而「建议调证」条数才是办案人实际面对的清单长度——
    实测一次降噪把它从 89 压到 24，总数却只从 107 降到 87，只看总数完全看不出来。
    """
    if not isinstance(report, dict):
        return {}
    leads = report.get("leads")
    if not isinstance(leads, list):
        return {}
    c = Counter()
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
    """一条 manifest 记录的「修订版」标识：``tool_version@ruleset前8位``。

    ★为什么不只用 tool_version：实测语料库 14 个样本里，**被重跑过的三个全部是同 tool_version、
    不同 ruleset_digest**——真实迭代节奏是「版本号不动、规则集天天在动」。只按版本号切版，
    一整轮规则改动的效果一份都量不出来。规则集变了检出就可能变，它必须进版本坐标。
    """
    tv = str(entry.get("tool_version") or "?")
    rd = str(entry.get("ruleset_digest") or "")
    return f"{tv}@{rd[:8]}" if rd else tv


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
    """库内出现过的修订版（``版本@规则摘要``，去重、稳定排序）。"""
    return sorted({
        revision_of(e) for e in entries
        if isinstance(e, dict) and e.get("tool_version")
    })


def resolve_revision(spec: str, revisions: list[str]) -> tuple[str | None, str]:
    """把用户输入解析成一个确切修订版。返回 ``(修订版 或 None, 出错说明)``。

    接受三种写法：完整 ``1.2.0@8bcab574``、纯版本号 ``1.2.0``（该版本下只有一个规则集时）、
    以及唯一前缀。**版本号下有多个规则集时拒绝猜**——猜错会把两次不同规则集的结果错当同一版对比。
    """
    spec = (spec or "").strip()
    if not spec:
        return None, "版本不能为空"
    if spec in revisions:
        return spec, ""
    hits = [r for r in revisions if r.startswith(spec)]
    if len(hits) == 1:
        return hits[0], ""
    if not hits:
        return None, f"{spec!r} 不在库内。可选：{revisions}"
    return None, (
        f"{spec!r} 对应多个规则集：{hits}。规则集变了检出就可能变，请写全（如 {hits[0]}）。"
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
        fa = set(ea.get("finding_ids") or [])
        fb = set(eb.get("finding_ids") or [])
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
            counts_from=dict(ea.get("counts") or {}),
            counts_to=dict(eb.get("counts") or {}),
            advice_from=advice_counts(ra),
            advice_to=advice_counts(rb),
            findings_added=sorted(fb - fa),
            findings_removed=sorted(fa - fb),
        )
        d.notes = _direction_notes(d)
        diffs.append(d)

    summary = _summarize(diffs, only_a, only_b, version_from, version_to)
    return diffs, summary


def _direction_notes(d: SampleDiff) -> list[str]:
    """只对**方向明确**的变化下判断；其余一律不评价（避免把降噪误判成劣化，反之亦然）。"""
    notes: list[str] = []
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
    a = d.advice_from.get(ADVICE_INVESTIGATE, 0)
    b = d.advice_to.get(ADVICE_INVESTIGATE, 0)
    if a != b:
        notes.append(f"建议调证 {a} → {b}（{'降噪' if b < a else '新增'}，须抽样核对是否误杀/误报）")
    return notes


def _summarize(
    diffs: list[SampleDiff], only_a: list[str], only_b: list[str],
    version_from: str, version_to: str,
) -> dict[str, Any]:
    changed = [d for d in diffs if d.changed]
    added = Counter(f for d in diffs for f in d.findings_added)
    removed = Counter(f for d in diffs for f in d.findings_removed)
    inv_from = sum(d.advice_from.get(ADVICE_INVESTIGATE, 0) for d in diffs)
    inv_to = sum(d.advice_to.get(ADVICE_INVESTIGATE, 0) for d in diffs)
    return {
        "version_from": version_from,
        "version_to": version_to,
        "compared": len(diffs),
        "changed": len(changed),
        "only_in_from": len(only_a),
        "only_in_to": len(only_b),
        "findings_added_total": dict(added.most_common()),
        "findings_removed_total": dict(removed.most_common()),
        "advice_investigate_from": inv_from,
        "advice_investigate_to": inv_to,
        "became_analyzable": sum(1 for d in diffs if any("由分析失败转为可分析" in n for n in d.notes)),
        "became_unanalyzable": sum(1 for d in diffs if any("由可分析转为分析失败" in n for n in d.notes)),
        "closure_downgraded": sum(1 for d in diffs if d.closure_from == "complete" and d.closure_to != "complete"),
        "hardening_newly_detected": sum(1 for d in diffs if not d.hardened_from and d.hardened_to),
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
]
