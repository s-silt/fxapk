"""两份分析报告的调证增量对比（供 ``fxapk diff`` 追踪同一 App 跨版本的变化）。

回答「新版比旧版**多/少了哪些调证线索**、端点、技术发现，以及身份 / 加固 / 分类是否变了」——
新增支付通道 / 钱包地址 / 后台入口、加固升级、SDK 变化等，是版本追踪与研判的高价值信号。

纯 dict 入、纯 dict 出：直接吃 report.json 反序列化的字典，不依赖 pipeline / androguard，可离线单测。
线索按 (category, value) 配对、端点按 (value, kind)、发现按 id；输出稳定、可被 agent / 脚本消费。
"""

from __future__ import annotations

#: meta 里追踪对比的身份 / 加固 / 运行标识键（变了即入 meta_changes）。
_META_TRACKED: tuple[str, ...] = (
    "package_name",
    "version_name",
    "version_code",
    "packer",
    "is_hardened",
    "mode",
    "analysis_status",
    "sample_sha256",
    "tool_version",
    "ruleset_digest",
)


def _lead_key(d: dict) -> tuple[str, str]:
    return (str(d.get("category", "")), str(d.get("value", "")))


def _endpoint_key(d: dict) -> tuple[str, str]:
    return (str(d.get("value", "")), str(d.get("kind", "")))


def _by_key(items: object, keyfn) -> dict:  # type: ignore[no-untyped-def]
    """把列表按 keyfn 建 {key: item} 映射（后者覆盖同键，与报告内既有去重口径一致）。"""
    out: dict = {}
    if isinstance(items, list):
        for it in items:
            if isinstance(it, dict):
                out[keyfn(it)] = it
    return out


def _diff_collection(old_items: object, new_items: object, keyfn) -> dict:  # type: ignore[no-untyped-def]
    """按 keyfn 配对，返回 {added, removed}（各为完整条目列表，保留原字段供消费方展示）。"""
    old_map = _by_key(old_items, keyfn)
    new_map = _by_key(new_items, keyfn)
    added = [new_map[k] for k in new_map if k not in old_map]
    removed = [old_map[k] for k in old_map if k not in new_map]
    return {"added": added, "removed": removed}


def _finding_key(f: dict) -> tuple[str, str]:
    """发现配对键 = (id, description)。★id 是**规则**标识不是实例标识：同一规则可命中多条（如
    jadx 每个硬编码密钥都共用常量 id ``JADX-HARDCODED-SECRET``），单用 id 会把多条塌缩、静默吞掉
    "新增密钥"这类核心调证增量。加 description 作实例区分（同规则的不同命中 description 不同）。"""
    return (str(f.get("id", "")), str(f.get("description", "")))


def _diff_findings(old_items: object, new_items: object) -> dict:
    """发现按 (id, description) 配对：{added, removed, changed}；changed = 同键但 severity/
    confidence/kind 变了（即同一条发现的属性升降级）。"""
    old_map = {_finding_key(f): f for f in old_items if isinstance(f, dict)} \
        if isinstance(old_items, list) else {}
    new_map = {_finding_key(f): f for f in new_items if isinstance(f, dict)} \
        if isinstance(new_items, list) else {}
    added = [new_map[k] for k in new_map if k not in old_map]
    removed = [old_map[k] for k in old_map if k not in new_map]
    changed = []
    for k in new_map:
        if k not in old_map:
            continue
        o, n = old_map[k], new_map[k]
        deltas = {
            attr: {"old": o.get(attr), "new": n.get(attr)}
            for attr in ("severity", "confidence", "kind")
            if o.get(attr) != n.get(attr)
        }
        if deltas:
            changed.append(
                {"id": str(n.get("id", "")), "title": str(n.get("title", "")), "changes": deltas}
            )
    return {"added": added, "removed": removed, "changed": changed}


def _diff_meta(old_meta: object, new_meta: object) -> dict:
    """对比 meta 里追踪的身份/加固键 + 嵌套 app_classification(type/score)，返回变化字典。"""
    om = old_meta if isinstance(old_meta, dict) else {}
    nm = new_meta if isinstance(new_meta, dict) else {}
    changes: dict = {}
    for k in _META_TRACKED:
        if om.get(k) != nm.get(k):
            changes[k] = {"old": om.get(k), "new": nm.get(k)}
    ocv = om.get("app_classification")
    ncv = nm.get("app_classification")
    oc = ocv if isinstance(ocv, dict) else {}
    nc = ncv if isinstance(ncv, dict) else {}
    for k in ("type", "score"):
        if oc.get(k) != nc.get(k):
            changes[f"app_classification.{k}"] = {"old": oc.get(k), "new": nc.get(k)}
    return changes


def diff_reports(old: object, new: object) -> dict:
    """对比两份 report.json 字典，返回调证增量的稳定结构（供 fxapk diff 打印 / agent 消费）。

    结构：``{leads, endpoints, findings, meta_changes, summary}``；leads/endpoints 各 {added, removed}，
    findings {added, removed, changed}，meta_changes 为变化键→{old,new}，summary 为各项计数。绝不抛。
    """
    o = old if isinstance(old, dict) else {}
    n = new if isinstance(new, dict) else {}
    leads = _diff_collection(o.get("leads"), n.get("leads"), _lead_key)
    endpoints = _diff_collection(o.get("endpoints"), n.get("endpoints"), _endpoint_key)
    findings = _diff_findings(o.get("findings"), n.get("findings"))
    meta_changes = _diff_meta(o.get("meta"), n.get("meta"))
    return {
        "leads": leads,
        "endpoints": endpoints,
        "findings": findings,
        "meta_changes": meta_changes,
        "summary": {
            "leads_added": len(leads["added"]),
            "leads_removed": len(leads["removed"]),
            "endpoints_added": len(endpoints["added"]),
            "endpoints_removed": len(endpoints["removed"]),
            "findings_added": len(findings["added"]),
            "findings_removed": len(findings["removed"]),
            "findings_changed": len(findings["changed"]),
            "meta_changed": len(meta_changes),
        },
    }
