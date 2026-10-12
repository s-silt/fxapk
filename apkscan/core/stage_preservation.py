"""把更早阶段的证据并入当前报告，且不去拼接互相冲突的运行时证明。

脱壳重分析会换成另一份 Report。这里只归档被取代的整份报告、带回它独有的端点/线索，
并在去重时保留每次不同的富化观察。不读取网页补采模块的内部助手。
"""

from __future__ import annotations

import hashlib
import json
import logging
from copy import deepcopy
from typing import Any

from apkscan.core import infra
from apkscan.core.models import (
    Endpoint,
    Evidence,
    EvidenceScope,
    Lead,
    LeadCategory,
    Report,
)
from apkscan.report import json as report_json

logger = logging.getLogger(__name__)

CARRIED_FROM = "superseded-static"
CARRIED_NOTE = "（沿用较早阶段，脱壳重分析未再生）"
_HISTORY = "enrichment_history"
_HISTORY_TRUNC = "enrichment_history_truncated"
_PRESERVE_ENRICHMENT = frozenset({_HISTORY, _HISTORY_TRUNC, "stage_preservation"})
_WEB_COPY_KEYS = (
    "web_supplement",
    "web_observation_plan",
    "web_observations",
)
_RAW_KEY = "_web_supplement_raws"
_RUNTIME_KEY = "web_supplement_runtime"
_MISSING = object()

_SAMPLE_FACT_KEYS = frozenset({
    "is_hardened",
    "packed",
    "packer",
    "packers",
    "hardening_structural",
    "repack_identity",
    "closure",
    "visibility",
})


def preserved_web_meta(prior: dict, active: dict) -> dict[str, Any]:
    """显式投影 REA 去重键、补采回执和独立网页观察。不合并其它 meta。"""
    out: dict[str, Any] = {}
    for key in _WEB_COPY_KEYS:
        if key in _SAMPLE_FACT_KEYS or key not in prior:
            continue
        if key not in active:
            out[key] = deepcopy(prior[key])
            continue
        if key == "web_supplement":
            merged = _merge_web_receipts(prior[key], active[key])
            if merged is not None:
                out[key] = merged
    raws = _union_strings(active.get(_RAW_KEY), prior.get(_RAW_KEY))
    if raws is not None:
        out[_RAW_KEY] = raws
    rounds = _union_json_items(active.get(_RUNTIME_KEY), prior.get(_RUNTIME_KEY))
    if rounds is not None:
        out[_RUNTIME_KEY] = rounds
    return out


def merge_carried_evidence(active: Report, previous: Report) -> None:
    """把前一阶段独有的端点/线索并入当前报告，并给同值对象补上缺失证据。"""
    _merge_endpoints(active, previous)
    _merge_leads(active, previous)
    _merge_finding_evidence(active, previous)


def extend_phase_history(
    previous: Report | None, existing_lineage: dict, apk_path: str,
) -> dict[str, Any]:
    """追加一份不嵌套旧快照的阶段归档。相同快照不重复记。"""
    if previous is None:
        return {}
    existing = _history_items(existing_lineage.get("phase_history"))
    truncated = existing_lineage.get("phase_history_truncated")
    snapshot, nested = _snapshot_report(previous)
    combined = _dedupe_entries(existing + _history_items(nested))
    entry = _history_entry(previous, snapshot, apk_path)
    digest = entry.get("snapshot_sha256")
    if not any(item.get("snapshot_sha256") == digest for item in combined):
        combined.append(entry)
    out: dict[str, Any] = {"phase_history": [deepcopy(item) for item in combined]}
    if isinstance(truncated, dict):
        out["phase_history_truncated"] = deepcopy(truncated)
    return out


def dedup_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    """按 value 去重。证据身份含 observed_at；runtime 整对象先到先得，冲突进历史。"""
    merged: dict[str, Endpoint] = {}
    for ep in endpoints:
        existing = merged.get(ep.value)
        if existing is None:
            merged[ep.value] = Endpoint(
                value=ep.value,
                kind=ep.kind,
                evidences=list(ep.evidences),
                is_cleartext=ep.is_cleartext,
                is_private=ep.is_private,
                is_suspicious=ep.is_suspicious,
                enrichment=_copy_enrichment(ep.enrichment),
            )
            continue
        existing.evidences.extend(ep.evidences)
        existing.is_cleartext = existing.is_cleartext or ep.is_cleartext
        existing.is_private = existing.is_private or ep.is_private
        existing.is_suspicious = existing.is_suspicious or ep.is_suspicious
        _merge_enrichment(existing, ep)
    for ep in merged.values():
        ep.evidences = _dedupe_evidence(ep.evidences)
    return list(merged.values())


def dedup_leads(leads: list[Lead]) -> list[Lead]:
    """按类别和归一化值去重。档位与降档保持先到者，证据和调取项取并集。"""
    merged: dict[tuple[LeadCategory, str], Lead] = {}
    for ld in leads:
        key = _lead_key(ld)
        cur = merged.get(key)
        if cur is None:
            merged[key] = ld
            continue
        _merge_lead(cur, ld)
    return list(merged.values())


def _merge_endpoints(active: Report, previous: Report) -> None:
    index = {ep.value: ep for ep in active.endpoints}
    for ep in previous.endpoints:
        found = index.get(ep.value)
        if found is None:
            clone = deepcopy(ep)
            marker = dict(clone.enrichment.get("stage_preservation") or {})
            marker["carried_from"] = CARRIED_FROM
            clone.enrichment["stage_preservation"] = marker
            active.endpoints.append(clone)
            index[clone.value] = clone
            continue
        found.evidences = _dedupe_evidence(
            list(found.evidences) + [deepcopy(ev) for ev in ep.evidences]
        )


def _merge_leads(active: Report, previous: Report) -> None:
    present = {_lead_key(ld) for ld in active.leads}
    incoming: list[Lead] = []
    for ld in previous.leads:
        if ld.category is LeadCategory.PACKER:
            continue
        incoming.append(deepcopy(ld))
    merged = dedup_leads(list(active.leads) + incoming)
    for ld in merged:
        if _lead_key(ld) in present:
            continue
        if CARRIED_NOTE not in (ld.notes or ""):
            ld.notes = f"{ld.notes}{CARRIED_NOTE}" if ld.notes else CARRIED_NOTE
    active.leads = merged


def _merge_finding_evidence(active: Report, previous: Report) -> None:
    by_id = {finding.id: finding for finding in active.findings if finding.id}
    for finding in previous.findings:
        if _hardening_finding(finding) or not finding.id:
            continue
        current = by_id.get(finding.id)
        if current is None:
            clone = deepcopy(finding)
            active.findings.append(clone)
            by_id[finding.id] = clone
            continue
        current.evidences = _dedupe_evidence(
            list(current.evidences) + [deepcopy(ev) for ev in finding.evidences]
        )


def _hardening_finding(finding: object) -> bool:
    category = str(getattr(finding, "category", "") or "").lower()
    analyzer = str(getattr(finding, "analyzer", "") or "").lower()
    ident = str(getattr(finding, "id", "") or "").lower()
    return analyzer == "packing" or category in {"packing", "packer", "hardening"} or (
        "packer" in ident
    )


def _snapshot_report(report: Report) -> tuple[dict[str, Any], list]:
    clone = deepcopy(report)
    if not isinstance(clone.meta, dict):
        clone.meta = {}
    fields = clone.meta
    lineage = fields.get("artifact_lineage") if isinstance(fields.get("artifact_lineage"), dict) else None
    nested: list = []
    if isinstance(lineage, dict):
        nested = _history_items(lineage.pop("phase_history", []))
        lineage.pop("phase_history_truncated", None)
        if not lineage:
            fields.pop("artifact_lineage", None)
    try:
        payload = report_json.to_dict(clone)
        json.dumps(payload, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        logger.exception("[stage] 阶段快照无法变成 JSON")
        return {"phase_status": "snapshot_failed", "reason": "json_incompatible"}, nested
    _mark_snapshot(payload)
    return payload, nested


def _mark_snapshot(payload: dict[str, Any]) -> None:
    """在已序列化的副本上标记被取代。不写回活报告的 meta。"""
    for name, section in payload.items():
        if name != "meta":
            continue
        if isinstance(section, dict):
            section["phase_status"] = "superseded"
            return
    payload["meta"] = {"phase_status": "superseded"}


def _history_entry(report: Report, snapshot: dict[str, Any], apk_path: str) -> dict[str, Any]:
    encoded = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    meta = report.meta if isinstance(report.meta, dict) else {}
    return {
        "snapshot_sha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
        "phase_status": "superseded" if snapshot.get("phase_status") != "snapshot_failed"
        else "snapshot_failed",
        "artifact_lineage": {
            "active_input": "prior-report",
            "apk_path": apk_path,
            "superseded_static_hardened": bool(meta.get("is_hardened")),
            "superseded_static_packed": meta.get("packed"),
        },
        "report": snapshot,
    }


def _history_items(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _dedupe_entries(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        digest = str(item.get("snapshot_sha256") or "")
        if digest and digest in seen:
            continue
        if digest:
            seen.add(digest)
        out.append(item)
    return out


def _copy_enrichment(enrichment: dict) -> dict:
    return deepcopy(enrichment)


def _merge_enrichment(existing: Endpoint, incoming: Endpoint) -> None:
    enrichment = existing.enrichment
    incoming_body = {
        key: value for key, value in incoming.enrichment.items() if key not in _PRESERVE_ENRICHMENT
    }
    if "tier" in enrichment or "tier" in incoming_body:
        current_tier = enrichment.get("tier")
        incoming_tier = incoming_body.get("tier")
        enrichment["tier"] = infra.best_tier(
            current_tier if isinstance(current_tier, str) else None,
            incoming_tier if isinstance(incoming_tier, str) else None,
        )
    canonical = {key: value for key, value in enrichment.items() if key not in _PRESERVE_ENRICHMENT}
    diff = _enrichment_diff(canonical, incoming_body)
    _remember_enrichment(enrichment, incoming_body, diff, incoming)
    for key, value in incoming_body.items():
        if key == "tier" or key in enrichment:
            continue
        enrichment[key] = deepcopy(value) if isinstance(value, (dict, list)) else value
    _absorb_history(enrichment, incoming)


def _enrichment_diff(canonical: dict, incoming: dict) -> dict[str, Any]:
    diff: dict[str, Any] = {}
    for key in sorted(set(canonical) | set(incoming)):
        left = canonical.get(key, _MISSING)
        right = incoming.get(key, _MISSING)
        if left == right:
            continue
        diff[key] = {"_absent": True} if right is _MISSING else _freeze(right)
    return diff


def _remember_enrichment(
    enrichment: dict, incoming_body: dict, diff: dict[str, Any], endpoint: Endpoint,
) -> None:
    if not diff:
        return
    signature = _sha(_freeze(incoming_body))
    history = enrichment.get(_HISTORY)
    if not isinstance(history, list):
        history = []
        enrichment[_HISTORY] = history
    for item in history:
        if isinstance(item, dict) and item.get("observation_sha256") == signature:
            _union_anchors(item, endpoint)
            return
    anchors = _anchors(endpoint)
    history.append({
        "source_stage": _stage(endpoint),
        "observation_sha256": signature,
        "observation": _freeze(incoming_body),
        "diff": diff,
        "evidence_anchors": anchors,
    })


def _absorb_history(enrichment: dict, incoming: Endpoint) -> None:
    """把 incoming 已有历史按观察签名稳定并集。整段 observation 原样保留，不拼进当前 runtime。"""
    raw = incoming.enrichment.get(_HISTORY)
    if not isinstance(raw, list):
        return
    history = enrichment.get(_HISTORY)
    if not isinstance(history, list):
        history = []
        enrichment[_HISTORY] = history
    positions: dict[str, int] = {}
    for index, item in enumerate(history):
        if isinstance(item, dict):
            positions.setdefault(_history_key(item), index)
    for item in raw:
        if not isinstance(item, dict):
            continue
        copied = deepcopy(item)
        observation = copied.get("observation")
        if isinstance(observation, dict):
            observation.pop(_HISTORY, None)
            observation.pop(_HISTORY_TRUNC, None)
        key = _history_key(copied)
        found = positions.get(key)
        if found is None:
            history.append(copied)
            positions[key] = len(history) - 1
            continue
        _union_anchor_values(history[found], copied.get("evidence_anchors"))
    truncated = incoming.enrichment.get(_HISTORY_TRUNC)
    if isinstance(truncated, dict) and not isinstance(enrichment.get(_HISTORY_TRUNC), dict):
        enrichment[_HISTORY_TRUNC] = deepcopy(truncated)


def _history_key(item: dict) -> str:
    signature = item.get("observation_sha256")
    if isinstance(signature, str) and signature:
        return signature
    return _sha({"observation": item.get("observation"), "diff": item.get("diff")})


def _union_anchors(record: dict, endpoint: Endpoint) -> None:
    anchors = record.get("evidence_anchors")
    if not isinstance(anchors, list):
        anchors = []
        record["evidence_anchors"] = anchors
    seen = {_canonical(item) for item in anchors if isinstance(item, dict)}
    for item in _anchors(endpoint):
        token = _canonical(item)
        if token in seen:
            continue
        anchors.append(item)
        seen.add(token)


def _union_anchor_values(record: dict, extra: object) -> None:
    if not isinstance(extra, list):
        return
    anchors = record.get("evidence_anchors")
    if not isinstance(anchors, list):
        anchors = []
        record["evidence_anchors"] = anchors
    seen = {_canonical(item) for item in anchors if isinstance(item, dict)}
    for item in extra:
        if not isinstance(item, dict):
            continue
        token = _canonical(item)
        if token in seen:
            continue
        anchors.append(deepcopy(item))
        seen.add(token)


def _anchors(endpoint: Endpoint) -> list[dict[str, Any]]:
    return [
        {
            "source": ev.source,
            "location": ev.location,
            "snippet": ev.snippet,
            "scope": _scope_token(ev.scope),
            "observed_at": ev.observed_at,
        }
        for ev in endpoint.evidences
    ]


def _stage(endpoint: Endpoint) -> str:
    sources = sorted({ev.source for ev in endpoint.evidences if ev.source})
    return ",".join(sources) if sources else "unspecified"


def _merge_lead(cur: Lead, incoming: Lead) -> None:
    _append_evidence(cur.source_refs, incoming.source_refs)
    if cur.base_advice is None and not cur.downgrades and not cur.advice and incoming.advice:
        cur.advice = incoming.advice
    elif cur.advice and incoming.advice and cur.advice != incoming.advice:
        _note_once(cur, f"（去重合并：另有分析器判为 {incoming.advice}）")
    _append_strings(cur.evidence_to_obtain, incoming.evidence_to_obtain)
    _append_strings(cur.sni_masquerade, incoming.sni_masquerade)
    _archive_lead_conflict(cur, incoming)


def _archive_lead_conflict(cur: Lead, incoming: Lead) -> None:
    parts: list[str] = []
    if incoming.subject and incoming.subject != cur.subject:
        parts.append(f"subject={incoming.subject}")
    if incoming.where_to_request and incoming.where_to_request != cur.where_to_request:
        parts.append(f"where_to_request={incoming.where_to_request}")
    if incoming.confidence != cur.confidence:
        parts.append(f"confidence={incoming.confidence.value}")
    if incoming.shape_uncertain != cur.shape_uncertain:
        parts.append(f"shape_uncertain={incoming.shape_uncertain}")
    if incoming.notes and incoming.notes not in (cur.notes or ""):
        parts.append("notes=" + incoming.notes)
    for part in parts:
        _note_once(cur, f"（去重归档：{part}）")


def _append_evidence(dest: list[Evidence], incoming: list[Evidence]) -> None:
    seen = {_evidence_identity(ev) for ev in dest}
    for ev in incoming:
        identity = _evidence_identity(ev)
        if identity in seen:
            continue
        dest.append(ev)
        seen.add(identity)


def _append_strings(dest: list[str], incoming: list[str]) -> None:
    for item in incoming:
        if item not in dest:
            dest.append(item)


def _note_once(lead: Lead, note: str) -> None:
    if note in (lead.notes or ""):
        return
    lead.notes = f"{lead.notes}{note}" if lead.notes else note


def _dedupe_evidence(evidences: list[Evidence]) -> list[Evidence]:
    seen: set[tuple[object, ...]] = set()
    out: list[Evidence] = []
    for ev in evidences:
        identity = _evidence_identity(ev)
        if identity in seen:
            continue
        seen.add(identity)
        out.append(ev)
    return out


def _evidence_identity(ev: Evidence) -> tuple[object, ...]:
    return (ev.source, ev.location, ev.snippet, _scope_token(ev.scope), ev.observed_at)


def _scope_token(scope: object) -> str:
    if isinstance(scope, EvidenceScope):
        return scope.value
    return str(scope or "")


def _lead_key(ld: Lead) -> tuple[LeadCategory, str]:
    kind = ld.category.value.lower()
    norm = infra.match_key(kind, ld.value) if kind in ("domain", "ip") else ld.value.strip()
    return (ld.category, norm)


def _union_strings(active: object, prior: object) -> list[str] | None:
    if not isinstance(prior, list):
        return None
    if not isinstance(active, list):
        return _take_strings(prior)
    merged = _take_strings(active)
    for item in _take_strings(prior):
        if item not in merged:
            merged.append(item)
    if merged == active:
        return None
    return merged


def _take_strings(value: list) -> list[str]:
    out: list[str] = []
    for item in value:
        if isinstance(item, str) and item not in out:
            out.append(item)
    return out


def _union_json_items(active: object, prior: object) -> list | None:
    if not isinstance(prior, list):
        return None
    if not isinstance(active, list):
        return deepcopy(prior)
    merged = deepcopy(active)
    seen = {_canonical(item) for item in merged}
    for item in prior:
        token = _canonical(item)
        if token in seen:
            continue
        merged.append(deepcopy(item))
        seen.add(token)
    if merged == active:
        return None
    return merged


def _merge_web_receipts(prior: object, active: object) -> dict[str, Any] | None:
    """累计网页回执。当前报告已是同一份回执时不改写；跳过/待执行不覆盖已成功哈希。"""
    if not isinstance(prior, dict) or not isinstance(active, dict):
        return None
    if json.dumps(prior, sort_keys=True, default=str) == json.dumps(active, sort_keys=True, default=str):
        return None
    from apkscan.core.web_supplement_preservation import commit_supplement, load_attempts

    scratch: dict[str, Any] = {}
    for attempt in (
        load_attempts({"web_supplement": deepcopy(prior)})
        + load_attempts({"web_supplement": deepcopy(active)})
    ):
        commit_supplement(scratch, attempt, round_id=str(attempt.get("round_id") or ""))
    merged = scratch.get("web_supplement")
    if not isinstance(merged, dict) or merged == active:
        return None
    return merged


def _freeze(value: object) -> Any:
    try:
        return json.loads(_canonical(value))
    except (TypeError, ValueError):
        logger.warning("[stage] 富化字段无法 JSON 化：%s", type(value).__name__)
        return {"_unserializable": type(value).__name__}


def _canonical(value: object) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":"),
    )


def _sha(value: object) -> str:
    try:
        raw = _canonical(value)
    except (TypeError, ValueError):
        raw = json.dumps({"_unserializable": type(value).__name__}, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
