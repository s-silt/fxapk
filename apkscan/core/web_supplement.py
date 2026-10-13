"""Automatic web-observation scheduling and candidate intake.

Live CDP authorization comes only from the caller config. On-disk web evidence
stays offline and is not reused as that authorization. New candidates use
``external-web-observation`` and are not observed-contact evidence.
``CaptureWindowObserver``, ``SkippingObserver`` and ``make_capture_observer``
are loaded from ``web_supplement_runtime`` on first use. This module does not
keep a second ready implementation.
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from apkscan.core.models import (
    ADVICE_REVIEW,
    OBSERVED_CONTACT_SOURCES,
    AnalysisConfig,
    Confidence,
    Endpoint,
    Evidence,
    EvidenceScope,
    Lead,
)
from apkscan.core.web_observation_plan import (
    CONFIG_SCHEMA,
    WebSupplementRequest,
    build_plan,
    clean_coverage,
    fixed_reason,
    load_config_path,
    parse_config,
    project_plan_for_digest,
)

if TYPE_CHECKING:
    from apkscan.core.web_supplement_runtime import (
        CaptureWindowObserver as CaptureWindowObserver,
        SkippingObserver as SkippingObserver,
        make_capture_observer as make_capture_observer,
    )

__all__ = [
    "CaptureWindowObserver",
    "SkippingObserver",
    "fixed_reason",
    "make_capture_observer",
    "project_for_digest",
]
from apkscan.core.webctx import WebContext

logger = logging.getLogger(__name__)

# 计划与回执是工具覆盖，不是案件信号。seen 列表是跨轮去重留档。
META_WRITE_OWNER = "core.web_supplement"
META_WRITE_CATEGORIES = {
    "_web_supplement_raws": "record",
    "web_observation_plan": "coverage",
}
META_WRITE_KEYS = frozenset(META_WRITE_CATEGORIES)

SOURCE = "external-web-observation"
NOTE = "网页观察候选，未经 App 归属与业务判定，不构成案件闭环"
SUMMARY_EXECUTED = "已自动补采解析{n}候选"
SUMMARY_SKIPPED = "网页补采已跳过：{reason}"
SUMMARY_FAILED = "网页补采失败：{reason}"
SUMMARY_GAP = "仍缺证据"
_SHA64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_PUBLISH_BYTES = 32 * 1024 * 1024
_DIGEST_STATUS = frozenset({
    "pending", "skipped", "ok", "executed", "failed", "unavailable", "not_applicable", "unknown",
})
_ROUND_IDS = frozenset({"single", "static", "round-1", "round-2", "round-3", "three_rounds"})
_PROVIDERS = frozenset({"", "rea", "inspect", "trace", "fxapk-cdp-trace"})
_DISPLAY_RELATIONS = 64


def assert_source_boundary() -> None:
    if SOURCE.startswith("runtime") or SOURCE in OBSERVED_CONTACT_SOURCES:
        raise RuntimeError("external web source must stay outside observed-contact")


assert_source_boundary()


def _digest_status(value: object, *, fallback: str) -> str:
    """Whitelist a status. A cached ``complete`` stays unknown."""
    if value == "complete":
        return "unknown"
    if not isinstance(value, str):
        return fallback if fallback in _DIGEST_STATUS else "unknown"
    if value not in _DIGEST_STATUS:
        return "skipped"
    return value


def _attempt_counts(attempts: object, status: str, latest_status: str) -> tuple[int, int]:
    """Count stored attempts only. Attempt bodies stay out of the digest."""
    if isinstance(attempts, list):
        rows = [item for item in attempts if isinstance(item, dict)]
        failed = sum(item.get("status") == "failed" for item in rows)
        return len(rows), failed
    if status in {"pending", "unknown"} and latest_status in {"pending", "unknown"}:
        return 0, 0
    return 1, int(latest_status == "failed" or status == "failed")


def summary_line(status: str, reason: str, candidates: int) -> str:
    code = fixed_reason(reason)
    if status in {"ok", "executed"} and candidates > 0:
        return f"{SUMMARY_EXECUTED.format(n=candidates)}；{SUMMARY_GAP}"
    if status in {"ok", "executed"}:
        return f"已自动补采解析0候选；{SUMMARY_GAP}"
    if status == "failed":
        return f"{SUMMARY_FAILED.format(reason=code)}；{SUMMARY_GAP}"
    return f"{SUMMARY_SKIPPED.format(reason=code)}；{SUMMARY_GAP}"


def project_for_digest(value: object) -> dict[str, Any]:
    """Whitelist projection. A cached ``complete`` is not relabelled as executed."""
    base = {
        "status": "pending",
        "reason": "no_config",
        "provider": "",
        "parse_counts": {"endpoints": 0, "config_leads": 0, "relations": 0, "scripts": 0},
        "round_id": "",
        "raw_sha256": [],
        "summary_line": summary_line("pending", "no_config", 0),
        "closure_evaluated": False,
        "app_attribution_verified": False,
        "latest_status": "pending",
        "latest_reason": "no_config",
        "attempt_count": 0,
        "failure_count": 0,
        "relation_omitted": 0,
        "capture_started": False,
    }
    if not isinstance(value, dict):
        base["reason"] = "config_rejected"
        base["status"] = "skipped"
        base["latest_status"] = "skipped"
        base["latest_reason"] = "config_rejected"
        base["summary_line"] = summary_line("skipped", "config_rejected", 0)
        return base
    status = _digest_status(value.get("status"), fallback="unknown")
    reason_raw = value.get("reason")
    reason = fixed_reason(reason_raw if isinstance(reason_raw, str) else "config_rejected")
    raw_counts = value.get("parse_counts")
    counts = raw_counts if isinstance(raw_counts, dict) else {}
    clean_counts = {}
    for key in ("endpoints", "config_leads", "relations", "scripts"):
        number = counts.get(key, 0)
        clean_counts[key] = number if isinstance(number, int) and not isinstance(number, bool) and number >= 0 else 0
    provider_raw = value.get("provider")
    provider = provider_raw if isinstance(provider_raw, str) and provider_raw in _PROVIDERS else ""
    round_raw = value.get("round_id")
    round_id = round_raw if isinstance(round_raw, str) and round_raw in _ROUND_IDS else ""
    raw_hashes = value.get("raw_sha256")
    hashes: list[str] = []
    if isinstance(raw_hashes, list):
        for item in raw_hashes:
            if isinstance(item, str) and _SHA64.fullmatch(item) and item not in hashes:
                hashes.append(item)
    candidates = clean_counts["endpoints"] + clean_counts["config_leads"]
    latest_status = _digest_status(value.get("latest_status", status), fallback=status)
    latest_reason_raw = value.get("latest_reason", reason)
    latest_reason = fixed_reason(latest_reason_raw if isinstance(latest_reason_raw, str) else "config_rejected")
    attempt_count, failure_count = _attempt_counts(value.get("attempts"), status, latest_status)
    relation_total = clean_counts["relations"]
    listed = value.get("relations")
    if isinstance(listed, list):
        relation_total = max(relation_total, sum(isinstance(item, dict) for item in listed))
    projected = {
        "status": status,
        "reason": reason,
        "provider": provider,
        "parse_counts": clean_counts,
        "round_id": round_id,
        "raw_sha256": hashes,
        "summary_line": summary_line(status, reason, candidates),
        "closure_evaluated": False,
        "app_attribution_verified": False,
        "latest_status": latest_status,
        "latest_reason": latest_reason,
        "attempt_count": attempt_count,
        "failure_count": failure_count,
        "relation_omitted": max(0, relation_total - _DISPLAY_RELATIONS),
        "capture_started": _strict_bool(value.get("capture_started"), value.get("boundary")),
    }
    coverage = clean_coverage(value.get("coverage"))
    if coverage:
        projected["coverage"] = coverage
    return projected


def _strict_bool(value: object, boundary: object = None) -> bool:
    """Accept only a real boolean. Strings and numbers are not started evidence."""
    if isinstance(value, bool):
        return value
    if isinstance(boundary, dict) and isinstance(boundary.get("capture_started"), bool):
        return boundary["capture_started"] is True
    return False


def _record(plan: dict[str, Any], **extra: Any) -> dict[str, Any]:
    counts = extra.pop("parse_counts", None) or {"endpoints": 0, "config_leads": 0, "relations": 0, "scripts": 0}
    status = extra.pop("status", plan.get("status") or "skipped")
    reason = fixed_reason(str(extra.pop("reason", plan.get("reason") or "skipped")))
    record = {
        "schema_version": "fxapk.web_supplement/1",
        "attempt": 1 if plan.get("execute") else 0,
        "status": status,
        "reason": reason,
        "provider": extra.pop("provider", plan.get("provider") or ""),
        "parse_counts": counts,
        "round_id": extra.pop("round_id", ""),
        "raw_sha256": extra.pop("raw_sha256", []),
        "relative_paths": extra.pop("relative_paths", []),
        "boundary": {
            "live_cdp": bool(extra.pop("live_cdp", False)),
            "capture_started": extra.pop("capture_started", False) is True,
            "device_modified": False,
            "closure_evaluated": False,
            "app_attribution_verified": False,
            "business_judgement": False,
        },
    }
    candidates = counts["endpoints"] + counts["config_leads"]
    record["summary_line"] = summary_line(status, reason, candidates)
    record["relations"] = _clean_relations(extra.pop("relations", []))
    coverage = clean_coverage(extra.pop("coverage", None))
    if coverage:
        record["coverage"] = coverage
    return record


def resolve_request(config: AnalysisConfig) -> tuple[WebSupplementRequest | None, str]:
    path = getattr(config, "web_supplement", None)
    inline = getattr(config, "web_supplement_request", None)
    if path and inline is not None:
        return None, "config_rejected"
    if inline is not None:
        return parse_config(inline if isinstance(inline, dict) else {"invalid": True})
    if not path:
        return None, ""
    try:
        return parse_config(load_config_path(path))
    except ValueError as exc:
        return None, fixed_reason(str(exc))


def discover_plugins() -> tuple[list[Any], list[dict[str, str]]]:
    from apkscan.plugins.registry import discover_plugins as load

    return load()


def _plugin() -> tuple[Any | None, str]:
    try:
        plugins, statuses = discover_plugins()
    except Exception:
        logger.exception("[web-supplement] plugin discovery failed")
        return None, "plugin_unavailable"
    for plugin in plugins:
        if getattr(plugin, "name", "") == "rea" and callable(getattr(plugin, "run_supplement", None)):
            return plugin, ""
    for status in statuses:
        if status.get("name") == "rea":
            return None, "plugin_unavailable"
    return None, "plugin_unavailable"


def _linked(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
    except OSError:
        return True
    probe = getattr(path, "is_junction", None)
    if probe is None:
        return False
    try:
        return bool(probe())
    except OSError:
        return True


def _assert_unlinked(path: Path) -> None:
    current = path
    for _ in range(64):
        if current.exists() and _linked(current):
            raise ValueError("link_escape")
        parent = current.parent
        if parent == current:
            return
        current = parent


def _copy_parts(name: str) -> tuple[str, ...]:
    if not isinstance(name, str) or not name or name.startswith(("/", "\\")) or ":" in name:
        raise ValueError("link_escape")
    parts = tuple(name.replace("\\", "/").split("/"))
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("link_escape")
    return parts


def _published_rel(location: str) -> str:
    raw = location.replace("\\", "/")
    if raw.startswith("web/"):
        raw = raw[4:]
    try:
        return "/".join(_copy_parts(raw))
    except ValueError:
        return "observation.json"


def _retag(
    evidence: Evidence,
    raw_sha: str,
    *,
    pointer: str = "",
    script_sha: str = "",
    request_id: str = "",
    session_id: str = "",
    frame_id: str = "",
    script_frame_id: str = "",
) -> Evidence:
    """Point at the published copy plus the original pointer and byte hash.

    External observation is batch reference. It is not case evidence and cannot
    pass the case reanalysis intake by scope alone.
    """
    rel = _published_rel(evidence.location or "observation.json")
    sha = script_sha
    if not sha and rel.startswith("scripts/") and rel.endswith(".js"):
        candidate = rel[len("scripts/"):-len(".js")]
        if _SHA64.fullmatch(candidate):
            sha = candidate
    location = f"external_observations/{raw_sha}/{rel}"
    bits: list[str] = []
    if pointer:
        bits.append("ptr=" + pointer.replace(" ", "")[:180])
    if sha and _SHA64.fullmatch(sha):
        bits.append("sha256=" + sha)
    for label, token in (
        ("request", _anchor_token(request_id)),
        ("session", _anchor_token(session_id)),
        ("frame", _anchor_token(frame_id)),
        ("script_frame", _anchor_token(script_frame_id)),
    ):
        if token:
            bits.append(label + "=" + token)
    if bits:
        location += "#" + "&".join(bits)
    return Evidence(
        source=SOURCE,
        location=location,
        snippet="",
        scope=EvidenceScope.BATCH_REFERENCE,
    )


def _frame_anchor(groups: object, fallback: str) -> tuple[str, str, str]:
    if isinstance(groups, list):
        for group in groups:
            if not isinstance(group, dict):
                continue
            frames = group.get("frames")
            if not isinstance(frames, list):
                continue
            for frame in frames:
                if not isinstance(frame, dict):
                    continue
                ref = frame.get("source_ref")
                pointer = fallback
                if isinstance(frame.get("original_ref"), str):
                    pointer = frame["original_ref"]
                if isinstance(ref, dict):
                    rel_raw = ref.get("relative_path")
                    sha_raw = ref.get("sha256")
                    orig_raw = ref.get("original_ref")
                    rel = rel_raw if isinstance(rel_raw, str) else ""
                    sha = sha_raw if isinstance(sha_raw, str) else ""
                    if isinstance(orig_raw, str) and orig_raw:
                        pointer = orig_raw
                    if rel:
                        return rel, sha, pointer or fallback
    return "observation.json", "", fallback


def _safe_relative(value: object) -> str:
    """Keep a relative evidence path. URLs and absolute paths are not anchors."""
    if not isinstance(value, str) or not value or "://" in value:
        return ""
    if value.startswith(("/", "\\")):
        return ""
    try:
        return "/".join(_copy_parts(value))
    except ValueError:
        return ""


def _anchor_token(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,120}", value):
        return ""
    return value


def _clean_relations(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    cleaned: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for item in value:
        if not isinstance(item, dict) or item.get("source") != SOURCE:
            continue
        url = item.get("url") if isinstance(item.get("url"), str) else ""
        if not url:
            continue
        sha_raw = item.get("script_sha256")
        sha = sha_raw if isinstance(sha_raw, str) else ""
        original_raw = item.get("original_ref")
        original = original_raw if isinstance(original_raw, str) else ""
        if any(char in original for char in "\n\r\x00"):
            original = ""
        row = {
            "source": SOURCE,
            "url": url,
            "original_ref": original,
            "script_sha256": sha if _SHA64.fullmatch(sha) else "",
            "relative_path": _safe_relative(item.get("relative_path")),
            "app_attribution_verified": False,
        }
        for key in ("request_id", "session_id", "frame_id", "script_frame_id", "loader_id"):
            token = _anchor_token(item.get(key))
            if token:
                row[key] = token
        for key in ("observed_identity_bridge", "async_parent_present"):
            if isinstance(item.get(key), bool):
                row[key] = item[key]
        gaps = clean_coverage({"status": "partial", "gaps": item.get("gaps")}).get("gaps", [])
        if gaps:
            row["gaps"] = gaps
        identity = (
            row["url"], row["original_ref"], row["script_sha256"], row["relative_path"],
            row.get("request_id", ""), row.get("session_id", ""), row.get("frame_id", ""),
            row.get("script_frame_id", ""), row.get("loader_id", ""),
        )
        if identity in seen:
            continue
        seen.add(identity)
        cleaned.append(row)
    return cleaned


def _parse_verified(verified: dict[str, Any]) -> dict[str, Any]:
    raw_receipt = verified.get("receipt")
    receipt: dict[str, Any] = raw_receipt if isinstance(raw_receipt, dict) else {}
    raw_copies = verified.get("copies")
    copies: dict[Any, Any] = raw_copies if isinstance(raw_copies, dict) else {}
    raw_sha = str(verified.get("raw_sha") or "")
    files: dict[str, bytes] = {}
    for name, blob in copies.items():
        if isinstance(name, str) and name.endswith(".js") and isinstance(blob, bytes):
            files[f"web/{name}"] = blob
    ctx = WebContext(AnalysisConfig(online=False), files=files, origin="")
    from apkscan.analyzers.js_bundle import JsBundleAnalyzer
    from apkscan.analyzers.web_evidence import (
        WebInlineConfigAnalyzer,
        WebRedirectChainAnalyzer,
        WebRequestRecipeAnalyzer,
    )

    endpoints: list[Endpoint] = []
    leads: list[Lead] = []
    findings: list[Any] = []
    for analyzer in (
        JsBundleAnalyzer(),
        WebRedirectChainAnalyzer(),
        WebRequestRecipeAnalyzer(),
        WebInlineConfigAnalyzer(),
    ):
        try:
            result = analyzer.analyze(ctx)  # type: ignore[arg-type]
        except Exception:
            logger.exception("[web-supplement] analyzer failed")
            raise ValueError("parse_failed") from None
        for endpoint in result.endpoints:
            endpoint.evidences = [_retag(ev, raw_sha) for ev in endpoint.evidences]
            endpoint.enrichment = {}
            endpoints.append(endpoint)
        for lead in result.leads:
            lead.advice = ADVICE_REVIEW
            lead.confidence = Confidence.LOW
            lead.notes = NOTE
            lead.source_refs = [_retag(ev, raw_sha) for ev in lead.source_refs]
            lead.evidence_to_obtain = ["网页观察候选与脚本位置的人工复核"]
            leads.append(lead)
        for finding in result.findings:
            finding.evidences = [_retag(ev, raw_sha) for ev in finding.evidences]
            finding.confidence = Confidence.LOW
            if NOTE not in (finding.recommendation or ""):
                finding.recommendation = ((finding.recommendation or "").rstrip() + "\n" + NOTE).strip()
            findings.append(finding)
        if analyzer.name == "web_inline_config":
            for name, blob in files.items():
                try:
                    text = blob.decode("utf-8", errors="replace")
                    hits = analyzer._scan_block(text, name)  # type: ignore[attr-defined]
                except Exception:
                    logger.exception("[web-supplement] config scan failed")
                    raise ValueError("parse_failed") from None
                for hit in hits:
                    from apkscan.analyzers._common import EndpointCollector
                    from apkscan.analyzers.web_evidence import _add_endpoint

                    collector = EndpointCollector()
                    _add_endpoint(collector, hit.value, name, "")
                    for endpoint in collector.endpoints({"url": 0, "domain": 1, "ip": 2}):
                        endpoint.evidences = [_retag(ev, raw_sha) for ev in endpoint.evidences]
                        endpoint.enrichment = {}
                        endpoints.append(endpoint)
                    if not isinstance(analyzer, WebInlineConfigAnalyzer):
                        continue
                    leads.append(analyzer._lead(hit))
                    leads[-1].advice = ADVICE_REVIEW
                    leads[-1].confidence = Confidence.LOW
                    leads[-1].notes = NOTE
                    leads[-1].source_refs = [_retag(ev, raw_sha) for ev in leads[-1].source_refs]
    relation_records = _request_relations(receipt, raw_sha, endpoints)
    return {
        "endpoints": endpoints,
        "leads": leads,
        "findings": findings,
        "raw_sha": raw_sha,
        "provider": str(verified.get("provider") or ""),
        "relations": len(relation_records),
        "relation_records": relation_records,
        "scripts": len(files),
        "copies": {name: blob for name, blob in copies.items() if isinstance(name, str) and isinstance(blob, bytes)},
        "coverage": clean_coverage(receipt.get("coverage")),
    }


def _request_relations(
    receipt: dict[str, Any],
    raw_sha: str,
    endpoints: list[Endpoint],
) -> list[dict[str, Any]]:
    """Adapt trace ``requests[].hops[]`` and older request.url receipts.

    URLs are handed to the existing endpoint collector. Relation rows keep the
    published script path, script hash, and original JSON pointer.
    """
    from apkscan.analyzers._common import EndpointCollector
    from apkscan.analyzers.web_evidence import _add_endpoint

    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str, str, str]] = set()
    requests = receipt.get("requests")
    if not isinstance(requests, list):
        return records
    for request in requests:
        if not isinstance(request, dict):
            continue
        original_ref = request.get("original_ref")
        source_ref = request.get("source_ref")
        request_pointer = original_ref if isinstance(original_ref, str) else ""
        if not request_pointer and isinstance(source_ref, str):
            request_pointer = source_ref
        request_id = _anchor_token(request.get("request_id") or request.get("id"))
        session_id = _anchor_token(request.get("session_id") or request.get("sessionId"))
        frame_id = _anchor_token(request.get("frame_id")) or _frame_token(request.get("stack_groups"))
        observed: list[tuple[str, str, str, str, str, dict[str, Any]]] = []
        request_url = request.get("url")
        if isinstance(request_url, str):
            rel, sha, pointer = _frame_anchor(request.get("stack_groups"), request_pointer)
            initiator_raw = request.get("initiator")
            initiator = initiator_raw if isinstance(initiator_raw, dict) else {}
            script_path = initiator.get("script_path")
            if not sha and isinstance(script_path, str):
                rel = script_path
            observed.append((request_url, rel, sha, pointer, frame_id, request))
        hops = request.get("hops")
        if isinstance(hops, list):
            for hop in hops:
                if not isinstance(hop, dict):
                    continue
                hop_url = hop.get("url")
                if not isinstance(hop_url, str):
                    continue
                hop_pointer = hop.get("original_ref")
                pointer = hop_pointer if isinstance(hop_pointer, str) else request_pointer
                groups = hop.get("stack_groups")
                if not isinstance(groups, list):
                    groups = request.get("stack_groups")
                rel, sha, _ = _frame_anchor(groups, pointer)
                hop_frame = _anchor_token(hop.get("frame_id")) or frame_id
                observed.append((hop_url, rel, sha, pointer, hop_frame, hop))
        for url, rel, sha, pointer, hop_frame, hop in observed:
            published = _published_rel(rel) if _safe_relative(rel) else "observation.json"
            anchor = (url, pointer, sha, published, request_id, session_id, hop_frame)
            if anchor in seen:
                continue
            seen.add(anchor)
            collector = EndpointCollector()
            _add_endpoint(collector, url, published, "")
            for endpoint in collector.endpoints({"url": 0, "domain": 1, "ip": 2}):
                endpoint.evidences = [
                    _retag(
                        ev, raw_sha, pointer=pointer, script_sha=sha,
                        request_id=request_id, session_id=session_id, frame_id=hop_frame,
                        script_frame_id=_script_frame_token(hop),
                    )
                    for ev in endpoint.evidences
                ]
                endpoint.enrichment = {}
                endpoints.append(endpoint)
            row = {
                "source": SOURCE,
                "url": url,
                "original_ref": pointer,
                "script_sha256": sha,
                "relative_path": f"external_observations/{raw_sha}/{published}",
                "app_attribution_verified": False,
            }
            if request_id:
                row["request_id"] = request_id
            if session_id:
                row["session_id"] = session_id
            if hop_frame:
                row["frame_id"] = hop_frame
            script_frame = _script_frame_token(hop)
            if script_frame:
                row["script_frame_id"] = script_frame
            loader = _anchor_token(hop.get("loader_id"))
            if loader:
                row["loader_id"] = loader
            for key in ("observed_identity_bridge", "async_parent_present"):
                if isinstance(hop.get(key), bool):
                    row[key] = hop[key]
            gaps = clean_coverage({"status": "partial", "gaps": hop.get("gaps")}).get("gaps", [])
            if gaps:
                row["gaps"] = gaps
            records.append(row)
    return records


def _script_frame_token(hop: object) -> str:
    if not isinstance(hop, dict):
        return ""
    groups = hop.get("stack_groups")
    if not isinstance(groups, list):
        return ""
    for group in groups:
        if not isinstance(group, dict):
            continue
        frames = group.get("frames")
        if not isinstance(frames, list):
            continue
        for frame in frames:
            if not isinstance(frame, dict):
                continue
            token = _anchor_token(frame.get("script_frame_id"))
            if token:
                return token
    return ""


def _frame_token(groups: object) -> str:
    if not isinstance(groups, list):
        return ""
    for group in groups:
        if not isinstance(group, dict):
            continue
        frames = group.get("frames")
        if not isinstance(frames, list):
            continue
        for frame in frames:
            if not isinstance(frame, dict):
                continue
            token = _anchor_token(frame.get("frame_id") or frame.get("frameId") or frame.get("id"))
            if token:
                return token
    return ""


def _publish(out_dir: str, raw_sha: str, copies: dict[str, bytes]) -> str:
    """Create-only publication. An existing directory must already be the exact set."""
    from apkscan.core.atomic import atomic_create_bytes

    if not isinstance(raw_sha, str) or _SHA64.fullmatch(raw_sha) is None:
        raise ValueError("config_rejected")
    if not isinstance(copies, dict):
        raise ValueError("parse_failed")
    expected: dict[str, bytes] = {}
    total = 0
    for name, blob in copies.items():
        rel = "/".join(_copy_parts(name))
        if not isinstance(blob, bytes):
            raise ValueError("parse_failed")
        total += len(blob)
        if total > _MAX_PUBLISH_BYTES:
            raise ValueError("oversize")
        if rel in expected:
            raise ValueError("publish_conflict")
        expected[rel] = blob
    root = Path(out_dir) / "external_observations" / raw_sha
    _assert_unlinked(root)
    relative = f"external_observations/{raw_sha}/"
    if root.exists():
        if not root.is_dir() or _linked(root):
            raise ValueError("link_escape")
        if not expected:
            raise ValueError("publish_conflict")
        actual: dict[str, Path] = {}
        for path in root.rglob("*"):
            if _linked(path):
                raise ValueError("link_escape")
            if path.is_file():
                actual[path.relative_to(root).as_posix()] = path
        if set(actual) != set(expected):
            raise ValueError("publish_conflict")
        for rel, blob in expected.items():
            current = hashlib.sha256(actual[rel].read_bytes()).digest()
            if current != hashlib.sha256(blob).digest():
                raise ValueError("publish_conflict")
        return relative
    root.mkdir(parents=True, exist_ok=False)
    for rel, blob in expected.items():
        target = root.joinpath(*rel.split("/"))
        if root.resolve() not in target.resolve().parents:
            raise ValueError("link_escape")
        if _linked(target) or target.exists():
            raise ValueError("publish_conflict")
        target.parent.mkdir(parents=True, exist_ok=True)
        if not atomic_create_bytes(target, blob):
            raise ValueError("publish_conflict")
    return relative


def _run_plugin(request: WebSupplementRequest, out_dir: str) -> dict[str, Any]:
    plugin, reason = _plugin()
    if plugin is None:
        return {"status": "unavailable", "reason": reason}
    if request.source == "cdp" and request.authorized is not True:
        return {"status": "skipped", "reason": "cdp_not_authorized"}
    try:
        result = plugin.run_supplement({
            "schema_version": CONFIG_SCHEMA,
            "mode": request.mode,
            "source": request.source,
            "path": request.path,
            "endpoint": request.endpoint,
            "target": request.target,
            "exact_origins": list(request.exact_origins),
            "related_targets": request.related_targets is True,
            "provider": request.provider,
            "observation_ms": request.observation_ms,
            "authorized": request.authorized,
            "out_dir": out_dir,
        })
    except Exception:
        logger.exception("[web-supplement] plugin failed")
        return {"status": "failed", "reason": "parse_failed"}
    if not isinstance(result, dict):
        return {"status": "failed", "reason": "parse_failed"}
    return result


def _nonnegative_count(value: object) -> int:
    """Reject a count before any report write. Missing stays zero."""
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("parse_failed")
    return value


def _web_only(endpoint: Endpoint) -> bool:
    return bool(endpoint.evidences) and all(ev.source == SOURCE for ev in endpoint.evidences)


def merge_candidates(
    endpoints: list[Endpoint],
    leads: list[Lead],
    parsed: dict[str, Any],
    seen_raw: set[str],
) -> dict[str, int]:
    from apkscan.core.web_supplement_preservation import sync_domain_leads, union_evidence, union_text

    raw_sha = str(parsed.get("raw_sha") or "")
    if raw_sha and raw_sha in seen_raw:
        return {"endpoints": 0, "config_leads": 0, "relations": 0, "scripts": 0, "duplicate": 1}
    relation_count = _nonnegative_count(parsed.get("relations", 0))
    script_count = _nonnegative_count(parsed.get("scripts", 0))
    incoming_endpoints = parsed.get("endpoints") or []
    incoming_leads = parsed.get("leads") or []
    if not isinstance(incoming_endpoints, list) or not isinstance(incoming_leads, list):
        raise ValueError("parse_failed")
    # Stage every read before mutation so a bad incoming row cannot leave a partial merge.
    staged_new: list[Endpoint] = []
    staged_evidence: list[tuple[Endpoint, list[Any]]] = []
    by_value: dict[str, Endpoint] = {}
    for endpoint in endpoints:
        by_value.setdefault(endpoint.value, endpoint)
    added = 0
    for endpoint in incoming_endpoints:
        evidences = list(endpoint.evidences)
        current = by_value.get(endpoint.value)
        if current is None:
            staged_new.append(endpoint)
            by_value[endpoint.value] = endpoint
            added += 1
            continue
        staged_evidence.append((current, evidences))
    staged_leads: list[Lead] = []
    lead_unions: list[tuple[Lead, list[Any], list[str]]] = []
    known = {(lead.category, lead.value): lead for lead in leads}
    config_added = 0
    for lead in incoming_leads:
        key = (lead.category, lead.value)
        current = known.get(key)
        refs = list(lead.source_refs)
        obtain = [item for item in lead.evidence_to_obtain if isinstance(item, str)]
        if current is None:
            staged_leads.append(lead)
            known[key] = lead
            config_added += 1
            continue
        lead_unions.append((current, refs, obtain))
    for endpoint in staged_new:
        endpoints.append(endpoint)
    for current, evidences in staged_evidence:
        union_evidence(current.evidences, evidences)
    for lead in staged_leads:
        leads.append(lead)
    for current, refs, obtain in lead_unions:
        union_evidence(current.source_refs, refs)
        union_text(current.evidence_to_obtain, obtain)
    sync_domain_leads(endpoints, leads)
    if raw_sha:
        seen_raw.add(raw_sha)
    return {
        "endpoints": added,
        "config_leads": config_added,
        "relations": relation_count,
        "scripts": script_count,
        "duplicate": 0,
    }


def clamp_web_only_leads(leads: list[Lead]) -> None:
    for lead in leads:
        refs = list(lead.source_refs)
        if refs and all(getattr(ev, "source", "") == SOURCE for ev in refs):
            lead.advice = ADVICE_REVIEW
            lead.confidence = Confidence.LOW
            lead.notes = NOTE


def _merge_findings(findings: list[Any], incoming: list[Any]) -> None:
    """Keep analyzer findings. An existing same-id finding keeps its grade."""
    from apkscan.core.web_supplement_preservation import union_evidence

    staged_new: list[Any] = []
    staged_evidence: list[tuple[Any, list[Any]]] = []
    index = {
        item.id: item
        for item in findings
        if isinstance(getattr(item, "id", None), str) and item.id
    }
    for finding in incoming:
        ident = getattr(finding, "id", None)
        if not isinstance(ident, str) or not ident:
            continue
        evidences = list(getattr(finding, "evidences", []) or [])
        current = index.get(ident)
        if current is None:
            staged_new.append(finding)
            index[ident] = finding
            continue
        staged_evidence.append((current, evidences))
    findings.extend(staged_new)
    for current, evidences in staged_evidence:
        union_evidence(current.evidences, evidences)


def _observed_plugin_status(status: str) -> str:
    """Keep an explicit skip or unavailable result. Any other non-success is a failure."""
    if status in {"unavailable", "skipped", "ok", "executed"}:
        return status
    return "failed"


def _project_agent_handoff(plan: dict[str, Any], meta: dict[str, Any]) -> None:
    """Refresh guidance from the cumulative receipt. Plan execute and history stay put."""
    projected = project_plan_for_digest(
        plan, meta.get("web_supplement"), meta.get("web_supplement_runtime"),
    )
    plan["agent_handoff"] = projected["agent_handoff"]


def apply_static(state: Any) -> None:
    """Insert candidates after analyzers. Failures stay inside this stage."""
    config = state.config
    meta = state.meta if isinstance(state.meta, dict) else {}
    request, rejected = resolve_request(config)
    plan = build_plan(
        request,
        platform=str(getattr(state, "platform", "") or ""),
        meta=meta,
        rejected=rejected,
    )
    meta["web_observation_plan"] = plan
    seen = meta.get("_web_supplement_raws")
    if not isinstance(seen, list):
        seen = []
        meta["_web_supplement_raws"] = seen
    if not plan.get("execute") or request is None:
        _store_supplement(meta, plan)
        _project_agent_handoff(plan, meta)
        return
    plugin_result = _run_plugin(request, str(getattr(config, "out_dir", "out") or "out"))
    raw_status = plugin_result.get("status")
    status = raw_status if isinstance(raw_status, str) and raw_status else "failed"
    observed = _observed_plugin_status(status)
    reason = fixed_reason(str(plugin_result.get("reason") or status))
    if observed not in {"ok", "executed"}:
        _store_supplement(
            meta, plan, status=observed, reason=reason,
            live_cdp=plugin_result.get("live_cdp") is True,
            capture_started=plugin_result.get("capture_started") is True,
        )
        plan["status"] = observed
        plan["reason"] = reason
        _project_agent_handoff(plan, meta)
        return
    verified = plugin_result.get("verified")
    if not isinstance(verified, dict):
        _store_supplement(meta, plan, status="failed", reason="parse_failed")
        plan["status"] = "failed"
        plan["reason"] = "parse_failed"
        _project_agent_handoff(plan, meta)
        return
    try:
        parsed = _parse_verified(verified)
        relative = _publish(str(config.out_dir or "out"), parsed["raw_sha"], parsed["copies"])
        counts = merge_candidates(state.endpoints, state.leads, parsed, set(seen))
        if not counts.get("duplicate"):
            found = getattr(state, "findings", None)
            if not isinstance(found, list):
                state.findings = []
                found = state.findings
            _merge_findings(found, parsed.get("findings") or [])
        if parsed["raw_sha"] and parsed["raw_sha"] not in seen:
            seen.append(parsed["raw_sha"])
    except Exception:
        logger.exception("[web-supplement] parse or publish failed")
        _store_supplement(meta, plan, status="failed", reason="parse_failed")
        plan["status"] = "failed"
        plan["reason"] = "parse_failed"
        _project_agent_handoff(plan, meta)
        return
    if counts.get("duplicate"):
        reason = "duplicate_raw"
        status_name = "skipped"
    else:
        reason = "executed"
        status_name = "executed"
    held = getattr(state, "web_only_endpoints", None)
    if not isinstance(held, list):
        state.web_only_endpoints = []
        held = state.web_only_endpoints
    kept: list[Endpoint] = []
    for endpoint in state.endpoints:
        if _web_only(endpoint):
            held.append(endpoint)
        else:
            kept.append(endpoint)
    state.endpoints = kept
    _store_supplement(
        meta,
        plan,
        status=status_name,
        reason=reason,
        provider=parsed["provider"],
        parse_counts={key: counts[key] for key in ("endpoints", "config_leads", "relations", "scripts")},
        raw_sha256=[parsed["raw_sha"]] if parsed["raw_sha"] and not counts.get("duplicate") else [],
        relative_paths=[relative] if not counts.get("duplicate") else [],
        relations=parsed.get("relation_records") or [],
        coverage=parsed.get("coverage") or None,
        live_cdp=bool(plugin_result.get("live_cdp")),
        capture_started=plugin_result.get("capture_started") is True,
    )
    plan["status"] = status_name
    plan["reason"] = reason
    _project_agent_handoff(plan, meta)


def _store_supplement(meta: dict[str, Any], plan: dict[str, Any], **extra: Any) -> None:
    from apkscan.core.web_supplement_preservation import commit_supplement

    commit_supplement(meta, _record(plan, **extra))


def restore_held_endpoints(state: Any) -> None:
    held = getattr(state, "web_only_endpoints", None)
    if isinstance(held, list) and held:
        state.endpoints.extend(held)
        state.web_only_endpoints = []


_RUNTIME_EXPORTS = ("CaptureWindowObserver", "SkippingObserver", "make_capture_observer")


def __getattr__(name: str) -> Any:
    """Lazy re-export. Importing the runtime module at load time can cycle."""
    if name not in _RUNTIME_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from apkscan.core import web_supplement_runtime as runtime

    value = getattr(runtime, name)
    globals()[name] = value
    return value
