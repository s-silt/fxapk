"""Live CDP observation inside an existing capture window.

The trace provider is a plugin subprocess. This module never imports ``fxapk_rea``.
Ready is taken only from the provider ``ready.json``. The capture deadline stops
that subprocess; the caller's browser is not closed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
from pathlib import Path
from typing import Any

from apkscan.core.models import (
    FINDING_KIND_OBSERVATION,
    AnalysisConfig,
    Confidence,
    Evidence,
    EvidenceScope,
    Finding,
    Severity,
)
from apkscan.core.web_observation_plan import (
    CONFIG_SCHEMA,
    fixed_reason,
    load_config_path,
    parse_config,
)

logger = logging.getLogger(__name__)

# seen 是跨轮去重留档。canonical web_supplement 由 preservation 投影写入。
META_WRITE_OWNER = "core.web_supplement_runtime"
META_WRITE_CATEGORIES = {
    "_web_supplement_raws": "record",
    "web_supplement_runtime": "record",
}
META_WRITE_KEYS = frozenset(META_WRITE_CATEGORIES)

SOURCE = "external-web-observation"
_POLL_SEC = 0.02
_JOIN_GRACE_SEC = 2.0
_WINDOW_RESERVE_MS = 2500
_ROUND_IN_PATH = re.compile(r"round([123])(?:\b|[-_/])")


class SkippingObserver:
    """Records a skip without contacting CDP or changing a device."""

    def __init__(self, reason: str) -> None:
        self.reason = fixed_reason(reason)
        self.events: list[str] = []

    def start(self, deadline: float | None) -> None:
        self.events.append("start")

    def wait_ready(self, deadline: float | None) -> str:
        self.events.append("ready")
        return "skipped"

    def finish(self) -> dict[str, Any]:
        self.events.append("finish")
        return {"status": "skipped", "reason": self.reason, "live_cdp": False}


def _load_plugin() -> tuple[Any | None, str]:
    try:
        from apkscan.plugins.registry import discover_plugins
    except Exception:
        logger.exception("[web-supplement] plugin discovery import failed")
        return None, "plugin_unavailable"
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


_DEFERRALS = frozenset({"not_requested", "device_unavailable", "pre_observer_failure"})


def authorized_cdp_config(path: str | None, request: dict[str, Any] | None) -> bool:
    """True when the caller authorized live CDP that static analysis must not run."""
    if path and request is not None:
        return False
    if request is not None:
        parsed, _reason = parse_config(request if isinstance(request, dict) else {"invalid": True})
    elif path:
        try:
            parsed, _reason = parse_config(load_config_path(path))
        except ValueError:
            return False
    else:
        return False
    return parsed is not None and parsed.mode == "auto" and parsed.authorized_cdp


def route_stripped_cdp(
    report: Any,
    path: str | None,
    request: dict[str, Any] | None,
    *,
    dynamic: bool,
    device: bool,
    observer_started: bool,
) -> None:
    """Record that authorized CDP did not run. Does not start a device or a browser."""
    if observer_started or not authorized_cdp_config(path, request):
        return
    meta = getattr(report, "meta", None)
    if not isinstance(meta, dict):
        return
    existing = meta.get("web_supplement_runtime")
    if isinstance(existing, list) and existing:
        return
    if not dynamic:
        deferral = "not_requested"
    elif not device:
        deferral = "device_unavailable"
    else:
        deferral = "pre_observer_failure"
    if deferral not in _DEFERRALS:
        deferral = "pre_observer_failure"
    _remember_runtime(report, {
        "status": "skipped",
        "reason": "cdp_deferred",
        "execution": "not_executed",
        "deferral": deferral,
        "provider": "fxapk-cdp-trace",
        "live_cdp": False,
        "capture_started": False,
    }, "")


def note_cdp_round_not_executed(
    report: Any,
    path: str | None,
    request: dict[str, Any] | None,
    *,
    round_id: str,
) -> None:
    """Append one not-executed receipt for a round whose observer never started.

    Existing receipts stay. A later round does not replace an earlier started one.
    """
    if not round_id or not authorized_cdp_config(path, request):
        return
    meta = getattr(report, "meta", None)
    if not isinstance(meta, dict):
        return
    existing = meta.get("web_supplement_runtime")
    if isinstance(existing, list):
        for item in existing:
            if isinstance(item, dict) and item.get("round_id") == round_id:
                return
    _remember_runtime(report, {
        "status": "skipped",
        "reason": "cdp_deferred",
        "execution": "not_executed",
        "deferral": "pre_observer_failure",
        "provider": "fxapk-cdp-trace",
        "live_cdp": False,
        "capture_started": False,
        "round_id": round_id,
        "observer_started": False,
    }, "")


def static_web_arguments(
    path: str | None, request: dict[str, Any] | None,
) -> tuple[str | None, dict[str, Any] | None]:
    """Keep bundle and rea-json on the static path. Live CDP waits for capture."""
    if path and request is not None:
        return path, request
    if request is not None:
        parsed, _reason = parse_config(request if isinstance(request, dict) else {"invalid": True})
    elif path:
        try:
            parsed, _reason = parse_config(load_config_path(path))
        except ValueError:
            return path, request
    else:
        return None, None
    if parsed is not None and parsed.mode == "auto" and parsed.authorized_cdp:
        return None, None
    return path, request


def _ready_ack(path: Path) -> bool:
    try:
        if not path.is_file() or path.is_symlink():
            return False
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    return (
        isinstance(payload, dict)
        and payload.get("status") == "ready"
        and payload.get("debugger_enabled") is True
    )


def _jsonable_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    safe = {key: value for key, value in receipt.items() if key != "verified"}
    started = safe.get("capture_started")
    if "capture_started" in safe and not isinstance(started, bool):
        safe.pop("capture_started", None)
    try:
        json.dumps(safe, ensure_ascii=False)
    except (TypeError, ValueError):
        return {"status": "failed", "reason": "parse_failed", "live_cdp": bool(safe.get("live_cdp"))}
    return safe


def _owned_capture_started(material_dir: str) -> bool:
    """True only when this directory has our marker and a provider ready ack."""
    root = Path(material_dir)
    marker = root / "fxapk-rea-bundle.json"
    ready = root / "ready.json"
    try:
        if (
            not marker.is_file() or marker.is_symlink()
            or not ready.is_file() or ready.is_symlink()
        ):
            return False
        marker_payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    return (
        isinstance(marker_payload, dict)
        and marker_payload.get("schema_version") == "fxapk-rea-bundle-marker/1"
        and marker_payload.get("kind") == "unverified_external_observation_bundle"
        and _ready_ack(ready)
    )


def _started_from_receipt(collected: dict[str, Any], material_dir: str) -> bool:
    """Prefer an explicit boolean. Do not upgrade a false start into live capture."""
    flag = collected.get("capture_started")
    if isinstance(flag, bool):
        return flag
    live = collected.get("live_cdp")
    if isinstance(live, bool):
        return live
    return _owned_capture_started(material_dir)


def _dispatch_observation_ms(requested: int, deadline: float) -> tuple[int, str]:
    """Fit configured observation into the capture window. Never extend that deadline."""
    remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
    if remaining_ms <= _WINDOW_RESERVE_MS:
        dispatched = min(requested, remaining_ms)
        if requested > remaining_ms:
            return dispatched, (
                "configured observation exceeds the remaining capture window; "
                "capped to that window and the capture deadline is unchanged"
            )
        return dispatched, ""
    cap = remaining_ms - _WINDOW_RESERVE_MS
    if requested > cap:
        return cap, (
            "configured observation shortened to the remaining capture window "
            "minus bootstrap and subprocess cleanup reserve; capture deadline unchanged"
        )
    return requested, ""


def _round_label(material_dir: str, rounds: list[dict[str, Any]]) -> str:
    if len(rounds) > 1:
        return "three_rounds"
    match = _ROUND_IN_PATH.search(material_dir.replace("\\", "/"))
    if match:
        return f"round-{match.group(1)}"
    return "single"


def _demote_external(evidence: Evidence) -> None:
    if evidence.source == SOURCE and evidence.scope is EvidenceScope.CASE_EVIDENCE:
        evidence.scope = EvidenceScope.BATCH_REFERENCE


def _publish_canonical(meta: dict[str, Any], rounds: list[dict[str, Any]], material_dir: str) -> None:
    from apkscan.core.web_supplement_preservation import publish_runtime_projection

    publish_runtime_projection(meta, rounds, round_id=_round_label(material_dir, rounds))


def _artifact_hashes(copies: dict[str, bytes]) -> dict[str, str]:
    return {
        name: hashlib.sha256(blob).hexdigest()
        for name, blob in sorted(copies.items())
        if isinstance(name, str) and isinstance(blob, bytes)
    }


def apply_verified(
    report: Any,
    verified: dict[str, Any],
    *,
    publish_dir: str,
    material_dir: str,
    live_cdp: bool,
) -> dict[str, Any]:
    """Parse an already verified bundle into the main report. Bytes stay out of JSON."""
    from apkscan.core.web_supplement import (  # stable parse/publish/merge API
        SOURCE as _SOURCE,
        _merge_findings,
        _parse_verified,
        _publish,
        clamp_web_only_leads,
        merge_candidates,
    )

    if _SOURCE != SOURCE:
        raise RuntimeError("web supplement provenance changed")
    try:
        parsed = _parse_verified(verified)
        copies_raw = parsed.get("copies")
        copies: dict[str, bytes] = {}
        if isinstance(copies_raw, dict):
            copies = {
                name: blob for name, blob in copies_raw.items()
                if isinstance(name, str) and isinstance(blob, bytes)
            }
        raw_sha = str(parsed.get("raw_sha") or "")
        relative = _publish(publish_dir, raw_sha, copies)
    except Exception:
        logger.exception("[web-supplement] runtime parse or publish failed")
        receipt = {
            "status": "failed", "reason": "parse_failed", "live_cdp": live_cdp,
            "material_path": material_dir,
        }
        _remember_runtime(report, receipt, material_dir)
        return _jsonable_receipt(receipt)
    endpoints = getattr(report, "endpoints", None)
    leads = getattr(report, "leads", None)
    findings = getattr(report, "findings", None)
    meta = getattr(report, "meta", None)
    if not isinstance(endpoints, list) or not isinstance(leads, list) or not isinstance(meta, dict):
        receipt = {
            "status": "failed", "reason": "parse_failed", "live_cdp": live_cdp,
            "material_path": material_dir,
        }
        _remember_runtime(report, receipt, material_dir)
        return _jsonable_receipt(receipt)
    seen_list = meta.get("_web_supplement_raws")
    if not isinstance(seen_list, list):
        seen_list = []
        meta["_web_supplement_raws"] = seen_list
    prior_values = {endpoint.value for endpoint in endpoints}
    prior_lead_ids = {id(lead) for lead in leads}
    try:
        counts = merge_candidates(endpoints, leads, parsed, set(str(item) for item in seen_list))
    except Exception:
        logger.exception("[web-supplement] runtime merge failed")
        receipt = {
            "status": "failed", "reason": "parse_failed", "live_cdp": live_cdp,
            "material_path": material_dir,
        }
        _remember_runtime(report, receipt, material_dir)
        return _jsonable_receipt(receipt)
    duplicate = bool(counts.get("duplicate"))
    if raw_sha and raw_sha not in seen_list and not duplicate:
        seen_list.append(raw_sha)
    if not duplicate:
        fresh = [endpoint for endpoint in endpoints if endpoint.value not in prior_values]
        if fresh:
            from apkscan.core.leads import build_endpoint_leads

            known = {(lead.category, lead.value) for lead in leads}
            for lead in build_endpoint_leads(fresh, online=False):
                key = (lead.category, lead.value)
                if key not in known:
                    leads.append(lead)
                    known.add(key)
        # 只封本轮新对象。build_endpoint_leads 已写过的 base_advice / downgrades 保持原样；
        # CONFIG_KEY 的空 base 在 clamp 把 advice 定为待核之后才封存。
        new_leads = [lead for lead in leads if id(lead) not in prior_lead_ids]
        if new_leads:
            from apkscan.core.leads import _apply_default_advice, apply_repack_quarantine
            from apkscan.core.models import seal_base_advice

            _apply_default_advice(new_leads)
            clamp_web_only_leads(new_leads)
            seal_base_advice(new_leads)
            apply_repack_quarantine(new_leads, meta)
    for endpoint in endpoints:
        for evidence in endpoint.evidences:
            if isinstance(evidence, Evidence):
                _demote_external(evidence)
    for lead in leads:
        for evidence in getattr(lead, "source_refs", []) or []:
            if isinstance(evidence, Evidence):
                _demote_external(evidence)
    added_findings = 0
    if isinstance(findings, list) and not duplicate:
        before = len(findings)
        _merge_findings(findings, [item for item in parsed.get("findings") or [] if isinstance(item, Finding)])
        for item in findings:
            for evidence in getattr(item, "evidences", []) or []:
                if isinstance(evidence, Evidence):
                    _demote_external(evidence)
        known = {getattr(item, "id", "") for item in findings}
        added_findings += len(findings) - before
        if counts.get("endpoints") or counts.get("config_leads") or counts.get("relations"):
            finding_id = f"WEB-SUPPLEMENT-{raw_sha[:12] or 'round'}"
            if finding_id not in known:
                findings.append(Finding(
                    id=finding_id,
                    title="外部网页观察候选",
                    severity=Severity.INFO,
                    category="web",
                    description=(
                        "候选来自 external-web-observation，advice 维持待核，"
                        f"raw sha256={raw_sha}。范围是批量参考，不是本案直接证据。"
                    ),
                    confidence=Confidence.LOW,
                    kind=FINDING_KIND_OBSERVATION,
                    evidences=[Evidence(
                        source=SOURCE,
                        location=f"raw:{raw_sha}|{relative}",
                        snippet="",
                        scope=EvidenceScope.BATCH_REFERENCE,
                    )],
                ))
                added_findings += 1
    receipt = {
        "status": "skipped" if duplicate else "executed",
        "reason": "duplicate_raw" if duplicate else "executed",
        "live_cdp": live_cdp,
        "provider": str(parsed.get("provider") or "fxapk-cdp-trace"),
        "provenance": SOURCE,
        "material_path": material_dir,
        "published_path": relative,
        "raw_sha256": raw_sha,
        "artifact_sha256": _artifact_hashes(copies),
        "parse_counts": {
            "endpoints": int(counts.get("endpoints") or 0),
            "config_leads": int(counts.get("config_leads") or 0),
            "relations": int(counts.get("relations") or 0),
            "scripts": int(counts.get("scripts") or 0),
            "findings": added_findings,
            "duplicate": int(counts.get("duplicate") or 0),
        },
        "relations": list(parsed.get("relation_records") or []),
        "relation_records": list(parsed.get("relation_records") or []),
    }
    coverage = parsed.get("coverage")
    if isinstance(coverage, dict) and coverage:
        receipt["coverage"] = coverage
    _remember_runtime(report, receipt, material_dir)
    return _jsonable_receipt(receipt)


def _remember_runtime(report: Any, receipt: dict[str, Any], material_dir: str) -> None:
    meta = getattr(report, "meta", None)
    if not isinstance(meta, dict):
        return
    rounds = meta.get("web_supplement_runtime")
    if not isinstance(rounds, list):
        rounds = []
        meta["web_supplement_runtime"] = rounds
    rounds.append(receipt)
    _publish_canonical(meta, rounds, material_dir)
    plan = meta.get("web_observation_plan")
    if isinstance(plan, dict):
        from apkscan.core.web_supplement import _project_agent_handoff

        _project_agent_handoff(plan, meta)


class CaptureWindowObserver:
    """Poll provider ready.json, then keep the worker until the shared deadline."""

    def __init__(
        self,
        request: dict[str, Any],
        *,
        report: Any = None,
        publish_dir: str,
    ) -> None:
        self._request = request
        self._report = report
        self._publish_dir = publish_dir
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._settled = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._deadline = 0.0
        self._budget: dict[str, Any] = {}
        self._result: dict[str, Any] = {"status": "failed", "reason": "pending", "live_cdp": False}
        self.round_dir = str(request.get("out_dir") or publish_dir)

    def start(self, deadline: float | None) -> None:
        self._deadline = deadline if isinstance(deadline, (int, float)) else time.monotonic()
        self._thread = threading.Thread(target=self._work, name="fxapk-web-observation", daemon=False)
        self._thread.start()

    def wait_ready(self, deadline: float | None) -> str:
        deadline_at = time.monotonic()
        if isinstance(deadline, (int, float)):
            deadline_at = float(deadline)
        while True:
            if self._ready.is_set():
                return "ready"
            if self._settled.is_set():
                return "failed"
            remaining = deadline_at - time.monotonic()
            if remaining <= 0:
                return "timeout"
            self._wake.wait(remaining)

    def finish(self) -> dict[str, Any]:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            grace = _JOIN_GRACE_SEC
            if self._deadline:
                grace = max(grace, self._deadline - time.monotonic() + _JOIN_GRACE_SEC)
            thread.join(timeout=grace)
        if thread is not None and thread.is_alive():
            self._result = {
                "status": "failed", "reason": "worker_not_stopped", "live_cdp": False,
            }
        self._result = _jsonable_receipt(self._result)
        self._result.setdefault("live_cdp", False)
        return self._result

    def _mark_ready(self) -> None:
        self._ready.set()
        self._wake.set()

    def _work(self) -> None:
        try:
            self._result = self._with_budget(self._observe())
        except Exception:
            logger.exception("[web-supplement] observation worker failed")
            self._result = self._with_budget({"status": "failed", "reason": "parse_failed", "live_cdp": False})
            self._sync_budget_receipt(self._result)
        else:
            self._sync_budget_receipt(self._result)
        finally:
            self._settled.set()
            self._wake.set()

    def _sync_budget_receipt(self, enriched: dict[str, Any]) -> None:
        meta = getattr(self._report, "meta", None)
        if not isinstance(meta, dict):
            return
        rounds = meta.get("web_supplement_runtime")
        if not isinstance(rounds, list) or not rounds or not isinstance(rounds[-1], dict):
            return
        for key in ("observation_ms_requested", "observation_ms", "observation_limit"):
            if key in enriched:
                rounds[-1][key] = enriched[key]

    def _with_budget(self, receipt: dict[str, Any]) -> dict[str, Any]:
        if self._budget:
            receipt = dict(receipt)
            receipt.update(self._budget)
        return receipt

    def _observe(self) -> dict[str, Any]:
        plugin, reason = _load_plugin()
        if plugin is None:
            return {"status": "unavailable", "reason": reason or "plugin_unavailable", "live_cdp": False}
        requested = self._request.get("observation_ms")
        if isinstance(requested, bool) or not isinstance(requested, int):
            requested = 0
        dispatched, limit = _dispatch_observation_ms(requested, self._deadline)
        self._budget = {
            "observation_ms_requested": requested,
            "observation_ms": dispatched,
        }
        if limit:
            self._budget["observation_limit"] = limit
        if requested > 0 and dispatched <= 0:
            return {
                "status": "failed", "reason": "timeout", "live_cdp": False,
            }
        payload = dict(self._request)
        payload["observation_ms"] = dispatched
        try:
            started = plugin.run_supplement({**payload, "phase": "start"})
        except Exception:
            logger.exception("[web-supplement] plugin start failed")
            return {"status": "failed", "reason": "parse_failed", "live_cdp": False}
        if not isinstance(started, dict):
            return {"status": "failed", "reason": "parse_failed", "live_cdp": False}
        if started.get("status") != "started":
            started.setdefault("live_cdp", False)
            return _jsonable_receipt(started)
        pid = started.get("pid")
        ready_path = Path(str(started.get("ready_path") or ""))
        material_dir = str(started.get("out_dir") or "")
        while not self._stop.is_set() and time.monotonic() < self._deadline:
            if _ready_ack(ready_path):
                self._mark_ready()
                break
            if not self._running(plugin, pid):
                break
            time.sleep(_POLL_SEC)
        while self._ready.is_set() and not self._stop.is_set() and time.monotonic() < self._deadline:
            if not self._running(plugin, pid):
                break
            time.sleep(_POLL_SEC)
        return self._stop_and_collect(plugin, pid, material_dir)

    def _running(self, plugin: Any, pid: object) -> bool:
        try:
            polled = plugin.run_supplement({"phase": "poll", "pid": pid})
        except Exception:
            logger.exception("[web-supplement] plugin poll failed")
            return False
        return isinstance(polled, dict) and polled.get("running") is True

    def _stop_and_collect(self, plugin: Any, pid: object, material_dir: str) -> dict[str, Any]:
        started = _owned_capture_started(material_dir)
        try:
            stopped = plugin.run_supplement({"phase": "stop", "pid": pid})
        except Exception:
            logger.exception("[web-supplement] plugin stop failed")
            return {
                "status": "failed", "reason": "worker_not_stopped",
                "live_cdp": started, "capture_started": started,
            }
        if not isinstance(stopped, dict) or stopped.get("stopped") is not True:
            return {
                "status": "failed", "reason": "worker_not_stopped",
                "live_cdp": started, "capture_started": started,
            }
        try:
            collected = plugin.run_supplement({"phase": "collect", "out_dir": material_dir})
        except Exception:
            logger.exception("[web-supplement] plugin collect failed")
            return {
                "status": "failed", "reason": "parse_failed", "live_cdp": started,
                "capture_started": started, "material_path": material_dir,
            }
        if not isinstance(collected, dict):
            return {
                "status": "failed", "reason": "parse_failed", "live_cdp": started,
                "capture_started": started, "material_path": material_dir,
            }
        verified = collected.pop("verified", None)
        observed = _started_from_receipt(collected, material_dir)
        if collected.get("status") == "ok" and isinstance(verified, dict):
            try:
                receipt = apply_verified(
                    self._report, verified, publish_dir=self._publish_dir,
                    material_dir=material_dir, live_cdp=observed,
                )
            except Exception:
                logger.exception("[web-supplement] dynamic backfill failed")
                return {
                    "status": "failed", "reason": "parse_failed", "live_cdp": observed,
                    "capture_started": observed, "material_path": material_dir,
                }
            receipt["capture_started"] = observed
            receipt["live_cdp"] = observed
            return _jsonable_receipt(receipt)
        collected["live_cdp"] = observed
        collected["capture_started"] = observed
        collected.setdefault("material_path", material_dir)
        return _jsonable_receipt(collected)


def make_capture_observer(
    config: AnalysisConfig | None,
    *,
    report: Any = None,
    publish_dir: str | None = None,
) -> Any | None:
    if config is None:
        return None
    from apkscan.core.web_supplement import resolve_request

    request, rejected = resolve_request(config)
    if rejected or request is None or request.mode != "auto":
        return None
    if not request.authorized_cdp:
        if request.source != "cdp":
            return None
        if request.authorized is not True:
            reason = "cdp_not_authorized"
        else:
            reason = "cdp_target_missing"
        return SkippingObserver(reason)
    if request.provider not in {"", "trace", "fxapk-cdp-trace"}:
        return SkippingObserver("provider_mismatch")
    out_dir = str(config.out_dir or "out")
    return CaptureWindowObserver({
        "schema_version": CONFIG_SCHEMA,
        "source": "cdp",
        "endpoint": request.endpoint,
        "target": request.target,
        "exact_origins": list(request.exact_origins),
        "related_targets": request.related_targets is True,
        "provider": request.provider or "trace",
        "observation_ms": request.observation_ms,
        "authorized": True,
        "out_dir": out_dir,
    }, report=report, publish_dir=publish_dir or out_dir)
