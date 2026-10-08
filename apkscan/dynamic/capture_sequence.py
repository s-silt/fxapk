"""Three capture rounds after unpack/reanalysis, using bundled observers."""
from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from apkscan.core.integrity import sha256_file
from apkscan.dynamic import capture
from apkscan.dynamic.capture_plan import _as_dict

logger = logging.getLogger(__name__)


def targeted_hooks(report: Any, *, unpacked: bool) -> tuple[str, ...]:
    """Select capability families from unpacked findings, never execute sample code."""
    if not unpacked:
        return ()
    payload = _as_dict(report)
    meta = payload.get("meta")
    meta = meta if isinstance(meta, Mapping) else {}
    selected: set[str] = set()
    if meta.get("crypto_recipe") or meta.get("runtime_crypto_recipe"):
        selected.add("crypto")
    if meta.get("webview_signals") or meta.get("webview_signal_count"):
        selected.add("jsbridge")
    repack = meta.get("repack_identity")
    stack = repack.get("stack") if isinstance(repack, Mapping) else None
    families = stack.get("families") if isinstance(stack, Mapping) else None
    if isinstance(families, Mapping) and families.get("sqlcipher"):
        selected.add("sqlcipher")
    if meta.get("config_probe_plan"):
        selected.add("okhttp")
    # Use finite, declared categories. Arbitrary paths/classes are not JS templates.
    for lead in payload.get("leads", []) if isinstance(payload.get("leads"), list) else []:
        if not isinstance(lead, Mapping):
            continue
        category = lead.get("category")
        if category in ("CRYPTO_RECIPE", "CRYPTO"):
            selected.add("crypto")
        elif category in ("SQLCIPHER", "DATABASE"):
            selected.add("sqlcipher")
        elif category in ("WEBVIEW", "JSBRIDGE"):
            selected.add("jsbridge")
        elif category == "REMOTE_CONFIG":
            selected.add("okhttp")
    return tuple(name for name in ("crypto", "okhttp", "jsbridge", "sqlcipher") if name in selected)


def run_rounds(package: str, *, report: Any, unpacked: bool, out_dir: str,
               duration: int = 60, serial: str | None = None, sample_sha256: str | None = None,
               runner: Callable[..., Any] | None = None,
               before_round: Callable[[str], None] | None = None,
               during_round: Callable[..., object] | None = None) -> list[dict[str, Any]]:
    """Keep separate outputs and failures; completion is not evidence completeness."""
    if isinstance(duration, bool) or not isinstance(duration, int) or duration < 1:
        raise ValueError("invalid_round_duration")
    seconds = min(duration, 1200)  # Three rounds stay within one hour.
    runner = capture.run if runner is None else runner
    targeted = targeted_hooks(report, unpacked=unpacked)
    plans = (
        ("pcap", "floor-only", None),
        ("probe", "no-proxy", ("crypto", "jsbridge", "sensitive_api", "okhttp",
                                  "sqlcipher", "clipboard", "accessibility")),
        ("targeted", "both", targeted),
    )
    records = []
    for number, (name, mode, hooks) in enumerate(plans, 1):
        out = Path(out_dir) / f"round{number}-{name}"
        record: dict[str, Any] = {"round": number, "kind": name, "mode": mode,
            "duration_seconds": seconds, "output_dir": str(out), "requested_hooks": list(hooks or ()),
            "status": "skipped", "reason": "", "observation_method": "packet_capture" if number == 1 else "instrumented",
            "identity_verified": False, "sample_sha256": sample_sha256}
        if name == "targeted" and not hooks:
            record["reason"] = "unpacked_evidence_or_supported_targeted_hook_missing"
        elif out.exists():
            record["reason"] = "round_output_exists_refuse_overwrite"
        else:
            try:
                if before_round is not None:
                    before_round(f"第 {number}/3 轮 {name}，约 {seconds} 秒；请在授权样本上触发待观察业务")
                kwargs: dict[str, Any] = {}
                if hooks is not None:
                    kwargs["selected_hooks"] = hooks
                if during_round is not None:
                    def interaction_callback(
                        *, deadline_monotonic: float | None = None,
                        n=number, k=name, m=mode, directory=out,
                    ) -> object:
                        if deadline_monotonic is None:
                            return during_round(n, k, m, directory)
                        return capture._invoke_interaction(
                            during_round, n, k, m, directory,
                            deadline_monotonic=deadline_monotonic,
                        )

                    kwargs["interaction"] = interaction_callback
                result = runner(
                    package, out=str(out), duration=seconds, serial=serial, report=report,
                    mode=mode, pass_tag=f"round{number}", **kwargs,
                )
                if not isinstance(result, Mapping) or result.get("status") not in ("done", "degraded", "skipped", "error"):
                    raise ValueError("invalid_capture_result")
                record.update(status=result["status"], reason=str(result.get("reason") or ""), result=dict(result))
                if isinstance(result.get("ui_observations"), list):
                    record["ui_observations"] = [item for item in result["ui_observations"] if isinstance(item, Mapping)]
                if result["status"] in ("done", "degraded"):
                    artifact = out / "runtime_report.json"
                    if artifact.is_file() and not artifact.is_symlink():
                        record["runtime_report_path"] = str(artifact)
                        record["runtime_report_sha256"] = sha256_file(artifact)
                    else:
                        record.update(status="degraded", reason="runtime_report_missing_or_unsafe")
            except Exception as exc:  # noqa: BLE001 - failure remains visible; later rounds can complement it
                logger.exception("[capture-sequence] round failed")
                record.update(status="error", reason=f"capture_round_failed:{type(exc).__name__}")
        records.append(record)
    return records


def complement_decryption(report: Any, records: list[dict[str, Any]]) -> dict[str, Any]:
    """Reuse recipe observations only in a hash-bound, same-run original sample.

    Original capture files are never edited. A successful decrypt is a derived
    observation, never a direct-contact proof or operator-identity verdict.
    """
    from apkscan.core.models import Report
    from apkscan.core.json_io import read_json_bounded
    from apkscan.core.integrity import sha256_hex
    from apkscan.dynamic import merge
    summary: dict[str, Any] = {"status": "not_attempted", "source_hashes": [],
                              "decrypted": 0, "failed": 0, "plaintext_endpoints": 0,
                              "gaps": [], "originals_modified": False, "attempted_round_count": 0,
                              "derived_evidence_requires_review": True}
    if not isinstance(report, Report):
        summary["gaps"].append("invalid_report")
        return summary
    identity = report.meta.get("capture_apk_identity")
    original = identity.get("original") if isinstance(identity, Mapping) else None
    sample_hash = original.get("sha256") if isinstance(original, Mapping) else None
    if (not isinstance(identity, Mapping) or identity.get("which") != "original"
        or not isinstance(sample_hash, str) or len(sample_hash) != 64
        or any(c not in "0123456789abcdef" for c in sample_hash)):
        summary["gaps"].append("original_sample_identity_unconfirmed")
        return summary
    if len(records) > 3:
        summary["gaps"].append("round_budget_exceeded")
        return summary
    sources = []
    seen_hashes: set[str] = set()
    for record in records:
        path, expected = record.get("runtime_report_path"), record.get("runtime_report_sha256")
        if record.get("sample_sha256") != sample_hash:
            summary["gaps"].append("round_sample_identity_mismatch")
            continue
        if not isinstance(path, str) or not isinstance(expected, str):
            continue
        try:
            payload, raw = read_json_bounded(Path(path), 128 * 1024 * 1024, 64)
            if not isinstance(payload, dict) or sha256_hex(raw) != expected:
                raise ValueError("stale_runtime_artifact")
            if payload.get("package_name") != report.package_name or payload.get("runtime_variant") != "original-runtime":
                raise ValueError("runtime_scope_mismatch")
            events = payload.get("crypto_events", [])
            if not isinstance(events, list) or len(events) > 4000 or any(not isinstance(e, dict) for e in events):
                raise ValueError("invalid_crypto_event_budget")
            if expected in seen_hashes:
                summary["gaps"].append("duplicate_capture_artifact")
                continue
            seen_hashes.add(expected)
            sources.append((path, expected, events))
        except (OSError, ValueError, TypeError, RecursionError):
            summary["gaps"].append("runtime_scope_or_artifact_validation_failed")
    if len(sources) < 2:
        summary["gaps"].append("insufficient_verified_rounds")
        return summary
    summary["source_hashes"] = [item[1] for item in sources]
    for path, _sha, _events in sources:
        extra = [event for other, _hash, events in sources if other != path for event in events]
        if not extra:
            continue
        summary["status"] = "attempted"
        summary["attempted_round_count"] += 1
        from apkscan.dynamic.capture_provenance import capture_scope
        recipe_hashes = sorted(h for other, h, events in sources if other != path and events)
        namespace = "capture:" + _sha + ";recipes:" + ",".join(recipe_hashes)
        with capture_scope(namespace):
            stats = merge.decrypt_runtime_messages(report, path, recipe_events=extra)
        for key in ("decrypted", "failed", "plaintext_endpoints"):
            summary[key] += stats.get(key, 0)
    if not summary["attempted_round_count"]:
        summary["gaps"].append("cross_round_recipe_observations_missing")
    return summary
