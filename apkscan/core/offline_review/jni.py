"""Review framed JNI observation streams without equating no hits to no JNI."""
from __future__ import annotations

from .common import lines, result


def review(data: bytes, options: dict) -> dict:
    run_id = options.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("jni_run_id_required")
    reasons, registrations, calls, hooks = set(), [], [], set()
    finished = False
    expected = 1
    for _, event, error in lines(data):
        if error or event is None:
            reasons.add(error or "invalid_event")
            continue
        if finished:
            reasons.add("events_after_end")
        if event.get("run_id") != run_id or event.get("seq") != expected:
            reasons.add("jni_scope_or_sequence_mismatch")
        expected = event.get("seq", 0) + 1 if type(event.get("seq")) is int else expected + 1
        kind = event.get("type")
        if kind == "hook_installed":
            hooks.add(str(event.get("hook")))
        elif kind == "jni_registration":
            if not all(isinstance(event.get(k), str) and event[k] for k in ("name", "signature", "address", "module")):
                reasons.add("jni_registration_invalid")
            else:
                registrations.append(event)
        elif kind == "jni_call":
            calls.append(event)
        elif kind == "end":
            finished = True
            if event.get("truncated"):
                reasons.add("jni_event_budget")
        elif kind in {"error", "lost", "limit"}:
            reasons.add("jni_" + kind)
        elif kind not in {"start", "dex", "scan_complete", "module"}:
            reasons.add("jni_unknown_event")
    if not finished:
        reasons.add("jni_capture_incomplete")
    if not hooks:
        reasons.add("jni_hooks_not_installed")
    if not registrations and not calls:
        reasons.add("jni_no_hits_in_window")
    return result("partial" if reasons else "ok", sorted(reasons),
                  run_id=run_id, hooks=sorted(hooks), registrations=registrations,
                  calls=calls, capture_complete=finished, runtime_observed=bool(calls or registrations),
                  scope="supplied_observation_window", source_binding_verified=False,
                  historical_registrations="not_observed")
