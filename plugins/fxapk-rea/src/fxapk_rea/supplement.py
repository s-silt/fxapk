"""Plugin-side web supplement. Core reaches this only through the entry-point object."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from apkscan.core.atomic import atomic_create_bytes

from .attachment import AttachError, _MAX_TRACE, _verify_bundle
from .evidence import EvidenceError, import_observation
from .trace import MAX_RAW_BYTES

_LIVE: dict[int, subprocess.Popen[bytes]] = {}
_OWNED_REQUESTS: dict[int, Path] = {}
_MAX_EXACT_ORIGINS = 9
_CONFIG_TRACE_ERRORS = frozenset({
    "invalid_observation_budget",
    "related_origin_rejected",
    "related_origin_limit",
    "related_origin_requires_related_targets",
    "pause_related_start_requires_related_targets",
    "navigate_origin_rejected",
    "invalid_click_selector",
})
_TRACE_STABLE = frozenset({
    "trace_oversize", "trace_deadline", "trace_limit", "source_unavailable",
    "trace_cleanup_failed", "artifact_exists_refuse_overwrite",
    "receipt_exists_refuse_overwrite", "output_exists_refuse_overwrite",
    "bundle_marker_unwritable", "cdp_setup_failed", "target_not_found",
    "target_origin_rejected", "top_frame_origin_rejected", "no_initial_context",
    "cdp_http_failed", "websocket_url_rejected", "redirect_refused", "target_type_rejected",
    "failed_bundle",
})
_ACTION_FIELDS = ("navigate", "click_selector", "pause_related_start")
_MAX_FAILURE_BYTES = 65536
# Trace raw stays at the acquisition/attachment cap. Do not raise either constant here.
_MAX_TRACE_ORIGINAL_BYTES = min(MAX_RAW_BYTES, _MAX_TRACE)


def _failed(reason: str, *, started: bool = False) -> dict[str, Any]:
    return {
        "status": "failed",
        "reason": reason,
        "live_cdp": started,
        "capture_started": started,
    }


def _read_object(path: Path, *, limit: int = _MAX_FAILURE_BYTES) -> dict[str, Any] | None:
    """Read one JSON object. ``limit`` is a byte cap, never an unbounded read."""
    if type(limit) is not int or isinstance(limit, bool) or limit < 1 or limit > _MAX_TRACE_ORIGINAL_BYTES:
        return None
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            return None
        # stat can go stale if the file grows. Read at most limit+1 and reject
        # the extra byte before any decode.
        with path.open("rb") as handle:
            raw = handle.read(limit + 1)
        if len(raw) > limit:
            return None
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _stable(value: object) -> str:
    return value if isinstance(value, str) and value in _TRACE_STABLE else ""


def _owned_marker(out: Path) -> bool:
    payload = _read_object(out / "fxapk-rea-bundle.json")
    return (
        isinstance(payload, dict)
        and payload.get("schema_version") == "fxapk-rea-bundle-marker/1"
        and payload.get("kind") == "unverified_external_observation_bundle"
    )


def _ready_started(out: Path) -> bool:
    payload = _read_object(out / "ready.json")
    return (
        isinstance(payload, dict)
        and payload.get("status") == "ready"
        and payload.get("debugger_enabled") is True
    )


def _capture_started(out: Path) -> bool:
    """Started means our marker plus the provider ready ack. A marker alone is only a claim."""
    return _owned_marker(out) and _ready_started(out)


def _boundary_reason(out: Path, fallback: str = "") -> str:
    """failure.json, then stopped_reason. Arbitrary text never becomes the reason."""
    failure = _read_object(out / "failure.json")
    filed = _stable(failure.get("reason") if isinstance(failure, dict) else None)
    if filed:
        return filed
    original = _read_object(
        out / "cdp-trace-original.json", limit=_MAX_TRACE_ORIGINAL_BYTES,
    )
    capture = original.get("capture") if isinstance(original, dict) else None
    stopped = _stable(capture.get("stopped_reason") if isinstance(capture, dict) else None)
    if stopped:
        return stopped
    return _stable(fallback)


def _related_flag(request: dict[str, Any]) -> tuple[bool | None, dict[str, Any] | None]:
    for key in _ACTION_FIELDS:
        if key in request:
            return None, _failed("config_rejected")
    if "related_targets" not in request:
        return None, None
    flag = request.get("related_targets")
    if not isinstance(flag, bool):
        return None, _failed("config_rejected")
    return flag, None


def _live_dir(request: dict[str, Any]) -> Path:
    return Path(str(request.get("out_dir") or "out")) / "web-supplement-cdp"


def run_supplement(request: dict[str, Any]) -> dict[str, Any]:
    phase = request.get("phase")
    if phase == "start":
        return _start(request)
    if phase == "poll":
        return _poll(request)
    if phase == "stop":
        return _stop(request)
    if phase == "collect":
        return _collect(str(request.get("out_dir") or ""))
    source = request.get("source")
    if source == "cdp":
        return _run_cdp(request)
    if source == "bundle":
        return _from_bundle(Path(str(request.get("path") or "")))
    if source == "rea-json":
        return _from_rea_json(request)
    return _failed("config_rejected")


def _from_bundle(path: Path) -> dict[str, Any]:
    try:
        verified = _verify_bundle(path)
    except AttachError as exc:
        return _failed(str(exc))
    except OSError:
        return _failed("bundle_rejected")
    return {
        "status": "ok", "reason": "ok", "verified": verified,
        "live_cdp": False, "capture_started": False,
    }


def _from_rea_json(request: dict[str, Any]) -> dict[str, Any]:
    source = Path(str(request.get("path") or ""))
    out = Path(str(request.get("out_dir") or "out")) / "web-supplement-import"
    if out.exists():
        return _failed("publish_conflict")
    try:
        import_observation(source, out)
        verified = _verify_bundle(out)
    except (EvidenceError, AttachError, OSError):
        return _failed("bundle_rejected")
    return {
        "status": "ok", "reason": "ok", "verified": verified,
        "live_cdp": False, "capture_started": False,
    }


def _cdp_gate(request: dict[str, Any]) -> dict[str, Any] | None:
    if request.get("authorized") is not True:
        return {"status": "skipped", "reason": "cdp_not_authorized", "live_cdp": False}
    endpoint = request.get("endpoint")
    target = request.get("target")
    if not isinstance(endpoint, str) or not isinstance(target, str):
        return {"status": "skipped", "reason": "cdp_target_missing", "live_cdp": False}
    _origins, rejected = _exact_origins(request)
    if rejected is not None:
        return rejected
    provider = request.get("provider") or "trace"
    if provider not in {"trace", "fxapk-cdp-trace", ""}:
        return {"status": "unavailable", "reason": "target_unavailable", "live_cdp": False}
    observation_ms = request.get("observation_ms")
    if isinstance(observation_ms, bool) or not isinstance(observation_ms, int):
        return _failed("config_rejected")
    try:
        __import__("websockets")
    except ImportError:
        return {"status": "unavailable", "reason": "trace_dependency_missing", "live_cdp": False}
    return None


def _exact_origins(request: dict[str, Any]) -> tuple[list[str] | None, dict[str, Any] | None]:
    origins = request.get("exact_origins")
    if not isinstance(origins, list) or not origins:
        return None, {"status": "skipped", "reason": "cdp_target_missing", "live_cdp": False}
    clean: list[str] = []
    for item in origins:
        if not isinstance(item, str) or not item:
            return None, {"status": "skipped", "reason": "cdp_target_missing", "live_cdp": False}
        clean.append(item)
    if len(clean) > _MAX_EXACT_ORIGINS:
        return None, _failed("config_rejected")
    return clean, None


def _invoke_trace(
    endpoint: str,
    target: str,
    origins: list[str],
    observation_ms: int,
    out: Path,
    *,
    related_targets: bool | None = None,
) -> None:
    """Pass every authorized origin. Extra origins stay on related targets.

    ``related_targets=True`` also enables same-origin workers when only one origin
    is authorized. Explicit false does not turn off the legacy multi-origin path.
    Navigation, clicks and pause stay off.
    """
    from .trace import run_trace

    related = origins[1:]
    enabled = bool(related) or related_targets is True
    run_trace(
        endpoint,
        target,
        origins[0],
        observation_ms,
        out,
        [],
        related_targets=enabled,
        related_origin=list(related) if related else None,
        navigate=None,
        click_selector=None,
        pause_related_start=False,
    )


def _acquisition_failure(out: Path, code: str) -> dict[str, Any]:
    started = _capture_started(out)
    if code == "trace_dependency_missing":
        return {
            "status": "unavailable", "reason": code,
            "live_cdp": False, "capture_started": False,
        }
    if code in _CONFIG_TRACE_ERRORS:
        return _failed("config_rejected")
    reason = _boundary_reason(out, code)
    if not reason:
        reason = "failed_bundle" if _owned_marker(out) or (out / "failure.json").is_file() else "target_unavailable"
    return _failed(reason, started=started)


def _run_cdp(request: dict[str, Any]) -> dict[str, Any]:
    """Synchronous live capture for analyze-web. Dynamic windows use phase=start."""
    gated = _cdp_gate(request)
    if gated is not None:
        return gated
    origins, rejected = _exact_origins(request)
    if rejected is not None or origins is None:
        return rejected or _failed("config_rejected")
    related, rejected_flag = _related_flag(request)
    if rejected_flag is not None:
        return rejected_flag
    out = _live_dir(request)
    if out.is_symlink() or out.exists():
        return _failed("publish_conflict")
    observation_ms = request.get("observation_ms")
    if isinstance(observation_ms, bool) or not isinstance(observation_ms, int):
        return _failed("config_rejected")
    try:
        if related is None:
            _invoke_trace(
                str(request.get("endpoint")), str(request.get("target")), origins,
                observation_ms, out,
            )
        else:
            _invoke_trace(
                str(request.get("endpoint")), str(request.get("target")), origins,
                observation_ms, out, related_targets=related,
            )
        verified = _verify_bundle(out)
    except EvidenceError as exc:
        return _acquisition_failure(out, str(exc))
    except AttachError as exc:
        return _failed(_attach_reason(out, str(exc)), started=_capture_started(out))
    except OSError:
        return _failed("bundle_rejected", started=_capture_started(out))
    except Exception:
        return _acquisition_failure(out, "")
    return {
        "status": "ok", "reason": "ok", "verified": verified,
        "live_cdp": True, "capture_started": True,
    }


def _start(request: dict[str, Any]) -> dict[str, Any]:
    gated = _cdp_gate(request)
    if gated is not None:
        return gated
    out = _live_dir(request)
    if out.is_symlink() or out.exists():
        return _failed("publish_conflict")
    origins, rejected = _exact_origins(request)
    if rejected is not None or origins is None:
        return rejected or _failed("config_rejected")
    related, rejected_flag = _related_flag(request)
    if rejected_flag is not None:
        return rejected_flag
    payload = {
        "source": "cdp",
        "authorized": True,
        "endpoint": request.get("endpoint"),
        "target": request.get("target"),
        "exact_origins": origins,
        "provider": request.get("provider") or "trace",
        "observation_ms": request.get("observation_ms"),
        "out_dir": str(out),
    }
    if isinstance(related, bool):
        payload["related_targets"] = related
    request_path = out.parent / f"{out.name}-request.json"
    try:
        request_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        return _failed("parse_failed")
    if request_path.is_symlink() or request_path.exists():
        return _failed("publish_conflict")
    try:
        created = atomic_create_bytes(request_path, json.dumps(payload).encode("utf-8"))
    except OSError:
        return _failed("parse_failed")
    if not created:
        return _failed("publish_conflict")
    src = str(Path(__file__).resolve().parents[1])
    env = os.environ.copy()
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "fxapk_rea.supplement_worker", "--request", str(request_path)],
            env=env,
            creationflags=_spawn_flags(),
        )
    except OSError:
        _remove_owned(request_path)
        return {"status": "failed", "reason": "target_unavailable", "live_cdp": False}
    _LIVE[proc.pid] = proc
    _OWNED_REQUESTS[proc.pid] = request_path
    return {
        "status": "started",
        "pid": proc.pid,
        "ready_path": str(out / "ready.json"),
        "out_dir": str(out),
        "live_cdp": False,
    }


def _poll(request: dict[str, Any]) -> dict[str, Any]:
    proc = _LIVE.get(_pid(request))
    if proc is None:
        return {"running": False}
    code = proc.poll()
    return {"running": code is None, "returncode": code}


def _spawn_flags() -> int:
    if sys.platform != "win32":
        return 0
    group = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    hidden = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return group | hidden


def _remove_owned(path: Path | None) -> None:
    if path is None or path.is_symlink():
        return
    try:
        path.unlink()
    except OSError:
        return


def _stop(request: dict[str, Any]) -> dict[str, Any]:
    pid = _pid(request)
    proc = _LIVE.pop(pid, None)
    owned = _OWNED_REQUESTS.pop(pid, None)
    if proc is None:
        return {"stopped": False, "reason": "worker_not_stopped"}
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                _LIVE[pid] = proc
                if owned is not None:
                    _OWNED_REQUESTS[pid] = owned
                return {"stopped": False, "reason": "worker_not_stopped", "returncode": None}
    if proc.poll() is None:
        _LIVE[pid] = proc
        if owned is not None:
            _OWNED_REQUESTS[pid] = owned
        return {"stopped": False, "reason": "worker_not_stopped", "returncode": None}
    _remove_owned(owned)
    return {"stopped": True, "returncode": proc.returncode}


def _pid(request: dict[str, Any]) -> int:
    pid = request.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int):
        return -1
    return pid


def _attach_reason(path: Path, code: str) -> str:
    if code == "failed_bundle":
        return _boundary_reason(path) or "failed_bundle"
    if code in _TRACE_STABLE or code in {
        "bundle_rejected", "invalid_bundle_marker", "source_hash_mismatch",
        "artifact_hash_mismatch", "not_a_directory",
    }:
        return code if code != "not_a_directory" else "bundle_rejected"
    return "bundle_rejected"


def _collect_failure(path: Path) -> str:
    """Explicit failure marker or a stable failed stop. A saved trace is not a failure."""
    marker = path / "failure.json"
    if marker.is_symlink() or marker.is_file():
        return _boundary_reason(path) or "failed_bundle"
    return _boundary_reason(path)


def _collect(out_dir: str) -> dict[str, Any]:
    path = Path(out_dir)
    started = _capture_started(path)
    reason = _collect_failure(path)
    if reason:
        return _failed(reason, started=started)
    if not (path / "fxapk-rea-bundle.json").is_file():
        return _failed("target_unavailable", started=False)
    try:
        verified = _verify_bundle(path)
    except AttachError as exc:
        return _failed(_attach_reason(path, str(exc)), started=started)
    except OSError:
        return _failed("bundle_rejected", started=started)
    return {
        "status": "ok", "reason": "ok", "verified": verified,
        "live_cdp": True, "capture_started": True,
    }
