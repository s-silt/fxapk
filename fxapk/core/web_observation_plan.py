"""Pure selector for automatic web observation. It never opens a browser or device."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA = "fxapk.web_observation_plan/1"
CONFIG_SCHEMA = "fxapk.web_supplement.v1"
MAX_CONFIG_BYTES = 65536
MAX_OBSERVATION_MS = 60_000
MAX_ORIGINS = 8
MODES = frozenset({"auto", "off"})
SOURCES = frozenset({"bundle", "rea-json", "cdp"})
PROVIDERS = frozenset({"", "rea", "inspect", "trace", "fxapk-cdp-trace"})
PLATFORMS = frozenset({"android", "web"})
FIELDS = frozenset({
    "schema_version", "mode", "source", "path", "endpoint", "target",
    "exact_origins", "provider", "observation_ms", "authorized", "related_targets",
})
REASONS = frozenset({
    "no_config", "mode_off", "no_web_signal", "material_missing", "config_rejected",
    "unknown_field", "invalid_type", "duplicate_json_key", "link_escape", "oversize",
    "observation_ms_limit", "cdp_not_authorized", "cdp_target_missing", "plugin_unavailable",
    "trace_dependency_missing", "target_unavailable", "bundle_rejected", "duplicate_raw",
    "parse_failed", "publish_conflict", "executed", "skipped", "pending", "unavailable",
    "ok", "failed", "not_live_cdp", "ready", "timeout", "source_hash_mismatch",
    "artifact_hash_mismatch", "invalid_bundle_marker", "failed_bundle",
    "provider_mismatch",
    "trace_oversize", "trace_deadline", "trace_limit", "source_unavailable",
    "trace_cleanup_failed", "artifact_exists_refuse_overwrite",
    "receipt_exists_refuse_overwrite", "output_exists_refuse_overwrite",
    "bundle_marker_unwritable", "cdp_setup_failed", "target_not_found",
    "target_origin_rejected", "top_frame_origin_rejected", "no_initial_context",
    "cdp_http_failed", "websocket_url_rejected", "redirect_refused", "target_type_rejected",
    "worker_not_stopped", "cdp_deferred",
})
HANDOFF_SCHEMA = "fxapk.web_agent_handoff/1"
PLAN_STATUSES = frozenset({
    "pending", "skipped", "selected", "executed", "failed", "not_applicable", "unavailable",
})
RUNTIME_PROVIDERS = frozenset({"trace", "fxapk-cdp-trace"})
SUCCESS_STATUSES = frozenset({"executed", "ok"})
_FAILURE_REASONS = frozenset({
    "plugin_unavailable", "trace_dependency_missing", "target_unavailable", "bundle_rejected",
    "parse_failed", "publish_conflict", "failed", "unavailable", "timeout",
    "source_hash_mismatch", "artifact_hash_mismatch", "invalid_bundle_marker", "failed_bundle",
    "config_rejected", "invalid_type", "unknown_field", "duplicate_json_key", "link_escape",
    "oversize", "observation_ms_limit", "not_live_cdp", "provider_mismatch",
    "trace_oversize", "trace_deadline", "trace_limit", "source_unavailable",
    "trace_cleanup_failed", "artifact_exists_refuse_overwrite",
    "receipt_exists_refuse_overwrite", "output_exists_refuse_overwrite",
    "bundle_marker_unwritable", "cdp_setup_failed", "target_not_found",
    "target_origin_rejected", "top_frame_origin_rejected", "no_initial_context",
    "cdp_http_failed", "websocket_url_rejected", "redirect_refused", "target_type_rejected",
})
_ARGV_SELFCHECK = ("fxapk", "selfcheck", "--offline", "--no-probe")
_ARGV_TRACE_CAPABILITIES = ("fxapk", "rea", "capabilities", "--provider", "trace")
_ARGV_ANALYZE_SUPPLEMENT = (
    "fxapk", "analyze", "<sample>", "--offline", "--out", "<new-out-dir>",
    "--web-supplement", "<config>",
)
_ARGV_ANALYZE_WEB_SUPPLEMENT = (
    "fxapk", "analyze-web", "<evidence-dir>", "--offline", "--out", "<new-out-dir>",
    "--web-supplement", "<config>",
)
_ARGV_SUPPLEMENT_WEB = (
    "fxapk", "supplement-web", "<report.json>", "--web-supplement", "<config>",
    "--out", "<new-out-dir>",
)
_ARGV_ATTACH = (
    "fxapk", "rea", "attach", "--bundle", "<bundle-dir>", "--report", "<report>", "--out", "<out-dir>",
)
_STOP = (
    "handoff_is_not_authorization",
    "handoff_does_not_set_execute_or_closure",
    "same_url_frame_or_click_not_verified",
    "do_not_repeat_blindly",
    "do_not_start_auto_or_capture_only_to_import",
    "attach_is_observation_only",
    "plugin_adds_no_case_close",
    "no_real_android_webview_acceptance",
)


@dataclass
class WebSupplementRequest:
    mode: str = "off"
    source: str = ""
    path: str = ""
    endpoint: str = ""
    target: str = ""
    exact_origins: tuple[str, ...] = ()
    provider: str = ""
    observation_ms: int = 0
    authorized: bool = False
    related_targets: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def explicit_material(self) -> bool:
        return self.source in {"bundle", "rea-json"} and bool(self.path)

    @property
    def authorized_cdp(self) -> bool:
        return (
            self.source == "cdp"
            and self.authorized is True
            and bool(self.endpoint)
            and bool(self.target)
            and bool(self.exact_origins)
        )


def fixed_reason(reason: str) -> str:
    return reason if isinstance(reason, str) and reason in REASONS else "config_rejected"


_COVERAGE_STATUS = frozenset({"partial", "complete", "unknown"})
_COVERAGE_GAPS = frozenset({
    "loader_unknown",
    "oopif_worker_unsupported",
    "related_target_uncovered",
    "click_attribution_unavailable",
    "target_app_attribution_unavailable",
    "provenance_unauthenticated",
    "closure_unavailable",
    "attach_before_history_unobserved",
    "loader_conflict",
    "unresolved_parent_id",
    "async_parent_truncated",
    "missing_context",
    "frame_mismatch",
    "wrong_session",
    "source_tamper",
    "coordinate_unproven",
    "source_ambiguous",
    "cross_frame_async_unverified",
    "hop_identity_conflict",
    "worker_frame_mismatch",
    "related_target_conflict",
    "related_target_unknown",
    "trace_cleanup_failed",
    "worker_top_frame_rejected",
    "source_unavailable",
})


def clean_coverage(value: object) -> dict[str, Any]:
    """Keep partial/complete and whitelist gap codes. Free text is dropped."""
    if not isinstance(value, dict):
        return {}
    status = value.get("status")
    if status not in _COVERAGE_STATUS:
        status = "unknown"
    gaps: list[str] = []
    raw = value.get("gaps")
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, str) and item in _COVERAGE_GAPS and item not in gaps:
                gaps.append(item)
    if status == "unknown" and not gaps:
        return {}
    return {"status": status, "gaps": gaps}


def empty_plan(reason: str = "no_config") -> dict[str, Any]:
    code = fixed_reason(reason)
    return {
        "schema_version": SCHEMA,
        "mode": "off",
        "status": "pending" if code == "no_config" else "skipped",
        "reason": code,
        "execute": False,
        "source": "",
        "provider": "",
        "gaps": [code],
        "closure_evaluated": False,
    }


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _reject_link(path: Path) -> None:
    if path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)()):
        raise ValueError("link_escape")


def _json_too_deep(blob: bytes, limit: int = 32) -> bool:
    """Reject nested payloads before ``json.loads`` can recurse without a bound."""
    depth = 0
    in_string = False
    escape = False
    for byte in blob:
        if in_string:
            if escape:
                escape = False
            elif byte == 0x5C:
                escape = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
            continue
        if byte in (0x7B, 0x5B):
            depth += 1
            if depth > limit:
                return True
        elif byte in (0x7D, 0x5D) and depth:
            depth -= 1
    return False


def load_config_bytes(blob: bytes) -> dict[str, Any]:
    if len(blob) > MAX_CONFIG_BYTES:
        raise ValueError("oversize")
    if _json_too_deep(blob):
        raise ValueError("invalid_type")
    try:
        payload = json.loads(blob.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=lambda _v: None)
    except RecursionError:
        raise ValueError("invalid_type") from None
    except ValueError as exc:
        if str(exc) == "duplicate_json_key":
            raise
        raise ValueError("invalid_type") from None
    if not isinstance(payload, dict):
        raise ValueError("invalid_type")
    return payload


def load_config_path(path: str) -> dict[str, Any]:
    target = Path(path)
    _reject_link(target)
    if not target.is_file():
        raise ValueError("config_rejected")
    try:
        size = target.stat().st_size
    except OSError:
        raise ValueError("config_rejected") from None
    if size > MAX_CONFIG_BYTES:
        raise ValueError("oversize")
    try:
        blob = target.read_bytes()
    except OSError:
        raise ValueError("config_rejected") from None
    return load_config_bytes(blob)


def parse_config(payload: dict[str, Any] | None) -> tuple[WebSupplementRequest | None, str]:
    if payload is None:
        return None, "no_config"
    if not isinstance(payload, dict):
        return None, "invalid_type"
    unknown = [key for key in payload if key not in FIELDS]
    if unknown:
        return None, "unknown_field"
    if payload.get("schema_version") != CONFIG_SCHEMA:
        return None, "config_rejected"
    mode = payload.get("mode")
    source = payload.get("source")
    if not isinstance(mode, str) or mode not in MODES:
        return None, "invalid_type"
    if not isinstance(source, str) or source not in SOURCES:
        return None, "invalid_type"
    path = payload.get("path", "")
    endpoint = payload.get("endpoint", "")
    target = payload.get("target", "")
    provider = payload.get("provider", "")
    origins = payload.get("exact_origins", [])
    observation_ms = payload.get("observation_ms", 0)
    authorized = payload.get("authorized", False)
    related_targets = payload.get("related_targets", False)
    if not isinstance(path, str) or not isinstance(endpoint, str) or not isinstance(target, str):
        return None, "invalid_type"
    if not isinstance(provider, str) or provider not in PROVIDERS:
        return None, "invalid_type"
    if not isinstance(origins, list) or len(origins) > MAX_ORIGINS:
        return None, "invalid_type"
    if any(not isinstance(item, str) or not _exact_origin(item) for item in origins):
        return None, "invalid_type"
    if isinstance(observation_ms, bool) or not isinstance(observation_ms, int):
        return None, "invalid_type"
    if observation_ms < 0 or observation_ms > MAX_OBSERVATION_MS:
        return None, "observation_ms_limit"
    if not isinstance(authorized, bool) or not isinstance(related_targets, bool):
        return None, "invalid_type"
    if path.lower().startswith(("http://", "https://", "ws://", "wss://")):
        return None, "config_rejected"
    return WebSupplementRequest(
        mode=mode,
        source=source,
        path=path,
        endpoint=endpoint,
        target=target,
        exact_origins=tuple(origins),
        provider=provider,
        observation_ms=observation_ms,
        authorized=authorized,
        related_targets=related_targets,
        raw=dict(payload),
    ), ""


def _exact_origin(value: str) -> bool:
    if len(value) > 256 or any(char in value for char in " \t\r\n?#@\\"):
        return False
    if "://" not in value:
        return False
    scheme, rest = value.split("://", 1)
    if scheme not in {"http", "https", "ws", "wss"} or not rest or "/" in rest:
        return False
    return True


def has_webview_signal(meta: dict[str, Any] | None) -> bool:
    if not isinstance(meta, dict):
        return False
    signals = meta.get("webview_signals")
    if isinstance(signals, list) and len(signals) > 0:
        return True
    count = meta.get("webview_signal_count")
    return isinstance(count, int) and not isinstance(count, bool) and count > 0


def _sealed(plan: dict[str, Any]) -> dict[str, Any]:
    refresh_agent_handoff(plan, None)
    return plan


def build_plan(
    request: WebSupplementRequest | None,
    *,
    platform: str,
    meta: dict[str, Any] | None,
    rejected: str = "",
) -> dict[str, Any]:
    """Decide execution from signals, explicit files, or an authorized CDP target.

    A bare API URL is not a signal. Authorization is read only from the caller config.
    """
    if rejected:
        plan = _stamp_platform(empty_plan(rejected), platform)
        plan["status"] = "skipped"
        return _sealed(plan)
    if request is None:
        if platform == "web" or has_webview_signal(meta):
            return _sealed(_stamp_platform(empty_plan("no_config"), platform))
        plan = empty_plan("no_config")
        plan["status"] = "not_applicable"
        plan["gaps"] = []
        return _sealed(_stamp_platform(plan, platform))
    plan = _stamp_platform(empty_plan("mode_off"), platform)
    plan["mode"] = request.mode
    plan["source"] = request.source
    plan["provider"] = request.provider
    if request.mode != "auto":
        plan["reason"] = "mode_off"
        plan["gaps"] = ["mode_off"]
        return _sealed(plan)
    signal = platform == "web" or has_webview_signal(meta)
    if request.source == "cdp" and request.provider in {"rea", "inspect"}:
        plan.update(status="skipped", reason="provider_mismatch", execute=False, gaps=["provider_mismatch"])
        return _sealed(plan)
    if request.authorized_cdp:
        plan.update(status="selected", reason="ok", execute=True, gaps=[])
        return _sealed(plan)
    if request.source == "cdp":
        reason = "cdp_not_authorized" if request.authorized is not True else "cdp_target_missing"
        plan.update(status="skipped", reason=reason, execute=False, gaps=[reason])
        return _sealed(plan)
    if request.explicit_material:
        plan.update(status="selected", reason="ok", execute=True, gaps=[])
        return _sealed(plan)
    if signal:
        plan.update(status="skipped", reason="material_missing", execute=False, gaps=["material_missing"])
        return _sealed(plan)
    plan.update(status="skipped", reason="no_web_signal", execute=False, gaps=["no_web_signal"])
    return _sealed(plan)


def _enum(value: object, allowed: frozenset[str], default: str = "") -> str:
    return value if isinstance(value, str) and value in allowed else default


def _known_platform(value: object) -> str:
    return value if isinstance(value, str) and value in PLATFORMS else ""


def _stamp_platform(plan: dict[str, Any], platform: str) -> dict[str, Any]:
    plan["platform"] = _known_platform(platform)
    return plan


def _action(code: str, instruction: str, argv: tuple[str, ...] = ()) -> dict[str, Any]:
    return {"code": code, "instruction": instruction, "argv": list(argv)}


def _supplement_template(platform: str) -> tuple[str, ...] | None:
    if platform == "web":
        return _ARGV_ANALYZE_WEB_SUPPLEMENT
    if platform == "android":
        return _ARGV_ANALYZE_SUPPLEMENT
    return None


_OUTCOME_STATUSES = PLAN_STATUSES | SUCCESS_STATUSES | frozenset({"unknown", "skipped"})


def _token(value: object, allowed: frozenset[str]) -> tuple[str, bool]:
    """Whitelist a string token. Non-strings are malformed and never tested with ``in``."""
    if value is None or value == "":
        return "", False
    if isinstance(value, str) and value in allowed:
        return value, False
    return "unknown", True


def _safe_outcome(outcome: dict[str, Any] | None) -> tuple[dict[str, str], bool]:
    if not isinstance(outcome, dict):
        return {"status": "", "reason": "", "provider": "", "prior_status": ""}, False
    status, malformed = _token(outcome.get("status"), _OUTCOME_STATUSES)
    reason_value = outcome.get("reason")
    if reason_value is None or reason_value == "":
        reason = ""
    elif isinstance(reason_value, str):
        reason = fixed_reason(reason_value)
    else:
        reason = ""
        malformed = True
    prior_value = outcome.get("prior_status")
    prior = prior_value if isinstance(prior_value, str) and prior_value in SUCCESS_STATUSES else ""
    if prior_value not in (None, "") and not isinstance(prior_value, str):
        malformed = True
    provider_value = outcome.get("provider")
    if provider_value not in (None, "") and not isinstance(provider_value, str):
        malformed = True
    return {
        "status": status,
        "reason": reason,
        "provider": _enum(provider_value, PROVIDERS),
        "prior_status": prior,
    }, malformed


def _material(plan: dict[str, str], outcome: dict[str, str]) -> tuple[str, str]:
    """Return selected runtime provider and material kind. REA package name is not a provider."""
    source = plan["source"]
    provider = plan["provider"]
    verified = outcome["provider"]
    if source == "cdp" and provider in {"rea", "inspect"}:
        return "", "provider_mismatch"
    if source == "cdp" and provider in RUNTIME_PROVIDERS:
        if verified in RUNTIME_PROVIDERS:
            return verified, "runtime_trace"
        return provider, "runtime_trace"
    if source == "cdp" and provider == "" and verified in RUNTIME_PROVIDERS:
        return verified, "runtime_trace"
    if source == "rea-json":
        return "", "rea_offline_material"
    if provider == "inspect" and source != "cdp":
        return "", "rea_inspect_standalone"
    if source == "bundle":
        verified_receipt = outcome["status"] in SUCCESS_STATUSES | {"skipped"} and outcome["reason"] in {
            "executed", "ok", "duplicate_raw",
        }
        if verified_receipt:
            kept = verified if verified in PROVIDERS and verified else ""
            return kept, "bundle_verified"
        return "", "bundle_unverified"
    return "", "none"


def _latest_failure(plan: dict[str, str], outcome: dict[str, str]) -> bool:
    if outcome["status"] in {"failed", "unavailable", "unknown"}:
        return True
    return outcome["reason"] in _FAILURE_REASONS


def _had_success(plan: dict[str, str], outcome: dict[str, str]) -> bool:
    return plan["status"] in SUCCESS_STATUSES or outcome["prior_status"] in SUCCESS_STATUSES


def build_agent_handoff(
    plan: dict[str, Any] | None,
    outcome: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compact guidance from whitelisted plan and outcome fields. Never reads instructions."""
    raw = plan if isinstance(plan, dict) else {}
    coverage = clean_coverage(outcome.get("coverage") if isinstance(outcome, dict) else None)
    status_value = raw.get("status")
    plan_malformed = bool(raw) and "status" in raw and not isinstance(status_value, str)
    status = status_value if isinstance(status_value, str) and status_value in PLAN_STATUSES else ""
    if raw and "status" in raw and status == "":
        status = "unknown"
    if not raw:
        status = "unknown" if outcome else _enum(raw.get("status"), PLAN_STATUSES, "unknown")
    reason_raw = raw.get("reason")
    if reason_raw not in (None, "") and not isinstance(reason_raw, str):
        plan_malformed = True
    safe = {
        "status": status or "unknown",
        "reason": fixed_reason(reason_raw) if isinstance(reason_raw, str) else (
            "no_config" if isinstance(status, str) and status in {"pending", "not_applicable", ""} else "config_rejected"
        ),
        "source": _enum(raw.get("source"), SOURCES),
        "provider": _enum(raw.get("provider"), PROVIDERS),
        "mode": _enum(raw.get("mode"), MODES),
        "platform": _known_platform(raw.get("platform")),
    }
    if safe["status"] == "unknown":
        safe["reason"] = "config_rejected"
    result_outcome, outcome_malformed = _safe_outcome(outcome)
    selected, kind = _material(safe, result_outcome)
    reason = result_outcome["reason"] or safe["reason"]
    if result_outcome["status"] in {"failed", "unavailable", "unknown"} or result_outcome["reason"] in _FAILURE_REASONS:
        reason = result_outcome["reason"] or reason
    relevant = not (
        safe["status"] in {"not_applicable", "unknown"} and safe["reason"] in {"no_config", "config_rejected"}
        and safe["source"] == "" and not result_outcome["status"]
    )
    if safe["reason"] == "no_web_signal" and safe["source"] not in {"bundle", "rea-json", "cdp"}:
        relevant = False
    why = "unknown"
    unmet: list[str] = []
    actions: list[dict[str, Any]] = []
    checks = ["read_plan_status_reason_source_provider", "read_latest_receipt"]
    failure = _latest_failure(safe, result_outcome) and bool(result_outcome["status"] or result_outcome["reason"])
    outcome_live = result_outcome["status"] in {"executed", "ok", "failed", "unavailable"} or bool(
        result_outcome["reason"]
    )
    if plan_malformed or outcome_malformed:
        why = "unknown"
        relevant = True
        actions.append(_action(
            "inspect_diagnostics",
            "回执字段类型无法识别。查看既有诊断，不要把它当成成功、已调度或待复核。",
        ))
    elif safe["status"] == "unknown" and not failure:
        why = "unknown"
        actions.append(_action(
            "inspect_diagnostics",
            "状态无法识别。查看既有诊断，不要把它当成成功或 ready。",
        ))
        relevant = True
    elif safe["reason"] == "mode_off":
        why = "mode_off"
        relevant = True
        actions = []
        checks.append("respect_mode_off")
    elif failure and _had_success(safe, result_outcome):
        why = "review_failure"
        relevant = True
        unmet.append("latest_failure")
        actions.append(_action(
            "review_failure",
            "先看最新失败回执，再决定是否修正输入。不要只沿用更早的成功。",
        ))
        checks.append("compare_latest_failure_with_prior_success")
    elif not outcome_live and (safe["reason"] == "no_web_signal" or (
        safe["status"] == "not_applicable" and safe["reason"] == "no_config" and safe["source"] == ""
    )):
        why = "no_web_signal"
        relevant = False
    elif reason in {"plugin_unavailable"} or result_outcome["status"] == "unavailable" and reason == "plugin_unavailable":
        why = "plugin_missing"
        unmet.append("plugin_install")
        actions.append(_action(
            "check_plugin",
            "插件缺失。运行离线自检并阅读安装文档。不要改写授权。",
            _ARGV_SELFCHECK,
        ))
    elif reason == "trace_dependency_missing":
        why = "trace_dependency_missing"
        unmet.append("trace_extra")
        actions.append(_action(
            "check_trace_capabilities",
            "只检查本机 trace 前置。status=ok 不是实测。",
            _ARGV_TRACE_CAPABILITIES,
        ))
    elif reason == "cdp_not_authorized":
        why = "needs_authorization"
        unmet.append("existing_user_authorization")
        actions.append(_action(
            "confirm_authorization",
            "核对调用方已经给出的授权。不要制造 authorized=true。",
        ))
    elif reason == "cdp_target_missing":
        why = "needs_target"
        unmet.append("exact_authorized_target")
        actions.append(_action(
            "identify_authorized_target",
            "确认已经授权的精确 target。不要编造 WebView 发现命令。",
        ))
    elif reason == "provider_mismatch" or kind == "provider_mismatch":
        why = "provider_mismatch"
        unmet.append("runtime_provider")
        actions.append(_action(
            "provider_mismatch",
            "source=cdp 不能使用 rea 或 inspect。不会改写成 trace。",
        ))
    elif reason == "worker_not_stopped":
        why = "worker_not_stopped"
        relevant = True
        unmet.append("worker_process")
        actions.append(_action(
            "stop_worker_process",
            "采集进程没有停干净。先结束残留进程并核对环境，再决定是否重采。不要把它当成输入或配置被拒绝。",
        ))
    elif reason == "trace_cleanup_failed":
        why = "trace_cleanup_failed"
        relevant = True
        unmet.append("worker_environment")
        actions.append(_action(
            "clean_worker_environment",
            "采集环境或 worker 没有清理干净。先结束残留进程并核对环境，再决定是否重采。不要把它当成输入或配置被拒绝。",
        ))
    elif reason == "cdp_deferred":
        why = "cdp_deferred"
        relevant = True
        unmet.append("authorized_capture_window")
        actions.append(_action(
            "await_authorized_capture",
            "这次没有执行已授权的 CDP。下一条命令只补已有报告的本地材料，不授予设备权限，也不要只为导入再跑一遍分析。",
            _ARGV_SUPPLEMENT_WEB,
        ))
    elif reason in _FAILURE_REASONS or safe["status"] in {"failed", "unavailable"}:
        why = "inspect_input"
        unmet.append("valid_input")
        actions.append(_action(
            "inspect_diagnostics",
            "查看诊断并修正输入。不要原样重跑。",
        ))
    elif (
        safe["status"] in SUCCESS_STATUSES
        or result_outcome["status"] in SUCCESS_STATUSES
        or result_outcome["reason"] == "duplicate_raw"
        or safe["reason"] == "duplicate_raw"
    ):
        why = "review_candidates"
        actions.append(_action(
            "review_candidates",
            "复核规范证据和新候选。不要重复采集。attach 只挂观察，不解析进主报告。",
        ))
        checks.append("review_canonical_candidates")
        if coverage.get("status") == "partial" or coverage.get("gaps"):
            names = ",".join(coverage.get("gaps") or [])
            actions.append(_action(
                "review_coverage_gaps",
                "执行状态可以是 executed，覆盖仍是 partial"
                + (f"（{names}）" if names else "")
                + "。可以复核候选，缺覆盖要单独标明。不要因此自动闭环或盲目重采。",
            ))
            checks.append("review_coverage_gaps")
    elif safe["status"] == "selected":
        why = "scheduled"
        actions.append(_action(
            "await_receipt",
            "fxapk 会调度已选提供方。读回执后再决定，不要另起采集。",
        ))
    elif reason == "material_missing":
        why = "needs_material"
        relevant = True
        unmet.append("local_material_or_authorized_cdp")
        actions.append(_action(
            "supplement_existing_report",
            "已有报告只补网页材料时用这条固定命令。不要为了补网页再跑一次 APK 分析、auto、安装或 capture。命令模板不是授权。",
            _ARGV_SUPPLEMENT_WEB,
        ))
    elif reason in {"no_config"} or safe["status"] == "pending":
        template = _supplement_template(safe["platform"])
        if template is None:
            why = "unknown"
            relevant = True
            actions.append(_action(
                "inspect_diagnostics",
                "报告没有已知 platform。先核对证据面再选入口，不要猜 APK 分析命令。",
            ))
        else:
            why = "needs_material"
            relevant = True
            unmet.append("local_material_or_authorized_cdp")
            actions.append(_action(
                "prepare_web_supplement",
                "首次分析使用这条命令：准备本地材料或已授权 CDP 目标，再在下一次本来要跑的分析上传入 --web-supplement。不要为导入另起 auto、安装或 capture。attach 只挂观察。",
                template,
            ))
            actions.append(_action(
                "supplement_existing_report",
                "已有报告只补网页材料时用 supplement-web。不要为了补网页再跑一次 APK 分析、auto、安装或 capture。命令模板不是授权。",
                _ARGV_SUPPLEMENT_WEB,
            ))
    else:
        why = "unknown"
        actions.append(_action(
            "inspect_diagnostics",
            "状态无法识别。查看既有诊断，不要把它当成成功或 ready。",
        ))
    handoff = {
        "schema_version": HANDOFF_SCHEMA,
        "relevant": relevant,
        "why": why,
        "selected_provider": selected,
        "material_kind": kind,
        "unmet_inputs": unmet,
        "next_actions": actions,
        "evidence_checks": checks,
        "stop_conditions": list(_STOP),
        "authorization": False,
        "closure_evaluated": False,
    }
    if coverage:
        handoff["coverage_status"] = coverage["status"]
        handoff["coverage_gaps"] = coverage["gaps"]
    return handoff


def refresh_agent_handoff(
    plan: dict[str, Any],
    outcome: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Replace guidance only. Status, execute, and history stay with the caller."""
    handoff = build_agent_handoff(plan, outcome)
    plan["agent_handoff"] = handoff
    return handoff


def project_plan_for_digest(
    raw_plan: object,
    supplement: object = None,
    runtime: object = None,
) -> dict[str, Any]:
    """Recompute guidance from whitelisted fields and the latest receipt."""
    plan = raw_plan if isinstance(raw_plan, dict) else {}
    raw_status = plan.get("status")
    if isinstance(raw_status, str) and raw_status in PLAN_STATUSES:
        status = raw_status
    elif raw_status in (None, ""):
        status = "pending"
    else:
        status = "unknown"
    raw_reason = plan.get("reason")
    reason = fixed_reason(raw_reason if isinstance(raw_reason, str) else "no_config")
    safe_plan = {
        "status": raw_status if isinstance(raw_status, str) and raw_status in PLAN_STATUSES else "unknown",
        "reason": reason if isinstance(raw_reason, str) else "config_rejected",
        "source": _enum(plan.get("source"), SOURCES),
        "provider": _enum(plan.get("provider"), PROVIDERS),
        "mode": _enum(plan.get("mode"), MODES),
        "platform": _known_platform(plan.get("platform")),
    }
    if not plan:
        safe_plan["status"] = "unknown"
    prior = ""
    latest: dict[str, Any] | None = None
    if isinstance(supplement, dict):
        supplement_status = supplement.get("status")
        if isinstance(supplement_status, str) and supplement_status in SUCCESS_STATUSES:
            prior = supplement_status
        latest_status = supplement.get("latest_status", supplement_status)
        latest_reason = supplement.get("latest_reason", supplement.get("reason"))
        latest = {
            "status": latest_status,
            "reason": latest_reason,
            "provider": supplement.get("provider"),
            "prior_status": prior,
            "coverage": supplement.get("coverage"),
        }
    if isinstance(runtime, list) and runtime and isinstance(runtime[-1], dict):
        last = runtime[-1]
        latest = {
            "status": last.get("status"),
            "reason": last.get("reason"),
            "provider": last.get("provider"),
            "coverage": last["coverage"] if "coverage" in last else None,
            "prior_status": prior or (
                safe_plan["status"] if isinstance(safe_plan["status"], str) and safe_plan["status"] in SUCCESS_STATUSES else ""
            ),
        }
        if last.get("execution") == "not_executed":
            latest["execution"] = "not_executed"
    projected = {
        "status": status,
        "reason": reason,
        "execute": plan.get("execute") is True,
        "source": safe_plan["source"],
        "provider": safe_plan["provider"],
        "closure_evaluated": False,
        "agent_handoff": build_agent_handoff(safe_plan, latest),
    }
    if isinstance(latest, dict) and latest.get("execution") == "not_executed":
        projected["execution"] = "not_executed"
    if safe_plan["platform"]:
        projected["platform"] = safe_plan["platform"]
    return projected
