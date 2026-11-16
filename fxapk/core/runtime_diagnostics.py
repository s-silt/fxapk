"""运行时覆盖诊断。

静态清单和动态采集都把事实交给这里分类。诊断只解释覆盖：不新增端点、
不改闭环、不把早退或无日志退出写成 Frida 检测。缺字段保持 unknown。
不同窗口和不同启动身份不共享覆盖。
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

SCHEMA = "runtime-diagnostics/1"
META_WRITE_OWNER = "core.runtime_diagnostics"
META_WRITE_CATEGORIES = {
    "runtime_diagnostics": "coverage",
}
META_WRITE_KEYS = frozenset(META_WRITE_CATEGORIES)

_ITEM_FIELDS = (
    "class",
    "event",
    "apk_sha256",
    "window_id",
    "run_id",
    "pid",
    "start_token",
    "uid",
    "process_role",
    "module_sha256",
    "build_id",
    "abi",
    "observer_attached",
    "observer_requested",
    "time_source",
    "time_precision",
    "runtime_variant",
    "window_coverage_shared",
    "run_coverage_shared",
    "source_event",
    "source_report_sha256",
    "component_name",
    "declared_value",
    "device_id",
)
_VARIANTS = frozenset({"original-runtime", "modified-runtime"})
_ISOLATED_UID_MIN = 90000
_ISOLATED_UID_MAX = 99999


def _text(value: object) -> str:
    if isinstance(value, str) and value:
        return value
    return "unknown"


def _number(value: object) -> int | str:
    if isinstance(value, bool) or not isinstance(value, int):
        return "unknown"
    return value


def _flag(value: object) -> bool | str:
    if isinstance(value, bool):
        return value
    return "unknown"


def _reuse_key(raw: Mapping[str, Any]) -> tuple[str, str, str, int] | None:
    """同一 run、同一 APK、可用设备身份下的 PID 才放进同一组。"""
    pid = _number(raw.get("pid"))
    if not isinstance(pid, int):
        return None
    run_id = _text(raw.get("run_id"))
    apk = _text(raw.get("apk_sha256"))
    if run_id == "unknown" or apk == "unknown":
        return None
    device = raw.get("device_id")
    if isinstance(device, str) and device.strip() and device != "unknown":
        device_key = device
    else:
        device_key = "unknown"
    return (apk, run_id, device_key, pid)


def explain_coverage(records: object, *, prior: object = None) -> dict[str, Any]:
    """逐条分类。同一 PID 的不同启动身份只说明不能互借覆盖。"""
    rows = [item for item in records if isinstance(item, dict)] if isinstance(records, list) else []
    earlier = [item for item in prior if isinstance(item, dict)] if isinstance(prior, list) else []
    tokens_by_key: dict[tuple[str, str, str, int], set[str]] = {}
    for raw in [*earlier, *rows]:
        key = _reuse_key(raw)
        token = _text(raw.get("start_token"))
        if key is not None and token != "unknown":
            tokens_by_key.setdefault(key, set()).add(token)
    items = [_classify(raw, tokens_by_key) for raw in rows]
    return {
        "schema": SCHEMA,
        "frida_detection": "not_inferred",
        "endpoints_added": 0,
        "closure_evaluated": False,
        "items": items,
    }


def _classify(
    raw: Mapping[str, Any],
    tokens_by_key: Mapping[tuple[str, str, str, int], set[str]],
) -> dict[str, Any]:
    pid = _number(raw.get("pid"))
    expected = _number(raw.get("expected_pid"))
    uid = _number(raw.get("uid"))
    start = _text(raw.get("start_token"))
    event = raw.get("event") if isinstance(raw.get("event"), str) else ""
    logs = raw.get("logs") if "logs" in raw else "missing"
    observer = _flag(raw.get("observer_attached"))
    requested = _flag(raw.get("observer_requested"))
    late_evidence = raw.get("observer_late_evidence") is True
    variant = raw.get("runtime_variant")
    source_event: str | None = None
    if isinstance(pid, int) and isinstance(expected, int) and pid != expected:
        kind, label = "coverage-gap", "pid_mismatch"
    elif isinstance(uid, int) and _ISOLATED_UID_MIN <= uid <= _ISOLATED_UID_MAX:
        if start == "unknown" or _text(raw.get("apk_sha256")) == "unknown":
            kind, label = "coverage-gap", "identity_unattributed"
            source_event = "uid_isolated"
        else:
            kind, label = "observed-event", "uid_isolated"
    elif (
        (reuse_key := _reuse_key(raw)) is not None
        and start != "unknown"
        and len(tokens_by_key.get(reuse_key, ())) > 1
    ):
        kind, label = "coverage-gap", "pid_reuse"
    elif event == "early_exit":
        kind, label = "coverage-gap", "early_exit_unattributed"
    elif event == "process_exit" and logs is False:
        kind, label = "coverage-gap", "no_log_exit"
    elif event == "observer_late" and late_evidence:
        kind, label = "coverage-gap", "observer_late"
    elif event == "observer_late":
        # 只有调用方给出的时间证据才保留迟到。没有证据时不沿用这条事件名。
        kind, label = "coverage-gap", "observer_unknown"
    elif observer is False and requested is False:
        kind, label = "coverage-gap", "not_requested"
    elif observer is False and requested is True and late_evidence:
        kind, label = "coverage-gap", "observer_late"
    elif observer is False and requested is True:
        kind, label = "coverage-gap", "observer_not_attached"
    elif observer is False:
        kind, label = "coverage-gap", "observer_unknown"
    elif event == "java_hook":
        kind, label = "coverage-gap", "java_only"
    elif event == "selinux_query":
        kind, label = "observed-event", "selinux_query"
    elif event in {"isolated_process", "app_zygote"}:
        declared = raw.get("declared_value")
        if declared is True:
            kind, label = "static-potential", event
        elif declared is False:
            kind, label = "static-recorded", event
        else:
            kind, label = "coverage-gap", "unclassified"
    elif (
        event == "capture_window"
        and variant == "original-runtime"
        and raw.get("status") == "failed"
    ):
        kind, label = "coverage-gap", "original_uncovered"
    elif event == "capture_window":
        kind, label = "observed-event", "capture_window"
    else:
        kind, label = "coverage-gap", "unclassified"
    if kind == "observed-event" and _text(raw.get("apk_sha256")) == "unknown":
        source_event = label
        kind, label = "coverage-gap", "identity_unattributed"
    item = {
        "class": kind,
        "event": label,
        "apk_sha256": _text(raw.get("apk_sha256")),
        "window_id": _text(raw.get("window_id")),
        "run_id": _text(raw.get("run_id")),
        "pid": pid,
        "start_token": start,
        "uid": uid,
        "process_role": _text(raw.get("process_role")),
        "module_sha256": _text(raw.get("module_sha256")),
        "build_id": _text(raw.get("build_id")),
        "abi": _text(raw.get("abi")),
        "observer_attached": observer,
        "observer_requested": requested,
        "time_source": _text(raw.get("time_source")),
        "time_precision": _text(raw.get("time_precision")),
        "runtime_variant": variant if isinstance(variant, str) and variant in _VARIANTS else "unknown",
        "window_coverage_shared": False,
        "run_coverage_shared": False,
        "component_name": _text(raw.get("component_name")),
        "declared_value": raw.get("declared_value") if isinstance(raw.get("declared_value"), bool) else "unknown",
        "device_id": _text(raw.get("device_id")),
    }
    if source_event is not None:
        item["source_event"] = source_event
    return item


def _sha256_text(value: object) -> str | None:
    if not isinstance(value, str) or len(value) != 64:
        return None
    lowered = value.lower()
    if any(character not in "0123456789abcdef" for character in lowered):
        return None
    return lowered


def _bind_report_identity(item: dict[str, Any], sample: str | None) -> None:
    """有样本哈希才给这次覆盖。对不上或主报告没有哈希时，留下事件并取消覆盖资格。"""
    if item.get("class") != "observed-event":
        return
    apk = _sha256_text(item.get("apk_sha256"))
    if sample is not None and apk is not None and apk == sample:
        return
    item["source_event"] = item.get("event")
    item["class"] = "coverage-gap"
    item["event"] = "identity_mismatch" if sample is not None and apk is not None else "identity_unattributed"


def project_runtime_diagnostics(meta: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """默认出口只保留覆盖解释。没有该键时返回 None。"""
    if not isinstance(meta, Mapping) or "runtime_diagnostics" not in meta:
        return None
    raw = meta.get("runtime_diagnostics")
    if not isinstance(raw, dict):
        return {
            "schema": SCHEMA,
            "status": "invalid",
            "reason": "invalid_type",
            "frida_detection": "not_inferred",
            "endpoints_added": 0,
            "closure_evaluated": False,
            "items": [],
        }
    items: list[dict[str, Any]] = []
    raw_items = raw.get("items")
    if isinstance(raw_items, list):
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            projected = {field: item.get(field, "unknown") for field in _ITEM_FIELDS}
            projected["window_coverage_shared"] = False
            projected["run_coverage_shared"] = False
            items.append(projected)
    return {
        "schema": SCHEMA,
        "frida_detection": "not_inferred",
        "endpoints_added": 0,
        "closure_evaluated": False,
        "items": items,
    }


def merge_process_observations(report: Any, records: object) -> None:
    """追加分类结果。旧条目保留，不新增端点，也不改闭环。"""
    meta = getattr(report, "meta", None)
    if not isinstance(meta, dict):
        return
    existing = meta.get("runtime_diagnostics")
    kept: list[Any] = []
    if isinstance(existing, dict) and isinstance(existing.get("items"), list):
        kept.extend(existing["items"])
    rows = [item for item in records if isinstance(item, dict)] if isinstance(records, list) else []
    explained = explain_coverage(rows, prior=kept)
    sample = _sha256_text(meta.get("sample_sha256"))
    fresh = explained["items"]
    for raw, item in zip(rows, fresh, strict=False):
        _bind_report_identity(item, sample)
        attachment = _sha256_text(raw.get("source_report_sha256"))
        if attachment is not None:
            item["source_report_sha256"] = attachment
        source_path = raw.get("source_report_path")
        if isinstance(source_path, str) and source_path:
            item["source_report_path"] = source_path
    items = [*kept, *fresh]
    _reconcile_pid_reuse(items)
    meta["runtime_diagnostics"] = {
        "schema": SCHEMA,
        "frida_detection": "not_inferred",
        "endpoints_added": 0,
        "closure_evaluated": False,
        "items": items,
    }


def _reconcile_pid_reuse(items: list[Any]) -> None:
    """后到的窗口如果证明同一 run 里 PID 换过启动身份，补标已经留下的那条。不改各窗口自己的身份。"""
    groups: dict[tuple[str, str, str, int], set[str]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        key = _reuse_key(item)
        token = _text(item.get("start_token"))
        if key is not None and token != "unknown":
            groups.setdefault(key, set()).add(token)
    for item in items:
        if not isinstance(item, dict):
            continue
        key = _reuse_key(item)
        token = item.get("start_token")
        if key is None or not isinstance(token, str) or token in ("", "unknown"):
            continue
        if len(groups.get(key, ())) <= 1:
            continue
        if item.get("event") not in ("capture_window", "pid_reuse"):
            continue
        item["class"] = "coverage-gap"
        item["event"] = "pid_reuse"


def observation_from_capture(
    *,
    pid: object,
    uid: object,
    hook_status: object,
    retreated: object,
    runtime_variant: object,
    pass_tag: object,
    apk_sha256: object = None,
    run_id: object = None,
    start_token: object = None,
) -> dict[str, Any]:
    """把采集函数里已经拿到的事实收成一条原始观察。不推断检测。

    ``pass_tag`` 只作窗口。运行身份和进程启动身份没有单独事实时保持空，不抄窗口名。
    """
    if retreated is True:
        event = "early_exit"
        status = "failed"
    elif hook_status == "java-unavailable":
        event = "java_hook"
        status = None
    else:
        event = "capture_window"
        status = None
    if hook_status == "confirmed":
        observer: bool | None = True
        requested: bool | None = True
    elif hook_status == "none":
        observer = False
        requested = False
    elif hook_status == "unconfirmed":
        observer = False
        requested = True
    elif hook_status == "java-unavailable":
        observer = None
        requested = True
    else:
        observer = None
        requested = None
    variant = runtime_variant if runtime_variant in _VARIANTS else None
    window = pass_tag if isinstance(pass_tag, str) and pass_tag else None
    run = run_id if isinstance(run_id, str) and run_id else None
    token = start_token if isinstance(start_token, str) and start_token else None
    return {
        "event": event,
        "pid": pid if isinstance(pid, int) and not isinstance(pid, bool) else None,
        "uid": uid if isinstance(uid, int) and not isinstance(uid, bool) else None,
        "observer_attached": observer,
        "observer_requested": requested,
        "runtime_variant": variant,
        "window_id": window,
        "run_id": run,
        "start_token": token,
        "apk_sha256": apk_sha256 if isinstance(apk_sha256, str) and apk_sha256 else None,
        "status": status,
        "time_source": "unknown",
        "time_precision": "unknown",
    }
