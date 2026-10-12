"""安全投影：外部网页观察只留下计数、固定缺口和相对指针。

本模块不导入可选插件。畸形输入返回 unknown，不能变成 complete。
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

_HEX = re.compile(r"[0-9a-f]{64}")
_RELATIVE = re.compile(r"external_observations/[0-9a-f]{64}/")
_PROVIDERS = frozenset({"rea", "fxapk-cdp-trace"})
_IDENTITIES = frozenset({"unknown", "declared"})
_FLAGS = (
    "provenance_authenticated",
    "target_app_attribution_verified",
    "click_attribution_verified",
    "closure_evaluated",
)
_ACTIONS = ("review_copied_observation", "do_not_treat_as_case_closure")

# 原始缺口码只映射到固定分类。映射不到的字符串不进入任何出口。
_RAW_GAP_MAP = {
    "raw_network_bodies_unavailable": "raw_body_unavailable",
    "per_request_time_unavailable": "time_unavailable",
    "target_app_identity_unverified": "identity_unverified",
    "click_attribution_unverified": "click_unverified",
    "click_attribution_unavailable": "click_unverified",
    "target_app_attribution_unavailable": "identity_unverified",
    "provenance_unauthenticated": "provenance_unauthenticated",
    "closure_unavailable": "closure_not_evaluated",
    "script_source_unavailable": "script_incomplete",
    "cdp_hash_unavailable": "hash_unverified",
    "cdp_hash_relation_unverified": "hash_unverified",
    "console_outside_window": "time_unavailable",
    "console_time_unknown": "time_unavailable",
    "cross_frame_async_unsupported": "async_unverified",
    "cross_frame_async_unverified": "async_unverified",
    "oopif_worker_unsupported": "worker_unverified",
    "attach_before_history_unobserved": "history_unobserved",
    "source_tamper": "script_incomplete",
    "missing_context": "identity_unverified",
    "frame_mismatch": "frame_unverified",
    "unresolved_parent_id": "async_unverified",
    "async_parent_truncated": "async_unverified",
    "loader_conflict": "frame_unverified",
    "coordinate_unproven": "script_incomplete",
    "source_ambiguous": "script_incomplete",
    "wrong_session": "identity_unverified",
    "hop_identity_conflict": "identity_unverified",
    "identity_unverified": "identity_unverified",
    "click_unverified": "click_unverified",
    "closure_not_evaluated": "closure_not_evaluated",
    "partial_coverage": "partial_coverage",
    "raw_body_unavailable": "raw_body_unavailable",
    "time_unavailable": "time_unavailable",
    "script_incomplete": "script_incomplete",
    "hash_unverified": "hash_unverified",
    "async_unverified": "async_unverified",
    "worker_unverified": "worker_unverified",
    "history_unobserved": "history_unobserved",
    "frame_unverified": "frame_unverified",
}
GAP_LABELS = {
    "identity_unverified": "目标应用身份未验证",
    "provenance_unauthenticated": "来源未认证",
    "click_unverified": "点击归因未验证",
    "closure_not_evaluated": "未评估案件闭环",
    "partial_coverage": "观察覆盖不完整",
    "raw_body_unavailable": "原始响应体不可用",
    "time_unavailable": "时间不可用或不在窗口内",
    "script_incomplete": "脚本内容不完整或未绑定",
    "hash_unverified": "脚本哈希未认证",
    "async_unverified": "异步栈未验证",
    "worker_unverified": "worker 或跨进程 frame 未验证",
    "history_unobserved": "附着前历史未观察",
    "frame_unverified": "frame 身份未验证",
}
_ALWAYS_GAPS = (
    "identity_unverified",
    "provenance_unauthenticated",
    "click_unverified",
    "closure_not_evaluated",
    "partial_coverage",
)


def classify_gaps(values: object) -> tuple[list[str], int]:
    """把原始缺口收成固定分类。返回 (排序后的分类, 未能归类的条数)。"""
    found: set[str] = set(_ALWAYS_GAPS)
    unknown = 0
    if not isinstance(values, list):
        return sorted(found), unknown
    for item in values[:256]:
        mapped = _RAW_GAP_MAP.get(item) if isinstance(item, str) else None
        if mapped is None:
            unknown += 1
        else:
            found.add(mapped)
    return sorted(found), unknown


def _count(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 0 or value > 1_000_000:
        return None
    return value


def _unknown_document() -> dict[str, Any]:
    return {
        "status": "unknown",
        "coverage_status": "unknown",
        "count": 0,
        "authenticated": False,
        "provenance_authenticated": False,
        "target_app_attribution_verified": False,
        "click_attribution_verified": False,
        "closure_evaluated": False,
        "request_count": 0,
        "script_count": 0,
        "async_count": 0,
        "action_count": 0,
        "gaps": [],
        "actions": list(_ACTIONS),
        "relative_paths": [],
        "source_sha256": [],
        "observations": [],
    }


_ROW_KEYS = frozenset(
    {
        "schema_version",
        "provider",
        "source_sha256",
        "bundle_relative_path",
        "request_count",
        "script_count",
        "async_count",
        "action_count",
        "identity",
        "coverage_status",
        "gaps",
        "unclassified_gap_count",
        "bundle_integrity_checked",
        "provenance_authenticated",
        "target_app_attribution_verified",
        "click_attribution_verified",
        "closure_evaluated",
        "context_record",
        "manifest_sha256",
    }
)
_ATTACHMENT_SCHEMA = "fxapk-web-observation-attachment/1"


def _unknown_row() -> dict[str, Any]:
    return {
        "status": "unknown",
        "provider": "unknown",
        "identity": "unknown",
        "source_sha256": "",
        "relative_path": "",
        "request_count": 0,
        "script_count": 0,
        "async_count": 0,
        "action_count": 0,
        "gaps": [],
    }


def _project_row(item: object) -> dict[str, Any]:
    status = "partial"
    if not isinstance(item, dict):
        return _unknown_row()
    item = {key: item[key] for key in item if key in _ROW_KEYS}
    if item.get("schema_version") != _ATTACHMENT_SCHEMA:
        return _unknown_row()
    provider = item.get("provider")
    if provider not in _PROVIDERS:
        provider = "unknown"
        status = "unknown"
    identity = item.get("identity")
    if identity not in _IDENTITIES:
        identity = "unknown"
        status = "unknown"
    sha = item.get("source_sha256")
    if not isinstance(sha, str) or _HEX.fullmatch(sha) is None:
        sha = ""
        status = "unknown"
    relative = item.get("bundle_relative_path")
    if not isinstance(relative, str) or _RELATIVE.fullmatch(relative) is None:
        relative = ""
        status = "unknown"
    elif sha and relative != f"external_observations/{sha}/":
        relative = ""
        status = "unknown"
    if item.get("coverage_status") != "partial":
        status = "unknown"
    if item.get("bundle_integrity_checked") is not True:
        status = "unknown"
    for flag in _FLAGS:
        if item.get(flag) is not False:
            status = "unknown"
    gaps: list[str] = []
    raw_gaps = item.get("gaps")
    if not isinstance(raw_gaps, list):
        status = "unknown"
    else:
        for gap in raw_gaps:
            if isinstance(gap, str) and gap in GAP_LABELS:
                if gap not in gaps:
                    gaps.append(gap)
            else:
                status = "unknown"
    counts: dict[str, int] = {}
    for key in ("request_count", "script_count", "async_count", "action_count"):
        parsed = _count(item.get(key))
        if parsed is None:
            status = "unknown"
            counts[key] = 0
        else:
            counts[key] = parsed
    return {
        "status": status,
        "provider": provider,
        "identity": identity,
        "source_sha256": sha,
        "relative_path": relative,
        "request_count": counts["request_count"],
        "script_count": counts["script_count"],
        "async_count": counts["async_count"],
        "action_count": counts["action_count"],
        "gaps": gaps,
    }


def digest_web_observations(value: object) -> dict[str, Any]:
    """供 digest 与 HTML 使用的白名单视图。永不抛出，永不返回 complete。"""
    try:
        if not isinstance(value, list):
            return _unknown_document()
        rows = [_project_row(item) for item in value[:32]]
        if len(value) > 32:
            rows.append(_project_row(None))
        known_gaps: list[str] = []
        paths: list[str] = []
        hashes: list[str] = []
        totals = {"request_count": 0, "script_count": 0, "async_count": 0, "action_count": 0}
        for row in rows:
            for gap in row["gaps"]:
                if gap not in known_gaps:
                    known_gaps.append(gap)
            if row["relative_path"] and row["relative_path"] not in paths:
                paths.append(row["relative_path"])
            if row["source_sha256"] and row["source_sha256"] not in hashes:
                hashes.append(row["source_sha256"])
            for key in totals:
                totals[key] += row[key]
        status = (
            "partial" if rows and all(row["status"] == "partial" for row in rows) else "unknown"
        )
        return {
            "status": status,
            "coverage_status": status,
            "count": len(rows),
            "authenticated": False,
            "provenance_authenticated": False,
            "target_app_attribution_verified": False,
            "click_attribution_verified": False,
            "closure_evaluated": False,
            "request_count": totals["request_count"],
            "script_count": totals["script_count"],
            "async_count": totals["async_count"],
            "action_count": totals["action_count"],
            "gaps": known_gaps,
            "actions": list(_ACTIONS),
            "relative_paths": paths,
            "source_sha256": hashes,
            "observations": rows,
        }
    except Exception:
        logger.error("web observation projection failed closed")
        return _unknown_document()
