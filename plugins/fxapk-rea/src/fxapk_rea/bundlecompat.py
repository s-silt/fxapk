"""旧观察回执与当前投影的契约比较。

schema 仍是 */1。没有 projection_revision 的已保存 v1 按该版本的旧必需字段校验。
只允许明确列出的本轮新增字段，以及字符串 gaps 列表的顺序差异。
少字段、旧值变化、未知新增字段都拒绝。补充投影不得把 partial 提升成 complete，
也不得把认证旗标写成真。
"""

from __future__ import annotations

VOLATILE = frozenset({"artifacts", "imported_at_utc", "acquisition", "tool_version"})
FLAGS = (
    "click_attribution_verified",
    "target_app_attribution_verified",
    "provenance_authenticated",
    "closure_evaluated",
)
TRACE_SCHEMA = "fxapk-cdp-trace-observation/1"
REA_SCHEMA = "rea-web-observation/1"
# 当前投影还不写这个键。将来两边同时带同一已知版本时，新增字段改为必需。
REVISION_KEY = "projection_revision"
TRACE_SESSION_REVISION = "trace-v1-session"
KNOWN_REVISIONS = frozenset({TRACE_SESSION_REVISION})

_COMMON = frozenset(
    {"schema_version", "producer", "coverage", "source", *FLAGS}
)
_REQUIRED: dict[tuple[str, str | None], dict[str, frozenset[str]]] = {
    (TRACE_SCHEMA, None): {
        "": _COMMON | {"capture", "requests"},
        "coverage": frozenset({"status", "gaps"}),
        "source": frozenset({"sha256", "relative_path"}),
        "capture": frozenset(
            {"target_id", "session_id", "origin", "id", "tool_version", "started_at"}
        ),
        "requests": frozenset(
            {
                "request_id",
                "original_ref",
                "hops",
                "stack_groups",
                "gaps",
                "observed_identity_bridge",
                "async_parent_present",
            }
        ),
        "requests/hops": frozenset(
            {
                "seq",
                "url",
                "original_ref",
                "frame_id",
                "loader_id",
                "epoch",
                "context_unique_id",
                "observed_identity_bridge",
                "async_parent_present",
                "stack_groups",
                "gaps",
            }
        ),
        "requests/hops/stack_groups": frozenset({"kind", "frames"}),
        "requests/hops/stack_groups/frames": frozenset(
            {
                "script_id",
                "context_id",
                "context_unique_id",
                "frame_id",
                "loader_id",
                "epoch",
                "original_ref",
                "source_ref",
                "function_name",
            }
        ),
        "requests/stack_groups": frozenset({"kind", "frames"}),
        "requests/stack_groups/frames": frozenset(
            {
                "script_id",
                "context_id",
                "context_unique_id",
                "frame_id",
                "loader_id",
                "epoch",
                "original_ref",
                "source_ref",
                "function_name",
            }
        ),
    },
    (REA_SCHEMA, None): {
        "": _COMMON
        | {
            "status",
            "provider",
            "target",
            "allowed_origins",
            "capture_window",
            "scripts",
            "requests",
            "console_events",
        },
        "coverage": frozenset({"status", "gaps"}),
        "source": frozenset({"sha256", "relative_path"}),
    },
}
# 无 revision 的 trace v1：这些键可以只出现在当前投影里。
# 旧 script_frame_id 迁移按帧身份核对，不占未来新增字段的 64 条预算，
# 也不再单设迁移条数上限。条数受原始包、事件和栈的既有上限约束。
_ADDED: dict[tuple[str, str | None], dict[str, frozenset[str]]] = {
    (TRACE_SCHEMA, None): {
        "": frozenset({"actions", "startup_interventions", "related_targets"}),
        "requests": frozenset({"session_id", "target_id"}),
        "requests/hops": frozenset({"session_id"}),
    }
}


class Compat:
    def __init__(self) -> None:
        self.ok = True
        self.gap_reordered = False
        self.added_paths: list[str] = []
        self.legacy_frame_paths: list[str] = []

    @property
    def changed(self) -> bool:
        return self.gap_reordered or bool(self.added_paths) or bool(self.legacy_frame_paths)


def _certifies(value: object) -> bool:
    if isinstance(value, dict):
        status = value.get("status")
        if status == "complete":
            return True
        coverage = value.get("coverage_status")
        if isinstance(coverage, str) and coverage != "partial":
            return True
        for key, item in value.items():
            if key in FLAGS and item is not False:
                return True
            if _certifies(item):
                return True
        return False
    if isinstance(value, list):
        return any(_certifies(item) for item in value)
    return False


def _shape(path: str) -> str:
    parts: list[str] = []
    for part in path.split("/"):
        if not part:
            continue
        if part.endswith("]") and "[" in part:
            part = part.split("[", 1)[0]
        parts.append(part)
    return "/".join(parts)


class _BadRevision:
    """两边的 projection_revision 不能按同一已知契约解释。"""


def _revision(saved: dict[str, object], fresh: dict[str, object]) -> str | None | _BadRevision:
    saved_has = REVISION_KEY in saved
    fresh_has = REVISION_KEY in fresh
    saved_rev = saved.get(REVISION_KEY)
    fresh_rev = fresh.get(REVISION_KEY)
    if saved_has != fresh_has or saved_rev != fresh_rev:
        return _BadRevision()
    if not saved_has:
        return None
    if not isinstance(saved_rev, str) or saved_rev not in KNOWN_REVISIONS:
        return _BadRevision()
    return saved_rev


def _tables(
    schema: str, revision: str | None
) -> tuple[dict[str, frozenset[str]], dict[str, frozenset[str]]]:
    required = dict(_REQUIRED.get((schema, None), {"": _COMMON}))
    added = dict(_ADDED.get((schema, None), {}))
    if schema == TRACE_SCHEMA and revision == TRACE_SESSION_REVISION:
        required["requests"] = required.get("requests", frozenset()) | {
            "session_id",
            "target_id",
        }
        required["requests/hops"] = required.get("requests/hops", frozenset()) | {"session_id"}
        added = {}
    elif revision is not None:
        added = {}
    return required, added


def _fail(result: Compat) -> None:
    result.ok = False


def _legacy_frame(saved: dict[str, object], fresh: dict[str, object], hop_frame_id: str) -> dict[str, object] | None:
    """Old traces stored the script frame in frame_id and omitted script_frame_id.

    Same-frame receipts may only gain script_frame_id equal to that frame.
    A cross-frame async receipt may move frame_id to the enclosing hop frame
    when the saved frame_id is the fresh script frame. Other differences stay
    mismatches. The returned object is a comparison copy.
    """
    if "script_frame_id" in saved or "script_frame_id" not in fresh:
        return None
    script_frame = fresh.get("script_frame_id")
    saved_frame = saved.get("frame_id")
    fresh_frame = fresh.get("frame_id")
    if not isinstance(script_frame, str) or script_frame == "" or saved_frame != script_frame:
        return None
    same = fresh_frame == saved_frame
    moved = (
        hop_frame_id != ""
        and fresh_frame == hop_frame_id
        and fresh_frame != saved_frame
    )
    if not same and not moved:
        return None
    adjusted = dict(saved)
    adjusted["frame_id"] = fresh_frame
    return adjusted


def _walk(
    saved: object,
    fresh: object,
    path: str,
    result: Compat,
    required: dict[str, frozenset[str]],
    added: dict[str, frozenset[str]],
    hop_frame_id: str = "",
) -> None:
    if isinstance(saved, dict) and isinstance(fresh, dict):
        shape = _shape(path)
        need = required.get(shape, frozenset())
        if any(key not in saved or key not in fresh for key in need):
            _fail(result)
            return
        if shape.endswith("frames"):
            adjusted = _legacy_frame(saved, fresh, hop_frame_id)
            if adjusted is not None:
                result.legacy_frame_paths.append(path or "frames")
                saved = adjusted
                allow = set(added.get(shape, frozenset()))
                allow.add("script_frame_id")
                added = {**added, shape: frozenset(allow)}
        child_hop = hop_frame_id
        if shape == "requests":
            hops = fresh.get("hops")
            if isinstance(hops, list) and hops and isinstance(hops[0], dict):
                # 请求级 stack 只复制首个 hop。多 hop 也只用这个身份，不能改挂到后面的 hop。
                if fresh.get("stack_groups") == hops[0].get("stack_groups"):
                    frame = hops[0].get("frame_id")
                    if isinstance(frame, str) and frame:
                        child_hop = frame
        if shape.endswith("hops"):
            frame = fresh.get("frame_id")
            if isinstance(frame, str):
                child_hop = frame
        for key in saved:
            if key in VOLATILE or key == REVISION_KEY:
                continue
            child = f"{path}/{key}" if path else key
            if key not in fresh:
                _fail(result)
                return
            _walk(saved[key], fresh[key], child, result, required, added, child_hop)
            if not result.ok:
                return
        allow = added.get(shape, frozenset())
        for key, item in fresh.items():
            if key in VOLATILE or key in saved or key == REVISION_KEY:
                continue
            child = f"{path}/{key}" if path else key
            if key not in allow or key in FLAGS or _certifies(item):
                _fail(result)
                return
            if key == "script_frame_id" and path in result.legacy_frame_paths:
                continue
            result.added_paths.append(child)
        return
    if isinstance(saved, list) and isinstance(fresh, list):
        if path.endswith("/gaps") or path == "gaps":
            if (
                all(isinstance(item, str) for item in saved)
                and all(isinstance(item, str) for item in fresh)
            ):
                if sorted(saved) != sorted(fresh):
                    _fail(result)
                elif saved != fresh:
                    result.gap_reordered = True
                return
        if len(saved) != len(fresh):
            _fail(result)
            return
        for index, (left, right) in enumerate(zip(saved, fresh, strict=True)):
            _walk(left, right, f"{path}[{index}]", result, required, added, hop_frame_id)
            if not result.ok:
                return
        return
    if saved != fresh:
        _fail(result)


def assess(saved: object, fresh: object) -> Compat:
    """比较去掉易变字段后的回执。ok 为假时不得挂接。"""
    result = Compat()
    if not isinstance(saved, dict) or not isinstance(fresh, dict):
        _fail(result)
        return result
    schema = saved.get("schema_version")
    if not isinstance(schema, str) or schema != fresh.get("schema_version"):
        _fail(result)
        return result
    revision = _revision(saved, fresh)
    if isinstance(revision, _BadRevision):
        _fail(result)
        return result
    required, added = _tables(schema, revision)
    top = required.get("", frozenset())
    if any(key not in saved or key not in fresh for key in top):
        _fail(result)
        return result
    for flag in FLAGS:
        if saved.get(flag) is not False or fresh.get(flag) is not False:
            _fail(result)
            return result
    saved_coverage = saved.get("coverage")
    fresh_coverage = fresh.get("coverage")
    if (
        not isinstance(saved_coverage, dict)
        or not isinstance(fresh_coverage, dict)
        or saved_coverage.get("status") != "partial"
        or fresh_coverage.get("status") != "partial"
    ):
        _fail(result)
        return result
    _walk(saved, fresh, "", result, required, added, "")
    if len(result.added_paths) > 64:
        _fail(result)
    result.added_paths.sort()
    return result
