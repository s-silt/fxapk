from __future__ import annotations

import json
import os
import tempfile
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from apkscan.core.integrity import sha256_hex, sha256_text

from .inventory import DISPOSITIONS, SCHEMA_VERSION as COVERAGE_SCHEMA_VERSION
from .inventory import audit_coverage
from .triage import normalize_host


DECISION_SCHEMA_VERSION = "phase2-decision/1.1"
MATERIALIZER_VERSION = "phase2-materialize/1.1"

_PARENT_SCOPE = "parent"
_MEMBER_SCOPE = "member"
_SCOPES = frozenset({_PARENT_SCOPE, _MEMBER_SCOPE})
_ACCEPTED = "accepted_clue"
_AUTO_BUCKETS = {
    "auto:duplicate_or_merged": "duplicate_or_merged",
    "auto:report_only": "report_only",
    "auto:excluded_with_reason": "excluded_with_reason",
}


class DecisionError(Exception):
    """判决处理失败。"""


class DecisionSchemaError(DecisionError):
    """判决记录不符合 schema。"""


class DecisionGraphError(DecisionError):
    """判决 supersedes 图不合法。"""


class MaterializationError(DecisionError):
    """物化前置或后置校验失败。"""


@dataclass(frozen=True)
class GraphState:
    """全量判决图的确定性校验结果。"""

    decisions: tuple[dict[str, Any], ...]
    active_by_unit: Mapping[tuple[str, str], dict[str, Any]]
    orphaned: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class MaterializationResult:
    """物化结果及报告。"""

    coverage: dict[str, Any]
    report: dict[str, Any]


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _read_json_object(line: str, line_number: int) -> dict[str, Any]:
    try:
        value = json.loads(line)
    except json.JSONDecodeError as exc:
        raise DecisionSchemaError(
            f"decisions.jsonl 第 {line_number} 行不是合法 JSON: {exc.msg}"
        ) from exc
    if not isinstance(value, dict):
        raise DecisionSchemaError(
            f"decisions.jsonl 第 {line_number} 行必须是 JSON 对象"
        )
    return value


def _require_string(
    record: Mapping[str, Any],
    key: str,
    *,
    allow_empty: bool = False,
) -> str:
    value = record.get(key)
    if not isinstance(value, str):
        raise DecisionSchemaError(f"字段 {key} 必须是字符串")
    if not allow_empty and not value:
        raise DecisionSchemaError(f"字段 {key} 不能为空")
    return value


def _require_nullable_string(
    record: Mapping[str, Any],
    key: str,
) -> str | None:
    value = record.get(key)
    if value is not None and not isinstance(value, str):
        raise DecisionSchemaError(f"字段 {key} 必须是字符串或 null")
    return value


def _require_string_list(record: Mapping[str, Any], key: str) -> list[str]:
    value = record.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise DecisionSchemaError(f"字段 {key} 必须是字符串数组")
    return value


def logical_unit(record: Mapping[str, Any]) -> tuple[str, str]:
    """返回判决所属逻辑单元。"""
    scope = record.get("scope")
    if scope == _PARENT_SCOPE:
        return scope, _require_string(record, "parent_id")
    if scope == _MEMBER_SCOPE:
        return scope, _require_string(record, "candidate_id")
    raise DecisionSchemaError("scope 必须为 parent 或 member")


def members_hash(member_candidate_ids: Iterable[str]) -> str:
    """按规格计算逻辑单元成员集哈希。"""
    members = sorted(set(member_candidate_ids))
    return "mh:" + sha256_text("\n".join(members))


def signals_hash(signals: Iterable[Any]) -> str:
    """signals_hash 唯一口径（复审 P1#2）：sha256("\\n".join(sorted(str(s))))。
    decide / decide-member / decide-batch / replay / cli 全部调用它，杜绝多口径假漂移。"""
    return sha256_text("\n".join(sorted(str(signal) for signal in signals)))


def decision_id_for_payload(payload: Mapping[str, Any]) -> str:
    """根据去除 decision_id 的规范化 payload 计算判决 ID。"""
    material = dict(payload)
    material.pop("decision_id", None)
    return "d2:" + sha256_text(_canonical_json(material))[:32]


def validate_decision_record(
    record: Mapping[str, Any],
    *,
    members_by_parent: Mapping[str, Iterable[str]] | None = None,
    known_clue_ids: set[str] | None = None,
    expected_case_id: str | None = None,
) -> None:
    """校验单条判决记录的 schema 闭合性。"""
    required = {
        "schema_version",
        "decision_id",
        "event_id",
        "case_id",
        "decided_at",
        "decided_by",
        "scope",
        "parent_id",
        "candidate_id",
        "disposition",
        "reason",
        "next_action",
        "accepts",
        "clue_id",
        "supersedes",
        "members_hash",
        "decided_against",
        "note",
    }
    missing = sorted(required - set(record))
    if missing:
        raise DecisionSchemaError(f"判决缺少字段: {', '.join(missing)}")

    if record["schema_version"] != DECISION_SCHEMA_VERSION:
        raise DecisionSchemaError(
            f"不支持的判决 schema_version: {record['schema_version']!r}"
        )

    decision_id = _require_string(record, "decision_id")
    if not decision_id.startswith("d2:"):
        raise DecisionSchemaError("decision_id 必须以 d2: 开头")
    _require_string(record, "event_id")
    case_id = _require_string(record, "case_id")
    if expected_case_id is not None and case_id != expected_case_id:
        raise DecisionSchemaError(
            f"case_id 不匹配: 期望 {expected_case_id!r}，实际 {case_id!r}"
        )
    _require_string(record, "decided_at")
    _require_string(record, "decided_by")
    scope = record["scope"]
    if scope not in _SCOPES:
        raise DecisionSchemaError("scope 必须为 parent 或 member")

    parent_id = _require_nullable_string(record, "parent_id")
    candidate_id = _require_nullable_string(record, "candidate_id")
    disposition = record["disposition"]
    if disposition not in DISPOSITIONS:
        raise DecisionSchemaError(f"非法 disposition: {disposition!r}")

    reason = _require_nullable_string(record, "reason")
    next_action = _require_nullable_string(record, "next_action")
    clue_id = _require_nullable_string(record, "clue_id")

    if scope == _PARENT_SCOPE:
        if not parent_id:
            raise DecisionSchemaError("parent scope 必须有 parent_id")
        if candidate_id is not None:
            raise DecisionSchemaError("parent scope 的 candidate_id 必须为 null")
    else:
        if parent_id is None:
            raise DecisionSchemaError("member scope 必须冗余记录 parent_id")
        if not candidate_id:
            raise DecisionSchemaError("member scope 必须有 candidate_id")
        # member 的 candidate 必须真属于其冗余记录的 parent（复审 P2#6），否则留下错误审计元数据
        if members_by_parent is not None and candidate_id not in set(
            members_by_parent.get(parent_id, ())
        ):
            raise DecisionSchemaError(
                f"member scope 的 candidate {candidate_id} 不属于 parent {parent_id}"
            )

    if disposition != _ACCEPTED and not reason:
        raise DecisionSchemaError("非 accepted_clue 判决必须填写 reason")
    if disposition == "pending_with_action" and not next_action:
        raise DecisionSchemaError("pending_with_action 必须填写 next_action")
    if disposition != "pending_with_action" and next_action is not None:
        raise DecisionSchemaError("仅 pending_with_action 可以填写 next_action")
    if disposition != _ACCEPTED and clue_id is not None:
        raise DecisionSchemaError("非 accepted_clue 判决的 clue_id 必须为 null")

    accepts = record["accepts"]
    if not isinstance(accepts, list):
        raise DecisionSchemaError("accepts 必须是数组")

    supersedes = _require_string_list(record, "supersedes")
    if len(set(supersedes)) != len(supersedes):
        raise DecisionSchemaError("supersedes 不得包含重复 decision_id")

    if scope == _PARENT_SCOPE and disposition == _ACCEPTED:
        if not accepts:
            raise DecisionSchemaError(
                "parent scope accepted_clue 必须至少点名一个 candidate"
            )
        if clue_id is not None:
            raise DecisionSchemaError(
                "parent scope accepted_clue 的顶层 clue_id 必须为 null"
            )
        if members_by_parent is not None:
            members = set(members_by_parent.get(parent_id or "", ()))
        else:
            members = None

        accepted_candidates: list[str] = []
        accepted_clues: list[str] = []
        for item in accepts:
            if not isinstance(item, dict):
                raise DecisionSchemaError("accepts 每一项必须是对象")
            item_candidate = item.get("candidate_id")
            item_clue = item.get("clue_id")
            if not isinstance(item_candidate, str) or not item_candidate:
                raise DecisionSchemaError("accepts.candidate_id 必须是非空字符串")
            if not isinstance(item_clue, str) or not item_clue:
                raise DecisionSchemaError("accepts.clue_id 必须是非空字符串")
            accepted_candidates.append(item_candidate)
            accepted_clues.append(item_clue)
            if members is not None and item_candidate not in members:
                raise DecisionSchemaError(
                    f"accepts 点名了不属于 parent {parent_id} 的 candidate "
                    f"{item_candidate}"
                )
        if len(set(accepted_candidates)) != len(accepted_candidates):
            raise DecisionSchemaError("accepts 内 candidate_id 不得重复")
        if len(set(accepted_clues)) != len(accepted_clues):
            raise DecisionSchemaError("accepts 内 clue_id 不得重复")
    elif scope == _MEMBER_SCOPE and disposition == _ACCEPTED:
        if not clue_id:
            raise DecisionSchemaError(
                "member scope accepted_clue 必须填写顶层 clue_id"
            )
        if accepts:
            raise DecisionSchemaError(
                "member scope accepted_clue 的 accepts 必须为空"
            )
    else:
        if accepts:
            raise DecisionSchemaError("非 accepted_clue 的 accepts 必须为空")
        if clue_id is not None:
            raise DecisionSchemaError("非 accepted_clue 的顶层 clue_id 必须为 null")

    if known_clue_ids is not None:
        clue_values: list[str] = []
        if clue_id is not None:
            clue_values.append(clue_id)
        clue_values.extend(
            item["clue_id"]
            for item in accepts
            if isinstance(item, dict) and isinstance(item.get("clue_id"), str)
        )
        unknown = sorted(set(clue_values) - known_clue_ids)
        if unknown:
            raise DecisionSchemaError(
                f"判决引用不存在的 clue_id: {', '.join(unknown)}"
            )

    mh_value = record["members_hash"]
    if not isinstance(mh_value, str) or not mh_value.startswith("mh:"):
        raise DecisionSchemaError("members_hash 必须是 mh: 前缀字符串")
    decided_against = record["decided_against"]
    if not isinstance(decided_against, dict):
        raise DecisionSchemaError("decided_against 必须是对象")
    for key in (
        "inventory_fingerprint",
        "triage_bucket",
        "triage_tier",
        "signals_hash",
    ):
        if not isinstance(decided_against.get(key), str):
            raise DecisionSchemaError(
                f"decided_against.{key} 必须是字符串"
            )
    if not isinstance(record["note"], str):
        raise DecisionSchemaError("note 必须是字符串")

    expected_id = decision_id_for_payload(record)
    if expected_id != decision_id:
        raise DecisionSchemaError(
            f"decision_id 校验失败: 期望 {expected_id}，实际 {decision_id}"
        )


def load_decisions(
    path: Path,
    *,
    members_by_parent: Mapping[str, Iterable[str]] | None = None,
    known_clue_ids: set[str] | None = None,
    expected_case_id: str | None = None,
) -> tuple[dict[str, Any], ...]:
    """读取并校验 decisions.jsonl 的每一行，不跳过任何坏行。"""
    if not path.exists():
        return ()

    decisions: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for line_number, raw_line in enumerate(handle, 1):
            if not raw_line.strip():
                raise DecisionSchemaError(
                    f"decisions.jsonl 第 {line_number} 行为空行"
                )
            record = _read_json_object(raw_line, line_number)
            validate_decision_record(
                record,
                members_by_parent=members_by_parent,
                known_clue_ids=known_clue_ids,
                expected_case_id=expected_case_id,
            )
            decisions.append(record)
    return tuple(decisions)


def _decision_fingerprint(decisions: Sequence[Mapping[str, Any]]) -> str:
    normalized = "\n".join(_canonical_json(dict(item)) for item in decisions)
    return sha256_text(normalized)


def _decision_file_sha256(path: Path) -> str:
    """判决账本当前字节。缺文件抛 ``OSError``，不用空哈希冒充已落盘账本。"""
    from apkscan.core.phase2.chain import file_sha256

    return file_sha256(path)


def ensure_decision_ledger(path: Path) -> str:
    """自动结案在物化时落一份显式空账本，返回该文件当前字节的哈希。

    已有文件原样保留。缺文件才创建空文件；之后删掉它，gate 不能再把它读成
    从未建账。
    """
    if path.exists() and not path.is_file():
        raise OSError(f"判决账本不是文件：{path}")
    if not path.is_file():
        _atomic_write_text(path, "")
    return _decision_file_sha256(path)


def validate_decision_graph(
    decisions: Sequence[Mapping[str, Any]],
    *,
    inventory_candidate_ids: set[str] | None = None,
    triage_parent_ids: set[str] | None = None,
    members_by_parent: Mapping[str, Iterable[str]] | None = None,
) -> GraphState:
    """校验 supersedes 全图并返回每个逻辑单元唯一活动末端。"""
    ids: dict[str, dict[str, Any]] = {}
    events: dict[str, dict[str, Any]] = {}
    units: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    superseded: set[str] = set()

    for record in decisions:
        validate_decision_record(
            record,
            members_by_parent=members_by_parent,
        )
        decision_id = record["decision_id"]
        event_id = record["event_id"]
        if decision_id in ids:
            raise DecisionGraphError(f"decision_id 重复: {decision_id}")
        if event_id in events:
            raise DecisionGraphError(f"event_id 重复: {event_id}")
        ids[decision_id] = dict(record)
        events[event_id] = dict(record)
        unit = logical_unit(record)
        units[unit].append(dict(record))

        for target in record["supersedes"]:
            if target == decision_id:
                raise DecisionGraphError(f"判决 {decision_id} 存在自环")
            if target not in ids:
                raise DecisionGraphError(
                    f"判决 {decision_id} 前向引用或断链: {target}"
                )
            target_record = ids[target]
            if logical_unit(target_record) != unit:
                raise DecisionGraphError(
                    f"判决 {decision_id} 跨逻辑单元 supersede: {target}"
                )
            superseded.add(target)

    adjacency: dict[str, tuple[str, ...]] = {
        record["decision_id"]: tuple(record["supersedes"])
        for record in decisions
    }
    visiting: set[str] = set()
    visited: set[str] = set()

    for decision_id in sorted(adjacency):
        stack = [(decision_id, False)]
        while stack:
            node, leaving = stack.pop()
            if leaving:
                visiting.remove(node)
                visited.add(node)
                continue
            if node in visiting:
                raise DecisionGraphError(f"supersedes 图存在环: {node}")
            if node in visited:
                continue
            visiting.add(node)
            stack.append((node, True))
            stack.extend((target, False) for target in reversed(adjacency.get(node, ())))

    active_by_unit: dict[tuple[str, str], dict[str, Any]] = {}
    for unit, unit_records in sorted(units.items()):
        active = [
            record
            for record in unit_records
            if record["decision_id"] not in superseded
        ]
        if len(active) != 1:
            active_ids = sorted(record["decision_id"] for record in active)
            raise DecisionGraphError(
                f"逻辑单元 {unit[0]}:{unit[1]} 活动末端数量为 "
                f"{len(active)}: {', '.join(active_ids)}"
            )
        active_by_unit[unit] = active[0]

    active_parent_accepts: dict[str, str] = {}
    for (scope, key), record in active_by_unit.items():
        if scope == _PARENT_SCOPE and record["disposition"] == _ACCEPTED:
            for item in record["accepts"]:
                active_parent_accepts[item["candidate_id"]] = record["decision_id"]

    for (scope, key), record in active_by_unit.items():
        if scope == _MEMBER_SCOPE:
            candidate_id = record["candidate_id"]
            if candidate_id in active_parent_accepts:
                raise DecisionGraphError(
                    f"candidate {candidate_id} 同时被 member 判决 "
                    f"{record['decision_id']} 和 parent 判决 "
                    f"{active_parent_accepts[candidate_id]} 活动接受"
                )

    orphaned: list[dict[str, Any]] = []
    for (scope, key), record in sorted(active_by_unit.items()):
        if scope == _MEMBER_SCOPE:
            if (
                inventory_candidate_ids is not None
                and key not in inventory_candidate_ids
            ):
                orphaned.append(record)
        elif (
            triage_parent_ids is not None
            and key not in triage_parent_ids
        ):
            orphaned.append(record)

    return GraphState(
        decisions=tuple(dict(item) for item in decisions),
        active_by_unit=active_by_unit,
        orphaned=tuple(orphaned),
    )


def _candidate_ids(inventory: Any) -> tuple[str, ...]:
    return tuple(candidate.candidate_id for candidate in inventory.candidates)


def _parent_members(triage: Any) -> dict[str, tuple[str, ...]]:
    return {
        proposal.parent_id: tuple(proposal.member_candidate_ids)
        for proposal in triage.parents
    }


def _proposal_map(triage: Any) -> dict[str, Any]:
    return {proposal.parent_id: proposal for proposal in triage.parents}


def _known_clue_ids(clue_records: Sequence[Mapping[str, Any]]) -> set[str]:
    result: set[str] = set()
    for record in clue_records:
        clue_id = record.get("clue_id")
        if isinstance(clue_id, str) and clue_id:
            result.add(clue_id)
    return result


def _entry_from_decision(
    candidate: Any,
    decision: Mapping[str, Any],
) -> dict[str, Any]:
    candidate_id = candidate.candidate_id
    disposition = decision["disposition"]
    result: dict[str, Any] = {
        "candidate_id": candidate_id,
        "disposition": disposition,
        "materialized_from": f"decision:{decision['decision_id']}",
    }

    if disposition == _ACCEPTED:
        if decision["scope"] == _MEMBER_SCOPE:
            clue_id = decision["clue_id"]
        else:
            selected = [
                item
                for item in decision["accepts"]
                if item["candidate_id"] == candidate_id
            ]
            if selected:
                clue_id = selected[0]["clue_id"]
            else:
                clue_id = None
        if clue_id is not None:
            result["clue_id"] = clue_id
            result["provenance"] = candidate.provenance_dict()
            return result

        selected_candidate = sorted(
            item["candidate_id"] for item in decision["accepts"]
        )[0]
        return {
            "candidate_id": candidate_id,
            "disposition": "duplicate_or_merged",
            "reason": (
                "同 parent 证据成员，结论由判决 "
                f"{decision['decision_id']} 点名的 accepted candidate 承载"
            ),
            "materialized_from": f"decision:{decision['decision_id']}",
            "propagation": "accepted_parent_unselected_member",
            "merged_into_candidate_id": selected_candidate,
            "source_decision_id": decision["decision_id"],
        }

    reason = decision["reason"]
    if reason is not None:
        result["reason"] = f"[判决 {decision['decision_id']}] {reason}"
    if disposition == "pending_with_action":
        result["next_action"] = decision["next_action"]
    return result


def materialize_snapshot(
    inventory: Any,
    triage: Any,
    decisions: Sequence[Mapping[str, Any]],
    clue_records: Sequence[Mapping[str, Any]],
    *,
    case_id: str,
    decisions_fingerprint: str | None = None,
) -> MaterializationResult:
    """纯内存确定性物化；失败时不产生任何文件。"""
    issues = getattr(inventory, "issues", ())
    if issues:
        raise MaterializationError(
            "Phase1 inventory 存在问题: "
            + ", ".join(str(getattr(issue, "code", issue)) for issue in issues)
        )

    parent_members = _parent_members(triage)
    candidate_ids = set(_candidate_ids(inventory))
    parent_ids = set(parent_members)
    graph = validate_decision_graph(
        decisions,
        inventory_candidate_ids=candidate_ids,
        triage_parent_ids=parent_ids,
        members_by_parent=parent_members,
    )
    # ★members_hash 漂移检测（复审 P1#2）：判决记录的成员集快照必须与当前 triage 成员集一致。
    # 否则 Phase1 补包后旧 parent 判决会静默把新成员降 duplicate_or_merged。漂移（含 key 已不在
    # 当前 inventory/triage）的判决不传播、记入 stale 报告，其 candidate 回落 auto/skeleton，
    # 等 replay（期2c）迁移——决不静默套用过期判决。
    stale_decisions: list[dict[str, Any]] = []
    active_members: dict[str, dict[str, Any]] = {}
    active_parents: dict[str, dict[str, Any]] = {}
    for (scope, key), value in sorted(graph.active_by_unit.items()):
        if scope == _MEMBER_SCOPE:
            if key not in candidate_ids or value.get("members_hash") != members_hash([key]):
                stale_decisions.append(value)
            else:
                active_members[key] = value
        else:
            if value.get("members_hash") != members_hash(parent_members.get(key, ())):
                stale_decisions.append(value)
            else:
                active_parents[key] = value
    proposals = _proposal_map(triage)
    entries: list[dict[str, Any]] = []

    for candidate in inventory.candidates:
        candidate_id = candidate.candidate_id
        member_decision = active_members.get(candidate_id)
        if member_decision is not None:
            entries.append(_entry_from_decision(candidate, member_decision))
            continue

        parent_id = candidate.parent_id
        parent_decision = active_parents.get(parent_id)
        if parent_decision is not None:
            entries.append(_entry_from_decision(candidate, parent_decision))
            continue

        proposal = proposals.get(parent_id)
        if proposal is not None and proposal.bucket in _AUTO_BUCKETS:
            entries.append(
                {
                    "candidate_id": candidate_id,
                    "disposition": _AUTO_BUCKETS[proposal.bucket],
                    "reason": f"[auto:triage {proposal.tier}] {proposal.why}",
                    "materialized_from": "auto:triage",
                }
            )
            continue

        tier = proposal.tier if proposal is not None else "unknown"
        entries.append(
            {
                "candidate_id": candidate_id,
                "disposition": "pending_with_action",
                "reason": f"human 队列尚未判决（{tier}）",
                "next_action": "在 queue.md 复核该 parent 并用 decide 记录判决",
                "materialized_from": "skeleton",
            }
        )

    entries.sort(key=lambda item: item["candidate_id"])  # 显式规范序（复审 P2#5）
    actual_ids = [entry["candidate_id"] for entry in entries]
    expected_ids = list(_candidate_ids(inventory))
    if sorted(actual_ids) != sorted(expected_ids):
        raise MaterializationError(
            "物化 candidate_id 守恒失败: "
            f"expected={len(expected_ids)}, actual={len(actual_ids)}"
        )

    snapshot: dict[str, Any] = {
        "schema_version": COVERAGE_SCHEMA_VERSION,
        "case_id": case_id,
        "inventory_fingerprint": inventory.fingerprint,
        "entries": entries,
        "decisions_fingerprint": (
            decisions_fingerprint
            if decisions_fingerprint is not None
            else _decision_fingerprint(decisions)
        ),
        "materializer_version": MATERIALIZER_VERSION,
    }

    # 内嵌自检只校验 snapshot 结构自洽 + 本次判决实际 accept 的 clue 存在且对齐，
    # 不校验"全量已出线索是否都已 accept"（那是 gate 的职责）。否则零判决/部分判决时，
    # 尚未 accept 的已出 phase1 线索会误报 clue_not_accepted，令 materialize 无法运行。
    # ★只取最终 entries 里真正物化为 accepted_clue 的 clue（复审 P1#1）：遍历全部历史 decisions
    # 会把被 supersede 的旧 accepted clue 也纳入，令合法推翻（accepted→excluded）无法物化。
    accepted_clue_ids = {
        str(entry["clue_id"])
        for entry in entries
        if entry["disposition"] == _ACCEPTED and entry.get("clue_id")
    }
    self_check_clues = [
        record for record in clue_records
        if record.get("clue_id") in accepted_clue_ids
    ]
    audit = audit_coverage(inventory, snapshot, self_check_clues)
    blockers = list(getattr(audit, "blockers", ()))
    if not getattr(audit, "ok", False) or blockers:
        raise MaterializationError(
            "物化结果未通过 coverage audit: "
            + ", ".join(str(item) for item in blockers)
        )

    stale_ids = sorted(record["decision_id"] for record in stale_decisions)
    report = {
        "schema_version": MATERIALIZER_VERSION,
        "case_id": case_id,
        "decisions_fingerprint": snapshot["decisions_fingerprint"],
        "stale_decisions": stale_ids,
        "warning_count": len(stale_ids),
        "entry_count": len(entries),
    }
    return MaterializationResult(coverage=snapshot, report=report)


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
        text=True,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def write_materialization(
    result: MaterializationResult,
    *,
    phase2_dir: Path,
) -> None:
    """原子写入 coverage.json 和 materialize_report.json。"""
    coverage_text = _canonical_json(result.coverage) + "\n"
    report_text = _canonical_json(result.report) + "\n"
    _atomic_write_text(phase2_dir / "coverage.json", coverage_text)
    _atomic_write_text(phase2_dir / "materialize_report.json", report_text)


def _load_clue_records(path: Path) -> list[dict[str, Any]]:
    from .inventory import load_clue_records

    return load_clue_records(path)


def materialize_case(
    case_dir: Path,
    *,
    inventory: Any,
    triage: Any,
    decisions_path: Path | None = None,
    clue_records_path: Path | None = None,
    dry_run: bool = False,
) -> MaterializationResult:
    """编排单 case 的读取、校验、纯物化和原子写入。"""
    case_id = str(inventory.case_id)
    if not case_id:
        raise MaterializationError(
            "inventory.case_id 为空；case_id 只来自显式 --case-id 或 manifest"
        )
    phase2_dir = case_dir / "phase2"
    decisions_file = decisions_path or phase2_dir / "decisions.jsonl"
    if clue_records_path is not None:
        clue_records = _load_clue_records(clue_records_path)
    else:
        default_clues = case_dir / "clue_records.jsonl"
        clue_records = _load_clue_records(default_clues) if default_clues.exists() else []

    parent_members = _parent_members(triage)
    decisions = load_decisions(
        decisions_file,
        members_by_parent=parent_members,
        known_clue_ids=_known_clue_ids(clue_records),
        expected_case_id=case_id,
    )
    result = materialize_snapshot(
        inventory,
        triage,
        decisions,
        clue_records,
        case_id=case_id,
        decisions_fingerprint=_decision_fingerprint(decisions),
    )
    if not dry_run:
        # 先落真实空账本再钉字节。dry-run 不写文件，也不把缺失记成空哈希。
        result.coverage["decisions_sha256"] = ensure_decision_ledger(decisions_file)
        write_materialization(result, phase2_dir=phase2_dir)
    return result


def _iso8601_seconds() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def build_decision(
    *,
    case_id: str,
    decided_by: str,
    scope: str,
    parent_id: str,
    candidate_id: str | None,
    disposition: str,
    reason: str | None,
    next_action: str | None,
    accepts: Sequence[Mapping[str, str]],
    clue_id: str | None,
    supersedes: Sequence[str],
    members_hash_value: str,
    decided_against: Mapping[str, str],
    note: str = "",
    event_id: str | None = None,
    decided_at: str | None = None,
) -> dict[str, Any]:
    """构造带确定性 decision_id 的判决记录。"""
    payload: dict[str, Any] = {
        "schema_version": DECISION_SCHEMA_VERSION,
        "event_id": event_id or str(uuid.uuid4()),
        "case_id": case_id,
        "decided_at": decided_at or _iso8601_seconds(),
        "decided_by": decided_by,
        "scope": scope,
        "parent_id": parent_id,
        "candidate_id": candidate_id,
        "disposition": disposition,
        "reason": reason,
        "next_action": next_action,
        "accepts": [dict(item) for item in accepts],
        "clue_id": clue_id,
        "supersedes": list(supersedes),
        "members_hash": members_hash_value,
        "decided_against": dict(decided_against),
        "note": note,
    }
    payload["decision_id"] = decision_id_for_payload(payload)
    return payload


def _intent_decided_against(proposal: Any, fingerprint: str) -> dict[str, str]:
    signals = tuple(str(s) for s in _gate_get(proposal, "signals", ()))
    return {
        "inventory_fingerprint": fingerprint,
        "triage_bucket": str(_gate_get(proposal, "bucket", "")),
        "triage_tier": str(_gate_get(proposal, "tier", "")),
        "signals_hash": signals_hash(signals),
    }


def build_decisions_from_intents(
    inventory: Any,
    triage: Any,
    intents: Sequence[Mapping[str, Any]],
    *,
    case_id: str,
    decided_by: str,
) -> list[dict[str, Any]]:
    """把一批判决意图一次性构造成 decision 列表：★只 build 一次 triage，杜绝逐条 decide 的
    296×0.7s 重算（耗时优化）。校验/图/CAS 仍由 append_decisions 兜底。

    每条 intent：{"scope":"parent"|"member"（默认 parent）,
      parent：<parent_id 或唯一前缀>；member 用 "candidate"：<candidate_id 或前缀>,
      "disposition":<6 值>, "reason"?, "next_action"?,
      "accepts"?:[{"candidate":<前缀>,"clue":<clue_id>}]（仅 parent accepted），
      "clue_id"?（仅 member accepted），"supersedes"?:[decision_id...]}
    """
    parents = list(_gate_get(triage, "parents", ()))
    parent_members = {
        str(_gate_get(p, "parent_id")): tuple(
            str(m) for m in _gate_get(p, "member_candidate_ids", ()))
        for p in parents
    }
    proposals = {str(_gate_get(p, "parent_id")): p for p in parents}
    cand_to_parent = {
        str(cid): str(_gate_get(p, "parent_id"))
        for p in parents for cid in _gate_get(p, "member_candidate_ids", ())
    }
    fingerprint = str(_gate_get(inventory, "fingerprint", ""))
    result: list[dict[str, Any]] = []
    for idx, intent in enumerate(intents, 1):
        # ★结构护栏（判决批量复审 P2#2）：一行 JSON 若是 null/数字/数组，或 accepts 不是
        #   对象数组，下面的 intent.get / 迭代会抛 AttributeError/TypeError——那不在
        #   _cmd_decide_file 的捕获列表里，会漏成 traceback。先在这里转成 DecisionError。
        if not isinstance(intent, Mapping):
            raise DecisionError(
                f"第 {idx} 条判决意图不是 JSON 对象：{type(intent).__name__}")
        raw_accepts = intent.get("accepts", ())
        if not isinstance(raw_accepts, (list, tuple)):
            raise DecisionError(
                f"第 {idx} 条 accepts 必须是数组，实为 {type(raw_accepts).__name__}")
        if any(not isinstance(a, Mapping) for a in raw_accepts):
            raise DecisionError(f"第 {idx} 条 accepts 的每个元素都必须是对象")
        scope = str(intent.get("scope", _PARENT_SCOPE))
        if scope == _PARENT_SCOPE:
            resolved = resolve_unique_prefix(str(intent["parent"]), parent_members, label="parent")
            proposal = proposals[resolved]
            member_ids = parent_members[resolved]
            accepts = [
                {"candidate_id": resolve_unique_prefix(str(a["candidate"]), member_ids, label="candidate"),
                 "clue_id": str(a["clue"])}
                for a in intent.get("accepts", ())
            ]
            result.append(build_decision(
                case_id=case_id, decided_by=decided_by, scope="parent", parent_id=resolved,
                candidate_id=None, disposition=str(intent["disposition"]),
                reason=intent.get("reason"), next_action=intent.get("next_action"),
                accepts=accepts, clue_id=None, supersedes=list(intent.get("supersedes", ())),
                members_hash_value=members_hash(member_ids),
                decided_against=_intent_decided_against(proposal, fingerprint)))
        else:
            cand = resolve_unique_prefix(str(intent["candidate"]), list(cand_to_parent), label="candidate")
            parent_id = cand_to_parent[cand]
            result.append(build_decision(
                case_id=case_id, decided_by=decided_by, scope="member", parent_id=parent_id,
                candidate_id=cand, disposition=str(intent["disposition"]),
                reason=intent.get("reason"), next_action=intent.get("next_action"),
                accepts=[], clue_id=intent.get("clue_id"), supersedes=list(intent.get("supersedes", ())),
                members_hash_value=members_hash([cand]),
                decided_against=_intent_decided_against(proposals[parent_id], fingerprint)))
    return result


def _active_for_unit(
    decisions: Sequence[Mapping[str, Any]],
    unit: tuple[str, str],
) -> list[dict[str, Any]]:
    records = [dict(item) for item in decisions if logical_unit(item) == unit]
    superseded = {
        target
        for record in records
        for target in record["supersedes"]
    }
    return [
        record
        for record in records
        if record["decision_id"] not in superseded
    ]


def validate_new_decision(
    new_decision: Mapping[str, Any],
    existing_decisions: Sequence[Mapping[str, Any]],
    *,
    members_by_parent: Mapping[str, Iterable[str]],
    inventory_candidate_ids: set[str],
    known_clue_ids: set[str],
    case_id: str,
) -> None:
    """校验新判决及其对已有活动末端的收敛语义。"""
    validate_decision_record(
        new_decision,
        members_by_parent=members_by_parent,
        known_clue_ids=known_clue_ids,
        expected_case_id=case_id,
    )
    unit = logical_unit(new_decision)
    active = _active_for_unit(existing_decisions, unit)
    active_ids = {record["decision_id"] for record in active}
    supplied = set(new_decision["supersedes"])

    if active and not supplied:
        raise DecisionGraphError(
            f"逻辑单元 {unit[0]}:{unit[1]} 已有活动判决，必须提供 supersedes: "
            + ", ".join(sorted(active_ids))
        )
    if not supplied.issubset(active_ids):
        stale = sorted(supplied - active_ids)
        raise DecisionGraphError(
            "supersedes 必须只指向当前活动末端，非法目标: "
            + ", ".join(stale)
        )
    if active_ids and supplied != active_ids:
        missing = sorted(active_ids - supplied)
        raise DecisionGraphError(
            "supersedes 必须一次收敛该单元全部活动末端，遗漏: "
            + ", ".join(missing)
        )

    validate_decision_graph(
        (*existing_decisions, dict(new_decision)),
        inventory_candidate_ids=inventory_candidate_ids,
        triage_parent_ids=set(members_by_parent),
        members_by_parent=members_by_parent,
    )


def append_decision(
    path: Path,
    decision: Mapping[str, Any],
    *,
    members_by_parent: Mapping[str, Iterable[str]],
    inventory_candidate_ids: set[str],
    known_clue_ids: set[str],
    case_id: str,
) -> tuple[dict[str, Any], ...]:
    """读全量、校验新行、原子重写 decisions.jsonl。"""
    before = path.read_bytes() if path.exists() else b""
    existing = load_decisions(
        path,
        members_by_parent=members_by_parent,
        known_clue_ids=known_clue_ids,
        expected_case_id=case_id,
    )
    validate_new_decision(
        decision,
        existing,
        members_by_parent=members_by_parent,
        inventory_candidate_ids=inventory_candidate_ids,
        known_clue_ids=known_clue_ids,
        case_id=case_id,
    )
    all_decisions = (*existing, dict(decision))
    text = "".join(_canonical_json(item) + "\n" for item in all_decisions)
    # compare-and-swap（复审 P1#3）：写盘前重读，确认 decisions.jsonl 未被其他进程改动，
    # 缩小无锁 read→validate→replace 的 lost-update 竞态窗口；冲突则拒绝、要求重跑。
    after = path.read_bytes() if path.exists() else b""
    if after != before:
        raise DecisionGraphError("decisions.jsonl 在校验期间被其他进程修改，请重跑 decide")
    _atomic_write_text(path, text)
    return all_decisions


def append_decisions(
    path: Path,
    new_decisions: Sequence[Mapping[str, Any]],
    *,
    members_by_parent: Mapping[str, Iterable[str]],
    inventory_candidate_ids: set[str],
    known_clue_ids: set[str],
    case_id: str,
    dry_run: bool = False,
) -> tuple[dict[str, Any], ...]:
    """整批原子追加（复审 P2#5）：对累积集合逐条校验，一次 CAS + 一次 replace，杜绝半批。

    ★dry_run=True 走**完全相同**的「读台账 + 逐条 validate_new_decision」，只是不落盘。
      判决批量的 --dry-run 必须经此路径，否则预检报「将写入 N 条」而真跑被 supersedes /
      known-clue / 同批冲突拒绝，dry-run 的成功状态就是假的（判决批量复审 P2#3）。
    """
    before = path.read_bytes() if path.exists() else b""
    accumulated = list(load_decisions(
        path, members_by_parent=members_by_parent,
        known_clue_ids=known_clue_ids, expected_case_id=case_id))
    for decision in new_decisions:
        validate_new_decision(
            decision, accumulated, members_by_parent=members_by_parent,
            inventory_candidate_ids=inventory_candidate_ids,
            known_clue_ids=known_clue_ids, case_id=case_id)
        accumulated.append(dict(decision))
    if dry_run:
        return tuple(accumulated)  # 校验全过、但不写盘
    text = "".join(_canonical_json(item) + "\n" for item in accumulated)
    after = path.read_bytes() if path.exists() else b""
    if after != before:
        raise DecisionGraphError("decisions.jsonl 在校验期间被其他进程修改，请重跑 decide-batch")
    _atomic_write_text(path, text)
    return tuple(accumulated)


def resolve_unique_prefix(
    value: str,
    candidates: Iterable[str],
    *,
    label: str,
) -> str:
    """解析精确值或唯一前缀；歧义和不存在均失败。"""
    ordered = sorted(set(candidates))
    exact = [item for item in ordered if item == value]
    if exact:
        return exact[0]
    matches = [item for item in ordered if item.startswith(value)]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise DecisionError(f"{label} 不存在: {value}")
    raise DecisionError(
        f"{label} 前缀不唯一 {value!r}: " + ", ".join(matches)
    )


def show_parent_members(
    inventory: Any,
    triage: Any,
    parent_id: str,
) -> tuple[dict[str, str], ...]:
    """返回 CLI 展示用的稳定成员列表。"""
    parent_members = _parent_members(triage)
    resolved = resolve_unique_prefix(
        parent_id,
        parent_members,
        label="parent_id",
    )
    by_id = {candidate.candidate_id: candidate for candidate in inventory.candidates}
    result: list[dict[str, str]] = []
    for candidate_id in parent_members[resolved]:
        candidate = by_id[candidate_id]
        result.append(
            {
                "candidate_id": candidate.candidate_id,
                "package_id": candidate.package_id,
                "evidence_id": candidate.evidence_id,
                "scope": candidate.scope,
            }
        )
    return tuple(result)


@dataclass(frozen=True)
class GateReport:
    ok: bool
    blockers: tuple[str, ...]
    warnings: tuple[str, ...]
    declarations: tuple[str, ...]


_G10_DECLARATION = (
    "HONEST_GAP[G10]: 排除桶∩established 仅覆盖 Phase1 报告内 runtime 信号（G8）。"
    "包外 pcap survey 未完整绑定当前案件、样本与登记抓包，不能据此作穷尽性排除。"
    "已提供的 established 观察仍触发 G9；完整且已验证的 --survey 才消除此声明。"
)


def _gate_get(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


def _gate_canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _gate_inventory_candidates(inventory: Any) -> tuple[Any, ...]:
    candidates = _gate_get(inventory, "candidates", ())
    if candidates is None:
        return ()
    return tuple(candidates)


def _gate_triage_parents(triage: Any) -> tuple[Any, ...]:
    parents = _gate_get(triage, "parents", ())
    if parents is None:
        return ()
    return tuple(parents)


def _gate_parent_id(proposal: Any) -> str | None:
    value = _gate_get(proposal, "parent_id")
    return str(value) if value is not None else None


def _gate_candidate_id(candidate: Any) -> str | None:
    value = _gate_get(candidate, "candidate_id")
    return str(value) if value is not None else None


def _gate_entry_parent_id(
    entry: Mapping[str, Any],
    candidate_to_parent: Mapping[str, str],
) -> str | None:
    parent_id = entry.get("parent_id")
    if parent_id is not None:
        return str(parent_id)

    candidate_id = entry.get("candidate_id")
    if candidate_id is None:
        return None
    return candidate_to_parent.get(str(candidate_id))


def _gate_entry_disposition(entry: Mapping[str, Any]) -> str | None:
    disposition = entry.get("disposition")
    return str(disposition) if disposition is not None else None


def _gate_is_decision_materialization(entry: Mapping[str, Any]) -> bool:
    materialized_from = entry.get("materialized_from")
    return (
        isinstance(materialized_from, str)
        and materialized_from.startswith("decision:")
    )


def _gate_bucket_disposition_matches(
    bucket: Any,
    disposition: Any,
) -> bool:
    if not isinstance(bucket, str) or not isinstance(disposition, str):
        return False
    if bucket == disposition:
        return True
    if bucket.startswith("auto:") and bucket[5:] == disposition:
        return True
    return False


def _gate_signals(proposal: Any) -> tuple[str, ...]:
    signals = _gate_get(proposal, "signals", ())
    if signals is None:
        return ()
    if isinstance(signals, str):
        return (signals,)
    try:
        return tuple(sorted(str(signal) for signal in signals))
    except TypeError:
        return ()


def _gate_proposal_hosts(proposal: Any) -> tuple[str, ...]:
    """从 triage proposal 的 display/value 中提取可比较的网络主机。"""
    values: list[str] = []

    for field_name in ("display", "value"):
        value = _gate_get(proposal, field_name)
        if value is None:
            continue
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, Iterable) and not isinstance(value, Mapping):
            values.extend(str(item) for item in value)

    hosts: list[str] = []
    for value in values:
        # ★用 url/ip/domain 三种 kind 各试一次（复审 P1#2）：URL 值必须走 kind=url 才能提出 hostname，
        # 仅 host/ip 会把 "https://100.64.0.2:443/a" 漏掉或截成 "https:"。取并集，噪音不匹配 established 不误报。
        for kind in ("url", "ip", "domain"):
            try:
                normalized = normalize_host(kind, value)
            except Exception:
                continue
            if normalized:
                hosts.append(str(normalized))

    return tuple(sorted(set(hosts)))


def _gate_audit_blocker_text(blocker: Any) -> str:
    code = _gate_get(blocker, "code")
    if code is None:
        code = str(blocker)
    return f"G5: coverage 审计失败 {code}"


def run_gate(
    inventory: Any,
    triage: Any,
    decisions: Any,
    clue_records: Any,
    coverage: Any,
    *,
    case_id: str,
    survey_established_hosts: set[str] | None = None,
    survey_assessed: bool | None = None,
    allow_pending: bool = False,
) -> GateReport:
    blockers: list[str] = []
    warnings: list[str] = []
    declarations: list[str] = []

    inventory_issues = _gate_get(inventory, "issues", ())
    if inventory_issues:
        blockers.append(f"G1: inventory.issues 非空 {inventory_issues!r}")

    candidates = _gate_inventory_candidates(inventory)
    proposals = _gate_triage_parents(triage)

    inventory_candidate_ids = {
        candidate_id
        for candidate in candidates
        if (candidate_id := _gate_candidate_id(candidate)) is not None
    }
    triage_parent_ids = {
        parent_id
        for proposal in proposals
        if (parent_id := _gate_parent_id(proposal)) is not None
    }
    members_by_parent: dict[str, tuple[str, ...]] = {}
    for proposal in proposals:
        parent_id = _gate_parent_id(proposal)
        if parent_id is None:
            continue
        members = _gate_get(proposal, "member_candidate_ids", ())
        try:
            members_by_parent[parent_id] = tuple(sorted(str(member) for member in members))
        except TypeError:
            members_by_parent[parent_id] = ()

    try:
        validate_decision_graph(
            decisions,
            inventory_candidate_ids=inventory_candidate_ids,
            triage_parent_ids=triage_parent_ids,
            members_by_parent=members_by_parent,
        )
    except DecisionError as exc:
        blockers.append(f"G2: decision graph 非法 {exc}")

    coverage_mapping = coverage if isinstance(coverage, Mapping) else {}
    inventory_fingerprint = _gate_get(inventory, "fingerprint")
    actual_decisions_fingerprint: str | None
    try:
        actual_decisions_fingerprint = _decision_fingerprint(decisions)
    except Exception as exc:
        actual_decisions_fingerprint = None
        blockers.append(f"G3: decisions fingerprint 计算失败 {exc}")

    if coverage_mapping.get("inventory_fingerprint") != inventory_fingerprint:
        blockers.append("G3: coverage 陈旧，inventory fingerprint 不一致，请重跑 materialize")
    if coverage_mapping.get("decisions_fingerprint") != actual_decisions_fingerprint:
        blockers.append("G3: coverage 陈旧，decisions fingerprint 不一致，请重跑 materialize")

    try:
        rematerialized = materialize_snapshot(
            inventory,
            triage,
            decisions,
            clue_records,
            case_id=case_id,
            decisions_fingerprint=coverage_mapping.get("decisions_fingerprint"),
        ).coverage
        # decisions_sha256 只钉账本文件字节，不在内存重物化里。G4 比的是判决内容。
        recorded = dict(coverage_mapping)
        recorded.pop("decisions_sha256", None)
        if _gate_canonical_bytes(recorded) != _gate_canonical_bytes(rematerialized):
            blockers.append("G4: coverage 与现场重物化结果不一致，请重跑 materialize")
    except Exception as exc:
        blockers.append(f"G4: coverage 现场重物化失败 {exc}")

    try:
        audit = audit_coverage(inventory, coverage_mapping, clue_records)
        if not bool(_gate_get(audit, "ok", False)):
            audit_blockers = _gate_get(audit, "blockers", ())
            for audit_blocker in audit_blockers or ():
                blockers.append(_gate_audit_blocker_text(audit_blocker))
            if not audit_blockers:
                blockers.append("G5: coverage 审计失败")
    except Exception as exc:
        blockers.append(f"G5: coverage 审计执行失败 {exc}")

    raw_entries = coverage_mapping.get("entries", ())
    entries: tuple[Mapping[str, Any], ...]
    if isinstance(raw_entries, list | tuple):
        entries = tuple(
            entry for entry in raw_entries if isinstance(entry, Mapping)
        )
    else:
        entries = ()
        blockers.append("G6: coverage.entries 缺失或格式非法")

    pending_count = sum(
        _gate_entry_disposition(entry) == "pending_with_action"
        for entry in entries
    )
    if pending_count:
        message = f"G6: coverage 中 pending_with_action 数量为 {pending_count}"
        if allow_pending:
            warnings.append(message)
        else:
            blockers.append(message)

    candidate_to_parent: dict[str, str] = {}
    for candidate in candidates:
        candidate_id = _gate_candidate_id(candidate)
        parent_id = _gate_get(candidate, "parent_id")
        if candidate_id is not None and parent_id is not None:
            candidate_to_parent[candidate_id] = str(parent_id)

    entries_by_parent: dict[str, list[Mapping[str, Any]]] = {}
    for entry in entries:
        parent_id = _gate_entry_parent_id(entry, candidate_to_parent)
        if parent_id is not None:
            entries_by_parent.setdefault(parent_id, []).append(entry)

    for proposal in sorted(
        proposals,
        key=lambda item: _gate_parent_id(item) or "",
    ):
        parent_id = _gate_parent_id(proposal)
        if parent_id is None:
            blockers.append("G7: triage proposal 缺少 parent_id")
            continue

        parent_entries = entries_by_parent.get(parent_id, [])
        dispositions = {
            _gate_entry_disposition(entry)
            for entry in parent_entries
            if _gate_entry_disposition(entry) is not None
        }
        non_skeleton = any(
            entry.get("materialized_from") != "skeleton"
            for entry in parent_entries
        )
        bucket = _gate_get(proposal, "bucket")
        if bucket == "human" and not non_skeleton:
            blockers.append(
                f"G7: human parent {parent_id} 未在 coverage 中形成非 skeleton 物化"
            )
        elif isinstance(bucket, str) and bucket.startswith("auto:"):
            if not any(
                _gate_bucket_disposition_matches(bucket, disposition)
                for disposition in dispositions
            ) and not any(
                _gate_is_decision_materialization(entry)
                for entry in parent_entries
            ):
                blockers.append(
                    f"G7: auto parent {parent_id} 的物化 disposition 与提议桶不一致"
                )

    proposal_by_parent = {
        _gate_parent_id(proposal): proposal
        for proposal in proposals
        if _gate_parent_id(proposal) is not None
    }
    for entry in entries:
        if _gate_entry_disposition(entry) != "excluded_with_reason":
            continue
        candidate_id = entry.get("candidate_id", "<unknown>")
        parent_id = _gate_entry_parent_id(entry, candidate_to_parent)
        proposal = proposal_by_parent.get(parent_id)
        if proposal is None:
            blockers.append(
                f"G8: excluded candidate {candidate_id} 缺少 triage parent {parent_id}"
            )
            continue
        runtime_signals = {
            "runtime_contact",
            "is_c2",
            "runtime_seen",
        }.intersection(_gate_signals(proposal))
        if runtime_signals:
            blockers.append(
                f"G8: excluded candidate {candidate_id} 的 parent {parent_id}"
                f" 含 runtime 信号 {','.join(sorted(runtime_signals))}"
            )

        if survey_established_hosts is not None:
            established = {
                str(host) for host in survey_established_hosts
            }
            matched_hosts = established.intersection(
                _gate_proposal_hosts(proposal)
            )
            if matched_hosts:
                blockers.append(
                    f"G9: excluded candidate {candidate_id} 的 parent {parent_id}"
                    f" 命中 survey established host "
                    f"{','.join(sorted(matched_hosts))}"
                )

    # None preserves the historical programmatic API; CLI always supplies the
    # validated completeness bit, independently of positive G9 observations.
    if survey_established_hosts is None or survey_assessed is False:
        declarations.append(_G10_DECLARATION)

    return GateReport(
        ok=not blockers,
        blockers=tuple(blockers),
        warnings=tuple(warnings),
        declarations=tuple(declarations),
    )


def extract_established_hosts(survey: Mapping[str, Any]) -> set[str]:
    """Validate legacy endpoint/state shapes and extract normalized positive IPs."""
    from .survey import validate_established_hosts

    return validate_established_hosts(
        survey, allow_unknown_states="schema_version" not in survey,
    )


def _batch_existing_active_parents(
    existing_decisions: Iterable[Mapping[str, Any]],
) -> set[str]:
    decisions = tuple(existing_decisions)
    superseded: set[str] = set()
    for decision in decisions:
        values = decision.get("supersedes", ())
        if values is None:
            continue
        if isinstance(values, str):
            values = (values,)
        for value in values:
            superseded.add(str(value))

    active: set[str] = set()
    for decision in decisions:
        # 只 parent-scope 判决算 parent 已判（复审 P1#3）：member-scope 例外判决也冗余记录
        # parent_id，若不过滤会把仅有个别成员例外的 parent 误当整体已判、令组批跳过其余成员。
        if decision.get("scope") != "parent":
            continue
        parent_id = decision.get("parent_id")
        if parent_id is None:
            continue
        identity = decision.get("decision_id")
        if identity is None or str(identity) not in superseded:
            active.add(str(parent_id))
    return active


def build_batch_decisions(
    triage: Any,
    *,
    tier_prefix: str,
    disposition: str,
    reason: str,
    decided_by: str,
    expect: int,
    existing_decisions: Iterable[Mapping[str, Any]],
    skip_decided: bool = False,
    inventory_fingerprint: str,
) -> list[dict[str, Any]]:
    if disposition == _ACCEPTED:
        raise DecisionError("batch 禁止 disposition=accepted_clue，accept 必须逐条点名")
    if disposition == "pending_with_action":
        # pending 需逐条 next_action，组批无法统一提供（复审 P1#4），提前拒绝而非延迟到写盘
        raise DecisionError("batch 禁止 disposition=pending_with_action（需逐条 next_action）")
    if expect < 0:
        raise DecisionError(f"预期条数不能为负数：{expect}")

    selected = [
        proposal
        for proposal in _gate_triage_parents(triage)
        if _gate_get(proposal, "bucket") == "human"
        and str(_gate_get(proposal, "tier", "")).startswith(tier_prefix)
    ]
    selected.sort(key=lambda proposal: _gate_parent_id(proposal) or "")

    active_parents = _batch_existing_active_parents(existing_decisions)
    conflicts = sorted(
        parent_id
        for parent_id in (
            _gate_parent_id(proposal) for proposal in selected
        )
        if parent_id is not None and parent_id in active_parents
    )
    if conflicts and not skip_decided:
        raise DecisionError(
            "batch 中已有活动末端的 parent："
            + ",".join(conflicts)
        )

    pending = [
        proposal
        for proposal in selected
        if (_gate_parent_id(proposal) or "") not in active_parents
    ]
    if len(pending) != expect:
        raise DecisionError(f"预期 {expect} 条，实际 {len(pending)} 条")

    parent_ids = sorted(
        parent_id
        for parent_id in (_gate_parent_id(proposal) for proposal in pending)
        if parent_id is not None
    )
    batch_id = "b2:" + sha256_hex(_gate_canonical_bytes(parent_ids))[:16]

    result: list[dict[str, Any]] = []
    for proposal in pending:
        parent_id = _gate_parent_id(proposal)
        if parent_id is None:
            raise DecisionError("batch proposal 缺少 parent_id")

        members = _gate_get(proposal, "member_candidate_ids", ())
        member_ids = tuple(sorted(str(member) for member in members))
        signals = _gate_signals(proposal)
        decision = build_decision(
            case_id=str(_gate_get(triage, "case_id", "")),
            decided_by=decided_by,
            scope="parent",
            parent_id=parent_id,
            candidate_id=None,
            disposition=disposition,
            reason=reason,
            next_action=None,
            accepts=[],
            clue_id=None,
            supersedes=[],
            members_hash_value=members_hash(member_ids),
            decided_against={
                "inventory_fingerprint": inventory_fingerprint,
                "triage_bucket": _gate_get(proposal, "bucket"),
                "triage_tier": _gate_get(proposal, "tier"),
                "signals_hash": signals_hash(signals),
            },
            note=f"batch:{batch_id}",
        )
        result.append(decision)

    return result


@dataclass(frozen=True)
class ReplayItem:
    decision_id: str
    scope: str
    key: str
    classification: str
    detail: str
    next_action: str


@dataclass(frozen=True)
class ReplayReport:
    old_fingerprint: str
    new_fingerprint: str
    summary: dict[str, int]
    items: tuple[ReplayItem, ...]


def _replay_as_id(value: Any, *, field_name: str) -> str:
    """读取并校验逻辑标识，未知或空值直接失败。"""
    if value is None:
        raise ValueError(f"replay: 缺少 {field_name}")
    result = str(value)
    if not result:
        raise ValueError(f"replay: {field_name} 为空")
    return result


def _replay_sequence(value: Any) -> tuple[Any, ...]:
    """将可迭代字段转为确定性可重复读取的元组。"""
    if value is None:
        return ()
    if isinstance(value, (str, bytes)):
        return (value,)
    if isinstance(value, Mapping):
        return tuple(value.values())
    try:
        return tuple(value)
    except TypeError as exc:
        raise ValueError("replay: 字段不可迭代") from exc


def _replay_inventory_candidate_ids(inventory: Any) -> frozenset[str]:
    """读取 inventory.candidates 中的 candidate_id。"""
    candidates = _gate_get(inventory, "candidates", ())
    if isinstance(candidates, Mapping):
        raw_candidates = tuple(candidates.items())
    else:
        raw_candidates = tuple(candidates or ())

    result: set[str] = set()
    for entry in raw_candidates:
        if isinstance(candidates, Mapping):
            mapping_key, candidate = entry
            candidate_id = _gate_get(candidate, "candidate_id", mapping_key)
        else:
            candidate_id = _gate_get(entry, "candidate_id", entry)
        result.add(_replay_as_id(candidate_id, field_name="candidate_id"))
    return frozenset(result)


def _replay_parent_proposals(triage: Any) -> dict[str, Any]:
    """建立 parent_id 到当前 proposal 的唯一映射。"""
    proposals = _replay_sequence(_gate_get(triage, "parents", ()))
    result: dict[str, Any] = {}

    for proposal in proposals:
        parent_id = _replay_as_id(
            _gate_get(proposal, "parent_id"),
            field_name="proposal.parent_id",
        )
        if parent_id in result:
            raise ValueError(f"replay: triage 中存在重复 parent_id: {parent_id}")
        result[parent_id] = proposal

    return result


def _replay_decided_against(decision: Any) -> Any:
    value = _gate_get(decision, "decided_against", {})
    return {} if value is None else value


def _replay_is_excluded(disposition: Any) -> bool:
    return str(disposition).startswith("excluded_")


def _replay_runtime_signal(signals: Iterable[Any]) -> bool:
    runtime_signals = {"runtime_contact", "is_c2", "runtime_seen"}
    return any(str(signal) in runtime_signals for signal in signals)


def _replay_old_fingerprint(active_decisions: Iterable[Any]) -> str:
    """以出现次数最多的旧指纹为准；并以活动判决排序顺序解决并列。"""
    fingerprints: list[str] = []

    for decision in active_decisions:
        value = _gate_get(
            _replay_decided_against(decision),
            "inventory_fingerprint",
        )
        if value is not None and str(value):
            fingerprints.append(str(value))

    if not fingerprints:
        return ""

    counts: dict[str, int] = {}
    first_index: dict[str, int] = {}
    for index, fingerprint in enumerate(fingerprints):
        counts[fingerprint] = counts.get(fingerprint, 0) + 1
        first_index.setdefault(fingerprint, index)

    return min(
        counts,
        key=lambda fingerprint: (
            -counts[fingerprint],
            first_index[fingerprint],
            fingerprint,
        ),
    )


def _replay_make_item(
    decision: Any,
    *,
    scope: str,
    key: str,
    classification: str,
    detail: str,
    next_action: str,
) -> ReplayItem:
    decision_id = _replay_as_id(
        _gate_get(decision, "decision_id"),
        field_name="decision_id",
    )
    return ReplayItem(
        decision_id=decision_id,
        scope=scope,
        key=key,
        classification=classification,
        detail=detail,
        next_action=next_action,
    )


def classify_replay_change(
    inventory: Any,
    triage: Any,
    decisions: Iterable[Mapping[str, Any]],
) -> ReplayReport:
    """诊断补包后活动判决的迁移状态。

    该函数只读取输入，不修改任何输入对象；所有输出顺序均显式确定。
    """
    decisions = tuple(decisions)  # 固化为 Sequence，供图校验与多次遍历
    inventory_candidate_ids = _replay_inventory_candidate_ids(inventory)
    proposals_by_parent = _replay_parent_proposals(triage)

    # ★不传 members_by_parent：replay 要诊断的正是"旧判决 accepts 与新成员集不匹配"；若走
    # accepts∈当前成员 的 schema 校验，点名消失场景会被 validate 提前拒、无法分类为 blocked_stale。
    graph_state = validate_decision_graph(
        decisions,
        inventory_candidate_ids=set(inventory_candidate_ids),
        triage_parent_ids=set(proposals_by_parent),
    )

    active_by_unit = _gate_get(graph_state, "active_by_unit")
    if active_by_unit is None:
        raise ValueError("replay: GraphState 缺少 active_by_unit")

    active_entries: list[tuple[str, str, Any]] = []
    for unit, decision in active_by_unit.items():
        if not isinstance(unit, tuple) or len(unit) != 2:
            raise ValueError("replay: active_by_unit 包含非法逻辑单元")

        scope = _replay_as_id(unit[0], field_name="scope")
        key = _replay_as_id(unit[1], field_name="unit.key")

        if scope not in {_PARENT_SCOPE, _MEMBER_SCOPE}:
            raise ValueError(f"replay: 未知 scope: {scope}")

        active_entries.append((scope, key, decision))

    active_entries.sort(key=lambda entry: (entry[0], entry[1]))

    old_fingerprint = _replay_old_fingerprint(
        decision for _, _, decision in active_entries
    )
    new_fingerprint = _replay_as_id(
        _gate_get(inventory, "fingerprint"),
        field_name="inventory.fingerprint",
    )

    counts = {
        "unchanged": 0,
        "carry_with_note": 0,
        "blocked_stale": 0,
        "removed": 0,
    }
    items: list[ReplayItem] = []

    for scope, key, decision in active_entries:
        disposition = str(_gate_get(decision, "disposition", ""))
        decided_against = _replay_decided_against(decision)

        classification = "unchanged"
        detail = ""
        next_action = ""

        if scope == _PARENT_SCOPE:
            parent_id = _replay_as_id(
                _gate_get(decision, "parent_id", key),
                field_name="decision.parent_id",
            )
            proposal = proposals_by_parent.get(parent_id)

            if proposal is None:
                classification = "removed"
                detail = "该 parent 已不在当前 inventory，原判决作废"
                next_action = "无需迁移"
            else:
                current_members = tuple(
                    _replay_as_id(member_id, field_name="member_candidate_id")
                    for member_id in _replay_sequence(
                        _gate_get(proposal, "member_candidate_ids", ())
                    )
                )
                current_member_ids = frozenset(current_members)
                current_members_hash = members_hash(current_members)

                old_members_hash = _gate_get(decision, "members_hash")
                old_signals_hash = _gate_get(
                    decided_against,
                    "signals_hash",
                )
                current_signals = tuple(
                    str(signal)
                    for signal in _replay_sequence(
                        _gate_get(proposal, "signals", ())
                    )
                )
                current_signals_hash = signals_hash(current_signals)

                current_bucket = _gate_get(proposal, "bucket")
                current_tier = _gate_get(proposal, "tier")
                old_bucket = _gate_get(decided_against, "triage_bucket")
                old_tier = _gate_get(decided_against, "triage_tier")

                # ★先判 runtime blocker（复审 P1#3）：当前 excluded_* 且含 runtime 信号必须 blocked_stale，
                # 不被 members 变化分支遮蔽——同一份新 runtime 证据不该因是否恰好新增成员而得到不同结果。
                if _replay_is_excluded(disposition) and _replay_runtime_signal(current_signals):
                    classification = "blocked_stale"
                    detail = "排除判决的前提被推翻：当前证据含 runtime 信号"
                    next_action = "复核新 runtime 证据后重新 decide 并 supersede"
                elif current_members_hash != old_members_hash:
                    if disposition == _ACCEPTED:
                        accepted_candidates = {
                            _replay_as_id(
                                _gate_get(accept, "candidate_id"),
                                field_name="accepts.candidate_id",
                            )
                            for accept in _replay_sequence(
                                _gate_get(decision, "accepts", ())
                            )
                        }
                        if accepted_candidates <= current_member_ids:
                            classification = "carry_with_note"
                            detail = (
                                "点名成员仍在、判决沿用；新增成员将物化为 "
                                "duplicate_or_merged，请确认是否应单独 accept"
                            )
                            next_action = "确认后沿用，无需迁移"
                        else:
                            classification = "blocked_stale"
                            detail = "accepted 点名成员已消失，须重判"
                            next_action = "重新 decide 并 supersede"
                    else:
                        classification = "carry_with_note"
                        detail = "成员集变化，判决自动继承到新成员，请确认"
                        next_action = "确认后沿用，无需迁移"
                elif (
                    current_signals_hash != old_signals_hash
                    or current_bucket != old_bucket
                    or current_tier != old_tier
                ):
                    classification = "carry_with_note"
                    detail = "分层信号变化，判决沿用，请确认"
                    next_action = "确认后沿用，无需迁移"

        else:
            parent_id = _replay_as_id(
                _gate_get(decision, "parent_id"),
                field_name="decision.parent_id",
            )
            if key not in inventory_candidate_ids:
                classification = "removed"
                detail = "该 candidate 已不在当前 inventory，原判决作废"
                next_action = "无需迁移"
            else:
                proposal = proposals_by_parent.get(parent_id)
                if proposal is not None:
                    current_signals = tuple(
                        str(signal)
                        for signal in _replay_sequence(
                            _gate_get(proposal, "signals", ())
                        )
                    )
                    if _replay_is_excluded(disposition) and _replay_runtime_signal(
                        current_signals
                    ):
                        classification = "blocked_stale"
                        detail = "排除判决的前提被推翻：新证据出现 runtime 信号"
                        next_action = "复核新 runtime 证据后重新 decide 并 supersede"

        counts[classification] += 1

        if classification != "unchanged":
            items.append(
                _replay_make_item(
                    decision,
                    scope=scope,
                    key=key,
                    classification=classification,
                    detail=detail,
                    next_action=next_action,
                )
            )

    return ReplayReport(
        old_fingerprint=old_fingerprint,
        new_fingerprint=new_fingerprint,
        summary=counts,
        items=tuple(items),
    )
