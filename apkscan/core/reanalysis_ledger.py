"""P3-C reanalysis proposal projection and verifiable sidecar publication."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

from apkscan.core import judgment_ledger as jl
from apkscan.core import reanalysis as rp
from apkscan.core import recognition_contract as rc
from apkscan.core.atomic import atomic_create_bytes


@dataclass(frozen=True, slots=True)
class ProjectionReceipt:
    """Summary of a proposal projection operation."""

    appended: int
    skipped_nonterminal_dedupe: int
    # 同 action_id 已在链上（含终态动作被同输入重规划的情形）：幂等跳过而不是让
    # 底座以 duplicate record_id 崩溃（codex 复审 P1）。
    skipped_already_recorded: int


def _fail(code: str, field_path: str) -> NoReturn:
    raise rc.SchemaValidationError(code, field_path=field_path)


def append_reanalysis_proposals(
    events: tuple[jl.LedgerEvent, ...],
    *,
    planned: tuple[rp.PlannedAction, ...],
    actor: rc.Actor,
    occurred_at: str,
) -> tuple[tuple[jl.LedgerEvent, ...], ProjectionReceipt]:
    """Project planned actions as proposal events, skipping active duplicates."""

    current = events
    appended = 0
    skipped_dedupe = 0
    skipped_recorded = 0
    nonterminal = {
        jl.ActionStatus.PROPOSED,
        jl.ActionStatus.AUTHORIZED,
    }

    for planned_action in planned:
        projection = jl.replay(current)
        statuses = dict(projection.action_statuses)
        candidate = planned_action.action

        # 确定性规划下同输入恒同 action_id：链上已有（无论状态）即同一提议的重放，
        # 幂等跳过；终态动作尤其不能再走 append——底座会以重复 record_id 拒绝。
        if any(
            action.action_id == candidate.action_id
            for action in projection.actions
        ):
            skipped_recorded += 1
            continue

        duplicate = any(
            action.dedupe_key == candidate.dedupe_key
            and statuses.get(action.action_id) in nonterminal
            for action in projection.actions
        )
        if duplicate:
            skipped_dedupe += 1
            continue

        event = jl.make_event(
            current,
            jl.EventType.ACTION_PROPOSED,
            actor,
            occurred_at,
            candidate,
        )
        current = jl.append_event(current, event)
        appended += 1

    return current, ProjectionReceipt(
        appended=appended,
        skipped_nonterminal_dedupe=skipped_dedupe,
        skipped_already_recorded=skipped_recorded,
    )


def publish_reanalysis_ledger(
    events: tuple[jl.LedgerEvent, ...],
    *,
    out_dir: str,
    sample_sha256: str,
) -> dict[str, object]:
    """Publish a create-only, replay-verified ledger sidecar."""

    if re.fullmatch(r"[0-9a-f]{64}", sample_sha256) is None:
        _fail(
            "sample_sha256_invalid",
            "sample_sha256 must be exactly 64 lowercase hexadecimal characters",
        )

    locator = f"reanalysis-ledger-{sample_sha256}.jsonl"
    target = Path(out_dir) / locator

    try:
        data = "".join(
            f"{jl.encode_event(event)}\n" for event in events
        ).encode("utf-8")
        created = atomic_create_bytes(target, data)
    except Exception:
        return {
            "locator": locator,
            "ok": False,
            "published": False,
            "replay_ok": False,
            "reason": "publish_failed",
        }

    if not created:
        return {
            "locator": locator,
            "ok": False,
            "published": False,
            "replay_ok": False,
            "reason": "already_exists",
        }

    try:
        read_back = target.read_bytes()
        if read_back != data:
            raise ValueError("published bytes differ from source bytes")

        decoded = tuple(
            jl.decode_event(line)
            for line in read_back.decode("utf-8").splitlines()
        )
        jl.validate_event_chain(decoded)
        jl.replay(decoded)
    except Exception:
        # 文件已落盘但未通过回读验证：ok=False——绝不声称闭合，published 只表
        # 「留下了一个不可验证的文件」这一事实（codex 复审 P2：单一成功判据）。
        return {
            "locator": locator,
            "ok": False,
            "published": True,
            "replay_ok": False,
            "reason": "replay_failed",
        }

    return {
        "locator": locator,
        "ok": True,
        "published": True,
        "replay_ok": True,
        "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
        "event_count": len(events),
    }
