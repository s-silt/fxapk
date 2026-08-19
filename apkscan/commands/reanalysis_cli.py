"""CLI contract for projecting reanalysis requests from a judgment ledger."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn, cast

import typer

from apkscan.core import judgment_ledger as jl
from apkscan.core import reanalysis as rp
from apkscan.core import reanalysis_contract as rxc
from apkscan.core import reanalysis_ledger as rl
from apkscan.commands.evaluate_cli import evaluate as _evaluate_command
from apkscan.commands.labels_cli import labels_app
from apkscan.commands.split_cli import split_app
from apkscan.core import recognition_contract as rc
from apkscan.core.atomic import atomic_create_bytes

recognize_app = typer.Typer(
    add_completion=False,
    help=("识别与取证重分析请求投影。生产映射 v1 可能产生诚实空结果；空输出≠无缺口。"),
)

# labels 子组（P4-C）：只读标签校验器，挂在同一 recognize 命名空间下。
recognize_app.add_typer(labels_app, name="labels")

# split 子组（P5-D）：防泄漏 split-manifest 的构建与只读复验。
recognize_app.add_typer(split_app, name="split")

# evaluate 单命令（P5-E）：四任务评测 + 显式阈值晋级门（exit 4=门未过）。
recognize_app.command("evaluate")(_evaluate_command)

DEFAULT_POLICY = rp.DEFAULT_ADMISSION_POLICY

_LEDGER_PROFILE = "p3e2-v1"
_RECEIPT_SCHEMA_VERSION = "1.0"
_PRODUCER_ID = "fxapk-recognize-reanalysis"
_PRODUCER_VERSION = "1.0"
_ACTOR_ID = "fxapk-recognize-reanalysis"
_SAMPLE_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_PRIORITY_RANK = {"high": 0, "review": 1, "low": 2}


def _fail(message: str) -> NoReturn:
    """Report a contract failure and terminate with CLI usage-error status."""

    typer.echo(f"error: {message}", err=True)
    raise typer.Exit(code=2)


def _producer() -> rc.ProducerRef:
    """Return the fixed SYSTEM producer used by this CLI projection."""

    return rc.ProducerRef(
        kind=rc.ProducerKind.SYSTEM,
        producer_id=_PRODUCER_ID,
        version=_PRODUCER_VERSION,
        artifact_digest=None,
        configuration_digest=None,
    )


def _actor() -> rc.Actor:
    """Return the fixed SYSTEM actor used for ledger proposal events."""

    return rc.Actor(
        kind=rc.ActorKind.SYSTEM,
        actor_id=_ACTOR_ID,
    )


def _occurred_at() -> str:
    """Return a UTC ledger timestamp in the required wire format."""

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _receipt_path(out_path: Path) -> Path:
    """Derive the receipt path associated with a requests target."""

    return Path(f"{out_path}.receipt.json")


def _ensure_create_only(out_path: Path, receipt_path: Path) -> None:
    """Reject occupied output targets before reading or processing the ledger."""

    if out_path.exists():
        _fail(f"output target already exists: {out_path}")
    if receipt_path.exists():
        _fail(f"receipt target already exists: {receipt_path}")


def _load_ledger(path: Path):
    """Decode, validate, and replay a non-empty JSONL judgment ledger."""

    try:
        payload = path.read_bytes()
        text = payload.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        _fail(f"invalid_ledger: {exc}")

    lines = text.splitlines()
    if not lines or any(not line.strip() for line in lines):
        _fail("invalid_ledger: ledger must contain non-empty JSONL records")

    try:
        events = tuple(jl.decode_event(line) for line in lines)
        if not events:
            _fail("invalid_ledger: ledger contains no events")
        jl.validate_event_chain(events)
        projection = jl.replay(events)
    except typer.Exit:
        raise
    except Exception as exc:
        _fail(f"invalid_ledger: {exc}")

    return events, projection


def _event_count(events: Sequence[object], event_type: jl.EventType) -> int:
    """Count events of a specified ledger event type."""

    return sum(1 for event in events if getattr(event, "event_type", None) is event_type)


def _validate_profile(events: Sequence[object], projection: object) -> str:
    """Validate profile p3e2-v1 and return its raw sample SHA-256 value."""

    run_count = _event_count(events, jl.EventType.RUN_OPENED)
    question_count = _event_count(events, jl.EventType.QUESTION_OPENED)

    projected_questions = getattr(projection, "questions", ())
    if run_count != 1 or question_count < 1 or len(projected_questions) != question_count:
        _fail(
            "unsupported_ledger_profile: p3e2-v1 requires exactly one "
            "RUN_OPENED and at least one QUESTION_OPENED"
        )

    run = getattr(projection, "run", None)
    if run is None:
        _fail("unsupported_ledger_profile: replay projection has no run")

    subjects = getattr(run, "subjects", ())
    sample_subjects = tuple(
        subject for subject in subjects if getattr(subject, "kind", None) is rc.SubjectKind.SAMPLE
    )

    if len(sample_subjects) > 1:
        _fail("ambiguous_sample_subject: multiple SAMPLE subjects")
    if len(sample_subjects) != 1:
        _fail("invalid_sample_subject: exactly one SAMPLE subject is required")

    sample_value = getattr(sample_subjects[0], "value", None)
    if not isinstance(sample_value, str) or _SAMPLE_PATTERN.fullmatch(sample_value) is None:
        _fail(
            "invalid_sample_subject: SAMPLE value must be exactly "
            "64 lowercase hexadecimal characters"
        )

    return sample_value


def _mapping_counts(items: Sequence[tuple[str, int]]) -> dict[str, int]:
    """Convert an immutable count-pair sequence to a JSON object."""

    return dict(items)


def _empty_planning_receipt() -> dict[str, object]:
    """Build receipt fields for the mandated no-gaps planning fast path."""

    return {
        "predicate_version": DEFAULT_POLICY.predicate_version,
        "mapping_version": DEFAULT_POLICY.mapping_version,
        "matrix_version": rxc.MATRIX_VERSION,
        "gaps_seen": 0,
        "suppressed_not_open": 0,
        "suppressed_low_value": 0,
        "suppressed_unknown_reason": 0,
        "suppressed_by_ceiling": (),
        "emitted": (),
    }


def _planning_receipt_fields(receipt: object) -> dict[str, object]:
    """Extract the frozen public fields from a planning receipt."""

    return {
        "predicate_version": getattr(receipt, "predicate_version"),
        "mapping_version": getattr(receipt, "mapping_version"),
        "matrix_version": getattr(receipt, "matrix_version"),
        "gaps_seen": getattr(receipt, "gaps_seen"),
        "suppressed_not_open": getattr(receipt, "suppressed_not_open"),
        "suppressed_low_value": getattr(receipt, "suppressed_low_value"),
        "suppressed_unknown_reason": getattr(
            receipt,
            "suppressed_unknown_reason",
        ),
        "suppressed_by_ceiling": getattr(
            receipt,
            "suppressed_by_ceiling",
        ),
        "emitted": getattr(receipt, "emitted"),
    }


def _as_wire_mapping(value: object) -> Mapping[str, object]:
    """Require a string-keyed mapping for local wire inspection."""

    if not isinstance(value, Mapping):
        raise ValueError("encoded request is not an object")

    result: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError("encoded request contains a non-string key")
        result[key] = item
    return result


def _required_string(
    mapping: Mapping[str, object],
    key: str,
) -> str:
    """Read a required string field from an encoded wire object."""

    value = mapping.get(key)
    if not isinstance(value, str):
        raise ValueError(f"encoded request field {key!r} is not a string")
    return value


def _sort_key(row: Mapping[str, object]) -> tuple[int, float, str, str]:
    """Return the contractually frozen total-order key for a request."""

    priority_value = row.get("priority")
    priority = _as_wire_mapping(priority_value)

    priority_class = _required_string(priority, "class")
    try:
        rank = _PRIORITY_RANK[priority_class]
    except KeyError as exc:
        raise ValueError(f"unsupported request priority class: {priority_class}") from exc

    information_gain = priority.get("expected_information_gain")
    if not isinstance(information_gain, (int, float)) or isinstance(information_gain, bool):
        raise ValueError("encoded request expected_information_gain is not numeric")

    dedupe_key = _required_string(row, "dedupe_key")
    request_id = _required_string(row, "request_id")
    return rank, -float(information_gain), dedupe_key, request_id


def _authorization_value(row: Mapping[str, object]) -> str:
    """Return the encoded authorization level."""

    return _required_string(row, "authorization")


def _emit_authorization_warnings(
    rows: Sequence[Mapping[str, object]],
) -> None:
    """Emit mandatory warnings for every request above OFFLINE authorization."""

    warned = 0
    for row in rows:
        authorization = _authorization_value(row)
        if authorization == "offline":
            continue

        request_id = _required_string(row, "request_id")
        analysis_type = _required_string(row, "analysis_type")
        request_hex = request_id.rsplit("sha256:", maxsplit=1)[-1][:12]

        typer.echo(
            f"{request_hex} {analysis_type} authorization={authorization}",
            err=True,
        )
        warned += 1

    if warned:
        typer.echo(f"非 OFFLINE proposed 请求共 {warned} 条", err=True)
        typer.echo(
            "以上请求均为 proposed，未获授权；执行须另行人工授权",
            err=True,
        )


def _publish_pair(
    out_path: Path,
    receipt_path: Path,
    request_payload: bytes,
    receipt_payload: bytes,
) -> None:
    """Publish requests then receipt while preserving the pair invariant.

    走仓库的 create-only 原子原语（O_EXCL 语义）而不是 replace：前置 exists()
    检查与写入之间若有并发者抢先创建目标，这里会失败而不是覆盖它；回滚也只删
    本次成功创建的文件（codex 复审 P1：replace 语义会吃掉并发者的产物）。
    """

    requests_published = False
    try:
        if not atomic_create_bytes(out_path, request_payload):
            raise OSError("requests target appeared concurrently")
        requests_published = True
        if not atomic_create_bytes(receipt_path, receipt_payload):
            raise OSError("receipt target appeared concurrently")
    except Exception:
        if requests_published:
            try:
                out_path.unlink()
            except FileNotFoundError:
                pass
        raise


@recognize_app.command(
    "reanalysis",
    help=(
        "从 p3e2-v1 judgment ledger 投影 proposed 重分析请求。"
        "生产映射 v1 可能不映射任何缺口，因此空输出≠无缺口；"
        "合法空结果会发布零字节 requests 文件及 receipt。"
    ),
)
def reanalysis(
    ledger: Path = typer.Argument(
        ...,
        help="输入 judgment ledger JSONL。",
    ),
    out: Path = typer.Option(
        ...,
        "--out",
        help="create-only requests JSONL 输出路径。",
    ),
    ceiling: rc.AuthorizationLevel = typer.Option(
        rc.AuthorizationLevel.AUTHORIZED_DEVICE,
        "--ceiling",
        help="授权上限：offline、passive_online 或 authorized_device。",
    ),
    ledger_out: Path | None = typer.Option(
        None,
        "--ledger-out",
        help="可选的扩展 judgment ledger sidecar 输出目录。",
    ),
) -> None:
    """Project proposed reanalysis requests without executing any analysis."""

    receipt_path = _receipt_path(out)
    _ensure_create_only(out, receipt_path)

    events, projection = _load_ledger(ledger)
    sample_sha256 = _validate_profile(events, projection)

    try:
        questions = getattr(projection, "questions")
        gaps = getattr(projection, "gaps")
        gap_statuses = dict(getattr(projection, "gap_statuses"))
        anchors = getattr(projection, "anchors")

        planned: list[rp.PlannedAction] = []
        planned_with_context: list[tuple[rp.PlannedAction, rxc.PlanningContext]] = []
        planning_fields = _empty_planning_receipt()
        planned_questions = 0

        for question in questions:
            question_gaps = tuple(gap for gap in gaps if gap.question_id == question.question_id)
            # 空 gap 的 question 不进 planner（诚实空快路径的逐 question 形态）。
            if not question_gaps:
                continue
            question_gap_statuses = {gap.gap_id: gap_statuses[gap.gap_id] for gap in question_gaps}
            context = rxc.PlanningContext(
                question=question,
                gaps=question_gaps,
                gap_statuses=question_gap_statuses,
                anchors=anchors,
                supporting_observation_ids=(),
                contradicting_observation_ids=(),
                authorization_ceiling=ceiling,
                sample_digest=f"sha256:{sample_sha256}",
            )
            planning = rp.plan_reanalysis(
                context,
                producer=_producer(),
                policy=DEFAULT_POLICY,
            )
            question_fields = _planning_receipt_fields(planning.receipt)
            planned_questions += 1

            # 版本字段各 question 同策略同值，取实跑收据的（防未来策略注入时留空默认）。
            for field in ("predicate_version", "mapping_version", "matrix_version"):
                planning_fields[field] = question_fields[field]
            for field in (
                "gaps_seen",
                "suppressed_not_open",
                "suppressed_low_value",
                "suppressed_unknown_reason",
            ):
                planning_fields[field] = cast(int, planning_fields[field]) + cast(
                    int, question_fields[field]
                )
            for field in ("suppressed_by_ceiling", "emitted"):
                aggregate_counts = _mapping_counts(
                    cast(Sequence[tuple[str, int]], planning_fields[field])
                )
                for key, count in cast(Sequence[tuple[str, int]], question_fields[field]):
                    aggregate_counts[key] = aggregate_counts.get(key, 0) + count
                planning_fields[field] = tuple(sorted(aggregate_counts.items()))

            for planned_action in planning.planned:
                planned.append(planned_action)
                planned_with_context.append((planned_action, context))

        encoded_rows: list[Mapping[str, object]] = []
        for planned_action, context in planned_with_context:
            request = rxc.project_reanalysis_request(
                planned_action.action, context, planned_action.meta
            )
            encoded = rxc.encode_reanalysis_request(request)
            encoded_rows.append(_as_wire_mapping(encoded))

        encoded_rows.sort(key=_sort_key)

        sidecar_to_rollback: Path | None = None
        ledger_sidecar: object
        if ledger_out is None:
            ledger_sidecar = None
        elif planned:
            extended, _projection_receipt = rl.append_reanalysis_proposals(
                events,
                planned=tuple(planned),
                actor=_actor(),
                occurred_at=_occurred_at(),
            )
            ledger_sidecar = rl.publish_reanalysis_ledger(
                extended,
                out_dir=str(ledger_out),
                sample_sha256=sample_sha256,
            )
            if isinstance(ledger_sidecar, dict) and ledger_sidecar.get("ok") is True:
                sidecar_to_rollback = Path(str(ledger_out)) / str(ledger_sidecar["locator"])
        else:
            ledger_sidecar = {
                "published": False,
                "reason": "no_proposals",
            }

        suppressed_by_ceiling = cast(
            Sequence[tuple[str, int]],
            planning_fields["suppressed_by_ceiling"],
        )
        emitted = cast(
            Sequence[tuple[str, int]],
            planning_fields["emitted"],
        )

        over_ceiling_by_type = _mapping_counts(suppressed_by_ceiling)
        emitted_by_type = _mapping_counts(emitted)

        receipt: dict[str, object] = {
            "schema_version": _RECEIPT_SCHEMA_VERSION,
            "predicate_version": planning_fields["predicate_version"],
            "mapping_version": planning_fields["mapping_version"],
            "matrix_version": planning_fields["matrix_version"],
            "ledger_profile": _LEDGER_PROFILE,
            "questions_seen": len(questions),
            "questions_planned": planned_questions,
            "gaps_seen": planning_fields["gaps_seen"],
            "suppressed": {
                "not_open": planning_fields["suppressed_not_open"],
                "low_value": planning_fields["suppressed_low_value"],
                "unknown_reason": planning_fields["suppressed_unknown_reason"],
                "over_ceiling": {
                    "count": sum(over_ceiling_by_type.values()),
                    "by_type": over_ceiling_by_type,
                },
            },
            "emitted": {
                "count": sum(emitted_by_type.values()),
                "by_type": emitted_by_type,
            },
            "ledger_sidecar": ledger_sidecar,
        }

        if encoded_rows:
            request_text = "".join(
                json.dumps(
                    row,
                    ensure_ascii=False,
                    sort_keys=True,
                )
                + "\n"
                for row in encoded_rows
            )
            request_payload = request_text.encode("utf-8")
        else:
            request_payload = b""

        receipt_payload = json.dumps(
            receipt,
            ensure_ascii=False,
            sort_keys=True,
        ).encode("utf-8")

        _publish_pair(
            out,
            receipt_path,
            request_payload,
            receipt_payload,
        )
    except typer.Exit:
        raise
    except Exception as exc:
        # 双文件未成对落地时，连带回滚本次发布的扩展账本 sidecar——
        # 不留「有提案 sidecar 却无 requests」的孤儿（codex 复审 P2）。
        if sidecar_to_rollback is not None:
            try:
                sidecar_to_rollback.unlink()
            except FileNotFoundError:
                pass
        _fail(f"reanalysis_projection_failed: {exc}")

    _emit_authorization_warnings(encoded_rows)
