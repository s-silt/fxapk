"""fxapk recognize evaluate 评测与晋级门命令。"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
from pathlib import Path
from typing import Any

import typer

from apkscan.core import recognition_evaluation as evaluation
from apkscan.core import recognition_labels as rlabels
from apkscan.core import recognition_training as rtraining
from apkscan.core.atomic import atomic_create_bytes


evaluate_app = typer.Typer(
    help=(
        "离线评测识别任务并执行显式晋级门；不联网、不启动子进程。"
        "评测错误退出 2，晋级门 fail/not_eligible 退出 4。"
    ),
    no_args_is_help=True,
)


_TASKS = {"family", "pair", "group", "clue"}

_PARAM_KEYS: dict[str, set[str]] = {
    "family": {"level", "layers", "known_unknown_samples"},
    "pair": {"k", "layers", "lineages"},
    "group": {
        "layers",
        "positive_subtypes",
        "cannot_link_subtypes",
        "repack_subtypes",
    },
    "clue": {"top_n", "layers"},
}

_PREDICTION_KEYS = {
    "family": "predictions",
    "pair": "rankings",
    "group": "groups",
    "clue": "candidates",
}


def _exit_error(message: str) -> None:
    typer.echo(f"error: {message}", err=True)
    raise typer.Exit(code=2)


def _read_json(path: Path, error_message: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        _exit_error(error_message)


def _string_list(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list):
        return None
    if not all(isinstance(item, str) for item in value):
        return None
    return tuple(value)


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _validate_params(task: str, payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != _PARAM_KEYS[task]:
        _exit_error("params_invalid")

    if task == "family":
        if not isinstance(payload["level"], str):
            _exit_error("params_invalid")
        layers = _string_list(payload["layers"])
        samples = _string_list(payload["known_unknown_samples"])
        if layers is None or samples is None:
            _exit_error("params_invalid")
        return {
            "level": payload["level"],
            "layers": layers,
            "known_unknown_samples": samples,
        }

    if task == "pair":
        if not _positive_int(payload["k"]):
            _exit_error("params_invalid")
        layers = _string_list(payload["layers"])
        lineages = _string_list(payload["lineages"])
        if layers is None or lineages is None:
            _exit_error("params_invalid")
        return {
            "k": payload["k"],
            "layers": layers,
            "lineages": lineages,
        }

    if task == "group":
        layers = _string_list(payload["layers"])
        positive = _string_list(payload["positive_subtypes"])
        cannot_link = _string_list(payload["cannot_link_subtypes"])
        repack = _string_list(payload["repack_subtypes"])
        if layers is None or positive is None or cannot_link is None or repack is None:
            _exit_error("params_invalid")
        return {
            "layers": layers,
            "positive_subtypes": positive,
            "cannot_link_subtypes": cannot_link,
            "repack_subtypes": repack,
        }

    if not _positive_int(payload["top_n"]):
        _exit_error("params_invalid")
    layers = _string_list(payload["layers"])
    if layers is None:
        _exit_error("params_invalid")
    return {"top_n": payload["top_n"], "layers": layers}


def _load_manifest(path: Path) -> tuple[Any, str]:
    try:
        encoded = path.read_bytes()
        text = encoded.decode("utf-8")
    except Exception:
        _exit_error("manifest_unreadable")

    try:
        manifest = rtraining.load_split_manifest(text)
    except rtraining.SplitManifestError as exc:
        typer.echo(f"error: {exc.reason_code}", err=True)
        raise typer.Exit(code=2) from None
    except Exception:
        _exit_error("manifest_unreadable")

    # 回显 manifest 自身的域分离 digest（切分的规范身份），不是文件字节 sha256；
    # load 已验证 digest 与内容一致，此处读取即可信。
    return manifest, str(json.loads(text)["manifest_digest"])


def _load_labels(path: Path) -> tuple[Any, str]:
    try:
        encoded = path.read_bytes()
    except Exception:
        _exit_error("labels_unreadable")

    try:
        labels = rlabels.load_recognition_labels(path)
    except rlabels.RecognitionLabelValidationError as exc:
        typer.echo(f"error: {exc.code} at line {exc.line}", err=True)
        raise typer.Exit(code=2) from None
    except Exception:
        _exit_error("labels_unreadable")

    return labels, hashlib.sha256(encoded).hexdigest()


def _sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdefABCDEF" for char in value)
    )


def _load_predictions(path: Path, task: str) -> Any:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        _exit_error("predictions_unreadable")

    key = _PREDICTION_KEYS[task]
    if not isinstance(payload, dict) or set(payload) != {key}:
        _exit_error("predictions_unreadable")

    rows = payload[key]
    if not isinstance(rows, list):
        _exit_error("predictions_unreadable")

    if task == "family":
        result = []
        for row in rows:
            if (
                not isinstance(row, dict)
                or set(row) != {"sample_sha256", "family_id"}
                or not _sha256(row["sample_sha256"])
                or not isinstance(row["family_id"], str)
            ):
                _exit_error("predictions_unreadable")
            result.append(
                evaluation.FamilyPrediction(
                    sample_sha256=row["sample_sha256"],
                    family_id=row["family_id"],
                )
            )
        return tuple(result)

    if task == "pair":
        result = []
        for row in rows:
            if (
                not isinstance(row, dict)
                or set(row) != {"query_sha256", "ranked"}
                or not _sha256(row["query_sha256"])
                or not isinstance(row["ranked"], list)
            ):
                _exit_error("predictions_unreadable")

            ranked: list[tuple[str, float]] = []
            for item in row["ranked"]:
                if (
                    not isinstance(item, list)
                    or len(item) != 2
                    or not _sha256(item[0])
                    or not isinstance(item[1], (int, float))
                    or isinstance(item[1], bool)
                    or not math.isfinite(float(item[1]))
                ):
                    _exit_error("predictions_unreadable")
                ranked.append((item[0], float(item[1])))

            result.append(
                evaluation.PairRanking(
                    query_sha256=row["query_sha256"],
                    ranked=tuple(ranked),
                )
            )
        return tuple(result)

    if task == "group":
        result = []
        for group in rows:
            if not isinstance(group, list) or not all(_sha256(item) for item in group):
                _exit_error("predictions_unreadable")
            result.append(tuple(group))
        return tuple(result)

    result = []
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row)
            != {
                "clue_ref",
                "subject_sha256",
                "predicted_verdict",
                "predicted_ownership",
                "evidence_ref",
            }
            or not isinstance(row["clue_ref"], str)
            or not _sha256(row["subject_sha256"])
            or not isinstance(row["predicted_verdict"], str)
            or not isinstance(row["predicted_ownership"], str)
            or (row["evidence_ref"] is not None and not isinstance(row["evidence_ref"], str))
        ):
            _exit_error("predictions_unreadable")

        result.append(
            evaluation.ClueCandidate(
                clue_ref=row["clue_ref"],
                subject_sha256=row["subject_sha256"],
                predicted_verdict=row["predicted_verdict"],
                predicted_ownership=row["predicted_ownership"],
                evidence_ref=row["evidence_ref"],
            )
        )
    return tuple(result)


def _evaluate(
    task: str,
    labels: Any,
    manifest: Any,
    split: str,
    params: dict[str, Any],
    predictions: Any,
) -> Any:
    try:
        if task == "family":
            return evaluation.evaluate_family(
                labels,
                manifest,
                split,
                params["level"],
                predictions,
                layers=params["layers"],
                known_unknown_samples=params["known_unknown_samples"],
            )
        if task == "pair":
            return evaluation.evaluate_pairs(
                labels,
                manifest,
                split,
                predictions,
                k=params["k"],
                layers=params["layers"],
                lineages=params["lineages"],
            )
        if task == "group":
            return evaluation.evaluate_groups(
                labels,
                manifest,
                split,
                predictions,
                layers=params["layers"],
                positive_subtypes=params["positive_subtypes"],
                cannot_link_subtypes=params["cannot_link_subtypes"],
                repack_subtypes=params["repack_subtypes"],
            )
        return evaluation.evaluate_clues(
            labels,
            manifest,
            split,
            predictions,
            top_n=params["top_n"],
            layers=params["layers"],
        )
    except evaluation.RecognitionEvaluationError as exc:
        typer.echo(f"error: {exc.reason_code}", err=True)
        raise typer.Exit(code=2) from None


def _json_value(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {
            field.name: _json_value(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return value


def _metrics(result: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    encoded = _json_value(result)
    provenance = encoded.pop("provenance")
    return provenance, encoded


def _load_gates(path: Path | None) -> Any:
    if path is None:
        return None
    payload = _read_json(path, "gates_invalid")
    if not isinstance(payload, dict):
        _exit_error("gates_invalid")

    for name, rule in payload.items():
        if not isinstance(name, str) or not isinstance(rule, dict):
            _exit_error("gates_invalid")
        if set(rule) not in ({"min"}, {"max"}):
            _exit_error("gates_invalid")
        threshold = next(iter(rule.values()))
        if (
            not isinstance(threshold, (int, float))
            or isinstance(threshold, bool)
            or not math.isfinite(float(threshold))
        ):
            _exit_error("gates_invalid")
    return payload


def _apply_gates(gates: Any, metrics: dict[str, Any], eligible: bool) -> dict[str, Any] | None:
    if gates is None:
        return None

    for name in gates:
        value = metrics.get(name)
        if name not in metrics or (
            value is not None and (not isinstance(value, (int, float)) or isinstance(value, bool))
        ):
            _exit_error("gates_invalid")

    checks: dict[str, Any] = {}
    if not eligible:
        status = "not_eligible"
        for name, rule in gates.items():
            operator = "min" if "min" in rule else "max"
            checks[name] = {
                "operator": operator,
                "threshold": rule[operator],
                "value": metrics[name],
                "verdict": "not_eligible",
            }
        return {"status": status, "checks": checks}

    failed = False
    for name, rule in gates.items():
        operator = "min" if "min" in rule else "max"
        threshold = rule[operator]
        value = metrics[name]
        passed = value is not None and (
            value >= threshold if operator == "min" else value <= threshold
        )
        if not passed:
            failed = True
        checks[name] = {
            "operator": operator,
            "threshold": threshold,
            "value": value,
            "verdict": "pass" if passed else "fail",
        }

    return {"status": "fail" if failed else "pass", "checks": checks}


@evaluate_app.command("evaluate")
def evaluate(
    manifest: Path = typer.Option(..., "--manifest", help="split manifest 路径。"),
    labels: Path = typer.Option(..., "--labels", help="识别标签 JSONL 路径。"),
    task: str = typer.Option(..., "--task", help="family|pair|group|clue。"),
    split: str = typer.Option(..., "--split", help="待评测切分名。"),
    params: Path = typer.Option(..., "--params", help="任务参数 JSON 路径。"),
    predictions: Path = typer.Option(..., "--predictions", help="预测 JSON 路径。"),
    out: Path = typer.Option(..., "--out", help="新建 metrics JSON 路径。"),
    gates: Path | None = typer.Option(None, "--gates", help="可选晋级门 JSON 路径。"),
) -> None:
    """评测单个识别任务；门 fail 或 not_eligible 时退出 4。"""
    if task not in _TASKS:
        _exit_error("params_invalid")
    if out.exists():
        _exit_error("out_exists")

    manifest_value, manifest_digest = _load_manifest(manifest)
    labels_value, labels_digest = _load_labels(labels)
    params_payload = _read_json(params, "params_invalid")
    params_value = _validate_params(task, params_payload)
    prediction_value = _load_predictions(predictions, task)

    result = _evaluate(
        task,
        labels_value,
        manifest_value,
        split,
        params_value,
        prediction_value,
    )
    provenance, metrics = _metrics(result)
    gate_payload = _load_gates(gates)
    gate_result = _apply_gates(
        gate_payload,
        metrics,
        bool(provenance["promotion_eligible"]),
    )

    document = {
        "schema_version": "1.0",
        "task": task,
        "split_name": split,
        "manifest_digest": manifest_digest,
        "labels_digest": labels_digest,
        "params": _json_value(params_payload),
        "provenance": provenance,
        "metrics": metrics,
        "gates": gate_result,
    }
    encoded = (
        json.dumps(
            document,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    ).encode("utf-8")

    try:
        published = atomic_create_bytes(out, encoded)
    except OSError:
        _exit_error("out_unwritable")
    if not published:
        _exit_error("out_exists")

    evaluated = provenance["evaluated_count"]
    eligible = provenance["promotion_eligible"]
    summary = f"task={task} split={split} evaluated={evaluated} promotion_eligible={str(eligible)}"
    if gate_result is not None:
        summary += f" gates={gate_result['status']}"
    typer.echo(summary)

    if gate_result is not None and gate_result["status"] != "pass":
        raise typer.Exit(code=4)
