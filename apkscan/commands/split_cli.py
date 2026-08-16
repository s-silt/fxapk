"""fxapk recognize split-manifest 构建与校验命令。"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import typer

from apkscan.core import corpus_catalog
from apkscan.core import recognition_labels as rlabels
from apkscan.core import recognition_training as rtraining
from apkscan.core.atomic import atomic_create_bytes


split_app = typer.Typer(
    help="构建或校验识别 split-manifest；离线只读，不联网、不启动子进程。",
    no_args_is_help=True,
)

_SPLIT_NAMES = (
    "train",
    "test_temporal_seen",
    "test_unseen_family",
    "test_adversarial",
    "calibration",
)

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CONFIG_KEYS = {
    "cutoff_date",
    "unseen_families",
    "adversarial_samples",
    "calibration_samples",
    "derivations",
    "policy_version",
}


def _exit_error(message: str) -> None:
    typer.echo(f"error: {message}", err=True)
    raise typer.Exit(code=2)


def _read_json(path: Path, error_message: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        _exit_error(error_message)


def _is_date(value: object) -> bool:
    return isinstance(value, str) and bool(_DATE_RE.fullmatch(value))


def _load_time_table(path: Path) -> dict[str, str]:
    payload = _read_json(path, "time_table_invalid")

    if not isinstance(payload, dict):
        _exit_error("time_table_invalid")

    result: dict[str, str] = {}
    for case_id, date in payload.items():
        if not isinstance(case_id, str) or not _is_date(date):
            _exit_error("time_table_invalid")
        result[case_id] = date

    return result


def _string_tuple(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list):
        return None
    if not all(isinstance(item, str) for item in value):
        return None
    return tuple(value)


def _load_config(path: Path) -> dict[str, Any]:
    payload = _read_json(path, "config_invalid")

    if not isinstance(payload, dict):
        _exit_error("config_invalid")
    if set(payload) != _CONFIG_KEYS:
        _exit_error("config_invalid")

    cutoff_date = payload["cutoff_date"]
    policy_version = payload["policy_version"]
    unseen_families = _string_tuple(payload["unseen_families"])
    adversarial_samples = _string_tuple(payload["adversarial_samples"])
    calibration_samples = _string_tuple(payload["calibration_samples"])
    derivations_value = payload["derivations"]

    if not _is_date(cutoff_date):
        _exit_error("config_invalid")
    if not isinstance(policy_version, str):
        _exit_error("config_invalid")
    if unseen_families is None:
        _exit_error("config_invalid")
    if adversarial_samples is None:
        _exit_error("config_invalid")
    if calibration_samples is None:
        _exit_error("config_invalid")

    if not isinstance(derivations_value, list):
        _exit_error("config_invalid")

    derivations: list[tuple[str, str]] = []
    for item in derivations_value:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or not isinstance(item[0], str)
            or not isinstance(item[1], str)
        ):
            _exit_error("config_invalid")
        derivations.append((item[0], item[1]))

    return {
        "cutoff_date": cutoff_date,
        "unseen_families": unseen_families,
        "adversarial_samples": adversarial_samples,
        "calibration_samples": calibration_samples,
        "derivations": tuple(derivations),
        "policy_version": policy_version,
    }


def _load_labels(path: Path) -> tuple[Any, str]:
    try:
        label_bytes = path.read_bytes()
    except Exception:
        _exit_error("labels_unreadable at line 0")

    try:
        label_set = rlabels.load_recognition_labels(path)
    except rlabels.RecognitionLabelValidationError as exc:
        typer.echo(f"error: {exc.code} at line {exc.line}", err=True)
        raise typer.Exit(code=2) from None
    except Exception:
        _exit_error("labels_unreadable at line 0")

    return label_set, hashlib.sha256(label_bytes).hexdigest()


def _catalog_inputs(corpus: Path) -> tuple[list[dict], str]:
    try:
        rows, diagnostics = corpus_catalog.read_catalog(corpus)
    except Exception:
        _exit_error("catalog_corrupt")

    if diagnostics:
        _exit_error("catalog_corrupt")

    try:
        revision = corpus_catalog.catalog_revision(corpus)
    except Exception:
        _exit_error("catalog_corrupt")

    return rows, revision


def _unit_sample_count(unit: Any) -> int:
    members = getattr(unit, "members", ())
    return len(members)


def _print_manifest_summary(manifest: Any, encoded: bytes) -> None:
    for name in _SPLIT_NAMES:
        units = tuple(manifest.splits[name])
        samples = sum(_unit_sample_count(unit) for unit in units)
        typer.echo(f"split {name} units={len(units)} samples={samples}")

    typer.echo(f"excluded_rows={manifest.excluded_row_count}")
    typer.echo(f"digest={hashlib.sha256(encoded).hexdigest()}")


@split_app.command("build")
def build(
    corpus: Path = typer.Option(
        ...,
        "--corpus",
        help="catalog 所在 corpus 目录。",
    ),
    labels: Path = typer.Option(
        ...,
        "--labels",
        help="识别标签 JSONL 文件路径。",
    ),
    time_table: Path = typer.Option(
        ...,
        "--time-table",
        help="case 日期 JSON 文件路径。",
    ),
    config: Path = typer.Option(
        ...,
        "--config",
        help="split 策略配置 JSON 文件路径。",
    ),
    out: Path = typer.Option(
        ...,
        "--out",
        help="新建的 manifest.json 文件路径。",
    ),
) -> None:
    """根据 catalog、标签、日期表和配置构建 split-manifest。"""
    if out.exists():
        _exit_error("out_exists")

    catalog_rows, catalog_revision = _catalog_inputs(corpus)
    label_set, labels_digest = _load_labels(labels)
    time_values = _load_time_table(time_table)
    config_values = _load_config(config)

    split_config = rtraining.SplitConfig(
        cutoff_date=config_values["cutoff_date"],
        unseen_families=config_values["unseen_families"],
        adversarial_samples=config_values["adversarial_samples"],
        calibration_samples=config_values["calibration_samples"],
        derivations=config_values["derivations"],
        policy_version=config_values["policy_version"],
        labels_digest=labels_digest,
        catalog_revision=catalog_revision,
    )

    try:
        manifest = rtraining.build_split_manifest(
            catalog_rows=catalog_rows,
            label_set=label_set,
            time_table=time_values,
            config=split_config,
        )
        encoded_text = rtraining.encode_split_manifest(manifest)
    except rtraining.SplitManifestError as exc:
        # 只输出稳定码：detail 含 case/日期/sha 等动态输入，回显会造成外带
        # 泄漏面（codex 复审 P1）。
        typer.echo(f"error: {exc.reason_code}", err=True)
        raise typer.Exit(code=2) from None

    encoded = encoded_text.encode("utf-8")

    # 原子 create-only 发布：临时文件 fsync 后以 no-replace 原语落盘，
    # 写中断绝不留截断目标文件（codex 复审 P1）。
    try:
        published = atomic_create_bytes(out, encoded)
    except OSError:
        _exit_error("out_unwritable")
    if not published:
        _exit_error("out_exists")

    _print_manifest_summary(manifest, encoded)


@split_app.command("validate")
def validate(
    manifest: Path = typer.Option(
        ...,
        "--manifest",
        help="待校验的 split-manifest 文件路径。",
    ),
) -> None:
    """只读加载并校验 split-manifest。"""
    try:
        encoded = manifest.read_bytes()
        text = encoded.decode("utf-8")
    except Exception:
        _exit_error("manifest_unreadable")

    try:
        loaded = rtraining.load_split_manifest(text)
    except rtraining.SplitManifestError as exc:
        typer.echo(f"error: {exc.reason_code}", err=True)
        raise typer.Exit(code=2) from None
    except Exception:
        _exit_error("manifest_invalid")

    _print_manifest_summary(loaded, encoded)
