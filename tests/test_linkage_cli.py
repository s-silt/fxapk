"""CLI contracts for private linkage labels and aggregate evaluation."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from apkscan import cli
from apkscan.core import corpus, linkage_labels
from apkscan.core.linkage_ml import (
    LinkageModelArtifact,
    PAIR_FEATURE_NAMES,
    PAIR_FEATURE_SCHEMA_VERSION,
    current_rule_engine_contract,
)


def _sha(char: str) -> str:
    return char * 64


def _report(sample: str, native_sha: str) -> dict:
    return {
        "schema_version": "1.0",
        "analysis_status": "complete",
        "completeness": 1.0,
        "package_name": "com.example.fixture",
        "meta": {
            "sample_sha256": sample,
            "tool_version": "1.6.1",
            "ruleset_digest": "rules",
            "native_lib_hashes": [{"name": "libfixturecore.so", "sha256": native_sha, "size": 123}],
            "repack_identity": {"verdict": "unknown"},
        },
        "leads": [],
        "endpoints": [],
        "findings": [],
    }


def _add_report(corpus_dir, sample: str, native_sha: str, case_id: str) -> None:  # noqa: ANN001
    report = _report(sample, native_sha)
    result = corpus.add_report(
        corpus_dir,
        report,
        json.dumps(report, sort_keys=True),
        case_id=case_id,
    )
    assert result["added"] is True


def _family(sample: str, family_id: str) -> dict:
    return {
        "kind": "family_membership",
        "schema_version": "1.0",
        "sample_sha256": sample,
        "family_id": family_id,
        "relation_subtype": "binary_lineage",
        "status": "confirmed",
        "label_basis": ["independent-review"],
        "reason_codes": ["manual-diff"],
        "evidence_ref": "fixture-evidence-bundle-001",
    }


def _write_jsonl(path, rows: list[dict]) -> None:  # noqa: ANN001
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def test_link_evaluate_cli_is_aggregate_only(tmp_path) -> None:
    sample_a, sample_b, sample_c = _sha("a"), _sha("b"), _sha("c")
    native_sha = _sha("f")
    corpus_dir = tmp_path / "corpus"
    _add_report(corpus_dir, sample_a, native_sha, "private-case-a")
    _add_report(corpus_dir, sample_b, native_sha, "private-case-b")
    _add_report(corpus_dir, sample_c, native_sha, "private-case-c")
    labels = tmp_path / "private-labels.jsonl"
    _write_jsonl(
        labels,
        [
            _family(sample_a, "private-family"),
            _family(sample_b, "private-family"),
            {
                "kind": "pair_judgment",
                "schema_version": "1.0",
                "left_sha256": sample_a,
                "right_sha256": sample_c,
                "relation": "negative",
                "relation_subtype": "technical_link_relevant",
                "status": "confirmed",
                "reason_codes": ["manual-diff"],
                "sampling_class": "hard",
                "label_basis": ["independent-review"],
                "evidence_ref": "fixture-evidence-bundle-001",
            },
        ],
    )

    result = CliRunner().invoke(
        cli.app,
        [
            "corpus",
            "link-evaluate",
            "--corpus",
            str(corpus_dir),
            "--labels",
            str(labels),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "不做脱敏" not in result.stderr
    payload = json.loads(result.stdout)
    assert payload["experimental"] is True
    assert payload["privacy"]["aggregate_only"] is True
    assert payload["rules_cap_regression"]["status"] == "blocked"
    assert payload["rules_cap_regression"]["model_training"]["unlocked_by_this_tier"] is False
    assert payload["input_options"] == {
        "engine": "rules-v2",
        "include_quarantined": False,
    }
    for private_value in (
        sample_a,
        sample_b,
        sample_c,
        native_sha,
        "private-family",
        "private-case-a",
        "private-case-b",
        "private-case-c",
        str(labels),
    ):
        assert private_value not in result.stdout
        assert private_value not in result.stderr


def test_link_labels_validate_and_invalid_engine_exit_contract(tmp_path) -> None:
    labels = tmp_path / "labels.jsonl"
    _write_jsonl(labels, [_family(_sha("a"), "family-1")])
    runner = CliRunner()

    validated = runner.invoke(cli.app, ["corpus", "link-labels-validate", "--labels", str(labels)])
    assert validated.exit_code == 0, validated.output
    payload = json.loads(validated.stdout)
    assert payload["valid"] is True
    assert payload["record_count"] == 1
    assert _sha("a") not in validated.stdout
    assert "family-1" not in validated.stdout

    rejected = runner.invoke(
        cli.app,
        [
            "corpus",
            "link-evaluate",
            "--labels",
            str(labels),
            "--engine",
            "unknown",
            "--corpus",
            str(tmp_path / "unused-corpus"),
        ],
    )
    assert rejected.exit_code == 2
    assert "rules-v2" in rejected.stderr


def test_link_labels_validate_enforces_independent_review_evidence_ref(tmp_path) -> None:
    """真入口：带 evidence_ref 的 independent-review 标签能过，缺失/空白的被拒。"""
    runner = CliRunner()

    accepted = tmp_path / "labels-with-evidence.jsonl"
    _write_jsonl(accepted, [_family(_sha("a"), "family-1")])
    ok = runner.invoke(cli.app, ["corpus", "link-labels-validate", "--labels", str(accepted)])
    assert ok.exit_code == 0, ok.output
    assert json.loads(ok.stdout)["valid"] is True

    missing = _family(_sha("a"), "family-1")
    missing.pop("evidence_ref")
    rejected = tmp_path / "labels-missing-evidence.jsonl"
    _write_jsonl(rejected, [missing])
    denied = runner.invoke(cli.app, ["corpus", "link-labels-validate", "--labels", str(rejected)])
    assert denied.exit_code == 2
    assert "fixture-evidence-bundle-001" not in denied.stderr

    blank = _family(_sha("a"), "family-1")
    blank["evidence_ref"] = "   "
    blank_path = tmp_path / "labels-blank-evidence.jsonl"
    _write_jsonl(blank_path, [blank])
    blank_denied = runner.invoke(
        cli.app, ["corpus", "link-labels-validate", "--labels", str(blank_path)]
    )
    assert blank_denied.exit_code == 2


def test_invalid_or_in_worktree_labels_fail_without_echoing_values(tmp_path, monkeypatch) -> None:
    private_value = _sha("e")
    private_field = "case-2026-secret-name"
    labels = tmp_path / "invalid.jsonl"
    _write_jsonl(labels, [_family(private_value, "family-1") | {private_field: private_value}])
    runner = CliRunner()

    invalid = runner.invoke(cli.app, ["corpus", "link-labels-validate", "--labels", str(labels)])
    assert invalid.exit_code == 2
    assert private_value not in invalid.stderr
    assert private_field not in invalid.stderr
    assert str(labels) not in invalid.stderr

    monkeypatch.setattr("apkscan.commands.corpus._inside_git_worktree", lambda _path: True)
    blocked = runner.invoke(cli.app, ["corpus", "link-labels-validate", "--labels", str(labels)])
    assert blocked.exit_code == 2
    assert str(labels) not in blocked.stderr


def test_semantic_label_conflicts_fail_closed_across_cli_gates(tmp_path) -> None:
    sample_a, sample_b = _sha("a"), _sha("b")
    native_sha = _sha("f")
    corpus_dir = tmp_path / "corpus"
    _add_report(corpus_dir, sample_a, native_sha, "private-case-a")
    _add_report(corpus_dir, sample_b, native_sha, "private-case-b")
    labels = tmp_path / "private-conflicting-labels.jsonl"
    family_id = "private-conflicting-family"
    _write_jsonl(
        labels,
        [
            _family(sample_a, family_id),
            _family(sample_b, family_id),
            {
                "kind": "pair_judgment",
                "schema_version": "1.0",
                "left_sha256": sample_a,
                "right_sha256": sample_b,
                "relation": "negative",
                "relation_subtype": "technical_link_relevant",
                "status": "confirmed",
                "reason_codes": ["manual-diff"],
                "sampling_class": "hard",
                "label_basis": ["independent-review"],
                "evidence_ref": "fixture-evidence-bundle-001",
            },
        ],
    )
    model_out = tmp_path / "private-model.json"
    commands = [
        ["corpus", "link-labels-validate", "--labels", str(labels)],
        [
            "corpus", "link-readiness", "--labels", str(labels),
            "--corpus", str(corpus_dir),
        ],
        [
            "corpus", "link-train", "--labels", str(labels),
            "--model-out", str(model_out), "--corpus", str(corpus_dir),
        ],
    ]

    for command in commands:
        result = CliRunner().invoke(cli.app, command)
        assert result.exit_code == 2, result.output
        for private_value in (sample_a, sample_b, native_sha, family_id, str(labels)):
            assert private_value not in result.stdout
            assert private_value not in result.stderr
    assert model_out.exists() is False


def test_missing_private_label_path_is_never_echoed_by_typer(tmp_path) -> None:
    secret_path = tmp_path / "secret-investigation" / "missing-labels.jsonl"
    model_out = tmp_path / "outside-model.json"
    commands = [
        ["corpus", "link-labels-validate", "--labels", str(secret_path)],
        ["corpus", "link-evaluate", "--labels", str(secret_path)],
        ["corpus", "link-discover", "--labels", str(secret_path)],
        ["corpus", "link-readiness", "--labels", str(secret_path)],
        [
            "corpus",
            "link-train",
            "--labels",
            str(secret_path),
            "--model-out",
            str(model_out),
        ],
    ]

    for command in commands:
        result = CliRunner().invoke(cli.app, command)
        assert result.exit_code == 1, result.output
        assert str(secret_path) not in result.stdout
        assert str(secret_path) not in result.stderr


def test_existing_private_model_output_directory_is_never_echoed(tmp_path) -> None:
    secret_path = tmp_path / "secret-investigation" / "missing-labels.jsonl"
    model_out = tmp_path / "private-case-model-output"
    model_out.mkdir()

    result = CliRunner().invoke(
        cli.app,
        [
            "corpus",
            "link-train",
            "--labels",
            str(secret_path),
            "--model-out",
            str(model_out),
        ],
    )

    assert result.exit_code == 1, result.output
    assert str(secret_path) not in result.stdout
    assert str(secret_path) not in result.stderr
    assert str(model_out) not in result.stdout
    assert str(model_out) not in result.stderr


def test_unreadable_private_label_path_uses_safe_loader_error(tmp_path, monkeypatch) -> None:
    secret_path = tmp_path / "restricted-investigation" / "labels.jsonl"

    def _unreadable(_path):  # noqa: ANN001
        try:
            raise OSError("permission denied")
        except OSError as exc:
            raise linkage_labels.LabelValidationError(
                "unable to read label file as UTF-8"
            ) from exc

    monkeypatch.setattr(linkage_labels, "load_linkage_labels", _unreadable)
    result = CliRunner().invoke(
        cli.app,
        ["corpus", "link-labels-validate", "--labels", str(secret_path)],
    )

    assert result.exit_code == 1, result.output
    assert str(secret_path) not in result.stdout
    assert str(secret_path) not in result.stderr


def test_empty_labels_are_reported_as_insufficient_without_failing_cli(tmp_path) -> None:
    corpus_dir = tmp_path / "corpus"
    _add_report(corpus_dir, _sha("a"), _sha("f"), "private-case")
    labels = tmp_path / "empty.jsonl"
    labels.write_text("", encoding="utf-8")

    result = CliRunner().invoke(
        cli.app,
        [
            "corpus",
            "link-evaluate",
            "--corpus",
            str(corpus_dir),
            "--labels",
            str(labels),
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["status"] == "insufficient_independent_labels"


def test_link_discover_cli_omits_private_values_by_default(tmp_path) -> None:
    sample_a, sample_b = _sha("a"), _sha("b")
    native_sha = _sha("f")
    corpus_dir = tmp_path / "corpus"
    _add_report(corpus_dir, sample_a, native_sha, "private-case-a")
    _add_report(corpus_dir, sample_b, native_sha, "private-case-b")
    labels = tmp_path / "private-labels.jsonl"
    _write_jsonl(
        labels,
        [_family(sample_a, "private-family"), _family(sample_b, "private-family")],
    )

    result = CliRunner().invoke(
        cli.app,
        [
            "corpus",
            "link-discover",
            "--corpus",
            str(corpus_dir),
            "--labels",
            str(labels),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["status"] == "complete"
    assert payload["privacy"]["contains_raw_identifiers"] is False
    assert payload["input_options"] == {
        "include_quarantined": False,
        "evidence_values": "omit",
    }
    assert "不做脱敏" not in result.stderr
    for private_value in (
        sample_a,
        sample_b,
        native_sha,
        "private-family",
        "private-case-a",
        "private-case-b",
        str(labels),
    ):
        assert private_value not in result.stdout
        assert private_value not in result.stderr


def test_link_discover_raw_requires_explicit_mode_and_warns(tmp_path) -> None:
    sample_a, sample_b = _sha("a"), _sha("b")
    native_sha = _sha("f")
    corpus_dir = tmp_path / "corpus"
    _add_report(corpus_dir, sample_a, native_sha, "case-a")
    _add_report(corpus_dir, sample_b, native_sha, "case-b")
    labels = tmp_path / "labels.jsonl"
    family_id = "sensitivegroupmarker"
    _write_jsonl(labels, [_family(sample_a, family_id), _family(sample_b, family_id)])

    result = CliRunner().invoke(
        cli.app,
        [
            "corpus",
            "link-discover",
            "--corpus",
            str(corpus_dir),
            "--labels",
            str(labels),
            "--evidence-values",
            "raw",
        ],
    )

    assert result.exit_code == 0, result.output
    assert native_sha in result.stdout
    assert "family" in result.stdout
    assert "不做脱敏" in result.stderr


def test_link_discover_rejects_ambiguous_value_mode(tmp_path) -> None:
    labels = tmp_path / "labels.jsonl"
    labels.write_text("", encoding="utf-8")

    result = CliRunner().invoke(
        cli.app,
        [
            "corpus",
            "link-discover",
            "--corpus",
            str(tmp_path / "unused-corpus"),
            "--labels",
            str(labels),
            "--evidence-values",
            "masked",
        ],
    )

    assert result.exit_code == 2
    assert "omit" in result.stderr
    assert "raw" in result.stderr


def test_review_cli_defaults_to_identifier_free_output(tmp_path) -> None:
    sample_a, sample_b = _sha("a"), _sha("b")
    native_sha = _sha("f")
    corpus_dir = tmp_path / "corpus"
    _add_report(corpus_dir, sample_a, native_sha, "private-case-a")
    _add_report(corpus_dir, sample_b, native_sha, "private-case-b")
    runner = CliRunner()

    explained = runner.invoke(
        cli.app,
        [
            "corpus",
            "link-explain",
            sample_a,
            sample_b,
            "--corpus",
            str(corpus_dir),
        ],
    )
    grouped = runner.invoke(
        cli.app,
        ["corpus", "link-groups", "--corpus", str(corpus_dir)],
    )

    assert explained.exit_code == 0, explained.output
    assert grouped.exit_code == 0, grouped.output
    assert json.loads(explained.stdout)["evidence_values"] == "omit"
    assert json.loads(grouped.stdout)["evidence_values"] == "omit"
    assert "不做脱敏" not in explained.stderr
    assert "不做脱敏" not in grouped.stderr
    for rendered in (explained.stdout, grouped.stdout):
        for private_value in (
            sample_a,
            sample_b,
            native_sha,
            "private-case-a",
            "private-case-b",
        ):
            assert private_value not in rendered


def test_training_cli_blocks_before_writing_when_default_gate_is_unmet(tmp_path) -> None:
    sample_a, sample_b = _sha("a"), _sha("b")
    native_sha = _sha("f")
    corpus_dir = tmp_path / "corpus"
    _add_report(corpus_dir, sample_a, native_sha, "private-case-a")
    _add_report(corpus_dir, sample_b, native_sha, "private-case-b")
    labels = tmp_path / "labels.jsonl"
    family_id = "sensitivegroupmarker"
    _write_jsonl(labels, [_family(sample_a, family_id), _family(sample_b, family_id)])
    model_out = tmp_path / "model.json"
    runner = CliRunner()

    readiness = runner.invoke(
        cli.app,
        [
            "corpus",
            "link-readiness",
            "--corpus",
            str(corpus_dir),
            "--labels",
            str(labels),
        ],
    )
    trained = runner.invoke(
        cli.app,
        [
            "corpus",
            "link-train",
            "--corpus",
            str(corpus_dir),
            "--labels",
            str(labels),
            "--model-out",
            str(model_out),
        ],
    )

    assert readiness.exit_code == 0, readiness.output
    assert trained.exit_code == 0, trained.output
    assert json.loads(readiness.stdout)["status"] == "blocked"
    train_payload = json.loads(trained.stdout)
    assert train_payload["status"] == "blocked"
    assert train_payload["artifact_written"] is False
    assert model_out.exists() is False
    for rendered in (readiness.stdout, trained.stdout):
        for private_value in (sample_a, sample_b, native_sha, family_id):
            assert private_value not in rendered


def _hex(value: int) -> str:
    return f"{value:02x}" * 32


def _hard_negative(left: str, right: str) -> dict:
    return {
        "kind": "pair_judgment",
        "schema_version": "1.0",
        "left_sha256": left,
        "right_sha256": right,
        "relation": "negative",
        "relation_subtype": "technical_link_relevant",
        "status": "confirmed",
        "reason_codes": ["shared-commodity-component"],
        "sampling_class": "hard",
        "label_basis": ["independent-review"],
        "evidence_ref": "fixture-evidence-bundle-001",
    }


def test_regression_tier_ready_never_unlocks_training_via_cli(tmp_path) -> None:
    """★后门锁（真入口）：回归档 ready 时生产档照旧 blocked，link-train 拒训且零 artifact。

    语料：9 个样本共享同一强 native 锚 → 36 个被召回的单锚候选，全部按独立复核确认为
    hard negative（≥30 → 回归档 ready）；另 3 个种子族（native 依据、feature-overlapping）
    只提供家族多样性，不产生独立正例 → 生产档因独立正例为 0 保持
    insufficient_independent_labels。突变验证目标：把 train_linkage_challenger 的
    readiness 门禁改坏（如恒放行），本测试必须变红。
    """
    corpus_dir = tmp_path / "corpus"
    cluster = [_hex(0x10 + index) for index in range(9)]
    shared_native = _hex(0xF0)
    for sample in cluster:
        _add_report(corpus_dir, sample, shared_native, "private-case-cluster")
    family_samples: list[str] = []
    records: list[dict] = []
    for family_number in range(3):
        for member_number in range(2):
            offset = family_number * 2 + member_number
            sample = _hex(0x30 + offset)
            family_samples.append(sample)
            _add_report(corpus_dir, sample, _hex(0xE0 + offset), "private-case-family")
            records.append(
                {
                    "kind": "family_membership",
                    "schema_version": "1.0",
                    "sample_sha256": sample,
                    "family_id": f"opaque-family-{family_number}",
                    "relation_subtype": "binary_lineage",
                    "status": "confirmed",
                    "label_basis": ["native-binary-review"],
                }
            )
    records.extend(
        _hard_negative(left, right)
        for index, left in enumerate(cluster)
        for right in cluster[index + 1 :]
    )
    labels = tmp_path / "labels.jsonl"
    _write_jsonl(labels, records)
    model_out = tmp_path / "model.json"
    runner = CliRunner()

    readiness = runner.invoke(
        cli.app,
        ["corpus", "link-readiness", "--corpus", str(corpus_dir), "--labels", str(labels)],
    )
    trained = runner.invoke(
        cli.app,
        [
            "corpus",
            "link-train",
            "--corpus",
            str(corpus_dir),
            "--labels",
            str(labels),
            "--model-out",
            str(model_out),
        ],
    )

    assert readiness.exit_code == 0, readiness.output
    payload = json.loads(readiness.stdout)
    tier = payload["rules_cap_regression"]
    # 回归档确实 ready，且输出自我标识：只背书封顶回归声明，明说不解锁训练、不产 artifact。
    assert tier["tier"] == "rules-v2-cap-regression-v1"
    assert tier["status"] == "ready_for_cap_regression"
    assert tier["claim_supported"] is True
    assert tier["counts"]["recalled_independent_hard_negative_pair_count"] == 36
    assert tier["counts"]["confirmed_family_group_count"] == 3
    assert tier["model_training"]["gated_by_this_tier"] is False
    assert tier["model_training"]["unlocked_by_this_tier"] is False
    assert tier["produces_model_artifact"] is False
    # 生产档顶层原样 fail-closed，不被 ready 的回归档影响。
    assert payload["status"] == "blocked"
    assert payload["reason"] == "insufficient_independent_labels"

    assert trained.exit_code == 0, trained.output
    train_payload = json.loads(trained.stdout)
    assert train_payload["status"] == "blocked"
    assert train_payload["reason"] == "insufficient_independent_labels"
    assert train_payload["artifact_written"] is False
    assert model_out.exists() is False
    # 训练路径根本不咨询回归档：输出里没有它，也就没有可被误读的"已达标"信号。
    assert "rules_cap_regression" not in train_payload

    for rendered in (readiness.stdout, trained.stdout):
        for private_value in (*cluster, *family_samples, shared_native):
            assert private_value not in rendered


def test_link_candidates_applies_explicit_shadow_model_after_full_rule_recall(
    tmp_path, monkeypatch
) -> None:
    sample_a, sample_b = _sha("a"), _sha("b")
    native_sha = _sha("f")
    corpus_dir = tmp_path / "corpus"
    _add_report(corpus_dir, sample_a, native_sha, "case-a")
    _add_report(corpus_dir, sample_b, native_sha, "case-b")
    model_path = tmp_path / "model.json"
    model_path.write_text("{}", encoding="utf-8")
    rule_contract = current_rule_engine_contract()
    model = LinkageModelArtifact(
        model_id="fxapk-linkage-logreg-v1",
        feature_schema_version=PAIR_FEATURE_SCHEMA_VERSION,
        feature_names=PAIR_FEATURE_NAMES,
        rule_policy_id=rule_contract["policy_id"],
        rule_policy_digest=rule_contract["policy_digest"],
        rule_result_schema_version=rule_contract["result_schema_version"],
        rule_feature_schema_version=rule_contract["feature_schema_version"],
        rule_normalization_version=rule_contract["normalization_version"],
        scaler_mean=tuple(0.0 for _ in PAIR_FEATURE_NAMES),
        scaler_scale=tuple(1.0 for _ in PAIR_FEATURE_NAMES),
        coefficients=tuple(0.0 for _ in PAIR_FEATURE_NAMES),
        intercept=0.0,
        artifact_digest=_sha("d"),
    )
    monkeypatch.setattr(
        "apkscan.commands.corpus._load_private_linkage_model", lambda _path: model
    )

    result = CliRunner().invoke(
        cli.app,
        [
            "corpus",
            "link-candidates",
            "--corpus",
            str(corpus_dir),
            "--model",
            str(model_path),
            "--limit",
            "1",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["ml"]["status"] == "applied"
    assert payload["ml"]["candidate_space"] == "deterministic_rule_candidates_only"
    assert payload["count"] == 1
    assert payload["total_before_limit"] == 1
    assert payload["candidates"][0]["ml_rank"] == 1
    assert payload["candidates"][0]["rank"] == 1


def test_missing_private_model_path_is_not_echoed_by_typer(tmp_path) -> None:
    corpus_dir = tmp_path / "corpus"
    _add_report(corpus_dir, _sha("a"), _sha("f"), "case-a")
    secret_path = tmp_path / "secret-investigation" / "missing-model.json"

    result = CliRunner().invoke(
        cli.app,
        [
            "corpus",
            "link-candidates",
            "--corpus",
            str(corpus_dir),
            "--model",
            str(secret_path),
        ],
    )

    assert result.exit_code == 1, result.output
    assert str(secret_path) not in result.stdout
    assert str(secret_path) not in result.stderr


def _safe_linkage_commands(labels, model_out, corpus_dir) -> list[list[str]]:  # noqa: ANN001
    return [
        ["corpus", "link-evaluate", "--labels", str(labels), "--corpus", str(corpus_dir)],
        ["corpus", "link-discover", "--labels", str(labels), "--corpus", str(corpus_dir)],
        ["corpus", "link-explain", _sha("a"), _sha("b"), "--corpus", str(corpus_dir)],
        ["corpus", "link-groups", "--corpus", str(corpus_dir)],
        ["corpus", "link-readiness", "--labels", str(labels), "--corpus", str(corpus_dir)],
        [
            "corpus",
            "link-train",
            "--labels",
            str(labels),
            "--model-out",
            str(model_out),
            "--corpus",
            str(corpus_dir),
        ],
    ]


def test_aggregate_and_omit_commands_hide_rejected_corpus_path(tmp_path, monkeypatch) -> None:
    labels = tmp_path / "labels.jsonl"
    labels.write_text("", encoding="utf-8")
    model_out = tmp_path / "model.json"
    private_corpus = tmp_path / "case-2026-secret-corpus"
    original = __import__("apkscan.commands.corpus", fromlist=["_inside_git_worktree"])
    real_inside = original._inside_git_worktree
    monkeypatch.setattr(
        "apkscan.commands.corpus._inside_git_worktree",
        lambda path: path == private_corpus or real_inside(path),
    )

    for command in _safe_linkage_commands(labels, model_out, private_corpus):
        result = CliRunner().invoke(cli.app, command)
        assert result.exit_code == 2, result.output
        assert str(private_corpus) not in result.stdout
        assert str(private_corpus) not in result.stderr


def test_aggregate_and_omit_commands_hide_manifest_error_paths(tmp_path, monkeypatch) -> None:
    labels = tmp_path / "labels.jsonl"
    labels.write_text("", encoding="utf-8")
    model_out = tmp_path / "model.json"
    corpus_dir = tmp_path / "corpus"
    private_path = tmp_path / "case-2026-secret-corpus" / "manifest.jsonl"

    def _broken_manifest(_root):  # noqa: ANN001
        raise OSError(f"cannot read manifest at {private_path}")

    monkeypatch.setattr(corpus, "load_materialized_manifest", _broken_manifest)

    for command in _safe_linkage_commands(labels, model_out, corpus_dir):
        result = CliRunner().invoke(cli.app, command)
        assert result.exit_code == 1, result.output
        assert str(corpus_dir) not in result.stdout
        assert str(corpus_dir) not in result.stderr
        assert str(private_path) not in result.stdout
        assert str(private_path) not in result.stderr
