"""既有报告与当前分析修订的兼容提示：只比较复现坐标，不读案件正文。"""

from __future__ import annotations

from apkscan.core.report_compat import report_revision_warnings


def _warnings(
    meta: dict,
    *,
    version: str = "1.3.2",
    commit: str | None = "new456",
    rules: str | None = "rules-new",
) -> list[str]:
    return report_revision_warnings(
        meta,
        current_version=version,
        current_build_commit=commit,
        current_ruleset_digest=rules,
    )


def test_same_revision_has_no_warning() -> None:
    meta = {
        "tool_version": "1.3.2",
        "ruleset_digest": "rules-new",
        "evidence_manifest": {"build_commit": "new456"},
    }

    assert _warnings(meta) == []


def test_same_version_different_commit_warns() -> None:
    warnings = _warnings({
        "tool_version": "1.3.2",
        "ruleset_digest": "rules-new",
        "evidence_manifest": {"build_commit": "old123"},
    })

    assert len(warnings) == 1
    assert "代码修订" in warnings[0]
    assert "重新分析" in warnings[0]


def test_version_and_ruleset_mismatches_share_one_warning() -> None:
    warnings = _warnings({
        "tool_version": "1.3.1",
        "ruleset_digest": "rules-old",
        "evidence_manifest": {"build_commit": "new456"},
    })

    assert len(warnings) == 1
    assert "工具版本" in warnings[0]
    assert "规则摘要" in warnings[0]


def test_manifest_version_is_used_when_meta_version_is_absent() -> None:
    meta = {
        "ruleset_digest": "rules-new",
        "evidence_manifest": {
            "tool_version": "1.3.2",
            "build_commit": "new456",
        },
    }

    assert _warnings(meta) == []


def test_legacy_report_without_version_warns() -> None:
    warnings = _warnings({"ruleset_digest": "rules-new"})

    assert len(warnings) == 1
    assert "未记录工具版本" in warnings[0]


def test_unavailable_build_commits_do_not_create_a_false_mismatch() -> None:
    meta = {
        "tool_version": "1.3.2",
        "ruleset_digest": "rules-new",
        "evidence_manifest": {"build_commit": "old123"},
    }

    assert _warnings(meta, commit=None) == []


def test_malformed_meta_is_treated_as_a_legacy_report() -> None:
    warnings = report_revision_warnings(
        None,  # type: ignore[arg-type]
        current_version="1.3.2",
        current_build_commit=None,
        current_ruleset_digest=None,
    )

    assert len(warnings) == 1
    assert "未记录工具版本" in warnings[0]
