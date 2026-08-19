"""P3-E1 红态契约：visibility → EvidenceGap 纯函数层（gap_production）。

契约见 docs/superpowers/specs/2026-08-17-p3e-gap-production-design.md：只消费
blocked_claims、责任来源聚合、fail-closed 三口（schema/unattributable/claim_unknown）、
确定性。夹具按 visibility.assess schema 1.1 真实形态构造。
"""

from __future__ import annotations

import pytest

from apkscan.core import recognition_contract as rc
from apkscan.core.gap_production import (
    GAP_PRODUCTION_VERSION,
    GapProductionError,
    build_visibility_gaps,
)

QUESTION_ID = "question-sha256:" + "ab" * 32


def _producer(kind: rc.ProducerKind = rc.ProducerKind.SYSTEM) -> rc.ProducerRef:
    return rc.ProducerRef(
        kind=kind,
        producer_id="fxapk.pipeline",
        version="test-1",
        artifact_digest=None,
        configuration_digest=None,
    )


_ALL_SOURCES = ("dex", "java", "native", "resource", "runtime")


def _visibility(
    blocked: list[str] | None = None,
    levels: dict[str, str] | None = None,
    **over: object,
) -> dict:
    sources = {
        name: {"visibility": "complete", "why": [], "inputs_seen": []} for name in _ALL_SOURCES
    }
    for name, level in (levels or {}).items():
        sources[name]["visibility"] = level
    doc: dict = {
        "schema_version": "1.1",
        "sources": sources,
        "claims": {},
        "blocked_claims": blocked or [],
        "remediation": "not_attempted",
        "notes": [],
        "next_actions": [],
        "degraded": bool(blocked),
    }
    doc.update(over)
    return doc


def _build(doc: dict, producer: rc.ProducerRef | None = None):
    return build_visibility_gaps(
        doc,
        question_id=QUESTION_ID,
        producer=producer if producer is not None else _producer(),
    )


# ---------------------------------------------------------------- T1-T4：主路径


def test_single_blocked_claim_java_timeout_exact_fields() -> None:
    doc = _visibility(blocked=["static_endpoint_exhaustive"], levels={"java": "timeout"})
    gaps = _build(doc)
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap.effect is rc.GapEffect.BLOCKS_CLAIM
    assert gap.claim_id is None
    assert gap.question_id == QUESTION_ID
    assert gap.reason_codes == (
        "claim.static_endpoint_exhaustive",
        "java_visibility_timeout",
    )
    assert gap.required_observation_types == ("jadx_java_surface",)
    assert gap.coverage_requirements == ()
    assert gap.gap_id.startswith("gap-sha256:")


def test_multi_source_responsibility_aggregates_sorted() -> None:
    doc = _visibility(
        blocked=["static_endpoint_exhaustive"],
        levels={"dex": "partial", "java": "failed"},
    )
    (gap,) = _build(doc)
    assert gap.reason_codes == (
        "claim.static_endpoint_exhaustive",
        "dex_visibility_partial",
        "java_visibility_failed",
    )
    assert gap.required_observation_types == ("dex_string_surface", "jadx_java_surface")


def test_multiple_blocked_claims_sorted_and_deterministic() -> None:
    doc = _visibility(
        blocked=["no_remote_config", "static_endpoint_exhaustive"],
        levels={"dex": "unavailable", "java": "partial", "resource": "unknown"},
    )
    gaps = _build(doc)
    assert [g.reason_codes for g in gaps] == [
        # blocked claims 按排序序：no_remote_config（dex+resource）在前
        ("claim.no_remote_config", "dex_visibility_unavailable", "resource_visibility_unknown"),
        (
            "claim.static_endpoint_exhaustive",
            "dex_visibility_unavailable",
            "java_visibility_partial",
            "resource_visibility_unknown",
        ),
    ]
    assert len({g.gap_id for g in gaps}) == 2
    again = _build(doc)
    assert [g.gap_id for g in again] == [g.gap_id for g in gaps]


def test_honest_empty_when_nothing_blocked() -> None:
    assert _build(_visibility()) == ()


# ---------------------------------------------------- T5-T7：fail-closed 三口


def test_invalid_visibility_shapes_rejected() -> None:
    for doc in (
        _visibility(schema_version="1.0"),
        {"schema_version": "1.1"},  # 缺 sources/blocked_claims
        _visibility(sources="not-a-dict"),
        _visibility(blocked_claims="not-a-list"),
    ):
        with pytest.raises(GapProductionError) as exc:
            _build(doc)  # type: ignore[arg-type]
        assert exc.value.reason_code == "visibility_invalid"


def test_blocked_claim_without_insufficient_source_rejected() -> None:
    # 主张被封锁但所有所需来源都 complete——形状矛盾，必须 fail-closed
    doc = _visibility(blocked=["no_contact_harvesting"])
    with pytest.raises(GapProductionError) as exc:
        _build(doc)
    assert exc.value.reason_code == "blocked_claim_unattributable"


def test_unknown_claim_name_rejected() -> None:
    doc = _visibility(blocked=["brand_new_claim"], levels={"dex": "partial"})
    with pytest.raises(GapProductionError) as exc:
        _build(doc)
    assert exc.value.reason_code == "claim_unknown"


# ------------------------------------------------------------- T8-T9：边界


def test_positive_claims_never_produce_gaps() -> None:
    # claims 里有正向资格记录、blocked 为空 → 绝不产 gap（与 T4 分开锁语义）
    doc = _visibility(
        claims={"no_sms_interception": {"qualified": True}},
        levels={"native": "partial"},  # 有不足来源但没有 blocked claim
    )
    assert _build(doc) == ()


def test_query_producer_rejected_by_factory() -> None:
    doc = _visibility(blocked=["static_endpoint_exhaustive"], levels={"java": "failed"})
    with pytest.raises(Exception) as exc:
        _build(doc, producer=_producer(rc.ProducerKind.QUERY))
    assert "producer_kind_forbidden" in str(exc.value)


def test_version_constant_present() -> None:
    assert GAP_PRODUCTION_VERSION == "gap-prod-v1"


# --------------------------------------------------- codex 复审补锁（P1/P2）


def test_runtime_unknown_blocked_claim_produces_gap() -> None:
    """未评估（unknown）是责任来源：runtime 没做观测恰是最该补证的缺口。

    与 visibility._INSUFFICIENT 的差异是有意分叉（见模块注释）；此测试锁住
    「仅因未评估被封锁的主张必须产 gap、绝不落 unattributable」。
    """
    doc = _visibility(blocked=["runtime_contact_observed"], levels={"runtime": "unknown"})
    (gap,) = _build(doc)
    assert gap.reason_codes == (
        "claim.runtime_contact_observed",
        "runtime_visibility_unknown",
    )
    assert gap.required_observation_types == ("runtime_capture",)


def test_static_claim_with_unknown_source_attributes() -> None:
    doc = _visibility(blocked=["no_sms_interception"], levels={"dex": "unknown"})
    (gap,) = _build(doc)
    assert gap.reason_codes == ("claim.no_sms_interception", "dex_visibility_unknown")


def test_malformed_source_values_rejected() -> None:
    bad_level = _visibility(blocked=["no_sms_interception"])
    bad_level["sources"]["dex"]["visibility"] = 7  # 非字符串档位
    with pytest.raises(GapProductionError) as exc:
        _build(bad_level)
    assert exc.value.reason_code == "visibility_invalid"
    bad_item = _visibility()
    bad_item["blocked_claims"] = [123]  # 非字符串主张项
    with pytest.raises(GapProductionError) as exc:
        _build(bad_item)
    assert exc.value.reason_code == "visibility_invalid"
