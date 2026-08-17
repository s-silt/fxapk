from __future__ import annotations

from typing import Any, Final, Mapping, NoReturn

from apkscan.core import recognition_codec as codec
from apkscan.core import recognition_contract as rc


GAP_PRODUCTION_VERSION: Final = "gap-prod-v1"

_VISIBILITY_SCHEMA_VERSION: Final = "1.1"

# ★与 visibility._INSUFFICIENT 的差异是**有意的**：本表多含 "unknown"（未评估）。
#   visibility 层把「确证盲区」与「未评估」分开，服务的是报告措辞与 closure 封顶
#   （前者封顶、后者豁免）；gap 层的问题是「还缺什么观察」——未评估恰是最该补证的，
#   两者都必须产 gap。语义区分不丢：reason token 的档位后缀（…_visibility_unknown
#   vs …_visibility_timeout）保留了它，由 P3-E3 的映射 v2 分流处置（codex 复审后显式化）。
_VISIBILITY_INSUFFICIENT: Final = frozenset(
    {
        "partial",
        "stub_only",
        "opaque",
        "unavailable",
        "unknown",
        "timeout",
        "failed",
    }
)

_VISIBILITY_LEVELS: Final = frozenset(
    {
        "complete",
        *_VISIBILITY_INSUFFICIENT,
    }
)

# 与 visibility._CLAIM_REQUIREMENTS 同源的生产侧副本。
_CLAIM_REQUIREMENTS: Final[dict[str, tuple[str, ...]]] = {
    "static_endpoint_exhaustive": ("dex", "java", "native", "resource"),
    "no_contact_harvesting": ("dex",),
    "no_sms_interception": ("dex",),
    "no_remote_config": ("dex", "resource"),
    "config_chain_complete": ("dex", "resource"),
    "no_hardcoded_credential": ("dex", "java", "native", "resource"),
    "runtime_contact_observed": ("runtime",),
}

_OBSERVATION_TYPES: Final[dict[str, str]] = {
    "dex": "dex_string_surface",
    "java": "jadx_java_surface",
    "native": "native_string_surface",
    "resource": "resource_surface",
    "runtime": "runtime_capture",
}


class GapProductionError(Exception):
    def __init__(self, reason_code: str, detail: str) -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code}: {detail}")


def _fail(reason_code: str, detail: str) -> NoReturn:
    raise GapProductionError(reason_code, detail)


def _validate_visibility(
    visibility: Mapping[str, Any],
) -> tuple[Mapping[str, Any], tuple[str, ...]]:
    if not isinstance(visibility, Mapping):
        _fail("visibility_invalid", "visibility must be a mapping")

    if visibility.get("schema_version") != _VISIBILITY_SCHEMA_VERSION:
        _fail(
            "visibility_invalid",
            "schema_version must be exactly '1.1'",
        )

    if "sources" not in visibility:
        _fail("visibility_invalid", "missing sources")

    sources = visibility["sources"]
    if not isinstance(sources, Mapping):
        _fail("visibility_invalid", "sources must be a mapping")

    if "blocked_claims" not in visibility:
        _fail("visibility_invalid", "missing blocked_claims")

    blocked_claims = visibility["blocked_claims"]
    if not isinstance(blocked_claims, (list, tuple)):
        _fail("visibility_invalid", "blocked_claims must be a list or tuple")

    normalized_claims: list[str] = []
    for index, claim in enumerate(blocked_claims):
        if not isinstance(claim, str) or not claim:
            _fail(
                "visibility_invalid",
                f"blocked_claims[{index}] must be a non-empty string",
            )
        normalized_claims.append(claim)

    for source, source_value in sources.items():
        if not isinstance(source, str) or not source:
            _fail("visibility_invalid", "sources keys must be non-empty strings")
        if not isinstance(source_value, Mapping):
            _fail(
                "visibility_invalid",
                f"sources[{source!r}] must be a mapping",
            )
        if "visibility" not in source_value:
            _fail(
                "visibility_invalid",
                f"sources[{source!r}] is missing visibility",
            )
        level = source_value["visibility"]
        if not isinstance(level, str) or level not in _VISIBILITY_LEVELS:
            _fail(
                "visibility_invalid",
                f"sources[{source!r}].visibility is invalid",
            )

    return sources, tuple(sorted(normalized_claims))


def build_visibility_gaps(
    visibility: Mapping[str, Any],
    *,
    question_id: str,
    producer: rc.ProducerRef,
) -> tuple[rc.EvidenceGap, ...]:
    sources, blocked_claims = _validate_visibility(visibility)

    gaps: list[rc.EvidenceGap] = []

    for claim_name in blocked_claims:
        required_sources = _CLAIM_REQUIREMENTS.get(claim_name)
        if required_sources is None:
            _fail(
                "claim_unknown",
                f"blocked claim is not registered: {claim_name}",
            )

        insufficient_sources: list[tuple[str, str]] = []
        for source_name in required_sources:
            if source_name not in sources:
                _fail(
                    "visibility_invalid",
                    f"missing required source {source_name!r} for claim {claim_name!r}",
                )

            level = sources[source_name]["visibility"]
            if level in _VISIBILITY_INSUFFICIENT:
                insufficient_sources.append((source_name, level))

        if not insufficient_sources:
            _fail(
                "blocked_claim_unattributable",
                f"blocked claim has no insufficient required source: {claim_name}",
            )

        reason_codes = tuple(
            sorted(
                {f"{source_name}_visibility_{level}" for source_name, level in insufficient_sources}
            )
        )
        required_observation_types = tuple(
            sorted({_OBSERVATION_TYPES[source_name] for source_name, _ in insufficient_sources})
        )

        gaps.append(
            codec.build_evidence_gap(
                question_id=question_id,
                claim_id=None,
                effect=rc.GapEffect.BLOCKS_CLAIM,
                reason_codes=reason_codes,
                required_observation_types=required_observation_types,
                coverage_requirements=(),
                producer=producer,
            )
        )

    return tuple(gaps)
