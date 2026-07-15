# Infrastructure Role Classifier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic, evidence-preserving PR3 role classifier for domestic relay, origin, and edge candidates without introducing scoring or cloaking detection.

**Architecture:** Normalize semantic facts into immutable `RoleFeature` objects, then evaluate private declarative role definitions into public `RoleAssessment` explanations. Eligibility is a boolean safety gate; all numeric weights, confidence, and ranking remain outside this PR for PR4.

**Tech Stack:** Python 3.11+, frozen dataclasses, string enums, pytest, Ruff, Pyright.

## Global Constraints

- Do not modify existing analyzers or existing report JSON schema.
- Do not call external APIs or perform active scanning.
- Do not add numeric scores, confidence, weights, or machine learning.
- Do not infer an operator or criminal subject from ASN, provider, cloud, or IDC evidence.
- `cloaking_edge_node` must be reserved as an `edge_candidate` subtype and must not be classified until PR8.
- Generic OpenResty, nginx, or PHP strings must never create a role candidate by themselves.
- Preserve deterministic ordering and JSON-safe serialization.
- Use pytest, type hints, and the repository's three local gates before submission.

---

## File Structure

- Create `apkscan/attribution/roles.py`: role vocabulary, feature and assessment value objects, declarative definitions, and the stateless classifier.
- Modify `apkscan/attribution/__init__.py`: export the new public PR3 API without changing existing exports.
- Create `tests/test_attribution_roles.py`: model validation, eligibility, false-positive, isolation, and determinism tests.
- Keep `apkscan/attribution/models.py`, `apkscan/network/*`, analyzers, CLI, and report serialization unchanged.

### Task 1: Role vocabulary and immutable explanation models

**Files:**
- Create: `apkscan/attribution/roles.py`
- Test: `tests/test_attribution_roles.py`

**Interfaces:**
- Consumes: `AttributionEvidence` from `apkscan.attribution.models` and `NetworkEntity` from `apkscan.network`.
- Produces: `InfrastructureRole`, `RoleSignal`, `RoleFeature`, and `RoleAssessment`.

- [ ] **Step 1: Write failing enum and model tests**

Create `tests/test_attribution_roles.py` with these helpers and tests:

```python
from __future__ import annotations

import dataclasses
import json

import pytest

from apkscan.attribution.models import AttributionEvidence
from apkscan.attribution.roles import (
    InfrastructureRole,
    RoleAssessment,
    RoleFeature,
    RoleSignal,
)
from apkscan.network import NetworkEntity, NetworkEntityType


def _entity(value: str = "1.2.3.4") -> NetworkEntity:
    return NetworkEntity(NetworkEntityType.IP, value, sources=["pcap"])


def _evidence(
    evidence_id: str,
    *,
    target: NetworkEntity | None = None,
    evidence_type: str = "role_signal",
) -> AttributionEvidence:
    return AttributionEvidence(
        id=evidence_id,
        source="pcap",
        type=evidence_type,
        target=target or _entity(),
        value=True,
        confidence=0.8,
    )


def _feature(signal: RoleSignal, evidence_id: str) -> RoleFeature:
    return RoleFeature(signal=signal, evidence=_evidence(evidence_id))


def test_role_vocabulary_and_cloaking_parent_are_stable() -> None:
    assert [role.value for role in InfrastructureRole] == [
        "domestic_relay_candidate",
        "origin_candidate",
        "edge_candidate",
        "cloaking_edge_node",
    ]
    assert InfrastructureRole.CLOAKING_EDGE_NODE.parent is InfrastructureRole.EDGE_CANDIDATE
    assert InfrastructureRole.EDGE_CANDIDATE.parent is None


def test_role_feature_is_keyword_only_frozen_and_validated() -> None:
    feature = _feature(RoleSignal.DIRECT_CONNECTION, "ev-1")
    assert feature.signal is RoleSignal.DIRECT_CONNECTION
    with pytest.raises(dataclasses.FrozenInstanceError):
        feature.signal = RoleSignal.REDIRECT  # type: ignore[misc]
    with pytest.raises(TypeError):
        RoleFeature(RoleSignal.DIRECT_CONNECTION, _evidence("ev-2"))  # type: ignore[misc]
    with pytest.raises((TypeError, ValueError)):
        RoleFeature(signal="not-a-signal", evidence=_evidence("ev-3"))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        RoleFeature(signal=RoleSignal.REDIRECT, evidence=object())  # type: ignore[arg-type]


def test_role_assessment_is_json_safe_and_has_no_score_or_confidence() -> None:
    target = _entity()
    supporting = _evidence("ev-support", target=target)
    negative = _evidence("ev-negative", target=target)
    assessment = RoleAssessment(
        target=target,
        role=InfrastructureRole.ORIGIN_CANDIDATE,
        eligible=False,
        matched_signals=(RoleSignal.BUSINESS_API,),
        matched_evidence=(supporting,),
        missing_evidence=(RoleSignal.NON_PUBLIC_CDN,),
        negative_signals=(RoleSignal.PUBLIC_CDN,),
        negative_evidence=(negative,),
    )
    payload = assessment.to_dict()
    assert payload["role"] == "origin_candidate"
    assert payload["missing_evidence"] == ["non_public_cdn"]
    assert json.loads(json.dumps(payload)) == payload
    assert "score" not in payload
    assert "confidence" not in payload
    assert not hasattr(assessment, "score")
    assert not hasattr(assessment, "confidence")
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```powershell
python -m pytest tests/test_attribution_roles.py -q
```

Expected: collection fails because `apkscan.attribution.roles` does not exist.

- [ ] **Step 3: Implement the enums and value objects**

Create `apkscan/attribution/roles.py` with:

```python
"""Explainable infrastructure role eligibility without numeric scoring."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from apkscan.attribution.models import AttributionEvidence
from apkscan.network import NetworkEntity


class InfrastructureRole(str, Enum):
    DOMESTIC_RELAY_CANDIDATE = "domestic_relay_candidate"
    ORIGIN_CANDIDATE = "origin_candidate"
    EDGE_CANDIDATE = "edge_candidate"
    CLOAKING_EDGE_NODE = "cloaking_edge_node"

    @property
    def parent(self) -> InfrastructureRole | None:
        if self is InfrastructureRole.CLOAKING_EDGE_NODE:
            return InfrastructureRole.EDGE_CANDIDATE
        return None


class RoleSignal(str, Enum):
    DIRECT_CONNECTION = "direct_connection"
    DOMESTIC_NETWORK = "domestic_network"
    REDIRECT = "redirect"
    SUBSEQUENT_OVERSEAS_CONNECTION = "subsequent_overseas_connection"
    NON_PUBLIC_CDN = "non_public_cdn"
    PUBLIC_CDN = "public_cdn"
    BUSINESS_API = "business_api"
    LOGIN_ENDPOINT = "login_endpoint"
    STABLE_IP = "stable_ip"
    HISTORICAL_DNS = "historical_dns"
    BUSINESS_CERTIFICATE = "business_certificate"
    MANY_SHARED_DOMAINS = "many_shared_domains"
    COOKIE_CHALLENGE = "cookie_challenge"
    SHARED_TLS = "shared_tls"
    CONTENT_DIFFERENCE = "content_difference"


def _coerce_signal(value: object) -> RoleSignal:
    if isinstance(value, RoleSignal):
        return value
    if isinstance(value, str):
        try:
            return RoleSignal(value)
        except ValueError as exc:
            raise ValueError(f"invalid role signal: {value!r}") from exc
    raise TypeError(f"signal must be RoleSignal or str, got {type(value).__name__}")


def _coerce_role(value: object) -> InfrastructureRole:
    if isinstance(value, InfrastructureRole):
        return value
    if isinstance(value, str):
        try:
            return InfrastructureRole(value)
        except ValueError as exc:
            raise ValueError(f"invalid infrastructure role: {value!r}") from exc
    raise TypeError(
        f"role must be InfrastructureRole or str, got {type(value).__name__}"
    )


def _normalize_signals(value: object) -> tuple[RoleSignal, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError("signals must be a non-string iterable")
    return tuple(sorted({_coerce_signal(item) for item in value}, key=lambda item: item.value))


def _evidence_key(item: AttributionEvidence) -> tuple[str, str, str, str, str]:
    return (
        item.id,
        item.source,
        item.type,
        item.target.kind.value,
        item.target.value,
    )


def _normalize_evidence(
    value: object, *, target: NetworkEntity
) -> tuple[AttributionEvidence, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError("evidence must be a non-string iterable")
    unique: dict[tuple[str, str, str, str, str], AttributionEvidence] = {}
    for item in value:
        if not isinstance(item, AttributionEvidence):
            raise TypeError(
                f"evidence must contain AttributionEvidence, got {type(item).__name__}"
            )
        if item.target != target:
            raise ValueError("assessment evidence target must equal assessment target")
        unique[_evidence_key(item)] = item
    return tuple(unique[key] for key in sorted(unique))


@dataclass(frozen=True, kw_only=True)
class RoleFeature:
    signal: RoleSignal
    evidence: AttributionEvidence

    def __post_init__(self) -> None:
        object.__setattr__(self, "signal", _coerce_signal(self.signal))
        if not isinstance(self.evidence, AttributionEvidence):
            raise TypeError("evidence must be AttributionEvidence")


@dataclass(frozen=True, kw_only=True)
class RoleAssessment:
    target: NetworkEntity
    role: InfrastructureRole
    eligible: bool
    matched_signals: tuple[RoleSignal, ...] = ()
    matched_evidence: tuple[AttributionEvidence, ...] = ()
    missing_evidence: tuple[RoleSignal, ...] = ()
    negative_signals: tuple[RoleSignal, ...] = ()
    negative_evidence: tuple[AttributionEvidence, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.target, NetworkEntity):
            raise TypeError("target must be NetworkEntity")
        object.__setattr__(self, "role", _coerce_role(self.role))
        if not isinstance(self.eligible, bool):
            raise TypeError("eligible must be bool")
        object.__setattr__(
            self, "matched_signals", _normalize_signals(self.matched_signals)
        )
        object.__setattr__(
            self, "missing_evidence", _normalize_signals(self.missing_evidence)
        )
        object.__setattr__(
            self, "negative_signals", _normalize_signals(self.negative_signals)
        )
        object.__setattr__(
            self,
            "matched_evidence",
            _normalize_evidence(self.matched_evidence, target=self.target),
        )
        object.__setattr__(
            self,
            "negative_evidence",
            _normalize_evidence(self.negative_evidence, target=self.target),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "role": self.role.value,
            "eligible": self.eligible,
            "matched_signals": [item.value for item in self.matched_signals],
            "matched_evidence": [item.to_dict() for item in self.matched_evidence],
            "missing_evidence": [item.value for item in self.missing_evidence],
            "negative_signals": [item.value for item in self.negative_signals],
            "negative_evidence": [item.to_dict() for item in self.negative_evidence],
        }
```

- [ ] **Step 4: Run the focused tests**

Run:

```powershell
python -m pytest tests/test_attribution_roles.py -q
```

Expected: the three Task 1 tests pass.

- [ ] **Step 5: Commit Task 1**

```powershell
git add -- apkscan/attribution/roles.py tests/test_attribution_roles.py
git commit -m "feat(attribution): add role explanation models"
```

### Task 2: Declarative eligibility rules and classifier

**Files:**
- Modify: `apkscan/attribution/roles.py`
- Modify: `tests/test_attribution_roles.py`

**Interfaces:**
- Consumes: `RoleClassifier.assess(target, features)` receives one `NetworkEntity` and an iterable of `RoleFeature`.
- Produces: `RoleClassifier.classify(target, features) -> tuple[RoleAssessment, ...]`, containing eligible top-level assessments only.

- [ ] **Step 1: Add failing positive and explanation tests**

Append these tests:

```python
from apkscan.attribution.roles import RoleClassifier


def _features(*signals: RoleSignal) -> list[RoleFeature]:
    return [_feature(signal, f"ev-{index}") for index, signal in enumerate(signals)]


def test_domestic_relay_requires_location_connection_and_transition() -> None:
    classifier = RoleClassifier()
    features = _features(
        RoleSignal.DIRECT_CONNECTION,
        RoleSignal.DOMESTIC_NETWORK,
        RoleSignal.SUBSEQUENT_OVERSEAS_CONNECTION,
    )
    result = classifier.classify(_entity(), features)
    assert [item.role for item in result] == [
        InfrastructureRole.DOMESTIC_RELAY_CANDIDATE
    ]
    assert result[0].eligible is True
    assert result[0].missing_evidence == (
        RoleSignal.NON_PUBLIC_CDN,
        RoleSignal.REDIRECT,
    )


def test_origin_accepts_business_api_plus_independent_correlation() -> None:
    result = RoleClassifier().classify(
        _entity(),
        _features(
            RoleSignal.BUSINESS_API,
            RoleSignal.LOGIN_ENDPOINT,
            RoleSignal.HISTORICAL_DNS,
            RoleSignal.NON_PUBLIC_CDN,
        ),
    )
    assert [item.role for item in result] == [InfrastructureRole.ORIGIN_CANDIDATE]
    assert result[0].missing_evidence == (
        RoleSignal.BUSINESS_CERTIFICATE,
        RoleSignal.STABLE_IP,
    )


def test_edge_requires_two_distinct_behavior_or_correlation_signals() -> None:
    classifier = RoleClassifier()
    assert classifier.classify(
        _entity(), _features(RoleSignal.REDIRECT)
    ) == ()
    result = classifier.classify(
        _entity(),
        _features(RoleSignal.REDIRECT, RoleSignal.COOKIE_CHALLENGE),
    )
    assert [item.role for item in result] == [InfrastructureRole.EDGE_CANDIDATE]


def test_assess_returns_ineligible_explanations_but_never_cloaking() -> None:
    assessments = RoleClassifier().assess(_entity(), ())
    assert [item.role for item in assessments] == [
        InfrastructureRole.DOMESTIC_RELAY_CANDIDATE,
        InfrastructureRole.ORIGIN_CANDIDATE,
        InfrastructureRole.EDGE_CANDIDATE,
    ]
    assert all(not item.eligible for item in assessments)
    assert InfrastructureRole.CLOAKING_EDGE_NODE not in {
        item.role for item in assessments
    }
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run:

```powershell
python -m pytest tests/test_attribution_roles.py -q
```

Expected: import or attribute failure because `RoleClassifier` is not defined.

- [ ] **Step 3: Add private definitions and the classifier**

Append to `apkscan/attribution/roles.py`:

```python
@dataclass(frozen=True)
class _Requirement:
    signals: frozenset[RoleSignal]
    minimum: int = 1

    def met_by(self, present: frozenset[RoleSignal]) -> bool:
        return len(self.signals & present) >= self.minimum


@dataclass(frozen=True)
class _RoleDefinition:
    role: InfrastructureRole
    supporting: frozenset[RoleSignal]
    requirements: tuple[_Requirement, ...]
    blockers: frozenset[RoleSignal] = frozenset()


_TRANSITION = frozenset(
    {RoleSignal.REDIRECT, RoleSignal.SUBSEQUENT_OVERSEAS_CONNECTION}
)
_ORIGIN_CORRELATION = frozenset(
    {
        RoleSignal.LOGIN_ENDPOINT,
        RoleSignal.STABLE_IP,
        RoleSignal.HISTORICAL_DNS,
        RoleSignal.BUSINESS_CERTIFICATE,
    }
)
_EDGE_SIGNALS = frozenset(
    {
        RoleSignal.MANY_SHARED_DOMAINS,
        RoleSignal.REDIRECT,
        RoleSignal.COOKIE_CHALLENGE,
        RoleSignal.SHARED_TLS,
        RoleSignal.CONTENT_DIFFERENCE,
    }
)

_ROLE_DEFINITIONS = (
    _RoleDefinition(
        role=InfrastructureRole.DOMESTIC_RELAY_CANDIDATE,
        supporting=frozenset(
            {
                RoleSignal.DIRECT_CONNECTION,
                RoleSignal.DOMESTIC_NETWORK,
                RoleSignal.REDIRECT,
                RoleSignal.SUBSEQUENT_OVERSEAS_CONNECTION,
                RoleSignal.NON_PUBLIC_CDN,
            }
        ),
        requirements=(
            _Requirement(frozenset({RoleSignal.DIRECT_CONNECTION})),
            _Requirement(frozenset({RoleSignal.DOMESTIC_NETWORK})),
            _Requirement(_TRANSITION),
        ),
        blockers=frozenset({RoleSignal.PUBLIC_CDN}),
    ),
    _RoleDefinition(
        role=InfrastructureRole.ORIGIN_CANDIDATE,
        supporting=frozenset(
            {RoleSignal.BUSINESS_API, RoleSignal.NON_PUBLIC_CDN}
        )
        | _ORIGIN_CORRELATION,
        requirements=(
            _Requirement(frozenset({RoleSignal.BUSINESS_API})),
            _Requirement(_ORIGIN_CORRELATION),
        ),
        blockers=frozenset({RoleSignal.PUBLIC_CDN}),
    ),
    _RoleDefinition(
        role=InfrastructureRole.EDGE_CANDIDATE,
        supporting=_EDGE_SIGNALS,
        requirements=(_Requirement(_EDGE_SIGNALS, minimum=2),),
    ),
)


def _normalize_features(value: object) -> tuple[RoleFeature, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError("features must be a non-string iterable of RoleFeature")
    unique: dict[tuple[str, str, str, str, str, str], RoleFeature] = {}
    for item in value:
        if not isinstance(item, RoleFeature):
            raise TypeError(
                f"features must contain RoleFeature, got {type(item).__name__}"
            )
        key = (item.signal.value, *_evidence_key(item.evidence))
        unique[key] = item
    return tuple(unique[key] for key in sorted(unique))


class RoleClassifier:
    """Evaluate explainable role eligibility without scores or confidence."""

    def assess(
        self,
        target: NetworkEntity,
        features: Iterable[RoleFeature],
    ) -> tuple[RoleAssessment, ...]:
        if not isinstance(target, NetworkEntity):
            raise TypeError("target must be NetworkEntity")
        normalized = tuple(
            feature
            for feature in _normalize_features(features)
            if feature.evidence.target == target
        )
        present = frozenset(feature.signal for feature in normalized)
        by_signal: dict[RoleSignal, list[AttributionEvidence]] = {}
        for feature in normalized:
            by_signal.setdefault(feature.signal, []).append(feature.evidence)
        return tuple(
            self._assess_definition(target, definition, present, by_signal)
            for definition in _ROLE_DEFINITIONS
        )

    def classify(
        self,
        target: NetworkEntity,
        features: Iterable[RoleFeature],
    ) -> tuple[RoleAssessment, ...]:
        return tuple(item for item in self.assess(target, features) if item.eligible)

    @staticmethod
    def _assess_definition(
        target: NetworkEntity,
        definition: _RoleDefinition,
        present: frozenset[RoleSignal],
        by_signal: dict[RoleSignal, list[AttributionEvidence]],
    ) -> RoleAssessment:
        matched = definition.supporting & present
        negative = definition.blockers & present
        matched_evidence = tuple(
            evidence
            for signal in matched
            for evidence in by_signal.get(signal, ())
        )
        negative_evidence = tuple(
            evidence
            for signal in negative
            for evidence in by_signal.get(signal, ())
        )
        eligible = not negative and all(
            requirement.met_by(present) for requirement in definition.requirements
        )
        return RoleAssessment(
            target=target,
            role=definition.role,
            eligible=eligible,
            matched_signals=tuple(matched),
            matched_evidence=matched_evidence,
            missing_evidence=tuple(definition.supporting - present),
            negative_signals=tuple(negative),
            negative_evidence=negative_evidence,
        )
```

- [ ] **Step 4: Run focused tests and fix only implementation defects**

Run:

```powershell
python -m pytest tests/test_attribution_roles.py -q
```

Expected: all Task 1 and Task 2 tests pass.

- [ ] **Step 5: Commit Task 2**

```powershell
git add -- apkscan/attribution/roles.py tests/test_attribution_roles.py
git commit -m "feat(attribution): classify infrastructure role candidates"
```

### Task 3: False-positive barriers, target isolation, and deterministic API exports

**Files:**
- Modify: `tests/test_attribution_roles.py`
- Modify: `apkscan/attribution/roles.py`
- Modify: `apkscan/attribution/__init__.py`

**Interfaces:**
- Consumes: the Task 2 classifier and immutable models.
- Produces: stable package exports and regression coverage for the PR3 acceptance cases.

- [ ] **Step 1: Add failing false-positive and determinism tests**

Append:

```python
def test_public_cdn_blocks_origin_and_is_reported_as_negative_evidence() -> None:
    result = RoleClassifier().assess(
        _entity(),
        _features(
            RoleSignal.BUSINESS_API,
            RoleSignal.HISTORICAL_DNS,
            RoleSignal.PUBLIC_CDN,
        ),
    )
    origin = next(
        item for item in result if item.role is InfrastructureRole.ORIGIN_CANDIDATE
    )
    assert origin.eligible is False
    assert origin.negative_signals == (RoleSignal.PUBLIC_CDN,)
    assert [item.id for item in origin.negative_evidence] == ["ev-2"]


def test_generic_banner_and_shared_asn_alone_have_no_role_signal() -> None:
    target = _entity()
    generic_banner = _evidence(
        "banner", target=target, evidence_type="generic_server_banner"
    )
    shared_asn = _evidence("asn", target=target, evidence_type="asn")
    assert RoleClassifier().classify(target, ()) == ()
    assert generic_banner.type == "generic_server_banner"
    assert shared_asn.type == "asn"


def test_features_for_other_targets_are_ignored() -> None:
    target = _entity()
    other = _entity("5.6.7.8")
    features = [
        RoleFeature(
            signal=RoleSignal.BUSINESS_API,
            evidence=_evidence("other-api", target=other),
        ),
        RoleFeature(
            signal=RoleSignal.HISTORICAL_DNS,
            evidence=_evidence("other-dns", target=other),
        ),
    ]
    assert RoleClassifier().classify(target, features) == ()


def test_duplicate_features_and_input_order_do_not_change_output() -> None:
    first = _feature(RoleSignal.REDIRECT, "redirect")
    second = _feature(RoleSignal.COOKIE_CHALLENGE, "cookie")
    classifier = RoleClassifier()
    left = [item.to_dict() for item in classifier.assess(_entity(), [first, second, first])]
    right = [item.to_dict() for item in classifier.assess(_entity(), [second, first])]
    assert left == right


def test_public_api_exports_role_types() -> None:
    from apkscan.attribution import (
        InfrastructureRole as ExportedRole,
        RoleAssessment as ExportedAssessment,
        RoleClassifier as ExportedClassifier,
        RoleFeature as ExportedFeature,
        RoleSignal as ExportedSignal,
    )

    assert ExportedRole is InfrastructureRole
    assert ExportedAssessment is RoleAssessment
    assert ExportedClassifier is RoleClassifier
    assert ExportedFeature is RoleFeature
    assert ExportedSignal is RoleSignal
```

- [ ] **Step 2: Run the focused tests to expose export or ordering defects**

Run:

```powershell
python -m pytest tests/test_attribution_roles.py -q
```

Expected: the export test fails until `apkscan.attribution.__init__` is updated; any ordering or deduplication failure must also be visible here.

- [ ] **Step 3: Export the public API**

Replace `apkscan/attribution/__init__.py` with:

```python
"""Network infrastructure attribution models and explainable role inference."""

from apkscan.attribution.models import AttributionEvidence
from apkscan.attribution.roles import (
    InfrastructureRole,
    RoleAssessment,
    RoleClassifier,
    RoleFeature,
    RoleSignal,
)

__all__ = [
    "AttributionEvidence",
    "InfrastructureRole",
    "RoleAssessment",
    "RoleClassifier",
    "RoleFeature",
    "RoleSignal",
]
```

- [ ] **Step 4: Run focused and adjacent tests**

Run:

```powershell
python -m pytest tests/test_attribution_roles.py tests/test_attribution_models.py tests/test_network_converters.py -q
```

Expected: all tests pass and existing attribution/converter behavior remains unchanged.

- [ ] **Step 5: Run static checks on changed code**

Run:

```powershell
python -m ruff check apkscan/attribution tests/test_attribution_roles.py
python -m pyright apkscan/attribution
```

Expected: both commands exit 0. Fix type or lint defects without weakening tests.

- [ ] **Step 6: Commit Task 3**

```powershell
git add -- apkscan/attribution/__init__.py apkscan/attribution/roles.py tests/test_attribution_roles.py
git commit -m "test(attribution): guard role classifier false positives"
```

### Task 4: Full verification and PR readiness

**Files:**
- Verify only: all changed PR3 files.

**Interfaces:**
- Consumes: completed PR3 branch.
- Produces: evidence that PR3 is compatible with the whole repository.

- [ ] **Step 1: Inspect the exact branch diff**

Run:

```powershell
git diff --check master...HEAD
git diff --stat master...HEAD
git status --short
```

Expected: no whitespace errors; only PR3 files and the untracked local `.vs/` directory are present. Never stage `.vs/`.

- [ ] **Step 2: Run all three mandatory local gates**

Run:

```powershell
python -m ruff check apkscan tests
python -m pyright apkscan
python -m pytest -q
```

Expected: Ruff exits 0, Pyright reports zero errors, and pytest completes with zero failures.

- [ ] **Step 3: Review against the design**

Confirm from the diff and tests:

- only three top-level roles are assessed or classified;
- cloaking is vocabulary-only and has `edge_candidate` as parent;
- no score/confidence field or numeric weight exists in PR3;
- public CDN blocks origin and domestic relay eligibility;
- a single redirect, ASN, or generic server banner cannot classify a role;
- matched, missing, and negative evidence remain attributable to exact evidence IDs;
- no analyzer, API, graph, report, CLI, or existing schema was changed.

- [ ] **Step 4: Commit any review fixes as a focused commit**

If review finds a defect, first add a failing regression test, run it to observe the failure, implement the smallest fix, rerun focused tests, then commit only the affected PR3 files with a conventional message describing that defect. If no defect is found, create no empty commit.
