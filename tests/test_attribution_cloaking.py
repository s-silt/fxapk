"""PR8 cloaking_edge_node subtype: strong multi-signal classification + scoring.

Positives, the mandatory OpenResty/plain-edge negatives, the subtype-implication
and policy/definition invariants, scoring, and the forward-compatible graph
annotation. New coverage is kept here; the ~7 pre-PR8 "reserved" assertions were
flipped in place in test_attribution_roles.py / test_attribution_scorer.py.
"""

from __future__ import annotations

import itertools

import pytest

from apkscan.attribution import (
    AttributionEvidence,
    EvidenceScorer,
    InfrastructureRole as R,
    RoleClassifier,
    RoleFeature,
    RoleSignal as S,
)
from apkscan.attribution.roles import _CLOAKING_STRONG, _EDGE_SIGNALS, _ROLE_DEFINITIONS
from apkscan.attribution.scorer import _ROLE_POLICIES
from apkscan.network import NetworkEntity, NetworkEntityType


def _entity(value: str = "1.2.3.4") -> NetworkEntity:
    return NetworkEntity(NetworkEntityType.IP, value, ("pcap",))


def _features(*signals: S, target: NetworkEntity | None = None) -> list[RoleFeature]:
    target = target or _entity()
    return [
        RoleFeature(
            signal=signal,
            evidence=AttributionEvidence(
                id=f"ev-{signal.value}-{i}", source="pcap", type="role_signal",
                target=target, value=True, confidence=1.0,
            ),
        )
        for i, signal in enumerate(signals)
    ]


def _assess(*signals: S) -> dict[R, object]:
    target = _entity()
    return {a.role: a for a in RoleClassifier().assess(target, _features(*signals, target=target))}


# --------------------------------------------------------------------------- #
# Positives
# --------------------------------------------------------------------------- #
def test_two_strong_signals_are_cloaking_and_edge() -> None:
    a = _assess(S.CONTENT_DIFFERENCE, S.COOKIE_CHALLENGE)
    assert a[R.CLOAKING_EDGE_NODE].eligible is True
    assert a[R.EDGE_CANDIDATE].eligible is True  # subtype instance


def test_cookie_challenge_plus_redirect_is_cloaking() -> None:
    assert _assess(S.COOKIE_CHALLENGE, S.REDIRECT)[R.CLOAKING_EDGE_NODE].eligible is True


def test_public_cdn_is_context_not_a_blocker() -> None:
    a = _assess(S.PUBLIC_CDN, S.CONTENT_DIFFERENCE, S.COOKIE_CHALLENGE)
    cloaking = a[R.CLOAKING_EDGE_NODE]
    assert cloaking.eligible is True  # public CDN must NOT veto cloaking
    assert S.PUBLIC_CDN in cloaking.context_signals
    assert S.PUBLIC_CDN not in cloaking.negative_signals
    assert S.PUBLIC_CDN not in cloaking.matched_signals


# --------------------------------------------------------------------------- #
# Negatives (the anti-false-positive core)
# --------------------------------------------------------------------------- #
def test_ordinary_shared_hosting_edge_is_not_cloaking() -> None:
    # many_shared_domains + shared_tls: an OpenResty/shared-hosting edge, no
    # behavioral cloaking. Edge yes, cloaking no, with the strong signals listed.
    a = _assess(S.MANY_SHARED_DOMAINS, S.SHARED_TLS)
    assert a[R.EDGE_CANDIDATE].eligible is True
    cloaking = a[R.CLOAKING_EDGE_NODE]
    assert cloaking.eligible is False
    assert set(cloaking.missing_evidence) == {S.CONTENT_DIFFERENCE, S.COOKIE_CHALLENGE, S.REDIRECT}
    assert cloaking.matched_signals == ()
    assert set(cloaking.context_signals) == {S.MANY_SHARED_DOMAINS, S.SHARED_TLS}


@pytest.mark.parametrize("strong", [S.CONTENT_DIFFERENCE, S.COOKIE_CHALLENGE, S.REDIRECT])
def test_a_single_strong_signal_is_not_cloaking(strong) -> None:
    assert _assess(strong)[R.CLOAKING_EDGE_NODE].eligible is False


def test_one_strong_plus_one_weak_is_not_cloaking() -> None:
    a = _assess(S.CONTENT_DIFFERENCE, S.SHARED_TLS)
    assert a[R.CLOAKING_EDGE_NODE].eligible is False  # 1 strong < 2
    assert a[R.EDGE_CANDIDATE].eligible is True         # but 2 edge signals


def test_banner_only_entity_triggers_nothing() -> None:
    # a server banner is not a RoleSignal, so an entity with no features is
    # ineligible for every role — "weak never solo-triggers" is structural.
    a = _assess()
    assert all(not assessment.eligible for assessment in a.values())


# --------------------------------------------------------------------------- #
# Invariants
# --------------------------------------------------------------------------- #
def test_cloaking_eligibility_is_exactly_two_strong_and_implies_edge() -> None:
    # Full characterization over all 2^6 subsets: cloaking is eligible IFF >=2
    # strong signals are present (so no weak signal can ever pad the count), and
    # whenever it is eligible the parent edge is too.
    signals = sorted(_EDGE_SIGNALS | {S.PUBLIC_CDN}, key=lambda s: s.value)
    for size in range(len(signals) + 1):
        for combo in itertools.combinations(signals, size):
            a = _assess(*combo)
            expected = len(set(combo) & _CLOAKING_STRONG) >= 2
            assert a[R.CLOAKING_EDGE_NODE].eligible is expected, combo
            if a[R.CLOAKING_EDGE_NODE].eligible:
                assert a[R.EDGE_CANDIDATE].eligible, combo


def _definition(role: R):
    return next(d for d in _ROLE_DEFINITIONS if d.role is role)


def test_subtype_definitions_only_tighten_the_parent() -> None:
    # For every role with a parent, its requirement/supporting signals are a subset
    # of the parent's, its blockers a superset, and its minimum no smaller.
    for definition in _ROLE_DEFINITIONS:
        parent_role = definition.role.parent
        if parent_role is None:
            continue
        parent = _definition(parent_role)
        child_req = frozenset().union(*(r.signals for r in definition.requirements))
        parent_req = frozenset().union(*(r.signals for r in parent.requirements))
        assert child_req <= parent_req
        assert definition.supporting <= parent.supporting
        assert definition.blockers >= parent.blockers
        assert min(r.minimum for r in definition.requirements) >= min(
            r.minimum for r in parent.requirements
        )


def test_policy_buckets_match_definition_buckets_for_every_role() -> None:
    # The codebase-wide convention, now explicit: positive-weight == supporting,
    # zero-weight == context, negative-weight == blockers.
    definitions = {d.role: d for d in _ROLE_DEFINITIONS}
    for role, policy in _ROLE_POLICIES.items():
        definition = definitions[role]
        positive = {s for s, w in policy.weights.items() if w > 0}
        zero = {s for s, w in policy.weights.items() if w == 0}
        negative = {s for s, w in policy.weights.items() if w < 0}
        assert positive == definition.supporting, role
        assert zero == definition.context, role
        assert negative == definition.blockers, role


# --------------------------------------------------------------------------- #
# Scoring + graph annotation
# --------------------------------------------------------------------------- #
def _canonical_cloaking_score(target: NetworkEntity):
    features = _features(S.CONTENT_DIFFERENCE, S.COOKIE_CHALLENGE, target=target)
    assessment = next(
        a for a in RoleClassifier().assess(target, features) if a.role is R.CLOAKING_EDGE_NODE
    )
    return EvidenceScorer().score(assessment)


def test_cloaking_scores_with_correct_arithmetic() -> None:
    score = _canonical_cloaking_score(_entity())
    assert score.role is R.CLOAKING_EDGE_NODE
    assert score.eligible is True
    assert score.raw_score == 70  # content_difference 40 + cookie_challenge 30
    assert score.score == 70
    assert score.confidence == 0.70


def test_cloaking_rolescore_is_a_valid_graph_annotation() -> None:
    from apkscan.attribution.graph import build_infrastructure_graph

    score = _canonical_cloaking_score(_entity("203.0.113.5"))
    graph = build_infrastructure_graph(artifact_id="sample-A", role_scores=[score])
    node = next(n for n in graph.nodes if (n.node_type.value, n.value) == ("IP", "203.0.113.5"))
    assert [role.role.value for role in node.roles] == ["cloaking_edge_node"]
