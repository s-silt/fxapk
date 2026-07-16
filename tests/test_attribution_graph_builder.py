"""PR7 builder: per-evidence-type edge derivation from real fact shapes."""

from __future__ import annotations

import pytest

from apkscan.attribution.graph import _EDGE_HANDLERS, build_infrastructure_graph
from apkscan.network import Observation
from apkscan.network.converters import ConversionResult
from tests.attribution_graph_fakes import (
    cert,
    domain,
    domestic_relay_score,
    domestic_relay_score_for,
    edge_tuples,
    evidence,
    host,
    ip,
    node_keys,
)


def _build(*evs, role_scores=(), conversions=()):
    return build_infrastructure_graph(
        artifact_id="sample-A", extra_evidence=evs, role_scores=role_scores, conversions=conversions
    )


def test_edge_registry_is_the_documented_closed_set() -> None:
    assert set(_EDGE_HANDLERS) == {
        "network_flow", "http_request", "http_response", "http_redirect",
        "tls_sni", "dns_resolution", "dns_alias",
        "resolved_ip", "related_ip", "related_hostname", "asn", "cert_san_dns",
    }


def test_dns_resolution_evidence_direction_is_inverted() -> None:
    # converter emits target=answer IP, value=qname -> DOMAIN(value) RESOLVES_TO IP(target)
    g = _build(evidence(id="e1", type="dns_resolution", target=ip("1.2.3.4"), value="api.example.com"))
    assert ("resolves_to", "DOMAIN", "api.example.com", "IP", "1.2.3.4") in edge_tuples(g)
    assert ("resolves_to", "IP", "1.2.3.4", "DOMAIN", "api.example.com") not in edge_tuples(g)


def test_shodan_resolved_ip_and_pcap_dns_resolution_agree_on_direction() -> None:
    g = _build(
        evidence(id="e1", type="dns_resolution", target=ip("1.2.3.4"), value="a.example.com"),
        evidence(id="e2", type="resolved_ip", target=domain("a.example.com"), value="1.2.3.4", source="shodan"),
    )
    resolves = [e for e in g.edges if e.relation.value == "resolves_to"]
    assert len(resolves) == 1  # merged into one edge
    assert set(resolves[0].provenance) == {"e1", "e2"}


def test_tls_sni_emits_served_at_and_contacted() -> None:
    g = _build(evidence(id="e1", type="tls_sni", target=domain("x.com"), value="1.2.3.4"))
    tuples = edge_tuples(g)
    assert ("served_at", "DOMAIN", "x.com", "IP", "1.2.3.4") in tuples
    assert ("contacted", "APK", "sample-A", "DOMAIN", "x.com") in tuples


def test_network_flow_contacts_dst_ip_only() -> None:
    g = _build(evidence(id="e1", type="network_flow", target=ip("1.2.3.4"), value="tcp/443"))
    assert edge_tuples(g) == {("contacted", "APK", "sample-A", "IP", "1.2.3.4")}


def test_dns_alias_direction() -> None:
    g = _build(evidence(id="e1", type="dns_alias", target=domain("www.a.com"), value="cdn.b.net"))
    assert ("alias_of", "DOMAIN", "www.a.com", "DOMAIN", "cdn.b.net") in edge_tuples(g)


def test_http_redirect_to_location_host() -> None:
    g = _build(evidence(id="e1", type="http_redirect", target=domain("a.com"), value="https://b.com/path?x=1"))
    tuples = edge_tuples(g)
    assert ("redirects_to", "DOMAIN", "a.com", "DOMAIN", "b.com") in tuples
    assert ("contacted", "APK", "sample-A", "DOMAIN", "a.com") in tuples


def test_related_ip_is_weak_intel_related_not_resolution() -> None:
    g = _build(evidence(id="e1", type="related_ip", target=domain("example.com"), value="9.9.9.9", source="fofa"))
    tuples = edge_tuples(g)
    assert ("intel_related", "DOMAIN", "example.com", "IP", "9.9.9.9") in tuples
    assert not any(t[0] in ("resolves_to", "served_at") for t in tuples)


def test_asn_evidence_makes_canonical_asn_node() -> None:
    g = _build(evidence(id="e1", type="asn", target=ip("1.2.3.4"), value=13335, source="shodan"))
    assert ("in_asn", "IP", "1.2.3.4", "ASN", "AS13335") in edge_tuples(g)
    assert ("ASN", "AS13335") in node_keys(g)


@pytest.mark.parametrize("bad", [True, 0, -1, "not-a-number"])
def test_asn_bad_value_is_quarantined(bad) -> None:
    g = _build(evidence(id="e1", type="asn", target=ip("1.2.3.4"), value=bad, source="shodan"))
    assert not any(e.relation.value == "in_asn" for e in g.edges)
    assert not any(n.node_type.value == "ASN" for n in g.nodes)
    assert any(i.reference == "e1" for i in g.issues)


def test_cert_san_certifies_domain() -> None:
    g = _build(evidence(id="e1", type="cert_san_dns", target=cert(), value="san.example.com", source="censys"))
    assert ("certifies", "CERTIFICATE", "sha256:" + "a" * 64, "DOMAIN", "san.example.com") in edge_tuples(g)


def test_cert_san_wildcard_is_a_faithful_domain_node() -> None:
    # normalize_domain accepts a wildcard label, and a wildcard SAN is a real cert
    # fact — keep it verbatim rather than fabricate a stripped domain.
    g = _build(evidence(id="e1", type="cert_san_dns", target=cert(), value="*.evil.com", source="censys"))
    assert ("certifies", "CERTIFICATE", "sha256:" + "a" * 64, "DOMAIN", "*.evil.com") in edge_tuples(g)


def test_cert_san_invalid_value_is_quarantined() -> None:
    g = _build(evidence(id="e1", type="cert_san_dns", target=cert(), value="bad domain name", source="censys"))
    assert not any(e.relation.value == "certifies" for e in g.edges)
    assert any(i.reference == "e1" for i in g.issues)


def test_cert_fingerprint_makes_no_edge() -> None:
    g = _build(evidence(
        id="e1", type="cert_fingerprint_sha256", target=cert(), value="a" * 64, source="censys"
    ))
    assert g.edges == ()
    assert ("CERTIFICATE", "sha256:" + "a" * 64) in node_keys(g)  # node admitted via provenance


def test_unknown_type_is_provenance_only_no_edge_no_issue() -> None:
    g = _build(evidence(id="e1", type="service_banner", target=ip("1.2.3.4"), value="nginx", source="shodan"))
    assert g.edges == ()
    assert g.issues == ()
    assert ("IP", "1.2.3.4") in node_keys(g)
    node = next(n for n in g.nodes if n.node_type.value == "IP")
    assert "e1" in node.provenance


def test_role_consumed_verbatim_not_rederived(monkeypatch) -> None:
    score = domestic_relay_score("1.2.3.4")
    import apkscan.attribution.graph as graph_mod  # noqa: F401 - builder must not re-run these

    from apkscan.attribution import roles as roles_mod
    from apkscan.attribution import scorer as scorer_mod

    monkeypatch.setattr(roles_mod.RoleClassifier, "assess",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("re-derived")))
    monkeypatch.setattr(scorer_mod.EvidenceScorer, "score",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("re-scored")))

    g = build_infrastructure_graph(artifact_id="sample-A", role_scores=(score,))
    node = next(n for n in g.nodes if (n.node_type.value, n.value) == ("IP", "1.2.3.4"))
    assert [r.role.value for r in node.roles] == ["domestic_relay_candidate"]


def test_role_only_target_still_admits_node() -> None:
    g = _build(role_scores=(domestic_relay_score("1.2.3.4"),))
    assert ("IP", "1.2.3.4") in node_keys(g)


def test_ineligible_role_is_kept() -> None:
    # an origin_candidate assessment on an IP with only DOMESTIC_NETWORK evidence is
    # ineligible; the annotation is still carried (negatives are explainability).
    from apkscan.attribution import (
        EvidenceScorer,
        InfrastructureRole,
        RoleClassifier,
        RoleFeature,
        RoleSignal,
    )

    target = ip("1.2.3.4")
    ev = evidence(id="r1", type="business_api", target=target, value=True)
    feature = RoleFeature(signal=RoleSignal.BUSINESS_API, evidence=ev)
    origin = next(
        a for a in RoleClassifier().assess(target, [feature])
        if a.role is InfrastructureRole.ORIGIN_CANDIDATE
    )
    score = EvidenceScorer().score(origin)
    assert score.eligible is False
    g = _build(role_scores=(score,))
    node = next(n for n in g.nodes if (n.node_type.value, n.value) == ("IP", "1.2.3.4"))
    assert [r.role.value for r in node.roles] == ["origin_candidate"]
    assert node.roles[0].eligible is False


def test_container_level_type_errors_raise() -> None:
    with pytest.raises(ValueError):
        build_infrastructure_graph(artifact_id="   ")
    with pytest.raises(TypeError):
        build_infrastructure_graph(artifact_id="x", conversions=[object()])  # type: ignore[list-item]
    with pytest.raises(TypeError):
        build_infrastructure_graph(artifact_id="x", extra_evidence=[object()])  # type: ignore[list-item]


def test_one_dirty_fact_never_aborts_the_build() -> None:
    g = _build(
        evidence(id="ok", type="dns_resolution", target=ip("1.2.3.4"), value="good.example.com"),
        evidence(id="bad", type="resolved_ip", target=domain("example.com"), value="not-an-ip", source="shodan"),
    )
    assert any(e.relation.value == "resolves_to" for e in g.edges)  # good fact survives
    assert any(i.reference == "bad" for i in g.issues)  # bad fact quarantined


@pytest.mark.parametrize("bad_url", ["http://[::1", "https://[bad]/x", "not a url", "https:///nohost"])
def test_malformed_redirect_location_is_quarantined_not_crashing(bad_url) -> None:
    g = _build(
        evidence(id="good", type="dns_resolution", target=ip("1.2.3.4"), value="good.example.com"),
        evidence(id="r1", type="http_redirect", target=domain("a.com"), value=bad_url, source="mitmproxy"),
    )
    assert any(e.relation.value == "resolves_to" for e in g.edges)  # good fact survives
    assert not any(e.relation.value == "redirects_to" for e in g.edges)
    assert any(i.reference == "r1" for i in g.issues)


def test_host_targeted_role_does_not_crash_and_is_quarantined() -> None:
    # a HOST-kind role target folds onto a DOMAIN node whose kind differs, which
    # GraphNode role validation would reject — the builder must skip + record, not crash.
    score = domestic_relay_score_for(host("example.com:8443"))
    g = build_infrastructure_graph(artifact_id="s", role_scores=(score,))
    dom = next((n for n in g.nodes if (n.node_type.value, n.value) == ("DOMAIN", "example.com")), None)
    assert dom is not None and dom.roles == ()  # node admitted, no role attached
    assert any(i.stage == "role" for i in g.issues)


@pytest.mark.parametrize("etype", ["http_request", "http_response"])
def test_http_request_and_response_contact_the_host(etype) -> None:
    g = _build(evidence(id="e1", type=etype, target=host("api.example.com:8443"), value="x"))
    assert edge_tuples(g) == {("contacted", "APK", "sample-A", "DOMAIN", "api.example.com")}


def test_related_hostname_is_intel_related() -> None:
    g = _build(evidence(id="e1", type="related_hostname", target=ip("1.2.3.4"), value="h.example.com", source="fofa"))
    tuples = edge_tuples(g)
    assert ("intel_related", "IP", "1.2.3.4", "DOMAIN", "h.example.com") in tuples
    assert not any(t[0] in ("alias_of", "resolves_to") for t in tuples)


def test_self_referential_facts_make_no_edge() -> None:
    # http->https same-host upgrade, CNAME to self, related-hostname == target: no
    # self-loop edge, and (for the redirect) the contacted edge still appears.
    g = _build(
        evidence(id="e1", type="http_redirect", target=domain("a.com"), value="https://a.com/next", source="mitmproxy"),
        evidence(id="e2", type="dns_alias", target=domain("b.com"), value="b.com"),
        evidence(id="e3", type="related_hostname", target=domain("c.com"), value="c.com", source="fofa"),
    )
    assert not any(e.relation.value in ("redirects_to", "alias_of", "intel_related") for e in g.edges)
    assert ("contacted", "APK", "sample-A", "DOMAIN", "a.com") in edge_tuples(g)


def test_observation_enriches_provenance_but_drops_device_src_ip() -> None:
    obs = Observation(
        id="obs-1", source="pcap", type="network_flow",
        entities=(ip("10.0.0.5"), ip("1.2.3.4")),  # device src + remote dst
    )
    conversion = ConversionResult(
        observations=(obs,),
        evidence=(evidence(id="f1", type="network_flow", target=ip("1.2.3.4"), value="tcp/443"),),
    )
    g = build_infrastructure_graph(artifact_id="s", conversions=[conversion])
    assert ("IP", "10.0.0.5") not in node_keys(g)  # device src IP is never admitted
    dst = next(n for n in g.nodes if (n.node_type.value, n.value) == ("IP", "1.2.3.4"))
    assert {"f1", "obs-1"} <= set(dst.provenance)  # observation id folded into provenance


def test_conflicting_id_across_conversions_raises_in_any_order() -> None:
    a = ConversionResult(evidence=(evidence(id="dup", type="asn", target=ip("1.2.3.4"), value=13335, source="shodan"),))
    b = ConversionResult(evidence=(evidence(id="dup", type="asn", target=ip("1.2.3.4"), value=20940, source="censys"),))
    with pytest.raises(ValueError):
        build_infrastructure_graph(artifact_id="s", conversions=[a, b])
    with pytest.raises(ValueError):
        build_infrastructure_graph(artifact_id="s", conversions=[b, a])


def test_merge_equivalence() -> None:
    from apkscan.network.converters import merge_conversion_results

    a = ConversionResult(evidence=(evidence(id="e1", type="dns_resolution", target=ip("1.2.3.4"), value="a.com"),))
    b = ConversionResult(evidence=(evidence(id="e2", type="asn", target=ip("1.2.3.4"), value=13335, source="shodan"),))
    import json
    g_two = build_infrastructure_graph(artifact_id="s", conversions=[a, b])
    g_merged = build_infrastructure_graph(artifact_id="s", conversions=[merge_conversion_results(a, b)])
    assert json.dumps(g_two.to_dict(), sort_keys=True) == json.dumps(g_merged.to_dict(), sort_keys=True)
