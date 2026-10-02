"""Public-looking SNI cannot exempt its separate transport peer from review.

Synthetic address classification is injected: no public host is queried and no
real infrastructure is labelled suspicious by these tests.
"""
import pytest

from apkscan.core import infra
from apkscan.core.enrichment import _enrichment_targets
from apkscan.core.models import Report
from apkscan.dynamic import merge, pcap_ingest


@pytest.mark.parametrize("ports", [(443,), (40001,), (443, 40001)])
def test_public_domain_exclusion_does_not_remove_real_peer(ports, monkeypatch):
    peer = "198.51.100.20"
    name = "public-service.example.test"
    monkeypatch.setattr(pcap_ingest, "_ip_public", lambda value: value == peer)
    monkeypatch.setattr(infra, "classify_domain", lambda value: (infra.ADVICE_SKIP, "synthetic public service"))
    monkeypatch.setattr(infra, "effective_advice", lambda *a, **kw: infra.ADVICE_SKIP)
    monkeypatch.setattr(infra, "effective_ip_advice", lambda *a, **kw: infra.ADVICE_INVESTIGATE)
    flows = []
    for port in ports:
        flows.append(pcap_ingest.Flow("tcp", "192.168.1.2", 45678, peer, port,
                                     payload_bytes=800, sni={name}, first_ts=100, last_ts=101))
        flows.append(pcap_ingest.Flow("tcp", peer, port, "192.168.1.2", 45678,
                                     payload_bytes=1600, first_ts=100, last_ts=101))
    endpoints = pcap_ingest.to_runtime_endpoints(pcap_ingest.PcapSummary(flows=flows))
    report = Report("com.example.synthetic", {"online": False}, [], [], [], [])
    merge.merge_runtime_endpoints(report, endpoints)
    assert any(ep.value == peer and ep.kind == "ip" for ep in report.endpoints)
    targets = _enrichment_targets(report.endpoints)
    assert [(ep.kind, ep.value) for ep in targets] == [("ip", peer)]
    assert any(name in (ev.snippet or "") for ep in report.endpoints if ep.value == peer for ev in ep.evidences)


def test_ledger_retains_dns_and_peer_observation_times_without_identity_claim(monkeypatch):
    peer = "198.51.100.20"
    monkeypatch.setattr(pcap_ingest, "_ip_public", lambda value: value == peer)
    summary = pcap_ingest.PcapSummary(flows=[
        pcap_ingest.Flow("tcp", "192.168.1.2", 45678, peer, 443,
                         payload_bytes=100, first_ts=120, last_ts=125, sni={"public.example.test"})],
        dns_records=[pcap_ingest.DnsRecord("public.example.test", 1, 0,
                    answers=[{"type": 1, "value": "198.51.100.21", "ttl": 30}], ts=115)])
    ledger = pcap_ingest.to_ledger_dict(summary)
    assert ledger["dns_records"][0]["observed_at"] == 115
    row = ledger["remote_endpoints"][0]
    assert (row["first_ts"], row["last_ts"]) == (120, 125)
    assert row["sni_identity_verified"] is False
    assert row["ip"] == peer
