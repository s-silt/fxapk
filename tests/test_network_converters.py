from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import pytest

from apkscan.dynamic.pcap_ingest import DnsRecord, Flow, PcapSummary
from apkscan.dynamic.tshark_backend import HttpRequest
from apkscan.network import NetworkEntityType
from apkscan.network.converters import (
    ConversionResult,
    convert_http_requests,
    convert_mitmproxy_flows,
    convert_pcap_summary,
    merge_conversion_results,
)


def _by_type(result: ConversionResult, observation_type: str) -> list[Any]:
    return [item for item in result.observations if item.type == observation_type]


def _evidence_by_type(result: ConversionResult, evidence_type: str) -> list[Any]:
    return [item for item in result.evidence if item.type == evidence_type]


def _entity_values(result: ConversionResult, kind: NetworkEntityType) -> list[str]:
    return [item.value for item in result.entities if item.kind is kind]


def _full_summary() -> PcapSummary:
    return PcapSummary(
        flows=[
            Flow(
                proto="tcp",
                src_ip="10.0.0.2",
                src_port=53000,
                dst_ip="2001:0db8:0:0::1",
                dst_port=443,
                packets=4,
                bytes_=900,
                payload_bytes=512,
                first_ts=1_700_000_000.25,
                last_ts=1_700_000_001.5,
                flags={"ack", "syn"},
                sni={"API.Example.COM."},
                ja3={"771,4865-4866,0-16,29,0"},
            ),
            Flow(
                proto="udp",
                src_ip="10.0.0.2",
                src_port=54000,
                dst_ip="1.1.1.1",
                dst_port=443,
                packets=2,
                bytes_=240,
                payload_bytes=180,
                first_ts=1_700_000_002.0,
                last_ts=1_700_000_002.25,
                sni={"H3.Example.com"},
                quic_versions={"00000001"},
                quic_dcids={"aabb"},
                quic_scids={"ccdd"},
                alpn={"h3", "h3-29"},
            ),
        ],
        dns_queries={"orphan.example."},
        dns_records=[
            DnsRecord(
                qname="API.Example.COM.",
                qtype=1,
                rcode=0,
                txid=7,
                ts=1_700_000_000.0,
                answers=[
                    {"type": 1, "value": "203.0.113.8", "ttl": 60},
                    {"type": 28, "value": "2001:0db8::8", "ttl": 120},
                    {"type": 5, "value": "Edge.Example.NET.", "ttl": 30},
                    {"type": 16, "value": "opaque-config", "ttl": 10},
                ],
            ),
            DnsRecord(
                qname="missing.example",
                qtype=1,
                rcode=3,
                txid=8,
                ts=1_700_000_003.0,
                answers=[],
            ),
        ],
    )


def test_convert_pcap_preserves_flow_dns_tls_and_quic_facts() -> None:
    result = convert_pcap_summary(
        _full_summary(),
        artifact_id="sha256:pcap-one",
        raw_reference="artifacts/floor.pcap",
    )

    flows = _by_type(result, "network_flow")
    assert len(flows) == 2
    tcp = next(item for item in flows if item.attributes["protocol"] == "tcp")
    assert tcp.attributes == {
        "bytes": 900,
        "dst_ip": "2001:db8::1",
        "dst_port": 443,
        "first_ts": 1_700_000_000.25,
        "flags": ["ack", "syn"],
        "last_ts": 1_700_000_001.5,
        "packets": 4,
        "payload_bytes": 512,
        "protocol": "tcp",
        "src_ip": "10.0.0.2",
        "src_port": 53000,
    }
    assert tcp.timestamp == 1_700_000_000.25
    assert tcp.raw_reference == "artifacts/floor.pcap"
    assert [entity.value for entity in tcp.entities] == ["10.0.0.2", "2001:db8::1"]

    tls = _by_type(result, "tls_client_hello")
    assert len(tls) == 2
    tcp_tls = next(item for item in tls if item.attributes["transport"] == "tcp")
    assert tcp_tls.attributes["sni"] == ["api.example.com"]
    assert tcp_tls.attributes["ja3"] == ["771,4865-4866,0-16,29,0"]
    assert tcp_tls.attributes["offered_alpn"] == []

    quic = _by_type(result, "quic_connection")
    assert len(quic) == 1
    assert quic[0].attributes["versions"] == ["00000001"]
    assert quic[0].attributes["dcids"] == ["aabb"]
    assert quic[0].attributes["scids"] == ["ccdd"]
    assert quic[0].attributes["offered_alpn"] == ["h3", "h3-29"]
    assert "http3" not in quic[0].attributes

    assert len(_by_type(result, "dns_message")) == 2
    resolutions = _by_type(result, "dns_resolution")
    assert {(item.entities[0].value, item.entities[1].value) for item in resolutions} == {
        ("api.example.com", "203.0.113.8"),
        ("api.example.com", "2001:db8::8"),
    }
    assert {item.attributes["ttl"] for item in resolutions} == {60, 120}
    aliases = _by_type(result, "dns_alias")
    assert [(entity.value) for entity in aliases[0].entities] == [
        "api.example.com",
        "edge.example.net",
    ]
    assert len(_by_type(result, "dns_query")) == 1
    assert _by_type(result, "dns_query")[0].entities[0].value == "orphan.example"


def test_pcap_evidence_is_atomic_and_does_not_invent_certificates_or_roles() -> None:
    result = convert_pcap_summary(_full_summary(), artifact_id="capture-a")

    flows = _evidence_by_type(result, "network_flow")
    assert {item.value for item in flows} == {"tcp/443", "udp/443"}
    assert all(item.confidence == 1.0 for item in flows)
    assert not _evidence_by_type(result, "network_connection")
    assert {(item.target.value, item.value) for item in _evidence_by_type(result, "dns_resolution")} == {
        ("203.0.113.8", "api.example.com"),
        ("2001:db8::8", "api.example.com"),
    }
    assert {(item.target.value, item.value) for item in _evidence_by_type(result, "tls_sni")} == {
        ("api.example.com", "2001:db8::1"),
        ("h3.example.com", "1.1.1.1"),
    }
    assert not _entity_values(result, NetworkEntityType.CERTIFICATE)
    forbidden = {"origin_candidate", "edge_candidate", "domestic_relay_candidate", "cloaking_edge_node"}
    assert forbidden.isdisjoint({item.type for item in result.observations})
    assert forbidden.isdisjoint({item.type for item in result.evidence})


def test_dns_message_keeps_nxdomain_txt_and_full_answer_metadata() -> None:
    result = convert_pcap_summary(_full_summary(), artifact_id="capture-a")
    messages = _by_type(result, "dns_message")

    successful = next(item for item in messages if item.attributes["rcode"] == 0)
    assert successful.attributes["qtype"] == 1
    assert successful.attributes["txid"] == 7
    assert successful.attributes["answers"] == [
        {"ttl": 60, "type": 1, "value": "203.0.113.8"},
        {"ttl": 30, "type": 5, "value": "edge.example.net"},
        {"ttl": 10, "type": 16, "value": "opaque-config"},
        {"ttl": 120, "type": 28, "value": "2001:db8::8"},
    ]
    missing = next(item for item in messages if item.attributes["rcode"] == 3)
    assert missing.attributes["answers"] == []
    assert missing.timestamp == 1_700_000_003.0
    assert not any(item.target.value == "missing.example" for item in result.evidence)


def test_pcap_conversion_is_deterministic_across_input_and_set_order() -> None:
    left = _full_summary()
    right = _full_summary()
    right.flows.reverse()
    right.dns_records.reverse()
    right.dns_queries = set(reversed(sorted(right.dns_queries)))
    for flow in right.flows:
        flow.flags = set(reversed(sorted(flow.flags)))
        flow.sni = set(reversed(sorted(flow.sni)))
        flow.alpn = set(reversed(sorted(flow.alpn)))
    right.dns_records[-1].answers.reverse()

    first = convert_pcap_summary(left, artifact_id="capture-a").to_dict()
    second = convert_pcap_summary(right, artifact_id="capture-a").to_dict()
    assert first == second
    assert json.dumps(first, sort_keys=True)


def test_pcap_flow_ids_are_stable_when_partial_sort_keys_tie() -> None:
    first = Flow(
        proto="tcp",
        src_ip="10.0.0.2",
        src_port=51000,
        dst_ip="203.0.113.8",
        dst_port=443,
        packets=2,
        bytes_=200,
        first_ts=10.0,
        last_ts=11.0,
        sni={"a.example"},
    )
    second = Flow(
        proto="tcp",
        src_ip="10.0.0.2",
        src_port=51000,
        dst_ip="203.0.113.8",
        dst_port=443,
        packets=4,
        bytes_=400,
        first_ts=10.0,
        last_ts=11.0,
        sni={"b.example"},
    )

    forward = convert_pcap_summary(
        PcapSummary(flows=[first, second]), artifact_id="capture-a"
    )
    reverse = convert_pcap_summary(
        PcapSummary(flows=[second, first]), artifact_id="capture-a"
    )

    assert forward.to_dict() == reverse.to_dict()


def test_flows_differing_only_in_tls_metadata_remain_distinct() -> None:
    common = {
        "proto": "tcp",
        "src_ip": "10.0.0.2",
        "src_port": 51000,
        "dst_ip": "203.0.113.8",
        "dst_port": 443,
        "packets": 2,
        "bytes_": 200,
        "payload_bytes": 100,
        "first_ts": 10.0,
        "last_ts": 11.0,
    }
    first = Flow(**common, ja3={"aa"})
    second = Flow(**common, ja3={"bb"})

    forward = convert_pcap_summary(
        PcapSummary(flows=[first, second]), artifact_id="capture-a"
    )
    reverse = convert_pcap_summary(
        PcapSummary(flows=[second, first]), artifact_id="capture-a"
    )

    assert len(_by_type(forward, "network_flow")) == 2
    assert len(_evidence_by_type(forward, "network_flow")) == 2
    assert forward.to_dict() == reverse.to_dict()


def test_unrelated_pcap_flow_does_not_change_existing_ids() -> None:
    flow = Flow(
        proto="tcp",
        src_ip="10.0.0.2",
        src_port=51000,
        dst_ip="203.0.113.8",
        dst_port=443,
        first_ts=10.0,
        last_ts=11.0,
    )
    unrelated = Flow(
        proto="tcp",
        src_ip="10.0.0.2",
        src_port=50000,
        dst_ip="198.51.100.7",
        dst_port=80,
        first_ts=1.0,
        last_ts=2.0,
    )

    original = convert_pcap_summary(
        PcapSummary(flows=[flow]), artifact_id="capture-a"
    )
    prepended = convert_pcap_summary(
        PcapSummary(flows=[unrelated, flow]), artifact_id="capture-a"
    )

    original_id = _by_type(original, "network_flow")[0].id
    retained_id = next(
        item.id
        for item in _by_type(prepended, "network_flow")
        if item.attributes["dst_ip"] == "203.0.113.8"
    )
    assert retained_id == original_id


def test_unrelated_dns_record_does_not_change_existing_ids() -> None:
    target = DnsRecord(
        qname="z.example",
        qtype=1,
        rcode=0,
        txid=10,
        ts=10.0,
        answers=[{"type": 1, "value": "203.0.113.8", "ttl": 60}],
    )
    unrelated = DnsRecord(
        qname="a.example",
        qtype=1,
        rcode=0,
        txid=11,
        ts=1.0,
        answers=[{"type": 1, "value": "198.51.100.7", "ttl": 60}],
    )

    original = convert_pcap_summary(
        PcapSummary(dns_records=[target]), artifact_id="capture-a"
    )
    prepended = convert_pcap_summary(
        PcapSummary(dns_records=[unrelated, target]), artifact_id="capture-a"
    )

    original_ids = {
        item.type: item.id
        for item in original.observations
        if item.entities[0].value == "z.example"
    }
    retained_ids = {
        item.type: item.id
        for item in prepended.observations
        if item.entities[0].value == "z.example"
    }
    assert retained_ids == original_ids


def test_canonically_identical_dns_records_remain_distinct_occurrences() -> None:
    first = DnsRecord(
        qname="API.Example.COM.",
        qtype=1,
        rcode=0,
        txid=7,
        ts=10.0,
        answers=[{"type": 1, "value": "203.0.113.8", "ttl": 60}],
    )
    second = DnsRecord(
        qname="api.example.com",
        qtype=1,
        rcode=0,
        txid=7,
        ts=10.0,
        answers=[{"type": 1, "value": "203.0.113.8", "ttl": 60}],
    )

    result = convert_pcap_summary(
        PcapSummary(dns_records=[first, second]), artifact_id="capture-a"
    )

    messages = _by_type(result, "dns_message")
    resolutions = _by_type(result, "dns_resolution")
    assert len(messages) == 2
    assert len({item.id for item in messages}) == 2
    assert len(resolutions) == 2
    assert len({item.id for item in resolutions}) == 2


def test_failed_flow_does_not_consume_valid_flow_occurrence() -> None:
    valid = Flow(
        proto="tcp",
        src_ip="10.0.0.2",
        src_port=0,
        dst_ip="203.0.113.8",
        dst_port=443,
    )
    invalid = {
        "proto": "tcp",
        "src_ip": "10.0.0.2",
        "dst_ip": "203.0.113.8",
        "dst_port": 443,
    }

    original = convert_pcap_summary(
        PcapSummary(flows=[valid]), artifact_id="capture-a"
    )
    with_invalid = convert_pcap_summary(
        PcapSummary(flows=[invalid, valid]), artifact_id="capture-a"
    )

    assert _by_type(with_invalid, "network_flow")[0].id == _by_type(
        original, "network_flow"
    )[0].id


def test_failed_dns_record_does_not_consume_valid_record_occurrence() -> None:
    valid = DnsRecord(
        qname="api.example.com",
        qtype=0,
        rcode=0,
        txid=7,
        ts=10.0,
        answers=[],
    )
    invalid = {
        "qname": "api.example.com",
        "rcode": 0,
        "txid": 7,
        "ts": 10.0,
        "answers": [],
    }

    original = convert_pcap_summary(
        PcapSummary(dns_records=[valid]), artifact_id="capture-a"
    )
    with_invalid = convert_pcap_summary(
        PcapSummary(dns_records=[invalid, valid]), artifact_id="capture-a"
    )

    assert _by_type(with_invalid, "dns_message")[0].id == _by_type(
        original, "dns_message"
    )[0].id


def test_pcap_keeps_private_and_syn_only_flows_as_facts() -> None:
    summary = PcapSummary(
        flows=[
            Flow(
                proto="tcp",
                src_ip="10.0.0.2",
                src_port=40000,
                dst_ip="192.168.1.10",
                dst_port=8080,
                packets=1,
                flags={"syn"},
            )
        ]
    )
    result = convert_pcap_summary(summary, artifact_id="capture-a")
    flow = _by_type(result, "network_flow")[0]
    assert flow.attributes["payload_bytes"] == 0
    assert flow.attributes["flags"] == ["syn"]
    assert _evidence_by_type(result, "network_flow")[0].target.value == "192.168.1.10"


def test_identical_quic_connections_remain_distinct_observations() -> None:
    flow = Flow(
        proto="udp",
        src_ip="10.0.0.2",
        src_port=54000,
        dst_ip="1.1.1.1",
        dst_port=443,
        first_ts=10.0,
        last_ts=11.0,
        sni={"h3.example.com"},
        quic_versions={"00000001"},
        quic_dcids={"aabb"},
        alpn={"h3"},
    )
    result = convert_pcap_summary(
        PcapSummary(flows=[flow, flow]), artifact_id="capture-a"
    )
    quic = _by_type(result, "quic_connection")
    assert len(quic) == 2
    assert quic[0].id != quic[1].id


def test_invalid_flow_timestamp_order_is_isolated() -> None:
    summary = PcapSummary(
        flows=[
            Flow(
                proto="tcp",
                src_ip="10.0.0.2",
                src_port=40000,
                dst_ip="203.0.113.8",
                dst_port=443,
                first_ts=5.0,
                last_ts=0.0,
            )
        ]
    )
    result = convert_pcap_summary(summary, artifact_id="capture-a")
    assert not result.observations
    assert result.issues[0].stage == "pcap.flow"


def test_bad_pcap_item_isolated_without_losing_valid_dns() -> None:
    summary = _full_summary()
    summary.flows.append(
        Flow(proto="tcp", src_ip="not-an-ip", src_port=1, dst_ip="1.2.3.4", dst_port=443)
    )
    result = convert_pcap_summary(summary, artifact_id="capture-a")

    assert len(_by_type(result, "network_flow")) == 2
    assert _by_type(result, "dns_message")
    assert any(issue.stage == "pcap.flow" and issue.index == 2 for issue in result.issues)


def test_invalid_tls_auxiliary_value_does_not_drop_core_flow() -> None:
    flow = Flow(
        proto="tcp",
        src_ip="10.0.0.2",
        src_port=50000,
        dst_ip="203.0.113.8",
        dst_port=443,
        sni={"api.example.com", "bad host"},
    )

    result = convert_pcap_summary(
        PcapSummary(flows=[flow]), artifact_id="capture-a"
    )

    assert len(_by_type(result, "network_flow")) == 1
    assert _by_type(result, "tls_client_hello")[0].attributes["sni"] == [
        "api.example.com"
    ]
    assert [(item.stage, item.index) for item in result.issues] == [
        ("pcap.flow.aux", 0)
    ]


def test_invalid_dns_answer_does_not_drop_message_or_valid_resolution() -> None:
    record = DnsRecord(
        qname="api.example.com",
        qtype=1,
        rcode=0,
        txid=7,
        ts=10.0,
        answers=[
            {"type": 1, "value": "203.0.113.8", "ttl": 60},
            {"type": 5, "value": "bad host", "ttl": 60},
        ],
    )

    result = convert_pcap_summary(
        PcapSummary(dns_records=[record]), artifact_id="capture-a"
    )

    assert len(_by_type(result, "dns_message")) == 1
    resolution = _by_type(result, "dns_resolution")[0]
    assert resolution.entities[1].value == "203.0.113.8"
    assert [(item.stage, item.index) for item in result.issues] == [
        ("pcap.dns.answer", 0)
    ]


@pytest.mark.parametrize(
    ("summary", "artifact_id", "error"),
    [
        (object(), "capture-a", TypeError),
        (PcapSummary(), "", ValueError),
        (PcapSummary(), 3, TypeError),
    ],
)
def test_pcap_top_level_contract_errors_are_not_swallowed(
    summary: object, artifact_id: object, error: type[Exception]
) -> None:
    with pytest.raises(error):
        convert_pcap_summary(summary, artifact_id=artifact_id)  # type: ignore[arg-type]


def test_convert_tshark_http_preserves_each_path_and_sanitizes_query() -> None:
    requests = [
        HttpRequest(
            host="API.Example.COM:8443",
            method="POST",
            uri="/login?token=secret#fragment",
            user_agent="fxapk-test/1",
            dst_ip="203.0.113.20",
            dst_port="8443",
        ),
        HttpRequest(
            host="api.example.com:8443",
            method="GET",
            uri="/config",
            dst_ip="203.0.113.20",
            dst_port="8443",
        ),
    ]
    result = convert_http_requests(
        requests,
        artifact_id="sha256:pcap-one",
        source="tls-decrypted",
        scheme="https",
        raw_reference="artifacts/floor.pcap",
        timestamp=1_700_000_010.0,
    )

    observations = _by_type(result, "http_request")
    assert len(observations) == 2
    assert {item.attributes["path"] for item in observations} == {"/login", "/config"}
    login = next(item for item in observations if item.attributes["path"] == "/login")
    assert login.attributes["authority"] == "api.example.com:8443"
    assert login.attributes["host"] == "api.example.com"
    assert login.attributes["port"] == 8443
    assert login.attributes["dst_ip"] == "203.0.113.20"
    assert login.attributes["dst_port"] == 8443
    assert login.attributes["user_agent"] == "fxapk-test/1"
    assert login.timestamp == 1_700_000_010.0
    serialized = json.dumps(result.to_dict(), sort_keys=True)
    assert "secret" not in serialized
    assert "token=" not in serialized
    assert _entity_values(result, NetworkEntityType.URL) == [
        "https://api.example.com:8443/config",
        "https://api.example.com:8443/login",
    ]


def test_http_authority_supports_ip_literal_and_ipv6() -> None:
    result = convert_http_requests(
        [
            HttpRequest(host="203.0.113.9", method="GET", uri="/v4"),
            HttpRequest(host="[2001:0db8::9]:9443", method="GET", uri="/v6"),
        ],
        artifact_id="capture-a",
        source="tshark",
        scheme="http",
    )
    assert _entity_values(result, NetworkEntityType.IP) == ["2001:db8::9", "203.0.113.9"]
    assert _entity_values(result, NetworkEntityType.HOST) == [
        "203.0.113.9",
        "[2001:db8::9]:9443",
    ]


def test_tshark_explicit_default_port_uses_canonical_host_identity() -> None:
    explicit = convert_http_requests(
        [HttpRequest(host="API.Example.COM:443", method="GET", uri="/status")],
        artifact_id="capture-explicit",
        source="tshark",
        scheme="https",
    )
    implicit = convert_http_requests(
        [HttpRequest(host="API.Example.COM", method="GET", uri="/status")],
        artifact_id="capture-implicit",
        source="tshark",
        scheme="https",
    )

    assert _entity_values(explicit, NetworkEntityType.HOST) == ["api.example.com"]
    assert _entity_values(explicit, NetworkEntityType.URL) == [
        "https://api.example.com/status"
    ]
    assert _by_type(explicit, "http_request")[0].attributes == _by_type(
        implicit, "http_request"
    )[0].attributes


def test_bad_http_item_isolated() -> None:
    result = convert_http_requests(
        [
            HttpRequest(host="good.example", method="GET", uri="/"),
            HttpRequest(host="bad host", method="GET", uri="/"),
        ],
        artifact_id="capture-a",
        source="tshark",
        scheme="http",
    )
    assert len(_by_type(result, "http_request")) == 1
    assert result.issues[0].stage == "http.request"
    assert result.issues[0].index == 1


def test_identical_http_requests_remain_distinct_observations() -> None:
    request = HttpRequest(host="api.example.com", method="GET", uri="/poll")
    result = convert_http_requests(
        [request, request],
        artifact_id="capture-a",
        source="tshark",
        scheme="https",
    )
    observations = _by_type(result, "http_request")
    assert len(observations) == 2
    assert observations[0].id != observations[1].id


def test_unrelated_http_request_does_not_change_existing_ids() -> None:
    requests = [
        HttpRequest(host="api.example.com", method="GET", uri="/a"),
        HttpRequest(host="api.example.com", method="GET", uri="/b"),
    ]
    original = convert_http_requests(
        requests, artifact_id="capture-a", source="tshark", scheme="https"
    )
    prepended = convert_http_requests(
        [HttpRequest(host="other.example", method="GET", uri="/"), *requests],
        artifact_id="capture-a",
        source="tshark",
        scheme="https",
    )

    original_ids = {
        item.attributes["path"]: item.id for item in _by_type(original, "http_request")
    }
    prepended_ids = {
        item.attributes["path"]: item.id
        for item in _by_type(prepended, "http_request")
        if item.attributes["host"] == "api.example.com"
    }
    assert prepended_ids == original_ids


@dataclass
class _ServerConn:
    peername: tuple[object, ...] = ("203.0.113.50", 443)


@dataclass
class _Message:
    host: str = "Gate.Example.COM"
    port: int = 443
    scheme: str = "https"
    method: str = "GET"
    path: str = "/verify?session=secret"
    headers: dict[str, str] = field(
        default_factory=lambda: {
            "Accept": "text/html",
            "Authorization": "Bearer secret-token",
            "Cookie": "session=secret-cookie",
            "Referer": "https://Gate.Example.COM/start?token=header-secret#part",
            "User-Agent": "mobile-client",
        }
    )
    raw_content: bytes | None = b"request"
    timestamp_start: float = 1_700_000_020.0


@dataclass
class _Response:
    status_code: int = 302
    headers: object = field(
        default_factory=lambda: {
            "Location": "https://Origin.Example.NET/login?ticket=secret",
            "Content-Type": "text/html",
            "Content-Length": "42",
            "Server": "openresty",
            "Set-Cookie": "challenge=secret-value; Path=/; HttpOnly",
        }
    )
    raw_content: bytes | None = b"redirect body"
    timestamp_start: float = 1_700_000_020.5


@dataclass
class _MitmFlow:
    request: _Message = field(default_factory=_Message)
    response: _Response | None = field(default_factory=_Response)
    server_conn: _ServerConn = field(default_factory=_ServerConn)


class _MultiHeaders:
    def items(self, multi: bool = False) -> list[tuple[str, str]]:
        if multi:
            return [
                ("Set-Cookie", "challenge=one; Path=/"),
                ("Set-Cookie", "verified=two; Path=/"),
            ]
        return [("Set-Cookie", "challenge=one; Path=/, verified=two; Path=/")]


def test_convert_mitm_flow_preserves_response_redirect_without_credentials() -> None:
    result = convert_mitmproxy_flows(
        [_MitmFlow()],
        artifact_id="sha256:mitm-one",
        raw_reference="artifacts/flows.mitm",
    )

    request = _by_type(result, "http_request")[0]
    assert request.source == "mitmproxy"
    assert request.attributes["headers"] == {
        "accept": "text/html",
        "referer": "https://gate.example.com/start",
        "user-agent": "mobile-client",
    }
    assert request.attributes["content_length"] == 7
    assert request.attributes["path"] == "/verify"

    response = _by_type(result, "http_response")[0]
    assert response.attributes["status"] == 302
    assert response.attributes["headers"] == {
        "content-length": "42",
        "content-type": "text/html",
        "location": "https://origin.example.net/login",
        "server": "openresty",
    }
    assert response.attributes["content_length"] == 13
    assert response.attributes["set_cookie_names"] == ["challenge"]
    assert response.attributes["request_observation_id"] == request.id

    redirect = _by_type(result, "http_redirect")[0]
    assert redirect.attributes["location"] == "https://origin.example.net/login"
    assert redirect.attributes["request_observation_id"] == request.id
    assert _entity_values(result, NetworkEntityType.DOMAIN) == [
        "gate.example.com",
        "origin.example.net",
    ]
    assert "https://origin.example.net/login" in _entity_values(result, NetworkEntityType.URL)

    serialized = json.dumps(result.to_dict(), sort_keys=True)
    for secret in (
        "Bearer",
        "secret-token",
        "secret-cookie",
        "secret-value",
        "ticket=",
        "header-secret",
    ):
        assert secret not in serialized


def test_mitm_flow_without_response_only_emits_request() -> None:
    result = convert_mitmproxy_flows(
        [_MitmFlow(response=None)], artifact_id="capture-a"
    )
    assert len(_by_type(result, "http_request")) == 1
    assert not _by_type(result, "http_response")
    assert not _by_type(result, "http_redirect")


def test_mitm_unknown_content_length_is_distinct_from_known_empty_body() -> None:
    unknown = convert_mitmproxy_flows(
        [
            _MitmFlow(
                request=_Message(raw_content=None),
                response=_Response(raw_content=None),
            )
        ],
        artifact_id="capture-unknown",
    )
    empty = convert_mitmproxy_flows(
        [
            _MitmFlow(
                request=_Message(raw_content=b""),
                response=_Response(raw_content=b""),
            )
        ],
        artifact_id="capture-empty",
    )

    assert "content_length" not in _by_type(unknown, "http_request")[0].attributes
    assert "content_length" not in _by_type(unknown, "http_response")[0].attributes
    assert _by_type(empty, "http_request")[0].attributes["content_length"] == 0
    assert _by_type(empty, "http_response")[0].attributes["content_length"] == 0


def test_mitm_preserves_every_set_cookie_name_from_multi_headers() -> None:
    result = convert_mitmproxy_flows(
        [_MitmFlow(response=_Response(headers=_MultiHeaders()))],
        artifact_id="capture-a",
    )

    response = _by_type(result, "http_response")[0]
    assert response.attributes["set_cookie_names"] == ["challenge", "verified"]


def test_invalid_redirect_is_isolated_without_losing_response() -> None:
    result = convert_mitmproxy_flows(
        [
            _MitmFlow(
                response=_Response(
                    headers={"Location": "javascript:alert(1)", "Server": "nginx"}
                )
            )
        ],
        artifact_id="capture-a",
    )

    response = _by_type(result, "http_response")[0]
    assert response.attributes["status"] == 302
    assert response.attributes["headers"] == {"server": "nginx"}
    assert not _by_type(result, "http_redirect")
    assert [(item.stage, item.index) for item in result.issues] == [
        ("mitm.redirect", 0)
    ]


def test_mitm_ipv6_peername_four_tuple_is_accepted() -> None:
    flow = _MitmFlow(server_conn=_ServerConn(("2001:0db8::50", 443, 0, 2)))
    result = convert_mitmproxy_flows([flow], artifact_id="capture-a")
    request = _by_type(result, "http_request")[0]
    assert request.attributes["dst_ip"] == "2001:db8::50"
    assert not result.issues


def test_mitm_explicit_default_port_uses_canonical_host_identity() -> None:
    explicit = convert_mitmproxy_flows(
        [_MitmFlow(request=_Message(host="Gate.Example.COM:443"), response=None)],
        artifact_id="capture-explicit",
    )
    implicit = convert_mitmproxy_flows(
        [_MitmFlow(request=_Message(host="Gate.Example.COM"), response=None)],
        artifact_id="capture-implicit",
    )

    assert _entity_values(explicit, NetworkEntityType.HOST) == ["gate.example.com"]
    assert _entity_values(explicit, NetworkEntityType.URL) == [
        "https://gate.example.com/verify"
    ]
    assert _by_type(explicit, "http_request")[0].attributes == _by_type(
        implicit, "http_request"
    )[0].attributes


def test_unrelated_mitm_flow_does_not_change_existing_ids() -> None:
    target = _MitmFlow()
    original = convert_mitmproxy_flows([target], artifact_id="capture-a")
    prepended = convert_mitmproxy_flows(
        [
            _MitmFlow(
                request=_Message(host="unrelated.example", path="/"), response=None
            ),
            target,
        ],
        artifact_id="capture-a",
    )

    original_ids = {item.type: item.id for item in original.observations}
    retained_ids = {
        item.type: item.id
        for item in prepended.observations
        if any(entity.value == "gate.example.com" for entity in item.entities)
    }
    assert retained_ids == original_ids


def test_mitm_linkage_is_stable_when_identical_requests_have_distinct_responses() -> None:
    first = _MitmFlow(
        response=_Response(
            status_code=301,
            headers={"Location": "https://one.example/next", "Server": "nginx"},
        )
    )
    second = _MitmFlow(
        response=_Response(
            status_code=302,
            headers={"Location": "https://two.example/next", "Server": "nginx"},
        )
    )

    forward = convert_mitmproxy_flows(
        [first, second], artifact_id="capture-a"
    )
    reverse = convert_mitmproxy_flows(
        [second, first], artifact_id="capture-a"
    )

    assert forward.to_dict() == reverse.to_dict()


def test_merge_results_unions_entity_sources_and_is_deterministic() -> None:
    pcap = PcapSummary(
        flows=[
            Flow(
                proto="tcp",
                src_ip="10.0.0.2",
                src_port=50000,
                dst_ip="203.0.113.20",
                dst_port=443,
                sni={"api.example.com"},
            )
        ]
    )
    left = convert_pcap_summary(pcap, artifact_id="pcap-a")
    right = convert_http_requests(
        [HttpRequest(host="api.example.com", method="GET", uri="/")],
        artifact_id="pcap-a",
        source="tshark",
        scheme="http",
    )
    merged = merge_conversion_results(left, right)

    domain = next(
        entity
        for entity in merged.entities
        if entity.kind is NetworkEntityType.DOMAIN and entity.value == "api.example.com"
    )
    assert domain.sources == ("pcap", "tshark")
    assert merged.to_dict() == merge_conversion_results(right, left).to_dict()


def test_merge_preserves_identical_http_facts_from_distinct_sources() -> None:
    request = HttpRequest(host="api.example.com", method="GET", uri="/status")
    tshark = convert_http_requests(
        [request], artifact_id="capture-a", source="tshark", scheme="https"
    )
    decrypted = convert_http_requests(
        [request], artifact_id="capture-a", source="tls-decrypted", scheme="https"
    )

    forward = merge_conversion_results(tshark, decrypted)
    reverse = merge_conversion_results(decrypted, tshark)

    assert len(_by_type(forward, "http_request")) == 2
    assert len(_evidence_by_type(forward, "http_request")) == 2
    assert {item.source for item in _by_type(forward, "http_request")} == {
        "tshark",
        "tls-decrypted",
    }
    assert forward.to_dict() == reverse.to_dict()


def test_conversion_result_json_is_fully_serializable() -> None:
    result = merge_conversion_results(
        convert_pcap_summary(_full_summary(), artifact_id="pcap-a"),
        convert_mitmproxy_flows([_MitmFlow()], artifact_id="mitm-a"),
    )
    assert json.loads(json.dumps(result.to_dict())) == result.to_dict()
