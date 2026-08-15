from __future__ import annotations

from apkscan.core.attribution import build_domain_control
from apkscan.core.closure.sources import _set_attribution
from apkscan.core.models import Endpoint


def _enrichment() -> dict:
    return {
        "rdap": {
            "registrar": "Example Registrar",
            "nameservers": ["VIP8.ALIDNS.COM.", "vip7.alidns.com"],  # leak-scan: allow 公共DNS产品测试夹具
            "source": "rdap",
        },
        "dns": {
            "cname": ["route.example.test", "origin.example.test"],
        },
    }


def test_paid_alidns_nameservers_identify_product_not_account_or_jurisdiction() -> None:
    control = build_domain_control("managed.example.test", _enrichment())

    assert control["registrar"] == {
        "name": "Example Registrar", "source": "rdap", "confidence": "reported"
    }
    assert control["authoritative_dns"]["provider"] == "Alibaba Cloud DNS"
    assert control["authoritative_dns"]["product"] == "Public Authoritative DNS / Public Zone"
    assert control["authoritative_dns"]["service_tier"] == "paid"
    assert control["authoritative_dns"]["nameservers"] == [
        "vip7.alidns.com", "vip8.alidns.com"  # leak-scan: allow 公共DNS产品测试夹具
    ]
    assert control["authoritative_dns"]["jurisdiction"] == "unknown"
    assert control["zone_account"]["status"] == "unknown"
    assert control["record_operator"]["status"] == "unknown"
    assert control["limitations"] == [
        "shared_or_anycast_nameserver_does_not_identify_tenant_or_operator"
    ]


def test_domain_control_is_wired_even_when_server_attribution_has_no_ip() -> None:
    endpoint = Endpoint(value="managed.example.test", kind="domain", enrichment=_enrichment())

    _set_attribution(endpoint)

    assert endpoint.enrichment["domain_control"]["managed_zone"] == "managed.example.test"
    assert "attribution" not in endpoint.enrichment, "没有解析 IP 时不得伪造服务器五层归因"
