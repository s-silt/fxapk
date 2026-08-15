from __future__ import annotations

import math

import pytest

from apkscan.network.fingerprints import (
    normalize_authority,
    normalize_domain,
    normalize_ip,
    sanitize_absolute_url,
    sanitize_http_path,
    stable_digest,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("203.0.113.8", "203.0.113.8"),
        ("2001:0db8:0:0::8", "2001:db8::8"),
    ],
)
def test_normalize_ip(raw: str, expected: str) -> None:
    assert normalize_ip(raw) == expected


@pytest.mark.parametrize("raw", ["", " 203.0.113.8", "not-an-ip"])
def test_normalize_ip_rejects_invalid_values(raw: str) -> None:
    with pytest.raises(ValueError):
        normalize_ip(raw)


def test_normalize_domain_handles_idna_case_and_trailing_dots() -> None:
    assert normalize_domain("BÜCHER.Example..") == "xn--bcher-kva.example"


@pytest.mark.parametrize(
    "raw",
    ["", ".", "bad host.example", "bad..example", "203.0.113.8"],
)
def test_normalize_domain_rejects_non_domains(raw: str) -> None:
    with pytest.raises(ValueError):
        normalize_domain(raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("API.Example.COM:8443", ("api.example.com:8443", "api.example.com", 8443, False)),
        ("203.0.113.8", ("203.0.113.8", "203.0.113.8", None, True)),
        ("[2001:0db8::8]:443", ("[2001:db8::8]:443", "2001:db8::8", 443, True)),
    ],
)
def test_normalize_authority(raw: str, expected: tuple[str, str, int | None, bool]) -> None:
    assert normalize_authority(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "user:secret@example.com",
        "bad host",
        "example.com/path",
        "2001:db8::8",
        "example.com:0",
        "example.com:65536",
    ],
)
def test_normalize_authority_rejects_unsafe_or_ambiguous_values(raw: str) -> None:
    with pytest.raises(ValueError):
        normalize_authority(raw)


def test_sanitize_http_path_never_keeps_authority_query_or_fragment() -> None:
    assert sanitize_http_path("https://user:secret@example.com/login?token=x#part") == "/login"
    assert sanitize_http_path("config?token=x") == "/config"
    assert sanitize_http_path("") == "/"


def test_sanitize_absolute_url_normalizes_and_drops_sensitive_parts() -> None:
    assert (
        sanitize_absolute_url("HTTPS://API.Example.COM:443/login?ticket=secret#part")
        == "https://api.example.com/login"
    )
    assert (
        sanitize_absolute_url("http://[2001:0db8::8]:8080/a?x=1")
        == "http://[2001:db8::8]:8080/a"
    )


def test_stable_digest_is_canonical_namespaced_and_full_sha256() -> None:
    left = stable_digest("fact", {"b": [2, 1], "a": 1})
    right = stable_digest("fact", {"a": 1, "b": [2, 1]})
    assert left == right
    assert len(left) == 64
    assert left != stable_digest("other", {"a": 1, "b": [2, 1]})


@pytest.mark.parametrize("payload", [{"bad": {1, 2}}, {"bad": math.nan}])
def test_stable_digest_rejects_noncanonical_json(payload: object) -> None:
    with pytest.raises(ValueError):
        stable_digest("fact", payload)


def test_parse_asn_shared_contract() -> None:
    """P1：共享 ASN 解析契约（core 五层 + assemble 角色共用同一份）——返回 (asn, org_tail)，严格全匹配、绝不抛。"""
    from apkscan.network.fingerprints import parse_asn
    assert parse_asn(13335) == (13335, None)
    assert parse_asn("AS13335") == (13335, None)
    assert parse_asn("AS13335 Cloudflare, Inc.") == (13335, "Cloudflare, Inc.")
    assert parse_asn("13335 Org Ltd") == (13335, "Org Ltd")
    assert parse_asn(True) == (None, None)          # bool 是 int 子类须排除
    assert parse_asn(0) == (None, None)             # 越界(下)
    assert parse_asn(4_294_967_295) == (None, None)  # 越界(上)
    assert parse_asn("Cloudflare 13335") == (None, None)  # 绝不从中间抠数字
    assert parse_asn("garbage") == (None, None)
    assert parse_asn(None) == (None, None)
    assert parse_asn("9" * 5000) == (None, None)    # ★超长数字串按位数拒、不触 int() 4300 位限制抛


def test_network_category_shared_contract() -> None:
    """P1：网络类别规范取值单一来源——五层(core)与角色层(assemble)的类别集合都由 network.categories 构建、不漂移。"""
    from apkscan.attribution import assemble
    from apkscan.core import attribution as core
    from apkscan.network import categories as cat
    assert cat.CAT_CLOUD == "cloud" and cat.CAT_IDC == "idc" and cat.CAT_CDN == "cdn"
    # core 的 CAT_* 就是共享常量（re-export）
    assert core.CAT_CLOUD is cat.CAT_CLOUD and core.CAT_CDN is cat.CAT_CDN
    # assemble 的语义集合由共享常量构建（不再硬编码字符串）
    assert assemble._CDN_CATEGORIES == frozenset({cat.CAT_CDN})
    assert assemble._NON_PUBLIC_CDN_HOSTING == frozenset({cat.CAT_CLOUD, cat.CAT_IDC})
