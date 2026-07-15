"""统一网络实体模型测试。"""

from __future__ import annotations

import dataclasses
import json

import pytest

from apkscan.network import NetworkEntity, NetworkEntityType


EXPECTED_TYPES = {
    "DOMAIN",
    "IP",
    "CERTIFICATE",
    "ASN",
    "URL",
    "HOST",
    "PROVIDER",
    "NETWORK_CLUSTER",
}


def test_entity_type_values_are_stable_strings() -> None:
    assert issubclass(NetworkEntityType, str)
    assert {member.value for member in NetworkEntityType} == EXPECTED_TYPES


@pytest.mark.parametrize("member", list(NetworkEntityType))
def test_kind_accepts_enum_and_exact_value(member: NetworkEntityType) -> None:
    assert NetworkEntity(member, "example").kind is member
    assert NetworkEntity(member.value, "example").kind is member


def test_value_and_sources_are_normalized() -> None:
    entity = NetworkEntity(
        NetworkEntityType.IP,
        " 1.2.3.4 ",
        sources=[" fofa ", "vt", "fofa", "", "   ", "otx"],
    )
    assert entity.value == "1.2.3.4"
    assert entity.sources == ("fofa", "otx", "vt")


def test_sources_accept_iterable_and_default_to_tuple() -> None:
    defaulted = NetworkEntity(NetworkEntityType.DOMAIN, "example.com")
    generated = NetworkEntity(
        NetworkEntityType.DOMAIN,
        "example.com",
        sources=(source for source in ("b", "a", "a")),
    )
    assert defaulted.sources == ()
    assert generated.sources == ("a", "b")


def test_sources_do_not_change_entity_identity() -> None:
    left = NetworkEntity(NetworkEntityType.IP, "1.2.3.4", sources=["fofa"])
    right = NetworkEntity(NetworkEntityType.IP, "1.2.3.4", sources=["vt"])
    assert left == right
    assert hash(left) == hash(right)
    assert len({left, right}) == 1


def test_kind_or_value_changes_entity_identity() -> None:
    base = NetworkEntity(NetworkEntityType.IP, "1.2.3.4")
    assert base != NetworkEntity(NetworkEntityType.IP, "5.6.7.8")
    assert base != NetworkEntity(NetworkEntityType.HOST, "1.2.3.4")


def test_entity_is_frozen() -> None:
    entity = NetworkEntity(NetworkEntityType.IP, "1.2.3.4")
    with pytest.raises(dataclasses.FrozenInstanceError):
        entity.value = "9.9.9.9"  # type: ignore[misc]


def test_to_dict_is_json_safe_and_uses_public_schema() -> None:
    entity = NetworkEntity(NetworkEntityType.URL, "https://x/", sources=["vt", "fofa"])
    payload = entity.to_dict()
    assert payload == {
        "type": "URL",
        "value": "https://x/",
        "sources": ["fofa", "vt"],
    }
    assert json.loads(json.dumps(payload)) == payload


@pytest.mark.parametrize("bad_kind", ["not_a_type", "Domain "])
def test_invalid_kind_value_rejected(bad_kind: str) -> None:
    with pytest.raises(ValueError):
        NetworkEntity(bad_kind, "example")


@pytest.mark.parametrize("bad_kind", [123, None, object()])
def test_invalid_kind_type_rejected(bad_kind: object) -> None:
    with pytest.raises(TypeError):
        NetworkEntity(bad_kind, "example")  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_value", [123, None, b"bytes", ["x"]])
def test_invalid_entity_value_type_rejected(bad_value: object) -> None:
    with pytest.raises(TypeError):
        NetworkEntity(NetworkEntityType.IP, bad_value)  # type: ignore[arg-type]


@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
def test_blank_entity_value_rejected(blank: str) -> None:
    with pytest.raises(ValueError):
        NetworkEntity(NetworkEntityType.IP, blank)


@pytest.mark.parametrize("bad_source", [123, None, b"x", ["nested"]])
def test_invalid_source_type_rejected(bad_source: object) -> None:
    with pytest.raises(TypeError):
        NetworkEntity(
            NetworkEntityType.IP,
            "1.2.3.4",
            sources=[bad_source],  # type: ignore[list-item]
        )


@pytest.mark.parametrize("bad_sources", ["fofa", 123, None])
def test_invalid_sources_collection_rejected(bad_sources: object) -> None:
    with pytest.raises(TypeError):
        NetworkEntity(
            NetworkEntityType.IP,
            "1.2.3.4",
            sources=bad_sources,  # type: ignore[arg-type]
        )
