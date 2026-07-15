"""统一网络观测模型测试。"""

from __future__ import annotations

import dataclasses
import json

import pytest

from apkscan.network import NetworkEntity, NetworkEntityType, Observation


def _entity(value: str = "1.2.3.4") -> NetworkEntity:
    return NetworkEntity(NetworkEntityType.IP, value, sources=["pcap"])


def _observation(**overrides: object) -> Observation:
    values: dict[str, object] = {
        "id": "obs-1",
        "source": "pcap",
        "type": "network_connection",
        "entities": [_entity()],
    }
    values.update(overrides)
    return Observation(**values)  # type: ignore[arg-type]


def test_observation_normalizes_fact_and_defaults() -> None:
    entity = _entity()
    observation = _observation(
        id=" obs-1 ",
        source=" tshark ",
        type=" flow ",
        entities=[entity],
        timestamp=123,
    )
    assert (observation.id, observation.source, observation.type) == (
        "obs-1",
        "tshark",
        "flow",
    )
    assert observation.entities == (entity,)
    assert observation.attributes == {}
    assert observation.timestamp == 123.0
    assert observation.raw_reference is None


def test_observation_is_keyword_only_and_frozen() -> None:
    with pytest.raises(TypeError):
        Observation("o", "s", "t", (_entity(),))  # type: ignore[misc]
    observation = _observation()
    with pytest.raises(dataclasses.FrozenInstanceError):
        observation.id = "changed"  # type: ignore[misc]


def test_entity_order_is_preserved() -> None:
    first = _entity("1.1.1.1")
    second = _entity("2.2.2.2")
    assert _observation(entities=[second, first]).entities == (second, first)


def test_attributes_are_deep_copied_from_caller() -> None:
    original = {"nested": {"items": [1, 2]}}
    observation = _observation(attributes=original)
    original["nested"]["items"].append(3)  # type: ignore[index,union-attr]
    original["added"] = True
    assert observation.attributes == {"nested": {"items": [1, 2]}}


def test_to_dict_is_deterministic_json() -> None:
    first = _observation(
        attributes={"z": 1, "a": {"y": 2, "x": 1}, "items": [3, 1, 2]},
        timestamp=1,
        raw_reference="capture.pcap#frame=9",
    )
    second = _observation(
        attributes={"items": [3, 1, 2], "a": {"x": 1, "y": 2}, "z": 1},
        timestamp=1.0,
        raw_reference="capture.pcap#frame=9",
    )
    payload = first.to_dict()
    assert list(payload["attributes"]) == ["a", "items", "z"]
    assert list(payload["attributes"]["a"]) == ["x", "y"]  # type: ignore[index]
    assert payload["entities"] == [_entity().to_dict()]
    assert json.dumps(payload) == json.dumps(second.to_dict())


def test_observation_has_no_confidence_and_is_unhashable() -> None:
    observation = _observation()
    assert not hasattr(observation, "confidence")
    with pytest.raises(TypeError):
        hash(observation)


@pytest.mark.parametrize("field", ["id", "source", "type"])
@pytest.mark.parametrize("bad", ["", "   ", None, 1])
def test_invalid_identifier_rejected(field: str, bad: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        _observation(**{field: bad})


@pytest.mark.parametrize("bad", [[], [object()], ["1.2.3.4"], None])
def test_invalid_entities_rejected(bad: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        _observation(entities=bad)


@pytest.mark.parametrize(
    "bad",
    [
        [],
        {1: "non-string-key"},
        {"value": (1, 2)},
        {"value": {1, 2}},
        {"value": b"bytes"},
        {"value": object()},
        {"value": float("nan")},
        {"value": float("inf")},
        {"value": [float("-inf")]},
    ],
)
def test_invalid_attributes_rejected(bad: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        _observation(attributes=bad)


@pytest.mark.parametrize(
    "bad",
    [True, False, -1, float("nan"), float("inf"), float("-inf"), "1", object()],
)
def test_invalid_timestamp_rejected(bad: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        _observation(timestamp=bad)


def test_invalid_observation_raw_reference_rejected() -> None:
    with pytest.raises(TypeError):
        _observation(raw_reference=123)
