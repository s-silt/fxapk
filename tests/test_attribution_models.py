"""归因证据模型测试。"""

from __future__ import annotations

import dataclasses
import json

import pytest

from apkscan.attribution import AttributionEvidence
from apkscan.core.models import Evidence as CoreEvidence
from apkscan.network import NetworkEntity, NetworkEntityType


def _target() -> NetworkEntity:
    return NetworkEntity(NetworkEntityType.DOMAIN, "api.example.com", sources=["pcap"])


def _evidence(**overrides: object) -> AttributionEvidence:
    values: dict[str, object] = {
        "id": "ev-1",
        "source": "pcap",
        "type": "network_connection",
        "target": _target(),
        "value": "direct business connection",
        "confidence": 0.8,
    }
    values.update(overrides)
    return AttributionEvidence(**values)  # type: ignore[arg-type]


def test_evidence_normalizes_fields_and_defaults() -> None:
    evidence = _evidence(id=" ev-1 ", source=" tshark ", type=" flow ", confidence=1)
    assert (evidence.id, evidence.source, evidence.type) == ("ev-1", "tshark", "flow")
    assert evidence.confidence == 1.0
    assert evidence.timestamp is None
    assert evidence.raw_reference is None


@pytest.mark.parametrize("value", ["text", 1, 1.5, True, False, None])
def test_evidence_accepts_json_scalar_values(value: object) -> None:
    assert _evidence(value=value).value == value


def test_to_dict_is_json_safe_and_complete() -> None:
    evidence = _evidence(timestamp=123, raw_reference="capture.pcap#frame=9")
    payload = evidence.to_dict()
    assert payload == {
        "id": "ev-1",
        "source": "pcap",
        "type": "network_connection",
        "target": _target().to_dict(),
        "value": "direct business connection",
        "confidence": 0.8,
        "timestamp": 123.0,
        "raw_reference": "capture.pcap#frame=9",
    }
    assert json.loads(json.dumps(payload)) == payload


def test_evidence_is_keyword_only_frozen_and_hashable() -> None:
    with pytest.raises(TypeError):
        AttributionEvidence("e", "s", "t", _target(), "v", 1)  # type: ignore[misc]
    evidence = _evidence()
    with pytest.raises(dataclasses.FrozenInstanceError):
        evidence.id = "changed"  # type: ignore[misc]
    assert isinstance(hash(evidence), int)


def test_attribution_evidence_is_distinct_from_core_evidence() -> None:
    assert CoreEvidence is not AttributionEvidence


@pytest.mark.parametrize("field", ["id", "source", "type"])
@pytest.mark.parametrize("bad", ["", "   ", None, 1])
def test_invalid_evidence_identifier_rejected(field: str, bad: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        _evidence(**{field: bad})


@pytest.mark.parametrize("bad", ["api.example.com", 1, None, object()])
def test_invalid_target_rejected(bad: object) -> None:
    with pytest.raises(TypeError):
        _evidence(target=bad)


@pytest.mark.parametrize(
    "bad",
    [[1], {"a": 1}, (1,), {1}, b"bytes", object(), float("nan"), float("inf")],
)
def test_invalid_evidence_value_rejected(bad: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        _evidence(value=bad)


@pytest.mark.parametrize(
    "bad",
    [True, False, -0.1, 1.1, float("nan"), float("inf"), "0.5", None, object()],
)
def test_invalid_confidence_rejected(bad: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        _evidence(confidence=bad)


@pytest.mark.parametrize(
    "bad",
    [True, False, -1, float("nan"), float("inf"), float("-inf"), "1", object()],
)
def test_invalid_evidence_timestamp_rejected(bad: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        _evidence(timestamp=bad)


def test_invalid_evidence_raw_reference_rejected() -> None:
    with pytest.raises(TypeError):
        _evidence(raw_reference=123)
