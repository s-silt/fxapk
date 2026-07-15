"""网络基础设施归因的解释型证据模型。"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from apkscan.network import NetworkEntity


def _clean_identifier(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{name} must not be blank")
    return stripped


def _validate_value(value: object) -> str | int | float | bool | None:
    if value is None or isinstance(value, (bool, str, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("value float must be finite")
        return value
    raise TypeError("value must be a JSON scalar")


def _validate_confidence(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("confidence must be an int or float")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("confidence must be finite")
    if not 0.0 <= result <= 1.0:
        raise ValueError("confidence must be within [0, 1]")
    return result


def _validate_timestamp(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("timestamp must be an int, float, or None")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("timestamp must be finite")
    if result < 0:
        raise ValueError("timestamp must be non-negative")
    return result


@dataclass(frozen=True, kw_only=True)
class AttributionEvidence:
    """一个以单一网络实体为目标、带置信度的可解释断言。"""

    id: str
    source: str
    type: str
    target: NetworkEntity
    value: str | int | float | bool | None
    confidence: float
    timestamp: float | None = None
    raw_reference: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _clean_identifier("id", self.id))
        object.__setattr__(self, "source", _clean_identifier("source", self.source))
        object.__setattr__(self, "type", _clean_identifier("type", self.type))
        if not isinstance(self.target, NetworkEntity):
            raise TypeError("target must be a NetworkEntity")
        object.__setattr__(self, "value", _validate_value(self.value))
        object.__setattr__(self, "confidence", _validate_confidence(self.confidence))
        object.__setattr__(self, "timestamp", _validate_timestamp(self.timestamp))
        if self.raw_reference is not None and not isinstance(self.raw_reference, str):
            raise TypeError("raw_reference must be a string or None")

    def to_dict(self) -> dict[str, Any]:
        """返回确定且可直接 JSON 序列化的公开表示。"""
        return {
            "id": self.id,
            "source": self.source,
            "type": self.type,
            "target": self.target.to_dict(),
            "value": self.value,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "raw_reference": self.raw_reference,
        }
