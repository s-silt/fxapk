"""不可变且可验证的网络观测事实。"""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from apkscan.network.entities import JSONValue, NetworkEntity


def _normalize_identifier(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{name} must not be blank")
    return stripped


def _normalize_entities(value: object) -> tuple[NetworkEntity, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError("entities must be a non-string iterable of NetworkEntity")
    entities = tuple(value)
    if not entities:
        raise ValueError("entities must contain at least one NetworkEntity")
    for entity in entities:
        if not isinstance(entity, NetworkEntity):
            raise TypeError(
                f"entities must all be NetworkEntity, got {type(entity).__name__}"
            )
    return entities


def _normalize_json_value(value: object) -> JSONValue:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("attribute float values must be finite")
        return value
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, dict):
        return _normalize_json_dict(value)
    if isinstance(value, list):
        return [_normalize_json_value(item) for item in value]
    raise TypeError(f"unsupported attribute value type: {type(value).__name__}")


def _normalize_json_dict(value: object) -> dict[str, JSONValue]:
    if not isinstance(value, dict):
        raise TypeError(f"attributes must be a dict, got {type(value).__name__}")
    result: dict[str, JSONValue] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise TypeError(f"attribute keys must be strings, got {type(key).__name__}")
        result[key] = _normalize_json_value(item)
    return result


def _normalize_timestamp(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("timestamp must be an int or float")
    if not math.isfinite(value):
        raise ValueError("timestamp must be finite")
    if value < 0:
        raise ValueError("timestamp must be non-negative")
    return float(value)


def _normalize_raw_reference(value: object) -> str | None:
    if value is None or isinstance(value, str):
        return value
    raise TypeError(f"raw_reference must be a string or None, got {type(value).__name__}")


def _sorted_json(value: JSONValue) -> JSONValue:
    if isinstance(value, dict):
        return {key: _sorted_json(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_sorted_json(item) for item in value]
    return value


@dataclass(frozen=True, kw_only=True)
class Observation:
    """一个数据源产生的规范化事实，不包含推理置信度。

    dataclass 冻结字段绑定；``attributes`` 在构造时递归复制，调用方仍应将公开映射
    视为只读。``to_dict`` 总是返回新的 JSON 容器，避免序列化消费者反向修改观测。
    """

    id: str
    source: str
    type: str
    entities: tuple[NetworkEntity, ...]
    attributes: dict[str, JSONValue] = field(default_factory=dict)
    timestamp: float | None = None
    raw_reference: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _normalize_identifier("id", self.id))
        object.__setattr__(self, "source", _normalize_identifier("source", self.source))
        object.__setattr__(self, "type", _normalize_identifier("type", self.type))
        object.__setattr__(self, "entities", _normalize_entities(self.entities))
        object.__setattr__(self, "attributes", _normalize_json_dict(self.attributes))
        object.__setattr__(self, "timestamp", _normalize_timestamp(self.timestamp))
        object.__setattr__(
            self,
            "raw_reference",
            _normalize_raw_reference(self.raw_reference),
        )

    def to_dict(self) -> dict[str, Any]:
        """返回确定且可直接 JSON 序列化的公开表示。"""
        return {
            "id": self.id,
            "source": self.source,
            "type": self.type,
            "entities": [entity.to_dict() for entity in self.entities],
            "attributes": _sorted_json(self.attributes),
            "timestamp": self.timestamp,
            "raw_reference": self.raw_reference,
        }
