"""网络基础设施实体的稳定值对象。"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypeAlias

JSONScalar: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]


class NetworkEntityType(str, Enum):
    """归因引擎支持的网络实体类型。"""

    DOMAIN = "DOMAIN"
    IP = "IP"
    CERTIFICATE = "CERTIFICATE"
    ASN = "ASN"
    URL = "URL"
    HOST = "HOST"
    PROVIDER = "PROVIDER"
    NETWORK_CLUSTER = "NETWORK_CLUSTER"


@dataclass(frozen=True)
class NetworkEntity:
    """由类型和值确定身份的不可变网络实体。"""

    kind: NetworkEntityType
    value: str
    sources: tuple[str, ...] = field(default=(), compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", self._coerce_kind(self.kind))
        object.__setattr__(self, "value", self._coerce_value(self.value))
        object.__setattr__(self, "sources", self._coerce_sources(self.sources))

    @staticmethod
    def _coerce_kind(kind: object) -> NetworkEntityType:
        if isinstance(kind, NetworkEntityType):
            return kind
        if isinstance(kind, str):
            try:
                return NetworkEntityType(kind)
            except ValueError as exc:
                raise ValueError(f"invalid network entity kind: {kind!r}") from exc
        raise TypeError(f"kind must be NetworkEntityType or str, got {type(kind).__name__}")

    @staticmethod
    def _coerce_value(value: object) -> str:
        if not isinstance(value, str):
            raise TypeError(f"value must be str, got {type(value).__name__}")
        stripped = value.strip()
        if not stripped:
            raise ValueError("value must not be blank")
        return stripped

    @staticmethod
    def _coerce_sources(sources: object) -> tuple[str, ...]:
        if isinstance(sources, str) or not isinstance(sources, Iterable):
            raise TypeError("sources must be an iterable of str")
        cleaned: set[str] = set()
        for source in sources:
            if not isinstance(source, str):
                raise TypeError(f"sources must contain str, got {type(source).__name__}")
            stripped = source.strip()
            if stripped:
                cleaned.add(stripped)
        return tuple(sorted(cleaned))

    def to_dict(self) -> dict[str, Any]:
        """返回确定且可直接 JSON 序列化的公开表示。"""
        return {
            "type": self.kind.value,
            "value": self.value,
            "sources": list(self.sources),
        }
