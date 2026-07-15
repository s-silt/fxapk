"""统一网络事实模型。"""

from apkscan.network.entities import (
    JSONScalar,
    JSONValue,
    NetworkEntity,
    NetworkEntityType,
)
from apkscan.network.observations import Observation

__all__ = [
    "JSONScalar",
    "JSONValue",
    "NetworkEntity",
    "NetworkEntityType",
    "Observation",
]
