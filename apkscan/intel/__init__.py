"""PR5 被动情报 provider 接口的公开导出。

复用既有 apkscan.attribution / apkscan.network 类型；本包只定义 PR5 契约的
值对象与抽象基类，不含任何真实 provider、网络 I/O、缓存或报告接线。
"""

from apkscan.intel.models import (
    CAPABILITY_ENTITY_KIND,
    IntelCapability,
    IntelResult,
    IntelStatus,
    ProviderContractError,
    validate_certificate_value,
)
from apkscan.intel.providers import IntelProvider

__all__ = [
    "CAPABILITY_ENTITY_KIND",
    "IntelCapability",
    "IntelProvider",
    "IntelResult",
    "IntelStatus",
    "ProviderContractError",
    "validate_certificate_value",
]
