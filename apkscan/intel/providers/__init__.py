"""PR5 被动情报 provider 子包：抽象基类 IntelProvider 与契约异常。"""

from apkscan.intel.providers.base import IntelProvider, ProviderContractError

__all__ = [
    "IntelProvider",
    "ProviderContractError",
]
