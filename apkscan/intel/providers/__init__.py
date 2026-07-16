"""被动情报 provider 子包：PR5 抽象基类 + 契约异常，及 PR6 四个具体适配器。

适配器 import-pure：模块级只有常量与类定义，无 env 读取、无 Session 构造、无网络
I/O。凭据在 `_request_spec` 内即取即用，Session 在 `__init__` 注入。适配器不接入任何
运行时（无自动发现），只在显式 `lookup_*` 调用时执行。
"""

from apkscan.intel.providers.base import IntelProvider, ProviderContractError
from apkscan.intel.providers.censys import CensysIntelProvider
from apkscan.intel.providers.fofa import FofaIntelProvider
from apkscan.intel.providers.hunter import HunterIntelProvider
from apkscan.intel.providers.shodan import ShodanIntelProvider

__all__ = [
    "CensysIntelProvider",
    "FofaIntelProvider",
    "HunterIntelProvider",
    "IntelProvider",
    "ProviderContractError",
    "ShodanIntelProvider",
]
