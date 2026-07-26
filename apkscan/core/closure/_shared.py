"""closure 共享底座：闭环状态常量、运行配置 ``ClosureConfig`` 与极小工具 ``_mapping``。

为什么单独成模块：targets/layers/sources/gates 四个子模块都要用这些名字，而硬约束是
「子模块不得反向 import closure 包本身」。把公共常量与配置放进无任何包内依赖的底座模块，
其余子模块只做单向 ``from ._shared import``，从结构上杜绝循环导入。
（对外仍从 ``apkscan.core.closure`` 取用——包 ``__init__`` 全量 re-export。）
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from apkscan.core.models import (
    ANALYSIS_MODE_PASSIVE,
    ANALYSIS_MODES,
)

CLOSURE_COMPLETE = "complete"
CLOSURE_PARTIAL = "partial"
CLOSURE_FAILED = "failed"

SOURCE_STATUSES = frozenset({"hit", "no_record", "failed", "skipped", "disabled"})
LAYER_NAMES = (
    "runtime_evidence",
    "resource_registration",
    "bgp_announcement",
    "hosting_delivery",
    "request_target",
)


@dataclass(frozen=True)
class ClosureConfig:
    online: bool = True
    mode: str = ANALYSIS_MODE_PASSIVE
    max_targets: int = 6
    refresh: bool = False
    require_dynamic: bool | None = None

    def __post_init__(self) -> None:
        if self.mode not in ANALYSIS_MODES:
            raise ValueError(f"unsupported analysis mode: {self.mode}")
        if self.max_targets <= 0:
            raise ValueError("max_targets must be greater than zero")


def _mapping(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}
