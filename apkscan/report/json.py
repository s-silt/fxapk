"""apkscan.report.json — 把 Report 序列化为 JSON。

dataclass → dict（dataclasses.asdict），Enum → .value，写 UTF-8 JSON
（ensure_ascii=False, indent=2）。
"""

from __future__ import annotations

import dataclasses
import json
import logging
from enum import Enum
from pathlib import Path
from typing import Any

from apkscan.core.models import Lead, Report

logger = logging.getLogger(__name__)


def _to_jsonable(obj: Any) -> Any:
    """递归把任意对象转成可 JSON 序列化的结构。

    - Enum → .value
    - dataclass → dict（逐字段递归）
    - dict / list / tuple / set → 逐元素递归
    - 其它原样返回（基础类型）；不可序列化的兜底为 str()。
    """
    if isinstance(obj, Enum):
        return obj.value
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        d = {f.name: _to_jsonable(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
        # Lead 的派生标注（C2 / 实连）也落 JSON，便于下游程序化筛选「诈骗后端服务器」。
        if isinstance(obj, Lead):
            d["is_c2"] = obj.is_c2
            d["is_runtime_seen"] = obj.is_runtime_seen
        return d
    if isinstance(obj, dict):
        return {str(_to_jsonable(k)): _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_to_jsonable(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, (bytes, bytearray)):
        return obj.decode("utf-8", errors="replace")
    # 兜底：出现预期外类型被强制 str 化（可能是数据本应结构化却类型异常）。
    # 记一条 warning 让"无声降级"可追，而非静默掩盖。
    logger.warning("JSON 序列化遇到预期外类型，降级为 str：%s", type(obj).__name__)
    return str(obj)


def to_dict(report: Report) -> dict[str, Any]:
    """把 Report 转成纯 dict（Enum 已转为 value），便于序列化或测试断言。"""
    return _to_jsonable(report)


def dump(report: Report, path: str) -> None:
    """把 Report 写成 UTF-8 JSON 文件（ensure_ascii=False, indent=2）。"""
    payload = to_dict(report)
    out_path = Path(path)
    if out_path.parent and not out_path.parent.exists():
        out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
