"""线索追踪 + 办案进度台账（混合存储的权威源）。

`apkscan.track` 包负责把每次分析产出的线索（Lead）按 APK + 线索两级落进一份
JSON 台账（默认 ``~/.apkscan/tracking.json``，仓库之外、git 永不覆盖），并支持手动
改办案进度（status/notes/history）。后续阶段在此之上挂自动入账与局域网网页。

入账/台账层的铁律：**绝不抛**（坏文件当空 + logging）、JSON 原子落盘
（临时文件 + ``os.replace``）。
"""

from __future__ import annotations

from apkscan.track.ledger import TrackingLedger

__all__ = ["TrackingLedger"]
