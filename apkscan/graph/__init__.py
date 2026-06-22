"""apkscan.graph — 本地 Kuzu 案件图谱串案地基。

把每次分析过的 APK 及其强指纹持久化进本地 Kuzu 属性图，供 Codex 跨样本串并案件。
**kuzu 懒加载**：import 本包不触发 `import kuzu`（缺失只在真正用图谱命令时报，约束 C9）。
"""

from __future__ import annotations

from apkscan.graph.ingest import ingest_batch, ingest_report
from apkscan.graph.query import (
    prune_weak,
    query_by_kind,
    query_clusters,
    query_link,
    query_stats,
)
from apkscan.graph.store import GraphStore
from apkscan.graph.weight import WEIGHT_CONFIG, get_weight, is_strong

__all__ = [
    "WEIGHT_CONFIG",
    "GraphStore",
    "get_weight",
    "ingest_batch",
    "ingest_report",
    "is_strong",
    "prune_weak",
    "query_by_kind",
    "query_clusters",
    "query_link",
    "query_stats",
]
