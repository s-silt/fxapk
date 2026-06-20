"""Kuzu 案件图谱 schema（通用 Entity 属性图）。

数据模型（约束 C7：通用 Entity 而非每 kind 一表，A 期新 kind 零 DDL 迁移）：
- 节点 Apk(sha256 PK, package, label, analyzed_at, report_path, sign_sha256, sign_subject)
- 节点 Entity(id="{kind}:{value}" PK, kind, value, first_seen, last_seen, weight)
- 边 OBSERVED (Apk)-[:OBSERVED {weight}]->(Entity)

串案语义：两 Apk 共享 ≥1 Entity 即关联；团伙簇 = Apk-Entity-Apk 连通分量。
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# 幂等 DDL（实测 kuzu 0.11.3 IF NOT EXISTS 重跑不抛；ensure_schema 仍 try/except 兜底）。
SCHEMA_STATEMENTS: tuple[str, ...] = (
    """
    CREATE NODE TABLE IF NOT EXISTS Apk(
        sha256 STRING,
        package STRING,
        label STRING,
        analyzed_at STRING,
        report_path STRING,
        sign_sha256 STRING,
        sign_subject STRING,
        PRIMARY KEY (sha256)
    )
    """,
    """
    CREATE NODE TABLE IF NOT EXISTS Entity(
        id STRING,
        kind STRING,
        value STRING,
        first_seen STRING,
        last_seen STRING,
        weight DOUBLE,
        PRIMARY KEY (id)
    )
    """,
    """
    CREATE REL TABLE IF NOT EXISTS OBSERVED(
        FROM Apk TO Entity,
        weight DOUBLE
    )
    """,
)


def ensure_schema(conn: Any) -> None:
    """在连接上建表（幂等）。每条 DDL 单独 try/except：

    `IF NOT EXISTS` 已实测幂等，正常不抛；此处兜底「已存在」类异常——log 后吞掉、不重抛
    （非静默：debug 级可追）。conn 为 kuzu.Connection。
    """
    for stmt in SCHEMA_STATEMENTS:
        try:
            conn.execute(stmt)
        except Exception as exc:  # noqa: BLE001 - 防御性兜底「表已存在」，记 debug 不重抛
            logger.debug("[graph] schema DDL 跳过（疑似已存在）：%s", exc)
