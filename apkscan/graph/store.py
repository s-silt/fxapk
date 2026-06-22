"""Kuzu 案件图谱存储层。

铁律：
- **kuzu 懒加载**——import 本模块不触发 `import kuzu`；只有真正打开 DB（首次 execute）时才
  导入。kuzu 缺失 → 抛 ImportError 给上层统一处理（CLI 提示安装 / batch info 跳过），
  绝不在 import 期拖垮其它命令（约束 C9）。
- **单写者**（约束 C10）：所有 execute 经同一 `threading.Lock` 守护、同一连接。
- **连接生命周期**：用完必 `close()`（conn.close() + db.close()），否则残留连接锁库。
  支持上下文管理器。

实测 kuzu 0.11.3 API（实施依据）：`kuzu.Database(str_path)` + `kuzu.Connection(db)`；
参数占位符 `$name`、以 dict 传；`conn.execute()` 返回 QueryResult，取数 `.get_all()`，
转 dict `.rows_as_dict().get_all()`（键为列名/别名）。
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from apkscan.graph.schema import ensure_schema

logger = logging.getLogger(__name__)

# 单命令场景默认 DB（相对 cwd）；批量场景由调用方显式锚定 <out_dir>/.apkscan_cache/cases.kuzu。
_DEFAULT_DB = Path(".apkscan_cache") / "cases.kuzu"


def _now() -> str:
    """ISO8601 UTC 时间戳（first_seen / last_seen / analyzed_at）。"""
    return datetime.now(timezone.utc).isoformat()


class GraphStore:
    """本地 Kuzu 案件图谱的薄封装（懒打开、单写者、幂等 upsert）。"""

    def __init__(self, db_path: str | Path = "") -> None:
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB
        self._db: Any = None
        self._conn: Any = None
        self._lock = threading.Lock()

    # ---- 生命周期 ---------------------------------------------------------
    def _ensure_open(self) -> Any:
        """懒打开连接 + 建 schema。kuzu 缺失 → ImportError 上抛（不在此吞）。"""
        if self._conn is not None:
            return self._conn
        import kuzu  # 懒加载：缺失只在真正用图谱时报

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = kuzu.Database(str(self.db_path))
        self._conn = kuzu.Connection(self._db)
        ensure_schema(self._conn)
        return self._conn

    def ensure_ready(self) -> None:
        """显式打开连接（建库 + schema）。kuzu 缺失 → ImportError 上抛（不在此吞）。

        供 CLI 在调用 never-throw 的 delete_entity/unlink/prune_weak **之前**探活：
        那些方法自身吞 ImportError 返 0，CLI 需要先探活才能给出统一的「装 kuzu」提示。
        """
        with self._lock:
            self._ensure_open()

    def close(self) -> None:
        """关闭连接与 DB（绝不抛）。重复 close 安全。"""
        with self._lock:
            for name in ("_conn", "_db"):
                obj = getattr(self, name)
                if obj is None:
                    continue
                try:
                    obj.close()
                except Exception:
                    logger.warning("[graph] 关闭 %s 失败（已忽略）", name, exc_info=True)
                setattr(self, name, None)

    def __enter__(self) -> GraphStore:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ---- 执行 -------------------------------------------------------------
    def execute(self, query: str, params: dict | None = None) -> Any:
        """单写者锁守护下执行一条 Cypher，返回 QueryResult。"""
        with self._lock:
            conn = self._ensure_open()
            return conn.execute(query, params or {})

    def query_rows(self, query: str, params: dict | None = None) -> list[dict]:
        """执行并把结果转成 list[dict]（键为 RETURN 的列名/别名）。"""
        res = self.execute(query, params)
        try:
            return list(res.rows_as_dict().get_all())
        except Exception:  # noqa: BLE001 - 兜底：极端情况下手拼列名（0.11.3 正常有 rows_as_dict）
            cols = res.get_column_names()
            return [dict(zip(cols, row, strict=False)) for row in res.get_all()]

    def query_cypher(self, query: str) -> list[dict]:
        """原始 Cypher 逃生口（仅供只读探查；经同一连接/锁，不绕过 C10）。"""
        return self.query_rows(query)

    # ---- upsert（幂等 MERGE） --------------------------------------------
    def upsert_apk(
        self,
        sha256: str,
        *,
        package: str = "",
        label: str = "",
        sign_sha256: str = "",
        sign_subject: str = "",
        report_path: str = "",
    ) -> None:
        """upsert 一个 Apk 节点（同 sha256 重摄只更新、不产重复，约束 §5.3）。"""
        self.execute(
            "MERGE (a:Apk {sha256: $sha256}) "
            "SET a.package=$package, a.label=$label, a.analyzed_at=$now, "
            "a.report_path=$report_path, a.sign_sha256=$sign_sha256, a.sign_subject=$sign_subject",
            {
                "sha256": sha256,
                "package": package,
                "label": label,
                "now": _now(),
                "report_path": report_path,
                "sign_sha256": sign_sha256,
                "sign_subject": sign_subject,
            },
        )

    def upsert_entity(self, kind: str, value: str) -> str:
        """upsert 一个 Entity 节点，返回 entity id（"{kind}:{value}"）。

        first_seen 仅在新建时写、last_seen 每次更新；weight 取自 weight.py。
        """
        from apkscan.graph.weight import get_weight

        eid = f"{kind}:{value}"
        now = _now()
        self.execute(
            "MERGE (e:Entity {id: $id}) "
            "ON CREATE SET e.kind=$kind, e.value=$value, e.first_seen=$now, "
            "e.last_seen=$now, e.weight=$weight "
            "ON MATCH SET e.last_seen=$now, e.weight=$weight",
            {"id": eid, "kind": kind, "value": value, "now": now, "weight": get_weight(kind)},
        )
        return eid

    def link(self, apk_sha256: str, entity_kind: str, entity_value: str, weight: float = 1.0) -> None:
        """连一条 (Apk)-[:OBSERVED]->(Entity) 边（同对二次 MERGE 不产重复，约束 §5.3）。"""
        eid = f"{entity_kind}:{entity_value}"
        self.execute(
            "MATCH (a:Apk {sha256: $sha256}), (e:Entity {id: $eid}) "
            "MERGE (a)-[r:OBSERVED]->(e) SET r.weight=$weight",
            {"sha256": apk_sha256, "eid": eid, "weight": weight},
        )

    # ---- 删除（参数化防注入；绝不抛——失败 log 返 0） ----------------------
    def delete_entity(self, kind: str, value: str) -> int:
        """全局删除一个实体及其所有 OBSERVED 边。返回删除的实体数（0/1）。

        Kuzu 删除语义：先删边、再删节点（不依赖 DETACH DELETE 是否受支持）。
        value 来自样本/人工输入不可信 → 全经 query_rows(params=) 参数化（约束 C：防 Cypher 注入）。
        kuzu 缺失 / 查询异常一律 log + 返 0，绝不抛、不连累线索面板与主流程。
        """
        eid = f"{kind}:{value}"
        try:
            # 无 RETURN 的 DELETE 走 execute（不取行）；仅 COUNT 用 query_rows。
            self.execute(
                "MATCH (:Apk)-[r:OBSERVED]->(e:Entity {id: $id}) DELETE r",
                {"id": eid},
            )
            rows = self.query_rows(
                "MATCH (e:Entity {id: $id}) RETURN COUNT(e) AS c",
                {"id": eid},
            )
            n = int(rows[0]["c"]) if rows else 0
            self.execute(
                "MATCH (e:Entity {id: $id}) DELETE e",
                {"id": eid},
            )
            return n
        except Exception:
            logger.warning("[graph] delete_entity 失败（已隔离返 0）：%s", eid, exc_info=True)
            return 0

    def unlink(self, apk_sha256: str, kind: str, value: str) -> int:
        """只断这一条 (Apk)-[:OBSERVED]->(Entity) 边（不动节点）。返回删除的边数。

        全经参数化查询防注入；kuzu 缺失 / 查询异常一律 log + 返 0，绝不抛。
        """
        eid = f"{kind}:{value}"
        try:
            rows = self.query_rows(
                "MATCH (a:Apk {sha256: $sha})-[r:OBSERVED]->(e:Entity {id: $id}) RETURN COUNT(r) AS c",
                {"sha": apk_sha256, "id": eid},
            )
            n = int(rows[0]["c"]) if rows else 0
            self.execute(
                "MATCH (a:Apk {sha256: $sha})-[r:OBSERVED]->(e:Entity {id: $id}) DELETE r",
                {"sha": apk_sha256, "id": eid},
            )
            return n
        except Exception:
            logger.warning(
                "[graph] unlink 失败（已隔离返 0）：%s -> %s", apk_sha256, eid, exc_info=True
            )
            return 0
