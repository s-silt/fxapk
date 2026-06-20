"""案件图谱查询：link（按 sha256 邻接）/ query（按实体反查）/ cluster（团伙簇）/ stats。

所有函数返回纯 dict / list（JSON-ready，键 snake_case），供 CLI 直接 json.dumps 给 Codex。
排名与置信分依据 weight.py。
"""

from __future__ import annotations

from collections import Counter, defaultdict

from apkscan.graph.store import GraphStore
from apkscan.graph.weight import get_weight, is_strong

# 置信分归一化常数：confidence = score / (score + K)，单调、落 (0,1)。
# 契约：同一次查询内单调可比、可用于簇间排序；绝对值不稳定、不跨查询/版本承诺（见 spec §7.2）。
_CONF_K = 10.0


def query_stats(store: GraphStore) -> dict:
    """图谱体检：apk / entity / edge 计数 + 按 kind 分布。"""
    apk = store.query_rows("MATCH (a:Apk) RETURN COUNT(a) AS c")
    apk_count = int(apk[0]["c"]) if apk else 0
    edge = store.query_rows("MATCH (:Apk)-[r:OBSERVED]->(:Entity) RETURN COUNT(r) AS c")
    edge_count = int(edge[0]["c"]) if edge else 0
    kinds = store.query_rows("MATCH (e:Entity) RETURN e.kind AS kind")
    by_kind = Counter(str(r.get("kind") or "?") for r in kinds)
    return {
        "apk_count": apk_count,
        "entity_count": sum(by_kind.values()),
        "edge_count": edge_count,
        "entities_by_kind": dict(by_kind),
        "db": str(store.db_path),
    }


def query_link(store: GraphStore, sha256: str) -> dict:
    """拉出与指定 APK 共享强实体的关联 APK，按强实体权重和降序。"""
    apk = store.query_rows(
        "MATCH (a:Apk {sha256: $s}) RETURN a.sha256 AS sha256, a.package AS package, a.label AS label",
        {"s": sha256},
    )
    rows = store.query_rows(
        "MATCH (a1:Apk {sha256: $s})-[:OBSERVED]->(e:Entity)<-[:OBSERVED]-(a2:Apk) "
        "WHERE a2.sha256 <> a1.sha256 "
        "RETURN a2.sha256 AS sha256, a2.package AS package, "
        "e.kind AS kind, e.value AS value, e.weight AS weight",
        {"s": sha256},
    )
    grouped: dict[str, dict] = {}
    for r in rows:
        other = str(r.get("sha256") or "")
        g = grouped.setdefault(
            other,
            {
                "sha256": other,
                "package": str(r.get("package") or ""),
                "shared_entities": [],
                "strong_shared_count": 0,
                "strong_weight_sum": 0.0,
            },
        )
        kind = str(r.get("kind") or "")
        g["shared_entities"].append(
            {"kind": kind, "value": str(r.get("value") or ""), "weight": float(r.get("weight") or 0.0)}
        )
        if is_strong(kind):
            g["strong_shared_count"] += 1
            g["strong_weight_sum"] += float(r.get("weight") or 0.0)
    related = sorted(
        grouped.values(),
        key=lambda x: (x["strong_weight_sum"], x["strong_shared_count"], len(x["shared_entities"])),
        reverse=True,
    )
    return {"apk": apk[0] if apk else {"sha256": sha256}, "related": related}


def query_by_kind(store: GraphStore, kind: str, value: str) -> dict:
    """反查：给定实体（kind+value），列出所有观测到它的 APK。"""
    eid = f"{kind}:{value}"
    apks = store.query_rows(
        "MATCH (a:Apk)-[:OBSERVED]->(e:Entity {id: $id}) "
        "RETURN a.sha256 AS sha256, a.package AS package, a.label AS label",
        {"id": eid},
    )
    return {
        "entity": {"kind": kind, "value": value, "weight": get_weight(kind)},
        "apks": apks,
        "count": len(apks),
    }


def query_clusters(store: GraphStore, min_shared: int = 1) -> dict:
    """跑全图团伙簇（连通分量）+ 并案依据 + 置信分。

    --min-shared：过滤共享不同实体数低于 N 的弱关联对（默认 1）。
    """
    rows = store.query_rows(
        "MATCH (a1:Apk)-[:OBSERVED]->(e:Entity)<-[:OBSERVED]-(a2:Apk) "
        "WHERE a1.sha256 < a2.sha256 "
        "RETURN a1.sha256 AS a, a2.sha256 AS b, "
        "e.kind AS kind, e.value AS value, e.weight AS weight"
    )

    # 按样本对聚合共享实体。
    pair_entities: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in rows:
        pair = (str(r.get("a") or ""), str(r.get("b") or ""))
        pair_entities[pair].append(
            {
                "kind": str(r.get("kind") or ""),
                "value": str(r.get("value") or ""),
                "weight": float(r.get("weight") or 0.0),
            }
        )

    # 并查集：对「共享不同实体数 >= min_shared」的样本对连边。
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:
            parent[x], x = root, parent[x]
        return root

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    kept_pairs: list[tuple[str, str, list[dict]]] = []
    for (a, b), ents in pair_entities.items():
        distinct = {(e["kind"], e["value"]) for e in ents}
        if len(distinct) >= min_shared:
            union(a, b)
            kept_pairs.append((a, b, ents))

    groups: dict[str, set[str]] = defaultdict(set)
    for node in list(parent):
        groups[find(node)].add(node)

    clusters: list[dict] = []
    for root in sorted(groups):
        members = groups[root]
        if len(members) < 2:
            continue
        shared: dict[tuple[str, str], float] = {}
        for a, b, ents in kept_pairs:
            if a in members and b in members:
                for e in ents:
                    shared[(e["kind"], e["value"])] = e["weight"]
        shared_list = [
            {"kind": k, "value": v, "weight": w} for (k, v), w in sorted(shared.items())
        ]
        strong = {(k, v): w for (k, v), w in shared.items() if is_strong(k)}
        strong_weight_sum = sum(strong.values())
        strong_kind_count = len({k for k, _ in strong})
        score = strong_weight_sum + strong_kind_count
        if score > 0:
            confidence = round(score / (score + _CONF_K), 4)
        else:
            # 仅中/弱实体相连：用共享实体数兜底（仍单调、低于任何含强实体的簇）。
            n = len(shared_list)
            confidence = round(n / (n + _CONF_K), 4)
        clusters.append(
            {
                "members": sorted(members),
                "shared": shared_list,
                "confidence": confidence,
                "rationale": {
                    "strong_kind_count": strong_kind_count,
                    "strong_weight_sum": strong_weight_sum,
                    "shared_entity_count": len(shared_list),
                },
            }
        )

    clusters.sort(key=lambda c: c["confidence"], reverse=True)
    for i, c in enumerate(clusters, start=1):
        c["cluster_id"] = i
    return {"clusters": clusters, "cluster_count": len(clusters), "min_shared": min_shared}
