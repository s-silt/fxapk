"""跨样本团伙聚类引擎（纯离线后处理，零真机、零联网、零外部依赖）。

批量分析现在只按内容 sha256 精确去重（``ledger.py``，改名即跳过），抠出的签名证书 /
C2 域名 / AppID / 收款地址等强指标在批量层白白浪费。本模块把这些指标横向碰撞，把零散
单包升级为「团伙簇」——直击办案最缺的**串并**一环：

- 同一签名证书 sha256 = 同一开发者 / 打包账号
- 同一 C2 域名 / 同一收款地址 = 同一资金与服务器基础设施
- 同一 uni AppID = 同一前端工程

做法：每个样本从其 ``report.json``（dict）抽一组**强指纹**（高区分度、零公共基础设施），
建 ``指纹 -> [样本]`` 倒排索引，对共享任一强指纹的样本用并查集（union-find）连边成簇。
每个簇给出成员清单 + 并案依据（哪些指纹把它们连起来），可入卷支撑并案。

★ 只用强指纹（签名/ C2 / uni AppID / 收款地址），且**排除调试证书**（海量样本共用，
会把无关包错并）——宁可少并不可错并。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

__all__ = ["Fingerprint", "Cluster", "extract_fingerprints", "correlate"]

# 调试证书 subject 标记（CN=Android Debug…）：海量样本共用，绝不作并簇键。
_DEBUG_CERT_MARK = "android debug"


@dataclass(frozen=True)
class Fingerprint:
    """一个强指纹。kind ∈ {sign, c2, uni_appid, crypto_addr, firebase_project, telegram_bot}。"""

    kind: str
    value: str


@dataclass
class Cluster:
    """一个团伙簇：成员样本 + 把它们连起来的共享指纹（并案依据）。"""

    cluster_id: int
    members: list[str]
    shared: list[Fingerprint]


def extract_fingerprints(report: dict) -> set[Fingerprint]:
    """从单份报告（report.json 解析出的 dict）抽强指纹。绝不抛。

    - ``meta['sign_sha256']``（签名证书指纹）—— ``sign_subject`` 含 "Android Debug" 则跳过。
    - ``meta['uni_appid']`` / ``meta['crypto_addresses'][]``。
    - ``leads[]`` 中 ``is_c2=True`` 的 value（已研判的诈骗后端，排除了 CDN/SDK/公共服务）。
    """
    fps: set[Fingerprint] = set()
    meta = report.get("meta")
    if isinstance(meta, dict):
        subject = str(meta.get("sign_subject") or "").lower()
        sign = str(meta.get("sign_sha256") or "").strip()
        if sign and _DEBUG_CERT_MARK not in subject:
            fps.add(Fingerprint("sign", sign))
        uni = str(meta.get("uni_appid") or "").strip()
        if uni:
            fps.add(Fingerprint("uni_appid", uni))
        fb = str(meta.get("firebase_project_id") or "").strip()
        if fb:
            fps.add(Fingerprint("firebase_project", fb))
        for addr in meta.get("crypto_addresses") or []:
            if addr:
                fps.add(Fingerprint("crypto_addr", str(addr)))
        for tok in meta.get("telegram_bot_tokens") or []:
            if tok:
                fps.add(Fingerprint("telegram_bot", str(tok)))
    for lead in report.get("leads") or []:
        if isinstance(lead, dict) and lead.get("is_c2") and lead.get("value"):
            fps.add(Fingerprint("c2", str(lead["value"])))
    return fps


def correlate(samples: list[tuple[str, dict]]) -> list[Cluster]:
    """按共享强指纹把样本聚类，返回成员 ≥2 的团伙簇（cluster_id 从 1）。绝不抛。

    Args:
        samples: ``[(sample_id, report_dict)]``。sample_id 通常用 sha256 或文件名。
    """
    sample_fps: dict[str, set[Fingerprint]] = {}
    for sid, report in samples:
        try:
            sample_fps[sid] = extract_fingerprints(report)
        except Exception:
            logger.exception("[correlate] 抽指纹异常，跳过样本：%s", sid)
            sample_fps[sid] = set()

    # 倒排索引：指纹 -> 出现它的样本列表。
    index: dict[Fingerprint, list[str]] = {}
    for sid, fps in sample_fps.items():
        for fp in fps:
            index.setdefault(fp, []).append(sid)

    # 并查集：对出现在 ≥2 样本的指纹连边。
    parent: dict[str, str] = {sid: sid for sid, _ in samples}

    def find(x: str) -> str:
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:  # 路径压缩
            parent[x], x = root, parent[x]
        return root

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for sids in index.values():
        for other in sids[1:]:
            union(sids[0], other)

    # 收集连通分量 → 团伙簇。
    groups: dict[str, list[str]] = {}
    for sid, _ in samples:
        groups.setdefault(find(sid), []).append(sid)

    clusters: list[Cluster] = []
    cid = 0
    for root in sorted(groups):
        members = sorted(groups[root])
        if len(members) < 2:
            continue  # 孤包不入簇
        cid += 1
        member_set = set(members)
        shared = sorted(
            (fp for fp, sids in index.items() if len(member_set.intersection(sids)) >= 2),
            key=lambda f: (f.kind, f.value),
        )
        clusters.append(Cluster(cluster_id=cid, members=members, shared=shared))
    return clusters
