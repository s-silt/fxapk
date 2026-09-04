"""跨样本关联候选聚类（纯离线后处理，零真机、零联网、零外部依赖）。

批量分析会从各样本的 ``report.json`` 提取签名证书、C2 字面值、AppID、收款地址等较高
区分度的候选指纹并横向碰撞。相同字节或字面值只证明样本共享该指纹：证书和 AppID 可能被
共用、复制或随重打包继承，域名和服务器可能是共享基础设施，地址或凭据也可能来自模板、测试
数据或第三方组件。因此，输出只用于召回应优先人工复核的关联候选，不能独立认定开发、运营、
控制或法律主体相同，也不会自动形成并案结论。

做法：建立 ``指纹 -> [样本]`` 倒排索引，对共享任一候选指纹的样本用并查集
（union-find）连边成簇。每个簇保留成员清单和共享指纹，供复核者逐边排除公共组件、共享服务、
重打包继承及传递闭包误连；同一连通分量内的任意两个成员不一定直接共享指纹。

分析只纳入当前案件直接证据范围内、达到“建议调证”档的对应 Lead，并排除海量样本共用的
调试证书。这些门槛用于降低误报，不会把候选指纹升级为主体归属证据。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from apkscan.core.evidence_scope import project_serialized_leads

logger = logging.getLogger(__name__)

__all__ = [
    "CORRELATION_DISCLAIMER",
    "Fingerprint",
    "Cluster",
    "extract_fingerprints",
    "correlate",
]

CORRELATION_DISCLAIMER = (
    "各簇仅为共享指纹生成的人工复核关联候选；单一或多个共享指纹均不能独立认定"
    "同一开发、运营、控制或法律主体，也不会自动形成并案结论。"
)

# 调试证书 subject 标记（CN=Android Debug…）：海量样本共用，不作关联候选键。
_DEBUG_CERT_MARK = "android debug"

# 由 Lead 派生的候选指纹：category → fingerprint kind。它们只说明报告中出现相同值，
# 仍须排除共享服务、模板数据和重打包继承，不能据此认定同一运营者或控制者。
_LEAD_FP_KINDS = {
    "ADMIN_PANEL": "admin_host",
    "SELF_HOSTED_IM": "im_server",
    "WALLET_SECRET": "wallet_secret",
}
_ADVICE_INVESTIGATE = "建议调证"


@dataclass(frozen=True)
class Fingerprint:
    """一个关联候选指纹。kind ∈ {sign, c2, uni_appid, crypto_addr, firebase_project, telegram_bot,
    admin_host, im_server, wallet_secret}。"""

    kind: str
    value: str


@dataclass
class Cluster:
    """一个关联候选簇：成员样本 + 连接这些成员的共享指纹。"""

    cluster_id: int
    members: list[str]
    shared: list[Fingerprint]


def extract_fingerprints(report: dict) -> set[Fingerprint]:
    """从单份报告（report.json 解析出的 dict）抽关联候选指纹。绝不抛。

    - ``meta['sign_sha256']``（签名证书指纹）—— ``sign_subject`` 含 "Android Debug" 则跳过。
    - ``meta['uni_appid']`` / ``meta['crypto_addresses'][]``。
    - ``leads[]`` 中经 scope 投影后 ``is_c2=True`` 的 value（已研判的 C2 后端）。
    - ``leads[]`` 中 ADMIN_PANEL/SELF_HOSTED_IM（建议调证档）→ admin_host/im_server；
      WALLET_SECRET（建议调证档）→ wallet_secret。所有 Lead 指纹均须当前案件直接证据；批次
      参考或旧版未声明 scope 只能待核，不得连边。
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
    for lead in project_serialized_leads(report):
        if not isinstance(lead, dict) or not lead.get("value"):
            continue
        value = str(lead["value"])
        if lead.get("is_c2"):
            fps.add(Fingerprint("c2", value))
        # 所有 Lead 类候选指纹只收 scope 投影后的强档。钱包内容校验不能替代“它属于当前案件”
        # 的直接证据资格，因此不再无条件入图。
        kind = _LEAD_FP_KINDS.get(str(lead.get("category") or ""))
        if kind and lead.get("advice") == _ADVICE_INVESTIGATE:
            fps.add(Fingerprint(kind, value))
    return fps


def correlate(samples: list[tuple[str, dict]]) -> list[Cluster]:
    """按共享指纹召回成员 ≥2 的关联候选簇（cluster_id 从 1）。绝不抛。

    返回的连通分量只用于人工复核；共享一个或多个指纹不能独立证明主体相同，传递连接也不代表
    簇内任意两个成员直接相关。

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

    # 收集连通分量 → 关联候选簇。
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
