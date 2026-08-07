"""执行配置探测预案：把 :mod:`apkscan.core.config_probe` 组装的候选真正取回来。

## 为什么是独立一步、而不是分析时顺手做掉

预案要靠 ``asset_score``（"最像自有后端"的排序）才拼得出来，而它在流水线里排在下载阶段
**之后**——同一轮里没法既排完序又回头去取。这个时序不是缺陷：主动请求是不可逆的对外动作，
让它跨一轮、由人看过预案再决定要不要发，正是想要的。所以取回做成独立命令。

## 三种结果，绝不混为一谈

- ``hit``：取到了，且从中解出了域名/IP；
- ``no_content``：取到了，但没解出东西——这是**真的"查了没有"**；
- ``failed``：压根没取成（404 / 超时 / 被 SSRF 防护拦下）——这是"没查成"，不是"查了没有"。

把后两者混起来，报告里"未发现下发域名"就成了一句不知深浅的话。

## 默认不发流量

``authorized=False``（默认）时逐条产出 ``planned``，一个包也不发。要真发必须由调用方显式
传 ``authorized=True``，且 CLI 侧还要 ``--authorized-active``——门开两道，不是一道。
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from apkscan.core.atomic import atomic_write_bytes
from apkscan.core.models import Endpoint, Evidence

logger = logging.getLogger(__name__)

__all__ = [
    "REMOTE_CONFIG_SUBDIR",
    "ProbeOutcome",
    "ProbeRunResult",
    "archive_blob",
    "config_endpoint",
    "run_plan",
]

#: 原始配置对象落盘子目录名（相对输出目录）。报告里 stored_path 用相对路径，保报告可迁移。
REMOTE_CONFIG_SUBDIR = "remote_config"

#: 单次运行的请求数硬帽。预案本身已封顶，这里是第二道——防的是有人手改 report.json 里的
#: 候选列表后拿本命令当批量请求器用。
_MAX_REQUESTS = 40


@dataclass(frozen=True)
class ProbeOutcome:
    """单个候选的结果。``status`` ∈ {planned, hit, no_content, failed}。"""

    url: str
    status: str
    host: str = ""
    path: str = ""
    error: str | None = None
    sha256: str | None = None
    size: int | None = None
    decode_chain: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()
    stored_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"url": self.url, "status": self.status}
        if self.host:
            d["host"] = self.host
        if self.path:
            d["path"] = self.path
        for key in ("error", "sha256", "size", "stored_path"):
            val = getattr(self, key)
            if val is not None:
                d[key] = val
        for key in ("decode_chain", "domains", "ips"):
            val = getattr(self, key)
            if val:
                d[key] = list(val)
        return d


@dataclass
class ProbeRunResult:
    """一次运行的汇总。``endpoints`` 供调用方回灌报告。"""

    outcomes: list[ProbeOutcome] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    authorized: bool = False
    #: 被 ``_MAX_REQUESTS`` 或 ``limit`` 截掉的候选数。**必须说出来**：静默截断会让
    #: "都探过了" 变成一句假话。
    truncated: int = 0

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for o in self.outcomes:
            out[o.status] = out.get(o.status, 0) + 1
        return out

    def to_meta(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "authorized": self.authorized,
            "counts": self.counts(),
            "truncated": self.truncated,
            "outcomes": [o.to_dict() for o in self.outcomes],
        }


def archive_blob(archive_dir: "Path | None", sha: str, blob: bytes) -> str | None:
    """把原始配置对象字节原子落盘 ``<dir>/<sha>.bin``；返回**相对** stored_path。

    落盘失败（磁盘满/只读）不得连累已解出的域名/IP 线索——记 warning、返回 None
    （stored_path 缺失但线索仍在）。sha 命名幂等：同内容重复下载覆写同一文件、字节相同。
    """
    if archive_dir is None:
        return None
    try:
        atomic_write_bytes(archive_dir / f"{sha}.bin", blob)
    except OSError:
        logger.warning(
            "[remote_config] 原始配置对象落盘失败（已解出的线索不受影响）：%s", sha, exc_info=True
        )
        return None
    return f"{REMOTE_CONFIG_SUBDIR}/{sha}.bin"


def config_endpoint(value: str, kind: str, ref: str) -> Endpoint:
    """从远程配置解码回灌的端点。★source 恒为 ``remote-config``（非 runtime*）：不进
    observed-contact、也不 startswith('runtime')，故不误升"确认 C2"/"运行时出现"徽标
    ——它是"配置里出现的域名"线索，不是运行时实测接触。"""
    return Endpoint(
        value=value,
        kind=kind,
        evidences=[Evidence(
            source="remote-config",
            location=f"remote-config:{ref}",
            snippet=f"from remote-config {ref}"[:200],
        )],
    )


def _candidates_of(plan: Any) -> list[dict[str, Any]]:
    if not isinstance(plan, dict):
        return []
    raw = plan.get("candidates")
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw:
        if isinstance(item, dict) and isinstance(item.get("url"), str) and item["url"]:
            out.append(item)
    return out


def _fetch_one(
    cand: dict[str, Any], recipe: Any, archive_dir: "Path | None", sink: list[Endpoint]
) -> ProbeOutcome:
    """取一个候选并解码。任何失败都收敛成 ``failed`` 的 outcome，绝不抛。"""
    from apkscan.config.decode import decode_config_blob
    from apkscan.config.fetch import fetch_config_object

    url = str(cand.get("url"))
    host = str(cand.get("host") or "")
    path = str(cand.get("path") or "")
    try:
        fetched = fetch_config_object(url)
    except Exception as exc:  # noqa: BLE001 — 单个候选失败不得中断整批
        logger.warning("[config_probe] 下载异常 %s", url, exc_info=True)
        return ProbeOutcome(url=url, status="failed", host=host, path=path, error=str(exc))
    if not fetched.ok or fetched.raw is None:
        return ProbeOutcome(url=url, status="failed", host=host, path=path,
                            error=fetched.error or "下载失败")

    blob = fetched.raw
    sha = hashlib.sha256(blob).hexdigest()
    # 抓到即落盘，先于解码——解码失败也不能丢掉原始证据。
    stored = archive_blob(archive_dir, sha, blob)
    try:
        result = decode_config_blob(blob, recipe=recipe)
    except Exception as exc:  # noqa: BLE001 — 解码失败仍是「取到了」，别退化成「没取成」
        logger.warning("[config_probe] 解码异常 %s", url, exc_info=True)
        return ProbeOutcome(url=url, status="no_content", host=host, path=path,
                            error=f"解码异常：{exc}", sha256=sha, size=len(blob),
                            stored_path=stored)

    domains = tuple(result.domains)
    ips = tuple(result.ips)
    for d in domains:
        sink.append(config_endpoint(d, "domain", url))
    for ip in ips:
        sink.append(config_endpoint(ip, "ip", url))
    # ★取到了但没解出东西 = 「查了没有」，与「没取成」分开记。
    return ProbeOutcome(
        url=url, status="hit" if (domains or ips) else "no_content", host=host, path=path,
        sha256=sha, size=len(blob), decode_chain=tuple(result.decode_chain),
        domains=domains, ips=ips, stored_path=stored,
    )


def run_plan(
    plan: Any,
    *,
    authorized: bool = False,
    archive_dir: "Path | None" = None,
    recipe: Any = None,
    limit: int | None = None,
) -> ProbeRunResult:
    """执行（或预演）一份配置探测预案。

    Args:
        plan: ``report.meta['config_probe_plan']`` 的原样内容。形状不对 → 空结果。
        authorized: **只有显式 True 才会发出请求**。默认预演，零流量。
        archive_dir: 原始字节落盘目录；None 则不落盘（线索仍照出）。
        recipe: 解码配方（``CryptoRecipe`` 或 None）。
        limit: 本次最多请求几个候选；与内建硬帽取小。

    绝不抛：单个候选的任何异常都收敛进它自己的 outcome。
    """
    cands = _candidates_of(plan)
    cap = _MAX_REQUESTS if limit is None else max(0, min(limit, _MAX_REQUESTS))
    use, dropped = cands[:cap], max(0, len(cands) - cap)
    result = ProbeRunResult(authorized=authorized, truncated=dropped)

    if not authorized:
        result.outcomes = [
            ProbeOutcome(url=str(c["url"]), status="planned",
                         host=str(c.get("host") or ""), path=str(c.get("path") or ""))
            for c in use
        ]
        return result

    if use:
        logger.warning(
            "authorized-active：即将向目标发起 %d 个 live 请求（配置探测预案），请确认已获授权",
            len(use),
        )
    for cand in use:
        result.outcomes.append(_fetch_one(cand, recipe, archive_dir, result.endpoints))
    return result
