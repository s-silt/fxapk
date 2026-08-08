"""执行配置探测预案：把 :mod:`apkscan.core.config_probe` 组装的候选真正取回来。

## 为什么是独立一步、而不是分析时顺手做掉

预案要靠 ``asset_score``（"最像自有后端"的排序）才拼得出来，而它在流水线里排在下载阶段
**之后**——同一轮里没法既排完序又回头去取。这个时序不是缺陷：主动请求是不可逆的对外动作，
让它跨一轮、由人看过预案再决定要不要发，正是想要的。所以取回做成独立命令。

## 四种结果，绝不混为一谈

- ``hit``：取到了、解开了，且从中解出了域名/IP；
- ``no_content``：取到了、**解开了**，里面确实没有——这才是"查了没有"；
- ``undecoded``：取到了但解码链没走通，**内容未知**（多为密文而手头没配方）；
- ``failed``：压根没取成（404 / 超时 / 被 SSRF 防护拦下）——"没查成"。

后三者两两都不能混。曾把 ``undecoded`` 和 ``no_content`` 合成一档，于是「取回 3 个候选、
全是解不开的密文」打印成「取到但无内容 3」，报告里顺手写成"未发现下发域名"——
拿一坨看不懂的字节当了否定结论。

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

#: analyze 流水线的落盘子目录名（out_dir/remote_config/，见 pipeline._stage_remote_config_fetch）。
#: 只用来**构造目录**，不拼进 archive_blob 的返回值——stored_path 一律按实际写入位置登记，
#: 「相对 out_dir 保报告可迁移」的形式由知道报告落在哪的 pipeline 侧自己换算。
REMOTE_CONFIG_SUBDIR = "remote_config"

#: 单次运行的请求数硬帽。预案本身已封顶，这里是第二道——防的是有人手改 report.json 里的
#: 候选列表后拿本命令当批量请求器用。
_MAX_REQUESTS = 40


@dataclass(frozen=True)
class ProbeOutcome:
    """单个候选的结果。``status`` ∈ {planned, hit, undecoded, no_content, failed}。"""

    url: str
    status: str
    host: str = ""
    path: str = ""
    error: str | None = None
    sha256: str | None = None
    size: int | None = None
    #: 解码链是否真的走通。``False`` 时内容未知——**不等于**里面没有域名。
    decoded: bool = False
    decode_chain: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()
    #: 落盘位置，按调用方给的 archive_dir 原样表达（CLI：``--archive`` 怎么写就怎么记，
    #: 从运行目录可解析）。未落盘 / 落盘失败 → None。
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
        # ★decoded 恒输出（哪怕是 False）：它是「内容未知」与「确实没有」的唯一区分位，
        #   按"假值省略"的惯例漏掉它，读 JSON 的人就分不出这两种情形。
        if self.status in ("hit", "undecoded", "no_content"):
            d["decoded"] = self.decoded
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
    """把原始配置对象字节原子落盘 ``<dir>/<sha>.bin``；返回**实际写入位置**作 stored_path。

    ★返回值按调用方给的 ``archive_dir`` 原样拼出（给相对路径就记相对、给绝对就记绝对），
    **不猜任何前缀**：曾恒定返回 ``remote_config/<sha>.bin``——那只是 analyze 流水线自己的
    布局；``fxapk config-probe --archive <任意目录>`` 时登记出的路径指向不存在的位置，
    落盘的一手件只能靠 sha 全盘搜。「相对 out_dir 保报告可迁移」的换算由知道报告落在哪的
    调用方自己做（见 pipeline._fetch_decode_one）。

    落盘失败（磁盘满/只读）不得连累已解出的域名/IP 线索——记 warning、返回 None
    （stored_path 缺失但线索仍在）。sha 命名幂等：同内容重复下载覆写同一文件、字节相同。
    """
    if archive_dir is None:
        return None
    target = archive_dir / f"{sha}.bin"
    try:
        atomic_write_bytes(target, blob)
    except OSError:
        logger.warning(
            "[remote_config] 原始配置对象落盘失败（已解出的线索不受影响）：%s", sha, exc_info=True
        )
        return None
    # as_posix()：stored_path 跨平台统一用 / 分隔（与既有报告里的形状一致），Windows 上
    # Path() 也照样解析得回来。
    return target.as_posix()


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
        # 抛异常与「解码链走不通」是同一种处境：字节在手上，内容不知道。
        return ProbeOutcome(url=url, status="undecoded", host=host, path=path,
                            error=f"解码异常：{exc}", sha256=sha, size=len(blob),
                            stored_path=stored)

    domains = tuple(result.domains)
    ips = tuple(result.ips)
    for d in domains:
        sink.append(config_endpoint(d, "domain", url))
    for ip in ips:
        sink.append(config_endpoint(ip, "ip", url))
    # ★三分的分界就在这里，两个判断缺一不可：
    #   · 解码链没走通（decoded=False）→ undecoded：**内容未知**。多半是密文而手头没配方，
    #     绝不能说成"里面没有域名"——那是拿一坨看不懂的字节当否定结论。
    #   · 解开了、里面确实没有域名/IP → no_content：这才是真的"查了没有"。
    #   曾把两者合成一档，于是「取回 3 个候选、全是解不开的密文」会打印成
    #   「取到但无内容 3」，报告里顺手就写成"未发现下发域名"。
    if not result.decoded:
        status = "undecoded"
    elif domains or ips:
        status = "hit"
    else:
        status = "no_content"
    return ProbeOutcome(
        url=url, status=status, host=host, path=path,
        error=None if result.decoded else "解码链未走通，内容未知（多为密文而未提供配方）",
        sha256=sha, size=len(blob), decoded=result.decoded,
        decode_chain=tuple(result.decode_chain),
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
        archive_dir: 原始字节落盘目录；None 则不落盘（线索仍照出）。outcome.stored_path
            按此目录**原样**登记（给相对路径就记相对，从运行目录可解析），不再恒带
            ``remote_config/`` 前缀。
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
