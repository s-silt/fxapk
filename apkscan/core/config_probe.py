"""配置探测预案：把「后端域名」× 「配置接口路径」拼成可核验的候选 URL。

## 缺的是哪一环

config-chain 的链路是 APK → 配置接口 → 下发的域名/IP 池 → 落地 IDC。此前两头都有、中间断着：
:mod:`apkscan.analyzers.api_surface` 从 native/DEX 里提得到配置接口**路径**（``/api/home/config``、
``/api/v1/system/config/app_init``），:func:`apkscan.core.pipeline._stage_remote_config_fetch` 也早就
能下载解码远程配置——但前者只有 path、没有 host，拼不成一个能取的 URL，于是这条链在此断掉。

## 为什么不能直接做笛卡尔积

N 个域名 × M 个路径 里绝大多数组合根本不存在。全都发出去既是对无关主机的无谓请求，也会把
一堆 404 当成"探测过了"。所以：

- host 只取 **asset_score 排在前面的**（该视图按"最像 App 自有后端"排序，正是要打的那批）；
- 组合数硬封顶，超出即截断并**显式记录截断量**——静默截断会被读成"已全覆盖"；
- 产出的是**预案**，不是结果。passive（默认）模式下只写 meta，本模块不发起网络请求；
  只有 authorized-active 才把预案转成候选交给既有的下载解码链路。

## 边界

本模块**不发起任何网络请求**，纯组装。是否真的去取由调用方按运行模式决定——主被动隔离的
判定点仍在 pipeline，此处不重复实现、也不绕过。
"""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlsplit

from apkscan.core.redact import safe_exception_diagnostic, urlunsplit

logger = logging.getLogger(__name__)

#: 参与拼接的 host 数上限：asset_score 降序取前 N。再往后的域名多是三方 SDK / 公共服务，
#: 拼上自家配置路径没有意义。
_MAX_HOSTS = 8
#: 参与拼接的配置路径数上限。
_MAX_PATHS = 12
#: 候选 URL 总数硬封顶。超出即截断，并把截断量写进结果——只有说出来，"没探到"才不会被
#: 误读成"探过了没有"。
_MAX_CANDIDATES = 40

#: 只对这些 kind 的资产拼 URL（IP 直连配置接口的形态存在，但误报率高，交人工判断）。
_HOST_KINDS = frozenset({"domain"})


def _norm_path(path: str) -> str | None:
    """路径归一：必须以 / 开头、不含查询串与协议部分。不合形态 → None。"""
    p = (path or "").strip()
    if not p.startswith("/") or "://" in p or len(p) > 200:
        return None
    # 去掉可能混进来的查询串/锚点（提取自二进制时常粘连后续字节）
    for sep in ("?", "#", " "):
        p = p.split(sep, 1)[0]
    return p or None


def _host_of(value: str) -> str | None:
    """从资产值里取 host（既接受裸域名，也接受完整 URL）。"""
    v = (value or "").strip()
    if not v:
        return None
    if "://" in v:
        try:
            return urlsplit(v).hostname
        except ValueError as exc:
            # 不记 v 原文：解析已失败，不能假设 redact_url 认得它；只留类型与帧位置。
            logger.debug("[config_probe] URL 解析失败（%s）", safe_exception_diagnostic(exc))
            return None
    return v.split("/", 1)[0] or None


def build_plan(meta: Any) -> dict[str, Any] | None:
    """据报告 meta 组装配置探测预案。缺料 → None。绝不抛、绝不联网。

    Returns:
        ``{"candidates": [{"url", "host", "path", "host_score"}], "hosts_used", "paths_used",
        "truncated", "note"}``
    """
    try:
        if not isinstance(meta, dict):
            return None
        surface = meta.get("api_surface")
        paths_raw = surface.get("config_endpoints") if isinstance(surface, dict) else None
        if not isinstance(paths_raw, list):
            return None
        paths: list[str] = []
        for p in paths_raw:
            norm = _norm_path(p) if isinstance(p, str) else None
            if norm and norm not in paths:
                paths.append(norm)
        if not paths:
            return None

        scored = meta.get("asset_scores")
        hosts: list[tuple[str, float]] = []
        seen: set[str] = set()
        for item in scored if isinstance(scored, list) else []:
            if not isinstance(item, dict) or item.get("kind") not in _HOST_KINDS:
                continue
            host = _host_of(str(item.get("value") or ""))
            if not host or host in seen:
                continue
            seen.add(host)
            score = item.get("score")
            hosts.append((host, float(score) if isinstance(score, (int, float)) else 0.0))
            if len(hosts) >= _MAX_HOSTS:
                break
        if not hosts:
            return None

        use_paths = paths[:_MAX_PATHS]
        candidates: list[dict[str, Any]] = []
        # host 外层、path 内层：按 asset_score 降序铺开，截断时保住最像自有后端的那批的完整路径集。
        for host, score in hosts:
            for path in use_paths:
                if len(candidates) >= _MAX_CANDIDATES:
                    break
                candidates.append({
                    "url": urlunsplit(("https", host, path, "", "")),
                    "host": host,
                    "path": path,
                    "host_score": score,
                })
            if len(candidates) >= _MAX_CANDIDATES:
                break

        total = len(hosts) * len(use_paths)
        truncated = max(0, total - len(candidates))
        return {
            "schema_version": "1.0",
            "candidates": candidates,
            "hosts_used": len(hosts),
            "paths_used": len(use_paths),
            "paths_available": len(paths),
            "truncated": truncated,
            "note": (
                "候选由「asset_score 靠前的域名」×「提取到的配置接口路径」组合而成，"
                "多数组合并不真实存在；passive 模式下不会发起任何请求。"
            ),
        }
    except Exception:  # noqa: BLE001 — 组装失败不得影响主流程
        logger.exception("[config_probe] 预案组装异常")
        return None


__all__ = ["build_plan"]
