"""把 config-chain 各段拼成**单一控制链对象**：远程配置对象 → 加密配方 → 解码 → 后端域名/IP + 五层归因。

价值：报告输出的不再是孤立 IOC（CRYPTO_RECIPE / REMOTE_CONFIG / DOMAIN / IP 各一条），而是一条可读的
**控制链**——"App 从这个 OSS 对象拉配置、用这套 AES 配方解开、得到这些后端域名、落在这些 IDC"。

这是**附加视图**（纯从报告已有数据组装）：不改 leads / closure / service_operator。链锚定在每个已下载解码的
远程配置对象（``report.meta["remote_config_artifacts"]``），后端归因取自解出域名/IP 端点的 ``enrichment
["attribution"]``（五层，_stage_attribution 已写）。纯函数、绝不抛。
"""

from __future__ import annotations

import logging
import json
from copy import deepcopy
from typing import Any

logger = logging.getLogger(__name__)


def build_control_chains(
    artifacts: Any, recipe: Any, endpoints: list[Any]
) -> list[dict[str, Any]]:
    """据下载解码产出的 ConfigArtifact 列表拼控制链。绝不抛：坏条目跳过。

    Args:
        artifacts: ``report.meta["remote_config_artifacts"]``（dict 列表）。
        recipe: ``report.meta["crypto_recipe"]``（dict）或 None——链上的解密配方段。
        endpoints: pipeline 端点集（用于按 value 查解出域名/IP 的五层归因）。
    """
    if not isinstance(artifacts, list) or not artifacts:
        return []
    ep_by_value = {getattr(ep, "value", None): ep for ep in endpoints}
    recipe_summary = _recipe_summary(recipe)
    chains: list[dict[str, Any]] = []
    for art in artifacts:
        if not isinstance(art, dict):
            continue
        url = art.get("source_url")
        if not isinstance(url, str) or not url:
            continue
        backends: list[dict[str, Any]] = []
        for domain in art.get("domains") or []:
            if isinstance(domain, str) and domain:
                backends.append(_backend("domain", domain, ep_by_value.get(domain)))
        for ip in art.get("ips") or []:
            if isinstance(ip, str) and ip:
                backends.append(_backend("ip", ip, ep_by_value.get(ip)))
        fields = art.get("fields")
        fields = fields if isinstance(fields, list) else []
        gaps = {g for g in (art.get("gaps") or []) if isinstance(g, str)}
        if "fields" not in art and art.get("decoded"):
            gaps.add("field_path_unavailable")
        for backend in backends:
            backend["field_paths"] = sorted({
                f["path"] for f in fields if isinstance(f, dict)
                and f.get("value") == backend["value"] and isinstance(f.get("path"), str)
            })
            endpoint = ep_by_value.get(backend["value"])
            bindings = getattr(endpoint, "enrichment", {}).get("config_consumer_bindings", [])
            matching = [b for b in bindings if isinstance(b, dict) and b.get("artifact_sha256") == art.get("sha256")]
            backend["consumer_candidates"] = sorted(
                [dict(c, field_path=b["field_path"]) for b in matching for c in b.get("candidates", [])],
                key=lambda c: (c["field_path"], c["source_path"], c["method_offset"], c["key"]),
            )
            backend["consumer_gaps"] = sorted({g for b in matching for g in b.get("gaps", [])}) if matching else ["consumer_unbound_no_jadx"]
            runtime = getattr(endpoint, "enrichment", {}).get("config_runtime_bindings", [])
            runtime = [b for b in runtime if isinstance(b, dict) and b.get("artifact_sha256") == art.get("sha256")]
            for source, target in (("correlations", "runtime_correlations"), ("suspicions", "suspicions"), ("material_comparisons", "material_comparisons")):
                backend[target] = sorted([dict(c, field_path=b["field_path"]) for b in runtime for c in b.get(source, [])],
                                         key=lambda c: json.dumps(c, sort_keys=True))
            backend["runtime_gaps"] = [] if runtime else ["runtime_binding_unavailable"]
        chains.append({
            "source_url": url,
            "artifact_sha256": art.get("sha256"),
            "transforms": deepcopy(art.get("transforms") or []),
            "material": deepcopy(art.get("material") or {"complete": "unknown"}),
            "gaps": sorted(gaps),
            "stored_path": art.get("stored_path"),  # 落盘的原始配置对象（相对 out_dir）；未落盘 → None
            "crypto_recipe": recipe_summary,
            "decoded": bool(art.get("decoded")),
            "decode_chain": list(art.get("decode_chain") or []),
            "backends": backends,
        })
    return chains


def _backend(kind: str, value: str, endpoint: Any) -> dict[str, Any]:
    """一个后端节点（域名/IP）+ 其五层归因摘要（→ 承载方 / IDC / 边缘）。"""
    return {"kind": kind, "value": value, "attribution": _attribution_summary(endpoint)}


def _recipe_summary(recipe: Any) -> dict[str, Any] | None:
    """加密配方段的紧凑摘要（算法/模式/key 编码/iv 推导）；非 dict → None。不含 key 明文（只标编码）。"""
    if not isinstance(recipe, dict) or not recipe:
        return None
    return {
        "algo": recipe.get("algo"),
        "mode": recipe.get("mode"),
        "padding": recipe.get("padding"),
        "key_encoding": recipe.get("key_encoding"),
        "iv_derive": recipe.get("iv_derive"),
    }


def _attribution_summary(endpoint: Any) -> list[dict[str, Any]]:
    """从端点 ``enrichment["attribution"]`` 抽每个落地 IP 的五层归因紧凑摘要（承载方/机房/边缘/国家）。

    无端点 / 无归因 → 空列表。绝不抛：坏结构逐条跳过。取名优先、回落类别/tier/asn，供报告直接呈现"→ IDC"。
    """
    if endpoint is None:
        return []
    enrichment = getattr(endpoint, "enrichment", None)
    attribution = enrichment.get("attribution") if isinstance(enrichment, dict) else None
    if not isinstance(attribution, dict):
        return []
    out: list[dict[str, Any]] = []
    for record in attribution.get("ips") or []:
        if not isinstance(record, dict):
            continue
        out.append({
            "ip": record.get("ip"),
            "country": record.get("country"),
            "origin_network": _layer_label(record.get("origin_network"), "asn"),
            "hosting_provider": _layer_label(record.get("hosting_provider"), "category"),
            "edge_provider": _layer_label(record.get("edge_provider"), "tier"),
        })
    return out


def _layer_label(layer: Any, fallback_key: str) -> Any:
    """一层归因的可读标签：优先 name，回落指定字段（asn/category/tier）；非 dict → None。"""
    if not isinstance(layer, dict):
        return None
    return layer.get("name") or layer.get(fallback_key)


__all__ = ["build_control_chains"]
