"""Bounded active observation command; planning is strictly offline."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Annotated

import typer

from apkscan.core.json_io import REPORT_JSON_MAX_BYTES, load_json_file, read_bytes_bounded
from apkscan.core.probe_target import build_plan, run_plan


def _quantity(value: str, units: dict[str, int]) -> int:
    match = re.fullmatch(r"([0-9]{1,9})([a-zA-Z]*)", value)
    if match is None or match[2].lower() not in units:
        raise ValueError("invalid_budget_unit")
    return int(match[1]) * units[match[2].lower()]


def probe_target(
    report: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    target: Annotated[str, typer.Option("--target")],
    business_host: Annotated[str, typer.Option("--business-host")],
    allow: Annotated[list[str] | None, typer.Option("--allow")] = None,
    checks: str = typer.Option("tls", "--checks"),
    execute: bool = typer.Option(False, "--execute"),
    plan_only: bool = typer.Option(False, "--plan-only"),
    mode: str = typer.Option("passive", "--mode"),
    max_requests: int = typer.Option(6, "--max-requests"),
    max_bytes: str = typer.Option("2MiB", "--max-bytes", help="全部 HTTP 响应及证书 DER 字节上限，不含 TLS 协议开销。"),
    window: str = typer.Option("10m", "--window", help="总窗口秒数或 m 分钟，最大 10m。"),
    out: Path = typer.Option(Path("out"), "--out"),
    certificate_ownership: Path | None = typer.Option(None, "--certificate-ownership", help="独立提供方签名的证书归属材料。"),
    ownership_trust_anchor: Path | None = typer.Option(None, "--ownership-trust-anchor", help="另行核实的提供方 Ed25519 公钥。"),
    url: str = typer.Option("", "--url", help="业务或 Host 比较的已知 HTTPS 路径；不带查询参数或凭据。"),
    resource_url: str = typer.Option("", "--resource-url", help="经域名和候选 IP 比较的已知静态资源。"),
    object_url: str = typer.Option("", "--object-url", help="已知对象精确 URL，不猜路径或桶。"),
    follow_manifest: Path | None = typer.Option(None, "--follow-manifest", help="显式引用边 JSON：source_url/source_sha256/field_pointer/target_url。"),
    max_objects: int = typer.Option(0, "--max-objects", help="follow 必须显式设置对象数，最大 6。"),
    tls_bindings: Path | None = typer.Option(None, "--tls-bindings", help="独立提供方签名的同 IP 多域名绑定材料。"),
    bindings_trust_anchor: Path | None = typer.Option(None, "--bindings-trust-anchor", help="独立核实的绑定材料签名公钥。"),
) -> None:
    """默认只生成计划；显式 execute + authorized-active 执行白名单内检查，最多六次请求。"""
    try:
        if mode not in {"passive", "authorized-active"} or execute and plan_only:
            raise ValueError("invalid_mode")
        payload = load_json_file(report, limit=REPORT_JSON_MAX_BYTES)
        if not isinstance(payload, dict):
            raise ValueError("invalid_report")
        edges = load_json_file(follow_manifest, limit=65536) if follow_manifest else []
        if not isinstance(edges, list) or not all(isinstance(e, dict) for e in edges):
            raise ValueError("invalid_follow_manifest")
        plan = build_plan(payload, target=target, business_host=business_host, allow=allow or [],
                          checks=checks.split(","), max_requests=max_requests,
                          max_bytes=_quantity(max_bytes, {"": 1, "b": 1, "kib": 1024, "mib": 1024 * 1024}),
                          window=_quantity(window, {"": 1, "s": 1, "m": 60}), url=url, resource_url=resource_url,
                          object_url=object_url, follow_edges=edges, max_objects=max_objects)
        if not execute:
            typer.echo(json.dumps(plan, sort_keys=True))
            return
        if mode != "authorized-active":
            raise ValueError("execute_requires_authorized_active")
        material = read_bytes_bounded(certificate_ownership, 65536) if certificate_ownership else b""
        key = read_bytes_bounded(ownership_trust_anchor, 8192) if ownership_trust_anchor else b""
        bindings = read_bytes_bounded(tls_bindings, 65536) if tls_bindings else b""
        bindings_key = read_bytes_bounded(bindings_trust_anchor, 8192) if bindings_trust_anchor else b""
        typer.echo(f"按计划对白名单目标最多执行 {plan['planned_requests']} 次连接；目标会收到所列 SNI/Host/路径。归档含原始响应，未脱敏。", err=True)
        receipt = run_plan(plan, out, payload, authorized=True, ownership_material=material, ownership_key=key,
                           binding_material=bindings, binding_key=bindings_key)
        typer.echo(json.dumps({"receipt": str(receipt), "origin_status": "not_confirmed"}))
    except (ValueError, OSError) as exc:
        typer.echo(f"probe-target failed: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(code=2) from exc
