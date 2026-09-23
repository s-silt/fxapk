"""Explicit, bounded CDN resource/candidate comparison."""
from __future__ import annotations

import json
from pathlib import Path

import typer

from apkscan.core.origin_check import build_plan, run_check
from apkscan.core.origin_projection import publish_projection, validate_report_binding
from apkscan.core.origin_enrichment import enrich_origin_candidates


def origin_check(
    reference_url: str = typer.Option(..., "--reference-url", help="已知 CDN 业务资源 URL。"),
    candidate_url: str = typer.Option(..., "--candidate-url", help="候选 URL；域名用于 Host/SNI，路径保留原值。"),
    case_id: str = typer.Option(..., "--case-id"),
    source_note: str = typer.Option(..., "--source-note", help="候选来自哪个 APK/请求/历史记录及证据位置。"),
    report: Path = typer.Option(..., "--report", exists=True, dir_okay=False, help="已有 report.json，派生新报告而不覆盖原件。"),
    candidate_ip: str = typer.Option("", "--candidate-ip", help="仅固定候选连接 IP，保留候选 URL 的 Host/SNI。"),
    out: Path = typer.Option(Path("out"), "--out"),
    mode: str = typer.Option("passive", "--mode", help="passive 仅计划；authorized-active 最多两次 GET。"),
    enrich_providers: str = typer.Option("dns,asn,ip_rdap", "--enrich-providers", help="沿用 enrich batch 的精确源名；空串跳过。第三方会收到域名/IP。"),
) -> None:
    """核验指定资源与源站候选的关联。不会自动确认源站或改写案件报告。"""
    try:
        if mode not in {"passive", "authorized-active"}:
            raise ValueError("mode must be passive or authorized-active")
        plan = build_plan(reference_url, candidate_url, case_id=case_id,
                          source_note=source_note, candidate_ip=candidate_ip)
        baseline_bytes = report.read_bytes()
        payload = json.loads(baseline_bytes)
        if not isinstance(payload, dict):
            raise ValueError("Report must be a JSON object")
        validate_report_binding(payload, plan)
        if payload["meta"].get("origin_checks"):
            typer.echo("Use the original baseline report; derived origin-check reports cannot be chained.", err=True)
            raise typer.Exit(code=2)
        import hashlib
        plan["base_report_sha256"] = hashlib.sha256(baseline_bytes).hexdigest()
        if mode == "passive":
            # Do not echo query strings/source evidence values to shared terminal logs.
            typer.echo(json.dumps({"status": "planned", "max_requests": 2,
                "candidate_storage": plan["candidate"]["storage"]["product"] if plan["candidate"]["storage"] else None,
                "note": "No DNS or HTTP performed; authorized-active writes full evidence under --out."}))
            return
        typer.echo("将向指定参考地址和候选地址各发送一次 GET；选定富化源将收到域名/IP。完整证据保存在受控输出目录。", err=True)
        receipt = run_check(plan, out)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        try:
            data["provider_enrichment"] = enrich_origin_candidates(data, receipt.parent, enrich_providers)
        except (OSError, ValueError) as exc:
            data["provider_enrichment"] = {"status": "failed", "error_type": type(exc).__name__, "records": [], "coverage": None}
        receipt.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        publication = publish_projection(payload, receipt)
        typer.echo(json.dumps({"report": str(receipt.parent / "report.json"), "status": data["assessment"]["status"],
                              "origin_status": "not_confirmed", "projection": publication,
                              "enrichment_status": data["provider_enrichment"]["status"]}, ensure_ascii=False))
        if (publication["pdf"] != "written" or data["provider_enrichment"]["status"] not in {"complete", "not_requested"}
                or any(row["status"] == "failed" for row in data["observations"].values())):
            raise typer.Exit(code=1)
    except (ValueError, OSError) as exc:
        typer.echo(f"origin-check failed: {type(exc).__name__}", err=True)
        raise typer.Exit(code=2) from exc
