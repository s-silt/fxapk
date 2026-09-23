"""Connect origin checks to the existing Endpoint/Lead/Finding/report interfaces."""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from apkscan.core.models import Confidence, Endpoint, Evidence, Finding, Lead, LeadCategory, Severity
from apkscan.core.report_schema import ensure_writable_report_version
from apkscan.report.json import _to_jsonable

META_WRITE_OWNER = "core.origin_projection"
META_WRITE_CATEGORIES = {"origin_checks": "record", "closure": "signal"}
META_WRITE_KEYS = frozenset(META_WRITE_CATEGORIES)

_PRODUCTS = {"aliyun_oss": "阿里云 OSS", "tencent_cos": "腾讯云 COS", "huawei_obs": "华为云 OBS",
             "volcengine_tos": "火山引擎 TOS", "baidu_bos": "百度智能云 BOS", "kingsoft_ks3": "金山云 KS3"}
_STATUS = {"resource_match": "资源内容匹配", "content_differs": "资源内容不同", "inconclusive": "核验未充分"}


def _apply_provider_results(result: dict[str, Any], check: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    from apkscan.core.attribution import build_endpoint_attribution, score_edge_provider

    enrichment = check.get("provider_enrichment", {})
    coverage = enrichment.get("coverage") or {}
    records = {row["target"]: row for row in enrichment.get("records", [])}
    roles: list[str] = []
    for row in coverage.get("targets", []):
        target, kind = row["target"], row["kind"]
        endpoints = result.setdefault("endpoints", [])
        ep = next((r for r in endpoints if r.get("kind") == kind and r.get("value") == target), None)
        if ep is None:
            ep = _to_jsonable(Endpoint(target, kind))
            endpoints.append(ep)
        data = ep.setdefault("enrichment", {})
        statuses = row["source_status"]
        record_data = records.get(target, {}).get("enrichment", {})
        for source, state in statuses.items():
            data.pop(source, None)  # latest failed/skipped result cannot resurrect an earlier hit
            if state["status"] == "hit" and source in record_data:
                data[source] = record_data[source]
        data.setdefault("source_status", {}).update(statuses)
        attribution = build_endpoint_attribution(kind, target, data)
        if attribution:
            data["attribution"] = attribution
            layers = list(attribution.get("ips", []))
            domain_edge = attribution.get("domain_edge_provider")
            if domain_edge:
                layers.append({"edge_provider": domain_edge})
            for layer in layers:
                for key, label in (("resource_holder", "资源登记"), ("origin_network", "网络机构"),
                                   ("hosting_provider", "托管候选"), ("edge_provider", "边缘产品")):
                    item = layer.get(key) or {}
                    for candidate in [item, *item.get("other_candidates", [])]:
                        name = candidate.get("name") or candidate.get("organization")
                        if name:
                            value = f"{target} {label}={name}"
                            if value not in roles:
                                roles.append(value)
        else:
            data.pop("attribution", None)
    # Captured headers are scoped to this Host/SNI and connected IP. Do not copy
    # them to every IP returned by a later DNS query or to other co-hosted sites.
    for label, observation in check.get("observations", {}).items():
        headers = observation.get("response_headers")
        if not headers or not observation.get("http_status"):
            continue
        edge = score_edge_provider({"response_headers": dict(headers)})
        if not edge:
            continue
        request = check[label]
        host = request["host"]
        ep = next((r for r in result.setdefault("endpoints", []) if r.get("value") == host), None)
        if ep is None:
            ep = _to_jsonable(Endpoint(host, "domain"))
            result["endpoints"].append(ep)
        ep.setdefault("enrichment", {}).setdefault("origin_check_edges", []).append({
            "host": host, "sni": request["sni"], "connected_ip": observation.get("connected_ip"),
            "observed_at": observation.get("observed_at"), "edge_provider": edge})
        for candidate in [edge, *edge.get("other_candidates", [])]:
            roles.append(f"{host}@{observation.get('connected_ip', '未知')} 响应边缘产品={candidate['name']}（{candidate['tier']}）")
    return enrichment, roles


def validate_report_binding(payload: dict[str, Any], plan: dict[str, Any]) -> None:
    ensure_writable_report_version(payload.get("schema_version"))
    meta = payload.get("meta")
    if not isinstance(meta, dict):
        raise ValueError("Report meta must be an object")
    if meta.get("case_id") and meta["case_id"] != plan["case_id"]:
        raise ValueError("Report case identity mismatch")
    values = [str(row.get("value", "")) for key in ("endpoints", "leads")
              for row in payload.get(key, []) if isinstance(row, dict)]
    reference_host = plan["reference"]["host"]
    if not any((urlsplit(v).hostname or "" if "://" in v else v).lower().rstrip(".") == reference_host
               for v in values if v):
        raise ValueError("Reference host is absent from the selected report")


def integrate_check(payload: dict[str, Any], check: dict[str, Any], receipt: Path) -> dict[str, Any]:
    """Return a new report; keep every observation and never upgrade existing advice."""
    validate_report_binding(payload, check)
    raw = receipt.read_bytes()
    if json.loads(raw) != json.loads(json.dumps(check, allow_nan=False)):
        raise ValueError("Receipt content mismatch")
    digest = hashlib.sha256(raw).hexdigest()
    result = copy.deepcopy(payload)
    meta = result["meta"]
    checks = meta.setdefault("origin_checks", [])
    if not isinstance(checks, list):
        raise ValueError("Invalid origin_checks collection")
    if any(row.get("check_id") == digest for row in checks):
        return result
    if checks:
        raise ValueError("Use the original baseline report; chained projections are unsupported")
    enrichment, roles = _apply_provider_results(result, check)
    request = check["candidate"]
    target = request.get("connect_ip") or request["host"]
    try:
        ipaddress.ip_address(target)
        kind, category = "ip", LeadCategory.IP
    except ValueError:
        kind, category = "domain", LeadCategory.DOMAIN
    storage = request.get("storage") or {}
    product = _PRODUCTS.get(str(storage.get("product", "")), "服务商待核")
    status = check["assessment"]["status"]
    ref, cand = check["observations"]["reference"], check["observations"]["candidate"]
    # Full URLs and response headers remain in the controlled receipt; public projections do not copy tokens.
    detail = (f"【待核】源站候选核验：{target}；{_STATUS[status]}；产品地址线索：{product}。"
              f"参考域名 {check['reference']['host']}；候选 Host {request['host_header']}；"
              f"SNI {request['sni'] or '无'}；参考/候选 HTTP 状态 {ref.get('http_status', '失败')}/{cand.get('http_status', '失败')}；"
              f"观测时间 {cand.get('observed_at', '未知')}。仅针对指定资源，源站未确认，不代表目标 APK 实连或业务后台。"
              "内容相同仍可能是共享页面、镜像或代理；内容不同或访问失败不排除源站。"
              f"完整路径、候选来源、请求响应和哈希见核验回执，SHA-256={digest}。")
    coverage = enrichment.get("coverage") or {}
    outcomes = coverage.get("source_outcomes", {})
    detail += f"多源富化状态：{enrichment.get('status', 'not_requested')}；逐源结果统计：{json.dumps(outcomes, ensure_ascii=False)}。"
    if roles:
        detail += "服务商分层线索：" + "；".join(roles) + "。不等于客户或运营主体。"
    summary = (f"源站候选核验：{_STATUS[status]}；源站未确认；"
               f"多源富化：{enrichment.get('status', 'not_requested')}。"
               "完整详情见源站候选核验章节及核验回执。")
    evidence = Evidence(source="origin-check", location=f"origin-check.json#sha256={digest}", snippet=summary)
    ev = _to_jsonable(evidence)
    projection = {"check_id": digest, "case_id": check["case_id"], "target": target,
                  "reference_host": check["reference"]["host"], "product": product,
                  "status": status, "origin_status": "not_confirmed", "detail": detail,
                  "evidence_id": ev["evidence_id"], "receipt": "origin-check.json",
                  "storage_scope": storage.get("scope"), "evidence_status": "pending"}
    projection.update(enrichment_status=enrichment.get("status", "not_requested"),
                      source_outcomes=outcomes, provider_roles=roles,
                      coverage_relpath=enrichment.get("coverage_relpath"))
    checks.append(projection)
    endpoints = result.setdefault("endpoints", [])
    ep = next((r for r in endpoints if r.get("kind") == kind and r.get("value") == target), None)
    if ep is None:
        ep = _to_jsonable(Endpoint(target, kind))
        endpoints.append(ep)
    ep.setdefault("evidences", []).append(ev)
    ep.setdefault("enrichment", {}).setdefault("origin_checks", []).append(projection)
    leads = result.setdefault("leads", [])
    lead = next((r for r in leads if r.get("category") == category.value and r.get("value") == target), None)
    if lead is None:
        lead = _to_jsonable(Lead(category, target, where_to_request=f"{product}（签约主体待核）",
            confidence=Confidence.LOW, advice="待核", base_advice="待核"))
        leads.append(lead)
    lead.setdefault("source_refs", []).append(ev)
    lead["notes"] = (lead.get("notes", "") + "\n" + summary).strip()
    requests = lead.setdefault("evidence_to_obtain", [])
    for item in ("指定时段的加速配置及回源日志", "相关域名、主机或存储桶的账号关系；签约主体待核"):
        if item not in requests:
            requests.append(item)
    finding = Finding(
        id="origin-check." + digest[:16], title="CDN 源站候选核验", severity=Severity.INFO,
        category="origin-check", description=f"{target}：{_STATUS[status]}，源站未确认。完整结果见源站候选核验章节。",
        recommendation="以回源配置或日志进一步核实；保留待核状态。",
        evidences=[Evidence(source=evidence.source, location=evidence.location, snippet=f"{target}；源站未确认")])
    result.setdefault("findings", []).append(_to_jsonable(finding))
    closure = meta.get("closure")
    if isinstance(closure, dict) and closure.get("status") == "complete":
        closure["status"] = "partial"
        closure["origin_check_reassessment_required"] = True
        meta["closure"] = closure
    from apkscan.core.closure import refresh_visibility_snapshot
    refresh_visibility_snapshot(meta)
    return result


def publish_projection(payload: dict[str, Any], receipt: Path) -> dict[str, Any]:
    """Existing report renderers and IOC exporter consume the integrated report."""
    from apkscan.core.report_io import report_from_dict
    from apkscan.report import html, ioc, pdf

    check = json.loads(receipt.read_bytes())
    merged = integrate_check(payload, check, receipt)
    directory = receipt.parent
    report_path = directory / "report.json"
    report_path.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
    typed = report_from_dict(merged)
    html.render(typed, str(directory / "report.html"))
    ioc.write_csv(ioc.leads_to_ioc_rows(merged), str(directory / "ioc.csv"))
    pdf_ok = pdf.render(typed, str(directory / "report.pdf"), html_source=str(directory / "report.html"))
    status = {"report_json": "written", "html": "written", "ioc_csv": "written",
              "pdf": "written" if pdf_ok else "failed", "canonical_workbook": "requires_verified_package_projection"}
    (directory / "projection-status.json").write_text(json.dumps(status, indent=2), encoding="utf-8")
    hashes = {p.relative_to(directory).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.rglob("*")
              if p.is_file() and p.name != "SHA256.json"}
    (directory / "SHA256.json").write_text(json.dumps(hashes, indent=2), encoding="utf-8")
    return status
