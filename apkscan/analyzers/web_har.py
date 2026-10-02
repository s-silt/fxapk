"""Offline HAR request/response evidence, with explicit omissions and bounds."""
from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
from collections.abc import Mapping
from datetime import datetime
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlsplit

from apkscan.analyzers._common import EndpointCollector
from apkscan.analyzers.endpoints import EndpointsAnalyzer
from apkscan.analyzers.web_evidence import _iter_text, coverage_meta_categories_for
from apkscan.core.json_contract import reject_nonfinite_json_constant
from apkscan.core.models import AnalyzerResult, Evidence
from apkscan.core.registry import BaseAnalyzer
from apkscan.core.webctx import WebContext, canonical_evidence_name, looks_binary

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

MAX_ENTRIES = 1000
MAX_BODY_BYTES = 1024 * 1024
MAX_TOTAL_BODY_BYTES = 4 * 1024 * 1024


def _http_url(value: object, base: str = "") -> str | None:
    if not isinstance(value, str) or len(value) > 8192 or any(ord(ch) < 32 for ch in value):
        return None
    try:
        value = urljoin(base, value) if base else value
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return None
        _ = parsed.port
        return value
    except ValueError:
        return None


def _timestamp(value: object) -> float | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return date.timestamp() if date.tzinfo is not None else None
    except (ValueError, OverflowError, OSError):
        return None


class WebHarAnalyzer(BaseAnalyzer):
    name = "web_har"
    requires = ["web"]
    meta_key_categories = {"web_har_records": "record", "web_har_summary": "coverage",
                           "web_har_items_truncated": "coverage",
                           **coverage_meta_categories_for(name)}
    meta_keys = frozenset(meta_key_categories)

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        collector = EndpointCollector()
        records, bodies = [], {}
        gaps: dict[str, int] = {}
        total_body = 0
        examined = 0

        def gap(code: str) -> None:
            gaps[code] = gaps.get(code, 0) + 1

        for path, text in _iter_text(ctx, self.name, (".har", ".har.json"), result):
            try:
                payload = json.loads(text.lstrip("\ufeff"), parse_constant=reject_nonfinite_json_constant)
            except (ValueError, RecursionError):
                gap("invalid_har_json")
                continue
            log = payload.get("log") if isinstance(payload, dict) else None
            entries = log.get("entries") if isinstance(log, dict) else None
            if not isinstance(entries, list):
                gap("missing_entries")
                continue
            for index, entry in enumerate(entries):
                if examined >= MAX_ENTRIES:
                    gap("entry_budget_exceeded")
                    break
                examined += 1
                if not isinstance(entry, Mapping):
                    gap("invalid_entry")
                    continue
                request, response = entry.get("request"), entry.get("response")
                if not isinstance(request, Mapping) or not isinstance(response, Mapping):
                    gap("missing_request_or_response")
                    continue
                url = _http_url(request.get("url"))
                if not url:
                    gap("invalid_request_url")
                    continue
                location = f"{path}#/log/entries/{index}"
                observed = _timestamp(entry.get("startedDateTime"))
                evidence = Evidence(source="web", location=location + "/request/url", observed_at=observed)
                collector.add(url, "url", evidence)
                host = urlsplit(url).hostname or ""
                try:
                    ip = ipaddress.ip_address(host)
                    kind, private = "ip", not ip.is_global
                except ValueError:
                    kind, private = "domain", False
                collector.add(host, kind, evidence, is_private=private)
                status = response.get("status")
                status = status if isinstance(status, int) and not isinstance(status, bool) and 0 <= status <= 599 else None
                method = request.get("method")
                method = method.upper() if isinstance(method, str) and len(method) <= 32 and method.isascii() and method.isalpha() else "UNKNOWN"
                row = {"method": method, "entry_ref": location, "request_url": url, "status": status,
                       "response_recorded": bool(status and status >= 100),
                       "observed_at": observed, "target_app_attribution_verified": False,
                       "body_state": "absent"}
                # An explicit redirect relationship, never inferred from adjacent requests.
                redirect = _http_url(response.get("redirectURL"), url)
                if redirect and status is not None and 300 <= status < 400:
                    row["redirect_url"] = redirect
                    collector.add(redirect, "url", Evidence(source="web", location=location + "/response/redirectURL",
                                                          observed_at=observed))
                server_ip = entry.get("serverIPAddress")
                if isinstance(server_ip, str):
                    try:
                        row["server_ip"] = str(ipaddress.ip_address(server_ip))
                    except ValueError:
                        gap("invalid_server_ip")
                content = response.get("content")
                content = content if isinstance(content, Mapping) else {}
                body = content.get("text")
                if isinstance(body, str):
                    if len(body) > MAX_BODY_BYTES * 2:
                        row["body_state"] = "over_limit"
                        gap("body_budget_exceeded")
                    else:
                        try:
                            encoding = content.get("encoding")
                            if encoding not in (None, "", "base64"):
                                raise ValueError("unsupported_body_encoding")
                            raw = base64.b64decode(body, validate=True) if encoding == "base64" else body.encode("utf-8")
                            if len(raw) > MAX_BODY_BYTES or total_body + len(raw) > MAX_TOTAL_BODY_BYTES:
                                row["body_state"] = "over_limit"
                                gap("body_budget_exceeded")
                            else:
                                total_body += len(raw)
                                row["body_state"] = "captured"
                                row["body_sha256"] = hashlib.sha256(raw).hexdigest()
                                # Reuse the static extractor without executing returned code.
                                virtual = canonical_evidence_name(location + "/response/content.body", raw)
                                if not looks_binary(raw) and entry.get("_body_content_encoding") in (None, "", "identity"):
                                    bodies[virtual] = raw
                        except (ValueError, UnicodeError, binascii.Error):
                            row["body_state"] = "decode_error"
                            gap("body_decode_error")
                else:
                    gap("body_not_exported")
                if observed is None:
                    gap("observation_time_missing")
                if not row["response_recorded"]:
                    gap("response_not_recorded")
                if entry.get("_body_content_encoding") not in (None, "", "identity"):
                    gap("content_encoding_not_decoded")
                    if row["body_state"] == "captured":
                        row["body_state"] = "captured_encoded"
                if entry.get("_body_truncated") is True:
                    gap("exported_body_truncated")
                    if row["body_state"] == "captured":
                        row["body_state"] = "captured_truncated"
                records.append(row)
        if bodies:
            body_result = EndpointsAnalyzer().analyze(WebContext(ctx.config, files=bodies))
            if body_result.error:
                gap("body_analysis_failed")
            for endpoint in body_result.endpoints:
                for evidence in endpoint.evidences:
                    evidence.source = "web"
                result.endpoints.append(endpoint)
        result.endpoints.extend(collector.endpoints({"url": 0, "domain": 1, "ip": 2}))
        failed = gaps.get("invalid_har_json", 0) + gaps.get("missing_entries", 0)
        if failed:
            result.meta["web_har_read_failed"] = int(result.meta.get("web_har_read_failed", 0)) + failed
        if gaps.get("entry_budget_exceeded") or gaps.get("body_budget_exceeded"):
            result.meta["web_har_items_truncated"] = gaps.get("entry_budget_exceeded", 0) + gaps.get("body_budget_exceeded", 0)
        if gaps.get("exported_body_truncated"):
            result.meta["web_har_content_truncated"] = gaps["exported_body_truncated"]
        result.meta["web_har_records"] = records
        result.meta["web_har_summary"] = {
            "examined_entries": examined, "processed_entries": len(records), "decoded_body_bytes": total_body,
            "gaps": dict(sorted(gaps.items())), "complete_export_verified": False,
            "network_requests": 0, "target_app_attribution_verified": False,
        }
        return result
