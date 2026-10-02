"""Decode escaped URL literals in static JSON configurations, without eval."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from apkscan.analyzers._common import EndpointCollector
from apkscan.analyzers.endpoints import EndpointsAnalyzer
from apkscan.core.json_contract import reject_nonfinite_json_constant
from apkscan.core.models import AnalyzerResult
from apkscan.core.registry import BaseAnalyzer

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

MAX_FILES = 100
MAX_BYTES = 1024 * 1024
MAX_NODES = 10000
MAX_LITERAL = 8192


class JsonEndpointAnalyzer(BaseAnalyzer):
    name = "json_endpoints"
    requires: list[str] = []
    meta_key_categories = {"json_endpoint_coverage": "coverage",
                           "json_endpoints_read_failed": "coverage",
                           "json_endpoints_budget_exhausted": "coverage",
                           "json_endpoints_files_truncated": "coverage"}
    meta_keys = frozenset(meta_key_categories)

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        counters = {"files_examined": 0, "decoded_url_literals": 0,
                    "read_failed": 0, "invalid_json": 0, "over_limit": 0, "deferred_files": 0}
        collector = EndpointCollector()
        scanner = EndpointsAnalyzer()
        scanner._tier_context = "web" if ctx.platform == "web" else "apk"
        rules = scanner._load_rules()
        try:
            paths = sorted(p for p in ctx.list_files() if isinstance(p, str) and p.lower().endswith(".json"))
        except Exception:  # noqa: BLE001 - preserve the failure as coverage data
            counters["read_failed"] += 1
            paths = []
        for path in paths:
            if counters["files_examined"] >= MAX_FILES:
                counters["deferred_files"] += 1
                continue
            counters["files_examined"] += 1
            try:
                size = ctx.declared_size(path)
                if size is not None and size > MAX_BYTES:
                    counters["over_limit"] += 1
                    continue
                raw = ctx.read_file(path)
                if not isinstance(raw, bytes):
                    counters["read_failed"] += 1
                    continue
                if len(raw) > MAX_BYTES:
                    counters["over_limit"] += 1
                    continue
                if b"\\/" not in raw and b"\\u" not in raw:
                    continue  # Plain literals are already handled by endpoints.
                tree = json.loads(raw, parse_constant=reject_nonfinite_json_constant)
            except (ValueError, UnicodeError, RecursionError):
                counters["invalid_json"] += 1
                continue
            except Exception:  # noqa: BLE001 - coverage must expose context I/O failures
                counters["read_failed"] += 1
                continue
            pending = [("", tree)]
            visited = 0
            while pending:
                if visited >= MAX_NODES:
                    counters["over_limit"] += 1
                    break
                pointer, value = pending.pop()
                visited += 1
                if isinstance(value, dict):
                    remaining = max(0, MAX_NODES - visited - len(pending))
                    if len(value) > remaining:
                        counters["over_limit"] += 1
                    from itertools import islice
                    for key, item in reversed(list(islice(value.items(), remaining))):
                        token = key.replace("~", "~0").replace("/", "~1")
                        pending.append((pointer + "/" + token, item))
                elif isinstance(value, list):
                    remaining = max(0, MAX_NODES - visited - len(pending))
                    if len(value) > remaining:
                        counters["over_limit"] += 1
                    for index in reversed(range(min(len(value), remaining))):
                        pending.append((pointer + "/" + str(index), value[index]))
                elif isinstance(value, str) and any(s in value for s in ("http://", "https://", "ws://", "wss://")):
                    if len(value) > MAX_LITERAL:
                        counters["over_limit"] += 1
                        continue
                    counters["decoded_url_literals"] += 1
                    scanner._scan_text(value, "web" if ctx.platform == "web" else "resource",
                                       path + "#" + pointer + " (JSON-decoded)",
                                       collector, rules, bulk_len=len(value))
        result.endpoints = collector.endpoints({"url": 0, "domain": 1, "ip": 2})
        if counters["read_failed"] or counters["invalid_json"]:
            result.meta["json_endpoints_read_failed"] = counters["read_failed"] + counters["invalid_json"]
        if counters["over_limit"]:
            result.meta["json_endpoints_budget_exhausted"] = True
        if counters["deferred_files"]:
            result.meta["json_endpoints_files_truncated"] = counters["deferred_files"]
        result.meta["json_endpoint_coverage"] = counters
        return result
