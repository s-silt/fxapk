"""从清单里的显式进程属性给出静态覆盖诊断。

只在 android:isolatedProcess 或 android:useAppZygote 真的写在清单上时产出。
属性缺失保持未知，不按平台默认值补 false。不产生端点、发现或恶意结论。
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from apkscan.core.models import AnalyzerResult
from apkscan.core.registry import BaseAnalyzer
from apkscan.core.runtime_diagnostics import explain_coverage
from apkscan.core.xmlutil import android_attr, safe_fromstring

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_DECLARED = (
    ("isolatedProcess", "isolated_process", "isolated"),
    ("useAppZygote", "app_zygote", "app_zygote"),
)


def _parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    text = value.strip().lower()
    if text in {"true", "1"}:
        return True
    if text in {"false", "0"}:
        return False
    return None


class RuntimeDiagnosticsAnalyzer(BaseAnalyzer):
    """显式清单属性 → static-potential。没有属性就不写 meta。"""

    name = "runtime_diagnostics"
    meta_key_categories = {"runtime_diagnostics": "coverage"}
    meta_keys = frozenset(meta_key_categories)
    requires: list[str] = ["apk"]

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        xml = ctx.manifest_xml or ""
        if not xml.strip():
            return result
        try:
            root = safe_fromstring(xml)
        except Exception:
            logger.exception("runtime diagnostics manifest parse failed")
            return result
        records: list[dict[str, Any]] = []
        for service in root.findall("application/service"):
            raw_name = android_attr(service, "name")
            component = raw_name.strip() if isinstance(raw_name, str) and raw_name.strip() else "unknown"
            for attr, event, role in _DECLARED:
                declared = _parse_bool(android_attr(service, attr))
                if declared is None:
                    continue
                records.append({
                    "event": event,
                    "process_role": role,
                    "component_name": component,
                    "component_kind": "service",
                    "declared_value": declared,
                })
        if not records:
            return result
        result.meta["runtime_diagnostics"] = explain_coverage(records)
        return result
