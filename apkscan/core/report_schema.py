"""report.json 版本识别与确定性迁移。

读旧版可以迁移；未知未来版不得进入 typed/mutating 路径，避免 ``case close`` 用旧模型原地
改写新格式。只读消费者仍可先用 :func:`report_schema_info` 给出版本提示。
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Mapping

from apkscan.core.models import EvidenceScope, REPORT_SCHEMA_VERSION

META_WRITE_OWNER = "core.report_schema"
META_WRITE_CATEGORIES = {
    "report_schema_origin": "record",
}
META_WRITE_KEYS = frozenset(META_WRITE_CATEGORIES)

SUPPORTED_REPORT_SCHEMAS: tuple[str, ...] = ("1.0", "1.1", REPORT_SCHEMA_VERSION)


class UnsupportedReportSchema(ValueError):
    """报告版本不是当前 typed model 能安全解释的版本。"""


@dataclass(frozen=True)
class ReportSchemaInfo:
    source_version: str
    current_version: str
    supported: bool
    needs_migration: bool
    warnings: tuple[str, ...] = ()


def _version(payload: Mapping[str, object]) -> tuple[str, tuple[str, ...]]:
    raw = payload.get("schema_version")
    if raw is None or not str(raw).strip():
        return "1.0", ("报告未记录 schema_version，按 legacy 1.0 读取",)
    return str(raw).strip(), ()


def report_schema_info(payload: Mapping[str, object]) -> ReportSchemaInfo:
    version, warnings = _version(payload)
    supported = version in SUPPORTED_REPORT_SCHEMAS
    if not supported:
        warnings += (f"不支持的 report schema：{version}",)
    return ReportSchemaInfo(
        source_version=version,
        current_version=REPORT_SCHEMA_VERSION,
        supported=supported,
        needs_migration=supported and version != REPORT_SCHEMA_VERSION,
        warnings=warnings,
    )


def _scope(value: object) -> str:
    allowed = {item.value for item in EvidenceScope}
    if isinstance(value, EvidenceScope):
        return value.value
    # Protocol enum tokens are exact.  Trimming a malformed persisted value
    # would silently promote ``" case_evidence "`` to direct evidence.
    text = value if isinstance(value, str) else ""
    if text in allowed:
        return text
    # 缺失/坏值都不能被自动提升为当前案件直接证据；即使自称 1.2 也按不可信输入降级。
    return EvidenceScope.LEGACY_UNSPECIFIED.value


def _migrate_evidence_list(value: object) -> None:
    if not isinstance(value, list):
        return
    for item in value:
        if isinstance(item, dict):
            item["scope"] = _scope(item.get("scope"))


def _items(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def migrate_report_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """迁移到当前模型；未知未来版 fail-closed，输入对象不被原地修改。"""
    info = report_schema_info(payload)
    if not info.supported:
        raise UnsupportedReportSchema(
            f"unsupported report schema {info.source_version}; current={REPORT_SCHEMA_VERSION}"
        )
    out = deepcopy(dict(payload))
    for item in _items(out.get("leads")):
        if isinstance(item, dict):
            _migrate_evidence_list(item.get("source_refs"))
    for item in _items(out.get("endpoints")):
        if isinstance(item, dict):
            _migrate_evidence_list(item.get("evidences"))
    for item in _items(out.get("findings")):
        if isinstance(item, dict):
            _migrate_evidence_list(item.get("evidences"))
    out["schema_version"] = REPORT_SCHEMA_VERSION
    if info.needs_migration or info.warnings:
        meta = out.get("meta")
        meta = dict(meta) if isinstance(meta, Mapping) else {}
        meta["report_schema_origin"] = info.source_version
        out["meta"] = meta
    return out


def ensure_writable_report_version(version: object) -> None:
    """Report dataclass 落盘前只允许当前/可迁移旧版，拒绝未知未来版本。"""
    text = str(version).strip() if version is not None else "1.0"
    if text not in SUPPORTED_REPORT_SCHEMAS:
        raise UnsupportedReportSchema(
            f"unsupported report schema {text}; refusing to overwrite with {REPORT_SCHEMA_VERSION}"
        )


__all__ = [
    "ReportSchemaInfo",
    "SUPPORTED_REPORT_SCHEMAS",
    "UnsupportedReportSchema",
    "ensure_writable_report_version",
    "migrate_report_payload",
    "report_schema_info",
]
