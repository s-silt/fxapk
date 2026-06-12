"""apkscan.report.ioc — 把 report.json 的 leads 扁平成 IOC 行，导出 CSV。

目的：让调证线索能进 MISP / i2 / Maltego 做**跨案碰撞**。fxapk 自有的 HTML/JSON/PDF
是给人看的自定义 schema，无法直接喂情报平台；本模块产出零依赖、零风险的扁平 CSV。

铁律（与 report/json.py 一致）：纯函数层**禁** print/typer，对坏输入容错返回空/留空，
**绝不抛**。唯一打印的地方是 cli 的 export 命令。

列设计（9 列）::

    type,value,subject,where_to_request,advice,confidence,is_c2,sample_sha256,source

  - type            = Lead.category（DOMAIN/PAYMENT/CONFIG_KEY/CONTACT/CHANNEL…）
  - value/subject/where_to_request/advice = Lead 对应字段（None → 空串）
  - confidence      = Lead.confidence 枚举值字符串（report.json 已序列化为 "HIGH" 等）
  - is_c2           = Lead 的 is_c2 派生标注（report.json 的 Lead dict 已含该字段，直接读）
  - sample_sha256   = report["meta"]["sample_sha256"]（取证完整性功能将来才写，取不到留空）
  - source          = Lead.source_refs 第一个 Evidence 的 "source:location"（无则空）

保守映射：默认导出**全部** leads，但如实带 advice 列，让下游能按「建议调证」自行过滤；
``only_investigate=True`` 时只导 advice=建议调证 的（默认 False 全导）。
"""

from __future__ import annotations

import csv
import logging
from typing import Any

logger = logging.getLogger(__name__)

# CSV 列顺序（DictWriter 表头）。改这里即改导出 schema，下游平台映射依赖此顺序。
IOC_COLUMNS: list[str] = [
    "type",
    "value",
    "subject",
    "where_to_request",
    "advice",
    "confidence",
    "is_c2",
    "sample_sha256",
    "source",
]

# 研判建议中代表「应进情报平台当 IOC」的取值（only_investigate 过滤依据）。
_ADVICE_INVESTIGATE = "建议调证"


def _str_or_empty(value: Any) -> str:
    """把字段值转成字符串；None / 缺失 → 空串（CSV 列不留 None）。"""
    if value is None:
        return ""
    return str(value)


def _first_source(lead: dict[str, Any]) -> str:
    """取 Lead.source_refs 第一个 Evidence 的 "source:location"；任何异常形状 → 空串。

    source_refs 是 Evidence dict 列表（report.json 已把 dataclass 序列化为 dict）。
    容错：非 list、空、首元素非 dict、缺 source/location 键，统统返回空串，绝不抛。
    """
    refs = lead.get("source_refs")
    if not isinstance(refs, list) or not refs:
        return ""
    first = refs[0]
    if not isinstance(first, dict):
        return ""
    source = first.get("source")
    location = first.get("location")
    if not source and not location:
        return ""
    return f"{_str_or_empty(source)}:{_str_or_empty(location)}"


def _lead_to_row(lead: dict[str, Any], sample_sha256: str) -> dict[str, Any]:
    """把单条 Lead dict 映射成一行 IOC dict（列见 IOC_COLUMNS）。"""
    return {
        "type": _str_or_empty(lead.get("category")),
        "value": _str_or_empty(lead.get("value")),
        "subject": _str_or_empty(lead.get("subject")),
        "where_to_request": _str_or_empty(lead.get("where_to_request")),
        "advice": _str_or_empty(lead.get("advice")),
        "confidence": _str_or_empty(lead.get("confidence")),
        # is_c2 是 report.json 已落的派生 bool；缺失容错为 False。
        "is_c2": bool(lead.get("is_c2", False)),
        "sample_sha256": sample_sha256,
        "source": _first_source(lead),
    }


def leads_to_ioc_rows(report: dict[str, Any], only_investigate: bool = False) -> list[dict[str, Any]]:
    """把一份 report（report.json 解析结果）的 leads 映射成扁平 IOC 行。

    Args:
        report: report.json 解析出的 dict。坏输入（非 dict、缺 leads、leads 非 list、
            元素非 dict）一律容错——返回空列表或跳过坏元素，绝不抛。
        only_investigate: True 时只导 advice=建议调证 的行（默认 False 全导，但带 advice
            列让下游自行按「建议调证」过滤）。

    Returns:
        IOC 行列表，每行是列见 IOC_COLUMNS 的 dict。
    """
    if not isinstance(report, dict):
        return []

    leads = report.get("leads")
    if not isinstance(leads, list):
        return []

    # sample_sha256 容错：meta 缺失 / 非 dict / 无该键 → 空串（取证完整性功能将来才写 meta）。
    meta = report.get("meta")
    sample_sha256 = ""
    if isinstance(meta, dict):
        sample_sha256 = _str_or_empty(meta.get("sample_sha256"))

    rows: list[dict[str, Any]] = []
    for lead in leads:
        if not isinstance(lead, dict):
            continue  # 非 dict 的 lead（脏数据）跳过，不抛
        if only_investigate and lead.get("advice") != _ADVICE_INVESTIGATE:
            continue
        rows.append(_lead_to_row(lead, sample_sha256))
    return rows


def write_csv(rows: list[dict[str, Any]], path: str) -> None:
    """把 IOC 行写成 CSV 文件。

    编码：UTF-8 with BOM（``utf-8-sig``）——Excel 默认按本地代码页（中文 Windows 为 GBK）
    解 CSV，会把无 BOM 的 UTF-8 中文显示成乱码；带 BOM 则 Excel 正确识别为 UTF-8。下游
    平台（MISP/i2/pandas）读 utf-8-sig 也兼容（BOM 被当空白跳过）。

    newline=""：Python csv 模块约定，避免 Windows 下多写一个 \\r 产生空行。

    表头恒为 IOC_COLUMNS（即使 rows 为空也只写表头），保证下游 schema 稳定。绝不抛由调用
    方（cli）负责的 IO 异常——本函数只做写入。
    """
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=IOC_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
