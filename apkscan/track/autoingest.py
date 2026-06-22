"""自动入账 + 自动喂图谱的 best-effort 旁路（供 analyze / auto 静态步骤共用）。

设计 spec §4：每次产出报告后顺带把线索落进追踪台账，并把 APK/实体喂进案件图谱，
让闲置图谱随分析自然积累、支撑跨案串案。

铁律（与 ledger / graph.ingest 一致）：
- **绝不抛**给调用方：任何失败只 logging，**绝不影响主流程 / 报告产出**（旁路）。
- 台账入账失败 → warning。
- 图谱喂入失败 → warning；**kuzu 缺失（ImportError）→ 一次性 debug 提示后静默降级**
  （图谱是可选增强 extra，未装属正常）。
- 不裸 except、不在 try 里 swallow log。

两个旁路彼此独立：台账入账与图谱喂入互不阻断（一个炸了另一个照常）。
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apkscan.core.models import Report

logger = logging.getLogger(__name__)

# kuzu 缺失的 debug 提示只打一次（避免批量分析每个样本刷屏）。
_kuzu_missing_warned = False


def auto_track_and_ingest(
    report: Report,
    report_path: str,
    *,
    track: bool = True,
) -> None:
    """analyze / auto 静态步骤产出报告后调用：入台账 + 喂图谱。绝不抛。

    :param report: 内存中的 :class:`Report`（刚写出报告的同一对象）。
    :param report_path: 主报告路径（溯源用，落进台账 / 图谱）。
    :param track: 是否入账 + 喂图谱（CLI ``--no-track`` → False 时整体跳过）。
    """
    if not track:
        logger.debug("[track] --no-track：跳过自动入账与图谱喂入")
        return
    _upsert_ledger(report, report_path)
    _ingest_graph(report, report_path)


def _upsert_ledger(report: Report, report_path: str) -> None:
    """把报告 upsert 进追踪台账。失败记 warning，绝不抛（不影响报告产出）。"""
    try:
        from apkscan.track.ledger import TrackingLedger

        # TrackingLedger 构造即载入默认台账（~/.apkscan/tracking.json 或 env 覆盖），
        # upsert_report 内部已是 never-throw；此处仍包一层兜底任何意外（如构造异常）。
        TrackingLedger().upsert_report(report, report_path)
    except Exception:  # noqa: BLE001 — 入账旁路绝不抛：任何意外都 logging 后吞掉
        logger.warning("[track] 自动入账失败（已忽略，不影响报告产出）", exc_info=True)


def _ingest_graph(report: Report, report_path: str) -> None:
    """把报告喂进案件图谱。kuzu 缺失静默降级（一次性 debug）；其它失败 warning。绝不抛。"""
    global _kuzu_missing_warned
    try:
        from apkscan.graph import GraphStore, ingest_report
        from apkscan.report import json as report_json

        # Report → dict（与写出 report.json 同口径），喂图谱的 ingest_report 吃 dict。
        report_dict = report_json.to_dict(report)
        sha256 = ""
        meta = report_dict.get("meta")
        if isinstance(meta, dict):
            sha256 = str(meta.get("sample_sha256") or "")

        # kuzu 懒加载：GraphStore 构造不触发 import kuzu，首次 ingest（execute）才会。
        # ingest_report 把 kuzu 缺失的 ImportError 上抛（不当坏报告吞），在此统一降级。
        store = GraphStore()
        try:
            ingest_report(report_dict, store, report_path=report_path, sha256=sha256)
        finally:
            store.close()
    except ImportError:
        # kuzu 未装：可选 extra 缺失属正常，静默降级（仅一次 debug 提示，不刷屏）。
        if not _kuzu_missing_warned:
            _kuzu_missing_warned = True
            logger.debug("[graph] kuzu 未安装，跳过自动喂图谱（pip install kuzu==0.11.3 启用）")
    except Exception:  # noqa: BLE001 — 图谱喂入旁路绝不抛：任何意外都 logging 后吞掉
        logger.warning("[graph] 自动喂图谱失败（已忽略，不影响报告产出）", exc_info=True)
