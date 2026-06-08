"""apkscan.dynamic.merge — 把 capture 抓到的运行时端点并回主 Report。

目标：让 ``capture.run`` 抓到的运行时端点（真·C2 / 资金回调 / 配置拉取地址）从游离
的 ``runtime_report.json`` 进入主 ``Report.endpoints`` 与线索清单，并重渲
``report.html`` / ``report.json``，使其与静态端点享受同一套去重 / infra 分级 / 报告渲染，
而不是孤立躺在动态产物里被下游忽略。

放置说明：本模块归 ``dynamic`` 而非 ``report``——它依赖 pipeline 的端点去重与 infra
分级，属"动态补全编排"而非纯渲染；``report/`` 保持纯渲染职责。cli ``analyze --dynamic``
在 capture status==done 后调 :func:`merge_and_rerender`。

设计铁律（与 dynamic.__init__ / capture / pipeline 一致）：
- 纯逻辑、结构化返回（dict），**绝不把异常抛给调用方**（内部 try/except + logging）。
- 不静默吞错：每个 except 必 logging（warning / exception）。
- GUI-ready：耗时 / 分阶段函数接受可选 ``on_progress`` 回调上报进度（None 时 no-op）；
  本模块内**禁** print / typer.* / sys.exit / input。
- exe-ready：重渲时惰性 import ``apkscan.report.{json,html}``，容缺（缺失/异常不致命）。
- 全量 type hints；复用 pipeline 的 ``_dedup_endpoints`` / ``build_endpoint_leads`` /
  ``_apply_default_advice`` 保证与静态侧零行为偏移（由本模块测试锁定）。
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from apkscan.core import pipeline
from apkscan.core.models import Endpoint, Evidence, Report

logger = logging.getLogger(__name__)

# 运行时端点 / 证据的来源标记（与 capture._collect_flow_endpoints / models.Evidence 约定一致）。
_RUNTIME_SOURCE = "runtime"

# 重渲支持的报告格式（默认全产出，覆盖 analyze 首次写出的静态报告）。
_DEFAULT_FORMATS = ["html", "json"]


def _emit(on_progress: Callable[[str], None] | None, msg: str) -> None:
    """向可选进度回调上报一条消息（None 时 no-op）。

    回调异常一律吞掉 + logging，防止 GUI 端的回调实现炸穿动态内核。
    """
    if on_progress is None:
        return
    try:
        on_progress(msg)
    except Exception:  # noqa: BLE001 - GUI 回调异常不得影响合并逻辑
        logger.exception("on_progress 回调异常（已忽略）：%s", msg)


def load_runtime_endpoints(runtime_report_path: str) -> list[Endpoint]:
    """从 capture 写出的 ``runtime_report.json`` 重建运行时端点列表。

    capture 仍只返回 DynamicResult 五字段契约（不带 Endpoint 对象），cli 在 capture
    status==done 后调本函数把 ``runtime_report.json`` 的 ``endpoints`` 数组还原为
    ``list[Endpoint]``，再交 :func:`merge_runtime_endpoints` 并入——这样无需改动
    capture 的 DynamicResult 契约即可拿到运行时端点。

    Args:
        runtime_report_path: capture 产出的 runtime_report.json 路径。

    Returns:
        重建出的运行时 Endpoint 列表；文件缺失 / JSON 解析失败 / 结构异常 → ``[]``
        （记 logging，绝不抛）。每个 Endpoint 的 evidences 强制 source="runtime"。
    """
    import json
    from pathlib import Path

    path = Path(runtime_report_path)
    if not path.exists():
        logger.info("[merge] runtime 报告不存在，无运行时端点可并入：%s", path)
        return []

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        logger.exception("[merge] 读取/解析 runtime 报告失败：%s", path)
        return []

    raw_endpoints = payload.get("endpoints") if isinstance(payload, dict) else None
    if not isinstance(raw_endpoints, list):
        logger.warning("[merge] runtime 报告无 endpoints 数组或类型异常：%s", path)
        return []

    endpoints: list[Endpoint] = []
    for item in raw_endpoints:
        ep = _endpoint_from_jsonable(item)
        if ep is not None:
            endpoints.append(ep)
    logger.info("[merge] 从 runtime 报告重建运行时端点 %d 个：%s", len(endpoints), path)
    return endpoints


def _endpoint_from_jsonable(item: Any) -> Endpoint | None:
    """把单条序列化端点（dict）还原成 Endpoint；结构异常 → None（不抛）。"""
    if not isinstance(item, dict):
        logger.warning("[merge] 跳过非 dict 的端点条目：%r", type(item).__name__)
        return None
    try:
        value = item.get("value")
        kind = item.get("kind")
        if not isinstance(value, str) or not value:
            logger.warning("[merge] 端点缺少有效 value，跳过：%r", item)
            return None
        if not isinstance(kind, str) or not kind:
            kind = "url"

        evidences = _evidences_from_jsonable(item.get("evidences"), value)
        enrichment = item.get("enrichment")
        return Endpoint(
            value=value,
            kind=kind,
            evidences=evidences,
            is_cleartext=bool(item.get("is_cleartext", False)),
            is_private=bool(item.get("is_private", False)),
            is_suspicious=bool(item.get("is_suspicious", False)),
            enrichment=dict(enrichment) if isinstance(enrichment, dict) else {},
        )
    except Exception:  # noqa: BLE001 - 单条端点还原失败不应中断整体
        logger.exception("[merge] 还原端点失败，跳过：%r", item)
        return None


def _evidences_from_jsonable(raw: Any, value: str) -> list[Evidence]:
    """还原 evidences 列表，强制 source="runtime"；缺失则合成一条最小 runtime 证据。"""
    evidences: list[Evidence] = []
    if isinstance(raw, list):
        for ev in raw:
            if not isinstance(ev, dict):
                continue
            evidences.append(
                Evidence(
                    # 来源统一钉为 runtime：哪怕原 JSON 写串了，并入主报告也应标运行时。
                    source=_RUNTIME_SOURCE,
                    location=str(ev.get("location", "")),
                    snippet=str(ev.get("snippet", "")),
                )
            )
    if not evidences:
        evidences.append(Evidence(source=_RUNTIME_SOURCE, location="runtime_report.json", snippet=value))
    return evidences


def _force_runtime_source(endpoints: list[Endpoint]) -> None:
    """就地确保运行时端点的每条 evidence source="runtime"（合并语义靠 source 区分来源）。"""
    for ep in endpoints:
        for ev in ep.evidences:
            if ev.source != _RUNTIME_SOURCE:
                ev.source = _RUNTIME_SOURCE


def merge_runtime_endpoints(report: Report, endpoints: list[Endpoint]) -> dict[str, int]:
    """把运行时端点去重并入 ``report.endpoints``，对新引入的 domain/ip 生成线索。

    就地修改 ``report``（不重渲——重渲交 :func:`merge_and_rerender`）。合并语义完全复用
    pipeline 的 ``_dedup_endpoints``，与静态侧一致：

    1. 运行时 evidence 强制 source="runtime"。
    2. ``_dedup_endpoints(report.endpoints + endpoints)`` 去重合并：evidences 按
       (source, location, snippet) 去重并集、is_cleartext/is_private/is_suspicious 取 OR、
       enrichment 浅合并、kind 首现为准、保持首现顺序；写回 report.endpoints。运行时端点
       value 已被静态端点覆盖时，runtime evidence 并进同一 Endpoint（一端点同时带 dex+runtime）。
    3. 对"仅由运行时引入、静态未覆盖"的 domain/ip 端点调 ``build_endpoint_leads``，advice 由
       ``infra.classify_domain`` 分级（未命中 KNOWN_INFRA 的疑似 App 自有服务 → 建议调证）；
       按已有 leads 的 {(category.value, value)} 去重后 append。
    4. ``_apply_default_advice`` 兜底新 leads 的空 advice。
    5. meta 打标 runtime_merged / runtime_endpoint_count。

    Args:
        report: 主报告（静态产出），就地被修改。
        endpoints: 运行时端点（通常来自 :func:`load_runtime_endpoints`）。

    Returns:
        统计 dict ``{"merged", "new_leads", "total_endpoints"}``。内部 try/except，
        异常时返回零统计 + logging，绝不抛。
    """
    stats = {"merged": 0, "new_leads": 0, "total_endpoints": len(report.endpoints)}
    try:
        runtime_count = len(endpoints)
        _force_runtime_source(endpoints)

        # 合并前快照：用于判定哪些 value 是"仅运行时引入"（静态未覆盖）。
        static_values = {ep.value for ep in report.endpoints}

        before = len(report.endpoints)
        merged_endpoints = pipeline._dedup_endpoints(report.endpoints + endpoints)
        report.endpoints = merged_endpoints
        stats["total_endpoints"] = len(merged_endpoints)
        # "并入"计数：合并后净增的端点数（运行时端点中静态未覆盖、且彼此去重后的新 value）。
        stats["merged"] = max(0, len(merged_endpoints) - before)

        # 仅对"运行时引入且静态未覆盖"的 domain/ip 生成线索，避免与静态线索重复。
        runtime_only = [
            ep for ep in merged_endpoints if ep.value not in static_values
        ]
        new_leads = _build_runtime_leads(report, runtime_only)
        stats["new_leads"] = new_leads

        report.meta["runtime_merged"] = True
        report.meta["runtime_endpoint_count"] = runtime_count
        logger.info(
            "[merge] 运行时端点并入完成：merged=%d new_leads=%d total=%d",
            stats["merged"],
            stats["new_leads"],
            stats["total_endpoints"],
        )
    except Exception:  # noqa: BLE001 - 合并失败不得抛给调用方（不破坏已产出静态报告）
        logger.exception("[merge] 运行时端点并入异常")
    return stats


def _build_runtime_leads(report: Report, runtime_only: list[Endpoint]) -> int:
    """对仅运行时引入的端点生成 DOMAIN/IP 线索并去重 append 进 report.leads，返回新增数。"""
    # 已有 leads 的去重键集合：(category.value, value)。
    existing_keys: set[tuple[str, str]] = {
        (lead.category.value, lead.value) for lead in report.leads
    }
    candidate_leads = pipeline.build_endpoint_leads(
        runtime_only, online=report.meta.get("online", True)
    )
    new_leads: list = []
    for lead in candidate_leads:
        key = (lead.category.value, lead.value)
        if key in existing_keys:
            continue
        existing_keys.add(key)
        new_leads.append(lead)

    # 兜底新 leads 的空 advice（DOMAIN/IP 的 advice 已由 build_endpoint_leads 按 infra 分级）。
    pipeline._apply_default_advice(new_leads)
    report.leads.extend(new_leads)
    return len(new_leads)


def merge_and_rerender(
    report: Report,
    endpoints: list[Endpoint],
    out_dir: str,
    *,
    formats: list[str] | None = None,
    on_progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """并入运行时端点后按 ``formats`` 重渲报告，覆盖 ``out_dir`` 下的首次产出。

    供 cli ``analyze --dynamic`` 在 capture 后调用：先 :func:`merge_runtime_endpoints`
    就地补全 report，再惰性 import ``apkscan.report.{json,html}`` 覆盖写
    ``out_dir/report.{json,html}``，使真·C2 进入主线索清单与报告。

    Args:
        report: 主报告，就地被修改。
        endpoints: 运行时端点。
        out_dir: 报告输出目录（与 analyze 首次写出一致）。
        formats: 要重渲的格式，默认 ``["html", "json"]``。
        on_progress: 可选进度回调。

    Returns:
        在 :func:`merge_runtime_endpoints` 统计基础上加 ``"report_paths"``（成功重渲的
        报告路径列表；单格式失败不计入、不致命）。绝不抛。
    """
    from pathlib import Path

    _emit(on_progress, "并入运行时端点 ...")
    stats: dict[str, Any] = dict(merge_runtime_endpoints(report, endpoints))

    fmts = list(formats) if formats else list(_DEFAULT_FORMATS)
    out_path = Path(out_dir)
    try:
        out_path.mkdir(parents=True, exist_ok=True)
    except OSError:
        logger.exception("[merge] 创建输出目录失败：%s", out_dir)

    report_paths: list[str] = []
    if "json" in fmts:
        json_path = _rerender_json(report, out_path, on_progress)
        if json_path:
            report_paths.append(json_path)
    if "html" in fmts:
        html_path = _rerender_html(report, out_path, on_progress)
        if html_path:
            report_paths.append(html_path)

    stats["report_paths"] = report_paths
    return stats


def _rerender_json(report: Report, out_path: Any, on_progress: Callable[[str], None] | None) -> str:
    """惰性 import report.json 并覆盖写 report.json；失败记 logging 返回空串（不致命）。"""
    target = out_path / "report.json"
    _emit(on_progress, "重渲 report.json ...")
    try:
        from apkscan.report import json as report_json

        report_json.dump(report, str(target))
    except Exception:  # noqa: BLE001 - 单格式重渲失败不致命，不计入 report_paths
        logger.exception("[merge] 重渲 report.json 失败：%s", target)
        return ""
    return str(target)


def _rerender_html(report: Report, out_path: Any, on_progress: Callable[[str], None] | None) -> str:
    """惰性 import report.html 并覆盖写 report.html；失败记 logging 返回空串（不致命）。"""
    target = out_path / "report.html"
    _emit(on_progress, "重渲 report.html ...")
    try:
        from apkscan.report import html as report_html

        report_html.render(report, str(target))
    except Exception:  # noqa: BLE001 - 单格式重渲失败不致命，不计入 report_paths
        logger.exception("[merge] 重渲 report.html 失败：%s", target)
        return ""
    return str(target)


__all__ = [
    "load_runtime_endpoints",
    "merge_runtime_endpoints",
    "merge_and_rerender",
]
