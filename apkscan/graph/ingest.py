"""把分析报告摄入案件图谱。

约束 C8：摄入**绝不**另写指纹抽取逻辑，统一复用 `correlate.extract_fingerprints` 作为唯一
连边真相源（kind 口径与单批聚类完全一致）。

never-throw 边界（约束 C9 / 项目铁律）：
- 坏 / 残缺 report（缺 sha256、meta 非 dict、指纹值异常）→ log warning + 跳过该份，不抛。
- 但 kuzu 缺失（ImportError）属基础设施缺失，**不当坏报告吞**——上抛给调用方统一处理
  （CLI 提示安装；batch info 跳过且仍成功）。
"""

from __future__ import annotations

import logging

from apkscan.dynamic.correlate import extract_fingerprints
from apkscan.graph.store import GraphStore
from apkscan.graph.weight import get_weight

logger = logging.getLogger(__name__)


def ingest_report(
    report_dict: dict,
    store: GraphStore,
    *,
    report_path: str = "",
    sha256: str = "",
) -> bool:
    """把一份 report.json 解析出的 dict 摄入图谱。返回是否成功摄入。

    Args:
        report_dict: report.json 反序列化后的 dict。
        store: 目标图谱。
        report_path: 主报告路径（溯源用，可空）。
        sha256: APK 内容 sha256 覆盖值。batch 路径传 entry["sha256"]（已算好），
            避免依赖 ``meta.sample_sha256``（仅 analyze 路径设、auto 路径可能没有）。
    """
    try:
        # 非 dict / None 等坏输入由外层 except 兜（AttributeError → log+跳过）。
        meta = report_dict.get("meta")
        if not isinstance(meta, dict):
            meta = {}

        sha = str(sha256 or meta.get("sample_sha256") or "").strip()
        if not sha:
            logger.warning("[graph] report 缺 sha256（meta.sample_sha256 / 入参均空），跳过：%s", report_path)
            return False

        package = str(meta.get("package_name") or report_dict.get("package_name") or "")
        label = str(meta.get("app_label") or meta.get("label") or report_dict.get("app_label") or "")
        sign_sha256 = str(meta.get("sign_sha256") or "")
        sign_subject = str(meta.get("sign_subject") or "")

        store.upsert_apk(
            sha,
            package=package,
            label=label,
            sign_sha256=sign_sha256,
            sign_subject=sign_subject,
            report_path=report_path,
        )

        for fp in extract_fingerprints(report_dict):
            kind = str(fp.kind)
            value = str(fp.value)
            if not value:
                continue
            store.upsert_entity(kind, value)
            store.link(sha, kind, value, weight=get_weight(kind))
        return True
    except ImportError:
        # kuzu 未装：基础设施缺失，交上层统一处理，不当坏报告吞掉。
        raise
    except Exception:
        logger.warning("[graph] 摄入报告异常（已隔离跳过）：%s", report_path, exc_info=True)
        return False


def ingest_batch(analyzed: list[dict], store: GraphStore) -> dict:
    """逐条遍历 batch 的 ``analyzed`` 列表，复用 batch 既有主报告定位（不裸 glob），逐份摄入。

    Args:
        analyzed: batch ``run_folder`` 产出的 analyzed 列表，每项含 ``report_paths`` / ``sha256``。
        store: 目标图谱。

    Returns:
        ``{"ingested": int, "failed": int, "errors": list[str]}``。
    """
    from apkscan.dynamic.batch import _load_main_report  # 懒导入避免循环依赖

    ingested = 0
    failed = 0
    errors: list[str] = []

    for entry in analyzed or []:
        name = str(entry.get("apk") or entry.get("sha256") or "")
        report_paths = entry.get("report_paths") or []
        rep = _load_main_report(report_paths)
        if rep is None:
            failed += 1
            errors.append(name)
            continue
        main_path = next(
            (p for p in report_paths if p.lower().endswith(".json") and "runtime_report" not in p.lower()),
            "",
        )
        if ingest_report(
            rep, store, report_path=main_path, sha256=str(entry.get("sha256") or "")
        ):
            ingested += 1
        else:
            failed += 1
            errors.append(name)

    return {"ingested": ingested, "failed": failed, "errors": errors}
