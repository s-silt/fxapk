"""联网富化执行：两遍富化编排、主动/被动门控、富化器→端点调用与统计聚合。

从 pipeline.py 物理拆出（纯搬移、逻辑不变）：这一簇负责挑「建议调证」端点、按端点并发跑富化器、
两遍（归属→定辖区→境外被动取证）编排、以及 --mode 的主动/被动门控。pipeline 在 _stage_enrich
里调用 _enrichment_targets / _run_enrichment / _mode_gate。
"""

from __future__ import annotations

import json
import logging
import math
import os
import threading
import requests
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

from apkscan.core import forensic, infra
from apkscan.core.models import (
    ANALYSIS_MODE_AUTHORIZED_ACTIVE,
    ANALYSIS_MODE_PASSIVE,
    Endpoint,
    EnrichmentResult,
)
from apkscan.core.registry import BaseEnricher
from apkscan.core.source_status import provider_payload_if_hit

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


#: 富化并发度：按端点并发跑富化器（I/O 密集，瓶颈是 whois/rdap 的 ~30s 超时串行累加）。
#: 默认 8 个 worker。每个端点由单一 worker 串行跑其匹配的全部富化器，故同一 ep.enrichment
#: 无并发写竞争；只有跨端点共享的 provider 统计需加锁聚合。
ENRICH_MAX_WORKERS = 8


class ProviderResponseError(RuntimeError):
    """Sanitized marker for provider-declared errors in HTTP 200 responses."""


def _http_status_code(exc: Exception) -> int | None:
    """取异常携带的 HTTP 状态码；无则 None。

    ``not isinstance(value, bool)``：``bool`` 是 ``int`` 子类，某些 mock 会把
    ``status_code`` 设成 True/False，不排掉会变成 ``http_True``。
    """
    response = getattr(exc, "response", None)
    value = getattr(response, "status_code", None)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def safe_error_type(exc: Exception) -> str:
    """把富化失败归成**稳定、可公开**的分类码。

    富化器的异常来自联网查第三方 API，消息里可能夹带完整 URL（含 API key）、
    响应正文、代理地址。落进 ``EnrichmentResult.error`` 就会进报告 JSON 与
    ``enricher_status``，因此对外只给分类码，异常原文留日志。

    分类顺序有意义，勿调换：``UnicodeError`` 是 ``ValueError`` 子类，但语义是**请求侧**
    编码失败（如非 latin-1 的 key/header 塞进 HTTP 头），不是响应解析失败——放到
    ``ValueError`` 之后会误报成 ``parse_error``，把病根指向错误方向。
    """
    status_code = _http_status_code(exc)
    if status_code is not None:
        return f"http_{status_code}"
    if isinstance(exc, requests.Timeout):
        return "timeout"
    # 内置 TimeoutError（socket.timeout 在 3.10+ 就是它的别名）也归 timeout：
    # 富化器既有走 requests 的，也有走 socket / DoH 的，两条路的超时对调用方是同一件事。
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, ProviderResponseError):
        return "provider_response_error"
    if isinstance(exc, UnicodeError):
        return "request_encoding_error"
    if isinstance(exc, ValueError):
        return "parse_error"
    return type(exc).__name__


def _enrichment_targets(endpoints: list[Endpoint]) -> list[Endpoint]:
    """筛出"高度可疑"端点（域名/IP 且 infra 分级为"建议调证"）作为联网富化目标。

    只对疑似 App 自有服务/C2 的域名/IP 查 WHOIS/ICP/ASN；已知第三方基础设施/SDK/CDN
    （无需调证）、私网/回环 IP / 行情代码伪域名（待核）都不查。这正是"最后只对高度可疑的查、
    而不是有一个查一个"：省时（网络受限不被 infra 域名拖死、不误查 127.0.0.1）+ 聚焦调证。

    ★域名走 :func:`infra.effective_advice` 而不是裸 ``classify_domain``：后者不叠加来源可信度
      档（``tier``），于是「仅见于第三方库文件 / 超大字符串表、终判已被压到待核」的端点在这里
      仍被算成最高档、照样发起联网查询。``effective_advice`` 的 docstring 自己写着「目标筛选
      须与最终 Lead 研判用同一套判据，避免判据漂移」——这一行此前正是它要防的那种漂移。
      tier 由 analyze 阶段的抽取器写进 ``enrichment``、``_dedup_endpoints`` 合并，本函数跑在
      enrich 阶段，读得到。

    ★**IP 必须走 IP 判据**，不能跟着域名一起走 ``effective_advice``——那是域名接口（内部调
      ``classify_domain`` 并叠 tier 降档），拿它判 IP 会造出新的漂移：一个带 library-file tier
      的公网 IP 会在这里被压成待核、不再富化，而它最终的 Lead 走 ``classify_ip``、很可能仍是
      最高档，于是「该核查的 IP 却没有 ASN/RDAP 富化结果」。tier 的生产侧也没有从模型上限制
      只写给域名，指望它对 IP 恒为 None 是靠不住的。
    """
    targets: list[Endpoint] = []
    for ep in endpoints:
        if ep.kind == "domain":
            advice = infra.effective_advice(ep.value, ep.enrichment.get("tier"))
        elif ep.kind == "ip":
            advice, _reason = infra.classify_ip(ep.value)
        else:
            continue  # 非 domain/ip 本就不被 WHOIS/ICP/ASN 路由
        if advice == infra.ADVICE_INVESTIGATE:
            targets.append(ep)
    return targets


def _enrich_endpoints(
    endpoints: list[Endpoint],
    enrichers: list[BaseEnricher],
    *,
    gate: "Callable[[Endpoint, BaseEnricher], bool] | None" = None,
) -> list[dict]:
    """对每个端点按 applies_to 跑匹配的富化器，结果写入 endpoint.enrichment[provider]。

    ``gate``（可选）：额外的 (端点, 富化器)→bool 谓词，返回 False 则跳过该富化器（不计入统计）。
    不传则对匹配 applies_to 的富化器全跑（向后兼容；本仓当前富化器全部为被动，对目标零流量）。

    按端点并发（``ThreadPoolExecutor``，worker 数 = ``ENRICH_MAX_WORKERS``）：富化是
    I/O 密集（whois/rdap 单次可达 ~30s 超时），串行双重循环单包可达 7 分钟，按端点并发
    把这些超时叠在一起跑而非顺序累加。

    并发不变量：
    - 每个端点由**单一** worker 串行跑其匹配的全部富化器 → 同一 ``ep.enrichment``
      无并发写竞争；端点之间互不共享 enrichment dict。
    - ``endpoints`` 列表**原地不动、顺序不变**（只就地写 ``ep.enrichment``，绝不重排）。
    - 跨端点共享的 provider 统计用锁聚合，``attempted/ok/failed/typical_error`` 准确。
    - ip-api 免费档限速由 ``_ipinfo`` 内部的进程级线程安全限速器担保（asn 单查走 45/min·1.4s 闸、
      dns 批量走 /batch 15/min·4.0s 独立闸）——并发下仍是全局闸，本层只管并发分发。

    返回每个富化器的聚合状态 [{provider, attempted, ok, failed, typical_error}]，
    使富化器层的系统性失败（如某 provider 全部失败）在报告里透明可见，
    而非打散进各 endpoint 难以察觉。
    """
    stats: dict[str, dict] = {}
    stats_lock = threading.Lock()

    if endpoints:
        # max_workers 不超过端点数，避免端点少时空建大量线程。
        workers = max(1, min(ENRICH_MAX_WORKERS, len(endpoints)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="enrich") as pool:
            # list() 强制求值 → 任一 worker 内未捕获异常会在此重抛（_run_enrichers_on_endpoint
            # 内部已逐 enrich try/except，正常不会到这；这里是兜底，不让异常被 executor 静默吞掉）。
            list(pool.map(
                lambda ep: _run_enrichers_on_endpoint(ep, enrichers, stats, stats_lock, gate),
                endpoints,
            ))

    return list(stats.values())


def _stat(stats: dict[str, dict], provider: str) -> dict:
    """取/建某 provider 的统计条目（调用方须持 stats 的锁）。"""
    return stats.setdefault(
        provider,
        {"provider": provider, "attempted": 0, "ok": 0, "failed": 0, "typical_error": None},
    )


def _record_source_status(
    endpoint: Endpoint,
    provider: str,
    status: str,
    *,
    error_type: str | None = None,
) -> None:
    raw = endpoint.enrichment.setdefault("source_status", {})
    if not isinstance(raw, dict):
        raw = {}
        endpoint.enrichment["source_status"] = raw
    entry = {"status": status}
    if error_type:
        entry["error_type"] = error_type
    raw[provider] = entry


def _record_provider_failure(
    endpoint: Endpoint,
    provider: str,
    *,
    error_type: str,
    message: str,
) -> None:
    # A failed provider has no admissible evidence payload.  Keep only the
    # typed source outcome so stale/partial provider bytes cannot be consumed
    # later by attribution or closure code.
    endpoint.enrichment.pop(provider, None)
    _record_source_status(endpoint, provider, "failed", error_type=error_type)


def _strict_json_copy(value: object, active: set[int]) -> object:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("provider payload contains a non-finite number")
        return value
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active:
            raise ValueError("provider payload contains a reference cycle")
        active.add(identity)
        try:
            copied: dict[str, object] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise TypeError("provider payload object keys must be strings")
                copied[key] = _strict_json_copy(item, active)
            return copied
        finally:
            active.discard(identity)
    if isinstance(value, (list, tuple)):
        identity = id(value)
        if identity in active:
            raise ValueError("provider payload contains a reference cycle")
        active.add(identity)
        try:
            return [_strict_json_copy(item, active) for item in value]
        finally:
            active.discard(identity)
    raise TypeError(f"provider payload contains unsupported {type(value).__name__}")


def _strict_provider_payload(value: Mapping[object, object]) -> dict[str, object]:
    """Return an isolated strict-JSON copy of one provider-owned object.

    The round trip rejects arbitrary nested objects, non-finite floats, and
    reference cycles before provider data enters a report or batch ledger.
    """

    copied = _strict_json_copy(value, set())
    if not isinstance(copied, dict):  # pragma: no cover - Mapping input guarantees this
        raise TypeError("provider payload must encode as a JSON object")
    encoded = json.dumps(
        copied,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    decoded = json.loads(encoded)
    if not isinstance(decoded, dict):  # pragma: no cover - dict input guarantees this
        raise TypeError("provider payload must encode as a JSON object")
    return decoded


def _run_enrichers_on_endpoint(
    ep: Endpoint,
    enrichers: list[BaseEnricher],
    stats: dict[str, dict],
    stats_lock: threading.Lock,
    gate: "Callable[[Endpoint, BaseEnricher], bool] | None" = None,
) -> None:
    """对单个端点**串行**跑匹配的富化器（applies_to + gate 过滤），就地写 ep.enrichment + 聚合 stats。

    在单一 worker 内调用：同一 ep.enrichment 无并发写竞争；跨端点共享的 stats 用锁聚合。
    """
    for enricher in enrichers:
        applies_to = list(getattr(enricher, "applies_to", []) or [])
        if ep.kind not in applies_to:
            continue
        if gate is not None and not gate(ep, enricher):
            continue  # 门控谓词返回 False：跳过该富化器，不计统计
        provider = getattr(enricher, "name", "") or enricher.__class__.__name__

        with stats_lock:
            _stat(stats, provider)["attempted"] += 1

        try:
            result = enricher.enrich(ep)
        except Exception:  # noqa: BLE001 - 富化失败不阻塞主流程
            logger.exception("富化器执行异常：provider=%s endpoint=%s", provider, ep.value)
            _record_provider_failure(
                ep,
                provider,
                error_type="provider_exception",
                message="富化器异常",
            )
            with stats_lock:
                _note_fail(_stat(stats, provider), "富化器异常")
            continue

        if not isinstance(result, EnrichmentResult):
            logger.warning("富化器 %s 返回非法结果对象：%s", provider, type(result).__name__)
            _record_provider_failure(
                ep,
                provider,
                error_type="invalid_result_shape",
                message="enrich 返回非法结果对象",
            )
            with stats_lock:
                _note_fail(_stat(stats, provider), "invalid_result_shape")
            continue

        if (
            not isinstance(result.ok, bool)
            or not isinstance(result.data, Mapping)
            or (result.error is not None and not isinstance(result.error, str))
        ):
            logger.warning("富化器 %s 返回非对象 data：%s", provider, type(result.data).__name__)
            _record_provider_failure(
                ep,
                provider,
                error_type="invalid_result_data",
                message="invalid_result_data",
            )
            with stats_lock:
                _note_fail(_stat(stats, provider), "invalid_result_data")
            continue

        try:
            data = _strict_provider_payload(result.data)
        except Exception:  # noqa: BLE001 - provider-owned mapping access can raise arbitrarily
            logger.warning("富化器 %s 返回非严格 JSON data", provider)
            _record_provider_failure(
                ep,
                provider,
                error_type="invalid_result_payload",
                message="invalid_result_payload",
            )
            with stats_lock:
                _note_fail(_stat(stats, provider), "invalid_result_payload")
            continue
        if result.error:
            data.setdefault("error", result.error)
        status, error_type = _source_status_from_payload(data)
        if not result.ok and status != "failed":
            status = "failed"
            error_type = error_type or "provider_reported_failure"
        with stats_lock:
            st = _stat(stats, provider)
            if status == "hit":
                st["ok"] += 1
            elif status == "no_record":
                # 成功但零信息：显式标注，避免与"查到了"在报告里视觉混淆。
                data.setdefault("note", "查询无结果")
                _note_fail(st, "查询无结果")
            else:
                _note_fail(st, error_type or result.error or "富化失败")
        if status != "hit":
            ep.enrichment.pop(provider, None)
        else:
            ep.enrichment[provider] = data
        _record_source_status(ep, provider, status, error_type=error_type)


def _note_fail(st: dict, msg: str) -> None:
    """记一次失败到 provider 统计（调用方须持 stats_lock）。"""
    st["failed"] += 1
    if not st["typical_error"]:
        st["typical_error"] = msg


# overseas 阶段的组内顺序（确定性排序；shodan/certs 均被动、互不依赖，固定序保证串行==并行逐字节一致）。
_OVERSEAS_ORDER = {"shodan": 0, "certs": 1}


def _enricher_phase(enricher: BaseEnricher) -> str:
    """富化器阶段（缺失/空 → 默认 attribution，兼容未标 phase 的旧富化器）。"""
    return getattr(enricher, "phase", "attribution") or "attribution"


def _classify_endpoint_jurisdiction(ep: Endpoint) -> str:
    """据第①遍归属富化结果判该端点服务器辖区（国内/国外/未知）。绝不抛（失败→未知，保守）。"""
    e = ep.enrichment
    try:
        return forensic.classify_jurisdiction(
            ep.value,
            icp=provider_payload_if_hit(e, "icp"),
            rdap=provider_payload_if_hit(e, "rdap"),
            whois=provider_payload_if_hit(e, "whois"),
            dns=provider_payload_if_hit(e, "dns"),
            asn=provider_payload_if_hit(e, "asn"),
        )
    except Exception:  # noqa: BLE001 — 辖区判定失败不得炸主流程；保守判未知（宁可漏归类也不误标辖区）
        logger.debug("辖区判定失败，按未知处理：%s", ep.value, exc_info=True)
        return forensic.JURIS_UNKNOWN


def _mode_gate(mode: str) -> "Callable[[Endpoint, BaseEnricher], bool]":
    """按网络模式生成富化器门控谓词（防御纵深：真正在**调用点**拦，任何富化路径都过此闸）。

    - ``authorized-active``：全放行（含 active=True 的主动富化器）。
    - 其它（含默认 ``passive`` 及任何非法值 → 保守当被动）：只放行被动富化器（active 为假）。
    """
    if mode == ANALYSIS_MODE_AUTHORIZED_ACTIVE:
        return lambda _ep, _e: True
    return lambda _ep, enricher: not getattr(enricher, "active", False)


def _run_enrichment(
    targets: list[Endpoint],
    enrichers: list[BaseEnricher],
    gate: "Callable[[Endpoint, BaseEnricher], bool] | None" = None,
) -> list[dict]:
    """两遍富化编排（**单遍并发·每端点内两阶段**，无跨端点栅栏）：
    每个端点在自己的 worker 里串行跑 ①归属(attribution) → 定辖区 → ②境外被动取证(overseas)，
    端点之间互不等待——慢端点（如 30s WHOIS 超时）不再阻塞其它端点的第②阶段（去掉旧版两遍之间的栅栏）。

    第②遍只对【国外 + 未知】端点跑（境内走调证、不做境外取证）；overseas 富化器全部**被动**
    （shodan/certs 读公开库，对目标零流量）。辖区结果仅为 worker 内局部变量，**绝不写入 ep.enrichment**
    （避免 ``_jurisdiction`` 等内部键泄漏进 report.json）。

    ``gate=None`` **fail-closed**：缺省按 passive 门控（拦 active 富化器）。这样任何调用方（现在或
    将来）漏传 gate 都得到**安全**行为，绝不会静默把主动富化器放进被动运行。要全放行须
    显式传 ``gate=_mode_gate("authorized-active")``。
    """
    if gate is None:
        gate = _mode_gate(ANALYSIS_MODE_PASSIVE)
    attribution = [e for e in enrichers if _enricher_phase(e) == "attribution"]
    overseas = sorted(
        (e for e in enrichers if _enricher_phase(e) == "overseas"),
        key=lambda e: _OVERSEAS_ORDER.get(getattr(e, "name", ""), 0),
    )

    stats: dict[str, dict] = {}
    stats_lock = threading.Lock()

    def _enrich_one_two_phase(ep: Endpoint) -> None:
        # ① 归属富化。
        _run_enrichers_on_endpoint(ep, attribution, stats, stats_lock, gate)
        if not overseas:
            return
        # 定辖区（worker 内局部，绝不写回 ep.enrichment）。
        juris = _classify_endpoint_jurisdiction(ep)
        if juris not in (forensic.JURIS_FOREIGN, forensic.JURIS_UNKNOWN):
            return  # 境内：走调证、不做境外被动取证

        # ② 境外被动取证富化（同 worker 内串行，组内顺序由 overseas 排序保证确定性）。
        _run_enrichers_on_endpoint(ep, overseas, stats, stats_lock, gate)

    if targets:
        workers = max(1, min(ENRICH_MAX_WORKERS, len(targets)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="enrich") as pool:
            list(pool.map(_enrich_one_two_phase, targets))

    return list(stats.values())


def _provider_name(enricher: BaseEnricher) -> str:
    return getattr(enricher, "name", "") or type(enricher).__name__


def _provider_configured(enricher: BaseEnricher) -> bool:
    raw_required = getattr(enricher, "required_env", ())
    if not isinstance(raw_required, (list, tuple)):
        return True
    required = tuple(str(name) for name in raw_required if str(name))
    return not required or any((os.environ.get(name) or "").strip() for name in required)


def _source_status_from_payload(payload: object) -> tuple[str, str | None]:
    if not isinstance(payload, dict):
        return "failed", "missing_result"
    marker_missing = object()
    marker = payload.pop("_source_status", marker_missing)
    error_type = payload.pop("_error_type", None)
    # All underscore-prefixed fields are provider control/transport metadata,
    # never evidence that can turn an otherwise empty response into a hit.
    for key in tuple(payload):
        if isinstance(key, str) and key.startswith("_"):
            payload.pop(key, None)
    if marker is not marker_missing:
        if marker in {"hit", "no_record", "failed", "skipped", "disabled"}:
            return (
                str(marker),
                error_type.strip()
                if isinstance(error_type, str) and error_type.strip()
                else None,
            )
        return "failed", "invalid_source_status"
    error = str(payload.get("error") or "")
    note = str(payload.get("note") or "")
    folded = f"{error} {note}".lower()
    if error:
        if any(token in folded for token in ("无记录", "无结果", "not found", "no record", "404")):
            return "no_record", None
        return "failed", error.split(":", 1)[0][:80] or "provider_error"
    # ``_run_enrichers_on_endpoint`` adds a human-facing note to a successful
    # empty response.  That explanatory metadata is not provider evidence and
    # must not turn a no-record outcome into a hit.
    if not any(
        value not in (None, "", [], {})
        for key, value in payload.items()
        if key != "note"
    ):
        return "no_record", None
    return "hit", None


def _mark_case_close_deferred(
    endpoints: list[Endpoint], enrichers: list[BaseEnricher]
) -> None:
    """给普通解析里被 case-close 门挡下的源记 ``skipped/deferred_case_close``。

    只标**适用于该端点类型**的源（``applies_to`` 匹配），且**不覆盖**已有状态——
    本轮真跑过的结果永远优先。
    """
    deferred = [e for e in enrichers if getattr(e, "case_close_only", False)]
    if not deferred:
        return
    for endpoint in endpoints:
        source_status = endpoint.enrichment.setdefault("source_status", {})
        if not isinstance(source_status, dict):
            source_status = {}
            endpoint.enrichment["source_status"] = source_status
        for enricher in deferred:
            if endpoint.kind not in (getattr(enricher, "applies_to", []) or []):
                continue
            provider = _provider_name(enricher)
            if provider in source_status:
                continue
            source_status[provider] = {
                "status": "skipped",
                "reason": "deferred_case_close",
            }


def enrich_selected_targets(
    endpoints: list[Endpoint],
    enrichers: list[BaseEnricher],
    *,
    mode: str = ANALYSIS_MODE_PASSIVE,
    include_case_close: bool = False,
) -> list[dict]:
    """Enrich an explicit bounded target set and record per-target source outcomes.

    Ordinary analysis calls this with ``include_case_close=False`` so key-gated measurement
    providers cannot multiply quota usage across every static endpoint. Case closure opts in.
    """
    selected = [
        enricher
        for enricher in enrichers
        if include_case_close or not getattr(enricher, "case_close_only", False)
    ]
    if not include_case_close:
        # ★被 case-close 门挡下的源必须留痕：不记的话，报告里"结案才查所以现在没有"
        #   和"查过、没查到"完全无法区分，读的人会把前者读成后者。
        _mark_case_close_deferred(endpoints, enrichers)
    if not selected:
        return []
    if not include_case_close:
        return _run_enrichment(endpoints, selected, gate=_mode_gate(mode))

    allowed_by_mode = _mode_gate(mode)

    def gate(endpoint: Endpoint, enricher: BaseEnricher) -> bool:
        provider = _provider_name(enricher)
        source_status = endpoint.enrichment.setdefault("source_status", {})
        if not isinstance(source_status, dict):
            source_status = {}
            endpoint.enrichment["source_status"] = source_status
        if not allowed_by_mode(endpoint, enricher):
            source_status[provider] = {"status": "skipped", "reason": "active_mode_blocked"}
            return False
        if not _provider_configured(enricher):
            source_status[provider] = {"status": "disabled", "reason": "credential_not_configured"}
            return False
        # Provider will execute now; discard any cached status so the fresh payload decides hit/failure.
        source_status.pop(provider, None)
        return True

    stats = _enrich_endpoints(endpoints, selected, gate=gate)
    for endpoint in endpoints:
        source_status = endpoint.enrichment.setdefault("source_status", {})
        if not isinstance(source_status, dict):
            source_status = {}
            endpoint.enrichment["source_status"] = source_status
        for enricher in selected:
            if endpoint.kind not in (getattr(enricher, "applies_to", []) or []):
                continue
            provider = _provider_name(enricher)
            if provider in source_status:
                continue
            status, error_type = _source_status_from_payload(endpoint.enrichment.get(provider))
            entry: dict[str, str] = {"status": status}
            if error_type:
                entry["error_type"] = error_type
            source_status[provider] = entry
    return sorted(stats, key=lambda item: str(item.get("provider", "")))
