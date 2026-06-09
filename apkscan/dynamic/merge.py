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
import re
from collections.abc import Callable
from typing import Any

from apkscan.core import pipeline
from apkscan.core.models import (
    Confidence,
    Endpoint,
    Evidence,
    Lead,
    LeadCategory,
    Report,
)

logger = logging.getLogger(__name__)

# 运行时端点 / 证据的来源标记（与 capture._collect_flow_endpoints / models.Evidence 约定一致）。
_RUNTIME_SOURCE = "runtime"
# C5b：运行时解密出的明文端点来源标记（与抓包原始端点 "runtime" 区分，便于报告标注来源）。
_RUNTIME_DECRYPTED_SOURCE = "runtime-decrypted"

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
    """就地确保运行时端点的每条 evidence source="runtime"（合并语义靠 source 区分来源）。

    C5b：已标 "runtime-decrypted"（解密出的明文端点）的 evidence 放行——它本就是运行时
    来源的一种，需保留更精确的来源标记，便于报告区分"密文抓到"与"解密还原"。
    """
    for ep in endpoints:
        for ev in ep.evidences:
            if ev.source not in (_RUNTIME_SOURCE, _RUNTIME_DECRYPTED_SOURCE):
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


# ---------------------------------------------------------------------------
# C5b：用静态配方解密运行时信封报文 → 明文端点并入主报告
# ---------------------------------------------------------------------------

# 明文 JSON 里抽端点的正则：http(s) URL 与 /api 风格相对路径。
_PLAINTEXT_URL_RE = re.compile(r"""https?://[^\s"'`<>()\[\]{}\\^|,;]+""", re.IGNORECASE)
_PLAINTEXT_PATH_RE = re.compile(
    r"""(?<![\w.])(/(?:api|app|v\d+|gateway|service|interface|open|mobile|client|user|auth|register|login|pay|order|account|member|sys|admin|h5|wap|webconfig|config)
        (?:/[A-Za-z0-9_\-.~%]+)*)""",
    re.VERBOSE | re.IGNORECASE,
)


def decrypt_runtime_messages(report: Report, runtime_report_path: str) -> dict[str, int]:
    """用 ``report.meta["crypto_recipe"]`` 对 runtime_report.json 的信封报文解密，
    把明文里的端点（register/login/webConfig/产品/入金/客服等）并入 ``report``。

    流程（见 §3.4 spec）：
      1. 从 report.meta 取配方；无配方 → 跳过（零统计），保留密文，不崩。
      2. 读 runtime_report.json 的 messages。
      3. 每条 message 的请求/响应体若命中信封（含 data 与 timestamp）→ decrypt_envelope。
      4. 明文是合法 JSON → 抽 URL/路径/webName 关联域名 → Endpoint(source=runtime-decrypted)
         → 走 merge_runtime_endpoints 并入（去重/分级/产线索）。
      5. 解密失败/配方不全/padding 错 → warning + 保留原密文，不并入、不崩。
      6. 统计写 report.meta["runtime_decrypted"]。

    Returns:
        ``{"decrypted", "failed", "plaintext_endpoints"}``。内部 try/except，绝不抛。
    """
    stats = {"decrypted": 0, "failed": 0, "plaintext_endpoints": 0, "live_recipe": 0}
    try:
        from apkscan.core import appcrypto
        from apkscan.dynamic import cryptohook

        # P0：运行时密钥 hook 抓到的活体事件 → 反推「实测配方」，与静态配方浅合并（实测优先）。
        # 实测拿到权威 key（静态可能逆错/逆不到），iv 仅在实测恒定时覆盖、否则交静态推导。
        events = _load_crypto_events(runtime_report_path)
        live_meta = cryptohook.recipe_from_events(events) if events else None
        if live_meta:
            report.meta["runtime_crypto_recipe"] = dict(live_meta)
            report.meta["runtime_crypto_event_count"] = len(events)
            stats["live_recipe"] = 1
            logger.info("[merge] 采用运行时实测配方（活体 key）解密：%s", _recipe_brief(live_meta))
        # 冒充对象（webName/品牌/行业词）从活体明文抽出，写进 meta 供报告呈现。
        brand_hints = cryptohook.brand_hints_from_events(events) if events else []
        if brand_hints:
            report.meta["runtime_brand_hints"] = brand_hints
            logger.info("[merge] 运行时明文捕获冒充对象线索：%s", "、".join(brand_hints[:5]))

        # 候选配方（按优先级）：实测合并配方优先、纯静态配方兜底。逐信封依次尝试、首个解出即用。
        # 关键：「实测优先但绝不回归静态」——实测拿到二进制 key 覆盖、却与静态 iv 推导口径不兼容
        # （如静态 md5(key+ts) 对 hex key 失效）时，仍能用纯静态配方解出原本能解的信封。
        # 也顺带消解 iv 伪恒定风险：实测 fixed iv 解错其它信封时自动回退静态 md5 推导。
        static_meta = report.meta.get("crypto_recipe")
        merged_meta = _merge_recipe_meta(static_meta, live_meta)
        merged_recipe = appcrypto.CryptoRecipe.from_meta(merged_meta)
        if merged_recipe is None:
            logger.info("[merge] 无静态/运行时 crypto 配方，跳过运行时信封解密")
            return stats
        candidates = [merged_recipe]
        if live_meta:
            static_recipe = appcrypto.CryptoRecipe.from_meta(static_meta)
            if static_recipe is not None:
                candidates.append(static_recipe)  # 实测优先、静态兜底

        messages = _load_runtime_messages(runtime_report_path)
        if not messages:
            logger.info("[merge] runtime 报告无 messages，无信封可解密")
            return stats

        plaintext_endpoints: list[Endpoint] = []
        for msg in messages:
            url = str(msg.get("url", "")) if isinstance(msg, dict) else ""
            for body_key in ("response_body", "request_body"):
                body = msg.get(body_key) if isinstance(msg, dict) else None
                env = _parse_envelope(body)
                if env is None:
                    continue
                plain = _decrypt_with_candidates(
                    appcrypto, env["data"], candidates, env["timestamp"]
                )
                if plain is None:
                    stats["failed"] += 1
                    logger.warning(
                        "[merge] 信封解密失败（配方不全/padding 错/缺 crypto），保留密文：%s", url or body_key
                    )
                    continue
                stats["decrypted"] += 1
                eps = _endpoints_from_plaintext(plain, url)
                plaintext_endpoints.extend(eps)

        stats["plaintext_endpoints"] = len(plaintext_endpoints)
        if plaintext_endpoints:
            merge_runtime_endpoints(report, plaintext_endpoints)

        report.meta["runtime_decrypted"] = True
        report.meta["runtime_decrypt_stats"] = dict(stats)
        logger.info(
            "[merge] 运行时信封解密完成：decrypted=%d failed=%d plaintext_endpoints=%d",
            stats["decrypted"],
            stats["failed"],
            stats["plaintext_endpoints"],
        )
    except Exception:  # noqa: BLE001 - 解密失败不得抛给调用方（不破坏已产出报告）
        logger.exception("[merge] 运行时信封解密异常")
    return stats


def _load_runtime_messages(runtime_report_path: str) -> list[dict[str, Any]]:
    """读 runtime_report.json 的 messages 数组；缺文件/坏 JSON/无字段 → []（不抛）。"""
    import json
    from pathlib import Path

    path = Path(runtime_report_path)
    if not path.exists():
        logger.info("[merge] runtime 报告不存在，无信封报文：%s", path)
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        logger.exception("[merge] 读取/解析 runtime 报告失败（信封解密跳过）：%s", path)
        return []
    raw = payload.get("messages") if isinstance(payload, dict) else None
    if not isinstance(raw, list):
        return []
    return [m for m in raw if isinstance(m, dict)]


def _decrypt_with_candidates(
    appcrypto: Any, data: str, candidates: list[Any], timestamp: Any
) -> str | None:
    """逐个候选配方尝试解密信封，返回首个解出的明文；全失败 → None（不抛）。

    候选按优先级排列（实测合并配方在前、纯静态兜底在后）：实测优先但绝不回归静态——
    实测配方解不出时自动落到静态配方，避免「实测覆盖把本可成功的静态解密拉成全失败」。
    """
    for recipe in candidates:
        plain = appcrypto.decrypt_envelope(data, recipe, timestamp)
        if plain is not None:
            return plain
    return None


def _load_events_field(runtime_report_path: str, field: str) -> list[dict[str, Any]]:
    """读 runtime_report.json 里某个事件数组字段（crypto_events/jsbridge_events/…）。

    缺文件/坏 JSON/无字段/旧版报告无该字段 → []（向后兼容，不抛）。
    """
    import json
    from pathlib import Path

    path = Path(runtime_report_path)
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        logger.exception("[merge] 读取/解析 runtime 报告失败（%s 跳过）：%s", field, path)
        return []
    raw = payload.get(field) if isinstance(payload, dict) else None
    if not isinstance(raw, list):
        return []
    return [e for e in raw if isinstance(e, dict)]


def _load_crypto_events(runtime_report_path: str) -> list[dict[str, Any]]:
    """读 runtime_report.json 的 crypto_events 数组（P0 运行时密钥 hook 产出）。"""
    return _load_events_field(runtime_report_path, "crypto_events")


def merge_runtime_traces(report: Report, runtime_report_path: str) -> dict[str, int]:
    """把 P1 运行时追踪（JS-bridge 暴露面/调用、敏感 API 实调）并回主报告。

    - JS-bridge：运行时实际暴露/调用的桥接接口 → Lead(CONFIG_KEY, "JSBridge:<iface>",
      source=runtime → is_runtime_seen=True)，去重并入；写 report.meta["runtime_jsbridge"]。
    - 敏感 API：运行时实测调用的 ``<类>.<方法>`` → 给匹配的静态 sensitive_api Finding 追加
      runtime Evidence（把"静态存在"升级为"活体确认"）；写 report.meta["runtime_sensitive_apis"]。

    Returns:
        ``{"jsbridge_leads", "api_confirmed"}``。内部 try/except，绝不抛。
    """
    stats = {"jsbridge_leads": 0, "api_confirmed": 0}
    try:
        from apkscan.dynamic import cryptohook

        jb_events = _load_events_field(runtime_report_path, "jsbridge_events")
        api_events = _load_events_field(runtime_report_path, "sensitive_api_events")

        jb_hints = cryptohook.jsbridge_hints_from_events(jb_events)
        if jb_hints:
            report.meta["runtime_jsbridge"] = jb_hints
            stats["jsbridge_leads"] = _add_runtime_jsbridge_leads(report, jb_hints)

        api_hints = cryptohook.sensitive_api_hints_from_events(api_events)
        if api_hints:
            report.meta["runtime_sensitive_apis"] = api_hints
            stats["api_confirmed"] = _confirm_sensitive_api_findings(report, api_hints)

        if jb_hints or api_hints:
            report.meta["runtime_traced"] = True
            logger.info(
                "[merge] 运行时追踪并回：jsbridge_leads=%d api_confirmed=%d",
                stats["jsbridge_leads"],
                stats["api_confirmed"],
            )
    except Exception:  # noqa: BLE001 - 追踪并回失败不得抛给调用方
        logger.exception("[merge] 运行时追踪并回异常")
    return stats


def _add_runtime_jsbridge_leads(report: Report, jb_hints: list[str]) -> int:
    """把运行时观测到的桥接接口加成 CONFIG_KEY Lead（source=runtime），去重 append。"""
    existing = {(lead.category.value, lead.value) for lead in report.leads}
    added = 0
    for hint in jb_hints:
        value = f"JSBridge:{hint}"
        key = (LeadCategory.CONFIG_KEY.value, value)
        if key in existing:
            # 已有同名（静态桥接框架）→ 追加 runtime 证据，升为活体确认。
            for lead in report.leads:
                if lead.category == LeadCategory.CONFIG_KEY and lead.value == value:
                    lead.source_refs.append(
                        Evidence(source=_RUNTIME_SOURCE, location="runtime", snippet=f"运行时暴露/调用：{hint}")
                    )
                    break
            continue
        existing.add(key)
        report.leads.append(
            Lead(
                category=LeadCategory.CONFIG_KEY,
                value=value,
                confidence=Confidence.HIGH,
                advice="建议调证",
                source_refs=[
                    Evidence(source=_RUNTIME_SOURCE, location="runtime", snippet=f"运行时暴露/调用：{hint}")
                ],
                notes="运行时实测：H5 可调用/已调用的原生 JS-bridge 接口（活体确认）。",
            )
        )
        added += 1
    return added


def _confirm_sensitive_api_findings(report: Report, api_hints: list[str]) -> int:
    """给匹配的静态 sensitive_api Finding 追加 runtime Evidence（活体确认）。

    匹配口径：运行时 api 串（如 "TelephonyManager.getDeviceId"）的方法名出现在 Finding 的
    title/description/id 里即视为同一能力，追加一条 runtime 证据。返回确认条数。
    """
    confirmed = 0
    method_names = {h.rsplit(".", 1)[-1] for h in api_hints if h}
    for finding in report.findings:
        if getattr(finding, "category", "") != "sensitive_api":
            continue
        hay = f"{finding.id} {finding.title} {finding.description}"
        matched = next((m for m in method_names if m and m in hay), None)
        if matched is None:
            continue
        finding.evidences.append(
            Evidence(source=_RUNTIME_SOURCE, location="runtime", snippet=f"运行时实测调用：{matched}")
        )
        confirmed += 1
    return confirmed


def _merge_recipe_meta(
    static_meta: Any, live_meta: dict[str, Any] | None
) -> dict[str, Any] | None:
    """把运行时实测配方浅合并到静态配方上（实测非空字段覆盖静态）；都没有 → None。

    语义：实测拿到的字段（权威 key、恒定 iv）覆盖静态推断；实测没把握的字段（如变化的
    iv 未设 iv_derive）保留静态值——避免无依据地改写静态推断、或把单次 iv 误当 fixed。
    """
    base: dict[str, Any] = dict(static_meta) if isinstance(static_meta, dict) else {}
    if isinstance(live_meta, dict):
        for key, val in live_meta.items():
            if val not in (None, ""):
                base[key] = val
    return base or None


def _recipe_brief(meta: dict[str, Any]) -> str:
    """配方一行摘要（日志用，不泄全 key）。"""
    key = str(meta.get("key", ""))
    key_tail = key[:4] + "…" + key[-4:] if len(key) >= 8 else key
    return (
        f"{meta.get('algo', '?')}-{meta.get('mode', '?')}/{meta.get('padding', '?')} "
        f"key({meta.get('key_encoding', '?')})={key_tail} iv={meta.get('iv_derive', '继承静态')}"
    )


def _parse_envelope(body: Any) -> dict[str, Any] | None:
    """把报文体（str 或 dict）解析为信封 dict，须含 data 与 timestamp 两键；否则 None。"""
    import json

    obj: Any = body
    if isinstance(body, str):
        if not body.strip():
            return None
        try:
            obj = json.loads(body)
        except ValueError:
            return None
    if not isinstance(obj, dict):
        return None
    if "data" not in obj or "timestamp" not in obj:
        return None
    data = obj.get("data")
    if not isinstance(data, str) or not data:
        return None
    return {"data": data, "timestamp": obj.get("timestamp")}


def _endpoints_from_plaintext(plaintext: str, source_url: str) -> list[Endpoint]:
    """从解密后的明文（合法 JSON 优先）抽端点：http(s) URL / /api 风格路径 / webName 关联域名。

    产 Endpoint(source="runtime-decrypted")。明文非 JSON 时退化为在文本上跑正则。
    """
    import json

    location = source_url or "runtime-decrypted"
    found: dict[str, Endpoint] = {}

    def _add(value: str, kind: str, snippet: str) -> None:
        value = value.strip()
        if not value or value in found:
            return
        found[value] = Endpoint(
            value=value,
            kind=kind,
            evidences=[
                Evidence(source=_RUNTIME_DECRYPTED_SOURCE, location=location, snippet=snippet[:200])
            ],
            is_cleartext=value.lower().startswith("http://"),
        )

    # 优先把明文当 JSON 递归收集字符串值（精确，能抓到 webName 等）。
    text_values: list[str] = []
    web_name = ""
    try:
        obj = json.loads(plaintext)
        for key, val in _walk_json_strings(obj):
            text_values.append(val)
            if key.lower() == "webname" and val:
                web_name = val
    except ValueError:
        text_values = [plaintext]

    haystack = "\n".join(text_values) if text_values else plaintext

    for m in _PLAINTEXT_URL_RE.finditer(haystack):
        raw = m.group(0).rstrip(".,;)\"'")
        _add(raw, "url", raw)
        host = _host_of_url(raw)
        if host:
            _add(host, "domain", raw)
    for m in _PLAINTEXT_PATH_RE.finditer(haystack):
        _add(m.group(1), "path", m.group(1))

    if web_name:
        # webName（冒充对象）本身不是端点，但作为线索片段附在第一个端点证据里更有价值；
        # 这里仅记日志，端点抽取已覆盖明文里的真实地址。
        logger.info("[merge] 解密明文含 webName（冒充对象）：%s", web_name)

    return list(found.values())


def _walk_json_strings(obj: Any, key: str = "") -> list[tuple[str, str]]:
    """递归收集 JSON 里的 (key, str_value) 对（用于从明文契约抽地址/字段）。"""
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_walk_json_strings(v, str(k)))
    elif isinstance(obj, list):
        for item in obj:
            out.extend(_walk_json_strings(item, key))
    elif isinstance(obj, str):
        out.append((key, obj))
    return out


def _host_of_url(url: str) -> str:
    """从 URL 取 host（不含端口/路径）。解析失败 → 空串。"""
    from urllib.parse import urlsplit

    try:
        netloc = urlsplit(url).netloc
    except ValueError:
        return ""
    host = netloc.split("@")[-1].split(":")[0]
    return host if "." in host else ""


def merge_and_rerender(
    report: Report,
    endpoints: list[Endpoint],
    out_dir: str,
    base: str = "report",
    *,
    formats: list[str] | None = None,
    on_progress: Callable[[str], None] | None = None,
    runtime_report_path: str | None = None,
) -> dict[str, Any]:
    """并入运行时端点后按 ``formats`` 重渲报告，覆盖 ``out_dir`` 下的首次产出。

    供 cli ``analyze --dynamic`` 在 capture 后调用：先 :func:`merge_runtime_endpoints`
    就地补全 report，再（C5b）用静态配方对 runtime_report.json 的信封报文
    :func:`decrypt_runtime_messages` 解密、把明文端点并入，最后惰性 import
    ``apkscan.report.{json,html}`` 覆盖写 ``out_dir/<base>.{json,html}``，使真·C2 与
    解密还原的接口契约都进入主线索清单与报告。

    Args:
        report: 主报告，就地被修改。
        endpoints: 运行时端点。
        out_dir: 报告输出目录（与 analyze 首次写出一致）。
        base: 报告文件名 base（APK 名去后缀）。**必须与静态首次写出同一 base**，否则静态
            写 ``<apk>.*`` 而重渲写 ``report.*`` 产两套报告。默认 ``"report"`` 仅兜底，
            调用方应显式传同一 base。
        formats: 要重渲的格式，默认 ``["html", "json"]``。
        on_progress: 可选进度回调。
        runtime_report_path: runtime_report.json 路径（含 messages 信封）；默认
            ``out_dir/runtime_report.json``。用于 C5b 解密。

    Returns:
        在 :func:`merge_runtime_endpoints` 统计基础上加 ``"report_paths"``（成功重渲的
        报告路径列表；单格式失败不计入、不致命）与 ``"decrypt_*"`` 解密统计。绝不抛。
    """
    from pathlib import Path

    out_path = Path(out_dir)

    _emit(on_progress, "并入运行时端点 ...")
    stats: dict[str, Any] = dict(merge_runtime_endpoints(report, endpoints))

    # C5b：用静态配方解密运行时信封报文，把明文端点并入（在端点并入之后、重渲之前）。
    _emit(on_progress, "解密运行时信封报文 ...")
    rr_path = runtime_report_path or str(out_path / "runtime_report.json")
    decrypt_stats = decrypt_runtime_messages(report, rr_path)
    stats["decrypted"] = decrypt_stats.get("decrypted", 0)
    stats["decrypt_failed"] = decrypt_stats.get("failed", 0)
    stats["plaintext_endpoints"] = decrypt_stats.get("plaintext_endpoints", 0)
    stats["live_recipe"] = decrypt_stats.get("live_recipe", 0)

    # P1：运行时追踪（JS-bridge 暴露面/调用、敏感 API 实调）并回 + 确认静态发现。
    _emit(on_progress, "并回运行时 JS-bridge / 敏感 API 追踪 ...")
    trace_stats = merge_runtime_traces(report, rr_path)
    stats["jsbridge_leads"] = trace_stats.get("jsbridge_leads", 0)
    stats["api_confirmed"] = trace_stats.get("api_confirmed", 0)

    fmts = list(formats) if formats else list(_DEFAULT_FORMATS)
    try:
        out_path.mkdir(parents=True, exist_ok=True)
    except OSError:
        logger.exception("[merge] 创建输出目录失败：%s", out_dir)

    report_paths: list[str] = []
    if "json" in fmts:
        json_path = _rerender_json(report, out_path, base, on_progress)
        if json_path:
            report_paths.append(json_path)
    if "html" in fmts:
        html_path = _rerender_html(report, out_path, base, on_progress)
        if html_path:
            report_paths.append(html_path)

    stats["report_paths"] = report_paths
    return stats


def _rerender_json(
    report: Report, out_path: Any, base: str, on_progress: Callable[[str], None] | None
) -> str:
    """惰性 import report.json 并覆盖写 ``<base>.json``；失败记 logging 返回空串（不致命）。"""
    target = out_path / f"{base}.json"
    _emit(on_progress, f"重渲 {base}.json ...")
    try:
        from apkscan.report import json as report_json

        report_json.dump(report, str(target))
    except Exception:  # noqa: BLE001 - 单格式重渲失败不致命，不计入 report_paths
        logger.exception("[merge] 重渲 %s 失败：%s", target.name, target)
        return ""
    return str(target)


def _rerender_html(
    report: Report, out_path: Any, base: str, on_progress: Callable[[str], None] | None
) -> str:
    """惰性 import report.html 并覆盖写 ``<base>.html``；失败记 logging 返回空串（不致命）。"""
    target = out_path / f"{base}.html"
    _emit(on_progress, f"重渲 {base}.html ...")
    try:
        from apkscan.report import html as report_html

        report_html.render(report, str(target))
    except Exception:  # noqa: BLE001 - 单格式重渲失败不致命，不计入 report_paths
        logger.exception("[merge] 重渲 %s 失败：%s", target.name, target)
        return ""
    return str(target)


__all__ = [
    "load_runtime_endpoints",
    "merge_runtime_endpoints",
    "decrypt_runtime_messages",
    "merge_runtime_traces",
    "merge_and_rerender",
]
