"""目标选择与排序：从报告的建议调证 leads 里挑出 domain/IP 端点，按 runtime-first 稳定排序并截断。

为什么这样切：这是闭环流程的入口筛选层——决定「对哪些目标做五层归因」，只依赖共享底座
``_shared``，不依赖五层组装（layers）、富化（sources）与验收（gates）。
FOFA 命名行解析（``_FOFA_FIELDS`` / ``_parse_fofa_row``）与运行时信号读取（``_runtime_info``）
也放这里：它们是排序依据（runtime 信号）与被动证据解析的最底层输入侧工具，被 layers 复用。
"""

from __future__ import annotations

import logging
from typing import Any

from apkscan.core import infra
from apkscan.core.models import (
    DOWNGRADE_REPACK_IDENTITY,
    DOWNGRADE_SNI_MASQUERADE,
    DOWNGRADE_SOURCE_TIER,
    Endpoint,
    Report,
    advice_is_consistent,
)
from apkscan.core.restore import is_restored, restore_index

from apkscan.core.closure._shared import _mapping

logger = logging.getLogger(__name__)

#: 已知的抑制来源 id。用于统计「这条线索是不是被人工放行过」——只认已知来源，磁盘上塞进来的
#: 陌生 id 不参与计数（免得凭空造出一个谁也不认识的放行理由）。
_KNOWN_DOWNGRADE_SOURCES = (
    DOWNGRADE_REPACK_IDENTITY,
    DOWNGRADE_SNI_MASQUERADE,
    DOWNGRADE_SOURCE_TIER,
)


#: FOFA 数组行的字段顺序（与富化器 ``multisource.FOFA_QUERY_FIELDS`` 查询串**逐字段同序**——
#  有漂移守卫测试比对二者，改一处必同步另一处）。FOFA 按数组返回，此前 closure 用魔数下标（row[10] 等）
#  取值，一旦 FOFA 改字段序/富化器改查询就静默错位污染归属；改用命名解析 + 形状校验（codex #3）。
_FOFA_FIELDS: tuple[str, ...] = (
    "host", "ip", "port", "protocol", "title", "server",
    "country", "region", "city", "as_number", "as_organization",
)


def _parse_fofa_row(row: object) -> dict[str, Any] | None:
    """把一条 FOFA 数组行按 ``_FOFA_FIELDS`` 解析成命名 dict。

    行长与字段数不符 → 记 warning 并**跳过该行**（形状漂移：FOFA 改列或富化器改查询，宁可少一条也不错位取值）。
    非 list / 空 → None。绝不抛。
    """
    if not isinstance(row, list):
        return None
    if len(row) != len(_FOFA_FIELDS):
        logger.warning(
            "FOFA 行字段数 %d 与预期 %d 不符（疑 FOFA 改列 / 富化器查询漂移），跳过该行以免错位取值",
            len(row), len(_FOFA_FIELDS),
        )
        return None
    return dict(zip(_FOFA_FIELDS, row))


def _runtime_info(endpoint: Endpoint) -> dict[str, Any]:
    runtime = _mapping(endpoint.enrichment.get("runtime"))
    runtime["observed"] = any(ev.source.startswith("runtime") for ev in endpoint.evidences)
    return runtime


def _match_value(category_or_kind: str, value: str) -> str:
    """Lead 与 Endpoint 配对用的规范化值 —— 薄封装，实现见 :func:`infra.match_key`。

    ★IP 侧要剥 ``:port/proto``：运行时回灌产出的 Lead 值形如 ``198.51.100.7:31861/tcp``（端口是
      调证函要写的东西，必须留在 Lead 上），而 Endpoint 一律是裸 IP（富化器、静态端点都按裸 IP
      算）。不剥就永远配不上——实测后果是**实测双向通信的真后端连闭环候选都进不去**，闭环转而
      挑满静态噪音，报告里 Lead 标着 is_runtime_contact=true、闭环却对它一无所知。

    保留本名是因为测试与包内调用都按它打桩；**逻辑不许在这里另写一份**，
    否则又会出现"选目标剥了、回写没剥"的分叉。
    """
    return infra.match_key(category_or_kind, value)


def _name_vendor_hinted(endpoint: Endpoint) -> bool:
    """该端点的静态证据**全部**来自文件名像 vendor bundle 的文件。

    ★弱信号，只作用于排序（见 ``infra.name_vendor_hint``）：文件名可伪造，故它既不改 advice
      也不排除候选，只在同档之内靠后。要求"全部证据都如此"——只要还有一条来自别处，
      这个值就不只是某个 vendor bundle 里的字面量。实连过的对端不适用（另有更强的优先项）。
    """
    locations = [str(ev.location or "") for ev in endpoint.evidences if str(ev.location or "")]
    return bool(locations) and all(infra.name_vendor_hint(loc) for loc in locations)


def _target_rank(
    endpoint: Endpoint, confidence_rank: int, shape_uncertain: bool = False
) -> tuple[int, int, int, int, int, int, int, str]:
    runtime = _runtime_info(endpoint)
    has_name = bool(runtime.get("sni") or runtime.get("http_host") or runtime.get("host"))
    return (
        0 if runtime.get("target_attributed") is True else 1,
        0 if runtime.get("has_payload") is True else 1,
        0 if has_name else 1,
        0 if runtime.get("observed") else 1,
        confidence_rank,
        # 文件名像第三方 vendor bundle 的排在同档之后（弱信号、不排除，见 _name_vendor_hinted）。
        1 if _name_vendor_hinted(endpoint) else 0,
        # 形态存疑的候选排在同档正常候选之后：Top-N 名额有限，不能让一个可能是版本号的
        # 字面挤掉一个确凿的后端地址（见 Lead.shape_uncertain）。仍参选，只是末位。
        1 if shape_uncertain else 0,
        endpoint.value.lower() if endpoint.kind == "domain" else endpoint.value,
    )


#: 无位置信息的候选归入的专用组名。★不能让它们「无 location 即豁免配额」——那等于给
#: 「把证据位置抹掉」开一条绕过通道。用一个不可能与真实路径相撞的名字（真实 location
#: 经归一后不含 NUL）。
_UNKNOWN_SOURCE_GROUP = "\x00unknown-source"


def _static_source_group(endpoint: Endpoint) -> str:
    """该端点的静态来源组 = 它**全部证据位置的集合**（归一、排序后拼成稳定键）。

    ★按集合而不是「单文件才算一组、多文件就豁免」：后者能被零成本绕过——把同一簇诱饵各写进
      同样的两个文件，每条的来源就都是"多处出现"，整簇一起逃过配额，且这个成本**不随诱饵数量
      增长**。按集合分组后，共享同一组合的一簇仍然只占一个名额。

    ★真正该被豁免配额的是「来源集合与别人都不同」的值——那自然落进它自己的组，无需特例。
    """
    locations = {str(ev.location or "").replace("\\", "/").lower() for ev in endpoint.evidences}
    locations.discard("")
    if not locations:
        return _UNKNOWN_SOURCE_GROUP
    return "\x00".join(sorted(locations))


def _diversify_by_source(ordered: list[Endpoint]) -> tuple[list[Endpoint], int]:
    """首轮每个静态来源组只占一个名额，同组其余候选顺延到后面。返回 (重排结果, 顺延数)。

    ★这条治的是本工具出过的一次实测事故：一份 ``chunk-vendors.<hash>.js`` 里第三方库硬编码
      的 28 个公共节点 IP 全部判「建议调证」，把 Top-6 目标占满，真实站点被挤到第 25 位之后
      ——办案方拿到的前 6 个调证目标没有一个是本案后端。

    ★为什么按「来源拥塞」治而不是按「识别第三方库」治：判断"这文件是不是第三方库"只能靠
      文件名 glob 或已知域名名单，两者都是**建它的人自己起的字符串**，可任意伪造；一旦把它
      做成硬判据，对手只要把业务主 bundle 命名成 ``chunk-vendors.<hash>.js``，真后端就会
      确定性地退出闭环候选——误判方向对对手有利。而「同一个文件贡献了一整簇候选」是结构性
      事实，不需要知道那文件是什么，伪造它也无从获益：把真后端和一堆诱饵塞进同一个文件，
      只会让它们彼此竞争同一个名额，而真后端在别处（另一文件 / 运行时）的出现照常入选。

    ★实连过的对端**不受配额限制**：那已经不是"某个文件里的字面量"，而是这台设备真的连过。
    """
    first: list[Endpoint] = []
    deferred: list[Endpoint] = []
    used_groups: set[str] = set()
    for endpoint in ordered:
        if _runtime_info(endpoint).get("observed"):
            first.append(endpoint)
            continue
        group = _static_source_group(endpoint)
        if group and group in used_groups:
            deferred.append(endpoint)
            continue
        if group:
            used_groups.add(group)
        first.append(endpoint)
    return first + deferred, len(deferred)


def _select_targets_with_stats(report: Report, max_targets: int) -> tuple[list[Endpoint], dict[str, object]]:
    """Order suspicious domain/IP leads (runtime-first) and split at ``max_targets``.

    Returns the selected endpoints plus a selection-stats mapping mirroring
    ``resolved_ip_selection`` so top-level target truncation is never silent: the
    caller records ``candidate_total``/``truncated``/``dropped`` and downgrades
    closure to partial when advisable candidates were dropped past the limit.
    """
    if max_targets <= 0:
        raise ValueError("max_targets must be greater than zero")

    # 兜底门：判为「正版重打包」时，其网络端点一律不进闭环目标——那些域名属被仿冒的正版
    # 厂商。主修复在生成 Lead 时降档，此处只防**旧版本产出的 / 手工编辑过的 / 隔离之后又被
    # 追加了新 Lead 的** report.json 绕过主修复。
    #
    # ★放行条件是**成员资格**，不是审计块存在与否。曾用"有块即视为人工恢复"，于是
    #   ``{"count": 0}``、只有 reason 的块、以及一个陈旧块（隔离跑完之后 dead-drop 又追加了
    #   一批从未经隔离的厂商域名）都能整门失效。人工恢复只改 advice、值仍留在 values 里，
    #   所以「在 values 里」才是"这条曾被隔离、后被人工放回"的凭据。
    meta = report.meta if isinstance(report.meta, dict) else {}
    rid = meta.get("repack_identity")
    is_repack = isinstance(rid, dict) and rid.get("verdict") == "repack_suspected"
    _blob = meta.get("repack_quarantine")
    restored_values = {
        str(v).lower()
        for v in ((_blob.get("values") or []) if isinstance(_blob, dict) else [])
        if isinstance(v, str)
    }
    repack_excluded = 0

    lead_rank: dict[tuple[str, str], int] = {}
    # 形态存疑（Lead.shape_uncertain）的值：仍参选，但排在同档正常候选之后。
    # ★取"任一条 lead 不存疑即不存疑"：同值多条 lead 时，只要有一条是靠地址性证据立住的，
    #   这个值就不该被形态存疑那条拖到末位。
    shape_ok: set[tuple[str, str]] = set()
    shape_suspect: set[tuple[str, str]] = set()
    # 因人工放行而未被抑制、从而进了候选的线索数。★必须显式呈现：手改 advice 会被下面的一致性
    # 守卫挡住，而手塞一条墓碑不会（跳过抑制后档位与空账本自洽）。不计数就等于给绕过守卫留了
    # 一条更安静的路——墓碑不做真伪校验，可见性是这里唯一站得住的保证。
    restored_lead_index = restore_index(meta)
    manually_restored = 0
    inconsistent_excluded = 0
    for lead in report.leads:
        if lead.advice != "建议调证" or lead.category.value not in {"DOMAIN", "IP"}:
            continue
        # ★一致性守卫：``advice`` 是由判据链结论与抑制来源算出的物化缓存。绕过 lift_downgrade
        #   直接手改 advice，会得到「档位说可查、账本却还压着」的矛盾态——而下一次任何重算都
        #   会把它压回去。此处 fail-closed（不进闭环目标）并计数，让矛盾可见而非静默放行。
        #   两个锚点都没有的旧数据无从校验，视为一致（见 models.advice_is_consistent）。
        if lead.base_advice is not None and not advice_is_consistent(lead):
            inconsistent_excluded += 1
            continue
        if restored_lead_index and any(
            is_restored(restored_lead_index, lead.category.value, lead.value, rid)
            for rid in _KNOWN_DOWNGRADE_SOURCES
        ):
            manually_restored += 1
        if is_repack and lead.value.lower() not in restored_values:
            repack_excluded += 1
            continue
        key = (lead.category.value.lower(), _match_value(lead.category.value, lead.value))
        lead_rank[key] = min(lead_rank.get(key, 9), {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(lead.confidence.value, 3))
        (shape_suspect if getattr(lead, "shape_uncertain", False) else shape_ok).add(key)

    candidates: list[tuple[Endpoint, int, bool]] = []
    for endpoint in report.endpoints:
        if endpoint.kind not in {"domain", "ip"} or endpoint.is_private:
            continue
        key = (endpoint.kind, _match_value(endpoint.kind, endpoint.value))
        if key not in lead_rank:
            continue
        candidates.append((endpoint, lead_rank[key], key in shape_suspect and key not in shape_ok))

    candidates.sort(key=lambda item: _target_rank(item[0], item[1], item[2]))
    ordered: list[Endpoint] = []
    seen: set[tuple[str, str]] = set()
    for endpoint, _rank, _suspect in candidates:
        value = endpoint.value.lower() if endpoint.kind == "domain" else endpoint.value
        key = (endpoint.kind, value)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(endpoint)

    # 同源去拥塞：首轮每个静态来源文件只占一个名额，避免一整簇同文件常量吃光 Top-N。
    # ★放在排序**之后**：rank 决定组内谁代表该来源，配额只决定组间的名额分配，两者不互相污染。
    ordered, source_deferred = _diversify_by_source(ordered)

    selected = ordered[:max_targets]
    dropped = ordered[max_targets:]
    stats: dict[str, object] = {
        "candidate_total": len(ordered),
        "selected": len(selected),
        "limit": max_targets,
        "truncated": len(dropped),
        "dropped": [endpoint.value for endpoint in dropped],
    }
    if repack_excluded:
        # 排除不静默：让读报告的人看得出"闭环目标为空"是因为隔离，而非样本真没有端点。
        stats["repack_excluded"] = repack_excluded
    if inconsistent_excluded:
        # 同理不静默：档位与抑制账本矛盾的线索被挡在闭环之外，得让人看见并去查为什么矛盾
        # （多半是有人绕过 `fxapk lead restore` 手改了 advice）。
        stats["inconsistent_excluded"] = inconsistent_excluded
    if manually_restored:
        # 「这条是被人放行的、不是判据说它干净」——必须能在闭环结果上直接看出来。
        stats["manually_restored"] = manually_restored
    if source_deferred:
        # 同样不静默：让读报告的人看得出「有一簇候选来自同一个文件、被顺延了」——这既是
        # 目标为何是这几个的解释，也是「那个文件值得单独看一眼」的提示。顺延不是排除，
        # 它们仍在候选序列里，只是排在各来源的头名之后。
        stats["source_deferred"] = source_deferred
    return selected, stats


def select_targets(report: Report, max_targets: int = 6) -> list[Endpoint]:
    """Select suspicious domain/IP leads in stable runtime-first order."""
    return _select_targets_with_stats(report, max_targets)[0]
