"""apkscan.core.runtime_inventory — 运行时回灌清单的**唯一** schema 与迁移真源。

★为什么放在 ``core`` 而不是 ``dynamic``：这份清单是 ``report.meta`` 的一块 **schema**，
写方在 ``dynamic``（pcap / probe 回灌），读方在 ``core``（闭环采集质量门）。放进 ``dynamic``
会迫使 ``core`` 反向 import ``dynamic``，把既有的 dynamic → core 单向依赖倒过来。

一份 ``report.json`` 有三个消费面、各读各的：``report.letters`` 读 ``leads``、闭环排序读 ``endpoints``、
可见性与采集质量读 ``meta``。运行时回灌路径（pcap / probe）往 ``meta`` 写一份「这次并入了什么」
的清单，就是本模块定义的东西。

★为什么要集中：此前「哪个键改过名、旧名是什么」散在各个调用点（``_prev_migrated(prev,
"domain_leads", "dns_queries")`` 这种），靠维护者临时决定传不传旧键。**同一个错误犯过三次**
（改名时只给撞见的那个键写迁移、漏掉结构相同的兄弟）。现在键集合与别名表是一份声明
（:data:`INVENTORY_FIELDS`），迁移按表驱动——将来再改名，漏掉兄弟键会被穷尽迁移测试直接照出来，
而不是等下一轮复审。

★**每个保留的键都必须说清楚谁读它**。清单曾经整块没有任何生产消费方（全仓只有 writer 与测试），
本模块的 :func:`derive_capture_quality` 就是那个消费方；凡是接不上消费方的键一律删除，
见 :data:`DROPPED_FIELDS`。
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

logger = logging.getLogger(__name__)

#: 清单落在 ``report.meta`` 下的键名。
INVENTORY_META_KEY = "runtime_merged_inventory"

#: 历史键名（本键自己也改过名）：pcap 路径最初叫 ``runtime_pcap_inventory``。
INVENTORY_META_ALIASES: tuple[str, ...] = ("runtime_pcap_inventory",)


@dataclass(frozen=True)
class _Field:
    """一个清单字段的声明：别名、类型、以及**谁读它**。

    ``reader`` 不是注释性质的装饰——它是本模块的准入条件：填不出 reader 的字段不该存在。
    """

    name: str
    kind: str                      # "count" | "flag" | "status"
    aliases: tuple[str, ...]
    reader: str


#: ★键集合与别名表的唯一真源。迁移、校验、穷尽测试全部按这张表驱动。
INVENTORY_FIELDS: tuple[_Field, ...] = (
    _Field(
        "remote_endpoints", "count", (),
        reader="derive_capture_quality → business_candidate_count（闭环采集质量门）",
    ),
    _Field(
        "domain_leads", "count", ("dns_queries",),
        reader="derive_capture_quality → runtime_domain_lead_count（闭环结果可见，"
               "区分「观测到域名但无可达端点」与「压根没流量」）",
    ),
    _Field(
        "parse_status", "status", (),
        reader="derive_capture_quality → floor_parse_status（空结果≠零流量）",
    ),
    _Field(
        "parse_degraded", "flag", (),
        reader="derive_capture_quality → floor_parse_status（历史上有过解析失败即不得报 ok）",
    ),
    _Field(
        "uid_attributed", "flag", (),
        reader="derive_capture_quality → target_attributed_count（False 则恒 0、闭环上限 partial）；"
               "★由 UID_ATTRIBUTED_SOURCES_KEY 那本来源账派生，不得被后一次无归因合并擦除",
    ),
    _Field(
        "sources", "list", ("source",),
        reader="derive_capture_quality → runtime_inventory_sources（读报告的人要分得清"
               "这份观测来自 pcap 回灌还是 probe 回灌，两条路径可以先后并进同一份报告）",
    ),
)

#: 各回灌路径**各自**的贡献集合键名。★必须分开记：共享 schema 判不了归属
#: （capture 路径产出的也是 runtime-pcap 证据，从 payload 反推会把它算进 pcap 名下），
#: 所以每条路径记自己那本账，计数取各本账的**并集**大小。
VALUE_SET_KEYS: Mapping[str, tuple[str, str]] = MappingProxyType({
    # source: (端点贡献集合键, 域名贡献集合键)
    "pcap": ("runtime_pcap_endpoint_values", "runtime_pcap_domain_values"),
    "probe": ("runtime_probe_endpoint_values", "runtime_probe_domain_values"),
})

#: UID 归因的**来源记账**键（落在 ``meta``，与贡献集合同一套记账法）。
#: ★为什么不能只在清单里存一个布尔：pcap 与 probe 可以先后并进同一份报告，后并入的
#: 无归因路径会把前一次的 ``uid_attributed=True`` 覆盖成 False——「这份观测能不能归到目标进程」
#: 这个结论就取决于合并顺序了。改为记「哪些来源带来了归因」，布尔由集合非空派生：
#: pcap→probe 与 probe→pcap 结果必然一致。
UID_ATTRIBUTED_SOURCES_KEY = "runtime_uid_attributed_sources"

#: ★**显式声明丢弃**的旧键 + 理由。删字段和加字段一样要留痕：
#: 旧报告里真有这些键，读到时按表跳过，而不是让维护者猜「这是不是漏迁移了」。
DROPPED_FIELDS: Mapping[str, str] = MappingProxyType({
    "flows_merged": "无任何消费方，且无法从别处派生（闭环只关心端点候选数）；"
                    "留着等于长期背一份没人读的迁移负担",
    "flows": "flows_merged 的更早旧名，随 flows_merged 一并丢弃",
})

_FIELDS_BY_NAME: Mapping[str, _Field] = MappingProxyType({f.name: f for f in INVENTORY_FIELDS})


def _count(value: object) -> int:
    """计数字段取值：缺失 / 坏类型 / 负数 / bool → 0（绝不抛）。"""
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value if value >= 0 else 0


def read_inventory(meta: Mapping[str, object]) -> dict[str, object]:
    """从 ``meta`` 里取出清单，兼容清单**自身**键名改过的旧报告。

    新键优先、缺失才回退旧名，两者绝不合并（合并会让迁移期的报告双计）。
    """
    for key in (INVENTORY_META_KEY, *INVENTORY_META_ALIASES):
        value = meta.get(key)
        if isinstance(value, Mapping):
            return dict(value)
    return {}


def migrate_count(prev: Mapping[str, object], name: str) -> int:
    """按别名表读上一份清单里的计数，兼容键改名过的旧报告。

    ★**新键优先、缺失才回退旧键，两者绝不相加**：只读新键的话，旧报告的历史计数会在下次合并时
      静默清零；相加的话，迁移期同时存在新旧键的报告又会双计。取一不相加。
    """
    field = _FIELDS_BY_NAME.get(name)
    if field is None or field.kind != "count":
        return 0
    if name in prev:
        return _count(prev.get(name))
    for alias in field.aliases:
        if alias in prev:
            return _count(prev.get(alias))
    return 0


def migrate_degraded(prev: Mapping[str, object]) -> bool:
    """这份报告此前有没有过解析降级——兼容没有 ``parse_degraded`` 键的旧报告。

    ★缺键时若简单地 ``bool(prev.get(...))``，一份 ``parse_status="parse_error"`` 的旧报告再并入
      一次正常采集，就会得到 ``False`` + ``parse_status`` 被覆盖成 ``"ok"``——**曾经解析失败
      这件事彻底消失**。故缺键时从旧 ``parse_status`` 反推。
    """
    if "parse_degraded" in prev:
        return bool(prev.get("parse_degraded"))
    status = prev.get("parse_status")
    return isinstance(status, str) and bool(status) and status != "ok"


def accumulate_values(meta: dict, key: str, values: Iterable[str]) -> list[str]:
    """把本次贡献的值并进 ``meta[key]`` 的集合，返回排序后的全集。

    ★为什么要在 meta 里**自己记一份贡献集合**，而不是从 ``payload["endpoints"]`` /
      ``payload["leads"]`` 反推：反推分不清是谁写的。曾试过按 ``source == "runtime-pcap"``
      钉边界，但 capture 路径也产出 runtime-pcap 证据（正常生产路径），于是名为 *pcap* 的清单
      会把 capture 的贡献一并算进去。共享 schema 判不了归属，只能各自记账。

    集合语义天然幂等：同一份采集并几次，结果不变。坏结构一律跳过，绝不抛。
    """
    prev = meta.get(key)
    merged = {v for v in prev if isinstance(v, str) and v} if isinstance(prev, list) else set()
    merged.update(v for v in values if isinstance(v, str) and v)
    ordered = sorted(merged)
    meta[key] = ordered
    return ordered


def migrate_sources(prev: Mapping[str, object]) -> list[str]:
    """读上一份清单记过的回灌来源，兼容旧报告只有单个 ``source`` 标量的形态。

    ★为什么是列表而不是标量：pcap 回灌与 probe 回灌**可以先后并进同一份报告**。写成标量的话，
      第二条路径会把第一条的来源覆盖掉，报告里就只剩下最后一次并入的那个名字——
      「这份观测是怎么来的」被悄悄改写。
    """
    raw = prev.get("sources")
    if isinstance(raw, list):
        return sorted({s for s in raw if isinstance(s, str) and s})
    legacy = prev.get("source")
    return [legacy] if isinstance(legacy, str) and legacy else []


def accumulate_uid_attributed_sources(
    meta: dict, source: str, uid_attributed: bool, prev: Mapping[str, object]
) -> list[str]:
    """记账「哪些来源带来了可靠 UID 归因」，返回排序后的全集。

    ★为什么要一本来源账而不是直接写布尔：``build_inventory`` 每次只知道**本次**这条路径有没有
      归因。pcap（有归因）先并、probe（无归因）后并时，直接写 ``bool(uid_attributed)`` 会把
      前一次的 True 擦成 False——闭环能不能报 ``target_attributed_count>0`` 就取决于两条路径的
      合并顺序了，而合并顺序不是证据事实。

    单调：已记入的来源不会被移除；只要**任一**已并入来源有归因，派生布尔恒为 True。
    故 pcap→probe 与 probe→pcap 结果必然一致。

    迁移：旧报告只有清单里的 ``uid_attributed=True`` 布尔、没有这本账（账是后加的），
    此时把它算作一份历史归因来源（``legacy``），否则历史结论会在下次合并时静默清零。
    """
    stored = meta.get(UID_ATTRIBUTED_SOURCES_KEY)
    merged = {s for s in stored if isinstance(s, str) and s} if isinstance(stored, list) else set()
    if not merged and prev.get("uid_attributed") is True:
        merged.add("legacy")
    if uid_attributed:
        merged.add(source)
    ordered = sorted(merged)
    meta[UID_ATTRIBUTED_SOURCES_KEY] = ordered
    return ordered


def build_inventory(
    meta: dict,
    *,
    source: str,
    endpoint_values: Iterable[str],
    domain_values: Iterable[str],
    parse_status: str,
    uid_attributed: bool = False,
) -> dict[str, object]:
    """按表组装一份新清单：记账本路径的贡献、迁移旧清单的历史信息，并写回 ``meta``。

    ★计数取**所有路径贡献集合的并集**大小，不是本路径那一本账的大小：两条路径都并进同一份
      报告时，只算自己那本会让计数小于报告里真实的端点数；而把两本账的长度相加又会把
      两条路径都观测到的同一个端点算两遍。并集是唯一既不漏报也不重复的口径。

    与旧计数取 ``max``：旧报告有计数却没有贡献集合（集合是后来才引入的），直接用集合长度会让
    历史计数被重置；相加又会把重叠部分算两遍——**无从判断重叠**，只能取单调下界。

    ★``uid_attributed`` 同理按来源记账后派生（见 :func:`accumulate_uid_attributed_sources`），
    不直接写本次那个布尔——否则「能否归因」会取决于 pcap / probe 的合并顺序。
    """
    prev = read_inventory(meta)
    ep_key, dom_key = VALUE_SET_KEYS.get(source, VALUE_SET_KEYS["pcap"])
    accumulate_values(meta, ep_key, endpoint_values)
    accumulate_values(meta, dom_key, domain_values)
    uid_sources = accumulate_uid_attributed_sources(meta, source, uid_attributed, prev)

    def _union(index: int) -> int:
        seen: set[str] = set()
        for keys in VALUE_SET_KEYS.values():
            stored = meta.get(keys[index])
            if isinstance(stored, list):
                seen.update(v for v in stored if isinstance(v, str) and v)
        return len(seen)

    return {
        "remote_endpoints": max(migrate_count(prev, "remote_endpoints"), _union(0)),
        "domain_leads": max(migrate_count(prev, "domain_leads"), _union(1)),
        "parse_status": parse_status,
        # 只要**任何一次**合并解析异常就置 True，且不被后续成功覆盖——
        # 「这份报告有过解析失败」不该被下一次成功抹掉。
        "parse_degraded": migrate_degraded(prev) or parse_status != "ok",
        # ★按来源记账后派生：只要任一已并入来源带来了可靠 UID 归因就为 True，
        # 后并入的无归因路径**不得**把它擦回 False（否则结论取决于合并顺序）。
        "uid_attributed": bool(uid_sources),
        "sources": sorted({*migrate_sources(prev), source}),
    }


def derive_capture_quality(inventory: Mapping[str, object]) -> dict[str, object]:
    """把清单派生成 ``evaluate_capture_quality`` 吃的采集质量输入。

    ★这是清单的**生产消费方**。此前清单整块没人读，于是「只走 pcap 回灌」的报告在闭环里
      拿到空 capture_quality → ``business_count=0`` → 判 **failed**，而正确结论是 **partial**
      （观测到了业务候选端点，只是做不了唯一归因）。

    ★绝不抬成 complete：``uid_attributed=False`` → ``target_attributed_count`` 恒 0；
      ``bidirectional_*`` 一律不补（缺失按 0 = fail-closed 是既定语义），本路径拿不到
      双向载荷统计，补默认值等于伪造观测强度。
    """
    if not inventory:
        return {}
    endpoints = _count(inventory.get("remote_endpoints"))
    domains = _count(inventory.get("domain_leads"))
    status = inventory.get("parse_status")
    parse_status = status if isinstance(status, str) and status else "ok"
    # 历史上有过解析失败 → 不得报 ok。空结果≠零流量，这一句是「提示重抓而非结案」的依据。
    if bool(inventory.get("parse_degraded")) and parse_status == "ok":
        parse_status = "degraded-history"
    sources = migrate_sources(inventory)
    return {
        "business_candidate_count": endpoints,
        # uid_attributed 为 False 时**显式**写 0：不写会让 evaluate_capture_quality 回退去
        # 读 pcap_app_attribution，而本路径压根没有那份数据。
        "target_attributed_count": endpoints if inventory.get("uid_attributed") is True else 0,
        "floor_parse_status": parse_status,
        # 供读报告的人核：观测到域名却没有可达端点，与「压根没有流量」长得完全不同。
        "runtime_domain_lead_count": domains,
        # 走 migrate_sources 而非直读：旧报告只有标量 source，这里也要如实读出来。
        "runtime_inventory_sources": sources or ["unknown"],
    }
