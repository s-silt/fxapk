"""端口归一化反推（A2）：用**实测端口**验证 / 反推「配置声明端口 → 真实连接端口」的变换。

背景：部分家族不把真实端口直接写进配置——配置里存的是 raw 端口，客户端运行时再按某个固定规则算出
真正要连的端口（如 ``真实 = raw + IP末段 + 某常量``）。这类规则**只能靠观测反推**：一边是解密出的
声明端口（案件数据，办案人提供，绝不入仓），一边是 fxapk 自己抓到的实测连接端口
（``endpoints[].enrichment["runtime"]["remote_endpoints"]``，pcap/socket 真观测）。两边按 IP 配对，
在**有界假设空间**里找能解释全部配对的最简变换。

★ 与「从字节猜 IP」的本质区别（务必守住）：本模块**不产生任何端点**。它只回答「这批**已观测到的**
端口，能否被某个简单变换解释」。输入的 observed 侧全是实测值，输出是一个**可证伪的**变换假设 + 它的
支持/反例明细。绝不把推出的端口当成"观测到的"。

★ 过拟合闸（④ 二进制提取的教训直接搬过来）：配对太少或太"齐"时，任何形式都能拟合，此时结论无意义。
故要求 ①配对数 ≥ ``min_support``；②声明端口至少 2 个不同值；③IP 末段至少 2 个不同值——否则判
``degenerate``，一律不给 confirmed。宁可说"数据不足以区分"，也不给一个凑出来的公式。

纯函数、绝不联网、绝不抛。
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

logger = logging.getLogger(__name__)

#: 端口合法区间（推出的端口越界即判该形式不成立）。
_PORT_MIN = 1
_PORT_MAX = 65535

#: 默认最少配对数：少于此不给 confirmed（1~2 组任何形式都能拟合，等于没结论）。
_DEFAULT_MIN_SUPPORT = 3


@dataclass(frozen=True)
class PortPair:
    """一组配对观测：同一 IP 上「配置声明端口」与「实测连接端口」。

    ``declared`` 来自办案人的解密结果（案件数据）；``observed`` 来自 fxapk 的运行时证据（pcap/socket
    实测）。两者都必须是真实数据——本模块不构造任何一侧。
    """

    ip: str
    declared: int
    observed: int


@dataclass(frozen=True)
class TransformCandidate:
    """一个候选变换假设及其证据。

    ``supported`` / ``contradicted`` 是配对明细（可复核）；``confirmed`` 仅在「解释全部配对
    且不 degenerate 且配对数达标」时为 True。
    """

    form: str
    constant: int | None
    formula: str
    supported: tuple[PortPair, ...] = ()
    contradicted: tuple[PortPair, ...] = ()
    confirmed: bool = False

    @property
    def support_count(self) -> int:
        return len(self.supported)


@dataclass
class InferenceResult:
    """反推结论：候选按「参数越少越靠前」排序（奥卡姆），外加数据充分性诊断。"""

    pairs: tuple[PortPair, ...] = ()
    candidates: tuple[TransformCandidate, ...] = ()
    degenerate: bool = False
    degenerate_reason: str = ""
    ambiguous_ips: tuple[str, ...] = ()
    notes: list[str] = field(default_factory=list)

    @property
    def best(self) -> TransformCandidate | None:
        """最简的**已确认**候选；无确认候选 → None（不退而求其次给个"最像"的）。"""
        for c in self.candidates:
            if c.confirmed:
                return c
        return None


def last_octet(ip: str) -> int | None:
    """IPv4 末段（0-255）；非 IPv4 / 非法 → None。绝不抛。"""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None
    if addr.version != 4:
        return None
    return int(addr.packed[-1])


def _predict(form: str, constant: int, ip: str, declared: int) -> int | None:
    """按某形式与常量算出预测端口；无法计算（非 IPv4 等）→ None。"""
    if form == "identity":
        return declared
    if form == "offset":
        return declared + constant
    if form == "octet_offset":
        octet = last_octet(ip)
        return None if octet is None else declared + octet + constant
    return None


def _implied_constant(form: str, pair: PortPair) -> int | None:
    """由单条配对反解该形式的常量；该形式对此配对不适用 → None。"""
    if form == "identity":
        return 0 if pair.observed == pair.declared else None
    if form == "offset":
        return pair.observed - pair.declared
    if form == "octet_offset":
        octet = last_octet(pair.ip)
        return None if octet is None else pair.observed - pair.declared - octet
    return None


#: 假设空间：**刻意保持小且可读**，按自由参数个数排序（奥卡姆：能用更简单的解释就不上复杂的）。
#: 不加更多形式（乘性、位运算、多参数拟合）是有意为之——形式越多越容易在少量配对上凑出巧合，
#: 那正是 ④ 二进制提取翻车的机理。要加新形式，先问「它在多少组真实配对上被独立验证过」。
_FORMS: tuple[tuple[str, str], ...] = (
    ("identity", "真实端口 = 声明端口（无归一化）"),
    ("offset", "真实端口 = 声明端口 + {K}"),
    ("octet_offset", "真实端口 = 声明端口 + IP末段 + {K}"),
)


def infer_port_transform(
    pairs: Iterable[PortPair], *, min_support: int = _DEFAULT_MIN_SUPPORT
) -> InferenceResult:
    """在有界假设空间里反推能解释全部配对的最简端口变换。

    对每种形式：逐配对反解常量 → 取众数常量 → 用该常量回代全部配对，分出支持 / 反例。
    仅当「无反例 + 配对数 ≥ min_support + 非 degenerate」才标 confirmed。

    Args:
        pairs: 配对观测（declared 来自解密、observed 来自实测）。
        min_support: 最少配对数，低于此一律不 confirmed（默认 3）。

    Returns:
        :class:`InferenceResult`；无有效配对时返回空结论（不抛）。
    """
    valid = tuple(
        p for p in pairs
        if isinstance(p, PortPair)
        and _PORT_MIN <= p.declared <= _PORT_MAX
        and _PORT_MIN <= p.observed <= _PORT_MAX
    )
    result = InferenceResult(pairs=valid)
    if not valid:
        result.notes.append("无有效配对（declared/observed 须为 1-65535 的端口）。")
        return result

    # --- 数据充分性诊断（过拟合闸）---
    distinct_declared = len({p.declared for p in valid})
    octets = {last_octet(p.ip) for p in valid}
    octets.discard(None)
    if len(valid) < min_support:
        result.degenerate = True
        result.degenerate_reason = (
            f"配对仅 {len(valid)} 组（< {min_support}）：任何形式都能拟合，结论无意义。"
        )
    elif distinct_declared < 2:
        result.degenerate = True
        result.degenerate_reason = (
            "全部配对的声明端口相同：无法区分「与声明端口相关」和「与之无关」的形式。"
        )
    elif len(octets) < 2:
        result.degenerate = True
        result.degenerate_reason = (
            "全部配对的 IP 末段相同：无法区分 offset 与 octet_offset（末段被吸收进常量）。"
        )

    candidates: list[TransformCandidate] = []
    for form, template in _FORMS:
        consts = [c for c in (_implied_constant(form, p) for p in valid) if c is not None]
        # 众数常量：出现次数最多者（并列取最小，保证确定性/可复现）。反解不出任何常量（该形式对全部
        # 配对都不适用，如端口不相等时的 identity）→ 取 0 照样参评：**每种试过的形式都要出现在结论里**，
        # 连同它的反例——否则读者看不出假设空间试了什么、被什么否掉（可证伪性）。
        const = min(sorted(set(consts)), key=lambda k: (-consts.count(k), k)) if consts else 0
        supported: list[PortPair] = []
        contradicted: list[PortPair] = []
        for p in valid:
            got = _predict(form, const, p.ip, p.declared)
            (supported if got == p.observed else contradicted).append(p)
        confirmed = (
            not contradicted
            and len(supported) >= min_support
            and not result.degenerate
        )
        candidates.append(TransformCandidate(
            form=form,
            constant=const,
            formula=template.replace("{K}", str(const)),
            supported=tuple(supported),
            contradicted=tuple(contradicted),
            confirmed=confirmed,
        ))

    # 已按 _FORMS 顺序（参数少 → 多）产出，保持该顺序即奥卡姆排序。
    result.candidates = tuple(candidates)
    if result.degenerate:
        result.notes.append(result.degenerate_reason)
    elif not any(c.confirmed for c in candidates):
        result.notes.append(
            "假设空间内没有能解释全部配对的形式——可能变换更复杂、或配对里混入了不同族/不同通道的端点。"
        )
    return result


def predict_port(candidate: TransformCandidate, ip: str, declared: int) -> int | None:
    """用**已确认**的变换预测某声明端口对应的真实端口。

    ★ 预测值是**推导所得、非观测**：写进任何产物时必须如实标注来源，绝不可当作"实测/确认连接"。
    未确认的候选、非法端口、算出越界 → None（不给不可信的数）。
    """
    if not isinstance(candidate, TransformCandidate) or not candidate.confirmed:
        return None
    if candidate.constant is None or not (_PORT_MIN <= declared <= _PORT_MAX):
        return None
    got = _predict(candidate.form, candidate.constant, ip, declared)
    if got is None or not (_PORT_MIN <= got <= _PORT_MAX):
        return None
    return got


def observed_ports_from_report(report: Any) -> dict[str, set[int]]:
    """从主报告里取**实测**的 IP→端口集合。

    数据源是 ``endpoints[].enrichment["runtime"]["remote_endpoints"]``（形如 ``"ip:port"``），
    由 pcap/socket 归因写入，是真观测。坏结构一律跳过，绝不抛。
    """
    out: dict[str, set[int]] = {}
    if not isinstance(report, dict):
        return out
    endpoints = report.get("endpoints")
    if not isinstance(endpoints, list):
        return out
    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        enrichment = ep.get("enrichment")
        runtime = enrichment.get("runtime") if isinstance(enrichment, dict) else None
        keys = runtime.get("remote_endpoints") if isinstance(runtime, dict) else None
        if not isinstance(keys, list):
            continue
        for key in keys:
            if not isinstance(key, str) or ":" not in key:
                continue
            host, _, port_s = key.rpartition(":")
            try:
                port = int(port_s)
            except ValueError:
                continue
            if not (_PORT_MIN <= port <= _PORT_MAX) or last_octet(host) is None:
                continue
            out.setdefault(host, set()).add(port)
    return out


def build_pairs(
    declared: Mapping[str, int], observed: Mapping[str, set[int]]
) -> tuple[list[PortPair], list[str], list[str]]:
    """按 IP 把声明端口与实测端口配对。

    Returns:
        ``(pairs, ambiguous_ips, unmatched_ips)``——``ambiguous_ips`` 是同一 IP 观测到**多个**端口的
        （不擅自挑一个，交人判；否则等于替办案人猜），``unmatched_ips`` 是声明了但没实测到的。
    """
    pairs: list[PortPair] = []
    ambiguous: list[str] = []
    unmatched: list[str] = []
    for ip, dport in (declared or {}).items():
        ip_s = str(ip).strip()
        if not isinstance(dport, int) or not (_PORT_MIN <= dport <= _PORT_MAX):
            continue
        ports = observed.get(ip_s)
        if not ports:
            unmatched.append(ip_s)
            continue
        if len(ports) > 1:
            ambiguous.append(ip_s)
            continue
        pairs.append(PortPair(ip=ip_s, declared=dport, observed=next(iter(ports))))
    pairs.sort(key=lambda p: (p.ip, p.declared))
    return pairs, sorted(set(ambiguous)), sorted(set(unmatched))


__all__ = [
    "PortPair",
    "TransformCandidate",
    "InferenceResult",
    "infer_port_transform",
    "predict_port",
    "observed_ports_from_report",
    "build_pairs",
    "last_octet",
]
