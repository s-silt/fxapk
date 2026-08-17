"""apkscan.dynamic.pcap_ingest — 带外 pcap → 接入节点/SNI/DNS 调证线索（纯标准库解析，零依赖）。

针对反分析涉诈 App：即便 TLS 解不开、走 MTProto/native 自建协议（普通抓包 endpoint=0），
只要有一份**带外抓的 pcap**（网关 tcpdump / PCAPdroid 免 root 导出 / Wireshark），就能从裸包抽出
**真实接入节点 IP:port + TLS SNI + DNS 查询 + JA3 指纹**，按 LeadCategory 聚成调证线索 / 回灌
``report.json``——把"解不开也能办案：带外拿接入节点 IP=穿透锚点"变成一条命令。

为什么纯标准库：fxapk 主打"零环境"（不强求 dpkt/scapy/pyshark/tshark）；这里只需 IP:port/SNI/DNS，
用 ``struct`` 手解经典 pcap 足够。支持 Ethernet/RAW-IP/Linux-SLL 链路、IPv4/IPv6、TCP/UDP，以及
pcapng 的 Enhanced Packet Block（best-effort）。**绝不抛**：坏包/坏文件逐条跳过 + logging。
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import math
import socket
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from apkscan.core import infra
from apkscan.core import runtime_inventory as _inv

# ★同包相对导入：runtime_evidence 是纯函数模块、不 import 任何兄弟模块，
#   所以这条边永远不会成环（它是判据的叶子，谁都能引它、它谁都不引）。
from . import runtime_evidence
from apkscan.core.atomic import atomic_write_text
from apkscan.core.models import (
    DOWNGRADE_SNI_MASQUERADE,
    SNI_MASQUERADE_KEY,
    Confidence,
    Endpoint,
    Evidence,
    EvidenceScope,
    Lead,
    LeadCategory,
    apply_downgrade,
    merge_runtime_into_lead_dict,
    revoke_superseded_evidence,
)
from apkscan.core.restore import restore_index, strip_restored_downgrades
from apkscan.core.report_schema import ensure_writable_report_version
from apkscan.network.fingerprints import KNOWN_INTERCEPT_IPS as _KNOWN_FANZHA
from apkscan.network.fingerprints import (  # noqa: F401 — public re-export (capture/closure/tests use pcap_ingest.is_known_intercept_ip)
    is_infrastructure_endpoint,
    is_known_intercept_ip,
)

logger = logging.getLogger(__name__)

META_WRITE_OWNER = "dynamic.pcap_ingest"
META_WRITE_CATEGORIES = {
    'runtime_merged': 'signal',
    'runtime_merged_inventory': 'record',
    'runtime_pcap_merges': 'record',
    'runtime_pcap_attribution_ledger': 'record',
    # 带 --uid-sockets 回灌时写：与 capture 落**同一个键**，下游（closure 门控、报告）
    # 不必区分归因数据是哪条路径产的。见 merge_into_report_json。
    # 类别随 capture 侧的既有声明（signal）——同一个键两处类别不一致会被契约测试拦下。
    'capture_signals': 'signal',
}
META_WRITE_KEYS = frozenset(META_WRITE_CATEGORIES)

_SOURCE = "runtime-pcap"

#: 做过 UID 归因、且结论是「不属于目标应用」时改钉的来源。仍是 runtime*（``is_runtime_seen``
#: 不变、报告照常标"运行时出现"），但不在 :data:`apkscan.core.models.OBSERVED_CONTACT_SOURCES`
#: 里，故 ``is_runtime_contact`` 为假、不会渲染成"已抓到通信的确认 C2"。
#: 与 ``dynamic.merge._RUNTIME_DERIVED_SOURCE`` 同值同义——那边管的是合成/写串的来源，
#: 这边管的是**归因否定**的来源，两条降档通道汇到同一档。
_UNATTRIBUTED_SOURCE = "runtime-derived"

#: 公开别名。``capture`` 在 UID 归因产出后要按同一组常量重标已建好的端点证据
#: （见 ``capture._annotate_runtime_endpoints``）——跨模块比对来源标签必须共用常量，
#: 各处写字面量的话，这边改了名那边不会红。
RUNTIME_PCAP_SOURCE = _SOURCE
RUNTIME_UNATTRIBUTED_SOURCE = _UNATTRIBUTED_SOURCE

_ATTRIBUTION_LEDGER_KEY = "runtime_pcap_attribution_ledger"
_ATTRIBUTION_LEDGER_VERSION = 1
_MAX_ATTRIBUTION_LEDGER_FINGERPRINTS = 4096
_MAX_LEDGER_ATTRIBUTION_LENGTH = 128
_ATTRIBUTION_RUNTIME_KEYS = (
    "target_attributed",
    "attribution",
    "target_among_candidates",
    "attribution_score",
)


class _AttributionLedgerRejected(ValueError):
    """账本版本/资源边界不受当前实现支持；整次落盘须 fail-closed。"""


def _safe_ledger_verdict(result: object) -> dict[str, object]:
    """只保留 ledger 投影需要的有界字段；详细 socket 证据不在此复制。

    ★``is_target_app`` 按 :mod:`runtime_evidence` 的口径存**三态**：``True`` / ``False`` /
      ``None``（ambiguous、unattributed 或坏值一律归一成 ``None``）。三者都是"问过了"，
      在表内且不为 True 即 DENIED——不能像旧私库草稿那样只认显式 bool，
      否则 ambiguous 记录经账本一转手就丢了降档结论。
    """
    if not isinstance(result, dict):
        return {}
    is_target = result.get("is_target_app")
    out: dict[str, object] = {
        "is_target_app": is_target if isinstance(is_target, bool) else None,
    }
    attribution = result.get("attribution")
    if isinstance(attribution, str):
        out["attribution"] = attribution[:_MAX_LEDGER_ATTRIBUTION_LENGTH]
    score = result.get("score")
    if (
        isinstance(score, (int, float))
        and not isinstance(score, bool)
        and math.isfinite(score)
    ):
        out["score"] = score
    among = result.get("target_uid_among_candidates")
    if isinstance(among, bool):
        out["target_uid_among_candidates"] = among
    return out


def _parse_carrier(carrier: object) -> tuple[str, str] | None:
    """校验 ``tcp|udp/ip:port``，返回（规范 carrier，规范 IP）。"""
    if not isinstance(carrier, str) or carrier.count("/") != 1:
        return None
    proto, endpoint = carrier.split("/", 1)
    if proto not in {"tcp", "udp"}:
        return None
    try:
        if endpoint.startswith("["):
            close = endpoint.find("]")
            if close <= 1 or endpoint[close + 1 : close + 2] != ":":
                return None
            host = endpoint[1:close]
            port_text = endpoint[close + 2 :]
        else:
            host, port_text = endpoint.rsplit(":", 1)
        port = int(port_text)
        if not 1 <= port <= 65535:
            return None
        address = ipaddress.ip_address(host)
    except (ValueError, TypeError):
        return None
    canonical_ip = str(address)
    return f"{proto}/{canonical_ip}:{port}", canonical_ip


def _carrier_ip(carrier: str) -> str:
    """从合法 carrier 取规范 IP；兼容裸/方括号 IPv6，坏值返回空串。"""
    parsed = _parse_carrier(carrier)
    return parsed[1] if parsed is not None else ""


def _carrier_set_target_flag(
    app_attr: dict[str, dict] | None,
    carriers: set[str],
) -> bool | None:
    """一组 carrier 的 IP 级目标归属：True / False / None（缺信息）。

    量词全部来自 :mod:`runtime_evidence`（唯一真源），此处只做组合，不自定判据：

    - 任一 carrier 单独判为 TARGET → ``True``。目标连过该 IP 的任一端口，该 IP 即算
      被目标连过（与 has_payload/state 的聚合哲学一致）；个别端口缺结论不掩盖已确认的
      TARGET——这也是既有 ``_attr_block`` 逐端口 or-合并的既有语义。
    - 整组按保守量词判 DENIED（全部在表内、无一 TARGET）→ ``False``。
    - 其余 → ``None``：缺任一结论且无 TARGET 时保持 MISSING，不得用部分否定盖信息缺口。
    """
    if not carriers:
        return None
    if any(
        runtime_evidence.verdict_for_carriers(app_attr, (carrier,))
        is runtime_evidence.AttributionVerdict.TARGET
        for carrier in carriers
    ):
        return True
    if runtime_evidence.is_denied(
        runtime_evidence.verdict_for_carriers(app_attr, carriers)
    ):
        return False
    return None


def _sanitize_ledger_capture(capture: object) -> dict | None:
    """把历史 capture 收窄到版本 1 的可投影形状；坏对象直接隔离。"""
    if not isinstance(capture, dict):
        return None
    carrier_ips: dict[str, str] = {}
    raw_ips = capture.get("carrier_ips")
    if isinstance(raw_ips, dict):
        for carrier, value in raw_ips.items():
            parsed = _parse_carrier(carrier)
            if parsed is None or not isinstance(value, str):
                continue
            try:
                stored_ip = str(ipaddress.ip_address(value))
            except ValueError:
                continue
            if stored_ip == parsed[1]:
                carrier_ips[parsed[0]] = stored_ip

    verdicts: dict[str, dict[str, object]] = {}
    raw_verdicts = capture.get("verdicts")
    if isinstance(raw_verdicts, dict):
        for carrier, result in raw_verdicts.items():
            parsed = _parse_carrier(carrier)
            safe = _safe_ledger_verdict(result)
            if parsed is None or not safe:
                continue
            verdicts[parsed[0]] = safe
            carrier_ips.setdefault(parsed[0], parsed[1])

    sni_carriers: dict[str, list[str]] = {}
    raw_sni = capture.get("sni_carriers")
    if isinstance(raw_sni, dict):
        for name, carriers in raw_sni.items():
            if not isinstance(name, str) or not isinstance(carriers, list):
                continue
            valid = sorted({
                parsed[0]
                for carrier in carriers
                if (parsed := _parse_carrier(carrier)) is not None
            })
            if valid:
                sni_carriers[name[:253]] = valid
    return {
        "carrier_ips": dict(sorted(carrier_ips.items())),
        "sni_carriers": dict(sorted(sni_carriers.items())),
        "verdicts": dict(sorted(verdicts.items())),
    }


def _load_attribution_ledger(meta: dict) -> dict:
    """读取/初始化按 PCAP fingerprint 记账的归因真源。

    旧报告没有 fingerprint 级归因，只能把既有 carrier 结论和正向计数迁入 legacy；
    这些无法解释的历史结论不得被新抓包静默擦除。
    """
    raw = meta.get(_ATTRIBUTION_LEDGER_KEY)
    if isinstance(raw, dict) and "version" in raw:
        if raw.get("version") != _ATTRIBUTION_LEDGER_VERSION:
            raise _AttributionLedgerRejected("unsupported attribution ledger version")
        captures = raw.get("captures")
        if not isinstance(captures, dict):
            raise _AttributionLedgerRejected("malformed attribution ledger captures")
        if len(captures) > _MAX_ATTRIBUTION_LEDGER_FINGERPRINTS:
            raise _AttributionLedgerRejected("attribution ledger exceeds resource limit")
        clean_captures: dict[str, dict] = {}
        for capture_id, capture in captures.items():
            if (
                not isinstance(capture_id, str)
                or not capture_id
                or len(capture_id) > 128
            ):
                continue
            clean = _sanitize_ledger_capture(capture)
            if clean is not None:
                clean_captures[capture_id] = clean

        legacy_target_ips: set[str] = set()
        raw_targets = raw.get("legacy_target_ips")
        if isinstance(raw_targets, list):
            for value in raw_targets:
                if not isinstance(value, str):
                    continue
                try:
                    legacy_target_ips.add(str(ipaddress.ip_address(value)))
                except ValueError:
                    continue
        floor = raw.get("legacy_target_count_floor")
        clean_ledger: dict = {
            "version": _ATTRIBUTION_LEDGER_VERSION,
            "captures": clean_captures,
            "legacy_target_ips": sorted(legacy_target_ips),
            "legacy_target_count_floor": (
                floor
                if isinstance(floor, int) and not isinstance(floor, bool) and floor >= 0
                else 0
            ),
        }
        legacy_unscoped = _sanitize_ledger_capture(raw.get("legacy_unscoped"))
        if legacy_unscoped is not None:
            clean_ledger["legacy_unscoped"] = legacy_unscoped
        meta[_ATTRIBUTION_LEDGER_KEY] = clean_ledger
        return clean_ledger

    legacy_results: dict[str, dict] = {}
    signals = meta.get("capture_signals")
    stored_attr = signals.get("pcap_app_attribution") if isinstance(signals, dict) else None
    if isinstance(stored_attr, dict):
        for carrier, result in stored_attr.items():
            parsed = _parse_carrier(carrier)
            safe = _safe_ledger_verdict(result)
            if parsed is not None and safe:
                legacy_results[parsed[0]] = safe

    pcap_target_key = _inv.TARGET_ATTRIBUTED_SET_KEYS["pcap"]
    raw_legacy_targets = meta.get(pcap_target_key)
    legacy_targets = sorted({
        value
        for value in (raw_legacy_targets if isinstance(raw_legacy_targets, list) else [])
        if isinstance(value, str) and value
    })
    previous = _inv.read_inventory(meta)
    known_targets: set[str] = set()
    for key in _inv.TARGET_ATTRIBUTED_SET_KEYS.values():
        values = meta.get(key)
        if isinstance(values, list):
            known_targets.update(
                value for value in values if isinstance(value, str) and value
            )
    legacy_floor = max(
        _inv.migrate_count(previous, "target_attributed") - len(known_targets),
        0,
    )
    ledger: dict = {
        "version": _ATTRIBUTION_LEDGER_VERSION,
        "captures": {},
        "legacy_target_ips": legacy_targets,
        "legacy_target_count_floor": legacy_floor,
    }
    if legacy_results:
        # 老报告没有 fingerprint；仅隔离留痕，绝不参加新抓包的 carrier/IP 投影。
        ledger["legacy_unscoped"] = {
            "carrier_ips": {
                carrier: _carrier_ip(carrier) for carrier in sorted(legacy_results)
            },
            "sni_carriers": {},
            "verdicts": legacy_results,
        }
        if isinstance(signals, dict):
            signals.pop("pcap_app_attribution", None)
    meta[_ATTRIBUTION_LEDGER_KEY] = ledger
    return ledger


def _update_attribution_ledger(
    meta: dict,
    fingerprint: str,
    summary: "PcapSummary",
    app_attr: dict[str, dict] | None,
) -> tuple[dict[str, dict], dict[str, bool], list[str]]:
    """更新当前 fingerprint，并返回 carrier/IP/target-IP 三个确定性投影。"""
    ledger = _load_attribution_ledger(meta)
    captures = ledger["captures"]
    if (
        fingerprint not in captures
        and len(captures) >= _MAX_ATTRIBUTION_LEDGER_FINGERPRINTS
    ):
        raise _AttributionLedgerRejected("attribution ledger fingerprint limit reached")
    current = captures.get(fingerprint)
    if not isinstance(current, dict):
        current = {"carrier_ips": {}, "sni_carriers": {}, "verdicts": {}}
    remotes = remote_endpoints(summary)
    carrier_ips = {
        f"{remote.proto}/{remote.ip}:{remote.port}": remote.ip
        for remote in remotes
    }
    current["carrier_ips"] = {
        carrier: carrier_ips[carrier] for carrier in sorted(carrier_ips)
    }
    current["sni_carriers"] = {
        name: sorted(carriers)
        for name, carriers in sorted(_sni_carriers(summary).items())
    }
    verdicts = current.get("verdicts")
    verdicts = dict(verdicts) if isinstance(verdicts, dict) else {}
    if isinstance(app_attr, dict):
        for carrier in sorted(carrier_ips):
            result = app_attr.get(carrier)
            safe = _safe_ledger_verdict(result)
            if safe:
                verdicts[carrier] = safe
    current["verdicts"] = verdicts
    captures[fingerprint] = current

    contributions: dict[str, list[tuple[str, dict]]] = {}
    carrier_to_ip: dict[str, str] = {}
    for capture_id in sorted(captures):
        capture = captures.get(capture_id)
        if not isinstance(capture, dict):
            continue
        ips = capture.get("carrier_ips")
        values = capture.get("verdicts")
        if not isinstance(ips, dict) or not isinstance(values, dict):
            continue
        for carrier, result in values.items():
            if isinstance(carrier, str) and isinstance(result, dict):
                contributions.setdefault(carrier, []).append((capture_id, result))
                ip = ips.get(carrier)
                if isinstance(ip, str) and ip:
                    carrier_to_ip[carrier] = ip

    carrier_projection: dict[str, dict] = {}
    for carrier, items in sorted(contributions.items()):
        targets = [item for item in items if item[1].get("is_target_app") is True]
        chosen = min(targets or items, key=lambda item: item[0])[1]
        carrier_projection[carrier] = dict(chosen)

    ip_states: dict[str, list[bool]] = {}
    for carrier, result in carrier_projection.items():
        ip = carrier_to_ip.get(carrier) or _carrier_ip(carrier)
        if ip:
            ip_states.setdefault(ip, []).append(result.get("is_target_app") is True)
    ip_projection = {
        ip: any(states) for ip, states in sorted(ip_states.items()) if states
    }
    legacy_targets = {
        value
        for value in ledger.get("legacy_target_ips", [])
        if isinstance(value, str) and value
    }
    # legacy 只有 IP 级历史状态、没有 fingerprint。可保留未被本轮解释的旧目标，
    # 但同一 IP 一旦有完整 DENIED（全部在表内、无一 TARGET），旧状态只能留在
    # quarantine，不能压过新证据。
    legacy_targets.difference_update(
        ip for ip, verdict in ip_projection.items() if verdict is False
    )
    target_ips = sorted({
        *legacy_targets,
        *(ip for ip, verdict in ip_projection.items() if verdict),
    })
    return carrier_projection, ip_projection, target_ips


def _apply_inventory_attribution_projection(meta: dict, target_ips: list[str]) -> None:
    """以 ledger 投影替换 pcap 那本目标账，并保留 probe 与 legacy floor。

    ★这是全模块唯一允许**收缩**目标集的地方：``_inv.accumulate_values`` 的集合语义
      只增不减（幂等所需），但显式 DENIED 是新证据、必须能把 IP 撤出目标集——
      收缩的依据是账本全量投影，不是"本次没看到"。
    """
    meta[_inv.TARGET_ATTRIBUTED_SET_KEYS["pcap"]] = list(target_ips)
    known: set[str] = set()
    for key in _inv.TARGET_ATTRIBUTED_SET_KEYS.values():
        values = meta.get(key)
        if isinstance(values, list):
            known.update(value for value in values if isinstance(value, str) and value)
    ledger = meta.get(_ATTRIBUTION_LEDGER_KEY)
    floor = (
        ledger.get("legacy_target_count_floor", 0)
        if isinstance(ledger, dict)
        else 0
    )
    inventory = meta.get(_inv.INVENTORY_META_KEY)
    if isinstance(inventory, dict):
        inventory["target_attributed"] = max(
            floor if isinstance(floor, int) and floor >= 0 else 0,
            len(known),
        )


def _endpoint_source(proto: str, ip: str, port: object, app_attr: dict[str, dict] | None) -> str:
    """按 UID 归因结果决定该远端证据的来源标签。

    ★三态，不是两态——与 :func:`_attr_block` 同一条哲学（「没做归因」≠「做了归因、结论是否」）：

    - **没有归因表**（未采 socket 快照）→ 维持 ``runtime-pcap``。工具连这个问题都没问过，
      属信息缺失，不因缺信息反向降档，否则等于把"不知道"写成"不是"。
    - **有归因表但该远端不在其中** → 同上，维持原样。
    - **有归因表且明确判定 ``is_target_app`` 不为真** → 降为 ``runtime-derived``。
      这是**否定证据**，不是缺失：工具已经算出这条流不属于目标应用（unattributed / 属他进程 /
      仅 probable），此时若仍按 observed-contact 渲染，就是把别的应用的流量说成本样本实连。

    ★这条降档存在的理由（2026-08-12 实证）：同一次全设备抓包并入两个样本的报告后，
      工具已判 ``is_target_app=false`` 的流量在报告中仍显示为"已抓到通信的确认 C2"；
      同批次另有一处把 ``unattributed`` 的 17 个包写成"命中 0"，一处把 24 个端点里
      18 个 ``unattributed`` 的一律给了 contact。三次同源，根因都在**来源标签不带归因结论**。
    """
    # ★判据本身在 runtime_evidence（唯一真源），本函数只负责把 verdict 映射成来源标签。
    #   此前判据在这里与 capture 各写一份、靠注释同步——同一份 pcap 经不同路径得到相反结论。
    verdict = runtime_evidence.verdict_for_endpoint(app_attr, proto, ip, port)
    return _UNATTRIBUTED_SOURCE if runtime_evidence.is_denied(verdict) else _SOURCE


def _sni_carriers(summary: PcapSummary) -> dict[str, set[str]]:
    """SNI 域名 → 承载它的归因键（``proto/ip:port``）集合。

    ★键必须由 :func:`remote_endpoints` 产出，不能自己按 ``flow.dst`` 拼——那等于**重新假定**
      哪一端是远端。出站流里 dst 确实是服务器，但设备上的应用监听 TLS、外部主动连入时，
      ClientHello 在 ``公网源 → 本机目的`` 方向，按 dst 拼会得到本机地址；归因表的键是远端，
      查表必然落空，于是被当作"未完全归因"而保留 observed-contact——**保守的方向恰好是
      本次要消除的过度断言**。``remote_endpoints`` 对出站/入站/双公网三种形态都判过方向，
      且归因表本身就是它的产出喂进 ``socket_attr.attribute_remote_endpoints`` 得来的，同源必对齐。

    DNS 查询出来的域名没有承载连接，不进本表——那是"查过这个名字"，不是"连过这台机器"。
    """
    carriers: dict[str, set[str]] = {}
    for re_ in remote_endpoints(summary):
        for name in re_.sni:
            carriers.setdefault(name, set()).add(f"{re_.proto}/{re_.ip}:{re_.port}")
    return carriers


def _aggregate_source(carriers: set[str] | None, app_attr: dict[str, dict] | None) -> str:
    """按**一组**承载连接的归因结果，决定该证据的来源标签。

    用在两类被聚合的对象上：SNI 域名（承载 = 出现过该 SNI 的全部远端）与按裸 IP 折叠的端点
    （承载 = 该 IP 的全部端口）。与 :func:`_endpoint_source` 同为三态，只是判据从单个远端
    变成集合：

    - 无归因表 / 没有承载连接（DNS 查询名）→ 维持 ``runtime-pcap``。
    - 任一承载端点确属目标应用 → 维持。目标确实连过，哪怕别的进程也连了同一个名字/同一台机器。
    - 有承载端点未被归因（不在表内）→ 维持。缺信息不反向降档，同 :func:`_endpoint_source` 第 2 态。
    - 全部承载端点都被归因、且无一属目标 → 降为 ``runtime-derived``。

    ★域名不是归因表的键，但不能因此一概按无法归因处理：SNI 是**某条具体连接**里的字段，
      那条连接有 ``proto/ip:port``、查得到归因。此前域名侧固定钉 ``runtime-pcap``，
      于是同一条被判非目标的连接，IP 侧降了档、它的 SNI 域名却仍渲染成"已抓到通信"。
    ★按裸 IP 折叠的端点同理：只看首个被迭代到的端口，结论会随 flow 顺序摇摆。
    """
    # ★同上：量词在 runtime_evidence 里定义一次，这里只做 verdict → 来源标签的映射。
    verdict = runtime_evidence.verdict_for_carriers(app_attr, carriers or ())
    return _UNATTRIBUTED_SOURCE if runtime_evidence.is_denied(verdict) else _SOURCE

# TLS GREASE 值（JA3 计算须剔除）：0x0a0a, 0x1a1a, …, 0xfafa。
_GREASE = {(b << 8) | b for b in range(0x0A, 0x100, 0x10)}


@dataclass
class Flow:
    """一条按 5 元组聚合的流（方向：src→dst）。"""

    proto: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    packets: int = 0
    bytes_: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    sni: set[str] = field(default_factory=set)
    ja3: set[str] = field(default_factory=set)
    flags: set[str] = field(default_factory=set)  # 本方向见到的 TCP 标志：syn/ack/synack/rst/fin/psh
    payload_bytes: int = 0  # 本方向 L4 应用层载荷累计字节（TCP：TCP 头之后）
    # QUIC（HTTP/3）长包头明文元数据（RFC 9000 §17.2，纯 stdlib、无需解密）——供 h3 归因 + 按连接 ID
    # 跨 IP 迁移/NAT 重绑关联（五元组聚合做不到）。各 set 有 per-flow 上限（见 _MAX_QUIC_CIDS）。
    quic_versions: set[str] = field(default_factory=set)
    quic_dcids: set[str] = field(default_factory=set)
    quic_scids: set[str] = field(default_factory=set)
    alpn: set[str] = field(default_factory=set)  # ALPN 协商协议（h3/h2/http1.1）——QUIC Initial 解出


@dataclass
class DnsRecord:
    """一条 DNS 查询/应答的结构化证据——保留 QTYPE/RCODE/answers，供 TXT 配置下发通道等直接入报告。"""

    qname: str
    qtype: int
    rcode: int
    txid: int = 0
    answers: list[dict] = field(default_factory=list)  # [{"type": int, "value": str, "ttl": int}]
    ts: float = 0.0


# TCP 连接态分级（远端聚合后据双向载荷/握手标志判定；与 Codex 交接 P0-1 口径一致）。
STATE_ESTABLISHED = "established"  # 双向均有应用层载荷 —— 已通信的真接入节点
STATE_SYN_ONLY = "syn_only"  # 仅本机 SYN、无 SYN-ACK、无任何载荷 —— 连接尝试/待核
STATE_RESET = "reset"  # 见 RST 且无载荷 —— 连接被拒/待核
STATE_UNKNOWN = "unknown"  # 其它（单向载荷、握手无数据等）

# 已知反诈拦截节点（Codex fengzhixin 案抓包交接 §6）：涉诈域名被拦后解析至此的拦截页 IP——非业务
# 接入/落地机。即便有双向载荷（拦截页会回数据）也必须与待核业务接入池严格区分、勿据此调证。
# 常量与判定已上移至 apkscan.network.fingerprints（供 pcap ingest 与归因桥接共用），此处经上方
# import 以 _KNOWN_FANZHA / is_known_intercept_ip 别名保留原有引用。


@dataclass
class ConnObs:
    """A2：一条本机↔远端连接的观测——本机临时端口 + pcap 流时间区间。供 socket_attr 五元组+时间窗归因
    把该远端消歧到具体 UID（floor pcap 帧时钟 = 设备时钟，可与设备侧 socket 观测区间直接比对）。"""

    local_port: int
    first_ts: float = 0.0
    last_ts: float = 0.0


@dataclass
class RemoteEndpoint:
    """按公网远端 (ip:port/proto) 跨多条 5 元组聚合的接入节点——分级 established/syn_only/reset/unknown。"""

    ip: str
    port: int
    proto: str
    out_bytes: int = 0  # 本机→远端 应用层载荷
    in_bytes: int = 0  # 远端→本机 应用层载荷
    packets: int = 0
    connection_count: int = 0  # 不同本机源端口数（连接尝试次数）
    flags: set[str] = field(default_factory=set)
    sni: set[str] = field(default_factory=set)
    ja3: set[str] = field(default_factory=set)
    first_ts: float = 0.0
    last_ts: float = 0.0
    state: str = STATE_UNKNOWN
    quic_versions: set[str] = field(default_factory=set)  # 该远端观测到的 QUIC 版本（h3 归因）
    alpn: set[str] = field(default_factory=set)  # ALPN 协商协议（h3/h2）——QUIC Initial 解出
    #: A2：每本机端口一条连接观测（本地端口 + 时间窗），供五元组归因消歧到 UID。connection_count 仍是
    #: 计数（可含同端口不同本机 IP），connections 按本地端口聚合两方向的时间区间。
    connections: list[ConnObs] = field(default_factory=list)

    @property
    def has_payload(self) -> bool:
        return self.out_bytes > 0 or self.in_bytes > 0


@dataclass
class PcapSummary:
    flows: list[Flow] = field(default_factory=list)
    dns_queries: set[str] = field(default_factory=set)
    dns_records: list[DnsRecord] = field(default_factory=list)
    #: 解析状态——让调用方区分「采集/解析失败」与「真实零业务流量」（二者过去都是空 flows）。
    #: ok=正常解析（flows 可为空=真零流量）；read_error=文件读失败；unparseable=非 pcap/pcapng（坏 magic/过短）；
    #: parse_error=解析中途异常。失败态时 flows 通常为空但**不代表**零流量，closure/pcap-leads 据此不误判。
    parse_status: str = "ok"
    error: str | None = None


# ---------------------------------------------------------------------------
# 解析入口
# ---------------------------------------------------------------------------


def _has_pcap_magic(data: bytes) -> bool:
    """前 4 字节是否 pcap/pcapng magic（经典 µs/ns 大小端 + pcapng SHB）。"""
    return len(data) >= 4 and data[:4] in (
        b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d", b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1", b"\x0a\x0d\x0d\x0a",
    )


def parse_pcap(path: str) -> PcapSummary:
    """读 pcap 文件并解析；文件缺失/坏 → **带失败态**的 summary（不抛）。"""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        logger.exception("[pcap] 读取 pcap 失败：%s", path)
        return PcapSummary(parse_status="read_error", error=f"{type(exc).__name__}: {exc}")
    return parse_pcap_bytes(data)


def parse_pcap_bytes(data: bytes) -> PcapSummary:
    """解析 pcap/pcapng 字节，聚合出 flows + DNS 查询。绝不抛。失败态写 parse_status/error。"""
    summ = PcapSummary()
    if not _has_pcap_magic(data):
        # 坏 magic / 过短 = 非 pcap/pcapng：显式标失败，不与「合法零流量」混同（否则 pcap-leads 误判采集成功）。
        summ.parse_status = "unparseable"
        summ.error = f"unrecognized magic {data[:4].hex()}" if data else "empty input"
        return summ
    # 有效 magic 但连头都放不下 = 截断文件：也标失败，别当「零流量」（经典全局头 24B、pcapng 最小 SHB 28B）。
    min_len = 28 if data[:4] == b"\x0a\x0d\x0d\x0a" else 24
    if len(data) < min_len:
        summ.parse_status = "unparseable"
        summ.error = f"truncated header: {len(data)} bytes (< {min_len})"
        return summ
    flows: dict[tuple, Flow] = {}
    asm = _HelloReassembler()  # 每份 pcap 独立、无模块级态（并行分析器安全）
    qdec = _QuicDecryptor()    # QUIC Initial 解密态（密钥缓存 + CRYPTO 重组），同样每份 pcap 独立
    diag: dict[str, object] = {}  # 迭代器回传：某记录/块声明字节数超出实际 → 文件中途截断
    try:
        for ts, linktype, frame in _iter_frames(data, diag):
            try:
                _process_frame(ts, linktype, frame, flows, summ, asm, qdec)
            except Exception:  # noqa: BLE001 - 单包坏不影响其余
                logger.debug("[pcap] 跳过坏包", exc_info=True)
    except Exception as exc:  # noqa: BLE001 - 整体解析异常也不抛
        logger.exception("[pcap] 解析异常")
        summ.parse_status = "parse_error"
        summ.error = f"{type(exc).__name__}: {exc}"
    # 收尾：对未凑齐的 stitch（snaplen 截断/丢续段）best-effort 捞 SNI 回填对应 Flow（复审 #2：
    # 恢复旧代码对截断 record 能捞出 SNI 的行为，弃 JA3 以不产出算错值）。
    asm.drain()
    for dkey, sni in asm.salvaged:
        f = flows.get(("tcp", *dkey))
        if f is not None:
            f.sni.add(sni)
    summ.flows = list(flows.values())
    if summ.parse_status == "ok" and diag.get("truncated"):
        # 有效头但文件中途截断（某记录/块声明字节数超出实际）：flows 可能不全——显式标 truncated，
        # 不当「ok 零/完整流量」，操作员据此知道要重抓（区别于干净零流量或完整解析）。
        summ.parse_status = "truncated"
        summ.error = "capture truncated mid-file (a record/block claims more bytes than present)"
    return summ


# ---------------------------------------------------------------------------
# 帧迭代：经典 pcap + pcapng（best-effort）
# ---------------------------------------------------------------------------


def _iter_frames(data: bytes, diag: dict[str, object] | None = None) -> Iterator[tuple[float, int, bytes]]:
    if len(data) < 24:
        return
    magic = data[:4]
    # 经典 pcap 有微秒(a1b2c3d4 / d4c3b2a1)与纳秒(a1b23c4d / 4d3cb2a1)两种精度魔数,
    # 小数字段除数不同:µs→1e6、ns→1e9。混用会让 observed_at 偏移最多近千秒。
    if magic == b"\xa1\xb2\xc3\xd4":
        endian, frac_div = ">", 1e6
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, frac_div = ">", 1e9
    elif magic == b"\xd4\xc3\xb2\xa1":
        endian, frac_div = "<", 1e6
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, frac_div = "<", 1e9
    elif magic == b"\x0a\x0d\x0d\x0a":
        yield from _iter_pcapng(data, diag)
        return
    else:
        logger.info("[pcap] 非 pcap/pcapng（magic=%s），跳过", magic.hex())
        return
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    n = len(data)
    while off + 16 <= n:
        ts_sec, ts_usec_or_nsec, incl, _orig = struct.unpack(endian + "IIII", data[off : off + 16])
        off += 16
        if incl < 0 or off + incl > n:
            if diag is not None:  # 记录声明字节数超出实际 = 文件中途截断（有效头、非坏 magic）
                diag["truncated"] = True
            break
        frame = data[off : off + incl]
        off += incl
        yield (float(ts_sec) + ts_usec_or_nsec / frac_div, linktype, frame)


def _pcapng_if_tsresol(idb_body: bytes, endian: str) -> float:
    """从 IDB 选项解析 if_tsresol(code 9) → 时间戳除数。缺省 1e6（微秒）。

    值字节 v：MSB=0 → 10^(v&0x7f) 秒的负幂（如 v=6→µs=1e6、v=9→ns=1e9）；MSB=1 → 2^(v&0x7f)。
    没有它就默认微秒——旧代码对所有 EPB 硬编码 /1e6，遇纳秒(if_tsresol=9)的 pcapng 会把时间戳放大 1000×，
    与 socket 时间线形成假「已知冲突」、把本应 confirmed 的五元组归因误降级。
    """
    # IDB body: linktype(2) reserved(2) snaplen(4) 之后是 options(TLV: code(2) len(2) value 4字节对齐)。
    opt = 8
    while opt + 4 <= len(idb_body):
        code, length = struct.unpack(endian + "HH", idb_body[opt : opt + 4])
        opt += 4
        if code == 0:  # opt_endofopt
            break
        if code == 9 and length >= 1:  # if_tsresol
            v = idb_body[opt]
            return float(2 ** (v & 0x7F)) if (v & 0x80) else float(10 ** (v & 0x7F))
        opt += (length + 3) & ~3  # 4 字节对齐
    return 1e6


def _iter_pcapng(data: bytes, diag: dict[str, object] | None = None) -> Iterator[tuple[float, int, bytes]]:
    """最小 pcapng：按 section 跟踪字节序 + 每接口 linktype/if_tsresol，产出 Enhanced/Simple Packet Block 的帧。"""
    n = len(data)
    if n < 12:
        return
    endian = "<"  # 占位，遇首个 SHB 即按其 byte-order magic 重定
    linktypes: list[int] = []
    tsresols: list[float] = []
    off = 0
    while off + 8 <= n:
        # SHB 的 block type 0x0A0D0D0A 字节序无关（回文）——每遇 SHB 重定本 section 字节序 + 重置接口表
        # （pcapng 允许多 section 用不同字节序；旧代码只在首个 SHB 判一次，后续异序 section 被误解或停止）。
        if data[off : off + 4] == b"\x0a\x0d\x0d\x0a":
            if off + 12 > n:
                if diag is not None:
                    diag["truncated"] = True
                break
            endian = "<" if data[off + 8 : off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            linktypes = []
            tsresols = []
        btype, blen = struct.unpack(endian + "II", data[off : off + 8])
        if blen < 12 or off + blen > n:
            if diag is not None and off + blen > n:  # 块长越界=中途截断（blen<12 是坏块结构，非截断，不误标）
                diag["truncated"] = True
            break
        body = data[off + 8 : off + blen - 4]
        if btype == 0x00000001:  # IDB: linktype(2) reserved(2) snaplen(4) options...
            if len(body) >= 2:
                linktypes.append(struct.unpack(endian + "H", body[:2])[0])
                tsresols.append(_pcapng_if_tsresol(body, endian))
        elif btype == 0x00000006:  # EPB: interface_id(4) ts_hi(4) ts_lo(4) caplen(4) origlen(4) data
            if len(body) >= 20:
                if_id, ts_hi, ts_lo, caplen, _orig = struct.unpack(endian + "IIIII", body[:20])
                # 非法 interface_id（越界或尚无 IDB）= malformed 块：跳过，不借用接口 0 的 linktype/tsresol 误解。
                # linktypes/tsresols 逐 IDB 成对追加，len 一致，故 if_id 合法即两者都可安全索引。
                if if_id < len(linktypes):
                    frame = body[20 : 20 + caplen]
                    yield (((ts_hi << 32) | ts_lo) / tsresols[if_id], linktypes[if_id], frame)
        elif btype == 0x00000003:  # Simple Packet Block：无时间戳 → 0.0（下游按 <=0 = 未知处理，不当真时刻）
            lt = linktypes[0] if linktypes else 1
            if len(body) >= 4:
                yield (0.0, lt, body[4:])
        off += blen


# ---------------------------------------------------------------------------
# 链路层 → IP → L4
# ---------------------------------------------------------------------------


def _strip_link(linktype: int, frame: bytes) -> tuple[int | None, bytes]:
    """剥链路层，返回 (ethertype, ip_payload)。ethertype 0x0800=IPv4 0x86dd=IPv6。"""
    if linktype == 1:  # Ethernet
        if len(frame) < 14:
            return None, b""
        et = struct.unpack("!H", frame[12:14])[0]
        payload = frame[14:]
        while et == 0x8100 and len(payload) >= 4:  # 802.1Q VLAN
            et = struct.unpack("!H", payload[2:4])[0]
            payload = payload[4:]
        return et, payload
    if linktype in (101, 12, 14):  # RAW IP
        if not frame:
            return None, b""
        ver = frame[0] >> 4
        return (0x0800 if ver == 4 else 0x86DD if ver == 6 else None), frame
    if linktype == 113:  # Linux SLL（v1，16 字节头）
        if len(frame) < 16:
            return None, b""
        return struct.unpack("!H", frame[14:16])[0], frame[16:]
    if linktype == 276:  # Linux SLL2（-i any 在 libpcap>=1.10 / tcpdump>=4.99 下的产物，20 字节头）
        if len(frame) < 20:
            return None, b""
        # SLL2：protocol(EtherType) 在头部 offset 0，IP 载荷从 offset 20 起。
        return struct.unpack("!H", frame[0:2])[0], frame[20:]
    if linktype == 0:  # BSD loopback
        if len(frame) < 4:
            return None, b""
        fam = struct.unpack("=I", frame[:4])[0]
        return (0x0800 if fam == 2 else 0x86DD), frame[4:]
    return None, b""


def _parse_ipv4(b: bytes) -> tuple[int, str, str, bytes] | None:
    """解析 IPv4 头，返回 ``(protocol, src, dst, L4 载荷)``。

    ★载荷必须按头里的 ``total_length`` 截断，不能一路切到帧尾：抓包工具会在 IP 数据之后
    追加自己的元数据（PCAPdroid 的 ``dump_extensions`` 就在帧尾附 UID/包名），那段字节
    若继续喂给 TCP/TLS 解析，碰上 ``0x16`` 开头就会被读成 ClientHello，解出**伪 SNI**。
    实测样本里目标的 30124/30139 后端因此被绑上了 zhihu.com / bilibili.com。  # leak-scan: allow SNI 伪装判据说明：借用的知名域名是被冒用方，非本方资产

    ``total_length`` 不可信（小于头长，或大于实际字节）时退回按实际字节切——宁可少截
    也不能因为一个坏字段把整包丢掉。
    """
    if len(b) < 20:
        return None
    ihl = (b[0] & 0x0F) * 4
    if ihl < 20 or len(b) < ihl:
        return None
    total_length = struct.unpack("!H", b[2:4])[0]
    end = total_length if ihl <= total_length <= len(b) else len(b)
    return b[9], socket.inet_ntoa(b[12:16]), socket.inet_ntoa(b[16:20]), b[ihl:end]


def _parse_ipv6(b: bytes) -> tuple[int, str, str, bytes] | None:
    """解析 IPv6 头，返回 ``(next-header, src, dst, L4 载荷)``；扩展头从简（非 6/17 即跳过）。

    与 IPv4 同理按 ``payload_length`` 截断——见 :func:`_parse_ipv4` 的说明。
    """
    if len(b) < 40:
        return None
    src = socket.inet_ntop(socket.AF_INET6, b[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, b[24:40])
    next_header = b[6]
    payload_length = struct.unpack("!H", b[4:6])[0]
    end = 40 + payload_length
    # ★payload_length==0 只在 next-header 是 Hop-by-Hop(0) 时才可能是 Jumbogram
    #   （RFC 2675：真实长度在逐跳选项里）。普通的零载荷 IPv6 包同样合法且常见，
    #   把它一律当 Jumbogram 退回全帧，等于又把抓包工具的帧尾元数据喂回给 L4 解析。
    if payload_length == 0:
        if next_header == 0:
            end = len(b)          # 可能是 Jumbogram，本层不解扩展头，保守取全部
        else:
            end = 40              # 确实没有载荷
    elif end > len(b):
        end = len(b)              # 抓包截断或字段坏 → 退回实际字节
    return next_header, src, dst, b[40:end]


def _parse_tcp(b: bytes) -> tuple[int, int, int, int, bytes] | None:
    if len(b) < 20:
        return None
    sport, dport = struct.unpack("!HH", b[:4])
    seq = struct.unpack("!I", b[4:8])[0]  # 序列号：跨段 TLS 握手重组用
    flags = b[13]  # TCP 标志字节（FIN/SYN/RST/PSH/ACK…）
    off = (b[12] >> 4) * 4
    if off < 20 or len(b) < off:
        return sport, dport, seq, flags, b""
    return sport, dport, seq, flags, b[off:]


def _parse_udp(b: bytes) -> tuple[int, int, bytes] | None:
    if len(b) < 8:
        return None
    sport, dport = struct.unpack("!HH", b[:4])
    return sport, dport, b[8:]


# ---------------------------------------------------------------------------
# QUIC（HTTP/3）长包头元数据（RFC 9000 §17.2）——纯 stdlib、零解密
# ---------------------------------------------------------------------------
# 现代 App 大量走 QUIC（UDP/443），mitm/frida 全看不到。长包头的 version/DCID/SCID 是**明文**，无需
# 任何密钥即可抽取：拿来做 h3 归因、按连接 ID 跨 IP 迁移/NAT 重绑关联（五元组做不到）、发现 QUIC-only
# 后端。★Initial 解密→SNI 是下一步（需惰性 cryptography），本层只做明文元数据、保住模块"零依赖"承诺。

_MAX_QUIC_CIDS = 8  # 每 Flow 各 QUIC set 上限（防海量连接 ID 撑内存）
#: 已知 QUIC 版本：v1(RFC 9000) / v2(RFC 9369)。★不收 vneg(0)：它由服务端在版本不匹配时回、无 h3 归因
#: 增量（同连接的客户端 Initial 是 v1、照样标 QUIC），且收录 0 会让 NTP 等全零填充协议包假阳（复审 #1/#3）。
_QUIC_KNOWN_VERSIONS = frozenset({0x00000001, 0x6B3343CF})


def _is_quic_version(v: int) -> bool:
    """v 是否像合法 QUIC 版本（挡随机 UDP 假阳）：已知版本 / draft(0xff0000xx) / GREASE(0x?a?a?a?a)。"""
    if v in _QUIC_KNOWN_VERSIONS:
        return True
    if (v & 0xFFFFFF00) == 0xFF000000:  # draft-ietf-quic-transport-xx
        return True
    return (v & 0x0F0F0F0F) == 0x0A0A0A0A  # GREASE（强制版本协商的保留版本）


def _parse_quic_long_header(app: bytes) -> tuple[str, str, str] | None:
    """解析 QUIC 长包头 → (version_hex, dcid_hex, scid_hex)；非 QUIC 长包头 → None。绝不抛。

    只读明文字段（version + 单字节 CID 长度 + CID）——token/length/包号/frame 是解密层的事（本层不碰）。
    """
    try:
        if len(app) < 7:
            return None
        if (app[0] & 0xC0) != 0xC0:  # QUIC 长包头恒 11xxxxxx（长包头位 0x80 + fixed bit 0x40）
            return None
        version = int.from_bytes(app[1:5], "big")
        if not _is_quic_version(version):  # 挡随机 UDP 假阳
            return None
        p = 5
        dcid_len = app[p]
        if dcid_len > 20 or p + 1 + dcid_len > len(app):  # RFC 9000：CID ≤ 20 字节
            return None
        p += 1
        dcid = app[p : p + dcid_len]
        p += dcid_len
        if p >= len(app):
            return None
        scid_len = app[p]
        if scid_len > 20 or p + 1 + scid_len > len(app):
            return None
        p += 1
        scid = app[p : p + scid_len]
        return f"{version:08x}", dcid.hex(), scid.hex()
    except Exception:  # noqa: BLE001 - 坏 QUIC 头不抛
        return None


def _ingest_quic(app: bytes, f: Flow, qdec: "_QuicDecryptor", flow_key: tuple) -> bool:
    """是 QUIC 长包头则抽元数据（+ v1 Initial 尝试解密→SNI/ALPN）填进 Flow、返回 True；否则 False
    （供调用方决定是否再当 DNS 解——内容优先派发）。"""
    meta = _parse_quic_long_header(app)
    if meta is None:
        return False
    version, dcid, scid = meta
    if len(f.quic_versions) < _MAX_QUIC_CIDS:
        f.quic_versions.add(version)
    if dcid and len(f.quic_dcids) < _MAX_QUIC_CIDS:
        f.quic_dcids.add(dcid)
    if scid and len(f.quic_scids) < _MAX_QUIC_CIDS:
        f.quic_scids.add(scid)
    # v1 Initial（type 位 00）且 cryptography 可用 → 解密取 ClientHello 的 SNI/ALPN（QUIC 全密文时唯一
    # 应用层线索，与 TCP「SNI 不丢」对等）。Initial 密钥仅依赖明文 DCID，无需任何会话密钥。
    if version == "00000001" and (app[0] & 0x30) == 0 and qdec.available:
        _ingest_quic_initial(app, f, qdec, flow_key)
    return True


# ---------------------------------------------------------------------------
# QUIC Initial 解密（RFC 9001）：Initial 密钥从公开 DCID 派生 → 去头保护 → AEAD → CRYPTO → ClientHello
# ---------------------------------------------------------------------------
# ★纯取证解析、零注入：Initial 密钥仅依赖**明文** DCID，无需任何会话密钥；1-RTT 应用数据不解（需会话
# 密钥）。cryptography 惰性引入（非 fxapk 声明依赖）——缺库则本层静默禁用、只落 QUIC 元数据，模块其余
# 保持零依赖、绝不抛。密钥派生已对 RFC 9001 §A.1 官方向量（iv/hp）逐字节验证。

_QUIC_INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")  # RFC 9001 §5.2 v1
_MAX_QUIC_CRYPTO = 65536   # 单连接 CRYPTO 重组缓冲上限（真实 ClientHello <16KB，封 64KiB）
_MAX_QUIC_PENDING = 512    # 并发 CRYPTO 重组连接上限（超出 FIFO 淘汰最老）
_MAX_QUIC_DONE = 4096      # tombstone 上限
_MAX_QUIC_KEYS = 4096      # Initial 密钥缓存上限（DCID 明文可随时重派生，FIFO 淘汰无正确性代价；防无界 DoS）


def _quic_crypto_available() -> bool:
    """探 cryptography 是否可用（一次性，缺库则 QUIC 解密静默禁用、只落元数据）。"""
    try:
        import cryptography.hazmat.primitives.ciphers.aead  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def _read_quic_varint(b: bytes, p: int) -> tuple[int, int] | None:
    """RFC 9000 §16 变长整数 → (value, new_offset)；越界 → None。"""
    if p >= len(b):
        return None
    ln = 1 << (b[p] >> 6)
    if p + ln > len(b):
        return None
    val = b[p] & 0x3F
    for i in range(1, ln):
        val = (val << 8) | b[p + i]
    return val, p + ln


def _quic_client_initial_keys(dcid: bytes, cache: dict) -> tuple[bytes, bytes, bytes] | None:
    """RFC 9001 §5.2：客户端原始 DCID → client Initial (key, iv, hp)。缺 cryptography / 失败 → None。缓存。"""
    if dcid in cache:
        return cache[dcid]
    keys: tuple[bytes, bytes, bytes] | None = None
    try:
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.hazmat.primitives.hmac import HMAC
        from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

        def expand(secret: bytes, label: bytes, length: int) -> bytes:
            full = b"tls13 " + label  # RFC 8446 HKDF-Expand-Label 前缀
            info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
            return HKDFExpand(algorithm=SHA256(), length=length, info=info).derive(secret)

        h = HMAC(_QUIC_INITIAL_SALT, SHA256())
        h.update(dcid)
        cs = expand(h.finalize(), b"client in", 32)
        keys = (expand(cs, b"quic key", 16), expand(cs, b"quic iv", 12), expand(cs, b"quic hp", 16))
    except Exception:  # noqa: BLE001 - 密钥派生失败静默降级
        keys = None
    if len(cache) >= _MAX_QUIC_KEYS:
        cache.pop(next(iter(cache)), None)  # FIFO 淘汰最老（复审 #B：防唯一 DCID 洪水撑爆缓存）
    cache[dcid] = keys
    return keys


def _quic_try_decrypt(
    app: bytes, pn_off: int, length: int, keys: tuple[bytes, bytes, bytes]
) -> bytes | None:
    """用给定 (key,iv,hp) 对一个 v1 Initial 去头保护 + AES-128-GCM 解密 → 明文 frames；tag 不符 → None。"""
    try:
        key, iv, hp = keys
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        sample = app[pn_off + 4 : pn_off + 4 + 16]
        # ★AES-ECB 仅用于 RFC 9001 §5.4.1 规定的**头保护掩码**派生（对单个 16B sample 出 5B mask），
        #   非数据加密——QUIC 协议要求，勿按"ECB 泄露结构"误报。
        mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(sample)[:5]  # noqa: S305
        first = app[0] ^ (mask[0] & 0x0F)
        pnl = (first & 0x03) + 1
        if pn_off + pnl > len(app):
            return None
        pn_bytes = bytes(app[pn_off + i] ^ mask[1 + i] for i in range(pnl))
        header = bytes([first]) + app[1:pn_off] + pn_bytes  # AAD = 去保护后的完整头
        ct = app[pn_off + pnl : pn_off + length]
        nonce = bytes(x ^ y for x, y in zip(iv, b"\x00" * (12 - pnl) + pn_bytes))
        return AESGCM(key).decrypt(nonce, ct, header)  # tag 不符则抛 → None（天然过滤坏包/错密钥）
    except Exception:  # noqa: BLE001
        return None


def _decrypt_quic_initial(
    app: bytes, qdec: "_QuicDecryptor", flow_key: tuple
) -> tuple[tuple, bytes] | None:
    """解 v1 Initial → (重组桶键=flow_key, 明文 frames)。AEAD 失败/非 v1/坏包 → None。绝不抛。

    ★RFC 9001 §5.2：整条连接的 Initial 密钥固定由客户端**首个** DCID 派生（DCID 切换后不变，仅 Retry
    重算）。故按候选序试：已记录的连接原始 DCID 优先（覆盖 §7.2 服务端回包后切 DCID 的重传），回退本包
    DCID（覆盖首包 / Retry 重派生）；某候选 AEAD 成功即记住它。重组按 flow_key 分桶（非 per-packet DCID，
    否则切换后同连接被劈成两桶永不凑齐，复审 #A）。
    """
    try:
        if len(app) < 7 or (app[0] & 0xC0) != 0xC0 or int.from_bytes(app[1:5], "big") != 1:
            return None
        p = 5
        dl = app[p]
        p += 1
        if dl > 20 or p + dl > len(app):
            return None
        dcid = app[p : p + dl]
        p += dl
        if p >= len(app):
            return None
        sl = app[p]
        p += 1
        if sl > 20 or p + sl > len(app):
            return None
        p += sl  # 跳 SCID
        tv = _read_quic_varint(app, p)  # token length
        if tv is None:
            return None
        token_len, p = tv
        p += token_len
        lv = _read_quic_varint(app, p)  # length（= 包号 + 载荷含 16B AEAD tag）
        if lv is None:
            return None
        length, p = lv
        pn_off = p
        if pn_off + 4 + 16 > len(app) or pn_off + length > len(app) or length < 20:
            return None
        prior = qdec.conn_dcid.get(flow_key)
        seen: set[bytes] = set()
        for cand in (prior, dcid):  # 连接原始 DCID 优先，回退本包 DCID
            if cand is None or cand in seen:
                continue
            seen.add(cand)
            keys = _quic_client_initial_keys(cand, qdec.key_cache)
            if keys is None:
                continue
            plain = _quic_try_decrypt(app, pn_off, length, keys)
            if plain is not None:
                if len(qdec.conn_dcid) >= _MAX_QUIC_PENDING:
                    qdec.conn_dcid.pop(next(iter(qdec.conn_dcid)), None)  # FIFO 有界
                qdec.conn_dcid[flow_key] = cand  # 记住成功的连接 DCID（Retry 回退成功时自动更新）
                return flow_key, plain
        return None
    except Exception:  # noqa: BLE001 - 解密失败（服务端包/非 v1/坏包/无 cryptography）静默 None
        return None


def _collect_crypto_frames(plain: bytes) -> dict[int, bytes]:
    """遍历 QUIC frame 收 CRYPTO(0x06) → {offset: data}。PADDING/PING 跳；未知 frame 停。绝不抛。"""
    chunks: dict[int, bytes] = {}
    try:
        p = 0
        n = len(plain)
        while p < n and len(chunks) < _MAX_OOO_CHUNKS:
            ft = plain[p]
            p += 1
            if ft in (0x00, 0x01):  # PADDING / PING
                continue
            if ft != 0x06:  # 其它 frame（ACK 等结构复杂）→ 停（Initial 里 CRYPTO 通常靠前）
                break
            ov = _read_quic_varint(plain, p)
            if ov is None:
                break
            off, p = ov
            lv = _read_quic_varint(plain, p)
            if lv is None:
                break
            clen, p = lv
            if p + clen > n or clen > _MAX_QUIC_CRYPTO:
                break
            chunks[off] = plain[p : p + clen]
            p += clen
    except Exception:  # noqa: BLE001 - 坏 frame 不抛
        return chunks
    return chunks


@dataclass
class _QuicCryptoState:
    """某 DCID 的 CRYPTO 流重组暂存：自 offset 0 起连续前缀 buf + 乱序段 ooo。"""

    buf: bytearray = field(default_factory=bytearray)
    ooo: dict[int, bytes] = field(default_factory=dict)
    ooo_bytes: int = 0
    needed: int | None = None


class _QuicCryptoReassembler:
    """按 DCID 重组跨 Initial 包/乱序的 CRYPTO 流 → 完整 ClientHello handshake。有界，绝不 OOM。"""

    def __init__(self) -> None:
        self.pending: dict[object, _QuicCryptoState] = {}
        self.done: dict[object, None] = {}

    def _kill(self, dcid: object) -> None:
        self.pending.pop(dcid, None)
        self.done[dcid] = None
        if len(self.done) > _MAX_QUIC_DONE:
            self.done.pop(next(iter(self.done)), None)

    def feed(self, dcid: object, chunks: dict[int, bytes]) -> bytes | None:
        """喂一个 Initial 解出的 CRYPTO 片段集；凑齐 ClientHello 返回其字节，否则 None。绝不抛。"""
        if not chunks or dcid in self.done:
            return None
        st = self.pending.get(dcid)
        if st is None:
            if len(self.pending) >= _MAX_QUIC_PENDING:
                self.pending.pop(next(iter(self.pending)), None)  # FIFO 淘汰最老
            st = _QuicCryptoState()
            self.pending[dcid] = st
        for off in sorted(chunks):
            self._place(st, off, chunks[off])
            if st.ooo_bytes + len(st.buf) > _MAX_QUIC_CRYPTO:
                self._kill(dcid)
                return None
        return self._try_complete(dcid, st)

    def _place(self, st: _QuicCryptoState, off: int, data: bytes) -> None:
        blen = len(st.buf)
        if off == blen:
            st.buf += data
            while len(st.buf) in st.ooo:  # 补洞
                seg = st.ooo.pop(len(st.buf))
                st.ooo_bytes -= len(seg)
                st.buf += seg
        elif off < blen:  # 重叠：first-writer-wins，掐已覆盖前缀
            extra = data[blen - off :]
            if extra:
                st.buf += extra
        elif off <= _MAX_QUIC_CRYPTO and data:  # 乱序超前段（空段不占坑）
            if off not in st.ooo and len(st.ooo) < _MAX_OOO_CHUNKS:
                st.ooo[off] = data
                st.ooo_bytes += len(data)

    def _try_complete(self, dcid: object, st: _QuicCryptoState) -> bytes | None:
        if st.needed is None and len(st.buf) >= 4:
            if st.buf[0] != 0x01:  # 非 client_hello → 弃
                self._kill(dcid)
                return None
            st.needed = 4 + int.from_bytes(bytes(st.buf[1:4]), "big")
            if st.needed > _MAX_QUIC_CRYPTO:
                self._kill(dcid)
                return None
        if st.needed is not None and len(st.buf) >= st.needed:
            hs = bytes(st.buf[: st.needed])
            self._kill(dcid)
            return hs
        return None


class _QuicDecryptor:
    """每份 pcap 一个：QUIC Initial 密钥缓存 + CRYPTO 重组器 + cryptography 可用性（无模块级态）。"""

    def __init__(self) -> None:
        self.key_cache: dict[bytes, tuple[bytes, bytes, bytes] | None] = {}
        self.conn_dcid: dict[tuple, bytes] = {}  # 客户端→服务端流键 → 连接原始 DCID（RFC 9001 §5.2）
        self.reasm = _QuicCryptoReassembler()
        self.available = _quic_crypto_available()


def _ingest_quic_initial(app: bytes, f: Flow, qdec: "_QuicDecryptor", flow_key: tuple) -> None:
    """解 v1 Initial → CRYPTO 重组 → ClientHello 的 SNI/ALPN 填 Flow。任何失败静默降级（仍有元数据）。"""
    try:
        dec = _decrypt_quic_initial(app, qdec, flow_key)
        if dec is None:
            return
        bucket, plain = dec
        hs = qdec.reasm.feed(bucket, _collect_crypto_frames(plain))
        if hs is None:
            return
        sni, _ja3v, alpn = _parse_hs_client_hello(hs)
        if sni:
            f.sni.add(sni)
        for a in alpn[:8]:
            f.alpn.add(a)
    except Exception:  # noqa: BLE001 - QUIC 解密任何异常不抛
        logger.debug("[pcap] QUIC Initial 处理异常（忽略）", exc_info=True)


def _process_frame(
    ts: float, linktype: int, frame: bytes, flows: dict, summ: PcapSummary,
    asm: _HelloReassembler, qdec: "_QuicDecryptor",
) -> None:
    et, ipp = _strip_link(linktype, frame)
    if not ipp:
        return
    if et == 0x0800:
        info = _parse_ipv4(ipp)
    elif et == 0x86DD:
        info = _parse_ipv6(ipp)
    else:
        return
    if info is None:
        return
    proto_num, src_ip, dst_ip, l4 = info
    tcp_flags = 0
    if proto_num == 6:
        tcp_parsed = _parse_tcp(l4)
        if tcp_parsed is None:
            return
        sport, dport, seq, tcp_flags, app = tcp_parsed
        proto = "tcp"
    elif proto_num == 17:
        udp_parsed = _parse_udp(l4)
        if udp_parsed is None:
            return
        sport, dport, app = udp_parsed
        proto = "udp"
    else:
        return
    key = (proto, src_ip, sport, dst_ip, dport)
    f = flows.get(key)
    if f is None:
        f = Flow(proto, src_ip, sport, dst_ip, dport, first_ts=ts)
        flows[key] = f
    f.packets += 1
    f.bytes_ += len(frame)
    f.last_ts = ts
    f.payload_bytes += len(app)  # TCP/UDP 均计 L4 应用层载荷（UDP C2/QUIC 只有 UDP 载荷也算有载荷）
    if proto_num == 6:
        for name, bit in (("fin", 0x01), ("syn", 0x02), ("rst", 0x04), ("psh", 0x08), ("ack", 0x10)):
            if tcp_flags & bit:
                f.flags.add(name)
        if (tcp_flags & 0x02) and (tcp_flags & 0x10):  # SYN+ACK = 本流方向为"远端→本机"的握手应答
            f.flags.add("synack")
        dkey = (src_ip, sport, dst_ip, dport)
        if (tcp_flags & 0x02) and not (tcp_flags & 0x10):
            # 纯 SYN = 新连接：四元组复用则清该方向旧 stitch/tombstone。否则残留态会把新连接完整落
            # 单段的 ClientHello 引流进重组、按随机 ISN 算错偏移丢弃 → 破坏现有单段解析（复审 #1/#5）。
            asm.reset(dkey)
        # TLS 握手 record：完整落在本段内 → 走今天原样快路径（现有用例字节级不变）；不完整或该方向
        # 已在跨段 stitch 中 → 交定向重组器凑齐 record 再解，让跨段 ClientHello 的 SNI/JA3 不丢。
        r: tuple[str | None, str | None] | None = None
        if app[:1] == b"\x16":
            rec_len = struct.unpack("!H", app[3:5])[0] if len(app) >= 5 else -1
            if rec_len >= 0 and len(app) >= 5 + rec_len and dkey not in asm.pending:
                r = _parse_client_hello(app)
            else:
                r = asm.feed(dkey, seq, app, f.payload_bytes)
        elif app and dkey in asm.pending:  # continuation 段（非 0x16、非空）→ 补洞（空段不入，复审 #6）
            r = asm.feed(dkey, seq, app, f.payload_bytes)
        if r is not None:
            sni, ja3 = r
            if sni:
                f.sni.add(sni)
            if ja3:
                f.ja3.add(ja3)
        if (dport == 53 or sport == 53) and app:
            # ★DNS over TCP（RFC 1035 §4.2.2）：报文前置 2 字节长度前缀，其余与 UDP 同构。
            #   此前整个 TCP 分支不解 DNS，于是走 TCP/53 的采集**一条记录都出不来**——
            #   而这不是罕见形态：应答超 512 字节被 TC 截断后客户端就改走 TCP，部分系统解析器
            #   也直接用 TCP。实测本仓一份在手采集正是 223.5.5.5/tcp，24 个包解出 0 条记录，
            #   报告里显示"未观测到 DNS"，与"确实没查过域名"完全无法区分。
            for msg in _iter_tcp_dns_messages(app):
                qn = _parse_dns_qname(msg)
                if qn:
                    summ.dns_queries.add(qn)
                rec = _parse_dns(msg, ts)
                if rec is not None:
                    summ.dns_records.append(rec)
    if proto_num == 17 and app:
        # 内容优先派发：先看是不是 QUIC 长包头（严格 0xC0 门 + 版本白名单，真 DNS 命不中）——是则抽 QUIC
        # 元数据、**不**再当 DNS（哪怕在 UDP/53：反取证 C2 常把 QUIC 伪装到防火墙放行的 53，复审 #2）；
        # 否则若在 53 端口才当 DNS 解。
        if not _ingest_quic(app, f, qdec, (src_ip, sport, dst_ip, dport)) and (dport == 53 or sport == 53):
            qn = _parse_dns_qname(app)
            if qn:
                summ.dns_queries.add(qn)
            rec = _parse_dns(app, ts)
            if rec is not None:
                summ.dns_records.append(rec)


# ---------------------------------------------------------------------------
# TLS ClientHello（SNI + JA3）/ DNS
# ---------------------------------------------------------------------------


def _u16_list(b: bytes) -> list[int]:
    return [struct.unpack("!H", b[i : i + 2])[0] for i in range(0, len(b) - 1, 2)]


def _parse_sni_ext(ev: bytes) -> str | None:
    if len(ev) < 5:
        return None
    p = 2  # 跳 server_name_list 长度
    while p + 3 <= len(ev):
        ntype = ev[p]
        nlen = struct.unpack("!H", ev[p + 1 : p + 3])[0]
        name = ev[p + 3 : p + 3 + nlen]
        p += 3 + nlen
        if ntype == 0:  # host_name
            try:
                return name.decode("ascii")
            except UnicodeDecodeError:
                return name.decode("utf-8", "replace")
    return None


def _ja3(ver: int, ciphers: list[int], exts: list[int], curves: list[int], formats: list[int]) -> str:
    def j(lst: list[int]) -> str:
        return "-".join(str(x) for x in lst if x not in _GREASE)

    s = f"{ver},{j(ciphers)},{j(exts)},{j(curves)},{j(formats)}"
    return hashlib.md5(s.encode()).hexdigest()  # noqa: S324 - JA3 规范就是 md5，非安全用途


def _parse_alpn_ext(ev: bytes) -> list[str]:
    """解 ALPN 扩展（RFC 7301）ProtocolNameList → 协议名列表（如 ['h3','h2']）。绝不抛。"""
    out: list[str] = []
    try:
        if len(ev) < 2:
            return out
        total = struct.unpack("!H", ev[:2])[0]
        p = 2
        end = min(2 + total, len(ev))
        while p < end:
            ln = ev[p]
            p += 1
            if ln == 0 or p + ln > end:
                break
            name = ev[p : p + ln].decode("ascii", "replace")
            if name:
                out.append(name)
            p += ln
            if len(out) >= 16:
                break
    except Exception:  # noqa: BLE001 - 坏 ALPN 不抛
        return out
    return out


def _parse_hs_client_hello(hs: bytes) -> tuple[str | None, str | None, list[str]]:
    """解析**裸** TLS handshake ClientHello 消息（无 5 字节 record 头）→ (sni, ja3, alpn)。绝不抛。

    QUIC 的 CRYPTO 流里是裸 handshake（无 record 层）；TCP 侧剥掉 record 头后也复用此函数。
    """
    try:
        if len(hs) < 4 or hs[0] != 0x01:  # client_hello
            return None, None, []
        hs_len = int.from_bytes(hs[1:4], "big")
        body = hs[4 : 4 + hs_len]
        p = 0
        client_ver = struct.unpack("!H", body[p : p + 2])[0]
        p += 2 + 32  # version + random
        sid_len = body[p]
        p += 1 + sid_len
        cs_len = struct.unpack("!H", body[p : p + 2])[0]
        p += 2
        ciphers = _u16_list(body[p : p + cs_len])
        p += cs_len
        comp_len = body[p]
        p += 1 + comp_len
        sni: str | None = None
        alpn: list[str] = []
        curves: list[int] = []
        formats: list[int] = []
        ext_types: list[int] = []
        if p + 2 <= len(body):
            ext_total = struct.unpack("!H", body[p : p + 2])[0]
            p += 2
            end = min(p + ext_total, len(body))
            while p + 4 <= end:
                et = struct.unpack("!H", body[p : p + 2])[0]
                el = struct.unpack("!H", body[p + 2 : p + 4])[0]
                ev = body[p + 4 : p + 4 + el]
                p += 4 + el
                ext_types.append(et)
                if et == 0x0000:
                    sni = _parse_sni_ext(ev)
                elif et == 0x0010:  # ALPN（h3/h2 归因）
                    alpn = _parse_alpn_ext(ev)
                elif et == 0x000A and len(ev) >= 2:
                    curves = _u16_list(ev[2:])
                elif et == 0x000B and ev:
                    formats = list(ev[1:])
        return sni, _ja3(client_ver, ciphers, ext_types, curves, formats), alpn
    except Exception:  # noqa: BLE001 - 解析坏 ClientHello 不抛
        return None, None, []


def _parse_client_hello(rec: bytes) -> tuple[str | None, str | None]:
    """TLS **record** 层 ClientHello → (sni, ja3)（剥 5 字节 record 头后复用 _parse_hs_client_hello）。"""
    try:
        if len(rec) < 5 or rec[0] != 0x16:
            return None, None
        rec_len = struct.unpack("!H", rec[3:5])[0]
        sni, ja3, _alpn = _parse_hs_client_hello(rec[5 : 5 + rec_len])
        return sni, ja3
    except Exception:  # noqa: BLE001 - 解析坏 record 不抛
        return None, None


# ---------------------------------------------------------------------------
# ClientHello 跨段重组（P0 PCAP-first）
# ---------------------------------------------------------------------------
# 现代 Chrome/Cronet 的 ClientHello 常带 post-quantum key_share，超 1460B MSS 跨 2 个 TCP 段 —— 今天
# 逐包解析必丢 SNI/JA3。定向重组器：只在某方向**首个** TLS record 是 client_hello 且跨段时开有界缓冲，
# 按 seq 拼到 record 完整再喂 _parse_client_hello。纯解析、状态有界、绝不抛/绝不 OOM，不动 Flow schema，
# 不碰五元组聚合 / _KNOWN_FANZHA / netstate。顺带修掉：现有 _parse_client_hello 对截断 record 会静默算
# **错** JA3（扩展区没读全就提前退出），凑齐才解析天然消除之。
# ★不做（P1/授权动态分析）：通用双向流重组、HTTP 明文、跨多 record 的握手分片、ServerHello、QUIC。

_MAX_HELLO_BUF = 5 + 16384       # 单 stitch 缓冲上限（TLS 明文 record 上限；buf+ooo 合并计费）
_MAX_OOO_CHUNKS = 64             # 单 stitch 乱序段数上限（防碎段洪水撑 dict）
_MAX_STITCH_PKTS = 256           # 单 stitch 喂段数上限（封死慢速滴灌占坑；MSS≥536 时最大 record ~31 段）
_MAX_PENDING = 512               # 并发 stitch 上限（超出按插入序 FIFO 淘汰最老）
_MAX_DONE = 4096                 # tombstone 上限（防百万连接 pcap 撑爆）
_ANCHOR_MAX_PAYLOAD = 64 * 1024  # 锚窗：某方向累计载荷超此不再当锚（握手只在连接头部，挡长流密文伪锚）


@dataclass
class _HelloState:
    """某方向 ClientHello 跨段重组的暂存态：自 first_seq 起的连续前缀 buf + 乱序段 ooo 补洞。"""

    first_seq: int
    buf: bytearray
    needed: int | None = None  # 5 + rec_len；锚段不足 5 字节读不到时暂 None
    ooo: dict[int, bytes] = field(default_factory=dict)  # 乱序段：相对偏移 → payload
    ooo_bytes: int = 0
    pkts: int = 0


class _HelloReassembler:
    """按方向四元组 (src_ip,sport,dst_ip,dport) 重组跨 TCP 段的 TLS ClientHello（每份 pcap 一个实例）。

    唯一入口 :meth:`feed`：完整落在单段内的 CH 不进这里（调用方走快路径）；只有 record 不完整、或该方向
    已在 stitch 时才进来。重叠段 **first-writer-wins**（取证口径：确定性优先；重传内容一致，构造性不一致
    重叠只让本连接解析失败、不外溢）。任一上限超出 → 判死该状态、退回今天的单段行为，绝不抛、绝不 OOM。
    """

    def __init__(self) -> None:
        self.pending: dict[tuple, _HelloState] = {}
        self.done: dict[tuple, None] = {}
        self.salvaged: list[tuple[tuple, str]] = []  # 判死/EOF 对截断缓冲 best-effort 捞出的 SNI

    def reset(self, key: tuple) -> None:
        """纯 SYN 见新连接 → 清该方向重组残留（四元组复用，旧 stitch/tombstone 必失效，复审 #1/#5）。"""
        self.pending.pop(key, None)
        self.done.pop(key, None)

    def _kill(self, key: tuple) -> None:
        """杀死某方向的 stitch 并落 tombstone（一方向只试一次；tombstone 有上限、满则 FIFO 丢最老）。"""
        self.pending.pop(key, None)
        self.done[key] = None
        if len(self.done) > _MAX_DONE:
            self.done.pop(next(iter(self.done)), None)

    def _salvage(self, key: tuple, st: _HelloState) -> None:
        """record 凑不齐（snaplen 截断/丢续段）前，对已缓冲字节 best-effort 捞 SNI（弃 JA3，避免算错）。"""
        try:
            sni, _ja3 = _parse_client_hello(bytes(st.buf))
        except Exception:  # noqa: BLE001 - 捞 SNI 失败不影响主流程
            sni = None
        if sni:
            self.salvaged.append((key, sni))

    def _abandon(self, key: tuple, st: _HelloState) -> None:
        """判死未完成的 stitch：先 best-effort 捞 SNI 再落 tombstone（超限/丢段路径用）。"""
        self._salvage(key, st)
        self._kill(key)

    def drain(self) -> None:
        """解析结束：对 pending 里所有未完成 stitch best-effort 捞 SNI（不再落 tombstone）。"""
        for key, st in list(self.pending.items()):
            self._salvage(key, st)
        self.pending.clear()

    def feed(
        self, key: tuple, seq: int, app: bytes, flow_payload_bytes: int
    ) -> tuple[str | None, str | None] | None:
        """喂一个 TCP 段。返回 (sni, ja3)（record 凑齐并解析）或 None（还没齐/判死/非 CH）。绝不抛。"""
        try:
            if key in self.done:
                return None  # tombstone 短路：防长流密文里的 0x16 反复重开
            st = self.pending.get(key)
            if st is None:
                return self._anchor(key, seq, app, flow_payload_bytes)
            return self._absorb(key, st, seq, app)
        except Exception:  # noqa: BLE001 - 重组坏包不抛（外层已双保险，这里再兜一层）
            logger.debug("[pcap] ClientHello 重组异常（弃该方向）", exc_info=True)
            self._kill(key)
            return None

    def _anchor(
        self, key: tuple, seq: int, app: bytes, flow_payload_bytes: int
    ) -> tuple[str | None, str | None] | None:
        """锚门：仅当本段是某方向首个 TLS client_hello record（且跨段放不下）才建 stitch。"""
        if len(app) < 2 or app[0] != 0x16 or app[1] != 0x03:
            return None
        # 锚窗：握手只发生在连接头部；本段之前该方向累计载荷已超阈值 → 长流密文伪 0x16，不锚。
        if flow_payload_bytes - len(app) > _ANCHOR_MAX_PAYLOAD:
            return None
        if len(app) >= 6 and app[5] != 0x01:  # 非 client_hello（ServerHello/证书等）从不缓冲
            return None
        needed: int | None = None
        if len(app) >= 5:
            rec_len = struct.unpack("!H", app[3:5])[0]
            if rec_len > 16384:
                return None
            needed = 5 + rec_len
        if len(self.pending) >= _MAX_PENDING:
            old_key = next(iter(self.pending))  # FIFO 淘汰最老 stitch（淘汰前 best-effort 捞 SNI）
            self._salvage(old_key, self.pending.pop(old_key))
        st = _HelloState(first_seq=seq, buf=bytearray(app), needed=needed, pkts=1)
        self.pending[key] = st
        return self._try_complete(key, st)

    def _absorb(
        self, key: tuple, st: _HelloState, seq: int, app: bytes
    ) -> tuple[str | None, str | None] | None:
        """吸收续段/重传/乱序段。"""
        st.pkts += 1
        if st.pkts > _MAX_STITCH_PKTS:
            self._abandon(key, st)
            return None
        rel = (seq - st.first_seq) & 0xFFFFFFFF  # mod 2^32 天然处理 seq 回绕
        self._place(st, rel, app)
        # 补洞：弹出所有起点已被 buf 覆盖/衔接的乱序段（≤ 而非 ==；重叠前缀由 _place 的 rel<blen 掐掉，
        # 否则 repacketize 重传使 buf 一步越过某 ooo key 时该段永不 drain → 记账泄漏/永久洞，复审 #3）。
        while st.ooo:
            k = min(st.ooo)
            if k > len(st.buf):
                break
            seg = st.ooo.pop(k)
            st.ooo_bytes -= len(seg)
            self._place(st, k, seg)
        # 先试完成：本次 feed 已凑齐则切 record 解析，绝不因补洞后总账越限把已完整的 CH 误杀（复审 #4）。
        r = self._try_complete(key, st)
        if r is None and st.ooo_bytes + len(st.buf) > _MAX_HELLO_BUF:
            self._abandon(key, st)
        return r

    def _place(self, st: _HelloState, rel: int, app: bytes) -> None:
        """把一段按相对偏移放入缓冲：contiguous 追加 / 重叠掐前缀 / 超前存 ooo / 窗外丢弃。"""
        blen = len(st.buf)
        if rel == blen:
            st.buf += app
        elif rel < blen:  # 重传/重叠：first-writer-wins，掐掉已覆盖前缀
            extra = app[blen - rel:]
            if extra:
                st.buf += extra
        elif rel <= _MAX_HELLO_BUF and app:  # 乱序超前段：暂存补洞（空段不占坑，否则挡真数据，复审 #6）
            if rel not in st.ooo and len(st.ooo) < _MAX_OOO_CHUNKS:
                st.ooo[rel] = app
                st.ooo_bytes += len(app)
        # rel > _MAX_HELLO_BUF：垃圾/窗外/回绕旧段 → 丢弃

    def _try_complete(
        self, key: tuple, st: _HelloState
    ) -> tuple[str | None, str | None] | None:
        """buf 够长即读 needed、凑齐即切完整 record 喂 _parse_client_hello（一方向只试一次）。"""
        if st.needed is None and len(st.buf) >= 5:
            rec_len = struct.unpack("!H", bytes(st.buf[3:5]))[0]
            if rec_len > 16384:
                self._kill(key)
                return None
            st.needed = 5 + rec_len
        if st.needed is not None and len(st.buf) >= st.needed:
            rec = bytes(st.buf[: st.needed])
            self._kill(key)  # 重协商/多 CH 不管：现实客户端 CH 是一个大 record 跨多段
            return _parse_client_hello(rec)
        return None


#: 单个 TCP 段里最多取几条 DNS 消息。流水线查询会把多条塞进一段；封顶防构造出来的
#: 「一段几万条」把解析拖死（与 _MAX_QUIC_CIDS 等上限同一条防线）。
_MAX_TCP_DNS_PER_SEGMENT = 32


def _iter_tcp_dns_messages(app: bytes) -> list[bytes]:
    """从一个 TCP 段里切出完整的 DNS 报文（剥掉 RFC 1035 的 2 字节长度前缀）。

    ★只取**本段内完整**的报文，跨段的不拼。理由与 TLS 那边相反：ClientHello 跨段丢了
      就整条流没有 SNI，值得上重组器；而 DNS 跨段只影响那一条记录，为它引入第二套重组
      状态机（还要处理乱序/重传）风险高于收益。取不到就是取不到，绝不半解一条记录当证据。

    长度前缀本身可被伪造，故逐条校验：声明长度必须 ≥12（DNS 头长）且不超出剩余字节，
    否则**整段放弃**——继续往下猜偏移就是在编报文。
    """
    out: list[bytes] = []
    pos = 0
    while pos + 2 <= len(app) and len(out) < _MAX_TCP_DNS_PER_SEGMENT:
        size = struct.unpack("!H", app[pos:pos + 2])[0]
        if size < 12 or pos + 2 + size > len(app):
            break
        out.append(app[pos + 2:pos + 2 + size])
        pos += 2 + size
    return out


def _parse_dns_qname(b: bytes) -> str | None:
    if len(b) < 13:
        return None
    p = 12
    labels: list[str] = []
    while p < len(b):
        ln = b[p]
        if ln == 0:
            break
        if ln & 0xC0:  # 问题段里出现压缩指针（罕见）→ 放弃
            return None
        p += 1
        labels.append(b[p : p + ln].decode("ascii", "replace"))
        p += ln
        if len(labels) > 127:
            return None
    return ".".join(labels) if labels else None


def _read_name(msg: bytes, p: int) -> tuple[str, int]:
    """读 DNS 域名（支持 0xC0 压缩指针）；返回 (name, 指针后的偏移)。坏则返回 ("", p)。"""
    labels: list[str] = []
    jumped = False
    resume = p
    steps = 0
    while 0 <= p < len(msg):
        ln = msg[p]
        if ln == 0:
            p += 1
            break
        if ln & 0xC0 == 0xC0:  # 压缩指针
            if p + 1 >= len(msg):
                return "", resume
            ptr = ((ln & 0x3F) << 8) | msg[p + 1]
            if not jumped:
                resume = p + 2
            jumped = True
            p = ptr
            steps += 1
            if steps > 128:
                return ".".join(labels), resume
            continue
        p += 1
        labels.append(msg[p : p + ln].decode("ascii", "replace"))
        p += ln
        if len(labels) > 127:
            break
    return ".".join(labels), (resume if jumped else p)


def _decode_rdata(rtype: int, rdata: bytes, msg: bytes, rdata_off: int) -> str:
    """按 RR 类型解码 rdata → 可读值：A/AAAA=IP、CNAME/NS=域名、TXT=文本、其它=hex。绝不抛。"""
    try:
        if rtype == 1 and len(rdata) == 4:  # A
            return socket.inet_ntoa(rdata)
        if rtype == 28 and len(rdata) == 16:  # AAAA
            return socket.inet_ntop(socket.AF_INET6, rdata)
        if rtype in (5, 2, 12):  # CNAME / NS / PTR（可能含压缩指针，须在整包里读）
            name, _ = _read_name(msg, rdata_off)
            return name
        if rtype == 16:  # TXT：一或多段 长度前缀字符串
            out: list[str] = []
            i = 0
            while i < len(rdata):
                ln = rdata[i]
                i += 1
                out.append(rdata[i : i + ln].decode("ascii", "replace"))
                i += ln
            return "".join(out)
    except Exception:  # noqa: BLE001 - 单条 rdata 解码坏不抛
        return rdata.hex()
    return rdata.hex()


def _parse_dns(b: bytes, ts: float = 0.0) -> DnsRecord | None:
    """解析一条 DNS 报文（查询或应答）→ 结构化 DnsRecord（txid/qtype/rcode/answers）。绝不抛。

    保留 QTYPE/RCODE 与每条 answer 的 type/value/TTL——本案 TXT 配置下发通道(ClientCore 经
    DNS TXT 下发动态服务器 IP:端口)须能把 TXT 内容直接进报告，仅留 qname 会丢关键证据。
    """
    try:
        if len(b) < 12:
            return None
        txid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", b[:12])
        if qd < 1:
            return None
        rcode = flags & 0x000F
        qname, p = _read_name(b, 12)
        if p + 4 > len(b):
            return None
        qtype, _qclass = struct.unpack("!HH", b[p : p + 4])
        p += 4
        # 跳过其余问题段（通常 qd==1）。
        for _ in range(qd - 1):
            _n, p = _read_name(b, p)
            p += 4
            if p > len(b):
                return DnsRecord(qname=qname, qtype=qtype, rcode=rcode, txid=txid, ts=ts)
        answers: list[dict] = []
        for _ in range(an):
            if p >= len(b):
                break
            answer_name, p = _read_name(b, p)
            if p + 10 > len(b):
                break
            rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", b[p : p + 10])
            p += 10
            rdata = b[p : p + rdlen]
            value = _decode_rdata(rtype, rdata, b, p)
            p += rdlen
            # RR owner name 是还原 CNAME **边**所必需的。只留 value 只能得到一串目标名，
            # 无法证明哪一个名字指向哪一个名字；旧消费方仍可忽略这个纯追加字段。
            answers.append({"name": answer_name, "type": rtype, "value": value, "ttl": ttl})
        return DnsRecord(qname=qname, qtype=qtype, rcode=rcode, txid=txid, answers=answers, ts=ts)
    except Exception:  # noqa: BLE001 - 坏 DNS 报文不抛
        return None


# ---------------------------------------------------------------------------
# summary → Lead / 台账 / report.json
# ---------------------------------------------------------------------------


def _ip_public(ip: str) -> bool:
    """该地址是否算**可上报的远端**（摄取层口径），坏输入 → False。

    ★这与 ``infra.classify_ip`` 的"是否值得调证"是**两层不同的问题**，判据有意不同：

    ==================  ==========================  ==========================
    问题                本函数（摄取层）            classify_ip（出口层）
    ==================  ==========================  ==========================
    判据                非私网/回环/链路本地/       ``is_global``
                        多播/未指定/保留
    典型分歧            CGNAT ``100.64.0.0/10``     同一地址判"无需调证"
                        判 True（它确实是远端）     （运营商级 NAT，无调证对象）
    ==================  ==========================  ==========================

    **不要"顺手"把这里改成 ``is_global``**：本函数与 ``probe_ingest`` 的
    ``_ipv6_is_reportable`` / ``url_host_is_reportable`` 是**并集口径**——两条摄取
    路径的产出要合并，口径一旦不同，同一个后端就会被算两次。这三处的一致性由
    ``test_probe_ingest`` 的两条口径对齐测试锁着，单改本函数会直接把它们打红。

    收窄"要不要调证"应当在 ``classify_ip`` 那一层做，那里才有调证对象的概念。
    """
    try:
        a = ipaddress.ip_address(ip)
        return not (
            a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or a.is_reserved
        )
    except ValueError:
        return False


_IP_WHERE = "向云厂商 / IDC 调该 IP 的主机租户实名 + 入站连接日志（native/自建协议接入节点，穿透真源站锚点）。"
_DOMAIN_WHERE = "向注册商 / ICP 备案 / 云厂商调域名归属与租户实名。"


def _classify_state(re: "RemoteEndpoint") -> str:
    """据双向载荷 + 握手标志判连接态。双向载荷=established；仅 SYN 无应答无载荷=syn_only（待核）。"""
    if re.out_bytes > 0 and re.in_bytes > 0:
        return STATE_ESTABLISHED
    if re.has_payload:
        return STATE_UNKNOWN  # 单向有载荷：观测到数据但非双向（仍作线索，不降为待核）
    if "rst" in re.flags:
        return STATE_RESET
    if "syn" in re.flags and "synack" not in re.flags:
        return STATE_SYN_ONLY
    return STATE_UNKNOWN


def remote_endpoints(summary: PcapSummary) -> list[RemoteEndpoint]:
    """把 flows 按**公网远端** (ip:port/proto) 跨多条 5 元组聚合成接入节点，并分级连接态。

    本机↔远端两个方向（client→server / server→client）各自是一条 5 元组 Flow；此处按远端归并：
    - 本机→远端方向贡献 ``out_bytes`` + 本机侧标志（syn/rst）+ 连接尝试次数（不同本机源端口）;
    - 远端→本机方向贡献 ``in_bytes`` + 远端侧握手标志（synack）。
    仅公网远端入选（私网/回环远端跳过）。绝不抛。
    """
    agg: dict[tuple[str, str, int], RemoteEndpoint] = {}
    conn_src: dict[tuple[str, str, int], set[tuple[str, int]]] = {}
    #: A2：key → {本机端口: [first_ts, last_ts]}——按本机临时端口聚合两方向 Flow 的时间区间。
    conn_win: dict[tuple[str, str, int], dict[int, list[float]]] = {}

    def _touch(key: tuple[str, str, int], ip: str, port: int, proto: str) -> RemoteEndpoint:
        re = agg.get(key)
        if re is None:
            re = RemoteEndpoint(ip=ip, port=port, proto=proto)
            agg[key] = re
        return re

    def _touch_win(key: tuple[str, str, int], local_port: int, first_ts: float, last_ts: float) -> None:
        w = conn_win.setdefault(key, {}).get(local_port)
        if w is None:
            conn_win[key][local_port] = [first_ts, last_ts]
            return
        if first_ts and (w[0] == 0.0 or first_ts < w[0]):
            w[0] = first_ts
        if last_ts > w[1]:
            w[1] = last_ts

    for f in summary.flows:
        dst_pub = _ip_public(f.dst_ip)
        src_pub = _ip_public(f.src_ip)
        if dst_pub and not src_pub:
            remote_is_dst = True  # 本机(私)→远端(公)：出站
        elif src_pub and not dst_pub:
            remote_is_dst = False  # 远端(公)→本机(私)：入站
        elif dst_pub and src_pub:
            # 两端都公网（如移动网 IPv6 GUA 直连）——不丢弃：SYN 方向/端口启发式判哪端是远端。
            if "syn" in f.flags and "synack" not in f.flags:
                remote_is_dst = True  # 本机发起 SYN → dst 是远端
            elif "synack" in f.flags:
                remote_is_dst = False  # 见 SYN-ACK → src 是远端（服务端）
            else:
                remote_is_dst = f.dst_port <= f.src_port  # 端口小的一端更像服务端/远端
        else:
            continue  # 两端都私网：不产接入节点
        if remote_is_dst:  # 本机→远端：出站
            key = (f.proto, f.dst_ip, f.dst_port)
            re = _touch(key, f.dst_ip, f.dst_port, f.proto)
            re.out_bytes += f.payload_bytes
            re.flags |= {x for x in f.flags if x in ("syn", "rst", "fin", "ack", "psh")}
            re.sni |= f.sni
            re.ja3 |= f.ja3
            conn_src.setdefault(key, set()).add((f.src_ip, f.src_port))
            _touch_win(key, f.src_port, f.first_ts, f.last_ts)  # 出站：本机端口 = src_port
        else:  # 远端→本机：入站
            key = (f.proto, f.src_ip, f.src_port)
            re = _touch(key, f.src_ip, f.src_port, f.proto)
            re.in_bytes += f.payload_bytes
            if "synack" in f.flags:
                re.flags.add("synack")
            if "rst" in f.flags:
                re.flags.add("rst")
            re.sni |= f.sni
            re.ja3 |= f.ja3
            conn_src.setdefault(key, set()).add((f.dst_ip, f.dst_port))  # 入站方向也计本机端口(P1)
            _touch_win(key, f.dst_port, f.first_ts, f.last_ts)  # 入站：本机端口 = dst_port
        re.packets += f.packets
        re.quic_versions |= f.quic_versions  # QUIC 版本聚合到远端（两方向共用）
        re.alpn |= f.alpn  # ALPN 聚合到远端
        if f.first_ts and (re.first_ts == 0.0 or f.first_ts < re.first_ts):
            re.first_ts = f.first_ts
        if f.last_ts > re.last_ts:
            re.last_ts = f.last_ts

    for key, re in agg.items():
        re.connection_count = len(conn_src.get(key, set()))
        re.connections = [
            ConnObs(local_port=p, first_ts=w[0], last_ts=w[1])
            for p, w in sorted(conn_win.get(key, {}).items())
        ]
        re.state = _classify_state(re)
    # ★按 (ip, port, proto) 排序输出：dict 保插入序＝flow 序，同一组观测换个输入顺序
    #   就产生报告 diff。聚合键本身是 (proto, ip, port)，这里显式重排——读报告的人按 IP
    #   找端点，同 IP 的多端口要挨在一起，不能被 tcp/udp 分栏拆开（codex 复审 P2）。
    return [
        agg[key]
        for key in sorted(agg, key=lambda key: (key[1], key[2], key[0]))
    ]


#: SNI→运营方这条推断成立的前提：该 TLS 服务跑在**约定端口**上。
#: 只收公认的 TLS 端口——名单越长判据越弱，这里刻意保持窄。
_STANDARD_TLS_PORTS: frozenset[int] = frozenset({
    443,    # HTTPS / QUIC
    8443,   # 备用 HTTPS
    853,    # DNS-over-TLS
    993, 995, 465, 587,  # IMAPS / POP3S / SMTPS / submission
    636,    # LDAPS
    989, 990,  # FTPS
    5223,   # XMPP over TLS
})


def format_peer(ip: str, port: int, proto: str = "") -> str:
    """把 ``(ip, port[, proto])`` 拼成**无歧义**的端点字面。

    ★IPv6 必须加方括号（RFC 3986）：裸拼出来的 ``2001:db8::1:443/tcp`` 在字面上无法与
      「末段是 443 的裸地址」区分，下游 ``infra._strip_port_suffix`` 剥不掉端口，于是
      IPv6 的运行时 Lead 永远匹配不上裸 IPv6 Endpoint —— target 选择、closure 回写、
      letters 归属链三处同时击穿（codex P1）。IPv4 保持原样，不动既有形态。
    """
    hostport = infra.format_hostport(ip, port)
    return f"{hostport}/{proto}" if proto else hostport


def sni_camouflage_carriers(summary: PcapSummary) -> dict[str, list[str]]:
    """``{SNI 域名: [承载它的非标端点 ip:port/proto, ...]}``——只收**全部**承载端点都在非标端口的。

    ★为什么按端口判、而不是维护一份"知名域名"白名单：实测样本在 30135/tcp 的自建协议连接上
      打出网易云音乐、jsDelivr 镜像、有道、BootCDN 的 SNI。回灌把这些域名一并当业务线索，
      于是生成的是一封指名网易/有道的调证函——把无关企业写成了嫌疑方，本项目最重的那类错误。
      白名单挡不住：团伙下次换个域名就绕过去了。而**推断链**本身是可以判的——「ClientHello
      里写着 X，所以这台机器归 X 的运营方」这一步，只在 X 确实是跑在约定端口上的 TLS 服务时
      才成立。端口一非标，这条推断就没有前提，与域名有多知名无关。

    ★只在**全部**承载端点都非标时才算：只要该域名在某个标准端口上也出现过，就说明它确实作为
      TLS 服务被访问过，不该因为另有一条非标连接而整体降级。

    绝不抛；无 SNI / 无 flows → 空 dict。
    """
    carriers: dict[str, list[tuple[str, int, str]]] = {}
    for re_ in remote_endpoints(summary):
        for s in re_.sni:
            name = str(s).strip().lower().rstrip(".")
            if name:
                carriers.setdefault(name, []).append((re_.ip, re_.port, re_.proto))
    out: dict[str, list[str]] = {}
    for name, eps in carriers.items():
        if any(port in _STANDARD_TLS_PORTS for _ip, port, _proto in eps):
            continue
        out[name] = sorted(format_peer(ip, port, proto) for ip, port, proto in eps)
    return out


def to_report_leads(
    summary: PcapSummary, app_attr: dict[str, dict] | None = None
) -> list[Lead]:
    """把 pcap summary 转成 report 的 Lead（公网接入节点 IP + SNI/DNS 域名，source=runtime-pcap）。"""
    leads: list[Lead] = []
    seen: set[tuple[str, str]] = set()
    camouflage = sni_camouflage_carriers(summary)

    for re in remote_endpoints(summary):
        value = format_peer(re.ip, re.port, re.proto)
        masked = sorted(s for s in re.sni if str(s).strip().lower().rstrip(".") in camouflage)
        key = (LeadCategory.IP.value, value)
        if key in seen:
            continue
        seen.add(key)
        ja3 = ("，JA3=" + "/".join(sorted(re.ja3))) if re.ja3 else ""
        sni = ("，SNI=" + "/".join(sorted(re.sni))) if re.sni else ""
        quic = ("，QUIC=" + "/".join(sorted(re.quic_versions))) if re.quic_versions else ""
        if re.alpn:
            quic += "，ALPN=" + "/".join(sorted(re.alpn))
        if re.ip in _KNOWN_FANZHA:
            # 反诈拦截节点即便有双向载荷（拦截页会回数据）也非业务接入/落地机——标『无需调证』，
            # 不静默丢（仍留台账作拦截证据），但严禁当接入节点升"建议调证"、污染归因。
            advice, confidence = infra.ADVICE_SKIP, Confidence.HIGH
            notes = "反诈拦截节点（涉诈域名被拦后解析至此的拦截页）——非业务接入/落地机，排除，勿据此调证。"
        elif re.has_payload:
            advice, confidence = infra.ADVICE_INVESTIGATE, Confidence.HIGH
            if re.state == STATE_ESTABLISHED:
                notes = "带外 pcap 实测接入节点（双向载荷=已通信后端）；凭此 IP 调证穿透真源站。"
            else:
                notes = "带外 pcap 观测到应用层载荷（单向，未见回程）；作接入节点调证。"
        else:
            advice, confidence = infra.ADVICE_REVIEW, Confidence.MEDIUM
            notes = (
                "带外 pcap 仅见连接尝试（SYN-only / 无双向载荷 / RST），待核——"
                "可能为 ClientCore 轮询/容灾池或背景噪音，勿当实测接入节点直接调证。"
            )
        if masked and advice != infra.ADVICE_SKIP:
            # ★域名是戏服，这个 IP 才是实体。非标端口上借用知名域名做 SNI，是自建协议在混入
            #   背景流量——它**加重**而非削弱本端点的可疑度，同时把调证方向钉死在本 IP:端口上：
            #   被冒充的那家公司与本案无关，向它发函是把无关方写成嫌疑方。
            notes += (
                f"★该连接以 {'、'.join(masked)} 的名义握手，但端口非标准 TLS 端口——"
                "SNI 系伪装、不代表运营方；调证对象是本 IP:端口（向其 IDC/云厂商调租户实名与访问日志），"
                "**不是**被冒充域名的运营方。伪装本身是自建协议混流的加重信号。"
            )
        leads.append(
            Lead(
                category=LeadCategory.IP,
                value=value,
                where_to_request=_IP_WHERE,
                confidence=confidence,
                advice=advice,
                source_refs=[
                    Evidence(
                        # 归因判定不属于目标应用时降为 runtime-derived，见 _endpoint_source。
                        source=_endpoint_source(re.proto, re.ip, re.port, app_attr),
                        location="pcap",
                        snippet=(
                            f"->{value} state={re.state} out={re.out_bytes}B in={re.in_bytes}B "
                            f"conns={re.connection_count} pkts={re.packets}{sni}{ja3}{quic}"
                        )[:200],
                        observed_at=re.first_ts or None,  # 首包时间 → 观测时刻（0.0 视作未知留 None）
                    )
                ],
                # 结构化回带，让 letters 能自己渲染警示——上面那段 notes 文案下游出口读不到。
                sni_masquerade=masked if advice != infra.ADVICE_SKIP else [],
                notes=notes,
            )
        )

    domains: dict[str, str] = {}
    domain_ts: dict[str, float] = {}  # SNI 域名 → 承载它的最早 flow 首包时间（DNS 域名无 per-query ts，留空）
    for f in summary.flows:
        for s in f.sni:
            domains.setdefault(s, "TLS SNI")
            if f.first_ts and (s not in domain_ts or f.first_ts < domain_ts[s]):
                domain_ts[s] = f.first_ts
    for q in summary.dns_queries:
        domains.setdefault(q, "DNS 查询")

    camouflage = sni_camouflage_carriers(summary)
    sni_carriers = _sni_carriers(summary)
    for dom, src in sorted(domains.items()):
        key = (LeadCategory.DOMAIN.value, dom)
        if key in seen:
            continue
        seen.add(key)
        try:
            advice, _reason = infra.classify_domain(dom)
        except Exception:  # noqa: BLE001 - 分级失败给默认
            advice = "建议调证"
        notes = f"带外 pcap 捕获（{src}）。"
        confidence = Confidence.HIGH
        carriers = camouflage.get(dom)
        base = advice or infra.ADVICE_INVESTIGATE
        # SNI 只出现在非标准 TLS 端口上 → 它证明不了这台机器归谁运营，降档待核。
        # ★只在判据链本判最高档时才记这笔抑制：base 本来就是最低档的（已知第三方基础设施）
        #   压了也没有意义，撤销时也不会因此升档，记上去只是给账本添噪。
        masq_note = (
            f"⚠ 该域名仅作为 SNI 出现在非标准 TLS 端口（{'、'.join(carriers)}）上。"
            "标准端口之外，ClientHello 里的 SNI 不构成「该域名运营方即此端点运营方」的证据——"
            "自建协议用知名域名做 SNI 混入背景流量是常见手法。"
            "★标的应是承载它的 IP:端口，不是该域名的运营方；如需以此域名为标的，先核实证书/Host 一致。"
        ) if carriers and base == infra.ADVICE_INVESTIGATE else ""
        lead = Lead(
            category=LeadCategory.DOMAIN,
            value=dom,
            where_to_request=_DOMAIN_WHERE,
            confidence=confidence,
            advice=base,
            base_advice=base,
            source_refs=[
                Evidence(
                    # 承载该 SNI 的连接全被判非目标应用时降档，见 _aggregate_source。
                    source=_aggregate_source(sni_carriers.get(dom), app_attr),
                    location="pcap",
                    snippet=f"{src}: {dom}",
                    observed_at=domain_ts.get(dom),  # SNI 域名带首包时间，DNS 域名留 None
                )
            ],
                # ★被冒用的域名，其 Lead 的标的**就是**被借用的那个名字——故填自身。
                #   与 IP 侧填「本连接借用了谁」方向相反，但字段语义一致：这条线索上出现的
                #   这些名字，其持有方与本次分析无关，不得作为文书的受文方。
                #
                #   为什么必须是结构化字段、而不是上面那段 notes：notes 在合并与出口两处都
                #   丢失。实测（1.4.0）——该域名同时被 core.leads._domain_lead 产出一条
                #   ``ADVICE_INVESTIGATE`` 的同键 Lead，合并时 notes 不搬运，于是报告里活下来
                #   的是没有任何警示的那条，letters 照单套打出指向被冒用服务的文书。
                #   merge_runtime_into_lead_dict 早已实现该字段的并集搬运，此前**只有 IP 侧
                #   填了它**，域名侧一直空着，那套搬运逻辑完全落空。
            sni_masquerade=[dom] if carriers else [],
            notes=notes,
        )
        if masq_note:
            apply_downgrade(lead, DOWNGRADE_SNI_MASQUERADE, masq_note)
        leads.append(lead)
    return leads


def to_runtime_endpoints(
    summary: PcapSummary,
    *,
    stats: dict[str, object] | None = None,
    app_attr: dict[str, dict] | None = None,
) -> list[Endpoint]:
    """把 pcap summary 转成 runtime_report 的 ``Endpoint``（公网接入节点 IP + SNI/DNS 域名，
    ``source=runtime-pcap``）——供 capture 把带外 pcap 的接入节点【自动并入】``runtime_report.endpoints``，
    随后经 merge → asn 富化 → infra 归属分级（Google/云 IP 自动判为第三方基础设施并在报告里折叠）。

    与 :func:`to_report_leads` 同源（同样只收 public dst IP + SNI/DNS 域名），但产 ``Endpoint`` 而非
    ``Lead``；**此处不做噪音判定**——IP 侧交下游 asn/infra 分级，域名侧的 OS/GMS/连通性噪音由调用方
    （capture）按 host 名单折叠。绝不抛（坏 summary 退化为空列表由调用方兜底）。
    """
    endpoints: list[Endpoint] = []
    seen: set[str] = set()
    dropped = 0
    intercept_dropped: list[str] = []
    remotes = remote_endpoints(summary)
    # ★本函数按**裸 IP** 折叠（同 IP 的后续端口直接 continue），故来源标签必须按该 IP 的
    #   全部端口聚合判定。若只看首个被迭代到的端口，同一 IP 的 :443 属目标、:9000 属他进程时，
    #   结论会随 flow 顺序摇摆——443 先出现就是 runtime-pcap、9000 先出现就是 runtime-derived。
    ip_carriers: dict[str, set[str]] = {}
    for re_ in remotes:
        ip_carriers.setdefault(re_.ip, set()).add(f"{re_.proto}/{re_.ip}:{re_.port}")
    for re in remotes:
        # ★反诈拦截节点排除（Codex fengzhixin 案抓包交接 §6）：涉诈域名被拦后解析至此的拦截页，即便
        #   有双向载荷也非业务接入/落地机，绝不升为 runtime 端点（会污染归因）；仍在 pcap 台账留证。
        #
        # ★这条排除必须**可见**：它是全仓降噪纪律里唯一直接判「无需调证」的通道，而名单命中与否
        #   取决于一份人工维护的常量表。此前它与下面的「无载荷」共用一个计数、日志只提无载荷，
        #   于是「有个端点被当拦截节点吞了」在报告里完全看不出来。名单若哪天收错（某 IP 改作
        #   普通业务地址并被后端租用），静默丢弃会让人永远发现不了。
        if re.ip in _KNOWN_FANZHA:
            if re.ip not in intercept_dropped:
                intercept_dropped.append(re.ip)
            continue
        # ★自动并入护栏：无载荷（SYN-only/reset/仅握手）节点不升为主报告"公网 IP 建议调证"——
        # 下游 _ip_lead 对 pcap Endpoint 只按公私网给 advice、会绕过这里的态分级，故直接过滤；
        # 它们仍在 pcap 台账（to_report_leads）与原始 floor.pcap 中作"待核"，不静默丢弃。
        if not re.has_payload:
            dropped += 1
            continue
        if re.ip in seen:
            continue
        seen.add(re.ip)
        ja3 = ("，JA3=" + "/".join(sorted(re.ja3))) if re.ja3 else ""
        sni = ("，SNI=" + "/".join(sorted(re.sni))) if re.sni else ""
        quic = ("，QUIC=" + "/".join(sorted(re.quic_versions))) if re.quic_versions else ""
        if re.alpn:
            quic += "，ALPN=" + "/".join(sorted(re.alpn))
        endpoints.append(
            Endpoint(
                value=re.ip,
                kind="ip",
                evidences=[
                    Evidence(
                        # 端点按裸 IP 折叠，故按该 IP 的全部端口聚合判定，见 _aggregate_source。
                        source=_aggregate_source(ip_carriers.get(re.ip), app_attr),
                        location="pcap",
                        snippet=(
                            f"->{format_peer(re.ip, re.port, re.proto)} state={re.state} "
                            f"out={re.out_bytes}B in={re.in_bytes}B pkts={re.packets}{sni}{ja3}{quic}"
                        )[:200],
                        observed_at=re.first_ts or None,
                    )
                ],
            )
        )
    if dropped:
        logger.info(
            "[pcap] 自动并入过滤无载荷接入节点 %d 个（SYN-only/连接尝试，留 pcap 台账作待核，不升'建议调证'）",
            dropped,
        )
    if intercept_dropped:
        logger.info(
            "[pcap] 自动并入排除已知反诈拦截节点 %d 个：%s（非业务接入/落地机，留 pcap 台账留证）",
            len(intercept_dropped), "、".join(intercept_dropped),
        )
    if stats is not None:
        # ★两类丢弃分开记：性质完全不同——「无载荷」是形态判据，「拦截节点」是名单判据。
        #   合在一起数就等于把后者藏进前者里。
        stats["no_payload_dropped"] = dropped
        stats["intercept_excluded"] = list(intercept_dropped)
    # SNI / DNS 域名端点（DNS 域名无 per-query ts，留 None）。
    domain_ts: dict[str, float] = {}
    domains: dict[str, str] = {}
    for f in summary.flows:
        for s in f.sni:
            domains.setdefault(s, "TLS SNI")
            if f.first_ts and (s not in domain_ts or f.first_ts < domain_ts[s]):
                domain_ts[s] = f.first_ts
    for q in summary.dns_queries:
        domains.setdefault(q, "DNS 查询")
    # ★伪装判定必须随端点一起走：域名端点并入主报告后，由 core.leads._domain_lead 重新产 Lead，
    #   而那个生产者只看得到 Endpoint 自身——它不知道这个名字是从哪个端口的握手里抠出来的，
    #   于是把被冒用的域名判成 ``ADVICE_INVESTIGATE``。实测（1.4.0）由此对两个知名服务各套打出
    #   一份文书；同批未并入 endpoints 的两个伪装域名反而因走不到这条路径而幸免——决定安全与否
    #   的竟是「有没有进 endpoints」这条与伪装判断毫不相干的分叉。
    camouflage = sni_camouflage_carriers(summary)
    sni_carriers = _sni_carriers(summary)
    for dom, src in sorted(domains.items()):
        if dom in seen:
            continue
        seen.add(dom)
        ep = Endpoint(
            value=dom,
            kind="domain",
            evidences=[
                Evidence(
                    # 与 to_report_leads 的域名 Lead 同一判据，见 _aggregate_source。
                    source=_aggregate_source(sni_carriers.get(dom), app_attr),
                    location="pcap",
                    snippet=f"{src}: {dom}",
                    observed_at=domain_ts.get(dom),
                )
            ],
        )
        carriers = camouflage.get(str(dom).strip().lower().rstrip("."))
        if carriers:
            ep.enrichment[SNI_MASQUERADE_KEY] = {"carriers": list(carriers)}
        endpoints.append(ep)
    return endpoints


#: markdown 结构/行内语法字符：嵌不可信字段前逐字符反斜杠转义（含反引号，堵逃逸 inline-code 注入 HTML/链接）。
#: 无正则实现——本模块把 `re` 用作 RemoteEndpoint 循环变量，不引入 re 模块避免撞名。
_MD_SPECIAL_CHARS = frozenset("\\`*_{}[]()#+-.!|>&<~")


def _md_escape(value: object) -> str:
    """markdown 台账里嵌可能含不可信内容的字段（如 error 里的文件路径/解析异常串）前转义：折叠空白 +
    反斜杠转义 markdown 结构/行内语法字符（含反引号），防被渲染成结构/链接或逃逸注入原始 HTML。"""
    collapsed = " ".join(str(value).split())  # 折叠所有空白（含换行）为单空格，堵伪造新行/标题
    return "".join("\\" + ch if ch in _MD_SPECIAL_CHARS else ch for ch in collapsed)


def is_attribution_denied(lead: Lead) -> bool:
    """该 lead 是否**经归因明确判定**不属于目标应用。

    ★判据是"存在 ``runtime-derived`` 证据"，不是 ``not lead.is_runtime_contact``。
      **在本函数当前的输入上两者等价**（实测：``to_report_leads`` 产的每条 lead 都带
      runtime 证据，纯 DNS 域名同样带 ``runtime-pcap``，故 ``not is_runtime_contact``
      不会把它算进来）。分开写是因为两者的**语义**不同，而语义差会在别处显形：
      合并后的报告里，同一个值可能积累多次采集的证据、一次判是一次判否，
      那时 ``is_runtime_contact`` 仍为真而本函数为真——谁对取决于问的是
      "有没有被目标连过"还是"这次归因否掉了它"。

    展示层（台账标注、CLI 计数）共用本函数，是为了让"两处必须同口径"这件事显式成立，
    而不是靠两边各自写的表达式碰巧相等。
    """
    return any(ev.source == _UNATTRIBUTED_SOURCE for ev in lead.source_refs)


def _attribution_mark(lead: Lead) -> str:
    """台账行尾的归因标记。空串 = 本次没做归因，或归因认了它。

    ★台账**不删行**：它是"这次抓包看见了什么"的全量留证，无载荷节点、被排除的拦截节点
      都照列不误。归因判否的节点同样留着——但必须**标出来**，否则读台账的人会把整机流量
      里别的应用的连接当成本样本的调证锚点。
    """
    if is_attribution_denied(lead):
        return "  ⚠ **归因：不属目标应用**（整机抓包里的其他进程流量，不作本样本的调证锚点）"
    return ""


def build_ledger_md(summary: PcapSummary, app_attr: dict[str, dict] | None = None) -> str:
    """把 pcap 线索聚成调证台账（markdown），按 IP 接入节点 / 域名 分组。

    ``app_attr``：可选的 UID 归因表。给了就在行尾标出"不属目标应用"的节点——
    此前本函数不接归因，于是同一条命令里 ``--into`` 的报告已把某节点降档，
    ``--md`` 的台账却仍把它列在调证锚点下，两份产物结论相反。
    """
    leads = to_report_leads(summary, app_attr)
    ips = [l for l in leads if l.category == LeadCategory.IP]
    doms = [l for l in leads if l.category == LeadCategory.DOMAIN]
    lines: list[str] = [
        "# pcap 调证台账（带外抓包线索聚合）",
        "",
    ]
    if summary.parse_status != "ok":
        # error 可能含文件路径/解析异常串（潜在不可信）→ 转义后再嵌 markdown，别自己开注入面（同 probe-leads 的教训）。
        lines += [
            f"> ⚠ pcap 解析未成功（{_md_escape(summary.parse_status)}：{_md_escape(summary.error)}）——"
            "空结果**不代表零流量**，请核对 pcap 文件完整性/格式后重抓。",
            "",
        ]
    unattributed = sum(1 for l in ips + doms if _attribution_mark(l))
    lines += [
        f"接入节点 {len(ips)} 个、域名 {len(doms)} 个、DNS 查询 {len(summary.dns_queries)} 条。",
        "解不开密文也能办案：下列接入节点 IP/SNI 即穿透真源站的调证锚点。",
    ]
    if app_attr is not None:
        lines.append(
            f"> UID 归因已做：其中 **{unattributed}** 条经归因判定**不属于目标应用**，"
            "已在行尾标注——带外抓的是整机流量，那些是别的进程的连接，不作本样本的调证锚点。"
            if unattributed else
            "> UID 归因已做：未发现判定为「不属于目标应用」的节点。"
        )
    else:
        lines.append(
            "> ⚠ **本次未做 UID 归因**（没给 socket 快照）。带外抓的是整机流量，"
            "下列节点里可能混有其他应用的连接——那是「未归因」，不是「已确认属本样本」。"
        )
    lines += [
        "",
        "## 接入节点（IP:port）",
        "> 调证落点：" + _IP_WHERE,
        "",
    ]
    for l in ips:
        snippet = l.source_refs[0].snippet if l.source_refs else ""
        lines.append(f"- `{l.value}`  {snippet}{_attribution_mark(l)}")
    lines.append("")
    lines.append("## 域名（TLS SNI / DNS）")
    lines.append("> 调证落点：" + _DOMAIN_WHERE)
    lines.append("")
    for l in doms:
        lines.append(f"- `{l.value}`  [{l.advice}]  {l.notes}{_attribution_mark(l)}")
    lines.append("")
    return "\n".join(lines)


def to_ledger_dict(
    summary: PcapSummary, app_attr: dict[str, dict] | None = None
) -> dict[str, object]:
    """台账的程序化形态。``app_attr`` 给了就带上归因状态。

    ★``uid_attributed`` 是**顶层**字段，让消费者一眼分得清"没做归因"与"做了归因、都属目标"：
      两种情形下逐条的 ``target_attributed`` 都可能不为 True，但含义相反。此前本函数
      整个不接归因，消费者拿不到任何归因线索，只能把整机流量里的背景连接当案件线索。
    """
    leads = to_report_leads(summary, app_attr)
    res = remote_endpoints(summary)
    endpoints = [
        {
            "value": format_peer(re.ip, re.port, re.proto),
            "ip": re.ip,
            "port": re.port,
            "proto": re.proto,
            "state": re.state,  # established / syn_only / reset / unknown —— SYN-only 为连接尝试待核
            "out_bytes": re.out_bytes,
            "in_bytes": re.in_bytes,
            "packets": re.packets,
            "connection_count": re.connection_count,
            "sni": sorted(re.sni),
            "no_sni": not re.sni,
            "quic_versions": sorted(re.quic_versions),  # h3 归因（明文长包头元数据）
            "alpn": sorted(re.alpn),  # ALPN 协商协议（QUIC Initial 解出，h3/h2）
            # 归因摘要（做了才有键，见 _attr_block：缺失≠否定）
            **_attr_block(app_attr, re),
        }
        for re in res
    ]
    return {
        # 解析状态先行：程序化消费者据此区分「解析/采集失败」与「真实零业务流量」（失败态空 endpoints 不当零流量）。
        "parse_status": summary.parse_status,
        "error": summary.error,
        # 本次到底问没问过"这条流属不属于目标应用"。False 时下面所有 target_attributed 的缺失
        # 都只表示**没问过**，消费者不得据此判"不属目标"。
        "uid_attributed": app_attr is not None,
        "endpoints": [
            {
                "value": l.value,
                "advice": l.advice,
                "snippet": (l.source_refs[0].snippet if l.source_refs else ""),
                # runtime-pcap = 观测到接触；runtime-derived = 已归因、判定不属目标应用。
                "source": (l.source_refs[0].source if l.source_refs else ""),
                "runtime_contact": l.is_runtime_contact,
            }
            for l in leads
            if l.category == LeadCategory.IP
        ],
        "remote_endpoints": endpoints,
        # 按累计字节 / 连接尝试次数排序的 Top（供研判先看谁通信最多、谁被反复拨号）。
        "top_bytes": sorted(
            endpoints, key=lambda e: e["out_bytes"] + e["in_bytes"], reverse=True
        )[:10],
        "top_connections": sorted(endpoints, key=lambda e: e["connection_count"], reverse=True)[:10],
        "domains": [{"value": l.value, "advice": l.advice} for l in leads if l.category == LeadCategory.DOMAIN],
        "dns_queries": sorted(summary.dns_queries),
        "dns_records": [
            {
                "qname": r.qname,
                "qtype": r.qtype,
                "rcode": r.rcode,
                "txid": r.txid,
                "answers": r.answers,
            }
            for r in summary.dns_records
        ],
    }


def _attr_block(app_attr: dict[str, dict] | None, re_: "RemoteEndpoint") -> dict:
    """该远端的 UID 归因摘要，供写进端点的 ``enrichment["runtime"]``。

    ★没有 socket 快照（``app_attr`` 为空）时**返回空 dict**——一个字段都不写。
      「没做归因」与「做了归因、结论是不属于目标」必须分得开：前者是不知道，
      后者是证据。往缺失里填 ``target_attributed=False`` 就是把不知道写成了否定。

    键格式与 capture 的 ``capture_signals["pcap_app_attribution"]`` 一致（``proto/ip:port``），
    两条路径经 :func:`socket_attr.attribute_remote_endpoints` 同源产出。
    """
    if not app_attr:
        return {}
    hit = app_attr.get(f"{re_.proto}/{re_.ip}:{re_.port}")
    if not isinstance(hit, dict):
        return {}
    out: dict = {
        "target_attributed": hit.get("is_target_app") is True,
        "attribution": [str(hit.get("attribution", "unknown"))],
    }
    # 目标虽非本条流的所有者、但也连过该远端——不透出的话，下游按 target_attributed
    # 分拣会把"目标也连的真后端"整段当背景噪音丢掉。
    if hit.get("target_uid_among_candidates") is True:
        out["target_among_candidates"] = True
    if isinstance(hit.get("score"), (int, float)):
        out["attribution_score"] = hit["score"]
    return out


def _attr_block_for_carriers(
    app_attr: dict[str, dict] | None, carriers: set[str]
) -> dict:
    """一组 carrier 的 IP 级归因投影；缺任一结果且无 TARGET 时保持 MISSING。

    与 :func:`_attr_block`（单 carrier）的关系：判据同源（runtime_evidence 组合，
    见 :func:`_carrier_set_target_flag`），本函数解决的是**IP 级聚合**——端点 value
    是裸 IP，它的 target_attributed 必须由该 IP 全部端口的结论一次算出，
    不能在逐端口迭代里增量拼（拼出来的结论随 flow 顺序摇摆）。
    """
    flag = _carrier_set_target_flag(app_attr, carriers)
    if flag is None or not app_attr:
        return {}
    hits = [app_attr[carrier] for carrier in sorted(carriers) if carrier in app_attr]
    out: dict = {
        "target_attributed": flag,
        "attribution": sorted({
            str(hit.get("attribution", "unknown"))
            for hit in hits
            if isinstance(hit, dict)
        }),
    }
    if any(
        isinstance(hit, dict) and hit.get("target_uid_among_candidates") is True
        for hit in hits
    ):
        out["target_among_candidates"] = True
    scores = [
        hit["score"]
        for hit in hits
        if isinstance(hit, dict) and isinstance(hit.get("score"), (int, float))
    ]
    if scores:
        out["attribution_score"] = max(scores)
    return out


def _runtime_endpoint_dicts(
    summary: PcapSummary, app_attr: dict[str, dict] | None = None
) -> list[dict]:
    """把 pcap 接入节点转成 report.json 的 ``endpoints`` 条目（含 runtime 富化）。

    ``app_attr``：可选的 UID 归因表（``socket_attr.attribute_remote_endpoints`` 的产出）。
    给了才写 ``target_attributed`` 等字段——见 :func:`_attr_block`。

    ★``value`` 用**裸 IP**，不是 Lead 那样的 ``ip:port/proto``。两处各有各的道理：Lead 是调证
      标的，端口是要写进函里的；Endpoint 是被富化/被闭环排序的对象，得跟静态端点、跟各富化器
      的 IP 口径对齐。端口/协议/字节/连接态落进 ``enrichment["runtime"]``，闭环排序据此判优先级
      （见 ``closure.targets._target_rank``）。

    ★这一步此前整个不存在：回灌只往 ``leads`` 里追加，端点侧一片空白。于是"实测双向通信的真
      后端"连闭环候选都进不去——排序排的是端点，而那个端点根本没被创建。报告里 Lead 标着
      ``is_runtime_contact=true``，闭环却挑着静态噪音，两边各说各话。
    """
    camouflage = sni_camouflage_carriers(summary)
    # ★按 IP 聚合，不是按 (ip, port) 各产一条。
    #   同一 IP 上开多个业务端口是常态（实测：一台机 5479＋8796，呈「主通道＋心跳通道」成对形态）。
    #   端点的 value 是裸 IP，若每个端口各产一条同 key 的 dict，合并时后者会把前者的 runtime
    #   整个覆盖掉——端口、字节、SNI 全丢一半。mitm 侧早就用 ``mitm_peers`` 列表累积解决了
    #   同一问题（见 capture._collect_flow_endpoints 的注释），pcap 侧此前没有。
    by_ip: dict[str, dict] = {}
    remotes = remote_endpoints(summary)
    ip_carriers: dict[str, set[str]] = {}
    for remote in remotes:
        ip_carriers.setdefault(remote.ip, set()).add(
            f"{remote.proto}/{remote.ip}:{remote.port}"
        )
    for re_ in remotes:
        sni = sorted(re_.sni)
        # 这个端点打出来的 SNI 里，哪些是"非标端口上的"——即无法据以判定运营方的（见
        # sni_camouflage_carriers）。记在端点上，读报告的人能一眼看出这条连接在伪装成谁。
        masquerading = sorted(s for s in sni if s.strip().lower().rstrip(".") in camouflage)
        peer = format_peer(re_.ip, re_.port)
        snippet = (
            f"->{peer}/{re_.proto} state={re_.state} "
            f"out={re_.out_bytes}B in={re_.in_bytes}B conns={re_.connection_count}"
            + ("，SNI=" + "/".join(sni) if sni else "")
        )[:200]

        ep = by_ip.get(re_.ip)
        if ep is None:
            by_ip[re_.ip] = {
                "value": re_.ip,
                "kind": "ip",
                "is_private": False,  # remote_endpoints 只收公网远端
                "evidences": [{
                    # 逐端口诚实标记：该端口被判非目标应用就降档，与下方合并分支同法。
                    "source": _endpoint_source(re_.proto, re_.ip, re_.port, app_attr),
                    "location": "pcap",
                    "snippet": snippet, "observed_at": re_.first_ts or None,
                    "scope": EvidenceScope.CASE_EVIDENCE.value,
                }],
                "enrichment": {"runtime": {
                    # ★端口级明细：``["ip:port", …]``。这是 port-normalize 的数据源
                    #   （config/port_norm.py 按 IP 配对 declared↔observed 端口），
                    #   此前该字段根本没被生成，文档说的"报告实测端口交叉校验"对 pcap 报告不可用。
                    "remote_endpoints": [peer],
                    "ports": [re_.port],
                    # ★``port`` 是**代表端口**（下方合并时取字节数最大的那个），保留它是为了
                    #   向后兼容既有消费方与展示；同 IP 多端口的**权威明细看 ``ports`` /
                    #   ``remote_endpoints``**，不要拿它当"该 IP 只有这一个端口"。
                    "port": re_.port,
                    "proto": re_.proto,
                    "state": re_.state,
                    # 以下为**IP 级聚合**语义（跨该 IP 的全部端口）：闭环排序与门控读的是这几个。
                    "out_bytes": re_.out_bytes,
                    "in_bytes": re_.in_bytes,
                    "has_payload": re_.has_payload,
                    "connection_count": re_.connection_count,
                    "sni": sni,
                    # ★这条连接以谁的名义握手。它**不是**减分项：非标端口 + 借用知名域名做 SNI，
                    #   本身就是自建协议在混入背景流量，反而使这个 IP 更值得查。
                    #   记在端点上，是为了让调证对象指向本 IP:端口，而不是被冒充那家公司。
                    **({"sni_masquerade": masquerading} if masquerading else {}),
                    "first_ts": re_.first_ts or None,
                    "last_ts": re_.last_ts or None,
                    # ★target_attributed 只在**给了 socket 快照**时才写（见 _attr_block）。
                    #   没给就是缺，绝不因为"这是目标的 pcap"默认填 True——带外抓的是整机流量。
                    **_attr_block_for_carriers(app_attr, ip_carriers[re_.ip]),
                }},
            }
            continue

        # 同 IP 的后续端口：逐字段**合并**，绝不覆盖。
        rt = ep["enrichment"]["runtime"]
        if peer not in rt["remote_endpoints"]:
            rt["remote_endpoints"].append(peer)
        if re_.port not in rt["ports"]:
            rt["ports"].append(re_.port)
        # 代表端口取**流量最大**的那个（主通道），而不是最后并入的那个——
        # 实测形态是"一主一心跳"，心跳端口若成了代表值，展示与文书会指向次要通道。
        if re_.out_bytes + re_.in_bytes > rt["out_bytes"] + rt["in_bytes"]:
            rt["port"] = re_.port
        rt["out_bytes"] += re_.out_bytes
        rt["in_bytes"] += re_.in_bytes
        rt["connection_count"] += re_.connection_count
        # 任一端口有载荷即该 IP 有载荷；established 优先于 syn_only/reset（闭环据此判优先级）。
        rt["has_payload"] = bool(rt["has_payload"] or re_.has_payload)
        if re_.state == "established":
            rt["state"] = "established"
        if re_.proto != rt.get("proto"):
            rt["proto"] = "mixed"
        rt["sni"] = sorted(set(rt["sni"]) | set(sni))
        if masquerading:
            rt["sni_masquerade"] = sorted(set(rt.get("sni_masquerade") or []) | set(masquerading))
        for key, pick in (("first_ts", min), ("last_ts", max)):
            cur, new = rt.get(key), (re_.first_ts if key == "first_ts" else re_.last_ts) or None
            if new is not None:
                rt[key] = new if cur is None else pick(cur, new)
        # ★同 IP 多端口的归因按 **IP 级一次算出**（_attr_block_for_carriers），不逐端口
        #   增量拼。此前逐端口 or-合并虽修了"只认首个端口"，但只能升不能降、且首创分支
        #   与合并分支两套逻辑——同一 IP 的结论仍取决于哪个端口先被迭代到。
        #   聚合规则与 has_payload/state 同哲学：任一端口确属目标，该 IP 即算被目标连过。
        extra = _attr_block_for_carriers(app_attr, ip_carriers[re_.ip])
        if extra:
            for key in _ATTRIBUTION_RUNTIME_KEYS:
                rt.pop(key, None)
            rt.update(extra)
        ep["evidences"].append({
            # 逐端口诚实标记：同一 IP 下，属目标的端口与不属的端口各标各的来源。
            "source": _endpoint_source(re_.proto, re_.ip, re_.port, app_attr),
            "location": "pcap",
            "snippet": snippet, "observed_at": re_.first_ts or None,
            "scope": EvidenceScope.CASE_EVIDENCE.value,
        })

    return list(by_ip.values())


def _merge_runtime_endpoint_dicts(payload: dict, fresh: list[dict]) -> int:
    """把运行时端点并进 ``payload["endpoints"]``（按 (kind, value) 去重）。返回新增数。

    命中已有端点 → 把 runtime 富化与证据并进去（静态已知的 IP 这次被实测连上了，是升级不是重复）。
    """
    existing = payload.get("endpoints")
    if not isinstance(existing, list):
        existing = []
        payload["endpoints"] = existing
    by_key: dict[tuple[str, str], dict] = {
        (str(e.get("kind")), str(e.get("value"))): e
        for e in existing if isinstance(e, dict)
    }
    added = 0
    for ep in fresh:
        key = (ep["kind"], ep["value"])
        hit = by_key.get(key)
        if hit is None:
            by_key[key] = ep
            existing.append(ep)
            added += 1
            continue
        enr = hit.setdefault("enrichment", {})
        if isinstance(enr, dict):
            enr["runtime"] = _merge_runtime_blocks(enr.get("runtime"), ep["enrichment"]["runtime"])
        evs = hit.setdefault("evidences", [])
        if isinstance(evs, list):
            # 与 leads 侧同法：本次归因判否的那条观测，撤销它此前写下的 observed-contact 证据。
            # 不撤销的话两条并存，端点仍带着旧的 runtime-pcap，降档在端点侧同样落空。
            revoke_superseded_evidence(evs, ep["evidences"])
            # ★去重：同一份 pcap 重复 --into 时，此前每次都把同样的证据再追加一遍，
            #   报告里同一条连接被列 N 次，读的人以为观测到了 N 次。
            seen = {
                (
                    str(e.get("source")),
                    str(e.get("location")),
                    str(e.get("snippet")),
                    str(e.get("scope", EvidenceScope.LEGACY_UNSPECIFIED.value)),
                )
                for e in evs if isinstance(e, dict)
            }
            for e in ep["evidences"]:
                sig = (
                    str(e.get("source")),
                    str(e.get("location")),
                    str(e.get("snippet")),
                    str(e.get("scope", EvidenceScope.LEGACY_UNSPECIFIED.value)),
                )
                if sig in seen:
                    continue
                seen.add(sig)
                evs.append(e)
    return added


def _restamp_runtime_endpoint_evidence(payload: dict, fresh: list[dict]) -> int:
    """幂等闸拦下重复合并时，仍让**归因结论**落到端点证据上。返回重标的端点数。

    ★闸的目的是防止字节数/连接数二次累加（那会凭空长出观测强度、直接改变闭环结论），
      **不是**冻结结论。而"先没采到 socket 快照就回灌、后来补上快照重跑同一份 pcap"
      正是要更新归因的场景——若连来源标签一起挡住，降档永远到不了报告，
      端点会一直带着旧的 ``runtime-pcap`` 满足 ``is_runtime_contact``。

    只动 ``evidences``：撤销被取代的旧证据、补上本轮的新证据。绝不碰 ``enrichment``
    里的任何计数，闸要防的那件事一步都不放。

    ★**撤销与追加必须解耦**。此前写成"撤销数为 0 就整条跳过"，于是只有降档
      （``runtime-derived`` 取代 ``runtime-pcap``）走得通，反方向走不通：补上快照重跑、
      本轮明确判定**属于**目标应用时，incoming 全是 ``runtime-pcap``、撤销数恒 0，
      新证据永远追加不上去——lead 面经 :func:`merge_runtime_into_lead_dict` 已恢复
      ``is_runtime_contact``，endpoint 面却停在旧的降档证据上，**两个消费面对同一事实
      给出相反结论**。而闭环排序读的正是 endpoint 面，已确认属目标的后端会继续被当
      降档处理。撤销是"有取代关系时才做"，追加是"结论更新就要做"，两者互不为前提。
    """
    existing = payload.get("endpoints")
    if not isinstance(existing, list):
        return 0
    by_key = {
        (str(ep.get("kind")), str(ep.get("value"))): ep
        for ep in existing if isinstance(ep, dict)
    }
    restamped = 0
    for ep in fresh:
        hit = by_key.get((ep["kind"], ep["value"]))
        if hit is None:
            continue
        evs = hit.get("evidences")
        if not isinstance(evs, list):
            continue
        incoming = ep.get("evidences")
        incoming = incoming if isinstance(incoming, list) else []
        # 显式翻案（TARGET 恢复）走原位替换：同一观测只留一条、来源换成本轮结论，
        # 不靠"撤销+追加"拼两条——那会让升档后旧的 runtime-derived 与新的 runtime-pcap 并存。
        replaced = _replace_same_observation_evidence(evs, incoming)
        # 撤销：仅当本轮证据取代了旧证据（降档）才有事可做，返回 0 是常态、不是"无需更新"。
        revoked = revoke_superseded_evidence(evs, incoming)
        seen = {
            (str(e.get("source")), str(e.get("location")), str(e.get("snippet")))
            for e in evs if isinstance(e, dict)
        }
        added = 0
        for e in incoming:
            sig = (str(e.get("source")), str(e.get("location")), str(e.get("snippet")))
            if sig not in seen:
                seen.add(sig)
                evs.append(e)
                added += 1
        # ★enrichment.runtime 的**归因结论键**同样要跟上本轮结论——幂等闸冻的是
        #   字节数/连接数（观测强度），不是归因结论。此前这里对 enrichment 一概不碰，
        #   于是 TARGET→DENIED 反转后 `target_attributed` 永远留着旧 True，
        #   闭环排序读的正是它。仍然绝不碰计数键，闸要防的那件事一步都不放。
        old_runtime = ((hit.get("enrichment") or {}).get("runtime") or {})
        new_runtime = ((ep.get("enrichment") or {}).get("runtime") or {})
        runtime_changed = False
        if (
            isinstance(old_runtime, dict)
            and isinstance(new_runtime, dict)
            and "target_attributed" in new_runtime
        ):
            before = {
                key: old_runtime.get(key)
                for key in _ATTRIBUTION_RUNTIME_KEYS
                if key in old_runtime
            }
            for key in _ATTRIBUTION_RUNTIME_KEYS:
                old_runtime.pop(key, None)
            for key in _ATTRIBUTION_RUNTIME_KEYS:
                if key in new_runtime:
                    old_runtime[key] = new_runtime[key]
            after = {
                key: old_runtime.get(key)
                for key in _ATTRIBUTION_RUNTIME_KEYS
                if key in old_runtime
            }
            runtime_changed = before != after
        if replaced or revoked or added or runtime_changed:
            restamped += 1
    return restamped


def _serialized_evidence_identity(evidence: object) -> tuple[str, str, str]:
    if not isinstance(evidence, dict):
        return ("", "", "")
    return (
        str(evidence.get("location", "")),
        str(evidence.get("snippet", "")),
        str(evidence.get("scope", EvidenceScope.LEGACY_UNSPECIFIED.value)),
    )


def _replace_same_observation_evidence(existing: list, incoming: list) -> int:
    """同一观测显式翻案时原位换来源，保留无关证据与原顺序。"""
    replacements = {
        _serialized_evidence_identity(evidence): evidence
        for evidence in incoming
        if isinstance(evidence, dict)
    }
    changed = 0
    for index, evidence in enumerate(existing):
        replacement = replacements.get(_serialized_evidence_identity(evidence))
        if replacement is not None and evidence != replacement:
            existing[index] = replacement
            changed += 1
    return changed


def _lead_attribution_verdict(
    lead: Lead,
    summary: PcapSummary,
    app_attr: dict[str, dict] | None,
) -> bool | None:
    """把 Lead 映回其 carrier，供显式 TARGET 原位撤销旧降档证据。"""
    if lead.category is LeadCategory.IP:
        carriers = {
            f"{remote.proto}/{remote.ip}:{remote.port}"
            for remote in remote_endpoints(summary)
            if lead.value == format_peer(remote.ip, remote.port, remote.proto)
        }
    elif lead.category is LeadCategory.DOMAIN:
        carriers = _sni_carriers(summary).get(lead.value, set())
    else:
        carriers = set()
    return _carrier_set_target_flag(app_attr, carriers)


def _inherit_recorded_downgrades(payload: dict, fresh_leads: list, fresh_eps: list[dict]) -> None:
    """本次**没做归因**时，继承报告里已记下的否定结论。

    ★缺信息不得给否定证据翻案。上一轮带着 socket 快照跑出"这条流不属于目标应用"，
      这一轮忘了带 ``--uid-sockets``——两次看到的是同一批流量，但这一轮**没问过**归因问题。
      若照常写 ``runtime-pcap``，已被证否的端点会重新满足 ``is_runtime_contact``，
      过度断言就这么绕回来了。

    与 :data:`~apkscan.core.models.SUPERSEDED_EVIDENCE_SOURCES` 的方向互补：那边管"新的否定
    覆盖旧的观测"，这边管"新的缺信息不覆盖旧的否定"。带归因的轮次不走本函数——
    那时 ``is_target_app=true`` 是**新证据**，翻案是应当的。
    """
    downgraded: set[tuple[str, str]] = set()
    for bucket, value_key, ev_key in (("leads", "value", "source_refs"), ("endpoints", "value", "evidences")):
        for item in payload.get(bucket) or []:
            if not isinstance(item, dict):
                continue
            for ev in item.get(ev_key) or []:
                if isinstance(ev, dict) and ev.get("source") == _UNATTRIBUTED_SOURCE:
                    downgraded.add((str(item.get(value_key)), str(ev.get("snippet"))))

    if not downgraded:
        return
    for lead in fresh_leads:
        for ev in lead.source_refs:
            if ev.source == _SOURCE and (str(lead.value), str(ev.snippet)) in downgraded:
                ev.source = _UNATTRIBUTED_SOURCE
    for ep in fresh_eps:
        for ev in ep.get("evidences") or []:
            if ev.get("source") == _SOURCE and (str(ep.get("value")), str(ev.get("snippet"))) in downgraded:
                ev["source"] = _UNATTRIBUTED_SOURCE


def _norm_dns_name(value: object) -> str:
    """DNS 名规范化：小写、去末点；坏值/空值返回空串。"""
    return str(value or "").strip().lower().rstrip(".")


def _runtime_dns_endpoint_dicts(summary: PcapSummary) -> list[dict]:
    """把 PCAP 内可审计的 DNS answer 转成 domain endpoint。

    DNS 与 socket endpoint 的合并代数不同：前者是记录集合，不能受后者的流量求和指纹闸
    控制。每条 record 保留 qtype/rcode/txid/时间戳和 RR owner，CNAME 只写真实观测到的边。
    """
    by_name: dict[str, dict] = {}
    for rec in summary.dns_records:
        qname = _norm_dns_name(rec.qname)
        if not qname:
            continue
        answers: list[dict] = []
        ips: set[str] = set()
        edges: set[tuple[str, str]] = set()
        for ans in rec.answers:
            if not isinstance(ans, dict):
                continue
            rtype = ans.get("type")
            # RR owner 是 CNAME 边的左端，缺失时不能用 query name 代填：旧版摘要只存
            # target，遇到多跳链会被错误展开成多条 qname→target 推断边。
            owner = _norm_dns_name(ans.get("name"))
            value = str(ans.get("value") or "").strip()
            item = {
                "name": owner,
                "type": rtype,
                "value": _norm_dns_name(value) if rtype in (2, 5, 12) else value,
                "ttl": ans.get("ttl"),
            }
            answers.append(item)
            if rtype in (1, 28):
                try:
                    ips.add(str(ipaddress.ip_address(value)))
                except ValueError:
                    pass
            elif rtype == 5:
                target = _norm_dns_name(value)
                if owner and target:
                    edges.add((owner, target))

        record = {
            "qname": qname,
            "qtype": rec.qtype,
            "rcode": rec.rcode,
            "txid": rec.txid,
            "observed_at": rec.ts or None,
            "answers": answers,
        }
        snippet = (
            f"DNS {qname} qtype={rec.qtype} rcode={rec.rcode} "
            f"answers={len(answers)}"
        )[:200]
        ep = by_name.setdefault(qname, {
            "value": qname,
            "kind": "domain",
            "is_private": False,
            "evidences": [],
            "enrichment": {"dns_runtime": {
                "ips": [], "cname_edges": [], "records": [], "source": _SOURCE,
            }},
        })
        dns = ep["enrichment"]["dns_runtime"]
        dns["ips"] = sorted(set(dns["ips"]) | ips)
        edge_set = {
            (_norm_dns_name(e.get("from")), _norm_dns_name(e.get("to")))
            for e in dns["cname_edges"] if isinstance(e, dict)
        } | edges
        dns["cname_edges"] = [
            {"from": src, "to": dst} for src, dst in sorted(edge_set) if src and dst
        ]
        sig = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        seen_records = {
            json.dumps(r, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            for r in dns["records"] if isinstance(r, dict)
        }
        if sig not in seen_records:
            dns["records"].append(record)
        evidence = {
            "source": _SOURCE, "location": "pcap-dns",
            "snippet": snippet, "observed_at": rec.ts or None,
            "scope": EvidenceScope.CASE_EVIDENCE.value,
        }
        if evidence not in ep["evidences"]:
            ep["evidences"].append(evidence)
    return list(by_name.values())


def _merge_runtime_dns_endpoint_dicts(payload: dict, fresh: list[dict]) -> int:
    """把 DNS endpoint 按集合语义幂等并入，不累加观测强度。"""
    existing = payload.get("endpoints")
    if not isinstance(existing, list):
        existing = []
        payload["endpoints"] = existing
    by_key = {
        (str(e.get("kind")), _norm_dns_name(e.get("value"))): e
        for e in existing if isinstance(e, dict)
    }
    added = 0
    for ep in fresh:
        key = ("domain", _norm_dns_name(ep.get("value")))
        hit = by_key.get(key)
        if hit is None:
            existing.append(ep)
            by_key[key] = ep
            added += 1
            continue
        enr = hit.setdefault("enrichment", {})
        if not isinstance(enr, dict):
            continue
        old = enr.get("dns_runtime")
        old = old if isinstance(old, dict) else {}
        new = ep["enrichment"]["dns_runtime"]
        old["source"] = _SOURCE
        for dns_field in ("ips", "cname_edges", "records"):
            combined = [*(old.get(dns_field) or []), *(new.get(dns_field) or [])]
            unique: dict[str, object] = {}
            for value in combined:
                sig = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                unique.setdefault(sig, value)
            old[dns_field] = [unique[k] for k in sorted(unique)]
        enr["dns_runtime"] = old
        evs = hit.setdefault("evidences", [])
        if isinstance(evs, list):
            for evidence in ep.get("evidences") or []:
                if evidence not in evs:
                    evs.append(evidence)
    return added


def _fingerprint_sni_fragment(values: set[str]) -> str:
    """正常 SNI 保持旧指纹；含分隔符的异常值改用无歧义结构化编码。

    ★SNI 是**不可信输入**（对端想写什么写什么）。逗号 join 会让 ``{"a,b","c"}`` 与
      ``{"a","b,c"}`` 撞出同一段指纹——两份端点贡献不同的采集被幂等闸误判为同一份、
      第二份静默丢失。走 JSON 编码即无歧义；只对含分隔符的异常值启用，
      既有报告里已算好的正常指纹不作废。
    """
    ordered = sorted(values)
    if all("," not in value and "\r" not in value and "\n" not in value for value in ordered):
        return "sni=" + ",".join(ordered)
    return "sni-json=" + json.dumps(
        ordered,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def summary_merge_fingerprint(summary: PcapSummary) -> str:
    """这份采集结果的内容指纹，用于「同一份 pcap 别并第二次」。

    ★为什么需要它：``_merge_runtime_blocks`` 对字节数/连接数求和是**跨端口累计**的正确语义，
      但同一份 pcap 重复 ``--into`` 同一个 report.json 时，这个求和就变成了凭空翻倍——
      报告不幂等，而字节数正是闭环判"有无双向载荷"的输入。指纹按内容算（不按文件路径），
      所以两份**不同**的采集仍会正常累加，只挡住重复导入同一份。

    ★判据：指纹只描述**受这道闸保护、且具有累加语义的那一份贡献**——也就是端点侧。

      :func:`merge_into_report_json` 一个函数里其实有**三种不同的合并代数**，各自的幂等性来源
      不同，**不能共用一个"所有落盘内容"的集合**（这正是上一版的错误）：

      ===========================  ==================================  ==============
      合并代数                      字段                                 要不要进指纹
      ===========================  ==================================  ==============
      Lead 侧按证据签名去重（闸外）   ``dns_queries`` / ``packets`` /      **不要**
                                   ``ja3`` / ``alpn`` / ``quic``       （本来就幂等）
      端点侧**求和 / 并集**          端点统计、``sni``                    **要**
      ``meta`` 覆盖写                ``flows`` / ``parse_status``        **不要**
      ===========================  ==================================  ==============

      收多了会怎样：两份**端点贡献完全相同**、只差 ``parse_status``（或 JA3 / ALPN / QUIC /
      packets / DNS 查询）的采集会算出不同指纹 → 闸放行 → ``out_bytes`` / ``in_bytes`` /
      ``connection_count`` **再累加一遍**，凭空长出观测强度。而这些差异本来根本不需要这道闸：
      Lead 侧自带证据签名去重，``meta`` 是覆盖写。

      收少了会怎样：两份端点贡献**不同**的采集撞指纹、第二份被整体跳过，更新静默丢失。
      （实测过：端点与字节数相同、只是第二次多解出 SNI，Lead 侧照常拿到 ``sni_masquerade``、
      端点侧却连 ``runtime.sni`` 都没有，同一份报告两种说法。所以 ``sni`` 必须在。）

      故只收 :func:`_runtime_endpoint_dicts` **真正写进端点**、且参与求和/并集/取端点的字段。
      ★要改这里，先问「这个字段是不是端点侧累加语义的一部分」，而不是「它落不落盘」。
    """
    parts = [
        # 只列 _runtime_endpoint_dicts 真会写进 enrichment["runtime"] 的东西。
        # packets / ja3 / alpn / quic 只进 Lead 证据，闸外已按签名去重，故不在此。
        f"{re_.ip}|{re_.port}|{re_.proto}|{re_.state}"
        f"|out={re_.out_bytes}|in={re_.in_bytes}|conns={re_.connection_count}"
        f"|payload={int(bool(re_.has_payload))}"
        f"|ts={re_.first_ts}-{re_.last_ts}"
        f"|{_fingerprint_sni_fragment(re_.sni)}"
        for re_ in remote_endpoints(summary)
    ]
    # 无端点的采集（如纯 DNS）指纹恒定——这是对的：端点侧无贡献可累加，
    # 而它的 DNS 线索由闸外的 Lead 合并处理，不受本闸影响。
    blob = "\n".join(sorted(parts)).encode("utf-8", "replace")
    return hashlib.sha256(blob).hexdigest()


#: 端口级明细字段：合并时取并集，绝不覆盖（否则同 IP 多端口只剩最后一个）。
_RUNTIME_UNION_KEYS = ("remote_endpoints", "ports", "sni", "sni_masquerade")
#: 计数字段：合并时求和（跨端口累计）。
_RUNTIME_SUM_KEYS = ("out_bytes", "in_bytes", "connection_count")

#: 连接状态强度序（越大＝对"真发生过通信"的证据越强）。合并时取**最强**的那个，
#: 而不是让最后并入的来源说了算——否则一次 SYN-only 的补充采集会把已确证的
#: established 降级成"连接尝试待核"，闭环据此判优先级，等于把真后端降档。
_STATE_RANK = {
    STATE_UNKNOWN: 0,
    STATE_SYN_ONLY: 1,
    STATE_RESET: 2,      # 见 RST 说明对端有反应，强于纯 SYN-only
    STATE_ESTABLISHED: 3,
}


def _merge_runtime_blocks(old: object, new: dict) -> dict:
    """合并两份 ``enrichment["runtime"]``，逐字段按语义处理而非整体覆盖。

    ★此前是 ``{**old, **new}``——新块里有的键一律压掉旧值。同一 IP 上有两个业务端口时，
      后并入的那个把端口、字节数、SNI 全盖掉，报告里只剩一半端口。实测样本里
      「一台机开两个端口、一主一心跳」是常见形态，等于稳定漏掉一半调证标的。

    列表取并集、计数求和、时间取端点、``has_payload`` 取或。

    ``state`` 取**强度最高**的（见 :data:`_STATE_RANK`），``proto`` 两侧不同即升 ``mixed``、
    且 ``mixed`` 只升不降——此前这两个键都由 ``new`` 直接覆盖：一次只含 TCP 的补充采集会把
    已经是 ``mixed`` 的记录退回 ``tcp``，一次 SYN-only 采集会把已确证的 ``established``
    降成"连接尝试待核"。**合并只应增加信息，不应删除已确证的事实**（codex P1）。

    其余未列出的键沿用 ``new`` 覆盖 ``old``——包括 ``target_attributed``：pcap 路径**从不写**该键
    （做不了 UID 归因，见 _runtime_endpoint_dicts），故它不在 ``new`` 里，capture 路径写下的真
    归因不会被这里冲掉。

    ``port``（代表端口）取**两侧总字节数较大的那一侧**的值。跨来源合并时拿不到逐端口明细，
    只能按来源整体判断——比"后并入的赢"准，但比 :func:`_runtime_endpoint_dicts` 内部的逐端口
    比较弱。权威明细始终看 ``ports`` / ``remote_endpoints``。
    """
    base = dict(old) if isinstance(old, dict) else {}
    out = {**base, **new}

    def _traffic(block: dict) -> float:
        return sum(
            v for k in ("out_bytes", "in_bytes")
            if isinstance(v := block.get(k), (int, float))
        )

    if "port" in base and "port" in new and _traffic(base) > _traffic(new):
        out["port"] = base["port"]
    for key in _RUNTIME_UNION_KEYS:
        merged = sorted({*(base.get(key) or []), *(new.get(key) or [])},
                        key=lambda v: (isinstance(v, str), v))
        if merged:
            out[key] = merged
        elif key in out and not out[key]:
            out.pop(key, None)
    for key in _RUNTIME_SUM_KEYS:
        a, b = base.get(key), new.get(key)
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            out[key] = a + b
    if base.get("has_payload") or new.get("has_payload"):
        out["has_payload"] = True

    states = [s for s in (base.get("state"), new.get("state")) if isinstance(s, str) and s]
    if states:
        out["state"] = max(states, key=lambda s: _STATE_RANK.get(s, 0))

    protos = {p for p in (base.get("proto"), new.get("proto")) if isinstance(p, str) and p}
    if protos:
        out["proto"] = "mixed" if (len(protos) > 1 or "mixed" in protos) else protos.pop()
    for key, pick in (("first_ts", min), ("last_ts", max)):
        a, b = base.get(key), new.get(key)
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            out[key] = pick(a, b)
    return out


# ★清单的 schema、别名表、迁移与消费方派生全部集中在
#   :mod:`apkscan.core.runtime_inventory`。此前这几件事散在本模块的私有 helper 里，
#   靠维护者在每个调用点临时决定传不传旧键，同一个「只修撞见的那个键、
#   漏掉结构相同的兄弟」的错误犯过三次。现在按表驱动，probe 回灌路径复用
#   同一份声明——两条路径的清单形状不会再各自漂移。


def merge_into_report_json(
    report_json_path: str,
    summary: PcapSummary,
    app_attr: dict[str, dict] | None = None,
) -> int:
    """把 pcap 线索合并进 report.json：``leads`` + ``endpoints`` + ``meta`` 的运行时信号。

    ``app_attr``：可选的 UID 归因表。给了则端点带 ``target_attributed``，且 inventory 的
    ``uid_attributed`` 置 True（闭环因此不再把动态结论封顶在 partial）。**不给就一律不写**，
    见 :func:`_attr_block`。

    绝不抛，失败返 0。

    - 新键（(category, value) 不存在）→ append，计入返回的 added。
    - 命中已存在键（如静态已抓到同 domain/ip）→ 不丢弃，把 runtime 证据并进原 lead、升为
      ``is_runtime_seen``（静态→活体确认），不计入 added。
    - 落盘走 :func:`atomic_write_text`：写中途失败绝不留半截坏 JSON（保底 return 0）。

    ★只写 leads 是不够的，这份报告的三个消费面各读各的：调证函读 leads、闭环排序读 endpoints、
      可见性读 meta。此前只更新第一面，于是同一份报告里 Lead 标着"实测双向通信"、闭环却挑着
      静态噪音、digest 还写着"未做运行时观测"——三处自相矛盾，而每一处单看都是自洽的。
    """
    try:
        from apkscan.report import json as report_json

        path = Path(report_json_path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            logger.warning("[pcap] report.json 顶层非 dict，跳过：%s", path)
            return 0
        ensure_writable_report_version(payload.get("schema_version"))
        # ★归因真源先行：按 fingerprint 记账后拿到三个确定性投影，本轮所有消费面
        #   （lead 证据、端点 runtime、inventory、capture_signals）都从投影出发，
        #   不再各自读"本次的 app_attr"——那正是跨抓包互相擦写的根源。
        #   账本版本/资源边界不支持时在此抛出（_AttributionLedgerRejected），
        #   由外层兜底 return 0，文件一个字节都不动（fail-closed）。
        meta = payload.get("meta")
        if not isinstance(meta, dict):
            meta = {}
            payload["meta"] = meta
        fingerprint = summary_merge_fingerprint(summary)
        carrier_projection, ip_projection, projected_target_ips = (
            _update_attribution_ledger(meta, fingerprint, summary, app_attr)
        )
        current_carriers = {
            f"{remote.proto}/{remote.ip}:{remote.port}"
            for remote in remote_endpoints(summary)
        }
        effective_app_attr = {
            carrier: carrier_projection[carrier]
            for carrier in sorted(current_carriers)
            if carrier in carrier_projection
        }
        existing = payload.get("leads")
        if not isinstance(existing, list):
            existing = []
            payload["leads"] = existing
        existing_by_key: dict[tuple[str, str], dict] = {
            (str(item.get("category")), str(item.get("value"))): item
            for item in existing
            if isinstance(item, dict)
        }
        added = 0
        confirmed = 0
        # 人工恢复凭据（从这份报告自己的 meta 读）：命中的来源不复压。必须在循环外读一次——
        # meta 在下面才被规范化成 dict，此处用宽松取法，坏形状由 restore_index 兜底成空集。
        restored_index = restore_index(payload.get("meta"))
        pcap_domains: set[str] = set()   # 本次采集贡献的域名（用于 inventory，见下）
        fresh_leads = to_report_leads(summary, effective_app_attr)
        fresh_eps = _runtime_endpoint_dicts(summary, effective_app_attr)
        # ★端点的 target_attributed 以**账本 IP 投影**为准，不以本轮 effective 表为准：
        #   同 IP 的另一次抓包（另一 fingerprint、另一端口）确证过 TARGET 时，
        #   本轮哪怕判否，该 IP 仍是"目标连过"——carrier 各说各的，IP 级归账本裁。
        for endpoint in fresh_eps:
            value = str(endpoint.get("value", ""))
            if value not in ip_projection:
                continue
            runtime = ((endpoint.get("enrichment") or {}).get("runtime") or {})
            if isinstance(runtime, dict):
                runtime["target_attributed"] = ip_projection[value]
        if not app_attr:
            # 本次没有任何端点拿到归因结论：不得用"没问过"去覆盖上一轮"问过、答案是否"的结论。
            #
            # ★这里**判 falsy 是对的**，与顶层 ``uid_attributed`` 的 ``is not None`` 不矛盾——
            #   两者问的是不同层次的问题：
            #     - ``uid_attributed``（run 级）：这一轮**执行过**归因吗？``{}`` = 执行过。
            #     - 本分支（端点级）：**这个端点**本轮拿到结论了吗？表为空 = 一个都没有，
            #       每个端点都是"未归因"，按三态属缺信息，不得给已确证的否定翻案。
            #   实测：若此处改判 ``is None``，传 ``{}`` 会让上一轮已确证判否的端点
            #   重新升回 ``contact=True``——正是三态哲学最禁止的"缺信息翻案"。
            _inherit_recorded_downgrades(payload, fresh_leads, fresh_eps)
        for lead in fresh_leads:
            key = (lead.category.value, lead.value)
            if lead.category is LeadCategory.DOMAIN:
                pcap_domains.add(lead.value)
            lead_dict = report_json._to_jsonable(lead)
            hit = existing_by_key.get(key)
            if hit is not None:
                # 命中已存在键：不丢弃——把 runtime 证据并进原 lead、升为活体确认。
                # ★confirmed 只计**证据**并入；仅抑制账本变化（ledger）不是「确认」，
                #   混计会让日志把降档合并报成「runtime 确认 N 条」。
                # 显式 TARGET 时，同一观测此前记下的降档证据要**原位翻案**（换来源），
                # 不能只追加一条新证据让两个相反结论并存——消费方看到哪条全凭列表顺序。
                if _lead_attribution_verdict(
                    lead, summary, effective_app_attr
                ) is True:
                    refs = hit.get("source_refs")
                    incoming_refs = lead_dict.get("source_refs")
                    if isinstance(refs, list) and isinstance(incoming_refs, list):
                        _replace_same_observation_evidence(refs, incoming_refs)
                ev_merged, _ledger = merge_runtime_into_lead_dict(
                    hit, lead_dict, restored=restored_index
                )
                if ev_merged:
                    confirmed += 1
                continue
            # ★首次引入这个值也要认墓碑：这条分支 append 的是一个**已经带着抑制账本**的新
            #   lead，不过滤就等于绕开人工放行（真实序列：replay 放行 → 本轮静态侧没产出该值
            #   → pcap 首次发现 → 带抑制入库 → 核实被抹掉）。
            strip_restored_downgrades(lead_dict, restored_index)
            existing_by_key[key] = lead_dict
            existing.append(lead_dict)
            added += 1

        # ★幂等闸：同一份采集只并一次。Lead 侧本就按证据签名去重、天然幂等，但端点侧的
        #   字节数/连接数是**求和**的（跨端口累计所必需），重复并入会让计数凭空翻倍——
        #   而字节数正是闭环判"有无双向载荷"的输入，翻倍等于伪造观测强度。
        #   （meta 与 fingerprint 已在账本记账时取好，见函数开头。）
        merged_fps = meta.get("runtime_pcap_merges")
        if not isinstance(merged_fps, list):
            merged_fps = []          # 旧报告没有该键 / 键被写坏 → 安全重建
        merged_fps = [f for f in merged_fps if isinstance(f, str)]
        already = fingerprint in merged_fps

        # 端点侧（fresh_eps 已在上面与 leads 一起算好：继承已记下的否定结论要两侧同时到手）：
        # 闭环排序、五层归属、外部富化都以 endpoints 为对象，不补这一步等于白抓。
        # DNS record 是集合语义，不参与流量字节/连接数累加，必须在 flow fingerprint 闸外
        # 独立合并。否则纯 DNS 的指纹恒定，第二次不同 answer 会被静默丢弃。
        fresh_dns_eps = _runtime_dns_endpoint_dicts(summary)
        dns_ep_added = _merge_runtime_dns_endpoint_dicts(payload, fresh_dns_eps)
        for ep in fresh_dns_eps:
            name = _norm_dns_name(ep.get("value"))
            if name:
                pcap_domains.add(name)
            dns = ((ep.get("enrichment") or {}).get("dns_runtime") or {})
            for edge in dns.get("cname_edges") or []:
                if isinstance(edge, dict):
                    for field in ("from", "to"):
                        domain = _norm_dns_name(edge.get(field))
                        if domain:
                            pcap_domains.add(domain)
        if already:
            ep_added = 0
            restamped = _restamp_runtime_endpoint_evidence(payload, fresh_eps)
            logger.info(
                "[pcap] 这份采集已并入过（fingerprint=%s…），跳过端点合并以保幂等"
                "（归因结论仍重标 %d 个端点）",
                fingerprint[:12], restamped,
            )
        else:
            ep_added = _merge_runtime_endpoint_dicts(payload, fresh_eps)
            merged_fps.append(fingerprint)
            # ★这份名单**不截尾**。曾经加过 64 条上限来防 meta 膨胀，但截尾会让最老的采集"失忆"：
            #   再次导入时 already=False，字节数与连接数照样求和，凭空长出观测强度——正是这道闸
            #   要防的那件事，被防膨胀的措施自己放了回来。取证工具的取舍是**宁可漏、不可造**：
            #   多留几条哈希只是几 KB，而伪造出来的"双向载荷"会直接改变闭环结论（codex 三轮 P1）。
            meta["runtime_pcap_merges"] = merged_fps

        # meta 侧：可见性据此判 runtime 这一维走没走过。不写就一直是"未做运行时观测"。
        #
        # ★条件必须含 DNS：纯 DNS 采集（无 flow、无端点）同样是**真观测**，却曾被
        #   ``fresh_eps or summary.flows`` 整个挡在门外——首次导入不产生 inventory、
        #   ``runtime_merged`` 也不置 True，可见性一直显示"未做运行时观测"（codex 五轮 P1）。
        # DNS answer 现已随 fresh_dns_eps 落盘，故 record-only 采集也有可审计证据。
        observed = bool(fresh_eps or fresh_dns_eps or summary.flows or summary.dns_queries)
        if observed:
            meta["runtime_merged"] = True
            # ★清单的键集合、别名迁移、以及「谁读它」全部由 runtime_inventory 那张表决定；
            #   本路径只负责如实提供**自己这次贡献了哪些值**。计数由贡献集合派生，
            #   集合语义天然幂等（同一份采集并几次结果不变），所以不受上面的指纹闸影响。
            #   ★``uid_attributed`` **随本次是否真做了归因而定**：给了 socket 快照
            #   （``--uid-sockets`` 或同目录自动探测）才是 True。没给仍是 False，
            #   闭环据此把动态结论**封顶 partial**，绝不抬成 complete。
            #   —— 此前这里恒 False：即便 capture 早已把某端点判为 confirmed，
            #      经 ``pcap-leads --into`` 回灌后也一律降成"未归因"，
            #      同一份采集因走的路径不同得出相反结论。
            meta[_inv.INVENTORY_META_KEY] = _inv.build_inventory(
                meta,
                source="pcap",
                endpoint_values=(str(ep.get("value", "")) for ep in fresh_eps),
                domain_values=pcap_domains,
                parse_status=summary.parse_status,
                # ★``is not None`` 不用 ``bool()``：``{}`` = 归因执行过、只是没有可归因的远端，
                #   与"没执行过"含义相反。用 falsy 会让同一条命令的 ledger 写"已归因"、
                #   inventory 写"未归因"——同一份数据两个出口相反结论。
                uid_attributed=app_attr is not None,
                # ★只收**真的归到目标 app** 的那些端点值。传端点总数（或让下游拿总数顶替）
                #   会把背景噪音写成"目标已确认通信"——实测 33 个接入节点里只有 1 个属目标。
                #   值取**账本全量投影**而非本次 fresh_eps：目标集是跨抓包的裁决结果，
                #   本次没看到 ≠ 不再是目标，本次判否 = 从投影里退出（见下面的替换）。
                target_attributed_values=projected_target_ips,
            )
            # build_inventory 的集合语义只增不减；账本投影是唯一有权收缩目标集的裁决，
            # 故在其后**整体替换** pcap 那本账（probe 的账与 legacy floor 原样保留）。
            _apply_inventory_attribution_projection(meta, projected_target_ips)
            if app_attr is not None:
                # 与 capture 落同一个键：下游（closure 门控 evaluate_capture_quality、报告）
                # 读的是 capture_signals.pcap_app_attribution，不区分数据来自哪条路径。
                # ★``{}`` 也要写：它表示"归因执行过、结果为空"，与键缺失（没执行过）含义相反；
                #   塌掉的话，闭环会把"问过、没有可归因远端"当成"没问过"而封顶 partial。
                signals = meta.get("capture_signals")
                if not isinstance(signals, dict):
                    signals = {}
                    meta["capture_signals"] = signals
                # ★不再 ``update(app_attr)`` 全局覆写——那是 carrier 级"后写者胜"，
                #   反转一次抓包会连带擦掉另一次抓包已确证的结论。改为整表来自账本投影
                #   （TARGET-wins、确定性），capture_signals 从共享草稿变成派生视图。
                signal_projection = {
                    carrier: dict(result)
                    for carrier, result in sorted(carrier_projection.items())
                }
                # capture_signals 是既有的详细取证面：若当前输入与账本最终 verdict
                # 一致，保留其 UID/process 等原始细节；ledger 自身仍只存安全投影字段。
                if isinstance(app_attr, dict):
                    for carrier, projected in signal_projection.items():
                        current_result = app_attr.get(carrier)
                        if (
                            isinstance(current_result, dict)
                            and isinstance(current_result.get("is_target_app"), bool)
                            and current_result.get("is_target_app")
                            is projected.get("is_target_app")
                        ):
                            signal_projection[carrier] = dict(current_result)
                signals["pcap_app_attribution"] = signal_projection
            # 清单换过键名：旧键留着会让两套形状长期并存，读方各读一套。整块重建后清掉。
            for _stale in _inv.INVENTORY_META_ALIASES:
                meta.pop(_stale, None)

        # ★刷新派生视图：visibility 快照是**算出来的**，不是证据。上面往 meta 追加了
        #   ``runtime_merged`` / inventory，不重算就会落盘一份自相矛盾的报告——实测过
        #   「23 个运行时端点、27 条活体确认线索，快照却写着『未做运行时观测（纯静态分析）』」。
        #   判据本身没错（它读 runtime_merged），错在**没人把新信号带回快照**。
        #
        #   无条件刷、不放进 `if observed`：重算幂等且信息保持（见 refresh_visibility_snapshot
        #   与 _preserve_confirmed_gaps），所以连「本次无新信号、但快照本来就旧」的报告也会被
        #   一并修正；而真·空采集不会凭空得到 runtime 维——meta 里没有 runtime_merged，
        #   重算照样是 unavailable。
        #   ★延迟导入：closure.sources 反向懒引本模块，模块级互引会成环。
        from apkscan.core.closure import refresh_visibility_snapshot

        refresh_visibility_snapshot(meta)

        atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2))
        # ★把「没做 UID 归因」和「做了、0 条归目标」分开说：此前两者都只体现为
        #   "runtime 确认 0 条"，读的人无从判断该去补快照还是该接受这个结论。
        # ★三态各说各的，别把后两者合并：``None`` 没问过 / ``{}`` 问过但没有可归因远端 /
        #   非空表 才有计数可报。此前 ``if app_attr:`` 把 ``{}`` 归进"没给快照"，
        #   于是明明给了快照的纯 DNS 采集会被报成"未做 UID 归因"，读的人会去补一份已经有的东西。
        if app_attr:
            from apkscan.dynamic import socket_attr as _sa

            c = _sa.attribution_counts(app_attr)
            attr_note = (f"UID 归因 {c['total']} 个端点："
                         f"confirmed {c['confirmed']}/probable {c['probable']}/"
                         f"ambiguous {c['ambiguous']}/unattributed {c['unattributed']}，"
                         f"其中 {c['target_app']} 属目标 app")
        elif app_attr is not None:
            attr_note = "已做 UID 归因，但本次采集没有可归因的远端（无公网接入节点）"
        else:
            attr_note = "未做 UID 归因（本次没给 socket 快照）——不等于这些端点不属目标 app"
        logger.info(
            "[pcap] 追加 %d 条线索、%d 个运行时IP端点、%d 个DNS端点，runtime 证据合并 %d 条；%s → %s",
            added, ep_added, dns_ep_added, confirmed, attr_note, path,
        )
        return added
    except (OSError, ValueError):
        logger.exception("[pcap] 读取/解析 report.json 失败：%s", report_json_path)
        return 0
    except Exception:  # noqa: BLE001 - 追加失败不抛
        logger.exception("[pcap] 追加进 report.json 异常：%s", report_json_path)
        return 0
