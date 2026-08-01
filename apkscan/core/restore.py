"""人工恢复凭据（墓碑）：把「这条线索已经人工核实过、放行」这个判断变成可复用的状态。

**要解决的问题**：抑制机制是自动的，每次分析都会重新压。人工核实放行之后，只要重新跑一次
分析（换版本、补证据——实测是常态），同一条线索又被压回去，上一次的核实白做。

**边界**：本模块只认 ``report.meta`` 里的墓碑，**不碰任何存储**。凭据的跨运行持久化（存进
样本库、按样本哈希重放）属于 CLI 层的事——核心层不该知道样本库在哪、叫什么。两层的接口就是
``report.meta[MANUAL_RESTORES_KEY]`` 这一个键。

★**信任模型（必须明白，不然会高估这道机制）**：墓碑**不是**认证凭据，本模块也不做真伪校验。
  能改 ``report.json`` 的人本来就能改 ``advice``——所以墓碑防不住篡改，它解决的是另一件事：
  让「放行」这个人的判断可审计、可跨重跑复用。

  但有一处不对称必须补平：手改 ``advice`` 会被 closure 的一致性守卫挡下（档位与账本矛盾），
  而手塞一条墓碑不会——因为跳过抑制之后档位与空账本是自洽的。若就这么放着，等于给绕过守卫
  留了一条**更安静**的路。故：凡是因墓碑而未被抑制的线索，各出口都必须把它**显式计数并呈现**
  （closure 的 ``manually_restored``、digest 的同名字段），让「这条是被人放行的、不是判据说它
  干净」在任何一个消费面上都看得见。可见性是这里唯一站得住的保证，不是真伪。
"""

from __future__ import annotations

import logging
from typing import Any, Mapping

logger = logging.getLogger(__name__)

#: ``report.meta`` 里存放人工恢复凭据的键。写进报告、随报告流转，是对外契约的一部分。
MANUAL_RESTORES_KEY = "manual_restores"

#: 单条凭据的必需字段。``value`` 大小写不敏感（与 closure 的比对口径一致）。
_REQUIRED = ("category", "value", "source")


def norm_component(value: object) -> str:
    """墓碑三元组里单个分量的归一化：``strip`` + ``lower``。

    ★**公开**是有意的：凡是拿三元组做匹配的地方都必须用这一份。此前 ``models`` 为了保持
      纯 stdlib 叶子而复制过三行同样的逻辑——复制的是**安全键的匹配规则**，一旦哪天分叉，
      「已放行」在一处成立、另一处不成立，人工核实就会在某条路径上被静默抹掉。
      ``models`` 现在直接引本模块：本模块同样只依赖 stdlib，且不 import models，不成环。
    """
    return str(value or "").strip().lower()


#: 内部沿用的短名（保持既有调用点可读）。
_norm = norm_component


def restore_index(meta: Mapping[str, Any] | None) -> set[tuple[str, str, str]]:
    """把 ``meta`` 里的墓碑读成 ``{(category, value, source)}`` 索引；坏形状一律跳过，绝不抛。

    三元组而不是二元组：同一条线索可能同时被多个来源压着（重打包 + 伪装 SNI），人工放行的
    是**其中一条**——按 ``(值, 来源)`` 精确匹配，才不会因为放行了一条就把其余的也挡住复压。
    """
    if not isinstance(meta, Mapping):
        return set()
    raw = meta.get(MANUAL_RESTORES_KEY)
    if not isinstance(raw, list):
        return set()
    out: set[tuple[str, str, str]] = set()
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        if any(not _norm(item.get(k)) for k in _REQUIRED):
            continue
        out.add((_norm(item.get("category")), _norm(item.get("value")), _norm(item.get("source"))))
    return out


def is_restored(
    index: set[tuple[str, str, str]], category: object, value: object, source: object
) -> bool:
    """这条 ``(类别, 值, 抑制来源)`` 是否已被人工放行过。"""
    if not index:
        return False
    return (_norm(category), _norm(value), _norm(source)) in index


def normalize_downgrades(raw: object) -> dict[str, str]:
    """把磁盘上的 ``downgrades`` 规整成 ``{来源 id: 说明}``；坏形状一律丢弃，绝不抛。

    ★**两条路径共用一份**：dict 合并（``models.merge_runtime_into_lead_dict``）与首次引入时的
      摘除（:func:`strip_restored_downgrades`）此前各写各的——一个 ``str()`` 硬转非字符串说明、
      另一个丢弃；一个 strip 来源 id、另一个不 strip。``report.json`` 是公开的持久化边界，
      同一份畸形数据经两条路径得到不同账本，就意味着「哪条路径先碰到它」决定了结果。

    规则：来源 id 必须是**非空白字符串**（strip 后存），说明必须是**真字符串**（不 ``str()``
    硬转——嵌套对象被转成 ``"{'a': 1}"`` 后看着像正常说明，实则是坏数据混进了判定输入）。
    """
    if not isinstance(raw, Mapping):
        return {}
    out: dict[str, str] = {}
    for rid, note in raw.items():
        if not (isinstance(rid, str) and rid.strip()):
            continue
        if not isinstance(note, str):
            continue
        out[rid.strip()] = note
    return out


def restored_sources_for(lead: Mapping[str, Any], index: set[tuple[str, str, str]]) -> set[str]:
    """这条 lead（dict 形态）上有哪些抑制来源是被人工放行的。

    各出口共用一份：digest 的 ``manually_restored`` 字段、letters 的正文警示、HTML 的线索级
    警示都靠它。分头实现的话，某个出口的匹配口径一偏，「这条是人放行的」就在那个出口上消失——
    而可见性正是这套机制唯一站得住的保证。
    """
    if not index:
        return set()
    category, value = norm_component(lead.get("category")), norm_component(lead.get("value"))
    return {source for (cat, val, source) in index if cat == category and val == value}


def strip_restored_downgrades(lead_dict: dict, index: set[tuple[str, str, str]]) -> bool:
    """把**新引入**的 lead dict 上已被人工放行的抑制来源摘掉并重算档位；返回是否动过。

    ★为什么新增分支也要过：回灌命中已有 lead 时走的是合并（那里已按墓碑过滤），但**首次**
      引入这个值时是直接 append 一个已经带着 downgrades 的 dict——同一条线索，只因为这次是
      新键就绕开了人工放行。真实序列：新报告 replay 放行 → 该值本轮静态侧没产出 → pcap 首次
      发现它 → append 带着抑制的新 lead → 人工核实又被抹掉。

    档位重算与合并路径同源：摘掉来源后按剩余账本与锚点重新算，不直接写档位。
    """
    if not index:
        return False
    current = normalize_downgrades(lead_dict.get("downgrades"))
    if not current:
        return False
    category, value = lead_dict.get("category"), lead_dict.get("value")
    kept = {
        rid: note
        for rid, note in current.items()
        if not is_restored(index, category, value, rid)
    }
    if kept == current:
        # 与规范化前逐字节相同才算“没动过”；否则即便没摘掉任何来源，也要把规范化结果写回，
        # 免得畸形账本原样留在报告里、下一条路径又按另一套规则解读它。
        if lead_dict.get("downgrades") == current:
            return False

    # 就地重算：与 models.merge_runtime_into_lead_dict 用同一套 helper，避免两处档位算法分叉。
    from apkscan.core.models import VALID_ADVICE, effective_advice

    def _anchor(v: object) -> str | None:
        return v.strip() if isinstance(v, str) and v.strip() in VALID_ADVICE else None

    lead_dict["downgrades"] = kept
    fresh = effective_advice(
        _anchor(lead_dict.get("base_advice")), kept, _anchor(lead_dict.get("legacy_effective_advice"))
    )
    if fresh:
        lead_dict["advice"] = fresh
    return True


def record_restore(
    meta: dict,
    *,
    category: str,
    value: str,
    source: str,
    note: str,
    at: str,
    prior_advice: str,
    new_advice: str,
) -> dict:
    """往 ``meta`` 里追加一条墓碑并返回它（同 ``(类别,值,来源)`` 已存在则更新说明与时刻）。

    ★墓碑记的是**放行这个动作**，不是当时的档位结论：``prior_advice`` / ``new_advice`` 只作
      审计留痕，重放时一律重新走 :func:`models.lift_downgrade` 算档位，不拿这里的值直接写。
      直接写的话，一份换了版本、判据链结论已经变了的新报告，会被旧档位覆盖。
    """
    entries = meta.get(MANUAL_RESTORES_KEY)
    if not isinstance(entries, list):
        entries = []
        meta[MANUAL_RESTORES_KEY] = entries
    key = (_norm(category), _norm(value), _norm(source))
    record = {
        "category": category,
        "value": value,
        "source": source,
        "note": note,
        "at": at,
        "prior_advice": prior_advice,
        "new_advice": new_advice,
    }
    for i, item in enumerate(entries):
        if not isinstance(item, Mapping):
            continue
        if (_norm(item.get("category")), _norm(item.get("value")), _norm(item.get("source"))) == key:
            entries[i] = record
            return record
    entries.append(record)
    return record


__all__ = [
    "MANUAL_RESTORES_KEY",
    "is_restored",
    "record_restore",
    "restore_index",
    "restored_sources_for",
    "strip_restored_downgrades",
]
