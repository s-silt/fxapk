# -*- coding: utf-8 -*-
"""Phase2 证据链：每个落盘产物记录上一环的哈希，stale 只有一个定义。

stale = 产物声明的上一环哈希，与该上一环当前字节的哈希对不上。
公开侧的 review 绑定和私有侧的 replay 迁移都用这个定义，不再各写一套。

内存里的 inventory / triage / coverage dict 不放链字段。金标准比对的就是那些
dict；链只出现在落盘信封和回执上。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from apkscan.core.integrity import sha256_canonical_json, sha256_file, sha256_hex

CHAIN_LINKS: tuple[str, ...] = (
    "report",
    "package",
    "inventory",
    "triage",
    "decision",
    "coverage",
    "gate-receipt",
    "review",
)
PREVIOUS_LINK: dict[str, str | None] = {
    "report": None,
    "package": "report",
    "inventory": "package",
    "triage": "inventory",
    "decision": "triage",
    "coverage": "decision",
    "gate-receipt": "coverage",
    "review": "gate-receipt",
}

# 与现有产物的 schema_version 字面量对齐。改版本必须同时改产出方，不能只改这里。
SCHEMA_VERSIONS: dict[str, str] = {
    "report": "1.2",
    "package": "1.0",
    "inventory": "1.0",
    "triage": "phase2-triage/1.0",
    "decision": "phase2-decision/1.1",
    "coverage": "1.0",
    "gate-receipt": "phase2-gate-receipt/1.0",
    "review": "1.0",
    "replay": "phase2-replay/1.0",
}

# 追加账本和旧 review 投影不在行上携带 previous_sha256。
# 要求它们补这个字段会改历史字节，或把「旧 review 仍可投影」变成新的出具条件。
ENVELOPE_LINKS: frozenset[str] = frozenset({"inventory", "triage", "gate-receipt"})


class ChainError(ValueError):
    """链上的哈希对不上，或产物缺了上一环声明。"""


def is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and set(value) <= set("0123456789abcdef")
    )


def file_sha256(path: str | Path) -> str:
    """文件当前字节的 SHA-256。缺文件抛 ``OSError``，不把缺失伪装成空哈希。"""
    return sha256_file(path)


def canonical_sha256(payload: object) -> str:
    """规范 JSON 的 SHA-256。拒绝 NaN / Infinity。"""
    return sha256_canonical_json(payload)


def bytes_sha256(data: bytes) -> str:
    return sha256_hex(data)


def chain_link(link: str, payload: Mapping[str, object], *, previous_sha256: str) -> dict[str, object]:
    """给一份已有产物补上一环声明。不改 payload 里的既有键。

    ``previous_sha256`` 必须是上一环当前字节的 SHA-256。链的第一环没有上一环，
    不走这里。
    """
    if link not in PREVIOUS_LINK or PREVIOUS_LINK[link] is None:
        raise ChainError(f"{link} 没有上一环，不能声明 previous_sha256")
    if not is_sha256(previous_sha256):
        raise ChainError("previous_sha256 必须是 64 位小写十六进制 SHA-256")
    if "previous_sha256" in payload:
        raise ChainError("产物已经声明了 previous_sha256")
    return {**dict(payload), "previous_link": PREVIOUS_LINK[link], "previous_sha256": previous_sha256}


def is_stale(declared_previous_sha256: object, current_previous_sha256: str) -> bool:
    """stale 的唯一定义：声明的上一环哈希与上一环当前字节对不上。

    声明缺失、不是 SHA-256、或与当前字节不同，都是 stale。对得上才不是。
    """
    if not is_sha256(current_previous_sha256):
        raise ChainError("current_previous_sha256 必须是 64 位小写十六进制 SHA-256")
    return declared_previous_sha256 != current_previous_sha256


def replay_stale(decision: Mapping[str, object], current_inventory_fingerprint: str) -> bool:
    """replay 侧的 stale：判决记录的 inventory_fingerprint 对不上当前清单。

    与 :func:`is_stale` 是同一个定义。判决把上一环指纹放在
    ``decided_against.inventory_fingerprint``，不是顶层 ``previous_sha256``。
    """
    decided_against = decision.get("decided_against")
    declared = (
        decided_against.get("inventory_fingerprint")
        if isinstance(decided_against, Mapping)
        else None
    )
    return is_stale(declared, current_inventory_fingerprint)


def review_stale(
    review: Mapping[str, object],
    *,
    current_manifest_sha256: str,
    current_receipt_sha256: str | None = None,
) -> bool:
    """review 侧的 stale。

    review 始终绑定 manifest 字节。绑定了门禁回执时，回执当前字节也必须对得上
    ``phase2_gate.receipt_sha256``。两处有一处对不上就是 stale。
    """
    if is_stale(review.get("manifest_sha256"), current_manifest_sha256):
        return True
    binding = review.get("phase2_gate")
    if current_receipt_sha256 is None or not isinstance(binding, Mapping):
        return False
    return is_stale(binding.get("receipt_sha256"), current_receipt_sha256)


def schema_document(link: str) -> dict[str, object]:
    """该环的 JSON Schema（draft 2020-12）。只约束链上必须有的字段，不重写产物全文。"""
    version = SCHEMA_VERSIONS[link]
    previous = PREVIOUS_LINK[link]
    properties: dict[str, object] = {
        "schema_version": {"const": version},
    }
    required = ["schema_version"]
    if link in ENVELOPE_LINKS and previous is not None:
        properties["previous_link"] = {"const": previous}
        properties["previous_sha256"] = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
        required.extend(["previous_link", "previous_sha256"])
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",  # leak-scan: allow JSON Schema 规范要求的 $schema 标识，不是案件域名
        "$id": f"fxapk-phase2/{link}.schema.json",
        "type": "object",
        "properties": properties,
        "required": required,
    }


def write_schema_documents(directory: str | Path) -> None:
    """把八环 schema 写到目录。已存在且内容相同则跳过，内容不同则拒绝覆盖。"""
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    for link in CHAIN_LINKS:
        path = target / f"{link}.schema.json"
        text = json.dumps(schema_document(link), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if path.exists() and path.read_text(encoding="utf-8") != text:
            raise ChainError(f"拒绝覆盖已有且不同的 schema：{path.name}")
        if not path.exists():
            path.write_text(text, encoding="utf-8")


__all__ = [
    "CHAIN_LINKS",
    "PREVIOUS_LINK",
    "SCHEMA_VERSIONS",
    "ChainError",
    "bytes_sha256",
    "canonical_sha256",
    "chain_link",
    "file_sha256",
    "is_sha256",
    "is_stale",
    "replay_stale",
    "review_stale",
    "schema_document",
    "write_schema_documents",
]
