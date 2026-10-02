# -*- coding: utf-8 -*-
"""Phase2 只读分层。

本模块只消费 Phase1 inventory，并只读重扫各包 report.json。
所有分层判据集中在本模块，CLI 不包含任何判据。
"""

from __future__ import annotations

import ipaddress
import json
from collections import defaultdict
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import inventory as pc


_COLLECTIONS: tuple[str, ...] = ("leads", "endpoints", "findings")
_RUNTIME_FIELDS: tuple[str, ...] = (
    "is_runtime_seen",
    "is_runtime_contact",
    "is_c2",
)


def normalize_host(kind: str, value: str) -> str:
    """把 lead/endpoint 的网络值收成纯 host。空值或 URL 解析失败时返回空字符串。

    与 :func:`apkscan.core.infra.match_key` 都用于让网络值可比，语义并不相同，
    R1 合并和 G9 established 比对继续用本函数：

    - ``kind=url`` 时用 ``urlsplit`` 取 hostname。``match_key`` 只做 strip 和 lower。
    - 端口只在 kind 为 ``ip`` 或 ``domain``、恰好一个冒号、且冒号后全是数字时去掉。
      ``match_key`` 只在类别为 IP 时处理端口：单冒号后的整段都去掉，并识别
      ``host:port/proto``。多冒号的 IPv6 在带 ``/proto`` 时，``match_key`` 可能把末段当端口。
    - 非 URL 先按第一个 ``/`` 截断。``match_key`` 对非 IP 保留 ``/`` 后面的路径。
    - 去掉末尾的 ``.``。``match_key`` 保留末尾的点。
    - 能解析的 IP（含括号 IPv6）收成 ``ipaddress`` 的压缩规范形。``match_key`` 只 lower。
    """
    text = str(value).strip()
    if not text:
        return ""

    normalized_kind = str(kind).strip().lower()

    if normalized_kind == "url":
        try:
            parsed = urlsplit(text)
            host = parsed.hostname or ""
        except ValueError:
            return ""
        return host.lower().rstrip(".")

    text = text.split("/", 1)[0].strip()
    text = text.rstrip(".")

    # 括号 IPv6（可带端口）：[2001:db8::1]:443 → 2001:db8::1
    if text.startswith("["):
        end = text.find("]")
        if end != -1:
            inner = text[1:end]
            try:
                return str(ipaddress.ip_address(inner)).lower()
            except ValueError:
                return inner.lower().rstrip(".")

    # 单冒号才可能是 IPv4:port；裸 IPv6 有多个冒号，端口须靠方括号区分，不在此剥。
    if normalized_kind in {"ip", "domain"} and text.count(":") == 1:
        host_part, port_part = text.rsplit(":", 1)
        if port_part.isdigit():
            text = host_part

    # IP 归一到 canonical（统一 IPv6 零压缩/大小写）；非 IP 原样小写去尾点。
    try:
        return str(ipaddress.ip_address(text)).lower()
    except ValueError:
        return text.lower().rstrip(".")


@dataclass(frozen=True)
class Proposal:
    collection: str
    parent_id: str
    display: str
    member_candidate_ids: tuple[str, ...]
    packages: int
    bucket: str
    tier: str
    why: str
    signals: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()
    merged_into: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "collection": self.collection,
            "parent_id": self.parent_id,
            "display": self.display,
            "member_candidate_ids": list(self.member_candidate_ids),
            "packages": self.packages,
            "bucket": self.bucket,
            "tier": self.tier,
            "why": self.why,
            "signals": list(self.signals),
            "conflicts": list(self.conflicts),
            "merged_into": list(self.merged_into),
        }


@dataclass(frozen=True)
class Triage:
    schema_version: str
    case_id: str
    inventory_fingerprint: str
    totals: dict[str, int]
    parents: tuple[Proposal, ...]
    issues: tuple[Any, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "inventory_fingerprint": self.inventory_fingerprint,
            "totals": dict(self.totals),
            "parents": [parent.to_dict() for parent in self.parents],
            "issues": [_issue_to_dict(issue) for issue in self.issues],
        }


@dataclass(frozen=True)
class _ParentVersion:
    package_name: str
    parent: dict[str, Any]


def _issue_to_dict(issue: Any) -> Any:
    if is_dataclass(issue) and not isinstance(issue, type):
        return asdict(issue)
    if isinstance(issue, dict):
        return dict(issue)
    return {
        "code": str(getattr(issue, "code", "")),
        "location": str(getattr(issue, "location", "")),
        "detail": str(getattr(issue, "detail", "")),
        "next_action": str(getattr(issue, "next_action", "")),
        "severity": str(getattr(issue, "severity", "")),
    }


def _read_parent_versions(
    case_dir: Path,
    inventory: Any,
) -> dict[tuple[str, str], tuple[_ParentVersion, ...]]:
    """按稳定 parent_id 重扫报告；★只读 inventory 已接纳的包，杜绝坏包污染判据。

    只信任 ``inventory.packages``（已过 manifest/哈希/资源/符号链接校验），不自行按目录
    发现包。否则被 ``build_inventory`` 拒绝的包（缺 manifest、重复 package_id、超限、
    unsafe symlink 等）会混进 lead_index 与 advice 版本，污染 R1/R4/跨包冲突判定。
    报告路径取 inventory 候选记录的 ``report_relpath``（即 manifest artifacts 登记的真实文件名）。
    """
    result: dict[tuple[str, str], list[_ParentVersion]] = defaultdict(list)

    relpath_by_package: dict[str, str] = {}
    for candidate in getattr(inventory, "candidates", ()):
        relpath = getattr(candidate, "report_relpath", "")
        if relpath:
            relpath_by_package.setdefault(str(getattr(candidate, "package_id", "")), str(relpath))
    package_reports = sorted({
        (str(getattr(p, "directory_name", "")),
         relpath_by_package.get(str(getattr(p, "package_id", "")), "report.json"))
        for p in inventory.packages
    })

    for name, relpath in package_reports:
        if not name:
            continue
        package_root = (case_dir / name).resolve()
        report_path = (package_root / relpath).resolve()
        if not report_path.is_relative_to(package_root) or not report_path.is_file():
            continue

        with report_path.open("r", encoding="utf-8") as handle:
            report = json.load(handle)

        if not isinstance(report, dict):
            continue

        for collection in _COLLECTIONS:
            raw_items = report.get(collection, [])
            if not isinstance(raw_items, list):
                continue

            for parent in raw_items:
                if not isinstance(parent, dict):
                    continue
                stable = pc._stable_parent_id(collection, parent)
                if stable is None:
                    continue
                parent_id, _ = stable
                result[(collection, parent_id)].append(
                    _ParentVersion(name, parent)
                )

    return {
        key: tuple(
            sorted(
                versions,
                key=lambda item: (
                    item.package_name,
                    json.dumps(
                        item.parent,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
            )
        )
        for key, versions in sorted(result.items())
    }


def _bool_state(parent: dict[str, Any], field_name: str) -> str:
    """返回 true、false、null 或 missing，严格区分字段缺失与 null。"""
    if field_name not in parent:
        return "missing"
    value = parent[field_name]
    if type(value) is bool:
        return "true" if value else "false"
    if value is None:
        return "null"
    return "invalid"


def _all_runtime_false(versions: tuple[_ParentVersion, ...]) -> bool:
    return bool(versions) and all(
        _bool_state(item.parent, field_name) == "false"
        for item in versions
        for field_name in _RUNTIME_FIELDS
    )


def _runtime_complete(versions: tuple[_ParentVersion, ...]) -> bool:
    return bool(versions) and all(
        _bool_state(item.parent, field_name) in {"true", "false"}
        for item in versions
        for field_name in _RUNTIME_FIELDS
    )


def _advice_values(
    versions: tuple[_ParentVersion, ...],
) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                str(item.parent.get("advice", "<缺失>"))
                for item in versions
            }
        )
    )


def _display_for(
    candidates: list[Any],
    versions: tuple[_ParentVersion, ...],
) -> str:
    if candidates and str(getattr(candidates[0], "display_value", "")):
        return str(getattr(candidates[0], "display_value", ""))

    for version in versions:
        value = version.parent.get("value")
        if value is not None:
            return str(value)
        title = version.parent.get("title")
        if title is not None:
            return str(title)
        identifier = version.parent.get("id")
        if identifier is not None:
            return str(identifier)
    return ""


def _lead_index(
    parent_versions: dict[tuple[str, str], tuple[_ParentVersion, ...]],
) -> dict[str, tuple[str, ...]]:
    """建立 host 到 lead parent_id 列表的单向镜像索引。"""
    index: dict[str, list[str]] = defaultdict(list)

    for (collection, parent_id), versions in sorted(parent_versions.items()):
        if collection != "leads":
            continue

        for version in versions:
            category = str(version.parent.get("category", ""))
            if category not in {"DOMAIN", "IP"}:
                continue
            host = normalize_host(
                category.lower(),
                str(version.parent.get("value", "")),
            )
            if host:
                index[host].append(parent_id)
                break

    return {
        host: tuple(sorted(set(parent_ids)))
        for host, parent_ids in sorted(index.items())
    }


def _make_proposal(
    collection: str,
    parent_id: str,
    candidates: list[Any],
    versions: tuple[_ParentVersion, ...],
    lead_index: dict[str, tuple[str, ...]],
) -> Proposal:
    member_ids = tuple(
        sorted(str(getattr(candidate, "candidate_id", "")) for candidate in candidates)
    )
    package_ids = tuple(
        sorted({str(getattr(candidate, "package_id", "")) for candidate in candidates})
    )
    display = _display_for(candidates, versions)
    signals: list[str] = []
    conflicts: list[str] = []
    merged_into: tuple[str, ...] = ()

    if collection == "findings":
        severities = tuple(
            sorted(
                {
                    str(version.parent.get("severity", "<缺失>"))
                    for version in versions
                }
            )
        )
        tier = "finding:" + "/".join(severities or ("<缺失>",))
        return Proposal(
            collection,
            parent_id,
            display,
            member_ids,
            len(package_ids),
            "auto:report_only",
            tier,
            "分析叙事（finding）非逐值调证对象",
            tuple(f"severity={value}" for value in severities),
        )

    if collection == "endpoints":
        kinds = tuple(
            sorted(
                {
                    str(version.parent.get("kind", "<缺失>"))
                    for version in versions
                }
            )
        )
        kind = kinds[0] if len(kinds) == 1 else ""
        values = tuple(
            str(version.parent.get("value", ""))
            for version in versions
            if version.parent.get("value") is not None
        )
        host = normalize_host(kind, values[0] if values else "")

        if kind == "path":
            return Proposal(
                collection,
                parent_id,
                display,
                member_ids,
                len(package_ids),
                "auto:report_only",
                "endpoint:path",
                "URL 路径非发函对象（接口面清单）",
                tuple(f"kind={value}" for value in kinds),
            )

        # 同 host 不证明证据重复：运行时端点仍须逐条复核，不能借静态 lead 自动排除。
        runtime_evidence = any(
            any(
                isinstance(evidence, dict)
                and str(evidence.get("source", "")).startswith("runtime")
                for evidence in version.parent.get("evidences", [])
            )
            or (
                isinstance(version.parent.get("enrichment"), dict)
                and bool(version.parent["enrichment"].get("runtime"))
            )
            for version in versions
        )
        if runtime_evidence:
            return Proposal(
                collection, parent_id, display, member_ids, len(package_ids),
                "human", "T1:runtime_endpoint", "运行时端点证据须独立复核，同 host 不构成证据镜像",
                ("runtime_seen", "runtime_endpoint"),
            )

        merged_into = lead_index.get(host, ())
        if host and merged_into:
            return Proposal(
                collection,
                parent_id,
                display,
                member_ids,
                len(package_ids),
                "auto:duplicate_or_merged",
                "R1-MIRROR",
                "endpoint host 规范化后与同案 lead 网络身份同值，判决挂 lead",
                ("R1-MIRROR",),
                (),
                merged_into,
            )

        return Proposal(
            collection,
            parent_id,
            display,
            member_ids,
            len(package_ids),
            "human",
            "T1:endpoint无lead镜像",
            "endpoint 没有同案 lead 镜像，必须逐条复核",
            ("endpoint无lead镜像",),
        )

    # leads
    advice_values = _advice_values(versions)
    advice_conflict = len(advice_values) != 1
    effective_advice = advice_values[0] if len(advice_values) == 1 else ""

    if advice_conflict:
        conflicts.append("跨包advice=" + "/".join(advice_values))
        signals.append("跨包advice冲突")

    runtime_states = {
        field_name: tuple(
            sorted(
                {
                    _bool_state(version.parent, field_name)
                    for version in versions
                }
            )
        )
        for field_name in _RUNTIME_FIELDS
    }

    runtime_seen_true = "true" in runtime_states["is_runtime_seen"]
    runtime_contact_true = "true" in runtime_states["is_runtime_contact"]
    c2_true = "true" in runtime_states["is_c2"]
    runtime_incomplete = not _runtime_complete(versions)

    if runtime_contact_true:
        signals.append("runtime_contact")
    if c2_true:
        signals.append("is_c2")
    if effective_advice == "建议调证":
        signals.append("advice=建议调证")
    if runtime_seen_true:
        signals.append("runtime_seen")
    if runtime_incomplete:
        signals.append("runtime字段不完整")

    if advice_conflict:
        return Proposal(
            collection,
            parent_id,
            display,
            member_ids,
            len(package_ids),
            "human",
            "T1:跨包advice冲突",
            "跨包 advice 不一致，必须复核；值为 " + "/".join(advice_values),
            tuple(signals),
            tuple(conflicts),
        )

    if runtime_contact_true or c2_true or effective_advice == "建议调证" or runtime_seen_true:
        tier_parts = [
            signal
            for signal in (
                "runtime_contact",
                "is_c2",
                "advice=建议调证",
                "runtime_seen",
                "runtime字段不完整",
            )
            if signal in signals
        ]
        return Proposal(
            collection,
            parent_id,
            display,
            member_ids,
            len(package_ids),
            "human",
            "T1:" + "+".join(tier_parts),
            "存在需逐条复核的运行时或调证信号",
            tuple(signals),
            tuple(conflicts),
        )

    if effective_advice == "无需调证":
        if not _all_runtime_false(versions):
            return Proposal(
                collection,
                parent_id,
                display,
                member_ids,
                len(package_ids),
                "human",
                "T1:runtime字段不完整",
                "advice=无需调证，但三个 runtime 字段未全部显式为 False，禁止自动排除",
                tuple(signals),
                tuple(conflicts),
            )

        downgrade_keys = sorted(
            {
                str(key)
                for version in versions
                for key in (
                    version.parent.get("downgrades", {})
                    if isinstance(version.parent.get("downgrades"), dict)
                    else {}
                )
            }
        )
        return Proposal(
            collection,
            parent_id,
            display,
            member_ids,
            len(package_ids),
            "auto:excluded_with_reason",
            "R4-LEDGER",
            "Phase1 降档台账 advice=无需调证 downgrades="
            + repr(downgrade_keys or ["(空)"]),
            tuple(signals),
            tuple(conflicts),
        )

    if effective_advice == "待核" and _all_runtime_false(versions):
        categories = tuple(
            sorted(
                {
                    str(version.parent.get("category", "<缺失>"))
                    for version in versions
                }
            )
        )
        confidences = tuple(
            sorted(
                {
                    str(version.parent.get("confidence", "<缺失>"))
                    for version in versions
                }
            )
        )
        category = categories[0] if len(categories) == 1 else "/".join(categories)
        confidence = "/".join(confidences or ("<缺失>",))
        return Proposal(
            collection,
            parent_id,
            display,
            member_ids,
            len(package_ids),
            "human",
            f"T2:待核静态 {category} conf={confidence}",
            "advice=待核且三个 runtime 字段均显式为 False，进入 T2 形态组批展示",
            tuple(signals),
            tuple(conflicts),
        )

    return Proposal(
        collection,
        parent_id,
        display,
        member_ids,
        len(package_ids),
        "human",
        "T1:runtime字段不完整",
        "无法确认静态-only，缺少有效 advice 或 runtime 三态信息",
        tuple(signals),
        tuple(conflicts),
    )


def build_triage(inventory: Any, case_dir: Path) -> Triage:
    """构建只读 triage；inventory.candidates 是唯一候选分母。"""
    parent_versions = _read_parent_versions(case_dir, inventory)
    lead_index = _lead_index(parent_versions)

    candidates_by_parent: dict[tuple[str, str], list[Any]] = defaultdict(list)
    for candidate in inventory.candidates:
        key = (
            str(getattr(candidate, "collection", "")),
            str(getattr(candidate, "parent_id", "")),
        )
        candidates_by_parent[key].append(candidate)

    proposals: list[Proposal] = []
    for collection, parent_id in sorted(candidates_by_parent):
        candidates = sorted(
            candidates_by_parent[(collection, parent_id)],
            key=lambda item: (
                str(getattr(item, "candidate_id", "")),
                str(getattr(item, "package_id", "")),
            ),
        )
        versions = parent_versions.get((collection, parent_id), ())
        proposals.append(
            _make_proposal(
                collection,
                parent_id,
                candidates,
                versions,
                lead_index,
            )
        )

    proposals.sort(key=lambda item: (item.collection, item.parent_id))

    auto_count = sum(item.bucket != "human" for item in proposals)
    human_count = len(proposals) - auto_count
    t1_count = sum(
        item.bucket == "human" and item.tier.startswith("T1")
        for item in proposals
    )
    t2_group_keys = {
        (
            str(next(iter(item.signals), "")),
            item.tier,
        )
        for item in proposals
        if item.bucket == "human" and item.tier.startswith("T2:")
    }

    totals = {
        "candidates": len(inventory.candidates),
        "parents": len(proposals),
        "auto": auto_count,
        "human": human_count,
        "t1": t1_count,
        "t2_groups": len(t2_group_keys),
    }

    # 精确集合守恒：不只比数量，比 candidate_id 的 multiset，并单独锁唯一性与非空。
    # 只比数量会放过"一漏一重"（[A,B] vs [A,A] 数量都是 2）。
    expected = [str(getattr(c, "candidate_id", "")) for c in inventory.candidates]
    if "" in expected:
        raise ValueError("inventory 存在空 candidate_id")
    if len(expected) != len(set(expected)):
        raise ValueError("inventory candidate_id 非唯一")
    actual = [cid for item in proposals for cid in item.member_candidate_ids]
    if sorted(actual) != sorted(expected):
        raise ValueError(
            "候选覆盖集合不一致（数量或身份不符，含一漏一重）："
            f"parents={len(actual)}, inventory={len(expected)}"
        )

    return Triage(
        schema_version="phase2-triage/1.0",
        case_id=str(inventory.case_id),
        inventory_fingerprint=str(inventory.fingerprint),
        totals=totals,
        parents=tuple(proposals),
        issues=tuple(inventory.issues),
    )


def _tier_sort_key(proposal: Proposal) -> tuple[int, str, str, str]:
    if proposal.tier.startswith("T1:跨包advice冲突"):
        rank = 0
    elif proposal.tier.startswith("T1:runtime_contact"):
        rank = 1
    elif "is_c2" in proposal.tier:
        rank = 2
    elif "advice=建议调证" in proposal.tier:
        rank = 3
    elif "runtime_seen" in proposal.tier:
        rank = 4
    elif "endpoint无lead镜像" in proposal.tier:
        rank = 5
    else:
        rank = 6
    return rank, proposal.collection, proposal.parent_id, proposal.display


def render_queue_md(triage: Triage) -> str:
    """渲染稳定的人读清单，不产生额外结构化落盘文件。"""
    parents = list(triage.parents)
    human = [item for item in parents if item.bucket == "human"]
    t1 = sorted(
        [item for item in human if item.tier.startswith("T1:")],
        key=_tier_sort_key,
    )
    t2 = sorted(
        [item for item in human if item.tier.startswith("T2:")],
        key=lambda item: (item.tier, item.collection, item.parent_id),
    )
    auto = [item for item in parents if item.bucket != "human"]

    lines = [
        "# Phase2 人读清单",
        "",
        f"- 案件：`{triage.case_id}`",
        f"- inventory fingerprint：`{triage.inventory_fingerprint}`",
        f"- 候选：{triage.totals['candidates']}",
        f"- case-parent：{triage.totals['parents']}",
        f"- 人判：{triage.totals['human']}（T1={triage.totals['t1']}）",
        "",
        "## T1：逐条复核",
        "",
    ]

    if not t1:
        lines.append("无。")
    else:
        for item in t1:
            lines.extend(
                [
                    f"### `{item.tier}`｜{item.collection}｜{item.display}",
                    f"- parent_id：`{item.parent_id}`",
                    f"- candidate_ids：{', '.join(f'`{x}`' for x in item.member_candidate_ids)}",
                    f"- 包数：{item.packages}",
                    f"- 理由：{item.why}",
                    f"- signals：{', '.join(item.signals) or '无'}",
                    f"- conflicts：{', '.join(item.conflicts) or '无'}",
                    "",
                ]
            )

    lines.extend(["## T2：形态组批展示", ""])
    if not t2:
        lines.append("无。")
    else:
        groups: dict[str, list[Proposal]] = defaultdict(list)
        for item in t2:
            groups[item.tier].append(item)
        for group_name in sorted(groups):
            lines.append(f"### 组：`{group_name}`")
            lines.append("> 仅作展示单位，不承载组决；同段或同形态不等于同主体。")
            for item in groups[group_name]:
                lines.append(
                    f"- {item.collection}｜{item.display}｜`{item.parent_id}`"
                    f"｜候选数={len(item.member_candidate_ids)}"
                )
            lines.append("")

    lines.extend(["## 自动处置摘要", ""])
    lines.append(f"已自动处置 {len(auto)} 条 case-parent（附理由，可推翻）。")
    for item in auto:
        lines.append(
            f"- `{item.bucket}`｜{item.collection}｜{item.display}"
            f"｜{item.why}"
        )

    lines.extend(
        [
            "",
            "## Phase1 issues",
            "",
        ]
    )
    if not triage.issues:
        lines.append("无。")
    else:
        for issue in triage.issues:
            issue_dict = _issue_to_dict(issue)
            lines.append(
                "- "
                + json.dumps(
                    issue_dict,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )

    return "\n".join(lines) + "\n"
