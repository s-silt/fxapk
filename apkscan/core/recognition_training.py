"""构建与加载防泄漏 recognition split-manifest。

依据 §10 split-manifest 契约：以传递闭包形成原子单位，确定性分配切分，
并在编码与加载阶段 fail-closed 复验结构、摘要及隔离不变量。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import hashlib
import json
import re
from typing import Any, Final, Mapping, NoReturn, TYPE_CHECKING

if TYPE_CHECKING:
    from apkscan.core.recognition_labels import (
        RecognitionLabelSet,
    )


_POLICY_VERSION: Final[str] = "split-v1"
_SCHEMA_VERSION: Final[str] = "1.0"
_DOMAIN_MANIFEST: Final[str] = "fxapk-split-manifest-v1\n"
_DOMAIN_UNIT: Final[str] = "fxapk-split-unit-v1\n"
_SHA_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")
_SPLIT_NAMES: Final[tuple[str, ...]] = (
    "train",
    "test_temporal_seen",
    "test_unseen_family",
    "test_adversarial",
    "calibration",
)
_SPLIT_NAME_SET: Final[frozenset[str]] = frozenset(_SPLIT_NAMES)
_RESERVED_FAMILY_IDS: Final[frozenset[str]] = frozenset({"unknown", "abstain"})
_CONFIRMED: Final[str] = "confirmed"
_ACTIVE_RECORD_STATE: Final[str] = "active"
_MERGE_REASONS: Final[frozenset[str]] = frozenset(
    {
        "same_case",
        "confirmed_family",
        "confirmed_positive_relation",
        "derivation",
    }
)


class SplitManifestError(Exception):
    """split-manifest 构建或加载失败。"""

    def __init__(self, reason_code: str, detail: str) -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code}: {detail}")


def _fail(reason_code: str, detail: str) -> NoReturn:
    raise SplitManifestError(reason_code, detail)


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        _fail("manifest_invalid", f"不可规范化 JSON: {exc}")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_sha(value: Any, where: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        _fail("sha_invalid", f"{where} 不是合法 sha256")
    return value


def _validate_date(value: Any, where: str) -> str:
    if not isinstance(value, str) or len(value) != 10:
        _fail("date_invalid", f"{where} 不是严格 YYYY-MM-DD 日期")
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        _fail("date_invalid", f"{where} 不是严格 YYYY-MM-DD 日期")
    if parsed.isoformat() != value:
        _fail("date_invalid", f"{where} 不是严格 YYYY-MM-DD 日期")
    return value


def _sorted_unique(values: Any, where: str) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        _fail("manifest_invalid", f"{where} 必须是序列")
    if any(not isinstance(item, str) for item in values):
        _fail("manifest_invalid", f"{where} 必须只含字符串")
    result = tuple(sorted(set(values)))
    if len(result) != len(values):
        _fail("manifest_invalid", f"{where} 必须无重复")
    return result


@dataclass(frozen=True, slots=True)
class SplitConfig:
    cutoff_date: str
    unseen_families: tuple[str, ...]
    adversarial_samples: tuple[str, ...]
    calibration_samples: tuple[str, ...]
    derivations: tuple[tuple[str, str], ...]
    policy_version: str
    labels_digest: str
    catalog_revision: str


@dataclass(frozen=True, slots=True)
class SplitUnit:
    unit_id: str
    members: tuple[str, ...]
    case_ids: tuple[str, ...]
    family_ids: tuple[str, ...]
    unit_date: str | None
    merge_reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SplitManifest:
    schema_version: str
    policy_version: str
    cutoff_date: str
    labels_digest: str
    catalog_revision: str
    time_table_digest: str
    excluded_row_count: int
    unseen_families: tuple[str, ...]
    adversarial_samples: tuple[str, ...]
    calibration_samples: tuple[str, ...]
    train: tuple[SplitUnit, ...]
    test_temporal_seen: tuple[SplitUnit, ...]
    test_unseen_family: tuple[SplitUnit, ...]
    test_adversarial: tuple[SplitUnit, ...]
    calibration: tuple[SplitUnit, ...]

    @property
    def splits(self) -> Mapping[str, tuple[SplitUnit, ...]]:
        return {name: getattr(self, name) for name in _SPLIT_NAMES}


class _UnionFind:
    def __init__(self, values: tuple[str, ...]) -> None:
        self.parent: dict[str, str] = {value: value for value in values}
        self.rank: dict[str, int] = {value: 0 for value in values}

    def find(self, value: str) -> str:
        parent: str = self.parent[value]
        if parent != value:
            parent = self.find(parent)
            self.parent[value] = parent
        return parent

    def union(self, left: str, right: str) -> None:
        root_left: str = self.find(left)
        root_right: str = self.find(right)
        if root_left == root_right:
            return
        if self.rank[root_left] < self.rank[root_right]:
            root_left, root_right = root_right, root_left
        self.parent[root_right] = root_left
        if self.rank[root_left] == self.rank[root_right]:
            self.rank[root_left] += 1


def _unit_id(members: tuple[str, ...]) -> str:
    return _sha256_text(_DOMAIN_UNIT + _canonical_json(list(members)))


def _manifest_dict(manifest: SplitManifest, include_digest: bool) -> dict[str, Any]:
    def unit_dict(unit: SplitUnit) -> dict[str, Any]:
        return {
            "unit_id": unit.unit_id,
            "members": list(unit.members),
            "case_ids": list(unit.case_ids),
            "family_ids": list(unit.family_ids),
            "unit_date": unit.unit_date,
            "merge_reasons": list(unit.merge_reasons),
        }

    result: dict[str, Any] = {
        "schema_version": manifest.schema_version,
        "policy_version": manifest.policy_version,
        "cutoff_date": manifest.cutoff_date,
        "labels_digest": manifest.labels_digest,
        "catalog_revision": manifest.catalog_revision,
        "time_table_digest": manifest.time_table_digest,
        "excluded_row_count": manifest.excluded_row_count,
        "unseen_families": list(manifest.unseen_families),
        "adversarial_samples": list(manifest.adversarial_samples),
        "calibration_samples": list(manifest.calibration_samples),
    }
    for name in _SPLIT_NAMES:
        result[name] = [unit_dict(unit) for unit in getattr(manifest, name)]
    if include_digest:
        body: str = _canonical_json(result)
        result["manifest_digest"] = _sha256_text(_DOMAIN_MANIFEST + body)
    return result


def _validate_manifest_invariants(manifest: SplitManifest) -> None:
    membership: dict[str, str] = {}
    unseen: set[str] = set(manifest.unseen_families)
    adversarial: set[str] = set(manifest.adversarial_samples)
    calibration: set[str] = set(manifest.calibration_samples)

    for split_name in _SPLIT_NAMES:
        units: tuple[SplitUnit, ...] = getattr(manifest, split_name)
        # 切分内单位必须按 members 升序——digest 只锁内容不锁顺序，重排重签
        # 在此被拒（codex 复审 P2）。
        for left_unit, right_unit in zip(units, units[1:]):
            if left_unit.members >= right_unit.members:
                _fail("manifest_invalid", f"{split_name} 单位未按 canonical 顺序")
        for unit in units:
            if unit.unit_id != _unit_id(unit.members):
                _fail("manifest_invalid", "unit_id 与 members 不匹配")
            if not unit.members:
                _fail("manifest_invalid", "单位不得为空")
            if tuple(sorted(unit.members)) != unit.members:
                _fail("manifest_invalid", "members 未排序")
            if tuple(sorted(set(unit.members))) != unit.members:
                _fail("manifest_invalid", "members 含重复 sha")
            for member in unit.members:
                previous: str | None = membership.get(member)
                if previous is not None:
                    _fail("manifest_invalid", f"sha 跨单位: {member}")
                membership[member] = split_name

            if split_name in {"test_adversarial", "test_unseen_family"}:
                if unit.unit_date is not None:
                    _validate_date(unit.unit_date, "unit_date")
            elif unit.unit_date is None:
                _fail("manifest_invalid", f"{split_name} 单位缺少 unit_date")

            if split_name == "test_adversarial" and (set(unit.members) & calibration):
                _fail("calibration_conflict", "adversarial 单位含 calibration 样本")

            if unseen & set(unit.family_ids) and split_name != "test_unseen_family":
                _fail(
                    "unseen_isolation_violation",
                    "unseen family 出现在非 test_unseen_family 切分",
                )

    if len(membership) != len(
        {
            member
            for split in _SPLIT_NAMES
            for unit in getattr(manifest, split)
            for member in unit.members
        }
    ):
        _fail("manifest_invalid", "sha 归属不唯一")

    # 指名 adversarial/calibration 样本可以不在场（语料外），但在场就必须落
    # 各自切分——加载器不信任构建器，独立复验该不变量（codex 复审 P1）。
    for member, split_name in membership.items():
        if member in adversarial and split_name != "test_adversarial":
            _fail("manifest_invalid", f"adversarial 样本落在 {split_name}")
        if member in calibration and split_name != "calibration":
            _fail("calibration_conflict", f"calibration 样本落在 {split_name}")


def build_split_manifest(
    catalog_rows: list[dict[str, Any]],
    label_set: "RecognitionLabelSet",
    time_table: Mapping[str, str],
    config: SplitConfig,
) -> SplitManifest:
    """纯函数构建确定性的防泄漏 split-manifest。"""
    if config.policy_version != _POLICY_VERSION:
        _fail("policy_unknown", f"不支持 policy_version: {config.policy_version}")
    cutoff: str = _validate_date(config.cutoff_date, "cutoff_date")

    unseen_families: tuple[str, ...] = tuple(sorted(set(config.unseen_families)))
    adversarial: tuple[str, ...] = tuple(
        sorted(
            {_validate_sha(value, "adversarial_samples") for value in config.adversarial_samples}
        )
    )
    calibration: tuple[str, ...] = tuple(
        sorted(
            {_validate_sha(value, "calibration_samples") for value in config.calibration_samples}
        )
    )
    derivations: tuple[tuple[str, str], ...] = tuple(
        sorted(
            {
                (
                    _validate_sha(pair[0], "derivations.left"),
                    _validate_sha(pair[1], "derivations.right"),
                )
                for pair in config.derivations
            }
        )
    )

    normalized_time: dict[str, str] = {}
    for case_id, value in time_table.items():
        if not isinstance(case_id, str):
            _fail("date_invalid", "time_table case_id 必须是字符串")
        normalized_time[case_id] = _validate_date(value, f"time_table[{case_id}]")
    time_digest: str = _sha256_text(_canonical_json(normalized_time))

    nodes: set[str] = set()
    active_rows: list[dict[str, Any]] = []
    excluded: int = 0
    case_members: dict[str, set[str]] = {}

    for row in catalog_rows:
        if row.get("record_state", _ACTIVE_RECORD_STATE) != _ACTIVE_RECORD_STATE:
            excluded += 1
            continue
        sha: str = _validate_sha(row.get("sample_sha256"), "catalog.sample_sha256")
        case_values: Any = row.get("case_ids", [])
        if not isinstance(case_values, list) or any(
            not isinstance(item, str) for item in case_values
        ):
            _fail("manifest_invalid", "catalog.case_ids 必须是字符串列表")
        row_cases: tuple[str, ...] = tuple(sorted(set(case_values)))
        nodes.add(sha)
        active_rows.append({"sha": sha, "cases": row_cases})
        for case_id in row_cases:
            case_members.setdefault(case_id, set()).add(sha)

    confirmed = tuple(record for record in label_set.effective if record.status == _CONFIRMED)
    family_by_sha: dict[str, set[str]] = {}
    family_groups: dict[str, set[str]] = {}
    relation_edges: list[tuple[str, str]] = []
    for record in confirmed:
        if record.kind == "family_assignment":
            sha = _validate_sha(record.sample_sha256, "label.sample_sha256")
            family_id = record.family_id
            if not isinstance(family_id, str):
                _fail("manifest_invalid", "family_id 必须是字符串")
            nodes.add(sha)
            family_by_sha.setdefault(sha, set()).add(family_id)
            if family_id not in _RESERVED_FAMILY_IDS:
                family_groups.setdefault(family_id, set()).add(sha)
        elif record.kind == "relation_judgment" and record.relation == "positive":
            left = _validate_sha(record.left_sha256, "label.left_sha256")
            right = _validate_sha(record.right_sha256, "label.right_sha256")
            nodes.update((left, right))
            relation_edges.append((left, right))

    for left, right in derivations:
        nodes.update((left, right))

    uf = _UnionFind(tuple(sorted(nodes)))
    edge_reasons: dict[tuple[str, str], set[str]] = {}

    def add_edge(left: str, right: str, reason: str) -> None:
        key = (left, right) if left <= right else (right, left)
        edge_reasons.setdefault(key, set()).add(reason)
        uf.union(left, right)

    for group_members in case_members.values():
        ordered = tuple(sorted(group_members))
        for index, left in enumerate(ordered):
            for right in ordered[index + 1 :]:
                add_edge(left, right, "same_case")
    for group_members in family_groups.values():
        ordered = tuple(sorted(group_members))
        for index, left in enumerate(ordered):
            for right in ordered[index + 1 :]:
                add_edge(left, right, "confirmed_family")
    for left, right in relation_edges:
        add_edge(left, right, "confirmed_positive_relation")
    for left, right in derivations:
        add_edge(left, right, "derivation")

    components: dict[str, set[str]] = {}
    for node in sorted(nodes):
        components.setdefault(uf.find(node), set()).add(node)

    units_by_split: dict[str, list[SplitUnit]] = {name: [] for name in _SPLIT_NAMES}
    for members_set in sorted(components.values(), key=lambda values: tuple(sorted(values))):
        members: tuple[str, ...] = tuple(sorted(members_set))
        cases: set[str] = set()
        for row in active_rows:
            if row["sha"] in members_set:
                cases.update(row["cases"])
        dates = [normalized_time[case_id] for case_id in cases if case_id in normalized_time]
        unit_date: str | None = max(dates) if dates else None
        families: set[str] = set()
        for member in members:
            families.update(family_by_sha.get(member, set()))

        if set(members) & set(adversarial):
            split = "test_adversarial"
        elif families & set(unseen_families):
            split = "test_unseen_family"
        elif set(members) & set(calibration):
            if unit_date is None:
                _fail("time_missing", f"缺失 case 日期: {sorted(cases)}")
            if unit_date > cutoff:
                _fail("calibration_conflict", "calibration 样本晚于 cutoff_date")
            split = "calibration"
        else:
            if unit_date is None:
                _fail("time_missing", f"缺失 case 日期: {sorted(cases)}")
            split = "train" if unit_date <= cutoff else "test_temporal_seen"

        reasons: set[str] = set()
        for edge, edge_reason in edge_reasons.items():
            if set(edge) <= members_set:
                reasons.update(edge_reason)
        unit = SplitUnit(
            unit_id=_unit_id(members),
            members=members,
            case_ids=tuple(sorted(cases)),
            family_ids=tuple(sorted(families)),
            unit_date=unit_date,
            merge_reasons=tuple(sorted(reasons)),
        )
        units_by_split[split].append(unit)

    manifest = SplitManifest(
        schema_version=_SCHEMA_VERSION,
        policy_version=config.policy_version,
        cutoff_date=cutoff,
        labels_digest=config.labels_digest,
        catalog_revision=config.catalog_revision,
        time_table_digest=time_digest,
        excluded_row_count=excluded,
        unseen_families=unseen_families,
        adversarial_samples=adversarial,
        calibration_samples=calibration,
        **{name: tuple(units_by_split[name]) for name in _SPLIT_NAMES},
    )
    _validate_manifest_invariants(manifest)
    return manifest


def encode_split_manifest(manifest: SplitManifest) -> str:
    """编码 canonical JSON manifest。"""
    _validate_manifest_invariants(manifest)
    payload: dict[str, Any] = _manifest_dict(manifest, include_digest=True)
    return _canonical_json(payload) + "\n"


def load_split_manifest(text: str) -> SplitManifest:
    """解析、校验摘要并独立复验 manifest 不变量。"""
    try:
        payload: Any = json.loads(text)
    except (TypeError, ValueError) as exc:
        _fail("manifest_invalid", f"JSON 无效: {exc}")
    if not isinstance(payload, dict):
        _fail("manifest_invalid", "顶层必须是对象")

    digest = payload.get("manifest_digest")
    if not isinstance(digest, str):
        _fail("manifest_invalid", "缺少 manifest_digest")
    body = dict(payload)
    del body["manifest_digest"]
    expected = _sha256_text(_DOMAIN_MANIFEST + _canonical_json(body))
    if digest != expected:
        _fail("digest_mismatch", "manifest_digest 不匹配")
    if payload.get("schema_version") != _SCHEMA_VERSION:
        _fail("schema_unknown", "不支持的 schema_version")
    if payload.get("policy_version") != _POLICY_VERSION:
        _fail("policy_unknown", "不支持的 policy_version")

    required = {
        "schema_version",
        "policy_version",
        "cutoff_date",
        "labels_digest",
        "catalog_revision",
        "time_table_digest",
        "excluded_row_count",
        "unseen_families",
        "adversarial_samples",
        "calibration_samples",
        "manifest_digest",
        *_SPLIT_NAMES,
    }
    if set(payload) != required:
        _fail("manifest_invalid", "顶层字段集合不匹配")

    cutoff = _validate_date(payload["cutoff_date"], "cutoff_date")
    excluded = payload["excluded_row_count"]
    if not isinstance(excluded, int) or excluded < 0:
        _fail("manifest_invalid", "excluded_row_count 无效")

    def parse_units(split_name: str) -> tuple[SplitUnit, ...]:
        raw_units = payload[split_name]
        if not isinstance(raw_units, list):
            _fail("manifest_invalid", f"{split_name} 必须是列表")
        result: list[SplitUnit] = []
        for raw in raw_units:
            if not isinstance(raw, dict) or set(raw) != {
                "unit_id",
                "members",
                "case_ids",
                "family_ids",
                "unit_date",
                "merge_reasons",
            }:
                _fail("manifest_invalid", f"{split_name} 单位结构无效")
            unit_id = raw["unit_id"]
            if not isinstance(unit_id, str):
                _fail("manifest_invalid", "unit_id 无效")
            members = _sorted_unique(raw["members"], "members")
            members = tuple(_validate_sha(item, "members") for item in members)
            cases = _sorted_unique(raw["case_ids"], "case_ids")
            families = _sorted_unique(raw["family_ids"], "family_ids")
            reasons = _sorted_unique(raw["merge_reasons"], "merge_reasons")
            if any(reason not in _MERGE_REASONS for reason in reasons):
                _fail("manifest_invalid", "未知 merge_reason")
            unit_date = raw["unit_date"]
            if unit_date is not None:
                unit_date = _validate_date(unit_date, "unit_date")
            result.append(SplitUnit(unit_id, members, cases, families, unit_date, reasons))
        return tuple(result)

    manifest = SplitManifest(
        schema_version=payload["schema_version"],
        policy_version=payload["policy_version"],
        cutoff_date=cutoff,
        labels_digest=payload["labels_digest"],
        catalog_revision=payload["catalog_revision"],
        time_table_digest=payload["time_table_digest"],
        excluded_row_count=excluded,
        unseen_families=_sorted_unique(payload["unseen_families"], "unseen_families"),
        adversarial_samples=tuple(
            _validate_sha(item, "adversarial_samples")
            for item in _sorted_unique(payload["adversarial_samples"], "adversarial_samples")
        ),
        calibration_samples=tuple(
            _validate_sha(item, "calibration_samples")
            for item in _sorted_unique(payload["calibration_samples"], "calibration_samples")
        ),
        **{name: parse_units(name) for name in _SPLIT_NAMES},
    )
    _validate_manifest_invariants(manifest)
    # 冻结文件必须逐字节 canonical：重排单位/键序后重签 digest 仍会在此被拒
    # （codex 复审 P2——digest 只锁内容，不锁编码形态）。
    if encode_split_manifest(manifest) != text:
        _fail("manifest_invalid", "manifest 编码非 canonical 形态")
    return manifest
