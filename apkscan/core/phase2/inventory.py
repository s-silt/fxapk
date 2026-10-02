# -*- coding: utf-8 -*-
"""Phase1 证据清单与 Phase2 处置覆盖审计（只读、确定性、fail-closed）。

这个 Module 提供第二阶段的独立分母：不是从已经写进清单的行反推“都处理了”，而是先从
不可变 Phase1 包枚举每个 Lead / Endpoint / Finding，再要求每个候选恰好一个处置。
"""
from __future__ import annotations

from apkscan.core.bounded_io import read_limited
from apkscan.core.json_io import (
    read_json_bounded as _read_json_bounded,
    json_depth as _json_depth,
)

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from apkscan.core.integrity import sha256_hex
from apkscan.core.json_contract import (
    parse_finite_json_float,
    reject_nonfinite_json_constant,
)

SCHEMA_VERSION = "1.0"
COLLECTIONS = ("leads", "endpoints", "findings")
DISPOSITIONS = frozenset({
    "accepted_clue",
    "excluded_with_reason",
    "pending_with_action",
    "duplicate_or_merged",
    "report_only",
    "unsupported_due_to_visibility",
})
_PARENT_SENTINEL = "__parent__"
_PARENT_SCOPE = "parent"


@dataclass(frozen=True)
class InventoryLimits:
    max_package_directories: int = 512
    max_manifest_bytes: int = 4 * 1024 * 1024
    max_report_bytes: int = 128 * 1024 * 1024
    max_collection_items: int = 100_000
    max_evidence_items_per_parent: int = 10_000
    max_total_candidates: int = 250_000
    max_json_depth: int = 64


@dataclass(frozen=True)
class InventoryIssue:
    code: str
    location: str
    detail: str
    next_action: str
    severity: str = "blocker"


@dataclass(frozen=True)
class ReviewCandidate:
    candidate_id: str
    package_id: str
    collection: str
    parent_id: str
    evidence_id: str
    scope: str
    has_evidence: bool
    manifest_sha256: str
    report_relpath: str = "report.json"
    display_value: str = ""

    def provenance_dict(self) -> dict[str, str]:
        return {
            "candidate_id": self.candidate_id,
            "package_id": self.package_id,
            "collection": self.collection,
            "parent_id": self.parent_id,
            "evidence_id": self.evidence_id,
            "scope": self.scope,
            "manifest_sha256": self.manifest_sha256,
            "report_relpath": self.report_relpath,
        }


@dataclass(frozen=True)
class Phase1Package:
    package_id: str
    directory_name: str
    manifest_sha256: str
    report_sha256: str


@dataclass
class Phase1EvidenceInventory:
    case_id: str
    packages: list[Phase1Package] = field(default_factory=list)
    candidates: list[ReviewCandidate] = field(default_factory=list)
    issues: list[InventoryIssue] = field(default_factory=list)
    fingerprint: str = ""
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "fingerprint": self.fingerprint,
            "packages": [vars(item) for item in self.packages],
            "candidates": [vars(item) for item in self.candidates],
            "issues": [vars(item) for item in self.issues],
            "stats": {
                "package_count": len(self.packages),
                "candidate_count": len(self.candidates),
                "blocker_count": len(self.issues),
            },
        }


@dataclass(frozen=True)
class CoverageIssue:
    code: str
    detail: str
    next_action: str
    candidate_id: str = ""
    clue_id: str = ""


@dataclass
class CoverageAudit:
    blockers: list[CoverageIssue] = field(default_factory=list)
    warnings: list[CoverageIssue] = field(default_factory=list)
    candidate_count: int = 0
    covered_count: int = 0
    accepted_clue_count: int = 0
    disposition_counts: dict[str, int] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.blockers


def _issue(code: str, location: str, detail: str, action: str) -> InventoryIssue:
    return InventoryIssue(code, location, detail, action)


def _coverage_issue(
    code: str,
    detail: str,
    action: str,
    *,
    candidate_id: str = "",
    clue_id: str = "",
) -> CoverageIssue:
    return CoverageIssue(code, detail, action, candidate_id, clue_id)


def _registered_report_path(package_dir: Path, manifest: Mapping[str, Any]) -> Path | None:
    """Resolve the one report registered by a public ``case-package.json``.

    Older private packages used the fixed name ``report.json``.  Public 1.6+
    packages preserve the analysis report's real filename in ``artifacts``.
    The fixed name is returned as written when that file exists; artifact paths
    go through :func:`apkscan.core.case_package.resolve_package_artifact_path`.

    ``reject_absolute=False`` keeps the previous lookup: an absolute path that
    still resolves to an existing file inside the package is accepted. The case
    verifier's default rejects that absolute path as unsafe. Those two policies
    stay separate.
    """
    artifacts = manifest.get("artifacts")
    # A declared manifest is authoritative. An unrelated report.json must not
    # replace the verified, possibly renamed report artifact.
    if artifacts is None:
        legacy = package_dir / "report.json"
        return legacy.resolve() if legacy.is_file() else None
    if not isinstance(artifacts, list):
        return None
    paths = [item.get("path") for item in artifacts
             if isinstance(item, Mapping) and item.get("kind") == "report"]
    report_rel = paths[0] if paths else None
    if len(paths) != 1 or not isinstance(report_rel, str) or not report_rel:
        return None
    from apkscan.core.case_package import (
        ArtifactPathVerdict,
        resolve_package_artifact_path,
    )

    verdict, resolved = resolve_package_artifact_path(
        package_dir, report_rel, strict=True, reject_absolute=False,
    )
    if verdict is not ArtifactPathVerdict.INSIDE or resolved is None or not resolved.is_file():
        return None
    return resolved


def _stable_parent_id(collection: str, parent: Mapping[str, Any]) -> tuple[str, str] | None:
    if collection == "leads":
        category, value = parent.get("category"), parent.get("value")
        if not isinstance(category, str) or not category or not isinstance(value, str) or not value:
            return None
        identity = [category, value]
        display = value
    elif collection == "endpoints":
        kind, value = parent.get("kind"), parent.get("value")
        if not isinstance(kind, str) or not kind or not isinstance(value, str) or not value:
            return None
        identity = [kind, value]
        display = value
    else:
        rule_id = parent.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            return None
        # One rule may emit one finding per concrete component.  The rule id
        # alone is therefore not a parent identity; include stable finding
        # content so every emitted Finding remains independently reviewable.
        identity = [rule_id, parent.get("title"), parent.get("description")]
        display = str(parent.get("title") or rule_id)
    raw = json.dumps(identity, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return f"{collection[:-1]}:{sha256_hex(raw)}", display


def candidate_id(
    package_id: str,
    collection: str,
    parent_id: str,
    evidence_id: str,
    scope: str,
) -> str:
    material = "\0".join(("1", package_id, collection, parent_id, evidence_id, scope))
    return "p1:" + sha256_hex(material.encode("utf-8"))


def _evidence_field(collection: str, parent: Mapping[str, Any]) -> tuple[str, Any] | None:
    """定位父对象上已经声明的证据列表字段。

    与 :func:`apkscan.core.models.has_case_evidence` 回答的不是同一个问题。那个函数接收
    类型化的 ``list[Evidence]``，看其中有没有 ``scope is CASE_EVIDENCE``。本函数只看原始
    dict：leads 认 ``source_refs``，endpoints 认 ``evidences``，findings 两套字段都在且值
    不同则返回 ``conflicting_aliases``。缺键表示未声明；空列表表示已声明且没有证据，后面
    仍会生成 parent 候选。``evidence_scope.serialized_has_case_evidence`` 同样只看作用域里
    有没有本案直接证据，不看字段有没有被声明。
    """
    if collection == "leads":
        return ("source_refs", parent.get("source_refs")) if "source_refs" in parent else None
    if collection == "endpoints":
        return ("evidences", parent.get("evidences")) if "evidences" in parent else None
    has_evidences = "evidences" in parent
    has_refs = "source_refs" in parent
    if has_evidences and has_refs and parent.get("evidences") != parent.get("source_refs"):
        return "conflicting_aliases", None
    if has_evidences:
        return "evidences", parent.get("evidences")
    if has_refs:
        return "source_refs", parent.get("source_refs")
    return None


def _append_candidate(
    inv: Phase1EvidenceInventory,
    limits: InventoryLimits,
    candidate: ReviewCandidate,
    location: str,
) -> bool:
    if len(inv.candidates) >= limits.max_total_candidates:
        if not any(i.code == "resource_limit_exceeded" for i in inv.issues):
            inv.issues.append(_issue(
                "resource_limit_exceeded",
                location,
                f"candidate count exceeds {limits.max_total_candidates}",
                "raise the reviewed limit deliberately or split the case package",
            ))
        return False
    inv.candidates.append(candidate)
    return True


def _collect_report_candidates(
    inv: Phase1EvidenceInventory,
    package_id: str,
    manifest_sha256: str,
    report: Mapping[str, Any],
    report_relpath: str,
    location: str,
    limits: InventoryLimits,
) -> None:
    seen_parent: set[tuple[str, str]] = set()
    seen_evidence: set[tuple[str, str, str, str]] = set()
    for collection in COLLECTIONS:
        if collection not in report:
            inv.issues.append(_issue(
                "missing_required_collection", location, f"missing {collection}",
                "regenerate the Phase1 report with all required collections",
            ))
            continue
        parents = report[collection]
        if not isinstance(parents, list):
            inv.issues.append(_issue(
                "wrong_collection_shape", location, f"{collection} is not a list",
                "repair or regenerate the immutable Phase1 package",
            ))
            continue
        if len(parents) > limits.max_collection_items:
            inv.issues.append(_issue(
                "resource_limit_exceeded", location,
                f"{collection} count exceeds {limits.max_collection_items}",
                "raise the reviewed limit deliberately or split the package",
            ))
            continue
        for index, parent in enumerate(parents):
            item_location = f"{location}:{collection}[{index}]"
            if not isinstance(parent, dict):
                inv.issues.append(_issue(
                    "wrong_parent_shape", item_location, "parent is not an object",
                    "regenerate the Phase1 report",
                ))
                continue
            identity = _stable_parent_id(collection, parent)
            if identity is None:
                inv.issues.append(_issue(
                    "missing_parent_identity", item_location,
                    "parent lacks its collection-specific stable identity fields",
                    "regenerate the report with category/value, kind/value, or finding id",
                ))
                continue
            parent_id, display = identity
            parent_key = (collection, parent_id)
            if parent_key in seen_parent:
                inv.issues.append(_issue(
                    "duplicate_parent_id", item_location, f"duplicate {parent_id}",
                    "deduplicate the Phase1 parent objects before review",
                ))
                continue
            seen_parent.add(parent_key)
            evidence_field = _evidence_field(collection, parent)
            if evidence_field is None:
                inv.issues.append(_issue(
                    "missing_evidence_field", item_location,
                    "parent has no declared evidence list",
                    "regenerate the Phase1 report; an absent list is not an empty list",
                ))
                continue
            field_name, evidences = evidence_field
            if field_name == "conflicting_aliases":
                inv.issues.append(_issue(
                    "conflicting_evidence_aliases", item_location,
                    "finding has different evidences and source_refs",
                    "regenerate the report with one canonical evidence list",
                ))
                continue
            if not isinstance(evidences, list):
                inv.issues.append(_issue(
                    "wrong_evidence_shape", item_location,
                    f"{field_name} is not a list",
                    "regenerate the Phase1 report",
                ))
                continue
            if len(evidences) > limits.max_evidence_items_per_parent:
                inv.issues.append(_issue(
                    "resource_limit_exceeded", item_location,
                    f"evidence count exceeds {limits.max_evidence_items_per_parent}",
                    "raise the reviewed limit deliberately or reduce duplicate evidence",
                ))
                continue
            if not evidences:
                _append_candidate(inv, limits, ReviewCandidate(
                    candidate_id(package_id, collection, parent_id, _PARENT_SENTINEL, _PARENT_SCOPE),
                    package_id, collection, parent_id, _PARENT_SENTINEL, _PARENT_SCOPE,
                    False, manifest_sha256, report_relpath, display_value=display,
                ), item_location)
                continue
            for evidence_index, evidence in enumerate(evidences):
                evidence_location = f"{item_location}:{field_name}[{evidence_index}]"
                if not isinstance(evidence, dict):
                    inv.issues.append(_issue(
                        "wrong_evidence_shape", evidence_location,
                        "evidence is not an object", "regenerate the Phase1 report",
                    ))
                    continue
                evidence_id = evidence.get("evidence_id")
                scope = evidence.get("scope", "legacy_unspecified")
                if not isinstance(evidence_id, str) or not evidence_id:
                    inv.issues.append(_issue(
                        "missing_evidence_id", evidence_location,
                        "evidence_id is missing", "regenerate the Phase1 evidence identity",
                    ))
                    continue
                if not isinstance(scope, str) or not scope:
                    inv.issues.append(_issue(
                        "missing_evidence_scope", evidence_location,
                        "scope is missing or invalid", "regenerate the Phase1 evidence scope",
                    ))
                    continue
                if evidence_id == _PARENT_SENTINEL or scope == _PARENT_SCOPE:
                    inv.issues.append(_issue(
                        "reserved_evidence_identity", evidence_location,
                        "real evidence uses a reserved parent sentinel",
                        "regenerate the Phase1 evidence identity",
                    ))
                    continue
                evidence_key = (collection, parent_id, evidence_id, scope)
                if evidence_key in seen_evidence:
                    # evidence_id+scope is the public evidence identity.  A
                    # merged report may preserve several coordinates/snippets
                    # for that same observation; Phase2 reviews it once.
                    continue
                seen_evidence.add(evidence_key)
                _append_candidate(inv, limits, ReviewCandidate(
                    candidate_id(package_id, collection, parent_id, evidence_id, scope),
                    package_id, collection, parent_id, evidence_id, scope,
                    True, manifest_sha256, report_relpath, display_value=display,
                ), evidence_location)


def _inventory_fingerprint(inv: Phase1EvidenceInventory) -> str:
    material = {
        "schema_version": inv.schema_version,
        "case_id": inv.case_id,
        "packages": [
            {"package_id": p.package_id, "manifest_sha256": p.manifest_sha256,
             "report_sha256": p.report_sha256}
            for p in inv.packages
        ],
        "candidates": [c.provenance_dict() for c in inv.candidates],
        "issues": [(i.code, i.location, i.detail) for i in inv.issues],
    }
    blob = json.dumps(
        material, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return sha256_hex(blob)


def _verify_and_read_case_id(
    manifest_path: Path, manifest: Mapping[str, Any], location: str
) -> tuple[str | None, list[InventoryIssue]]:
    """Delegate integrity to the public Phase1 verifier; return the manifest case_id."""
    from apkscan.core.case_package import verify_case_package

    checked = verify_case_package(manifest_path)
    if checked.get("status") != "verified":
        raw_issues = checked.get("issues")
        count = len(raw_issues) if isinstance(raw_issues, list) else 0
        return None, [_issue(
            "package_integrity_failed", location,
            f"public verifier rejected the package ({count} issue(s))",
            "run `fxapk case status <case-package.json>` and regenerate the package",
        )]
    if checked.get("package_id") != manifest.get("package_id"):
        return None, [_issue(
            "manifest_snapshot_mismatch", location, "verified manifest differs from the loaded snapshot",
            "retry from a stable immutable package",
        )]
    value = manifest.get("case_id")
    return (value if isinstance(value, str) and value else None), []


def _resolve_case_id(
    inv: Phase1EvidenceInventory,
    explicit: str | None,
    manifest_case_ids: Mapping[str, str],
    *,
    strict: bool,
    fallback: str,
) -> None:
    """case_id 只来自显式参数或 manifest；二者冲突或缺失均 fail-closed，绝不从目录名猜。"""
    observed = sorted(set(manifest_case_ids.values()))
    if len(observed) > 1:
        inv.issues.append(_issue(
            "case_id_conflict", "manifests",
            f"{len(observed)} distinct case_id values across packages",
            "split packages from different cases into separate case directories",
        ))
    if explicit is not None:
        from apkscan.core.case_identity import normalize_case_id

        try:
            normalized = normalize_case_id(explicit)
        except ValueError as exc:
            inv.issues.append(_issue(
                "case_id_invalid", "arguments", str(exc), "pass a valid --case-id",
            ))
            return
        inv.case_id = normalized
        for location, value in sorted(manifest_case_ids.items()):
            if value != normalized:
                inv.issues.append(_issue(
                    "case_id_mismatch", location,
                    "manifest case_id differs from the requested case_id",
                    "check --case-id or move the package to its own case directory",
                ))
        return
    if len(observed) == 1:
        inv.case_id = observed[0]
        return
    if strict:
        if inv.packages:
            inv.issues.append(_issue(
                "case_id_missing", "manifests",
                "no case_id could be established from manifests",
                "pass --case-id explicitly; directory names are never used as case identity",
            ))
        inv.case_id = ""
        return
    inv.case_id = fallback


def build_inventory(
    case_dir: Path,
    limits: InventoryLimits | None = None,
    *,
    package_manifests: list[Path] | None = None,
    case_id: str | None = None,
    verify_packages: bool = True,
) -> Phase1EvidenceInventory:
    """只读枚举一个案件目录内全部 Phase1 包；任何坏形状都进入 blocking issues。

    ``verify_packages=True``（默认、CLI 唯一路径）时每个包必须先通过公开
    ``verify_case_package``（package_id、附件哈希、报告身份），且 case_id 只取自显式参数
    或 manifest。``False`` 仅供针对候选枚举逻辑的单元测试使用合成夹具。
    """
    limits = limits or InventoryLimits()
    root = Path(case_dir)
    inv = Phase1EvidenceInventory(case_id=case_id or "")
    manifest_case_ids: dict[str, str] = {}
    if not root.is_dir():
        inv.issues.append(_issue(
            "case_dir_missing", str(root), "case directory does not exist",
            "select an existing Phase2 case directory",
        ))
        if not verify_packages and not case_id:
            inv.case_id = root.name
        inv.fingerprint = _inventory_fingerprint(inv)
        return inv
    if package_manifests is None:
        children = sorted((child for child in root.iterdir() if child.is_dir()), key=lambda p: p.name)
        manifests = [child / "case-package.json" for child in children]
    else:
        manifests = sorted({Path(p).resolve() for p in package_manifests})
        children = [p.parent for p in manifests]
    if len(children) > limits.max_package_directories:
        inv.issues.append(_issue(
            "resource_limit_exceeded", str(root),
            f"package directory count exceeds {limits.max_package_directories}",
            "raise the reviewed limit deliberately or split the case",
        ))
        children = children[: limits.max_package_directories]
    seen_packages: set[str] = set()
    for manifest_path in manifests[:limits.max_package_directories]:
        child = manifest_path.parent
        legacy_report_path = child / "report.json"
        has_manifest = manifest_path.is_file()
        if not (has_manifest or legacy_report_path.is_file()):
            continue
        if child.is_symlink() or not has_manifest:
            inv.issues.append(_issue(
                "missing_pair_file", child.name,
                "package requires case-package.json and one registered report artifact",
                "complete or remove the partial package before review",
            ))
            continue
        try:
            manifest, manifest_raw = _read_json_bounded(
                manifest_path, limits.max_manifest_bytes, limits.max_json_depth
            )
            if not isinstance(manifest, dict):
                raise ValueError("manifest must be a JSON object")
            report_path = _registered_report_path(child, manifest)
            if report_path is None:
                inv.issues.append(_issue(
                    "missing_pair_file", child.name,
                    "package requires exactly one readable registered report artifact",
                    "regenerate the immutable Phase1 package",
                ))
                continue
            report, report_raw = _read_json_bounded(
                report_path, limits.max_report_bytes, limits.max_json_depth
            )
        except OverflowError as exc:
            inv.issues.append(_issue(
                "resource_limit_exceeded", child.name, str(exc),
                "raise the reviewed limit deliberately or regenerate a bounded package",
            ))
            continue
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            inv.issues.append(_issue(
                "invalid_json", child.name, str(exc),
                "regenerate the immutable Phase1 package",
            ))
            continue
        if not isinstance(report, dict):
            inv.issues.append(_issue(
                "wrong_top_level_shape", child.name,
                "manifest and report must both be JSON objects",
                "regenerate the immutable Phase1 package",
            ))
            continue
        package_id = manifest.get("package_id")
        if not isinstance(package_id, str) or not package_id:
            inv.issues.append(_issue(
                "missing_package_id", child.name, "package_id is missing",
                "regenerate case-package.json",
            ))
            continue
        if package_id in seen_packages:
            inv.issues.append(_issue(
                "duplicate_package_id", child.name, f"duplicate package_id {package_id}",
                "resolve duplicate immutable packages before review",
            ))
            continue
        if verify_packages:
            manifest_case_id, verify_issues = _verify_and_read_case_id(
                manifest_path, manifest, child.name
            )
            if verify_issues:
                inv.issues.extend(verify_issues)
                continue
            report_artifacts = [item for item in manifest.get("artifacts", [])
                                if isinstance(item, Mapping) and item.get("kind") == "report"]
            if len(report_artifacts) != 1 or report_artifacts[0].get("sha256") != sha256_hex(report_raw):
                inv.issues.append(_issue(
                    "report_snapshot_hash_mismatch", child.name,
                    "loaded report bytes do not match the verified manifest",
                    "retry from a stable immutable package",
                ))
                continue
            if manifest_case_id is not None:
                manifest_case_ids[child.name] = manifest_case_id
        seen_packages.add(package_id)
        manifest_sha = sha256_hex(manifest_raw)
        package = Phase1Package(
            package_id, child.name, manifest_sha, sha256_hex(report_raw)
        )
        inv.packages.append(package)
        _collect_report_candidates(
            inv, package_id, manifest_sha, report,
            report_path.relative_to(child.resolve()).as_posix(), child.name, limits
        )
    _resolve_case_id(
        inv, case_id, manifest_case_ids, strict=verify_packages, fallback=case_id or root.name
    )
    inv.packages.sort(key=lambda p: (p.package_id, p.directory_name))
    inv.candidates.sort(key=lambda c: (
        c.package_id, c.collection, c.parent_id, c.evidence_id, c.scope, c.candidate_id,
    ))
    inv.issues.sort(key=lambda i: (i.code, i.location, i.detail))
    inv.fingerprint = _inventory_fingerprint(inv)
    return inv


def _provenance_matches(candidate: ReviewCandidate, provenance: Mapping[str, Any]) -> bool:
    expected = candidate.provenance_dict()
    return all(provenance.get(key) == value for key, value in expected.items())


def _resolve_clue_candidate(
    clue: Mapping[str, Any],
    candidates: Mapping[str, ReviewCandidate],
    blockers: list[CoverageIssue],
) -> ReviewCandidate | None:
    clue_id = str(clue.get("clue_id") or "")
    provenance = clue.get("phase1_provenance")
    if not isinstance(provenance, dict):
        blockers.append(_coverage_issue(
            "missing_phase1_provenance", "Phase1 clue has no provenance object",
            "regenerate the clue provenance from the immutable package",
            clue_id=clue_id,
        ))
        return None
    raw_candidate_id = provenance.get("candidate_id")
    if isinstance(raw_candidate_id, str) and raw_candidate_id:
        candidate = candidates.get(raw_candidate_id)
        if candidate is None:
            blockers.append(_coverage_issue(
                "unknown_clue_candidate", "clue points to an unknown candidate",
                "rebuild inventory and regenerate the clue provenance",
                candidate_id=raw_candidate_id, clue_id=clue_id,
            ))
            return None
        if not _provenance_matches(candidate, provenance):
            blockers.append(_coverage_issue(
                "provenance_mismatch", "expanded clue provenance contradicts candidate",
                "regenerate provenance from the selected candidate",
                candidate_id=candidate.candidate_id, clue_id=clue_id,
            ))
            return None
        return candidate

    evidence_id = provenance.get("evidence_id")
    manifest_sha = provenance.get("manifest_sha256")
    report_relpath = provenance.get("report_relpath")
    if not all(isinstance(value, str) and value for value in (
        evidence_id, manifest_sha, report_relpath
    )):
        blockers.append(_coverage_issue(
            "malformed_legacy_provenance", "legacy provenance lacks required fields",
            "regenerate the clue with candidate_id provenance", clue_id=clue_id,
        ))
        return None
    matches = [
        candidate for candidate in candidates.values()
        if candidate.evidence_id == evidence_id
        and candidate.manifest_sha256 == manifest_sha
        and candidate.report_relpath == report_relpath
    ]
    clue_value = clue.get("clue_value")
    if len(matches) > 1 and isinstance(clue_value, str) and clue_value:
        value_matches = [c for c in matches if c.display_value == clue_value]
        if value_matches:
            matches = value_matches
        lead_matches = [c for c in matches if c.collection == "leads"]
        if len(lead_matches) == 1:
            matches = lead_matches
    if len(matches) != 1:
        blockers.append(_coverage_issue(
            "ambiguous_legacy_provenance",
            f"legacy evidence maps to {len(matches)} candidates",
            "select the exact parent and rewrite provenance with candidate_id",
            clue_id=clue_id,
        ))
        return None
    return matches[0]


def audit_coverage(
    inventory: Phase1EvidenceInventory,
    snapshot: Mapping[str, Any] | object,
    clue_records: Sequence[Mapping[str, Any]] | object,
) -> CoverageAudit:
    """校验覆盖快照与线索 JSONL 的双向映射；不修数据、不做 latest-wins。"""
    audit = CoverageAudit(candidate_count=len(inventory.candidates))
    for issue in inventory.issues:
        audit.blockers.append(_coverage_issue(
            f"inventory_{issue.code}", issue.detail, issue.next_action
        ))
    candidates = {c.candidate_id: c for c in inventory.candidates}
    if not isinstance(snapshot, Mapping):
        audit.blockers.append(_coverage_issue(
            "invalid_coverage_snapshot", "coverage snapshot is not an object",
            "create a schema-versioned coverage snapshot",
        ))
        return audit
    if snapshot.get("schema_version") != SCHEMA_VERSION:
        audit.blockers.append(_coverage_issue(
            "coverage_schema_version", "unsupported coverage schema version",
            "regenerate the snapshot with the current workflow",
        ))
    if snapshot.get("case_id") != inventory.case_id:
        audit.blockers.append(_coverage_issue(
            "coverage_case_mismatch", "coverage case_id does not match inventory",
            "select the matching case coverage snapshot",
        ))
    supplied_fingerprint = snapshot.get("inventory_fingerprint")
    if supplied_fingerprint not in (None, "", inventory.fingerprint):
        audit.blockers.append(_coverage_issue(
            "inventory_fingerprint_mismatch", "coverage was built from another inventory",
            "rebuild coverage from the current immutable Phase1 packages",
        ))
    entries = snapshot.get("entries")
    if not isinstance(entries, list):
        audit.blockers.append(_coverage_issue(
            "invalid_coverage_entries", "coverage entries is not a list",
            "regenerate the coverage snapshot",
        ))
        entries = []

    entries_by_candidate: dict[str, Mapping[str, Any]] = {}
    accepted_by_clue: dict[str, list[str]] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            audit.blockers.append(_coverage_issue(
                "invalid_coverage_entry", f"entry {index} is not an object",
                "regenerate the coverage snapshot",
            ))
            continue
        raw_candidate_id = entry.get("candidate_id")
        if not isinstance(raw_candidate_id, str) or not raw_candidate_id:
            audit.blockers.append(_coverage_issue(
                "missing_candidate_id", f"entry {index} has no candidate_id",
                "select a candidate from the current inventory",
            ))
            continue
        if raw_candidate_id in entries_by_candidate:
            audit.blockers.append(_coverage_issue(
                "duplicate_disposition", "candidate has multiple dispositions",
                "keep exactly one materialized disposition; do not use latest-wins",
                candidate_id=raw_candidate_id,
            ))
            continue
        entries_by_candidate[raw_candidate_id] = entry
        candidate = candidates.get(raw_candidate_id)
        if candidate is None:
            audit.blockers.append(_coverage_issue(
                "unknown_candidate", "coverage references a stale/unknown candidate",
                "remove stale entry and review the current inventory",
                candidate_id=raw_candidate_id,
            ))
            continue
        disposition = entry.get("disposition")
        if disposition not in DISPOSITIONS:
            audit.blockers.append(_coverage_issue(
                "invalid_disposition", f"unsupported disposition {disposition!r}",
                "choose one allowed disposition", candidate_id=raw_candidate_id,
            ))
            continue
        audit.disposition_counts[disposition] = audit.disposition_counts.get(disposition, 0) + 1
        if disposition == "accepted_clue":
            clue_id = entry.get("clue_id")
            provenance = entry.get("provenance")
            if not isinstance(clue_id, str) or not clue_id:
                audit.blockers.append(_coverage_issue(
                    "missing_clue_id", "accepted candidate has no clue_id",
                    "link exactly one clue row", candidate_id=raw_candidate_id,
                ))
            else:
                accepted_by_clue.setdefault(clue_id, []).append(raw_candidate_id)
            if not isinstance(provenance, Mapping) or not _provenance_matches(candidate, provenance):
                audit.blockers.append(_coverage_issue(
                    "coverage_provenance_mismatch",
                    "accepted coverage provenance does not exactly match inventory",
                    "regenerate provenance from the selected candidate",
                    candidate_id=raw_candidate_id,
                    clue_id=clue_id if isinstance(clue_id, str) else "",
                ))
        else:
            reason = entry.get("reason")
            if not isinstance(reason, str) or not reason.strip():
                audit.blockers.append(_coverage_issue(
                    "missing_reason", "non-accepted disposition has no reason",
                    "record the review rationale", candidate_id=raw_candidate_id,
                ))
            if disposition == "pending_with_action":
                action = entry.get("next_action")
                if not isinstance(action, str) or not action.strip():
                    audit.blockers.append(_coverage_issue(
                        "missing_next_action", "pending disposition has no next action",
                        "record the concrete evidence/review action",
                        candidate_id=raw_candidate_id,
                    ))

    for candidate_id_value in sorted(candidates):
        if candidate_id_value not in entries_by_candidate:
            audit.blockers.append(_coverage_issue(
                "missing_disposition", "Phase1 candidate has no Phase2 disposition",
                "review this candidate and record exactly one disposition",
                candidate_id=candidate_id_value,
            ))
    audit.covered_count = sum(1 for cid in candidates if cid in entries_by_candidate)
    for clue_id, mapped in sorted(accepted_by_clue.items()):
        if len(mapped) > 1:
            audit.blockers.append(_coverage_issue(
                "duplicate_accepted_mapping", "one clue accepts multiple candidates",
                "split the clue rows or add an explicit merged-clue contract",
                clue_id=clue_id,
            ))

    if not isinstance(clue_records, Sequence) or isinstance(clue_records, (str, bytes)):
        audit.blockers.append(_coverage_issue(
            "invalid_clue_records", "clue records is not a sequence",
            "load the bounded clue JSONL before audit",
        ))
        clue_records = []
    clues_by_id: dict[str, Mapping[str, Any]] = {}
    clue_candidates: dict[str, str] = {}
    for clue in clue_records:
        if not isinstance(clue, Mapping):
            audit.blockers.append(_coverage_issue(
                "invalid_clue_record", "clue record is not an object",
                "repair the clue JSONL before release",
            ))
            continue
        if clue.get("case_id") != inventory.case_id:
            continue
        clue_id = clue.get("clue_id")
        if not isinstance(clue_id, str) or not clue_id:
            audit.blockers.append(_coverage_issue(
                "missing_clue_record_id", "clue row has no clue_id",
                "assign a stable clue_id",
            ))
            continue
        if clue_id in clues_by_id:
            audit.blockers.append(_coverage_issue(
                "duplicate_clue_id", "clue_id is duplicated",
                "retire or renumber the duplicate row", clue_id=clue_id,
            ))
            continue
        clues_by_id[clue_id] = clue
        if clue.get("origin") != "phase1":
            continue
        resolved = _resolve_clue_candidate(clue, candidates, audit.blockers)
        if resolved is not None:
            clue_candidates[clue_id] = resolved.candidate_id

    accepted_count = 0
    for clue_id, mapped in sorted(accepted_by_clue.items()):
        if len(mapped) != 1:
            continue
        candidate_id_value = mapped[0]
        clue = clues_by_id.get(clue_id)
        if clue is None:
            audit.blockers.append(_coverage_issue(
                "missing_clue_record", "accepted clue_id does not exist",
                "create the linked clue row or change the disposition",
                candidate_id=candidate_id_value, clue_id=clue_id,
            ))
            continue
        if clue.get("origin") != "phase1" or clue_candidates.get(clue_id) != candidate_id_value:
            audit.blockers.append(_coverage_issue(
                "provenance_mismatch", "coverage and clue provenance do not agree",
                "regenerate both sides from the same candidate",
                candidate_id=candidate_id_value, clue_id=clue_id,
            ))
            continue
        accepted_count += 1
    audit.accepted_clue_count = accepted_count

    for clue_id, candidate_id_value in sorted(clue_candidates.items()):
        entry = entries_by_candidate.get(candidate_id_value)
        if (
            not isinstance(entry, Mapping)
            or entry.get("disposition") != "accepted_clue"
            or entry.get("clue_id") != clue_id
        ):
            audit.blockers.append(_coverage_issue(
                "clue_not_accepted", "Phase1 clue points to a candidate not accepted by coverage",
                "make the coverage disposition and clue link agree",
                candidate_id=candidate_id_value, clue_id=clue_id,
            ))
    return audit


def load_clue_records(path: Path, *, max_bytes: int = 64 * 1024 * 1024) -> list[dict[str, Any]]:
    """有界读取 JSONL；坏行直接抛错，由 CLI/release gate 转成阻断。"""
    file = Path(path)
    if file.is_symlink() or file.stat().st_size > max_bytes:
        raise ValueError("clue JSONL is unsafe or exceeds the resource limit")
    with file.open("rb") as stream:
        raw = read_limited(stream, max_bytes)
    if len(raw) > max_bytes:
        raise ValueError("clue JSONL exceeds the resource limit while reading")
    out: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        item = json.loads(line, parse_constant=reject_nonfinite_json_constant,
                          parse_float=parse_finite_json_float)
        if not isinstance(item, dict):
            raise ValueError(f"clue line {line_number} is not an object")
        if _json_depth(item) > 64:
            raise ValueError(f"clue line {line_number} exceeds the depth limit")
        out.append(item)
    return out


def load_coverage_snapshot(
    path: Path, *, max_bytes: int = 64 * 1024 * 1024
) -> dict[str, Any]:
    """有界读取覆盖快照；不接受符号链接、超限文件或非对象顶层。"""
    payload, _raw = _read_json_bounded(Path(path), max_bytes, 64)
    if not isinstance(payload, dict):
        raise ValueError("coverage snapshot is not an object")
    return payload


def build_coverage_skeleton(inventory: Phase1EvidenceInventory) -> dict[str, Any]:
    """为每个候选建立显式待处理项；它是工作队列，不是假装已经审核完成。"""
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": inventory.case_id,
        "inventory_fingerprint": inventory.fingerprint,
        "entries": [
            {
                "candidate_id": candidate.candidate_id,
                "disposition": "pending_with_action",
                "reason": "尚未完成人工审核",
                "next_action": "核对 Phase1 原始证据并选择最终处置",
                "display": {
                    "collection": candidate.collection,
                    "value": candidate.display_value,
                    "evidence_id": candidate.evidence_id,
                },
            }
            for candidate in inventory.candidates
        ],
    }
