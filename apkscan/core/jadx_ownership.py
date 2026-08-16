"""把 JADX 结构索引 diff 投影为代码区域 ownership 标注（P1-D）。

★缺官方 baseline 时一切保持 UNKNOWN；与 baseline 不同只说明观察差异，绝不
自动标 suspect——反编译噪声、工具版本差异都能造成 digest 漂移，升格是人的
判断，不进工具。本模块任何路径都不产出 SUSPECT_FIRST_PARTY /
INHERITED_THIRD_PARTY / SHARED_INFRASTRUCTURE。
"""

from __future__ import annotations

from dataclasses import dataclass

from apkscan.core.jadx_index import LoadedIndex
from apkscan.core.jadx_structure_diff import (
    MethodRegion,
    _read_structure,
    diff_index_structure,
)
from apkscan.core.recognition_contract import OwnershipValue


@dataclass(frozen=True, slots=True)
class RegionOwnership:
    region: MethodRegion
    ownership: OwnershipValue
    reason: str


@dataclass(frozen=True, slots=True)
class OwnershipProjection:
    subject_index_key: str
    baseline_index_key: str | None
    regions: tuple[RegionOwnership, ...]
    subject_coverage: str
    baseline_coverage: str | None
    absence_claimable: bool


def _region_sort_key(item: RegionOwnership) -> tuple[object, ...]:
    region = item.region
    return (
        region.class_name,
        region.method,
        region.path,
        region.start_line,
        region.end_line,
        region.body_digest,
    )


def _regions_by_identity(
    structures: dict[str, tuple[str, list[MethodRegion]]],
) -> dict[tuple[str, str], list[MethodRegion]]:
    """按方法身份 (class_name, "name/arity") 分组该身份的全部声明。"""
    grouped: dict[tuple[str, str], list[MethodRegion]] = {}
    for class_name, (_, regions) in structures.items():
        for region in regions:
            grouped.setdefault((class_name, region.method), []).append(region)
    return grouped


def project_ownership(
    subject: LoadedIndex, baseline: LoadedIndex | None
) -> OwnershipProjection:
    """将 subject 侧全部方法区域按官方 baseline 的结构事实分类。

    baseline 的「official」身份由调用方断言；两侧 manifest digest 经 ledger
    anchors 可追溯。removed（baseline 有而 subject 无）不产 region——本投影
    只标注 subject 侧的区域。
    """
    subject_structures = _read_structure(subject)
    subject_by_identity = _regions_by_identity(subject_structures)

    if baseline is None:
        regions = tuple(
            RegionOwnership(
                region=region,
                ownership=OwnershipValue.UNKNOWN,
                reason="no_official_baseline",
            )
            for identity in sorted(subject_by_identity)
            for region in subject_by_identity[identity]
        )
        return OwnershipProjection(
            subject_index_key=subject.manifest.index_key,
            baseline_index_key=None,
            regions=tuple(sorted(regions, key=_region_sort_key)),
            subject_coverage=subject.coverage,
            baseline_coverage=None,
            absence_claimable=False,
        )

    # 复用 P1-C 的完整 diff 路径：两侧结构在此都经过同一套 fail-closed 校验。
    diff_index_structure(baseline, subject)
    baseline_by_identity = _regions_by_identity(_read_structure(baseline))
    both_complete = subject.coverage == "complete" and baseline.coverage == "complete"

    projected: list[RegionOwnership] = []
    for identity, subject_regions in subject_by_identity.items():
        baseline_regions = baseline_by_identity.get(identity)
        if baseline_regions is None:
            ownership = OwnershipValue.UNKNOWN
            # ★absent 仍是 UNKNOWN：baseline 选错版本会整批误标；partial 时
            #   连「baseline 里没有」都说不出口，归因到覆盖缺口。
            reason = "absent_from_baseline" if both_complete else "baseline_coverage_partial"
        else:
            subject_digests = sorted(item.body_digest for item in subject_regions)
            baseline_digests = sorted(item.body_digest for item in baseline_regions)
            if subject_digests == baseline_digests:
                ownership = OwnershipValue.INHERITED_OFFICIAL
                reason = "matches_official_baseline"
            else:
                ownership = OwnershipValue.UNKNOWN
                reason = "modified_relative_to_baseline"
        for region in subject_regions:
            projected.append(
                RegionOwnership(region=region, ownership=ownership, reason=reason)
            )

    return OwnershipProjection(
        subject_index_key=subject.manifest.index_key,
        baseline_index_key=baseline.manifest.index_key,
        regions=tuple(sorted(projected, key=_region_sort_key)),
        subject_coverage=subject.coverage,
        baseline_coverage=baseline.coverage,
        absence_claimable=both_complete,
    )


__all__ = [
    "OwnershipProjection",
    "RegionOwnership",
    "project_ownership",
]
