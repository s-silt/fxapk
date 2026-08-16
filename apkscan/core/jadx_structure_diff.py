"""两个 JADX 结构索引之间的确定性结构与代码区域 diff（P1-C）。"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import NoReturn

from apkscan.core.jadx_index import (
    REASON_MALFORMED,
    JadxIndexError,
    LoadedIndex,
    _normalize_safe_relative_path,
    _validate_digest,
    _validate_shard_structure,
)


def _malformed(path: str) -> NoReturn:
    raise JadxIndexError(REASON_MALFORMED, path)


@dataclass(frozen=True, slots=True)
class MethodRegion:
    class_name: str
    method: str
    path: str
    start_line: int
    end_line: int
    body_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.class_name, str) or not self.class_name:
            _malformed("$.class_name")
        if not isinstance(self.method, str) or not self.method:
            _malformed("$.method")
        _normalize_safe_relative_path(self.path, "$.path")
        if (
            isinstance(self.start_line, bool)
            or not isinstance(self.start_line, int)
            or self.start_line < 1
        ):
            _malformed("$.start_line")
        if (
            isinstance(self.end_line, bool)
            or not isinstance(self.end_line, int)
            or self.end_line < self.start_line
        ):
            _malformed("$.end_line")
        _validate_digest(self.body_digest, "$.body_digest")


@dataclass(frozen=True, slots=True)
class ChangedMethod:
    class_name: str
    path: str
    method: str
    left_regions: tuple[MethodRegion, ...]
    right_regions: tuple[MethodRegion, ...]


@dataclass(frozen=True, slots=True)
class StructuralDiff:
    #: 类身份是 (class_name, path)——schema 1.2 起同名不同路径是独立身份。
    added_classes: tuple[tuple[str, str], ...]
    removed_classes: tuple[tuple[str, str], ...]
    added_methods: tuple[MethodRegion, ...]
    removed_methods: tuple[MethodRegion, ...]
    changed_methods: tuple[ChangedMethod, ...]
    unchanged_methods: int
    left_coverage: str
    right_coverage: str
    absence_claimable: bool


def _validate_call(call: object, path: str) -> None:
    if not isinstance(call, Mapping) or set(call) != {"callee", "line"}:
        _malformed(path)
    callee = call["callee"]
    line = call["line"]
    if (
        not isinstance(callee, str)
        or isinstance(line, bool)
        or not isinstance(line, int)
        or line < 1
    ):
        _malformed(path)


def _read_structure(
    index: LoadedIndex,
) -> dict[tuple[str, str], list[MethodRegion]]:
    """聚合结构；类身份为 (class_name, path)。

    跨 shard 的同 (name, path) 是多 dex 脱壳 dump 重复类的常态——合并其方法
    区域（digest 多重集随之翻倍，比对侧保守得 changed，绝不误判 match）；
    同一 shard 内的精确重复由 _validate_shard_structure fail-closed 拦截。"""
    if not isinstance(index, LoadedIndex):
        _malformed("$")
    if index.coverage not in ("complete", "partial"):
        _malformed("$.coverage")
    if not isinstance(index.shards, tuple):
        _malformed("$.shards")

    classes: dict[tuple[str, str], list[MethodRegion]] = {}

    for shard_index, shard in enumerate(index.shards):
        shard_path = f"$.shards[{shard_index}]"
        if not isinstance(shard, Mapping):
            _malformed(shard_path)

        # ★与 load 侧共用同一套完整校验（排序/重复三元组/标识符/path∈files）——
        # 单一来源杜绝两套规则漂移；伪造 LoadedIndex 在此 fail-closed。
        files_raw = shard.get("files")
        if not isinstance(files_raw, list) or any(
            not isinstance(item, str) for item in files_raw
        ):
            _malformed(f"{shard_path}.files")
        _validate_shard_structure(shard, set(files_raw))

        structure = shard.get("structure")
        if not isinstance(structure, Mapping) or set(structure) != {"classes"}:
            _malformed(f"{shard_path}.structure")

        raw_classes = structure["classes"]
        if not isinstance(raw_classes, list):
            _malformed(f"{shard_path}.structure.classes")

        for class_index, raw_class in enumerate(raw_classes):
            class_path = f"{shard_path}.structure.classes[{class_index}]"
            if (
                not isinstance(raw_class, Mapping)
                or set(raw_class) != {"name", "path", "methods"}
            ):
                _malformed(class_path)

            class_name = raw_class["name"]
            relative_path = raw_class["path"]
            raw_methods = raw_class["methods"]
            if (
                not isinstance(class_name, str)
                or not class_name
                or not isinstance(relative_path, str)
                or not isinstance(raw_methods, list)
            ):
                _malformed(class_path)

            try:
                normalized_path = _normalize_safe_relative_path(
                    relative_path, f"{class_path}.path"
                )
            except JadxIndexError:
                _malformed(f"{class_path}.path")

            identity = (class_name, normalized_path)
            regions = classes.setdefault(identity, [])
            for method_index, raw_method in enumerate(raw_methods):
                method_path = f"{class_path}.methods[{method_index}]"
                required = {
                    "name",
                    "arity",
                    "start_line",
                    "end_line",
                    "body_digest",
                    "calls",
                }
                if not isinstance(raw_method, Mapping) or set(raw_method) != required:
                    _malformed(method_path)

                name = raw_method["name"]
                arity = raw_method["arity"]
                start_line = raw_method["start_line"]
                end_line = raw_method["end_line"]
                body_digest = raw_method["body_digest"]
                calls = raw_method["calls"]
                if (
                    not isinstance(name, str)
                    or not name
                    or isinstance(arity, bool)
                    or not isinstance(arity, int)
                    or arity < 0
                    or not isinstance(calls, list)
                ):
                    _malformed(method_path)

                for call_index, call in enumerate(calls):
                    _validate_call(call, f"{method_path}.calls[{call_index}]")

                try:
                    region = MethodRegion(
                        class_name=class_name,
                        method=f"{name}/{arity}",
                        path=normalized_path,
                        start_line=start_line,
                        end_line=end_line,
                        body_digest=body_digest,
                    )
                except JadxIndexError:
                    _malformed(method_path)
                regions.append(region)

    return classes


def _region_sort_key(region: MethodRegion) -> tuple[object, ...]:
    return (
        region.path,
        region.start_line,
        region.end_line,
        region.body_digest,
    )


def _method_sort_key(region: MethodRegion) -> tuple[object, ...]:
    return (
        region.class_name,
        region.path,
        region.method,
        region.start_line,
        region.end_line,
        region.body_digest,
    )


def diff_index_structure(left: LoadedIndex, right: LoadedIndex) -> StructuralDiff:
    """返回两个 LoadedIndex 的确定性结构 diff（类身份 = (class_name, path)）。"""
    left_classes = _read_structure(left)
    right_classes = _read_structure(right)

    left_identities = set(left_classes)
    right_identities = set(right_classes)
    added_classes = tuple(sorted(right_identities - left_identities))
    removed_classes = tuple(sorted(left_identities - right_identities))

    added_methods: list[MethodRegion] = []
    removed_methods: list[MethodRegion] = []
    changed_methods: list[ChangedMethod] = []
    unchanged_methods = 0

    for class_name, path in sorted(left_identities & right_identities):
        left_regions = left_classes[(class_name, path)]
        right_regions = right_classes[(class_name, path)]

        left_by_method: dict[str, list[MethodRegion]] = {}
        right_by_method: dict[str, list[MethodRegion]] = {}
        for region in left_regions:
            left_by_method.setdefault(region.method, []).append(region)
        for region in right_regions:
            right_by_method.setdefault(region.method, []).append(region)

        for method in sorted(set(left_by_method) | set(right_by_method)):
            left_method_regions = left_by_method.get(method, [])
            right_method_regions = right_by_method.get(method, [])
            left_method_regions.sort(key=_region_sort_key)
            right_method_regions.sort(key=_region_sort_key)

            if not left_method_regions:
                added_methods.extend(right_method_regions)
            elif not right_method_regions:
                removed_methods.extend(left_method_regions)
            else:
                left_digests = sorted(region.body_digest for region in left_method_regions)
                right_digests = sorted(region.body_digest for region in right_method_regions)
                if left_digests == right_digests:
                    unchanged_methods += 1
                else:
                    changed_methods.append(
                        ChangedMethod(
                            class_name=class_name,
                            path=path,
                            method=method,
                            left_regions=tuple(left_method_regions),
                            right_regions=tuple(right_method_regions),
                        )
                    )

    added_methods.sort(key=_method_sort_key)
    removed_methods.sort(key=_method_sort_key)
    changed_methods.sort(key=lambda item: (item.class_name, item.path, item.method))

    return StructuralDiff(
        added_classes=added_classes,
        removed_classes=removed_classes,
        added_methods=tuple(added_methods),
        removed_methods=tuple(removed_methods),
        changed_methods=tuple(changed_methods),
        unchanged_methods=unchanged_methods,
        left_coverage=left.coverage,
        right_coverage=right.coverage,
        absence_claimable=left.coverage == "complete" and right.coverage == "complete",
    )


__all__ = [
    "ChangedMethod",
    "MethodRegion",
    "StructuralDiff",
    "diff_index_structure",
]
