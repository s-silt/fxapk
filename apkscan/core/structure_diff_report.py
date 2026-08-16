"""将 JADX StructuralDiff 投影为 ``fxapk diff`` 的消费面结构（P2-B）。

本模块只负责内存对象之间的纯投影，不负责读取缓存、文件系统或报告——把缓存加载
失败与报告级 diff 解耦，结构 diff 才能按 fail-open 处理。输出绝不含文件系统路径
（MethodRegion.path 是索引内相对路径，可以带）。
"""

from __future__ import annotations

from collections.abc import Callable

from apkscan.core.jadx_structure_diff import (
    ChangedMethod,
    MethodRegion,
    StructuralDiff,
)

#: 每类明细列表的输出上限。运行时经模块属性读取（测试/部署策略可安全收紧），
#: 消费时不得复制到提前求值的常量。
_MAX_DETAIL_ITEMS: int = 1000


def _region_dict(region: MethodRegion) -> dict[str, object]:
    """把方法区域投影为机器可读对象（类名/方法/索引内相对路径/行号/digest）。"""
    return {
        "class_name": region.class_name,
        "method": region.method,
        "path": region.path,
        "start_line": region.start_line,
        "end_line": region.end_line,
        "body_digest": region.body_digest,
    }


def _class_dict(identity: tuple[str, str]) -> dict[str, object]:
    """把类身份投影为机器可读对象（schema 1.2：(class_name, path)）。"""
    return {"class_name": identity[0], "path": identity[1]}


def _changed_dict(changed: ChangedMethod) -> dict[str, object]:
    """把变更方法投影为稳定、可序列化的机器可读对象。"""
    return {
        "class_name": changed.class_name,
        "path": changed.path,
        "method": changed.method,
        "left_regions": [_region_dict(item) for item in changed.left_regions],
        "right_regions": [_region_dict(item) for item in changed.right_regions],
    }


def _bounded_details(
    name: str,
    items: tuple[object, ...],
    encoder: Callable[[object], object],
    limit: int,
) -> dict[str, object]:
    """生成一组带完整计数和截断留痕的明细字段。

    所有明细共享同一个运行时上限——统一在此截断，杜绝某一类明细忘记留痕或
    用了过期上限。
    """
    if limit < 0:
        limit = 0
    emitted_items = items[:limit]
    return {
        name: [encoder(item) for item in emitted_items],
        f"{name}_total": len(items),
        f"{name}_emitted": len(emitted_items),
    }


def _coverage_caveats(left_coverage: str, right_coverage: str) -> list[dict[str, str]]:
    """生成稳定的 caveat 列表（code + 人读文本）。"""
    caveats: list[dict[str, str]] = [
        {
            "code": "absence_is_unobserved",
            "text": "absence=索引覆盖内未观察到，绝非不存在",
        }
    ]
    if left_coverage == "partial" or right_coverage == "partial":
        caveats.append(
            {
                "code": "coverage_partial",
                "text": "至少一侧索引覆盖不完整，absence 结论仅适用于已覆盖内容",
            }
        )
    return caveats


def project_structure_diff(
    diff: StructuralDiff,
    *,
    left_index_key: str,
    right_index_key: str,
    left_manifest_digest: str,
    right_manifest_digest: str,
) -> dict[str, object]:
    """将 StructuralDiff 投影为 report 消费面的 ``structure_diff`` 段。

    身份字段使用调用方已经校验过的 key 与 manifest digest——key 不是 provenance，
    cache root 是信任边界不是真实性证据，输出不得暗示「从配置 root 载入=官方」。
    coverage 取 StructuralDiff 自带的值（结构比较实际使用的那份）。
    """
    limit = _MAX_DETAIL_ITEMS

    added_classes = tuple(diff.added_classes)
    removed_classes = tuple(diff.removed_classes)
    added_methods = tuple(diff.added_methods)
    removed_methods = tuple(diff.removed_methods)
    changed_methods = tuple(diff.changed_methods)

    # counts 是**截断前**全量计数：读的人先看规模、再看被上限裁过的明细。
    counts: dict[str, int] = {
        "added_classes": len(added_classes),
        "removed_classes": len(removed_classes),
        "added_methods": len(added_methods),
        "removed_methods": len(removed_methods),
        "changed_methods": len(changed_methods),
        "unchanged_methods": diff.unchanged_methods,
    }

    result: dict[str, object] = {
        "status": "ok",
        "old": {
            "index_key": left_index_key,
            "coverage": diff.left_coverage,
            "manifest_digest": left_manifest_digest,
        },
        "new": {
            "index_key": right_index_key,
            "coverage": diff.right_coverage,
            "manifest_digest": right_manifest_digest,
        },
        "absence_claimable": diff.absence_claimable,
        "counts": counts,
        "limit": limit,
        "caveats": _coverage_caveats(diff.left_coverage, diff.right_coverage),
    }

    detail_groups: list[dict[str, object]] = [
        _bounded_details(
            "added_classes", added_classes,
            lambda item: _class_dict(item), limit,  # type: ignore[arg-type]
        ),
        _bounded_details(
            "removed_classes", removed_classes,
            lambda item: _class_dict(item), limit,  # type: ignore[arg-type]
        ),
        _bounded_details(
            "added_methods", added_methods,
            lambda item: _region_dict(item), limit,  # type: ignore[arg-type]
        ),
        _bounded_details(
            "removed_methods", removed_methods,
            lambda item: _region_dict(item), limit,  # type: ignore[arg-type]
        ),
        _bounded_details(
            "changed", changed_methods,
            lambda item: _changed_dict(item), limit,  # type: ignore[arg-type]
        ),
    ]
    for group in detail_groups:
        result.update(group)

    result["truncated"] = any(
        int(result[f"{name}_emitted"]) < int(result[f"{name}_total"])  # type: ignore[call-overload]
        for name in (
            "added_classes", "removed_classes",
            "added_methods", "removed_methods", "changed",
        )
    )
    return result
