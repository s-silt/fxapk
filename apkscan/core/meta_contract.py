"""分析器写入 ``Report.meta`` 的运行时契约。

分析器类上的 ``meta_keys`` 是准入的权威来源；这里汇总声明并补充 pipeline 派生键的合并策略。
静态扫描器只在契约测试中反向核对生产写入，pipeline 运行时不解析源码，安装包形态下保持稳定。
"""

from __future__ import annotations

from dataclasses import dataclass

MERGE_REPLACE = "replace"
MERGE_BOOLEAN_OR = "boolean_or"
PIPELINE_OWNER = "pipeline"
MISSING_ANALYZERS_KEY = "missing_analyzers"
META_CATEGORY_SIGNAL = "signal"
META_CATEGORY_RECORD = "record"
META_CATEGORY_COVERAGE = "coverage"
META_CATEGORIES = frozenset({
    META_CATEGORY_SIGNAL, META_CATEGORY_RECORD, META_CATEGORY_COVERAGE,
})


@dataclass(frozen=True)
class MetaKeyContract:
    """一个 meta 键的所有者与聚合策略。"""

    owners: frozenset[str]
    category: str = META_CATEGORY_SIGNAL
    pending_review: bool = False
    merge: str = MERGE_REPLACE


def _build_registry() -> dict[str, MetaKeyContract]:
    owners_by_key: dict[str, set[str]] = {}
    category_by_key: dict[str, str] = {}
    pending_by_key: dict[str, bool] = {}
    # 自动发现返回的实例同时提供稳定 name 与本地声明，不再维护中心 owner/键清单。
    from apkscan.core.registry import discover_analyzers

    for analyzer in discover_analyzers():
        categories = getattr(analyzer, "meta_key_categories", None)
        if not isinstance(categories, dict):
            raise RuntimeError(f"分析器 {analyzer.name!r} 未声明 meta_key_categories")
        if frozenset(categories) != analyzer.meta_keys:
            raise RuntimeError(
                f"分析器 {analyzer.name!r} 的 meta_keys 与 meta_key_categories 键集合不一致"
            )
        pending = getattr(analyzer, "meta_category_pending", frozenset())
        if not isinstance(pending, frozenset) or not pending <= analyzer.meta_keys:
            raise RuntimeError(f"分析器 {analyzer.name!r} 的待定类别声明非法")
        if any(categories[key] != META_CATEGORY_SIGNAL for key in pending):
            raise RuntimeError(f"分析器 {analyzer.name!r} 的待定键必须保守归入 signal")
        for key in analyzer.meta_keys:
            if not isinstance(key, str) or not key:
                raise RuntimeError(f"分析器 {analyzer.name!r} 的 meta_keys 含非法键：{key!r}")
            owners_by_key.setdefault(key, set()).add(analyzer.name)
            category = categories[key]
            if category not in META_CATEGORIES:
                raise RuntimeError(
                    f"分析器 {analyzer.name!r} 的 meta 键 {key!r} 类别非法：{category!r}"
                )
            previous = category_by_key.setdefault(key, category)
            if previous != category:
                raise RuntimeError(
                    f"共享 meta 键 {key!r} 类别冲突：{previous!r} != {category!r}"
                )
            pending_by_key[key] = pending_by_key.get(key, False) or key in pending

    registry = {
        key: MetaKeyContract(
            owners=frozenset(owners),
            category=category_by_key[key],
            pending_review=pending_by_key[key],
        )
        for key, owners in owners_by_key.items()
    }
    truncation = registry.get("dex_strings_truncated")
    if truncation is not None:
        registry["dex_strings_truncated"] = MetaKeyContract(
            owners=truncation.owners,
            category=truncation.category,
            pending_review=truncation.pending_review,
            merge=MERGE_BOOLEAN_OR,
        )
    # pipeline 派生键也走普通注册。保留键若被分析器声明，必须在启动期直接报错；
    # 不能覆盖掉分析器 owner 后再让运行期把它的整块 meta 静默拒绝。
    for key in ("dex_strings_truncated_by", MISSING_ANALYZERS_KEY):
        if key in registry:
            owners = sorted(registry[key].owners)
            raise RuntimeError(f"pipeline 保留 meta 键 {key!r} 被分析器声明：{owners!r}")
        registry[key] = MetaKeyContract(
            owners=frozenset({PIPELINE_OWNER}),
            category=META_CATEGORY_COVERAGE,
        )
    return registry


META_KEY_REGISTRY: dict[str, MetaKeyContract] = _build_registry()


def allowed_meta_keys(analyzer_name: str) -> frozenset[str]:
    """返回某分析器获准产出的键集合。未知分析器默认无权限（fail closed）。"""

    return frozenset(
        key
        for key, contract in META_KEY_REGISTRY.items()
        if analyzer_name in contract.owners and PIPELINE_OWNER not in contract.owners
    )


def validate_registry_owners(analyzer_names: set[str]) -> frozenset[str]:
    """返回注册表中本轮未发现的分析器，供 pipeline 显式降级。

    运行期新分析器不在这里把整个 stage 打死：它若产出未登记 meta，
    聚合门会原子拒绝整块并把该分析器标红。而注册表残留可能是单模块
    import 失败的设计降级形态，必须留痕但不得清空其他分析器结果。
    """

    registered = {
        owner
        for contract in META_KEY_REGISTRY.values()
        for owner in contract.owners
        if owner != PIPELINE_OWNER
    }
    return frozenset(registered - analyzer_names)
