"""静态扫描的**覆盖度协议**：把「我没看全」这件事变成结构化数据。

★为什么要有这层：取证工具里 ``count=0`` 有两种截然不同的含义——「扫全了，确实没有」与
「没扫全，所以没看见」。前者是结论，后者只是没做完。两者在报告里长得一模一样时，读报告的人
会把「没扫到」当成「没有」，那正是本仓要堵的头号误读。

键名约定 ``<analyzer>_<suffix>``，各分析器只写自己前缀的键（无跨分析器合并问题）。

★**缺失 = 无事件**：不写零值、不写 False。沿用既有的 ``dex_strings_truncated`` 先例——
键出现即表示「确实发生过这类覆盖缺口」，于是消费方只需判断键在不在、值真不真，
不必区分「写了 0」与「没写」。
"""

from __future__ import annotations

from collections.abc import Mapping

#: 覆盖度事件的后缀表。每一项都对应一种「这次没看全」的具体形态——
#: 分开记而不是合成一个布尔，是因为处置动作不同：读失败要查权限/损坏，
#: 超大跳过要调上限或换策略，预算耗尽说明样本体量超出当前配额。
COVERAGE_SUFFIXES: tuple[str, ...] = (
    "list_failed",        # bool：枚举失败，整层根本没看到
    "files_truncated",    # int>0：文件数超上限，被截掉的文件数
    "read_failed",        # int>0：读取失败的文件数
    "content_truncated",  # int>0：单文件内容被截断的文件数
    "oversize_skipped",   # int>0：单文件超大小上限、整个被跳过的文件数
    "budget_exhausted",   # bool：累计预算耗尽、提前停止
    "items_truncated",    # int>0：产出条数超上限、被丢弃的条数
)


def coverage_meta_key(analyzer: str, suffix: str) -> str:
    """拼出某分析器的覆盖度 meta 键；后缀不在表里直接抛（拼错的键等于静默丢痕迹）。"""
    if suffix not in COVERAGE_SUFFIXES:
        raise ValueError(f"未知覆盖度后缀：{suffix!r}")
    return f"{analyzer}_{suffix}"


def coverage_meta_keys_for(analyzer: str) -> frozenset[str]:
    """某分析器的全部覆盖度键（供 ``meta_key_categories`` 声明与消费方枚举）。"""
    return frozenset(coverage_meta_key(analyzer, suffix) for suffix in COVERAGE_SUFFIXES)


def iter_coverage_meta_keys(analyzers: list[str]) -> frozenset[str]:
    """多个分析器的覆盖度键并集。"""
    return frozenset(
        coverage_meta_key(analyzer, suffix)
        for analyzer in analyzers
        for suffix in COVERAGE_SUFFIXES
    )


def collect_coverage(meta: Mapping[str, object]) -> dict[str, object]:
    """从 ``meta`` 里挑出**已写入且非零/非假**的覆盖度键，供 visibility / digest 统一消费。

    ★只收真值：按「缺失=无事件」的约定，写进来的零值/False 是噪音而非事实，
      混进来会让消费方把「没发生」渲染成一条覆盖缺口警告。
    """
    suffixes = tuple(f"_{suffix}" for suffix in COVERAGE_SUFFIXES)
    return {
        key: value
        for key, value in meta.items()
        if isinstance(key, str) and key.endswith(suffixes) and bool(value)
    }
