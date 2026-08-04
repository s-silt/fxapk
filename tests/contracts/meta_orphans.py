"""``report.meta`` 孤儿键的冻结基线 —— 止血层，不治病。

孤儿的定义
----------

**生产代码写了、但既无生产代码读取、也无模板读取的键。**

- 生产消费与测试消费必须分开：测试读一个键只说明「有人锁过它的值」，
  说明不了它进过任何产物链路——那批「只有测试读」的键恰恰是问题最集中的一批，
  混在一起它们会假装合格（见 ``ScanResult`` 的字段注释）。
- 模板（Jinja ``.j2``）是独立一路证据：本仓确有只在模板里被读的兼容旧键
  （实测 6 个），漏算会把仍在被渲染的键误判成孤儿、进而被错误清理。

为什么是「双向严格相等」而不是「不超过 N 个」
--------------------------------------------

单向上限会让改善（孤儿获得消费方）悄悄不被记录，基线慢慢和现实脱节，
最终又变回一张没人信的表。基线必须诚实：

- 新增孤儿 → 红（回归，正是本机制要治的病）；
- 孤儿被解决 → 也红（好消息，但请把这条从基线移除，让改善留痕）;
- 键被删除 → 红（基线要跟着更新）。

更新基线（每条差异都必须有人看过，不是无脑重生成）::

    python -m tests.contracts.meta_orphans --write
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from tests.contracts import meta_scan

#: 基线文件：键 → 写入它的生产文件列表（owner 信息，供下一轮按归属分类处置）。
BASELINE_PATH = Path(__file__).with_name("meta_orphan_baseline.json")

_README = [
    "meta 孤儿键冻结基线：生产代码写了、但生产代码与模板都没人读的键。",
    "本文件由 python -m tests.contracts.meta_orphans --write 生成，",
    "由 test_meta_orphan_baseline.py 与现实做双向严格比对：",
    "新增孤儿会红（回归）；孤儿获得消费方也会红（请把该条移除，让改善留痕）。",
    "值是写入该键的生产文件列表（owner），供下一轮分类处置；",
    "有限键族已按权威注册表展开成 分析器×后缀 的具体键（键名即含分析器身份）；",
    "仅当后缀不在权威定义域内时才保留 <family:...> 原始标记（可见，不静默丢弃）。",
    "★不要为了让测试变绿而无脑重生成——每条差异都必须有人看过并说得出为什么。",
]


def compute_orphans(root: Path) -> tuple[dict[str, list[str]], set[str]]:
    """返回 ``(孤儿键 → 排序后的写入文件列表, 全部生产写入键)``。

    第二项含族标记，供比对层区分「孤儿被解决」（键还在写、有人读了）
    与「键被删除」（不再被生产代码写入）——两者要更新基线的方向相同，
    但对下一轮的意义完全不同，报错必须分开说。

    边界判断（每条都有测试锁住）：

    - **模板读取算生产消费**：模板由生产代码渲染进最终产物，
      ``scan_templates`` 是独立一路证据，漏算会误判仍在被渲染的键。
    - **有限键族展开成「分析器 × 后缀」的具体键**参与：写入工厂虽然共享，
      下游完全可以只按字面消费其中一个分析器的键——族标记粒度会让一个分析器的
      消费方把同后缀所有分析器的孤儿一并救出去（复审实证），且丢失分析器身份、
      下一轮没法按归属分类。取值域来自权威注册表（与既有契约同源），
      表外后缀不展开、保留原始标记（可见，不静默丢弃）。族访问同样区分生产/测试——
      ``scan_repository`` 把两侧的族访问都归进 ``families``，这里按文件前缀分开。
      ★工厂形态的**生产**读取（分析器名是运行时变量）按定义域视为消费整个后缀，
        这是族读取动态本性的如实建模，不是粒度塌缩；字面读取只救字面那一个键。
    - **未解析动态点不进基线**：它们不是键，无从判定消费关系；
      分析器侧的开放写入已由既有契约逐点冻结
      （``test_analyzer_unresolved_writes_match_reviewed_baseline``），
      全仓动态点的冻结留给下一轮。
    """
    res = meta_scan.scan_repository(root)
    tpl_root = root / "apkscan"
    tpl_keys = set(meta_scan.scan_templates(tpl_root)) if tpl_root.is_dir() else set()

    orphans: dict[str, list[str]] = {}
    for key in res.orphans():
        if key in tpl_keys:
            continue  # 模板还在渲染它，不是孤儿
        orphans[key] = sorted({a.file for a in res.produced[key]})

    # 有限键族：生产侧的族写入展开成「分析器 × 后缀」的具体键逐个判定。
    # ★必须按文件前缀分开生产/测试：scan_repository 的 families 不分侧，
    #   测试里的族读取绝不能把族键从孤儿名单里救出去（与普通键同一条纪律）。
    def _is_production(access: meta_scan.Access) -> bool:
        return not access.file.startswith("tests/")

    fam_read_suffixes = {
        _parse_family_marker(a.key)[1]
        for a in res.families if a.kind == "read" and _is_production(a)
    }
    fam_written: set[str] = set()
    for a in res.families:
        if a.kind != "write" or not _is_production(a):
            continue
        family, suffix = _parse_family_marker(a.key)
        concrete = _family_concrete_keys(family, suffix)
        if concrete is None:
            # 表外后缀/未知族：不展开也不丢弃，保留原始标记让它可见
            fam_written.add(a.key)
            orphans[a.key] = sorted({*orphans.get(a.key, []), a.file})
            continue
        for key in concrete:
            fam_written.add(key)
            consumed = (
                key in res.production_consumed  # 字面读取只救字面那一个键
                or key in tpl_keys
                or suffix in fam_read_suffixes  # 工厂读取按定义域消费整个后缀
            )
            if not consumed:
                orphans[key] = sorted({*orphans.get(key, []), a.file})

    return orphans, set(res.produced) | fam_written


def _parse_family_marker(marker: str) -> tuple[str, str]:
    """``<family:族名:后缀>`` → ``(族名, 后缀)``。格式坏了直接抛，不猜。"""
    inner = marker.removeprefix("<family:").removesuffix(">")
    family, _, suffix = inner.partition(":")
    if not family or not suffix:
        raise ValueError(f"非法的族标记：{marker!r}")
    return family, suffix


def _family_concrete_keys(family: str, suffix: str) -> list[str] | None:
    """把 (族, 后缀) 展开成具体键；族或后缀不在权威定义域内时返回 ``None``。

    ★取值域来自权威注册表（``discover_analyzers``），与既有契约
      ``test_coverage_key_domain_comes_from_registry_not_runtime`` 同源：
      因能力门控而未运行的分析器也必须在展开域里，它那份「我没看全」
      恰恰是最该留痕的。
    """
    if family != "web_coverage":
        return None
    from apkscan.analyzers.web_evidence import COVERAGE_SUFFIXES
    from apkscan.core.registry import discover_analyzers

    if suffix not in COVERAGE_SUFFIXES:
        return None
    web = sorted(
        analyzer.name for analyzer in discover_analyzers()
        if "web" in (getattr(analyzer, "requires", None) or [])
    )
    return [f"{name}_{suffix}" for name in web]


def diff_against_baseline(
    current: dict[str, list[str]],
    baseline: dict[str, list[str]],
    written_keys: set[str],
) -> list[str]:
    """双向严格比对，返回能直接指导下一步动作的差异清单（空列表 = 一致）。

    ★三个方向都必须红，缺一不可：只报新增是单向「不超过」，
      改善会悄悄不被记录，基线慢慢和现实脱节（本轮明确要求堵死的形态）。
    """
    problems: list[str] = []
    for key in sorted(set(current) - set(baseline)):
        writers = "、".join(current[key])
        problems.append(
            f"新增孤儿：{key!r}（写入于 {writers}）——请给它接上生产消费方；"
            "确属有意暂挂时才把它加进基线，留给下一轮分类处置"
        )
    for key in sorted(set(baseline) - set(current)):
        if key in written_keys:
            problems.append(
                f"已解决：{key!r} 获得了消费方（生产代码或模板，好消息）"
                "——请把这条从基线移除，让改善留痕"
            )
        else:
            problems.append(
                f"键已删除：{key!r} 不再被生产代码写入——请把这条从基线移除"
            )
    for key in sorted(set(baseline) & set(current)):
        if baseline[key] != current[key]:
            problems.append(
                f"写入点漂移：{key!r} 基线记录 {baseline[key]}，"
                f"现为 {current[key]}——owner 信息要保持诚实，请更新基线该条"
            )
    return problems


def load_baseline() -> dict[str, list[str]]:
    """读基线文件。格式坏了直接抛——基线是契约的一半，不容忍静默降级。"""
    data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    orphans = data["orphans"]
    if not isinstance(orphans, dict):
        raise TypeError(f"基线 orphans 字段必须是对象，实际 {type(orphans).__name__}")
    out: dict[str, list[str]] = {}
    for key, files in orphans.items():
        if not isinstance(files, list) or not all(isinstance(f, str) for f in files):
            raise TypeError(f"基线键 {key!r} 的写入文件列表格式非法：{files!r}")
        out[str(key)] = list(files)
    return out


def write_baseline(root: Path) -> dict[str, list[str]]:
    """按当前现实重写基线（键排序，LF 换行），返回写入的内容。"""
    current, _ = compute_orphans(root)
    payload = {
        "readme": _README,
        "orphans": {key: current[key] for key in sorted(current)},
    }
    text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    BASELINE_PATH.write_text(text, encoding="utf-8", newline="\n")
    return current


def main(argv: list[str]) -> int:
    if argv != ["--write"]:
        print(__doc__)
        return 2
    root = Path(__file__).resolve().parents[2]
    old = load_baseline() if BASELINE_PATH.exists() else {}
    new = write_baseline(root)
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    print(f"基线已写入 {BASELINE_PATH}：共 {len(new)} 条；新增 {len(added)}，移除 {len(removed)}")
    for key in added:
        print(f"  + {key}")
    for key in removed:
        print(f"  - {key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
