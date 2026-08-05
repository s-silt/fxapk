"""孤儿键基线契约 —— 止血层：存量孤儿被逐条钉住，此后任何漂移立刻变红。

★本文件锁两层东西，缺一层都会假绿：

1. **基线与现实的双向严格相等**（主契约）：新增孤儿红、孤儿被解决也红、
   键被删除也红。单向「不超过 N 个」会让改善悄悄不被记录、基线与现实脱节。
2. **计算与比对原语自身的行为**（地基纪律）：基线由 ``compute_orphans`` 生成，
   它错了主契约就建在错的集合上、而且错得无声——所以模板救回、测试读不算、
   键族分侧、三方向报错，每条边界都要有自己的测试。
   这也是四刀突变里「把检查改成单向」那一刀的落点：主契约对单向弱化不敏感
   （现实与基线一致时两个方向都是空集），必须由这里的原语测试打红。
"""

from __future__ import annotations

from pathlib import Path

from tests.contracts import meta_orphans


# --- 主契约：基线 ↔ 现实 双向严格相等 ----------------------------------------


def test_orphan_baseline_matches_reality_both_ways() -> None:
    """★主契约。红的时候逐条说清：哪个键、属于谁、是回归还是改善。

    - 新增孤儿 = 回归（有人写了没人读的信号，正是本机制要治的病）→ 接上消费方；
    - 已解决 / 键已删除 = 现实变好或变化了 → 更新基线对应条目，让变化留痕。
    ★不要为了变绿无脑重生成基线——每条差异都必须有人看过并说得出为什么。
    """
    root = Path(__file__).resolve().parents[2]
    current, written = meta_orphans.compute_orphans_by_category(root)
    baseline = meta_orphans.load_baseline()

    problems = meta_orphans.diff_categories_against_baseline(current, baseline, written)
    assert not problems, (
        "孤儿基线与现实不一致（逐条处置后可用 "
        "python -m tests.contracts.meta_orphans --write 重写基线）：\n  "
        + "\n  ".join(problems)
    )


def test_baseline_file_is_wellformed_and_nonvacuous() -> None:
    """基线文件本身的形状：有说明、有条目、owner 信息齐全。

    ★防「空对空」：若 compute_orphans 整体失效返回空集、又有人顺手 --write，
      主契约会在两个空集上假绿。本条钉住基线的既有规模不允许无声清零
      （治病治到清零的那天，这条测试应当与基线一起被有意识地更新，而不是被绕过）。
    """
    baseline = meta_orphans.load_baseline()
    total = sum(len(group) for group in baseline.values())
    # 变更史（每次下调都必须写清是**哪个键真的接上了消费方**，不许只改数字）：
    #   119 → 118：control_chains 接进 digest 的 control_chains 段
    #              （见 evidence_exit_contract 的同名证据单元）。
    assert total == 118, f"三类存量应守恒为 118，实际 {total}"
    for category, group in baseline.items():
        for key, files in group.items():
            assert key, f"{category} 基线里有空键"
            assert files, f"{key!r} 没有记录写入文件（owner 缺失）"
            for f in files:
                assert f.startswith("apkscan/"), f"{key!r} 的写入点 {f!r} 不在生产代码里"


# --- 计算原语的边界（每条对应 compute_orphans 文档里的一条判断） -------------


def _write_repo(
    tmp_path: Path,
    prod: dict[str, str],
    tests: dict[str, str] | None = None,
    templates: dict[str, str] | None = None,
) -> Path:
    (tmp_path / "apkscan").mkdir(parents=True, exist_ok=True)
    (tmp_path / "tests").mkdir(parents=True, exist_ok=True)
    for name, src in prod.items():
        (tmp_path / "apkscan" / name).write_text(src, encoding="utf-8")
    for name, src in (tests or {}).items():
        (tmp_path / "tests" / name).write_text(src, encoding="utf-8")
    for name, src in (templates or {}).items():
        (tmp_path / "apkscan" / name).write_text(src, encoding="utf-8")
    return tmp_path


def test_template_read_rescues_key_from_orphanhood(tmp_path: Path) -> None:
    """★模板是独立一路证据：只在 ``.j2`` 里被读的键不是孤儿。

    本仓真实存在这种兼容旧键的读法（实测 6 个键只靠模板救回）；
    漏算它会把仍在被渲染的键误判成孤儿、进而在下一轮被错误清理。
    """
    root = _write_repo(
        tmp_path,
        prod={"w.py": 'def f(report):\n    report.meta["tpl_only"] = 1\n'
                       '    report.meta["nobody"] = 1\n'},
        templates={"page.j2": '<p>{{ meta.get("tpl_only") }}</p>\n'},
    )
    orphans, written = meta_orphans.compute_orphans(root)
    assert "tpl_only" not in orphans, "模板读取没被算成消费"
    assert "nobody" in orphans
    assert written == {"tpl_only", "nobody"}


def test_test_only_read_is_still_an_orphan(tmp_path: Path) -> None:
    """★生产消费与测试消费必须分开：测试读只说明有人锁过值，
    说明不了它进过产物链路——混在一起，问题最集中的那批键会假装合格。"""
    root = _write_repo(
        tmp_path,
        prod={"w.py": 'def f(report):\n    report.meta["test_only_read"] = 1\n'},
        tests={"t.py": 'def test_x(report):\n    assert report.meta.get("test_only_read")\n'},
    )
    orphans, _ = meta_orphans.compute_orphans(root)
    assert "test_only_read" in orphans, "测试读取被误算成生产消费"


def test_production_read_removes_orphan(tmp_path: Path) -> None:
    root = _write_repo(
        tmp_path,
        prod={
            "w.py": 'def f(report):\n    report.meta["consumed"] = 1\n',
            "r.py": 'def g(report):\n    return report.meta.get("consumed")\n',
        },
    )
    orphans, _ = meta_orphans.compute_orphans(root)
    assert "consumed" not in orphans


def test_orphan_records_its_writers_as_owner_info(tmp_path: Path) -> None:
    """基线的值 = 写入文件列表：下一轮分类要按 owner 分批处置，光有键名不够。"""
    root = _write_repo(
        tmp_path,
        prod={
            "a.py": 'def f(report):\n    report.meta["dual"] = 1\n',
            "b.py": 'def g(report):\n    report.meta["dual"] = 2\n',
        },
    )
    orphans, _ = meta_orphans.compute_orphans(root)
    assert orphans["dual"] == ["apkscan/a.py", "apkscan/b.py"]


_FAMILY_WRITE = ('def f(result, analyzer):\n'
                 '    result.meta[coverage_meta_key(analyzer, "read_failed")] = 3\n')


def test_family_write_expands_to_per_analyzer_concrete_keys(tmp_path: Path) -> None:
    """★有限键族不因写法动态而被排除，且必须展开成「分析器 × 后缀」的具体键：
    键名携带分析器身份，下一轮才能按归属分类；族标记本身不进基线。"""
    root = _write_repo(tmp_path, prod={"w.py": _FAMILY_WRITE})
    orphans, written = meta_orphans.compute_orphans(root)
    assert "<family:web_coverage:read_failed>" not in orphans, "族标记应展开，不应原样入基线"
    for key in ("web_inline_config_read_failed", "web_redirect_chain_read_failed",
                "web_request_recipe_read_failed"):
        assert key in orphans, f"展开键 {key!r} 缺席"
        assert key in written
        assert orphans[key] == ["apkscan/w.py"], "展开键必须保留写入文件（owner）"


def test_literal_read_rescues_only_that_analyzers_key(tmp_path: Path) -> None:
    """★复审 P1-1 的修复点：字面消费一个分析器的键，不得救出同后缀的其他分析器。

    此前按族标记粒度判定，任意一个分析器的该后缀键被消费，同后缀所有分析器
    的键都会被视为已消费（写入工厂共享 ≠ 下游按动态分析器名统一消费）。
    """
    read = ('def g(result):\n'
            '    return result.meta.get("web_inline_config_read_failed")\n')
    root = _write_repo(tmp_path, prod={"w.py": _FAMILY_WRITE, "r.py": read})
    orphans, _ = meta_orphans.compute_orphans(root)
    assert "web_inline_config_read_failed" not in orphans, "字面读取没救出对应的展开键"
    assert "web_redirect_chain_read_failed" in orphans, "一个分析器的消费方救出了别人的孤儿"
    assert "web_request_recipe_read_failed" in orphans


def test_factory_read_consumes_the_whole_suffix_domain(tmp_path: Path) -> None:
    """工厂形态的生产读取（分析器名是运行时变量）按定义域消费整个后缀——
    这是族读取动态本性的如实建模：静态上它可能读到域内任何分析器的键。"""
    read = ('def g(result, analyzer):\n'
            '    return result.meta.get(coverage_meta_key(analyzer, "read_failed"))\n')
    root = _write_repo(tmp_path, prod={"w.py": _FAMILY_WRITE, "r.py": read})
    orphans, _ = meta_orphans.compute_orphans(root)
    assert not [k for k in orphans if k.endswith("_read_failed")], (
        "工厂读取覆盖整个后缀定义域，展开键不该再是孤儿"
    )


def test_out_of_domain_suffix_keeps_visible_marker(tmp_path: Path) -> None:
    """表外后缀不展开也不静默丢弃：保留原始标记入孤儿名单，红了有人看。"""
    write = ('def f(result, analyzer):\n'
             '    result.meta[coverage_meta_key(analyzer, "bogus_suffix")] = 3\n')
    root = _write_repo(tmp_path, prod={"w.py": write})
    orphans, written = meta_orphans.compute_orphans(root)
    assert "<family:web_coverage:bogus_suffix>" in orphans, "表外后缀被静默丢弃"
    assert "<family:web_coverage:bogus_suffix>" in written


def test_family_read_in_tests_does_not_rescue_expanded_keys(tmp_path: Path) -> None:
    """★族访问同样要分生产/测试：scan_repository 的 families 不分侧，
    这里必须按文件前缀分开——否则测试里的族读取会把展开键从孤儿名单救出去，
    与「测试读不算消费」这条纪律直接矛盾。"""
    root = _write_repo(
        tmp_path,
        prod={"w.py": _FAMILY_WRITE},
        tests={"t.py": 'def test_x(result, a):\n'
                       '    assert result.meta.get(coverage_meta_key(a, "read_failed"))\n'},
    )
    orphans, _ = meta_orphans.compute_orphans(root)
    assert "web_inline_config_read_failed" in orphans, "测试里的族读取被误算成生产消费"


# --- 比对原语：三个方向都必须红 ----------------------------------------------
#
# ★主契约在「现实与基线一致」时对单向弱化不敏感（两个方向都是空集照样绿），
#   所以「把检查改成单向不超过」这类退化只能由下面这些测试打红。


def test_new_orphan_is_reported_as_regression() -> None:
    problems = meta_orphans.diff_against_baseline(
        current={"fresh": ["apkscan/x.py"]}, baseline={}, written_keys={"fresh"},
    )
    assert len(problems) == 1
    assert "新增孤儿" in problems[0]
    assert "fresh" in problems[0]
    assert "apkscan/x.py" in problems[0], "报错必须带 owner，不能只丢键名"


def test_resolved_orphan_demands_baseline_removal() -> None:
    """孤儿获得消费方是好消息，但**也要红**：单向检查会让改善无声流失。"""
    problems = meta_orphans.diff_against_baseline(
        current={}, baseline={"healed": ["apkscan/x.py"]}, written_keys={"healed"},
    )
    assert len(problems) == 1
    assert "已解决" in problems[0]
    assert "healed" in problems[0]


def test_deleted_key_is_distinguished_from_resolved() -> None:
    """键被删除与孤儿被解决对下一轮意义完全不同，报错必须分开说。"""
    problems = meta_orphans.diff_against_baseline(
        current={}, baseline={"gone": ["apkscan/x.py"]}, written_keys=set(),
    )
    assert len(problems) == 1
    assert "键已删除" in problems[0]
    assert "gone" in problems[0]


def test_writer_drift_is_reported() -> None:
    """owner 信息也要诚实：写入点搬家了，基线要跟着更新。"""
    problems = meta_orphans.diff_against_baseline(
        current={"moved": ["apkscan/new.py"]},
        baseline={"moved": ["apkscan/old.py"]},
        written_keys={"moved"},
    )
    assert len(problems) == 1
    assert "写入点漂移" in problems[0]


def test_identical_state_yields_no_problems() -> None:
    same = {"k": ["apkscan/x.py"]}
    assert meta_orphans.diff_against_baseline(same, dict(same), {"k"}) == []


def test_new_signal_orphan_is_a_regression_but_new_record_is_not() -> None:
    baseline = {"signal": {}, "record": {}, "coverage": {}}
    current = {
        "signal": {"decision": ["apkscan/x.py"]},
        "record": {"stat": ["apkscan/x.py"]},
        "coverage": {},
    }
    problems = meta_orphans.diff_categories_against_baseline(
        current, baseline, {"decision", "stat"},
    )
    assert len(problems) == 1
    assert "decision" in problems[0]
    assert "stat" not in problems[0]


def test_signal_comparison_remains_strictly_bidirectional() -> None:
    baseline = {
        "signal": {"healed": ["apkscan/x.py"]},
        "record": {},
        "coverage": {},
    }
    current = {"signal": {}, "record": {}, "coverage": {}}
    problems = meta_orphans.diff_categories_against_baseline(
        current, baseline, {"healed"},
    )
    assert len(problems) == 1
    assert "已解决" in problems[0]
