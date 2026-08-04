"""扫描器自身的测试 —— 整套 meta 契约的地基，它错了全盘皆错。

★为什么这份测试要先于扫描器的任何使用方存在：基线集合由扫描器生成，
  若它漏扫一种写法，那个键就不会进基线，后面所有检查都建在错的集合上，
  而且**错得无声无息**（正是本机制要治的那种缺陷形态）。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.contracts import meta_scan


def _keys(src: str, kind: str) -> set[str]:
    return {a.key for a in meta_scan.scan_source(src) if a.kind == kind}


def _dynamic(src: str) -> list[meta_scan.Access]:
    return [a for a in meta_scan.scan_source(src) if a.key.startswith("<dynamic")]


# --- 写入的各种写法 ---------------------------------------------------------

WRITE_CASES = [
    pytest.param('report.meta["a"] = 1', {"a"}, id="下标赋值"),
    pytest.param('state.meta["b"] = 1', {"b"}, id="state.meta"),
    pytest.param('result.meta["c"] = 1', {"c"}, id="result.meta"),
    pytest.param('meta["d"] = 1', {"d"}, id="裸 meta 变量"),
    pytest.param('report.meta.setdefault("e", [])', {"e"}, id="setdefault"),
    pytest.param('report.meta.update({"f": 1, "g": 2})', {"f", "g"}, id="update 字典字面量"),
    pytest.param('report.meta.update(h=1)', {"h"}, id="update 关键字参数"),
    pytest.param('m = state.meta\nm["i"] = 1', {"i"}, id="别名传播"),
    pytest.param('raw_meta = report.get("meta")\nraw_meta["j"] = 1', {"j"}, id="report.get(meta) 别名"),
    # ★以下三种是**路径 A 最初漏掉的形态**：不是逐键下标赋值，而是整体给一个字典。
    #   它们不是假想——是运行期观测（路径 C）在真仓库上抓出 7 个键后回头定位到的真实写法：
    #   analyzers/permissions.py、analyzers/remote_config.py、core/pipeline.py 都这么写。
    #   这条教训值得记：单一扫描器无法验证自己的盲区，必须有另一路独立证据。
    pytest.param('result.meta = {"k1": 1, "k2": 2}', {"k1", "k2"}, id="★整体字典赋值"),
    pytest.param('report.meta: dict = {"k3": 1}', {"k3"}, id="★带类型标注的整体赋值"),
    pytest.param('r = AnalyzerResult(analyzer="x", meta={"k4": 1})', {"k4"}, id="★构造时传入 meta="),
]


@pytest.mark.parametrize(("src", "expect"), WRITE_CASES)
def test_write_forms_are_detected(src: str, expect: set[str]) -> None:
    """每种写法都必须被认出——漏一种，那种写法写的键就永远进不了基线。"""
    assert _keys(src, "write") >= expect


# --- 读取的各种写法 ---------------------------------------------------------

READ_CASES = [
    pytest.param('x = report.meta["a"]', {"a"}, id="下标读取"),
    pytest.param('x = report.meta.get("b")', {"b"}, id="get"),
    pytest.param('x = report.meta.get("c", None)', {"c"}, id="get 带默认值"),
    pytest.param('x = report.meta.pop("d", None)', {"d"}, id="pop"),
    pytest.param('m = report.meta\nx = m.get("e")', {"e"}, id="别名后读取"),
]


@pytest.mark.parametrize(("src", "expect"), READ_CASES)
def test_read_forms_are_detected(src: str, expect: set[str]) -> None:
    """漏认读取方 = 把一个有人消费的键误判成孤儿，进而被错误地清理掉。"""
    assert _keys(src, "read") >= expect


# --- 动态键：必须暴露，绝不静默跳过 ------------------------------------------


DYNAMIC_CASES = [
    pytest.param('report.meta[key] = 1', id="变量作键"),
    pytest.param('report.meta[f"{name}_count"] = 1', id="f-string 作键"),
    pytest.param('report.meta.update(other)', id="update 非字面量字典"),
    pytest.param('report.meta.update(**kw)', id="update 双星展开"),
    pytest.param('x = report.meta.get(key)', id="变量作键读取"),
]


# --- 常量键：解析，而不是豁免 -----------------------------------------------


def test_module_constant_key_is_resolved() -> None:
    """``meta[SOME_KEY]`` 里 SOME_KEY 是模块常量时，必须解析成真实键名。

    ★为什么解析而不是列进豁免名单：豁免名单会不断增长，最终变成动态访问的逃生口；
      常量被重命名时基线看不到键变化；而且豁免抹掉了「固定常量」与「真正开放的
      ``meta[key]``」之间的区别——后者才是必须堵的绕过通道。
      本仓有约 20 处这种写法（DEX_TRUNCATED_META_KEY / MANUAL_RESTORES_KEY 等）。
    """
    src = 'K = "dex_strings_truncated"\ndef f(result):\n    result.meta[K] = True\n'
    assert _keys(src, "write") == {"dex_strings_truncated"}
    assert not _dynamic(src), "常量键仍被当成动态键"


def test_cross_module_constant_key_is_resolved() -> None:
    """跨模块一跳：``meta[_inv.INVENTORY_META_KEY]``（本仓 pcap_ingest/probe_ingest 的写法）。"""
    # ★键是完整模块路径（见 test_same_stem_modules_do_not_share_a_constant_table）
    symbols = {"apkscan.core.runtime_inventory": {"INVENTORY_META_KEY": "runtime_merged_inventory"}}
    src = ("from apkscan.core import runtime_inventory as _inv\n"
           "def f(meta):\n    meta[_inv.INVENTORY_META_KEY] = 1\n")
    got = {a.key for a in meta_scan.scan_source(src, symbols=symbols) if a.kind == "write"}
    assert got == {"runtime_merged_inventory"}


CONSTANT_POISON_CASES = [
    pytest.param('K = "a"\nif flag:\n    K = "b"\ndef f(meta):\n    meta[K] = 1',
                 id="条件赋值"),
    pytest.param('K = "a"\ndef f(meta):\n    K = "b"\n    meta[K] = 1',
                 id="函数内局部遮蔽"),
    pytest.param('K = "a"\nK = "b"\nK = "c"\ndef f(meta):\n    meta[K] = 1',
                 id="三次重赋值"),
    pytest.param('K = "a"\nfrom x import K\ndef f(meta):\n    meta[K] = 1',
                 id="import 覆盖"),
    pytest.param('K = "a"\nfor K in items:\n    pass\ndef f(meta):\n    meta[K] = 1',
                 id="循环变量绑定"),
    pytest.param('K = "a"\ndel K\ndef f(meta):\n    meta[K] = 1',
                 id="del 之后"),
]


@pytest.mark.parametrize("src", CONSTANT_POISON_CASES)
def test_poisoned_constant_never_resolves_to_a_stale_value(src: str) -> None:
    """★名字被二次绑定过，一律不再解析——**绝不用旧值**。

    复审用这几个构造实证过：早先的实现会把它们错误地登记成 'a' 或 'c'。
    根因是「值不同才 pop」不是永久失效（第三次赋值会重新被接受），
    且模块常量表被无差别用于所有作用域。

    ★解析错比不解析更糟：不解析只是落进 unresolved（可见、可人工处理），
      解析错则把一个真实键登记成**错的名字**，基线从此建在错的集合上，而且无声。
    """
    got = _keys(src, "write")
    assert got == set() or "<dynamic>" in {a.key for a in meta_scan.scan_source(src)}, (
        f"被污染的常量被解析成了 {got}——应落 unresolved"
    )
    assert "a" not in got and "c" not in got, f"用了过期的常量值：{got}"


OPEN_WRITE_CASES = [
    pytest.param('def f(result):\n    result.meta = build_meta()', id="整体赋非字典字面量"),
    pytest.param('def f(result, other):\n    result.meta = other', id="整体赋另一个变量"),
    pytest.param('def f(report):\n    report.meta: dict = build_meta()', id="带标注整体赋函数返回值"),
    pytest.param('def f(other):\n    r = AnalyzerResult(meta=other)', id="构造时传非字典"),
]


@pytest.mark.parametrize("src", OPEN_WRITE_CASES)
def test_whole_meta_assignment_from_unknown_source_is_surfaced(src: str) -> None:
    """★整体赋一个键不可知的值，必须进 unresolved，不能静默跳过。

    此前只在右值是字典字面量时登记，右值是函数调用/变量时**什么都不记**——
    于是这类写法既不进 produced、也不进 unresolved，凭空绕过整套契约，
    还会让「已无开放写入」这个结论假成立（复审实测指出）。
    """
    assert _dynamic(src), f"开放的整体写入被静默跳过：{src!r}"


NOT_REPORT_META_CASES = [
    pytest.param('def f():\n    meta: dict = field(default_factory=dict)', id="dataclass 字段声明"),
    pytest.param('def f(x):\n    merged_meta = {"alg": x}\n    return merged_meta',
                 id="碰巧叫 merged_meta 的局部字典"),
    pytest.param('def f(pkt):\n    meta = parse_quic_header(pkt)', id="碰巧叫 meta 的解析结果"),
    pytest.param('def f(tpl, report):\n    return tpl.render(meta=report.meta)',
                 id="模板渲染传参（纯消费）"),
    pytest.param('def f(x):\n    return helper(meta=x)', id="任意函数的 meta= 关键字"),
]


@pytest.mark.parametrize("src", NOT_REPORT_META_CASES)
def test_things_that_merely_look_like_report_meta_are_not_counted(src: str) -> None:
    """★叫 ``meta`` 不等于就是 ``Report.meta``——这类不得计入写入或动态点。

    复审逐项核过：早先版本把 19 处这样的东西报成了「开放整体写入」，其中包括
    dataclass 字段声明、`merge.py` 里碰巧叫 ``merged_meta`` 的 crypto 子字典、
    `pcap_ingest.py` 里的 QUIC 包头解析结果、以及 ``template.render(meta=...)``。

    误报的代价不比漏报小：它会把「哪里还有开放写入」这个判断整个污染掉，
    让人以为有 19 个口子要堵，而真正的口子淹没在噪音里。
    """
    accesses = meta_scan.scan_source(src)
    assert not accesses, f"非 report.meta 的东西被计入了：{accesses}"


def test_same_stem_modules_do_not_share_a_constant_table(tmp_path: Path) -> None:
    """★符号表按完整模块路径建，不用文件名短名。

    本仓真实存在 ``apkscan/commands/corpus.py`` 与 ``apkscan/core/corpus.py``
    （另有三个 ``models.py``）。短名做键会把两张常量表合并，
    后扫描的模块无声覆盖先扫描的，于是跨模块常量键可能解析到**错的值**。
    """
    (tmp_path / "apkscan" / "a").mkdir(parents=True)
    (tmp_path / "apkscan" / "b").mkdir(parents=True)
    (tmp_path / "tests").mkdir()
    (tmp_path / "apkscan" / "a" / "dup.py").write_text('K = "from_a"\n', encoding="utf-8")
    (tmp_path / "apkscan" / "b" / "dup.py").write_text('K = "from_b"\n', encoding="utf-8")
    (tmp_path / "apkscan" / "user.py").write_text(
        "from apkscan.b.dup import K\ndef f(meta):\n    meta[K] = 1\n", encoding="utf-8"
    )

    res = meta_scan.scan_repository(tmp_path)
    assert "from_b" in res.produced, f"跨模块常量解析到了错的表：{sorted(res.produced)}"
    assert "from_a" not in res.produced


def test_constant_resolution_refuses_to_guess() -> None:
    """解析边界必须收窄：认不出就落 unresolved，**绝不猜**。

    重赋值、条件赋值、函数调用产生的键一律不解析——宁可少认，不可猜错：
    猜错会把一个真实键登记成错的名字，比不认更糟（基线从此建在错的集合上）。
    """
    # 重赋值 → 放弃
    src = 'K = "a"\nK = "b"\ndef f(meta):\n    meta[K] = 1\n'
    assert _dynamic(src), "重赋值的常量被猜了一个值"
    # 函数调用产生的键 → 不解析
    src2 = 'def f(meta):\n    meta[make_key()] = 1\n'
    assert _dynamic(src2)


def test_bounded_key_family_is_not_an_open_dynamic_key() -> None:
    """有限键族（``coverage_meta_key(analyzer, "read_failed")``）不算开放动态键。

    ★这四个键记录的是「列举失败 / 文件数被截 / 读取失败 N 份 / 单份内容被截」——
      也就是**「我没看全」**。它们此前是 f-string 动态键，静态扫描认不出，于是既进不了
      契约、也无法被「有没有人消费」的检查覆盖；而缺了它们，「未发现某后端」与
      「确实没有该后端」在报告里长得一模一样。

    收敛成工厂函数后，定义域静态封闭（有限后缀表 × 权威注册表里的分析器名），
    应记为族访问而非 unresolved。
    """
    src = 'def f(result, analyzer):\n    result.meta[coverage_meta_key(analyzer, "read_failed")] = 3\n'
    acc = meta_scan.scan_source(src)
    fams = [a for a in acc if a.key.startswith("<family:")]
    assert fams, "有限键族被当成了开放动态键"
    assert fams[0].key == "<family:web_coverage:read_failed>"
    assert not [a for a in acc if a.key.startswith("<dynamic")], "同一处被重复记成了动态键"


def test_coverage_key_domain_comes_from_registry_not_runtime() -> None:
    """★键族的取值域必须来自**权威分析器注册表**，不是「运行时碰巧跑过的名字」。

    否则一个因能力门控而未运行的分析器会从契约里整个消失，
    它那份「我没看全」的事实也就无从登记——而那恰恰是最该留痕的情形。
    """
    from apkscan.analyzers.web_evidence import COVERAGE_SUFFIXES, iter_coverage_meta_keys
    from apkscan.core.registry import discover_analyzers

    web = sorted(a.name for a in discover_analyzers()
                 if "web" in (getattr(a, "requires", None) or []))
    keys = iter_coverage_meta_keys()
    assert web, "没发现 web 分析器，取值域为空则本条失去意义"
    assert len(keys) == len(web) * len(COVERAGE_SUFFIXES)
    for name in web:  # 每个注册的分析器都必须在键族里，一个都不能少
        for suf in COVERAGE_SUFFIXES:
            assert f"{name}_{suf}" in keys


def test_coverage_key_rejects_suffix_outside_the_family() -> None:
    """表外后缀必须当场拒绝，不能悄悄造出一个契约管不着的键。

    ★这是键族「定义域封闭」的兜底：若手滑写成 ``coverage_meta_key(a, "read_faild")``
      而工厂照单全收，就会凭空产生一个既不在契约、也没人消费的键——
      而它本该承载「我没看全」这类最不该丢的事实。静态扫描只认得族标记，
      拦不住这种拼写错误，只有运行期校验能。
    """
    from apkscan.analyzers.web_evidence import coverage_meta_key

    assert coverage_meta_key("web_inline_config", "read_failed") == "web_inline_config_read_failed"
    with pytest.raises(ValueError):
        coverage_meta_key("web_inline_config", "read_faild")  # 拼写错误
    with pytest.raises(ValueError):
        coverage_meta_key("web_inline_config", "whatever")


@pytest.mark.parametrize("src", DYNAMIC_CASES)
def test_dynamic_keys_are_surfaced_not_dropped(src: str) -> None:
    """★动态键必须记进 unresolved。

    静默跳过等于给「绕过契约」留一条无声的路：写 ``meta[k] = v`` 就能凭空造一个
    不在任何基线里的键，而没有任何检查会红。这与本机制要治的缺陷是同一形态。
    """
    assert _dynamic(src), f"动态键被静默跳过了：{src!r}"


# --- 生产 / 测试消费必须分开 -------------------------------------------------


def test_production_and_test_consumers_are_separated(tmp_path: Path) -> None:
    """★这条锁的是那 66 个「只有测试读」的键。

    若扫描把 tests/ 的读取算作消费方，这批键会假装合格通过检查——
    而它们恰恰是问题最集中的一批（有人写、有测试读、但**产物链路上无人消费**）。
    """
    (tmp_path / "apkscan").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "apkscan" / "w.py").write_text(
        'def f(report):\n    report.meta["only_test_reads"] = 1\n', encoding="utf-8"
    )
    (tmp_path / "tests" / "t.py").write_text(
        'def test_x(report):\n    assert report.meta.get("only_test_reads")\n', encoding="utf-8"
    )

    res = meta_scan.scan_repository(tmp_path)

    assert "only_test_reads" in res.produced
    assert "only_test_reads" in res.test_consumed
    assert "only_test_reads" not in res.production_consumed
    assert "only_test_reads" in res.orphans(), "测试读取被误算成生产消费方"


def test_repository_scan_finds_real_known_keys() -> None:
    """在真仓库上跑一遍，锚定几个已知键，防止扫描器整体失效后所有断言空对空。"""
    root = Path(__file__).resolve().parents[2]
    res = meta_scan.scan_repository(root)

    assert len(res.produced) > 50, f"只扫到 {len(res.produced)} 个 meta 键，扫描器可能整体失效"
    # 这三个键的存在与消费关系是本次调查中人工确认过的事实
    assert "dex_strings_truncated" in res.produced
    assert "dex_strings_truncated" in res.production_consumed  # core/visibility.py 读它
    assert "app_classification" in res.produced


def test_template_scan_catches_jinja_reads() -> None:
    """模板是独立一路证据：本仓模板里有 ``meta.get("uniapp")`` 这类兼容旧键的读法，
    漏扫会把仍在被渲染的键误判成孤儿。"""
    root = Path(__file__).resolve().parents[2]
    tpl_keys = meta_scan.scan_templates(root / "apkscan")
    assert tpl_keys, "模板里一个 meta 读取都没扫到，正则或路径有问题"
