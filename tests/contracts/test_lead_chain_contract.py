"""契约 A：Lead 生产链的必经四步 —— 主契约 + 扫描器自身的测试。

★本文件锁两层东西，缺一层都会假绿：

1. **主契约**：生产代码里每个 ``build_endpoint_leads`` 调用点，同一函数作用域
   （或一跳同模块 helper）内必须齐备另外三步且顺序正确。
2. **路径登记表**（防空转）：已知调用点与现实**双向严格相等**。扫描器若因写法漂移
   而失明，发现 0 个调用点 → 0 条违规 → 主契约假绿；登记表在那一刻红。
   新增第四条生产路径同样在这里红——不是违规，是要求作者**有意识地登记**：
   新路径把 Lead 送进出口，就要连四步一起接（这次事故正是「接出口忘接隔离」）。
3. **扫描器原语**：每种「该红的形态」都有自己的测试——扫描器漏认一种，
   那种写法的缺步就永远无声（与 meta_scan/test_meta_scan 同一纪律）。
"""

from __future__ import annotations

import functools
from pathlib import Path

from tests.contracts import lead_chain_scan
from tests.contracts.lead_chain_scan import STEP_ORDER, ChainScan, scan_source


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


@functools.lru_cache(maxsize=None)
def _repo_scan() -> ChainScan:
    return lead_chain_scan.scan_repository(_repo_root())


# --- 主契约 -----------------------------------------------------------------


def test_every_lead_production_path_runs_all_four_steps() -> None:
    """★主契约。红的时候逐条指名：哪个文件哪个函数缺哪一步、缺它的后果是什么。

    修法永远是**补上缺的那一步**（参照三条既有路径的写法），或在确实不进
    report.leads 出口的路径上加 ``# lead-chain: exempt <理由>`` 显式豁免——
    绝不是改扫描器让它闭嘴。
    """
    scan = _repo_scan()
    assert not scan.violations, (
        "Lead 生产链契约违规（四步：build_endpoint_leads → _apply_default_advice → "
        "seal_base_advice → apply_repack_quarantine）：\n  "
        + lead_chain_scan.format_violations(scan.violations)
    )


#: 已知生产路径登记表：(文件, 函数)。★这不是主契约的执行清单（调用点靠发现，
#: 新路径缺步照样被主契约抓）；它是**防扫描器失明的地板** + 新路径的登记闸：
#: 出现第 4 条路径时这里红，作者更新登记表的那一下就是「我知道我在新接一条
#: 进出口的 Lead 路径」的显式确认。
_KNOWN_PATHS = {
    ("apkscan/core/pipeline.py", "_stage_build_leads"),      # 静态主链
    ("apkscan/dynamic/merge.py", "_build_runtime_leads"),    # 动态回灌
    ("apkscan/cli.py", "_merge_config_probe_into_report"),   # config-probe 跨轮回灌
}


def test_production_path_registry_matches_reality_both_ways() -> None:
    scan = _repo_scan()
    actual = {(s.file, s.function) for s in scan.sites}
    added = actual - _KNOWN_PATHS
    removed = _KNOWN_PATHS - actual
    problems = [f"新增生产路径（确认四步已接齐后登记进 _KNOWN_PATHS）：{p}" for p in sorted(added)]
    problems += [f"路径已消失（有意删除/改名请从 _KNOWN_PATHS 注销）：{p}" for p in sorted(removed)]
    assert not problems, "\n  ".join(problems)


def test_no_exemptions_expected_today() -> None:
    """当前生产代码应为 0 个豁免——三条路径都已补齐四步。将来出现豁免时
    把这里改成逐条登记（理由必须写在生产代码的 def 行上，这里只锁数量），
    别静默放行。"""
    scan = _repo_scan()
    assert scan.exemptions == [], [
        f"{site.file}::{site.function}: {reason}" for site, reason in scan.exemptions
    ]


# --- 扫描器原语：每种「该红的形态」都要有自己的测试 -------------------------


_FOUR_STEPS_OK = """
def path(eps, meta, leads):
    leads.extend(build_endpoint_leads(eps))
    _apply_default_advice(leads)
    seal_base_advice(leads)
    apply_repack_quarantine(leads, meta)
"""


def _violations(src: str) -> ChainScan:
    return scan_source(src, "apkscan/x.py")


def test_full_chain_is_clean() -> None:
    scan = _violations(_FOUR_STEPS_OK)
    assert scan.violations == []
    assert [(s.function, s.line) for s in scan.sites] == [("path", 3)]


def test_missing_quarantine_is_named_with_consequence() -> None:
    """★这次事故的形态：只做前三步。报错必须指名文件/函数/缺的步骤和后果。"""
    src = """
def merge_probe(eps, meta, leads):
    leads.extend(build_endpoint_leads(eps))
    _apply_default_advice(leads)
    seal_base_advice(leads)
"""
    scan = _violations(src)
    assert len(scan.violations) == 1
    v = scan.violations[0]
    assert v.kind == "missing-step"
    assert v.function == "merge_probe"
    assert "apply_repack_quarantine" in v.detail
    assert "被仿冒" in v.detail, "报错必须带后果，不能只丢函数名"


def test_each_missing_step_is_reported_separately() -> None:
    src = """
def bare(eps, leads):
    leads.extend(build_endpoint_leads(eps))
"""
    scan = _violations(src)
    missing = {v.detail.split("。")[0] for v in scan.violations if v.kind == "missing-step"}
    assert missing == {f"缺 {s}" for s in STEP_ORDER}


def test_one_hop_helper_satisfies_a_step() -> None:
    """merge.py 的真实形态：quarantine 在直接调用的同模块 helper 里。"""
    src = """
def _quarantine(report, leads):
    pipeline.apply_repack_quarantine(leads, report.meta)

def path(report, eps):
    new = pipeline.build_endpoint_leads(eps)
    pipeline._apply_default_advice(new)
    seal_base_advice(new)
    _quarantine(report, new)
"""
    assert _violations(src).violations == []


def test_two_hops_are_not_followed() -> None:
    """★边界如实：两跳追不了（静态追多跳不可靠），必须红——收拢结构或显式豁免。"""
    src = """
def _inner(leads, meta):
    apply_repack_quarantine(leads, meta)

def _outer(report, leads):
    _inner(leads, report.meta)

def path(report, eps):
    new = build_endpoint_leads(eps)
    _apply_default_advice(new)
    seal_base_advice(new)
    _outer(report, new)
"""
    scan = _violations(src)
    assert [v.kind for v in scan.violations] == ["missing-step"]
    assert "apply_repack_quarantine" in scan.violations[0].detail


def test_steps_in_outer_scope_do_not_cover_nested_call_site() -> None:
    """★边界如实：入口藏在嵌套函数里、步骤在外层——按最内层作用域计，红。
    这种拆法让「哪一批 leads 走了四步」在静态上不可判，红了要求收拢。"""
    src = """
def outer(eps, meta, leads):
    def inner():
        return build_endpoint_leads(eps)
    leads.extend(inner())
    _apply_default_advice(leads)
    seal_base_advice(leads)
    apply_repack_quarantine(leads, meta)
"""
    scan = _violations(src)
    assert {v.function for v in scan.violations} == {"inner"}
    assert len(scan.violations) == 3


def test_wrong_order_is_flagged() -> None:
    """顺序即判据：seal 晚于 quarantine 会把抑制后的档位烙进 base_advice。"""
    src = """
def path(eps, meta, leads):
    leads.extend(build_endpoint_leads(eps))
    _apply_default_advice(leads)
    apply_repack_quarantine(leads, meta)
    seal_base_advice(leads)
"""
    scan = _violations(src)
    assert [v.kind for v in scan.violations] == ["order"]
    assert "seal_base_advice" in scan.violations[0].detail


def test_indirect_reference_is_flagged_not_ignored() -> None:
    """入口被取值（赋变量/传参）→ 数据流追不了 → 必须可见地红，绝不静默放过。"""
    src = """
def path(eps):
    fn = build_endpoint_leads
    return fn(eps)
"""
    scan = _violations(src)
    assert [v.kind for v in scan.violations] == ["indirect-ref"]
    assert scan.sites == []


def test_module_level_call_is_flagged() -> None:
    scan = _violations("leads = build_endpoint_leads(eps)\n")
    assert [v.kind for v in scan.violations] == ["module-level-call"]


def test_mentions_in_docstring_and_comment_are_not_call_sites() -> None:
    src = '''
def doc():
    """build_endpoint_leads 只是被提及，不是调用。"""
    # build_endpoint_leads 注释也不是
    return 1
'''
    scan = _violations(src)
    assert scan.sites == []
    assert scan.violations == []


def test_entry_functions_own_recursion_is_not_a_site() -> None:
    """入口函数自身（含递归重构）不是消费路径，不得被要求四步。"""
    src = """
def build_endpoint_leads(eps):
    if not eps:
        return []
    return build_endpoint_leads(eps[:1])
"""
    scan = _violations(src)
    assert scan.sites == []
    assert scan.violations == []


def test_exemption_with_reason_is_recorded_and_skipped() -> None:
    src = """
def probe(eps):  # lead-chain: exempt 产出不进 report.leads，仅本地比对
    return build_endpoint_leads(eps)
"""
    scan = _violations(src)
    assert scan.violations == []
    assert len(scan.exemptions) == 1
    site, reason = scan.exemptions[0]
    assert site.function == "probe"
    assert "不进 report.leads" in reason


def test_exemption_without_reason_is_a_violation() -> None:
    src = """
def probe(eps):  # lead-chain: exempt
    return build_endpoint_leads(eps)
"""
    scan = _violations(src)
    assert [v.kind for v in scan.violations] == ["exempt-no-reason"]


def test_stale_exemption_is_a_violation() -> None:
    src = """
def unrelated(x):  # lead-chain: exempt 旧理由
    return x + 1
"""
    scan = _violations(src)
    assert [v.kind for v in scan.violations] == ["stale-exempt"]


def test_attribute_form_entry_and_steps_are_recognized() -> None:
    """pipeline.build_endpoint_leads / pipeline._apply_default_advice 这类
    模块前缀调用（merge.py 的真实写法）必须与裸名同等对待。"""
    src = """
def path(eps, meta, leads):
    leads.extend(pipeline.build_endpoint_leads(eps))
    pipeline._apply_default_advice(leads)
    models.seal_base_advice(leads)
    pipeline.apply_repack_quarantine(leads, meta)
"""
    scan = _violations(src)
    assert scan.violations == []
    assert len(scan.sites) == 1
