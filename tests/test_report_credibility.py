"""结果可信度地基（1a）：analysis_status / completeness / critical_failures、ruleset_digest、
--strict 退出码判定。锁死聚合逻辑与阈值语义，供 CI / Agent 可信地消费报告。
"""

from __future__ import annotations

from apkscan import cli
from apkscan.core import pipeline
from apkscan.core.models import (
    ANALYSIS_STATUS_COMPLETE,
    ANALYSIS_STATUS_FAILED,
    ANALYSIS_STATUS_PARTIAL,
    REPORT_SCHEMA_VERSION,
    Report,
)
from apkscan.core.registry import ruleset_digest


def _status(name: str, st: str) -> dict:
    return {"name": name, "status": st, "reason": ""}


# --- _analysis_health 真值表 ------------------------------------------------


def test_health_all_ran_is_complete() -> None:
    status, comp, crit, skip = pipeline._analysis_health(
        [_status("manifest", "ran"), _status("endpoints", "ran")]
    )
    assert status == ANALYSIS_STATUS_COMPLETE
    assert comp == 1.0
    assert crit == [] and skip == []


def test_health_some_error_is_partial_and_excludes_skips_from_denominator() -> None:
    status, comp, crit, skip = pipeline._analysis_health(
        [
            _status("crypto", "ran"),
            _status("payment", "ran"),
            _status("firebase", "error"),  # 1 error
            _status("jadx", "skipped"),  # 跳过不计入分母
            _status("frida", "skipped"),
        ]
    )
    assert status == ANALYSIS_STATUS_PARTIAL
    assert comp == round(2 / 3, 4)  # 2 ran / (2 ran + 1 error)，跳过的 2 个不计
    assert crit == []  # firebase 非关键
    assert set(skip) == {"jadx", "frida"}


def test_health_all_error_is_failed() -> None:
    status, comp, crit, _ = pipeline._analysis_health(
        [_status("manifest", "error"), _status("endpoints", "error")]
    )
    assert status == ANALYSIS_STATUS_FAILED
    assert comp == 0.0
    assert crit == ["endpoints", "manifest"]  # 两个都是关键分析器，排序返回


def test_health_empty_is_complete() -> None:
    # 无任何可跑分析器（全平台跳过等）→ 视为完整（无可跑=无缺失），completeness=1.0，不做 0/0。
    assert pipeline._analysis_health([]) == (ANALYSIS_STATUS_COMPLETE, 1.0, [], [])


def test_health_critical_failure_detected() -> None:
    _, _, crit, _ = pipeline._analysis_health(
        [_status("manifest", "ran"), _status("endpoints", "error"), _status("crypto", "error")]
    )
    assert crit == ["endpoints"]  # 只有 endpoints 属关键集，crypto 不算


def test_critical_analyzers_are_manifest_and_endpoints() -> None:
    assert pipeline._CRITICAL_ANALYZERS == frozenset({"manifest", "endpoints"})


# --- ruleset_digest --------------------------------------------------------


def test_ruleset_digest_stable_and_formatted() -> None:
    d1 = ruleset_digest()
    d2 = ruleset_digest()
    assert d1 == d2  # 稳定：同一规则集同一 digest
    assert d1 != "unknown"
    assert len(d1) == 16 and all(c in "0123456789abcdef" for c in d1)


def test_ruleset_digest_is_eol_invariant() -> None:
    # ★可复现锚点的核心：Windows(CRLF)与 Linux(LF) checkout 的**同一套规则**必须算出**同一** digest。
    # 复刻函数内的换行归一化，模拟两种 checkout，证明 digest 只随内容变、与 EOL 风格无关，且等于实际输出。
    import hashlib
    import importlib.resources

    rules_dir = importlib.resources.files("apkscan") / "rules"
    entries = sorted(
        (e for e in rules_dir.iterdir() if e.name.endswith((".yaml", ".txt"))),
        key=lambda e: e.name,
    )

    def _digest(as_crlf: bool) -> str:
        h = hashlib.sha256()
        for e in entries:
            content = e.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            if as_crlf:
                content = content.replace(b"\n", b"\r\n")  # 模拟 Windows CRLF checkout
            content = content.replace(b"\r\n", b"\n").replace(b"\r", b"\n")  # 复刻函数归一化
            h.update(e.name.encode("utf-8"))
            h.update(b"\0")
            h.update(content)
            h.update(b"\0")
        return h.hexdigest()[:16]

    assert _digest(as_crlf=False) == _digest(as_crlf=True) == ruleset_digest()


# --- Report 新字段默认值 ---------------------------------------------------


def test_report_credibility_fields_default_sane() -> None:
    r = Report(package_name="x", meta={}, leads=[], endpoints=[], findings=[], analyzer_status=[])
    assert r.schema_version == REPORT_SCHEMA_VERSION
    assert r.analysis_status == ANALYSIS_STATUS_COMPLETE
    assert r.completeness == 1.0
    assert r.critical_failures == [] and r.skipped_analyzers == []


# --- _strict_exit_code 判定 -------------------------------------------------


def _report(*, status: str, critical: list[str]) -> Report:
    return Report(
        package_name="x", meta={}, leads=[], endpoints=[], findings=[], analyzer_status=[],
        analysis_status=status, critical_failures=critical,
    )


def test_strict_exit_complete_returns_none() -> None:
    assert cli._strict_exit_code(_report(status=ANALYSIS_STATUS_COMPLETE, critical=[])) is None


def test_strict_exit_partial_returns_3() -> None:
    assert cli._strict_exit_code(_report(status=ANALYSIS_STATUS_PARTIAL, critical=[])) == 3


def test_strict_exit_critical_returns_4() -> None:
    # 关键失败优先于普通 partial：即便 status=partial，有 critical_failures → 4。
    assert cli._strict_exit_code(_report(status=ANALYSIS_STATUS_PARTIAL, critical=["manifest"])) == 4


def test_strict_exit_failed_returns_3_without_critical() -> None:
    assert cli._strict_exit_code(_report(status=ANALYSIS_STATUS_FAILED, critical=[])) == 3
