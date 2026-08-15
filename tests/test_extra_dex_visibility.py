"""额外 DEX（脱壳产物）的加载账目：请求了几个 vs 真解析成功几个。

★为什么要单独一组测试：实测两个样本各 dump 出 33 个 DEX，androguard 因不认
Android 10+ 的 hidden-api flag 抛 ValueError，各只成功解析 10 个。而当时的输出是
"额外 DEX：33 个并入静态分析" + "ran=35 skipped=0 error=0" —— 读报告的人没有任何
线索能察觉两成输入根本没进来。
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from apkscan.core.apk import _load_extra_dex, build_extra_dex_report


def test_load_extra_dex_reports_failures_with_digest(tmp_path: Path) -> None:
    """坏 DEX 不炸主流程，但必须留下 path / sha256 / 错误类型。"""
    good = tmp_path / "classes.dex"
    bad = tmp_path / "classes02.dex"
    # 不构造合法 DEX——两个都会解析失败，这里要断言的是失败**被记下来**而不是被吞掉。
    good.write_bytes(b"dex\n035\x00" + b"\x00" * 64)
    bad.write_bytes(b"not a dex at all")

    loaded, failures = _load_extra_dex([str(good), str(bad)])

    assert len(loaded) + len(failures) == 2, "每个输入都要有下落，不能凭空消失"
    assert failures, "解析失败必须被记录，不能只落日志"
    for item in failures:
        assert item["path"]
        assert item["error_type"]
        assert len(item["sha256"]) == 64, "失败文件要留 sha256，便于回溯是哪一份"

    bad_entry = next(f for f in failures if f["path"] == str(bad))
    assert bad_entry["sha256"] == hashlib.sha256(b"not a dex at all").hexdigest()


def test_load_extra_dex_missing_file_is_recorded_not_swallowed(tmp_path: Path) -> None:
    _loaded, failures = _load_extra_dex([str(tmp_path / "nope.dex")])
    assert len(failures) == 1
    assert failures[0]["error_type"] in {"FileNotFoundError", "OSError"}


def test_build_report_counts_and_completeness() -> None:
    report = build_extra_dex_report(
        [f"/dump/classes{i}.dex" for i in range(33)],
        loaded=10,
        failures=[
            {"path": f"/dump/classes{i}.dex", "sha256": "x" * 64,
             "error_type": "ValueError", "error": "not a valid HiddenApiClassDataItem"}
            for i in range(23)
        ],
    )
    assert report["requested"] == 33
    assert report["loaded"] == 10
    assert report["failed"] == 23
    assert report["complete"] is False
    assert report["failures_by_error"] == {"ValueError": 23}
    # 失败明细不逐条塞进 meta（成批失败会把 meta 撑肿），只留样例
    assert len(report["failure_samples"]) <= 10  # type: ignore[arg-type]


def test_build_report_complete_only_when_nothing_failed() -> None:
    assert build_extra_dex_report(["a.dex"], loaded=1, failures=[])["complete"] is True
    assert build_extra_dex_report([], loaded=0, failures=[])["complete"] is False


def test_pipeline_writes_extra_dex_visibility_into_meta() -> None:
    """★接线断言：ctx 上的账目要真的走进 report.meta，否则下游读不到。

    用真的 ``_PipelineState`` 构造（而非鸭子类型的替身）：该 stage 的降级判读按 ``state.platform``
    分流，替身少一个字段就测不到生产路径走的那条分支。
    """
    from types import SimpleNamespace

    from apkscan.core.models import AnalysisConfig
    from apkscan.core.pipeline import _PipelineState, _stage_degradation_flags

    state = _PipelineState(
        ctx=SimpleNamespace(  # type: ignore[arg-type]  # 本 stage 只 getattr 这几项
            dex_available=True,
            apk_validation_ok=True,
            extra_dex_report={
                "requested": 33, "loaded": 10, "failed": 23, "complete": False,
                "failures_by_error": {"ValueError": 23}, "failure_samples": [],
            },
        ),
        config=AnalysisConfig(online=False),
        platform="android",
        capabilities=set(),
    )
    _stage_degradation_flags(state)

    assert state.meta["extra_dex_visibility"]["failed"] == 23
    assert state.meta["extra_dex_visibility"]["loaded"] == 10


def test_cli_reports_after_loading_not_before(capsys: Any) -> None:
    """★不能在加载前宣布"N 个并入"——那是替结果打包票。"""
    from apkscan.cli import _echo_extra_dex_result

    _echo_extra_dex_result({
        "requested": 33, "loaded": 10, "failed": 23,
        "failures_by_error": {"ValueError": 23}, "failure_samples": [],
    })
    out = capsys.readouterr().out
    assert "发现 33" in out and "成功并入 10" in out and "失败 23" in out
    assert "ValueError" in out

    _echo_extra_dex_result({
        "requested": 5, "loaded": 5, "failed": 0,
        "failures_by_error": {}, "failure_samples": [],
    })
    out = capsys.readouterr().out
    assert "5 个已并入" in out
