"""报告的运行溯源锚点：什么时候跑的、在什么环境上跑的。

报告此前记了 tool_version / ruleset_digest / dependency_versions / 各类 hash，唯独缺**时刻**与
**运行环境**。缺时刻的后果实测过：判断一份报告是哪次跑出来的只能看文件 mtime，而云盘同步会改
mtime，等于没有。缺环境的后果是同样本同版本仍可能因 OS / 解释器差异走到不同分支，而锚点看不出来。

★本文件最要紧的一条是隐私不变量：环境快照用**白名单**，绝不带主机名与登录用户名。报告会随案
  流转、会导成 PDF 发出去——机器身份一旦写进去就收不回来了，跟仓库里那条"真实地址别写进去"
  是同一类不可逆错误。
"""

from __future__ import annotations

import json
from datetime import datetime

import pytest

from apkscan.core import pipeline
from apkscan.report.json import to_dict


def _meta(report) -> dict:
    return report.meta


def test_started_at_is_captured_before_any_stage_runs(analyzed_report) -> None:
    """★时刻在流水线入口取，不是在末尾的 credibility 阶段取。

    末尾取到的是"分析结束时间"，差着整段分析时长；对跨机比对同一次运行毫无用处。
    """
    started = _meta(analyzed_report).get("analysis_started_at")
    assert started, "report.meta 缺 analysis_started_at"
    parsed = datetime.fromisoformat(started)
    assert parsed.tzinfo is not None, f"时刻必须带时区偏移，实得 {started!r}"


def test_environment_snapshot_present_and_whitelisted(analyzed_report) -> None:
    """环境快照存在，且字段**只能**是白名单里的那几个。"""
    env = _meta(analyzed_report).get("analysis_environment")
    assert isinstance(env, dict) and env, "report.meta 缺 analysis_environment"
    extra = set(env) - set(pipeline._RUN_ENV_FIELDS)
    assert not extra, f"环境快照混进白名单外的字段：{sorted(extra)}"
    for key in ("os", "python"):
        assert env.get(key), f"环境快照缺 {key}"


def test_environment_never_carries_machine_identity(analyzed_report, monkeypatch) -> None:
    """★隐私不变量：主机名与登录用户名不得出现在报告的任何角落。

    用可辨识的哨兵值替掉 ``platform.node`` 与 ``getpass.getuser``，再把整份报告序列化后全文搜——
    只断言"当前实现没调用它们"是不够的，日后换个 API（``platform.uname()`` 里就带 node）
    照样会漏，全文搜才拦得住。
    """
    import getpass
    import platform as _platform

    monkeypatch.setattr(_platform, "node", lambda: "SENTINEL-HOSTNAME-9c1f")
    monkeypatch.setattr(getpass, "getuser", lambda: "SENTINEL-USERNAME-9c1f")

    env = pipeline._run_environment()
    blob = json.dumps({**to_dict(analyzed_report), "env_recomputed": env}, ensure_ascii=False)
    for sentinel in ("SENTINEL-HOSTNAME-9c1f", "SENTINEL-USERNAME-9c1f"):
        assert sentinel not in blob, f"报告里出现了机器身份：{sentinel}"


def test_run_environment_survives_a_broken_platform_api(monkeypatch) -> None:
    """探测环境绝不能炸主流程：某个 ``platform`` 调用抛了，其余字段照收。"""
    import platform as _platform

    def _boom() -> str:
        raise RuntimeError("platform 探测失败（模拟）")

    monkeypatch.setattr(_platform, "machine", _boom)
    env = pipeline._run_environment()
    assert "machine" not in env
    assert env.get("python"), "单个字段失败不该让整份快照变空"


def test_provenance_fields_round_trip_through_json(analyzed_report) -> None:
    """两个字段要能原样落盘——只在内存里有，等于没记。"""
    payload = to_dict(analyzed_report)
    meta = payload["meta"]
    assert meta.get("analysis_started_at") == _meta(analyzed_report)["analysis_started_at"]
    assert meta.get("analysis_environment") == _meta(analyzed_report)["analysis_environment"]


def test_local_iso_helper_is_unambiguous() -> None:
    """辅助函数本身：秒精度、带偏移、可被 ``fromisoformat`` 读回。"""
    value = pipeline._now_local_iso()
    parsed = datetime.fromisoformat(value)
    assert parsed.tzinfo is not None
    assert parsed.microsecond == 0, f"秒精度即可，实得 {value!r}"


@pytest.fixture(scope="module")
def analyzed_report():
    """跑一次真流水线拿报告——断言必须落在**真实产出**上，不能自己拼一个 meta 糊弄过去。"""
    from apkscan.core.models import AnalysisConfig
    from tests.conftest import FakeContext
    from tests.synthetic.samples import SAMPLES

    sample = SAMPLES[0]
    ctx = FakeContext(dex_strings=sample.dex_strings, files=sample.files)
    return pipeline.run(ctx, AnalysisConfig(online=False))
