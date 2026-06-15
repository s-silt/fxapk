"""registry 单测：能力探测 + 自动发现的重名/requires 校验（之前零直测，全被 monkeypatch 掩盖）。

不联网、不碰真工具：探测助手全 monkeypatch，确定性。
"""

from __future__ import annotations

import logging

import pytest

from apkscan.core import registry
from apkscan.core.models import AnalyzerResult
from apkscan.core.registry import BaseAnalyzer, _dedup_and_validate, detect_capabilities


# ---------------------------------------------------------------------------
# detect_capabilities：工具探测 + online 派生（真实逻辑，过去恒被 stub）
# ---------------------------------------------------------------------------


def _stub_all_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """把所有工具/设备/网络探测打成"不存在"，便于逐项点亮断言。"""
    monkeypatch.setattr(registry.tools, "has_jadx", lambda: False)
    monkeypatch.setattr(registry.tools, "has_adb", lambda: False)
    monkeypatch.setattr(registry, "_has_network", lambda timeout=2.0: False)
    monkeypatch.setattr(registry.device, "has_frida", lambda: False)
    monkeypatch.setattr(registry.device, "has_frida_dexdump", lambda: False)
    monkeypatch.setattr(registry.device, "has_mitmproxy", lambda: False)
    monkeypatch.setattr(registry.device, "has_device", lambda: False)


def test_detect_capabilities_all_absent_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_all_absent(monkeypatch)
    assert detect_capabilities(online=True) == set()


def test_detect_capabilities_online_false_never_adds_online(monkeypatch: pytest.MonkeyPatch) -> None:
    """online=False 时即便有网也**绝不**加 online（边界，过去无测覆盖）。"""
    _stub_all_absent(monkeypatch)
    monkeypatch.setattr(registry, "_has_network", lambda timeout=2.0: True)  # 有网
    assert "online" not in detect_capabilities(online=False)


def test_detect_capabilities_online_true_with_network(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_all_absent(monkeypatch)
    monkeypatch.setattr(registry, "_has_network", lambda timeout=2.0: True)
    assert "online" in detect_capabilities(online=True)


def test_detect_capabilities_online_true_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_all_absent(monkeypatch)  # _has_network=False
    assert "online" not in detect_capabilities(online=True)


def test_detect_capabilities_jadx_and_adb(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_all_absent(monkeypatch)
    monkeypatch.setattr(registry.tools, "has_jadx", lambda: True)
    monkeypatch.setattr(registry.tools, "has_adb", lambda: True)
    caps = detect_capabilities(online=False)
    assert {"jadx", "adb"} <= caps


def test_detect_capabilities_dynamic(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_all_absent(monkeypatch)
    monkeypatch.setattr(registry.device, "has_frida", lambda: True)
    monkeypatch.setattr(registry.device, "has_device", lambda: True)
    caps = detect_capabilities(online=False)
    assert {"frida", "device"} <= caps
    assert "frida-dexdump" not in caps  # 未点亮的不混入


# ---------------------------------------------------------------------------
# _dedup_and_validate：重名 + requires 拼写错（过去无校验，静默失效）
# ---------------------------------------------------------------------------


class _DupA(BaseAnalyzer):
    name = "dup"

    def analyze(self, ctx: object) -> AnalyzerResult:  # noqa: ARG002
        return AnalyzerResult(analyzer=self.name)


class _DupB(BaseAnalyzer):
    name = "dup"

    def analyze(self, ctx: object) -> AnalyzerResult:  # noqa: ARG002
        return AnalyzerResult(analyzer=self.name)


class _TypoRequires(BaseAnalyzer):
    name = "typo"
    requires = ["jdax"]  # 把 jadx 拼错 → 永久 skip

    def analyze(self, ctx: object) -> AnalyzerResult:  # noqa: ARG002
        return AnalyzerResult(analyzer=self.name)


class _NoName(BaseAnalyzer):
    name = ""

    def analyze(self, ctx: object) -> AnalyzerResult:  # noqa: ARG002
        return AnalyzerResult(analyzer=self.name)


class _GoodReq(BaseAnalyzer):
    name = "good"
    requires = ["apk", "jadx"]  # 全是已知能力

    def analyze(self, ctx: object) -> AnalyzerResult:  # noqa: ARG002
        return AnalyzerResult(analyzer=self.name)


def test_name_collision_keeps_first_and_logs(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.ERROR):
        kept = _dedup_and_validate([_DupA(), _DupB()], kind="分析器")
    assert len(kept) == 1
    assert isinstance(kept[0], _DupA)  # 保留首个
    assert any("name 冲突" in r.message for r in caplog.records)


def test_unknown_requires_logged(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.ERROR):
        kept = _dedup_and_validate([_TypoRequires()], kind="分析器")
    assert len(kept) == 1  # 仍保留（不删，只告警）——但拼写错会被点名
    assert any("未知能力名" in r.message and "jdax" in r.message for r in caplog.records)


def test_empty_name_skipped(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.ERROR):
        kept = _dedup_and_validate([_NoName()], kind="分析器")
    assert kept == []  # 无名分析器被跳过
    assert any("name 为空" in r.message for r in caplog.records)


def test_known_requires_no_warning(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.ERROR):
        kept = _dedup_and_validate([_GoodReq()], kind="分析器")
    assert len(kept) == 1
    assert not any("未知能力名" in r.message for r in caplog.records)


def test_real_discovery_has_no_collisions_or_typos(caplog: pytest.LogCaptureFixture) -> None:
    """真发现一遍内置分析器/富化器：不应触发任何重名或 requires 拼写错告警（守门）。"""
    with caplog.at_level(logging.ERROR):
        analyzers = registry.discover_analyzers()
        enrichers = registry.discover_enrichers()
    assert analyzers and enrichers
    names = [a.name for a in analyzers]
    assert len(names) == len(set(names))  # 无重名
    errors = [r.message for r in caplog.records if r.levelno >= logging.ERROR]
    assert not errors, f"内置分析器/富化器发现期不应有 error：{errors}"
