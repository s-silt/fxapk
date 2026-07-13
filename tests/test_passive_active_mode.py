"""主动/被动模式硬隔离（代码层强制，非仅文档声明）。

安全边界：passive（默认）绝不调用会**向目标发流量**的主动富化器（active=True，如 webcheck 经
web-check SaaS 对目标 live 探测）；authorized-active 才放行。本测试锁死：
- _mode_gate 谓词：passive/非法值 → 拦 active、放行被动；authorized-active → 全放行。
- _run_enrichment 端到端：passive gate 下 active 富化器**根本不被调用**、也不进 enrichment/统计。
- webcheck 确实声明 active=True（此前错标为继承 False，本修复的核心）。
- CLI --mode 非法值被拒（退出码 2）。
"""

from __future__ import annotations

import threading
from pathlib import Path

from typer.testing import CliRunner

from apkscan import cli
from apkscan.core import pipeline
from apkscan.core.models import (
    ANALYSIS_MODE_AUTHORIZED_ACTIVE,
    ANALYSIS_MODE_PASSIVE,
    Endpoint,
    EnrichmentResult,
)
from apkscan.core.registry import BaseEnricher
from apkscan.enrichers.webcheck import WebCheckEnricher


class _SpyEnricher(BaseEnricher):
    """记录被调用端点的假富化器；active 可配（模拟主动 vs 被动）。"""

    def __init__(self, name: str, *, active: bool) -> None:
        self.name = name
        self.applies_to = ["domain", "ip"]
        self.active = active
        self._lock = threading.Lock()
        self.seen: list[str] = []

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        with self._lock:
            self.seen.append(ep.value)
        return EnrichmentResult(provider=self.name, ok=True, data={"who": ep.value})


# --- _mode_gate 谓词 -------------------------------------------------------


def test_mode_gate_passive_blocks_active_allows_passive() -> None:
    gate = pipeline._mode_gate(ANALYSIS_MODE_PASSIVE)
    ep = Endpoint(value="d.fraud.cn", kind="domain")
    assert gate(ep, _SpyEnricher("act", active=True)) is False
    assert gate(ep, _SpyEnricher("pas", active=False)) is True


def test_mode_gate_authorized_active_allows_active() -> None:
    gate = pipeline._mode_gate(ANALYSIS_MODE_AUTHORIZED_ACTIVE)
    ep = Endpoint(value="d.fraud.cn", kind="domain")
    assert gate(ep, _SpyEnricher("act", active=True)) is True
    assert gate(ep, _SpyEnricher("pas", active=False)) is True


def test_mode_gate_unknown_mode_is_conservatively_passive() -> None:
    # 非法/未知 mode 绝不当成 active 放行——保守按被动拦下主动富化器。
    gate = pipeline._mode_gate("garbage-mode")
    ep = Endpoint(value="d.fraud.cn", kind="domain")
    assert gate(ep, _SpyEnricher("act", active=True)) is False


# --- _run_enrichment 端到端：gate 真正拦住 active ---------------------------


def test_run_enrichment_passive_never_invokes_active() -> None:
    passive = _SpyEnricher("dns_fake", active=False)
    active = _SpyEnricher("webcheck_fake", active=True)
    ep = Endpoint(value="d0.fraud.cn", kind="domain")

    stats = pipeline._run_enrichment(
        [ep], [passive, active], gate=pipeline._mode_gate(ANALYSIS_MODE_PASSIVE)
    )

    assert passive.seen == ["d0.fraud.cn"]  # 被动照跑
    assert active.seen == []  # ★主动**根本没被调用**（零流量到目标）
    assert "webcheck_fake" not in ep.enrichment  # 未写入富化结果
    providers = {s["provider"] for s in stats}
    assert "webcheck_fake" not in providers  # gate-skip 不计统计
    assert "dns_fake" in providers


def test_run_enrichment_authorized_active_invokes_active() -> None:
    passive = _SpyEnricher("dns_fake", active=False)
    active = _SpyEnricher("webcheck_fake", active=True)
    ep = Endpoint(value="d0.fraud.cn", kind="domain")

    pipeline._run_enrichment(
        [ep], [passive, active], gate=pipeline._mode_gate(ANALYSIS_MODE_AUTHORIZED_ACTIVE)
    )

    assert active.seen == ["d0.fraud.cn"]  # 显式授权下主动富化器放行
    assert ep.enrichment["webcheck_fake"]["who"] == "d0.fraud.cn"


def test_run_enrichment_no_gate_defaults_passive_fail_closed() -> None:
    # ★fail-closed：缺 gate → 默认按 passive 拦 active（将来漏传 gate 也得到安全行为，
    #   绝不静默把主动富化器放进被动运行）。
    passive = _SpyEnricher("dns_fake", active=False)
    active = _SpyEnricher("webcheck_fake", active=True)
    ep = Endpoint(value="d0.fraud.cn", kind="domain")
    pipeline._run_enrichment([ep], [passive, active])  # 不传 gate
    assert passive.seen == ["d0.fraud.cn"]
    assert active.seen == []  # 缺 gate 也拦住 active


# --- webcheck 错标修复 -----------------------------------------------------


def test_webcheck_declares_active_true() -> None:
    # ★本修复核心：webcheck 经 SaaS 对目标 live 探测，是本仓唯一主动富化器，必须 active=True
    #   （此前继承 BaseEnricher 默认 False，被 passive 模式误放行）。
    assert WebCheckEnricher().active is True


def test_all_other_enrichers_are_passive() -> None:
    # 防回归：除 webcheck 外，自动发现的富化器都应是被动（active 为假）。若将来新增主动富化器，
    # 必须显式 active=True 并在此更新白名单——强制作者对"是否碰目标"表态。
    from apkscan.core.registry import discover_enrichers

    active_names = {
        e.name for e in discover_enrichers() if getattr(e, "active", False)
    }
    assert active_names == {"webcheck"}, f"意外的主动富化器：{active_names - {'webcheck'}}"


# --- ctx.config 与 pipeline config 一致性（codex 复审加固）------------------


def test_pipeline_canonicalizes_ctx_config_to_run_config(fake_ctx, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # ★分析器读 ctx.config、pipeline 门控/报告读 config 参数——二者不一致时以 pipeline 的 config 为准
    #   对齐 ctx，防"报告标 passive 但分析器（contacts getMe）按 ctx.config 的 authorized-active 主动
    #   探测"的错配。
    from apkscan.core.models import AnalysisConfig

    monkeypatch.setattr(pipeline, "discover_analyzers", lambda: [])
    monkeypatch.setattr(pipeline, "discover_enrichers", lambda: [])
    monkeypatch.setattr(pipeline, "detect_capabilities", lambda online=True: set())

    fake_ctx.config = AnalysisConfig(online=False, mode=ANALYSIS_MODE_AUTHORIZED_ACTIVE)  # ctx 侧不一致
    run_cfg = AnalysisConfig(online=False, mode=ANALYSIS_MODE_PASSIVE)
    report = pipeline.run(fake_ctx, run_cfg)

    assert fake_ctx.config is run_cfg  # 已对齐：分析器现在看到 pipeline 的 config
    assert report.meta["mode"] == ANALYSIS_MODE_PASSIVE  # 报告与分析器 mode 一致，无分叉


# --- contacts.py Telegram getMe：主动探测同样受 mode 门控 ------------------


class _FakeCfg:
    def __init__(self, online: bool, mode: str) -> None:
        self.online = online
        self.mode = mode


class _FakeCtx:
    def __init__(self, online: bool, mode: str) -> None:
        self.config = _FakeCfg(online, mode)


def test_getme_skipped_in_passive_mode_even_online(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # ★passive（默认）：即便 online 也不发 getMe（用接料人 token 触其 live bot=主动侦察）。
    from apkscan.analyzers.contacts import ContactsAnalyzer

    called = {"getme": False}

    def _boom(_self: object, _token: str) -> str | None:
        called["getme"] = True  # 不应被调用
        return "should_not_run"

    monkeypatch.setattr(ContactsAnalyzer, "_getme_username", _boom)
    note = ContactsAnalyzer()._maybe_getme("123:abc", _FakeCtx(online=True, mode=ANALYSIS_MODE_PASSIVE))
    assert called["getme"] is False  # 主动探测未发
    assert "passive" in note and "authorized-active" in note


def test_getme_runs_in_authorized_active(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from apkscan.analyzers.contacts import ContactsAnalyzer

    monkeypatch.setattr(ContactsAnalyzer, "_getme_username", lambda _self, _token: "fraudbot")
    note = ContactsAnalyzer()._maybe_getme(
        "123:abc", _FakeCtx(online=True, mode=ANALYSIS_MODE_AUTHORIZED_ACTIVE)
    )
    assert "fraudbot" in note  # 显式授权下才在线核验


# --- CLI --mode 校验 -------------------------------------------------------


def test_cli_analyze_rejects_invalid_mode(tmp_path: Path) -> None:
    dummy = tmp_path / "x.apk"
    dummy.write_bytes(b"PK\x03\x04")  # 存在即可（mode 校验在 load 之前）
    res = CliRunner().invoke(cli.app, ["analyze", str(dummy), "--mode", "bogus"])
    assert res.exit_code == 2
    assert "--mode" in res.output
