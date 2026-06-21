"""两遍富化（attribution→attack_surface）门控专项测试。

验证合规关键控制（不发真实网络，用假富化器记录被调端点）：
- 第①遍 attribution 富化器对所有目标跑、并据其结果定辖区；
- 第②遍 attack_surface **被动**富化器仅对【国外+未知】端点跑（境内不碰）；
- 第②遍 **主动探测**（active=True）富化器**仅对【国外】**端点跑（未知也不主动触达）；
- 辖区内部信号**绝不泄漏**进 ep.enrichment（report.json 不含 _jurisdiction 等内部键）。
"""

from __future__ import annotations

import threading

from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.pipeline import _run_enrichment
from apkscan.core.registry import BaseEnricher


class _RecordingEnricher(BaseEnricher):
    """记录被调端点 value 的假富化器（线程安全）。"""

    def __init__(self, name: str, phase: str, active: bool, data: dict | None = None) -> None:
        self.name = name
        self.applies_to = ["ip", "domain"]
        self.phase = phase
        self.active = active
        self._data = data or {}
        self.seen: set[str] = set()
        self._lock = threading.Lock()

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        with self._lock:
            self.seen.add(ep.value)
        return EnrichmentResult(provider=self.name, ok=True, data=dict(self._data))


class _AttrEnricher(BaseEnricher):
    """第①遍归属富化器：据端点 value 给归属国（驱动辖区判定）。name=asn 落入 classify 读取的键。"""

    name = "asn"
    applies_to = ["ip", "domain"]
    phase = "attribution"
    active = False

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        v = ep.value
        if "us" in v:
            data = {"country": "United States"}  # → 国外
        elif "cnhost" in v:
            data = {"country": "China"}  # → 国内
        else:
            data = {}  # 无归属国信号 → 未知
        return EnrichmentResult(provider="asn", ok=True, data=data)


def _ep(value: str) -> Endpoint:
    return Endpoint(value=value, kind="domain", evidences=[])


def test_two_phase_gating_active_foreign_only_passive_foreign_and_unknown() -> None:
    foreign = _ep("evil-us.com")     # 归属美国 → 国外
    domestic = _ep("evil-cnhost.com")  # 归属中国 → 国内
    unknown = _ep("evil-unk.com")    # 无归属信号 → 未知
    targets = [foreign, domestic, unknown]

    attr = _AttrEnricher()
    passive = _RecordingEnricher("shodan", phase="attack_surface", active=False, data={"ports": [80]})
    active = _RecordingEnricher("recon", phase="attack_surface", active=True, data={"open_ports": [80]})

    _run_enrichment(targets, [attr, passive, active])

    # 第①遍归属对所有目标跑。
    # 被动攻击面：国外 + 未知（境内不碰）。
    assert passive.seen == {"evil-us.com", "evil-unk.com"}
    # 主动探测：仅国外（未知也不主动触达，境内不碰）。
    assert active.seen == {"evil-us.com"}
    # 境内端点完全不进第②遍。
    assert "evil-cnhost.com" not in passive.seen
    assert "evil-cnhost.com" not in active.seen

    # 辖区内部信号绝不泄漏进 ep.enrichment（避免进 report.json 被误当 provider）。
    for ep in targets:
        assert "_jurisdiction" not in ep.enrichment
        assert not any(k.startswith("_") for k in ep.enrichment)


def test_two_phase_no_attack_surface_enrichers_is_noop_beyond_attribution() -> None:
    # 只有 attribution 富化器时，行为退化为单遍（无第②遍）。
    foreign = _ep("evil-us.com")
    attr = _AttrEnricher()
    stats = _run_enrichment([foreign], [attr])
    assert any(s["provider"] == "asn" for s in stats)
    assert "asn" in foreign.enrichment
    assert "_jurisdiction" not in foreign.enrichment


def test_active_recon_tier_gated_even_when_foreign() -> None:
    # ★ 回归（review high）：库内置档（tier=library-file）端点最终判"待核"，即便辖区=国外也绝不主动探测。
    # 该域名 classify=建议调证、归属美国→国外，但 tier=library-file → effective_advice=待核 → active gate 拦下。
    lib_foreign = Endpoint(
        value="lib-us-c2.com", kind="domain", evidences=[], enrichment={"tier": "library-file"}
    )
    attr = _AttrEnricher()
    passive = _RecordingEnricher("shodan", phase="attack_surface", active=False, data={"ports": [80]})
    active = _RecordingEnricher("recon", phase="attack_surface", active=True, data={"open_ports": [80]})

    _run_enrichment([lib_foreign], [attr, passive, active])

    # 被动攻击面：国外端点仍跑（被动无 tier 闸、零目标流量、无害）。
    assert "lib-us-c2.com" in passive.seen
    # 主动探测：被 tier 闸拦下（最终待核，不建议调证）→ 绝不主动触网。
    assert "lib-us-c2.com" not in active.seen


def test_apply_forensic_domestic_flip_suppresses_attack_surface_and_recon() -> None:
    # ★ 回归（review high #3/#9）：shodan country 把端点最终翻成「国内」时，
    # 该 Lead 不得再挂任何攻击面/主动探测证据行（合规呈现自洽、可审计）。
    from apkscan.core import infra
    from apkscan.core.pipeline import _apply_forensic

    ev: list[str] = []
    notes = _apply_forensic(
        infra.ADVICE_INVESTIGATE, "x.com", ev, "",
        shodan={"country": "China", "ports": [80], "services": [{"port": 80, "product": "nginx"}]},
        recon={"open_ports": [80], "services": [{"port": 80, "service": "HTTP"}]},
    )
    assert "国内" in notes  # 最终标「国内·可调证」
    assert not any("Shodan 暴露面" in e for e in ev)
    assert not any("主动探测" in e for e in ev)

    # 对照：归属国外 → 攻击面 + 主动探测证据都渲染。
    ev2: list[str] = []
    _apply_forensic(
        infra.ADVICE_INVESTIGATE, "y.com", ev2, "",
        shodan={"country": "United States", "ports": [80], "services": [{"port": 80, "product": "nginx"}]},
        recon={"open_ports": [80], "services": [{"port": 80, "service": "HTTP"}]},
    )
    assert any("Shodan 暴露面" in e for e in ev2)
    assert any("主动探测" in e for e in ev2)
