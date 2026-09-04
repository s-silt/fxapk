"""两遍富化（attribution → overseas）门控专项测试。

验证合规关键控制（不发真实网络，用假富化器记录被调端点）：
- 第①遍 attribution 富化器对所有目标跑、并据其结果定辖区；
- 第②遍 overseas 第三方数据富化器（shodan/certs）仅对【国外 + 未知】端点跑；
- 辖区内部信号**绝不泄漏**进 ep.enrichment（report.json 不含 _jurisdiction 等内部键）。

★ 本仓已无任何主动探测能力：overseas 富化器均为 active=False，不直连目标业务服务，但会向
第三方数据源提交目标标识。
"""

from __future__ import annotations

import threading

from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.enrichment import enrich_selected_targets
from apkscan.core.pipeline import _run_enrichment
from apkscan.core.registry import BaseEnricher


class _RecordingEnricher(BaseEnricher):
    """记录被调端点 value 的假富化器（线程安全）。"""

    def __init__(self, name: str, phase: str, data: dict | None = None) -> None:
        self.name = name
        self.applies_to = ["ip", "domain"]
        self.phase = phase
        self.active = False  # 不直连目标业务服务；第三方披露边界由对应源说明。
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


def test_two_phase_gating_overseas_foreign_and_unknown_not_domestic() -> None:
    foreign = _ep("evil-us.com")       # 归属美国 → 国外
    domestic = _ep("evil-cnhost.com")  # 归属中国 → 国内
    unknown = _ep("evil-unk.com")      # 无归属信号 → 未知
    targets = [foreign, domestic, unknown]

    attr = _AttrEnricher()
    overseas = _RecordingEnricher("shodan", phase="overseas", data={"ports": [80]})

    _run_enrichment(targets, [attr, overseas])

    # 第②遍境外被动取证：仅【国外 + 未知】（境内走调证、完全不碰）。
    assert overseas.seen == {"evil-us.com", "evil-unk.com"}
    assert "evil-cnhost.com" not in overseas.seen
    assert domestic.enrichment["source_status"]["shodan"] == {
        "status": "skipped",
        "reason": "jurisdiction_gate",
    }

    # 辖区内部信号绝不泄漏进 ep.enrichment（避免进 report.json 被误当 provider）。
    for ep in targets:
        assert "_jurisdiction" not in ep.enrichment
        assert not any(k.startswith("_") for k in ep.enrichment)


def test_two_phase_no_overseas_enrichers_is_noop_beyond_attribution() -> None:
    # 只有 attribution 富化器时，行为退化为单遍（无第②遍）。
    foreign = _ep("evil-us.com")
    attr = _AttrEnricher()
    stats = _run_enrichment([foreign], [attr])
    assert any(s["provider"] == "asn" for s in stats)
    assert "asn" in foreign.enrichment
    assert "_jurisdiction" not in foreign.enrichment


def test_two_phase_conflicting_hosting_signals_remain_eligible_for_followup() -> None:
    endpoint = _ep("mixed.example")
    dns = _RecordingEnricher(
        "dns",
        phase="attribution",
        data={"hosting": [{"ip": "198.51.100.31", "country": "China"}]},
    )
    asn = _RecordingEnricher(
        "asn",
        phase="attribution",
        data={"country": "United States"},
    )
    overseas = _RecordingEnricher("shodan", phase="overseas", data={"ports": [443]})

    _run_enrichment([endpoint], [dns, asn, overseas])

    assert overseas.seen == {"mixed.example"}
    assert endpoint.enrichment["source_status"]["shodan"] == {"status": "hit"}


def test_plain_selected_enrichment_does_not_run_case_close_only_provider() -> None:
    endpoint = _ep("evil-us.com")
    case_only = _RecordingEnricher("case-only", phase="attribution", data={"hit": True})
    case_only.case_close_only = True

    enrich_selected_targets(
        [endpoint],
        [case_only],
        mode="passive",
        include_case_close=False,
    )

    assert case_only.seen == set()
    assert "case-only" not in endpoint.enrichment


def test_apply_forensic_domestic_flip_suppresses_overseas_evidence() -> None:
    # ★ 回归：shodan country 把端点最终翻成「国内」时，该 Lead 不得再挂任何境外被动定位证据行
    #   （合规呈现自洽、可审计）。
    from apkscan.core import infra
    from apkscan.core.leads import _apply_forensic

    ev: list[str] = []
    notes = _apply_forensic(
        infra.ADVICE_INVESTIGATE, "x.com", ev, "",
        shodan={"country": "China", "ip": "198.51.100.32", "ports": [80],
                "services": [{"port": 80, "product": "nginx"}]},
    )
    assert "国内" in notes  # 最终标「国内·可调证」
    assert not any("基础设施候选归属" in e for e in ev)
    assert not any("Shodan 开放端口" in e for e in ev)

    # 对照：归属国外 → 境外基础设施候选证据渲染（候选归属 + 开放端口/服务）。
    ev2: list[str] = []
    _apply_forensic(
        infra.ADVICE_INVESTIGATE, "y.com", ev2, "",
        shodan={"country": "United States", "ip": "198.51.100.48", "ports": [80],
                "services": [{"port": 80, "product": "nginx"}]},
    )
    assert any("基础设施候选归属" in e for e in ev2)
    assert any("Shodan 开放端口" in e for e in ev2)
