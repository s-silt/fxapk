"""config-chain 层⑦：第一方资产评分测试。

覆盖：各加权信号累加（APK引用/运行时/配置出现/业务路径/自有后端）、公共 SDK-CDN 减分、IP 公共边缘减分、
rank_assets 降序、pipeline 附加阶段写 meta["asset_scores"]。纯离线。
"""

from __future__ import annotations

from apkscan.config.asset_score import AssetScore, rank_assets, score_asset
from apkscan.core import pipeline
from apkscan.core.models import AnalysisConfig, Endpoint, Evidence


def _ep(value, kind, sources=(), enrichment=None):
    return Endpoint(
        value=value, kind=kind,
        evidences=[Evidence(source=s, location="x") for s in sources],
        enrichment=enrichment or {},
    )


def test_all_signals_accumulate_for_own_backend() -> None:
    ep = _ep(
        "api.evil-c2.com", "domain",
        sources=("dex", "runtime-pcap", "remote-config"),
        enrichment={"runtime": {"business_api_paths": ["/api/order"]}},
    )
    s = score_asset(ep)
    # 30(apk) + 20(runtime) + 15(config) + 10(business) + 10(own-backend/建议调证) = 85
    assert s.score == 85
    joined = " ".join(s.reasons)
    assert "apk-code-ref+30" in joined and "runtime-access+20" in joined
    assert "config-appearance+15" in joined and "business-path+10" in joined and "own-backend+10" in joined


def test_public_sdk_cdn_domain_penalized() -> None:
    s = score_asset(_ep("at.alicdn.com", "domain", sources=("dex",)))  # iconfont CDN → 无需调证
    assert s.score == 30 - 40  # apk-ref +30，public-infra -40 → -10
    assert any("public-infra-40" in r for r in s.reasons)


def test_login_path_alone_counts_as_business() -> None:
    ep = _ep("api.evil-c2.com", "domain", sources=("remote-config",),
             enrichment={"runtime": {"login_paths": ["/login"]}})
    s = score_asset(ep)
    # 15(config) + 10(business) + 10(own-backend) = 35
    assert s.score == 35


def test_ip_with_edge_attribution_penalized() -> None:
    ip = _ep("1.2.3.4", "ip", sources=("runtime-pcap",),
             enrichment={"attribution": {"ips": [{"ip": "1.2.3.4", "edge_provider": {"tier": "confirmed"}}]}})
    s = score_asset(ip)
    assert s.score == 20 - 40  # runtime +20，public-edge -40 → -20
    assert any("public-edge-40" in r for r in s.reasons)


def test_ip_without_edge_is_neutral_infra() -> None:
    ip = _ep("1.2.3.4", "ip", sources=("runtime-pcap",),
             enrichment={"attribution": {"ips": [{"ip": "1.2.3.4", "hosting_provider": {"category": "idc"}}]}})
    assert score_asset(ip).score == 20  # 无 edge → 无公共边缘减分


def test_rank_assets_sorts_descending_and_skips_urls() -> None:
    own = _ep("api.evil-c2.com", "domain", sources=("dex",))     # 30 + 10 = 40
    pub = _ep("at.alicdn.com", "domain", sources=("dex",))       # 30 - 40 = -10
    url = _ep("https://api.evil-c2.com/x", "url", sources=("dex",))  # 跳过
    ranked = rank_assets([pub, url, own])
    assert [r.value for r in ranked] == ["api.evil-c2.com", "at.alicdn.com"]
    assert all(isinstance(r, AssetScore) for r in ranked)


def test_empty_and_bad_endpoint() -> None:
    assert rank_assets([]) == []
    s = score_asset(_ep("", ""))  # 空端点不抛
    assert s.score == 0


def _state():
    return pipeline._PipelineState(ctx=None, config=AnalysisConfig(), platform="android", capabilities=set())  # type: ignore[arg-type]


def test_stage_asset_score_writes_sorted_meta() -> None:
    st = _state()
    st.endpoints = [
        _ep("at.alicdn.com", "domain", sources=("dex",)),         # -10
        _ep("api.evil-c2.com", "domain", sources=("dex", "remote-config")),  # 30+15+10=55
    ]
    pipeline._stage_asset_score(st)
    scores = st.meta["asset_scores"]
    assert scores[0]["value"] == "api.evil-c2.com" and scores[0]["score"] == 55
    assert scores[-1]["value"] == "at.alicdn.com"
    assert isinstance(scores[0]["reasons"], list)


def test_stage_noop_without_endpoints() -> None:
    st = _state()
    pipeline._stage_asset_score(st)
    assert "asset_scores" not in st.meta
