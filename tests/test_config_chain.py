"""config-chain 层⑥：控制链对象组装测试。

覆盖：远程配置对象 → 加密配方 → 解码 → 后端域名/IP + 五层归因（→ IDC）拼成单一 chain；配方摘要不含 key
明文；无 artifacts → 空；pipeline 附加阶段写 meta["control_chains"] 且无产物时 no-op。
"""

from __future__ import annotations

from apkscan.config.chain import build_control_chains
from apkscan.core import pipeline
from apkscan.core.models import AnalysisConfig, Endpoint


def _ep_with_idc(value: str = "api.evil-c2.com"):
    return Endpoint(value=value, kind="domain", enrichment={"attribution": {"ips": [{
        "ip": "1.2.3.4", "country": "CN",
        "origin_network": {"asn": 4134, "name": "China Telecom"},
        "hosting_provider": {"category": "idc", "name": "SomeIDC"},
        "edge_provider": {"tier": None},
    }]}})


def test_build_control_chains_links_config_to_backends() -> None:
    artifacts = [{
        "source_url": "https://cfg.oss-cn-hangzhou.aliyuncs.com/app/domain.dat",
        "decoded": True, "decode_chain": ["base64", "aes", "json"],
        "domains": ["api.evil-c2.com"], "ips": ["1.2.3.4"],
    }]
    recipe = {"algo": "AES", "mode": "CBC", "padding": "Pkcs7",
              "key": "SECRET_KEY_PLAINTEXT", "key_encoding": "utf8", "iv_derive": "fixed"}
    chains = build_control_chains(artifacts, recipe, [_ep_with_idc()])
    assert len(chains) == 1
    c = chains[0]
    assert c["source_url"].endswith("domain.dat")
    assert c["decoded"] is True and c["decode_chain"] == ["base64", "aes", "json"]
    assert c["crypto_recipe"]["algo"] == "AES" and c["crypto_recipe"]["iv_derive"] == "fixed"
    assert "key" not in c["crypto_recipe"]  # ★配方摘要绝不含 key 明文

    kinds = {(b["kind"], b["value"]) for b in c["backends"]}
    assert ("domain", "api.evil-c2.com") in kinds and ("ip", "1.2.3.4") in kinds
    # 域名后端携带五层归因 → 落到 IDC（这是"→ 基础设施"的链尾）
    dom = next(b for b in c["backends"] if b["value"] == "api.evil-c2.com")
    assert dom["attribution"][0]["hosting_provider"] == "SomeIDC"
    assert dom["attribution"][0]["country"] == "CN"
    assert dom["attribution"][0]["origin_network"] == "China Telecom"


def test_empty_when_no_artifacts() -> None:
    assert build_control_chains(None, None, []) == []
    assert build_control_chains([], {"algo": "AES"}, []) == []
    assert build_control_chains("not a list", None, []) == []  # type: ignore[arg-type]


def test_recipe_none_and_backends_without_endpoint() -> None:
    chains = build_control_chains(
        [{"source_url": "https://x/c.dat", "decoded": False, "domains": ["a.com"], "ips": []}],
        None, [],
    )
    assert chains[0]["crypto_recipe"] is None  # 无配方段
    # 后端存在但无对应端点归因 → attribution 空列表（不抛）
    assert chains[0]["backends"][0] == {"kind": "domain", "value": "a.com", "attribution": []}


def test_bad_artifact_entries_skipped() -> None:
    chains = build_control_chains(
        ["not a dict", {"no_source_url": True}, {"source_url": "https://x/c.dat", "decoded": True}],
        None, [],
    )
    assert len(chains) == 1 and chains[0]["source_url"].endswith("c.dat")


# --------------------------------------------------------------------------- #
# pipeline 附加阶段
# --------------------------------------------------------------------------- #
def _state():
    return pipeline._PipelineState(  # type: ignore[arg-type]
        ctx=None, config=AnalysisConfig(), platform="android", capabilities=set())


def test_stage_control_chain_writes_meta() -> None:
    st = _state()
    st.endpoints = [_ep_with_idc()]
    st.meta["remote_config_artifacts"] = [{
        "source_url": "https://x/c.dat", "decoded": True, "decode_chain": ["json"],
        "domains": ["api.evil-c2.com"], "ips": [],
    }]
    st.meta["crypto_recipe"] = {"algo": "AES", "mode": "CBC"}
    pipeline._stage_control_chain(st)
    assert "control_chains" in st.meta
    chain = st.meta["control_chains"][0]
    assert chain["backends"][0]["value"] == "api.evil-c2.com"
    assert chain["backends"][0]["attribution"][0]["hosting_provider"] == "SomeIDC"


def test_stage_control_chain_noop_without_artifacts() -> None:
    st = _state()
    pipeline._stage_control_chain(st)
    assert "control_chains" not in st.meta  # 无下载解码产物 → 不产链键
