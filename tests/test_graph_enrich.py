"""图谱增强：A 期新线索（后台 host / 自建 IM / 钱包凭据）接入指纹 → 自动入图串案。

extract_fingerprints 把这些强连边线索转成指纹，correlate / Kuzu 图谱据此跨样本串案。
"""

from __future__ import annotations

import pytest

from apkscan.dynamic.correlate import Fingerprint, correlate, extract_fingerprints
from apkscan.graph.weight import get_weight, is_strong


def _report(leads: list[dict]) -> dict:
    return {"meta": {}, "leads": leads}


def test_admin_panel_investigate_becomes_admin_host_fp() -> None:
    r = _report([{"category": "ADMIN_PANEL", "value": "admin.evil.com", "advice": "建议调证"}])
    assert Fingerprint("admin_host", "admin.evil.com") in extract_fingerprints(r)


def test_admin_panel_review_not_fingerprinted() -> None:
    # 待核档不入图（避免弱信号污染串案）。
    r = _report([{"category": "ADMIN_PANEL", "value": "admin.evil.com", "advice": "待核"}])
    assert all(fp.kind != "admin_host" for fp in extract_fingerprints(r))


def test_self_hosted_im_investigate_becomes_im_server_fp() -> None:
    r = _report([{"category": "SELF_HOSTED_IM", "value": "evilbroker.com", "advice": "建议调证"}])
    assert Fingerprint("im_server", "evilbroker.com") in extract_fingerprints(r)


def test_wallet_secret_always_fingerprinted() -> None:
    # 钱包私钥/助记词经校验和，恒为铁证 → 不依赖 advice 也入图。
    r = _report([{"category": "WALLET_SECRET", "value": "seed phrase here", "advice": "建议调证"}])
    assert Fingerprint("wallet_secret", "seed phrase here") in extract_fingerprints(r)


def test_correlate_clusters_on_shared_admin_host() -> None:
    a = _report([{"category": "ADMIN_PANEL", "value": "admin.evil.com", "advice": "建议调证"}])
    b = _report([{"category": "ADMIN_PANEL", "value": "admin.evil.com", "advice": "建议调证"}])
    clusters = correlate([("a", a), ("b", b)])
    assert len(clusters) == 1
    assert set(clusters[0].members) == {"a", "b"}


def test_new_kind_weights_are_strong() -> None:
    for kind in ("wallet_secret", "admin_host", "im_server"):
        assert is_strong(kind)
        assert get_weight(kind) >= 8.0


def test_graph_clusters_on_shared_wallet_secret(tmp_path) -> None:
    pytest.importorskip("kuzu")
    from apkscan.graph import GraphStore, ingest_report, query_clusters

    with GraphStore(str(tmp_path / "cases.kuzu")) as store:
        for sha in ("A", "B"):
            rep = {
                "meta": {"sample_sha256": sha},
                "leads": [
                    {"category": "WALLET_SECRET", "value": "shared mnemonic", "advice": "建议调证"}
                ],
            }
            ingest_report(rep, store, sha256=sha)
        cl = query_clusters(store)
        assert cl["cluster_count"] == 1
        assert set(cl["clusters"][0]["members"]) == {"A", "B"}
