"""跨样本团伙聚类（apkscan.dynamic.correlate）测试。

纯读各样本 report.json（dict）→ 抽强指纹 → 倒排 + union-find 聚类 → 团伙簇。
强指纹=高区分度：签名 sha256(非调试证书) / is_c2 域名 / uni AppID / 链上收款地址。
全离线纯函数，不碰真机。
"""

from __future__ import annotations

from apkscan.dynamic.correlate import Cluster, Fingerprint, correlate, extract_fingerprints


def _report(
    *,
    sign: str | None = None,
    subject: str = "CN=Evil Corp",
    uni: str | None = None,
    addrs: list[str] | None = None,
    c2: list[str] | None = None,
    fb: str | None = None,
) -> dict:
    leads = [
        {"category": "DOMAIN", "value": v, "is_c2": True, "is_runtime_seen": False}
        for v in (c2 or [])
    ]
    meta: dict = {"sign_subject": subject}
    if sign is not None:
        meta["sign_sha256"] = sign
    if uni is not None:
        meta["uni_appid"] = uni
    if addrs is not None:
        meta["crypto_addresses"] = addrs
    if fb is not None:
        meta["firebase_project_id"] = fb
    return {"meta": meta, "leads": leads}


def test_extract_firebase_project_fingerprint() -> None:
    fps = extract_fingerprints(_report(fb="proj-123"))
    assert Fingerprint("firebase_project", "proj-123") in fps


def test_correlate_shared_firebase_project_forms_cluster() -> None:
    clusters = correlate([("a", _report(fb="proj-9")), ("b", _report(fb="proj-9"))])
    assert len(clusters) == 1
    assert set(clusters[0].members) == {"a", "b"}


def test_extract_fingerprints_all_kinds() -> None:
    fps = extract_fingerprints(
        _report(sign="AA", uni="__UNI__X", addrs=["TQn9addr"], c2=["evil.com"])
    )
    assert Fingerprint("sign", "AA") in fps
    assert Fingerprint("uni_appid", "__UNI__X") in fps
    assert Fingerprint("crypto_addr", "TQn9addr") in fps
    assert Fingerprint("c2", "evil.com") in fps


def test_extract_skips_debug_cert() -> None:
    fps = extract_fingerprints(_report(sign="DBG", subject="CN=Android Debug,O=Android,C=US"))
    assert not any(f.kind == "sign" for f in fps)  # 调试证书海量样本共用，不作并簇键


def test_extract_ignores_empty_values() -> None:
    fps = extract_fingerprints(_report(sign="", uni=""))
    assert not any(f.kind in ("sign", "uni_appid") for f in fps)


def test_correlate_shared_c2_forms_cluster() -> None:
    clusters = correlate(
        [
            ("a", _report(c2=["evil.com"])),
            ("b", _report(c2=["evil.com"])),
            ("c", _report(c2=["other.com"])),
        ]
    )
    assert len(clusters) == 1
    assert set(clusters[0].members) == {"a", "b"}


def test_correlate_no_shared_no_cluster() -> None:
    clusters = correlate([("a", _report(c2=["x.com"])), ("b", _report(c2=["y.com"]))])
    assert clusters == []


def test_correlate_transitive_via_different_keys() -> None:
    # a~b 共享签名，b~c 共享 uni → 三者归一簇（连通分量）。
    clusters = correlate(
        [
            ("a", _report(sign="S1")),
            ("b", _report(sign="S1", uni="U1")),
            ("c", _report(uni="U1")),
        ]
    )
    assert len(clusters) == 1
    assert set(clusters[0].members) == {"a", "b", "c"}


def test_correlate_singleton_excluded() -> None:
    clusters = correlate(
        [
            ("a", _report(c2=["x.com"])),
            ("b", _report(c2=["x.com"])),
            ("lone", _report(sign="ZZ")),
        ]
    )
    assert len(clusters) == 1
    assert "lone" not in clusters[0].members  # 不共享任何指纹的孤包不入簇


def test_cluster_lists_shared_fingerprints() -> None:
    clusters = correlate(
        [
            ("a", _report(sign="S", c2=["x.com"])),
            ("b", _report(sign="S", c2=["x.com"])),
        ]
    )
    assert isinstance(clusters[0], Cluster)
    shared = {(f.kind, f.value) for f in clusters[0].shared}
    assert ("sign", "S") in shared
    assert ("c2", "x.com") in shared
