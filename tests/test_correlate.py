"""跨样本关联候选聚类（apkscan.dynamic.correlate）测试。

纯读各样本 report.json（dict）→ 抽候选指纹 → 倒排 + union-find 聚类 → 关联候选簇。
共享指纹只用于人工复核召回，不能独立认定主体或自动并案。全离线纯函数，不碰真机。
"""

from __future__ import annotations

import pytest

from apkscan.dynamic.correlate import (
    CORRELATION_DISCLAIMER,
    Cluster,
    Fingerprint,
    correlate,
    extract_fingerprints,
)


def test_correlation_disclaimer_preserves_evidence_boundary() -> None:
    assert "人工复核" in CORRELATION_DISCLAIMER
    assert "不能独立认定" in CORRELATION_DISCLAIMER
    assert "不会自动形成并案结论" in CORRELATION_DISCLAIMER


def _report(
    *,
    sign: str | None = None,
    subject: str = "CN=Evil Corp",
    uni: str | None = None,
    addrs: list[str] | None = None,
    c2: list[str] | None = None,
    fb: str | None = None,
    tg: list[str] | None = None,
) -> dict:
    leads = [
        {
            "category": "DOMAIN",
            "value": v,
            "advice": "建议调证",
            "is_c2": True,
            "is_runtime_seen": False,
            "source_refs": [
                {
                    "source": "dex",
                    "location": "classes.dex",
                    "scope": "case_evidence",
                }
            ],
        }
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
    if tg is not None:
        meta["telegram_bot_tokens"] = tg
    return {"meta": meta, "leads": leads}


def test_extract_firebase_project_fingerprint() -> None:
    fps = extract_fingerprints(_report(fb="proj-123"))
    assert Fingerprint("firebase_project", "proj-123") in fps


def test_extract_telegram_bot_fingerprint() -> None:
    fps = extract_fingerprints(_report(tg=["12345678:AbcdefghijklmnopqrstuvwxyZ0123456789"]))
    assert Fingerprint("telegram_bot", "12345678:AbcdefghijklmnopqrstuvwxyZ0123456789") in fps


def test_correlate_shared_telegram_bot_forms_cluster() -> None:
    tok = "12345678:AbcdefghijklmnopqrstuvwxyZ0123456789"
    clusters = correlate([("a", _report(tg=[tok])), ("b", _report(tg=[tok]))])
    assert len(clusters) == 1
    assert set(clusters[0].members) == {"a", "b"}


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
    assert not any(f.kind == "sign" for f in fps)  # 调试证书海量样本共用，不作候选聚类键


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
    # shared 须精确列全两条候选连接（a~b 签名 + b~c uni），
    # 只断言 >=2 会漏掉半数共享指纹却不报红——这里锁定精确集合。
    shared = {(f.kind, f.value) for f in clusters[0].shared}
    assert shared == {("sign", "S1"), ("uni_appid", "U1")}


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


def _lead(category: str, value: str, scope: str | None) -> dict:
    evidence = {"source": "dex", "location": "classes.dex"}
    if scope is not None:
        evidence["scope"] = scope
    return {
        "category": category,
        "value": value,
        "advice": "建议调证",
        "is_c2": category in {"DOMAIN", "IP"},
        "source_refs": [evidence],
    }


@pytest.mark.parametrize(
    "scope", ["batch_reference", "legacy_unspecified", None, "bad", " case_evidence "]
)
@pytest.mark.parametrize(
    ("category", "kind"),
    [
        ("DOMAIN", "c2"),
        ("ADMIN_PANEL", "admin_host"),
        ("SELF_HOSTED_IM", "im_server"),
        ("WALLET_SECRET", "wallet_secret"),
    ],
)
def test_reference_only_lead_never_becomes_a_strong_fingerprint(
    scope: str | None, category: str, kind: str
) -> None:
    report = {"meta": {}, "leads": [_lead(category, "shared-value", scope)]}

    fps = extract_fingerprints(report)

    assert Fingerprint(kind, "shared-value") not in fps


@pytest.mark.parametrize(
    ("category", "kind"),
    [
        ("DOMAIN", "c2"),
        ("ADMIN_PANEL", "admin_host"),
        ("SELF_HOSTED_IM", "im_server"),
        ("WALLET_SECRET", "wallet_secret"),
    ],
)
def test_direct_case_lead_remains_a_strong_fingerprint(category: str, kind: str) -> None:
    report = {
        "meta": {},
        "leads": [_lead(category, "shared-value", "case_evidence")],
    }

    assert Fingerprint(kind, "shared-value") in extract_fingerprints(report)


def test_matching_direct_endpoint_can_qualify_network_fingerprint() -> None:
    lead = _lead("DOMAIN", "backend.example", "batch_reference")
    report = {
        "meta": {},
        "leads": [lead],
        "endpoints": [
            {
                "kind": "domain",
                "value": "backend.example",
                "evidences": [
                    {
                        "source": "runtime-pcap",
                        "location": "capture.pcap",
                        "scope": "case_evidence",
                    }
                ],
            }
        ],
    }

    assert Fingerprint("c2", "backend.example") in extract_fingerprints(report)


def test_malformed_whitespace_network_category_never_becomes_c2_fingerprint() -> None:
    report = {
        "meta": {},
        "leads": [_lead(" DOMAIN ", "backend.example", "case_evidence")],
    }

    assert Fingerprint("c2", "backend.example") not in extract_fingerprints(report)
