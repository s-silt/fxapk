"""证据可见性求值：壳桩样本的「未发现」不得被读成「不存在」。零真实数据。"""
from __future__ import annotations

from apkscan.core import visibility as V
from apkscan.report.digest import build_digest


def _report(**meta) -> dict:
    return {"meta": meta, "leads": [], "endpoints": [], "findings": [], "analysis_status": "complete"}


def test_clean_sample_blocks_nothing():
    a = V.assess(_report(dex_available=True))
    assert a["sources"]["dex"]["visibility"] == V.VIS_COMPLETE
    assert a["blocked_claims"] == []
    assert a["degraded"] is False


def test_stub_dex_blocks_exhaustiveness_claims():
    """★壳桩样本：依赖 DEX 的穷尽性结论一律无资格下。

    这是本模块存在的理由——没有它，一份壳桩报告会平静地写「未发现网络端点」，
    读的人（尤其是 AI）无从分辨那是「扫过了确实没有」还是「压根看不见」。
    """
    a = V.assess(_report(is_hardened=True, packed=None,
                         hardening_structural={"reason": "stub-dex"}))
    assert a["sources"]["dex"]["visibility"] == V.VIS_STUB_ONLY
    assert "static_endpoint_exhaustive" in a["blocked_claims"]
    assert "no_contact_harvesting" in a["blocked_claims"]
    assert a["degraded"] is True
    assert any("不能解读为不存在" in n for n in a["notes"])


def test_packed_none_does_not_mean_unhardened():
    """★`packed` 为空 ≠ 未加固：结构判据命中时厂商未识别，但 DEX 照样不可见。

    以 `packed` 是否有值判加固，会漏掉全部未识别厂商的壳——那恰恰是最需要标注的一类。
    """
    a = V.assess(_report(is_hardened=True, packed=None))
    assert a["sources"]["dex"]["visibility"] == V.VIS_STUB_ONLY
    assert a["blocked_claims"]


def test_unpack_reanalysis_restores_dex_visibility():
    """★脱壳回灌已生效 → DEX 重新可见；此时的 is_hardened 描述的是**被取代的原包**。

    不做这层区分，脱壳成功的样本会永远背着原包的加固结论，白白损失一整轮可见性。
    """
    a = V.assess(_report(
        is_hardened=True,
        artifact_lineage={"active_input": "unpacked", "unpacked_dex_count": 3},
    ))
    assert a["remediation"] == V.REM_REANALYZED
    assert a["sources"]["dex"]["visibility"] == V.VIS_COMPLETE
    assert "no_contact_harvesting" not in a["blocked_claims"]


def test_opaque_string_pool_blocks_dex_claims():
    """编译期字符串混淆：DEX 读得到字节，但 endpoints/contacts 依赖的字符串池是空的。"""
    a = V.assess(_report(dex_string_pool={"suspicious": True, "sampled": 800}))
    assert a["sources"]["dex"]["visibility"] == V.VIS_OPAQUE
    assert "static_endpoint_exhaustive" in a["blocked_claims"]


def test_native_obfuscation_only_blocks_claims_needing_native():
    """★可见性落到**主张**而非分析器：native 不可见不该牵连纯 DEX 的结论。

    endpoints 同时扫 DEX/manifest/资源/native，一刀切会把 manifest 里明摆着的域名也标成不可信。
    """
    a = V.assess(_report(native_obfuscation={"suspected": ["libx.so"]}))
    assert a["sources"]["native"]["visibility"] == V.VIS_OPAQUE
    assert "static_endpoint_exhaustive" in a["blocked_claims"]   # 需要 native
    assert "no_contact_harvesting" not in a["blocked_claims"]    # 只需要 dex


def test_assess_never_raises_on_garbage():
    for bad in (None, [], "x", {"meta": "not-a-dict"}, {"meta": {"dex_string_pool": 7}}):
        got = V.assess(bad)
        assert isinstance(got, dict) and "blocked_claims" in got


def test_blocks_claim_helper():
    a = V.assess(_report(is_hardened=True))
    assert V.blocks_claim(a, "static_endpoint_exhaustive") is True
    assert V.blocks_claim(a, "some_unrelated_claim") is False
    assert V.blocks_claim(None, "x") is False


# ---------------------------------------------------------------------------
# 接线：求值结果必须真的到达消费方，否则等于没做
# ---------------------------------------------------------------------------


def test_digest_surfaces_visibility_before_leads():
    """★digest 必须把可见性放在 leads **之前**——消费方要先知道哪里没看见。"""
    rep = _report(is_hardened=True, hardening_structural={"reason": "stub-dex"})
    rep["meta"]["visibility"] = V.assess(rep)
    d = build_digest(rep)
    keys = list(d)
    assert "visibility" in keys, "digest 未透出可见性，AI 会把空线索读成样本干净"
    assert keys.index("visibility") < keys.index("leads")
    assert d["visibility"]["degraded"] is True
    assert d["visibility"]["blocked_claims"], "被阻断的主张没进 digest"
    assert any("端点" in b["label"] for b in d["visibility"]["blocked_claims"])


def test_digest_old_report_degrades_to_unknown_not_complete():
    """★旧报告没有该字段时降级方向必须是「未知」，不是「输入都看得见」。

    把缺失当成完整，正是本模块要防的那类误读——在它自己身上犯就更荒唐。
    """
    d = build_digest(_report(is_hardened=True))
    assert d["visibility"]["available"] is False
    assert "未知" in d["visibility"]["note"]


def test_pipeline_stage_registered():
    """可见性阶段必须在 pipeline 里真的被调用（只写模块不接线 = 没做）。"""
    import inspect

    from apkscan.core import pipeline

    src = inspect.getsource(pipeline)
    assert '_run_stage(state, "visibility"' in src
