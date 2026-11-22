"""证据可见性求值：壳桩样本的「未发现」不得被读成「不存在」。零真实数据。"""
from __future__ import annotations

import pytest

from pathlib import Path

from fxapk.analyzers import jadx
from fxapk.analyzers.jadx import _build_jadx_receipt
from fxapk.core import visibility as V
from fxapk.core.models import Report
from fxapk.report.digest import build_digest
from fxapk.report.html import render_to_string


def _report(**meta) -> dict:
    return {"meta": meta, "leads": [], "endpoints": [], "findings": [], "analysis_status": "complete"}


def test_assess_records_only_inputs_seen_for_each_source() -> None:
    """快照必须自带求值输入出处；否则刷新时无法区分「新增信号」与「旧信号被裁掉」。"""
    assessment = V.assess(_report(
        dex_available=True,
        is_hardened=True,
        capture_quality={"endpoint_total": 1},
        unrelated="ignored",
    ))

    assert assessment["schema_version"] == "1.1"
    assert assessment["sources"]["dex"]["inputs_seen"] == [
        "dex_available", "is_hardened",
    ]
    assert assessment["sources"]["runtime"]["inputs_seen"] == ["capture_quality"]
    assert assessment["sources"]["native"]["inputs_seen"] == []
    assert assessment["sources"]["resource"]["inputs_seen"] == []


#: Java 面完整覆盖的最小凭据（receipt.complete=True 是唯一 complete 依据）。
_JADX_OK = {"status": "ok", "complete": True, "reason_codes": []}


def test_clean_static_run_blocks_no_static_claim():
    """静态输入完整（含 Java 面 receipt complete）→ 静态那几条结论全部有资格下。

    ``runtime_contact_observed`` 仍被阻断且 degraded=True：纯静态分析确实没资格说
    「已掌握运行时实连去向」，这是如实标注而非缺陷（见动态侧那组测试）。
    """
    a = V.assess(_report(dex_available=True, resource_files_scanned=42, jadx_receipt=_JADX_OK))
    assert a["sources"]["dex"]["visibility"] == V.VIS_COMPLETE
    assert a["sources"]["resource"]["visibility"] == V.VIS_COMPLETE
    assert a["sources"]["java"]["visibility"] == V.VIS_COMPLETE
    static_claims = [c for c in a["blocked_claims"] if c != "runtime_contact_observed"]
    assert static_claims == []


def test_unassessed_resource_layer_blocks_exhaustiveness_claims():
    """★「这一维没评估过」不等于「已确认完整」——但要与「查过、看不见」分开记。

    资源层此前恒为 unknown，而资格判定只拦 _INSUFFICIENT，于是一个从未被评估的
    资源面照样能签发「静态端点已穷尽」「未发现远程配置」。本域最典型的手法之一
    正是把接口藏在加密资源里。
    """
    a = V.assess(_report(dex_available=True, jadx_receipt=_JADX_OK))  # 无任何资源层信号
    assert a["sources"]["resource"]["visibility"] == V.VIS_UNKNOWN
    assert "static_endpoint_exhaustive" in a["blocked_claims"]
    claim = a["claims"]["static_endpoint_exhaustive"]
    assert claim["unassessed_sources"] == ["resource"]
    assert claim["missing_sources"] == [], "未评估不该被记成确证不可见"


# ---------------------------------------------------------------------------
# java（JADX 反编译面）独立通道 —— B2
# ---------------------------------------------------------------------------


def test_dex_complete_jadx_timeout_channels_independent():
    """★B2 核心：dex 与 java 是两个独立通道。JADX 超时只降 java（=timeout），绝不连坐 dex
    （仍 complete）；且 java 只阻断依赖 Java 穷尽性的主张，与 Java 无关的 dex 独立主张不受牵连。"""
    a = V.assess(_report(
        dex_available=True, resource_files_scanned=1,
        jadx_receipt={"status": "timeout", "complete": False,
                      "reason_codes": ["producer_timeout"]},
    ))
    assert a["sources"]["dex"]["visibility"] == V.VIS_COMPLETE
    assert a["sources"]["java"]["visibility"] == V.VIS_TIMEOUT
    for claim in ("static_endpoint_exhaustive", "no_hardcoded_credential"):
        assert claim in a["blocked_claims"]
        assert "java" in a["claims"][claim]["missing_sources"]
    # 只生成 Java 穷尽性 blockers：通讯录/短信/远程配置由 dex/资源面独立支撑，不因 JADX 失败被阻断。
    for claim in ("no_contact_harvesting", "no_sms_interception", "no_remote_config"):
        assert "java" not in a["claims"][claim]["missing_sources"]
    assert a["claims"]["no_contact_harvesting"]["eligible"] is True


def test_java_failed_and_receipt_gap_ranks():
    """failed 与「receipt 契约缺口」分档：前者 java=failed，后者 java=partial（阳性保留、只挡穷尽）。"""
    a = V.assess(_report(dex_available=True, jadx_receipt={
        "status": "failed", "complete": False, "reason_codes": ["producer_failed"]}))
    assert a["sources"]["java"]["visibility"] == V.VIS_FAILED

    b = V.assess(_report(dex_available=True, jadx_receipt={
        "status": "ok", "complete": False, "reason_codes": ["read_failed"]}))
    assert b["sources"]["java"]["visibility"] == V.VIS_PARTIAL


@pytest.mark.parametrize("contradiction", [
    {"status": "partial"},
    {"reason_codes": ["scan_limit_hit"]},
    {"scan": {"scan_limit_hit": True, "files_scanned": 0, "files_total": 0}},
    {"scan": {"truncated_files": 1, "files_scanned": 3, "files_total": 3}},
    {"scan": {"files_scanned": 2, "files_total": 3}},
    {"scan": None},
    {"scan": {"files_scanned": 3, "files_selected": 2, "files_total": 3}},
])
def test_java_complete_flag_cannot_override_explicit_gaps(contradiction: dict) -> None:
    report = _report(
        dex_available=True,
        resource_files_scanned=1,
        jadx_receipt={**_JADX_OK, **contradiction},
    )
    assessment = V.assess(report)
    assert assessment["sources"]["java"]["visibility"] == V.VIS_PARTIAL
    assert assessment["sources"]["dex"]["visibility"] == V.VIS_COMPLETE
    assert "static_endpoint_exhaustive" in assessment["blocked_claims"]
    assert V.java_coverage_observation(report)["state"] == V.VIS_PARTIAL
    assert V.assess(report) == assessment

    report["meta"]["visibility"] = assessment
    digest = build_digest(report)["visibility"]
    assert digest["sources"]["java"] == V.VIS_PARTIAL
    assert "static_endpoint_exhaustive" in {item["claim"] for item in digest["blocked_claims"]}


@pytest.mark.parametrize(("scan", "expected"), [
    pytest.param({"files_scanned": 3}, V.VIS_COMPLETE, id="only-scanned"),
    pytest.param({"files_total": 3}, V.VIS_COMPLETE, id="only-total"),
    pytest.param({"files_scanned": 3, "files_selected": 3}, V.VIS_COMPLETE, id="agrees"),
    pytest.param({"files_total": True}, V.VIS_PARTIAL, id="malformed"),
    pytest.param({"files_scanned": 3, "files_selected": 2}, V.VIS_PARTIAL, id="contradiction"),
    pytest.param({"files_total": 3, "truncated_files": 1}, V.VIS_PARTIAL, id="truncated"),
])
def test_java_receipt_with_one_of_paired_counts(
    scan: dict[str, int | bool], expected: str,
) -> None:
    report = _report(
        dex_available=True,
        resource_files_scanned=1,
        jadx_receipt={**_JADX_OK, "scan": scan},
    )
    assessment = V.assess(report)
    assert assessment["sources"]["java"]["visibility"] == expected
    assert V.java_coverage_observation(report)["state"] == expected
    assert V.java_scan_counts(report["meta"]) is None
    report["meta"]["visibility"] = assessment
    digest = build_digest(report)["visibility"]
    assert digest["sources"]["java"] == expected
    assert "java_scan" not in digest


def test_java_truncated_full_count_in_html() -> None:
    report = Report(package_name="com.synthetic.coverage", meta={
        "jadx_receipt": {
            **_JADX_OK,
            "scan": {"truncated_files": 1, "files_scanned": 3, "files_total": 3},
        },
    }, leads=[], endpoints=[], findings=[], analyzer_status=[])
    report.meta["visibility"] = V.assess({"meta": report.meta})
    html = render_to_string(report)
    assert "3/3" in html
    assert "Java 覆盖回执的完整标记与扫描记录冲突" in html


def test_saved_java_conflict_display_keeps_original_report() -> None:
    from copy import deepcopy

    saved = {
        "sources": {"java": {"visibility": "complete", "why": []}, "dex": {"visibility": "complete"}},
        "claims": {
            "static_endpoint_exhaustive": {"eligible": True, "missing_sources": ["resource"]},
            "unchanged": {"label": "synthetic unrelated label", "eligible": False},
        },
        "blocked_claims": ["unchanged"],
        "remediation": "synthetic unchanged remediation",
        "notes": ["synthetic saved explanation"],
        "next_actions": ["synthetic retained action"],
        "degraded": False,
    }
    meta = {"visibility": saved, "closure": {"status": "partial"}, "jadx_receipt": {
        **_JADX_OK, "scan": {"files_scanned": 3, "files_total": 3, "truncated_files": 1},
    }}
    snapshot = deepcopy(meta)
    projection = V.project_persisted_visibility(meta)
    assert isinstance(projection, dict)
    assert projection["sources"]["java"]["visibility"] == "partial"
    assert projection["sources"]["dex"] == saved["sources"]["dex"]
    assert projection["claims"]["unchanged"] == saved["claims"]["unchanged"]
    assert projection["claims"]["static_endpoint_exhaustive"]["missing_sources"] == ["resource", "java"]
    assert projection["blocked_claims"] == ["unchanged", "static_endpoint_exhaustive", "no_hardcoded_credential"]
    assert projection["remediation"] == saved["remediation"]
    assert projection["next_actions"] == saved["next_actions"]

    digest = build_digest(_report(**meta))["visibility"]
    r = Report(package_name="com.synthetic.coverage", meta=meta, leads=[], endpoints=[], findings=[], analyzer_status=[])
    html = render_to_string(r)
    assert digest["sources"]["java"] == "partial" and digest["sources"]["dex"] == "complete"
    assert digest["java_scan"] == {"files_scanned": 3, "files_total": 3}
    assert projection["sources"]["java"]["why"][0] in html
    assert projection["notes"][-1] in digest["notes"]
    assert "3/3" in html
    assert "<li>static_endpoint_exhaustive</li>" in html
    assert "<li>no_hardcoded_credential</li>" in html
    assert V.project_persisted_visibility({**meta, "visibility": projection}) is projection
    assert meta == snapshot


@pytest.mark.parametrize("saved_java", [
    "complete",
    {"visibility": "complete", "why": False},
    {"visibility": "complete", "why": None},
    {"visibility": "complete", "why": ""},
    {"visibility": "complete", "why": ["synthetic legacy reason", 7]},
])
def test_saved_java_legacy_shape_conflicts_with_current_producer_receipt(
    saved_java: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from copy import deepcopy

    # Run the project scanner on inert Java text, not a saved historical artifact.
    monkeypatch.setattr(jadx, "_MAX_FILE_BYTES", 32)
    for name, content in {"A.java": "class A {}", "B.java": "class B {}",
                          "C.java": "// " + "x" * 64}.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    scan = jadx.JadxAnalyzer()._scan_java(tmp_path).receipt
    assert (scan["files_scanned"], scan["files_selected"], scan["files_total"], scan["truncated_files"]) == (3, 3, 3, 1)
    receipt = _build_jadx_receipt(
        status="ok", runs=[{"options_digest": "synthetic", "ownership_complete": True,
                            "termination_complete": True}],
        scan=scan,
        cleanup={"complete": True}, analyzer_error=False,
    )
    assert receipt["complete"] is False and receipt["reason_codes"] == ["source_file_truncated"]
    meta = {"visibility": {"sources": {"java": saved_java}, "blocked_claims": []},
            "jadx_receipt": receipt}
    original = deepcopy(meta)
    digest = build_digest(_report(**meta))["visibility"]
    report = Report(package_name="com.synthetic.coverage", meta=meta, leads=[], endpoints=[],
                    findings=[], analyzer_status=[])
    html = render_to_string(report)
    assert digest["sources"]["java"] == "partial"
    assert digest["java_scan"] == {"files_scanned": 3, "files_total": 3}
    assert {row["claim"] for row in digest["blocked_claims"]} == {
        "static_endpoint_exhaustive", "no_hardcoded_credential",
    }
    for claim in ("static_endpoint_exhaustive", "no_hardcoded_credential"):
        assert f"<li>{claim}</li>" in html
    java_row = html.split("<td>java</td>", 1)[1].split("</tr>", 1)[0]
    assert "<td>partial</td>" in java_row and "3/3" not in java_row
    assert "3/3" in html.split('id="jadx-java-scan"', 1)[1].split("</p>", 1)[0]
    if isinstance(saved_java, dict) and saved_java.get("why") == ["synthetic legacy reason", 7]:
        why = V.project_persisted_visibility(meta)["sources"]["java"]["why"]
        assert why[:2] == ["synthetic legacy reason", 7]
        assert "synthetic legacy reason" in java_row
    assert "不能判为完整" in html
    assert meta == original


@pytest.mark.parametrize("why", [[], None, False, ""])
def test_saved_java_compatible_empty_why_keeps_view_when_complete_is_not_boolean(why: object) -> None:
    saved = {"sources": {"java": {"visibility": "complete", "why": why}}}
    scan = {"files_scanned": 3, "files_total": 3, "truncated_files": 1}
    for receipt in (
        {"status": "ok", "scan": scan},
        {"status": "ok", "scan": scan, "complete": "true"},
        {"status": "ok", "scan": scan, "complete": 1},
    ):
        assert V.project_persisted_visibility({"visibility": saved, "jadx_receipt": receipt}) is saved


@pytest.mark.parametrize("scan", [
    None, {}, {"truncated_files": 1},
    {"files_scanned": 0, "files_total": 0, "truncated_files": 0},
    {"files_scanned": 3, "files_total": 3, "truncated_files": True},
    {"files_scanned": 3, "files_total": 3, "truncated_files": "1"},
    {"files_scanned": 4, "files_total": 3, "truncated_files": 1},
    {"files_scanned": 0, "files_total": 0, "truncated_files": 1},
    {"files_scanned": 3, "files_total": 3, "truncated_files": 1, "read_failed": False},
    *[{"files_scanned": 3, "files_total": 3, "truncated_files": 1, key: value}
      for key, value in (("files_selected", "3"), ("files_selected", 2), ("files_selected", 4),
                         ("scan_limit_hit", 0), ("discovery_failed", None),
                         ("scan_exceptions", -1), ("read_failed", -1))],
])
def test_saved_java_projection_keeps_view_without_valid_truncation(scan: object) -> None:
    saved = {"sources": {"java": {"visibility": "complete", "why": []}}}
    assert V.project_persisted_visibility({"visibility": saved}) is saved
    assert V.project_persisted_visibility({
        "visibility": saved, "jadx_receipt": {**_JADX_OK, "status": "skipped", "scan": scan},
    }) is saved
    assert V.project_persisted_visibility({
        "visibility": saved, "jadx_receipt": {**_JADX_OK, "scan": scan},
    }) is saved
    assert V.project_persisted_visibility({"jadx_receipt": {**_JADX_OK, "scan": scan}}) is None


def test_java_complete_empty_scan_keeps_complete() -> None:
    report = _report(jadx_receipt={
        **_JADX_OK,
        "scan": {"scan_limit_hit": False, "files_scanned": 0, "files_total": 0},
    })
    assert V.java_coverage_observation(report)["state"] == V.VIS_COMPLETE


def test_scheduler_receipt_overrides_jadx_selfreport():
    """★消费端权威链：调度器执行 receipt（analyzer_receipts.jadx）比 analyzer 自报状态更外层——
    scheduler_error/analyzer_error 定 failed、scheduler_timeout 定 timeout，即使 jadx_receipt
    声称 complete（更早写下的自报不可能知道调度层后来发生了什么）。"""
    base = dict(dex_available=True, jadx_receipt=_JADX_OK)
    a = V.assess(_report(**base, analyzer_receipts={
        "jadx": {"lane": "long", "execution": "scheduler_error"}}))
    assert a["sources"]["java"]["visibility"] == V.VIS_FAILED

    b = V.assess(_report(**base, analyzer_receipts={
        "jadx": {"lane": "long", "execution": "scheduler_timeout"}}))
    assert b["sources"]["java"]["visibility"] == V.VIS_TIMEOUT

    # completed 不覆盖：定档回落 coverage receipt。
    c = V.assess(_report(**base, analyzer_receipts={
        "jadx": {"lane": "long", "execution": "completed"}}))
    assert c["sources"]["java"]["visibility"] == V.VIS_COMPLETE


def test_legacy_report_jadx_status_ok_is_unknown_not_complete():
    """旧报告（无 receipt）：jadx_status=ok 只说 CLI 退出码 0（读失败/截断/清理一概未记）——
    记 unknown（穷尽性主张仍无资格），绝不虚构 complete；确证失败态（timeout）照记。"""
    a = V.assess(_report(dex_available=True, jadx_status="ok"))
    assert a["sources"]["java"]["visibility"] == V.VIS_UNKNOWN
    assert "java" in a["claims"]["static_endpoint_exhaustive"]["unassessed_sources"]

    b = V.assess(_report(dex_available=True, jadx_status="timeout"))
    assert b["sources"]["java"]["visibility"] == V.VIS_TIMEOUT


def test_internal_error_fallback_keeps_six_source_schema(monkeypatch) -> None:  # noqa: ANN001
    """求值内部异常时仍返回完整六源形状，不能只在正常路径存在新增 source。"""
    def _boom(meta):  # noqa: ANN001
        raise RuntimeError("visibility 内部故障（模拟）")

    monkeypatch.setattr(V, "_dex_visibility", _boom)
    assessment = V.assess(_report(dex_available=True))
    assert list(assessment["sources"]) == [
        "manifest", "dex", "java", "native", "resource", "runtime",
    ]
    assert assessment["sources"]["java"]["visibility"] == V.VIS_UNKNOWN


def test_encrypted_resources_are_opaque_not_unknown():
    """uni-app 代码加密：资源层确证不可读，属实测缺口而非未评估。"""
    a = V.assess(_report(dex_available=True, uni_encrypted=True))
    assert a["sources"]["resource"]["visibility"] == V.VIS_OPAQUE
    assert "static_endpoint_exhaustive" in a["blocked_claims"]
    assert a["claims"]["static_endpoint_exhaustive"]["missing_sources"] == ["resource"]


def test_identified_crypto_recipe_makes_resource_partial():
    """识别出加密配置文件但尚未解密并入 → 资源层部分不可读。"""
    a = V.assess(_report(dex_available=True, crypto_recipe={"algo": "AES/CBC"}))
    assert a["sources"]["resource"]["visibility"] == V.VIS_PARTIAL
    assert "static_endpoint_exhaustive" in a["blocked_claims"]


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


def test_truncated_scan_blocks_exhaustiveness():
    """★扫描截断是最隐蔽的可见性缺口：分析器跑成功、状态全绿，只是没扫完。

    实测一个 100MB 样本的 DEX 字符串超 20 万条上限被截断——此时「未发现某接口」完全可能只是
    因为它排在截断线之后。上限本身必要（防内存爆），但截断这个**事实**必须传下去。
    """
    a = V.assess(_report(dex_strings_truncated=True))
    assert a["sources"]["dex"]["visibility"] == V.VIS_PARTIAL
    assert "static_endpoint_exhaustive" in a["blocked_claims"]
    assert any("截断" in n for n in a["notes"])


def test_native_config_channel_surfaces_as_next_action():
    """★接线断言：控制面通道被识别出来，就得出现在"下一步怎么补"里。

    地址按算法逐日生成，静态端点集里本来就不会有它——不把这条摆出来，
    读的人会继续在静态里挖一个根本不存在的域名。
    """
    a = V.assess(_report(native_config_channel={
        "templates": [{"url_template": "https://%s.example-oss.com/%s.dat"}],
        "missing_inputs": ["AppName", "SDKVersion"],
        "next_actions": ["..."],
    }))
    assert any("native 侧发现控制面通道" in x for x in a["next_actions"])
    assert any("AppName" in x for x in a["next_actions"])


def test_extra_dex_partial_load_blocks_exhaustiveness():
    """★真样本回归：脱壳 dump 出 33 个 DEX，androguard 只吃下 10 个。

    控制台原本写"33 个并入静态分析"、分析器状态 error=0，读的人会以为 33 个都分析过。
    两成输入没进来比字符串扫到一半缺得更多，必须先于截断判定。
    """
    a = V.assess(_report(extra_dex_visibility={
        "requested": 33, "loaded": 10, "failed": 23, "complete": False,
        "failures_by_error": {"ValueError": 23},
        "failure_samples": [],
    }))
    assert a["sources"]["dex"]["visibility"] == V.VIS_PARTIAL
    assert "static_endpoint_exhaustive" in a["blocked_claims"]
    assert any("脱壳产物未全部进入分析" in n for n in a["notes"])


def test_extra_dex_fully_loaded_does_not_degrade():
    """全部并入成功时不得因为"用了 extra-dex"就降级——那会把干净的完整分析说成残缺。"""
    a = V.assess(_report(extra_dex_visibility={
        "requested": 33, "loaded": 33, "failed": 0, "complete": True,
        "failures_by_error": {}, "failure_samples": [],
    }))
    assert a["sources"]["dex"]["visibility"] == V.VIS_COMPLETE


def test_hardened_with_merged_extra_dex_not_stub_only():
    """★手动 `analyze --extra-dex` 回灌：原包加固，但 dump DEX 已并入 → 不再判 stub_only。

    治「29 个 DEX 已并入、字符串 24.5 万、却因 is_hardened=True 仍标 stub_only」——该报告不走
    unpack 的 remediation 升级路径（不设 unpacked/artifact_lineage），加固短路会抢先把已经看得见的
    代码判成看不见，抵消脱壳回灌的全部收益。判据：loaded>0 时按并入完整度评估（有失败→partial，
    全并入→complete），而非先行 stub_only。
    """
    partial = V.assess(_report(is_hardened=True, extra_dex_visibility={
        "requested": 33, "loaded": 29, "failed": 4, "complete": False,
        "failures_by_error": {"ValueError": 4}, "failure_samples": [],
    }))
    assert partial["sources"]["dex"]["visibility"] == V.VIS_PARTIAL
    assert any("并入" in n and "DEX" in n for n in partial["notes"])

    full = V.assess(_report(is_hardened=True, extra_dex_visibility={
        "requested": 29, "loaded": 29, "failed": 0, "complete": True,
        "failures_by_error": {}, "failure_samples": [],
    }))
    assert full["sources"]["dex"]["visibility"] == V.VIS_COMPLETE

    # 回归护栏：加固但**无**脱壳并入仍是 stub_only（别把这条一起放松了）。
    none_merged = V.assess(_report(is_hardened=True))
    assert none_merged["sources"]["dex"]["visibility"] == V.VIS_STUB_ONLY


def test_dex_not_scanned_is_unavailable():
    a = V.assess(_report(dex_scanned=False))
    assert a["sources"]["dex"]["visibility"] == V.VIS_UNAVAILABLE
    assert a["blocked_claims"]


def test_repack_suspected_raises_attribution_caveat():
    """★重打包件的接口/域名归**被仿冒的正版厂商**，照单列进清单会向无关企业发函。

    这是归属问题不是可见性问题，但后果同样方向性、同样此前无人消费，故一并在此告警。
    """
    a = V.assess(_report(repack_identity={"verdict": "repack_suspected"}))
    assert any("重打包" in n and "官方同版本包差分" in n for n in a["notes"])
    # 自研件不得触发该告警（否则每份报告都挂一条，等于没有）
    b = V.assess(_report(repack_identity={"verdict": "self_built"}))
    assert not any("重打包" in n for n in b["notes"])


def test_debug_cert_raises_attribution_caveat_when_not_repack():
    """★判不出重打包 ≠ 排除重打包：调试证书在场时仍须提醒差分核实。

    调试证书对「自研批量打包」与「第三方重签正版」同样常见，方向双向兼容；
    再叠加 v2/v3-only 包结构性没有签名别名，判据这时是**缺失**而非"查过没有"。
    此前 self_built / unknown 两种 verdict 下归属告警完全缺席，报告里没有任何东西
    把人往差分核实上拉——退回 _attribution_caveat 的这一分支，本测试即红。
    """
    for verdict in ("self_built", "unknown"):
        a = V.assess(_report(
            repack_identity={"verdict": verdict, "signature": {"debug_cert": True}}
        ))
        assert any("调试证书" in n and "差分核实" in n for n in a["notes"]), verdict

    # 非 debug 证书不挂该提醒——否则每份报告都挂一条，等于没有
    b = V.assess(_report(
        repack_identity={"verdict": "self_built", "signature": {"debug_cert": False}}
    ))
    assert not any("调试证书" in n for n in b["notes"])


# ---------------------------------------------------------------------------
# 动态侧：运行时观测是静态盲区的独立补救渠道
# ---------------------------------------------------------------------------


def test_static_only_run_cannot_claim_runtime_contact():
    """★纯静态分析没资格说「已掌握运行时实连去向」——静态再完整也证不了跑起来连了谁。

    加固样本尤其如此：真实后端往往只在运行时由配置下发，静态里根本不存在。
    """
    a = V.assess(_report(dex_available=True))
    assert a["sources"]["runtime"]["visibility"] == V.VIS_UNAVAILABLE
    assert "runtime_contact_observed" in a["blocked_claims"]
    # 但纯静态不该因此把静态那几条也一起阻断
    assert "no_contact_harvesting" not in a["blocked_claims"]


def test_complete_capture_unblocks_runtime_claim():
    a = V.assess(_report(
        runtime_merged=True,
        capture_quality={"dynamic_status": "complete", "reason": "ok"},
    ))
    assert a["sources"]["runtime"]["visibility"] == V.VIS_COMPLETE
    assert "runtime_contact_observed" not in a["blocked_claims"]


def test_degraded_capture_is_partial_not_complete():
    a = V.assess(_report(
        runtime_merged=True,
        capture_quality={"dynamic_status": "degraded", "reason": "no business candidate"},
    ))
    assert a["sources"]["runtime"]["visibility"] == V.VIS_PARTIAL
    assert "runtime_contact_observed" in a["blocked_claims"]


def test_next_actions_tell_you_how_to_fix_the_gap():
    """★只报「哪里瞎了」不给补法等于半截活：消费方拿到 degraded 报告得知道下一步做什么。"""
    a = V.assess(_report(is_hardened=True))          # 壳桩 + 未脱壳 + 未做动态
    joined = " ".join(a["next_actions"])
    assert "unpack" in joined, "壳桩未回灌却没提示脱壳"
    assert "capture" in joined, "静态受限且无动态证据却没提示抓包"


def test_next_actions_do_not_suggest_unpack_after_successful_reanalysis():
    """已脱壳回灌就别再劝脱壳——重复建议会让人不再看这个字段。"""
    a = V.assess(_report(
        is_hardened=True,
        artifact_lineage={"active_input": "unpacked", "unpacked_dex_count": 3},
    ))
    assert not any("unpack" in x for x in a["next_actions"])


def test_next_actions_surface_config_probe_plan():
    """配置探测预案生成后要告诉人怎么用它（授权后重跑可取回下发的域名/IP 池）。"""
    a = V.assess(_report(
        is_hardened=True,
        config_probe_plan={"candidates": [{"url": "https://h.test/api/home/config"}]},
    ))
    joined = " ".join(a["next_actions"])
    assert "authorized-active" in joined and "config_probe_plan" in joined


def test_digest_carries_next_actions():
    rep = _report(is_hardened=True)
    rep["meta"]["visibility"] = V.assess(rep)
    d = build_digest(rep)
    assert d["visibility"]["next_actions"], "补法没传到 digest，AI 消费面看不到"


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

    from fxapk.core import pipeline

    src = inspect.getsource(pipeline)
    assert '_run_stage(state, "visibility"' in src
