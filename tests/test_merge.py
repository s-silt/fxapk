"""apkscan.dynamic.merge 的单测。

策略：合成 Report + 运行时 Endpoint，全程无设备/无子进程：
- 验证运行时端点去重并入 report.endpoints（与静态 value 重叠时并进同一端点）。
- 验证仅运行时引入的 domain/ip 走 infra 分级生成线索（默认建议调证 / 已知基础设施无需调证）。
- 验证 source="runtime" 标注、meta 打标、统计计数。
- load_runtime_endpoints：从 capture 写出的 runtime_report.json 还原；缺文件/坏 JSON → []。
- merge_and_rerender：惰性 import report.{html,json} 重渲；report 模块缺失不致命。
- 全程不抛（结构化返回）。
"""

from __future__ import annotations

import base64 as _b64
import hashlib as _hashlib
import json
import warnings as _warnings
from typing import Any

from apkscan.core import infra
from apkscan.core.models import (
    Confidence,
    Endpoint,
    Evidence,
    Lead,
    LeadCategory,
    Report,
)
from apkscan.dynamic import merge


# ---------------------------------------------------------------------------
# 合成 Report / Endpoint 帮助器
# ---------------------------------------------------------------------------


def _make_report(
    *,
    endpoints: list[Endpoint] | None = None,
    leads: list[Lead] | None = None,
    meta: dict[str, Any] | None = None,
) -> Report:
    return Report(
        package_name="com.test.app",
        meta=dict(meta or {}),
        leads=list(leads or []),
        endpoints=list(endpoints or []),
        findings=[],
        analyzer_status=[],
    )


def _runtime_ep(value: str, kind: str, **kwargs: Any) -> Endpoint:
    return Endpoint(
        value=value,
        kind=kind,
        evidences=[Evidence(source="runtime", location="flows.mitm", snippet=value)],
        **kwargs,
    )


# ---------------------------------------------------------------------------
# merge_runtime_endpoints：去重 / 并入
# ---------------------------------------------------------------------------


def test_merge_runtime_endpoints_adds_new_endpoint() -> None:
    report = _make_report()
    eps = [_runtime_ep("api.fraud-c2.cn", "domain")]
    stats = merge.merge_runtime_endpoints(report, eps)

    values = {ep.value for ep in report.endpoints}
    assert "api.fraud-c2.cn" in values
    assert stats["merged"] == 1
    assert stats["total_endpoints"] == 1


def test_merge_dedups_runtime_endpoint_matching_static_value() -> None:
    """运行时端点 value 已在静态端点 → 并进同一 Endpoint，不新增端点。"""
    static_ep = Endpoint(
        value="api.fraud-c2.cn",
        kind="domain",
        evidences=[Evidence(source="dex", location="classes.dex", snippet="api.fraud-c2.cn")],
    )
    report = _make_report(endpoints=[static_ep])
    eps = [_runtime_ep("api.fraud-c2.cn", "domain")]

    stats = merge.merge_runtime_endpoints(report, eps)

    # 仍只有 1 个端点（同 value 合并）
    matching = [ep for ep in report.endpoints if ep.value == "api.fraud-c2.cn"]
    assert len(matching) == 1
    # 同时带 dex + runtime 两条证据
    sources = {ev.source for ev in matching[0].evidences}
    assert sources == {"dex", "runtime"}
    assert stats["merged"] == 0  # 净增端点 0
    assert stats["total_endpoints"] == 1


def test_merge_runtime_evidence_source_is_runtime() -> None:
    """哪怕传入端点 evidence 来源写串，并入后也钉为 runtime。"""
    report = _make_report()
    ep = Endpoint(
        value="api.fraud-c2.cn",
        kind="domain",
        evidences=[Evidence(source="dex", location="x", snippet="y")],  # 故意写错来源
    )
    merge.merge_runtime_endpoints(report, [ep])
    merged = next(e for e in report.endpoints if e.value == "api.fraud-c2.cn")
    assert all(ev.source == "runtime" for ev in merged.evidences)


# ---------------------------------------------------------------------------
# merge_runtime_endpoints：infra 分级生成线索
# ---------------------------------------------------------------------------


def test_merge_generates_domain_lead_with_investigate_advice() -> None:
    """疑似 App 自有服务（未命中 KNOWN_INFRA）→ 建议调证。"""
    report = _make_report()
    eps = [_runtime_ep("c2.fraud-gw.cn", "domain")]
    stats = merge.merge_runtime_endpoints(report, eps)

    domain_leads = [
        lead for lead in report.leads if lead.category == LeadCategory.DOMAIN
    ]
    assert len(domain_leads) == 1
    assert domain_leads[0].value == "c2.fraud-gw.cn"
    assert domain_leads[0].advice == infra.ADVICE_INVESTIGATE
    assert stats["new_leads"] == 1


def test_merge_known_infra_runtime_domain_marked_skip() -> None:
    """命中 KNOWN_INFRA（如腾讯云）→ 无需调证。"""
    report = _make_report()
    eps = [_runtime_ep("res.myqcloud.com", "domain")]
    merge.merge_runtime_endpoints(report, eps)

    lead = next(lead for lead in report.leads if lead.value == "res.myqcloud.com")
    assert lead.advice == infra.ADVICE_SKIP


def test_merge_offline_meta_propagates_offline_note_to_runtime_lead() -> None:
    """离线扫描（report.meta['online']=False）：运行时引入的 domain 线索应带"离线未查询"
    标注，与静态侧一致，不被默认 online=True 当成已联网核实（不假成功）。"""
    report = _make_report(meta={"online": False})
    eps = [_runtime_ep("c2.fraud-gw.cn", "domain")]
    merge.merge_runtime_endpoints(report, eps)

    lead = next(lead for lead in report.leads if lead.value == "c2.fraud-gw.cn")
    assert "离线扫描" in lead.notes


def test_merge_online_meta_no_offline_note() -> None:
    """联网扫描（meta['online']=True）：运行时线索不带离线标注。"""
    report = _make_report(meta={"online": True})
    eps = [_runtime_ep("c2.fraud-gw.cn", "domain")]
    merge.merge_runtime_endpoints(report, eps)

    lead = next(lead for lead in report.leads if lead.value == "c2.fraud-gw.cn")
    assert "离线扫描" not in lead.notes


def test_merge_does_not_duplicate_existing_static_lead() -> None:
    """运行时端点 value 已有同 (category, value) 的静态 Lead → 不重复生成。"""
    static_lead = Lead(
        category=LeadCategory.DOMAIN,
        value="api.fraud-c2.cn",
        confidence=Confidence.HIGH,
        advice=infra.ADVICE_INVESTIGATE,
    )
    static_ep = Endpoint(
        value="api.fraud-c2.cn",
        kind="domain",
        evidences=[Evidence(source="dex", location="x", snippet="y")],
    )
    report = _make_report(endpoints=[static_ep], leads=[static_lead])

    eps = [_runtime_ep("api.fraud-c2.cn", "domain")]
    stats = merge.merge_runtime_endpoints(report, eps)

    domain_leads = [
        lead for lead in report.leads if lead.value == "api.fraud-c2.cn"
    ]
    assert len(domain_leads) == 1  # 仍只有静态那一条
    assert stats["new_leads"] == 0


def test_merge_ip_lead_generated_for_runtime_ip() -> None:
    report = _make_report()
    eps = [_runtime_ep("203.0.113.9", "ip")]
    merge.merge_runtime_endpoints(report, eps)

    ip_leads = [lead for lead in report.leads if lead.category == LeadCategory.IP]
    assert len(ip_leads) == 1
    assert ip_leads[0].value == "203.0.113.9"
    # 公网 IP 默认建议调证
    assert ip_leads[0].advice == infra.ADVICE_INVESTIGATE


def test_merge_private_ip_marked_skip() -> None:
    """内网 IP（is_private）→ 无需调证。"""
    report = _make_report()
    eps = [_runtime_ep("192.168.1.1", "ip", is_private=True)]
    merge.merge_runtime_endpoints(report, eps)
    lead = next(lead for lead in report.leads if lead.value == "192.168.1.1")
    assert lead.advice == infra.ADVICE_SKIP


def test_merge_applies_default_advice_to_new_leads() -> None:
    """新生成的 DOMAIN/IP Lead advice 非空（infra 分级或默认兜底）。"""
    report = _make_report()
    eps = [
        _runtime_ep("c2.fraud-gw.cn", "domain"),
        _runtime_ep("203.0.113.9", "ip"),
    ]
    merge.merge_runtime_endpoints(report, eps)
    for lead in report.leads:
        assert lead.advice  # 非空


def test_merge_url_endpoint_does_not_generate_lead() -> None:
    """URL 端点本身不直接产 Lead（与 build_endpoint_leads 语义一致），但仍并入端点。"""
    report = _make_report()
    eps = [_runtime_ep("https://c2.fraud-gw.cn/notify", "url")]
    stats = merge.merge_runtime_endpoints(report, eps)
    assert any(ep.value == "https://c2.fraud-gw.cn/notify" for ep in report.endpoints)
    assert stats["new_leads"] == 0


# ---------------------------------------------------------------------------
# meta 打标 / 统计
# ---------------------------------------------------------------------------


def test_merge_sets_meta_runtime_merged_flag() -> None:
    report = _make_report()
    eps = [_runtime_ep("c2.fraud-gw.cn", "domain")]
    merge.merge_runtime_endpoints(report, eps)
    assert report.meta["runtime_merged"] is True
    assert report.meta["runtime_endpoint_count"] == 1


def test_merge_returns_counts() -> None:
    report = _make_report()
    eps = [
        _runtime_ep("c2.fraud-gw.cn", "domain"),
        _runtime_ep("203.0.113.9", "ip"),
    ]
    stats = merge.merge_runtime_endpoints(report, eps)
    assert stats == {"merged": 2, "new_leads": 2, "total_endpoints": 2}


def test_merge_uses_pipeline_dedup_semantics(monkeypatch) -> None:
    """合并必须复用 pipeline._dedup_endpoints（确保零行为偏移）。"""
    from apkscan.core import pipeline

    called: dict[str, bool] = {"dedup": False}
    real_dedup = pipeline._dedup_endpoints

    def _spy(endpoints):
        called["dedup"] = True
        return real_dedup(endpoints)

    monkeypatch.setattr(pipeline, "_dedup_endpoints", _spy)
    report = _make_report()
    merge.merge_runtime_endpoints(report, [_runtime_ep("c2.fraud-gw.cn", "domain")])
    assert called["dedup"] is True


def test_merge_never_raises_on_internal_error(monkeypatch) -> None:
    """内部异常（如 dedup 炸）不抛，返回零统计。"""
    from apkscan.core import pipeline

    def _boom(endpoints):
        raise RuntimeError("dedup exploded")

    monkeypatch.setattr(pipeline, "_dedup_endpoints", _boom)
    report = _make_report()
    stats = merge.merge_runtime_endpoints(report, [_runtime_ep("c2.fraud-gw.cn", "domain")])
    # 不抛；返回的统计是初始零值（total_endpoints 为原始端点数）
    assert stats["merged"] == 0
    assert stats["new_leads"] == 0


# ---------------------------------------------------------------------------
# load_runtime_endpoints
# ---------------------------------------------------------------------------


def _write_runtime_report(path, endpoints_payload: list[dict[str, Any]], **extra: Any) -> None:
    payload = {
        "package_name": "com.test.app",
        "source": "runtime",
        "endpoints": endpoints_payload,
        **extra,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def test_load_runtime_endpoints_rebuilds_from_json(tmp_path) -> None:
    report_file = tmp_path / "runtime_report.json"
    _write_runtime_report(
        report_file,
        [
            {
                "value": "https://c2.fraud-gw.cn/notify",
                "kind": "url",
                "evidences": [
                    {"source": "runtime", "location": "flows.mitm", "snippet": "x"}
                ],
                "is_cleartext": False,
                "is_private": False,
                "is_suspicious": True,
                "enrichment": {},
            },
            {
                "value": "c2.fraud-gw.cn",
                "kind": "domain",
                "evidences": [
                    {"source": "runtime", "location": "flows.mitm", "snippet": "y"}
                ],
            },
        ],
    )

    eps = merge.load_runtime_endpoints(str(report_file))
    by_value = {ep.value: ep for ep in eps}
    assert set(by_value) == {"https://c2.fraud-gw.cn/notify", "c2.fraud-gw.cn"}
    assert by_value["https://c2.fraud-gw.cn/notify"].kind == "url"
    assert by_value["https://c2.fraud-gw.cn/notify"].is_suspicious is True
    assert by_value["c2.fraud-gw.cn"].kind == "domain"
    # source 一律 runtime
    for ep in eps:
        assert all(ev.source == "runtime" for ev in ep.evidences)


def test_load_runtime_endpoints_missing_file_returns_empty(tmp_path) -> None:
    assert merge.load_runtime_endpoints(str(tmp_path / "nope.json")) == []


def test_load_runtime_endpoints_bad_json_returns_empty_logged(tmp_path, caplog) -> None:
    report_file = tmp_path / "runtime_report.json"
    report_file.write_text("{not valid json", encoding="utf-8")
    import logging

    with caplog.at_level(logging.ERROR):
        eps = merge.load_runtime_endpoints(str(report_file))
    assert eps == []
    assert any("runtime" in rec.message for rec in caplog.records)


def test_load_runtime_endpoints_missing_endpoints_array_returns_empty(tmp_path) -> None:
    report_file = tmp_path / "runtime_report.json"
    report_file.write_text(json.dumps({"package_name": "x"}), encoding="utf-8")
    assert merge.load_runtime_endpoints(str(report_file)) == []


def test_load_runtime_endpoints_skips_bad_entries(tmp_path) -> None:
    """坏端点条目（无 value / 非 dict）被跳过，好的仍还原。"""
    report_file = tmp_path / "runtime_report.json"
    _write_runtime_report(
        report_file,
        [
            "not-a-dict",
            {"kind": "domain"},  # 无 value
            {"value": "good.fraud-gw.cn", "kind": "domain"},
        ],
    )
    eps = merge.load_runtime_endpoints(str(report_file))
    assert [ep.value for ep in eps] == ["good.fraud-gw.cn"]


def test_load_runtime_endpoints_synthesizes_evidence_when_missing(tmp_path) -> None:
    """端点无 evidences 时合成一条 runtime 证据，保证下游分级有据可依。"""
    report_file = tmp_path / "runtime_report.json"
    _write_runtime_report(
        report_file,
        [{"value": "c2.fraud-gw.cn", "kind": "domain"}],
    )
    eps = merge.load_runtime_endpoints(str(report_file))
    assert len(eps) == 1
    assert len(eps[0].evidences) == 1
    assert eps[0].evidences[0].source == "runtime"


# ---------------------------------------------------------------------------
# merge_and_rerender
# ---------------------------------------------------------------------------


def test_merge_and_rerender_writes_html_and_json(tmp_path) -> None:
    report = _make_report()
    eps = [_runtime_ep("c2.fraud-gw.cn", "domain")]
    stats = merge.merge_and_rerender(report, eps, str(tmp_path))

    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "report.html").exists()
    assert str(tmp_path / "report.json") in stats["report_paths"]
    assert str(tmp_path / "report.html") in stats["report_paths"]
    # 合并统计也透传
    assert stats["merged"] == 1
    assert stats["new_leads"] == 1


def test_merge_and_rerender_only_json_format(tmp_path) -> None:
    report = _make_report()
    eps = [_runtime_ep("c2.fraud-gw.cn", "domain")]
    stats = merge.merge_and_rerender(report, eps, str(tmp_path), formats=["json"])

    assert (tmp_path / "report.json").exists()
    assert not (tmp_path / "report.html").exists()
    assert stats["report_paths"] == [str(tmp_path / "report.json")]


def test_merge_and_rerender_uses_same_base(tmp_path) -> None:
    """问题 2：merge 重渲用传入的 base（APK 名）写 <base>.{json,html}，不写死 report.*。

    这是「静态写 <apk>.* 而重渲写 report.* 产两套」回退坑的锁定测试：base 一致则只一套。
    """
    report = _make_report()
    eps = [_runtime_ep("c2.fraud-gw.cn", "domain")]
    stats = merge.merge_and_rerender(report, eps, str(tmp_path), "demo")

    assert (tmp_path / "demo.json").exists()
    assert (tmp_path / "demo.html").exists()
    # 不再写死 report.*（否则与静态侧 <apk>.* 产两套报告）。
    assert not (tmp_path / "report.json").exists()
    assert not (tmp_path / "report.html").exists()
    assert str(tmp_path / "demo.json") in stats["report_paths"]
    assert str(tmp_path / "demo.html") in stats["report_paths"]


def test_merge_and_rerender_base_preserves_chinese(tmp_path) -> None:
    """中文 base 也正常写出（报告本就中文）。"""
    report = _make_report()
    stats = merge.merge_and_rerender(report, [], str(tmp_path), "深远记算", formats=["json"])
    assert (tmp_path / "深远记算.json").exists()
    assert stats["report_paths"] == [str(tmp_path / "深远记算.json")]


def test_merge_and_rerender_report_module_missing_not_fatal(tmp_path, monkeypatch) -> None:
    """重渲单格式失败（如渲染异常）不致命：不计入 report_paths，仍返回统计。"""
    report = _make_report()
    eps = [_runtime_ep("c2.fraud-gw.cn", "domain")]

    def _boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("render exploded")

    # 让 html 渲染炸，json 正常。
    from apkscan.report import html as report_html

    monkeypatch.setattr(report_html, "render", _boom)

    stats = merge.merge_and_rerender(report, eps, str(tmp_path))
    assert (tmp_path / "report.json").exists()
    assert str(tmp_path / "report.json") in stats["report_paths"]
    assert str(tmp_path / "report.html") not in stats["report_paths"]
    # 合并仍完成
    assert report.meta["runtime_merged"] is True


def test_merge_and_rerender_returns_report_paths(tmp_path) -> None:
    report = _make_report()
    eps = [_runtime_ep("c2.fraud-gw.cn", "domain")]
    stats = merge.merge_and_rerender(report, eps, str(tmp_path))
    assert isinstance(stats["report_paths"], list)
    assert all(isinstance(p, str) for p in stats["report_paths"])


def test_merge_and_rerender_on_progress_called(tmp_path) -> None:
    report = _make_report()
    eps = [_runtime_ep("c2.fraud-gw.cn", "domain")]
    msgs: list[str] = []
    merge.merge_and_rerender(
        report, eps, str(tmp_path), on_progress=lambda m: msgs.append(m)
    )
    assert msgs  # 至少上报了一条进度
    assert any("并入" in m for m in msgs)


def test_merge_and_rerender_on_progress_exception_swallowed(tmp_path) -> None:
    """GUI 回调炸不应影响合并/重渲。"""
    report = _make_report()
    eps = [_runtime_ep("c2.fraud-gw.cn", "domain")]

    def _bad_cb(_m: str) -> None:
        raise RuntimeError("gui callback exploded")

    stats = merge.merge_and_rerender(report, eps, str(tmp_path), on_progress=_bad_cb)
    assert (tmp_path / "report.json").exists()
    assert stats["report_paths"]


# ---------------------------------------------------------------------------
# GUI-ready：核心模块不含 print / typer / sys.exit
# ---------------------------------------------------------------------------


def test_merge_module_has_no_print_or_typer() -> None:
    """核心模块禁 print / typer / sys.exit / input —— 用 AST 检查真实调用，

    避免误伤 docstring / 注释里对这些禁用项的说明性提及。
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(merge))
    called_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                called_names.add(func.id)
            elif isinstance(func, ast.Attribute):
                # 形如 typer.echo / sys.exit：记 "<root>.<attr>"
                if isinstance(func.value, ast.Name):
                    called_names.add(f"{func.value.id}.{func.attr}")

    assert "print" not in called_names
    assert "input" not in called_names
    assert "sys.exit" not in called_names
    assert not any(n.startswith("typer.") for n in called_names)


# ---------------------------------------------------------------------------
# C5b：用静态配方解密运行时信封报文 → 明文端点并入
# ---------------------------------------------------------------------------

_C5B_KEY = "55f0e4afd83cf8dcae7a4d3daf663467"
_C5B_TS = 1700000000000


def _c5b_recipe_meta() -> dict[str, Any]:
    return {
        "algo": "AES",
        "mode": "CFB",
        "padding": "Pkcs7",
        "segment_size": 128,
        "key": _C5B_KEY,
        "key_encoding": "utf8",
        "iv_derive": "md5(key+ts)[:16]",
        "iv_value": None,
        "envelope_fields": ["data", "timestamp"],
        "payload_encoding": "base64",
        "source": "assets/.../app-service.js",
    }


def _c5b_encrypt(plaintext: str) -> str:
    """用 C5b 配方加密明文，返回信封 data（base64）。"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    try:
        from cryptography.hazmat.decrepit.ciphers.modes import CFB
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.modes import CFB

    kb = _C5B_KEY.encode("utf-8")
    iv = _hashlib.md5(kb + str(_C5B_TS).encode()).hexdigest()[:16].encode("utf-8")
    pb = plaintext.encode("utf-8")
    pad = 16 - (len(pb) % 16)
    padded = pb + bytes([pad]) * pad
    with _warnings.catch_warnings():
        _warnings.simplefilter("ignore")
        enc = Cipher(algorithms.AES(kb), CFB(iv)).encryptor()
        ct = enc.update(padded) + enc.finalize()
    return _b64.b64encode(ct).decode("ascii")


def _write_runtime_report_with_messages(tmp_path, messages: list[dict[str, Any]]) -> str:
    path = tmp_path / "runtime_report.json"
    payload = {
        "package_name": "com.test.app",
        "source": "runtime",
        "capture_complete": True,
        "endpoint_total": 0,
        "endpoints": [],
        "messages": messages,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return str(path)


_C5B_PLAINTEXT = json.dumps(
    {
        "webName": "示例证券",
        "register": "/api/register",
        "login": "/api/login",
        "webConfig": "https://gw.hxhcapi.vip/config",
        "inviteCode": "ABC123",
    },
    ensure_ascii=False,
)


def test_decrypt_runtime_messages_extracts_plaintext_endpoints(tmp_path) -> None:
    """合成 runtime_report.json（含信封）+ report.meta 配方 → 明文端点以
    source=runtime-decrypted 并入 report.endpoints，并产新 lead。"""
    data = _c5b_encrypt(_C5B_PLAINTEXT)
    env = json.dumps({"data": data, "timestamp": _C5B_TS})
    rr_path = _write_runtime_report_with_messages(
        tmp_path, [{"url": "https://api.hxhcapi.vip/post", "response_body": env}]
    )
    report = _make_report(meta={"crypto_recipe": _c5b_recipe_meta()})

    stats = merge.decrypt_runtime_messages(report, rr_path)

    assert stats["decrypted"] == 1
    assert stats["failed"] == 0
    assert stats["plaintext_endpoints"] >= 1
    assert report.meta["runtime_decrypted"] is True

    # 明文里的 webConfig URL 与其 host 应作为端点并入，证据来源 runtime-decrypted。
    values = {ep.value for ep in report.endpoints}
    assert "https://gw.hxhcapi.vip/config" in values
    assert "/api/register" in values or "/api/login" in values
    decrypted_eps = [
        ep
        for ep in report.endpoints
        if any(ev.source == "runtime-decrypted" for ev in ep.evidences)
    ]
    assert decrypted_eps
    # 解密引入的 domain 应产线索。
    domain_leads = [l for l in report.leads if l.category == LeadCategory.DOMAIN]
    assert any("hxhcapi.vip" in l.value for l in domain_leads)


def test_decrypt_runtime_messages_no_recipe_skips(tmp_path) -> None:
    """report.meta 无 crypto_recipe → 不解密、保留密文、不崩、统计 decrypted=0。"""
    data = _c5b_encrypt(_C5B_PLAINTEXT)
    env = json.dumps({"data": data, "timestamp": _C5B_TS})
    rr_path = _write_runtime_report_with_messages(tmp_path, [{"response_body": env}])
    report = _make_report()  # 无配方

    stats = merge.decrypt_runtime_messages(report, rr_path)

    assert stats["decrypted"] == 0
    assert stats["plaintext_endpoints"] == 0
    assert "runtime_decrypted" not in report.meta
    assert report.endpoints == []


def test_decrypt_runtime_messages_bad_envelope_preserved(tmp_path, caplog) -> None:
    """坏信封（坏 base64） → warning + 不并入明文端点，不崩。"""
    env = json.dumps({"data": "!!!not base64!!!", "timestamp": _C5B_TS})
    rr_path = _write_runtime_report_with_messages(tmp_path, [{"response_body": env}])
    report = _make_report(meta={"crypto_recipe": _c5b_recipe_meta()})

    import logging

    with caplog.at_level(logging.WARNING):
        stats = merge.decrypt_runtime_messages(report, rr_path)

    assert stats["decrypted"] == 0
    assert stats["failed"] == 1
    assert report.endpoints == []  # 未并入明文端点
    assert caplog.records


def test_decrypt_runtime_messages_non_envelope_ignored(tmp_path) -> None:
    """报文体非信封（无 data/timestamp） → 不解密、不报失败。"""
    rr_path = _write_runtime_report_with_messages(
        tmp_path, [{"response_body": json.dumps({"foo": "bar"})}]
    )
    report = _make_report(meta={"crypto_recipe": _c5b_recipe_meta()})
    stats = merge.decrypt_runtime_messages(report, rr_path)
    assert stats["decrypted"] == 0
    assert stats["failed"] == 0


def test_decrypt_runtime_messages_missing_crypto_lib(tmp_path, monkeypatch) -> None:
    """缺 cryptography → 不解密、warning、静态报告不受损（保留密文，不崩）。"""
    from apkscan.core import appcrypto

    monkeypatch.setattr(appcrypto, "_HAS_CRYPTO", False)
    data = "anybase64=="
    env = json.dumps({"data": data, "timestamp": _C5B_TS})
    rr_path = _write_runtime_report_with_messages(tmp_path, [{"response_body": env}])
    report = _make_report(meta={"crypto_recipe": _c5b_recipe_meta()})

    stats = merge.decrypt_runtime_messages(report, rr_path)
    assert stats["decrypted"] == 0
    assert stats["failed"] == 1
    assert report.endpoints == []


def test_merge_and_rerender_runs_decryption(tmp_path) -> None:
    """merge_and_rerender 端到端：信封 messages + 配方 → 解密统计进 stats、明文端点入报告。"""
    data = _c5b_encrypt(_C5B_PLAINTEXT)
    env = json.dumps({"data": data, "timestamp": _C5B_TS})
    _write_runtime_report_with_messages(
        tmp_path, [{"url": "https://api.hxhcapi.vip/post", "response_body": env}]
    )
    report = _make_report(meta={"crypto_recipe": _c5b_recipe_meta()})

    stats = merge.merge_and_rerender(report, [], str(tmp_path))

    assert stats["decrypted"] == 1
    assert stats["plaintext_endpoints"] >= 1
    values = {ep.value for ep in report.endpoints}
    assert "https://gw.hxhcapi.vip/config" in values
    assert (tmp_path / "report.json").exists()


def test_merge_and_rerender_no_runtime_report_no_decrypt(tmp_path) -> None:
    """无 runtime_report.json → 解密零统计、不崩、正常重渲。"""
    report = _make_report(meta={"crypto_recipe": _c5b_recipe_meta()})
    stats = merge.merge_and_rerender(report, [], str(tmp_path))
    assert stats["decrypted"] == 0
    assert (tmp_path / "report.json").exists()
