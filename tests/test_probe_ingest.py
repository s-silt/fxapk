"""apkscan.dynamic.probe_ingest 的单测。

probe_ingest 把 46 个独立 frida 探针(`-l` 注入)吐到 console 的 `[tag][LEAD-...]` 散点输出，
解析→按 LeadCategory 分类→去重→聚成调证台账(md/json)，并可追加进 report.json。
本套测试覆盖：解析只取含 [LEAD 的行、tag→category 分类、去重、台账分组、report.json 追加。
"""

from __future__ import annotations

import json

from apkscan.core.models import LeadCategory
from apkscan.dynamic import probe_ingest


# ---- 真实探针输出取样（格式与 probe-templates/*.js 实际 console.log 一致）----
_SAMPLE_LOG = "\n".join(
    [
        "[pay][alipay] PayTask.payV2 调起：",
        "[pay][alipay]   seller_id = 2088123456789012  [LEAD-定人:收款主体→向支付宝调实名结算账户]",
        "[pay][alipay]   notify_url = https://pay.evil-backend.com/notify  [LEAD-穿透:真后端]",
        "[pay][wechat]   partnerId = 1900000109  [LEAD-定人:商户号→向财付通/微信支付调实名结算账户]",
        "[sms][LEAD-定人] 转发 destinationAddress=+8613800138000 正文=验证码123456 [LEAD-OTP]",
        "[push-c2][LEAD-C2] payload 含 wss://c2.evil-backend.com:8443/cmd",
        "[sens][LEAD-固证] 读取通讯录 ← ContentResolver.query content://contacts",
        "[ks][LEAD-固证:可拷脱机解密] alias=\"chat_key\" 类型=对称密钥 安全级别=软件(可拷走→脱机解密)",
        "[a11y][LEAD-固证] dispatchGesture ← 模拟手势(自动确认转账)",
        "[nfc][LEAD-固证] IsoDep.transceive >>> 00A4040007A0000000031010  [LEAD-定人] SELECT AID=A0000000031010",
        "[netstat] [LEAD->接入节点] 106.53.21.146:30113  SYN_SENT",
        "[sdk] OpenInstall appKey = ehahb5  [LEAD]",
        "[tg] TL_auth_signIn username=qq888999  [LEAD->登录明文]",
        "[nav] onCreate com.x.SplashActivity   <== 疑似 splash/loading/视频层",  # 无 LEAD，应被忽略
        "[wipe] 已就绪 —— 普通日志行，无 LEAD",  # 无 LEAD，应被忽略
    ]
)


def test_parse_only_keeps_lead_lines() -> None:
    """只解析含 [LEAD 的行，普通日志行(onCreate/已就绪)被忽略。"""
    leads = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    assert len(leads) >= 11  # 11 条带 LEAD 的取样
    for pl in leads:
        assert "[LEAD" in pl.raw


def test_classify_pay_to_payment() -> None:
    leads = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    pay = [pl for pl in leads if pl.probe == "pay"]
    assert pay, "应解析出 pay 探针的线索"
    assert all(pl.category == LeadCategory.PAYMENT for pl in pay)
    # 商户号/seller_id 的 where_to_request 指向支付机构
    assert any("支付" in (pl.where_to_request or "") for pl in pay)


def test_classify_sms_to_sms_forwarding() -> None:
    leads = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    sms = [pl for pl in leads if pl.probe == "sms"]
    assert sms and all(pl.category == LeadCategory.SMS_FORWARDING for pl in sms)


def test_classify_push_c2_to_self_hosted_im() -> None:
    leads = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    c2 = [pl for pl in leads if pl.probe == "push-c2"]
    assert c2 and all(pl.category == LeadCategory.SELF_HOSTED_IM for pl in c2)


def test_classify_sensitive_to_victim_data() -> None:
    leads = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    sens = [pl for pl in leads if pl.probe == "sens"]
    assert sens and all(pl.category == LeadCategory.VICTIM_DATA for pl in sens)


def test_classify_keystore_to_crypto_recipe() -> None:
    leads = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    ks = [pl for pl in leads if pl.probe == "ks"]
    assert ks and all(pl.category == LeadCategory.CRYPTO_RECIPE for pl in ks)


def test_classify_a11y_to_remote_control() -> None:
    leads = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    a = [pl for pl in leads if pl.probe == "a11y"]
    assert a and all(pl.category == LeadCategory.REMOTE_CONTROL for pl in a)


def test_classify_nfc_to_card_merchant() -> None:
    leads = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    n = [pl for pl in leads if pl.probe == "nfc"]
    assert n and all(pl.category == LeadCategory.CARD_MERCHANT for pl in n)


def test_classify_netstat_to_ip() -> None:
    leads = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    ns = [pl for pl in leads if pl.probe == "netstat"]
    assert ns and all(pl.category == LeadCategory.IP for pl in ns)
    assert any("30113" in pl.value for pl in ns)


def test_value_strips_bracket_markers() -> None:
    """value 去掉 [tag]/[LEAD..] 方括号标记，保留真锚点内容。"""
    leads = probe_ingest.parse_probe_log("[sdk] OpenInstall appKey = ehahb5  [LEAD]")
    assert leads
    assert "ehahb5" in leads[0].value
    assert "[LEAD" not in leads[0].value and "[sdk]" not in leads[0].value


def test_dedup_by_category_and_value() -> None:
    dup = "[sdk] appKey = ehahb5 [LEAD]\n[sdk] appKey = ehahb5 [LEAD]\n[sdk] appKey = other [LEAD]"
    leads = probe_ingest.dedup(probe_ingest.parse_probe_log(dup))
    vals = [pl.value for pl in leads]
    assert len(vals) == len(set((pl.category, pl.value) for pl in leads))
    assert len([v for v in vals if "ehahb5" in v]) == 1


def test_build_ledger_md_groups_by_category() -> None:
    md = probe_ingest.build_ledger_md(probe_ingest.parse_probe_log(_SAMPLE_LOG))
    assert "# " in md or "## " in md  # 有标题
    # 分类中文名/where_to_request 出现
    assert "PAYMENT" in md or "支付" in md
    assert "向" in md  # where_to_request 含"向…调"
    assert "ehahb5" in md  # 锚点值进了台账


def test_to_report_leads_sets_runtime_source_and_advice() -> None:
    rls = probe_ingest.to_report_leads(probe_ingest.parse_probe_log(_SAMPLE_LOG))
    assert rls
    for lead in rls:
        assert lead.source_refs and lead.source_refs[0].source.startswith("runtime")
        assert lead.advice in ("建议调证", "待核")
    # is_runtime_seen 应为 True（source=runtime）
    assert all(lead.is_runtime_seen for lead in rls)


def test_coverage_axes_flags_missing_and_suggests() -> None:
    """只抓到 PAYMENT(定人轴)时，穿透/固证轴标未覆盖并给补跑建议。"""
    leads = probe_ingest.parse_probe_log("[pay] seller_id=2088123 [LEAD-定人]")
    cov = probe_ingest.coverage_axes(leads)
    assert len(cov) == 3  # 定人/穿透/固证
    ren = {k: v for k, v in cov.items()}
    dingren = next(v for k, v in ren.items() if "定人" in k)
    assert dingren["covered"] and "PAYMENT" in dingren["categories"]
    chuantou = next(v for k, v in ren.items() if "穿透" in k)
    assert not chuantou["covered"]
    assert "http-url" in chuantou["suggestion"] or "netstat" in chuantou["suggestion"]
    guzheng = next(v for k, v in ren.items() if "固证" in k)
    assert not guzheng["covered"] and guzheng["suggestion"]


def test_ledger_md_includes_coverage_section() -> None:
    md = probe_ingest.build_ledger_md(probe_ingest.parse_probe_log(_SAMPLE_LOG))
    assert "取证完备性" in md
    assert "定人" in md and "穿透" in md and "固证" in md


def test_build_ledger_md_escapes_injection_in_value() -> None:
    """★回归（codex 全库审计 P1）：探针 value/probe 样本可控，markdown 台账须转义反引号/HTML/链接，
    不裸包 inline-code 让载荷逃逸注入（主 HTML 报告另走 Jinja 自动转义、不受此路径影响）。"""
    from apkscan.core.models import LeadCategory

    payload = "x` <img src=x onerror=alert(document.domain)> `"
    lead = probe_ingest.ProbeLead(category=LeadCategory.PAYMENT, value=payload, probe="pay", raw=payload)
    md = probe_ingest.build_ledger_md([lead])
    assert "<img" not in md.replace("\\<img", "")  # 无裸 <img（只余被转义的 \<img）
    assert "\\`" in md  # 反引号被转义，载荷无法逃逸 inline-code


def test_merge_into_report_json_appends_and_dedups(tmp_path) -> None:
    report = {"leads": [{"category": "PAYMENT", "value": "已存在 2088", "advice": "建议调证"}]}
    p = tmp_path / "report.json"
    p.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
    pls = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    added = probe_ingest.merge_into_report_json(str(p), pls)
    assert added > 0
    out = json.loads(p.read_text(encoding="utf-8"))
    assert len(out["leads"]) == 1 + added
    # 原有 lead 仍在
    assert any(l.get("value") == "已存在 2088" for l in out["leads"])
    # 新 lead 带 source=runtime
    new_lead = next(l for l in out["leads"] if "ehahb5" in str(l.get("value", "")))
    assert new_lead["source_refs"][0]["source"].startswith("runtime")


# ======================================================================
# 原子写：写中途失败不留半截坏 JSON
# ======================================================================


def test_merge_atomic_keeps_old_content_when_write_fails(tmp_path, monkeypatch) -> None:
    p = tmp_path / "report.json"
    original = {"leads": [{"category": "PAYMENT", "value": "已存在 2088", "advice": "建议调证"}]}
    p.write_text(json.dumps(original, ensure_ascii=False, indent=2), encoding="utf-8")

    def boom(*_a, **_k):
        raise OSError("disk full (simulated)")

    monkeypatch.setattr(probe_ingest.atomic_write_text.__module__ + ".Path.write_text", boom, raising=True)

    pls = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    added = probe_ingest.merge_into_report_json(str(p), pls)
    assert added == 0
    reloaded = json.loads(p.read_text(encoding="utf-8"))
    assert reloaded == original


# ======================================================================
# runtime 确认合并（非 dedup 丢弃）
# ======================================================================


def test_merge_runtime_confirms_existing_static_lead(tmp_path) -> None:
    """静态已有同 (category,value)，回灌 runtime 探针观测 → 合并升为活体确认，不丢 runtime 证据。"""
    p = tmp_path / "report.json"
    # OpenInstall appKey = ehahb5 → CONFIG_KEY / value 含 "ehahb5"
    pls = probe_ingest.parse_probe_log("[sdk] OpenInstall appKey = ehahb5  [LEAD]")
    runtime_lead = probe_ingest.to_report_leads(pls)[0]
    static_lead = {
        "category": runtime_lead.category.value,
        "value": runtime_lead.value,
        "advice": "建议调证",
        "source_refs": [{"source": "dex", "location": "com/x/Cfg", "snippet": "静态硬编码"}],
        "is_runtime_seen": False,
    }
    p.write_text(json.dumps({"leads": [static_lead]}, ensure_ascii=False, indent=2), encoding="utf-8")

    probe_ingest.merge_into_report_json(str(p), pls)
    out = json.loads(p.read_text(encoding="utf-8"))
    same = [l for l in out["leads"] if l.get("value") == runtime_lead.value]
    assert len(same) == 1  # 未新增重复
    merged = same[0]
    sources = [str(ev.get("source", "")) for ev in merged.get("source_refs", [])]
    assert any(s.startswith("runtime") for s in sources)
    assert any(s == "dex" for s in sources)
    assert merged.get("is_runtime_seen") is True


# ======================================================================
# Evidence.observed_at 回灌落库
# ======================================================================


def test_parse_extracts_leading_timestamp() -> None:
    """行首 ISO 时间戳被解析进 ProbeLead.observed_at（epoch 秒）；无则 None。"""
    ts_line = "2026-07-02 10:30:00 [sdk] appKey = ehahb5 [LEAD]"
    pls = probe_ingest.parse_probe_log(ts_line)
    assert pls
    assert pls[0].observed_at is not None
    # 无时间戳的行 observed_at 为 None
    plain = probe_ingest.parse_probe_log("[sdk] appKey = xyz [LEAD]")
    assert plain and plain[0].observed_at is None


def test_observed_at_落库_into_report_json(tmp_path) -> None:
    p = tmp_path / "report.json"
    p.write_text(json.dumps({"leads": []}, ensure_ascii=False), encoding="utf-8")
    pls = probe_ingest.parse_probe_log("2026-07-02 10:30:00 [sdk] appKey = ehahb5 [LEAD]")
    probe_ingest.merge_into_report_json(str(p), pls)
    out = json.loads(p.read_text(encoding="utf-8"))
    lead = next(l for l in out["leads"] if "ehahb5" in str(l.get("value", "")))
    assert lead["source_refs"][0].get("observed_at") is not None
