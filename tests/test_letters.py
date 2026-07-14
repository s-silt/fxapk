"""apkscan.report.letters 单测 + fxapk letters CLI 薄包装测试。

letters 纯函数层把 report.json 的 leads 套打成「调证函 / 协查文书」草稿（markdown），
铁律（与 ioc.py 一致）：纯函数禁 print/typer、对坏输入容错返回空/跳过、绝不抛；
CLI 命令包 try/except、坏输入友好提示 + 退出码 1。

严格过滤（核验要求）：只对**可办案化**的 Lead 套打——
  - advice == "建议调证"；
  - evidence_to_obtain 非空；
  - where_to_request 是真实受文机关（不含「非调证对象 / 无直接调证对象 / 解密配方 /
    跨样本关联」等标记）。
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from apkscan import cli
from apkscan.report import letters

runner = CliRunner()


# ---------------------------------------------------------------------------
# 测试夹具
# ---------------------------------------------------------------------------


def _payment_lead() -> dict:
    """一条可办案化的 PAYMENT 建议调证 Lead（带 where_to_request + evidence + source_refs）。"""
    return {
        "category": "PAYMENT",
        "value": "支付宝 2088xxx",
        "subject": "某某科技有限公司",
        "where_to_request": "支付宝（蚂蚁集团）",
        "evidence_to_obtain": ["该收款账户实名信息", "近 3 个月交易流水", "绑定手机号/设备"],
        "advice": "建议调证",
        "confidence": "HIGH",
        "source_refs": [
            {
                "source": "resource",
                "location": "strings.xml",
                "snippet": "...",
                "evidence_id": "ev-pay-0001",
            },
            {"source": "dex", "location": "com/x/Pay.java", "evidence_id": "ev-pay-0002"},
        ],
    }


def _certificate_signing_lead() -> dict:
    """certificate 的 SIGNING Lead：where_to_request 含「无直接调证对象」→ 应被过滤。"""
    return {
        "category": "SIGNING",
        "value": "AA:BB:CC:DD",
        "subject": "CN=Android Debug",
        "where_to_request": "证书指纹用于跨样本关联同一开发者；无直接调证对象",
        "evidence_to_obtain": ["相同签名指纹的其他涉诈App"],
        "advice": "建议调证",
        "confidence": "HIGH",
        "source_refs": [{"source": "cert", "location": "CN=Android Debug"}],
    }


def _crypto_recipe_lead() -> dict:
    """crypto_recipe 的 Lead：where_to_request 含「解密配方，非调证对象」→ 应被过滤。"""
    return {
        "category": "CRYPTO_RECIPE",
        "value": "AES/CBC key=...",
        "subject": None,
        "where_to_request": "（解密配方，非调证对象）凭此可离线解密全部 {data,timestamp} 信封流量",
        "evidence_to_obtain": ["可据此解密的全部加密流量明文"],
        "advice": "建议调证",
        "confidence": "HIGH",
        "source_refs": [{"source": "dex", "location": "bundle.js"}],
    }


def _no_evidence_lead() -> dict:
    """evidence_to_obtain 为空的 Lead → 应被过滤（没有可调取证据不发函）。"""
    return {
        "category": "DOMAIN",
        "value": "noev.example.com",
        "subject": None,
        "where_to_request": "阿里云",
        "evidence_to_obtain": [],
        "advice": "建议调证",
        "confidence": "MEDIUM",
        "source_refs": [{"source": "dex", "location": "x.java", "evidence_id": "ev-x"}],
    }


def _not_investigate_lead() -> dict:
    """advice 非「建议调证」的 Lead → 应被过滤。"""
    return {
        "category": "CONFIG_KEY",
        "value": "GETUI_APPID=xxxx",
        "subject": None,
        "where_to_request": "个推（每日互动）",
        "evidence_to_obtain": ["应用注册信息"],
        "advice": "无需调证",
        "confidence": "LOW",
        "source_refs": [{"source": "dex", "location": "x.java"}],
    }


def _make_report() -> dict:
    """一份含 5 条 lead 的 report dict：只有 1 条 PAYMENT 可办案化。"""
    return {
        "package_name": "com.fraud.app",
        "meta": {"sample_sha256": "abc123def456"},
        "leads": [
            _payment_lead(),
            _certificate_signing_lead(),
            _crypto_recipe_lead(),
            _no_evidence_lead(),
            _not_investigate_lead(),
        ],
    }


# 免责声明关键词（顶部固定标注）。
_DISCLAIMER_KEYS = ["线索建议草稿", "依法定程序签发", "候选", "非武断认定"]


# ---------------------------------------------------------------------------
# build_letters —— 过滤 + 字段映射
# ---------------------------------------------------------------------------


def test_payment_lead_produces_one_letter() -> None:
    """仅 1 条 PAYMENT 可办案化 → 产 1 份文书。"""
    out = letters.build_letters(_make_report())
    assert len(out) == 1
    assert out[0]["category"] == "PAYMENT"


def test_letter_core_fields() -> None:
    letter = letters.build_letters(_make_report())[0]
    assert letter["recipient"] == "支付宝（蚂蚁集团）"
    assert letter["target"] == "支付宝 2088xxx"
    assert letter["subject"] == "某某科技有限公司"
    assert letter["evidence_items"] == [
        "该收款账户实名信息",
        "近 3 个月交易流水",
        "绑定手机号/设备",
    ]


def test_evidence_refs_use_evidence_id() -> None:
    """source_refs 每条带 evidence_id → evidence_refs 用 evidence_id。"""
    letter = letters.build_letters(_make_report())[0]
    assert letter["evidence_refs"] == ["ev-pay-0001", "ev-pay-0002"]


def test_evidence_refs_fallback_to_source_location() -> None:
    """无 evidence_id 时 evidence_refs 降级为 source:location。"""
    report = {
        "leads": [
            {
                "category": "PAYMENT",
                "value": "x",
                "where_to_request": "支付宝",
                "evidence_to_obtain": ["实名"],
                "advice": "建议调证",
                "source_refs": [{"source": "dex", "location": "a.java"}],
            }
        ]
    }
    letter = letters.build_letters(report)[0]
    assert letter["evidence_refs"] == ["dex:a.java"]


def test_body_md_has_disclaimer_at_top() -> None:
    """body_md 顶部固定免责声明。"""
    letter = letters.build_letters(_make_report())[0]
    body = letter["body_md"]
    # 免责声明应在正文顶部（出现在标题/受文机关之前的前几行）
    head = body[:400]
    for key in _DISCLAIMER_KEYS:
        assert key in head, f"免责声明缺关键词：{key}"


def test_body_md_contains_recipient_target_and_evidence() -> None:
    letter = letters.build_letters(_make_report())[0]
    body = letter["body_md"]
    assert "支付宝（蚂蚁集团）" in body  # 受文机关
    assert "支付宝 2088xxx" in body  # 标的
    assert "该收款账户实名信息" in body  # 待调取证据清单


def test_title_present() -> None:
    letter = letters.build_letters(_make_report())[0]
    assert isinstance(letter["title"], str) and letter["title"].strip()


# ---------------------------------------------------------------------------
# markdown 注入防护 —— Lead.value/subject 抽取自不可信样本，不得污染文书结构
# ---------------------------------------------------------------------------


def _malicious_value_lead() -> dict:
    """value 精心构造：换行 + 伪标题 + 伪字段行 + markdown 链接/加粗语法。"""
    return {
        "category": "PAYMENT",
        "value": "真实值\n\n# 伪造标题\n\n**受文机关（候选）：** 被污染的机关\n[点我](http://evil.example.com)",
        "subject": "**伪造加粗**",
        "where_to_request": "支付宝（蚂蚁集团）",
        "evidence_to_obtain": ["该收款账户实名信息"],
        "advice": "建议调证",
        "confidence": "HIGH",
        "source_refs": [{"source": "dex", "location": "x.java", "evidence_id": "ev-1"}],
    }


def test_body_md_neutralizes_injected_markdown_structure() -> None:
    """恶意 value 里的换行/标题/字段行/链接语法不得在 body_md 里变成真实 markdown 结构。

    注：模板自身的真实受文机关行也会输出 "**受文机关（候选）：**"（来自固定文案，非注入），
    故不能断言"全篇无裸星号"——须针对注入片段本身（含"被污染的机关"字样）精确断言已转义。
    """
    report = {"package_name": "com.fraud.app", "meta": {}, "leads": [_malicious_value_lead()]}
    letter = letters.build_letters(report)[0]
    body = letter["body_md"]

    # 换行被折叠为空格：不会新起一行、不会被解析成独立的标题/字段结构。
    assert "\n# 伪造标题" not in body
    assert "\n\n# 伪造标题" not in body
    # 内容完整保留（不丢证据），但结构字符（# ** [] ()）均被转义，渲染不出标题/加粗/链接。
    assert "被污染的机关" in body
    assert "\\# 伪造标题" in body
    assert "\\*\\*受文机关（候选）：\\*\\* 被污染的机关" in body
    assert "[点我](http://evil.example.com)" not in body  # 未转义的裸链接语法不应出现
    assert "\\[点我\\]" in body


def test_body_md_neutralizes_injected_subject() -> None:
    report = {"package_name": "com.fraud.app", "meta": {}, "leads": [_malicious_value_lead()]}
    letter = letters.build_letters(report)[0]
    body = letter["body_md"]
    assert "**伪造加粗**" not in body
    assert "\\*\\*伪造加粗\\*\\*" in body


def test_write_letters_index_neutralizes_injected_value(tmp_path: Path) -> None:
    """index.md 的 [target](file) 链接文本同样要防注入（比 body_md 更危险的链接语法位置）。"""
    report = {"package_name": "com.fraud.app", "meta": {}, "leads": [_malicious_value_lead()]}
    letters_list = letters.build_letters(report)
    letters.write_letters(letters_list, str(tmp_path))
    index_text = (tmp_path / "letters" / "index.md").read_text(encoding="utf-8")
    assert "\n\n# 伪造标题" not in index_text
    assert "[点我](http://evil.example.com)" not in index_text
    assert "\\[点我\\]" in index_text


# ---------------------------------------------------------------------------
# 严格过滤 —— 各类 Lead 被排除
# ---------------------------------------------------------------------------


def test_certificate_signing_lead_filtered_out() -> None:
    """where_to_request 含「无直接调证对象」→ 不产函。"""
    report = {"leads": [_certificate_signing_lead()]}
    assert letters.build_letters(report) == []


def test_crypto_recipe_lead_filtered_out() -> None:
    """where_to_request 含「解密配方 / 非调证对象」→ 不产函。"""
    report = {"leads": [_crypto_recipe_lead()]}
    assert letters.build_letters(report) == []


def test_empty_evidence_lead_filtered_out() -> None:
    """evidence_to_obtain 空 → 不产函。"""
    report = {"leads": [_no_evidence_lead()]}
    assert letters.build_letters(report) == []


def test_non_investigate_lead_filtered_out() -> None:
    """advice 非「建议调证」→ 不产函。"""
    report = {"leads": [_not_investigate_lead()]}
    assert letters.build_letters(report) == []


def test_missing_where_to_request_filtered_out() -> None:
    """where_to_request 缺失/空 → 不产函（无受文机关）。"""
    report = {
        "leads": [
            {
                "category": "PAYMENT",
                "value": "x",
                "where_to_request": "",
                "evidence_to_obtain": ["实名"],
                "advice": "建议调证",
                "source_refs": [],
            }
        ]
    }
    assert letters.build_letters(report) == []


# ---------------------------------------------------------------------------
# 坏 report —— 容错返回空、绝不抛
# ---------------------------------------------------------------------------


def test_report_not_a_dict_returns_empty() -> None:
    assert letters.build_letters("not-a-dict") == []  # type: ignore[arg-type]
    assert letters.build_letters(None) == []  # type: ignore[arg-type]


def test_missing_leads_key_returns_empty() -> None:
    assert letters.build_letters({"meta": {}}) == []


def test_leads_not_a_list_returns_empty() -> None:
    assert letters.build_letters({"leads": "oops"}) == []
    assert letters.build_letters({"leads": None}) == []


def test_non_dict_lead_skipped() -> None:
    report = {"leads": ["not-a-dict", 42, None, _payment_lead()]}
    out = letters.build_letters(report)
    assert len(out) == 1
    assert out[0]["target"] == "支付宝 2088xxx"


# ---------------------------------------------------------------------------
# write_letters —— 落盘 + index.md + 文件名安全化
# ---------------------------------------------------------------------------


def test_write_letters_creates_files_and_index(tmp_path: Path) -> None:
    out_letters = letters.build_letters(_make_report())
    paths = letters.write_letters(out_letters, str(tmp_path))
    assert paths  # 返回写出的路径列表
    # 每份文书 + index.md
    letters_dir = tmp_path / "letters"
    assert letters_dir.is_dir()
    index = letters_dir / "index.md"
    assert index.is_file()
    assert str(index) in paths
    # 至少一份文书 md
    mds = [p for p in letters_dir.glob("*.md") if p.name != "index.md"]
    assert len(mds) == 1


def test_write_letters_index_lists_each_letter(tmp_path: Path) -> None:
    out_letters = letters.build_letters(_make_report())
    letters.write_letters(out_letters, str(tmp_path))
    index_text = (tmp_path / "letters" / "index.md").read_text(encoding="utf-8")
    assert "支付宝 2088xxx" in index_text  # 标的进索引


def test_write_letters_filename_sanitized(tmp_path: Path) -> None:
    """value 含 / : 等非法文件名字符 → 被清理。"""
    dirty = {
        "leads": [
            {
                "category": "DOMAIN",
                "value": "http://a/b:c*d?.com",
                "where_to_request": "阿里云",
                "evidence_to_obtain": ["租户实名"],
                "advice": "建议调证",
                "source_refs": [{"source": "dex", "location": "x.java"}],
            }
        ]
    }
    out_letters = letters.build_letters(dirty)
    paths = letters.write_letters(out_letters, str(tmp_path))
    md_paths = [p for p in paths if not p.endswith("index.md")]
    assert len(md_paths) == 1
    name = Path(md_paths[0]).name
    # 文件名不含非法字符
    for ch in '/\\:*?"<>|':
        assert ch not in name


def test_write_letters_empty_writes_index_only(tmp_path: Path) -> None:
    paths = letters.write_letters([], str(tmp_path))
    # 空也写 index.md（稳定输出），无其它 md
    index = tmp_path / "letters" / "index.md"
    assert index.is_file()
    assert str(index) in paths
    mds = [p for p in (tmp_path / "letters").glob("*.md") if p.name != "index.md"]
    assert mds == []


def test_write_letters_content_utf8(tmp_path: Path) -> None:
    out_letters = letters.build_letters(_make_report())
    paths = letters.write_letters(out_letters, str(tmp_path))
    md = next(p for p in paths if not p.endswith("index.md"))
    text = Path(md).read_text(encoding="utf-8")
    # 顶部免责声明 + 中文不乱码
    for key in _DISCLAIMER_KEYS:
        assert key in text


# ---------------------------------------------------------------------------
# CLI：fxapk letters
# ---------------------------------------------------------------------------


def _write_report_json(path: Path) -> None:
    path.write_text(json.dumps(_make_report(), ensure_ascii=False), encoding="utf-8")


def test_cli_letters_happy_path(tmp_path: Path) -> None:
    report_json = tmp_path / "case.json"
    _write_report_json(report_json)
    out_dir = tmp_path / "letters_out"

    res = runner.invoke(cli.app, ["letters", str(report_json), "--out", str(out_dir)])
    assert res.exit_code == 0
    assert (out_dir / "letters").is_dir()
    assert (out_dir / "letters" / "index.md").is_file()
    # 打印生成份数（1 份）
    assert "1" in res.output


def test_cli_letters_default_out_is_report_dir(tmp_path: Path) -> None:
    report_json = tmp_path / "mycase.json"
    _write_report_json(report_json)

    res = runner.invoke(cli.app, ["letters", str(report_json)])
    assert res.exit_code == 0
    # 默认 out = report.json 同目录 → tmp_path/letters/
    assert (tmp_path / "letters" / "index.md").is_file()


def test_cli_letters_missing_file(tmp_path: Path) -> None:
    res = runner.invoke(cli.app, ["letters", str(tmp_path / "nope.json")])
    assert res.exit_code == 1
    assert res.exception is None or isinstance(res.exception, SystemExit)
    assert "错误" in res.output or "找不到" in res.output or "不存在" in res.output


def test_cli_letters_bad_json(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json", encoding="utf-8")
    res = runner.invoke(cli.app, ["letters", str(bad)])
    assert res.exit_code == 1
    assert res.exception is None or isinstance(res.exception, SystemExit)
    assert "错误" in res.output or "解析" in res.output or "JSON" in res.output


# ---------------------------------------------------------------------------
# 五层基础设施归属链渲染进调证函（slice-1c-2）
# ---------------------------------------------------------------------------


def _lead_for(value: str) -> dict:
    """一条可办案化 Lead（advice=建议调证 + evidence + 真实受文机关），value 用于关联 endpoint。"""
    return {
        "category": "DOMAIN", "value": value, "subject": "某科技有限公司",
        "where_to_request": "域名注册商 / 云厂商", "advice": "建议调证",
        "evidence_to_obtain": ["注册人实名", "租户日志"],
        "source_refs": [{"evidence_id": "E1"}],
    }


def _five_layer(ip: str, *, holder: str | None = None, asn: int | None = None,
                asn_org: str = "", category: str = "unknown", edge: str | None = None) -> dict:
    return {
        "ip": ip,
        "resource_holder": {"name": holder, "source": "rdap-ip" if holder else None,
                            "confidence": "high" if holder else "unknown"},
        "origin_network": {"asn": asn, "organization": asn_org or None, "category": category,
                           "confidence": "high" if asn is not None else "unknown"},
        "hosting_provider": {"name": asn_org or None, "role": "cloud_host" if asn_org else None,
                             "confidence": "medium" if asn_org else "unknown"},
        "edge_provider": {"name": edge, "role": "reverse_proxy" if edge else None,
                          "tier": "probable" if edge else None},
        "service_operator": {"name": None, "confidence": "unknown"},
    }


def _report_with_attr(value: str, ips: list[dict]) -> dict:
    return {
        "leads": [_lead_for(value)],
        "endpoints": [{"value": value, "kind": "domain",
                       "enrichment": {"attribution": {"endpoint": value, "kind": "domain", "ips": ips}}}],
    }


def test_attribution_chain_rendered_in_letter() -> None:
    """★五层归属链套进调证函正文，且作结构化字段 attribution 回带。"""
    ips = [_five_layer("45.76.1.1", holder="VULTR-AS20473", asn=20473, asn_org="Vultr",
                       category="cloud", edge="Cloudflare")]
    out = letters.build_letters(_report_with_attr("pay.x.com", ips))
    assert len(out) == 1
    body = out[0]["body_md"]
    assert "基础设施归属链" in body
    assert "落地 IP" in body and "45" in body
    assert "VULTR-AS20473".replace("-", "\\-") in body  # 资源登记方（_md_safe 转义了 -）
    assert "AS20473" in body and "cloud" in body        # 网络运营方
    assert "Cloudflare" in body and "较可能" in body      # 边缘（tier=probable→较可能）
    assert out[0]["attribution"] is not None and out[0]["attribution"]["ips"][0]["ip"] == "45.76.1.1"


def test_attribution_unknown_layers_and_edge_labeled() -> None:
    """未知层显式标「未知」、edge 未识别标「未识别专属特征」（不塞空、不冒充）。"""
    ips = [_five_layer("1.1.1.1", holder=None, asn=13335, asn_org="Cloudflare", category="cdn", edge=None)]
    body = letters.build_letters(_report_with_attr("x.com", ips))[0]["body_md"]
    assert "资源登记方：未知" in body
    assert "边缘/CDN/代理：未识别专属特征" in body


def test_attribution_service_operator_never_inferred() -> None:
    """★核心纪律：每个落地 IP 都标『实际运营者：未知（不从基础设施归属推断）』，防把持有方当运营者。"""
    ips = [_five_layer("45.76.1.1", holder="X", asn=1, asn_org="Y", category="cloud", edge="Z")]
    body = letters.build_letters(_report_with_attr("x.com", ips))[0]["body_md"]
    assert body.count("实际运营者：未知") == 1
    assert "不从基础设施归属推断" in body


def test_attribution_absent_no_section() -> None:
    """无 endpoints / 无匹配 value / 无 attribution → 不渲染该段，且不破坏既有正文。"""
    # 无 endpoints
    body1 = letters.build_letters({"leads": [_lead_for("x.com")]})[0]["body_md"]
    assert "基础设施归属链" not in body1 and "拟调取证据" in body1
    # endpoints 存在但 value 不匹配
    rep = {"leads": [_lead_for("a.com")],
           "endpoints": [{"value": "b.com", "enrichment": {"attribution": {"ips": [_five_layer("1.1.1.1")]}}}]}
    out = letters.build_letters(rep)
    assert "基础设施归属链" not in out[0]["body_md"] and out[0]["attribution"] is None


def test_attribution_markdown_injection_escaped() -> None:
    """★安全：RDAP/ASN org 是外部数据，恶意 markdown 被 _md_safe 转义，不破坏文书结构。"""
    ips = [_five_layer("1.1.1.1", holder="Evil](http://x)", asn=1, asn_org="**bold** [x](y)",
                       category="cloud", edge="a`code`b")]
    body = letters.build_letters(_report_with_attr("x.com", ips))[0]["body_md"]
    assert "](http://x)" not in body   # 链接语法被转义
    assert "**bold**" not in body       # 加粗语法被转义
    assert "`code`" not in body         # 行内代码被转义


def test_attribution_many_ips_capped() -> None:
    """域名解析到很多 IP → 只展示前 _MAX_ATTR_IPS 个 + 「另有 N 个」提示（防文书爆长）。"""
    ips = [_five_layer(f"10.0.0.{i}", asn=i + 1, asn_org=f"Org{i}", category="cloud") for i in range(8)]
    body = letters.build_letters(_report_with_attr("x.com", ips))[0]["body_md"]
    assert body.count("- 落地 IP") == letters._MAX_ATTR_IPS  # 前缀区分标题里"按落地 IP 分层"
    assert f"另有 {8 - letters._MAX_ATTR_IPS} 个解析 IP 未列" in body


def test_attribution_robust_bad_shapes() -> None:
    """坏形状（endpoints 非 list、ips 非 list、层非 dict、混入坏元素）→ 容错、绝不抛。"""
    assert letters.build_letters({"leads": [_lead_for("x")], "endpoints": "nope"})  # 不抛
    rep = {"leads": [_lead_for("x")],
           "endpoints": [{"value": "x", "enrichment": {"attribution": {"ips": [None, 5, _five_layer("9.9.9.9", asn=1, asn_org="Z", category="cloud")]}}}]}
    body = letters.build_letters(rep)[0]["body_md"]
    assert "9.9.9.9".replace(".", "\\.") in body  # 坏元素跳过、有效的仍渲染


def test_attribution_index_robust_bad_report() -> None:
    """_attribution_index 坏顶层输入容错、绝不抛（模块铁律）。"""
    assert letters._attribution_index(None) == {}
    assert letters._attribution_index([]) == {}
    assert letters._attribution_index({"endpoints": "nope"}) == {}


def test_attribution_no_crossmatch_on_type_mismatch() -> None:
    """Lead.value 与 endpoint.value 类型不同（123 vs "123"）不得串号关联。"""
    rep = {
        "leads": [dict(_lead_for("x"), value=123)],
        "endpoints": [{"value": "123", "enrichment": {"attribution": {"ips": [_five_layer("10.0.0.9", asn=1)]}}}],
    }
    assert letters.build_letters(rep)[0]["attribution"] is None


def test_attribution_empty_records_not_counted() -> None:
    """无 IP 的空记录不占限长额度、不渲染成「落地 IP（未知）」垃圾。"""
    ips = [{}] * 5 + [_five_layer("10.0.0.4", asn=1, asn_org="Z", category="cloud")]
    body = letters.build_letters(_report_with_attr("x.com", ips))[0]["body_md"]
    assert "10.0.0.4".replace(".", "\\.") in body
    assert "落地 IP（未知）" not in body and "另有" not in body
