"""HTML 报告出口的三个信号：五层归属链 / 形态存疑 / SNI 伪装。

★为什么单独一个文件：这三条信号此前**只在 letters 出口存在**，主报告模板 0 命中。
  人先读报告做研判、再决定要不要走文书出口——警示到文书阶段才出现，研判已经做完了。
  ``Lead.shape_uncertain`` / ``Lead.sni_masquerade`` 的字段注释明写：这两个字段
  存在的唯一意义就是让下游出口能看见它，而"假定下游会去翻"已经栽过两次。
  故本文件的断言全部是**出口级**的：渲染真 HTML，断言字句真的出现在产物里。

夹具地址一律用文档保留段（``198.51.100.0/24`` / ``example.com``）与合成组织名。
"""

from __future__ import annotations

from apkscan.core import infra
from apkscan.core.models import (
    Confidence,
    Endpoint,
    Lead,
    LeadCategory,
    Report,
)
from apkscan.report import html as report_html
from apkscan.report import letters

# 两个落地 IP：第一个五层齐全（且 org 里埋了 HTML 注入载荷），第二个只有 deferred。
_ATTRIBUTION = {
    "ips": [
        {
            "ip": "198.51.100.7",
            "resource_holder": {"name": "SYNTH-HOLDER-A", "source": "RDAP", "confidence": "high"},
            "origin_network": {
                "asn": 64500,
                "organization": "SYNTH-NET<img src=x onerror=alert(1)>",
                "category": "hosting",
                "confidence": "medium",
            },
            "hosting_provider": {"name": "SYNTH-IDC", "role": "idc", "confidence": "medium"},
            "edge_provider": {"name": "SYNTH-EDGE", "role": "cdn", "tier": "probable"},
        },
        {"ip": "198.51.100.8", "resource_holder": {"deferred": "case_close"}},
    ]
}


def _report(leads: list[Lead], endpoints: list[Endpoint] | None = None) -> Report:
    return Report(
        package_name="com.synthetic.test",
        meta={},
        leads=leads,
        endpoints=endpoints if endpoints is not None else [],
        findings=[],
        analyzer_status=[],
    )


def _ip_lead(value: str, **kw: object) -> Lead:
    kw.setdefault("advice", infra.ADVICE_INVESTIGATE)
    kw.setdefault("confidence", Confidence.HIGH)
    return Lead(category=LeadCategory.IP, value=value, **kw)  # type: ignore[arg-type]


def _render_with_attribution(lead_value: str) -> str:
    """渲染一份「Lead 值为 lead_value + 裸 IP 端点带五层归因」的报告。"""
    return report_html.render_to_string(
        _report(
            [_ip_lead(lead_value)],
            [Endpoint(value="198.51.100.7", kind="ip", enrichment={"attribution": _ATTRIBUTION})],
        )
    )


# ---------------------------------------------------------------------------
# 五层归属链
# ---------------------------------------------------------------------------


def test_attribution_chain_renders_all_five_layers() -> None:
    out = _render_with_attribution("198.51.100.7")
    assert letters.ATTRIBUTION_CHAIN_HEADING in out
    assert "SYNTH-HOLDER-A（RDAP，置信高）" in out  # resource_holder
    assert "AS64500" in out and "hosting" in out  # origin_network
    assert "SYNTH-IDC" in out  # hosting_provider
    assert "SYNTH-EDGE" in out and "较可能" in out  # edge_provider（tier 中文化）


def test_attribution_heading_warns_against_inferring_operator() -> None:
    """标题必须带「勿据此认定 App 运营者」——把基础设施持有方当运营者是本项目最重的错误。"""
    assert "勿据此认定 App 运营者" in _render_with_attribution("198.51.100.7")


def test_service_operator_unknown_disclaimer_once_per_ip() -> None:
    """★每个落地 IP 下都必须有「实际运营者：未知（不从基础设施归属推断）」，一个不能少。"""
    out = _render_with_attribution("198.51.100.7")
    assert out.count(letters.SERVICE_OPERATOR_ROW[1]) == 2  # 夹具 2 个落地 IP


def test_service_operator_is_never_rendered_as_a_known_party() -> None:
    """五层模型里 service_operator 恒 unknown：产物里不得出现「实际运营者：<某公司>」。"""
    out = _render_with_attribution("198.51.100.7")
    for name in ("SYNTH-HOLDER-A", "SYNTH-IDC", "SYNTH-EDGE"):
        assert f"实际运营者</span>：{name}" not in out


def test_lead_with_port_suffix_still_matches_bare_ip_endpoint() -> None:
    """★运行时回灌的 Lead 形如 ``198.51.100.7:31861/tcp``，端点是裸 IP。

    必须走 infra.match_key 剥端口才关联得上——letters 侧正是在这里栽过：**恰恰是 pcap
    实测到的真后端**（最该写清归属的那个）永远关联不上五层链，正文只剩空壳。
    """
    out = _render_with_attribution("198.51.100.7:31861/tcp")
    assert "SYNTH-HOLDER-A" in out, "带端口尾缀的 Lead 没关联上归属链"


def test_attribution_deferred_is_labeled_explicitly_not_unknown() -> None:
    """analyze 阶段未逐 IP 查 RDAP 时标「待结案补全」，不与真正的「查无登记方」混同。"""
    assert "待结案 RDAP 补全" in _render_with_attribution("198.51.100.7")


def test_attribution_absent_renders_no_chain() -> None:
    """没有五层归因就不该出现归属链块（不造空壳）。"""
    out = report_html.render_to_string(_report([_ip_lead("198.51.100.7")]))
    assert letters.ATTRIBUTION_CHAIN_HEADING not in out


def test_attribution_many_ips_are_capped_with_remainder_note() -> None:
    """CDN 多 IP 不得把报告撑爆：限长与「另有 N 个」口径复用 letters（两出口一致）。"""
    many = {"ips": [{"ip": f"198.51.100.{i}", "resource_holder": {"name": f"H{i}"}} for i in range(9)]}
    out = report_html.render_to_string(
        _report(
            [_ip_lead("198.51.100.0")],
            [Endpoint(value="198.51.100.0", kind="ip", enrichment={"attribution": many})],
        )
    )
    assert out.count(letters.SERVICE_OPERATOR_ROW[1]) == letters._MAX_ATTR_IPS
    assert f"另有 {9 - letters._MAX_ATTR_IPS} 个解析 IP 未列" in out


def test_attribution_index_does_not_cross_kinds() -> None:
    """域名与 IP 字面撞车时不得互相串归因（kind 必须入键）。"""
    out = report_html.render_to_string(
        _report(
            [Lead(category=LeadCategory.DOMAIN, value="198.51.100.7", advice=infra.ADVICE_INVESTIGATE)],
            [Endpoint(value="198.51.100.7", kind="ip", enrichment={"attribution": _ATTRIBUTION})],
        )
    )
    assert "SYNTH-HOLDER-A" not in out


# ---------------------------------------------------------------------------
# 形态存疑
# ---------------------------------------------------------------------------


def test_shape_uncertain_warning_reaches_html_outlet() -> None:
    out = report_html.render_to_string(_report([_ip_lead("10.0.0.1", shape_uncertain=True)]))
    assert "标的形态存疑" in out
    assert "发函前请人工确认该值确系网络地址" in out


def test_shape_uncertain_wording_is_the_same_source_as_letters() -> None:
    """★字句只此一份：报告出口渲染的纯文本必须与 letters 的常量同源。

    退化成两份字面，改了一处忘另一处就是必然（本项目已在 notes→出口 上栽过两次）。
    """
    out = report_html.render_to_string(_report([_ip_lead("10.0.0.1", shape_uncertain=True)]))
    plain = letters.spans_to_plain(letters.SHAPE_UNCERTAIN_WARNING_SPANS)
    # 产物里强调段被 <strong> 切开，故按分段逐段核（每段都必须在）。
    for _kind, text in letters.SHAPE_UNCERTAIN_WARNING_SPANS:
        assert text.strip() in out
    assert plain.startswith("⚠ 标的形态存疑：")


def test_shape_uncertain_not_rendered_when_flag_absent() -> None:
    out = report_html.render_to_string(_report([_ip_lead("198.51.100.7")]))
    assert "标的形态存疑" not in out


def test_shape_uncertain_warning_survives_advice_skip() -> None:
    """★即便 advice 被降到 :data:`infra.ADVICE_SKIP` 档（手编 / 旧产物 round-trip）也必须渲染警示。

    静默丢弃正是这个字段要防的那种出口断裂——弱化展示可以，消失不行。
    """
    out = report_html.render_to_string(
        _report([_ip_lead("10.0.0.1", advice=infra.ADVICE_SKIP, shape_uncertain=True)])
    )
    assert "标的形态存疑" in out


# ---------------------------------------------------------------------------
# SNI 伪装
# ---------------------------------------------------------------------------


def test_sni_masquerade_warning_reaches_html_outlet() -> None:
    out = report_html.render_to_string(
        _report([_ip_lead("198.51.100.7", sni_masquerade=["music.example.com"])])
    )
    assert "的名义握手" in out
    assert "music.example.com" in out
    assert "切勿向其发函" in out, "必须点明别向被冒用域名的持有方发函"


def test_sni_masquerade_says_it_is_aggravating_not_mitigating() -> None:
    """语义不能反：伪装是加重信号，不是减分项。"""
    out = report_html.render_to_string(
        _report([_ip_lead("198.51.100.7", sni_masquerade=["music.example.com"])])
    )
    assert "加重信号，非减分项" in out


def test_sni_masquerade_absent_renders_no_warning() -> None:
    out = report_html.render_to_string(_report([_ip_lead("198.51.100.7")]))
    assert "的名义握手" not in out


def test_sni_masquerade_survives_advice_skip() -> None:
    out = report_html.render_to_string(
        _report([_ip_lead("198.51.100.7", advice=infra.ADVICE_SKIP, sni_masquerade=["music.example.com"])])
    )
    assert "的名义握手" in out


# ---------------------------------------------------------------------------
# ★安全：外部数据一律转义（RDAP/ASN org 名、SNI 域名都来自外部）
# ---------------------------------------------------------------------------


def test_external_org_name_cannot_inject_markup() -> None:
    """ASN org 名来自外部富化响应；埋 <img onerror> 必须以转义形式落地。"""
    out = _render_with_attribution("198.51.100.7")
    assert "<img src=x" not in out
    assert "&lt;img src=x" in out


def test_external_sni_name_cannot_inject_markup() -> None:
    """SNI 域名来自样本流量，同样是外部数据。"""
    out = report_html.render_to_string(
        _report([_ip_lead("198.51.100.7", sni_masquerade=["<script>alert(1)</script>"])])
    )
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_no_double_escaping_in_warnings() -> None:
    """HTML 出口不得再叠一层 markdown 转义（会渲染出 &amp;lt; 这种脏字符）。"""
    out = report_html.render_to_string(
        _report(
            [_ip_lead("198.51.100.7", shape_uncertain=True, sni_masquerade=["a-b.example.com"])]
        )
    )
    assert "&amp;lt;" not in out
    assert "a-b.example.com" in out, "markdown 的 _md_safe 转义不该漏进 HTML 出口"


def test_emphasis_is_rendered_as_tags_not_literal_asterisks() -> None:
    """强调走 <strong>；markdown 的 ** 不该原样漏进 HTML。"""
    out = report_html.render_to_string(_report([_ip_lead("10.0.0.1", shape_uncertain=True)]))
    assert "<strong>⚠ 标的形态存疑：</strong>" in out
    assert "**⚠ 标的形态存疑：**" not in out


# ---------------------------------------------------------------------------
# 出口中性层本身（letters 侧，两出口共用）
# ---------------------------------------------------------------------------


def test_markdown_projection_is_unchanged() -> None:
    """★中性层重构后，markdown 出口的字面必须与重构前逐字节一致（letters 出口不许有可见变化）。"""
    assert letters.SHAPE_UNCERTAIN_WARNING == (
        "**⚠ 标的形态存疑：** 该值四段数字均偏低、且在样本中未见以地址形式使用（无端口、"
        "不在 URL 内），形态上与版本号/序号无法区分；判定为地址是靠 ASN 归属落在云/IDC 托管段"
        "推得，非样本内的地址性证据。**发函前请人工确认该值确系网络地址**——若实为版本串，"
        "本函标的不存在，会向无关的云厂商索取一个并不存在的租户。"
    )


def test_sni_markdown_projection_is_unchanged() -> None:
    assert letters.sni_masquerade_warning(["a.example.com"]) == (
        "**⚠ 该连接以 a\\.example\\.com 的名义握手：** 这些域名仅作为 SNI 出现在"
        "**非标准 TLS 端口**上，系伪装、不代表本地址的运营方——被冒用域名的持有方与本案无关，"
        "**切勿向其发函**。本函标的即上述 IP 与端口。伪装本身是自建协议混入背景流量的"
        "加重信号，非减分项。"
    )


def test_sni_spans_empty_for_no_names() -> None:
    assert letters.sni_masquerade_warning_spans([]) == ()
    assert letters.sni_masquerade_warning_spans(["  "]) == ()
    assert letters.sni_masquerade_warning([]) == ""


def test_ip_chain_view_tolerates_bad_input() -> None:
    """坏输入容错、绝不抛（letters 模块铁律）。"""
    assert letters.ip_chain_view(None) is None  # type: ignore[arg-type]
    assert letters.ip_chain_view("nope") is None  # type: ignore[arg-type]
    assert letters.attribution_chain_view(None) == ([], 0)  # type: ignore[arg-type]
    assert letters.attribution_chain_view({"ips": "nope"}) == ([], 0)
    assert letters.attribution_chain_view({"ips": [{}, {"ip": "  "}]}) == ([], 0)


def test_html_render_tolerates_bad_attribution_shapes() -> None:
    """端点 enrichment.attribution 形状坏掉时，渲染不得抛。"""
    for bad in ("nope", 123, [], {"ips": {}}, {"ips": [None, 5]}):
        out = report_html.render_to_string(
            _report(
                [_ip_lead("198.51.100.7")],
                [Endpoint(value="198.51.100.7", kind="ip", enrichment={"attribution": bad})],
            )
        )
        assert letters.ATTRIBUTION_CHAIN_HEADING not in out


def test_endpoint_missing_kind_still_matches_via_wildcard() -> None:
    """端点缺 kind（手编 / 旧产物）时靠通配键捞回——归因不该因少个字段就静默消失。"""
    out = report_html.render_to_string(
        _report(
            [_ip_lead("198.51.100.7")],
            [Endpoint(value="198.51.100.7", kind="", enrichment={"attribution": _ATTRIBUTION})],
        )
    )
    assert "SYNTH-HOLDER-A" in out
