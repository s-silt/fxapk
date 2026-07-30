"""非标端口上的 SNI 伪装：域名是戏服，IP 才是实体。

实测（某案）：`30135/tcp` 上的自建协议连接打出网易云音乐、jsDelivr 镜像、有道、BootCDN
的 SNI。回灌把这些域名一并当业务线索——生成的是一封**指名网易/有道**的调证函，把无关企业
写成了嫌疑方。这是本项目最重的一类错误。

判据按**端口**而非域名白名单：白名单挡不住下一次换域名，而推断链本身可判——「ClientHello
里写着 X，所以这台机器归 X 的运营方」这一步，只在 X 确实是跑在约定端口上的 TLS 服务时才成立。

方向同样要紧：伪装**加重**该 IP 的可疑度（自建协议在混流），不是把它一起降级。所以
域名降档、IP 那条反而点名"它在冒充谁、调证对象是本 IP:端口"。
"""

from __future__ import annotations

from apkscan.core import infra
from apkscan.core.models import LeadCategory
from apkscan.dynamic import pcap_ingest

_BACKEND = "8.138.171.104"  # leak-scan: allow SNI 伪装载体的真后端夹具，需被判公网远端才进 carriers
#: 刻意用一个**不在** KNOWN_INFRA 名单里的域名。
#: 实测那批（music.163.com / 有道 / BootCDN）已陆续进了已知第三方名单，但伪装判据的价值恰恰
#: 在于**不依赖名单**——团伙下次换一个没人收录过的知名域名，名单就已经落后了。
_FAKE_SNI = "player.mediastatic-cdn.com"


def _flow(dst_ip: str, dst_port: int, sni: set[str] | None = None, *,
          inbound: bool = False, payload: int = 4000) -> pcap_ingest.Flow:
    if inbound:
        return pcap_ingest.Flow(
            proto="tcp", src_ip=dst_ip, src_port=dst_port,
            dst_ip="192.168.10.233", dst_port=45678,
            packets=18, payload_bytes=payload, flags={"synack"}, sni=set(sni or ()),
        )
    return pcap_ingest.Flow(
        proto="tcp", src_ip="192.168.10.233", src_port=45678,
        dst_ip=dst_ip, dst_port=dst_port,
        packets=22, payload_bytes=payload, flags={"syn"}, sni=set(sni or ()),
    )


def _summary(*flows: pcap_ingest.Flow) -> pcap_ingest.PcapSummary:
    return pcap_ingest.PcapSummary(flows=list(flows))


def _lead(leads: list, value: str):
    return next(ld for ld in leads if ld.value == value)


# ---------------------------------------------------------------------------
# 判据本体
# ---------------------------------------------------------------------------


def test_sni_on_nonstandard_port_is_flagged() -> None:
    """★核心：只在非标端口上出现过的 SNI，证明不了这台机器归谁运营。"""
    s = _summary(_flow(_BACKEND, 30135, {_FAKE_SNI}), _flow(_BACKEND, 30135, {_FAKE_SNI}, inbound=True))
    carriers = pcap_ingest.sni_camouflage_carriers(s)
    assert carriers == {_FAKE_SNI: [f"{_BACKEND}:30135/tcp"]}


def test_sni_on_standard_port_is_not_flagged() -> None:
    """反向护栏：443 上的 SNI 是正常 TLS 服务，不得被标伪装（否则全库域名线索报废）。"""
    s = _summary(_flow("59.111.181.60", 443, {_FAKE_SNI}))  # leak-scan: allow SNI 伪装载体的真后端夹具，需被判公网远端才进 carriers
    assert pcap_ingest.sni_camouflage_carriers(s) == {}


def test_sni_seen_on_any_standard_port_is_exonerated() -> None:
    """★同名域名只要在标准端口上也出现过，就说明它确实作为 TLS 服务被访问过 → 整体不降级。

    只按"存在一条非标连接"降级，会把真实访问过该域名的样本一并误伤。
    """
    s = _summary(
        _flow(_BACKEND, 30135, {_FAKE_SNI}),           # 伪装的那条
        _flow("59.111.181.60", 443, {_FAKE_SNI}),      # 真访问网易的那条  # leak-scan: allow SNI 伪装载体的真后端夹具，需被判公网远端才进 carriers
    )
    assert pcap_ingest.sni_camouflage_carriers(s) == {}


def test_no_sni_or_no_flows_is_empty() -> None:
    assert pcap_ingest.sni_camouflage_carriers(_summary()) == {}
    assert pcap_ingest.sni_camouflage_carriers(_summary(_flow(_BACKEND, 30135))) == {}


# ---------------------------------------------------------------------------
# 出口：域名降档，IP 加重
# ---------------------------------------------------------------------------


def test_masquerade_domain_leaves_the_subpoena_outlets() -> None:
    """★被冒充的域名不得以「建议调证」出函——那封函的受文机关是网易，与本案无关。"""
    assert infra.classify_domain(_FAKE_SNI)[0] == infra.ADVICE_INVESTIGATE, (
        "前提：该域名本会被判建议调证（不在已知第三方名单里）"
    )
    s = _summary(_flow(_BACKEND, 30135, {_FAKE_SNI}), _flow(_BACKEND, 30135, {_FAKE_SNI}, inbound=True))

    lead = _lead(pcap_ingest.to_report_leads(s), _FAKE_SNI)

    assert lead.category is LeadCategory.DOMAIN
    assert lead.advice == infra.ADVICE_REVIEW, "仍留在清单里供人核，但关掉四个调证出口"
    assert lead.is_c2 is False
    assert "SNI 不构成" in lead.notes and "非标准 TLS 端口" in lead.notes


def test_masquerade_makes_the_ip_more_suspicious_not_less() -> None:
    """★方向锁：域名是戏服，IP 才是嫌疑人的服务器。

    伪装是自建协议在混入背景流量——它加重本端点的可疑度。若把 IP 也一起降档，就等于
    因为对方伪装得好而放过它，方向正好反了。
    """
    s = _summary(_flow(_BACKEND, 30135, {_FAKE_SNI}), _flow(_BACKEND, 30135, {_FAKE_SNI}, inbound=True))

    ip_lead = _lead(pcap_ingest.to_report_leads(s), f"{_BACKEND}:30135/tcp")

    assert ip_lead.advice == infra.ADVICE_INVESTIGATE, "实测双向载荷的后端仍是调证对象"
    assert ip_lead.is_c2 is True
    assert _FAKE_SNI in ip_lead.notes, "要点名它在冒充谁"
    assert "调证对象是本 IP:端口" in ip_lead.notes
    assert "不是" in ip_lead.notes and "被冒充域名的运营方" in ip_lead.notes


def test_masquerade_is_recorded_on_the_endpoint() -> None:
    """结构化落在端点上：读报告的人不必去 notes 里捞，程序化消费方也能筛。"""
    s = _summary(_flow(_BACKEND, 30135, {_FAKE_SNI}), _flow(_BACKEND, 30135, {_FAKE_SNI}, inbound=True))

    eps = pcap_ingest._runtime_endpoint_dicts(s)
    rt = next(e for e in eps if e["value"] == _BACKEND)["enrichment"]["runtime"]

    assert rt["sni_masquerade"] == [_FAKE_SNI]
    assert rt["port"] == 30135
    assert rt["has_payload"] is True


def test_standard_port_endpoint_has_no_masquerade_marker() -> None:
    """不得平白给正常端点加标记（标记贬值成噪声就没人看了）。"""
    s = _summary(_flow("59.111.181.60", 443, {_FAKE_SNI}))  # leak-scan: allow SNI 伪装载体的真后端夹具，需被判公网远端才进 carriers
    rt = pcap_ingest._runtime_endpoint_dicts(s)[0]["enrichment"]["runtime"]
    assert "sni_masquerade" not in rt


def test_masquerade_survives_report_json_roundtrip_into_the_letter() -> None:
    """★接线闭环：伪装警示必须自己走到**调证函正文**，不能停在 Lead.notes。

    letters 全文不渲染 notes（与 shape_uncertain 那次一模一样的断裂）。所以要钉的是整条链路：
    pcap → Lead.sni_masquerade → report.json 往返 → 调证函正文点名"别发给被冒用的那家公司"。
    只要 Lead 字段、report_io 往返、letters 渲染任意一环退回去，本测试即红。
    """
    import json

    from apkscan.core import report_io
    from apkscan.report import letters

    s = _summary(_flow(_BACKEND, 30135, {_FAKE_SNI}), _flow(_BACKEND, 30135, {_FAKE_SNI}, inbound=True))
    lead = _lead(pcap_ingest.to_report_leads(s), f"{_BACKEND}:30135/tcp")
    assert lead.sni_masquerade == [_FAKE_SNI], "pcap 侧没把伪装结构化回带"

    # 经 report.json 的实际序列化形态往返（letters 吃的是磁盘上的 dict，不是内存对象）。
    payload = {"leads": [json.loads(json.dumps(_lead_as_dict(lead)))]}
    revived = report_io.report_from_dict(payload)
    assert revived.leads[0].sni_masquerade == [_FAKE_SNI], "report.json 往返把伪装字段丢了"

    out = letters.build_letters(payload)
    assert len(out) == 1
    body = out[0]["body_md"]
    # _md_safe 会转义 . 与 -（防被渲染成列表/标题），比对时按同规则还原。
    assert _FAKE_SNI in body.replace("\\", ""), "调证函正文没点名被冒用的域名"
    assert "切勿向其发函" in body, "没警示别把函发给被冒用的那家公司"
    assert out[0]["sni_masquerade"] == [_FAKE_SNI]  # 结构化回带供 HTML/PDF 消费


def _lead_as_dict(lead) -> dict:
    """按 report/json.py 的实际做法（dataclasses.asdict + Enum→value）序列化一条 Lead。"""
    import dataclasses

    d = dataclasses.asdict(lead)
    d["category"] = lead.category.value
    d["confidence"] = lead.confidence.value
    d["source_refs"] = [{**r, "evidence_id": f"E{i}"} for i, r in enumerate(d["source_refs"])]
    # pcap 侧的 Lead 不带 evidence_to_obtain——它由 closure 的 _update_target_leads 回写
    # （正是 P1-2 那条链）。letters 要求该字段非空才套打，故这里补上以模拟**结案之后**的状态。
    d["evidence_to_obtain"] = d.get("evidence_to_obtain") or ["租户实名", "访问日志"]
    return d


def test_no_masquerade_means_no_warning_in_letter() -> None:
    """无伪装的普通 IP 线索不得平白多出这段警示（警示贬值成噪声就没人看了）。"""
    from apkscan.report import letters

    s = _summary(_flow("59.111.181.60", 443, set()), _flow("59.111.181.60", 443, set(), inbound=True))  # leak-scan: allow SNI 伪装载体的真后端夹具，需被判公网远端才进 carriers
    lead = _lead(pcap_ingest.to_report_leads(s), "59.111.181.60:443/tcp")  # leak-scan: allow SNI 伪装载体的真后端夹具，需被判公网远端才进 carriers
    assert lead.sni_masquerade == []
    body = letters.build_letters({"leads": [_lead_as_dict(lead)]})[0]["body_md"]
    assert "切勿向其发函" not in body


def test_masquerade_merges_into_an_existing_lead(tmp_path) -> None:
    """★入口级：已存在同 (category,value) 的 Lead 时，后续才发现的伪装名必须并进去。

    走真实入口 merge_into_report_json（不是手搓 dict）。此前 merge_runtime_into_lead_dict
    只搬 Evidence、不碰 sni_masquerade，于是「先并了一份没 SNI 的采集、后来才抓到伪装」
    这条最常见的路径上，结构化警示永远进不了报告，letters 也就渲染不出「切勿向其发函」——
    正是本修复要避免的误发函风险。去掉并集逻辑，本测试即红。
    """
    import json

    from apkscan.report import letters

    report = tmp_path / "report.json"
    report.write_text(json.dumps({"leads": [], "endpoints": [], "meta": {}}, ensure_ascii=False),
                      encoding="utf-8")

    # 第一次采集：同一个后端、同一个端口，但没抓到 SNI。
    first = _summary(_flow(_BACKEND, 30135, set(), payload=1200),
                     _flow(_BACKEND, 30135, set(), inbound=True, payload=800))
    pcap_ingest.merge_into_report_json(str(report), first)
    payload = json.loads(report.read_text(encoding="utf-8"))
    lead = _lead_dict(payload, f"{_BACKEND}:30135/tcp")
    assert not lead.get("sni_masquerade"), "第一次采集本就没有 SNI"

    # 第二次采集：同一后端同一端口，这次抓到了伪装 SNI → 命中既有 Lead 走合并路径。
    second = _summary(_flow(_BACKEND, 30135, {_FAKE_SNI}, payload=1500),
                      _flow(_BACKEND, 30135, {_FAKE_SNI}, inbound=True, payload=900))
    pcap_ingest.merge_into_report_json(str(report), second)
    payload = json.loads(report.read_text(encoding="utf-8"))
    lead = _lead_dict(payload, f"{_BACKEND}:30135/tcp")

    assert lead.get("sni_masquerade") == [_FAKE_SNI], "伪装名没并进既有 Lead"

    # 并且真的走到调证函正文里（这才是这个字段存在的意义）
    lead = dict(lead)
    lead["evidence_to_obtain"] = ["租户实名", "访问日志"]   # closure 回写才填，此处补上
    body = letters.build_letters({"leads": [lead]})[0]["body_md"]
    assert "切勿向其发函" in body


def _lead_dict(payload: dict, value: str) -> dict:
    return next(ld for ld in payload["leads"] if ld.get("value") == value)


def test_known_third_party_domain_stays_skip() -> None:
    """已判「无需调证」的（jsDelivr 等在第三方名单里）不受影响——只降"本会出函"的那些。"""
    assert infra.classify_domain("cdn.jsdelivr.net")[0] == infra.ADVICE_SKIP
    s = _summary(_flow(_BACKEND, 30135, {"cdn.jsdelivr.net"}))
    lead = _lead(pcap_ingest.to_report_leads(s), "cdn.jsdelivr.net")
    assert lead.advice == infra.ADVICE_SKIP
