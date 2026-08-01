"""非标端口上的 SNI 伪装：域名是戏服，IP 才是实体。

实测形态：某非标端口上的自建协议连接，在 ClientHello 里打出多个知名内容分发 / 笔记 / 音乐
服务的 SNI。若把这些域名一并当业务线索，套打出来的就是一份指向那些服务持有方的文书，把无关
第三方列成了标的——本项目最重的一类误判。

判据按**端口**而非域名白名单：白名单挡不住下一次换域名，而推断链本身可判——「ClientHello
里写着 X，所以这台机器归 X 的运营方」这一步，只在 X 确实是跑在约定端口上的 TLS 服务时才成立。

方向同样要紧：伪装**加重**该 IP 的可疑度（自建协议在混流），不是把它一起降级。所以
域名降档、IP 那条反而点名"它在冒充谁、标的是本 IP:端口"。
"""

from __future__ import annotations

from apkscan.core import infra
from apkscan.core.leads import build_endpoint_leads
from apkscan.core.models import SNI_MASQUERADE_KEY, LeadCategory
from apkscan.dynamic import pcap_ingest

#: 合成的「公网远端」夹具地址，取自 RFC 6598 共享地址空间（100.64.0.0/10）。
#:
#: ★为什么不用 RFC 5737 的文档段：``ipaddress`` 把 192.0.2.0/24 那三段判为 ``is_private``，而
#:   ``pcap_ingest._ip_public`` 要求非私网才认作公网远端——文档段根本进不了 carriers，判据跑
#:   不起来。而 leak-scan 拦的恰恰是 ``is_global`` 为真的字面。两条判据结构上互斥，于是此前
#:   只能逐行写行内豁免顶着真实地址用，真实后端地址因此反复出现在公开仓库里。
#:
#:   共享地址空间同时满足两边：``is_global`` 为假故护栏放行、无需任何豁免；``is_private`` 亦为
#:   假故仍被判作公网远端。该段保留给运营商级 NAT、不分配给终端，天然不会是任何真实后端。
#:   ★注意它过不了 ``infra.classify_ip``（那条按 ``is_global`` 判），故只适用于本文件这类
#:   走 pcap 层判据的夹具；断言 IP 分档的测试仍需另想办法。
_BACKEND = "100.64.0.10"
#: 标准 TLS 端口上的对照地址（同段另一个值）。
_STD_PORT_HOST = "100.64.0.20"
#: 承载伪装 SNI 的非标端口。判据只关心「是否落在标准 TLS 端口名单内」，具体数值无关——
#: 故取一个不含任何编号语义的值，不必也不该照抄实测样本里的那个。
_ODD_PORT = 40001
#: 刻意用一个**不在** KNOWN_INFRA 名单里的域名。
#: 实测被借用的那批知名域名已陆续进了已知第三方名单，但伪装判据的价值恰恰在于**不依赖名单**
#: ——样本作者下次换一个没人收录过的知名域名，名单就已经落后了。
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
    s = _summary(_flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}), _flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}, inbound=True))
    carriers = pcap_ingest.sni_camouflage_carriers(s)
    assert carriers == {_FAKE_SNI: [f"{_BACKEND}:{_ODD_PORT}/tcp"]}


def _aggregated_ips(s: pcap_ingest.PcapSummary) -> set[str]:
    """该 summary 里真正被聚合成公网远端的地址集合。

    ★这两条反向测试断言的是「结果为空」，而端点压根没进来时结果也是空——**两种原因产出
      同一个绿**。夹具用的共享地址空间正踩在这条缝上：它现在能过 ``_ip_public``（该函数按
      is_private 判），但若哪天改按 ``is_global`` 判，这些地址会在聚合阶段就被滤掉，两条
      测试会在护栏其实已经失效的情况下继续全绿。故先钉住前置事实，再断言豁免。
    """
    return {ep.ip for ep in pcap_ingest.remote_endpoints(s)}


def test_sni_on_standard_port_is_not_flagged() -> None:
    """反向护栏：443 上的 SNI 是正常 TLS 服务，不得被标伪装（否则全库域名线索报废）。"""
    s = _summary(_flow(_STD_PORT_HOST, 443, {_FAKE_SNI}))  # 合成段，护栏放行、无需豁免

    assert _STD_PORT_HOST in _aggregated_ips(s), "前置：该地址须真被聚合，否则下面的空结果是假绿"

    assert pcap_ingest.sni_camouflage_carriers(s) == {}


def test_sni_seen_on_any_standard_port_is_exonerated() -> None:
    """★同名域名只要在标准端口上也出现过，就说明它确实作为 TLS 服务被访问过 → 整体不降级。

    只按"存在一条非标连接"降级，会把真实访问过该域名的样本一并误伤。
    """
    s = _summary(
        _flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}),           # 伪装的那条
        _flow(_STD_PORT_HOST, 443, {_FAKE_SNI}),      # 真访问该服务的那条（合成段）
    )

    # 前置：两条 flow 都要真进聚合——豁免必须是「标准端口那条也在」换来的，
    # 而不是「标准端口那条根本没进来、非标那条也没进来」凑出的空。
    assert {_BACKEND, _STD_PORT_HOST} <= _aggregated_ips(s)

    assert pcap_ingest.sni_camouflage_carriers(s) == {}


def test_no_sni_or_no_flows_is_empty() -> None:
    assert pcap_ingest.sni_camouflage_carriers(_summary()) == {}
    assert pcap_ingest.sni_camouflage_carriers(_summary(_flow(_BACKEND, _ODD_PORT))) == {}


# ---------------------------------------------------------------------------
# 出口：域名降档，IP 加重
# ---------------------------------------------------------------------------


def test_masquerade_domain_leaves_the_subpoena_outlets() -> None:
    """★被冒充的域名不得判 ADVICE_INVESTIGATE——那份文书的受文方会是被冒充的那家服务商。"""
    assert infra.classify_domain(_FAKE_SNI)[0] == infra.ADVICE_INVESTIGATE, (
        "前提：该域名本会被判建议调证（不在已知第三方名单里）"
    )
    s = _summary(_flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}), _flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}, inbound=True))

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
    s = _summary(_flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}), _flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}, inbound=True))

    ip_lead = _lead(pcap_ingest.to_report_leads(s), f"{_BACKEND}:{_ODD_PORT}/tcp")

    assert ip_lead.advice == infra.ADVICE_INVESTIGATE, "实测双向载荷的后端仍是调证对象"
    assert ip_lead.is_c2 is True
    assert _FAKE_SNI in ip_lead.notes, "要点名它在冒充谁"
    assert "调证对象是本 IP:端口" in ip_lead.notes
    assert "不是" in ip_lead.notes and "被冒充域名的运营方" in ip_lead.notes


def test_masquerade_is_recorded_on_the_endpoint() -> None:
    """结构化落在端点上：读报告的人不必去 notes 里捞，程序化消费方也能筛。"""
    s = _summary(_flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}), _flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}, inbound=True))

    eps = pcap_ingest._runtime_endpoint_dicts(s)
    rt = next(e for e in eps if e["value"] == _BACKEND)["enrichment"]["runtime"]

    assert rt["sni_masquerade"] == [_FAKE_SNI]
    assert rt["port"] == _ODD_PORT
    assert rt["has_payload"] is True


def test_standard_port_endpoint_has_no_masquerade_marker() -> None:
    """不得平白给正常端点加标记（标记贬值成噪声就没人看了）。"""
    s = _summary(_flow(_STD_PORT_HOST, 443, {_FAKE_SNI}))  # 合成段，护栏放行、无需豁免
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

    s = _summary(_flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}), _flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}, inbound=True))
    lead = _lead(pcap_ingest.to_report_leads(s), f"{_BACKEND}:{_ODD_PORT}/tcp")
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

    s = _summary(_flow(_STD_PORT_HOST, 443, set()), _flow(_STD_PORT_HOST, 443, set(), inbound=True))  # 合成段，护栏放行、无需豁免
    lead = _lead(pcap_ingest.to_report_leads(s), f"{_STD_PORT_HOST}:443/tcp")  # 合成段，护栏放行、无需豁免
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
    first = _summary(_flow(_BACKEND, _ODD_PORT, set(), payload=1200),
                     _flow(_BACKEND, _ODD_PORT, set(), inbound=True, payload=800))
    pcap_ingest.merge_into_report_json(str(report), first)
    payload = json.loads(report.read_text(encoding="utf-8"))
    lead = _lead_dict(payload, f"{_BACKEND}:{_ODD_PORT}/tcp")
    assert not lead.get("sni_masquerade"), "第一次采集本就没有 SNI"

    # 第二次采集：同一后端同一端口，这次抓到了伪装 SNI → 命中既有 Lead 走合并路径。
    second = _summary(_flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}, payload=1500),
                      _flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}, inbound=True, payload=900))
    pcap_ingest.merge_into_report_json(str(report), second)
    payload = json.loads(report.read_text(encoding="utf-8"))
    lead = _lead_dict(payload, f"{_BACKEND}:{_ODD_PORT}/tcp")

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
    s = _summary(_flow(_BACKEND, _ODD_PORT, {"cdn.jsdelivr.net"}))
    lead = _lead(pcap_ingest.to_report_leads(s), "cdn.jsdelivr.net")
    assert lead.advice == infra.ADVICE_SKIP


# ---------------------------------------------------------------------------
# 第二条生产路径：域名端点并入主报告后，由 core.leads._domain_lead 重新产 Lead
#
# ★上面那批测试锁的全是 pcap 自己那条路（to_report_leads）。真正走到套打出口的却是另一条：
#   域名端点并入 report.endpoints 后，_domain_lead 会**重新**产一条同名 Lead，而那个生产者
#   只看得到 Endpoint 自身，压根不知道这个名字是从哪个端口的握手里抠出来的。
#
#   实测（fxapk 1.4.0）：同一份报告里四个伪装域名分裂成 2:2——进了 endpoints 的两个被判
#   ADVICE_INVESTIGATE 并真的套打出了指向被冒用服务的文书；没进 endpoints 的两个因走不到
#   这条路而幸免。决定安全与否的竟是「有没有进 endpoints」这条与伪装判断毫不相干的分叉，
#   上面那批测试全绿也没抓住。故本节按**真入口**逐环钉死。
# ---------------------------------------------------------------------------

#: 对照用的真业务域名：同样不在已知名单里，但只在标准端口出现 → 必须**保持** ADVICE_INVESTIGATE。
#: 护栏收得过宽会把真标的一起吃掉，那比漏更糟。
#: ★不能用 example.com / .test / .invalid：那些是标准保留域，classify_domain 一律判 ADVICE_REVIEW，
#:   而本对照项要求的恰恰是「本会被判 ADVICE_INVESTIGATE」的角色，保留域承担不了。同 _FAKE_SNI。
_REAL_BACKEND_DOMAIN = "gateway.appnode-svc.com"  # leak-scan: allow 合成对照域名，须被判 ADVICE_INVESTIGATE 故不能用保留域


def test_masquerade_travels_with_the_domain_endpoint() -> None:
    """接线①：伪装事实必须随**域名端点**一起走，否则下游生产者无从得知。"""
    s = _summary(
        _flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}),
        _flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}, inbound=True),
    )

    eps = pcap_ingest.to_runtime_endpoints(s)
    dom_ep = next(e for e in eps if e.kind == "domain" and e.value == _FAKE_SNI)

    assert dom_ep.enrichment[SNI_MASQUERADE_KEY] == {"carriers": [f"{_BACKEND}:{_ODD_PORT}/tcp"]}


def test_standard_port_domain_endpoint_carries_no_marker() -> None:
    """反向：正常 TLS 服务的域名端点不得被平白打标（标记贬值成噪声就没人看了）。"""
    s = _summary(_flow(_STD_PORT_HOST, 443, {_REAL_BACKEND_DOMAIN}))  # 合成段，护栏放行、无需豁免

    eps = pcap_ingest.to_runtime_endpoints(s)
    dom_ep = next(e for e in eps if e.kind == "domain" and e.value == _REAL_BACKEND_DOMAIN)

    assert SNI_MASQUERADE_KEY not in dom_ep.enrichment


def test_domain_lead_producer_downgrades_the_masqueraded_name() -> None:
    """★接线②：走 build_endpoint_leads 这个**真入口**——被冒用的域名不得判 ADVICE_INVESTIGATE。

    这是真实报告里实际走的那条路。删掉 _domain_lead 里读伪装事实的那段，本测试必红。
    """
    assert infra.classify_domain(_FAKE_SNI)[0] == infra.ADVICE_INVESTIGATE, (
        "前提：该域名本会被判 ADVICE_INVESTIGATE（不在已知第三方名单里）"
    )
    s = _summary(
        _flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}),
        _flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}, inbound=True),
    )
    dom_eps = [e for e in pcap_ingest.to_runtime_endpoints(s) if e.kind == "domain"]

    lead = _lead(build_endpoint_leads(dom_eps, online=False), _FAKE_SNI)

    assert lead.advice == infra.ADVICE_REVIEW, "本条路径此前判 ADVICE_INVESTIGATE 并真的套打了"
    assert lead.is_c2 is False
    assert lead.sni_masquerade == [_FAKE_SNI], "结构化标记要在，notes 在合并与出口两处都会丢"
    assert "非标准 TLS 端口" in lead.notes


def test_domain_lead_producer_keeps_the_real_backend() -> None:
    """★反向护栏：不得误伤真标的。

    实测同一份 pcap 里，对象存储的租户桶域名与伪装域名同在，降档若收得过宽就把该套打的
    一起关掉了——那比漏更糟。
    """
    assert infra.classify_domain(_REAL_BACKEND_DOMAIN)[0] == infra.ADVICE_INVESTIGATE
    s = _summary(
        _flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}),                       # 伪装的那条
        _flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}, inbound=True),
        _flow(_STD_PORT_HOST, 443, {_REAL_BACKEND_DOMAIN}),       # 真业务的那条  # 合成段，护栏放行、无需豁免
    )
    dom_eps = [e for e in pcap_ingest.to_runtime_endpoints(s) if e.kind == "domain"]

    lead = _lead(build_endpoint_leads(dom_eps, online=False), _REAL_BACKEND_DOMAIN)

    assert lead.advice == infra.ADVICE_INVESTIGATE
    assert lead.sni_masquerade == []


def test_letters_never_drafts_for_a_masqueraded_domain() -> None:
    """★接线③：出口硬闸，与上游判据相互独立。

    上游任何一环退回去，套打出来的都是一份指向被冒用服务持有方的文书。故出口自己再挡一次：
    标的自身出现在自己的 sni_masquerade 里 → 绝不套打。删掉 _is_actionable 里那道闸，
    即便 advice 被上游误升为 ADVICE_INVESTIGATE 本测试也必须红。
    """
    from apkscan.report import json as report_json
    from apkscan.report import letters

    s = _summary(
        _flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}),
        _flow(_BACKEND, _ODD_PORT, {_FAKE_SNI}, inbound=True),
    )
    dom_eps = [e for e in pcap_ingest.to_runtime_endpoints(s) if e.kind == "domain"]
    lead = _lead(build_endpoint_leads(dom_eps, online=False), _FAKE_SNI)

    payload = report_json._to_jsonable(lead)
    assert letters._is_actionable(payload) is False

    # 出口闸独立成立：即便上游把 advice 误升回 ADVICE_INVESTIGATE，也照样不套打。
    payload["advice"] = infra.ADVICE_INVESTIGATE
    assert letters._is_actionable(payload) is False, "出口闸不得依赖 advice 判对"
