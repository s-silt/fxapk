"""非标端口上的 SNI 伪装：域名是戏服，IP 才是实体。

实测（范旻案）：`30135/tcp` 上的自建协议连接打出网易云音乐、jsDelivr 镜像、有道、BootCDN
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

_BACKEND = "8.138.171.104"
_FAKE_SNI = "music.163.com"


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
    s = _summary(_flow("59.111.181.60", 443, {_FAKE_SNI}))
    assert pcap_ingest.sni_camouflage_carriers(s) == {}


def test_sni_seen_on_any_standard_port_is_exonerated() -> None:
    """★同名域名只要在标准端口上也出现过，就说明它确实作为 TLS 服务被访问过 → 整体不降级。

    只按"存在一条非标连接"降级，会把真实访问过该域名的样本一并误伤。
    """
    s = _summary(
        _flow(_BACKEND, 30135, {_FAKE_SNI}),           # 伪装的那条
        _flow("59.111.181.60", 443, {_FAKE_SNI}),      # 真访问网易的那条
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
    s = _summary(_flow("59.111.181.60", 443, {_FAKE_SNI}))
    rt = pcap_ingest._runtime_endpoint_dicts(s)[0]["enrichment"]["runtime"]
    assert "sni_masquerade" not in rt


def test_known_third_party_domain_stays_skip() -> None:
    """已判「无需调证」的（jsDelivr 等在第三方名单里）不受影响——只降"本会出函"的那些。"""
    assert infra.classify_domain("cdn.jsdelivr.net")[0] == infra.ADVICE_SKIP
    s = _summary(_flow(_BACKEND, 30135, {"cdn.jsdelivr.net"}))
    lead = _lead(pcap_ingest.to_report_leads(s), "cdn.jsdelivr.net")
    assert lead.advice == infra.ADVICE_SKIP
