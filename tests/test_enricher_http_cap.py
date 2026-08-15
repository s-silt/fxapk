"""富化器 HTTP 响应体硬上限（codex 全库审计 P1）：防被劫持/异常源返回巨型 JSON 在 .json()/.text 前撑爆内存。"""

from __future__ import annotations

import pytest

from apkscan.enrichers import _http


class _FakeResp:
    """假 requests.Response：iter_content 产出可控字节，close 记录已关闭。"""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks
        self.closed = False

    def iter_content(self, _n: int):  # noqa: ANN201
        yield from self._chunks

    def close(self) -> None:
        self.closed = True


def test_cap_body_rejects_oversized_response() -> None:
    """流式累计超硬帽 → 抛 ResponseTooLarge 并中止连接（下载阶段就拦，不等 .json() 撑爆内存）。"""
    resp = _FakeResp([b"x" * 4] * 5)  # 共 20 字节
    with pytest.raises(_http.ResponseTooLarge):
        _http._cap_body(resp, 10)  # 上限 10 < 20 → 拒绝
    assert resp.closed  # 中止时关闭连接


def test_cap_body_accepts_within_limit_and_backfills_content() -> None:
    """限内响应正常回填 _content，让 resp.json()/.text 照常可用。"""
    resp = _FakeResp([b"hel", b"lo"])
    out = _http._cap_body(resp, 1000)
    assert out._content == b"hello"
    assert resp.closed


def test_capped_session_post_is_capped(monkeypatch) -> None:
    """★codex B1：CappedSession.post 同样流式限体（Quake 走 session.post，此前绕过帽）。"""
    captured: dict[str, object] = {}

    def _fake_super_post(self, url, **kwargs):  # noqa: ANN001, ANN202
        captured["stream"] = kwargs.get("stream")
        return _FakeResp([b"x" * 8] * 3)  # 24 字节

    import requests as _rq
    monkeypatch.setattr(_rq.Session, "post", _fake_super_post)
    monkeypatch.setattr(_http, "_MAX_RESPONSE_BYTES", 10)
    with pytest.raises(_http.ResponseTooLarge):
        _http.CappedSession().post("https://x")
    assert captured["stream"] is True  # 流式下载才能在灌爆前中止


def test_capped_post_helper_is_capped(monkeypatch) -> None:
    """★capped_post（ip-api /batch 等明文 POST 源用）流式限体。"""
    def _fake_post(url, **kwargs):  # noqa: ANN001, ANN202
        assert kwargs.get("stream") is True
        return _FakeResp([b"y" * 16] * 2)  # 32 字节
    monkeypatch.setattr(_http.requests, "post", _fake_post)
    monkeypatch.setattr(_http, "_MAX_RESPONSE_BYTES", 10)
    with pytest.raises(_http.ResponseTooLarge):
        _http.capped_post("http://ip-api.com/batch", json=[])


def test_capped_requests_shim_routes_get_and_post_through_cap() -> None:
    """★shim 的 .get/.post 就是 capped_get/capped_post——绑给富化器 requests 符号即全局限体。"""
    assert _http.capped_requests.get is _http.capped_get
    assert _http.capped_requests.post is _http.capped_post


def test_enricher_modules_bind_capped_requests() -> None:
    """★asn/dns/rdap/icp/_ipinfo 的模块级 requests 符号 = 有界 shim（生产联网即限体）。"""
    from apkscan.enrichers import _ipinfo, asn, dns, icp, rdap

    for mod in (asn, dns, icp, rdap, _ipinfo):
        assert mod.requests is _http.capped_requests, f"{mod.__name__} 未绑有界 shim"


class _RedirectClient:
    """假 client：首个响应给 302→Location，之后给 200。记录实际请求过的 URL。"""

    def __init__(self, location: str) -> None:
        self.location = location
        self.urls: list[str] = []
        self._served_redirect = False

    def get(self, url, **kwargs):  # noqa: ANN001, ANN201
        self.urls.append(url)
        if not self._served_redirect:
            self._served_redirect = True
            return _RedirResp(302, {"Location": self.location})
        return _RedirResp(200, {})


class _RedirResp:
    def __init__(self, status_code: int, headers: dict) -> None:
        self.status_code = status_code
        self.headers = headers


def test_guarded_get_blocks_redirect_to_metadata_endpoint() -> None:
    """★codex B3：重定向到云元数据/链路本地地址（169.254.169.254）被拒（SSRF 防护）。"""
    client = _RedirectClient("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(_http.SSRFBlocked):
        _http.guarded_get(client, "https://rdap.org/domain/x.com")
    # 初始 rdap.org 请求发出、但危险的重定向目标绝不请求
    assert client.urls == ["https://rdap.org/domain/x.com"]


def test_guarded_get_blocks_redirect_to_private_ip() -> None:
    """★重定向到内网私有地址（10.0.0.0/8）同样被拒。"""
    client = _RedirectClient("http://10.0.0.5/admin")
    with pytest.raises(_http.SSRFBlocked):
        _http.guarded_get(client, "https://rdap.org/domain/x.com")


def test_guarded_get_returns_non_redirect_without_dns() -> None:
    """★非重定向响应直接返回，不对初始 URL 做 host 校验（离线 fake 不触 DNS）。"""
    client = _RedirectClient("unused")
    client._served_redirect = True  # 首个即 200
    resp = _http.guarded_get(client, "https://rdap.org/domain/x.com")
    assert resp.status_code == 200


def test_host_is_public_rejects_private_and_metadata() -> None:
    """★_host_is_public：字面私网/链路本地 IP 判不安全（无 DNS，字面 IP 直判）。"""
    assert _http._host_is_public("169.254.169.254") is False  # 云元数据
    assert _http._host_is_public("127.0.0.1") is False        # 环回
    assert _http._host_is_public("10.0.0.1") is False         # 私网
    assert _http._host_is_public("192.168.1.1") is False      # 私网


def test_multisource_default_session_is_capped() -> None:
    """默认（未注入 session）用有界 CappedSession，生产富化走响应体硬帽。"""
    from apkscan.enrichers.multisource import RipeStatBgpEnricher

    assert isinstance(RipeStatBgpEnricher()._http, _http.CappedSession)


def test_injected_session_is_not_overridden() -> None:
    """注入的假 session 不被换成 CappedSession（测试可控响应，不受帽影响）。"""
    from apkscan.enrichers.multisource import RipeStatBgpEnricher

    sentinel = object()
    assert RipeStatBgpEnricher(session=sentinel)._http is sentinel
