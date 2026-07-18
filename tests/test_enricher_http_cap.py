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


def test_multisource_default_session_is_capped() -> None:
    """默认（未注入 session）用有界 CappedSession，生产富化走响应体硬帽。"""
    from apkscan.enrichers.multisource import RipeStatBgpEnricher

    assert isinstance(RipeStatBgpEnricher()._http, _http.CappedSession)


def test_injected_session_is_not_overridden() -> None:
    """注入的假 session 不被换成 CappedSession（测试可控响应，不受帽影响）。"""
    from apkscan.enrichers.multisource import RipeStatBgpEnricher

    sentinel = object()
    assert RipeStatBgpEnricher(session=sentinel)._http is sentinel
