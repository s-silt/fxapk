"""_ipinfo.lookup_ip 共享函数单测：mock 掉网络层（requests），不发任何真实请求。

把 asn.py 的单 IP ip-api 查询逻辑抽成共享函数 ``lookup_ip(ip, http=...)``，
供 asn / dns 复用，不重复造轮子。

覆盖：
- 成功路径：ip-api 返回 status=success → 提取 isp/org/asn/country。
- 缺字段 → None。
- HTTP 4xx/5xx（raise_for_status）→ 抛异常（由调用方 enrich 统一兜底）。
- 接口 status=fail → 抛 ValueError。
- 返回非对象 → 抛 ValueError。
- 传入的 http 模块被真正使用（带 timeout / fields 参数）。
"""

from __future__ import annotations

import pytest

import apkscan.enrichers._ipinfo as ipinfo_mod
from apkscan.enrichers._ipinfo import lookup_ip


class _FakeResponse:
    def __init__(
        self, json_data: object, raise_for_status_exc: Exception | None = None
    ) -> None:
        self._json = json_data
        self._raise_for_status_exc = raise_for_status_exc

    def raise_for_status(self) -> None:
        if self._raise_for_status_exc is not None:
            raise self._raise_for_status_exc

    def json(self) -> object:
        return self._json


class _FakeRequests:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.response: _FakeResponse | None = None
        self.raises: Exception | None = None

    def get(self, url: str, **kwargs: object) -> _FakeResponse:
        self.calls.append((url, dict(kwargs)))
        if self.raises is not None:
            raise self.raises
        assert self.response is not None, "测试未配置 response"
        return self.response


def _success_payload() -> dict[str, str]:
    return {
        "status": "success",
        "country": "China",
        "isp": "Alibaba.com LLC",
        "org": "Aliyun Computing Co",
        "as": "AS37963 Hangzhou Alibaba Advertising Co.,Ltd.",
        "query": "1.2.3.4",
    }


def test_lookup_ip_success_extracts_fields() -> None:
    http = _FakeRequests()
    http.response = _FakeResponse(_success_payload())

    data = lookup_ip("1.2.3.4", http=http)

    assert data["isp"] == "Alibaba.com LLC"
    assert data["org"] == "Aliyun Computing Co"
    assert data["asn"] == "AS37963 Hangzhou Alibaba Advertising Co.,Ltd."
    assert data["country"] == "China"

    # 触网恰好一次，带 timeout 与 fields。
    assert len(http.calls) == 1
    url, kwargs = http.calls[0]
    assert "1.2.3.4" in url
    assert kwargs.get("timeout") == ipinfo_mod.IPINFO_TIMEOUT
    assert kwargs["params"]["fields"] == ipinfo_mod.IPINFO_FIELDS


def test_lookup_ip_missing_fields_become_none() -> None:
    http = _FakeRequests()
    http.response = _FakeResponse({"status": "success", "query": "8.8.8.8"})

    data = lookup_ip("8.8.8.8", http=http)
    assert data["isp"] is None
    assert data["org"] is None
    assert data["asn"] is None
    assert data["country"] is None


def test_lookup_ip_http_error_raises() -> None:
    http = _FakeRequests()
    http.response = _FakeResponse({}, raise_for_status_exc=RuntimeError("429"))
    with pytest.raises(RuntimeError):
        lookup_ip("1.2.3.4", http=http)


def test_lookup_ip_status_fail_raises_valueerror() -> None:
    http = _FakeRequests()
    http.response = _FakeResponse(
        {"status": "fail", "message": "private range", "query": "10.0.0.1"}
    )
    with pytest.raises(ValueError, match="private range"):
        lookup_ip("10.0.0.1", http=http)


def test_lookup_ip_non_object_raises_valueerror() -> None:
    http = _FakeRequests()
    http.response = _FakeResponse(["not", "a", "dict"])
    with pytest.raises(ValueError):
        lookup_ip("1.2.3.4", http=http)


def test_lookup_ip_uses_default_requests_when_not_given(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """不传 http 时回退到模块自带的 requests（同样被 mock，不触真网）。"""
    fake = _FakeRequests()
    fake.response = _FakeResponse(_success_payload())
    monkeypatch.setattr(ipinfo_mod, "requests", fake)

    data = lookup_ip("1.2.3.4")
    assert data["country"] == "China"
    assert len(fake.calls) == 1
