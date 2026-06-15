"""AsnEnricher 单测：mock 掉网络层（requests），不发任何真实请求。

覆盖：
- 基本属性 name / applies_to。
- 成功路径：ip-api 返回 status=success → ok=True，字段被正确提取。
- 失败路径①：requests 抛异常（超时等）→ ok=False 且 error 非空，不抛出。
- 失败路径②：接口返回 status=fail → ok=False，不抛出。
- 失败路径③：HTTP 4xx/5xx（raise_for_status）→ ok=False。
- 空 IP → ok=False，不触网。
- 本地 JSON 缓存：首查写盘、二次查命中缓存（不再触网）。
- 缓存目录不存在时自动创建。
- 限速已集中到 _ipinfo（asn 不再自带限速）；conftest autouse 已重置共享状态并打桩 sleep。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import apkscan.enrichers.asn as asn_mod
from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.enrichers.asn import AsnEnricher


# --- 通用打桩 -------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """把缓存重定向到临时目录，互不干扰，且不污染项目根。"""
    cache_dir = tmp_path / ".apkscan_cache"
    cache_file = cache_dir / "asn.json"
    monkeypatch.setattr(asn_mod, "CACHE_DIR", cache_dir)
    monkeypatch.setattr(asn_mod, "CACHE_FILE", cache_file)
    return cache_file


# 限速已集中到 _ipinfo：sleep 打桩 + 共享状态重置由 conftest 的 autouse fixture
# (_reset_ipinfo_shared_state) 统一处理，asn 测试不再自带 _no_sleep。


class _FakeResponse:
    """假的 requests.Response：可配置 JSON、HTTP 异常。"""

    def __init__(
        self,
        json_data: object,
        raise_for_status_exc: Exception | None = None,
    ) -> None:
        self._json = json_data
        self._raise_for_status_exc = raise_for_status_exc

    def raise_for_status(self) -> None:
        if self._raise_for_status_exc is not None:
            raise self._raise_for_status_exc

    def json(self) -> object:
        return self._json


class _FakeRequests:
    """假的 ``requests`` 模块：记录调用，按配置返回响应或抛异常。"""

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


@pytest.fixture
def fake_requests(monkeypatch: pytest.MonkeyPatch) -> _FakeRequests:
    """把假 requests 注入 enricher 模块命名空间。"""
    fake = _FakeRequests()
    monkeypatch.setattr(asn_mod, "requests", fake)
    return fake


def _ep(value: str = "1.2.3.4") -> Endpoint:
    return Endpoint(value=value, kind="ip")


def _success_payload() -> dict[str, str]:
    return {
        "status": "success",
        "country": "China",
        "isp": "Alibaba.com LLC",
        "org": "Aliyun Computing Co",
        "as": "AS37963 Hangzhou Alibaba Advertising Co.,Ltd.",
        "query": "1.2.3.4",
    }


# --- 基本属性 -------------------------------------------------------------


def test_name_and_applies_to() -> None:
    enr = AsnEnricher()
    assert enr.name == "asn"
    assert enr.applies_to == ["ip"]


# --- 成功路径 -------------------------------------------------------------


def test_enrich_success_extracts_fields(fake_requests: _FakeRequests) -> None:
    fake_requests.response = _FakeResponse(_success_payload())
    result = AsnEnricher().enrich(_ep())

    assert isinstance(result, EnrichmentResult)
    assert result.provider == "asn"
    assert result.ok is True
    assert result.error is None
    assert result.data["isp"] == "Alibaba.com LLC"
    assert result.data["org"] == "Aliyun Computing Co"
    assert result.data["asn"] == "AS37963 Hangzhou Alibaba Advertising Co.,Ltd."
    assert result.data["country"] == "China"

    # 触网恰好一次，带 timeout 与 fields。
    assert len(fake_requests.calls) == 1
    url, kwargs = fake_requests.calls[0]
    assert "1.2.3.4" in url
    assert kwargs.get("timeout") == asn_mod.ASN_TIMEOUT
    assert kwargs["params"]["fields"] == asn_mod.ASN_FIELDS


def test_enrich_missing_fields_become_none(fake_requests: _FakeRequests) -> None:
    fake_requests.response = _FakeResponse(
        {"status": "success", "query": "8.8.8.8"}
    )
    result = AsnEnricher().enrich(_ep("8.8.8.8"))
    assert result.ok is True
    assert result.data["isp"] is None
    assert result.data["org"] is None
    assert result.data["asn"] is None
    assert result.data["country"] is None


# --- 失败路径 -------------------------------------------------------------


def test_enrich_network_error_returns_not_ok(fake_requests: _FakeRequests) -> None:
    fake_requests.raises = TimeoutError("connection timed out")
    result = AsnEnricher().enrich(_ep())

    assert isinstance(result, EnrichmentResult)
    assert result.provider == "asn"
    assert result.ok is False
    assert result.error
    assert "TimeoutError" in result.error
    assert result.data == {}


def test_enrich_api_status_fail_returns_not_ok(fake_requests: _FakeRequests) -> None:
    fake_requests.response = _FakeResponse(
        {"status": "fail", "message": "private range", "query": "10.0.0.1"}
    )
    result = AsnEnricher().enrich(_ep("10.0.0.1"))
    assert result.ok is False
    assert result.error
    assert "private range" in result.error


def test_enrich_http_error_returns_not_ok(fake_requests: _FakeRequests) -> None:
    fake_requests.response = _FakeResponse(
        {}, raise_for_status_exc=RuntimeError("429 Too Many Requests")
    )
    result = AsnEnricher().enrich(_ep())
    assert result.ok is False
    assert "RuntimeError" in result.error


def test_enrich_does_not_raise_on_arbitrary_exception(
    fake_requests: _FakeRequests,
) -> None:
    fake_requests.raises = ValueError("bad json")
    result = AsnEnricher().enrich(_ep())
    assert result.ok is False
    assert "ValueError" in result.error


def test_failed_query_not_cached(
    fake_requests: _FakeRequests, _isolated_cache: Path
) -> None:
    fake_requests.raises = RuntimeError("boom")
    AsnEnricher().enrich(_ep())
    assert not _isolated_cache.exists()


# --- 空 IP（不触网）-------------------------------------------------------


def test_empty_ip_short_circuits(fake_requests: _FakeRequests) -> None:
    result = AsnEnricher().enrich(Endpoint(value="   ", kind="ip"))
    assert result.ok is False
    assert result.error
    assert fake_requests.calls == []  # 没触网


# --- 缓存 -----------------------------------------------------------------


def test_result_written_to_cache(
    fake_requests: _FakeRequests, _isolated_cache: Path
) -> None:
    fake_requests.response = _FakeResponse(_success_payload())
    AsnEnricher().enrich(_ep("9.9.9.9"))

    assert _isolated_cache.is_file()
    cache = json.loads(_isolated_cache.read_text(encoding="utf-8"))
    assert "9.9.9.9" in cache
    assert cache["9.9.9.9"]["isp"] == "Alibaba.com LLC"
    assert cache["9.9.9.9"]["country"] == "China"


def test_cache_hit_skips_network(fake_requests: _FakeRequests) -> None:
    fake_requests.response = _FakeResponse(_success_payload())
    enr = AsnEnricher()

    first = enr.enrich(_ep("5.5.5.5"))
    assert first.ok is True
    assert len(fake_requests.calls) == 1

    # 第二次：命中缓存，不再触网。
    fake_requests.response = _FakeResponse(
        {"status": "success", "isp": "SHOULD NOT BE USED"}
    )
    second = enr.enrich(_ep("5.5.5.5"))
    assert second.ok is True
    assert second.data["isp"] == "Alibaba.com LLC"
    assert len(fake_requests.calls) == 1  # 没有新增网络调用


def test_cache_hit_across_instances(fake_requests: _FakeRequests) -> None:
    fake_requests.response = _FakeResponse(_success_payload())
    AsnEnricher().enrich(_ep("6.6.6.6"))
    assert len(fake_requests.calls) == 1

    # 新实例也能读到磁盘缓存。
    result = AsnEnricher().enrich(_ep("6.6.6.6"))
    assert result.ok is True
    assert result.data["isp"] == "Alibaba.com LLC"
    assert len(fake_requests.calls) == 1


def test_cache_dir_created_when_missing(
    fake_requests: _FakeRequests, _isolated_cache: Path
) -> None:
    assert not _isolated_cache.parent.exists()
    fake_requests.response = _FakeResponse(_success_payload())
    AsnEnricher().enrich(_ep("7.7.7.7"))
    assert _isolated_cache.parent.is_dir()
    assert _isolated_cache.is_file()
