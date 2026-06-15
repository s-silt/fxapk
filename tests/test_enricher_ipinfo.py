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
from apkscan.enrichers._ipinfo import lookup_ip, lookup_ips_batch


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
        self.post_calls: list[tuple[str, dict]] = []
        self.response: _FakeResponse | None = None
        self.post_response: _FakeResponse | None = None
        self.raises: Exception | None = None

    def get(self, url: str, **kwargs: object) -> _FakeResponse:
        self.calls.append((url, dict(kwargs)))
        if self.raises is not None:
            raise self.raises
        assert self.response is not None, "测试未配置 response"
        return self.response

    def post(self, url: str, **kwargs: object) -> _FakeResponse:
        self.post_calls.append((url, dict(kwargs)))
        if self.raises is not None:
            raise self.raises
        assert self.post_response is not None, "测试未配置 post_response"
        return self.post_response


@pytest.fixture(autouse=True)
def _reset_state() -> None:
    """每个 ipinfo 测试前清共享缓存 + 限速时钟（与 conftest autouse 并行无害，显式更稳）。"""
    ipinfo_mod.reset_state()


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


# --- ① 共享内存缓存命中（第二次不触网）------------------------------------


def test_lookup_ip_second_call_hits_shared_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同一 IP 第二次 lookup_ip 命中共享缓存，不再触网（client.get 仍为 1 次）。"""
    monkeypatch.setattr(ipinfo_mod, "_SLEEP", lambda *_a, **_k: None)
    http = _FakeRequests()
    http.response = _FakeResponse(_success_payload())

    first = lookup_ip("1.2.3.4", http=http)
    assert first["country"] == "China"
    assert len(http.calls) == 1

    # 改 response 以证明第二次走的是缓存而非新网络结果。
    http.response = _FakeResponse(
        {"status": "success", "country": "SHOULD-NOT-USE", "query": "1.2.3.4"}
    )
    second = lookup_ip("1.2.3.4", http=http)
    assert second["country"] == "China"  # 仍是首查缓存
    assert len(http.calls) == 1  # 没有新增网络调用


def test_lookup_ip_cache_shared_across_callers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """一个 http 实例查过的 IP，另一个 http 实例也能命中（进程级共享缓存）。"""
    monkeypatch.setattr(ipinfo_mod, "_SLEEP", lambda *_a, **_k: None)
    http_a = _FakeRequests()
    http_a.response = _FakeResponse(_success_payload())
    lookup_ip("1.2.3.4", http=http_a)
    assert len(http_a.calls) == 1

    http_b = _FakeRequests()  # 未配置 response，命中缓存就不会触网
    data = lookup_ip("1.2.3.4", http=http_b)
    assert data["isp"] == "Alibaba.com LLC"
    assert http_b.calls == []


# --- ② 共享限速器（fake monotonic + 记录 sleep 时长，纯逻辑断言）-----------


def test_lookup_ip_respects_shared_rate_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """连续两次查不同 IP，第二次需等待 ≥ IPINFO_MIN_INTERVAL（用 fake monotonic 驱动）。

    不真 sleep：sleep 仅记录入参；monotonic 由脚本推进。
    第 1 次：clock=100（远大于 reset 后的 last=0）→ 无需等待，置 last=100。
    第 2 次：clock=100.5（距上次仅 0.5s<1.4）→ 应 sleep≈1.4-0.5=0.9。
    """
    slept: list[float] = []
    clock = [100.0]
    monkeypatch.setattr(ipinfo_mod, "_SLEEP", lambda s: slept.append(s))
    monkeypatch.setattr(ipinfo_mod, "_MONOTONIC", lambda: clock[0])

    http = _FakeRequests()
    http.response = _FakeResponse({"status": "success", "query": "1.1.1.1"})
    lookup_ip("1.1.1.1", http=http)
    assert slept == []  # 首查距 reset 时钟已远超间隔，无需等待

    clock[0] = 100.5  # 距上次仅过 0.5s
    http.response = _FakeResponse({"status": "success", "query": "2.2.2.2"})
    lookup_ip("2.2.2.2", http=http)

    assert len(slept) == 1
    assert slept[0] == pytest.approx(ipinfo_mod.IPINFO_MIN_INTERVAL - 0.5)


def test_lookup_ip_no_wait_when_interval_elapsed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """距上次已超过 IPINFO_MIN_INTERVAL → 第二次不 sleep。"""
    slept: list[float] = []
    clock = [100.0]
    monkeypatch.setattr(ipinfo_mod, "_SLEEP", lambda s: slept.append(s))
    monkeypatch.setattr(ipinfo_mod, "_MONOTONIC", lambda: clock[0])

    http = _FakeRequests()
    http.response = _FakeResponse({"status": "success", "query": "1.1.1.1"})
    lookup_ip("1.1.1.1", http=http)

    clock[0] = 100.0 + ipinfo_mod.IPINFO_MIN_INTERVAL + 1.0
    http.response = _FakeResponse({"status": "success", "query": "2.2.2.2"})
    lookup_ip("2.2.2.2", http=http)
    assert slept == []


# --- ②b 批量端点独立限速器（/batch 15/min·4.0s，独立于单查 1.4s）------------


def test_lookup_ips_batch_uses_batch_interval_not_single(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """两次连续 /batch POST：第二次须等待 ≈ IPINFO_BATCH_MIN_INTERVAL（4.0s），而非单查 1.4s。

    /batch 端点限额 15/min，远低于单查 45/min；复用 1.4s 单查闸会把 batch POST 推到 ~43/min
    触发 429。本测试用 fake monotonic 驱动，断言 batch 用的是 4.0s 闸（≈15/min）。
    """
    slept: list[float] = []
    clock = [100.0]
    monkeypatch.setattr(ipinfo_mod, "_SLEEP", lambda s: slept.append(s))
    monkeypatch.setattr(ipinfo_mod, "_MONOTONIC", lambda: clock[0])

    http = _FakeRequests()
    http.post_response = _FakeResponse([_batch_item("1.1.1.1", "US")])
    lookup_ips_batch(["1.1.1.1"], http=http)
    assert slept == []  # 首批距 reset 时钟已远超间隔，无需等待

    clock[0] = 100.5  # 距上次仅过 0.5s
    http.post_response = _FakeResponse([_batch_item("2.2.2.2", "CN")])
    lookup_ips_batch(["2.2.2.2"], http=http)

    assert len(slept) == 1
    # 关键：用的是 batch 4.0s 闸（4.0-0.5=3.5），不是单查 1.4s 闸（否则会是 0.9）。
    assert slept[0] == pytest.approx(ipinfo_mod.IPINFO_BATCH_MIN_INTERVAL - 0.5)
    assert slept[0] != pytest.approx(ipinfo_mod.IPINFO_MIN_INTERVAL - 0.5)


def test_batch_and_single_limiters_are_independent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """单查闸与批量闸各自独立计时：单查请求不挤占批量节奏（反之亦然）。

    场景：批量 POST 后立刻单查 GET——单查只看自己的 1.4s 闸（首查不等），不被批量闸影响；
    随后再来一批，批量闸仍按自己上次 batch 时间算（距 0.5s → 等 3.5s）。
    """
    slept: list[float] = []
    clock = [100.0]
    monkeypatch.setattr(ipinfo_mod, "_SLEEP", lambda s: slept.append(s))
    monkeypatch.setattr(ipinfo_mod, "_MONOTONIC", lambda: clock[0])

    http = _FakeRequests()
    http.post_response = _FakeResponse([_batch_item("1.1.1.1", "US")])
    lookup_ips_batch(["1.1.1.1"], http=http)  # batch t=100, last_batch=100
    assert slept == []

    # 单查 GET：自己的单查闸 last_call 仍是 reset 的 0 → 距 100 远超 1.4 → 不等。
    clock[0] = 100.5
    http.response = _FakeResponse({"status": "success", "query": "9.9.9.9"})
    lookup_ip("9.9.9.9", http=http)
    assert slept == []  # 单查不被批量闸挤占

    # 再来一批：批量闸看的是 last_batch=100，clock=100.5 → 等 4.0-0.5=3.5（不受中间单查影响）。
    http.post_response = _FakeResponse([_batch_item("2.2.2.2", "CN")])
    lookup_ips_batch(["2.2.2.2"], http=http)
    assert len(slept) == 1
    assert slept[0] == pytest.approx(ipinfo_mod.IPINFO_BATCH_MIN_INTERVAL - 0.5)


def test_reset_state_clears_batch_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """reset_state 同时清批量限速时钟：复位后首批不等待。"""
    slept: list[float] = []
    clock = [100.0]
    monkeypatch.setattr(ipinfo_mod, "_SLEEP", lambda s: slept.append(s))
    monkeypatch.setattr(ipinfo_mod, "_MONOTONIC", lambda: clock[0])

    http = _FakeRequests()
    http.post_response = _FakeResponse([_batch_item("1.1.1.1", "US")])
    lookup_ips_batch(["1.1.1.1"], http=http)  # last_batch=100

    ipinfo_mod.reset_state()  # 批量时钟归 0
    clock[0] = 100.5  # 仍距 "100" 仅 0.5s，但时钟已被清 → 不应等待
    http.post_response = _FakeResponse([_batch_item("2.2.2.2", "CN")])
    lookup_ips_batch(["2.2.2.2"], http=http)
    assert slept == []


# --- ③ lookup_ips_batch：POST /batch、去重、分块、跳过、写缓存 --------------


def _batch_item(ip: str, country: str) -> dict[str, str]:
    return {
        "status": "success",
        "country": country,
        "isp": f"ISP-{ip}",
        "org": f"Org-{ip}",
        "as": f"AS-{ip}",
        "query": ip,
    }


def test_lookup_ips_batch_posts_to_batch_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """多 IP 一次 POST /batch，返回 {ip: info}；body 为 [{query,fields}...]。"""
    monkeypatch.setattr(ipinfo_mod, "_SLEEP", lambda *_a, **_k: None)
    http = _FakeRequests()
    http.post_response = _FakeResponse(
        [_batch_item("1.1.1.1", "US"), _batch_item("2.2.2.2", "CN")]
    )

    result = lookup_ips_batch(["1.1.1.1", "2.2.2.2"], http=http)

    assert set(result) == {"1.1.1.1", "2.2.2.2"}
    assert result["1.1.1.1"]["country"] == "US"
    assert result["1.1.1.1"]["org"] == "Org-1.1.1.1"
    assert result["2.2.2.2"]["asn"] == "AS-2.2.2.2"

    # 恰好一次 POST，命中 /batch 端点，未走单查 GET。
    assert http.calls == []
    assert len(http.post_calls) == 1
    url, kwargs = http.post_calls[0]
    assert url == ipinfo_mod.IPINFO_BATCH_URL
    assert kwargs.get("timeout") == ipinfo_mod.IPINFO_TIMEOUT
    body = kwargs["json"]
    assert [item["query"] for item in body] == ["1.1.1.1", "2.2.2.2"]
    assert all(item["fields"] == ipinfo_mod.IPINFO_FIELDS for item in body)


def test_lookup_ips_batch_dedupes_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """重复 IP 去重后只查一次（body 仅含唯一 IP）。"""
    monkeypatch.setattr(ipinfo_mod, "_SLEEP", lambda *_a, **_k: None)
    http = _FakeRequests()
    http.post_response = _FakeResponse([_batch_item("1.1.1.1", "US")])

    result = lookup_ips_batch(["1.1.1.1", "1.1.1.1", "", "1.1.1.1"], http=http)

    assert set(result) == {"1.1.1.1"}
    assert len(http.post_calls) == 1
    body = http.post_calls[0][1]["json"]
    assert [item["query"] for item in body] == ["1.1.1.1"]


def test_lookup_ips_batch_chunks_over_100(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """>100 IP 分块成多次 POST（每块 ≤ IPINFO_BATCH_MAX）。"""
    monkeypatch.setattr(ipinfo_mod, "_SLEEP", lambda *_a, **_k: None)
    ips = [f"10.0.{i // 256}.{i % 256}" for i in range(150)]

    http = _FakeRequests()
    responses: list[_FakeResponse] = [
        _FakeResponse([_batch_item(ip, "US") for ip in ips[:100]]),
        _FakeResponse([_batch_item(ip, "US") for ip in ips[100:]]),
    ]
    seq = iter(responses)

    def _post(url: str, **kwargs: object) -> _FakeResponse:
        http.post_calls.append((url, dict(kwargs)))
        return next(seq)

    monkeypatch.setattr(http, "post", _post)

    result = lookup_ips_batch(ips, http=http)

    assert len(result) == 150
    assert len(http.post_calls) == 2
    assert len(http.post_calls[0][1]["json"]) == 100
    assert len(http.post_calls[1][1]["json"]) == 50


def test_lookup_ips_batch_skips_non_success_item(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """单 IP status!=success 被跳过（不入结果、不缓存，允许后续重试）。"""
    monkeypatch.setattr(ipinfo_mod, "_SLEEP", lambda *_a, **_k: None)
    http = _FakeRequests()
    http.post_response = _FakeResponse(
        [
            _batch_item("1.1.1.1", "US"),
            {"status": "fail", "message": "private range", "query": "10.0.0.1"},
        ]
    )

    result = lookup_ips_batch(["1.1.1.1", "10.0.0.1"], http=http)

    assert set(result) == {"1.1.1.1"}
    assert "10.0.0.1" not in result
    # 被跳过的 IP 未入缓存：随后单查会触网。
    http.response = _FakeResponse({"status": "fail", "message": "x", "query": "10.0.0.1"})
    with pytest.raises(ValueError):
        lookup_ip("10.0.0.1", http=http)
    assert len(http.calls) == 1


def test_lookup_ips_batch_writes_cache_for_later_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """批量结果写入共享缓存：随后 lookup_ip 同一 IP 命中缓存不触网。"""
    monkeypatch.setattr(ipinfo_mod, "_SLEEP", lambda *_a, **_k: None)
    http = _FakeRequests()
    http.post_response = _FakeResponse([_batch_item("1.1.1.1", "US")])
    lookup_ips_batch(["1.1.1.1"], http=http)
    assert len(http.post_calls) == 1

    # 不配置 GET response：命中缓存才不会触网。
    data = lookup_ip("1.1.1.1", http=http)
    assert data["country"] == "US"
    assert http.calls == []


def test_lookup_ips_batch_uses_cache_skips_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """已缓存的 IP 不进 batch 请求；全部命中缓存时不发 POST。"""
    monkeypatch.setattr(ipinfo_mod, "_SLEEP", lambda *_a, **_k: None)
    http = _FakeRequests()
    http.response = _FakeResponse(_batch_item("1.1.1.1", "US"))
    lookup_ip("1.1.1.1", http=http)  # 先把 1.1.1.1 缓存

    result = lookup_ips_batch(["1.1.1.1"], http=http)
    assert result["1.1.1.1"]["country"] == "US"
    assert http.post_calls == []  # 全命中缓存，无 POST


def test_lookup_ips_batch_non_array_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """/batch 返回非数组 → 抛 ValueError（由调用方兜底）。"""
    monkeypatch.setattr(ipinfo_mod, "_SLEEP", lambda *_a, **_k: None)
    http = _FakeRequests()
    http.post_response = _FakeResponse({"not": "an array"})
    with pytest.raises(ValueError):
        lookup_ips_batch(["1.1.1.1"], http=http)


# --- ④ reset_state 清缓存 -------------------------------------------------


def test_reset_state_clears_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """reset_state 后同一 IP 需重新触网（缓存已清）。"""
    monkeypatch.setattr(ipinfo_mod, "_SLEEP", lambda *_a, **_k: None)
    http = _FakeRequests()
    http.response = _FakeResponse(_success_payload())
    lookup_ip("1.2.3.4", http=http)
    assert len(http.calls) == 1

    ipinfo_mod.reset_state()

    http.response = _FakeResponse(_success_payload())
    lookup_ip("1.2.3.4", http=http)
    assert len(http.calls) == 2  # 缓存被清，重新触网
