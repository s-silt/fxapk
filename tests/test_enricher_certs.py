"""CertsEnricher 单测：mock crt.sh（requests），不发真实请求。

覆盖：crt.sh JSON 归一（多行 name_value/通配/CN 去重）、只保留本域子域（过滤无关 SAN）、
超时/HTTP 错误 → ok=False、空结果 ok=True 且缓存、缓存命中不复触网、礼貌限速间隔、
攻击面渲染并入「关联子域(crt.sh)…串案」证据行、classify_jurisdiction 接受 certs kwarg。
"""

from __future__ import annotations

from pathlib import Path

import pytest

import apkscan.enrichers.certs as certs_mod
from apkscan.core import forensic
from apkscan.core.models import Endpoint
from apkscan.enrichers.certs import CertsEnricher

# 取自真实 crt.sh ?output=json 响应形态的精简样例（name_value 可多行含通配，含一条无关 SAN）。
_CRTSH_PAYLOAD = [
    {
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "evil.example",
        "name_value": "*.evil.example\nevil.example\napi.evil.example",
    },
    {
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "pay.evil.example",
        "name_value": "pay.evil.example",
    },
    {
        # 同证书带其它无关域的 SAN（多域证书常见）——不属 evil.example 域树，须被过滤掉。
        "issuer_name": "C=BE, O=GlobalSign nv-sa, CN=GlobalSign GCC R3",
        "common_name": "admin.evil.example",
        "name_value": "admin.evil.example\nunrelated-other.com",
    },
]


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(certs_mod, "CACHE_DIR", tmp_path / ".apkscan_cache")
    monkeypatch.setattr(certs_mod, "CACHE_FILE", tmp_path / ".apkscan_cache" / "certs.json")
    # 礼貌限速：测试里把 sleep 换成无操作 + 重置进程级闸时间戳，避免真等。
    monkeypatch.setattr(certs_mod.time, "sleep", lambda _s: None)
    monkeypatch.setattr(certs_mod, "_last_request_at", 0.0)


class _Resp:
    def __init__(self, status: int, payload: object, text: str | None = None) -> None:
        self.status_code = status
        self._p = payload
        # text 默认非空，让 _query 走 json() 分支；测空体场景显式传 text=""。
        self.text = text if text is not None else "[non-empty]"

    def json(self) -> object:
        return self._p

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeRequests:
    """记录每次调用的 params，便于断言触网次数 / 通配查询串。"""

    def __init__(self, status: int, payload: object, *, exc: Exception | None = None,
                 text: str | None = None) -> None:
        self.status = status
        self.payload = payload
        self.exc = exc
        self.text = text
        self.calls: list[dict] = []

    def get(self, url, params=None, timeout=None):  # type: ignore[no-untyped-def]
        self.calls.append({"url": url, "params": params or {}, "timeout": timeout})
        if self.exc is not None:
            raise self.exc
        return _Resp(self.status, self.payload, text=self.text)


def _ep(value: str = "evil.example") -> Endpoint:
    return Endpoint(value=value, kind="domain", evidences=[])


# --------------------------------------------------------------------------- 归一

def test_parses_and_normalizes_related_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeRequests(200, _CRTSH_PAYLOAD)
    monkeypatch.setattr(certs_mod._http, "capped_get", fake.get)
    res = CertsEnricher().enrich(_ep())
    assert res.ok is True
    hosts = res.data["related_hostnames"]
    # 通配 *.evil.example → evil.example；多行 name_value/CN 去重；排序稳定。
    assert hosts == [
        "admin.evil.example",
        "api.evil.example",
        "evil.example",
        "pay.evil.example",
    ]
    # 无关域 SAN 被过滤，不串错案。
    assert "unrelated-other.com" not in hosts
    assert res.data["hostname_total"] == 4
    assert res.data["cert_count"] == 3
    # issuer 汇总去重（两条 Let's Encrypt 合一 + 一条 GlobalSign）。
    assert len(res.data["issuers"]) == 2
    # 走了通配查询串。
    assert fake.calls and fake.calls[0]["params"].get("q") == "%.evil.example"
    assert fake.calls[0]["params"].get("output") == "json"


def test_timeout_ok_false_not_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    """crt.sh 超时（requests 抛）→ ok=False，不缓存，便于重试。"""
    fake = _FakeRequests(200, None, exc=TimeoutError("read timed out"))
    monkeypatch.setattr(certs_mod._http, "capped_get", fake.get)
    e = CertsEnricher()
    res = e.enrich(_ep())
    assert res.ok is False
    assert "TimeoutError" in (res.error or "")
    n = len(fake.calls)
    e.enrich(_ep())  # 失败未缓存 → 再次触网
    assert len(fake.calls) > n


def test_http_error_ok_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """crt.sh 502/503（raise_for_status 抛）→ ok=False。"""
    fake = _FakeRequests(502, {})
    monkeypatch.setattr(certs_mod._http, "capped_get", fake.get)
    res = CertsEnricher().enrich(_ep())
    assert res.ok is False


def test_empty_result_ok_true_and_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    """crt.sh 返回空列表（无证书）→ ok=True 无关联主机名，且缓存（避免对慢接口复查）。"""
    fake = _FakeRequests(200, [])
    monkeypatch.setattr(certs_mod._http, "capped_get", fake.get)
    e = CertsEnricher()
    res = e.enrich(_ep())
    assert res.ok is True
    assert res.data["related_hostnames"] == []
    assert res.data["hostname_total"] == 0
    n = len(fake.calls)
    e.enrich(_ep())  # 命中缓存（含空结果）→ 不再触网
    assert len(fake.calls) == n


def test_empty_body_treated_as_no_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """crt.sh 偶发返回空体（非 JSON）→ 按无结果归一，不抛、不调 json()。"""
    fake = _FakeRequests(200, None, text="")  # payload=None 但走不到 json()
    monkeypatch.setattr(certs_mod._http, "capped_get", fake.get)
    res = CertsEnricher().enrich(_ep())
    assert res.ok is True
    assert res.data["related_hostnames"] == []


def test_cache_hit_skips_network(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeRequests(200, _CRTSH_PAYLOAD)
    monkeypatch.setattr(certs_mod._http, "capped_get", fake.get)
    e = CertsEnricher()
    e.enrich(_ep())
    n = len(fake.calls)
    e.enrich(_ep())
    assert len(fake.calls) == n


def test_empty_value_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeRequests(200, _CRTSH_PAYLOAD)
    monkeypatch.setattr(certs_mod._http, "capped_get", fake.get)
    res = CertsEnricher().enrich(Endpoint(value="   ", kind="domain", evidences=[]))
    assert res.ok is False
    assert not fake.calls  # 空值绝不触网


# --------------------------------------------------------------------------- 限速

def test_throttle_sleeps_when_too_soon(monkeypatch: pytest.MonkeyPatch) -> None:
    """相邻请求间隔不足 _MIN_INTERVAL → _throttle 触发一次 sleep（受控时钟验证逻辑，不真等）。"""
    fake_now = {"t": 1000.0}
    slept: list[float] = []
    monkeypatch.setattr(certs_mod.time, "monotonic", lambda: fake_now["t"])
    monkeypatch.setattr(certs_mod.time, "sleep", lambda s: slept.append(s))
    monkeypatch.setattr(certs_mod, "_last_request_at", 0.0)

    certs_mod._throttle()  # 首次：距 0 已 1000s，无需 sleep
    assert not slept
    certs_mod._throttle()  # 紧接第二次（同一时刻）：间隔 0 < _MIN_INTERVAL → sleep
    assert slept and slept[0] == pytest.approx(certs_mod._MIN_INTERVAL)


# --------------------------------------------------------------------------- 渲染

def test_render_related_subdomains() -> None:
    lines = forensic.render_related_subdomains({
        "related_hostnames": ["api.evil.example", "pay.evil.example", "admin.evil.example"],
        "hostname_total": 3,
        "source": "crtsh",
    })
    blob = "\n".join(lines)
    assert "api.evil.example" in blob and "pay.evil.example" in blob
    assert "crt.sh" in blob
    assert "串案" in blob


def test_render_related_subdomains_truncates() -> None:
    hosts = [f"h{i}.evil.example" for i in range(30)]
    lines = forensic.render_related_subdomains(
        {"related_hostnames": hosts, "hostname_total": 30, "source": "crtsh"}
    )
    blob = "\n".join(lines)
    assert "等共 30 个" in blob


def test_render_related_subdomains_empty() -> None:
    assert forensic.render_related_subdomains({"related_hostnames": [], "source": "crtsh"}) == []
    assert forensic.render_related_subdomains({"note": "x"}) == []
    assert forensic.render_related_subdomains(None) == []


def test_classify_jurisdiction_accepts_certs_kwarg() -> None:
    """certs 不携带归属国，但须被 classify_jurisdiction 接受（pipeline **enr 透传不 TypeError）。"""
    assert (
        forensic.classify_jurisdiction("evil.example", certs={"related_hostnames": []})
        == forensic.JURIS_UNKNOWN
    )
