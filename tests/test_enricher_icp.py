"""IcpEnricher 单测：mock 掉网络层（requests / provider），不发任何真实请求。

覆盖：
- 基本属性 name / applies_to。
- 默认无 provider → ok=False，error 为“需人工核”，data 含工信部 + 域名直查链接。
- 接入 provider 成功路径：ok=True，字段被正确提取，结果写缓存。
- 失败路径①：requests 抛异常（超时等）→ ok=False，error 含异常信息且仍附人工核链接。
- 失败路径②：HTTP 4xx/5xx（raise_for_status）→ ok=False。
- 失败路径③：provider 返回非对象 → ok=False。
- 空域名 → ok=False，不触网。
- 缓存：成功写盘、二次命中（不再触网）；失败/需人工核不写缓存。
- 缓存目录不存在时自动创建。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import apkscan.enrichers.icp as icp_mod
from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.enrichers.icp import IcpEnricher, IcpUnavailable
from apkscan.selfcheck import build_credential_components


# --- 通用打桩 -------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """把缓存重定向到临时目录，互不干扰，且不污染项目根。"""
    cache_dir = tmp_path / ".apkscan_cache"
    cache_file = cache_dir / "icp.json"
    monkeypatch.setattr(icp_mod, "CACHE_DIR", cache_dir)
    monkeypatch.setattr(icp_mod, "CACHE_FILE", cache_file)
    return cache_file


class _FakeResponse:
    """假的 requests.Response：可配置 JSON、HTTP 异常。"""

    def __init__(
        self,
        json_data: object,
        raise_for_status_exc: Exception | None = None,
        status_code: int = 200,
    ) -> None:
        self._json = json_data
        self._raise_for_status_exc = raise_for_status_exc
        self.status_code = status_code

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

    def post(self, url: str, **kwargs: object) -> _FakeResponse:
        self.calls.append((url, dict(kwargs)))
        if self.raises is not None:
            raise self.raises
        assert self.response is not None, "测试未配置 response"
        return self.response


@pytest.fixture
def fake_requests(monkeypatch: pytest.MonkeyPatch) -> _FakeRequests:
    """把假 requests 注入 enricher 模块命名空间。"""
    fake = _FakeRequests()
    monkeypatch.setattr(icp_mod, "requests", fake)
    return fake


class _ProviderEnricher(IcpEnricher):
    """覆写 _provider_url 以模拟“已接入 provider”的子类，复用网络/缓存骨架。"""

    PROVIDER = "http://icp.provider.test/query?domain={domain}"

    def _provider_url(self, domain: str) -> str | None:
        return self.PROVIDER.format(domain=domain)


def _ep(value: str = "pay.fraud-gw.cn") -> Endpoint:
    return Endpoint(value=value, kind="domain")


def _success_payload() -> dict[str, str]:
    return {
        "subject": "示例网关有限公司",
        "license_no": "京ICP备12345678号-1",
        "site_name": "支付网关",
        "nature": "企业",
    }


# --- 基本属性 -------------------------------------------------------------


def test_name_and_applies_to() -> None:
    enr = IcpEnricher()
    assert enr.name == "icp"
    assert enr.applies_to == ["domain"]
    assert enr.required_env == ("FXAPK_ICP_HAPI_KEY",)


def test_custom_provider_does_not_require_hapi_key() -> None:
    assert _ProviderEnricher().required_env == ()


def test_selfcheck_does_not_gate_custom_provider_on_hapi_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FXAPK_ICP_HAPI_KEY", raising=False)
    monkeypatch.setattr(
        "apkscan.core.registry.discover_enrichers",
        lambda: [_ProviderEnricher()],
    )

    assert build_credential_components() == []


def test_hapi_bearer_request_maps_documented_record(
    fake_requests: _FakeRequests,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """防回归：HAPI key 只能进请求头，备案记录必须映射到统一 ICP 字段。"""
    token = "synthetic-hapi-token-for-test"
    monkeypatch.setenv("FXAPK_ICP_HAPI_KEY", token)
    fake_requests.response = _FakeResponse(
        {
            "code": 200,
            "msg": "success",
            "params": {
                "list": [
                    {
                        "unitName": "示例科技有限公司",
                        "natureName": "企业",
                        "serviceLicence": "京ICP备00000000号-1",
                        "mainLicence": "京ICP备00000000号",
                        "serviceName": "示例网站",
                        "updateRecordTime": "2026-08-31",
                        "domain": "example.test",
                    }
                ]
            },
        }
    )

    result = IcpEnricher().enrich(_ep("WWW.Example.TEST"))

    assert result.ok is True
    assert result.data == {
        "subject": "示例科技有限公司",
        "license_no": "京ICP备00000000号-1",
        "main_license_no": "京ICP备00000000号",
        "site_name": "示例网站",
        "nature": "企业",
        "approval_time": "2026-08-31",
        "provider_name": "hapi",
    }
    assert len(fake_requests.calls) == 1
    url, kwargs = fake_requests.calls[0]
    assert url == "https://api.8450.cn/api/icp"
    assert kwargs["headers"] == {"Authorization": f"Bearer {token}"}
    assert kwargs["data"] == {
        "type": "web",
        "search": "www.example.test",
        "pageNum": "1",
        "pageSize": "10",
    }
    assert token not in url
    assert token not in json.dumps(kwargs["data"], ensure_ascii=False)


def test_hapi_empty_result_is_no_record_not_provider_failure(
    fake_requests: _FakeRequests,
    monkeypatch: pytest.MonkeyPatch,
    _isolated_cache: Path,
) -> None:
    """防回归：查询成功但空结果必须是 no_record，且不能写成成功缓存。"""
    monkeypatch.setenv("FXAPK_ICP_HAPI_KEY", "synthetic-hapi-token-for-test")
    fake_requests.response = _FakeResponse(
        {"code": 200, "msg": "success", "params": {"list": []}}
    )

    result = IcpEnricher().enrich(_ep("no-record.example.test"))

    assert result.ok is True
    assert result.error is None
    assert result.data == {"_source_status": "no_record", "provider_name": "hapi"}
    assert not _isolated_cache.exists()


def test_hapi_declared_auth_error_is_stable_and_never_leaks_token(
    fake_requests: _FakeRequests,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """防回归：HAPI 业务错误只落稳定分类码，不落 token 或上游正文。"""
    token = "synthetic-hapi-token-for-test"
    monkeypatch.setenv("FXAPK_ICP_HAPI_KEY", token)
    fake_requests.response = _FakeResponse(
        {"code": 505, "msg": f"bad token {token}", "params": None}
    )

    result = IcpEnricher().enrich(_ep("auth-error.example.test"))

    assert result.ok is False
    assert result.error == "authentication_failed"
    assert token not in json.dumps(result.data, ensure_ascii=False)
    assert token not in str(result.error)


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (507, "quota_insufficient"),
        (511, "rate_limited"),
        (530, "provider_unavailable"),
        (599, "provider_error"),
    ],
)
def test_hapi_business_errors_have_stable_categories(
    fake_requests: _FakeRequests,
    monkeypatch: pytest.MonkeyPatch,
    code: int,
    expected: str,
) -> None:
    monkeypatch.setenv("FXAPK_ICP_HAPI_KEY", "synthetic-hapi-token-for-test")
    fake_requests.response = _FakeResponse(
        {"code": code, "msg": "provider detail must not escape", "params": None}
    )

    result = IcpEnricher().enrich(_ep(f"business-{code}.example.test"))

    assert result.ok is False
    assert result.error == expected


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [
        (401, "authentication_failed"),
        (403, "authentication_failed"),
        (402, "quota_insufficient"),
        (429, "rate_limited"),
        (500, "provider_unavailable"),
        (503, "provider_unavailable"),
        (400, "invalid_request"),
        (418, "invalid_request"),
    ],
)
def test_hapi_http_errors_have_stable_categories(
    fake_requests: _FakeRequests,
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
    expected: str,
) -> None:
    monkeypatch.setenv("FXAPK_ICP_HAPI_KEY", "synthetic-hapi-token-for-test")
    fake_requests.response = _FakeResponse(
        {"code": 200, "params": []}, status_code=status_code
    )

    result = IcpEnricher().enrich(_ep(f"http-{status_code}.example.test"))

    assert result.ok is False
    assert result.error == expected


def test_hapi_nested_wrapper_is_unwrapped(
    fake_requests: _FakeRequests,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FXAPK_ICP_HAPI_KEY", "synthetic-hapi-token-for-test")
    fake_requests.response = _FakeResponse(
        {
            "code": 200,
            "params": {
                "data": {
                    "list": [
                        {
                            "companyName": "嵌套示例公司",
                            "serviceLicence": "京ICP备00000001号-1",
                            "domainName": "nested.example.test",
                        }
                    ]
                }
            },
        }
    )

    result = IcpEnricher().enrich(_ep("nested.example.test"))

    assert result.ok is True
    assert result.data["subject"] == "嵌套示例公司"
    assert result.data["license_no"] == "京ICP备00000001号-1"


def test_hapi_unknown_nonempty_wrapper_is_parse_error_and_not_cached(
    fake_requests: _FakeRequests,
    monkeypatch: pytest.MonkeyPatch,
    _isolated_cache: Path,
) -> None:
    monkeypatch.setenv("FXAPK_ICP_HAPI_KEY", "synthetic-hapi-token-for-test")
    fake_requests.response = _FakeResponse(
        {"code": 200, "params": {"data": {"unexpected": "shape"}}}
    )

    result = IcpEnricher().enrich(_ep("bad-wrapper.example.test"))

    assert result.ok is False
    assert result.error == "parse_error"
    assert not _isolated_cache.exists()


def test_hapi_explicit_mismatched_candidates_are_no_record(
    fake_requests: _FakeRequests,
    monkeypatch: pytest.MonkeyPatch,
    _isolated_cache: Path,
) -> None:
    monkeypatch.setenv("FXAPK_ICP_HAPI_KEY", "synthetic-hapi-token-for-test")
    fake_requests.response = _FakeResponse(
        {
            "code": 200,
            "params": {
                "list": [
                    {
                        "unitName": "甲公司",
                        "serviceLicence": "京ICP备00000002号",
                        "domain": "other.example.test",
                    },
                    {
                        "unitName": "乙公司",
                        "serviceLicence": "京ICP备00000003号",
                        "domain": "unrelated.example.test",
                    },
                ]
            },
        }
    )

    result = IcpEnricher().enrich(_ep("wanted.example.test"))

    assert result.ok is True
    assert result.data["_source_status"] == "no_record"
    assert not _isolated_cache.exists()


def test_hapi_parent_domain_record_matches_subdomain(
    fake_requests: _FakeRequests,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FXAPK_ICP_HAPI_KEY", "synthetic-hapi-token-for-test")
    fake_requests.response = _FakeResponse(
        {
            "code": 200,
            "params": {
                "list": [
                    {
                        "companyName": "根域主体",
                        "serviceLicence": "京ICP备00000004号",
                        "domain": "example.test",
                    }
                ]
            },
        }
    )

    result = IcpEnricher().enrich(_ep("api.example.test"))

    assert result.ok is True
    assert result.data["subject"] == "根域主体"


def test_hapi_root_query_does_not_accept_child_domain_record(
    fake_requests: _FakeRequests,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FXAPK_ICP_HAPI_KEY", "synthetic-hapi-token-for-test")
    fake_requests.response = _FakeResponse(
        {
            "code": 200,
            "params": {
                "list": [
                    {
                        "unitName": "子域主体",
                        "serviceLicence": "京ICP备00000008号",
                        "domain": "api.example.test",
                    }
                ]
            },
        }
    )

    result = IcpEnricher().enrich(_ep("example.test"))

    assert result.ok is True
    assert result.data["_source_status"] == "no_record"


def test_hapi_root_query_does_not_accept_www_child_record(
    fake_requests: _FakeRequests,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FXAPK_ICP_HAPI_KEY", "synthetic-hapi-token-for-test")
    fake_requests.response = _FakeResponse(
        {
            "code": 200,
            "params": {
                "list": [
                    {
                        "unitName": "WWW 子域主体",
                        "serviceLicence": "京ICP备00000014号",
                        "domain": "www.example.test",
                    }
                ]
            },
        }
    )

    result = IcpEnricher().enrich(_ep("example.test"))

    assert result.ok is True
    assert result.data["_source_status"] == "no_record"


def test_hapi_multiple_ancestors_choose_nearest_domain(
    fake_requests: _FakeRequests,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FXAPK_ICP_HAPI_KEY", "synthetic-hapi-token-for-test")
    fake_requests.response = _FakeResponse(
        {
            "code": 200,
            "params": {
                "list": [
                    {
                        "unitName": "较远主体",
                        "serviceLicence": "京ICP备00000009号",
                        "domain": "example.test",
                    },
                    {
                        "unitName": "最近主体",
                        "serviceLicence": "京ICP备00000010号",
                        "domain": "b.example.test",
                    },
                ]
            },
        }
    )

    result = IcpEnricher().enrich(_ep("a.b.example.test"))

    assert result.ok is True
    assert result.data["subject"] == "最近主体"


def test_hapi_same_domain_conflict_is_no_record(
    fake_requests: _FakeRequests,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FXAPK_ICP_HAPI_KEY", "synthetic-hapi-token-for-test")
    fake_requests.response = _FakeResponse(
        {
            "code": 200,
            "params": {
                "list": [
                    {
                        "unitName": "候选甲",
                        "serviceLicence": "京ICP备00000011号",
                        "domain": "example.test",
                    },
                    {
                        "unitName": "候选乙",
                        "serviceLicence": "京ICP备00000012号",
                        "domain": "example.test",
                    },
                ]
            },
        }
    )

    result = IcpEnricher().enrich(_ep("api.example.test"))

    assert result.ok is True
    assert result.data["_source_status"] == "no_record"


def test_hapi_main_license_alias_is_authoritative(
    fake_requests: _FakeRequests,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FXAPK_ICP_HAPI_KEY", "synthetic-hapi-token-for-test")
    fake_requests.response = _FakeResponse(
        {
            "code": 200,
            "params": {
                "mainLicense": "京ICP备00000013号",
                "domain": "alias.example.test",
            },
        }
    )

    result = IcpEnricher().enrich(_ep("alias.example.test"))

    assert result.ok is True
    assert result.data["license_no"] == "京ICP备00000013号"
    assert result.data["main_license_no"] == "京ICP备00000013号"


def test_hapi_record_without_authoritative_fields_is_parse_error(
    fake_requests: _FakeRequests,
    monkeypatch: pytest.MonkeyPatch,
    _isolated_cache: Path,
) -> None:
    monkeypatch.setenv("FXAPK_ICP_HAPI_KEY", "synthetic-hapi-token-for-test")
    fake_requests.response = _FakeResponse(
        {"code": 200, "params": {"domain": "empty.example.test"}}
    )

    result = IcpEnricher().enrich(_ep("empty.example.test"))

    assert result.ok is False
    assert result.error == "parse_error"
    assert not _isolated_cache.exists()


# --- 默认无 provider：优雅降级到人工核 ------------------------------------


def test_default_no_provider_returns_manual_hint() -> None:
    result = IcpEnricher().enrich(_ep())

    assert isinstance(result, EnrichmentResult)
    assert result.provider == "icp"
    assert result.ok is False
    # error 只放稳定分类码；人工核验指引在 data["hint"]（见下一条断言）。
    assert result.error == "provider_unavailable"
    # data 给出人工核验所需链接。
    assert result.data["status"] == "manual_required"
    assert result.data["miit_url"] == icp_mod.MIIT_BEIAN_URL
    assert "pay.fraud-gw.cn" in result.data["lookup_url"]
    assert result.data["hint"] == icp_mod.MANUAL_HINT


def test_query_raises_icp_unavailable_by_default() -> None:
    # 内部查询点：默认配置抛 IcpUnavailable（可插拔契约）。
    with pytest.raises(IcpUnavailable):
        IcpEnricher()._query("example.cn")


def test_manual_path_does_not_write_cache(_isolated_cache: Path) -> None:
    IcpEnricher().enrich(_ep("nocache.cn"))
    assert not _isolated_cache.exists()


# --- 接入 provider：成功路径 ----------------------------------------------


def test_provider_success_extracts_fields(fake_requests: _FakeRequests) -> None:
    fake_requests.response = _FakeResponse(_success_payload())
    result = _ProviderEnricher().enrich(_ep("beian-ok.cn"))

    assert isinstance(result, EnrichmentResult)
    assert result.provider == "icp"
    assert result.ok is True
    assert result.error is None
    assert result.data["subject"] == "示例网关有限公司"
    assert result.data["license_no"] == "京ICP备12345678号-1"
    assert result.data["site_name"] == "支付网关"
    assert result.data["nature"] == "企业"

    # 触网恰好一次，带 timeout，且 URL 含归一化域名。
    assert len(fake_requests.calls) == 1
    url, kwargs = fake_requests.calls[0]
    assert "beian-ok.cn" in url
    assert kwargs.get("timeout") == icp_mod.ICP_TIMEOUT


def test_provider_alt_keys_extracted(fake_requests: _FakeRequests) -> None:
    # 工信部风格字段名（unitName/mainLicence/...）也能解析。
    fake_requests.response = _FakeResponse(
        {
            "unitName": "某科技公司",
            "mainLicence": "沪ICP备99999999号",
            "siteName": "官网",
            "natureName": "企业",
        }
    )
    result = _ProviderEnricher().enrich(_ep("alt.cn"))
    assert result.ok is True
    assert result.data["subject"] == "某科技公司"
    assert result.data["license_no"] == "沪ICP备99999999号"
    assert result.data["site_name"] == "官网"
    assert result.data["nature"] == "企业"


def test_provider_missing_fields_become_none(fake_requests: _FakeRequests) -> None:
    fake_requests.response = _FakeResponse({"subject": "仅主体"})
    result = _ProviderEnricher().enrich(_ep("partial.cn"))
    assert result.ok is True
    assert result.data["subject"] == "仅主体"
    assert result.data["license_no"] is None
    assert result.data["site_name"] is None
    assert result.data["nature"] is None


# --- 接入 provider：失败路径 ----------------------------------------------


def test_provider_network_error_returns_not_ok(
    fake_requests: _FakeRequests,
) -> None:
    fake_requests.raises = TimeoutError("connection timed out")
    result = _ProviderEnricher().enrich(_ep("timeout.cn"))

    assert isinstance(result, EnrichmentResult)
    assert result.provider == "icp"
    assert result.ok is False
    assert result.error == "timeout"
    # 即便网络异常，也仍附上人工核验链接。
    assert result.data["status"] == "manual_required"
    assert result.data["hint"] == icp_mod.MANUAL_HINT


def test_provider_http_error_returns_not_ok(fake_requests: _FakeRequests) -> None:
    fake_requests.response = _FakeResponse(
        {}, raise_for_status_exc=RuntimeError("429 Too Many Requests")
    )
    result = _ProviderEnricher().enrich(_ep("http429.cn"))
    assert result.ok is False
    assert "RuntimeError" in result.error


def test_provider_non_object_payload_returns_not_ok(
    fake_requests: _FakeRequests,
) -> None:
    fake_requests.response = _FakeResponse(["not", "a", "dict"])
    result = _ProviderEnricher().enrich(_ep("badjson.cn"))
    assert result.ok is False
    assert result.error


def test_enrich_does_not_raise_on_arbitrary_exception(
    fake_requests: _FakeRequests,
) -> None:
    fake_requests.raises = ValueError("bad json")
    result = _ProviderEnricher().enrich(_ep("boom.cn"))
    assert result.ok is False
    assert result.error == "parse_error"


def test_provider_failed_query_not_cached(
    fake_requests: _FakeRequests, _isolated_cache: Path
) -> None:
    fake_requests.raises = RuntimeError("boom")
    _ProviderEnricher().enrich(_ep("failcache.cn"))
    assert not _isolated_cache.exists()


# --- 空域名（不触网）------------------------------------------------------


def test_empty_domain_short_circuits(fake_requests: _FakeRequests) -> None:
    result = IcpEnricher().enrich(Endpoint(value="   ", kind="domain"))
    assert result.ok is False
    assert result.error
    assert fake_requests.calls == []  # 没触网


# --- 缓存 -----------------------------------------------------------------


def test_provider_result_written_to_cache(
    fake_requests: _FakeRequests, _isolated_cache: Path
) -> None:
    fake_requests.response = _FakeResponse(_success_payload())
    _ProviderEnricher().enrich(_ep("cache-me.test"))

    assert _isolated_cache.is_file()
    cache = json.loads(_isolated_cache.read_text(encoding="utf-8"))
    key = next(key for key in cache if key.endswith("|cache-me.test"))
    assert key.startswith("custom:")
    assert cache[key]["subject"] == "示例网关有限公司"


def test_cache_hit_skips_network(fake_requests: _FakeRequests) -> None:
    fake_requests.response = _FakeResponse(_success_payload())
    enr = _ProviderEnricher()

    first = enr.enrich(_ep("repeat.cn"))
    assert first.ok is True
    assert len(fake_requests.calls) == 1

    # 第二次：命中缓存，不再触网。
    fake_requests.response = _FakeResponse({"subject": "SHOULD NOT BE USED"})
    second = enr.enrich(_ep("repeat.cn"))
    assert second.ok is True
    assert second.data["subject"] == "示例网关有限公司"
    assert len(fake_requests.calls) == 1  # 没有新增网络调用


def test_cache_hit_across_instances(fake_requests: _FakeRequests) -> None:
    fake_requests.response = _FakeResponse(_success_payload())
    _ProviderEnricher().enrich(_ep("persist.cn"))
    assert len(fake_requests.calls) == 1

    # 新实例也能读到磁盘缓存。
    result = _ProviderEnricher().enrich(_ep("persist.cn"))
    assert result.ok is True
    assert result.data["subject"] == "示例网关有限公司"
    assert len(fake_requests.calls) == 1


def test_cache_dir_created_when_missing(
    fake_requests: _FakeRequests, _isolated_cache: Path
) -> None:
    assert not _isolated_cache.parent.exists()
    fake_requests.response = _FakeResponse(_success_payload())
    _ProviderEnricher().enrich(_ep("mkdir.cn"))
    assert _isolated_cache.parent.is_dir()
    assert _isolated_cache.is_file()


def test_domain_normalized_lowercase_in_cache(
    fake_requests: _FakeRequests, _isolated_cache: Path
) -> None:
    fake_requests.response = _FakeResponse(_success_payload())
    _ProviderEnricher().enrich(_ep("MixedCase.TEST"))
    cache = json.loads(_isolated_cache.read_text(encoding="utf-8"))
    assert any(key.endswith("|mixedcase.test") for key in cache)
    # 触网时用归一化后的域名。
    assert "mixedcase.test" in fake_requests.calls[0][0]


def test_custom_cache_cannot_satisfy_hapi_query(
    fake_requests: _FakeRequests,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_requests.response = _FakeResponse(_success_payload())
    _ProviderEnricher().enrich(_ep("isolated.example.test"))
    assert len(fake_requests.calls) == 1

    monkeypatch.setenv("FXAPK_ICP_HAPI_KEY", "synthetic-hapi-token-for-test")
    fake_requests.response = _FakeResponse(
        {
            "code": 200,
            "params": {
                "list": [
                    {
                        "unitName": "HAPI 主体",
                        "serviceLicence": "京ICP备00000005号",
                        "domain": "isolated.example.test",
                    }
                ]
            },
        }
    )

    result = IcpEnricher().enrich(_ep("isolated.example.test"))

    assert result.ok is True
    assert result.data["subject"] == "HAPI 主体"
    assert len(fake_requests.calls) == 2


def test_hapi_cache_cannot_satisfy_custom_provider_query(
    fake_requests: _FakeRequests,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FXAPK_ICP_HAPI_KEY", "synthetic-hapi-token-for-test")
    fake_requests.response = _FakeResponse(
        {
            "code": 200,
            "params": {
                "list": [
                    {
                        "unitName": "HAPI 主体",
                        "serviceLicence": "京ICP备00000006号",
                        "domain": "reverse.example.test",
                    }
                ]
            },
        }
    )
    IcpEnricher().enrich(_ep("reverse.example.test"))
    assert len(fake_requests.calls) == 1

    fake_requests.response = _FakeResponse(_success_payload())
    result = _ProviderEnricher().enrich(_ep("reverse.example.test"))

    assert result.ok is True
    assert result.data["subject"] == "示例网关有限公司"
    assert len(fake_requests.calls) == 2


def test_hapi_success_cache_skips_second_request(
    fake_requests: _FakeRequests,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FXAPK_ICP_HAPI_KEY", "synthetic-hapi-token-for-test")
    fake_requests.response = _FakeResponse(
        {
            "code": 200,
            "params": {
                "list": [
                    {
                        "unitName": "缓存主体",
                        "serviceLicence": "京ICP备00000007号",
                        "domain": "hapi-cache.example.test",
                    }
                ]
            },
        }
    )

    first = IcpEnricher().enrich(_ep("hapi-cache.example.test"))
    second = IcpEnricher().enrich(_ep("hapi-cache.example.test"))

    assert first.ok is True
    assert second.ok is True
    assert second.data["provider_name"] == "hapi"
    assert len(fake_requests.calls) == 1


def test_unavailable_logged_once_for_multiple_domains(
    _isolated_cache: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """未配置 provider（系统性不可用）→ 多域名只记一次 INFO，不逐域名刷屏；
    但每个域名仍返回人工核验数据（manual_required + 工信部链接）。"""
    import logging

    enr = IcpEnricher()
    with caplog.at_level(logging.INFO, logger="apkscan.enrichers.icp"):
        enr.enrich(_ep("a.cn"))
        enr.enrich(_ep("b.cn"))
        enr.enrich(_ep("c.cn"))

    assert caplog.text.count("ICP 自动查询不可用") == 1
    r = enr.enrich(_ep("d.cn"))
    assert r.ok is False
    assert r.data and r.data.get("status") == "manual_required"
