"""WhoisEnricher 单测：mock 掉网络层（python-whois），不发任何真实请求。

覆盖：
- 基本属性 name / applies_to。
- 成功路径：whois.whois 返回 dict-like → ok=True，字段被正确提取。
- 失败路径：whois.whois 抛异常 → ok=False 且 error 非空，不抛出。
- 字段归一：list 字段取首个、datetime → isoformat。
- 空域名 → ok=False，不触网。
- 本地 JSON 缓存：首查写盘、二次查命中缓存（不再触网）。
- 缓存目录不存在时自动创建。
"""

from __future__ import annotations

import json
import sys
import types
from datetime import datetime
from pathlib import Path

import pytest

import apkscan.enrichers.whois as whois_mod
from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.enrichers.whois import WhoisEnricher


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """把缓存重定向到临时目录，互不干扰，且不污染项目根。"""
    cache_dir = tmp_path / ".apkscan_cache"
    cache_file = cache_dir / "whois.json"
    monkeypatch.setattr(whois_mod, "CACHE_DIR", cache_dir)
    monkeypatch.setattr(whois_mod, "CACHE_FILE", cache_file)
    return cache_file


class _FakeWhoisModule(types.ModuleType):
    """假的 ``whois`` 模块：记录调用次数，按配置返回或抛异常。"""

    def __init__(self) -> None:
        super().__init__("whois")
        self.calls: list[tuple[str, dict]] = []
        self.return_value: object = {}
        self.raises: Exception | None = None

    def whois(self, domain: str, **kwargs):  # noqa: ANN003
        self.calls.append((domain, kwargs))
        if self.raises is not None:
            raise self.raises
        return self.return_value


@pytest.fixture
def fake_whois(monkeypatch: pytest.MonkeyPatch) -> _FakeWhoisModule:
    """把假 ``whois`` 模块塞进 sys.modules，使 enricher 内部 ``import whois`` 命中它。"""
    mod = _FakeWhoisModule()
    monkeypatch.setitem(sys.modules, "whois", mod)
    return mod


def _ep(value: str = "pay.fraud-gw.cn") -> Endpoint:
    return Endpoint(value=value, kind="domain")


# --- 基本属性 -------------------------------------------------------------


def test_name_and_applies_to():
    enr = WhoisEnricher()
    assert enr.name == "whois"
    # 避免 whois 双查：归属收敛到 rdap（RDAP→whois 兜底），独立 WhoisEnricher 不再被
    # pipeline 路由 → applies_to 置空。其查询函数仍供 rdap 复用（见下）。
    assert enr.applies_to == []


# --- 可复用查询函数（供 rdap 兜底复用）-------------------------------------


def test_query_whois_reusable_function(fake_whois: _FakeWhoisModule):
    """whois.py 把查询+抽取逻辑抽成可复用的模块级函数 query_whois(domain)->dict。"""
    from apkscan.enrichers.whois import query_whois

    fake_whois.return_value = {
        "registrar": "GoDaddy.com, LLC",
        "registrant_name": "Zhang San",
        "creation_date": datetime(2021, 5, 1, 12, 0, 0),
        "country": "CN",
    }
    data = query_whois("reuse.cn")
    assert data["registrar"] == "GoDaddy.com, LLC"
    assert data["registrant"] == "Zhang San"
    assert data["creation_date"] == "2021-05-01T12:00:00"
    assert fake_whois.calls[0][0] == "reuse.cn"


def test_query_whois_propagates_exception(fake_whois: _FakeWhoisModule):
    """query_whois 不吞错：网络失败原样抛出，由调用方决定兜底（rdap 据此回退失败）。"""
    from apkscan.enrichers.whois import query_whois

    fake_whois.raises = TimeoutError("down")
    with pytest.raises(TimeoutError):
        query_whois("boom.cn")


# --- 成功路径 -------------------------------------------------------------


def test_enrich_success_extracts_fields(fake_whois: _FakeWhoisModule):
    fake_whois.return_value = {
        "registrar": "GoDaddy.com, LLC",
        "registrant_name": "Zhang San",
        "org": "Fraud Gateway Co",
        "creation_date": datetime(2021, 5, 1, 12, 0, 0),
        "country": "CN",
    }
    result = WhoisEnricher().enrich(_ep())

    assert isinstance(result, EnrichmentResult)
    assert result.provider == "whois"
    assert result.ok is True
    assert result.error is None
    assert result.data["registrar"] == "GoDaddy.com, LLC"
    assert result.data["registrant"] == "Zhang San"
    assert result.data["org"] == "Fraud Gateway Co"
    assert result.data["creation_date"] == "2021-05-01T12:00:00"
    assert result.data["country"] == "CN"
    # 触网恰好一次，且带 timeout。
    assert len(fake_whois.calls) == 1
    assert fake_whois.calls[0][0] == "pay.fraud-gw.cn"
    assert fake_whois.calls[0][1].get("timeout") == whois_mod.WHOIS_TIMEOUT


def test_enrich_list_fields_take_first(fake_whois: _FakeWhoisModule):
    # 多注册商 / 多注册时间是常见返回形态。
    fake_whois.return_value = {
        "registrar": ["Reg A", "Reg B"],
        "creation_date": [datetime(2020, 1, 2), datetime(2020, 1, 3)],
    }
    result = WhoisEnricher().enrich(_ep())
    assert result.ok is True
    assert result.data["registrar"] == "Reg A"
    assert result.data["creation_date"] == "2020-01-02T00:00:00"


def test_enrich_missing_fields_become_none(fake_whois: _FakeWhoisModule):
    fake_whois.return_value = {"registrar": "Only Registrar"}
    result = WhoisEnricher().enrich(_ep())
    assert result.ok is True
    assert result.data["registrar"] == "Only Registrar"
    assert result.data["registrant"] is None
    assert result.data["org"] is None
    assert result.data["creation_date"] is None
    assert result.data["country"] is None


# --- 失败路径 -------------------------------------------------------------


def test_enrich_network_error_returns_not_ok(fake_whois: _FakeWhoisModule):
    fake_whois.raises = TimeoutError("connection timed out")
    result = WhoisEnricher().enrich(_ep())

    assert isinstance(result, EnrichmentResult)
    assert result.provider == "whois"
    assert result.ok is False
    assert result.error
    assert "TimeoutError" in result.error
    assert result.data == {}


def test_enrich_does_not_raise_on_arbitrary_exception(fake_whois: _FakeWhoisModule):
    fake_whois.raises = ValueError("unparseable whois response")
    # 不应抛出。
    result = WhoisEnricher().enrich(_ep())
    assert result.ok is False
    assert "ValueError" in result.error


def test_failed_query_not_cached(fake_whois: _FakeWhoisModule, _isolated_cache: Path):
    fake_whois.raises = RuntimeError("boom")
    WhoisEnricher().enrich(_ep())
    # 失败不写缓存文件。
    assert not _isolated_cache.exists()


# --- 空域名（不触网）------------------------------------------------------


def test_empty_domain_short_circuits(fake_whois: _FakeWhoisModule):
    result = WhoisEnricher().enrich(Endpoint(value="   ", kind="domain"))
    assert result.ok is False
    assert result.error
    assert fake_whois.calls == []  # 没触网


# --- 缓存 -----------------------------------------------------------------


def test_result_written_to_cache(fake_whois: _FakeWhoisModule, _isolated_cache: Path):
    fake_whois.return_value = {"registrar": "Cached Reg", "country": "US"}
    WhoisEnricher().enrich(_ep("cache-me.cn"))

    assert _isolated_cache.is_file()
    cache = json.loads(_isolated_cache.read_text(encoding="utf-8"))
    assert "cache-me.cn" in cache
    assert cache["cache-me.cn"]["registrar"] == "Cached Reg"
    assert cache["cache-me.cn"]["country"] == "US"


def test_cache_hit_skips_network(fake_whois: _FakeWhoisModule):
    fake_whois.return_value = {"registrar": "First Reg"}
    enr = WhoisEnricher()

    first = enr.enrich(_ep("repeat.cn"))
    assert first.ok is True
    assert len(fake_whois.calls) == 1

    # 第二次：命中缓存，不再触网。
    fake_whois.return_value = {"registrar": "Should Not Be Used"}
    second = enr.enrich(_ep("repeat.cn"))
    assert second.ok is True
    assert second.data["registrar"] == "First Reg"
    assert len(fake_whois.calls) == 1  # 没有新增网络调用


def test_cache_hit_across_instances(fake_whois: _FakeWhoisModule):
    fake_whois.return_value = {"registrar": "Persisted Reg"}
    WhoisEnricher().enrich(_ep("persist.cn"))
    assert len(fake_whois.calls) == 1

    # 新实例也能读到磁盘缓存。
    result = WhoisEnricher().enrich(_ep("persist.cn"))
    assert result.ok is True
    assert result.data["registrar"] == "Persisted Reg"
    assert len(fake_whois.calls) == 1


def test_cache_dir_created_when_missing(
    fake_whois: _FakeWhoisModule, _isolated_cache: Path
):
    assert not _isolated_cache.parent.exists()
    fake_whois.return_value = {"registrar": "R"}
    WhoisEnricher().enrich(_ep("mkdir.cn"))
    assert _isolated_cache.parent.is_dir()
    assert _isolated_cache.is_file()


def test_domain_normalized_lowercase_in_cache(
    fake_whois: _FakeWhoisModule, _isolated_cache: Path
):
    fake_whois.return_value = {"registrar": "R"}
    WhoisEnricher().enrich(_ep("MixedCase.CN"))
    cache = json.loads(_isolated_cache.read_text(encoding="utf-8"))
    assert "mixedcase.cn" in cache
    # 触网时用归一化后的域名。
    assert fake_whois.calls[0][0] == "mixedcase.cn"


# --- 系统性失败：数据文件缺失（打包 exe 未收 whois 数据）优雅降级 --------------


def test_missing_data_file_disables_whois_for_run(
    fake_whois: _FakeWhoisModule, _isolated_cache: Path
) -> None:
    """whois 数据文件缺失(FileNotFoundError，常见于 frozen exe 未收 whois 数据)：
    首次失败记一次提示并本次禁用，后续域名短路、不再触网、不再刷 traceback。"""
    fake_whois.raises = FileNotFoundError("public_suffix_list.dat 缺失")
    enr = WhoisEnricher()

    r1 = enr.enrich(_ep("a.fraud-gw.cn"))
    assert r1.ok is False
    assert "数据" in (r1.error or "")
    assert len(fake_whois.calls) == 1  # 触网一次

    # 第二个域名：已禁用 → 短路，不再触网。
    r2 = enr.enrich(_ep("b.fraud-gw.cn"))
    assert r2.ok is False
    assert len(fake_whois.calls) == 1  # 仍只 1 次（被短路）


def test_short_err_strips_whois_boilerplate() -> None:
    """WHOIS 大段 VeriSign 法律声明 boilerplate → 只留首行关键信息（去噪）。"""
    from apkscan.enrichers.whois import _short_err

    boilerplate = (
        'No match for "MAPS.GOOGLEAPIS.COM".\n\n'
        ">>> Last update of whois database: 2026-06-09T16:04:21Z <<<\n\n"
        "NOTICE: The expiration date displayed ...\n\n"
        "TERMS OF USE: You are not authorized ...\n"
    )
    out = _short_err(Exception(boilerplate))
    assert out == 'No match for "MAPS.GOOGLEAPIS.COM".'
    assert "NOTICE" not in out
    assert "TERMS OF USE" not in out


def test_short_err_caps_length() -> None:
    from apkscan.enrichers.whois import _short_err

    assert len(_short_err(Exception("x" * 500))) <= 120
