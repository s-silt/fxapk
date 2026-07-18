"""config-chain slice-1b-2：授权档下载 + pipeline 接线测试。

覆盖：主被动硬隔离门控（passive/offline 不下载、authorized-active 才下载）、下载→解码→端点回灌、
回灌端点的信任边界（source='remote-config'，非 observed-contact、非 runtime-seen）、下载失败优雅降级、
以及 fetch_config_object 的大小帽/状态码/非法 URL。全程不打真网（monkeypatch）。
"""

from __future__ import annotations

import base64
import gzip
import json

import pytest

from apkscan.config.fetch import FetchResult, fetch_config_object
from apkscan.core import pipeline
from apkscan.core.models import (
    ANALYSIS_MODE_AUTHORIZED_ACTIVE,
    ANALYSIS_MODE_PASSIVE,
    AnalysisConfig,
    Lead,
    LeadCategory,
)

_CONFIG = {"domains": ["api.evil-c2.com"], "ips": ["45.11.22.33"]}
_JSON = json.dumps(_CONFIG).encode()
_URL = "https://cfg.oss-cn-hangzhou.aliyuncs.com/app/domain.dat"


def _state(*, online: bool, mode: str, urls: list[str], out_dir: str = "out"):
    cfg = AnalysisConfig(online=online, mode=mode, out_dir=out_dir)
    st = pipeline._PipelineState(ctx=None, config=cfg, platform="android", capabilities=set())  # type: ignore[arg-type]
    st.leads = [Lead(category=LeadCategory.REMOTE_CONFIG, value=u) for u in urls]
    return st


# --------------------------------------------------------------------------- #
# 门控：passive / offline 绝不下载
# --------------------------------------------------------------------------- #
def test_passive_mode_does_not_fetch(monkeypatch) -> None:
    def _boom(*_a, **_k):
        raise AssertionError("passive 模式绝不应下载")

    monkeypatch.setattr(pipeline, "fetch_config_object", _boom)
    st = _state(online=True, mode=ANALYSIS_MODE_PASSIVE, urls=[_URL])
    pipeline._stage_remote_config_fetch(st)
    assert st.meta["remote_config_fetch_skipped_passive_mode"] == 1
    assert st.endpoints == []
    assert "remote_config_artifacts" not in st.meta


def test_offline_does_not_fetch(monkeypatch) -> None:
    monkeypatch.setattr(pipeline, "fetch_config_object", lambda *a, **k: pytest.fail("offline 不应下载"))
    st = _state(online=False, mode=ANALYSIS_MODE_AUTHORIZED_ACTIVE, urls=[_URL])
    pipeline._stage_remote_config_fetch(st)
    assert st.meta["remote_config_fetch_skipped"] == "offline"
    assert st.endpoints == []


def test_no_candidates_is_noop() -> None:
    st = _state(online=True, mode=ANALYSIS_MODE_AUTHORIZED_ACTIVE, urls=[])
    pipeline._stage_remote_config_fetch(st)
    assert not any(k.startswith("remote_config_") for k in st.meta)


# --------------------------------------------------------------------------- #
# 授权档：下载 → 解码 → 端点回灌
# --------------------------------------------------------------------------- #
def test_authorized_active_fetches_decodes_and_feeds_back(monkeypatch, tmp_path) -> None:
    blob = gzip.compress(_JSON)
    monkeypatch.setattr(
        pipeline, "fetch_config_object",
        lambda url, **k: FetchResult(url, True, blob, 200, None),
    )
    st = _state(online=True, mode=ANALYSIS_MODE_AUTHORIZED_ACTIVE, urls=[_URL], out_dir=str(tmp_path))
    pipeline._stage_remote_config_fetch(st)

    values = {ep.value for ep in st.endpoints}
    assert "api.evil-c2.com" in values and "45.11.22.33" in values
    art = st.meta["remote_config_artifacts"]
    assert len(art) == 1 and art[0]["decoded"] is True
    assert art[0]["decode_chain"] == ["gzip", "json"]
    assert art[0]["domains"] == ["api.evil-c2.com"] and art[0]["ips"] == ["45.11.22.33"]
    assert st.meta["remote_config_fetched"] == 1

    # ★原始 blob 落盘：stored_path 相对、文件存在、字节原样保真
    import hashlib
    sha = hashlib.sha256(blob).hexdigest()
    assert art[0]["stored_path"] == f"remote_config/{sha}.bin"
    archived = tmp_path / "remote_config" / f"{sha}.bin"
    assert archived.read_bytes() == blob  # 原始字节完整
    assert st.meta["remote_config_archived"] == 1


def test_fed_back_endpoints_are_not_observed_contact(monkeypatch, tmp_path) -> None:
    """信任边界：回灌端点 source='remote-config'——既非 observed-contact（确认 C2），也不 startswith('runtime')。"""
    monkeypatch.setattr(
        pipeline, "fetch_config_object",
        lambda url, **k: FetchResult(url, True, base64.b64encode(_JSON), 200, None),
    )
    st = _state(online=True, mode=ANALYSIS_MODE_AUTHORIZED_ACTIVE, urls=[_URL], out_dir=str(tmp_path))
    pipeline._stage_remote_config_fetch(st)

    ep = next(ep for ep in st.endpoints if ep.value == "api.evil-c2.com")
    assert ep.evidences[0].source == "remote-config"
    # 构造一条带该证据的 Lead，确认两个 runtime 徽标属性都为假（不误升"确认 C2"/"运行时出现"）
    lead = Lead(category=LeadCategory.DOMAIN, value=ep.value, source_refs=list(ep.evidences))
    assert lead.is_runtime_contact is False
    assert lead.is_runtime_seen is False


def test_fetch_failure_degrades_without_crash(monkeypatch) -> None:
    monkeypatch.setattr(
        pipeline, "fetch_config_object",
        lambda url, **k: FetchResult(url, False, None, 404, "HTTP 404"),
    )
    st = _state(online=True, mode=ANALYSIS_MODE_AUTHORIZED_ACTIVE, urls=[_URL])
    pipeline._stage_remote_config_fetch(st)
    assert st.endpoints == []
    art = st.meta["remote_config_artifacts"]
    assert art[0]["decoded"] is False and art[0]["error"] == "HTTP 404"
    assert st.meta["remote_config_fetched"] == 0


# --------------------------------------------------------------------------- #
# fetch_config_object 单元（fake requests，不打真网）
# --------------------------------------------------------------------------- #
class _FakeResp:
    def __init__(self, status=200, headers=None, chunks=(b"",)):
        self.status_code = status
        self.headers = headers or {}
        self._chunks = chunks

    def iter_content(self, _n):
        return iter(self._chunks)

    def close(self):
        pass


def test_fetch_rejects_non_http_url() -> None:
    r = fetch_config_object("ftp://x/y")
    assert r.ok is False and r.raw is None


_PUB = "https://8.8.8.8/y"  # 公网 IP 字面量：过 SSRF 检查（免真 DNS），requests 仍被 mock、不打真网


def test_fetch_ok_and_status_and_size_cap(monkeypatch) -> None:
    pytest.importorskip("requests")
    import requests

    monkeypatch.setattr(requests, "get", lambda *a, **k: _FakeResp(200, {}, (b"abc", b"def")))
    r = fetch_config_object(_PUB)
    assert r.ok is True and r.raw == b"abcdef"

    monkeypatch.setattr(requests, "get", lambda *a, **k: _FakeResp(404))
    assert fetch_config_object(_PUB).ok is False

    # Content-Length 预检超帽
    monkeypatch.setattr(requests, "get", lambda *a, **k: _FakeResp(200, {"Content-Length": "999999"}))
    assert fetch_config_object(_PUB, max_bytes=1024).ok is False

    # 流式累计超帽
    monkeypatch.setattr(requests, "get", lambda *a, **k: _FakeResp(200, {}, (b"x" * 800, b"y" * 800)))
    assert fetch_config_object(_PUB, max_bytes=1024).ok is False


def test_target_is_safe_blocks_internal_and_metadata() -> None:
    from apkscan.config.fetch import _target_is_safe

    for bad in (
        "http://169.254.169.254/latest/meta-data/iam/",  # 云元数据（链路本地）
        "http://127.0.0.1/x", "http://10.0.0.1/x", "http://192.168.1.1/x", "http://172.16.0.1/x",
    ):
        assert _target_is_safe(bad)[0] is False, bad
    assert _target_is_safe("https://8.8.8.8/x")[0] is True  # 公网放行


def test_fetch_blocks_ssrf_before_request(monkeypatch) -> None:
    pytest.importorskip("requests")
    import requests

    monkeypatch.setattr(requests, "get", lambda *a, **k: pytest.fail("SSRF 目标绝不应发起请求"))
    r = fetch_config_object("http://169.254.169.254/appconfig/x.json")
    assert r.ok is False and "SSRF" in (r.error or "")


def test_fetch_disables_redirects(monkeypatch) -> None:
    pytest.importorskip("requests")
    import requests

    captured: dict = {}

    def _get(url, **kwargs):
        captured.update(kwargs)
        return _FakeResp(200, {}, (b"ok",))

    monkeypatch.setattr(requests, "get", _get)
    fetch_config_object(_PUB)
    assert captured.get("allow_redirects") is False  # 禁跟随重定向（防 302→内网 SSRF）


def test_fetch_wall_clock_deadline_aborts(monkeypatch) -> None:
    pytest.importorskip("requests")
    import requests

    from apkscan.config import fetch as fetchmod

    times = iter([0.0, 1e9, 1e9, 1e9])  # deadline 计算=0 → 30；循环内 monotonic=1e9 远超 → 立即中止
    monkeypatch.setattr(fetchmod.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(requests, "get", lambda *a, **k: _FakeResp(200, {}, (b"x" * 10, b"y" * 10)))
    r = fetch_config_object(_PUB)
    assert r.ok is False and "总时限" in (r.error or "")
