"""Spamhaus DROP 网段标注富化器测试。

夹具网段一律用文档保留段 / CGNAT 段自造——真实 DROP 清单里当然是真 IP，
但那是运行时下载的数据，不进代码库（leak-scan 会阻断真实公网 IPv4 字面量）。
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from apkscan.core.models import Endpoint
from apkscan.enrichers import spamhaus
from apkscan.enrichers.spamhaus import SpamhausDropEnricher


def _lines(*records: dict[str, Any], timestamp: int = 1700000000) -> str:
    """拼一份 JSON Lines 清单：N 条网段记录 + 末尾一行 metadata。"""
    body = [json.dumps(record) for record in records]
    body.append(
        json.dumps(
            {
                "type": "metadata",
                "timestamp": timestamp,
                "size": 0,
                "records": len(records),
                "copyright": "test",
                "terms": "test",
            }
        )
    )
    return "\n".join(body)


_R1 = {"cidr": "192.0.2.0/24", "sblid": "SBL000001", "rir": "arin"}
_R2 = {"cidr": "100.64.0.0/16", "sblid": "SBL000002", "rir": "apnic"}
_R3 = {"cidr": "100.64.5.0/24", "sblid": "SBL000003", "rir": "apnic"}


class _FakeResponse:
    def __init__(self, text: str, status: int = 200) -> None:
        self.text = text
        self.status_code = status

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")


class _FakeHttp:
    """替身 HTTP 层，记录调用次数以验证"整表只下载一次"。"""

    def __init__(self, text: str | None = None, exc: Exception | None = None) -> None:
        self.text = text
        self.exc = exc
        self.calls = 0
        self._lock = threading.Lock()
        self.delay = 0.0

    def capped_get(self, url: str, timeout: float | None = None) -> _FakeResponse:
        del url, timeout
        with self._lock:
            self.calls += 1
        if self.delay:
            time.sleep(self.delay)
        if self.exc is not None:
            raise self.exc
        assert self.text is not None
        return _FakeResponse(self.text)


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """每个用例独立的缓存目录 + 清空进程内共享表，避免用例间互相污染。"""
    cache_dir = tmp_path / ".apkscan_cache"
    monkeypatch.setattr(spamhaus, "CACHE_DIR", cache_dir)
    monkeypatch.setattr(spamhaus, "CACHE_FILE", cache_dir / "spamhaus_drop_v4.json")
    SpamhausDropEnricher._table = None
    SpamhausDropEnricher._refreshing = False
    SpamhausDropEnricher._last_failure_at = None
    SpamhausDropEnricher._last_failure_error = None
    SpamhausDropEnricher._last_failure_cache_file = None
    yield
    SpamhausDropEnricher._table = None
    SpamhausDropEnricher._last_failure_at = None


def _ip(value: str) -> Endpoint:
    return Endpoint(value=value, kind="ip", is_suspicious=True)


def _install(monkeypatch: pytest.MonkeyPatch, fake: _FakeHttp) -> _FakeHttp:
    monkeypatch.setattr(spamhaus, "_http", fake)
    return fake


# --------------------------------------------------------------------------- #
# 解析
# --------------------------------------------------------------------------- #
def test_metadata_line_is_not_treated_as_a_record(monkeypatch: pytest.MonkeyPatch) -> None:
    """末行 metadata 的键与网段记录完全不同，混进记录表会造出假条目。"""
    fake = _install(monkeypatch, _FakeHttp(_lines(_R1, _R2, timestamp=1700000123)))

    result = SpamhausDropEnricher().enrich(_ip("192.0.2.10"))

    assert result.ok is True
    assert result.data["network_listed"] is True
    assert result.data["matched_cidr"] == "192.0.2.0/24"
    assert result.data["list_timestamp"] == 1700000123
    assert fake.calls == 1


def test_declared_record_count_mismatch_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """metadata 声明的条数与实际不符 → 清单不可信，不得给出判定。"""
    body = _lines(_R1)
    tampered = body.replace('"records": 1', '"records": 5')
    _install(monkeypatch, _FakeHttp(tampered))

    result = SpamhausDropEnricher().enrich(_ip("192.0.2.10"))

    assert result.ok is False
    assert "network_listed" not in result.data


def test_missing_metadata_line_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _FakeHttp(json.dumps(_R1)))

    result = SpamhausDropEnricher().enrich(_ip("192.0.2.10"))

    assert result.ok is False
    assert "network_listed" not in result.data


# --------------------------------------------------------------------------- #
# ★不可判定不得返回正常值
# --------------------------------------------------------------------------- #
def test_download_failure_is_never_reported_as_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    """★清单没拿到 ≠ 这个 IP 干净。把不可判定说成"未命中"是最危险的错误。"""
    _install(monkeypatch, _FakeHttp(exc=RuntimeError("network down")))

    result = SpamhausDropEnricher().enrich(_ip("192.0.2.10"))

    assert result.ok is False
    assert result.data == {}
    assert "network_listed" not in result.data
    assert result.error is not None


def test_miss_is_only_reported_after_successful_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _FakeHttp(_lines(_R1)))

    result = SpamhausDropEnricher().enrich(_ip("203.0.113.10"))

    assert result.ok is True
    assert result.data["network_listed"] is False
    assert result.data["status"] == "checked"
    assert "matched_cidr" not in result.data


# --------------------------------------------------------------------------- #
# 匹配
# --------------------------------------------------------------------------- #
def test_longest_prefix_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    """清单里存在重叠网段时，应返回范围最具体的那条。"""
    _install(monkeypatch, _FakeHttp(_lines(_R2, _R3)))

    result = SpamhausDropEnricher().enrich(_ip("100.64.5.7"))

    assert result.data["matched_cidr"] == "100.64.5.0/24"
    assert result.data["sbl_id"] == "SBL000003"


def test_overlapping_outside_specific_range_falls_back_to_supernet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _FakeHttp(_lines(_R2, _R3)))

    result = SpamhausDropEnricher().enrich(_ip("100.64.9.1"))

    assert result.data["matched_cidr"] == "100.64.0.0/16"


def test_hit_carries_third_party_annotation_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    """★字段必须表明这是第三方清单的网段级标注，不是对运营者的判定。"""
    _install(monkeypatch, _FakeHttp(_lines(_R1)))

    result = SpamhausDropEnricher().enrich(_ip("192.0.2.10"))

    assert result.data["annotation_scope"] == "network"
    assert result.data["evidence_type"] == "third_party_network_list"
    assert result.data["list_name"] == "Spamhaus DROP"


# --------------------------------------------------------------------------- #
# 不适用输入
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("value", "reason"),
    [("2001:db8::1", "ipv6_not_supported"), ("not-an-ip", "invalid_ip")],
)
def test_not_applicable_inputs_skip_download(
    monkeypatch: pytest.MonkeyPatch, value: str, reason: str
) -> None:
    fake = _install(monkeypatch, _FakeHttp(_lines(_R1)))

    result = SpamhausDropEnricher().enrich(_ip(value))

    assert result.ok is True
    assert result.data["status"] == "not_applicable"
    assert result.data["reason"] == reason
    assert "network_listed" not in result.data
    assert fake.calls == 0


# --------------------------------------------------------------------------- #
# 缓存与并发
# --------------------------------------------------------------------------- #
def test_second_endpoint_reuses_shared_table(monkeypatch: pytest.MonkeyPatch) -> None:
    """结案时会对几十个 IP 分别调 enrich()，整表只能下载一次。"""
    fake = _install(monkeypatch, _FakeHttp(_lines(_R1, _R2)))
    enricher = SpamhausDropEnricher()

    enricher.enrich(_ip("192.0.2.10"))
    enricher.enrich(_ip("100.64.1.1"))
    SpamhausDropEnricher().enrich(_ip("203.0.113.1"))

    assert fake.calls == 1


def test_concurrent_endpoints_download_only_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """并发富化下，多个线程不得各自发起一次整表下载。"""
    fake = _install(monkeypatch, _FakeHttp(_lines(_R1, _R2)))
    fake.delay = 0.05  # 拉长竞争窗口
    results: list[bool] = []
    lock = threading.Lock()

    def worker(suffix: int) -> None:
        outcome = SpamhausDropEnricher().enrich(_ip(f"192.0.2.{suffix}"))
        with lock:
            results.append(bool(outcome.ok))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(1, 9)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert fake.calls == 1
    assert results and all(results)


def test_expired_cache_triggers_redownload(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install(monkeypatch, _FakeHttp(_lines(_R1)))
    SpamhausDropEnricher().enrich(_ip("192.0.2.10"))
    assert fake.calls == 1

    # 把内存表与磁盘缓存的时间戳都推到 TTL 之外
    SpamhausDropEnricher._table = None
    cache_file = spamhaus.CACHE_FILE
    cached = json.loads(cache_file.read_text(encoding="utf-8"))
    cached["cached_at"] = time.time() - spamhaus.CACHE_TTL_SECONDS - 60
    cache_file.write_text(json.dumps(cached), encoding="utf-8")

    SpamhausDropEnricher().enrich(_ip("192.0.2.10"))

    assert fake.calls == 2


def test_fresh_cache_avoids_network(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install(monkeypatch, _FakeHttp(_lines(_R1)))
    SpamhausDropEnricher().enrich(_ip("192.0.2.10"))
    SpamhausDropEnricher._table = None  # 只清内存，留磁盘缓存

    result = SpamhausDropEnricher().enrich(_ip("192.0.2.10"))

    assert fake.calls == 1
    assert result.data["network_listed"] is True


def test_corrupt_cache_falls_back_to_download(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install(monkeypatch, _FakeHttp(_lines(_R1)))
    spamhaus.CACHE_DIR.mkdir(parents=True, exist_ok=True)
    spamhaus.CACHE_FILE.write_text("{ not json", encoding="utf-8")

    result = SpamhausDropEnricher().enrich(_ip("192.0.2.10"))

    assert result.ok is True
    assert fake.calls == 1


def test_repeated_failure_does_not_storm_upstream(monkeypatch: pytest.MonkeyPatch) -> None:
    """下载失败后短期内不得反复重试，否则几十个端点会把上游打爆。"""
    fake = _install(monkeypatch, _FakeHttp(exc=RuntimeError("down")))

    first = SpamhausDropEnricher().enrich(_ip("192.0.2.10"))
    second = SpamhausDropEnricher().enrich(_ip("192.0.2.11"))

    assert first.ok is False
    assert second.ok is False
    assert fake.calls == 1


def test_enricher_declares_passive_no_credential() -> None:
    enricher = SpamhausDropEnricher()

    assert enricher.active is False          # 不直连目标业务服务
    assert enricher.required_env == ()       # 零 key
    assert enricher.applies_to == ["ip"]
