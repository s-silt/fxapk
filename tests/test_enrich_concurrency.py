"""并发富化（pipeline._enrich_endpoints）契约测试。

子项目②：把 endpoints×enrichers 的串行双重循环改成按端点并发
（ThreadPoolExecutor，I/O 密集）。本测试用「假富化器」（可控延迟 / 调用计数 /
注入异常）锁死以下不变量，全程不发真实网络请求：

- 并发结果与串行**逐字段一致**（enrichment dict、provider 统计完全相同）。
- 所有端点都被富化（无漏）。
- provider 聚合统计（attempted/ok/failed/typical_error）准确。
- endpoints 列表顺序稳定（只改 enrichment，绝不重排端点）。
- 逐 enrich 的 try/except 不吞错：异常端点写入 ok=False、统计计入 failed。
- 并发确实带来加速（总耗时 << 串行累加）。
- 限速器（asn._respect_rate_limit）在并发下仍是全局闸：
  并发多线程调用，相邻两次真实查询间隔 >= ASN_MIN_INTERVAL（不突破 45/min）。
- asn / icp 缓存并发写不损坏（最终 JSON 可解析且含全部条目）。
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

import apkscan.enrichers.asn as asn_mod
from apkscan.core import pipeline
from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher
from apkscan.enrichers.asn import AsnEnricher


# --- 假富化器 --------------------------------------------------------------


class _DelayEnricher(BaseEnricher):
    """可配置延迟 / 调用计数的假富化器：成功返回携带端点 value 的 data。"""

    def __init__(self, name: str, applies_to: list[str], delay: float = 0.0) -> None:
        self.name = name
        self.applies_to = applies_to
        self.delay = delay
        self._lock = threading.Lock()
        self.seen: list[str] = []

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        if self.delay:
            time.sleep(self.delay)
        with self._lock:
            self.seen.append(ep.value)
        return EnrichmentResult(
            provider=self.name, ok=True, data={"who": ep.value, "kind": ep.kind}
        )


class _FlakyEnricher(BaseEnricher):
    """对特定端点抛异常的假富化器（验证 try/except 不吞错、统计计 failed）。"""

    name = "flaky"
    applies_to = ["domain"]

    def __init__(self, boom_values: set[str]) -> None:
        self.boom_values = boom_values

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        if ep.value in self.boom_values:
            raise RuntimeError(f"boom {ep.value}")
        return EnrichmentResult(provider=self.name, ok=True, data={"ok_for": ep.value})


def _domains(n: int) -> list[Endpoint]:
    return [Endpoint(value=f"d{i}.fraud.cn", kind="domain") for i in range(n)]


def _mixed(n: int) -> list[Endpoint]:
    eps: list[Endpoint] = []
    for i in range(n):
        eps.append(Endpoint(value=f"d{i}.fraud.cn", kind="domain"))
        eps.append(Endpoint(value=f"10.0.0.{i}", kind="ip"))
    return eps


# --- 模块级 worker 常量存在且默认 8 --------------------------------------


def test_max_workers_constant_default_eight() -> None:
    assert hasattr(pipeline, "ENRICH_MAX_WORKERS")
    assert pipeline.ENRICH_MAX_WORKERS == 8


# --- 所有端点被富化、enrichment 写入 ---------------------------------------


def test_all_endpoints_enriched() -> None:
    eps = _mixed(6)  # 6 domain + 6 ip
    dom = _DelayEnricher("icp", ["domain"])
    ip = _DelayEnricher("asn", ["ip"])

    pipeline._enrich_endpoints(eps, [dom, ip])

    for ep in eps:
        if ep.kind == "domain":
            assert ep.enrichment["icp"]["who"] == ep.value
            assert "asn" not in ep.enrichment  # applies_to 路由
        else:
            assert ep.enrichment["asn"]["who"] == ep.value
            assert "icp" not in ep.enrichment


# --- 端点顺序稳定（绝不重排）----------------------------------------------


def test_endpoint_order_preserved() -> None:
    eps = _domains(20)
    original = [e.value for e in eps]
    dom = _DelayEnricher("icp", ["domain"], delay=0.002)

    pipeline._enrich_endpoints(eps, [dom])

    assert [e.value for e in eps] == original  # 传入列表原地不动、顺序不变


# --- provider 统计准确 -----------------------------------------------------


def test_provider_stats_accurate_all_ok() -> None:
    eps = _domains(10)
    dom = _DelayEnricher("icp", ["domain"])

    stats = pipeline._enrich_endpoints(eps, [dom])
    by_provider = {s["provider"]: s for s in stats}

    assert by_provider["icp"]["attempted"] == 10
    assert by_provider["icp"]["ok"] == 10
    assert by_provider["icp"]["failed"] == 0
    assert by_provider["icp"]["typical_error"] is None


def test_provider_stats_count_failures() -> None:
    eps = _domains(5)
    boom = {"d1.fraud.cn", "d3.fraud.cn"}
    flaky = _FlakyEnricher(boom)

    stats = pipeline._enrich_endpoints(eps, [flaky])
    st = next(s for s in stats if s["provider"] == "flaky")

    assert st["attempted"] == 5
    assert st["ok"] == 3
    assert st["failed"] == 2
    assert st["typical_error"]  # 非空，记录了典型错误

    # 异常端点：try/except 不吞错，写入 ok=False（不丢 enrichment 键）。
    for ep in eps:
        if ep.value in boom:
            assert ep.enrichment["flaky"]["ok"] is False
        else:
            assert ep.enrichment["flaky"]["ok_for"] == ep.value


# --- 并发结果与串行逐字段一致 ----------------------------------------------


def test_concurrent_matches_serial_field_for_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """并发跑（默认 workers）与串行跑（workers=1）的 enrichment + 统计必须逐字段一致。"""
    boom = {"d2.fraud.cn"}

    def run_once(workers: int) -> tuple[list[Endpoint], list[dict]]:
        monkeypatch.setattr(pipeline, "ENRICH_MAX_WORKERS", workers)
        eps = _domains(8)
        icp = _DelayEnricher("icp", ["domain"], delay=0.001)
        flaky = _FlakyEnricher(boom)
        stats = pipeline._enrich_endpoints(eps, [icp, flaky])
        return eps, stats

    par_eps, par_stats = run_once(8)
    ser_eps, ser_stats = run_once(1)

    # enrichment 逐端点逐字段一致。
    assert [
        (e.value, e.enrichment) for e in par_eps
    ] == [(e.value, e.enrichment) for e in ser_eps]

    # provider 统计逐字段一致（按 provider 排序后比较，顺序无关）。
    def norm(ss: list[dict]) -> list:
        return sorted(tuple(sorted(s.items())) for s in ss)

    assert norm(par_stats) == norm(ser_stats)


# --- 并发确实加速 ----------------------------------------------------------


def test_concurrency_speeds_up(monkeypatch: pytest.MonkeyPatch) -> None:
    """8 个端点，每个 enrich 睡 0.1s。串行需 ~0.8s；并发(8 worker)应远小于串行累加。"""
    delay = 0.1
    n = 8

    def elapsed(workers: int) -> float:
        monkeypatch.setattr(pipeline, "ENRICH_MAX_WORKERS", workers)
        eps = _domains(n)
        dom = _DelayEnricher("icp", ["domain"], delay=delay)
        t0 = time.monotonic()
        pipeline._enrich_endpoints(eps, [dom])
        return time.monotonic() - t0

    par = elapsed(8)
    serial_lower_bound = delay * n  # 0.8s
    # 并发应明显快于串行下界；留宽松阈值避免 CI 抖动误报。
    assert par < serial_lower_bound * 0.6


# --- 限速器并发下仍是全局闸（不突破 45/min）-------------------------------


def test_asn_rate_limiter_global_under_concurrency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """多线程并发调用 asn._respect_rate_limit：相邻真实查询间隔 >= ASN_MIN_INTERVAL。

    用「记录每次放行时间戳」替代真实 sleep（按需快进 monotonic 时钟），既不真等
    又能验证闸门：任意相邻两次放行的逻辑时间差 >= ASN_MIN_INTERVAL。
    """
    enr = AsnEnricher()

    # 虚拟时钟：sleep 不真睡，只推进虚拟时间；monotonic 读虚拟时间。
    vclock = {"t": 0.0}
    vlock = threading.Lock()

    def fake_monotonic() -> float:
        with vlock:
            return vclock["t"]

    def fake_sleep(seconds: float) -> None:
        with vlock:
            vclock["t"] += max(0.0, seconds)

    monkeypatch.setattr(asn_mod.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(asn_mod.time, "sleep", fake_sleep)

    release_times: list[float] = []
    rlock = threading.Lock()

    def worker() -> None:
        enr._respect_rate_limit()
        with rlock:
            release_times.append(fake_monotonic())

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    release_times.sort()
    for a, b in zip(release_times, release_times[1:]):
        gap = b - a
        # 浮点容差。
        assert gap >= asn_mod.ASN_MIN_INTERVAL - 1e-9, f"间隔 {gap} < 限速 {asn_mod.ASN_MIN_INTERVAL}"


# --- 并发写 asn 缓存不损坏 -------------------------------------------------


def test_asn_cache_concurrent_writes_not_corrupted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """同一 AsnEnricher 实例并发写多个 IP 的缓存，最终 JSON 可解析且含全部条目。"""
    cache_dir = tmp_path / ".apkscan_cache"
    cache_file = cache_dir / "asn.json"
    monkeypatch.setattr(asn_mod, "CACHE_DIR", cache_dir)
    monkeypatch.setattr(asn_mod, "CACHE_FILE", cache_file)

    enr = AsnEnricher()
    n = 30

    def worker(i: int) -> None:
        enr._save_cache_entry(f"1.2.3.{i}", {"isp": f"isp{i}"})

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert cache_file.is_file()
    data = json.loads(cache_file.read_text(encoding="utf-8"))  # 可解析 = 未损坏
    assert len(data) == n
    for i in range(n):
        assert data[f"1.2.3.{i}"]["isp"] == f"isp{i}"


# --- 真实 enrich() 读写重叠路径并发不丢缓存（Windows race 回归）-------------


def _fake_asn_requests_factory() -> object:
    """构造每次 get() 都成功返回的假 requests（按 URL 里的 IP 回填 isp）。

    与 enrich() 真实路径配合：每个 IP 触网一次写一条缓存。线程安全（无共享可变态
    需要保护，calls 这里不校验）。
    """

    class _Resp:
        def __init__(self, payload: dict) -> None:
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return self._payload

    class _Req:
        def get(self, url: str, **kwargs: object) -> _Resp:
            # URL 形如 http://ip-api.com/json/1.2.3.4 —— 取末段当 IP/标识。
            ip = url.rstrip("/").rsplit("/", 1)[-1]
            return _Resp(
                {
                    "status": "success",
                    "isp": f"isp-{ip}",
                    "org": f"org-{ip}",
                    "as": f"AS{ip}",
                    "country": "X",
                    "query": ip,
                }
            )

    return _Req()


def test_asn_enrich_concurrent_no_silent_cache_loss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """走真实 enrich() 读写重叠路径并发跑 N 个 IP，缓存零丢失（Windows os.replace race 回归）。

    机理（修复前会红）：enrich() 开头 _load_cache() 在锁外 open 读 asn.json，与另一 worker
    _save_cache_entry 里持锁的 os.replace 撞同一文件 → Windows 抛 PermissionError(WinError 5)，
    被内层 try/except 吞成 warning，enrich() 照返 ok=True，缓存却静默丢失。
    本测试断言最终 JSON 含全部 N 条；修复（读写共用一把锁 + tmp 唯一后缀）后转绿。
    """
    cache_dir = tmp_path / ".apkscan_cache"
    cache_file = cache_dir / "asn.json"
    monkeypatch.setattr(asn_mod, "CACHE_DIR", cache_dir)
    monkeypatch.setattr(asn_mod, "CACHE_FILE", cache_file)
    # 限速 sleep 置空：本测试只验缓存不丢，不验限速。
    monkeypatch.setattr(asn_mod.time, "sleep", lambda _s: None)
    # 假 requests：每个 IP 成功返回。
    monkeypatch.setattr(asn_mod, "requests", _fake_asn_requests_factory())

    enr = AsnEnricher()
    n = 80  # 评审压测规模：每轮稳定丢 2~7 条
    ips = [f"1.2.3.{i}" for i in range(n)]

    results: list[EnrichmentResult] = []
    rlock = threading.Lock()

    def worker(ip: str) -> None:
        res = enr.enrich(Endpoint(value=ip, kind="ip"))
        with rlock:
            results.append(res)

    threads = [threading.Thread(target=worker, args=(ip,)) for ip in ips]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 所有 enrich 都成功（成功才写缓存）。
    assert all(r.ok for r in results), [r.error for r in results if not r.ok]

    assert cache_file.is_file()
    data = json.loads(cache_file.read_text(encoding="utf-8"))  # 可解析 = 未损坏
    missing = [ip for ip in ips if ip not in data]
    assert not missing, f"静默丢失 {len(missing)} 条缓存：{missing}"
    assert len(data) == n
    for ip in ips:
        assert data[ip]["isp"] == f"isp-{ip}"
