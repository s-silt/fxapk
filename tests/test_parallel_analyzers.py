"""分析器进程池并行：SnapshotContext 物化/pickle/协议 + 并行门控 + 确定性 + 真 spawn 等价。

分两层覆盖：
- 轻量（始终跑）：可 pickle 快照往返、门控逻辑、worker 函数进程内驱动、输出确定性。
- 重量（@pytest.mark.slow，需本地有真实 *.apk 样本，否则 skip）：真 multiprocessing.Pool spawn
  端到端，断言串行==并行**逐字节一致**——把原先"不在仓库的手动等价脚本"固化进测试套件。
"""

from __future__ import annotations

import dataclasses
import logging
import multiprocessing
import os
import pickle
from pathlib import Path

import pytest

from apkscan.core import pipeline
from apkscan.core.snapshot import SnapshotContext, build_snapshot
from tests.conftest import FakeContext


def _fake(**kw) -> FakeContext:  # type: ignore[no-untyped-def]
    return FakeContext(**kw)


def _find_real_apk() -> str | None:
    """定位真实 APK 样本（真 spawn 等价校验用）：优先 FXAPK_TEST_APK 环境变量，否则取仓库内首个
    *.apk（本地样本，已 gitignore、不随仓库分发）。都没有则返回 None → 测试 skip（CI 无样本不挂）。
    """
    env = os.environ.get("FXAPK_TEST_APK")
    if env and Path(env).is_file():
        return env
    repo_root = Path(__file__).resolve().parent.parent
    for apk in sorted(repo_root.glob("**/*.apk")):
        return str(apk)
    return None


_REAL_APK = _find_real_apk()


def test_build_snapshot_materializes_protocol() -> None:
    ctx = _fake(
        package_name="com.evil",
        platform="android",
        apk_path="/x/evil.apk",
        permissions=["android.permission.READ_SMS", "android.permission.CAMERA"],
        dex_strings=["Lcom/evil/Main;", "https://hxhcapi.vip/api"],
        files={"assets/config.json": b'{"k":1}', "res/icon.png": b"\x89PNG"},
    )
    snap = build_snapshot(ctx)
    assert snap.package_name == "com.evil" and snap.platform == "android"
    assert snap.apk_path == "/x/evil.apk"
    assert list(snap.dex_strings()) == ["Lcom/evil/Main;", "https://hxhcapi.vip/api"]
    assert snap.permissions() == ["android.permission.READ_SMS", "android.permission.CAMERA"]
    # 文本资源(.json)预读进快照；二进制(.png)不预读。
    assert snap.read_file("assets/config.json") == b'{"k":1}'
    assert "res/icon.png" not in snap._files


def test_snapshot_pickle_roundtrip_excludes_worker_apk() -> None:
    # pickle 安全：往返我们**自建**的 SnapshotContext（验证可过进程池 IPC），非反序列化外部不可信数据。
    # 生产中 ProcessPoolExecutor 同样只 pickle 本进程自建的快照（来自被分析 APK），不接收外部 pickle。
    snap = SnapshotContext(
        package_name="com.x", manifest_xml="<m/>", platform="android",
        config=None, apk_path="", permissions=["p"], components=None,
        dex_strings=("a", "b"), file_list=["f.json"], native_libs=[],
        certificates=[], files={"f.json": b"x"},
    )
    snap._worker_apk = object()  # 模拟 worker 内已建句柄
    restored = pickle.loads(pickle.dumps(snap))
    assert list(restored.dex_strings()) == ["a", "b"]
    assert restored.read_file("f.json") == b"x"
    assert restored._worker_apk is None  # 句柄不随 pickle 传，unpickle 后重置


def test_snapshot_read_file_missing_no_apk_returns_none() -> None:
    # 非预读文件 + 无 apk_path → 惰性兜底拿不到 APK → None（不抛）。
    snap = SnapshotContext(
        package_name="", manifest_xml="", platform="android", config=None,
        apk_path="", permissions=[], components=None, dex_strings=(), file_list=[],
        native_libs=[], certificates=[], files={},
    )
    assert snap.read_file("nope/missing.bin") is None


def test_should_parallelize_gating(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pipeline.os, "cpu_count", lambda: 8)
    monkeypatch.delenv("FXAPK_NO_PARALLEL", raising=False)
    eligible = [("a", object()), ("b", object()), ("c", object())]

    ok = _fake(platform="android", apk_path="/x.apk")
    assert pipeline._should_parallelize(ok, eligible) is True

    # 逃生开关。
    monkeypatch.setenv("FXAPK_NO_PARALLEL", "1")
    assert pipeline._should_parallelize(ok, eligible) is False
    monkeypatch.delenv("FXAPK_NO_PARALLEL", raising=False)

    # IPA(非 android) → 串行。
    assert pipeline._should_parallelize(_fake(platform="ios", apk_path="/x.ipa"), eligible) is False
    # 无 apk_path（worker 无法惰性兜底 read_file）→ 串行。
    assert pipeline._should_parallelize(_fake(platform="android", apk_path=""), eligible) is False
    # 分析器太少 → 串行。
    assert pipeline._should_parallelize(ok, eligible[:2]) is False
    # 单核 → 串行。
    monkeypatch.setattr(pipeline.os, "cpu_count", lambda: 1)
    assert pipeline._should_parallelize(ok, eligible) is False


def test_analyze_eligible_falls_back_to_serial_without_apk(monkeypatch: pytest.MonkeyPatch) -> None:
    # 无 apk_path → 不满足并行门控 → 走串行，结果正常。
    monkeypatch.setattr(pipeline.os, "cpu_count", lambda: 8)

    class _A:
        name = "spy"

        def analyze(self, ctx):  # type: ignore[no-untyped-def]
            from apkscan.core.models import AnalyzerResult
            r = AnalyzerResult(analyzer="spy")
            r.meta = {"saw": ctx.package_name}
            return r

    ctx = _fake(package_name="com.evil", platform="android", apk_path="")
    out = pipeline._analyze_eligible(ctx, [("spy", _A()), ("spy2", _A()), ("spy3", _A())])
    assert len(out) == 3
    assert all(err is None and res is not None for _n, res, err in out)
    assert out[0][1].meta["saw"] == "com.evil"


def test_permissions_meta_deterministically_sorted() -> None:
    # ★ 并行确定性根因修复：meta["permissions"] 排序，跨进程/跨运行稳定。
    from apkscan.analyzers.permissions import PermissionsAnalyzer

    ctx = _fake(permissions=[
        "android.permission.WRITE_SMS", "android.permission.CAMERA", "android.permission.READ_SMS",
    ])
    result = PermissionsAnalyzer().analyze(ctx)
    perms = result.meta["permissions"]
    assert perms == sorted(perms)


def test_permissions_short_name_collision_keeps_deterministic_full_name() -> None:
    # ★ 同短名碰撞确定性：两个不同全名归一到同一短名（MDM），无论输入顺序如何，
    #   都稳定保留字典序最小的全名 —— 去重在排序之后才能保证"留哪个全名"可复现。
    from apkscan.analyzers.permissions import PermissionsAnalyzer

    a = PermissionsAnalyzer().analyze(
        _fake(permissions=["com.b.permission.MDM", "com.a.permission.MDM"])
    )
    b = PermissionsAnalyzer().analyze(
        _fake(permissions=["com.a.permission.MDM", "com.b.permission.MDM"])
    )
    assert a.meta["permissions"] == b.meta["permissions"] == ["com.a.permission.MDM"]


def test_worker_init_and_analyze_resolve_run_and_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ★ 真并行 worker 路径覆盖（进程内直接驱动，不真 spawn）：_worker_init 缓存快照 + 发现分析器、
    #   _worker_analyze 按 name 解析并运行 + 未知 name 错误路径 + 分析器异常被捕获为错误（不抛、不丢）。
    from apkscan.core.models import AnalyzerResult

    class _Spy:
        name = "spy"

        def analyze(self, ctx):  # type: ignore[no-untyped-def]
            r = AnalyzerResult(analyzer="spy")
            r.meta = {"pkg": ctx.package_name}
            return r

    snap = build_snapshot(_fake(package_name="com.evil", platform="android", apk_path=""))

    monkeypatch.setattr(pipeline, "discover_analyzers", lambda: [_Spy()])
    pipeline._worker_init(snap)

    name, res, err = pipeline._worker_analyze("spy")
    assert name == "spy" and err is None and res is not None
    assert res.meta["pkg"] == "com.evil"  # 快照经 _worker_init 缓存后被分析器读到

    # 未知分析器 → 明确错误，不抛。
    assert pipeline._worker_analyze("ghost")[2] == "worker 未发现该分析器"

    # 分析器内部异常 → 捕获成错误字符串回传（堆栈由 logger.exception 落 worker stderr）。
    class _Boom:
        name = "boom"

        def analyze(self, ctx):  # type: ignore[no-untyped-def]
            raise ValueError("kaboom")

    monkeypatch.setattr(pipeline, "discover_analyzers", lambda: [_Boom()])
    pipeline._worker_init(snap)
    _, bres, berr = pipeline._worker_analyze("boom")
    assert bres is None and berr is not None
    assert "ValueError" in berr and "kaboom" in berr


def _eligible_for(ctx: object) -> list[tuple]:
    """复刻 pipeline.run 的 requires 门控，返回 [(name, analyzer)]（android 上几乎全部分析器）。"""
    from apkscan.core.registry import detect_capabilities, discover_analyzers

    caps = detect_capabilities(online=False)
    caps.add("apk" if getattr(ctx, "platform", "android") == "android" else "ipa")
    out: list[tuple] = []
    for a in discover_analyzers():
        name = getattr(a, "name", "") or a.__class__.__name__
        missing = [c for c in (getattr(a, "requires", []) or []) if c not in caps]
        if not missing:
            out.append((name, a))
    return out


def _canon(triples: list[tuple]) -> list[tuple]:
    """把 [(name, AnalyzerResult|None, error|None)] 规范化成可逐字段比较的结构（dataclass→dict）。"""
    return [
        (name, err, None if res is None else dataclasses.asdict(res))
        for name, res, err in triples
    ]


@pytest.mark.slow
@pytest.mark.skipif(
    _REAL_APK is None,
    reason="无真实 APK 样本（设 FXAPK_TEST_APK 或在仓库放置 *.apk 后启用真 spawn 等价校验）",
)
def test_serial_parallel_byte_identical_real_apk() -> None:
    """★ 固化『串行==并行 逐字节一致』这一 PR 核心不变量（此前仅由不在仓库的手动脚本背书）。

    真 spawn 进程池 vs 串行，同一真实 APK、同一 eligible 集，断言每个分析器结果逐字段一致。
    一次性覆盖：快照可 pickle 并经真实进程池 IPC 重建、worker 内 discover_analyzers 按名解析回
    同一分析器、pool.map 保序聚合、以及跨进程不同 PYTHONHASHSEED 下分析器输出仍确定（含二进制读
    经 worker 惰性重开真实 APK 与串行取到一致字节）。
    """
    from apkscan.core.apk import ApkParseError, load_apk
    from apkscan.core.models import AnalysisConfig

    assert _REAL_APK is not None  # skipif 已保证，仅为类型收窄
    try:
        ctx = load_apk(_REAL_APK, AnalysisConfig(online=False))
    except ApkParseError as exc:
        pytest.skip(f"本地 APK 样本无法解析（结构非法），跳过真 spawn 等价校验：{exc}")
    eligible = _eligible_for(ctx)
    assert len(eligible) >= 3  # 真实 APK 上常态满足并行门控

    serial = pipeline._analyze_serial(ctx, eligible)
    # ★ 直接调 _run_pool（满核 worker）绕过 _decide_workers 的内存封顶：否则低 RAM 机上
    #   _analyze_parallel 会回退串行 → serial==serial 假绿、悄悄不再真 spawn，掏空本不变量。
    names = [name for name, _ in eligible]
    cpu_cap = max(1, min(len(names), os.cpu_count() or 2))
    parallel = pipeline._run_pool(build_snapshot(ctx), names, cpu_cap)

    assert {n for n, _, _ in parallel} == {n for n, _ in eligible}  # pool.map 无遗漏
    assert _canon(serial) == _canon(parallel)  # 逐字段（含 findings/endpoints/leads/meta）一致


# ----------------------------------------------------------------------------
# worker 数内存封顶（_decide_workers / env 解析 / cgroup）——纯逻辑、零真 spawn。
# ----------------------------------------------------------------------------

_MB = 1024 * 1024


class _Spy:
    """模块级假分析器（_analyze_parallel 回退测需可被 _analyze_serial 跑）。"""

    def __init__(self, name: str = "spy") -> None:
        self.name = name

    def analyze(self, ctx):  # type: ignore[no-untyped-def]
        from apkscan.core.models import AnalyzerResult

        r = AnalyzerResult(analyzer=self.name)
        r.meta = {"pkg": getattr(ctx, "package_name", "")}
        return r


def _set_mem(monkeypatch: pytest.MonkeyPatch, *, cpu: int, avail: int) -> None:
    """固定 cpu 数与可用内存（绕过 psutil/cgroup），清掉相关 env，隔离 _decide_workers 逻辑。"""
    monkeypatch.setattr(pipeline.os, "cpu_count", lambda: cpu)
    monkeypatch.setattr(pipeline, "_available_bytes", lambda: avail)
    for e in ("FXAPK_MAX_WORKERS", "FXAPK_WORKER_BASE_MB", "FXAPK_MEM_SAFETY"):
        monkeypatch.delenv(e, raising=False)


@pytest.mark.parametrize(
    "cpu, avail_mb, names, snap_mb, expect",
    [
        (4, 8192, 10, 12, 4),   # 高 RAM → cpu_cap
        (4, 500, 10, 12, 1),    # 低 RAM → 1（调用方回退串行）
        (16, 3072, 25, 12, 8),  # mem_cap < cpu_cap → 压低
        (16, 64, 25, 12, 1),    # 极低 RAM → 1
    ],
)
def test_decide_workers_memory_cap(
    monkeypatch: pytest.MonkeyPatch, cpu: int, avail_mb: int, names: int, snap_mb: int, expect: int
) -> None:
    _set_mem(monkeypatch, cpu=cpu, avail=avail_mb * _MB)
    assert pipeline._decide_workers(snap_mb * _MB, names) == expect


@pytest.mark.parametrize(
    "cpu, env, expect",
    [
        (8, "3", 3),      # env < cpu_cap → env 值
        (4, "9999", 4),   # env > cpu_cap → 被 cpu_cap 夹
        (8, "1", 1),      # env=1 → 1（调用方回退串行）
        (8, " 4 ", 4),    # 带空格 strip 后接受
        (8, "0", 8),      # 非正 → 忽略，走内存路径（充足内存→cpu_cap）
        (8, "abc", 8),    # 非整数 → 忽略，走内存路径
        (8, "3.5", 8),    # 小数 → 忽略
    ],
)
def test_decide_workers_env_max_workers(
    monkeypatch: pytest.MonkeyPatch, cpu: int, env: str, expect: int
) -> None:
    _set_mem(monkeypatch, cpu=cpu, avail=64 * 1024 * _MB)  # 充足内存：非 env 路径给 cpu_cap
    monkeypatch.setenv("FXAPK_MAX_WORKERS", env)
    assert pipeline._decide_workers(12 * _MB, 20) == expect


def test_decide_workers_snapshot_tier_halves(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_mem(monkeypatch, cpu=8, avail=16 * 1024 * _MB)
    # 快照 50MB > 40MB 阈值：内存路径先算 8，超阈再砍半 → 4。
    assert pipeline._decide_workers(50 * _MB, 25) == 4


def test_decide_workers_psutil_failure_falls_back_and_never_raises(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(pipeline.os, "cpu_count", lambda: 16)
    for e in ("FXAPK_MAX_WORKERS", "FXAPK_WORKER_BASE_MB", "FXAPK_MEM_SAFETY"):
        monkeypatch.delenv(e, raising=False)

    def _boom() -> int:
        raise RuntimeError("psutil 炸了")

    monkeypatch.setattr(pipeline, "_available_bytes", _boom)
    with caplog.at_level(logging.WARNING, logger=pipeline.logger.name):
        # 不向上抛 + 返回 min(16, 4)=4（否则会被外层误记为"并行执行失败"）。
        assert pipeline._decide_workers(12 * _MB, 25) == 4
    assert any("固定兜底" in r.message for r in caplog.records)


def test_decide_workers_cpu_count_none(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_mem(monkeypatch, cpu=None, avail=64 * 1024 * _MB)  # type: ignore[arg-type]
    # os.cpu_count()=None → `or 2` → cpu_cap=min(10,2)=2。
    assert pipeline._decide_workers(12 * _MB, 10) == 2


def test_decide_workers_memory_reduced_logs_info(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _set_mem(monkeypatch, cpu=16, avail=3072 * _MB)
    with caplog.at_level(logging.INFO, logger=pipeline.logger.name):
        assert pipeline._decide_workers(12 * _MB, 25) == 8
    assert any("内存受限" in r.message for r in caplog.records)


def test_analyze_parallel_low_mem_falls_back_serial_without_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    eligible = [("a", _Spy("a")), ("b", _Spy("b")), ("c", _Spy("c"))]
    ctx = _fake(package_name="com.evil", platform="android", apk_path="/x.apk")
    monkeypatch.delenv("FXAPK_MAX_WORKERS", raising=False)
    monkeypatch.setattr("apkscan.core.snapshot.build_snapshot", lambda c: object())
    monkeypatch.setattr(pipeline, "_decide_workers", lambda *a, **k: 1)

    class _NoPool:
        def __init__(self, *a, **k) -> None:  # type: ignore[no-untyped-def]
            raise AssertionError("workers<=1 不应建进程池")

    monkeypatch.setattr(pipeline.multiprocessing, "Pool", _NoPool)
    out = pipeline._analyze_parallel(ctx, eligible)
    assert out == pipeline._analyze_serial(ctx, eligible)  # 回退串行结果


def test_env_max_workers_one_short_circuits_before_build_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FXAPK_MAX_WORKERS", "1")
    monkeypatch.setattr(pipeline.os, "cpu_count", lambda: 8)
    built = {"flag": False}

    def _spy_build(c):  # type: ignore[no-untyped-def]
        built["flag"] = True
        return object()

    monkeypatch.setattr("apkscan.core.snapshot.build_snapshot", _spy_build)

    class _NoPool:
        def __init__(self, *a, **k) -> None:  # type: ignore[no-untyped-def]
            raise AssertionError("强制串行不应建进程池")

    monkeypatch.setattr(pipeline.multiprocessing, "Pool", _NoPool)
    eligible = [("a", _Spy("a")), ("b", _Spy("b")), ("c", _Spy("c"))]
    out = pipeline._analyze_parallel(_fake(platform="android", apk_path="/x.apk"), eligible)
    assert built["flag"] is False  # 短路在 build_snapshot 之前，省 689ms 白跑
    assert len(out) == 3


def test_cgroup_v2_limit_caps(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pipeline.sys, "platform", "linux")
    v2 = ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.current")
    monkeypatch.setattr(pipeline.os.path, "exists", lambda p: p in v2)
    files = {
        "/sys/fs/cgroup/memory.max": "536870912",      # 512MB
        "/sys/fs/cgroup/memory.current": "100000000",  # ~95MB
    }
    monkeypatch.setattr(pipeline, "_read_cgroup_file", lambda p: files[p])
    assert pipeline._cgroup_available_bytes() == 536870912 - 100000000


def test_cgroup_v1_limit_caps(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    monkeypatch.setattr(pipeline.sys, "platform", "linux")
    v1l = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
    v1u = "/sys/fs/cgroup/memory/memory.usage_in_bytes"
    monkeypatch.setattr(pipeline.os.path, "exists", lambda p: p in (v1l, v1u))
    monkeypatch.setattr(
        pipeline.psutil, "virtual_memory", lambda: SimpleNamespace(available=10**12, total=8 * 1024 * _MB)
    )
    files = {v1l: str(512 * _MB), v1u: str(100 * _MB)}
    monkeypatch.setattr(pipeline, "_read_cgroup_file", lambda p: files[p])
    assert pipeline._cgroup_available_bytes() == 512 * _MB - 100 * _MB


def test_cgroup_v1_unlimited_sentinel_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    monkeypatch.setattr(pipeline.sys, "platform", "linux")
    v1l = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
    monkeypatch.setattr(pipeline.os.path, "exists", lambda p: p == v1l)
    monkeypatch.setattr(
        pipeline.psutil, "virtual_memory", lambda: SimpleNamespace(available=10**12, total=8 * 1024 * _MB)
    )
    monkeypatch.setattr(pipeline, "_read_cgroup_file", lambda p: str(0x7FFFFFFFFFFFF000))
    assert pipeline._cgroup_available_bytes() is None  # 经典哨兵 → 视为未设限


def test_cgroup_v1_usage_unreadable_falls_back_to_limit_not_host(monkeypatch: pytest.MonkeyPatch) -> None:
    # ★ 安全回退：limit 已知但 usage 文件不存在/读失败 → 返回 limit（受容器上限约束），绝不退回宿主机内存。
    from types import SimpleNamespace

    monkeypatch.setattr(pipeline.sys, "platform", "linux")
    v1l = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
    monkeypatch.setattr(pipeline.os.path, "exists", lambda p: p == v1l)  # usage 文件缺失
    monkeypatch.setattr(
        pipeline.psutil, "virtual_memory", lambda: SimpleNamespace(available=10**12, total=8 * 1024 * _MB)
    )
    monkeypatch.setattr(pipeline, "_read_cgroup_file", lambda p: str(512 * _MB))
    assert pipeline._cgroup_available_bytes() == 512 * _MB  # 退回 limit，非宿主机 10**12


def test_decide_workers_per_worker_scales_with_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    # 钉死 per_worker 的线性项 int(_SNAPSHOT_FACTOR * snapshot_size)：固定 cpu/avail，只增大快照
    # （均 <40MB 避开超阈砍半分支）→ per_worker 增大 → worker 数下降。
    _set_mem(monkeypatch, cpu=16, avail=3072 * _MB)
    small = pipeline._decide_workers(1 * _MB, 25)
    large = pipeline._decide_workers(35 * _MB, 25)
    assert large < small


def test_build_snapshot_total_budget_stops_preread(monkeypatch: pytest.MonkeyPatch) -> None:
    # 钉死 _MAX_SNAPSHOT_TOTAL_BYTES 累计预读预算的 break：超预算后停止预读，部分文件被跳过。
    from apkscan.core import snapshot as snap_mod

    monkeypatch.setattr(snap_mod, "_MAX_SNAPSHOT_TOTAL_BYTES", 1000)  # 1000B 预算
    files = {f"assets/f{i}.json": b"x" * 400 for i in range(5)}  # 5×400B=2000B > 预算
    snap = build_snapshot(_fake(platform="android", apk_path="", files=files))
    total = sum(len(v) for v in snap._files.values())
    assert total <= 1000              # 预读累计不超预算
    assert 0 < len(snap._files) < 5   # 部分预读、部分被 break 跳过（落 worker 惰性兜底）


def test_cgroup_v2_unlimited_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pipeline.sys, "platform", "linux")
    monkeypatch.setattr(pipeline.os.path, "exists", lambda p: p == "/sys/fs/cgroup/memory.max")
    monkeypatch.setattr(pipeline, "_read_cgroup_file", lambda p: "max")
    assert pipeline._cgroup_available_bytes() is None


def test_cgroup_non_linux_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pipeline.sys, "platform", "win32")
    assert pipeline._cgroup_available_bytes() is None


def test_available_bytes_takes_min_with_cgroup(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    monkeypatch.setattr(
        pipeline.psutil, "virtual_memory", lambda: SimpleNamespace(available=10**12, total=10**12)
    )
    monkeypatch.setattr(pipeline, "_cgroup_available_bytes", lambda: 500 * _MB)
    assert pipeline._available_bytes() == 500 * _MB  # cgroup 更小 → 取 cgroup
    monkeypatch.setattr(pipeline, "_cgroup_available_bytes", lambda: None)
    assert pipeline._available_bytes() == 10**12  # 无 cgroup → 取 psutil


def test_worker_base_and_mem_safety_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FXAPK_WORKER_BASE_MB", "100")
    assert pipeline._worker_base_bytes() == 100 * _MB
    monkeypatch.delenv("FXAPK_WORKER_BASE_MB", raising=False)
    assert pipeline._worker_base_bytes() == pipeline._WORKER_BASE_BYTES

    monkeypatch.setenv("FXAPK_MEM_SAFETY", "0.5")
    assert pipeline._mem_safety() == 0.5
    monkeypatch.setenv("FXAPK_MEM_SAFETY", "2")  # 越界 (0,1]
    assert pipeline._mem_safety() == pipeline._MEM_SAFETY
    monkeypatch.setenv("FXAPK_MEM_SAFETY", "abc")  # 非浮点
    assert pipeline._mem_safety() == pipeline._MEM_SAFETY


def test_should_parallelize_does_not_consult_memory(monkeypatch: pytest.MonkeyPatch) -> None:
    # 门控与内存逻辑解耦：_should_parallelize 绝不查内存（被调即失败以证明）。
    def _boom() -> int:
        raise AssertionError("门控不应查内存")

    monkeypatch.setattr(pipeline, "_available_bytes", _boom)
    monkeypatch.setattr(pipeline.psutil, "virtual_memory", _boom)
    monkeypatch.setattr(pipeline.os, "cpu_count", lambda: 8)
    monkeypatch.delenv("FXAPK_NO_PARALLEL", raising=False)
    ctx = _fake(platform="android", apk_path="/x.apk")
    assert pipeline._should_parallelize(ctx, [("a", 1), ("b", 1), ("c", 1)]) is True


# ---------------------------------------------------------------------------
# _run_pool 超时防护 —— 病态输入卡死单个 worker 不应让整批并行结果永久挂起
# ---------------------------------------------------------------------------


def test_run_pool_timeout_logs_and_reraises(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """mock multiprocessing.Pool.map_async(...).get 直接抛 multiprocessing.TimeoutError（不真 spawn
    慢 worker：worker 是全新 spawn 的解释器，主进程 monkeypatch 不传过去）：验证 `_run_pool` 的异常
    处理链——捕获、记带诊断的 warning、**归一为内置 TimeoutError** 重新 raise 供外层 `_analyze_eligible`
    的 except Exception 捕获回退串行；并断言走的是 with 退出即 __exit__（真实现=terminate() 强杀
    worker、超时真 bound 住墙钟）的 multiprocessing.Pool。
    """
    exited = {"called": False}

    class _StuckAsync:
        def get(self, timeout: float | None = None) -> object:
            assert timeout == pipeline._BATCH_TIMEOUT_SECONDS  # 预算传给了 get()
            raise multiprocessing.TimeoutError("worker 卡死（模拟）")

    class _FakePool:
        def __enter__(self) -> "_FakePool":
            return self

        def __exit__(self, *exc: object) -> bool:
            exited["called"] = True  # 真 Pool.__exit__=terminate() 强杀 worker
            return False

        def map_async(self, func: object, names: list[str]) -> _StuckAsync:
            return _StuckAsync()

    monkeypatch.setattr(pipeline.multiprocessing, "Pool", lambda **kw: _FakePool())
    with caplog.at_level(logging.WARNING):
        with pytest.raises(TimeoutError) as excinfo:
            pipeline._run_pool(object(), ["a", "b", "c"], 2)
    assert not isinstance(excinfo.value, multiprocessing.TimeoutError)  # 归一成内置 TimeoutError
    assert exited["called"]  # with 退出触发 __exit__（真实现 terminate 强杀，墙钟被 bound）
    assert any("超时" in r.message and "3 个分析器" in r.message for r in caplog.records)


def test_run_pool_normal_path_passes_timeout_to_get(monkeypatch: pytest.MonkeyPatch) -> None:
    """正常（不超时）路径：timeout 预算被正确传给 map_async().get()，结果原样返回、保序。"""

    class _OkAsync:
        def __init__(self, names: list[str]) -> None:
            self._names = names

        def get(self, timeout: float | None = None) -> list:
            assert timeout == pipeline._BATCH_TIMEOUT_SECONDS
            return [(n, "ok", None) for n in self._names]

    class _FakePool:
        def __enter__(self) -> "_FakePool":
            return self

        def __exit__(self, *exc: object) -> bool:
            return False

        def map_async(self, func: object, names: list[str]) -> _OkAsync:
            return _OkAsync(names)

    monkeypatch.setattr(pipeline.multiprocessing, "Pool", lambda **kw: _FakePool())
    result = pipeline._run_pool(object(), ["x", "y"], 2)
    assert result == [("x", "ok", None), ("y", "ok", None)]
