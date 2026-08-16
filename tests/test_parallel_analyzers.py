"""分析器进程池并行：SnapshotContext 物化/pickle/协议 + 并行门控 + 确定性 + 真 spawn 等价。

分两层覆盖：
- 轻量（始终跑）：可 pickle 快照往返、门控逻辑、worker 函数进程内驱动、输出确定性。
- 重量（@pytest.mark.slow，需显式设置 FXAPK_TEST_APK，否则 skip）：真 multiprocessing.Pool spawn
  端到端，断言串行==并行**逐字节一致**——把原先"不在仓库的手动等价脚本"固化进测试套件。
"""

from __future__ import annotations

import dataclasses
import logging
import multiprocessing
import os
import pickle
from collections.abc import Mapping
from pathlib import Path

import pytest

from apkscan.core import parallel
from apkscan.core.snapshot import SnapshotContext, build_snapshot
from tests.conftest import FakeContext


def _fake(**kw) -> FakeContext:  # type: ignore[no-untyped-def]
    return FakeContext(**kw)


def _find_real_apk(environ: Mapping[str, str] | None = None) -> str | None:
    """定位显式指定的真实 APK；未设置 ``FXAPK_TEST_APK`` 就跳过重型测试。

    分析工作树可能长期保留本地 APK。自动递归扫描会让普通 ``pytest`` 因本地文件状态不同而
    意外启动高内存真 spawn 测试，因此真实样本必须由操作者明确 opt-in。
    """
    env = (os.environ if environ is None else environ).get("FXAPK_TEST_APK")
    if env and Path(env).is_file():
        return env
    return None


_REAL_APK = _find_real_apk()


def test_find_real_apk_requires_explicit_env_even_when_local_apk_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """真实样本测试必须显式 opt-in，不能因工作树残留本地 APK 自动变成重型测试。"""
    local_apk = tmp_path / "local-evidence.apk"
    local_apk.write_bytes(b"synthetic-not-an-apk")
    # 即使旧式仓库扫描能找到 APK，未显式 opt-in 也必须忽略。这样干净 CI 上同样能钉住回归。
    monkeypatch.setattr(Path, "glob", lambda self, pattern: iter([local_apk]))

    assert _find_real_apk({}) is None
    assert _find_real_apk({"FXAPK_TEST_APK": str(local_apk)}) == str(local_apk)
    assert _find_real_apk({"FXAPK_TEST_APK": str(tmp_path / "missing.apk")}) is None


def test_build_snapshot_materializes_protocol() -> None:
    ctx = _fake(
        package_name="com.evil",
        platform="android",
        apk_path="/x/evil.apk",
        permissions=["android.permission.READ_SMS", "android.permission.CAMERA"],
        dex_strings=["Lcom/evil/Main;", "https://synthetic-c2a.vip/api"],
        files={"assets/config.json": b'{"k":1}', "res/icon.png": b"\x89PNG"},
    )
    snap = build_snapshot(ctx)
    assert snap.package_name == "com.evil" and snap.platform == "android"
    assert snap.apk_path == "/x/evil.apk"
    assert list(snap.dex_strings()) == ["Lcom/evil/Main;", "https://synthetic-c2a.vip/api"]
    assert snap.permissions() == ["android.permission.READ_SMS", "android.permission.CAMERA"]
    # 文本资源(.json)预读进快照；二进制(.png)不预读。
    assert snap.read_file("assets/config.json") == b'{"k":1}'
    assert "res/icon.png" not in snap._files


def test_build_snapshot_carries_extra_dex_paths_across_pickle() -> None:
    """dump DEX 路径必须物化进快照并活过 pickle 往返（进程池 IPC 的最小等价）。
    曾漏带：androguard 侧（dex_strings 已物化）看得见 33 个 dump DEX 的字符串，jadx 侧
    （要文件路径）在并行 worker 里拿到空列表——同一份样本、两侧口径静默分叉。"""
    dex_paths = ["/dump/classes.dex", "/dump/classes02.dex"]
    snap = build_snapshot(
        _fake(platform="android", apk_path="/x/evil.apk", extra_dex_paths=dex_paths)
    )
    assert snap.extra_dex_paths == dex_paths
    restored = pickle.loads(pickle.dumps(snap))
    assert restored.extra_dex_paths == dex_paths


def test_snapshot_satisfies_analysis_context_protocol() -> None:
    """runtime_checkable 结构闸：快照实例必须带齐 AnalysisContext 协议全部成员（含数据字段）。
    协议加字段而快照漏带 → 此测变红，而不是消费方 getattr 兜底静默拿空值（extra_dex_paths
    曾如此漏带）。与 snapshot.py 底部的 pyright 静态校验同口径，一静一动互为兜底。"""
    from apkscan.core.context import AnalysisContext

    snap = build_snapshot(_fake(platform="android", apk_path="/x.apk"))
    assert isinstance(snap, AnalysisContext)


def test_extra_dex_paths_reach_analyzer_through_parallel_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """★接线锁（并行真路径）：ctx.extra_dex_paths 必须穿过 _analyze_eligible→_analyze_parallel→
    build_snapshot→pickle(IPC)→_worker_init→_worker_analyze 整条链到达分析器。

    此前快照漏带该字段：串行生效、并行静默失效，而 android APK 默认并行 → 实际使用路径全程
    无效；FakeContext 自带字段使只调分析器的单测抓不到。进程池用进程内假 Pool 等价驱动
    （跑**真** initializer/_worker_init 与**真** map 函数/_worker_analyze，快照过真 pickle 往返），
    并断言分析器看到的 ctx 类型是 SnapshotContext——若并行链断裂回退串行（分析器会看到
    FakeContext 而"碰巧"读到字段），本测同样变红，不给回退路径假绿的机会。
    """
    from apkscan.core.models import AnalyzerResult

    dex_paths = ["/dump/classes.dex", "/dump/classes02.dex"]

    class _DexSpy:
        def __init__(self, name: str) -> None:
            self.name = name

        def analyze(self, ctx):  # type: ignore[no-untyped-def]
            r = AnalyzerResult(analyzer=self.name)
            # 与 jadx 消费方同一读法：字段缺失静默退化成 []，正是本测要抓的失效形态。
            r.meta = {
                "seen_extra_dex": list(getattr(ctx, "extra_dex_paths", None) or []),
                "ctx_type": type(ctx).__name__,
            }
            return r

    monkeypatch.setattr(parallel.os, "cpu_count", lambda: 8)
    monkeypatch.delenv("FXAPK_NO_PARALLEL", raising=False)
    monkeypatch.delenv("FXAPK_MAX_WORKERS", raising=False)
    monkeypatch.setattr(parallel, "_decide_workers", lambda *a, **k: 2)
    monkeypatch.setattr(
        parallel, "discover_analyzers", lambda: [_DexSpy(n) for n in ("s1", "s2", "s3")]
    )

    class _InProcessPool:
        """进程内等价 Pool：真 initializer + 真 map 函数，快照过真 pickle 往返模拟 spawn IPC，
        唯一省略的是真开子进程（真 spawn 端到端由 slow 档 test_serial_parallel_byte_identical_real_apk 覆盖）。"""

        def __init__(self, processes=None, initializer=None, initargs=()):  # type: ignore[no-untyped-def]
            initializer(*pickle.loads(pickle.dumps(initargs)))

        def terminate(self) -> None:
            pass

        def join(self) -> None:
            pass

        def apply_async(self, func, args):  # type: ignore[no-untyped-def]
            value = func(*args)  # 进程内即时执行（真 _worker_analyze）

            class _R:
                def get(self, timeout=None):  # type: ignore[no-untyped-def]
                    return value

            return _R()

    monkeypatch.setattr(parallel.multiprocessing, "Pool", _InProcessPool)

    ctx = _fake(platform="android", apk_path="/x/evil.apk", extra_dex_paths=dex_paths)
    eligible = [(n, _DexSpy(n)) for n in ("s1", "s2", "s3")]
    rows, receipts = parallel._analyze_eligible(ctx, eligible)

    assert len(rows) == 3 and all(err is None for _n, _r, err in rows)
    for _name, res, _err in rows:
        assert res is not None
        assert res.meta["ctx_type"] == "SnapshotContext"  # 真走并行快照路径，非串行回退假绿
        assert res.meta["seen_extra_dex"] == dex_paths  # dump DEX 路径穿过快照边界到达分析器
    # 执行 receipt：短批次全 completed（lane 是语义 lane，与传输形态无关）。
    assert receipts == {
        n: {"lane": "short", "execution": "completed"} for n in ("s1", "s2", "s3")
    }


def test_snapshot_pickle_roundtrip_excludes_worker_apk() -> None:
    # pickle 安全：往返我们**自建**的 SnapshotContext（验证可过进程池 IPC），非反序列化外部不可信数据。
    # 生产中 ProcessPoolExecutor 同样只 pickle 本进程自建的快照（来自被分析 APK），不接收外部 pickle。
    snap = SnapshotContext(
        package_name="com.x", manifest_xml="<m/>", platform="android",
        config=None, apk_path="", extra_dex_paths=[], jadx_cache_root=None, permissions=["p"], components=None,
        dex_strings=("a", "b"), file_list=["f.json"], native_libs=[],
        certificates=[], files={"f.json": b"x"},
    )
    snap._worker_apk = object()  # 模拟 worker 内已建句柄
    snap._worker_declared_sizes = {"f.json": 1}  # 模拟 worker 内已建声明大小表
    restored = pickle.loads(pickle.dumps(snap))
    assert list(restored.dex_strings()) == ["a", "b"]
    assert restored.read_file("f.json") == b"x"
    assert restored._worker_apk is None  # 句柄不随 pickle 传，unpickle 后重置
    assert restored._worker_declared_sizes is None  # 声明大小表同样每 worker 重建，不随 pickle 传


def test_snapshot_read_file_missing_no_apk_returns_none() -> None:
    # 非预读文件 + 无 apk_path → 惰性兜底拿不到 APK → None（不抛）。
    snap = SnapshotContext(
        package_name="", manifest_xml="", platform="android", config=None,
        apk_path="", extra_dex_paths=[], jadx_cache_root=None, permissions=[], components=None,
        dex_strings=(), file_list=[], native_libs=[], certificates=[], files={},
    )
    assert snap.read_file("nope/missing.bin") is None


def _snap_with_declared(declared: dict[str, int]) -> SnapshotContext:
    snap = SnapshotContext(
        package_name="", manifest_xml="", platform="android", config=None,
        apk_path="/x.apk", extra_dex_paths=[], jadx_cache_root=None, permissions=[], components=None,
        dex_strings=(), file_list=[], native_libs=[], certificates=[], files={},
    )
    snap._worker_declared_sizes = declared
    return snap


def test_lazy_read_skips_zip_bomb_by_declared_size() -> None:
    # ★并行 worker 惰性读:声明解压后大小超上限(500MB)→ 前置拦截、根本不开 APK/不解压 → None。
    snap = _snap_with_declared({"lib/arm64-v8a/bomb.so": 600 * 1024 * 1024})
    called = {"apk": False}

    def _spy() -> None:
        called["apk"] = True
        return None

    snap._ensure_worker_apk = _spy  # type: ignore[method-assign]
    assert snap.read_file("lib/arm64-v8a/bomb.so") is None
    assert called["apk"] is False  # 超上限 → 拦在解压前,未去开 APK


def test_lazy_read_passes_normal_declared_size() -> None:
    # 声明大小正常 → 过闸、进入惰性开 APK 路径（此处返 None 仅因 apk 打不开）。
    snap = _snap_with_declared({"assets/normal.bin": 1024})
    called = {"apk": False}

    def _spy() -> None:
        called["apk"] = True
        return None

    snap._ensure_worker_apk = _spy  # type: ignore[method-assign]
    assert snap.read_file("assets/normal.bin") is None
    assert called["apk"] is True  # 正常大小 → 过闸,去开 APK


def test_ensure_declared_sizes_reads_real_zip(tmp_path: object) -> None:
    import zipfile as _zip

    apk = tmp_path / "x.apk"  # type: ignore[attr-defined]
    with _zip.ZipFile(apk, "w") as zf:
        zf.writestr("assets/a.txt", b"hello")
        zf.writestr("lib/x.so", b"y" * 4096)
    snap = SnapshotContext(
        package_name="", manifest_xml="", platform="android", config=None,
        apk_path=str(apk), extra_dex_paths=[], jadx_cache_root=None, permissions=[], components=None,
        dex_strings=(), file_list=[], native_libs=[], certificates=[], files={},
    )
    sizes = snap._ensure_declared_sizes()
    assert sizes["assets/a.txt"] == 5
    assert sizes["lib/x.so"] == 4096
    assert snap._ensure_declared_sizes() is sizes  # 缓存:同一对象


def test_should_parallelize_gating(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(parallel.os, "cpu_count", lambda: 8)
    monkeypatch.delenv("FXAPK_NO_PARALLEL", raising=False)
    eligible = [("a", object()), ("b", object()), ("c", object())]

    ok = _fake(platform="android", apk_path="/x.apk")
    assert parallel._should_parallelize(ok, eligible) is True

    # 逃生开关。
    monkeypatch.setenv("FXAPK_NO_PARALLEL", "1")
    assert parallel._should_parallelize(ok, eligible) is False
    monkeypatch.delenv("FXAPK_NO_PARALLEL", raising=False)

    # 非 android 平台（防御式）→ 串行。
    assert parallel._should_parallelize(_fake(platform="other", apk_path="/x.apk"), eligible) is False
    # 无 apk_path（worker 无法惰性兜底 read_file）→ 串行。
    assert parallel._should_parallelize(_fake(platform="android", apk_path=""), eligible) is False
    # 分析器太少 → 串行。
    assert parallel._should_parallelize(ok, eligible[:2]) is False
    # 单核 → 串行。
    monkeypatch.setattr(parallel.os, "cpu_count", lambda: 1)
    assert parallel._should_parallelize(ok, eligible) is False


def test_analyze_eligible_falls_back_to_serial_without_apk(monkeypatch: pytest.MonkeyPatch) -> None:
    # 无 apk_path → 不满足并行门控 → 走串行，结果正常。
    monkeypatch.setattr(parallel.os, "cpu_count", lambda: 8)

    class _A:
        name = "spy"

        def analyze(self, ctx):  # type: ignore[no-untyped-def]
            from apkscan.core.models import AnalyzerResult
            r = AnalyzerResult(analyzer="spy")
            r.meta = {"saw": ctx.package_name}
            return r

    ctx = _fake(package_name="com.evil", platform="android", apk_path="")
    rows, receipts = parallel._analyze_eligible(
        ctx, [("spy", _A()), ("spy2", _A()), ("spy3", _A())]
    )
    assert len(rows) == 3
    assert all(err is None and res is not None for _n, res, err in rows)
    assert rows[0][1].meta["saw"] == "com.evil"
    assert all(r == {"lane": "short", "execution": "completed"} for r in receipts.values())


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

    monkeypatch.setattr(parallel, "discover_analyzers", lambda: [_Spy()])
    parallel._worker_init(snap)

    name, res, err = parallel._worker_analyze("spy")
    assert name == "spy" and err is None and res is not None
    assert res.meta["pkg"] == "com.evil"  # 快照经 _worker_init 缓存后被分析器读到

    # 未知分析器 → 明确错误，不抛。
    assert parallel._worker_analyze("ghost")[2] == "worker 未发现该分析器"

    # 分析器内部异常 → 捕获成错误字符串回传（堆栈由 logger.exception 落 worker stderr）。
    class _Boom:
        name = "boom"

        def analyze(self, ctx):  # type: ignore[no-untyped-def]
            raise ValueError("kaboom")

    monkeypatch.setattr(parallel, "discover_analyzers", lambda: [_Boom()])
    parallel._worker_init(snap)
    _, bres, berr = parallel._worker_analyze("boom")
    assert bres is None and berr is not None
    assert "ValueError" in berr and "kaboom" in berr


def _eligible_for(ctx: object) -> list[tuple]:
    """复刻 pipeline.run 的 requires 门控，返回 [(name, analyzer)]（android 上几乎全部分析器）。"""
    from apkscan.core.registry import detect_capabilities, discover_analyzers

    caps = detect_capabilities(online=False)
    caps.add("apk")
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

    serial = parallel._analyze_serial(ctx, eligible)
    # ★ 直接调 _run_pool（满核 worker）绕过 _decide_workers 的内存封顶：否则低 RAM 机上
    #   _analyze_parallel 会回退串行 → serial==serial 假绿、悄悄不再真 spawn，掏空本不变量。
    names = [name for name, _ in eligible]
    cpu_cap = max(1, min(len(names), os.cpu_count() or 2))
    par = parallel._run_pool(build_snapshot(ctx), names, cpu_cap)

    assert {n for n, _, _ in par} == {n for n, _ in eligible}  # pool.map 无遗漏
    assert _canon(serial) == _canon(par)  # 逐字段（含 findings/endpoints/leads/meta）一致


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
    monkeypatch.setattr(parallel.os, "cpu_count", lambda: cpu)
    monkeypatch.setattr(parallel, "_available_bytes", lambda: avail)
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
    assert parallel._decide_workers(snap_mb * _MB, names) == expect


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
    assert parallel._decide_workers(12 * _MB, 20) == expect


def test_decide_workers_snapshot_tier_halves(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_mem(monkeypatch, cpu=8, avail=16 * 1024 * _MB)
    # 快照 50MB > 40MB 阈值：内存路径先算 8，超阈再砍半 → 4。
    assert parallel._decide_workers(50 * _MB, 25) == 4


def test_decide_workers_psutil_failure_falls_back_and_never_raises(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(parallel.os, "cpu_count", lambda: 16)
    for e in ("FXAPK_MAX_WORKERS", "FXAPK_WORKER_BASE_MB", "FXAPK_MEM_SAFETY"):
        monkeypatch.delenv(e, raising=False)

    def _boom() -> int:
        raise RuntimeError("psutil 炸了")

    monkeypatch.setattr(parallel, "_available_bytes", _boom)
    with caplog.at_level(logging.WARNING, logger=parallel.logger.name):
        # 不向上抛 + 返回 min(16, 4)=4（否则会被外层误记为"并行执行失败"）。
        assert parallel._decide_workers(12 * _MB, 25) == 4
    assert any("固定兜底" in r.message for r in caplog.records)


def test_decide_workers_cpu_count_none(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_mem(monkeypatch, cpu=None, avail=64 * 1024 * _MB)  # type: ignore[arg-type]
    # os.cpu_count()=None → `or 2` → cpu_cap=min(10,2)=2。
    assert parallel._decide_workers(12 * _MB, 10) == 2


def test_decide_workers_memory_reduced_logs_info(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _set_mem(monkeypatch, cpu=16, avail=3072 * _MB)
    with caplog.at_level(logging.INFO, logger=parallel.logger.name):
        assert parallel._decide_workers(12 * _MB, 25) == 8
    assert any("内存受限" in r.message for r in caplog.records)


def test_analyze_parallel_low_mem_falls_back_serial_without_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    eligible = [("a", _Spy("a")), ("b", _Spy("b")), ("c", _Spy("c"))]
    ctx = _fake(package_name="com.evil", platform="android", apk_path="/x.apk")
    monkeypatch.delenv("FXAPK_MAX_WORKERS", raising=False)
    monkeypatch.setattr("apkscan.core.snapshot.build_snapshot", lambda c: object())
    monkeypatch.setattr(parallel, "_decide_workers", lambda *a, **k: 1)

    class _NoPool:
        def __init__(self, *a, **k) -> None:  # type: ignore[no-untyped-def]
            raise AssertionError("workers<=1 不应建进程池")

    monkeypatch.setattr(parallel.multiprocessing, "Pool", _NoPool)
    out = parallel._analyze_parallel(ctx, eligible)
    assert out == parallel._analyze_serial(ctx, eligible)  # 回退串行结果


def test_env_max_workers_one_short_circuits_before_build_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FXAPK_MAX_WORKERS", "1")
    monkeypatch.setattr(parallel.os, "cpu_count", lambda: 8)
    built = {"flag": False}

    def _spy_build(c):  # type: ignore[no-untyped-def]
        built["flag"] = True
        return object()

    monkeypatch.setattr("apkscan.core.snapshot.build_snapshot", _spy_build)

    class _NoPool:
        def __init__(self, *a, **k) -> None:  # type: ignore[no-untyped-def]
            raise AssertionError("强制串行不应建进程池")

    monkeypatch.setattr(parallel.multiprocessing, "Pool", _NoPool)
    eligible = [("a", _Spy("a")), ("b", _Spy("b")), ("c", _Spy("c"))]
    out = parallel._analyze_parallel(_fake(platform="android", apk_path="/x.apk"), eligible)
    assert built["flag"] is False  # 短路在 build_snapshot 之前，省 689ms 白跑
    assert len(out) == 3


def test_cgroup_v2_limit_caps(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(parallel.sys, "platform", "linux")
    v2 = ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.current")
    monkeypatch.setattr(parallel.os.path, "exists", lambda p: p in v2)
    files = {
        "/sys/fs/cgroup/memory.max": "536870912",      # 512MB
        "/sys/fs/cgroup/memory.current": "100000000",  # ~95MB
    }
    monkeypatch.setattr(parallel, "_read_cgroup_file", lambda p: files[p])
    assert parallel._cgroup_available_bytes() == 536870912 - 100000000


def test_cgroup_v1_limit_caps(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    monkeypatch.setattr(parallel.sys, "platform", "linux")
    v1l = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
    v1u = "/sys/fs/cgroup/memory/memory.usage_in_bytes"
    monkeypatch.setattr(parallel.os.path, "exists", lambda p: p in (v1l, v1u))
    monkeypatch.setattr(
        parallel.psutil, "virtual_memory", lambda: SimpleNamespace(available=10**12, total=8 * 1024 * _MB)
    )
    files = {v1l: str(512 * _MB), v1u: str(100 * _MB)}
    monkeypatch.setattr(parallel, "_read_cgroup_file", lambda p: files[p])
    assert parallel._cgroup_available_bytes() == 512 * _MB - 100 * _MB


def test_cgroup_v1_unlimited_sentinel_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    monkeypatch.setattr(parallel.sys, "platform", "linux")
    v1l = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
    monkeypatch.setattr(parallel.os.path, "exists", lambda p: p == v1l)
    monkeypatch.setattr(
        parallel.psutil, "virtual_memory", lambda: SimpleNamespace(available=10**12, total=8 * 1024 * _MB)
    )
    monkeypatch.setattr(parallel, "_read_cgroup_file", lambda p: str(0x7FFFFFFFFFFFF000))
    assert parallel._cgroup_available_bytes() is None  # 经典哨兵 → 视为未设限


def test_cgroup_v1_usage_unreadable_falls_back_to_limit_not_host(monkeypatch: pytest.MonkeyPatch) -> None:
    # ★ 安全回退：limit 已知但 usage 文件不存在/读失败 → 返回 limit（受容器上限约束），绝不退回宿主机内存。
    from types import SimpleNamespace

    monkeypatch.setattr(parallel.sys, "platform", "linux")
    v1l = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
    monkeypatch.setattr(parallel.os.path, "exists", lambda p: p == v1l)  # usage 文件缺失
    monkeypatch.setattr(
        parallel.psutil, "virtual_memory", lambda: SimpleNamespace(available=10**12, total=8 * 1024 * _MB)
    )
    monkeypatch.setattr(parallel, "_read_cgroup_file", lambda p: str(512 * _MB))
    assert parallel._cgroup_available_bytes() == 512 * _MB  # 退回 limit，非宿主机 10**12


def test_decide_workers_per_worker_scales_with_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    # 钉死 per_worker 的线性项 int(_SNAPSHOT_FACTOR * snapshot_size)：固定 cpu/avail，只增大快照
    # （均 <40MB 避开超阈砍半分支）→ per_worker 增大 → worker 数下降。
    _set_mem(monkeypatch, cpu=16, avail=3072 * _MB)
    small = parallel._decide_workers(1 * _MB, 25)
    large = parallel._decide_workers(35 * _MB, 25)
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
    monkeypatch.setattr(parallel.sys, "platform", "linux")
    monkeypatch.setattr(parallel.os.path, "exists", lambda p: p == "/sys/fs/cgroup/memory.max")
    monkeypatch.setattr(parallel, "_read_cgroup_file", lambda p: "max")
    assert parallel._cgroup_available_bytes() is None


def test_cgroup_non_linux_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(parallel.sys, "platform", "win32")
    assert parallel._cgroup_available_bytes() is None


def test_available_bytes_takes_min_with_cgroup(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    monkeypatch.setattr(
        parallel.psutil, "virtual_memory", lambda: SimpleNamespace(available=10**12, total=10**12)
    )
    monkeypatch.setattr(parallel, "_cgroup_available_bytes", lambda: 500 * _MB)
    assert parallel._available_bytes() == 500 * _MB  # cgroup 更小 → 取 cgroup
    monkeypatch.setattr(parallel, "_cgroup_available_bytes", lambda: None)
    assert parallel._available_bytes() == 10**12  # 无 cgroup → 取 psutil


def test_worker_base_and_mem_safety_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FXAPK_WORKER_BASE_MB", "100")
    assert parallel._worker_base_bytes() == 100 * _MB
    monkeypatch.delenv("FXAPK_WORKER_BASE_MB", raising=False)
    assert parallel._worker_base_bytes() == parallel._WORKER_BASE_BYTES

    monkeypatch.setenv("FXAPK_MEM_SAFETY", "0.5")
    assert parallel._mem_safety() == 0.5
    monkeypatch.setenv("FXAPK_MEM_SAFETY", "2")  # 越界 (0,1]
    assert parallel._mem_safety() == parallel._MEM_SAFETY
    monkeypatch.setenv("FXAPK_MEM_SAFETY", "abc")  # 非浮点
    assert parallel._mem_safety() == parallel._MEM_SAFETY


def test_should_parallelize_does_not_consult_memory(monkeypatch: pytest.MonkeyPatch) -> None:
    # 门控与内存逻辑解耦：_should_parallelize 绝不查内存（被调即失败以证明）。
    def _boom() -> int:
        raise AssertionError("门控不应查内存")

    monkeypatch.setattr(parallel, "_available_bytes", _boom)
    monkeypatch.setattr(parallel.psutil, "virtual_memory", _boom)
    monkeypatch.setattr(parallel.os, "cpu_count", lambda: 8)
    monkeypatch.delenv("FXAPK_NO_PARALLEL", raising=False)
    ctx = _fake(platform="android", apk_path="/x.apk")
    assert parallel._should_parallelize(ctx, [("a", 1), ("b", 1), ("c", 1)]) is True


# ---------------------------------------------------------------------------
# _run_pool exactly-once —— 单个任务卡死只标记自身，绝不丢已完成结果、绝不整批重跑
# ---------------------------------------------------------------------------


class _RecordingPool:
    """受控 Pool 替身：每次 apply_async 记录派发名；stuck 名单里的任务 get() 抛 TimeoutError。"""

    def __init__(self, stuck: set[str] | None = None) -> None:
        self.dispatched: list[str] = []
        self.exited = False
        self._stuck = stuck or set()

    def terminate(self) -> None:
        self.exited = True  # 真 Pool.terminate() 强杀残余 worker

    def join(self) -> None:
        pass

    def apply_async(self, func: object, args: tuple) -> object:  # noqa: ANN401
        name = args[0]
        self.dispatched.append(name)
        stuck = name in self._stuck

        class _R:
            def get(self, timeout: float | None = None) -> tuple:
                assert timeout is not None and 0.0 <= timeout <= parallel._BATCH_TIMEOUT_SECONDS
                if stuck:
                    raise multiprocessing.TimeoutError("worker 卡死（模拟）")
                return (name, f"res-{name}", None)

        return _R()


def test_run_pool_timeout_marks_only_stuck_task(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """★调度不变量（B1）：单任务超时 → 只把它标 scheduler_timeout；已完成结果原样收下、
    每个任务恰好派发一次、不抛异常（抛=触发外层整批串行重跑=已完成者执行两次）；
    with 退出仍强杀残余 worker。"""
    pool = _RecordingPool(stuck={"stuck"})
    monkeypatch.setattr(parallel.multiprocessing, "Pool", lambda **kw: pool)

    with caplog.at_level(logging.WARNING):
        rows = parallel._run_pool(object(), ["fast1", "stuck", "fast2"], 2)

    assert pool.dispatched == ["fast1", "stuck", "fast2"]  # exactly-once：每个恰好派发一次
    assert rows[0] == ("fast1", "res-fast1", None)
    assert rows[2] == ("fast2", "res-fast2", None)  # 慢任务不使已完成结果被丢弃/重跑
    name, res, err = rows[1]
    assert name == "stuck" and res is None
    assert err is not None and err.startswith("scheduler_timeout:")
    assert parallel._execution_state(err) == parallel.EXEC_SCHEDULER_TIMEOUT
    assert pool.exited  # 强杀残余 worker，墙钟被 bound
    assert any("stuck" in r.message and "不整批重跑" in r.message for r in caplog.records)


def test_run_pool_normal_path_returns_rows_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    """正常（不超时）路径：逐任务收集、保序返回，且 get() 拿到的是共享 deadline 的剩余预算。"""
    pool = _RecordingPool()
    monkeypatch.setattr(parallel.multiprocessing, "Pool", lambda **kw: pool)
    result = parallel._run_pool(object(), ["x", "y"], 2)
    assert result == [("x", "res-x", None), ("y", "res-y", None)]


def test_run_pool_clamps_float_rounding_to_batch_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deadline arithmetic must never pass a timeout above the declared batch budget."""
    pool = _RecordingPool()
    monotonic_value = 1_048_503.0367474168
    monkeypatch.setattr(parallel.multiprocessing, "Pool", lambda **kw: pool)
    monkeypatch.setattr(parallel.time, "monotonic", lambda: monotonic_value)

    result = parallel._run_pool(object(), ["x"], 1)

    assert result == [("x", "res-x", None)]


def test_run_pool_dispatch_failure_marks_rest_scheduler_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """派发中途失败：已派发的照常收，未派发的逐个标 scheduler_error——不向外抛（抛=整批重跑）。"""

    class _FailSecondPool(_RecordingPool):
        def apply_async(self, func: object, args: tuple) -> object:  # noqa: ANN401
            if len(self.dispatched) >= 1:
                raise RuntimeError("池损坏（模拟）")
            return super().apply_async(func, args)

    pool = _FailSecondPool()
    monkeypatch.setattr(parallel.multiprocessing, "Pool", lambda **kw: pool)
    rows = parallel._run_pool(object(), ["a", "b", "c"], 2)
    assert rows[0] == ("a", "res-a", None)
    for name, res, err in rows[1:]:
        assert res is None and err is not None and err.startswith("scheduler_error:")
    assert pool.dispatched == ["a"]  # 失败后不再尝试派发（不确定池状态）


def test_run_pool_teardown_failure_does_not_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    """★结构性「派发后不抛」：池收尾（terminate/join）自身抛异常也不得逃逸出 _run_pool——
    逃逸会命中外层 except 触发整批串行重跑，已完成的 analyzer 执行两次。结果照常返回。"""

    class _BadTeardownPool(_RecordingPool):
        def terminate(self) -> None:
            raise OSError("terminate 失败（模拟句柄异常）")

    pool = _BadTeardownPool()
    monkeypatch.setattr(parallel.multiprocessing, "Pool", lambda **kw: pool)
    rows = parallel._run_pool(object(), ["x", "y"], 2)  # 必须不抛
    assert rows == [("x", "res-x", None), ("y", "res-y", None)]


# ---------------------------------------------------------------------------
# lane 拆分 —— jadx 走 long lane，慢 jadx 不使快 analyzer 重跑，各执行恰好一次
# ---------------------------------------------------------------------------


def test_slow_jadx_does_not_rerun_fast_analyzers(monkeypatch: pytest.MonkeyPatch) -> None:
    """★B1 核心：jadx 独立 long lane（绝不进短批次）；短批次里有任务 scheduler_timeout 时，
    已完成结果保留、绝不触发整批串行重跑；receipts 按 eligible 原顺序逐 analyzer 定性。"""
    calls: dict[str, list] = {"parallel": [], "serial": []}

    def _fake_parallel(ctx: object, short: list) -> list[tuple]:
        calls["parallel"].append([n for n, _ in short])
        return [
            ("fast1", "r1", None),
            ("fast2", None,
             f"{parallel._SCHEDULER_TIMEOUT_PREFIX} 短批次预算内未完成（已完成结果保留，不重跑）"),
        ]

    def _spy_serial(ctx: object, items: list) -> list[tuple]:
        calls["serial"].append([n for n, _ in items])
        return [(n, f"sr-{n}", None) for n, _ in items]

    monkeypatch.setattr(parallel, "_should_parallelize", lambda ctx, e: True)
    monkeypatch.setattr(parallel, "_analyze_parallel", _fake_parallel)
    monkeypatch.setattr(parallel, "_analyze_serial", _spy_serial)

    eligible = [("fast1", object()), ("jadx", object()), ("fast2", object())]
    rows, receipts = parallel._analyze_eligible(object(), eligible)

    assert calls["parallel"] == [["fast1", "fast2"]]  # jadx 绝不进短批次
    assert calls["serial"] == [["jadx"]]  # 串行只跑 long lane；短批次超时不触发整批重跑
    assert [r[0] for r in rows] == ["fast1", "jadx", "fast2"]  # eligible 原顺序
    assert rows[0] == ("fast1", "r1", None)  # 快 analyzer 的已完成结果原样保留
    assert rows[1] == ("jadx", "sr-jadx", None)
    assert receipts["fast1"] == {"lane": "short", "execution": "completed"}
    assert receipts["jadx"] == {"lane": "long", "execution": "completed"}
    assert receipts["fast2"] == {"lane": "short", "execution": "scheduler_timeout"}


def test_long_and_short_lane_each_execute_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """真 analyzer 对象计数：lane 拆分后每个 analyzer 的 analyze() 恰好执行一次（串行路径）。"""
    from collections import Counter

    counts: Counter[str] = Counter()

    class _A:
        def __init__(self, name: str) -> None:
            self.name = name

        def analyze(self, ctx):  # type: ignore[no-untyped-def]
            counts[self.name] += 1
            return object()

    monkeypatch.setattr(parallel, "_should_parallelize", lambda ctx, e: False)
    eligible = [(n, _A(n)) for n in ("s1", "jadx", "s2")]
    rows, receipts = parallel._analyze_eligible(_fake(platform="android"), eligible)

    assert counts == {"s1": 1, "jadx": 1, "s2": 1}
    assert all(err is None for _n, _r, err in rows)
    assert receipts["jadx"]["lane"] == "long"
    assert receipts["s1"]["lane"] == receipts["s2"]["lane"] == "short"
