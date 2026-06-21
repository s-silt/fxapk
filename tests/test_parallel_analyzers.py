"""分析器进程池并行：SnapshotContext 物化/pickle/协议 + 并行门控 + 确定性 + 真 spawn 等价。

分两层覆盖：
- 轻量（始终跑）：可 pickle 快照往返、门控逻辑、worker 函数进程内驱动、输出确定性。
- 重量（@pytest.mark.slow，需本地有真实 *.apk 样本，否则 skip）：真 ProcessPoolExecutor spawn
  端到端，断言串行==并行**逐字节一致**——把原先"不在仓库的手动等价脚本"固化进测试套件。
"""

from __future__ import annotations

import dataclasses
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
    from apkscan.core.apk import load_apk
    from apkscan.core.models import AnalysisConfig

    assert _REAL_APK is not None  # skipif 已保证，仅为类型收窄
    ctx = load_apk(_REAL_APK, AnalysisConfig(online=False))
    eligible = _eligible_for(ctx)
    assert len(eligible) >= 3  # 真实 APK 上常态满足并行门控

    serial = pipeline._analyze_serial(ctx, eligible)
    parallel = pipeline._analyze_parallel(ctx, eligible)

    assert {n for n, _, _ in parallel} == {n for n, _ in eligible}  # pool.map 无遗漏
    assert _canon(serial) == _canon(parallel)  # 逐字段（含 findings/endpoints/leads/meta）一致
