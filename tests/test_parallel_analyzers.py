"""分析器进程池并行：SnapshotContext 物化/pickle/协议 + 并行门控 + 确定性。

真并行执行（ProcessPoolExecutor spawn）由手动等价校验脚本验证（串行==并行 输出逐字节一致）；
此处单测不真 spawn（Windows CI 易 flaky），只测可 pickle 快照 + 门控逻辑 + 输出确定性。
"""

from __future__ import annotations

import pickle

import pytest

from apkscan.core import pipeline
from apkscan.core.snapshot import SnapshotContext, build_snapshot
from tests.conftest import FakeContext


def _fake(**kw) -> FakeContext:  # type: ignore[no-untyped-def]
    return FakeContext(**kw)


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
