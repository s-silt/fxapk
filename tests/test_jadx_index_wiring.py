"""P2-A：JadxAnalyzer 持久索引接线（opt-in、fail-open、真入口锁）。

先于实现编写（红态契约）。真入口 = JadxAnalyzer.analyze(ctx)；jadx 进程一律
经 _patch 替身伪造（含 --version 探测分流）。设计见本地
docs/superpowers/specs/2026-08-16-p2-wiring-design.md（v2，不入 git）。
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from apkscan.analyzers import jadx
from apkscan.analyzers.jadx import JadxAnalyzer
from apkscan.core import proctree
from apkscan.core.jadx_index import DexRole, JadxIndexStore, LoadedIndex
from tests.conftest import FakeContext

_JAVA_BODY = 'class C { String u = "https://cfg-host.example/api"; }\n'


@pytest.fixture(autouse=True)
def _stub_resolve_jadx(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jadx.tools, "resolve_jadx", lambda: (["jadx"], {}))


def _owned(returncode: int | None = 0, *, stdout: str = "") -> proctree.OwnedRun:
    return proctree.OwnedRun(
        returncode=returncode, stdout=stdout, stderr="",
        timed_out=False, ownership_complete=True,
        termination_complete=True, forced_tree_kill=False, reason_codes=(),
    )


def _patch(monkeypatch: pytest.MonkeyPatch, *, version: str | None = "1.5.2") -> list[dict]:
    """run_owned 替身：--version 调用返回版本串；其余按 jadx 执行写合成 java 树。

    version=None 模拟版本探测失败（非零退出 + 空输出）。
    """
    calls: list[dict] = []

    def _run(cmd, *, timeout, env=None):  # noqa: ANN001
        calls.append({"cmd": list(cmd), "timeout": timeout, "env": env})
        if "--version" in cmd:
            if version is None:
                return _owned(returncode=1, stdout="")
            return _owned(returncode=0, stdout=version + "\n")
        out_dir = Path(cmd[cmd.index("-d") + 1])
        pkg = out_dir / "sources" / "com" / "x"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "C.java").write_text(_JAVA_BODY, encoding="utf-8")
        return _owned(0)

    monkeypatch.setattr(jadx.proctree, "run_owned", _run)
    return calls


def _apk(tmp_path: Path, *, dex_names: tuple[str, ...] = ("classes.dex",)) -> Path:
    """真 zip 形态的合成 APK：物化路径必须能从 zip 枚举 classes*.dex。"""
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        for i, name in enumerate(dex_names):
            # 20 字节：oversized 测试把上限 monkeypatch 成 16，payload 必须真的超限。
            zf.writestr(name, b"dex-payload-%08d" % i)
        zf.writestr("resources.arsc", b"rsrc")
    return apk


def _ctx(tmp_path: Path, *, cache: bool = True, dex_names: tuple[str, ...] = ("classes.dex",),
         extra: tuple[bytes, ...] = ()) -> FakeContext:
    ctx = FakeContext(apk_path=str(_apk(tmp_path, dex_names=dex_names)))
    if cache:
        ctx.jadx_cache_root = str(tmp_path / "jadx-cache")
    extras: list[str] = []
    for i, payload in enumerate(extra):
        p = tmp_path / f"dump{i}.dex"
        p.write_bytes(payload)
        extras.append(str(p))
    if extras:
        ctx.extra_dex_paths = extras
    return ctx


def _load(ctx: FakeContext, key: str) -> LoadedIndex:
    assert ctx.jadx_cache_root is not None
    store = JadxIndexStore(ctx.jadx_cache_root)
    loaded = store.load_index(key)
    assert isinstance(loaded, LoadedIndex), loaded
    return loaded


# ---------------------------------------------------------------------------
# opt-in 与真入口
# ---------------------------------------------------------------------------


def test_no_cache_root_stays_disabled_and_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★不给 cache root = 现行为 + status=disabled；文件系统零持久化。"""
    _patch(monkeypatch)
    ctx = _ctx(tmp_path, cache=False)
    result = JadxAnalyzer().analyze(ctx)
    assert result.meta["jadx_index_status"] == "disabled"
    assert "jadx_index_key" not in result.meta
    assert not (tmp_path / "jadx-cache").exists()
    # 既有产出不受影响。
    assert result.meta["jadx_status"] == "ok"
    assert result.meta["jadx_endpoint_count"] >= 1


def test_build_via_true_entrypoint(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """★真入口锁：analyze(ctx) 走完 → built + hex64 key + cache 内工件可 fail-closed 加载。"""
    _patch(monkeypatch)
    ctx = _ctx(tmp_path)
    result = JadxAnalyzer().analyze(ctx)
    assert result.meta["jadx_index_status"] == "built"
    key = result.meta["jadx_index_key"]
    assert isinstance(key, str) and len(key) == 64 and key == key.lower()
    loaded = _load(ctx, key)
    assert loaded.coverage in ("complete", "partial")
    # receipt 并入 index 块（不另立未注册富对象键）。
    assert result.meta["jadx_receipt"]["index"]["status"] == "built"
    # 索引内容来自最终扫描的 java 树。
    (shard,) = loaded.shards
    assert shard["files"], "shard 必须收录合成 java 文件"


def test_reuse_on_second_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch(monkeypatch)
    ctx = _ctx(tmp_path)
    first = JadxAnalyzer().analyze(ctx)
    second = JadxAnalyzer().analyze(ctx)
    assert first.meta["jadx_index_status"] == "built"
    assert second.meta["jadx_index_status"] == "reused"
    assert second.meta["jadx_index_key"] == first.meta["jadx_index_key"]


def test_meta_keys_registered() -> None:
    """新键必须注册进 meta_key_categories 契约，不是裸写 result.meta。"""
    cats = JadxAnalyzer.meta_key_categories
    assert cats.get("jadx_index_status") == "coverage"
    assert cats.get("jadx_index_key") == "record"


# ---------------------------------------------------------------------------
# 物化与 lineage
# ---------------------------------------------------------------------------


def test_apk_and_extra_dex_lineage_deterministic(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★lineage 规则：apk_dex 按数字序（classes10 在 classes9 后）、label 固定；
    extra_dex 按输入序、label 固定；digest 为复算值、不带任何路径。"""
    _patch(monkeypatch)
    ctx = _ctx(
        tmp_path,
        dex_names=("classes.dex", "classes2.dex", "classes10.dex"),
        extra=(b"dump-a", b"dump-b"),
    )
    result = JadxAnalyzer().analyze(ctx)
    assert result.meta["jadx_index_status"] == "built"
    loaded = _load(ctx, result.meta["jadx_index_key"])
    lineage = loaded.manifest.dex_lineage
    apk_items = [x for x in lineage if x.role is DexRole.APK_DEX]
    extra_items = [x for x in lineage if x.role is DexRole.EXTRA_DEX]
    assert [x.ordinal for x in apk_items] == [0, 1, 9]  # classes/classes2/classes10
    assert {x.source_label for x in apk_items} == {"apk"}
    assert [x.ordinal for x in extra_items] == [0, 1]
    assert {x.source_label for x in extra_items} == {"extra"}
    for item in lineage:
        assert "/" not in item.source_label and "\\" not in item.source_label
        assert item.digest.startswith("sha256:")


def test_unrecognized_zip_members_do_not_enter_lineage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """语法白名单：assets/evil.dex、classes01.dex（非法编号形态）不进 lineage。"""
    _patch(monkeypatch)
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("classes.dex", b"dex-main")
        zf.writestr("assets/evil.dex", b"not-apk-dex")
        zf.writestr("classes01.dex", b"bad-number-form")
    ctx = FakeContext(apk_path=str(apk))
    ctx.jadx_cache_root = str(tmp_path / "jadx-cache")
    result = JadxAnalyzer().analyze(ctx)
    assert result.meta["jadx_index_status"] == "built"
    loaded = _load(ctx, result.meta["jadx_index_key"])
    assert len(loaded.manifest.dex_lineage) == 1  # 只有 classes.dex


def test_oversized_dex_disables_indexing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """解压前大小闸：超限 → disabled + 稳定 reason；普通分析照常。"""
    _patch(monkeypatch)
    monkeypatch.setattr(jadx, "_MAX_MATERIALIZE_DEX_BYTES", 16)
    ctx = _ctx(tmp_path)  # dex 内容 20 字节 > 16
    result = JadxAnalyzer().analyze(ctx)
    assert result.meta["jadx_index_status"] == "disabled"
    assert "dex_too_large" in result.meta["jadx_receipt"]["index"]["reason_codes"]
    assert result.meta["jadx_status"] == "ok"  # 分析不受影响


# ---------------------------------------------------------------------------
# 版本探测与三态语义
# ---------------------------------------------------------------------------


def test_version_probe_failure_disables_indexing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★版本参与 key material：探测失败 → 本次禁用（不建不载），分析照常。"""
    _patch(monkeypatch, version=None)
    ctx = _ctx(tmp_path)
    result = JadxAnalyzer().analyze(ctx)
    assert result.meta["jadx_index_status"] == "disabled"
    assert "jadx_version_unavailable" in result.meta["jadx_receipt"]["index"]["reason_codes"]
    assert not list((tmp_path / "jadx-cache").glob("*")) if (
        tmp_path / "jadx-cache"
    ).exists() else True
    assert result.meta["jadx_endpoint_count"] >= 1


def test_version_probe_uses_resolved_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """探测必须打在 resolve_jadx 解析出的同一命令上。"""
    calls = _patch(monkeypatch)
    JadxAnalyzer().analyze(_ctx(tmp_path))
    version_calls = [c for c in calls if "--version" in c["cmd"]]
    assert version_calls and version_calls[0]["cmd"][0] == "jadx"


def test_cache_unavailable_is_terminal_not_miss(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★CacheUnavailable 绝不当 miss：不重建、不覆盖，status=unavailable。"""
    from apkscan.core.jadx_index import CacheUnavailable

    _patch(monkeypatch)
    monkeypatch.setattr(
        JadxIndexStore, "load_index", lambda self, key: CacheUnavailable("permission_denied")
    )
    ctx = _ctx(tmp_path)
    result = JadxAnalyzer().analyze(ctx)
    assert result.meta["jadx_index_status"] == "unavailable"
    cache = tmp_path / "jadx-cache"
    manifests = list(cache.rglob("manifest.json")) if cache.exists() else []
    assert manifests == []  # 绝无重建产物
    assert result.meta["jadx_endpoint_count"] >= 1


def test_jadx_zero_output_produces_no_index(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """jadx 0 产出（失败态）→ 不建索引（failed），绝不发布空索引冒充观察面。"""

    def _run(cmd, *, timeout, env=None):  # noqa: ANN001
        if "--version" in cmd:
            return _owned(0, stdout="1.5.2\n")
        return _owned(1)  # 不写任何 java

    monkeypatch.setattr(jadx.proctree, "run_owned", _run)
    ctx = _ctx(tmp_path)
    result = JadxAnalyzer().analyze(ctx)
    assert result.meta["jadx_index_status"] == "failed"
    cache = tmp_path / "jadx-cache"
    assert not (cache.exists() and list(cache.rglob("manifest.json")))
