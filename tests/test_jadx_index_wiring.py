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
from apkscan.core.jadx_index import (
    DexRole,
    IndexBuildResult,
    IndexBuildState,
    JadxIndexStore,
    Limits,
    LoadedIndex,
)
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
    """语法白名单：assets/evil.dex、classes01.dex、classes1.dex（非法编号形态）不进 lineage。"""
    _patch(monkeypatch)
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("classes.dex", b"dex-main")
        zf.writestr("assets/evil.dex", b"not-apk-dex")
        zf.writestr("classes01.dex", b"bad-number-form")
        zf.writestr("classes1.dex", b"bad-number-form-too")
    ctx = FakeContext(apk_path=str(apk))
    ctx.jadx_cache_root = str(tmp_path / "jadx-cache")
    result = JadxAnalyzer().analyze(ctx)
    assert result.meta["jadx_index_status"] == "built"
    loaded = _load(ctx, result.meta["jadx_index_key"])
    assert len(loaded.manifest.dex_lineage) == 1  # 只有 classes.dex
    # 不匹配的 .dex 形态不静默：计数进 receipt。
    assert result.meta["jadx_receipt"]["index"]["unrecognized_dex_members"] == 3


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


def test_failed_index_build_surfaces_stable_diagnostic_reason(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """发布门拒绝时回执必须保留稳定原因码，不能只剩笼统 build_failed。"""
    _patch(monkeypatch)
    monkeypatch.setattr(
        JadxIndexStore,
        "build_index",
        lambda self, source_root, manifest, *, scan=None: IndexBuildResult(
            state=IndexBuildState.FAILED,
            coverage="failed",
            diagnostics=("duplicate_structure at $.scan.structure",),
        ),
    )

    result = JadxAnalyzer().analyze(_ctx(tmp_path))

    assert result.meta["jadx_index_status"] == "failed"
    reasons = result.meta["jadx_receipt"]["index"]["reason_codes"]
    assert "index_build_failed" in reasons
    assert "duplicate_structure" in reasons


# ---------------------------------------------------------------------------
# 复审补锁（codex P2-A 复审：fail-open 闭合、流闸、最终 run 语义、卫生边界）
# ---------------------------------------------------------------------------


def test_index_subflow_exception_stays_fail_open(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★fail-open 承诺锁：索引扫描层抛异常 → 主分析产出完好、索引只降级为 failed。"""
    _patch(monkeypatch)

    def _boom(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise RuntimeError("index scan exploded")

    monkeypatch.setattr(jadx, "scan_java_sources", _boom)
    ctx = _ctx(tmp_path)
    result = JadxAnalyzer().analyze(ctx)
    assert result.error is None  # 绝不污染主分析
    assert result.meta["jadx_status"] == "ok"
    assert result.meta["jadx_endpoint_count"] >= 1
    assert result.meta["jadx_index_status"] == "failed"
    assert "index_exception" in result.meta["jadx_receipt"]["index"]["reason_codes"]


def test_copy_stream_limit_enforced_beyond_declared_size(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """流式写入闸独立于 zip 声明大小闸：实际字节超限即拒，不信任元数据。"""
    import io

    monkeypatch.setattr(jadx, "_MAX_MATERIALIZE_DEX_BYTES", 16)
    with pytest.raises(jadx._DexMaterializeError) as exc:
        jadx._copy_stream_limited(
            io.BytesIO(b"x" * 20), tmp_path / "out.dex", total_remaining=1 << 30
        )
    assert exc.value.code == "dex_too_large"
    # 总预算独立于单文件上限：单文件没超、总预算超 → materialize_budget_exceeded。
    with pytest.raises(jadx._DexMaterializeError) as exc2:
        jadx._copy_stream_limited(
            io.BytesIO(b"x" * 10), tmp_path / "out2.dex", total_remaining=8
        )
    assert exc2.value.code == "materialize_budget_exceeded"


def test_degraded_rerun_uses_final_run_and_prunes_lineage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★最终 run 语义：坏 extra DEX 触发降级重跑 → 索引基于重跑（lineage 剔除 extra、
    ordinal 不重排、coverage=partial、excluded_dex 留痕）。"""
    calls: list[dict] = []

    def _run(cmd, *, timeout, env=None):  # noqa: ANN001
        calls.append({"cmd": list(cmd)})
        if "--version" in cmd:
            return _owned(0, stdout="1.5.2\n")
        out_dir = Path(cmd[cmd.index("-d") + 1])
        if any(str(a).endswith("dump0.dex") for a in cmd):
            return _owned(1)  # 首跑带坏 dump：0 产出（模拟 jadx 被拖垮）
        pkg = out_dir / "sources" / "com" / "x"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "C.java").write_text(_JAVA_BODY, encoding="utf-8")
        return _owned(0)

    monkeypatch.setattr(jadx.proctree, "run_owned", _run)
    # b"junk..." 不是合法 DEX 头 → _dex_checksum_ok=False → 降级剔除。
    ctx = _ctx(tmp_path, extra=(b"junk-not-a-dex-at-all",))
    result = JadxAnalyzer().analyze(ctx)
    assert result.meta["jadx_status"] == "partial"
    assert result.meta["jadx_bad_dex_excluded"] == ["dump0.dex"]
    # 剔除后 coverage=partial → 索引状态 partial（built 的 partial 形态）。
    assert result.meta["jadx_index_status"] == "partial"
    index_block = result.meta["jadx_receipt"]["index"]
    assert "excluded_dex" in index_block["reason_codes"]
    loaded = _load(ctx, result.meta["jadx_index_key"])
    lineage = loaded.manifest.dex_lineage
    assert [x.role for x in lineage] == [DexRole.APK_DEX]  # extra 已剔除
    assert loaded.coverage == "partial"


def test_duplicate_zip_member_rejects_indexing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """同名 classes.dex 出现两次（zip 允许重名条目）→ ordinal 冲突即拒，分析照常。"""
    _patch(monkeypatch)
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("classes.dex", b"dex-payload-a")
        zf.writestr("classes.dex", b"dex-payload-b")
    ctx = FakeContext(apk_path=str(apk))
    ctx.jadx_cache_root = str(tmp_path / "jadx-cache")
    result = JadxAnalyzer().analyze(ctx)
    assert result.meta["jadx_index_status"] == "disabled"
    assert (
        "duplicate_apk_dex_member"
        in result.meta["jadx_receipt"]["index"]["reason_codes"]
    )
    assert result.meta["jadx_status"] == "ok"


def test_false_encrypted_dex_flag_still_builds_index(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """APK 可把未加密 DEX 的 ZIP bit 0 误置为 1；JADX 能读时，lineage 物化也应
    以 CRC 校验后的真实明文继续，不能因 Python zipfile 的口令前置闸禁用索引。"""
    _patch(monkeypatch)
    apk = _apk(tmp_path)
    raw = bytearray(apk.read_bytes())
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        cursor = 0
        while True:
            cursor = raw.find(signature, cursor)
            if cursor < 0:
                break
            offset = cursor + flag_offset
            flags = int.from_bytes(raw[offset : offset + 2], "little") | 0x1
            raw[offset : offset + 2] = flags.to_bytes(2, "little")
            cursor += len(signature)
    apk.write_bytes(raw)

    with zipfile.ZipFile(apk, "r") as archive:
        info = archive.getinfo("classes.dex")
        assert info.flag_bits & 0x1
        with pytest.raises(RuntimeError, match="password required"):
            archive.open(info, "r")

    ctx = FakeContext(apk_path=str(apk))
    ctx.jadx_cache_root = str(tmp_path / "jadx-cache")
    result = JadxAnalyzer().analyze(ctx)

    assert result.meta["jadx_status"] == "ok"
    assert result.meta["jadx_index_status"] == "built"
    assert "index_exception" not in result.meta["jadx_receipt"]["index"]["reason_codes"]
    loaded = _load(ctx, result.meta["jadx_index_key"])
    assert loaded.manifest.dex_lineage[0].digest.startswith("sha256:")


def test_forged_unavailable_reason_not_leaked_into_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★reason 卫生闸：伪造 CacheUnavailable 带 Windows 路径 → 绝不进 receipt，
    折叠为稳定码。"""
    from apkscan.core.jadx_index import CacheUnavailable

    _patch(monkeypatch)
    forged = CacheUnavailable(r"C:\evil\path with spaces\x.json")
    monkeypatch.setattr(JadxIndexStore, "load_index", lambda self, key: forged)
    ctx = _ctx(tmp_path)
    result = JadxAnalyzer().analyze(ctx)
    assert result.meta["jadx_index_status"] == "unavailable"
    reasons = result.meta["jadx_receipt"]["index"]["reason_codes"]
    assert all("evil" not in r and "\\" not in r for r in reasons)
    assert "invalid_cache_state" in reasons


def test_cache_unavailable_never_reaches_build(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """CacheUnavailable 终态锁的直接形态：build_index 一次都不许被调（spy 即炸）。"""
    from apkscan.core.jadx_index import CacheUnavailable

    _patch(monkeypatch)
    monkeypatch.setattr(
        JadxIndexStore, "load_index", lambda self, key: CacheUnavailable("io_error")
    )

    def _no_build(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202
        raise AssertionError("build_index must not be called on CacheUnavailable")

    monkeypatch.setattr(JadxIndexStore, "build_index", _no_build)
    result = JadxAnalyzer().analyze(_ctx(tmp_path))
    assert result.meta["jadx_index_status"] == "unavailable"


def test_resolve_none_not_reresolved(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★同一解析结果契约：启用索引时首次 resolve 得 None → 反编译绝不二次解析
    （即使 PATH 中途"变出"了另一个 jadx，也不许用它）。"""
    resolve_calls = {"n": 0}

    def _resolve():  # noqa: ANN202
        resolve_calls["n"] += 1
        return None if resolve_calls["n"] == 1 else (["jadx"], {})

    monkeypatch.setattr(jadx.tools, "resolve_jadx", _resolve)
    ran: list[list[str]] = []

    def _run(cmd, *, timeout, env=None):  # noqa: ANN001
        ran.append(list(cmd))
        return _owned(0, stdout="1.5.2\n")

    monkeypatch.setattr(jadx.proctree, "run_owned", _run)
    result = JadxAnalyzer().analyze(_ctx(tmp_path))
    assert resolve_calls["n"] == 1  # 绝无二次解析
    assert ran == []  # 没有任何 jadx 进程（含 --version）被启动
    assert result.meta["jadx_status"] == "failed"
    assert result.meta["jadx_index_status"] == "disabled"


# ---------------------------------------------------------------------------
# P1-D：统一扫描上限——修「_MAX_JAVA_FILES 调了不生效」的死旋钮
# ---------------------------------------------------------------------------


def test_structure_scan_receives_configured_file_limit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★核心：structure 索引扫描必须真正读 `_MAX_JAVA_FILES`，而非硬编码默认 5000。

    此前 structure 索引调用点写死 `Limits()`（取 dataclass 默认 max_files=5000），
    与已经进 options_digest、驱动缓存自动重建的 `_MAX_JAVA_FILES` 完全脱节——调大
    常量「看起来生效」（options_digest 变了、缓存会重建）但 structure 扫描仍然只扫
    5000。走 JadxAnalyzer.analyze 真入口，spy 包一层 scan_java_sources 观察它实际
    收到的 limits，而非只测 _declared_arity 这类下游细节测不到的这层接线。
    """
    real_scan_java_sources = jadx.scan_java_sources
    seen_limits: list[Limits] = []

    def _spy(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        limits = kwargs["limits"]
        assert isinstance(limits, Limits)
        seen_limits.append(limits)
        return real_scan_java_sources(*args, **kwargs)

    monkeypatch.setattr(jadx, "scan_java_sources", _spy)
    _patch(monkeypatch)
    JadxAnalyzer().analyze(_ctx(tmp_path))

    assert seen_limits
    assert seen_limits[-1].max_files == jadx._MAX_JAVA_FILES
