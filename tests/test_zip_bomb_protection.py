"""zip 炸弹前置防护单测（ApkContext._declared_sizes / IpaContext.read_file）。

威胁模型：zip 条目「声明的解压后大小」可与实际压缩体积严重不成比例，恶意构造的样本可让单个
条目声明解压到几 GB，真正 read_file() 解压那一刻就把分析机内存打爆——这是"读"这个动作本身
的风险，不是"读完之后如何缓存"的风险（后者已由既有的 _MAX_READ_CACHE_BYTES 覆盖）。

不构造真能撑爆内存的恶意大文件（不现实、不必要）：用 monkeypatch 把阈值临时降到比"任意正常
文件的声明大小"还小，精确验证"declared > 阈值 → 拦截"这条新分支本身，且不影响阈值内的正常读取。
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from apkscan.core import apk as apk_mod
from apkscan.core import ipa as ipa_mod
from apkscan.core.apk import ApkContext
from apkscan.core.ipa import load_ipa
from apkscan.core.models import AnalysisConfig


class _FakeAndroguardApk:
    """假 androguard APK：get_file 直接读同一个 zip 文件（模拟真实 get_file 语义，含缺失抛异常）。"""

    def __init__(self, zip_path: str) -> None:
        self._zip_path = zip_path

    def get_file(self, path: str) -> bytes:
        with zipfile.ZipFile(self._zip_path) as zf:
            return zf.read(path)  # 不存在时 zipfile 抛 KeyError，与真实 androguard 语义等价


def _make_test_zip(tmp_path: Path, entries: dict[str, bytes]) -> str:
    p = tmp_path / "demo.apk"
    with zipfile.ZipFile(p, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return str(p)


def _make_ctx(zip_path: str) -> ApkContext:
    return ApkContext(
        _FakeAndroguardApk(zip_path),
        [],
        AnalysisConfig(online=False),
        apk_path=zip_path,
    )


# ---------------------------------------------------------------------------
# ApkContext（androguard 侧）
# ---------------------------------------------------------------------------


def test_declared_sizes_reads_zip_central_directory(tmp_path: Path) -> None:
    zip_path = _make_test_zip(tmp_path, {"a.txt": b"hello", "b.txt": b"world!!"})
    ctx = _make_ctx(zip_path)
    assert ctx._declared_sizes == {"a.txt": 5, "b.txt": 7}


def test_declared_sizes_empty_when_no_apk_path(tmp_path: Path) -> None:
    zip_path = _make_test_zip(tmp_path, {"a.txt": b"hello"})
    ctx = ApkContext(_FakeAndroguardApk(zip_path), [], AnalysisConfig(online=False), apk_path="")
    assert ctx._declared_sizes == {}


def test_declared_sizes_empty_when_apk_path_unreadable(tmp_path: Path) -> None:
    bad_path = str(tmp_path / "not-a-zip.apk")
    Path(bad_path).write_bytes(b"not a zip at all")
    ctx = ApkContext(_FakeAndroguardApk(bad_path), [], AnalysisConfig(online=False), apk_path=bad_path)
    assert ctx._declared_sizes == {}  # 打不开 → 空 dict，不炸


def test_read_file_normal_within_threshold(tmp_path: Path) -> None:
    zip_path = _make_test_zip(tmp_path, {"normal.txt": b"hello world"})
    ctx = _make_ctx(zip_path)
    assert ctx.read_file("normal.txt") == b"hello world"


def test_read_file_rejects_when_declared_size_exceeds_threshold(
    tmp_path: Path, monkeypatch
) -> None:
    zip_path = _make_test_zip(tmp_path, {"bomb.bin": b"x" * 100})
    ctx = _make_ctx(zip_path)
    monkeypatch.setattr(apk_mod, "_MAX_DECOMPRESSED_FILE_BYTES", 10)
    assert ctx.read_file("bomb.bin") is None
    # 拒绝结果本身也走缓存（不必每次都重新查表判断）
    assert ctx._read_cache["bomb.bin"] is None


def test_read_file_missing_path_unaffected_by_size_check(tmp_path: Path) -> None:
    zip_path = _make_test_zip(tmp_path, {"a.txt": b"hi"})
    ctx = _make_ctx(zip_path)
    assert ctx.read_file("does-not-exist.txt") is None


# ---------------------------------------------------------------------------
# IpaContext（IPA 侧，self._zf 直接是标准库 zipfile）
# ---------------------------------------------------------------------------


def _make_ipa_zip(tmp_path: Path, files: dict[str, bytes]) -> str:
    p = tmp_path / "demo.ipa"
    root = "Payload/Demo.app/"
    import plistlib

    plist = {"CFBundleIdentifier": "com.evil.demo", "CFBundleExecutable": "Demo"}
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr(root + "Info.plist", plistlib.dumps(plist, fmt=plistlib.FMT_BINARY))
        for rel, data in files.items():
            zf.writestr(root + rel, data)
    return str(p)


def test_ipa_read_file_normal_within_threshold(tmp_path: Path) -> None:
    path = _make_ipa_zip(tmp_path, {"a.txt": b"hello ipa"})
    ctx = load_ipa(path, AnalysisConfig(online=False))
    assert ctx.read_file("Payload/Demo.app/a.txt") == b"hello ipa"


def test_ipa_read_file_rejects_when_declared_size_exceeds_threshold(
    tmp_path: Path, monkeypatch
) -> None:
    path = _make_ipa_zip(tmp_path, {"bomb.bin": b"y" * 100})
    ctx = load_ipa(path, AnalysisConfig(online=False))
    monkeypatch.setattr(ipa_mod, "_MAX_DECOMPRESSED_FILE_BYTES", 10)
    assert ctx.read_file("Payload/Demo.app/bomb.bin") is None


# ---------------------------------------------------------------------------
# 累计缓存总量上限（_MAX_TOTAL_CACHE_BYTES）：防"许多个体各自都在单文件阈值以下、但数量极多"
# 的病态累加撑爆内存（单文件上限挡不住）。monkeypatch 把总量上限降到很小，精确验证：
#   (a) 累计超上限后停止缓存（后续文件不进 _read_cache）；
#   (b) 未缓存的文件仍返回正确全字节（不缓存只损性能、不损正确性）；
#   (c) 重复读同一路径命中缓存提前返回，不重复计数。
# ApkContext / IpaContext 两侧对称覆盖（缓存决策口径一致）。
# 用 60 字节小文件（远在单文件阈值 32MB 以下），把总量上限压到 100 字节：
# a(60) 先进缓存使累计=60；b(60) 使 60+60=120>100，触发"将超总量→不缓存"分支。
# ---------------------------------------------------------------------------


def test_apk_read_file_stops_caching_after_total_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    zip_path = _make_test_zip(
        tmp_path, {"a.txt": b"a" * 60, "b.txt": b"b" * 60, "c.txt": b"c" * 60}
    )
    ctx = _make_ctx(zip_path)
    monkeypatch.setattr(apk_mod, "_MAX_TOTAL_CACHE_BYTES", 100)

    # a 在上限内 → 进缓存，计数累加。
    assert ctx.read_file("a.txt") == b"a" * 60
    assert "a.txt" in ctx._read_cache
    assert ctx._cached_bytes == 60

    # (a) 累计将超上限 → b 不进缓存；(b) 但仍返回正确全字节；计数不变。
    assert ctx.read_file("b.txt") == b"b" * 60
    assert "b.txt" not in ctx._read_cache
    assert ctx._cached_bytes == 60

    # 后续文件持续跳过缓存，仍返回全字节。
    assert ctx.read_file("c.txt") == b"c" * 60
    assert "c.txt" not in ctx._read_cache
    assert ctx._cached_bytes == 60


def test_apk_read_file_repeated_read_not_double_counted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    zip_path = _make_test_zip(tmp_path, {"a.txt": b"a" * 60})
    ctx = _make_ctx(zip_path)
    monkeypatch.setattr(apk_mod, "_MAX_TOTAL_CACHE_BYTES", 100)

    assert ctx.read_file("a.txt") == b"a" * 60
    assert ctx._cached_bytes == 60
    # (c) 重复读同一路径：命中缓存提前返回，_cached_bytes 不重复累加。
    assert ctx.read_file("a.txt") == b"a" * 60
    assert ctx._cached_bytes == 60
    assert ctx._read_cache["a.txt"] == b"a" * 60


def test_ipa_read_file_stops_caching_after_total_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = "Payload/Demo.app/"
    path = _make_ipa_zip(
        tmp_path, {"a.txt": b"a" * 60, "b.txt": b"b" * 60, "c.txt": b"c" * 60}
    )
    ctx = load_ipa(path, AnalysisConfig(online=False))
    monkeypatch.setattr(ipa_mod, "_MAX_TOTAL_CACHE_BYTES", 100)

    assert ctx.read_file(root + "a.txt") == b"a" * 60
    assert (root + "a.txt") in ctx._read_cache
    assert ctx._cached_bytes == 60

    # (a) 累计将超上限 → b 不进缓存；(b) 但仍返回正确全字节；计数不变。
    assert ctx.read_file(root + "b.txt") == b"b" * 60
    assert (root + "b.txt") not in ctx._read_cache
    assert ctx._cached_bytes == 60

    assert ctx.read_file(root + "c.txt") == b"c" * 60
    assert (root + "c.txt") not in ctx._read_cache
    assert ctx._cached_bytes == 60


def test_ipa_read_file_repeated_read_not_double_counted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = "Payload/Demo.app/"
    path = _make_ipa_zip(tmp_path, {"a.txt": b"a" * 60})
    ctx = load_ipa(path, AnalysisConfig(online=False))
    monkeypatch.setattr(ipa_mod, "_MAX_TOTAL_CACHE_BYTES", 100)

    assert ctx.read_file(root + "a.txt") == b"a" * 60
    assert ctx._cached_bytes == 60
    # (c) 重复读同一路径：命中缓存提前返回，不重复累加。
    assert ctx.read_file(root + "a.txt") == b"a" * 60
    assert ctx._cached_bytes == 60
    assert ctx._read_cache[root + "a.txt"] == b"a" * 60


# ---------------------------------------------------------------------------
# IPA 单文件缓存阈值（_MAX_READ_CACHE_BYTES）：apk 侧同名阈值已有测试
# （test_endpoints.py 组 F #3：超阈值不缓存、==阈值仍缓存），此处补 ipa 侧对称覆盖。
# monkeypatch 把阈值压到 100 字节，免造 32MB 大文件。
# ---------------------------------------------------------------------------


def test_ipa_read_file_skips_cache_over_per_file_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """超单文件阈值不缓存但仍返回全字节；恰等于阈值仍缓存（边界为 > 而非 >=，与 apk.py 一致）。"""
    root = "Payload/Demo.app/"
    path = _make_ipa_zip(tmp_path, {"big.bin": b"x" * 101, "edge.bin": b"e" * 100})
    ctx = load_ipa(path, AnalysisConfig(online=False))
    monkeypatch.setattr(ipa_mod, "_MAX_READ_CACHE_BYTES", 100)

    # 超阈值（101 > 100）→ 不进缓存、_cached_bytes 不增，但仍返回完整字节。
    assert ctx.read_file(root + "big.bin") == b"x" * 101
    assert (root + "big.bin") not in ctx._read_cache
    assert ctx._cached_bytes == 0

    # 临界值（100 == 100）→ 仍进缓存并计数（验证边界是 > 而非 >=）。
    assert ctx.read_file(root + "edge.bin") == b"e" * 100
    assert ctx._read_cache[root + "edge.bin"] == b"e" * 100
    assert ctx._cached_bytes == 100


# ---------------------------------------------------------------------------
# 绕过 read_file 的直接 zf.read() 路径（codex 全库审计）：入口/兜底/重打包也须查声明大小
# ---------------------------------------------------------------------------


class _NoGetFileApk:
    """假 androguard APK：get_file 恒空 → 强制走 AXML 清单兜底直读路径。"""

    def get_file(self, path: str) -> bytes:
        return b""


def test_ipa_load_rejects_bomb_info_plist(tmp_path: Path, monkeypatch) -> None:
    """★回归（codex 全库审计 P1）：load_ipa 入口必读的 Info.plist 也走声明大小检查——
    高压缩比 Info.plist 不能绕过 read_file 在上下文创建阶段全量解压致 OOM。"""
    path = _make_ipa_zip(tmp_path, {"a.txt": b"x"})  # Info.plist 实际约百字节
    monkeypatch.setattr(ipa_mod, "_MAX_DECOMPRESSED_FILE_BYTES", 10)
    with pytest.raises(ipa_mod.IpaParseError, match="zip 炸弹"):
        load_ipa(path, AnalysisConfig(online=False))


def test_repackage_rejects_bomb_entry(tmp_path: Path, monkeypatch) -> None:
    """★回归（codex 全库审计 P1）：重打包逐条目复制前查声明大小，超上限中止，不无界解压致 OOM。"""
    from apkscan.dynamic import repackage

    base = tmp_path / "base.apk"
    with zipfile.ZipFile(base, "w") as zf:
        zf.writestr("classes.dex", b"dex")
        zf.writestr("assets/big.bin", b"z" * 100)
    monkeypatch.setattr(apk_mod, "_MAX_DECOMPRESSED_FILE_BYTES", 10)
    with pytest.raises(ValueError, match="zip 炸弹"):
        repackage._replace_dex_in_zip(base, {}, tmp_path / "out.apk")


def test_apk_axml_fallback_respects_size_limit(tmp_path: Path, monkeypatch, caplog) -> None:
    """★回归（codex 全库审计 P1）：AndroidManifest.xml 清单兜底直读也走声明大小检查——
    高压缩比清单不绕过 read_file 被全量解压。"""
    apk = tmp_path / "m.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"z" * 100)
    ctx = ApkContext(_NoGetFileApk(), [], AnalysisConfig(online=False), apk_path=str(apk))
    monkeypatch.setattr(apk_mod, "_MAX_DECOMPRESSED_FILE_BYTES", 10)
    with caplog.at_level("WARNING"):
        result = ctx._axml_package
    assert result == ""  # 超上限 → 放弃兜底、不解析
    assert any("zip 炸弹" in rec.getMessage() for rec in caplog.records)  # 无修复则无此告警


def test_reject_if_zip_bomb_raises_on_oversized_entry(tmp_path: Path, monkeypatch) -> None:
    """★回归（codex 审计 needs-confirm）：交 androguard 全量解析前，声明解压超上限的条目 fail-fast，
    不让 androguard 内部解压 bomb DEX/manifest 致 OOM。"""
    p = tmp_path / "bomb.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("classes.dex", b"x" * 100)
    monkeypatch.setattr(apk_mod, "_MAX_DECOMPRESSED_FILE_BYTES", 10)
    with pytest.raises(apk_mod.ApkParseError, match="zip 炸弹"):
        apk_mod._reject_if_zip_bomb(str(p))


def test_reject_if_zip_bomb_passes_normal_and_nonzip(tmp_path: Path) -> None:
    """正常 APK 不拦；打不开/非 zip 不在此判死（交 androguard 走既有错误路径）。"""
    ok = tmp_path / "ok.apk"
    with zipfile.ZipFile(ok, "w") as zf:
        zf.writestr("classes.dex", b"x" * 100)
    apk_mod._reject_if_zip_bomb(str(ok))  # 不抛
    bad = tmp_path / "not.apk"
    bad.write_bytes(b"not a zip at all")
    apk_mod._reject_if_zip_bomb(str(bad))  # 打不开 → 不抛
