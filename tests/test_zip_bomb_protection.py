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
