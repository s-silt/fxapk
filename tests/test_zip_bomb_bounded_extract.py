"""zip 炸弹 Level 2：androguard / apkInspector 解压路径的「实际产出有界」闸。

Level 1（既有）只信 zip **中央目录**声明的解压后大小（`_declared_sizes` / `_reject_if_zip_bomb`）。
残余绕过面（逐行核实 androguard 4.1.4 + apkInspector 1.3.6）：

- `APK.get_file` → `ZipEntry.read` → `apkInspector.extract.extract_file_based_on_header_info`，
  **优先用 local header 的大小**（与中央目录可不一致），DEFLATE 时 `zlib.decompress(data, -15)`
  **无上限**——声明大小只决定读多少压缩字节，不约束解压产出；中央目录声明 100 字节、实际膨胀
  到数 GB 照样全量解压。`APK()` 构造期急切解压 manifest（arsc 在解析资源引用时解压）、
  `get_all_dex()` 解压 dex 走同一路。压缩输入本身也按 compressed_size 一次性 `read`，伪造巨大
  compressed_size 可逼出 ≤ 整个 APK 体积的一份额外拷贝。
- stdlib `zipfile` 的 `ZipExtFile` 按中央目录 file_size 截断，与 Level 1 自洽；只有这条路失守。

修法：与 `_install_axml_nsmap_shim` 同模式，幂等替换 apkInspector 的解压函数为有界版本
（`_bounded_extract_file_based_on_header_info`），产出超 `_MAX_DECOMPRESSED_FILE_BYTES` 即抛
`ZipEntryTooLargeError`；`load_apk` 与并行 worker 重开 APK 前都安装；`read_file` /
`_lazy_read` 把该异常转成 warning + None。

测试不造真能撑爆内存的大文件：monkeypatch 把上限压到 KB 级，用「中央目录与 local header 都
声称 100 字节、实际 DEFLATE 膨胀到 64 KiB」的条目精确验证「声明过闸、实际产出被封顶」。
"""

from __future__ import annotations

import logging
import struct
import zipfile
import zlib
from pathlib import Path
from typing import Any, cast

import pytest

from apkscan.core import apk as apk_mod
from apkscan.core.apk import ApkContext
from apkscan.core.models import AnalysisConfig

# ---------------------------------------------------------------------------
# 夹具：写 zip 后直接改写 local header 与中央目录里的「声明解压后大小」/「压缩方法」
# ---------------------------------------------------------------------------

_LOCAL_SIG = b"PK\x03\x04"
_CENTRAL_SIG = b"PK\x01\x02"


def _patch_headers(
    zip_path: Path,
    name: str,
    *,
    uncompressed_size: int | None = None,
    compressed_size: int | None = None,
    method: int | None = None,
) -> None:
    """改写条目 ``name`` 的 local header 与中央目录条目（不动数据区）。

    local header（30 字节定长）：方法在偏移 8，压缩大小在偏移 18，解压后大小在偏移 22；
    中央目录条目（46 字节定长）：方法在偏移 10，压缩大小在偏移 20，解压后大小在偏移 24。
    """
    raw = bytearray(zip_path.read_bytes())
    with zipfile.ZipFile(zip_path) as zf:
        info = zf.getinfo(name)
        start_dir = zf.start_dir  # type: ignore[attr-defined]
    assert raw[info.header_offset : info.header_offset + 4] == _LOCAL_SIG
    if method is not None:
        struct.pack_into("<H", raw, info.header_offset + 8, method)
    if compressed_size is not None:
        struct.pack_into("<I", raw, info.header_offset + 18, compressed_size)
    if uncompressed_size is not None:
        struct.pack_into("<I", raw, info.header_offset + 22, uncompressed_size)
    pos = start_dir
    patched = False
    while raw[pos : pos + 4] == _CENTRAL_SIG:
        fn_len, extra_len, comment_len = struct.unpack_from("<HHH", raw, pos + 28)
        fn = bytes(raw[pos + 46 : pos + 46 + fn_len]).decode("utf-8")
        if fn == name:
            if method is not None:
                struct.pack_into("<H", raw, pos + 10, method)
            if compressed_size is not None:
                struct.pack_into("<I", raw, pos + 20, compressed_size)
            if uncompressed_size is not None:
                struct.pack_into("<I", raw, pos + 24, uncompressed_size)
            patched = True
        pos += 46 + fn_len + extra_len + comment_len
    assert patched, f"中央目录里没找到 {name}"
    zip_path.write_bytes(bytes(raw))


_BOMB_PAYLOAD = b"\0" * (64 * 1024)  # DEFLATE 后 ~100 字节，解压 64 KiB


def _make_lying_apk(tmp_path: Path, *, method: int | None = None) -> Path:
    """`bomb.bin` 实际膨胀 64 KiB，但两处头都声称 100 字节；另带一个诚实的小条目。"""
    p = tmp_path / "lie.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("bomb.bin", _BOMB_PAYLOAD, compress_type=zipfile.ZIP_DEFLATED)
        zf.writestr("honest.txt", b"hello world", compress_type=zipfile.ZIP_STORED)
        zf.writestr("honest_deflate.txt", b"abc" * 200, compress_type=zipfile.ZIP_DEFLATED)
    _patch_headers(p, "bomb.bin", uncompressed_size=100, method=method)
    return p


def _zip_entry(path: Path) -> Any:
    from apkInspector.headers import ZipEntry

    return ZipEntry.parse(str(path), False)


def test_fixture_lies_consistently(tmp_path: Path) -> None:
    """夹具自证：中央目录（stdlib 视角）声明 100；真实数据能膨胀到 64 KiB。"""
    p = _make_lying_apk(tmp_path)
    with zipfile.ZipFile(p) as zf:
        info = zf.getinfo("bomb.bin")
        assert info.file_size == 100
        assert info.compress_size < 1024
        data = p.read_bytes()
        start = info.header_offset + 30 + len(info.filename) + len(info.extra)
        inflated = zlib.decompress(data[start : start + info.compress_size], -15)
        assert inflated == _BOMB_PAYLOAD


# ---------------------------------------------------------------------------
# shim 本体：安装后 apkInspector 的读取受上限约束；上限内逐字节等价
# ---------------------------------------------------------------------------


def test_shim_bounds_deflate_output_regardless_of_declared_sizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """★无修复即红：声明 100 字节、实际膨胀 64 KiB，上限 4 KiB → 必须抛 ZipEntryTooLargeError，
    不得把 64 KiB 全量解压出来。"""
    p = _make_lying_apk(tmp_path)
    apk_mod._install_bounded_zip_extract_shim()
    monkeypatch.setattr(apk_mod, "_MAX_DECOMPRESSED_FILE_BYTES", 4 * 1024)
    with caplog.at_level(logging.WARNING), pytest.raises(apk_mod.ZipEntryTooLargeError):
        _zip_entry(p).read("bomb.bin")
    assert any("zip 炸弹" in r.getMessage() for r in caplog.records)


def test_shim_is_byte_identical_within_limit(tmp_path: Path) -> None:
    """上限内（默认 500MB）：STORED / DEFLATED / 撒谎但实际仍在上限内的条目，字节与 stdlib 一致。"""
    p = _make_lying_apk(tmp_path)
    apk_mod._install_bounded_zip_extract_shim()
    entry = _zip_entry(p)
    assert entry.read("honest.txt") == b"hello world"
    assert entry.read("honest_deflate.txt") == b"abc" * 200
    # 撒谎条目：默认上限远大于 64 KiB → 与原函数一样全量返回（原函数就是这么做的）
    assert entry.read("bomb.bin") == _BOMB_PAYLOAD


def test_shim_tampered_method_does_not_fall_back_to_unbounded_stored_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """压缩方法篡改为 9（非 0/8）→ 原函数走「尝试 deflate、失败回退 STORED」分支。
    有界版：deflate 产出超限必须穿透为 ZipEntryTooLargeError，不得被回退分支吞掉。"""
    p = _make_lying_apk(tmp_path, method=9)
    apk_mod._install_bounded_zip_extract_shim()
    monkeypatch.setattr(apk_mod, "_MAX_DECOMPRESSED_FILE_BYTES", 4 * 1024)
    with pytest.raises(apk_mod.ZipEntryTooLargeError):
        _zip_entry(p).read("bomb.bin")


def test_shim_honest_oversize_stored_entry_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """STORED 条目本身超上限（诚实声明）→ 也在读取层封顶（Level 1 之外的第二道）。"""
    p = tmp_path / "big.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("big.bin", b"x" * 10_000, compress_type=zipfile.ZIP_STORED)
    apk_mod._install_bounded_zip_extract_shim()
    monkeypatch.setattr(apk_mod, "_MAX_DECOMPRESSED_FILE_BYTES", 1024)
    with pytest.raises(apk_mod.ZipEntryTooLargeError):
        _zip_entry(p).read("big.bin")


def test_shim_truncated_deflate_still_raises_zlib_error(tmp_path: Path) -> None:
    """语义对齐原函数：不完整的 deflate 流抛 zlib.error（上层据此判「读不到」），不是静默短读。"""
    p = tmp_path / "trunc.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("t.bin", b"q" * 5000, compress_type=zipfile.ZIP_DEFLATED)
    with zipfile.ZipFile(p) as zf:
        info = zf.getinfo("t.bin")
    raw = bytearray(p.read_bytes())
    start = info.header_offset + 30 + len(info.filename) + len(info.extra)
    # 把压缩数据后半截抹成零 → 流不完整
    half = info.compress_size // 2
    raw[start + half : start + info.compress_size] = b"\0" * (info.compress_size - half)
    p.write_bytes(bytes(raw))
    apk_mod._install_bounded_zip_extract_shim()
    with pytest.raises(zlib.error):
        _zip_entry(p).read("t.bin")


def test_install_shim_idempotent_and_patches_both_modules() -> None:
    import apkInspector.extract as _x
    import apkInspector.headers as _h

    apk_mod._install_bounded_zip_extract_shim()
    first = _h.extract_file_based_on_header_info
    apk_mod._install_bounded_zip_extract_shim()
    assert _h.extract_file_based_on_header_info is first, "重复安装不得层层套娃"
    assert _x.extract_file_based_on_header_info is first
    assert first is apk_mod._bounded_extract_file_based_on_header_info


# ---------------------------------------------------------------------------
# 接线：read_file / 并行 worker / load_apk / _ensure_worker_apk
# ---------------------------------------------------------------------------


class _RealZipEntryApk:
    """假 androguard APK：get_file 走真 apkInspector ZipEntry.read（即被 shim 的那条路）。"""

    def __init__(self, zip_path: str) -> None:
        self._entry = _zip_entry(Path(zip_path))

    def get_file(self, path: str) -> bytes:
        return self._entry.read(path)


def test_read_file_turns_too_large_into_warning_and_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """★无修复即红：中央目录声明 100 → Level 1 放行；读取层封顶 → read_file 返回 None 并 warning
    （不是 debug 级「未命中」）。"""
    p = _make_lying_apk(tmp_path)
    apk_mod._install_bounded_zip_extract_shim()
    ctx = ApkContext(_RealZipEntryApk(str(p)), [], AnalysisConfig(online=False), apk_path=str(p))
    assert ctx._declared_sizes["bomb.bin"] == 100  # Level 1 看到的是谎言
    monkeypatch.setattr(apk_mod, "_MAX_DECOMPRESSED_FILE_BYTES", 4 * 1024)
    with caplog.at_level(logging.WARNING):
        assert ctx.read_file("bomb.bin") is None
    assert ctx._read_cache["bomb.bin"] is None
    # ★锁的是 read_file 自己的专门分支（带 path 的「跳过」warning），不是 shim 内部那条——
    # 否则删掉 read_file 的 except 分支、靠泛 except 吞成 None 也能假绿（突变实测过）。
    assert any(
        r.levelno >= logging.WARNING
        and "read_file 跳过" in r.getMessage()
        and "zip 炸弹" in r.getMessage()
        and "bomb.bin" in r.getMessage()
        for r in caplog.records
    )
    # 诚实条目不受影响
    assert ctx.read_file("honest.txt") == b"hello world"


def test_snapshot_lazy_read_turns_too_large_into_warning_and_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from apkscan.core.snapshot import SnapshotContext

    p = _make_lying_apk(tmp_path)
    apk_mod._install_bounded_zip_extract_shim()
    snap = SnapshotContext.__new__(SnapshotContext)
    snap.apk_path = str(p)
    snap._files = {}
    snap._worker_apk = _RealZipEntryApk(str(p))
    snap._worker_declared_sizes = None
    monkeypatch.setattr(apk_mod, "_MAX_DECOMPRESSED_FILE_BYTES", 4 * 1024)
    with caplog.at_level(logging.WARNING):
        assert snap.read_file("bomb.bin") is None
    # 同 read_file：锁 _lazy_read 自己的专门分支，不接受 shim 内部 warning 冒充。
    assert any(
        r.levelno >= logging.WARNING
        and "snapshot 惰性 read_file 跳过" in r.getMessage()
        and "zip 炸弹" in r.getMessage()
        and "bomb.bin" in r.getMessage()
        for r in caplog.records
    )


def test_load_apk_installs_shim_before_androguard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """接线锁：load_apk 在交给 androguard 前安装有界解压 shim（删掉调用点即红）。"""
    calls: list[str] = []
    monkeypatch.setattr(apk_mod, "_install_bounded_zip_extract_shim", lambda: calls.append("shim"))
    bogus = tmp_path / "not.apk"
    bogus.write_bytes(b"not a zip")
    with pytest.raises(apk_mod.ApkParseError):
        apk_mod.load_apk(str(bogus), AnalysisConfig(online=False))
    assert calls == ["shim"]


def test_worker_reopen_installs_shim_before_androguard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """接线锁：并行 worker 惰性重开 APK 前也安装 shim（worker 是独立进程，不能指望主进程装过）。"""
    from apkscan.core.snapshot import SnapshotContext

    calls: list[str] = []
    monkeypatch.setattr(apk_mod, "_install_bounded_zip_extract_shim", lambda: calls.append("shim"))
    bogus = tmp_path / "not.apk"
    bogus.write_bytes(b"not a zip")
    snap = SnapshotContext.__new__(SnapshotContext)
    snap.apk_path = str(bogus)
    snap._worker_apk = None
    assert snap._ensure_worker_apk() is None  # 非 APK → 重开失败兜底 None
    assert calls == ["shim"]


# ---------------------------------------------------------------------------
# 端到端：load_apk 对核心条目（manifest / dex）的 Level 2 拒读必须 fail-fast
# ---------------------------------------------------------------------------


def test_load_apk_manifest_bomb_fails_fast_through_real_androguard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """真 androguard `APK()` 构造期会急切解压 AndroidManifest.xml：声明 100 字节、实际膨胀
    64 KiB、上限 4 KiB → 必须在解压层被 shim 拦下（留 warning）再由 load_apk 包装成
    ApkParseError，而不是先全量解压再因 AXML 解析失败才拒绝。
    无修复时：APK() 全量解压后判非法 APK，同样抛 ApkParseError 但**没有**有界解压的 warning。"""
    p = tmp_path / "m.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("AndroidManifest.xml", _BOMB_PAYLOAD, compress_type=zipfile.ZIP_DEFLATED)
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\0" * 64)
    _patch_headers(p, "AndroidManifest.xml", uncompressed_size=100)
    monkeypatch.setattr(apk_mod, "_MAX_DECOMPRESSED_FILE_BYTES", 4 * 1024)
    with caplog.at_level(logging.WARNING), pytest.raises(apk_mod.ApkParseError):
        apk_mod.load_apk(str(p), AnalysisConfig(online=False))
    assert any(
        "有界解压拒绝" in r.getMessage() and "AndroidManifest.xml" in r.getMessage()
        for r in caplog.records
    ), "manifest 炸弹必须在解压层被拦（而非全量解压后才因非法 APK 拒绝）"


class _FakeValidApk:
    """最小假 androguard APK：manifest 视为已合法解析，DEX 仍经**真 apkInspector** 读取。

    仓库没有能让真 `APK()` 过 is_valid_APK 的二进制 AXML 夹具，故 APK 类替换为最小对象；
    解压路径（被 shim 的那条）与 load_apk 的控制流都是真的。
    """

    def __init__(self, path: str) -> None:
        self._entry = _zip_entry(Path(path))

    def is_valid_APK(self) -> bool:  # noqa: N802 - 对齐 androguard 方法名
        return True

    def get_all_dex(self):  # noqa: ANN201 - 对齐 androguard 的生成器接口
        for name in sorted(self._entry.namelist()):
            if name.startswith("classes") and name.endswith(".dex"):
                yield self._entry.read(name)


def test_load_apk_dex_bomb_is_fail_fast_not_silent_downgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★codex 复审 P2（无修复即红）：炸弹在 classes2.dex（声明 100、实际 64 KiB）时，
    `get_all_dex()` 抛出的 ZipEntryTooLargeError 不得落进「可能加固 → 无 DEX 继续分析」的
    降级分支——那会把已解析的主 DEX 一并清空、形成静态分析规避。DEX 是核心条目，必须与
    Level 1 对核心条目的口径一致：整体 ApkParseError。"""
    import androguard.core.apk as androguard_apk

    p = tmp_path / "d.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\0" * 64)
        zf.writestr("classes2.dex", _BOMB_PAYLOAD, compress_type=zipfile.ZIP_DEFLATED)
    _patch_headers(p, "classes2.dex", uncompressed_size=100)
    monkeypatch.setattr(androguard_apk, "APK", _FakeValidApk)
    monkeypatch.setattr(apk_mod, "_MAX_DECOMPRESSED_FILE_BYTES", 4 * 1024)
    with pytest.raises(apk_mod.ApkParseError, match="zip 炸弹"):
        apk_mod.load_apk(str(p), AnalysisConfig(online=False))
    # 对照：没有炸弹时同一假 APK 能正常加载（证明上面的拒绝不是假 APK 本身造成的）。
    q = tmp_path / "ok.apk"
    with zipfile.ZipFile(q, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\0" * 64)
    ctx = apk_mod.load_apk(str(q), AnalysisConfig(online=False))
    assert isinstance(ctx, ApkContext)


# ---------------------------------------------------------------------------
# 压缩输入也要流式：compressed_size 可伪造，不得一次性 read(compressed_size)
# ---------------------------------------------------------------------------


class _RecordingReader:
    """包一层 BinaryIO：记录单次 read 请求的最大字节数（shim 只用到 read/seek/tell）。"""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.max_read = 0

    def read(self, n: int = -1) -> bytes:
        self.max_read = max(self.max_read, n if n >= 0 else 1 << 40)
        return self._inner.read(n)

    def seek(self, *args: Any) -> Any:
        return self._inner.seek(*args)

    def tell(self) -> int:
        return self._inner.tell()


def test_shim_streams_compressed_input_in_bounded_chunks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★codex 第二轮 P2（无修复即红）：DEFLATE 压缩输入分块读（≤ _INFLATE_CHUNK_BYTES），
    不再按 compressed_size 一次性物化。夹具用不可压缩数据（压缩后 ≈ 3 MiB），块大小压到 64 KiB，
    断言单次 read 请求 ≤ 64 KiB 且解压结果逐字节正确。"""
    import os

    payload = os.urandom(3 * 1024 * 1024)
    p = tmp_path / "stream.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("blob.bin", payload, compress_type=zipfile.ZIP_DEFLATED)
    entry = _zip_entry(p)
    reader = _RecordingReader(entry.zip)
    monkeypatch.setattr(apk_mod, "_INFLATE_CHUNK_BYTES", 64 * 1024)
    data, indicator = apk_mod._bounded_extract_file_based_on_header_info(
        cast(Any, reader),
        entry.get_local_header_dict("blob.bin"),
        entry.get_central_directory_entry_dict("blob.bin"),
    )
    assert indicator == "DEFLATED"
    assert data == payload
    assert reader.max_read <= 64 * 1024, f"单次读取 {reader.max_read} 字节，未流式"


def test_shim_never_asks_zlib_for_cap_sized_buffers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★codex 第三轮 P1（无修复即红）：`Decompress.flush(length)` / `decompress(data, max_length)` 的
    length 参数是**初始缓冲区大小**不是上限——把 `cap + 1 - len(output)` 传给 flush 会让 1 KiB
    的小文件也申请 ~500 MiB 临时缓冲。锁：在默认 500 MiB 上限下解压一个小条目，zlib 对象收到
    的任何 flush 参数都不得 ≥ 1 MiB（max_length 给 decompress 是合法的上限语义，不在此锁内）。"""

    class _Recording:
        def __init__(self, inner: Any) -> None:
            self._inner = inner
            self.flush_lengths: list[int | None] = []

        def decompress(self, data: bytes, max_length: int = 0) -> bytes:
            return self._inner.decompress(data, max_length)

        def flush(self, length: int | None = None) -> bytes:
            self.flush_lengths.append(length)
            return self._inner.flush() if length is None else self._inner.flush(length)

        def __getattr__(self, name: str) -> Any:
            return getattr(self._inner, name)

    made: list[_Recording] = []
    real_factory = zlib.decompressobj

    def factory(*args: Any, **kwargs: Any) -> _Recording:
        obj = _Recording(real_factory(*args, **kwargs))
        made.append(obj)
        return obj

    p = tmp_path / "small.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("small.txt", b"hello " * 200, compress_type=zipfile.ZIP_DEFLATED)
    entry = _zip_entry(p)
    monkeypatch.setattr(zlib, "decompressobj", factory)
    data, indicator = apk_mod._bounded_extract_file_based_on_header_info(
        entry.zip,
        entry.get_local_header_dict("small.txt"),
        entry.get_central_directory_entry_dict("small.txt"),
    )
    assert (data, indicator) == (b"hello " * 200, "DEFLATED")
    assert made, "有界解压必须经 zlib.decompressobj"
    for rec in made:
        assert all(length is None or length < 1024 * 1024 for length in rec.flush_lengths), (
            f"flush 申请了 cap 量级的缓冲：{rec.flush_lengths}"
        )


def test_shim_small_entry_peak_memory_is_small_under_default_cap(tmp_path: Path) -> None:
    """★直接锁住 P1 的失败形态本身：默认 500 MiB 上限下解压一个 1 KiB 条目，Python 侧分配峰值
    必须远小于上限（`flush(cap+1-len)` 会让峰值直奔 500 MiB；`decompress(max_length=cap)` 经
    CPython 3.11.15 / 3.12.10 实测按需增长、峰值 0.1 MiB，所以 max_length 无须切块）。"""
    import tracemalloc

    p = tmp_path / "tiny.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("tiny.txt", b"hello " * 200, compress_type=zipfile.ZIP_DEFLATED)
    entry = _zip_entry(p)
    local = entry.get_local_header_dict("tiny.txt")
    central = entry.get_central_directory_entry_dict("tiny.txt")
    assert apk_mod._MAX_DECOMPRESSED_FILE_BYTES >= 256 * 1024 * 1024  # 确认跑在默认上限下
    tracemalloc.start()
    try:
        data, indicator = apk_mod._bounded_extract_file_based_on_header_info(
            entry.zip, local, central
        )
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert (data, indicator) == (b"hello " * 200, "DEFLATED")
    assert peak < 16 * 1024 * 1024, f"小条目解压峰值 {peak / 2**20:.1f} MiB，疑按上限预分配缓冲"


def test_shim_lying_compressed_size_reads_correctly_and_stays_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """compressed_size 撒谎成 0xFFFFFFF0：原函数会一口气 read 到 EOF（整包拷贝）；流式版按块读、
    deflate 流到 eof 即停、尾随字节忽略——结果与原函数一致（zlib.decompress 同样忽略尾随），
    且单次读取仍 ≤ 块大小。"""
    p = tmp_path / "lie_csize.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("first.bin", b"abc" * 5000, compress_type=zipfile.ZIP_DEFLATED)
        zf.writestr("trailer.bin", b"z" * 200_000, compress_type=zipfile.ZIP_STORED)
    _patch_headers(p, "first.bin", compressed_size=0xFFFFFFF0)
    entry = _zip_entry(p)
    reader = _RecordingReader(entry.zip)
    monkeypatch.setattr(apk_mod, "_INFLATE_CHUNK_BYTES", 4096)
    data, indicator = apk_mod._bounded_extract_file_based_on_header_info(
        cast(Any, reader),
        entry.get_local_header_dict("first.bin"),
        entry.get_central_directory_entry_dict("first.bin"),
    )
    assert (data, indicator) == (b"abc" * 5000, "DEFLATED")
    assert reader.max_read <= 4096
