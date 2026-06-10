"""IpaContext / load_ipa / is_ipa / macho 单测：合成 IPA（zipfile + binary plist），零设备。"""

from __future__ import annotations

import plistlib
import zipfile
from pathlib import Path

import pytest

from apkscan.core import macho
from apkscan.core.apk import ApkParseError
from apkscan.core.ipa import IpaParseError, is_ipa, load_ipa
from apkscan.core.models import AnalysisConfig


def _make_ipa(
    tmp_path: Path,
    *,
    plist: dict | None = None,
    files: dict[str, bytes] | None = None,
    name: str = "demo.ipa",
    app: str = "Demo",
) -> str:
    """合成一个 IPA（Payload/<app>.app/...）。返回路径。"""
    p = tmp_path / name
    root = f"Payload/{app}.app/"
    pl = {"CFBundleIdentifier": "com.evil.demo", "CFBundleExecutable": app, **(plist or {})}
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr(root + "Info.plist", plistlib.dumps(pl, fmt=plistlib.FMT_BINARY))
        for rel, data in (files or {}).items():
            zf.writestr(root + rel, data)
    return str(p)


# ---------------------------------------------------------------------------
# is_ipa
# ---------------------------------------------------------------------------


def test_is_ipa_by_suffix(tmp_path):
    assert is_ipa(_make_ipa(tmp_path)) is True


def test_is_ipa_no_suffix_with_payload(tmp_path):
    path = _make_ipa(tmp_path, name="demo.bin")  # 无 .ipa 后缀但含 Payload/
    assert is_ipa(path) is True


def test_is_ipa_apk_is_false(tmp_path):
    p = tmp_path / "x.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"x")
    assert is_ipa(str(p)) is False


def test_is_ipa_plain_zip_false(tmp_path):
    p = tmp_path / "x.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("foo.txt", b"bar")
    assert is_ipa(str(p)) is False


def test_is_ipa_nonexistent_false():
    assert is_ipa("/no/such/file.bin") is False


# ---------------------------------------------------------------------------
# load_ipa / IpaContext 协议
# ---------------------------------------------------------------------------


def test_load_ipa_context_protocol(tmp_path):
    js = b'var u="https://c2.evil.com/api";'
    # 真二进制有大量 null 分隔的 C 串；凑够阈值（>=10 段）后 entry URL 才被提取（非加密）。
    macho_bin = b"\x00".join(
        [f"symbol_string_{i}".encode() for i in range(12)]
        + [b"https://entry.evil.com/seed"]
    )
    path = _make_ipa(
        tmp_path,
        plist={"CFBundleDisplayName": "示例证券"},
        files={"www/app.js": js, "Demo": macho_bin},
    )
    ctx = load_ipa(path, AnalysisConfig(online=False))

    assert ctx.platform == "ios"
    assert ctx.dex_available is False
    assert ctx.package_name == "com.evil.demo"  # CFBundleIdentifier
    assert ctx.manifest_xml == ""  # iOS 无 AndroidManifest
    assert ctx.permissions() == []
    assert ctx.certificates() == []
    assert ctx.components().activities == []  # ComponentSet 空
    # list_files 含 .app 下文件，路径以 / 分隔
    files = ctx.list_files()
    assert "Payload/Demo.app/www/app.js" in files
    # read_file 解出内容（含缓存）
    assert ctx.read_file("Payload/Demo.app/www/app.js") == js
    assert ctx.read_file("Payload/Demo.app/www/app.js") == js  # 缓存命中
    assert ctx.read_file("Payload/Demo.app/nope") is None
    # dex_strings 复用 macho 抽主二进制可读串
    strings = list(ctx.dex_strings())
    assert any("entry.evil.com" in s for s in strings)


def test_load_ipa_macho_encrypted_graceful(tmp_path):
    """FairPlay 加密/不可读主二进制（可读串 < 阈值）→ dex_strings 空，不抛。"""
    path = _make_ipa(tmp_path, files={"Demo": bytes(range(0, 16)) * 100})  # 高熵、几乎无可读串
    ctx = load_ipa(path, AnalysisConfig(online=False))
    assert list(ctx.dex_strings()) == []


def test_ipa_context_close_idempotent_and_context_manager(tmp_path):
    """IpaContext.close() 关闭底层 ZipFile（幂等）；亦支持 with 语境（防句柄泄漏/Windows 锁文件）。"""
    path = _make_ipa(tmp_path)
    ctx = load_ipa(path, AnalysisConfig(online=False))
    assert ctx._zf.fp is not None  # 打开中
    ctx.close()
    assert ctx._zf.fp is None  # ZipFile.close() 后 fp 置 None
    ctx.close()  # 幂等，不抛

    with load_ipa(path, AnalysisConfig(online=False)) as ctx2:
        assert ctx2.package_name == "com.evil.demo"
    assert ctx2._zf.fp is None  # 退出 with 自动关闭


def test_load_ipa_corrupt_raises_ipaparseerror(tmp_path):
    bad = tmp_path / "bad.ipa"
    bad.write_bytes(b"not a zip at all")
    with pytest.raises(IpaParseError):
        load_ipa(str(bad), AnalysisConfig(online=False))


def test_load_ipa_missing_payload_raises(tmp_path):
    p = tmp_path / "nopayload.ipa"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("foo.txt", b"bar")
    with pytest.raises(IpaParseError):
        load_ipa(str(p), AnalysisConfig(online=False))


def test_ipaparseerror_is_apkparseerror():
    """IpaParseError 继承 ApkParseError → CLI 的 except ApkParseError 统一兜住。"""
    assert issubclass(IpaParseError, ApkParseError)


# ---------------------------------------------------------------------------
# macho.scan_ascii_strings
# ---------------------------------------------------------------------------


def test_macho_extracts_printable_runs():
    data = b"\x00\x01hello world\x00\xffhttps://x.com/a\x00ab"  # "ab" < min_len 丢
    # 可读串 < 阈值会返空，这里凑够阈值：
    data2 = data + b"\x00".join(f"readable{i}str".encode() for i in range(12))
    out2 = macho.scan_ascii_strings(data2, min_len=4)
    assert any("hello world" in s for s in out2)
    assert any("https://x.com/a" in s for s in out2)


def test_macho_empty_and_encrypted_return_empty():
    assert macho.scan_ascii_strings(b"") == []
    assert macho.scan_ascii_strings(bytes(range(16)) * 50) == []  # 高熵无可读串


def test_macho_extracts_utf16le_runs():
    """UTF-16LE 对齐串（每字符后跟 0x00，iOS CFString 形态）也被捞回，纯 ASCII 扫描会漏。"""
    ascii_part = b"\x00".join(f"asciirun{i}str".encode() for i in range(12))  # 凑够阈值
    utf16_url = "https://utf16.evil.com/seed".encode("utf-16-le")
    out = macho.scan_ascii_strings(ascii_part + b"\x00\x00" + utf16_url, min_len=4)
    assert any("utf16.evil.com" in s for s in out)  # UTF-16 串被提取
    assert any("asciirun0str" in s for s in out)  # ASCII 串照常
