"""NativeObfuscationAnalyzer 单测：合成高熵/低串（疑加密）与正常 .so 验证启发式。

覆盖：
- 基本属性 name/requires。
- 无 .so → 空 meta、无 Finding。
- 高熵 + 低可读串（种子 PRNG 造"加密样"字节）→ NATIVE-OBFUSCATION-SUSPECTED(MEDIUM) + meta 记录。
- 正常 .so（大量可读符号串）→ 不误报。
- 白名单库（libc++_shared.so）即便内容高熵也不报。
- 太小（<64KB）的 .so 跳过。
- 鲁棒性：read_file 抛异常单库跳过不炸整体。
"""

from __future__ import annotations

import random

from apkscan.analyzers.native_obfuscation import NativeObfuscationAnalyzer
from apkscan.core.models import AnalyzerResult, Severity

from tests.conftest import FakeContext


def _encrypted_like(n: int = 96 * 1024) -> bytes:
    """确定性"加密样"字节：熵≈8.0、可读串密度低（种子固定，避免 flake）。"""
    return random.Random(1234).randbytes(n)


def _stringy_so(n: int = 96 * 1024) -> bytes:
    """正常 .so 样：大量可读符号串 → 高可读串密度、低熵，不应被判混淆。"""
    body = b"\x7fELF\x02\x01\x01\x00Java_com_test_app_NativeBridge_doWork\x00format=%s len=%d\x00"
    return (body * (n // len(body) + 1))[:n]


def _analyze(files: dict[str, bytes] | None = None) -> AnalyzerResult:
    return NativeObfuscationAnalyzer().analyze(FakeContext(files=files))


def test_analyzer_name_and_requires():
    a = NativeObfuscationAnalyzer()
    assert a.name == "native_obfuscation"
    assert a.requires == ["apk"]


def test_no_so_yields_empty():
    result = _analyze(files={"assets/config.json": b"{}"})
    assert result.error is None
    assert result.findings == []
    assert result.meta["native_obfuscation"] == []


def test_high_entropy_low_string_flagged():
    result = _analyze(files={"lib/arm64-v8a/libcore.so": _encrypted_like()})
    assert result.error is None
    assert len(result.meta["native_obfuscation"]) == 1
    info = result.meta["native_obfuscation"][0]
    assert info["lib"] == "lib/arm64-v8a/libcore.so"
    assert info["entropy"] >= 7.5
    assert info["string_density"] < 0.08

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.id == "NATIVE-OBFUSCATION-SUSPECTED"
    assert f.severity == Severity.MEDIUM
    assert f.category == "anti_analysis"


def test_normal_stringy_so_not_flagged():
    result = _analyze(files={"lib/arm64-v8a/libbiz.so": _stringy_so()})
    assert result.error is None
    assert result.meta["native_obfuscation"] == []
    assert result.findings == []


def test_benign_allowlisted_lib_not_flagged():
    # libc++_shared.so 在白名单：即便内容高熵也不报（降 FP）。
    result = _analyze(files={"lib/arm64-v8a/libc++_shared.so": _encrypted_like()})
    assert result.meta["native_obfuscation"] == []


def test_small_so_skipped():
    # 小于 64KB 的 .so 统计噪声大 → 跳过。
    result = _analyze(files={"lib/arm64-v8a/libstub.so": _encrypted_like(10 * 1024)})
    assert result.meta["native_obfuscation"] == []


def test_read_file_failure_does_not_crash():
    class _Ctx(FakeContext):
        def read_file(self, path: str) -> bytes | None:  # type: ignore[override]
            raise RuntimeError("boom read_file")

    ctx = _Ctx(files={"lib/arm64-v8a/libcore.so": _encrypted_like()})
    result = NativeObfuscationAnalyzer().analyze(ctx)
    # 单库读失败被吞并记录，整体不炸、无误报
    assert result.error is None
    assert result.meta["native_obfuscation"] == []
