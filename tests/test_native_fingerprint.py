"""native_fingerprint 分析器 + corpus so_sha256 家族反查（A1 框架）。零真实样本：合成 .so 字节。"""
from __future__ import annotations

import hashlib

from apkscan.analyzers.native_fingerprint import NativeFingerprintAnalyzer
from apkscan.core import corpus
from tests.conftest import FakeContext

_SO_A = b"\x7fELF" + b"family-core-bytes" * 100      # 合成"核心业务 .so"
_SO_B = b"\x7fELF" + b"other-lib" * 50


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def test_analyzer_hashes_app_so_into_meta() -> None:
    ctx = FakeContext(files={
        "lib/arm64-v8a/libclientcore.so": _SO_A,
        "lib/arm64-v8a/libother.so": _SO_B,
    }, native_libs=["lib/arm64-v8a/libclientcore.so", "lib/arm64-v8a/libother.so"])
    result = NativeFingerprintAnalyzer().analyze(ctx)
    hashes = result.meta["native_lib_hashes"]
    shas = {h["sha256"] for h in hashes}
    assert _sha(_SO_A) in shas and _sha(_SO_B) in shas
    core = next(h for h in hashes if h["sha256"] == _sha(_SO_A))
    assert core["name"] == "libclientcore.so" and core["size"] == len(_SO_A)


def test_analyzer_dedups_identical_so() -> None:
    """两个同字节 .so（换皮包同一核心库）→ 去重为一条指纹。"""
    ctx = FakeContext(files={"lib/a/libx.so": _SO_A, "lib/b/liby.so": _SO_A},
                      native_libs=["lib/a/libx.so", "lib/b/liby.so"])
    hashes = NativeFingerprintAnalyzer().analyze(ctx).meta["native_lib_hashes"]
    assert len([h for h in hashes if h["sha256"] == _sha(_SO_A)]) == 1


_SO_ARM64 = b"\x7fELF" + b"arm64-core" * 80
_SO_ARMV7 = b"\x7fELF" + b"armv7-core" * 80  # 同 basename、不同 ABI → 字节不同、sha256 不同


def test_hashes_all_abi_variants_same_basename() -> None:
    """★P1 无修复即失败：同名多 ABI 变体（libclientcore.so × arm64/armeabi）字节不同 → **各自**哈希。

    修前按 basename 塌缩（collect_so_basenames）会把两变体并成一条、漏掉另一个构建；本测试断言两个
    sha256 都在，修前必失败。
    """
    ctx = FakeContext(files={
        "lib/arm64-v8a/libclientcore.so": _SO_ARM64,
        "lib/armeabi-v7a/libclientcore.so": _SO_ARMV7,
    }, native_libs=["lib/arm64-v8a/libclientcore.so", "lib/armeabi-v7a/libclientcore.so"])
    hashes = NativeFingerprintAnalyzer().analyze(ctx).meta["native_lib_hashes"]
    shas = {h["sha256"] for h in hashes}
    assert _sha(_SO_ARM64) in shas and _sha(_SO_ARMV7) in shas
    assert len(hashes) == 2  # 两 ABI 变体各一条，未塌缩


def test_declared_size_gate_skips_oversized_so() -> None:
    """★P0-5 无修复即失败：声明解压后 > 64MB 的 .so 在 read_file **前**被拦——绝不 read。

    模拟「小压缩、巨解压」炸弹 .so：实际字节很小但 zip 声明 200MB。修前无前置 size 门 → read_file
    会被调用（并在真 APK 上让 androguard 全量膨胀进内存）；本测试断言该路径从未进入 reads，修前必失败。
    """
    class _Recording(FakeContext):
        def __init__(self, **kw) -> None:
            super().__init__(**kw)
            self.reads: list[str] = []

        def read_file(self, path: str) -> bytes | None:  # type: ignore[override]
            self.reads.append(path)
            return super().read_file(path)

    big, ok = "lib/arm64-v8a/libbomb.so", "lib/arm64-v8a/libok.so"
    ctx = _Recording(
        files={big: b"\x7fELF" + b"x" * 100, ok: _SO_A},
        native_libs=[big, ok],
        declared_sizes={big: 200 * 1024 * 1024},  # 声明 200MB（> 64MB 上限），实际字节仅百余字节
    )
    hashes = NativeFingerprintAnalyzer().analyze(ctx).meta["native_lib_hashes"]
    shas = {h["sha256"] for h in hashes}
    assert big not in ctx.reads  # 前置门拦下：从未 read（不膨胀）
    assert _sha(_SO_A) in shas  # 正常 .so 照常哈希
    assert not any(h["name"] == "libbomb.so" for h in hashes)


def test_native_lib_hashes_rejects_malformed_sha256() -> None:
    """★P2 无修复即失败：meta 里 sha256 非 64 位十六进制（截断/非 hex/占位）→ 丢弃，不造假家族簇。

    修前只判 `if sha`（任意非空串即收录），坏/导入的旧报告能凭 "deadbeef" 这类串造出假簇。断言坏形状被丢、
    负 size 归 None，修前必失败。
    """
    report = {"meta": {"native_lib_hashes": [
        {"name": "good.so", "sha256": _sha(_SO_A), "size": len(_SO_A)},
        {"name": "trunc.so", "sha256": "deadbeef", "size": 10},   # 太短（8 位）
        {"name": "nonhex.so", "sha256": "z" * 64, "size": 10},     # 64 位但非十六进制
        {"name": "neg.so", "sha256": _sha(_SO_B), "size": -5},     # 合法 sha 但 size 负
    ]}}
    out = corpus._native_lib_hashes(report)
    shas = {h["sha256"] for h in out}
    assert _sha(_SO_A) in shas
    assert "deadbeef" not in shas and "z" * 64 not in shas  # 坏形状丢弃
    neg = next(h for h in out if h["sha256"] == _sha(_SO_B))
    assert neg["size"] is None  # 负 size 归 None


def _entry(sample_sha: str, *so_bytes: bytes) -> dict:
    """构造一条 manifest 记录（经 manifest_entry，模拟报告有 native_lib_hashes）。"""
    report = {
        "meta": {"sample_sha256": sample_sha, "native_lib_hashes": [
            {"name": f"lib{i}.so", "sha256": _sha(b), "size": len(b)} for i, b in enumerate(so_bytes)
        ]},
    }
    return corpus.manifest_entry(report)


def test_manifest_entry_records_native_lib_hashes() -> None:
    e = _entry("aaa", _SO_A, _SO_B)
    shas = {h["sha256"] for h in e["native_lib_hashes"]}
    assert shas == {_sha(_SO_A), _sha(_SO_B)}


def test_find_by_so_sha256_pulls_family() -> None:
    """★A1 家族反查：同核心 .so（_SO_A）的两样本 + 一无关样本 → --by so_sha256 只拉出前两个。"""
    entries = [_entry("s1", _SO_A, _SO_B), _entry("s2", _SO_A), _entry("s3", _SO_B)]
    hits = corpus.find_by_native_lib(entries, _sha(_SO_A))
    samples = sorted(e["sample_sha256"] for e in hits)
    assert samples == ["s1", "s2"]  # s3 无 _SO_A，不命中


def test_find_by_so_sha256_case_insensitive_and_empty() -> None:
    entries = [_entry("s1", _SO_A)]
    assert corpus.find_by_native_lib(entries, _sha(_SO_A).upper())  # 大小写归一
    assert corpus.find_by_native_lib(entries, "") == []


def test_shared_native_libs_clusters_family() -> None:
    """跨样本同一 .so sha256 被 ≥2 样本引用 → 家族簇。"""
    entries = [_entry("s1", _SO_A), _entry("s2", _SO_A), _entry("s3", _SO_B)]
    clusters = corpus.shared_native_libs(entries)
    core = [c for c in clusters if c["sha256"] == _sha(_SO_A)]
    assert core and core[0]["samples"] == ["s1", "s2"]
    assert not any(c["sha256"] == _sha(_SO_B) for c in clusters)  # _SO_B 仅 1 样本，不成簇


def test_cli_seen_by_so_sha256(tmp_path) -> None:
    """★CLI 端到端：corpus seen <so_sha> --by so_sha256 一击拉出同族样本。"""
    import json

    from typer.testing import CliRunner

    from apkscan import cli

    def _report(sample: str, so_bytes: bytes) -> dict:
        return {
            "schema_version": "1.0", "analysis_status": "complete", "completeness": 1.0,
            "package_name": "com.x",
            "meta": {"sample_sha256": sample, "tool_version": "0.9.0", "ruleset_digest": "dd",
                     "native_lib_hashes": [{"name": "libclientcore.so", "sha256": _sha(so_bytes),
                                            "size": len(so_bytes)}]},
            "leads": [], "endpoints": [], "findings": [],
        }

    runner = CliRunner()
    corpus_dir = tmp_path / "corpus"
    for sha, blob in (("fam1", _SO_A), ("fam2", _SO_A), ("other", _SO_B)):
        rp = tmp_path / f"{sha}.json"
        rp.write_text(json.dumps(_report(sha, blob)), encoding="utf-8")
        add = runner.invoke(cli.app, ["corpus", "add", str(rp), "--case", "c1", "--corpus", str(corpus_dir)])
        assert add.exit_code == 0, add.stdout

    seen = runner.invoke(
        cli.app, ["corpus", "seen", _sha(_SO_A), "--by", "so_sha256", "--corpus", str(corpus_dir)])
    assert seen.exit_code == 0, seen.stdout
    payload = json.loads(seen.stdout)
    assert payload["seen"] is True and payload["count"] == 2  # fam1 + fam2，不含 other

    # ★shared-native：核心 .so 被 2 样本共享 → 家族簇
    shared = runner.invoke(cli.app, ["corpus", "shared-native", "--corpus", str(corpus_dir)])
    assert shared.exit_code == 0, shared.stdout
    clusters = json.loads(shared.stdout)["clusters"]
    core = next(c for c in clusters if c["sha256"] == _sha(_SO_A))
    assert sorted(core["samples"]) == ["fam1", "fam2"]

    # ★拼错 --by 拒跑（exit 2），且错误信息里列出 so_sha256（help 完整、不静默假阴性）
    bad = runner.invoke(cli.app, ["corpus", "seen", "x", "--by", "so_sh256", "--corpus", str(corpus_dir)])
    assert bad.exit_code == 2
    assert "so_sha256" in bad.stdout + str(bad.stderr or "")
