"""apkscan.core.integrity 单测：取证完整性元数据（可采性背书层）。

覆盖：
- ``sample_fingerprint``：真临时文件 → sha256/sha1/md5/size 与标准库交叉核对、
  analyzed_at 是 UTC ISO8601、含 tool_version/platform、坏路径容错（不抛、空 hash）。
- ``evidence_id``：确定性、相同 source|location 同 id、snippet 不参与 id（来源变更
  不致 id 漂移）、长度 16 hex。

定位说明：这是**证据链 / 可复现性元数据**，不出新线索；测试只钉「自证完整性」契约。
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path

from apkscan.core.integrity import evidence_id, sample_fingerprint


# --------------------------- sample_fingerprint ---------------------------


def test_sample_fingerprint_hashes_match_stdlib(tmp_path: Path) -> None:
    """对真临时文件，sha256/sha1/md5/size 与标准库直接计算一致。"""
    data = b"apkscan-evidence-integrity-\xe6\xb6\x89\xe8\xaf\x88" * 4096
    apk = tmp_path / "sample.apk"
    apk.write_bytes(data)

    fp = sample_fingerprint(str(apk), tool_version="9.9.9")

    assert fp["sha256"] == hashlib.sha256(data).hexdigest()
    assert fp["sha1"] == hashlib.sha1(data).hexdigest()
    assert fp["md5"] == hashlib.md5(data).hexdigest()
    assert fp["size"] == len(data)


def test_sample_fingerprint_carries_tool_version_and_platform(tmp_path: Path) -> None:
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"abc")
    fp = sample_fingerprint(str(apk), tool_version="1.2.3")
    assert fp["tool_version"] == "1.2.3"
    assert isinstance(fp["platform"], str) and fp["platform"]  # platform.platform()


def test_sample_fingerprint_analyzed_at_is_utc_iso8601(tmp_path: Path) -> None:
    """analyzed_at 必须是可解析的 ISO8601 且为 UTC（带 +00:00 / Z）。"""
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"abc")
    fp = sample_fingerprint(str(apk), tool_version="1.0.0")
    ts = fp["analyzed_at"]
    assert isinstance(ts, str) and ts
    # 能被 fromisoformat 解析（Z 归一为 +00:00），且是 UTC。
    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    assert parsed.utcoffset() is not None
    assert parsed.utcoffset().total_seconds() == 0  # type: ignore[union-attr]


def test_sample_fingerprint_streams_large_file(tmp_path: Path) -> None:
    """大文件（> 单块）流式哈希结果仍与一次性哈希一致（不撑内存路径正确）。"""
    data = b"\x00\xff" * (2 * 1024 * 1024)  # 4 MiB，跨多个 1 MiB 块
    apk = tmp_path / "big.apk"
    apk.write_bytes(data)
    fp = sample_fingerprint(str(apk), tool_version="1.0.0")
    assert fp["sha256"] == hashlib.sha256(data).hexdigest()
    assert fp["size"] == len(data)


def test_sample_fingerprint_missing_file_does_not_raise(tmp_path: Path) -> None:
    """读不到的检材 → 返回带空 hash 的 dict、不抛；元数据字段齐全。"""
    fp = sample_fingerprint(str(tmp_path / "nope.apk"), tool_version="1.0.0")
    assert fp["sha256"] == ""
    assert fp["sha1"] == ""
    assert fp["md5"] == ""
    assert fp["size"] == 0
    # 即便读不到也带工具版本 / 平台 / 时间戳（自证仍可追溯本次分析环境）。
    assert fp["tool_version"] == "1.0.0"
    assert fp["platform"]
    assert fp["analyzed_at"]


def test_sample_fingerprint_keys_complete(tmp_path: Path) -> None:
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"abc")
    fp = sample_fingerprint(str(apk), tool_version="1.0.0")
    assert set(fp) == {
        "sha256",
        "sha1",
        "md5",
        "size",
        "analyzed_at",
        "tool_version",
        "platform",
        "build_commit",  # ★取证复现：git commit SHA（源码树运行）/ None（pip 包）
        "build_dirty",
    }


# --------------------------- evidence_id ---------------------------


def test_evidence_id_is_deterministic_and_16_hex() -> None:
    eid = evidence_id("dex", "com/app/Pay.java")
    assert eid == evidence_id("dex", "com/app/Pay.java")  # 确定性
    assert len(eid) == 16
    assert all(c in "0123456789abcdef" for c in eid)


def test_evidence_id_matches_sha256_prefix() -> None:
    """显式钉算法：sha256("source|location") 前 16 位 hex。"""
    eid = evidence_id("runtime", "flows#0")
    expected = hashlib.sha256("runtime|flows#0".encode("utf-8")).hexdigest()[:16]
    assert eid == expected


def test_evidence_id_changes_with_source_or_location() -> None:
    base = evidence_id("dex", "A.java")
    assert evidence_id("native", "A.java") != base  # source 变
    assert evidence_id("dex", "B.java") != base  # location 变


def test_evidence_id_ignores_snippet() -> None:
    """id 只由 source|location 决定，与 snippet 无关。

    runtime 来源的 snippet 可能含每次抓包不同的随机/时间字段，纳入会致 id 漂移；
    本测试钉住「snippet 不参与 id」这条核验明确点出的契约（接口上 evidence_id 本就
    不接收 snippet 参数，此处从行为侧再钉一遍）。
    """
    eid = evidence_id("runtime", "flows#0")
    # 同 source|location，无论“伴随的 snippet”如何变化，id 恒定。
    assert eid == evidence_id("runtime", "flows#0")


# --------------------------- build_provenance（取证复现：git commit） ---------------------------
def test_build_provenance_graceful_when_no_git(monkeypatch, tmp_path: Path) -> None:
    """★取证复现：无 git / 非源码树（pip 包）→ build_commit=None、build_dirty=None，绝不抛。"""
    from apkscan.core import integrity

    monkeypatch.setattr(integrity, "_BUILD_PROVENANCE", None)  # 清进程内缓存

    def _boom(*a, **k):  # noqa: ANN002, ANN003, ANN202
        raise OSError("git not found")

    monkeypatch.setattr(integrity.subprocess, "run", _boom)
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"z")
    fp = sample_fingerprint(str(apk), tool_version="1.0.0")
    assert fp["build_commit"] is None and fp["build_dirty"] is None


def test_build_provenance_returns_commit_and_dirty(monkeypatch, tmp_path: Path) -> None:
    """源码树运行：git rev-parse → commit SHA；git status 非空 → build_dirty=True（锁定"哪版代码产的报告"）。"""
    import types

    from apkscan.core import integrity

    monkeypatch.setattr(integrity, "_BUILD_PROVENANCE", None)

    def _fake_run(args, **k):  # noqa: ANN001, ANN003, ANN202
        if "rev-parse" in args:
            return types.SimpleNamespace(returncode=0, stdout="abc123def456\n", stderr="")
        return types.SimpleNamespace(returncode=0, stdout=" M apkscan/x.py\n", stderr="")  # status → dirty

    monkeypatch.setattr(integrity.subprocess, "run", _fake_run)
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"z")
    fp = sample_fingerprint(str(apk), tool_version="1.0.0")
    assert fp["build_commit"] == "abc123def456" and fp["build_dirty"] is True
    monkeypatch.setattr(integrity, "_BUILD_PROVENANCE", None)  # 复原缓存，免污染后续


def test_build_provenance_failure_not_cached_reprobes(monkeypatch, tmp_path: Path) -> None:
    """★codex 复核 #1：git 首次失败不缓存 → 同进程内 git 恢复后重探仍能取到 commit（不被 None 永久钉住）。"""
    import types

    from apkscan.core import integrity

    monkeypatch.setattr(integrity, "_BUILD_PROVENANCE", None)
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"z")

    def _fail(*a, **k):  # noqa: ANN002, ANN003, ANN202
        raise OSError("git gone")

    monkeypatch.setattr(integrity.subprocess, "run", _fail)
    assert sample_fingerprint(str(apk), tool_version="1.0.0")["build_commit"] is None
    assert integrity._BUILD_PROVENANCE is None  # ★失败态未缓存

    def _ok(args, **k):  # noqa: ANN001, ANN003, ANN202
        if "rev-parse" in args:
            return types.SimpleNamespace(returncode=0, stdout="deadbeef\n", stderr="")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(integrity.subprocess, "run", _ok)
    assert sample_fingerprint(str(apk), tool_version="1.0.0")["build_commit"] == "deadbeef"  # 恢复后重探取到
    monkeypatch.setattr(integrity, "_BUILD_PROVENANCE", None)  # 复原缓存，免污染后续
