"""JadxAnalyzer 测试：mock subprocess（不真跑 jadx），覆盖成功 / 超时 / 非零 / 无 apk_path。"""

from __future__ import annotations

import subprocess
from pathlib import Path


from apkscan.analyzers import jadx
from apkscan.analyzers.jadx import JadxAnalyzer
from tests.conftest import FakeContext


def _ctx(tmp_path: Path) -> FakeContext:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04placeholder")
    return FakeContext(apk_path=str(apk))


def _fake_run_writing(java_body: str, returncode: int = 0, stderr: str = ""):
    """返回一个替身 subprocess.run：把 java_body 写进 jadx 的 -d 输出目录。"""

    def _run(cmd, **kwargs):  # noqa: ANN001
        out_dir = Path(cmd[cmd.index("-d") + 1])
        pkg = out_dir / "sources" / "com" / "x"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "C.java").write_text(java_body, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, returncode, stdout="done", stderr=stderr)

    return _run


def test_no_apk_path_skips_cleanly() -> None:
    result = JadxAnalyzer().analyze(FakeContext())
    assert result.meta["jadx_status"] == "no_apk_path"
    assert result.endpoints == []
    assert result.findings == []
    # 优雅跳过：记 error 文案但不抛。
    assert result.error == "无 apk_path，跳过 jadx 反编译"


def test_extracts_endpoint_and_secret(monkeypatch, tmp_path) -> None:
    java = (
        'public class C {\n'
        '  String url = "https://c2.jadx-found.cn/api/report";\n'
        '  String app_secret = "Abc123Xyz789Def456";\n'
        '  int n = obj.length;  // 不应被当域名\n'
        '}\n'
    )
    monkeypatch.setattr(jadx.subprocess, "run", _fake_run_writing(java))
    result = JadxAnalyzer().analyze(_ctx(tmp_path))

    assert result.meta["jadx_status"] == "ok"
    assert result.error is None
    vals = {e.value for e in result.endpoints}
    assert "https://c2.jadx-found.cn/api/report" in vals
    assert "c2.jadx-found.cn" in vals  # URL host 也抽成 domain 端点
    assert "obj.length" not in vals  # 代码片段不误判
    assert any(f.category == "secret" for f in result.findings)
    assert result.meta["jadx_endpoint_count"] >= 2


def test_timeout_records_status_not_crash(monkeypatch, tmp_path) -> None:
    def _raise(cmd, **kwargs):  # noqa: ANN001
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(jadx.subprocess, "run", _raise)
    result = JadxAnalyzer().analyze(_ctx(tmp_path))
    assert result.meta["jadx_status"] == "timeout"
    assert result.error is None  # 超时不抛，按无产物继续（端点为空）
    assert result.endpoints == []


def test_nonzero_exit_still_scans_partial_output(monkeypatch, tmp_path) -> None:
    java = 'class A { String u = "http://gw.evil-jadx.vip/x"; }'
    monkeypatch.setattr(
        jadx.subprocess, "run",
        _fake_run_writing(java, returncode=1, stderr="some classes failed"),
    )
    result = JadxAnalyzer().analyze(_ctx(tmp_path))
    assert result.meta["jadx_status"] == "partial"
    assert any(e.value == "http://gw.evil-jadx.vip/x" for e in result.endpoints)


def test_requires_jadx_capability() -> None:
    # requires 声明 jadx，pipeline 在无 jadx 能力时会 skipped（此处仅断言声明）。
    assert JadxAnalyzer().requires == ["jadx"]
