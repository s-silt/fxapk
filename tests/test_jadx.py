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


# --- C2：SDK 常量名误报被过滤 --------------------------------------------


def test_sdk_constant_secrets_not_flagged(monkeypatch, tmp_path) -> None:
    # MIPUSH_APPKEY=MIPUSH_APPKEY（value==key）、OPPOPUSH_APPKEY=OPPOPUSH_APPKEY、
    # KEY_DEVICE_TOKEN=deviceToken、METHOD_CHECK_APPKEY=dc_checkappkey 全是 SDK 常量名误报。
    java = (
        "class C {\n"
        '  String MIPUSH_APPKEY = "MIPUSH_APPKEY";\n'
        '  String OPPOPUSH_APPKEY = "OPPOPUSH_APPKEY";\n'
        '  String KEY_DEVICE_TOKEN = "deviceToken";\n'
        '  String METHOD_CHECK_APPKEY = "dc_checkappkey";\n'
        "}\n"
    )
    monkeypatch.setattr(jadx.subprocess, "run", _fake_run_writing(java))
    result = JadxAnalyzer().analyze(_ctx(tmp_path))
    assert [f for f in result.findings if f.category == "secret"] == []


def test_real_secret_still_flagged(monkeypatch, tmp_path) -> None:
    # ★ 回归锁：真凭据 app_secret=Abc123Xyz789Def456 仍产 HIGH secret Finding。
    java = 'class C { String app_secret = "Abc123Xyz789Def456"; }'
    monkeypatch.setattr(jadx.subprocess, "run", _fake_run_writing(java))
    result = JadxAnalyzer().analyze(_ctx(tmp_path))
    assert any(f.category == "secret" for f in result.findings)


def test_version_ip_filtered_real_ip_kept(monkeypatch, tmp_path) -> None:
    # C4：jadx 路径裸 IP 与 endpoints 共享判定——版本号 13.3.3.7 过滤，真 IP 8.8.8.8 保留。
    java = (
        "class C {\n"
        '  String ver = "13.3.3.7";\n'
        '  String dns = "8.8.8.8";\n'
        '  String lan = "192.168.0.1";\n'
        "}\n"
    )
    monkeypatch.setattr(jadx.subprocess, "run", _fake_run_writing(java))
    result = JadxAnalyzer().analyze(_ctx(tmp_path))
    vals = {e.value for e in result.endpoints}
    assert "13.3.3.7" not in vals
    assert "192.168.0.1" not in vals
    assert "8.8.8.8" in vals
