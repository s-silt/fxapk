"""JadxAnalyzer 测试：mock subprocess（不真跑 jadx），覆盖成功 / 超时 / 非零 / 无 apk_path。"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from apkscan.analyzers import jadx
from apkscan.analyzers.jadx import JadxAnalyzer
from tests.conftest import FakeContext


@pytest.fixture(autouse=True)
def _stub_resolve_jadx(monkeypatch: pytest.MonkeyPatch) -> None:
    """默认把 tools.resolve_jadx 桩成「裸 jadx、无额外 env」，使既有用例只关注 subprocess 行为。
    需要测 resolve_jadx 解析/JAVA_HOME 注入的用例各自覆盖此桩。"""
    monkeypatch.setattr(jadx.tools, "resolve_jadx", lambda: (["jadx"], {}))


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
    assert JadxAnalyzer().requires == ["jadx", "apk"]


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


def test_run_jadx_uses_resolved_full_path(monkeypatch, tmp_path) -> None:
    """回归：argv[0] 必须是 tools.resolve_jadx() 解析出的完整路径（Windows 下 jadx.bat），
    而非裸 'jadx'（裸名经 subprocess 启动会 WinError2，CreateProcess 不走 PATHEXT）。"""
    fake_exe = r"C:\tools\jadx\bin\jadx.BAT"
    monkeypatch.setattr(jadx.tools, "resolve_jadx", lambda: ([fake_exe], {}))
    seen: dict[str, object] = {}

    def _fake_run(cmd, **kwargs):  # noqa: ANN001
        seen["cmd"] = list(cmd)
        seen["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(cmd, 0, stdout="done", stderr="")

    monkeypatch.setattr(jadx.subprocess, "run", _fake_run)

    JadxAnalyzer()._run_jadx("app.apk", str(tmp_path))
    cmd = seen["cmd"]
    assert isinstance(cmd, list) and cmd[0] == fake_exe
    assert seen["env"] is None  # 无额外 env → 不显式传 env


def test_run_jadx_injects_java_home_from_addon(monkeypatch, tmp_path) -> None:
    """插件包路径：resolve_jadx 返回 JAVA_HOME → 必须注入子进程 env（无系统 Java 也能跑）。"""
    monkeypatch.setattr(
        jadx.tools,
        "resolve_jadx",
        lambda: ([r"C:\addon\jadx\bin\jadx.BAT"], {"JAVA_HOME": r"C:\addon\jre"}),
    )
    seen: dict[str, object] = {}

    def _fake_run(cmd, **kwargs):  # noqa: ANN001
        seen["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(jadx.subprocess, "run", _fake_run)

    JadxAnalyzer()._run_jadx("app.apk", str(tmp_path))
    env = seen["env"]
    assert isinstance(env, dict)
    assert env.get("JAVA_HOME") == r"C:\addon\jre"


def test_run_jadx_failed_when_no_jadx(monkeypatch, tmp_path) -> None:
    """resolve_jadx 落空（理论上 requires=['jadx'] 已门控）→ 返回 failed，不调 subprocess、不崩。"""
    monkeypatch.setattr(jadx.tools, "resolve_jadx", lambda: None)

    def _boom(*a, **k):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError("resolve_jadx 为 None 时不应调 subprocess")

    monkeypatch.setattr(jadx.subprocess, "run", _boom)

    assert JadxAnalyzer()._run_jadx("app.apk", str(tmp_path)) == "failed"


def _tree_with_pkg_case(tmp_path: Path, pkg_case: str, java: str) -> Path:
    """在 tmp 下造一棵 jadx 产物树，把同一类文件落进包目录 sources/<pkg_case>/（大小写可控）。"""
    root = tmp_path / pkg_case / "out"
    pkg = root / "sources" / pkg_case
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "AbstractC0336d.java").write_text(java, encoding="utf-8")
    return root


def _endpoint_locations(endpoints: list) -> list[tuple[str, str]]:  # noqa: ANN001
    return sorted((e.value, ev.location) for e in endpoints for ev in e.evidences)


def test_scan_java_location_case_deterministic(tmp_path) -> None:
    """★codex 复审 JADX flaky：jadx 多线程在 NTFS 大小写不敏感盘上把仅大小写不同的混淆包（v/V）落成
    随机大小写目录，两次运行 evidence.location 漂移（破坏 evidence_id 稳定 + 串行==并行逐字节一致）。
    修法把 location 规范化为小写正斜杠 → 两次（v 与 V）产逐字段一致的端点证据、location 确定。"""
    java = 'class C { String u = "https://c2.jadx-case.cn/report"; }'
    eps_lower, _, _ = JadxAnalyzer()._scan_java(_tree_with_pkg_case(tmp_path, "v", java))
    eps_upper, _, _ = JadxAnalyzer()._scan_java(_tree_with_pkg_case(tmp_path, "V", java))

    # 包目录大小写不同（v vs V），但规范化后 location 逐字节一致 → 两次运行端点证据完全相等。
    assert _endpoint_locations(eps_lower) == _endpoint_locations(eps_upper)
    assert eps_lower  # 确有端点被抽出（否则相等是空对空的假成立）
    for e in eps_lower:
        for ev in e.evidences:
            assert ev.location == ev.location.lower()  # 全小写
            assert "\\" not in ev.location             # 正斜杠（跨 OS 确定）
            assert ev.location.startswith("sources/v/")
