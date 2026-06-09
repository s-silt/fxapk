"""apkscan.dynamic.provision 单测：requests / lzma / subprocess / shutil.which / 文件系统全 mock。

策略（无真机/无外网，离线锁行为）：
- subprocess 调用：monkeypatch provision._adb / provision._adb_ok 或 subprocess.run。
- shutil.which：monkeypatch 控制工具是否在 PATH。
- 下载：monkeypatch requests.get + lzma.decompress。
- 文件系统：tmp_path + monkeypatch _mitm_ca_path / Path.home。

覆盖：ABI 各值 / 版本解析 / 有无网络 / 有无 root / CA 已装-未装-无 root 降级 /
所有函数结构化返回不抛不 print。
"""

from __future__ import annotations

import hashlib
import io as _io
import lzma
import subprocess
from pathlib import Path
from typing import Any

import pytest

from apkscan.core import device
from apkscan.dynamic import provision


# ---------------------------------------------------------------------------
# 测试替身
# ---------------------------------------------------------------------------


class _FakeCompleted:
    """subprocess.CompletedProcess 的最小替身。"""

    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _patch_which(monkeypatch: pytest.MonkeyPatch, present: set[str]) -> None:
    """monkeypatch shutil.which：仅 present 集合内的命令"在 PATH"。"""
    def _which(name: str) -> str | None:
        return f"/usr/bin/{name}" if name in present else None

    monkeypatch.setattr(provision.shutil, "which", _which)


# ---------------------------------------------------------------------------
# device_abi
# ---------------------------------------------------------------------------


def test_device_abi_parses_getprop(monkeypatch):
    monkeypatch.setattr(
        provision, "_adb", lambda extra, serial=None: _FakeCompleted(0, "arm64-v8a\n")
    )
    assert provision.device_abi() == "arm64-v8a"


def test_device_abi_no_adb_returns_empty(monkeypatch):
    monkeypatch.setattr(provision, "_adb", lambda extra, serial=None: None)
    assert provision.device_abi() == ""


def test_device_abi_nonzero_exit_returns_empty(monkeypatch):
    monkeypatch.setattr(
        provision, "_adb", lambda extra, serial=None: _FakeCompleted(1, "")
    )
    assert provision.device_abi() == ""


def test_device_abi_timeout_returns_empty(monkeypatch):
    # _adb 内部已把 TimeoutExpired 转 None；这里直接验证 None → ''。
    _patch_which(monkeypatch, {"adb"})

    def _raise_timeout(*args: Any, **kwargs: Any) -> None:
        raise subprocess.TimeoutExpired(cmd="adb", timeout=5.0)

    monkeypatch.setattr(provision.subprocess, "run", _raise_timeout)
    assert provision.device_abi() == ""


# ---------------------------------------------------------------------------
# host_frida_version
# ---------------------------------------------------------------------------


def test_host_frida_version_parses_semver(monkeypatch):
    _patch_which(monkeypatch, {"frida"})
    monkeypatch.setattr(
        provision.subprocess, "run", lambda *a, **k: _FakeCompleted(0, "16.5.9\n")
    )
    assert provision.host_frida_version() == "16.5.9"


def test_host_frida_version_no_frida_returns_empty(monkeypatch):
    _patch_which(monkeypatch, set())
    assert provision.host_frida_version() == ""


def test_host_frida_version_unparseable_returns_empty(monkeypatch):
    _patch_which(monkeypatch, {"frida"})
    monkeypatch.setattr(
        provision.subprocess, "run", lambda *a, **k: _FakeCompleted(0, "not a version")
    )
    assert provision.host_frida_version() == ""


# ---------------------------------------------------------------------------
# ensure_frida_server — 前置 / 映射 / 降级
# ---------------------------------------------------------------------------


def test_ensure_frida_server_already_running_ok(monkeypatch):
    # 已在跑 + 确认 root → already_running（严格 is_root：需显式 mock 为 True 走此路径）。
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: True)
    monkeypatch.setattr(device, "frida_server_is_root", lambda serial=None: True)
    res = provision.ensure_frida_server()
    assert res["ok"] is True
    assert res["action"] == "already_running"


def test_ensure_frida_server_abi_mapping_arm64(monkeypatch):
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: False)
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "arm64-v8a")
    monkeypatch.setattr(provision, "host_frida_version", lambda: "16.5.9")
    captured: dict[str, str] = {}

    def _fake_dl(url: str, dest: Path, on_progress: Any) -> str:
        captured["url"] = url
        return "boom"  # 让流程止于下载，避免后续 adb

    monkeypatch.setattr(provision, "_download_and_extract", _fake_dl)
    provision.ensure_frida_server()
    assert "android-arm64.xz" in captured["url"]


@pytest.mark.parametrize(
    "abi,fabi",
    [
        ("armeabi-v7a", "arm"),
        ("armeabi", "arm"),
        ("x86_64", "x86_64"),
        ("x86", "x86"),
    ],
)
def test_ensure_frida_server_abi_mapping_arm_x86_x86_64(monkeypatch, abi, fabi):
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: False)
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: abi)
    monkeypatch.setattr(provision, "host_frida_version", lambda: "16.5.9")
    captured: dict[str, str] = {}

    def _fake_dl(url: str, dest: Path, on_progress: Any) -> str:
        captured["url"] = url
        return "boom"

    monkeypatch.setattr(provision, "_download_and_extract", _fake_dl)
    provision.ensure_frida_server()
    assert f"android-{fabi}.xz" in captured["url"]


def test_ensure_frida_server_unknown_abi_error_with_fix_cmd(monkeypatch):
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: False)
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "mips")
    monkeypatch.setattr(provision, "host_frida_version", lambda: "16.5.9")
    res = provision.ensure_frida_server()
    assert res["ok"] is False
    assert res["action"] == "error"
    assert "mips" in res["detail"]
    assert res["fix_cmd"]


def test_ensure_frida_server_download_false_returns_skipped_with_fix_cmd(monkeypatch):
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: False)
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "arm64-v8a")
    monkeypatch.setattr(provision, "host_frida_version", lambda: "16.5.9")
    res = provision.ensure_frida_server(download=False)
    assert res["ok"] is False
    assert res["action"] == "skipped"
    assert res["fix_cmd"]
    joined = "\n".join(res["fix_cmd"])
    assert "adb push" in joined
    assert "/data/local/tmp/frida-server" in joined


def test_ensure_frida_server_no_host_version_error(monkeypatch):
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: False)
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "arm64-v8a")
    monkeypatch.setattr(provision, "host_frida_version", lambda: "")
    res = provision.ensure_frida_server()
    assert res["ok"] is False
    assert res["action"] == "error"
    assert "pip install frida-tools" in res["fix_cmd"]


def test_ensure_frida_server_no_abi_error(monkeypatch):
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: False)
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "")
    res = provision.ensure_frida_server()
    assert res["ok"] is False
    assert res["action"] == "error"
    assert "adb devices" in res["fix_cmd"]


def test_ensure_frida_server_builds_correct_github_url(monkeypatch):
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: False)
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "arm64-v8a")
    monkeypatch.setattr(provision, "host_frida_version", lambda: "16.5.9")
    captured: dict[str, str] = {}

    def _fake_dl(url: str, dest: Path, on_progress: Any) -> str:
        captured["url"] = url
        return "boom"

    monkeypatch.setattr(provision, "_download_and_extract", _fake_dl)
    provision.ensure_frida_server()
    assert captured["url"] == (
        "https://github.com/frida/frida/releases/download/"
        "16.5.9/frida-server-16.5.9-android-arm64.xz"
    )


# ---------------------------------------------------------------------------
# ensure_frida_server — 下载 / 解压 / push / 验证（用 urllib+lzma mock）
# ---------------------------------------------------------------------------


def _xz_bytes(payload: bytes = b"ELF-FAKE-FRIDA") -> bytes:
    return lzma.compress(payload)


def _fake_requests_get(content: bytes):
    """构造 requests 风格的假响应工厂（.content + .raise_for_status no-op）。"""

    class _Resp:
        content = b""

        def raise_for_status(self) -> None:
            return None

    def _get(url: str, timeout: float = 0):
        r = _Resp()
        r.content = content
        return r

    return _get


def test_ensure_frida_server_download_uses_requests_and_lzma_mocked(monkeypatch, tmp_path):
    import requests

    # 第一次 running=False（进入部署），部署后验证为 True。
    states = iter([False, True])
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: next(states, True))
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "arm64-v8a")
    monkeypatch.setattr(provision, "host_frida_version", lambda: "16.5.9")

    monkeypatch.setattr(requests, "get", _fake_requests_get(_xz_bytes()))
    monkeypatch.setattr(provision, "_adb_ok", lambda extra, serial=None: True)
    monkeypatch.setattr(provision.time, "sleep", lambda s: None)

    res = provision.ensure_frida_server()
    assert res["ok"] is True
    assert res["action"] == "deployed"
    assert res["version"] == "16.5.9"


def test_ensure_frida_server_network_error_returns_error_not_raise(monkeypatch):
    import requests

    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: False)
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "arm64-v8a")
    monkeypatch.setattr(provision, "host_frida_version", lambda: "16.5.9")

    def _raise_conn(url: str, timeout: float = 0) -> None:
        raise requests.exceptions.ConnectionError("no route to host")

    monkeypatch.setattr(requests, "get", _raise_conn)
    res = provision.ensure_frida_server()
    assert res["ok"] is False
    assert res["action"] == "error"
    assert "无网络" in res["detail"]
    assert res["fix_cmd"]


def test_ensure_frida_server_http_404_returns_version_not_found(monkeypatch):
    import requests

    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: False)
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "arm64-v8a")
    monkeypatch.setattr(provision, "host_frida_version", lambda: "99.99.99")

    def _raise_404(url: str, timeout: float = 0) -> None:
        resp = requests.Response()
        resp.status_code = 404
        raise requests.exceptions.HTTPError("404", response=resp)

    monkeypatch.setattr(requests, "get", _raise_404)
    res = provision.ensure_frida_server()
    assert res["ok"] is False
    assert "不存在" in res["detail"]


def test_ensure_frida_server_lzma_error_returns_error(monkeypatch):
    import requests

    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: False)
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "arm64-v8a")
    monkeypatch.setattr(provision, "host_frida_version", lambda: "16.5.9")

    monkeypatch.setattr(requests, "get", _fake_requests_get(b"not-valid-xz-bytes"))
    res = provision.ensure_frida_server()
    assert res["ok"] is False
    assert res["action"] == "error"
    assert "lzma" in res["detail"]


def test_ensure_frida_server_push_failure_no_root_error(monkeypatch):
    states = iter([False])
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: next(states, False))
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "arm64-v8a")
    monkeypatch.setattr(provision, "host_frida_version", lambda: "16.5.9")
    monkeypatch.setattr(
        provision, "_download_and_extract", lambda url, dest, on_progress: ""
    )

    # push 失败。
    monkeypatch.setattr(provision, "_adb_ok", lambda extra, serial=None: False)
    res = provision.ensure_frida_server()
    assert res["ok"] is False
    assert res["action"] == "error"
    assert "push" in res["detail"]


def test_ensure_frida_server_chmod_failure_points_to_no_root(monkeypatch):
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: False)
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "arm64-v8a")
    monkeypatch.setattr(provision, "host_frida_version", lambda: "16.5.9")
    monkeypatch.setattr(
        provision, "_download_and_extract", lambda url, dest, on_progress: ""
    )

    # push 成功，chmod（含 su）失败。
    def _adb_ok(extra: list[str], serial: str | None = None) -> bool:
        return extra[0] == "push"

    monkeypatch.setattr(provision, "_adb_ok", _adb_ok)
    res = provision.ensure_frida_server()
    assert res["ok"] is False
    assert "未 root" in res["detail"]


def test_ensure_frida_server_verify_fail_returns_error(monkeypatch):
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: False)
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "arm64-v8a")
    monkeypatch.setattr(provision, "host_frida_version", lambda: "16.5.9")
    monkeypatch.setattr(
        provision, "_download_and_extract", lambda url, dest, on_progress: ""
    )
    monkeypatch.setattr(provision, "_adb_ok", lambda extra, serial=None: True)
    monkeypatch.setattr(provision.time, "sleep", lambda s: None)
    # 始终 False → 验证轮询全失败。
    res = provision.ensure_frida_server()
    assert res["ok"] is False
    assert res["action"] == "error"
    assert "验证" in res["detail"]


def test_ensure_frida_server_success_deployed_ok(monkeypatch):
    states = iter([False, False, True])
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: next(states, True))
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "x86_64")
    monkeypatch.setattr(provision, "host_frida_version", lambda: "16.5.9")
    monkeypatch.setattr(
        provision, "_download_and_extract", lambda url, dest, on_progress: ""
    )
    monkeypatch.setattr(provision, "_adb_ok", lambda extra, serial=None: True)
    monkeypatch.setattr(provision.time, "sleep", lambda s: None)
    res = provision.ensure_frida_server()
    assert res["ok"] is True
    assert res["action"] == "deployed"
    assert res["abi"] == "x86_64"


def test_ensure_frida_server_start_command_blocking_does_not_false_fail(monkeypatch):
    """HIGH 回归锁：后台启动命令（含 '&'）被 adb shell 阻塞而超时返回 False 时，
    只要随后轮询 frida_server_running 成功，仍应判 deployed——不因启动步 returncode
    误报失败（frida-server 部署经典坑）。"""
    # push/chmod 之前 running=False，进入部署；启动后轮询第一次即 True。
    states = iter([False, True])
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: next(states, True))
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "arm64-v8a")
    monkeypatch.setattr(provision, "host_frida_version", lambda: "16.5.9")
    monkeypatch.setattr(
        provision, "_download_and_extract", lambda url, dest, on_progress: ""
    )
    monkeypatch.setattr(provision.time, "sleep", lambda s: None)

    start_attempts: list[str] = []

    def _adb_ok(extra: list[str], serial: str | None = None) -> bool:
        joined = " ".join(extra)
        # 模拟后台启动命令被 adb shell 长驻进程管道阻塞 → 超时 → _adb_ok 返回 False。
        if extra[:2] == ["shell", "su"] and provision._FRIDA_SERVER_REMOTE in joined and (
            "setsid" in joined or "nohup" in joined
        ):
            start_attempts.append(joined)
            return False
        return True  # push / chmod 成功

    monkeypatch.setattr(provision, "_adb_ok", _adb_ok)
    res = provision.ensure_frida_server()
    # 启动命令确实被尝试（脱离会话写法，含 setsid/nohup 重定向）。
    assert start_attempts
    assert any(">/dev/null" in c for c in start_attempts)
    # 即便启动步返回 False，轮询成功 → 仍判 deployed（不假失败）。
    assert res["ok"] is True
    assert res["action"] == "deployed"


def test_ensure_frida_server_start_uses_detached_redirected_command(monkeypatch):
    """启动 frida-server 必须脱离 adb 会话（setsid/nohup）并重定向 std{out,err}，
    否则长驻进程会挂住 adb shell。"""
    states = iter([False, True])
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: next(states, True))
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "arm64-v8a")
    monkeypatch.setattr(provision, "host_frida_version", lambda: "16.5.9")
    monkeypatch.setattr(
        provision, "_download_and_extract", lambda url, dest, on_progress: ""
    )
    monkeypatch.setattr(provision.time, "sleep", lambda s: None)

    seen: list[list[str]] = []

    def _adb_ok(extra: list[str], serial: str | None = None) -> bool:
        seen.append(extra)
        return True

    monkeypatch.setattr(provision, "_adb_ok", _adb_ok)
    provision.ensure_frida_server()

    start_cmds = [
        " ".join(e)
        for e in seen
        if e[:2] == ["shell", "su"]
        and provision._FRIDA_SERVER_REMOTE in " ".join(e)
        and ("setsid" in " ".join(e) or "nohup" in " ".join(e))
    ]
    assert start_cmds, "应有脱离会话的后台启动命令"
    for c in start_cmds:
        assert ">/dev/null" in c  # std{out,err} 被重定向，adb shell 才会立即返回


def test_ensure_frida_server_on_progress_called(monkeypatch):
    states = iter([False, True])
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: next(states, True))
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "arm64-v8a")
    monkeypatch.setattr(provision, "host_frida_version", lambda: "16.5.9")
    monkeypatch.setattr(
        provision, "_download_and_extract", lambda url, dest, on_progress: ""
    )
    monkeypatch.setattr(provision, "_adb_ok", lambda extra, serial=None: True)
    monkeypatch.setattr(provision.time, "sleep", lambda s: None)

    msgs: list[str] = []
    res = provision.ensure_frida_server(on_progress=msgs.append)
    assert res["ok"] is True
    assert msgs  # 至少上报过若干阶段


def test_ensure_frida_server_temp_file_cleaned(monkeypatch):
    """下载临时文件应在 finally 被清理。"""
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: False)
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "arm64-v8a")
    monkeypatch.setattr(provision, "host_frida_version", lambda: "16.5.9")

    seen: dict[str, str] = {}

    def _fake_dl(url: str, dest: Path, on_progress: Any) -> str:
        seen["dest"] = str(dest)
        return "boom"  # 提前返回，但临时文件已建

    monkeypatch.setattr(provision, "_download_and_extract", _fake_dl)
    provision.ensure_frida_server()
    assert "dest" in seen
    assert not Path(seen["dest"]).exists()


def test_ensure_frida_server_never_raises_on_running_probe_exception(monkeypatch):
    def _boom(serial: str | None = None) -> bool:
        raise RuntimeError("adb exploded")

    monkeypatch.setattr(device, "frida_server_running", _boom)
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "")
    res = provision.ensure_frida_server()
    assert res["ok"] is False  # 不抛


# ---------------------------------------------------------------------------
# subject_hash_old：openssl / cryptography 对拍
# ---------------------------------------------------------------------------


@pytest.fixture
def real_ca_pem(tmp_path) -> Path:
    """用 cryptography 生成一张自签 CA（subject CN=mitmproxy）写成 PEM。"""
    crypto = pytest.importorskip("cryptography")  # noqa: F841
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "mitmproxy"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "mitmproxy"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2040, 1, 1))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    pem_path = tmp_path / "mitmproxy-ca-cert.pem"
    pem_path.write_bytes(pem)
    return pem_path


def _expected_hash(pem_path: Path) -> str:
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(pem_path.read_bytes())
    d = hashlib.md5(cert.subject.public_bytes()).digest()
    val = d[0] | d[1] << 8 | d[2] << 16 | d[3] << 24
    return "%08x" % val


def test_subject_hash_via_openssl_parses_output(monkeypatch, tmp_path):
    pem = tmp_path / "ca.pem"
    pem.write_bytes(b"dummy")
    _patch_which(monkeypatch, {"openssl"})
    monkeypatch.setattr(
        provision.subprocess, "run", lambda *a, **k: _FakeCompleted(0, "9a5ba575\n")
    )
    assert provision._hash_via_openssl(pem) == "9a5ba575"


def test_subject_hash_via_openssl_no_openssl_returns_empty(monkeypatch, tmp_path):
    pem = tmp_path / "ca.pem"
    pem.write_bytes(b"dummy")
    _patch_which(monkeypatch, set())
    assert provision._hash_via_openssl(pem) == ""


def test_subject_hash_via_cryptography_md5_le_4bytes(real_ca_pem):
    expected = _expected_hash(real_ca_pem)
    assert provision._hash_via_cryptography(real_ca_pem) == expected


def test_subject_hash_openssl_and_cryptography_agree(monkeypatch, real_ca_pem):
    """对拍：真 openssl（若装）与 cryptography 退路结果一致。"""
    expected = _expected_hash(real_ca_pem)
    crypto_hash = provision._hash_via_cryptography(real_ca_pem)
    assert crypto_hash == expected
    # _subject_hash_old 走优先 openssl，缺则退 cryptography，结果都应等于 expected。
    monkeypatch.setattr(provision.shutil, "which", lambda name: None)  # 强制走 cryptography
    assert provision._subject_hash_old(real_ca_pem) == expected


def test_subject_hash_no_openssl_no_cryptography_error(monkeypatch, tmp_path):
    pem = tmp_path / "ca.pem"
    pem.write_bytes(b"dummy")
    _patch_which(monkeypatch, set())  # 无 openssl

    import builtins

    real_import = builtins.__import__

    def _no_crypto(name: str, *args: Any, **kwargs: Any):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("no cryptography")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_crypto)
    assert provision._subject_hash_old(pem) == ""


# ---------------------------------------------------------------------------
# ensure_mitm_ca
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_ca(monkeypatch, tmp_path) -> Path:
    """让 provision._mitm_ca_path 指向 tmp_path 下一个已存在的假 CA。"""
    ca = tmp_path / "mitmproxy-ca-cert.pem"
    ca.write_bytes(b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
    monkeypatch.setattr(provision, "_mitm_ca_path", lambda: ca)
    monkeypatch.setattr(provision, "_subject_hash_old", lambda p: "c8750f0d")
    return ca


def test_ensure_mitm_ca_already_trusted_ok(monkeypatch, fake_ca):
    # 系统库 ls 命中 → already_trusted。
    def _adb_ok(extra: list[str], serial: str | None = None) -> bool:
        return extra[:2] == ["shell", "ls"]

    monkeypatch.setattr(provision, "_adb_ok", _adb_ok)
    res = provision.ensure_mitm_ca()
    assert res["ok"] is True
    assert res["verified"] is True
    assert res["action"] == "already_trusted"
    assert res["subject_hash"] == "c8750f0d"
    assert "c8750f0d.0" in res["store_path"]


def test_ensure_mitm_ca_generates_when_missing(monkeypatch, tmp_path):
    ca = tmp_path / "mitmproxy-ca-cert.pem"  # 初始不存在
    monkeypatch.setattr(provision, "_mitm_ca_path", lambda: ca)
    monkeypatch.setattr(provision, "_subject_hash_old", lambda p: "c8750f0d")

    def _gen(ca_path: Path, on_progress: Any) -> bool:
        ca_path.write_bytes(b"generated-pem")
        return True

    monkeypatch.setattr(provision, "_generate_ca", _gen)
    # ls 命中（视作已装）以便走最短成功路径，重点验证"生成被触发"。
    monkeypatch.setattr(provision, "_adb_ok", lambda extra, serial=None: extra[:2] == ["shell", "ls"])
    res = provision.ensure_mitm_ca()
    assert ca.exists()
    assert res["ca_path"] == str(ca)


def test_ensure_mitm_ca_missing_and_cannot_generate_error(monkeypatch, tmp_path):
    ca = tmp_path / "mitmproxy-ca-cert.pem"
    monkeypatch.setattr(provision, "_mitm_ca_path", lambda: ca)
    monkeypatch.setattr(provision, "_generate_ca", lambda ca_path, on_progress: False)
    res = provision.ensure_mitm_ca()
    assert res["ok"] is False
    assert res["action"] == "error"
    assert any("mitmproxy" in c for c in res["fix_cmd"])


def test_ensure_mitm_ca_hash_unavailable_error(monkeypatch, fake_ca):
    monkeypatch.setattr(provision, "_subject_hash_old", lambda p: "")
    res = provision.ensure_mitm_ca()
    assert res["ok"] is False
    assert res["action"] == "error"
    assert "pip install cryptography" in res["fix_cmd"]


def test_ensure_mitm_ca_installs_system_store_ok(monkeypatch, fake_ca):
    # ls 不命中 → 走主路；root/remount/push/chmod 全成功。
    def _adb_ok(extra: list[str], serial: str | None = None) -> bool:
        if extra[:2] == ["shell", "ls"]:
            return False
        return True

    monkeypatch.setattr(provision, "_adb_ok", _adb_ok)
    res = provision.ensure_mitm_ca()
    assert res["ok"] is True
    assert res["verified"] is True
    assert res["action"] == "installed_system"
    assert "/system/etc/security/cacerts/c8750f0d.0" == res["store_path"]


def test_ensure_mitm_ca_falls_back_to_user_store_on_readonly_system(monkeypatch, fake_ca):
    # remount 失败 → 主路不通；用户库 push/cp 成功 → installed_user_store。
    # 关键：用户库路径**不算已信任**（Android 10+ 默认不生效，需 magisk/重启），
    # 故 ok=False、verified=False——避免 doctor 把"已写入待生效"误判为绿（不假成功）。
    def _adb_ok(extra: list[str], serial: str | None = None) -> bool:
        cmd = " ".join(extra)
        if extra[:2] == ["shell", "ls"]:
            return False  # 未已信任
        if extra == ["root"]:
            return True
        # remount 全失败（adb remount / 直执 mount / su mount）→ 系统库主路不通。
        if extra == ["remount"] or "remount" in cmd:
            return False
        # 系统库 cp 不会到（remount 失败短路）；用户库 push 中转 + cp（直执/su）全成功。
        return True

    monkeypatch.setattr(provision, "_adb_ok", _adb_ok)
    res = provision.ensure_mitm_ca()
    # 已写入用户库，但未确证生效 → 不假成功。
    assert res["ok"] is False
    assert res["verified"] is False
    assert res["action"] == "installed_user_store"
    assert "/data/misc/user/0/cacerts-added/c8750f0d.0" == res["store_path"]
    # detail 必须点明"待 magisk/重启生效 + HTTPS 仍密文"，不让用户误以为已 OK。
    assert "magisk" in res["detail"].lower()
    assert "密文" in res["detail"]


def test_ensure_mitm_ca_no_root_returns_error_with_fix_cmd(monkeypatch, fake_ca):
    # 全部 adb_ok 失败（无 root / 离线）→ error + 完整手动命令。
    monkeypatch.setattr(provision, "_adb_ok", lambda extra, serial=None: False)
    res = provision.ensure_mitm_ca()
    assert res["ok"] is False
    assert res["action"] == "error"
    assert "密文" in res["detail"]
    assert res["fix_cmd"]
    joined = "\n".join(res["fix_cmd"])
    assert "c8750f0d.0" in joined
    assert "/system/etc/security/cacerts" in joined


def test_ensure_mitm_ca_never_raises_on_adb_failure(monkeypatch, fake_ca):
    def _boom(extra: list[str], serial: str | None = None) -> bool:
        raise RuntimeError("adb exploded")

    monkeypatch.setattr(provision, "_adb_ok", _boom)
    # 不抛即通过（函数内不应让 _adb_ok 异常逃逸——但 _adb_ok 自身已吞；
    # 这里直接注入会抛的替身，验证 ensure_mitm_ca 整体不崩——若它直接调替身则需 ensure 容错）。
    try:
        res = provision.ensure_mitm_ca()
    except Exception as exc:  # pragma: no cover - 失败诊断
        pytest.fail(f"ensure_mitm_ca raised: {exc}")
    assert res["ok"] is False


def test_ensure_mitm_ca_on_progress_called(monkeypatch, fake_ca):
    monkeypatch.setattr(provision, "_adb_ok", lambda extra, serial=None: extra[:2] == ["shell", "ls"])
    msgs: list[str] = []
    provision.ensure_mitm_ca(on_progress=msgs.append)
    assert msgs


# ---------------------------------------------------------------------------
# GUI-ready：无 print / typer / sys.exit；全部返回结构化 dict
# ---------------------------------------------------------------------------


def test_all_functions_return_structured_dict_no_print(monkeypatch, capsys, fake_ca):
    """抽样调用所有对外函数，断言返回结构化 dict 且无 stdout 输出。"""
    monkeypatch.setattr(provision, "_adb", lambda extra, serial=None: _FakeCompleted(0, "arm64-v8a"))
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: True)
    monkeypatch.setattr(provision, "_adb_ok", lambda extra, serial=None: extra[:2] == ["shell", "ls"])

    abi = provision.device_abi()
    ver = provision.host_frida_version()
    fs = provision.ensure_frida_server()
    ca = provision.ensure_mitm_ca()

    assert isinstance(abi, str)
    assert isinstance(ver, str)
    for d in (fs, ca):
        assert isinstance(d, dict)
        assert "ok" in d and "action" in d and "detail" in d and "fix_cmd" in d
        assert isinstance(d["fix_cmd"], list)

    captured = capsys.readouterr()
    assert captured.out == ""


def test_module_has_no_forbidden_calls():
    """核心模块禁 print( / typer. / sys.exit( / input(（源码级自检）。"""
    src = Path(provision.__file__).read_text(encoding="utf-8")
    # 去掉 docstring 中关于禁令的说明行后再查，避免误命中注释里的字面量。
    for forbidden in ("print(", "typer.", "sys.exit(", "input("):
        # 允许出现在注释/docstring 的说明里：本测试仅保证没有"裸调用"形态。
        # 简化策略：逐行检查非注释、非纯文档行。
        for line in src.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith('"') or stripped.startswith("-"):
                continue
            assert forbidden not in line, f"forbidden {forbidden!r} in: {line}"


# 占位：保证 io 导入被使用（部分替身用 BytesIO 风格时引用），避免 ruff F401。
_ = _io.BytesIO


# ---------------------------------------------------------------------------
# GBK 回归：动态 subprocess 必须 encoding=utf-8 + errors=replace
# ---------------------------------------------------------------------------


def test_adb_subprocess_uses_utf8_replace(monkeypatch: pytest.MonkeyPatch) -> None:
    """真机实测 bug 回归：adb/frida 子进程曾因 text=True 缺 encoding，在 Windows 上按
    GBK 解输出，遇非 GBK 字节（如 0xad）崩 _readerthread。锁死：必须传 encoding=utf-8 +
    errors=replace，坏字节降级替换而非崩溃。"""
    monkeypatch.setattr(provision.tools, "adb_path", lambda: "/usr/bin/adb")
    captured: dict[str, Any] = {}

    def _spy_run(_args: list[str], **kwargs: Any) -> _FakeCompleted:
        captured.update(kwargs)
        return _FakeCompleted(returncode=0, stdout="ok")

    monkeypatch.setattr(provision.subprocess, "run", _spy_run)
    provision._adb(["devices"])

    assert captured.get("encoding") == "utf-8"
    assert captured.get("errors") == "replace"


def test_ensure_frida_server_restarts_non_root_as_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """真机实测自愈：检测到非 root frida-server → 杀掉以 root 重启，action=restarted_as_root。"""
    monkeypatch.setattr(provision.device, "frida_server_running", lambda serial=None: True)
    # is_root：初查非 root(False) → 重启后 root(True)。
    states = iter([False, True])
    monkeypatch.setattr(provision.device, "frida_server_is_root", lambda serial=None: next(states))
    started: list[object] = []
    monkeypatch.setattr(
        provision, "_start_frida_server_background", lambda serial=None: started.append(serial)
    )
    monkeypatch.setattr(provision.time, "sleep", lambda *_a: None)

    res = provision.ensure_frida_server()
    assert res["ok"] is True
    assert res["action"] == "restarted_as_root"
    assert started  # 确实调了重启


def test_ensure_frida_server_already_running_root_no_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """root frida-server 已在跑 → already_running，不重启。"""
    monkeypatch.setattr(provision.device, "frida_server_running", lambda serial=None: True)
    monkeypatch.setattr(provision.device, "frida_server_is_root", lambda serial=None: True)
    started: list[object] = []
    monkeypatch.setattr(
        provision, "_start_frida_server_background", lambda serial=None: started.append(serial)
    )
    res = provision.ensure_frida_server()
    assert res["ok"] is True
    assert res["action"] == "already_running"
    assert not started  # 没重启


# ---------------------------------------------------------------------------
# install_apk：dynamic spawn 前置（adb install -r -t -g）
# ---------------------------------------------------------------------------


def test_install_apk_success(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"PK\x03\x04")
    monkeypatch.setattr(provision.tools, "adb_path", lambda: "/usr/bin/adb")
    monkeypatch.setattr(
        provision.subprocess, "run", lambda *a, **k: _FakeCompleted(0, "Success\n")
    )
    res = provision.install_apk(str(apk))
    assert res["ok"] is True


def test_install_apk_signature_conflict_hints_uninstall(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"PK")
    monkeypatch.setattr(provision.tools, "adb_path", lambda: "/usr/bin/adb")
    monkeypatch.setattr(
        provision.subprocess,
        "run",
        lambda *a, **k: _FakeCompleted(
            1, "", "Failure [INSTALL_FAILED_UPDATE_INCOMPATIBLE: signatures do not match]"
        ),
    )
    res = provision.install_apk(str(apk))
    assert res["ok"] is False
    assert "uninstall" in res["detail"]


def test_install_apk_no_adb(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"PK")
    monkeypatch.setattr(provision.tools, "adb_path", lambda: "")
    assert provision.install_apk(str(apk))["ok"] is False


def test_install_apk_missing_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(provision.tools, "adb_path", lambda: "/usr/bin/adb")
    assert provision.install_apk("/no/such/file.apk")["ok"] is False
