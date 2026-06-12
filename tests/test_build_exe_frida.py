"""build_exe._ensure_frida_servers 轻测：mock urllib + 版本口径 + 缓存/失败处理。

只覆盖打包侧"下载各 ABI frida-server-.xz 到 .frida_servers/"的纯逻辑：
- 版本取 provision.host_frida_version()（同口径）。
- 全 4 个 ABI 都下；保持 .xz 压缩态（直接写 urlopen 返回的字节）。
- 已存在则跳过（缓存）；单 ABI 失败仅告警跳过、不抛、不阻断其余。
- 取不到版本时整体跳过、不触网。
不真打包、不真联网（urllib.request.urlopen 全 mock）。
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any

import pytest

build_exe = importlib.import_module("build_exe")


def test_ensure_frida_servers_downloads_all_abis_keeps_xz(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """取到版本 → 4 个 ABI 各下一次，写入的就是 urlopen 返回的原始 .xz 字节（不解压）。"""
    monkeypatch.setattr(build_exe, "_FRIDA_DIR", tmp_path)
    monkeypatch.setattr(build_exe, "_build_frida_version", lambda: "17.11.0")

    urls: list[str] = []

    class _Resp:
        def __init__(self, url: str) -> None:
            self._url = url

        def read(self) -> bytes:
            return b"XZBYTES:" + self._url.encode()

        def __enter__(self) -> "_Resp":
            return self

        def __exit__(self, *a: Any) -> None:
            return None

    def _fake_urlopen(url: str, timeout: float = 0) -> _Resp:
        urls.append(url)
        return _Resp(url)

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
    build_exe._ensure_frida_servers()

    # 4 个 ABI 各一次，文件名含 ver + 对应 abi，内容是原始 .xz 字节（未解压）。
    for abi in build_exe._FRIDA_ABIS:
        f = tmp_path / f"frida-server-17.11.0-android-{abi}.xz"
        assert f.exists()
        assert f.read_bytes().startswith(b"XZBYTES:")
    assert len(urls) == len(build_exe._FRIDA_ABIS)


def test_ensure_frida_servers_skips_cached(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """已存在的 ABI 跳过下载（缓存），仅下缺的。"""
    monkeypatch.setattr(build_exe, "_FRIDA_DIR", tmp_path)
    monkeypatch.setattr(build_exe, "_build_frida_version", lambda: "17.11.0")
    # 预置 arm64 缓存。
    (tmp_path / "frida-server-17.11.0-android-arm64.xz").write_bytes(b"cached")

    urls: list[str] = []

    class _Resp:
        def read(self) -> bytes:
            return b"new"

        def __enter__(self) -> "_Resp":
            return self

        def __exit__(self, *a: Any) -> None:
            return None

    def _fake_urlopen(url: str, timeout: float = 0) -> _Resp:
        urls.append(url)
        return _Resp()

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
    build_exe._ensure_frida_servers()

    # arm64 没重下（缓存保留），其余 3 个下了。
    assert (tmp_path / "frida-server-17.11.0-android-arm64.xz").read_bytes() == b"cached"
    assert not any("arm64.xz" in u for u in urls)
    assert len(urls) == len(build_exe._FRIDA_ABIS) - 1


def test_ensure_frida_servers_single_abi_failure_does_not_abort(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """单 ABI 下载失败仅跳过、不抛；其余 ABI 照常下载。"""
    monkeypatch.setattr(build_exe, "_FRIDA_DIR", tmp_path)
    monkeypatch.setattr(build_exe, "_build_frida_version", lambda: "17.11.0")

    class _Resp:
        def read(self) -> bytes:
            return b"ok"

        def __enter__(self) -> "_Resp":
            return self

        def __exit__(self, *a: Any) -> None:
            return None

    def _fake_urlopen(url: str, timeout: float = 0) -> _Resp:
        if "x86_64" in url:
            raise OSError("network down for x86_64")
        return _Resp()

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
    # 不抛。
    build_exe._ensure_frida_servers()

    # x86_64 缺，其余 3 个有。
    assert not (tmp_path / "frida-server-17.11.0-android-x86_64.xz").exists()
    for abi in ("arm64", "x86", "arm"):
        assert (tmp_path / f"frida-server-17.11.0-android-{abi}.xz").exists()


def test_ensure_frida_servers_no_version_skips_without_network(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """取不到 frida 版本 → 整体跳过，绝不触网（urlopen 一旦被调即失败）。"""
    monkeypatch.setattr(build_exe, "_FRIDA_DIR", tmp_path)
    monkeypatch.setattr(build_exe, "_build_frida_version", lambda: "")

    def _boom(*a: Any, **k: Any) -> None:
        raise AssertionError("无版本时不应触网")

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    build_exe._ensure_frida_servers()  # 不抛、不下载
    assert not list(tmp_path.glob("*.xz"))
