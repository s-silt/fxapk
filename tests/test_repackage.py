"""apkscan.dynamic.repackage 单测：去壳重打包（zip 替 DEX + 重签 + 装回 + 四联判活 + 降级）。

铁律呼应：返回 DynamicResult 五字段、绝不抛、subprocess 文件重定向不用 PIPE。
全 mock：不碰真机、不调真 apksigner/zipalign/keytool、不开真 frida。
"""

from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path
from typing import Any

import pytest

from apkscan.dynamic import STATUS_DONE, STATUS_ERROR, STATUS_SKIPPED
from apkscan.dynamic import repackage


def _make_apk(path: Path, *, dex: bytes = b"dex\n035\x00orig") -> None:
    """造一个最小原 APK zip：manifest + classes.dex + lib + 旧签名。"""
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", b"<manifest/>")
        z.writestr("classes.dex", dex)
        z.writestr("lib/arm64-v8a/libx.so", b"\x7fELF")
        z.writestr("META-INF/CERT.RSA", b"oldsig")
        z.writestr("META-INF/MANIFEST.MF", b"old")


def _make_dump(out_dir: Path, dexes: list[bytes]) -> None:
    dump = out_dir / "dump"
    dump.mkdir(parents=True, exist_ok=True)
    for i, d in enumerate(dexes):
        (dump / f"d{i}.dex").write_bytes(d)


def _caps_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(repackage.tools, "has_apksigner", lambda: True)
    monkeypatch.setattr(repackage.tools, "has_zipalign", lambda: True)
    monkeypatch.setattr(repackage.device, "has_device", lambda: True)
    monkeypatch.setattr(repackage, "_resolve_package_name", lambda p: "com.fraud.app")
    monkeypatch.setattr(repackage.device, "force_stop_app", lambda p, serial=None: None)


def _patch_build_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    """zipalign / 重签 桩成功（创建目标文件 + 返回 None）。"""
    monkeypatch.setattr(repackage, "_zipalign", lambda s, d, pb: (d.write_bytes(b"aligned"), None)[1])
    monkeypatch.setattr(
        repackage, "_ensure_keystore_and_sign", lambda s, d, pb: (d.write_bytes(b"signed"), None)[1]
    )


def _patch_provision(monkeypatch: pytest.MonkeyPatch, *, install_ok: bool = True) -> list[str]:
    """桩 provision.uninstall_app/install_apk，记录调用顺序。"""
    import apkscan.dynamic.provision as prov

    order: list[str] = []
    monkeypatch.setattr(prov, "uninstall_app", lambda p, serial=None: (order.append("uninstall"), {"ok": True})[1])
    monkeypatch.setattr(
        prov, "install_apk",
        lambda p, serial=None: (order.append("install"), {"ok": install_ok, "detail": "Success" if install_ok else "signatures do not match"})[1],
    )
    return order


# ---------------------------------------------------------------------------
# 能力 / 输入校验
# ---------------------------------------------------------------------------


def test_missing_tools_skipped(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(repackage.tools, "has_apksigner", lambda: False)
    monkeypatch.setattr(repackage.tools, "has_zipalign", lambda: True)
    monkeypatch.setattr(repackage.device, "has_device", lambda: True)
    res = repackage.run("x.apk", out=str(tmp_path))
    assert res["status"] == STATUS_SKIPPED
    assert "apksigner" in res["reason"]
    assert res["playbook"]


def test_bad_package_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _caps_ok(monkeypatch)
    monkeypatch.setattr(repackage, "_resolve_package_name", lambda p: "bad name!")
    res = repackage.run("x.apk", out=str(tmp_path))
    assert res["status"] == STATUS_ERROR
    assert "包名" in res["reason"]


def test_dump_empty_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _caps_ok(monkeypatch)
    apk = tmp_path / "s.apk"
    _make_apk(apk)
    res = repackage.run(str(apk), out=str(tmp_path / "out"))  # 无 dump 目录
    assert res["status"] == STATUS_ERROR
    assert "脱壳 DEX" in res["reason"]


def test_dex_all_invalid_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _caps_ok(monkeypatch)
    apk = tmp_path / "s.apk"
    _make_apk(apk)
    out = tmp_path / "out"
    _make_dump(out, [b"NOT a dex", b"also not"])  # 无 dex magic
    res = repackage.run(str(apk), out=str(out))
    assert res["status"] == STATUS_ERROR
    assert "无法可靠重组" in res["reason"]


# ---------------------------------------------------------------------------
# 成功 / 构建失败 / 降级
# ---------------------------------------------------------------------------


def test_repackage_success_done_uninstall_before_install(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _caps_ok(monkeypatch)
    _patch_build_ok(monkeypatch)
    monkeypatch.setattr(repackage, "_verdict_app_alive", lambda pkg, ser: (True, "存活且可附"))
    order = _patch_provision(monkeypatch, install_ok=True)

    apk = tmp_path / "s.apk"
    _make_apk(apk)
    out = tmp_path / "out"
    _make_dump(out, [b"dex\n035\x00aaaa", b"dex\n035\x00bb"])

    res = repackage.run(str(apk), out=str(out))
    assert res["status"] == STATUS_DONE
    assert res["artifacts"] and res["artifacts"][0].endswith("-deshelled.apk")
    assert order == ["uninstall", "install"]  # 先卸原包再装去壳包（签名必变）


def test_zipalign_fail_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _caps_ok(monkeypatch)
    monkeypatch.setattr(repackage, "_zipalign", lambda s, d, pb: "zipalign 失败（rc=1）")
    apk = tmp_path / "s.apk"
    _make_apk(apk)
    out = tmp_path / "out"
    _make_dump(out, [b"dex\n035\x00aaaa"])
    res = repackage.run(str(apk), out=str(out))
    assert res["status"] == STATUS_ERROR
    assert "zipalign" in res["reason"]


def test_sign_fail_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _caps_ok(monkeypatch)
    monkeypatch.setattr(repackage, "_zipalign", lambda s, d, pb: (d.write_bytes(b"a"), None)[1])
    monkeypatch.setattr(repackage, "_ensure_keystore_and_sign", lambda s, d, pb: "apksigner 重签失败（rc=1）")
    apk = tmp_path / "s.apk"
    _make_apk(apk)
    out = tmp_path / "out"
    _make_dump(out, [b"dex\n035\x00aaaa"])
    res = repackage.run(str(apk), out=str(out))
    assert res["status"] == STATUS_ERROR
    assert "apksigner" in res["reason"]


def test_install_fail_degrades_to_error_and_reinstalls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _caps_ok(monkeypatch)
    _patch_build_ok(monkeypatch)
    _patch_provision(monkeypatch, install_ok=False)  # 去壳包装不上
    degraded: list[bool] = []
    monkeypatch.setattr(repackage, "_degrade_reinstall_original", lambda *a: degraded.append(True))

    apk = tmp_path / "s.apk"
    _make_apk(apk)
    out = tmp_path / "out"
    _make_dump(out, [b"dex\n035\x00aaaa"])
    res = repackage.run(str(apk), out=str(out))
    assert res["status"] == STATUS_ERROR
    assert degraded == [True]  # 已尝试重装原包供 capture 兜底


def test_verdict_fail_degrades_to_skipped_and_reinstalls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _caps_ok(monkeypatch)
    _patch_build_ok(monkeypatch)
    _patch_provision(monkeypatch, install_ok=True)
    monkeypatch.setattr(repackage, "_verdict_app_alive", lambda pkg, ser: (False, "进程秒退"))
    degraded: list[bool] = []
    monkeypatch.setattr(repackage, "_degrade_reinstall_original", lambda *a: degraded.append(True))

    apk = tmp_path / "s.apk"
    _make_apk(apk)
    out = tmp_path / "out"
    _make_dump(out, [b"dex\n035\x00aaaa"])
    res = repackage.run(str(apk), out=str(out))
    assert res["status"] == STATUS_SKIPPED  # 装上但起不来 → 降级（绝不报 done）
    assert "秒退" in res["reason"]
    assert degraded == [True]


# ---------------------------------------------------------------------------
# 纯函数：DEX 映射 / zip 替换 / subprocess 范式
# ---------------------------------------------------------------------------


def test_map_dump_to_classes_biggest_is_main(tmp_path: Path) -> None:
    big = tmp_path / "big.dex"
    big.write_bytes(b"dex\n035\x00" + b"x" * 100)
    small = tmp_path / "small.dex"
    small.write_bytes(b"dex\n035\x00" + b"y" * 10)
    mapping = repackage._map_dump_to_classes([small, big])
    assert mapping is not None
    assert mapping[big] == "classes.dex"  # 最大者作主 classes.dex
    assert mapping[small] == "classes2.dex"


def test_map_dump_to_classes_none_when_no_valid_dex(tmp_path: Path) -> None:
    bad = tmp_path / "x.dex"
    bad.write_bytes(b"not a dex")
    assert repackage._map_dump_to_classes([bad]) is None


def test_replace_dex_in_zip_swaps_dex_and_drops_old_sig(tmp_path: Path) -> None:
    base = tmp_path / "base.apk"
    _make_apk(base, dex=b"dex\n035\x00ORIGINAL")
    new_dex = tmp_path / "new.dex"
    new_dex.write_bytes(b"dex\n035\x00DESHELLED")
    out = tmp_path / "out.apk"
    repackage._replace_dex_in_zip(base, {new_dex: "classes.dex"}, out)
    with zipfile.ZipFile(out, "r") as z:
        names = z.namelist()
        assert z.read("classes.dex") == b"dex\n035\x00DESHELLED"  # DEX 被替换
        assert "lib/arm64-v8a/libx.so" in names  # 资源/lib 保留
        assert not any(n.startswith("META-INF/") and n.lower().endswith((".rsa", ".mf")) for n in names)  # 旧签名删除


def test_run_tool_no_pipe_has_timeout_stdin_devnull(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """回归：外部工具 subprocess 绝不用 PIPE（Java 孙进程持管道致超时卡死），须文件重定向+timeout+stdin=DEVNULL。"""
    seen: dict[str, Any] = {}

    class _FakeProc:
        returncode = 0

    def _fake_run(args: list[str], **kwargs: Any) -> _FakeProc:
        seen["kwargs"] = kwargs
        return _FakeProc()

    monkeypatch.setattr(repackage.subprocess, "run", _fake_run)
    rc, _tail = repackage._run_tool(["apksigner", "--version"])
    assert rc == 0
    kw = seen["kwargs"]
    assert not kw.get("capture_output")
    assert kw.get("stdout") not in (None, subprocess.PIPE)  # 重定向到文件
    assert kw.get("stderr") == subprocess.STDOUT
    assert kw.get("stdin") == subprocess.DEVNULL
    assert kw.get("timeout") == repackage._TOOL_TIMEOUT
