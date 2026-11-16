"""发版前对已构建 wheel 跑一遍用户会走的离线路径。

在**已装好该 wheel 的干净环境**里执行（用 ``python -I`` 隔离源码树）::

    /tmp/smoke/bin/python -I tools/release_smoke.py --expect-version 1.27.1

步骤：版本核对 → 合成 APK 离线分析 → digest → 证据打包 → 校验 → 损坏副本校验必须非零。
只用标准库造合成夹具，不联网、不碰设备。任一步失败即非零退出，发版流程据此不上传。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def _fxapk() -> str:
    exe = shutil.which("fxapk", path=str(Path(sys.executable).parent))
    if exe is None:
        raise SystemExit("当前环境没有 fxapk 命令")
    return exe


def _run(args: list[str], *, expect_zero: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if expect_zero and proc.returncode != 0:
        raise SystemExit(f"命令失败（{proc.returncode}）：{args}\n{proc.stderr[-2000:]}")
    return proc


def _synthetic_apk(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", '<manifest package="com.example.synthetic"/>')
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 200)
        zf.writestr("assets/config.json", '{"api":"https://api.example.com/v1"}')


def _corrupt_first_member(src: Path, dst: Path) -> None:
    data = bytearray(src.read_bytes())
    with zipfile.ZipFile(src) as zf:
        info = zf.infolist()[0]
    offset = info.header_offset + 30 + len(info.filename.encode("utf-8")) + len(info.extra) + 1
    data[offset] ^= 0xFF
    dst.write_bytes(bytes(data))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect-version", required=True)
    ns = parser.parse_args(argv)

    import importlib.util

    import fxapk

    if Path(fxapk.__file__).resolve().is_relative_to(Path(__file__).resolve().parents[1]):
        raise SystemExit("fxapk 来自源码树而不是已安装的 wheel")
    if importlib.util.find_spec("apkscan") is not None:
        raise SystemExit("wheel 仍带有 apkscan 导入包")
    fxapk = _fxapk()
    if shutil.which("apkscan", path=str(Path(sys.executable).parent)):
        raise SystemExit("wheel 仍注册了 apkscan 命令别名")

    version = _run([fxapk, "--version"]).stdout.strip()
    if ns.expect_version not in version.split():
        raise SystemExit(f"版本不符：期望 {ns.expect_version}，实际 {version!r}")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        apk = root / "synthetic.apk"
        _synthetic_apk(apk)
        out = root / "out"
        _run([fxapk, "analyze", str(apk), "--offline", "--out", str(out)])
        report_path = out / "synthetic.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if report["meta"].get("sample_sha256") != hashlib.sha256(apk.read_bytes()).hexdigest():
            raise SystemExit("报告的 sample_sha256 与合成 APK 不符")
        _run([fxapk, "digest", str(report_path)])

        archive = root / "evidence.zip"
        _run([fxapk, "evidence", "pack", str(out), "--out", str(archive)])
        verified = _run([fxapk, "evidence", "verify", str(archive)])
        if json.loads(verified.stdout.strip().splitlines()[-1]).get("state") != "verified":
            raise SystemExit(f"证据校验未通过：{verified.stdout[-500:]}")

        bad = root / "evidence-corrupt.zip"
        _corrupt_first_member(archive, bad)
        rejected = _run([fxapk, "evidence", "verify", str(bad)], expect_zero=False)
        if rejected.returncode == 0:
            raise SystemExit("损坏的证据归档通过了校验")

    print(f"release smoke OK：{version}；损坏归档退出码 {rejected.returncode}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
