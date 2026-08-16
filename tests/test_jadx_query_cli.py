"""P2-D1：`fxapk jadx usage` / `fxapk jadx callpath` 只读查询子命令。红态契约。

真入口 = CliRunner。两个子命令都只引用已建索引，**绝不跑 jadx**（run_owned 零调用锁死）。
输出 JSON；空结果显式且带「空≠不存在/不可达」caveat；load 三态原样透出。
设计见本地 specs §P2-D1。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkscan import cli
from apkscan.core.jadx_index import (
    DexInput,
    DexRole,
    IndexBuildResult,
    JadxIndexManifest,
    JadxIndexStore,
    Limits,
    build_key_material,
    derive_index_key,
    scan_java_sources,
    verify_dex_inputs,
)

runner = CliRunner()

_OPTS = "sha256:" + "cd" * 32
_NEEDLE = "https://cfg-host.example/api"
_JAVA = {
    "com/x/Alpha.java": (
        "class Alpha {\n"
        "    void start() {\n"
        "        target();\n"
        "    }\n"
        "    void target() {\n"
        f'        String u = "{_NEEDLE}";\n'
        "    }\n"
        "}\n"
    ),
}


def _build_index(tmp_path: Path) -> tuple[Path, str]:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    dex = src / "classes.dex"
    dex.write_bytes(b"dex-q")
    digest = "sha256:" + hashlib.sha256(dex.read_bytes()).hexdigest()
    lineage = verify_dex_inputs(
        src,
        [DexInput(role=DexRole.APK_DEX, ordinal=0, source_label="apk",
                  relative_path="classes.dex", declared_digest=digest)],
    )
    key = derive_index_key(lineage, "1.5.2", _OPTS)
    manifest = JadxIndexManifest(
        index_key=key, key_material=build_key_material(lineage, "1.5.2", _OPTS),
        dex_lineage=lineage, jadx_version="1.5.2", options_digest=_OPTS,
    )
    java_root = tmp_path / "java"
    for rel, content in _JAVA.items():
        target = java_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    scan = scan_java_sources(java_root, [_NEEDLE], lineage=lineage[0], limits=Limits())
    store = JadxIndexStore(tmp_path / "cache")
    built = store.build_index(src, manifest, scan=scan)
    assert isinstance(built, IndexBuildResult), built
    return tmp_path / "cache", key


def _run(args: list[str]) -> tuple[int, dict | None]:
    result = runner.invoke(cli.app, args)
    try:
        return result.exit_code, json.loads(result.stdout)
    except ValueError:
        return result.exit_code, None


# ---------------------------------------------------------------------------
# usage
# ---------------------------------------------------------------------------


def test_usage_hits_shape(tmp_path: Path) -> None:
    """★命中列表：路径/行/列/digest 形态，绝不回显源码或查询值本身之外的内容。"""
    cache_root, key = _build_index(tmp_path)
    code, data = _run(
        ["jadx", "usage", _NEEDLE,
         "--jadx-cache-root", str(cache_root), "--jadx-index", key]
    )
    assert code == 0 and data is not None
    assert data["status"] == "ok"
    assert data["coverage"] in ("complete", "partial")
    hits = data["hits"]
    assert hits, "postings 里有该值，必须命中"
    hit = hits[0]
    assert hit["path"] == "com/x/Alpha.java"
    assert isinstance(hit["line"], int) and hit["line"] >= 1
    assert isinstance(hit["column"], int) and hit["column"] >= 1
    assert hit["value_digest"].startswith("sha256:")
    assert hit["ownership"] == "unknown"
    # lineage 是逻辑身份，不含路径。
    assert hit["lineage"]["role"] == "apk_dex"


def test_usage_empty_hits_explicit_with_caveat(tmp_path: Path) -> None:
    """★空结果显式 {"hits": []} + 「空≠不存在」稳定 caveat code。"""
    cache_root, key = _build_index(tmp_path)
    code, data = _run(
        ["jadx", "usage", "value-not-indexed",
         "--jadx-cache-root", str(cache_root), "--jadx-index", key]
    )
    assert code == 0 and data is not None
    assert data["status"] == "ok"
    assert data["hits"] == []
    assert any(c["code"] == "empty_is_not_absence" for c in data["caveats"])


def test_usage_load_miss_and_bad_syntax(tmp_path: Path) -> None:
    """load 三态透出：合法 key 无索引 → status=miss + 稳定 reason（exit 0，机器可判）；
    key 语法非法 → exit 2（语法关，不碰文件系统）。"""
    (tmp_path / "cache").mkdir(exist_ok=True)
    code, data = _run(
        ["jadx", "usage", "x",
         "--jadx-cache-root", str(tmp_path / "cache"), "--jadx-index", "e" * 64]
    )
    assert code == 0 and data is not None
    assert data["status"] == "miss"
    assert all(ch.islower() or ch.isdigit() or ch == "_" for ch in data["reason"])

    result = runner.invoke(
        cli.app,
        ["jadx", "usage", "x",
         "--jadx-cache-root", str(tmp_path / "cache"), "--jadx-index", "NOT-HEX"],
    )
    assert result.exit_code == 2


def _install_process_bombs(monkeypatch: pytest.MonkeyPatch) -> None:
    """锁死全部子进程启动入口——只读查询一个都不许碰。"""
    import os as _os
    import subprocess as _subprocess

    from apkscan.core import proctree

    def _boom(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise AssertionError("只读查询绝不允许启动子进程")

    monkeypatch.setattr(proctree, "run_owned", _boom)
    monkeypatch.setattr(_subprocess, "Popen", _boom)
    monkeypatch.setattr(_os, "system", _boom)


def test_usage_never_runs_jadx(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★只读承诺：查询全程零子进程。炸弹在夹具建完索引**之后**装——
    证明的是查询路径干净，不被夹具路径混淆。"""
    cache_root, key = _build_index(tmp_path)
    _install_process_bombs(monkeypatch)
    code, data = _run(
        ["jadx", "usage", _NEEDLE,
         "--jadx-cache-root", str(cache_root), "--jadx-index", key]
    )
    assert code == 0 and data is not None and data["status"] == "ok"


def test_callpath_never_runs_jadx(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """callpath 同款只读承诺锁。"""
    cache_root, key = _build_index(tmp_path)
    _install_process_bombs(monkeypatch)
    code, data = _run(
        ["jadx", "callpath", "Alpha#start/0", "Alpha#target/0",
         "--jadx-cache-root", str(cache_root), "--jadx-index", key]
    )
    assert code == 0 and data is not None and data["status"] == "ok"


def test_output_hygiene_no_source_no_host_paths(tmp_path: Path) -> None:
    """★输出卫生：查询原值、Java 源码行、宿主路径（cache root/盘符）都不得出现在
    完整 stdout 里——hits 只带 digest 与索引内相对路径。"""
    cache_root, key = _build_index(tmp_path)
    result = runner.invoke(
        cli.app,
        ["jadx", "usage", _NEEDLE,
         "--jadx-cache-root", str(cache_root), "--jadx-index", key],
    )
    assert result.exit_code == 0
    out = result.stdout
    assert _NEEDLE not in out  # 原值绝不回显（只有 digest）
    assert "String u =" not in out  # 源码行绝不回显
    for host_marker in (str(tmp_path), str(tmp_path).replace("\\", "\\\\")):
        assert host_marker not in out  # 宿主路径（含 JSON 转义形态）绝不出现


# ---------------------------------------------------------------------------
# callpath
# ---------------------------------------------------------------------------


def test_callpath_paths_shape(tmp_path: Path) -> None:
    """★路径列表：节点/边定位/resolution/limits 回显。"""
    cache_root, key = _build_index(tmp_path)
    code, data = _run(
        ["jadx", "callpath", "Alpha#start/0", "Alpha#target/0",
         "--jadx-cache-root", str(cache_root), "--jadx-index", key]
    )
    assert code == 0 and data is not None
    assert data["status"] == "ok"
    paths = data["paths"]
    assert paths, "start→target 有静态调用边，必须有路径"
    path = paths[0]
    assert len(path["nodes"]) == 2
    (edge,) = path["edges"]
    assert edge["caller_path"] == "com/x/Alpha.java"
    assert edge["resolution"] in ("unique", "ambiguous")
    assert isinstance(edge["line"], int) and edge["line"] >= 1
    # limits 回显（机器可读，读的人知道结果是 bounded 的）。
    limits = data["limits"]
    assert set(limits) == {"max_depth", "max_paths", "max_visited"}


def test_callpath_empty_is_not_unreachable(tmp_path: Path) -> None:
    """★空结果 ≠ 不可达：反向查询 paths=[] + 稳定 caveat code。"""
    cache_root, key = _build_index(tmp_path)
    code, data = _run(
        ["jadx", "callpath", "Alpha#target/0", "Alpha#start/0",
         "--jadx-cache-root", str(cache_root), "--jadx-index", key]
    )
    assert code == 0 and data is not None
    assert data["status"] == "ok"
    assert data["paths"] == []
    assert any(c["code"] == "no_path_is_not_unreachable" for c in data["caveats"])


def test_callpath_unavailable_reason_folded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """CacheUnavailable 透出 + 伪造 reason 带路径 → 折叠为稳定码。"""
    from apkscan.core.jadx_index import CacheUnavailable

    cache_root, key = _build_index(tmp_path)
    monkeypatch.setattr(
        JadxIndexStore, "load_index",
        lambda self, k: CacheUnavailable(r"C:\evil\p"),
    )
    code, data = _run(
        ["jadx", "callpath", "Alpha#start/0", "Alpha#target/0",
         "--jadx-cache-root", str(cache_root), "--jadx-index", key]
    )
    assert code == 0 and data is not None
    assert data["status"] == "unavailable"
    assert "evil" not in json.dumps(data)
    assert all(ch.islower() or ch.isdigit() or ch == "_" for ch in data["reason"])
