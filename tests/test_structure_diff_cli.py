"""P2-B：JADX 结构 diff 进 ``fxapk diff``（三参数齐备、只吃 report.json、fail-open）。

先于实现编写（红态契约）。真入口 = CliRunner 调 ``fxapk diff``。
设计见本地 docs/superpowers/specs/2026-08-16-p2-wiring-design.md §P2-B（不入 git）。

关键契约：
- 提供任一 index 参数 → 三参数（--jadx-cache-root/--jadx-index-old/--jadx-index-new）
  必须齐备，缺一拒绝；
- 提供 index 参数时两个操作数必须是 report.json——操作数为 APK 即拒，且**技术上**
  不得进入分析路径（"结构分支绝不跑 jadx"要为真，不是措辞上为真）；
- key 先按 hex64 语法校验再碰文件系统；
- 索引缺失/损坏/不可用 → structure_diff.status="unavailable" + 稳定 reason，
  report 级 diff 照常输出（fail-open）；
- "absence" 语义 = 「索引覆盖内未观察到」，绝非「不存在」（caveat 稳定 code 承载）。
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

_OPTS = "sha256:" + "ab" * 32


def _build_real_index(
    tmp_path: Path, tag: str, java_files: dict[str, str]
) -> tuple[Path, str]:
    """构造一份可 fail-closed 加载的真索引（单 apk_dex lineage + 结构扫描）。"""
    src = tmp_path / f"src-{tag}"
    src.mkdir(parents=True, exist_ok=True)
    dex = src / "classes.dex"
    dex.write_bytes(b"dex-" + tag.encode())
    digest = "sha256:" + hashlib.sha256(dex.read_bytes()).hexdigest()
    inputs = [
        DexInput(
            role=DexRole.APK_DEX,
            ordinal=0,
            source_label="apk",
            relative_path="classes.dex",
            declared_digest=digest,
        )
    ]
    lineage = verify_dex_inputs(src, inputs)
    key = derive_index_key(lineage, "1.5.2", _OPTS)
    manifest = JadxIndexManifest(
        index_key=key,
        key_material=build_key_material(lineage, "1.5.2", _OPTS),
        dex_lineage=lineage,
        jadx_version="1.5.2",
        options_digest=_OPTS,
    )
    java_root = tmp_path / f"java-{tag}"
    for rel, content in java_files.items():
        target = java_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    scan = scan_java_sources(java_root, [], lineage=lineage[0], limits=Limits())
    store = JadxIndexStore(tmp_path / "cache")
    built = store.build_index(src, manifest, scan=scan)
    assert isinstance(built, IndexBuildResult), built
    return tmp_path / "cache", key


def _report_file(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name
    path.write_text(
        json.dumps({"meta": {"package_name": "com.x"}, "leads": [], "endpoints": [],
                    "findings": []}),
        encoding="utf-8",
    )
    return path


_OLD_JAVA = {
    "com/x/A.java": "class A {\n    void m() {\n        int x = 1;\n    }\n}\n",
    "com/x/B.java": "class B {\n    void gone() {\n    }\n}\n",
}
_NEW_JAVA = {
    "com/x/A.java": "class A {\n    void m() {\n        int x = 2;\n    }\n}\n",
    "com/x/C.java": "class C {\n    void fresh() {\n    }\n}\n",
}


def _diff_with_index(
    tmp_path: Path, *extra_args: str
) -> tuple[int, dict | None, str]:
    """跑 fxapk diff（两操作数为最小 report.json）→ (exit_code, 解析后的 stdout JSON, stderr)。"""
    old = _report_file(tmp_path, "old.json")
    new = _report_file(tmp_path, "new.json")
    result = runner.invoke(cli.app, ["diff", str(old), str(new), *extra_args])
    data: dict | None
    try:
        data = json.loads(result.stdout)
    except ValueError:
        data = None
    stderr = result.output if result.exit_code != 0 else ""
    return result.exit_code, data, stderr


# ---------------------------------------------------------------------------
# 参数门：三参数齐备、只吃 report.json、key 语法先行
# ---------------------------------------------------------------------------


def test_no_index_args_keeps_current_output(tmp_path: Path) -> None:
    """不给 index 参数 → 现行为不变：输出无 structure_diff 键。"""
    code, data, _ = _diff_with_index(tmp_path)
    assert code == 0
    assert data is not None and "structure_diff" not in data


@pytest.mark.parametrize(
    "args",
    [
        ("--jadx-index-old", "a" * 64),
        ("--jadx-index-new", "b" * 64),
        ("--jadx-cache-root", "PLACEHOLDER_ROOT"),
        ("--jadx-cache-root", "PLACEHOLDER_ROOT", "--jadx-index-old", "a" * 64),
        ("--jadx-index-old", "a" * 64, "--jadx-index-new", "b" * 64),
    ],
)
def test_partial_index_args_rejected(tmp_path: Path, args: tuple[str, ...]) -> None:
    """★三参数缺一拒绝：任何不齐备组合都非零退出，不进入 diff 计算。"""
    resolved = tuple(
        str(tmp_path / "cache") if a == "PLACEHOLDER_ROOT" else a for a in args
    )
    code, _, _ = _diff_with_index(tmp_path, *resolved)
    assert code == 2  # 明确的参数拒绝码；崩溃（1）不算履约


def test_apk_operand_rejected_without_touching_analysis(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★操作数为 APK 即拒，且技术上不进分析路径（load_apk 一次都不许被调）。"""

    def _boom(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise AssertionError("index 组合下绝不允许现分析 APK")

    monkeypatch.setattr(cli, "load_apk", _boom)
    cache_root, key = _build_real_index(tmp_path, "solo", _OLD_JAVA)
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04fake")
    old = _report_file(tmp_path, "old.json")
    result = runner.invoke(
        cli.app,
        ["diff", str(old), str(apk),
         "--jadx-cache-root", str(cache_root),
         "--jadx-index-old", key, "--jadx-index-new", key],
    )
    assert result.exit_code == 2  # 明确拒绝，不是崩溃


@pytest.mark.parametrize("bad_key", ["XYZ", "A" * 64, "a" * 63, "../../etc/x", "a" * 65])
def test_bad_key_syntax_rejected_before_filesystem(tmp_path: Path, bad_key: str) -> None:
    """★key 先按 hex64 语法校验：cache root 指向不存在路径也必须在语法关就拒。"""
    code, _, _ = _diff_with_index(
        tmp_path,
        "--jadx-cache-root", str(tmp_path / "nonexistent-cache"),
        "--jadx-index-old", bad_key,
        "--jadx-index-new", "a" * 64,
    )
    assert code == 2  # 语法关的明确拒绝码


# ---------------------------------------------------------------------------
# structure_diff 段：ok 形态、fail-open、上限留痕
# ---------------------------------------------------------------------------


def test_structure_diff_ok_section(tmp_path: Path) -> None:
    """★真索引对比：schema 按设计——status/两侧身份/counts（截断前）/明细/caveats。"""
    cache_root, old_key = _build_real_index(tmp_path, "old", _OLD_JAVA)
    _, new_key = _build_real_index(tmp_path, "new", _NEW_JAVA)
    code, data, _ = _diff_with_index(
        tmp_path,
        "--jadx-cache-root", str(cache_root),
        "--jadx-index-old", old_key,
        "--jadx-index-new", new_key,
    )
    assert code == 0 and data is not None
    section = data["structure_diff"]
    assert section["status"] == "ok"
    # 两侧身份：index_key + coverage + manifest digest（sha256: 前缀、非路径）。
    for side, expected_key in (("old", old_key), ("new", new_key)):
        ident = section[side]
        assert ident["index_key"] == expected_key
        assert ident["coverage"] in ("complete", "partial")
        assert ident["manifest_digest"].startswith("sha256:")
    assert isinstance(section["absence_claimable"], bool)
    # counts 是**截断前**全量计数。
    counts = section["counts"]
    assert counts["added_classes"] == 1  # C
    assert counts["removed_classes"] == 1  # B
    assert counts["changed_methods"] == 1  # A.m 体变了
    # 类级明细按 schema 1.2 身份口径输出 (class_name, path) 对象——混淆同名类可区分。
    assert section["added_classes"] == [{"class_name": "C", "path": "com/x/C.java"}]
    assert section["removed_classes"] == [{"class_name": "B", "path": "com/x/B.java"}]
    # changed 明细 + 四元组（机器可读，非散文）。
    assert isinstance(section["changed"], list) and section["changed"]
    assert section["changed_total"] == 1
    assert section["changed_emitted"] == 1
    assert isinstance(section["limit"], int) and section["limit"] >= 1
    assert section["truncated"] is False
    # caveats：稳定 code + 人读文本；absence 语义必须有稳定 code 承载。
    caveats = section["caveats"]
    assert isinstance(caveats, list)
    assert all(
        isinstance(c, dict) and isinstance(c.get("code"), str) and isinstance(c.get("text"), str)
        for c in caveats
    )
    assert any(c["code"] == "absence_is_unobserved" for c in caveats)
    # report 级 diff 段照常存在。
    assert "summary" in data and "leads" in data


def test_index_unavailable_fail_open(tmp_path: Path) -> None:
    """★索引缺失 → structure_diff.status=unavailable + 稳定 reason；report 级 diff 照常。"""
    (tmp_path / "empty-cache").mkdir()
    code, data, _ = _diff_with_index(
        tmp_path,
        "--jadx-cache-root", str(tmp_path / "empty-cache"),
        "--jadx-index-old", "a" * 64,
        "--jadx-index-new", "b" * 64,
    )
    assert code == 0 and data is not None
    section = data["structure_diff"]
    assert section["status"] == "unavailable"
    assert isinstance(section["reason"], str) and section["reason"]
    # 稳定 code 语法（不含路径/异常文本）。
    assert all(ch.islower() or ch.isdigit() or ch == "_" for ch in section["reason"])
    assert "summary" in data and "leads" in data  # fail-open：报告级 diff 不受影响


def test_detail_caps_truncate_with_full_counts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★明细上限留痕：emitted<total、truncated=True，counts 仍是截断前全量。"""
    import apkscan.core.structure_diff_report as sdr

    monkeypatch.setattr(sdr, "_MAX_DETAIL_ITEMS", 1)
    old_java = {"com/x/A.java": "class A {\n    void m() {\n    }\n}\n"}
    new_java = {
        "com/x/A.java": "class A {\n    void m() {\n    }\n}\n",
        "com/x/N1.java": "class N1 {\n    void a() {\n    }\n}\n",
        "com/x/N2.java": "class N2 {\n    void b() {\n    }\n}\n",
    }
    cache_root, old_key = _build_real_index(tmp_path, "capold", old_java)
    _, new_key = _build_real_index(tmp_path, "capnew", new_java)
    code, data, _ = _diff_with_index(
        tmp_path,
        "--jadx-cache-root", str(cache_root),
        "--jadx-index-old", old_key,
        "--jadx-index-new", new_key,
    )
    assert code == 0 and data is not None
    section = data["structure_diff"]
    assert section["status"] == "ok"
    assert section["counts"]["added_classes"] == 2  # 截断前全量
    assert section["added_classes_total"] == 2
    assert section["added_classes_emitted"] == 1
    assert len(section["added_classes"]) == 1
    assert section["truncated"] is True


# ---------------------------------------------------------------------------
# 复审补锁（codex P2-B 复审）
# ---------------------------------------------------------------------------


def test_uppercase_json_operand_stays_on_json_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """.JSON 操作数（Windows 常见）：与 _report_dict_for 同口径大小写不敏感——
    放行后必走 JSON 读取分支，绝不进分析路径（load_apk 零调用锁死等价性）。"""

    def _boom(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise AssertionError("大小写变体也绝不允许进入分析路径")

    monkeypatch.setattr(cli, "load_apk", _boom)
    cache_root, key = _build_real_index(tmp_path, "uc", _OLD_JAVA)
    upper = tmp_path / "OLD.JSON"
    upper.write_text(
        json.dumps({"meta": {}, "leads": [], "endpoints": [], "findings": []}),
        encoding="utf-8",
    )
    new = _report_file(tmp_path, "new.json")
    result = runner.invoke(
        cli.app,
        ["diff", str(upper), str(new),
         "--jadx-cache-root", str(cache_root),
         "--jadx-index-old", key, "--jadx-index-new", key],
    )
    assert result.exit_code == 0  # 合法 JSON 报告，不因后缀大小写被拒


def test_no_index_args_output_keyset_unchanged(tmp_path: Path) -> None:
    """无 index 参数时输出键集恰为既有五键——锁"没有静默新增键"。"""
    code, data, _ = _diff_with_index(tmp_path)
    assert code == 0 and data is not None
    assert set(data) == {"leads", "endpoints", "findings", "meta_changes", "summary"}


def test_bad_key_never_touches_store(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★证伪加强：key 语法非法时 JadxIndexStore 构造一次都不许发生。"""
    import apkscan.core.jadx_index as ji

    def _boom(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise AssertionError("语法关之前绝不允许触碰 store")

    monkeypatch.setattr(ji.JadxIndexStore, "__init__", _boom)
    code, _, _ = _diff_with_index(
        tmp_path,
        "--jadx-cache-root", str(tmp_path / "cache"),
        "--jadx-index-old", "Z" * 64,
        "--jadx-index-new", "a" * 64,
    )
    assert code == 2


def test_diff_engine_exception_folds_to_stable_reason(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """★fail-open 加强：diff_index_structure 抛带路径的 JadxIndexError →
    reason 折叠为稳定码，JSON 不含路径/异常文本。"""
    import apkscan.core.jadx_structure_diff as jsd
    from apkscan.core.jadx_index import JadxIndexError

    cache_root, key = _build_real_index(tmp_path, "boom", _OLD_JAVA)

    def _boom(left, right):  # noqa: ANN001, ANN202
        raise JadxIndexError(r"C:\evil path\leak", "$.x")

    monkeypatch.setattr(jsd, "diff_index_structure", _boom)
    code, data, _ = _diff_with_index(
        tmp_path,
        "--jadx-cache-root", str(cache_root),
        "--jadx-index-old", key, "--jadx-index-new", key,
    )
    assert code == 0 and data is not None
    section = data["structure_diff"]
    assert section["status"] == "unavailable"
    assert section["reason"] == "index_unavailable"  # 非法 code 已折叠
    assert "evil" not in json.dumps(data)


def test_partial_coverage_emits_caveat(tmp_path: Path) -> None:
    """partial 侧参与对比 → coverage_partial caveat 出现；ok 段每组明细齐备 total/emitted。"""
    # max_files=1 截断出 partial coverage 的索引。
    src = tmp_path / "src-part"
    src.mkdir()
    dex = src / "classes.dex"
    dex.write_bytes(b"dex-part")
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
    java_root = tmp_path / "java-part"
    for rel, content in _OLD_JAVA.items():
        target = java_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    scan = scan_java_sources(java_root, [], lineage=lineage[0], limits=Limits(max_files=1))
    assert scan.coverage == "partial"
    store = JadxIndexStore(tmp_path / "cache")
    built = store.build_index(src, manifest, scan=scan)
    assert isinstance(built, IndexBuildResult)

    cache_root, full_key = _build_real_index(tmp_path, "full", _NEW_JAVA)
    code, data, _ = _diff_with_index(
        tmp_path,
        "--jadx-cache-root", str(cache_root),
        "--jadx-index-old", key, "--jadx-index-new", full_key,
    )
    assert code == 0 and data is not None
    section = data["structure_diff"]
    assert section["status"] == "ok"
    assert any(c["code"] == "coverage_partial" for c in section["caveats"])
    assert section["absence_claimable"] is False
    # 每组明细齐备 total/emitted。
    for name in ("added_classes", "removed_classes", "added_methods",
                 "removed_methods", "changed"):
        assert f"{name}_total" in section and f"{name}_emitted" in section
    # manifest_digest 与 cache 内文件字节精确一致。
    expected = "sha256:" + hashlib.sha256(
        (cache_root / key / "manifest.json").read_bytes()
    ).hexdigest()
    assert section["old"]["manifest_digest"] == expected
