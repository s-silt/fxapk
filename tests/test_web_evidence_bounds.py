"""网页证据的**边界与自污染**回归：Codex 独立复核抓出的三项（多成员 gzip / 遍历上限 /
``--out`` 等于证据根）。

为什么另立一个文件而不塞进 ``test_web_evidence.py``：那份测的是"抽得对不对"（链形、内联
配置、平台门控），这份测的是"读进来的边界对不对"——输入不可信时的拒收纪律。三组共同的
主题是**同一条原则**：宁可明确拒收并写进 ``load_errors``，也绝不把残缺/被污染的证据
当完整证据用；因为"部分证据"与"这份证据没线索"在报告里长得一模一样。

零真实数据：域名全用文档保留域，内容全为合成串。
"""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest

import apkscan.core.webctx as webctx_module
from apkscan.core.models import AnalysisConfig
from apkscan.core.webctx import (
    MAX_EVIDENCE_BYTES,
    WEB_PREFIX,
    load_web_evidence,
)

#: 文档保留域（RFC 2606）：夹具一律用合成值，不放任何真实数据。
DOC_HOST = "config.example.com"


def _evidence_dir(tmp_path: Path) -> Path:
    """造一份最小可分析证据目录（含一处内联配置 + 一跳跳转）。"""
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "landing.html").write_text(
        "<html><script>\n"
        f'window.apiBase = "https://{DOC_HOST}/api/v1";\n'
        f'location.replace("https://a.{DOC_HOST}/hop1");\n'
        "</script></html>",
        encoding="utf-8",
    )
    return root


# ---------------------------------------------------------------------------
# 1. concatenated gzip：全成员有界处理，绝不静默只读第一段
# ---------------------------------------------------------------------------


def test_multi_member_gzip_is_fully_decompressed() -> None:
    """★``gzip.compress(a) + gzip.compress(b)`` 是**合法**的一份 gzip（RFC 1952 §2.2）。

    此前只解第一个成员、剩下的落进 ``unused_data`` 被静默丢弃 —— 后半截里的域名/端点
    一条都抽不到，而报告长得跟"这份证据没线索"一模一样。
    """
    blob = gzip.compress(b"first") + gzip.compress(b"second")
    assert webctx_module._gunzip_bounded(blob) == b"firstsecond"


def test_multi_member_gzip_preserves_member_order() -> None:
    """成员顺序必须保持：跳转链靠顺序说话，拼错顺序等于伪造链形。"""
    blob = b"".join(gzip.compress(part) for part in (b"<html>", b"body", b"</html>"))
    assert webctx_module._gunzip_bounded(blob) == b"<html>body</html>"


def test_single_member_gzip_still_works() -> None:
    """回归护栏：改成按 member 循环不得破坏最常见的单成员情形。"""
    payload = b"<html>ok</html>"
    assert webctx_module._gunzip_bounded(gzip.compress(payload)) == payload


def test_multi_member_total_is_capped_across_all_members() -> None:
    """★上限是**单文件总解压量**，不是每成员各给一份，否则 N 个成员可放大 N 倍。"""
    half = MAX_EVIDENCE_BYTES // 2 + 1024
    blob = gzip.compress(b"a" * half) + gzip.compress(b"b" * half)
    assert webctx_module._gunzip_bounded(blob) is None, "多成员合计绕过了单文件上限"


def test_gzip_with_trailing_garbage_is_rejected_not_truncated() -> None:
    """尾随垃圾 → 明确拒收：已解出的部分是**不完整**证据，不许当完整页面入库。"""
    assert webctx_module._gunzip_bounded(gzip.compress(b"first") + b"\x00junk") is None


def test_truncated_second_member_rejects_the_whole_file() -> None:
    """第二成员被截断 → 整份拒收（与拒收截断的单成员同一条原则）。"""
    blob = gzip.compress(b"first") + gzip.compress(b"second")[:-6]
    assert webctx_module._gunzip_bounded(blob) is None


def test_truncated_single_member_still_rejected() -> None:
    """单成员截断的既有行为不得回退。"""
    assert webctx_module._gunzip_bounded(gzip.compress(b"payload")[:-6]) is None


def test_multi_member_gzip_evidence_loads_end_to_end(tmp_path: Path) -> None:
    """端到端：多成员 gzip 响应体**后半截**里的域名要真的进得了上下文。"""
    root = tmp_path / "gz"
    root.mkdir()
    tail = f'<script>fetch("https://tail.{DOC_HOST}/api");</script>'
    (root / "resp.body").write_bytes(
        gzip.compress(b"<html>head</html>") + gzip.compress(tail.encode("utf-8"))
    )
    ctx = load_web_evidence(root, AnalysisConfig(online=False))
    loaded = b"".join(ctx.read_file(path) or b"" for path in ctx.list_files())
    assert b"head" in loaded, "第一成员丢了"
    assert f"tail.{DOC_HOST}".encode("utf-8") in loaded, "多成员 gzip 的第二成员没进上下文"


def test_rejected_multi_member_gzip_is_recorded_in_load_errors(tmp_path: Path) -> None:
    """拒收要留痕：静默跳过会让"这份证据没线索"与"这份证据没被扫"分不清。"""
    root = tmp_path / "gzbad"
    root.mkdir()
    (root / "bad.body").write_bytes(gzip.compress(b"first") + b"\x00junk")
    ctx = load_web_evidence(root, AnalysisConfig(online=False))
    assert ctx.list_files() == []
    assert any("gzip" in message for message in ctx.load_errors)


# ---------------------------------------------------------------------------
# 2. 遍历清单硬上限：海量不支持后缀文件不得无界收集
# ---------------------------------------------------------------------------


def test_discovery_cap_bounds_traversal_of_unsupported_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★``MAX_EVIDENCE_FILES`` 只数**读入的文本证据**：一目录 ``.bin`` 一份都不计入，
    却每份都进遍历清单 —— 文件数上限形同没有，清单本身先把内存吃干。
    """
    root = tmp_path / "many"
    root.mkdir()
    for index in range(40):
        (root / f"blob{index:03d}.bin").write_bytes(b"\x00\x01")
    (root / "real.html").write_text("<html>ok</html>", encoding="utf-8")

    monkeypatch.setattr(webctx_module, "MAX_DISCOVERED_FILES", 10)
    errors: list[str] = []
    found = webctx_module._iter_files(root, errors)
    assert len(found) == 10, "发现数没有被硬封顶"
    assert any("遍历上限" in message for message in errors), "清单被截断必须写进 load_errors"


def test_discovery_cap_surfaces_through_load_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """截断必须在 ``ctx.load_errors`` 里可见：少扫了不许与"扫全了"长得一样。"""
    root = tmp_path / "many2"
    root.mkdir()
    for index in range(30):
        (root / f"pad{index:03d}.bin").write_bytes(b"\x00")
    (root / "a.html").write_text("<html>x</html>", encoding="utf-8")

    monkeypatch.setattr(webctx_module, "MAX_DISCOVERED_FILES", 5)
    ctx = load_web_evidence(root, AnalysisConfig(online=False))
    assert any("遍历上限" in message for message in ctx.load_errors)


def test_discovery_is_deterministic_under_truncation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★截到哪一份为止必须可复现：``os.walk`` 顺序随文件系统而变，故截断前先排序。"""
    root = tmp_path / "det"
    root.mkdir()
    for index in range(20):
        (root / f"f{index:03d}.bin").write_bytes(b"\x00")

    monkeypatch.setattr(webctx_module, "MAX_DISCOVERED_FILES", 6)
    first = [path.name for path in webctx_module._iter_files(root, [])]
    second = [path.name for path in webctx_module._iter_files(root, [])]
    assert first == second, "同一目录两次遍历结果不一致"
    assert first == sorted(first), "截断前未按名排序，截到哪一份不可复现"


def test_discovery_cap_keeps_symlink_safety(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """加上限不得破坏既有符号链接规则（不跟随链接目录、链接文件记 error）。"""
    root = tmp_path / "ln"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "in.html").write_text("<html>in</html>", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.html").write_text("<html>nope</html>", encoding="utf-8")
    try:
        (root / "link").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("本环境不允许创建符号链接")

    monkeypatch.setattr(webctx_module, "MAX_DISCOVERED_FILES", 100)
    found = [path.name for path in webctx_module._iter_files(root, [])]
    assert "in.html" in found, "链接安全规则把正常子目录也挡掉了"
    assert "secret.html" not in found, "跟随了符号链接目录，跳出了 root"


def test_unsupported_suffixes_do_not_consume_the_text_evidence_budget(
    tmp_path: Path,
) -> None:
    """默认上限下的正常路径：不支持后缀不入 ``files``，文本证据照常读入。"""
    root = tmp_path / "mixed"
    root.mkdir()
    for index in range(20):
        (root / f"x{index:02d}.bin").write_bytes(b"\x00")
    (root / "keep.html").write_text("<html>keep</html>", encoding="utf-8")
    ctx = load_web_evidence(root, AnalysisConfig(online=False))
    assert ctx.list_files() == [f"{WEB_PREFIX}keep.html"]


# ---------------------------------------------------------------------------
# 3. analyze-web 自污染：``--out`` 等于证据根必须拒绝
# ---------------------------------------------------------------------------


def test_exclude_dirs_cannot_exclude_the_root_itself(tmp_path: Path) -> None:
    """事实基线：把 root 自己放进 ``exclude_dirs`` **不会**排除 root 下的文件。

    ``_iter_files`` 只过滤子目录，root 本身永远被遍历。这正是防自污染必须落在 CLI 层
    的原因——指望 ``exclude_dirs=(root,)`` 挡住是错的。此断言若变化，说明语义改了，
    CLI 层那道拒绝可以重新评估。
    """
    root = tmp_path / "selfex"
    root.mkdir()
    (root / "report.html").write_text("<html>old report</html>", encoding="utf-8")
    ctx = load_web_evidence(root, AnalysisConfig(online=False), exclude_dirs=(root,))
    assert ctx.list_files() == [f"{WEB_PREFIX}report.html"]


def test_analyze_web_rejects_out_dir_equal_to_evidence_dir(tmp_path: Path) -> None:
    """★``--out <证据目录>`` 必须被拒：否则重跑会把上次的报告当新证据吃回去。"""
    from typer.testing import CliRunner

    from apkscan import cli

    root = _evidence_dir(tmp_path)
    result = CliRunner().invoke(
        cli.app, ["analyze-web", str(root), "--out", str(root), "--fmt", "json"]
    )
    assert result.exit_code == 2, "输出目录等于证据根竟被放行"
    assert "自污染" in result.output or "不能等于" in result.output
    assert not list(root.glob("report*.json")), "拒绝后不该写出任何报告"


def test_analyze_web_rejects_equal_out_dir_written_differently(tmp_path: Path) -> None:
    """同一目录的另一种写法（``.`` / 尾斜杠）同样要拒 —— 判据是 ``resolve()`` 后相等。"""
    from typer.testing import CliRunner

    from apkscan import cli

    root = _evidence_dir(tmp_path)
    result = CliRunner().invoke(
        cli.app,
        ["analyze-web", str(root), "--out", str(root / "."), "--fmt", "json"],
    )
    assert result.exit_code == 2, "同一目录的另一种拼法被放行了"


def test_analyze_web_rerun_into_subdir_does_not_reingest_old_report(
    tmp_path: Path,
) -> None:
    """端到端重跑：``--out`` 指到证据树内子目录时，上一轮报告不得被当新证据读回。"""
    from typer.testing import CliRunner

    from apkscan import cli

    root = _evidence_dir(tmp_path)
    out_dir = root / "out"
    runner = CliRunner()

    first = runner.invoke(
        cli.app, ["analyze-web", str(root), "--out", str(out_dir), "--fmt", "json"]
    )
    assert first.exit_code == 0, first.output
    assert list(out_dir.glob("*.json")), "第一轮没写出报告"

    second = runner.invoke(
        cli.app, ["analyze-web", str(root), "--out", str(out_dir), "--fmt", "json"]
    )
    assert second.exit_code == 0, second.output

    ctx = load_web_evidence(root, AnalysisConfig(online=False), exclude_dirs=(out_dir,))
    assert not any(path.startswith(f"{WEB_PREFIX}out/") for path in ctx.list_files()), (
        "上一轮的报告被当作新证据吃回去了"
    )


# ---------------------------------------------------------------------------
# 2b. 目录项 budget 用尽时的**确定性**：保留集合不许随枚举顺序而变
# ---------------------------------------------------------------------------


def _scandir_in_order(order: str):
    """构造一个把每个目录的条目按 ``order`` 重排的 ``os.scandir`` 替身。

    ``order`` ∈ ``{"forward", "reverse", "shuffled"}``。替身返回的是**真实** ``DirEntry``
    对象（``is_symlink`` / ``is_dir`` / ``is_file`` 语义与真实一致），只改枚举顺序 ——
    这正是不同文件系统之间实际会变的那一件事。
    """
    import os as _os
    import random as _random
    from contextlib import contextmanager

    real_scandir = _os.scandir

    @contextmanager
    def _fake(path):  # noqa: ANN001, ANN202
        with real_scandir(path) as it:
            entries = list(it)
        names = sorted(entries, key=lambda e: e.name)
        if order == "reverse":
            names.reverse()
        elif order == "shuffled":
            _random.Random(1234).shuffle(names)
        yield iter(names)

    return _fake


def _scandir_with_type_error(order: str, failing_name: str):
    """按指定顺序枚举，并让一个真实目录项在类型检查时稳定抛错。"""
    import os as _os
    import random as _random
    from contextlib import contextmanager

    real_scandir = _os.scandir

    class _FailingEntry:
        def __init__(self, entry) -> None:  # noqa: ANN001
            self.name = entry.name
            self.path = entry.path

        def is_symlink(self) -> bool:
            raise OSError("synthetic type-check failure")

    @contextmanager
    def _fake(path):  # noqa: ANN001, ANN202
        with real_scandir(path) as it:
            entries = [
                _FailingEntry(entry) if entry.name == failing_name else entry
                for entry in it
            ]
        entries.sort(key=lambda entry: entry.name)
        if order == "reverse":
            entries.reverse()
        elif order == "shuffled":
            _random.Random(1234).shuffle(entries)
        yield iter(entries)

    return _fake


def _discover_with_order(
    root: Path, monkeypatch: pytest.MonkeyPatch, order: str, entry_cap: int
) -> tuple[list[str], list[str]]:
    """在指定枚举顺序 + 指定目录项上限下跑一次发现，返回（文件名集合，errors）。"""
    errors: list[str] = []
    with monkeypatch.context() as patch:
        patch.setattr(webctx_module, "MAX_DISCOVERED_ENTRIES", entry_cap)
        patch.setattr(webctx_module.os, "scandir", _scandir_in_order(order))
        found = webctx_module._iter_files(root, errors)
    return sorted(path.name for path in found), errors


def _discover_with_type_error(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    order: str,
    entry_cap: int,
    failing_name: str,
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    with monkeypatch.context() as patch:
        patch.setattr(webctx_module, "MAX_DISCOVERED_ENTRIES", entry_cap)
        patch.setattr(
            webctx_module.os,
            "scandir",
            _scandir_with_type_error(order, failing_name),
        )
        found = webctx_module._iter_files(root, errors)
    return sorted(path.name for path in found), errors


def test_entry_budget_truncation_is_independent_of_scandir_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★同一目录 + 同一上限，**不同 ``scandir`` 枚举顺序**必须给出完全相同的结果。

    这是修复前真实存在的缺陷：目录项 budget 在某层拉到一半用尽时，进 ``batch`` 的是一个
    **依枚举顺序而定的任意前缀**，事后排序只是把那个任意子集排了序。于是同一份证据目录在
    两台机器上保留**不同**的证据集合（一台留 ``a``/``b``，另一台留 ``a``/``c``），而两边的
    输出都长得像"正常截断"——取证结论不可复现，比少读几份文件严重得多。

    现在的语义是 fail closed：budget 用尽的那一层 partial batch **整份丢弃**，保留下来的
    集合只由"被完整枚举过的目录"组成，因此与枚举顺序无关。
    """
    root = tmp_path / "orders"
    root.mkdir()
    for name in ("a", "b", "c", "d", "e", "f", "g", "h"):
        (root / f"{name}.html").write_text(f"<html>{name}</html>", encoding="utf-8")

    # 上限刻意小于条目总数 → 必然在这一层中途用尽。
    forward, forward_errors = _discover_with_order(root, monkeypatch, "forward", 3)
    reverse, reverse_errors = _discover_with_order(root, monkeypatch, "reverse", 3)
    shuffled, shuffled_errors = _discover_with_order(root, monkeypatch, "shuffled", 3)

    assert forward == reverse == shuffled, (
        "保留的证据集合随 scandir 枚举顺序而变 → 同一目录在不同机器上结论不同："
        f"forward={forward} reverse={reverse} shuffled={shuffled}"
    )
    # load_errors 的语义也必须一致（都如实说了"截断了"）。
    assert (
        [any("遍历上限" in m for m in errs) for errs in
         (forward_errors, reverse_errors, shuffled_errors)] == [True, True, True]
    ), "截断在某些枚举顺序下没有写进 load_errors"


def test_entry_budget_discards_partial_directory_type_errors_independent_of_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """截断目录的局部类型错误必须随 partial batch 一起丢弃，不能泄漏枚举顺序。"""
    root = tmp_path / "type-errors"
    root.mkdir()
    for name in ("a-bad.html", "b.html", "c.html", "d.html"):
        (root / name).write_text("<html>x</html>", encoding="utf-8")

    results = [
        _discover_with_type_error(
            root,
            monkeypatch,
            order,
            entry_cap=2,
            failing_name="a-bad.html",
        )
        for order in ("forward", "reverse", "shuffled")
    ]

    assert [found for found, _ in results] == [[], [], []]
    error_sets = [errors for _, errors in results]
    assert error_sets[0] == error_sets[1] == error_sets[2], error_sets
    assert any("遍历上限" in message for message in error_sets[0])
    assert not any("取条目类型失败" in message for message in error_sets[0])


def test_entry_budget_discards_the_partial_directory_entirely(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★budget 用尽的那一层：一份都不采纳（而不是采纳"碰巧先枚举到"的几份）。"""
    root = tmp_path / "partial"
    root.mkdir()
    for name in ("a", "b", "c", "d"):
        (root / f"{name}.html").write_text("<html>x</html>", encoding="utf-8")

    found, errors = _discover_with_order(root, monkeypatch, "forward", 2)
    assert found == [], f"partial batch 被采纳了，保留集合依赖枚举顺序：{found}"
    assert any("遍历上限" in message for message in errors)


def test_fully_enumerated_directories_are_still_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """反向护栏：budget 够用时照常收全，fail-closed 不许退化成"一遇上限就全丢"。"""
    root = tmp_path / "enough"
    root.mkdir()
    for name in ("a", "b", "c"):
        (root / f"{name}.html").write_text("<html>x</html>", encoding="utf-8")

    found, errors = _discover_with_order(root, monkeypatch, "reverse", 50)
    assert found == ["a.html", "b.html", "c.html"]
    assert not any("遍历上限" in message for message in errors)


def test_entry_budget_keeps_completely_enumerated_parent_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """被**完整枚举**的父目录照常保留；只有 budget 中途用尽的那一层被整份丢弃。

    这条钉住 fail-closed 的粒度：是"丢弃出问题的那一层"，不是"清空全部结果"。
    """
    root = tmp_path / "nested"
    (root / "sub").mkdir(parents=True)
    (root / "top.html").write_text("<html>top</html>", encoding="utf-8")
    for name in ("a", "b", "c", "d", "e", "f"):
        (root / "sub" / f"{name}.html").write_text("<html>x</html>", encoding="utf-8")

    # 上限 = 4：root 层 2 条（top.html + sub）完整枚举，sub 层 6 条必然中途用尽。
    forward, _ = _discover_with_order(root, monkeypatch, "forward", 4)
    reverse, _ = _discover_with_order(root, monkeypatch, "reverse", 4)
    assert forward == reverse, f"父目录保留结果随枚举顺序而变：{forward} vs {reverse}"
    assert forward == ["top.html"], f"完整枚举过的父目录内容应保留，实际 {forward}"
