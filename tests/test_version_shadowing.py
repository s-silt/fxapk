"""版本遮蔽自诊断：报告写的 tool_version 究竟来自哪份代码。

★真实踩坑：editable 安装是 1.3.0，但在旧源码目录下跑 ``python -m apkscan.cli`` 时，
当前目录的 apkscan 包遮蔽了已安装那份，报告写成 ``tool_version=0.10.0.dev0``，
而 ``fxapk --version`` 与 ``pip show`` 都显示 1.3.0。这是 Python 导入规则使然、
不是算法错误，但取证工具"同样本同版本→同结果"的承诺正是栽在这种地方。
"""

from __future__ import annotations

import sys
from typing import Any

import pytest
from typer.testing import CliRunner

from apkscan import selfcheck
from apkscan.cli import app

runner = CliRunner()


def test_version_component_reports_all_four_fields() -> None:
    item = selfcheck.build_version_component()
    for field in ("version=", "import_path=", "distribution=", "git_head="):
        assert field in item["detail"], f"缺少 {field}"


def test_version_component_ok_when_consistent() -> None:
    """本仓库自身跑测试时是 editable 安装，两边版本应一致。"""
    assert selfcheck.build_version_component()["status"] == "ok"


def test_shadowed_version_fails_closed(monkeypatch: Any) -> None:
    """★核心断言：分发版本与实际导入版本不一致 → unreachable + 给出修法。"""
    import apkscan

    monkeypatch.setattr(apkscan, "__version__", "0.10.0.dev0", raising=False)

    class _Dist:
        version = "1.3.0"

        def locate_file(self, _name: str) -> str:
            return "/site-packages"

    import importlib.metadata as md

    monkeypatch.setattr(md, "distribution", lambda _name: _Dist())

    item = selfcheck.build_version_component()
    assert item["status"] == "unreachable"
    assert "0.10.0.dev0" in item["detail"] and "1.3.0" in item["detail"]
    assert item["fix"], "必须给出怎么修，不能只报错"


def test_uninstalled_source_tree_is_not_an_error(monkeypatch: Any) -> None:
    """直接跑源码树（未 pip install）时两边对不上是正常的，不该报故障。"""
    import importlib.metadata as md

    def _raise(_name: str) -> None:
        raise md.PackageNotFoundError("fxapk")

    monkeypatch.setattr(md, "distribution", _raise)
    assert selfcheck.build_version_component()["status"] == "ok"


def test_selfcheck_includes_version_component() -> None:
    result = selfcheck.run_selfcheck(online=False, probe_network=False)
    names = [c["name"] for c in result["components"]]
    assert "version" in names
    # 版本项要排在能力项之前——其它项全绿也挡不住"跑的根本不是这份代码"。
    assert names.index("version") <= 1


def test_cli_version_verbose_prints_import_path() -> None:
    result = runner.invoke(app, ["--version-verbose"])
    assert result.exit_code == 0
    assert "import_path=" in result.output


def test_cli_version_verbose_exits_nonzero_when_shadowed(monkeypatch: Any) -> None:
    """★被遮蔽时退出码必须非零，否则批量流程里没人会发现用错了代码。"""
    monkeypatch.setattr(
        selfcheck,
        "build_version_component",
        lambda: {
            "name": "version", "category": "core", "status": "unreachable",
            "detail": "version=0.10.0.dev0 ★不一致：已安装 1.3.0，实际导入 0.10.0.dev0",
            "fix": "换个工作目录再跑",
        },
    )
    result = runner.invoke(app, ["--version-verbose"])
    assert result.exit_code == 1


@pytest.mark.skipif(sys.platform == "emscripten", reason="需要真实文件系统")
def test_git_head_returns_empty_outside_worktree(tmp_path: Any) -> None:
    assert selfcheck._git_head(str(tmp_path)) == ""
