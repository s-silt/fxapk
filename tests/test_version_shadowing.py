"""版本自诊断测试：报告写的 tool_version 究竟来自哪份代码、版本口径是否一致。

★两次真实踩坑，对应两条判据：

1. 遮蔽：editable 安装是 1.3.0，但在旧源码目录下跑 ``python -m apkscan.cli`` 时，
   当前目录的 apkscan 包遮蔽了已安装那份，报告写成 ``tool_version=0.10.0.dev0``，
   而 ``fxapk --version`` 与 ``pip show`` 都显示 1.3.0。
2. 元数据滞后：editable 安装后 pyproject 升到 1.6.1 没重装，元数据停在 1.5.2；
   ``__version__`` 优先取元数据 → imported 恒等于 dist，第一条判据永远沉默，
   报告 / corpus 主键 / integrity 指纹全写 1.5.2，而跑的是 1.6.1 的代码。

两次都是"同样本同版本→同结果"的承诺栽在版本口径上，不是算法错误。

★本文件所有断言一律用 monkeypatch 把三个版本源（imported / fallback / dist）钉死后再测：
测的是"一致时不报 / 不一致时报"这个语义，不是"这台机碰巧一致"——第 2 条踩坑恰好说明
本机随时可能处于不一致状态，裸跑 build_version_component 的断言在故障现场必翻车。
"""

from __future__ import annotations

import sys
from typing import Any

import pytest
from typer.testing import CliRunner

from apkscan import selfcheck
from apkscan.cli import app

runner = CliRunner()


class _FakeDist:
    """最小分发对象：build_version_component 只用 version 与 locate_file 两个成员。"""

    def __init__(self, version: str) -> None:
        self.version = version

    def locate_file(self, _name: str) -> str:
        return "/site-packages"


def _pin_versions(monkeypatch: Any, *, imported: str, fallback: str, dist: str | None) -> None:
    """把三个版本源全部钉死，让断言只依赖构造的场景、不依赖本机安装状态。

    dist=None 表示未安装（importlib.metadata 抛 PackageNotFoundError）。
    """
    import importlib.metadata as md

    import apkscan

    monkeypatch.setattr(apkscan, "__version__", imported, raising=False)
    monkeypatch.setattr(apkscan, "_FALLBACK_VERSION", fallback, raising=False)
    if dist is None:
        def _raise(_name: str) -> Any:
            raise md.PackageNotFoundError("fxapk")

        monkeypatch.setattr(md, "distribution", _raise)
    else:
        monkeypatch.setattr(md, "distribution", lambda _name: _FakeDist(dist))


def _project_root() -> str:
    """import_path 推出的项目根——fix 里的重装命令必须用它的绝对路径，不能用裸 `-e .`。

    跨环境成立（CI 上路径不同），故不硬编码。
    """
    from pathlib import Path

    import apkscan

    return str(Path(apkscan.__file__).resolve().parent.parent)


def test_version_component_reports_all_fields(monkeypatch: Any) -> None:
    _pin_versions(monkeypatch, imported="1.3.0", fallback="1.3.0", dist="1.3.0")
    item = selfcheck.build_version_component()
    for field in ("version=", "source_version=", "import_path=", "distribution=", "git_head="):
        assert field in item["detail"], f"缺少 {field}"


def test_version_component_ok_when_consistent(monkeypatch: Any) -> None:
    """三个版本源一致 → ok（不误报）。"""
    _pin_versions(monkeypatch, imported="1.3.0", fallback="1.3.0", dist="1.3.0")
    assert selfcheck.build_version_component()["status"] == "ok"


def test_shadowed_version_fails_closed(monkeypatch: Any) -> None:
    """★判据一：分发版本与实际导入版本不一致（遮蔽）→ unreachable + 给出修法。"""
    _pin_versions(monkeypatch, imported="0.10.0.dev0", fallback="0.10.0.dev0", dist="1.3.0")
    item = selfcheck.build_version_component()
    assert item["status"] == "unreachable"
    assert "0.10.0.dev0" in item["detail"] and "1.3.0" in item["detail"]
    assert item["fix"], "必须给出怎么修，不能只报错"
    # ★判据一先于判据二触发，遮蔽场景下用户看到的就是这条 fix——它必须自带「勿在当前目录重装」
    #   护栏。否则照做会把这棵非预期的树装成 editable、静默覆盖原安装、自检假性转绿
    #   （判据二有此护栏而判据一没有，正是外部复审指出的漏洞）。
    assert "import_path" in item["fix"], "fix 必须引导先核对 import_path"
    assert "切勿在当前目录重装" in item["fix"], "遮蔽分支的护栏不能只在判据二有"
    # ★重装目标必须给绝对路径：核对 import_path 无误 ≠ 当前 shell 就在那棵树的根上
    #   （经 PYTHONPATH 导入 A 树而 cwd 在 B 树时，`-e .` 装的是 B）。
    #   不能简单断言「不含 `-e .`」——文案里那句劝阻本身就含该字面量；改为正面断言给出了绝对路径。
    assert _project_root() in item["fix"], "重装命令须给 import_path 推出的项目根绝对路径"


def test_stale_metadata_fails_closed(monkeypatch: Any) -> None:
    """★判据二·正向（真实现场）：editable 安装后 pyproject 升版没重装 → 元数据滞后。

    __version__ 优先取元数据 → imported 恒等于 dist（1.5.2），判据一在这种故障下
    **结构上不可能触发**；必须由"源码树声明 vs 安装元数据"这条抓住。
    """
    _pin_versions(monkeypatch, imported="1.5.2", fallback="1.6.1", dist="1.5.2")
    item = selfcheck.build_version_component()
    assert item["status"] == "unreachable"
    assert "1.5.2" in item["detail"] and "1.6.1" in item["detail"]
    assert _project_root() in item["fix"], "① 分支修法须给项目根绝对路径，不是裸 `-e .`"
    # ★本仓 .venv 由 uv 建、不带 pip——只给 `python -m pip install -e .` 时照做会
    #   报 "No module named pip"（实测踩过）。fix 必须同时给 uv 的写法，否则这条
    #   自检把人引到一条在本项目自己的环境里跑不通的路上。
    assert "uv pip install -e" in item["fix"], "uv 建的 venv 没有 pip，修法必须覆盖"
    # ★P1-1：判据二不能无条件断言"是元数据滞后"——它也会被"另一棵树遮蔽"触发（现代树
    #   遮蔽时 imported==dist≠fallback）。若无条件建议重装，遮蔽场景照做会把非预期的树
    #   装成 editable、静默覆盖原安装。故 fix 必须先引导核对 import_path 分流，并给遮蔽护栏。
    assert "import_path" in item["fix"], "fix 必须引导先核对 import_path，区分滞后 vs 遮蔽"
    assert "切勿在当前目录重装" in item["fix"], "遮蔽分支的护栏（勿在当前目录重装）不能丢"


def test_metadata_ahead_of_source_fails_closed(monkeypatch: Any) -> None:
    """★判据二·反向：fallback 比元数据旧＝发版时忘同步 _FALLBACK_VERSION，同样要报。"""
    _pin_versions(monkeypatch, imported="1.6.1", fallback="1.5.2", dist="1.6.1")
    item = selfcheck.build_version_component()
    assert item["status"] == "unreachable"
    assert "1.6.1" in item["detail"] and "1.5.2" in item["detail"]
    assert item["fix"], "必须给出怎么修，不能只报错"


def test_uninstalled_source_tree_is_not_an_error(monkeypatch: Any) -> None:
    """直接跑源码树（未 pip install）时没有元数据可比，不该报故障。"""
    _pin_versions(monkeypatch, imported="1.6.1", fallback="1.6.1", dist=None)
    assert selfcheck.build_version_component()["status"] == "ok"


def test_stale_metadata_wiring_survives_rename(monkeypatch: Any) -> None:
    """★P2-1：判据二真接线测试——只钉 imported+dist（哨兵、彼此相等），**不钉 fallback**，
    让判据二走生产的真 `getattr(apkscan, "_FALLBACK_VERSION", "")` 读真值。

    这是唯一能抓住"改 __init__ 的 _FALLBACK_VERSION 名 + 顺手改契约测试字面量、
    漏改 selfcheck.py"这条两步错误链的测试：其余测试都 monkeypatch 钉死 fallback
    （setattr 凭空造属性），实现侧改名后它们照绿而判据二在生产静默死亡（fail-open）。
    这里真值恒不等于哨兵，任一侧改名 → getattr 返回 "" → 判据二短路 → status 变 ok → 本测试红。
    """
    import importlib.metadata as md

    import apkscan

    sentinel = "0.0.0+wiring-sentinel"  # 与真实 _FALLBACK_VERSION（1.6.x）必不相等
    monkeypatch.setattr(apkscan, "__version__", sentinel, raising=False)
    monkeypatch.setattr(md, "distribution", lambda _name: _FakeDist(sentinel))
    # ★刻意不碰 _FALLBACK_VERSION：判据二必须靠真 getattr 读到真值才会触发
    item = selfcheck.build_version_component()
    assert item["status"] == "unreachable", "判据二没接到真 _FALLBACK_VERSION（改名已静默失效？）"
    assert sentinel in item["detail"]


def test_fallback_version_contract_holds() -> None:
    """★锁 _FALLBACK_VERSION 契约（本文件唯一不 pin 版本的测试，锁的就是真实值）。

    判据二读的就是这个私有名：改名/清空不会让判据报错，而是让它**静默失效**（fail-open）——
    上面那些 monkeypatch 钉值的测试抓不到改名（setattr 会凭空造出属性）。同时锁"发版同步"：
    源码树里它必须与 pyproject 的 version 一致，否则判据二在正常 editable 安装下必误报。
    """
    import tomllib
    from pathlib import Path

    import apkscan

    fallback = getattr(apkscan, "_FALLBACK_VERSION", None)
    assert isinstance(fallback, str) and fallback, "_FALLBACK_VERSION 被改名或清空"
    pyproject = Path(apkscan.__file__).resolve().parent.parent / "pyproject.toml"
    if pyproject.exists():  # 只有源码树才有 pyproject；安装形态下退化为只锁存在性
        declared = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
        assert declared == fallback, "发版时 _FALLBACK_VERSION 未与 pyproject 同步"


def test_pyproject_version_is_pep440_canonical() -> None:
    """★pyproject version 必须已是 PEP440 规范形式。

    否则 setuptools 会把它归一化后写进元数据（如 1.7.0-rc1 → 1.7.0rc1、V1.2.0 → 1.2.0），
    而 _FALLBACK_VERSION 与上一条测试比的都是**原始串**，raw==raw 照绿，
    判据二却会在每次正常安装时误报。

    ★为什么与 test_fallback_version_contract_holds 拆开：pytest 的 Skipped 会让**整个测试函数**
    标记 skipped。旧写法里同步断言排在 importorskip **之前**，故 packaging 缺席时同步护栏
    其实仍会执行、不同步照样红（复审实测确认，早先「连同步护栏也被跳过」的说法不成立）；
    真实损失是——同步护栏通过时整条被标 skipped，报告上看不出它跑过，且 PEP440 检查静默丢失。
    两条各自独立呈现后不再互相掩盖，这是严格更优的写法。

    ★为什么直接 import packaging 而不用 ``importorskip``：packaging 是 pytest 自身的依赖
    （``pytest`` 声明 ``packaging>=22``），凡能跑到本测试的环境必然装有它——用 importorskip
    等于给一个不可能发生的缺失留了「静默放行」的口子，而这条守的是**正常安装后必然误报**
    的发版 contract，依赖缺失应当让流水线失败而不是跳过。
    """
    import tomllib
    from pathlib import Path

    # 硬依赖：缺失即 ImportError（测试失败），不静默跳过
    from packaging.utils import canonicalize_version

    import apkscan

    pyproject = Path(apkscan.__file__).resolve().parent.parent / "pyproject.toml"
    if not pyproject.exists():          # 安装形态下确无 pyproject 可查，跳过是正确语义
        pytest.skip("非源码树，无 pyproject.toml")
    declared = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
    # strip_trailing_zero=False：只规范分隔符/前缀/预发布记法，不去尾零（1.7.0 保持 1.7.0，不误伤）
    assert declared == canonicalize_version(declared, strip_trailing_zero=False), (
        f"pyproject version 非 PEP440 规范形式：{declared!r}——setuptools 归一化后会与 "
        f"_FALLBACK_VERSION 不符，导致判据二每次安装误报"
    )


def test_selfcheck_includes_version_component() -> None:
    result = selfcheck.run_selfcheck(online=False, probe_network=False)
    names = [c["name"] for c in result["components"]]
    assert "version" in names
    # 版本项要排在能力项之前——其它项全绿也挡不住"跑的根本不是这份代码"。
    assert names.index("version") <= 1


def test_cli_version_verbose_prints_import_path(monkeypatch: Any) -> None:
    """一致场景下打印 import_path 且退出码 0（版本源须钉死，本机可能正处于故障现场）。"""
    _pin_versions(monkeypatch, imported="1.3.0", fallback="1.3.0", dist="1.3.0")
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


def test_cli_version_verbose_exits_nonzero_on_stale_metadata(monkeypatch: Any) -> None:
    """★元数据滞后时 --version-verbose 同样非零退出（走真实判据、不 mock 组件）。"""
    _pin_versions(monkeypatch, imported="1.5.2", fallback="1.6.1", dist="1.5.2")
    result = runner.invoke(app, ["--version-verbose"])
    assert result.exit_code == 1


@pytest.mark.skipif(sys.platform == "emscripten", reason="需要真实文件系统")
def test_git_head_returns_empty_outside_worktree(tmp_path: Any) -> None:
    assert selfcheck._git_head(str(tmp_path)) == ""


def test_fix_does_not_offer_editable_reinstall_for_non_source_tree(
    monkeypatch: Any, tmp_path: Any
) -> None:
    """★P2-2：非 editable 安装（import_path 在 site-packages 下、其下无 pyproject.toml）时，
    fix 不得给 `pip install -e "<site-packages>"` 这种无意义命令。

    发行包用户触发判据二时，正确指引是「按包名重装/升级」，而不是 editable 安装一个不是源码树的目录。
    """
    import importlib.metadata as md

    import apkscan

    # 造一个「site-packages/apkscan/」形态：父目录下没有 pyproject.toml
    fake_site = tmp_path / "site-packages"
    (fake_site / "apkscan").mkdir(parents=True)
    monkeypatch.setattr(apkscan, "__file__", str(fake_site / "apkscan" / "__init__.py"))
    monkeypatch.setattr(apkscan, "__version__", "1.5.2", raising=False)
    monkeypatch.setattr(apkscan, "_FALLBACK_VERSION", "1.6.1", raising=False)
    monkeypatch.setattr(md, "distribution", lambda _name: _FakeDist("1.5.2"))

    item = selfcheck.build_version_component()
    assert item["status"] == "unreachable"
    assert "不适用 editable 重装" in item["fix"], "非源码树不得给 editable 重装命令"
    assert "按包名重装" in item["fix"], "发行包场景应指引按包名重装/升级"
