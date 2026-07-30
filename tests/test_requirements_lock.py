"""取证运行环境锁的完整性：锁必须钉死、且不得与 pyproject 脱节。

一份没人校验的锁一定会烂：加了依赖忘了更锁，锁就从"可复现的保证"退化成"一份过期的清单"，
而这种退化**无声无息**——照样能装、照样能跑，只是复现出的环境已经不是当初那个。本文件把
两条不变量钉成门禁。

★这里断言的是「锁自身是否自洽」，不是「锁住的版本是不是最新」。升级依赖是有意的动作，
  该由人发起并重生成锁；测试只负责让"忘了同步"当场变红。
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_LOCK = _ROOT / "requirements.lock"
_PYPROJECT = _ROOT / "pyproject.toml"

#: 依赖行：``name==version`` 后面可跟 ``; marker``。锁里只允许这一种形态。
_PIN_RE = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)==(?P<version>[^\s;]+)\s*(?:;.*)?$")


def _normalize(name: str) -> str:
    """PEP 503 名称归一：小写，``-``/``_``/``.`` 折成 ``-``。"""
    return re.sub(r"[-_.]+", "-", name).lower()


def _lock_lines() -> list[str]:
    return [
        line.strip()
        for line in _LOCK.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _locked_versions() -> dict[str, str]:
    out: dict[str, str] = {}
    for line in _lock_lines():
        m = _PIN_RE.match(line)
        assert m is not None, f"锁里有非精确钉死的行：{line!r}"
        out[_normalize(m.group("name"))] = m.group("version")
    return out


def _declared_requirements() -> dict[str, list[str]]:
    """pyproject 里声明的依赖：{来源: [需求串]}（含 optional-dependencies 各 extra）。"""
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    project = data.get("project", {})
    out: dict[str, list[str]] = {"dependencies": list(project.get("dependencies") or [])}
    for extra, reqs in (project.get("optional-dependencies") or {}).items():
        out[f"optional:{extra}"] = list(reqs)
    return out


def _requirement_name(req: str) -> str:
    return _normalize(re.split(r"[<>=!~\[;\s]", req.strip(), maxsplit=1)[0])


def test_lock_file_exists_and_is_not_empty() -> None:
    assert _LOCK.exists(), "requirements.lock 缺失——取证环境没有可复现的锚点"
    assert _lock_lines(), "requirements.lock 只有注释，没有任何钉死项"


def test_every_lock_entry_is_exactly_pinned() -> None:
    """★锁的全部意义在于精确：出现 ``>=`` / ``~=`` 就等于没锁。"""
    versions = _locked_versions()  # 内部对每行断言形态
    assert len(versions) == len(_lock_lines()), "有重复钉死的包名"


def test_lock_does_not_contain_the_project_itself() -> None:
    """``pip freeze`` 会带上 ``fxapk @ file://…`` 这类本地路径项，必须剔掉。

    留着会让锁只能在生成它的那台机器上装得起来——正好毁掉可复现这件事。
    """
    names = set(_locked_versions())
    for own in ("fxapk", "apkscan"):
        assert own not in names, f"锁里混进了本项目自身（{own}）"
    raw = _LOCK.read_text(encoding="utf-8")
    assert "file://" not in raw, "锁里有本地路径依赖，换台机器就装不起来"


#: 有意**不**进锁的 extra：开发工具不参与分析，版本漂移不会改变任何一份报告的结论，
#: 把它们锁进来只会让每次升 pytest/ruff 都得改锁。范围写在 requirements.lock 头部。
_UNLOCKED_EXTRAS = frozenset({"optional:dev"})


@pytest.mark.parametrize(
    "source", sorted(s for s in _declared_requirements() if s not in _UNLOCKED_EXTRAS)
)
def test_declared_dependencies_are_all_locked(source: str) -> None:
    """★核心防腐：pyproject 里声明的每个依赖都必须在锁里有钉死项。

    加了依赖却忘了重生成锁时，这条当场变红——否则锁会静默地少一项，
    而"少一项"与"锁全了"在装机结果上不同、在文件里却看不出来。
    """
    locked = set(_locked_versions())
    missing = [
        req for req in _declared_requirements()[source]
        if _requirement_name(req) not in locked
    ]
    assert not missing, f"{source} 里这些依赖没进锁：{missing}"


def test_dev_tools_stay_out_of_the_lock() -> None:
    """★把"只锁运行时"这条范围钉成契约，免得日后被当成漏了而顺手加进去。

    pytest / ruff / pyright 不参与分析：它们换版改不了任何一份报告的结论，锁进来只会
    让每次升级开发工具都得动这份取证锚点。
    """
    locked = set(_locked_versions())
    for tool in ("pytest", "ruff", "pyright"):
        assert tool not in locked, f"开发工具 {tool} 不该进运行时锁（见 requirements.lock 头部「范围」）"


def test_androguard_lock_agrees_with_the_pyproject_upper_bound() -> None:
    """锁住的 androguard 必须落在 pyproject 声明的大版本区间内。

    这条约束是取证性的：axml/dex 解析在 androguard 大版本间会变，
    锁与声明各说各话就意味着"装出来的"和"承诺支持的"不是同一个解析器。
    """
    declared = [
        r for r in _declared_requirements()["dependencies"]
        if _requirement_name(r) == "androguard"
    ]
    assert declared, "pyproject 不再声明 androguard？判据前提已变，请复核本测试"
    locked = _locked_versions()["androguard"]
    major = int(locked.split(".")[0])
    assert "<5" in declared[0] and major == 4, (
        f"锁住 androguard {locked}，与声明 {declared[0]} 不一致"
    )
