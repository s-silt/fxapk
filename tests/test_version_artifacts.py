"""产物级版本一致性测试：四种分发形态。

★两次真实踩坑（#350、#353）都是单点修复，缺的是产物级验证——
  包被真正构建/安装出来之后，版本到底一不一致。

本文件覆盖：
1. wheel    — 构建后安装到干净 venv，importlib.metadata 与 __version__ 一致
2. sdist    — 同上，且 pyproject.toml 版本与之一致
3. editable — pip install -e . 后三者一致（日常开发形态）
4. 冻结/无元数据 — dist-info 缺失时回落版本与 pyproject 一致，且不静默假装成功

★各条测试的「故意改坏什么会让它变红」注释置于每条 assert 旁。

与 test_version_shadowing.py 的两条契约判据（test_fallback_version_contract_holds、
test_pyproject_version_is_pep440_canonical）不重复：那两条是单元级（in-process），
这里是产物级（真实 build/install 产物 + subprocess 隔离验证）。
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# 共用辅助
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent

# `python -m build --no-isolation` 直接在当前环境调用构建后端：除 build 自身外，
# 还需要 pyproject [build-system].requires 声明的 setuptools 与 wheel 已安装。
# 缺任一则显式 skip，而不是让 subprocess 炸出无诊断信息的 CalledProcessError——
# CI 的 pytest matrix job 显式安装了三者，这两条测试在 CI 恒为真跑；
# locked-env 关有意不装构建工具链（锁环境对齐真实取证部署），在那里按 skip 通过。


def _importable_as_real_package(mod: str) -> bool:
    # 仅 find_spec 不够：本文件的 --no-isolation 构建会在仓库根留下 build/ 残留目录，
    # 从仓库根起的解释器会把它当命名空间包（spec 存在但 origin 为 None）误判成已安装。
    try:
        spec = importlib.util.find_spec(mod)
    except (ImportError, ValueError):
        return False
    return spec is not None and spec.origin is not None


_MISSING_BUILD_TOOLCHAIN = [
    mod for mod in ("build", "setuptools", "wheel") if not _importable_as_real_package(mod)
]


def _require_build_toolchain() -> None:
    """缺构建工具链时 skip；但 CI 矩阵关（FXAPK_REQUIRE_BUILD_TOOLCHAIN=1）缺链必须 fail。

    没有后者，谁改掉 ci.yml 里 build/setuptools/wheel 的安装行，这两条守门测试就会
    静默 skip、CI 照绿——#363 的事故正是守门测试从未真跑过就进了主干。
    """
    if not _MISSING_BUILD_TOOLCHAIN:
        return
    msg = f"构建工具链未安装：{_MISSING_BUILD_TOOLCHAIN}（需 build + setuptools + wheel）"
    if os.environ.get("FXAPK_REQUIRE_BUILD_TOOLCHAIN") == "1":
        pytest.fail(f"{msg}——本环境声明必须真跑产物级测试，缺链是 CI 配置错误，不许静默 skip")
    pytest.skip(msg)


def _pyproject_version() -> str:
    data = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return data["project"]["version"]


def _run(venv_python: str, code: str) -> str:
    """在隔离 venv 内执行单行 Python，返回 stdout（去首尾空白）。"""
    result = subprocess.run(
        [venv_python, "-I", "-c", code],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"子进程失败（exit {result.returncode}）:\n{result.stderr}")
    return result.stdout.strip()


def _make_venv(tmp_path: Path) -> str:
    """在 tmp_path 内创建干净 venv，返回其 python 可执行路径。"""
    venv_dir = tmp_path / "venv"
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        check=True,
        capture_output=True,
    )
    python = (
        venv_dir / "bin" / "python"
        if (venv_dir / "bin").exists()
        else venv_dir / "Scripts" / "python.exe"
    )
    return str(python)


def _pip_install(venv_python: str, *args: str) -> None:
    subprocess.run(
        [venv_python, "-m", "pip", "install", "--quiet", "--no-deps", *args],
        check=True,
        capture_output=True,
    )


def _installed_module_version(venv_python: str, venv_dir: Path) -> str:
    """在 venv 内导入 fxapk 返回 __version__；断言导入的是 venv 里装的那份而非仓库源码树。"""
    module_ver, module_file = _run(
        venv_python, "import fxapk; print(fxapk.__version__); print(fxapk.__file__)"
    ).splitlines()
    assert Path(module_file).resolve().is_relative_to(venv_dir.resolve()), (
        f"fxapk 从 {module_file} 导入，不在隔离 venv {venv_dir} 内——测到的不是安装产物"
    )
    return module_ver


def _build_artifact(dist_dir: Path, kind: str, pattern: str) -> Path:
    """构建 wheel/sdist 到 dist_dir，返回产物路径。不污染仓库 dist/。

    失败时把 build 的 stdout/stderr 完整附进异常——check=True 的裸
    CalledProcessError 不带子进程输出，CI 日志里只剩 exit 1 无从诊断（#363 实证）。
    """
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            f"--{kind}",
            "--outdir",
            str(dist_dir),
            str(_REPO_ROOT),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"python -m build --{kind} 失败（exit {result.returncode}）\n"
            f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
        )
    artifacts = list(dist_dir.glob(pattern))
    assert len(artifacts) == 1, f"预期 1 个 {pattern}，实际：{artifacts}"
    return artifacts[0]


def _build_wheel(dist_dir: Path) -> Path:
    return _build_artifact(dist_dir, "wheel", "*.whl")


def _build_sdist(dist_dir: Path) -> Path:
    return _build_artifact(dist_dir, "sdist", "*.tar.gz")


# ---------------------------------------------------------------------------
# 1. wheel 形态
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_wheel_version_consistent(tmp_path: Any) -> None:
    """wheel 安装后 importlib.metadata 版本 == fxapk.__version__。

    ★故意改坏：
    - 把 fxapk/__init__.py 里 _FALLBACK_VERSION 改成不同字串，不动 pyproject——
      wheel 打进去的 __version__ 优先取元数据，仍等于 pyproject，两者相等不报错；
      但本测试还额外断言 metadata_ver == module_ver，若 __version__ 不再读元数据
      而走错分支，两者将不等 → 本测试红。
    - 把 pyproject version 改成与元数据不同的值并重建 → metadata_ver 变，module_ver
      若仍取老元数据 → 两者不等 → 红。
    """
    _require_build_toolchain()
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    wheel_path = _build_wheel(dist_dir)

    venv_python = _make_venv(tmp_path)
    _pip_install(venv_python, str(wheel_path))

    # importlib.metadata.version("fxapk") 读已安装包元数据
    metadata_ver = _run(
        venv_python,
        "from importlib.metadata import version; print(version('fxapk'))",
    )
    # fxapk.__version__ 在 wheel 环境下应优先取元数据，与上面相等
    module_ver = _installed_module_version(venv_python, tmp_path / "venv")

    assert metadata_ver == module_ver, (
        f"wheel 安装后元数据版本({metadata_ver!r}) != 模块 __version__({module_ver!r})；"
        "说明 __version__ 没有优先读安装包元数据"
    )
    source_ver = _pyproject_version()
    assert metadata_ver == source_ver, (
        f"wheel 安装后元数据版本({metadata_ver!r}) != 源码 pyproject version({source_ver!r})；"
        "说明构建产物没带上当前声明的版本"
    )


# ---------------------------------------------------------------------------
# 2. sdist 形态
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_sdist_version_consistent(tmp_path: Any) -> None:
    """sdist 安装后 pyproject 版本 == importlib.metadata == __version__。

    ★故意改坏：
    - 构建前修改 pyproject version 但不改 _FALLBACK_VERSION → 安装后元数据取 pyproject
      的新值，module_ver 亦取元数据，两者仍相等；但 pyproject_ver（从 sdist 解包读取）
      与元数据不等 → 本测试红（sdist 还额外验 pyproject 一致性）。
    - 修改 _FALLBACK_VERSION 但不改 pyproject → sdist 里携带的 pyproject 版本不变，
      安装后元数据仍为 pyproject 值，module_ver 取元数据，与 pyproject_ver 相等；
      但安装包里 _FALLBACK_VERSION 与 pyproject 不符→ test_fallback_version_contract_holds
      那条会红（不是本条，两层互补）。
    """
    _require_build_toolchain()
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    sdist_path = _build_sdist(dist_dir)

    venv_python = _make_venv(tmp_path)
    _pip_install(venv_python, str(sdist_path))

    metadata_ver = _run(
        venv_python,
        "from importlib.metadata import version; print(version('fxapk'))",
    )
    module_ver = _installed_module_version(venv_python, tmp_path / "venv")

    # 从 sdist 解包读 pyproject 版本（验证打包时的源版本与安装后一致）
    import tarfile

    with tarfile.open(sdist_path, "r:gz") as tf:
        # pyproject.toml 在 sdist 根目录（fxapk-<ver>/pyproject.toml）
        pyproject_members = [m for m in tf.getnames() if m.endswith("/pyproject.toml")]
        assert pyproject_members, "sdist 内找不到 pyproject.toml"
        f = tf.extractfile(pyproject_members[0])
        assert f is not None
        sdist_pyproject_ver = tomllib.loads(f.read().decode())["project"]["version"]

    assert metadata_ver == module_ver, (
        f"sdist 安装后 metadata({metadata_ver!r}) != __version__({module_ver!r})"
    )
    assert sdist_pyproject_ver == metadata_ver, (
        f"sdist 内 pyproject version({sdist_pyproject_ver!r}) != 安装后元数据({metadata_ver!r})；"
        "说明 pyproject 与构建元数据不同步"
    )
    source_ver = _pyproject_version()
    assert sdist_pyproject_ver == source_ver, (
        f"sdist 内 pyproject version({sdist_pyproject_ver!r}) != 源码 pyproject version({source_ver!r})；"
        "说明 sdist 打进去的不是当前源码树的声明"
    )


# ---------------------------------------------------------------------------
# 3. editable 形态（日常开发形态）
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_editable_version_consistent(tmp_path: Any) -> None:
    """pip install -e . 后三者一致：pyproject == importlib.metadata == __version__。

    ★故意改坏（任一条均让本测试红）：
    - 改 pyproject version 不重装 → metadata_ver 仍是旧值（editable 元数据是安装时写死的）；
      module_ver 优先读元数据也是旧值；pyproject_ver 是新值 → pyproject_ver != metadata_ver → 红。
    - 改 _FALLBACK_VERSION 不改 pyproject → editable 下 __version__ 取元数据，不受影响；
      但 test_fallback_version_contract_holds 那条会红（互补）。
    - 在 __init__.py 里强制让 __version__ = _FALLBACK_VERSION（绕过元数据）→ module_ver
      变成 _FALLBACK_VERSION，若与 metadata_ver 不同 → 红。
    """
    venv_python = _make_venv(tmp_path)
    # editable install：把仓库工作树装进隔离 venv，不污染外部 venv
    _pip_install(venv_python, "-e", str(_REPO_ROOT))

    pyproject_ver = _pyproject_version()
    metadata_ver = _run(
        venv_python,
        "from importlib.metadata import version; print(version('fxapk'))",
    )
    module_ver = _run(venv_python, "import fxapk; print(fxapk.__version__)")

    assert metadata_ver == module_ver, (
        f"editable 安装后 metadata({metadata_ver!r}) != __version__({module_ver!r})"
    )
    assert pyproject_ver == metadata_ver, (
        f"pyproject version({pyproject_ver!r}) != editable 安装后 metadata({metadata_ver!r})；"
        "说明 editable 重装后元数据未与当前 pyproject 同步"
    )


# ---------------------------------------------------------------------------
# 4. 冻结/无元数据形态（dist-info 缺失时的回落行为）
# ---------------------------------------------------------------------------


#: 新解释器里执行的冻结形态探针：替换真实的 ``importlib.metadata.distribution``，只对 "fxapk"
#: 生效（miss 抛 PackageNotFoundError / present 返回指定版本），其余包照走原实现；然后从 scratch
#: 目录全新 import fxapk，打印公开 ``__version__``、模块位置与 distribution 是否被查询。
_FROZEN_PROBE = """
import importlib.metadata as md
import json
import sys

mode, scratch, present_version = sys.argv[1], sys.argv[2], sys.argv[3]
real_distribution = md.distribution
queried = []


class _PresentDistribution:
    version = present_version
    _path = None

    def locate_file(self, path):
        return ""


def distribution(name):
    if name != "fxapk":
        return real_distribution(name)
    queried.append(name)
    if mode == "missing":
        raise md.PackageNotFoundError(name)
    return _PresentDistribution()


md.distribution = distribution
sys.path.insert(0, scratch)
import fxapk

print(json.dumps({
    "version": fxapk.__version__,
    "fallback": getattr(fxapk, "_FALLBACK_VERSION", None),
    "file": fxapk.__file__,
    "queried": queried,
}))
"""

#: 与任何真实发版都不同的「已安装」版本：证明 distribution 命中时 __version__ 真取元数据。
_DISTINCT_DIST_VERSION = "999.0.0.dev0"


def _frozen_import(scratch: Path, mode: str, present_version: str = "") -> dict[str, Any]:
    """全新解释器（-I 隔离、-S 不加载 site-packages/.pth/editable finder、-B 不写字节码）里导入。"""
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c", _FROZEN_PROBE, mode, str(scratch), present_version],
        capture_output=True,
        text=True,
        cwd=scratch,
    )
    if result.returncode != 0:
        raise RuntimeError(f"冻结形态探针失败（{mode}，exit {result.returncode}）:\n{result.stderr}")
    return json.loads(result.stdout)


def test_frozen_fallback_matches_pyproject_and_is_not_silent(tmp_path: Path) -> None:
    """dist-info 缺失时公开 ``fxapk.__version__`` 回落到源码 pyproject 的版本；有元数据时取元数据。

    冻结形态 = 只有包文件、没有 dist-info：把 ``fxapk/`` 拷进 tmp_path 的 scratch 目录，
    在全新隔离解释器里从那里 import（不碰仓库 build/ 残留、不碰任何已安装的 fxapk），
    并直接控制真实 ``importlib.metadata.distribution("fxapk")`` 的 miss / present。

    ★故意改坏（每条均独立让本测试变红）：
    - 把 _FALLBACK_VERSION 改成 "" / "0.0.0" / 与 pyproject 不同的串：miss 时 __version__
      不等于源码 pyproject version → 红。
    - 版本解析不再查 distribution（如写死 __version__ = _FALLBACK_VERSION）：present 时
      __version__ 不等于 _DISTINCT_DIST_VERSION、且 queried 为空 → 红。
    - 回落分支改成别的值：miss 时 __version__ 不等于 pyproject → 红。
    """
    source_ver = _pyproject_version()
    assert source_ver and source_ver != _DISTINCT_DIST_VERSION

    scratch = tmp_path / "build" / "frozen"
    shutil.copytree(
        _REPO_ROOT / "fxapk",
        scratch / "fxapk",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    expected_file = (scratch / "fxapk" / "__init__.py").resolve()

    missing = _frozen_import(scratch, "missing")
    assert Path(missing["file"]).resolve() == expected_file, (
        f"fxapk 从 {missing['file']} 导入，不是 scratch 里的冻结副本——隔离失效"
    )
    assert missing["queried"], "版本初始化没有查询 distribution('fxapk')，miss 场景没被真正触发"
    assert missing["version"] == source_ver, (
        f"dist-info 缺失时 __version__={missing['version']!r}，不等于源码 pyproject version"
        f"({source_ver!r})；冻结形态会静默报错版本"
    )
    assert missing["fallback"] == source_ver, (
        f"_FALLBACK_VERSION({missing['fallback']!r}) != pyproject version({source_ver!r})"
    )

    present = _frozen_import(scratch, "present", _DISTINCT_DIST_VERSION)
    assert Path(present["file"]).resolve() == expected_file
    assert present["queried"], "版本初始化没有查询 distribution('fxapk')"
    assert present["version"] == _DISTINCT_DIST_VERSION, (
        f"distribution 给出 {_DISTINCT_DIST_VERSION!r} 时 __version__={present['version']!r}；"
        "说明 __version__ 没有优先取安装元数据"
    )
