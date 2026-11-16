"""通用安装文档不锁具体版本：版本专属内容只由发版流程按 tag 生成（release-notes 模板）。

PyPI 1.27.1 页面展示的 README 仍写着 ``fxapk==1.25.0``，就是这类手写版本号漂移。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_DOCS = (
    "README.md", "README.en.md", "USAGE.md", "USAGE.en.md",
    "ANDROID-UI.md", "ANDROID-UI.en.md",
)
_PINNED = re.compile(r"fxapk(?:\[[^\]]*\])?==\d|releases/tag/v\d|fxapk_[a-z_]+-\d+\.\d+\.\d+-py3")


@pytest.mark.parametrize("name", _DOCS)
def test_install_docs_do_not_pin_versions(name: str) -> None:
    text = (_ROOT / name).read_text(encoding="utf-8")
    hits = [m.group(0) for m in _PINNED.finditer(text)]
    assert not hits, f"{name} 手写了具体版本 {hits}；通用安装示例不锁版本，版本专属链接交给发版模板"


def test_release_notes_template_derives_versions_from_tag() -> None:
    template = (_ROOT / ".github" / "release-notes-template.md").read_text(encoding="utf-8")
    assert '"fxapk==$core_version"' in template
    assert not _PINNED.search(template.replace("$core_version", "").replace("$tag", ""))


def test_pattern_catches_pins() -> None:
    assert _PINNED.search('pip install "fxapk==1.25.0"')
    assert _PINNED.search("releases/tag/v1.25.0")
    assert _PINNED.search("./fxapk_android_ui-0.1.2-py3-none-any.whl")
    assert not _PINNED.search("python -m pip install fxapk")
    assert not _PINNED.search("releases/latest")
