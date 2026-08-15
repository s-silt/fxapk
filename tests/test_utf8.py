"""apkscan.core.utf8 单测：enable_utf8_runtime 设 env / 幂等 / 不抛 / 不覆盖用户设定；
utf8_subprocess_env 兜上 UTF-8 标记。全程不依赖真控制台（reconfigure/ctypes 被 try 包裹）。"""

from __future__ import annotations

import os

import pytest

from apkscan.core.utf8 import enable_utf8_runtime, utf8_subprocess_env


def test_enable_utf8_runtime_sets_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PYTHONUTF8", raising=False)
    monkeypatch.delenv("PYTHONIOENCODING", raising=False)
    enable_utf8_runtime()
    assert os.environ["PYTHONUTF8"] == "1"
    assert os.environ["PYTHONIOENCODING"] == "utf-8"


def test_enable_utf8_runtime_idempotent_no_raise() -> None:
    # 二次调用不抛、不改变已生效结果。
    enable_utf8_runtime()
    enable_utf8_runtime()


def test_enable_utf8_runtime_does_not_override_user_setting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """用户显式设了 PYTHONUTF8 → setdefault 不覆盖。"""
    monkeypatch.setenv("PYTHONUTF8", "0")
    enable_utf8_runtime()
    assert os.environ["PYTHONUTF8"] == "0"


def test_utf8_subprocess_env_adds_markers() -> None:
    env = utf8_subprocess_env({"FOO": "bar"})
    assert env["FOO"] == "bar"
    assert env["PYTHONUTF8"] == "1"
    assert env["PYTHONIOENCODING"] == "utf-8"


def test_utf8_subprocess_env_does_not_override() -> None:
    env = utf8_subprocess_env({"PYTHONUTF8": "0", "PYTHONIOENCODING": "gbk"})
    assert env["PYTHONUTF8"] == "0"
    assert env["PYTHONIOENCODING"] == "gbk"


def test_utf8_subprocess_env_defaults_to_os_environ(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINEL_VAR", "xyz")
    env = utf8_subprocess_env()
    assert env["SENTINEL_VAR"] == "xyz"
    assert env["PYTHONUTF8"] == "1"
