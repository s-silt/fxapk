"""Credential files are unnecessary for the public leak-scan/version entrypoints."""
from __future__ import annotations

import sys

import pytest

from apkscan import cli
from apkscan.core import dotenv, logsetup, utf8


@pytest.mark.parametrize("argv", [
    ["--version"], ["--help"], ["leak-scan", "--staged", "--strict"],
    ["ui", "--help"], ["ui", "capabilities"], ["ui", "snapshot"], ["ui", "run-plan"],
])
def test_offline_entrypoints_do_not_load_credentials(monkeypatch, argv):
    def forbidden():
        raise AssertionError("credential file must not be read")
    calls = []
    monkeypatch.setattr(sys, "argv", ["fxapk", *argv])
    monkeypatch.setattr(dotenv, "load_dotenv", forbidden)
    monkeypatch.setattr(logsetup, "setup_logging", lambda: None)
    monkeypatch.setattr(utf8, "enable_utf8_runtime", lambda: None)
    monkeypatch.setattr(cli, "app", lambda: calls.append("dispatch"))
    cli.main()
    assert calls == ["dispatch"]


def test_analysis_entrypoint_keeps_environment_loading(monkeypatch):
    calls = []
    monkeypatch.setattr(sys, "argv", ["fxapk", "analyze", "synthetic.apk", "--offline"])
    monkeypatch.setattr(dotenv, "load_dotenv", lambda: calls.append("load"))
    monkeypatch.setattr(logsetup, "setup_logging", lambda: None)
    monkeypatch.setattr(utf8, "enable_utf8_runtime", lambda: None)
    monkeypatch.setattr(cli, "app", lambda: calls.append("dispatch"))
    cli.main()
    assert calls == ["load", "dispatch"]
