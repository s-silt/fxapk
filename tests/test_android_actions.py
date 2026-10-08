from __future__ import annotations

import pytest

from apkscan.dynamic.actions import AndroidActions


class _Proc:
    def __init__(self, code: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = code
        self.stdout = stdout
        self.stderr = stderr


def test_actions_require_serial() -> None:
    with pytest.raises(ValueError, match="serial_required"):
        AndroidActions(serial="", package="com.example.synthetic")


def test_tap_uses_fixed_adb_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []
    monkeypatch.setattr(AndroidActions, "foreground_package", lambda self: self.package)
    monkeypatch.setattr("apkscan.dynamic.actions.device._run", lambda args, **kwargs: seen.append(args) or _Proc())
    actions = AndroidActions(serial="device-1", package="com.example.synthetic")

    assert actions.tap(10, 20).ok is True
    assert seen == [["adb", "-s", "device-1", "shell", "input", "tap", "10", "20"]]


def test_input_text_does_not_include_value_in_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(AndroidActions, "foreground_package", lambda self: self.package)
    monkeypatch.setattr("apkscan.dynamic.actions.device._run", lambda _args, **_kwargs: _Proc())
    actions = AndroidActions(serial="device-1", package="com.example.synthetic")

    result = actions.input_text("synthetic password")

    assert result.ok is True
    assert result.value_length == len("synthetic password")
    assert "password" not in result.detail


def test_foreground_unparseable_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("apkscan.dynamic.actions.device._run", lambda _args, **kwargs: _Proc(stdout="unknown format"))
    actions = AndroidActions(serial="device-1", package="com.example.synthetic")

    assert actions.foreground_package() is None



@pytest.mark.parametrize("value", ["hello;id", "$(id)", "a'b\"c", "a&b|c>d", "synthetic password"])
def test_input_text_is_one_literal_remote_shell_argument(monkeypatch, value) -> None:
    import shlex

    seen = []
    monkeypatch.setattr(AndroidActions, "foreground_package", lambda self: self.package)
    monkeypatch.setattr("apkscan.dynamic.actions.device._run", lambda args, **kwargs: seen.append(args) or _Proc())

    result = AndroidActions(serial="device-1", package="com.example.synthetic").input_text(value)

    assert result.ok
    command = " ".join(seen[-1][4:])
    # ADB joins shell argv again; quote characters must survive that boundary.
    assert shlex.split(command) == ["input", "text", value.replace(" ", "%s")]
    assert seen[-1][-1].startswith("'")


@pytest.mark.parametrize("value", ["literal%svalue", "tab\tvalue", "nonascii\u2603"])
def test_input_text_rejects_values_adb_cannot_preserve(monkeypatch, value) -> None:
    monkeypatch.setattr("apkscan.dynamic.actions.device._run", lambda *_a, **_k: pytest.fail("invalid text reached adb"))
    with pytest.raises(ValueError, match="invalid_input_text"):
        AndroidActions(serial="device-1", package="com.example.synthetic").input_text(value)


@pytest.mark.parametrize("failure", ["timeout", "called_process", "oserror"])
def test_input_text_failure_logs_do_not_expose_value(monkeypatch, caplog, failure) -> None:
    import logging
    import subprocess

    from apkscan.core import device

    secret = "synthetic-secret-321"
    monkeypatch.setattr(AndroidActions, "foreground_package", lambda self: self.package)
    monkeypatch.setattr(device.tools, "adb_path", lambda: "synthetic-adb")

    def fail(argv, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(argv, 1)
        if failure == "called_process":
            raise subprocess.CalledProcessError(1, argv)
        raise OSError("failed " + secret)

    monkeypatch.setattr(device.subprocess, "run", fail)
    with caplog.at_level(logging.DEBUG, logger=device.__name__):
        result = AndroidActions(serial="device-1", package="com.example.synthetic").input_text(secret)

    assert not result.ok
    assert secret not in caplog.text
    assert "input text" in caplog.text
    assert "redacted" in caplog.text


@pytest.mark.parametrize("operation", [lambda a: a.tap(1, 2), lambda a: a.input_text("synthetic"), lambda a: a.back()])
@pytest.mark.parametrize("foreground", [None, "com.example.other"])
def test_mutating_actions_refuse_unconfirmed_foreground(monkeypatch, operation, foreground) -> None:
    monkeypatch.setattr(AndroidActions, "foreground_package", lambda self: foreground)
    monkeypatch.setattr("apkscan.dynamic.actions.device._run", lambda *_a, **_k: pytest.fail("unbound action reached adb"))

    result = operation(AndroidActions(serial="device-1", package="com.example.synthetic"))

    assert not result.ok
    assert result.detail == "target_foreground_unconfirmed"



def test_adb_timeouts_follow_remaining_action_deadline(monkeypatch) -> None:
    from apkscan.dynamic import actions as action_module
    clock = [10.0]
    timeouts = []
    monkeypatch.setattr(action_module.time, "monotonic", lambda: clock[0])

    def run(args, **kwargs):
        timeouts.append(kwargs["timeout"])
        clock[0] += 0.75
        return _Proc(stdout="mResumedActivity: ActivityRecord{u0 com.example.synthetic/.Main}")

    monkeypatch.setattr(action_module.device, "_run", run)
    result = AndroidActions(serial="device-1", package="com.example.synthetic", deadline=11.0).tap(1, 2)
    assert result.ok
    assert timeouts == [1.0, 0.25]


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
@pytest.mark.parametrize("root_actions", [False, True])
@pytest.mark.parametrize("operation", [lambda a: a.tap(1, 2), lambda a: a.input_text("synthetic-secret"), lambda a: a.back()])
def test_exit_zero_security_exception_is_failure(monkeypatch, stream, root_actions, operation):
    monkeypatch.setattr(AndroidActions, "foreground_package", lambda self: self.package)
    proc = _Proc(**{stream: "java.lang.SecurityException: Injecting input events requires INJECT_EVENTS permission: synthetic-secret"})
    monkeypatch.setattr("apkscan.dynamic.actions.device._run", lambda *_a, **_k: proc)
    result = operation(AndroidActions(serial="device-1", package="com.example.synthetic", root_actions=root_actions))
    assert result.ok is False
    assert result.detail == "injection_permission_denied"
    assert "synthetic-secret" not in str(result.to_dict())


@pytest.mark.parametrize("text", ["Error: Invalid arguments", "Exception occurred while executing 'tap'", "su: Permission denied"])
def test_known_command_error_prefix_fails_even_at_exit_zero(monkeypatch, text):
    monkeypatch.setattr(AndroidActions, "foreground_package", lambda self: self.package)
    monkeypatch.setattr("apkscan.dynamic.actions.device._run", lambda *_a, **_k: _Proc(stdout=text))
    result = AndroidActions(serial="device-1", package="com.example.synthetic").tap(1, 2)
    assert not result.ok
    assert result.detail == "device_command_failed"


@pytest.mark.parametrize("text", ["Events injected: 1", "0 errors", "normal text mentions Error: later in a sentence"])
def test_normal_command_output_is_not_an_error(monkeypatch, text):
    monkeypatch.setattr(AndroidActions, "foreground_package", lambda self: self.package)
    monkeypatch.setattr("apkscan.dynamic.actions.device._run", lambda *_a, **_k: _Proc(stdout=text))
    assert AndroidActions(serial="device-1", package="com.example.synthetic").tap(1, 2).ok


@pytest.mark.parametrize("value", ["a,b", "a'b\"c", "$(id);x&y", "synthetic password"])
def test_explicit_root_text_preserves_two_shell_boundaries_and_redacts_logs(monkeypatch, value):
    import shlex

    calls = []
    monkeypatch.setattr(AndroidActions, "foreground_package", lambda self: self.package)
    monkeypatch.setattr("apkscan.dynamic.actions.device._run", lambda args, **kwargs: calls.append((args, kwargs)) or _Proc())
    result = AndroidActions(serial="device-exact", package="com.example.synthetic", root_actions=True).input_text(value)
    assert result.ok
    argv, kwargs = calls[0]
    assert argv[:4] == ["adb", "-s", "device-exact", "shell"]
    outer = shlex.split(" ".join(argv[4:]))
    assert outer[:2] == ["su", "-c"]
    assert len(outer) == 3
    assert shlex.split(outer[2]) == ["input", "text", value.replace(" ", "%s")]
    assert value not in str(kwargs["log_args"])
    assert "[redacted]" in str(kwargs["log_args"])


@pytest.mark.parametrize("operation,expected", [(lambda a: a.tap(12, 34), ["input", "tap", "12", "34"]),
                                               (lambda a: a.back(), ["input", "keyevent", "BACK"])])
def test_root_input_is_explicit_and_remains_package_and_serial_bound(monkeypatch, operation, expected):
    import shlex

    calls = []
    monkeypatch.setattr(AndroidActions, "foreground_package", lambda self: self.package)
    monkeypatch.setattr("apkscan.dynamic.actions.device._run", lambda args, **kwargs: calls.append(args) or _Proc())
    assert operation(AndroidActions(serial="device-exact", package="com.example.synthetic", root_actions=True)).ok
    assert calls[0][:6] == ["adb", "-s", "device-exact", "shell", "su", "-c"]
    assert shlex.split(shlex.split(" ".join(calls[0][4:]))[2]) == expected
    calls.clear()
    monkeypatch.setattr(AndroidActions, "foreground_package", lambda self: "com.example.other")
    assert not operation(AndroidActions(serial="device-exact", package="com.example.synthetic", root_actions=True)).ok
    assert calls == []


def test_root_actions_requires_a_boolean():
    with pytest.raises(ValueError, match="invalid_root_actions"):
        AndroidActions(serial="device-1", package="com.example.synthetic", root_actions="yes")
