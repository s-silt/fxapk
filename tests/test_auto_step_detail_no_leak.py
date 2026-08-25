"""auto 七个流水线兜底：未预期异常不得把异常文本带进 step.detail。

这七个 ``except Exception`` 是流水线的最后防线——它们捕获的是**未预期**异常，
消息可能来自第三方库、子进程输出或网络响应（带 URL、token、案件目标值）。
``step.detail`` 会走 ``_print_dynamic_result`` 直接打给用户看，是公开诊断边界。

**为什么固定文案而不是 ``safe_exception_text(exc)``**：后者的价值是让**已建立公开
诊断契约的异常**穿过边界；这里到了兜底仍是未知异常，类型名对用户没有行动价值，
反而会把内部实现类型变成外部稳定接口。已知且可操作的失败应在更靠近来源处转成
结构化结果或错误码，不该由这七个总兜底自动放行。原始证据由 ``logger.exception`` 留在日志。
"""

from __future__ import annotations

from typing import Any

import pytest

from apkscan.dynamic import STATUS_ERROR, auto

#: 三类不该外泄的值揉进同一个异常消息里。
_SECRET = "https://user:pw@leak-canary.example/a?token=CANARY_SECRET /home/u/cases/CASE-X"


class _LeakyError(RuntimeError):
    """消息里带凭据/目标/路径的未预期异常。"""


def _boom(*_args: Any, **_kwargs: Any) -> Any:
    raise _LeakyError(_SECRET)


#: (step 名, 调用 _run_* 的 thunk, 要打桩的模块与属性)
_CASES = [
    ("环境体检", lambda: auto._run_doctor(auto_fix=False, on_progress=None), ("apkscan.dynamic.doctor", "run")),
    (
        "静态分析",
        lambda: auto._run_static(
            "x.apk", out_dir="out", online=False, formats=["json"], on_progress=None
        ),
        ("apkscan.core.apk", "load_apk"),
    ),
    (
        "安装到设备",
        lambda: auto._run_install_app("x.apk", on_progress=None),
        ("apkscan.dynamic.provision", "install_apk"),
    ),
    (
        "脱壳",
        lambda: auto._run_unpack("x.apk", out_dir="out", has_device=True, on_progress=None),
        ("apkscan.dynamic.unpack", "run"),
    ),
    (
        "去壳重打包",
        lambda: auto._run_repackage(
            "x.apk", "com.example.app", out_dir="out", has_device=True, on_progress=None
        ),
        ("apkscan.dynamic.repackage", "run"),
    ),
    (
        "抓包",
        lambda: auto._run_capture(
            "com.example.app",
            out_dir="out",
            has_device=True,
            duration=1,
            on_progress=None,
            confirm=None,
        ),
        ("apkscan.dynamic.capture", "run"),
    ),
]


@pytest.mark.parametrize(("label", "call", "target"), _CASES, ids=[c[0] for c in _CASES])
def test_step_detail_never_carries_exception_text(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    label: str,
    call: Any,
    target: tuple[str, str],
) -> None:
    module_name, attr = target
    module = __import__(module_name, fromlist=[attr])
    monkeypatch.setattr(module, attr, _boom)
    caplog.set_level("ERROR")

    result = call()
    step = result[0] if isinstance(result, tuple) else result

    assert step["status"] == STATUS_ERROR
    detail = str(step["detail"])
    assert "详见日志" in detail, f"{label} 的兜底应指向日志"
    # 三类值逐个锁：任一出现都是回显面。
    assert "CANARY_SECRET" not in detail
    assert "leak-canary.example" not in detail
    assert "/home/u/cases/CASE-X" not in detail
    assert _SECRET not in detail
    # 类型名也不给：它对用户没有行动价值，且会把内部实现类型变成外部契约。
    assert "_LeakyError" not in detail
