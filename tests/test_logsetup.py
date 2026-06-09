"""apkscan.core.logsetup 单测：LocatingFormatter 给 WARNING+ 追加来源定位；
setup_logging 幂等、装 handler。"""

from __future__ import annotations

import logging

from apkscan.core.logsetup import LocatingFormatter, setup_logging


def _record(level: int, *, func: str = "myfunc", lineno: int = 42, module: str = "mymod") -> logging.LogRecord:
    rec = logging.LogRecord(
        name="apkscan.x", level=level, pathname="x.py", lineno=lineno,
        msg="boom", args=(), exc_info=None, func=func,
    )
    rec.module = module
    return rec


def test_warning_gets_location_tag() -> None:
    fmt = LocatingFormatter("%(levelname)s %(name)s: %(message)s")
    out = fmt.format(_record(logging.WARNING))
    assert "[@mymod.myfunc:42]" in out
    assert "boom" in out


def test_error_gets_location_tag() -> None:
    fmt = LocatingFormatter("%(message)s")
    assert "[@mymod.myfunc:42]" in fmt.format(_record(logging.ERROR))


def test_info_has_no_location_tag() -> None:
    fmt = LocatingFormatter("%(message)s")
    out = fmt.format(_record(logging.INFO))
    assert "[@" not in out  # INFO 不加定位，保持干净


def test_setup_logging_idempotent_and_installs_handler() -> None:
    root = logging.getLogger()
    saved = list(root.handlers)
    try:
        setup_logging()
        n1 = len(root.handlers)
        assert any(isinstance(h.formatter, LocatingFormatter) for h in root.handlers if h.formatter)
        setup_logging()  # 幂等：不重复加
        assert len(root.handlers) == n1
    finally:
        root.handlers[:] = saved
