"""apkscan.core.logsetup — 统一日志配置 + **错误定位标识**。

入口（cli.main / gui.main）调一次 :func:`setup_logging`，给根 logger 装一个会在
**WARNING 及以上**的每条日志末尾自动追加来源定位 ``[@<module>.<funcName>:<lineno>]`` 的
格式器。这样用户把日志贴回来时，一眼能看到错误是从哪个函数/行打出来的，便于精确反馈定位、
快速修改——无需逐条手工编码错误号、零维护。

设计：
- 仅 WARNING+ 追加定位（INFO 保持干净，不刷屏）。
- 幂等：重复调用不重复加 handler；先于各命令里残留的 ``logging.basicConfig`` 调用执行即可
  让本格式器生效（basicConfig 在根 logger 已有 handler 时是 no-op）。
- 绝不抛；仅 stdlib（logging/sys），便于各入口早调用。
"""

from __future__ import annotations

import logging
import sys

_DEFAULT_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
# handler 上的标记，避免重复安装。
_MARKER = "_apkscan_locating_handler"


class LocatingFormatter(logging.Formatter):
    """WARNING 及以上记录末尾追加 ``[@module.funcName:lineno]`` 来源定位。"""

    def format(self, record: logging.LogRecord) -> str:
        text = super().format(record)
        if record.levelno >= logging.WARNING:
            try:
                text = f"{text}  [@{record.module}.{record.funcName}:{record.lineno}]"
            except Exception:  # noqa: BLE001 — 定位拼接绝不能影响日志本身
                pass
        return text


def setup_logging(level: int = logging.INFO, *, stream: object | None = None) -> None:
    """安装带「错误定位标识」的根日志 handler。幂等、绝不抛。

    Args:
        level: 根 logger 级别（默认 INFO）。
        stream: 输出流（默认 ``sys.stderr``；None 时用 stderr）。
    """
    try:
        root = logging.getLogger()
        root.setLevel(level)
        # 已装过本 handler → 仅调级别即可，不重复加。
        for handler in root.handlers:
            if getattr(handler, _MARKER, False):
                return
        out = stream if stream is not None else sys.stderr
        new_handler = logging.StreamHandler(out)  # type: ignore[arg-type]
        new_handler.setFormatter(LocatingFormatter(_DEFAULT_FORMAT))
        setattr(new_handler, _MARKER, True)
        # 清掉已有 handler（如 basicConfig 装的），避免重复输出 + 让定位格式器接管。
        for old in list(root.handlers):
            root.removeHandler(old)
        root.addHandler(new_handler)
    except Exception:  # noqa: BLE001 — 日志配置失败不得阻断启动
        logging.getLogger(__name__).debug("setup_logging 失败（忽略）", exc_info=True)


__all__ = ["LocatingFormatter", "setup_logging"]
