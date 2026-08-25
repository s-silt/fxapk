"""apkscan.core.logsetup — 统一日志配置 + **错误定位标识** + **终端公开边界**。

入口（cli.main / gui.main）调一次 :func:`setup_logging`，给根 logger 装一个会在
**WARNING 及以上**的每条日志末尾自动追加来源定位 ``[@<module>.<funcName>:<lineno>]`` 的
格式器。这样用户把日志贴回来时，一眼能看到错误是从哪个函数/行打出来的，便于精确反馈定位、
快速修改——无需逐条手工编码错误号、零维护。

设计：
- 仅 WARNING+ 追加定位（INFO 保持干净，不刷屏）。
- 幂等：重复调用不重复加 handler；先于各命令里残留的 ``logging.basicConfig`` 调用执行即可
  让本格式器生效（basicConfig 在根 logger 已有 handler 时是 no-op）。
- 绝不抛；仅 stdlib（logging/sys），便于各入口早调用。

## ★终端就是公开边界

根 handler 默认指向 ``sys.stderr``——**写进日志 ≠ 私密**。``logger.exception(...)`` 会把整坨
traceback（含 ``str(exc)``、异常链 ``__cause__``、``add_note()`` 的注记）直接渲染到用户终端；
这些文本可能带完整 URL（含 API key）、响应正文、子进程命令行、设备路径、案件目标值。
只治理报告字段而放任日志，等于把泄露从一条通道搬到另一条。

因此本模块定义两件事：

1. :class:`LocatingFormatter` 对**带 ``exc_info`` / ``stack_info`` 的记录**不渲染原文，
   只输出固定文案（或调用点显式给的 ``public_message``）。一处 formatter 覆盖全仓所有
   ``logger.exception`` 调用点，无需逐个改写。
2. ``extra={"evidence_only": True}`` 的记录终端**整条丢弃**——子进程输出尾部、响应正文这类
   没有 ``exc_info`` 的原始证据走这条路：默认不落任何地方，只有显式配置的证据 handler 才收。

**未覆盖的面**：不带 ``exc_info`` 的普通插值（``logger.error("%s", exc)``、f-string 拼进
message 的）仍会原样输出——那要靠调用点自己脱敏，本模块拦不住，静态扫描
（``tests/test_no_raw_exception_in_public_sinks.py``）负责守。
"""

from __future__ import annotations

import copy
import logging
import sys

_DEFAULT_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
# handler 上的标记，避免重复安装。
_MARKER = "_apkscan_locating_handler"

#: 带 exc_info 的记录在终端上的兜底文案（调用点可用 extra={"public_message": ...} 覆盖）。
PUBLIC_EXCEPTION_PLACEHOLDER = "操作失败（异常详情不写入终端；如需诊断请启用证据日志）"

#: ``extra`` 里带这个标记的记录＝原始证据，终端 handler 整条丢弃。
EVIDENCE_ONLY_FLAG = "evidence_only"


class EvidenceOnlyFilter(logging.Filter):
    """挡掉标了 ``evidence_only`` 的记录——它们只该进显式证据 handler。"""

    def filter(self, record: logging.LogRecord) -> bool:
        return not getattr(record, EVIDENCE_ONLY_FLAG, False)


class LocatingFormatter(logging.Formatter):
    """终端格式器：追加来源定位；**带 traceback 的记录不渲染原文**。

    ``exc_info`` / ``stack_info`` 一旦存在，标准 formatter 会把 ``str(exc)``、异常链与注记
    全部拼进输出。这里改成只输出固定文案：既保住"哪个函数第几行出错"的定位（末尾的
    ``[@module.func:lineno]`` 仍在），又不让异常正文落到终端。

    ★``args`` / ``exc_text`` / ``stack_info`` 必须一并清掉：只清 ``exc_info`` 不够——
    ``logger.exception("失败：%s", exc)`` 的原文在 message 里，``exc_text`` 还可能已被
    别的 handler 缓存过。
    ★必须 copy 记录再改：同一条 ``LogRecord`` 会被交给所有 handler，就地修改会把证据
    handler 的内容一起抹掉。
    """

    def format(self, record: logging.LogRecord) -> str:
        if record.exc_info or record.stack_info:
            record = copy.copy(record)
            record.msg = getattr(record, "public_message", PUBLIC_EXCEPTION_PLACEHOLDER)
            record.args = ()
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
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
        new_handler.addFilter(EvidenceOnlyFilter())
        setattr(new_handler, _MARKER, True)
        # 清掉已有 handler（如 basicConfig 装的），避免重复输出 + 让定位格式器接管。
        for old in list(root.handlers):
            root.removeHandler(old)
        root.addHandler(new_handler)
    except Exception:  # noqa: BLE001 — 日志配置失败不得阻断启动
        logging.getLogger(__name__).debug("setup_logging 失败（忽略）", exc_info=True)


def log_evidence(logger: logging.Logger, message: str, *args: object) -> None:
    """把**原始证据**（子进程输出、响应正文、路径）记成 evidence-only。

    默认终端 handler 会整条丢弃它；只有显式配置的证据 handler 才收得到。
    调用点不必自己判断"这条能不能打"——凡是原文，走这里。
    """
    logger.debug(message, *args, extra={EVIDENCE_ONLY_FLAG: True})


__all__ = [
    "EVIDENCE_ONLY_FLAG",
    "PUBLIC_EXCEPTION_PLACEHOLDER",
    "EvidenceOnlyFilter",
    "LocatingFormatter",
    "log_evidence",
    "setup_logging",
]
