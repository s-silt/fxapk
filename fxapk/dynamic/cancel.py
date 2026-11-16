"""人工取消。停止后续抓包、旁路和闭环，不当成同意，也不当成闭环失败。"""

from __future__ import annotations


class AutoCancelled(Exception):
    """拒绝、Ctrl+C、Abort 或确认回调失败。调用方停后续步骤；本次资源仍由 finally 收。"""

    @property
    def reason(self) -> str:
        if self.args and isinstance(self.args[0], str):
            return self.args[0]
        return "cancelled"

    @property
    def code(self) -> str:
        """固定取消码（与 ``reason`` 同值），供日志等公开出口使用。"""
        return self.reason


#: 稳定取消出口。未知错误和操作失败继续用既有非零码，不占用 130。
CANCEL_EXIT_CODE = 130
