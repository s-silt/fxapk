"""apkscan 动态能力子包：真机脱壳（unpack）与抓包（capture）。

本包的具体实现（unpack.py / capture.py）由动态模块 agent 完成；cli.py 通过
**惰性导入** 调用 ``apkscan.dynamic.unpack.run`` / ``apkscan.dynamic.capture.run``，
未安装时优雅降级（打印"该功能未安装"），故本 __init__ 仅占位 + 固化契约。

★ DynamicResult 契约（unpack.run / capture.run 的返回值，跨 agent 接口，禁止偏移）::

    {
        "status": "done" | "degraded" | "skipped" | "error",   # 总体结果
        "reason": str,                             # status 的人类可读说明（skipped/error/degraded 必填）
        "artifacts": list[str],                    # 产物文件路径（dump 的 .dex、pcap、har 等）
        "playbook": list[str],                     # 已执行/建议执行的操作步骤（可复现取证手法）
        "report_paths": list[str],                 # 由产物再生成的报告路径（如脱壳后重分析的报告）
    }

约定：
- 设备/工具探测一律走 apkscan.core.device（纯 subprocess、不抛）。
- 任何失败都返回 status="error" 的 DynamicResult，不抛异常给 CLI。
- 无设备/无工具时返回 status="skipped"，reason 说明缺什么。
- status="degraded"：抓包跑完但未取到可用证据（代理未起 / MITM 0 字节 / floor 未拉回 /
  端点 0）——不能伪装成 "done"，reason 说明缺哪路、capture_complete=False。
"""

from __future__ import annotations

from typing import TypedDict


class DynamicResult(TypedDict):
    """unpack/capture 的统一返回契约（见模块 docstring）。"""

    status: str  # "done" | "skipped" | "error"
    reason: str
    artifacts: list[str]
    playbook: list[str]
    report_paths: list[str]


# status 取值常量，供实现方与调用方共用，避免裸字符串拼写漂移。
STATUS_DONE = "done"
STATUS_DEGRADED = "degraded"  # 抓包跑完但无可用证据（代理/MITM/floor 均失败或端点 0）
STATUS_SKIPPED = "skipped"
STATUS_ERROR = "error"


def empty_result(status: str = STATUS_SKIPPED, reason: str = "") -> DynamicResult:
    """构造一个字段齐全的空 DynamicResult，便于实现方填充。"""
    return DynamicResult(
        status=status,
        reason=reason,
        artifacts=[],
        playbook=[],
        report_paths=[],
    )


__all__ = [
    "DynamicResult",
    "STATUS_DONE",
    "STATUS_DEGRADED",
    "STATUS_SKIPPED",
    "STATUS_ERROR",
    "empty_result",
]
