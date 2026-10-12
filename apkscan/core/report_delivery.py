"""报告写出结果。成功与失败分开列，调用方按结果决定退出，不看目录里是否已有旧文件。"""

from __future__ import annotations

from dataclasses import dataclass


_REQUIRED = frozenset({"json", "html"})


@dataclass(frozen=True)
class ReportDelivery:
    """一次写出请求的结果。

    ``failed`` 只放本次请求了但没写成的 json/html。PDF 缺工具记在 ``skipped``。
    同目录里原有的 canonical 文件不在 ``written`` 里，不能当成这次成功。
    """

    requested: tuple[str, ...]
    written: tuple[str, ...]
    failed: tuple[str, ...]
    skipped: tuple[str, ...]

    def blocks_success(self) -> bool:
        """json/html 有失败，或请求了格式但一份都没写成（含只请求 PDF）。"""
        for fmt in self.requested:
            if fmt in _REQUIRED and fmt in self.failed:
                return True
        return bool(self.requested) and not self.written


def combine_deliveries(items: list[object]) -> ReportDelivery | None:
    """合并同一次任务里的多段写出。任一必需格式失败都保留在 failed 里。"""
    requested: list[str] = []
    written: list[str] = []
    failed: list[str] = []
    skipped: list[str] = []
    saw = False
    for item in items:
        if not isinstance(item, ReportDelivery):
            continue
        saw = True
        for bucket, source in (
            (requested, item.requested),
            (written, item.written),
            (failed, item.failed),
            (skipped, item.skipped),
        ):
            for fmt in source:
                if fmt not in bucket:
                    bucket.append(fmt)
    if not saw:
        return None
    return ReportDelivery(tuple(requested), tuple(written), tuple(failed), tuple(skipped))
