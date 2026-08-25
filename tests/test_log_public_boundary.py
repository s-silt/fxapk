"""终端日志的公开边界：traceback 永不落终端，原始证据只进显式证据 handler。

根 handler 默认指向 ``sys.stderr``——**写进日志 ≠ 私密**。此前把"原始证据留日志"当成
私有通道是错的：``logger.exception`` 会把 ``str(exc)``、异常链 ``__cause__``、
``add_note()`` 的注记整坨渲染到用户终端，其中可能有完整 URL（含 API key）、响应正文、
子进程命令行、设备路径。只治理报告字段而放任日志，等于把泄露从一条通道搬到另一条。

这里锁两条不变量：
1. **终端**：任何带 ``exc_info`` / ``stack_info`` 的记录都只输出固定文案，且定位信息仍在；
2. **证据面**：``log_evidence`` 的原文默认终端收不到，显式证据 handler 收得到。
"""

from __future__ import annotations

import io
import logging

import pytest

from apkscan.core.logsetup import (
    EVIDENCE_ONLY_FLAG,
    PUBLIC_EXCEPTION_PLACEHOLDER,
    EvidenceOnlyFilter,
    LocatingFormatter,
    log_evidence,
    setup_logging,
)

#: 一条消息里同时塞进凭据、目标域名、本地路径。
_CANARY_URL = "https://alice:PWCANARY@leak-canary.example/a?token=TOKCANARY"
_CANARY_PATH = "/home/canary-user/cases/CASE-CANARY"
_CANARY_NEEDLES = ("PWCANARY", "TOKCANARY", "leak-canary.example", "CASE-CANARY")


@pytest.fixture
def terminal(monkeypatch: pytest.MonkeyPatch) -> io.StringIO:
    """装一个与生产同构的终端 handler，返回它的缓冲区。"""
    root = logging.getLogger()
    monkeypatch.setattr(root, "handlers", [], raising=False)
    buffer = io.StringIO()
    setup_logging(logging.DEBUG, stream=buffer)
    return buffer


def _raise_with_cause() -> None:
    try:
        raise ValueError(f"inner {_CANARY_URL}")
    except ValueError as inner:
        raise RuntimeError(f"outer {_CANARY_PATH}") from inner


def test_terminal_never_renders_exception_text(terminal: io.StringIO) -> None:
    logger = logging.getLogger("probe.exception")

    try:
        raise RuntimeError(f"boom {_CANARY_URL} {_CANARY_PATH}")
    except RuntimeError:
        logger.exception("下载失败：%s", _CANARY_URL)  # 消息里也有 canary

    output = terminal.getvalue()
    assert PUBLIC_EXCEPTION_PLACEHOLDER in output
    assert "Traceback" not in output
    for needle in _CANARY_NEEDLES:
        assert needle not in output, f"{needle} 出现在终端输出里"


def test_terminal_suppresses_exception_chain(terminal: io.StringIO) -> None:
    """``raise ... from``：标准 formatter 会把 cause 一并渲染出来。"""
    logger = logging.getLogger("probe.chain")

    try:
        _raise_with_cause()
    except RuntimeError:
        logger.exception("链式失败")

    output = terminal.getvalue()
    assert "Traceback" not in output
    for needle in _CANARY_NEEDLES:
        assert needle not in output


def test_terminal_suppresses_exception_notes(terminal: io.StringIO) -> None:
    """``add_note()`` 的注记也走 traceback 渲染。"""
    logger = logging.getLogger("probe.notes")
    exc = RuntimeError("noted")
    exc.add_note(f"note: {_CANARY_URL}")

    try:
        raise exc
    except RuntimeError:
        logger.exception("带注记")

    output = terminal.getvalue()
    for needle in _CANARY_NEEDLES:
        assert needle not in output


def test_locating_suffix_survives_suppression(terminal: io.StringIO) -> None:
    """压掉原文不能连定位一起压掉——否则排障退化成'不知道哪儿炸的'。"""
    logger = logging.getLogger("probe.locating")

    try:
        raise RuntimeError("boom")
    except RuntimeError:
        logger.exception("失败")

    output = terminal.getvalue()
    assert "[@" in output and "test_log_public_boundary" in output


def test_public_message_extra_overrides_placeholder(terminal: io.StringIO) -> None:
    """调用点可以给一句更有用的固定文案，但仍不含原文。"""
    logger = logging.getLogger("probe.public")

    try:
        raise RuntimeError(f"boom {_CANARY_URL}")
    except RuntimeError:
        logger.exception("x", extra={"public_message": "配置下载失败（详见证据日志）"})

    output = terminal.getvalue()
    assert "配置下载失败（详见证据日志）" in output
    for needle in _CANARY_NEEDLES:
        assert needle not in output


def test_evidence_only_record_never_reaches_terminal(terminal: io.StringIO) -> None:
    logger = logging.getLogger("probe.evidence")

    log_evidence(logger, "输出尾部：%s", f"{_CANARY_URL} {_CANARY_PATH}")

    output = terminal.getvalue()
    for needle in _CANARY_NEEDLES:
        assert needle not in output


def test_evidence_handler_still_receives_raw_text(terminal: io.StringIO) -> None:
    """证据面留得住：显式证据 handler 拿得到原文，否则就成了'排障无据'。"""
    evidence = io.StringIO()
    handler = logging.StreamHandler(evidence)
    handler.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(handler)
    try:
        logger = logging.getLogger("probe.evidence.kept")
        log_evidence(logger, "输出尾部：%s", _CANARY_URL)
    finally:
        logging.getLogger().removeHandler(handler)

    assert _CANARY_URL in evidence.getvalue()
    assert _CANARY_URL not in terminal.getvalue()


def test_formatter_does_not_mutate_shared_record() -> None:
    """终端 formatter 必须 copy 记录——同一条 LogRecord 会交给所有 handler。"""
    formatter = LocatingFormatter("%(message)s")
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        record = logging.LogRecord(
            "n", logging.ERROR, __file__, 1, "原始消息", (), exc_info=True
        )

    formatter.format(record)

    assert record.msg == "原始消息", "记录被就地改写，证据 handler 会一起被抹掉"
    assert record.exc_info is not None


def test_evidence_filter_passes_normal_records() -> None:
    """过滤器只挡 evidence-only，普通记录照常放行。"""
    filt = EvidenceOnlyFilter()
    normal = logging.LogRecord("n", logging.INFO, __file__, 1, "x", (), None)
    evidence = logging.LogRecord("n", logging.INFO, __file__, 1, "x", (), None)
    setattr(evidence, EVIDENCE_ONLY_FLAG, True)

    assert filt.filter(normal) is True
    assert filt.filter(evidence) is False
