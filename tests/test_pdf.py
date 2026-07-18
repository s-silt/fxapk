"""apkscan.report.pdf 测试：全程 mock 浏览器与 subprocess，不真起 Chrome。"""

from __future__ import annotations

import subprocess
from pathlib import Path


from apkscan.report import pdf


def _src_html(tmp_path: Path) -> Path:
    p = tmp_path / "report.html"
    p.write_text("<html><body>报告</body></html>", encoding="utf-8")
    return p


def _run_writes_pdf(cmd, **kwargs):  # noqa: ANN001
    """替身 subprocess.run：把 --print-to-pdf= 目标写成一个假 PDF。"""
    pdf_arg = next(a for a in cmd if a.startswith("--print-to-pdf="))
    out = Path(pdf_arg.split("=", 1)[1])
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(b"%PDF-1.4\nfake pdf content\n%%EOF")
    return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")


def _run_no_output(cmd, **kwargs):  # noqa: ANN001
    """替身：浏览器非零退出且不产出 PDF。"""
    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom")


# --- find_browser -----------------------------------------------------------


def test_no_browser_returns_false(monkeypatch, tmp_path):
    monkeypatch.setattr(pdf, "find_browser", lambda: None)
    src = _src_html(tmp_path)
    ok = pdf.html_to_pdf(str(src), str(tmp_path / "out.pdf"))
    assert ok is False
    assert not (tmp_path / "out.pdf").exists()


# --- html_to_pdf 成功 -------------------------------------------------------


def test_html_to_pdf_success(monkeypatch, tmp_path):
    monkeypatch.setattr(pdf, "find_browser", lambda: "fake-chrome")
    monkeypatch.setattr(pdf.subprocess, "run", _run_writes_pdf)
    src = _src_html(tmp_path)
    out = tmp_path / "out.pdf"
    ok = pdf.html_to_pdf(str(src), str(out))
    assert ok is True
    assert out.is_file() and out.stat().st_size > 0


def test_html_to_pdf_browser_no_output(monkeypatch, tmp_path):
    monkeypatch.setattr(pdf, "find_browser", lambda: "fake-chrome")
    monkeypatch.setattr(pdf.subprocess, "run", _run_no_output)
    src = _src_html(tmp_path)
    ok = pdf.html_to_pdf(str(src), str(tmp_path / "out.pdf"))
    assert ok is False


def test_html_to_pdf_timeout(monkeypatch, tmp_path):
    def _raise(cmd, **kwargs):  # noqa: ANN001
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(pdf, "find_browser", lambda: "fake-chrome")
    monkeypatch.setattr(pdf.subprocess, "run", _raise)
    src = _src_html(tmp_path)
    ok = pdf.html_to_pdf(str(src), str(tmp_path / "out.pdf"))
    assert ok is False


def test_missing_source_html(monkeypatch, tmp_path):
    monkeypatch.setattr(pdf, "find_browser", lambda: "fake-chrome")
    ok = pdf.html_to_pdf(str(tmp_path / "nope.html"), str(tmp_path / "out.pdf"))
    assert ok is False


# --- render ----------------------------------------------------------------


def test_render_reuses_existing_html(monkeypatch, tmp_path):
    monkeypatch.setattr(pdf, "find_browser", lambda: "fake-chrome")
    monkeypatch.setattr(pdf.subprocess, "run", _run_writes_pdf)
    src = _src_html(tmp_path)
    out = tmp_path / "out.pdf"
    ok = pdf.render(report=None, pdf_path=str(out), html_source=str(src))
    assert ok is True
    assert out.is_file()


def test_render_falls_back_to_temp_html(monkeypatch, tmp_path):
    monkeypatch.setattr(pdf, "find_browser", lambda: "fake-chrome")
    monkeypatch.setattr(pdf.subprocess, "run", _run_writes_pdf)

    # 无 html_source：render 会 import apkscan.report.html 渲临时 HTML，monkeypatch 掉它。
    import apkscan.report.html as report_html

    def _fake_render(report, path):  # noqa: ANN001
        Path(path).write_text("<html>tmp</html>", encoding="utf-8")

    monkeypatch.setattr(report_html, "render", _fake_render)
    out = tmp_path / "out.pdf"
    ok = pdf.render(report=object(), pdf_path=str(out), html_source=None)
    assert ok is True
    assert out.is_file()


# --- --no-sandbox 条件化（codex 审计 P2）-----------------------------------


def test_needs_no_sandbox_env_and_root(monkeypatch):
    """★回归（codex 审计 P2）：默认非 root POSIX 启用浏览器沙箱；root / env 覆盖 才加 --no-sandbox。"""
    monkeypatch.setattr(pdf.sys, "platform", "linux")
    monkeypatch.delenv("FXAPK_PDF_NO_SANDBOX", raising=False)
    monkeypatch.setattr(pdf.os, "geteuid", lambda: 1000, raising=False)
    assert pdf._needs_no_sandbox() is False  # 非 root POSIX → 启用沙箱
    monkeypatch.setattr(pdf.os, "geteuid", lambda: 0, raising=False)
    assert pdf._needs_no_sandbox() is True  # root → 必须 --no-sandbox
    monkeypatch.setattr(pdf.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setenv("FXAPK_PDF_NO_SANDBOX", "1")
    assert pdf._needs_no_sandbox() is True  # env 逃生口


def test_html_to_pdf_omits_no_sandbox_for_nonroot_posix(monkeypatch, tmp_path):
    """非 root POSIX：导出命令不含 --no-sandbox（启用沙箱，纵深防御）。"""
    captured: dict = {}

    def _capture(cmd, **kwargs):  # noqa: ANN001
        captured["cmd"] = list(cmd)
        return _run_writes_pdf(cmd, **kwargs)

    monkeypatch.setattr(pdf, "find_browser", lambda: "fake-chrome")
    monkeypatch.setattr(pdf, "_needs_no_sandbox", lambda: False)
    monkeypatch.setattr(pdf.subprocess, "run", _capture)
    assert pdf.html_to_pdf(str(_src_html(tmp_path)), str(tmp_path / "out.pdf")) is True
    assert "--no-sandbox" not in captured["cmd"]


def test_html_to_pdf_includes_no_sandbox_when_needed(monkeypatch, tmp_path):
    """root / Windows / env：导出命令含 --no-sandbox。"""
    captured: dict = {}

    def _capture(cmd, **kwargs):  # noqa: ANN001
        captured["cmd"] = list(cmd)
        return _run_writes_pdf(cmd, **kwargs)

    monkeypatch.setattr(pdf, "find_browser", lambda: "fake-chrome")
    monkeypatch.setattr(pdf, "_needs_no_sandbox", lambda: True)
    monkeypatch.setattr(pdf.subprocess, "run", _capture)
    assert pdf.html_to_pdf(str(_src_html(tmp_path)), str(tmp_path / "out.pdf")) is True
    assert "--no-sandbox" in captured["cmd"]
