"""apkscan.report.pdf — 把 HTML 报告转 PDF（调用本机 Chrome / Edge / Chromium 无头打印）。

PDF 派生自 HTML：先有自包含 HTML 报告，再用 Chromium 系浏览器
``--headless --print-to-pdf`` 转换（保真度等同浏览器打印）。

设计：
- 无可用浏览器 / 转换失败 → 记 warning 返回 False（PDF 跳过，绝不影响 HTML/JSON，不抛）。
- 用独立 ``--user-data-dir`` 临时目录，避免与已运行的浏览器实例冲突（否则无头任务会被
  转交给现有进程、立即返回而不产出 PDF）。
- 跨平台：PATH 命令名 + Windows / macOS 常见安装路径都探一遍。
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apkscan.core.models import Report

logger = logging.getLogger(__name__)

# 浏览器无头打印的超时（秒）：大报告渲染需要点时间。
_PRINT_TIMEOUT = 120.0

# 候选浏览器（仅 Chromium 系支持 --print-to-pdf）。先查 PATH 命令名。
_BROWSER_COMMANDS: tuple[str, ...] = (
    "chrome",
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "msedge",
    "microsoft-edge",
    "microsoft-edge-stable",
    "brave",
    "brave-browser",
)

# 各平台常见安装路径（PATH 没有时兜底）。
_KNOWN_PATHS: tuple[str, ...] = (
    # Windows
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    # macOS
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    # Linux
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/microsoft-edge",
)


def find_browser() -> str | None:
    """定位一个 Chromium 系浏览器可执行文件；找不到返回 None。"""
    for cmd in _BROWSER_COMMANDS:
        found = shutil.which(cmd)
        if found:
            return found
    for path in _KNOWN_PATHS:
        if Path(path).is_file():
            return path
    return None


def _needs_no_sandbox() -> bool:
    """是否需要传 --no-sandbox：root（Chromium 拒绝以 root 带沙箱运行）/ Windows（沙箱形态不同、保守保留既有行为）/
    FXAPK_PDF_NO_SANDBOX（受限容器逃生口）。非 root POSIX 默认返回 False → 启用浏览器沙箱（纵深防御）。"""
    if (os.environ.get("FXAPK_PDF_NO_SANDBOX") or "").strip().lower() in ("1", "true", "yes"):
        return True
    if sys.platform == "win32":
        return True
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def html_to_pdf(html_path: str, pdf_path: str, *, timeout: float = _PRINT_TIMEOUT) -> bool:
    """用无头浏览器把 html_path 打印成 pdf_path。成功 True，否则 False（不抛）。"""
    browser = find_browser()
    if browser is None:
        logger.warning(
            "未找到 Chrome/Edge/Chromium，无法导出 PDF；"
            "请安装 Chromium 系浏览器后重试，或改用 HTML 报告。"
        )
        return False

    src = Path(html_path).resolve()
    if not src.is_file():
        logger.warning("PDF 源 HTML 不存在：%s", src)
        return False

    out = Path(pdf_path)
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        logger.exception("创建 PDF 输出目录失败：%s", out.parent)
        return False
    # ★ 必须用绝对路径：浏览器按自身工作目录解析 --print-to-pdf 的相对路径会失败。
    out = out.resolve()

    udd = tempfile.mkdtemp(prefix="apkscan_pdf_")
    cmd = [
        browser,
        "--headless=new",
        "--disable-gpu",
    ]
    # --no-sandbox 弱化浏览器沙箱（纵深防御）：渲染的是本项目自产、Jinja 自动转义的报告 HTML（无不可信内容），
    # 故默认在非 root POSIX 上**启用沙箱**；仅在 root（Chromium 拒绝以 root 带沙箱运行）/ Windows（沙箱形态不同，
    # 保守保留既有行为）/ FXAPK_PDF_NO_SANDBOX（受限容器逃生口）时才加 --no-sandbox。
    if _needs_no_sandbox():
        cmd.append("--no-sandbox")
    cmd += [
        "--no-pdf-header-footer",
        f"--user-data-dir={udd}",
        f"--print-to-pdf={out}",
        src.as_uri(),  # file:// URI，自动对中文路径做百分号编码
    ]
    logger.info("导出 PDF：%s → %s（%s）", src.name, out.name, Path(browser).name)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        logger.warning("浏览器导出 PDF 超时（%ss）：%s", timeout, src)
        return False
    except Exception:
        logger.exception("调用浏览器导出 PDF 失败：%s", browser)
        return False
    finally:
        shutil.rmtree(udd, ignore_errors=True)

    if out.is_file() and out.stat().st_size > 0:
        return True
    logger.warning(
        "浏览器未产出有效 PDF（returncode=%s）。stderr 尾部：%s",
        proc.returncode,
        (proc.stderr or "")[-500:],
    )
    return False


def render(report: "Report", pdf_path: str, *, html_source: str | None = None) -> bool:
    """把 Report 导出为 PDF。

    PDF 派生自 HTML：若 html_source 指向已存在的 HTML 报告则直接转换（复用，避免重渲）；
    否则把 report 渲成临时 HTML 再转。成功 True，失败（无浏览器/转换失败）False，不抛。
    """
    if html_source and Path(html_source).is_file():
        return html_to_pdf(html_source, pdf_path)

    # 没有现成 HTML：渲一份临时 HTML 再转。
    from apkscan.report import html as report_html

    tmp_dir = tempfile.mkdtemp(prefix="apkscan_pdfhtml_")
    try:
        tmp_html = Path(tmp_dir) / "report.html"
        try:
            report_html.render(report, str(tmp_html))
        except Exception:
            logger.exception("渲染临时 HTML 失败，无法导出 PDF")
            return False
        return html_to_pdf(str(tmp_html), pdf_path)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


__all__ = ["find_browser", "html_to_pdf", "render"]
