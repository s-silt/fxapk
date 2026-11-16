"""报告文件名 base 计算 + 文件名清理（无依赖，cli/auto/merge/controller 共用）。

用户已定口径：报告文件名用**所分析 APK 的文件名去后缀**作 base（demo.apk → demo.json /
demo.html / demo.pdf），多次分析互不覆盖、可区分。

设计铁律（与项目其它 core 模块一致）：
- 全程 type hints；绝不抛——任何异常路径都回退到安全 base。
- 中文保留（报告本就中文）；仅替换 Windows 非法字符与控制字符。
- ``runtime_report.json`` 是 capture 的独立契约名，不经本模块（调用方不要用它当 base）。
"""

from __future__ import annotations

import re
from pathlib import Path

# Windows 文件名非法字符 <>:"/\|?* 与控制字符（\x00-\x1f）。
_ILLEGAL_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')

# Windows 保留设备名（大小写不敏感）。叫 CON/NUL/COM1 等的文件名即便加后缀也可能被
# 当作 DOS 设备处理，为稳妥加 ``_`` 前缀避开。杀猪盘 APK 名多为 hash/中文，命中概率极低。
_RESERVED_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)


def sanitize_base(name: str) -> str:
    """把任意字符串清理成安全的报告文件名 base（不含扩展名、不含目录分隔符）。

    规则（顺序固定）：
      1. 非法字符 ``<>:"/\\|?*`` 与控制字符 → ``_``；
      2. 去首尾空白；
      3. 去首尾点（Windows 不允许文件名以点结尾）；
      4. 再去一次首尾空白（步骤 3 可能暴露出新的首尾空白）；
      5. 命中 Windows 保留设备名（CON/NUL/COM1… 大小写不敏感）→ 加 ``_`` 前缀。

    结果为空 → 返回 ``""``（交由 :func:`report_base` 回退）。中文等非 ASCII 字符保留。
    """
    cleaned = _ILLEGAL_RE.sub("_", name)
    cleaned = cleaned.strip().strip(".").strip()
    # 保留名判定按「点前主名」比较（``NUL.apk`` 已在 stem 阶段去后缀，这里多为保险）。
    if cleaned and cleaned.split(".", 1)[0].lower() in _RESERVED_NAMES:
        cleaned = "_" + cleaned
    return cleaned


def report_base(apk_path: str, package_name: str = "") -> str:
    """报告文件名 base：APK 文件名去后缀并清理；空/异常 → 清理后的 package_name
    → 再回退 ``"report"``。**绝不抛**，永远返回非空合法 base。

    - APK 去后缀用 ``Path(apk_path).stem``（``demo.apk`` → ``demo``，``a.b.apk`` → ``a.b``）。
    - 多重回退保证：哪怕 apk 名清理后全空、包名也空，仍返回 ``"report"``。

    Args:
        apk_path: 被分析的 APK 文件路径（取 stem 作首选 base）。
        package_name: 回退用的包名（apk stem 清理后为空时使用）。

    Returns:
        非空、Windows 安全的文件名 base（不含扩展名）。
    """
    try:
        stem = Path(apk_path).stem if apk_path else ""
    except Exception:
        # Path 对极端非法路径（如含 NUL）可能抛 ValueError 等，吞掉走回退。
        stem = ""
    for candidate in (stem, package_name):
        base = sanitize_base(candidate or "")
        if base:
            return base
    return "report"


__all__ = ["report_base", "sanitize_base"]
