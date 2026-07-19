"""零依赖 ``.env`` 加载（源码运行时从项目根 .env 读 API key 等密钥）。

设计取向（见使用方向）：项目今后由用户直接跑源码 + Codex 驱动，不再打包 exe/GUI，
故密钥走项目根 ``.env``（已 gitignore）。本模块在入口把 .env 的键值**兜底**注入
``os.environ``：

- **真实环境变量优先**：已在 ``os.environ`` 的键不覆盖（CI / 临时 export 仍然有效）。
- **绝不抛**：.env 缺失 / 编码坏 / 坏行都安全跳过，不影响主流程。
- 查找顺序：当前工作目录 ``.env`` → 仓库根 ``.env``（cwd 先注入、优先）。
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

#: 仓库根（apkscan/core/dotenv.py → parents[2] == 仓库根），用于在非项目根目录运行时兜底找 .env。
_REPO_ROOT = Path(__file__).resolve().parents[2]


def _candidate_paths(explicit: "str | os.PathLike[str] | None") -> list[Path]:
    if explicit is not None:
        return [Path(explicit)]
    # cwd 先于仓库根：用户在哪运行就优先用哪的 .env；去重保持顺序。
    out: list[Path] = []
    for p in (Path.cwd() / ".env", _REPO_ROOT / ".env"):
        if p not in out:
            out.append(p)
    return out


def _strip_inline_comment(val: str) -> str:
    """剥掉**未加引号**值尾部的行内注释（``KEY=abc  # 说明`` → ``abc``）。

    按 dotenv 惯例，只有**空白 + ``#``** 才起注释（``abc#def`` 里的 ``#`` 是值的一部分），
    故密钥本身含 ``#`` 不会被截断。取最早出现的那个分隔位。
    """
    cut = len(val)
    for sep in (" #", "\t#"):
        idx = val.find(sep)
        if idx != -1:
            cut = min(cut, idx)
    return val[:cut].rstrip()


def _parse_line(raw: str) -> "tuple[str, str] | None":
    """解析一行 ``KEY=VALUE``（支持 ``export KEY=...``、引号包裹与行内注释）；非法行返回 None。"""
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        return None
    key, _, val = line.partition("=")
    key = key.strip()
    if key.startswith("export "):
        key = key[len("export ") :].strip()
    if not key:
        return None
    val = val.strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
        return key, val[1:-1]  # 引号内原样保留：# 是值的一部分，不当注释
    # 未加引号才剥行内注释。★不剥的话，``KEY=<密钥>  # 备注`` 会把备注并进密钥——真实踩过：
    # 一个带中文备注的 API key 被塞进 HTTP 头，latin-1 编码不了而 UnicodeEncodeError。
    return key, _strip_inline_comment(val)


def load_dotenv(path: "str | os.PathLike[str] | None" = None) -> int:
    """把 .env 键值兜底注入 ``os.environ``（已存在的真实环境变量不覆盖）。返回注入条数。绝不抛。"""
    injected = 0
    for p in _candidate_paths(path):
        try:
            if not p.is_file():
                continue
            text = p.read_text(encoding="utf-8")
        except Exception:
            logger.debug(".env 读取失败，跳过：%s", p, exc_info=True)
            continue
        for raw in text.splitlines():
            parsed = _parse_line(raw)
            if parsed is None:
                continue
            key, val = parsed
            if key in os.environ:  # 真实环境变量 / cwd 已注入的优先，不覆盖
                continue
            os.environ[key] = val
            injected += 1
    if injected:
        logger.debug(".env 注入 %d 个键到环境变量", injected)
    return injected
