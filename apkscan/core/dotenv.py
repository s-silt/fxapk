"""零依赖 ``.env`` 加载（源码运行时从项目根 .env 读 API key 等密钥）。

设计取向（见使用方向）：项目今后由用户直接跑源码 + Codex 驱动，不再打包 exe/GUI，
故密钥走项目根 ``.env``（已 gitignore）。本模块在入口把 .env 里白名单内的键**兜底**注入
``os.environ``：

- **真实环境变量优先**：已在 ``os.environ`` 的键不覆盖（CI / 临时 export 仍然有效）。
- **绝不抛**：.env 缺失 / 编码坏 / 坏行都安全跳过，不影响主流程。
- 查找顺序：仓库根 ``.env``（源码运行）→ ``~/.fxapk/.env``（pip 安装）。仍不读当前工作目录的
  ``.env``——证据目录可能是攻击者交付的，其中的 ``.env`` 不得注入进程环境。显式传入 ``path``
  时只读该路径。
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

#: 仓库根（apkscan/core/dotenv.py → parents[2] == 仓库根），用于在非项目根目录运行时兜底找 .env。
_REPO_ROOT = Path(__file__).resolve().parents[2]

#: pip 安装后的用户级受信任位置。无家目录时 Path.home() 抛 RuntimeError/KeyError，退化为 None。
_USER_ENV: Path | None
try:
    _USER_ENV = Path.home() / ".fxapk" / ".env"
except (RuntimeError, KeyError):
    _USER_ENV = None

# 只放凭证/提供方配置。PATH、JAVA_HOME、FXAPK_TOOLCHAIN_FILE、FXAPK_TCPDUMP_BIN、
# FXAPK_ENABLE_REA、FXAPK_HANDOFF_ROOT、FXAPK_CORPUS 这类执行路径/安全门/数据根变量
# 只能由真实进程环境设置，不得加入。
_INJECTABLE_KEYS: frozenset[str] = frozenset(
    {
        "CENSYS_API_TOKEN",
        "FXAPK_ABUSEIPDB_KEY",
        "FXAPK_CENSYS_ORG_ID",
        "FXAPK_CENSYS_TOKEN",
        "FXAPK_DAYDAYMAP_KEY",
        "FXAPK_DAYDAYMAP_KEY2",
        "FXAPK_FEISHU_APP_ID",
        "FXAPK_FEISHU_APP_SECRET",
        "FXAPK_FEISHU_CHAT_ID",
        "FXAPK_FOFA_FIELD_PROFILE",
        "FXAPK_FOFA_KEY",
        "FXAPK_FOFA_URL",
        "FXAPK_HTTP_RATE_LIMITS",
        "FXAPK_HUNTER_CREDIT_MODE",
        "FXAPK_HUNTER_KEY",
        "FXAPK_HUNTER_QUOTA_DB",
        "FXAPK_ICP_HAPI_KEY",
        "FXAPK_OTX_KEY",
        "FXAPK_QUAKE_KEY",
        "FXAPK_QUAKE_KEY2",
        "FXAPK_QUAKE_URL",
        "FXAPK_SHODAN_KEY",
        "FXAPK_THREATBOOK_KEY",
        "FXAPK_URLSCAN_KEY",
        "FXAPK_VT_KEY",
        "FXAPK_WHOISXML_KEY",
        "FXAPK_ZOOMEYE_KEY",
        "FXAPK_ZOOMEYE_URL",
        "NGHIMMO_API_KEY",
        "OTX_API_KEY",
        "VT_API_KEY",
        "ZOOMEYE_API_KEY",
    }
)


def _candidate_paths(explicit: "str | os.PathLike[str] | None") -> list[Path]:
    if explicit is not None:
        return [Path(explicit)]
    # 不读 cwd .env：证据目录可能是攻击者交付的，其中的 .env 不得注入进程环境。
    # 仓库根优先；两条路径相同（或无家目录）时只保留前者。
    found: list[Path] = []
    for path in (_REPO_ROOT / ".env", _USER_ENV):
        if path is None or path in found:
            continue
        found.append(path)
    return found


def _strip_inline_comment(val: str) -> str:
    """剥掉**未加引号**值尾部的行内注释（``KEY=abc  # 说明`` → ``abc``）。

    按 dotenv 惯例，只有**空白 + ``#``** 才起注释（``abc#def`` 里的 ``#`` 是值的一部分），
    故密钥本身含 ``#`` 不会被截断。取最早出现的那个分隔位。
    ★空白判定用 ``str.isspace()`` 而非硬编码空格/制表符——从中文文档/聊天粘贴的注释常带
    **全角空格 U+3000 或 NBSP U+00A0**，只认 ``" #"``/``"\\t#"`` 会把注释整个并进密钥。
    """
    for idx, ch in enumerate(val):
        if ch == "#" and idx > 0 and val[idx - 1].isspace():
            return val[:idx].rstrip()
    return val.rstrip()


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
    # 引号包裹：按**配对的收尾引号**切，其后一律视为注释丢弃。
    # ★不能用 ``val[0] == val[-1]`` 判：``KEY="abc"  # 注释`` 的末字符属注释，判不出是引号包裹，
    #   会掉进下面的剥注释分支，把字面引号留在值里；更糟的是 ``KEY="a # b"  # 注释`` 会从引号**内部**
    #   的 ``# `` 切断，得到 ``"a``。
    if val[:1] in ("'", '"'):
        quote = val[0]
        end = val.find(quote, 1)
        if end != -1:
            return key, val[1:end]  # 引号内原样保留：# 是值的一部分，不当注释
        # 引号未闭合：退化为按未加引号处理，不猜。
    # 未加引号才剥行内注释。★不剥的话，``KEY=<密钥>  # 备注`` 会把备注并进密钥——真实踩过：
    # 一个带中文备注的 API key 被塞进 HTTP 头，latin-1 编码不了而 UnicodeEncodeError。
    return key, _strip_inline_comment(val)


def load_dotenv(path: "str | os.PathLike[str] | None" = None) -> int:
    """把 .env 白名单内的键兜底注入 ``os.environ``（已存在的真实环境变量不覆盖；其余键拒绝并告警）。

    返回注入条数。绝不抛。
    """
    injected = 0
    for p in _candidate_paths(path):
        try:
            if not p.is_file():
                continue
            # utf-8-sig：编辑器存的 .env 常带 BOM，用 utf-8 读会让**首个键名**变成 "﻿FXAPK_..."，
            # 于是"注入成功 1 条"但真实键查不到，且毫无告警——最难查的那种静默损坏。
            text = p.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            # 非 UTF-8（如 GBK）会让**整个文件**被丢弃、所有密钥凭空消失。这必须让用户看见，
            # 不能只留 debug 级日志：症状是"所有源都说没配密钥"，离病根极远。
            logger.warning(
                ".env 不是 UTF-8 编码，整份已跳过（所有密钥都不会加载）：%s；请另存为 UTF-8", p
            )
            continue
        except Exception:
            logger.debug(".env 读取失败，跳过：%s", p, exc_info=True)
            continue
        rejected: set[str] = set()
        for raw in text.splitlines():
            parsed = _parse_line(raw)
            if parsed is None:
                continue
            key, val = parsed
            if not val:
                # ★空占位（``KEY=``，常见于从 .env.example 抄来的模板行）不注入：一旦注入，
                # 高优先 .env 的空占位会**静默掩蔽**低优先 .env 里配好的真实值——症状是
                # "明明配了 key 却说没配"，离病根极远。想显式置空请用真实环境变量。
                logger.debug(".env 空占位跳过（不掩蔽低优先级来源）：%s（%s）", key, p)
                continue
            if key not in _INJECTABLE_KEYS:
                # 执行路径 / 安全门 / 数据根只记键名：不注入，告警也绝不带值。
                rejected.add(key)
                continue
            if key in os.environ:  # 真实环境变量优先，不覆盖
                continue
            os.environ[key] = val
            injected += 1
            # 只记键名与来源文件，绝不回显值——多 .env 并存时"这个值到底来自哪份文件"
            # 是排障第一问，此前零信号。
            logger.debug(".env 注入 %s ← %s", key, p)
        if rejected:
            logger.warning(
                ".env 拒绝注入非凭证键 %s（%s）；这些变量须在真实进程环境中设置，不得经 .env 注入",
                ", ".join(sorted(rejected)),
                p,
            )
    if injected:
        logger.debug(".env 共注入 %d 个键到环境变量", injected)
    return injected
