"""Go 二进制的 buildinfo 有界解析 —— 取版本 / 模块 / replace / ``-ldflags -X`` 变量名。

为什么值得单列一层：Go 链接器把构建元数据原样写进产物，其中 ``replace`` 指令里的本地
路径就是**开发机上的项目根**（实测样本里是 ``D:\\buildroot\\appsdk``），依赖清单能看出
技术栈（如 TLS 指纹拟态库），而 ``-ldflags -X`` 注入的值里可能是活体凭据。

★安全红线：``-X`` 的值**永不进入返回结构**。解析时就地换成指纹（类型 + 长度 + SHA256），
原值随局部变量一起丢弃。实测样本里注入的是一份可用的 RSA 私钥——那是能解控制面流量的
凭据，把它写进 report.json 等于把凭据分发出去，本地留存也不行。

有界与不抛：只认第一处哨兵、限总长与单值长度，任何异常都返回 None / 跳过该字段。
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

#: Go 链接器写在 modinfo 两侧的 16 字节哨兵（``runtime/debug`` 的 ``infoStart``/``infoEnd``）。
#: ★用哨兵而不是解 ``\xff Go buildinf:`` 魔数：pointer 格式要把虚拟地址翻成文件偏移才能
#: 读到字符串，既重又脆（依赖 ELF 段表正确）。哨兵定位对两种格式都直接可用。
_INFO_START = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
_INFO_END = bytes.fromhex("f932433186182072008242104116d8f2")

#: modinfo 段总长上限（实测真值约 3 KiB；64 KiB 已是极宽的天花板）。
_MAX_MODINFO = 64 * 1024
#: 单个字段值长度上限——超大 ``-ldflags`` 不该把 meta 撑肿。
_MAX_FIELD = 4 * 1024

#: Go 版本串（廉价、恒在，与 modinfo 是否可解无关）。
_GO_VERSION_RE = re.compile(rb"go1\.\d+(?:\.\d+)?")

#: ``-ldflags`` 里的 ``-X`` 注入。Go 接受多种等价写法，全部要认——漏掉一种，
#: 该注入值就拿不到指纹，且原文会留在 build_settings 里（"解析处即脱敏"的契约就破了）：
#:   -X main.Var=value        -X=main.Var=value
#:   -X 'main.Var=value'      -X="main.Var=value"
#:   -X main.Var='value'      （值本身带引号）
#: 变量名不含空格与等号；值可被单/双引号包裹，引号内允许空格。
_LDFLAGS_X_RE = re.compile(
    r"""-X[\s=]+                 # -X 后跟空格或等号
        (?:'|")?                 # 可选的整体开引号
        ([^\s'"=]+)              # 变量名 pkg.Var
        =
        (?:                      # 值：带引号则取引号内（可含空格），否则取到空白为止
            '([^']*)'
          | "([^"]*)"
          | ([^\s'"]*)
        )
    """,
    re.VERBOSE,
)


def _iter_ldflags_x(setting: str):
    """产出 ``(var, value)``；值的三种引号形态归一。"""
    for m in _LDFLAGS_X_RE.finditer(setting):
        var = m.group(1)
        value = next((g for g in m.group(2, 3, 4) if g is not None), "")
        yield var, value

#: 变量名看起来像凭据时，即便值不是 PEM 也只留指纹。
_SENSITIVE_VAR_RE = re.compile(r"(?i)(priv|secret|key|token|password|passwd|credential|cert)")

#: PEM 私钥头（判定 kind 用）。
_PEM_PRIVATE_RE = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")


@dataclass
class GoBuildInfo:
    """从 Go 产物里读到的构建元数据。``ldflags_x`` 里**只有变量名与值指纹**。"""

    go_version: str = ""
    main_path: str = ""
    main_module: str = ""
    replaces: list[str] = field(default_factory=list)
    deps: list[str] = field(default_factory=list)
    build_settings: dict[str, str] = field(default_factory=dict)
    ldflags_x: list[dict[str, object]] = field(default_factory=list)


def fingerprint_embedded_secret(var_name: str, value: str) -> dict[str, object]:
    """把注入值换成指纹：类型、长度、SHA256。**绝不回显原值。**

    先按 base64 有界解码试一次——注入的凭据常以 base64 形态出现，解出来才认得出是 PEM。
    """
    import base64
    import binascii

    raw = value[:_MAX_FIELD]
    encoded_sha = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()
    kind = "opaque"
    decoded_len: int | None = None
    decoded_sha = ""

    if _PEM_PRIVATE_RE.search(raw):
        kind = "private_key_pem"
    else:
        try:
            decoded = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError):
            decoded = b""
        if decoded:
            decoded_len = len(decoded)
            decoded_sha = hashlib.sha256(decoded).hexdigest()
            if _PEM_PRIVATE_RE.search(decoded.decode("utf-8", "replace")[:512]):
                kind = "private_key_pem_base64"

    if kind == "opaque" and _SENSITIVE_VAR_RE.search(var_name):
        kind = "sensitive_by_name"

    out: dict[str, object] = {
        "var": var_name,
        "kind": kind,
        "length": len(raw),
        "sha256": encoded_sha,
    }
    if decoded_len is not None:
        out["decoded_length"] = decoded_len
        out["decoded_sha256"] = decoded_sha
    return out


def _is_sensitive(kind: str) -> bool:
    return kind != "opaque"


def parse_go_buildinfo(blob: bytes) -> GoBuildInfo | None:
    """从 Go 产物字节里解析 buildinfo；不是 Go 产物或解不出 → None。绝不抛。"""
    try:
        version_match = _GO_VERSION_RE.search(blob)
        go_version = version_match.group(0).decode("ascii") if version_match else ""

        start = blob.find(_INFO_START)
        end = blob.find(_INFO_END, start + len(_INFO_START)) if start >= 0 else -1
        if start < 0 or end < 0:
            # 有 Go 版本串但无哨兵：仍是 Go 产物（可能被裁剪），至少把版本带出去。
            return GoBuildInfo(go_version=go_version) if go_version else None

        body_start = start + len(_INFO_START)
        if end - body_start > _MAX_MODINFO:
            logger.debug("[gobuildinfo] modinfo 段超上限 %d，跳过", _MAX_MODINFO)
            return GoBuildInfo(go_version=go_version) if go_version else None

        info = GoBuildInfo(go_version=go_version)
        text = blob[body_start:end].decode("utf-8", "replace")
        for line in text.splitlines():
            parts = line.split("\t")
            tag = parts[0]
            if tag == "path" and len(parts) >= 2:
                info.main_path = parts[1][:_MAX_FIELD]
            elif tag == "mod" and len(parts) >= 3:
                info.main_module = f"{parts[1]} {parts[2]}"[:_MAX_FIELD]
            elif tag == "dep" and len(parts) >= 3:
                info.deps.append(f"{parts[1]} {parts[2]}"[:_MAX_FIELD])
            elif tag == "=>" and len(parts) >= 2:
                info.replaces.append(parts[1][:_MAX_FIELD])
            elif tag == "build" and len(parts) >= 2:
                setting = "\t".join(parts[1:])
                key, _, val = setting.partition("=")
                redacted = val.strip()
                for var, raw_value in _iter_ldflags_x(setting):
                    fp = fingerprint_embedded_secret(var, raw_value)
                    # 非敏感的注入值（版本号、构建号）留明文有用；敏感的只留指纹。
                    if not _is_sensitive(str(fp["kind"])):
                        fp["value"] = raw_value[:_MAX_FIELD]
                    elif raw_value:
                        # ★同一个值在 build_settings 里还有一份原文：``-ldflags`` 的完整命令行
                        #   就包含 ``-X <var>=<私钥>``。只给 ldflags_x 上指纹是挡不住的——
                        #   凭据会从这条 setting 原样流进 meta。此处就地抹掉。
                        redacted = redacted.replace(
                            raw_value, f"<redacted:{str(fp['sha256'])[:12]}>"
                        )
                    info.ldflags_x.append(fp)
                info.build_settings[key.strip()[:_MAX_FIELD]] = redacted[:_MAX_FIELD]
        return info
    except Exception:  # noqa: BLE001 - 解析器绝不抛，坏输入按"读不出"处理
        logger.debug("[gobuildinfo] 解析失败，按无 buildinfo 处理", exc_info=True)
        return None
