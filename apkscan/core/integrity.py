"""取证完整性元数据（EvidenceManifest）—— 可采性背书层（纯函数，零第三方依赖）。

**定位**：这是把「技术报告」升级为「可入卷物证」的**证据链 / 可复现性元数据**层，
不是出新线索的功能。它只为已产出的报告补一层「自证完整性」背书：

- ``sample_fingerprint``：检材（APK）多算法指纹 + 本次分析环境（工具版本 / 平台 / 时间）。
- ``evidence_id``：对每条证据 (source, location) 取确定性短 id，便于跨报告 / 跨文件回溯。

法律措辞铁律（务必克制，不得夸大）：
- ``analyzed_at`` 是**分析时间，非扣押 / 采集时间**——本工具不接触原始检材的采集环节。
- ``md5`` / ``sha1`` 仅作兼容冗余，**完整性以 sha256 为准**。
- 任何自证（指纹 / .sha256 旁文件）均为**工具产物自证，不替代司法鉴定机构的证据保全**。

容错铁律：纯函数对坏输入容错——文件读不到返回带空 hash 的 dict 且**绝不抛**。
"""

from __future__ import annotations

import hashlib
import json
import logging
import platform
import subprocess
import unicodedata
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# 1 MiB 流式分块（与 dynamic/ledger.py 的 apk_sha256 同一范式）：大 APK 不一次性读进内存。
_READ_CHUNK = 1 << 20

#: git 溯源进程内缓存（一次运行不变，避免每份报告都 fork git）。
_BUILD_PROVENANCE: dict | None = None


def _build_provenance() -> dict:
    """本次构建的 git 溯源：``{build_commit, build_dirty}``。装成 pip 包 / 无 git / 非源码树 → build_commit=None。绝不抛。

    ★取证复现（外部复审）：master 的 ``tool_version``（如 0.10.0.dev0）区分不了具体 commit——同版本号可能对应
    不同代码。附 commit SHA + 工作树是否 dirty，才能锁定"哪一版代码产的这份报告"。结果进程内缓存。
    """
    global _BUILD_PROVENANCE
    if _BUILD_PROVENANCE is not None:
        return _BUILD_PROVENANCE
    commit: str | None = None
    dirty: bool | None = None
    repo = Path(__file__).resolve().parents[2]  # apkscan/core/integrity.py → 仓库根
    try:
        top = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
        )
        if (
            top.returncode != 0
            or not top.stdout.strip()
            or Path(top.stdout.strip()).resolve() != repo
        ):
            return {"build_commit": None, "build_dirty": None}
        # ★复审 #2：encoding="utf-8"/errors="replace"——git status 含 UTF-8 文件名时 text=True 默认按 locale
        #   解码，ASCII locale 下会抛 UnicodeDecodeError（不在 OSError/SubprocessError 内）。整段兜底 Exception。
        rev = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
        )
        if rev.returncode == 0 and rev.stdout.strip():
            commit = rev.stdout.strip()
            st = subprocess.run(
                ["git", "-C", str(repo), "status", "--porcelain"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
                check=False,
            )
            dirty = bool(st.stdout.strip()) if st.returncode == 0 else None
    except Exception:  # noqa: BLE001 — 绝不抛：git/解码/任何异常 → build_commit=None
        logger.debug(
            "[integrity] git 溯源不可得（非源码树 / 无 git / 异常）→ build_commit=None",
            exc_info=True,
        )
    result = {"build_commit": commit, "build_dirty": dirty}
    # ★复审 #1：只缓存成功探测；失败态（commit=None）不缓存 → 下次重探（git 临时不可用后恢复仍能取到）。
    if commit is not None:
        _BUILD_PROVENANCE = result
    return result


def current_build_provenance() -> dict[str, object]:
    """返回当前源码构建坐标的副本，避免调用方改写进程缓存。"""
    return dict(_build_provenance())


def web_evidence_fingerprint(files: Mapping[str, bytes], *, tool_version: str) -> dict[str, object]:
    """返回网页分析实际消费的规范证据集指纹。

    ``sample_fingerprint`` 钉住单个 APK 文件；网页分析的一级输入则是一组已落盘文件。
    本函数不重新遍历目录，而是接收 :class:`WebContext` 已规范化、实际交给分析器的
    ``{虚拟路径: 字节}``，避免“分析了一组、指纹算了另一组”的证据面漂移。

    整体摘要的输入是按 NFC 路径排序的规范 JSON 清单，每项只含 ``path``、``size``、
    ``sha256``。因此映射插入顺序和分析时间不影响 ``sha256``；任一被分析路径或字节变化
    都会改变它。原始落盘文件仍由 Phase-1 package 逐项哈希固定，本指纹只标识本次分析
    实际消费的证据集合。
    """
    # 空集合 fail-closed：空集指纹是跨案同值常量，进 corpus 会造成假同一性
    # （上游 analyze-web 已拒空证据目录，此处是防御纵深——合并复核加固）。
    if not files:
        raise ValueError("web evidence set must not be empty")
    entries: list[dict[str, object]] = []
    seen_paths: set[str] = set()
    total_size = 0
    for raw_path, data in files.items():
        if not isinstance(raw_path, str):
            raise TypeError("web evidence path must be a string")
        if not isinstance(data, bytes):
            raise TypeError("web evidence content must be bytes")
        path = unicodedata.normalize("NFC", raw_path)
        if path in seen_paths:
            raise ValueError(f"NFC-normalized path collision: {path}")
        seen_paths.add(path)
        size = len(data)
        entries.append(
            {
                "path": path,
                "size": size,
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
        total_size += size

    entries.sort(key=lambda item: str(item["path"]))
    canonical = json.dumps(
        entries,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return {
        "kind": "web_evidence_set",
        "sha256": hashlib.sha256(canonical).hexdigest(),
        "sha1": hashlib.sha1(canonical).hexdigest(),
        "md5": hashlib.md5(canonical).hexdigest(),
        "size": total_size,
        "file_count": len(entries),
        "files": entries,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "tool_version": tool_version,
        "platform": platform.platform(),
        **_build_provenance(),
    }


def sample_fingerprint(apk_path: str, *, tool_version: str) -> dict:
    """返回检材指纹 + 本次分析环境元数据（可采性背书的核心字段）。

    字段：
      - ``sha256`` / ``sha1`` / ``md5``：检材内容多算法摘要（流式分块计算，大文件不撑内存）。
        **完整性以 sha256 为准**；md5 / sha1 仅作兼容冗余。
      - ``size``：检材字节数。
      - ``analyzed_at``：本次分析的 UTC 时间（ISO8601）。**是分析时间，非扣押 / 采集时间。**
      - ``tool_version``：产出本指纹的 apkscan 版本（调用方传入）。
      - ``platform``：分析所在平台（``platform.platform()``），便于复现环境追溯。

    容错：文件读不到 / IO 失败 → 三个 hash 置空串、size 置 0，其余环境字段照常返回，
    **绝不抛**（只 logging），不阻断 analyze 主流程。
    """
    # 环境元数据先备好：即便后续读检材失败，也保留「本次分析环境」可追溯。
    analyzed_at = datetime.now(timezone.utc).isoformat()
    plat = platform.platform()

    h256 = hashlib.sha256()
    h1 = hashlib.sha1()
    hmd5 = hashlib.md5()
    size = 0
    ok = True
    try:
        with open(apk_path, "rb") as f:
            for chunk in iter(lambda: f.read(_READ_CHUNK), b""):
                h256.update(chunk)
                h1.update(chunk)
                hmd5.update(chunk)
                size += len(chunk)
    except OSError:
        # 检材读不到（路径错 / 权限 / 占用）：容错降级为空 hash，不抛、不阻断 analyze。
        logger.warning(
            "[integrity] 检材指纹计算失败（读不到检材），降级为空 hash：%s", apk_path, exc_info=True
        )
        ok = False

    return {
        "sha256": h256.hexdigest() if ok else "",
        "sha1": h1.hexdigest() if ok else "",
        "md5": hmd5.hexdigest() if ok else "",
        "size": size if ok else 0,
        "analyzed_at": analyzed_at,
        "tool_version": tool_version,
        "platform": plat,
        # ★取证复现：tool_version 之外再钉 git commit + 工作树 dirty（源码树运行时；pip 包 → None）。
        **_build_provenance(),
    }


def evidence_id(source: str, location: str) -> str:
    """对 (source, location) 生成确定性短 id：``sha256("{source}|{location}")`` 前 16 位 hex。

    **只用 source|location，不纳入 snippet**：snippet 对 runtime 来源可能含每次抓包不同的
    随机 / 时间字段（如信封时间戳），纳入会导致同一条证据的 id 在多次运行间漂移，破坏
    「可回溯」的稳定锚点。source|location 才是该证据在检材内的稳定坐标。
    """
    return hashlib.sha256(f"{source}|{location}".encode("utf-8")).hexdigest()[:16]
