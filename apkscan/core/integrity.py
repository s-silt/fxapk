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
import logging
import platform
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# 1 MiB 流式分块（与 dynamic/ledger.py 的 apk_sha256 同一范式）：大 APK 不一次性读进内存。
_READ_CHUNK = 1 << 20


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
        logger.warning("[integrity] 检材指纹计算失败（读不到检材），降级为空 hash：%s", apk_path, exc_info=True)
        ok = False

    return {
        "sha256": h256.hexdigest() if ok else "",
        "sha1": h1.hexdigest() if ok else "",
        "md5": hmd5.hexdigest() if ok else "",
        "size": size if ok else 0,
        "analyzed_at": analyzed_at,
        "tool_version": tool_version,
        "platform": plat,
    }


def evidence_id(source: str, location: str) -> str:
    """对 (source, location) 生成确定性短 id：``sha256("{source}|{location}")`` 前 16 位 hex。

    **只用 source|location，不纳入 snippet**：snippet 对 runtime 来源可能含每次抓包不同的
    随机 / 时间字段（如信封时间戳），纳入会导致同一条证据的 id 在多次运行间漂移，破坏
    「可回溯」的稳定锚点。source|location 才是该证据在检材内的稳定坐标。
    """
    return hashlib.sha256(f"{source}|{location}".encode("utf-8")).hexdigest()[:16]
