"""批量分析去重台账：按 APK 内容 sha256 记录「已分析过」，命中跳过、不重复跑。

放 ``.apkscan_cache/analyzed.json``（与 whois/icp/asn 富化缓存同目录）。设计铁律：
- **按内容 sha256 去重**：同一 APK 改个名也跳过（key 是内容、不是路径）。
- **绝不抛**：台账文件损坏 / 不可读 → 当空处理 + logging，不阻断批量主流程。
- **原子落盘**：每分析完一个就 record 一次（临时文件 + ``os.replace``），mid-batch 崩了
  已分析的记录不丢、不会留半截坏 JSON（沿用富化缓存的原子写思路）。
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path

logger = logging.getLogger(__name__)

_READ_CHUNK = 1 << 20  # 1 MiB：大 APK 流式哈希，不一次性读进内存


def apk_sha256(path: str) -> str:
    """流式算 APK 文件内容的 sha256（十六进制串）。大文件分块读，不撑内存。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_READ_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


class AnalyzedLedger:
    """``sha256 -> 记录`` 的 JSON 台账。坏文件/IO 失败一律吞成空 + logging，绝不抛给调用方。"""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._data: dict[str, dict] = self._load()

    def _load(self) -> dict[str, dict]:
        if not self._path.is_file():
            return {}
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            logger.warning("[ledger] 台账损坏/不可读，当空处理：%s", self._path, exc_info=True)
            return {}
        if not isinstance(raw, dict):
            logger.warning("[ledger] 台账顶层非 dict，当空处理：%s", self._path)
            return {}
        return raw

    def is_analyzed(self, sha: str) -> bool:
        """该内容 sha256 是否已分析过（命中即跳过）。"""
        return sha in self._data

    def get(self, sha: str) -> dict | None:
        """取某条记录（无则 None），供批量汇总 / 审计用。"""
        return self._data.get(sha)

    def record(self, sha: str, *, apk_name: str, report_dir: str, status: str) -> None:
        """记一条并原子落盘。绝不抛（IO 失败只 logging，内存态仍有效，不阻断批量）。"""
        self._data[sha] = {
            "apk_name": apk_name,
            "report_dir": report_dir,
            "status": status,
            "ts": time.time(),
        }
        self._save()

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(self._path.suffix + ".tmp")
            tmp.write_text(
                json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            os.replace(tmp, self._path)  # 同目录原子替换，不留半截坏文件
        except OSError:
            logger.warning("[ledger] 台账落盘失败（忽略）：%s", self._path, exc_info=True)
