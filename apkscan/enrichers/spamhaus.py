"""Spamhaus DROP IPv4 网段标注富化器。

Spamhaus DROP 是第三方维护的全量网段清单，因此本模块采用“整表下载、进程内共享、
本地缓存、逐 IP 本地匹配”的模式，而不是为每个端点发起 HTTP 请求。

成功下载或读取缓存后，记录会被组织为按前缀长度分组的 IPv4 前缀索引。查询最多进行
33 次整数前缀查找，复杂度为 O(IPv4 位数)，不会随 DROP 记录总数线性增长；若清单中
存在重叠网段，则优先返回最长前缀，也就是范围最具体的记录。

返回字段使用 ``network_listed``、``matched_cidr`` 和
``evidence_type="third_party_network_list"``，明确表达这是 Spamhaus 提供的网段级
第三方标注。DROP 命中不能证明具体 IP 的使用者或服务运营者身份，本富化器不得据此
填充或推断五层归属模型中的任何主体，尤其不得推断 ``service_operator``。

``network_listed=False`` 只会在清单成功取得且完成匹配后返回。清单下载、解析或刷新
失败时返回 ``ok=False``，不会把不可判定状态表示成“未命中”。IPv6 和非法 IP 返回
明确的 ``not_applicable`` 状态，并且不会触发清单下载。
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher
from apkscan.enrichers import _http

logger = logging.getLogger(__name__)

DROP_URL = "https://www.spamhaus.org/drop/drop_v4.json"
HTTP_TIMEOUT_SECONDS = 20
CACHE_TTL_SECONDS = 24 * 60 * 60
FAILED_REFRESH_RETRY_SECONDS = 60

CACHE_DIR = Path(".apkscan_cache")
CACHE_FILE = CACHE_DIR / "spamhaus_drop_v4.json"

_CACHE_SCHEMA_VERSION = 1
_CACHED_AT_KEY = "cached_at"


class _TableUnavailableError(RuntimeError):
    """表示 DROP 清单当前不可用于判定。"""


@dataclass(frozen=True, slots=True)
class _DropRecord:
    """一条经过校验和规范化的 Spamhaus DROP IPv4 网段记录。"""

    cidr: str
    prefix_length: int
    prefix_value: int
    sbl_id: str
    rir: str


@dataclass(frozen=True, slots=True)
class _DropTable:
    """可共享的不可变 DROP 清单及其 IPv4 前缀索引。"""

    records: tuple[_DropRecord, ...]
    prefix_index: tuple[dict[int, _DropRecord], ...]
    list_timestamp: int
    cached_at: float
    cache_file: Path

    def lookup(self, address: ipaddress.IPv4Address) -> _DropRecord | None:
        """按最长前缀优先规则查找包含给定 IPv4 地址的清单记录。"""
        address_value = int(address)
        for prefix_length in range(32, -1, -1):
            shift = 32 - prefix_length
            prefix_value = address_value >> shift if shift else address_value
            record = self.prefix_index[prefix_length].get(prefix_value)
            if record is not None:
                return record
        return None


class SpamhausDropEnricher(BaseEnricher):
    """用 Spamhaus DROP 对 IPv4 端点添加第三方网段级风险标注。

    该标注仅说明某个网段出现在 Spamhaus DROP 清单中，是第三方清单证据，不是本工具
    对端点行为的独立观测，也不是对 IP 使用者、基础设施租户或服务运营者的身份判定。
    结果只应进入端点富化信息和来源状态，不得参与五层归属推断。
    """

    name = "spamhaus"
    applies_to = ["ip"]
    phase = "attribution"
    active = False
    case_close_only = False
    required_env: tuple[str, ...] = ()

    # 所有实例共享一份内存表和刷新状态，保证并发端点查询只触发一次整表下载。
    _condition: ClassVar[threading.Condition] = threading.Condition(threading.Lock())
    _table: ClassVar[_DropTable | None] = None
    _refreshing: ClassVar[bool] = False
    _last_failure_at: ClassVar[float | None] = None
    _last_failure_error: ClassVar[str | None] = None
    _last_failure_cache_file: ClassVar[Path | None] = None

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        """对 IPv4 端点执行 DROP 网段匹配，并在本方法内兜住所有运行时异常。"""
        raw_value = str(ep.value).strip()

        try:
            address = ipaddress.ip_address(raw_value)
        except ValueError:
            return EnrichmentResult(
                provider=self.name,
                ok=True,
                data={
                    "status": "not_applicable",
                    "reason": "invalid_ip",
                    "list_name": "Spamhaus DROP",
                },
                error=None,
            )

        if not isinstance(address, ipaddress.IPv4Address):
            return EnrichmentResult(
                provider=self.name,
                ok=True,
                data={
                    "status": "not_applicable",
                    "reason": "ipv6_not_supported",
                    "list_name": "Spamhaus DROP",
                },
                error=None,
            )

        try:
            table = self._get_table()
            record = table.lookup(address)
        except Exception as exc:
            logger.warning("Spamhaus DROP 清单不可用", exc_info=True)
            return EnrichmentResult(
                provider=self.name,
                ok=False,
                data={},
                error=f"Spamhaus DROP 清单不可用：{exc}",
            )

        data: dict[str, Any] = {
            "status": "checked",
            "network_listed": record is not None,
            "list_name": "Spamhaus DROP",
            "list_timestamp": table.list_timestamp,
            "annotation_scope": "network",
            "evidence_type": "third_party_network_list",
        }
        if record is not None:
            data.update(
                {
                    "matched_cidr": record.cidr,
                    "sbl_id": record.sbl_id,
                    "rir": record.rir,
                }
            )

        return EnrichmentResult(
            provider=self.name,
            ok=True,
            data=data,
            error=None,
        )

    @classmethod
    def _get_table(cls) -> _DropTable:
        """取得新鲜清单；同一进程中只允许一个线程负责刷新。"""
        while True:
            now = time.time()
            monotonic_now = time.monotonic()

            with cls._condition:
                # 先取到局部变量再判空——直接对 ClassVar 判断，静态检查无法收窄 Optional。
                shared_table = cls._table
                if shared_table is not None and cls._table_is_fresh(shared_table, now):
                    return shared_table

                if (
                    cls._last_failure_at is not None
                    and cls._last_failure_error is not None
                    and cls._last_failure_cache_file == CACHE_FILE
                    and monotonic_now - cls._last_failure_at
                    < FAILED_REFRESH_RETRY_SECONDS
                ):
                    raise _TableUnavailableError(cls._last_failure_error)

                if cls._refreshing:
                    cls._condition.wait()
                    continue

                cached_table = cls._load_cache()
                if cached_table is not None and cls._table_is_fresh(cached_table, now):
                    cls._table = cached_table
                    cls._clear_failure()
                    return cached_table

                cls._refreshing = True
                break

        try:
            downloaded_table = cls._download_table()
        except Exception as exc:
            error_message = str(exc) or exc.__class__.__name__
            with cls._condition:
                cls._last_failure_at = time.monotonic()
                cls._last_failure_error = error_message
                cls._last_failure_cache_file = CACHE_FILE
                cls._refreshing = False
                cls._condition.notify_all()
            raise _TableUnavailableError(error_message) from exc

        with cls._condition:
            cls._save_cache(downloaded_table)
            cls._table = downloaded_table
            cls._clear_failure()
            cls._refreshing = False
            cls._condition.notify_all()
            return downloaded_table

    @classmethod
    def _table_is_fresh(cls, table: _DropTable | None, now: float) -> bool:
        """判断内存表是否属于当前缓存文件且仍在 TTL 内。"""
        if table is None or table.cache_file != CACHE_FILE:
            return False
        age = now - table.cached_at
        return 0 <= age < CACHE_TTL_SECONDS

    @classmethod
    def _clear_failure(cls) -> None:
        """清除最近一次刷新失败状态；调用方必须持有共享锁。"""
        cls._last_failure_at = None
        cls._last_failure_error = None
        cls._last_failure_cache_file = None

    @classmethod
    def _load_cache(cls) -> _DropTable | None:
        """读取并校验磁盘缓存；调用方必须持有 ``cls._condition`` 的锁。

        Windows 下文件读取句柄可能与另一线程的 ``replace`` 冲突，因此缓存读取、
        原子替换和进程内状态更新共用同一把锁。
        """
        if not CACHE_FILE.is_file():
            return None

        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("缓存根节点不是对象")
            if data.get("schema_version") != _CACHE_SCHEMA_VERSION:
                raise ValueError("缓存版本不受支持")

            cached_at = cls._require_number(data, _CACHED_AT_KEY)
            list_timestamp = cls._require_int(data, "list_timestamp")
            raw_records = data.get("records")
            if not isinstance(raw_records, list):
                raise ValueError("缓存 records 不是数组")

            return cls._build_table(
                raw_records=raw_records,
                list_timestamp=list_timestamp,
                cached_at=cached_at,
            )
        except Exception:
            logger.warning(
                "Spamhaus DROP 缓存读取或解析失败，忽略：%s",
                CACHE_FILE,
                exc_info=True,
            )
            return None

    @classmethod
    def _save_cache(cls, table: _DropTable) -> None:
        """原子保存清单缓存；调用方必须持有 ``cls._condition`` 的锁。"""
        cache_data = {
            "schema_version": _CACHE_SCHEMA_VERSION,
            _CACHED_AT_KEY: table.cached_at,
            "list_timestamp": table.list_timestamp,
            "records": [
                {
                    "cidr": record.cidr,
                    "sblid": record.sbl_id,
                    "rir": record.rir,
                }
                for record in table.records
            ],
        }

        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            tmp = CACHE_FILE.with_name(
                f"{CACHE_FILE.name}.{os.getpid()}.{threading.get_ident()}.tmp"
            )
            tmp.write_text(
                json.dumps(cache_data, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            tmp.replace(CACHE_FILE)
        except Exception:
            logger.warning(
                "Spamhaus DROP 缓存写入失败：%s",
                CACHE_FILE,
                exc_info=True,
            )

    @classmethod
    def _download_table(cls) -> _DropTable:
        """下载 JSON Lines 清单，跳过并校验末尾元数据行。"""
        response = _http.capped_get(DROP_URL, timeout=HTTP_TIMEOUT_SECONDS)
        response.raise_for_status()

        raw_records: list[dict[str, Any]] = []
        metadata: dict[str, Any] | None = None
        saw_metadata = False

        for line_number, raw_line in enumerate(response.text.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue

            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"第 {line_number} 行不是有效 JSON") from exc

            if not isinstance(item, dict):
                raise ValueError(f"第 {line_number} 行不是 JSON 对象")

            if item.get("type") == "metadata":
                if metadata is not None:
                    raise ValueError("清单包含多个元数据行")
                metadata = item
                saw_metadata = True
                continue

            if saw_metadata:
                raise ValueError("元数据行之后仍存在 DROP 记录")

            raw_records.append(item)

        if metadata is None:
            raise ValueError("清单缺少元数据行")

        list_timestamp = cls._require_int(metadata, "timestamp")
        declared_records = cls._require_int(metadata, "records")
        if declared_records != len(raw_records):
            raise ValueError(
                f"元数据声明 {declared_records} 条记录，实际解析 {len(raw_records)} 条"
            )

        return cls._build_table(
            raw_records=raw_records,
            list_timestamp=list_timestamp,
            cached_at=time.time(),
        )

    @classmethod
    def _build_table(
        cls,
        *,
        raw_records: list[Any],
        list_timestamp: int,
        cached_at: float,
    ) -> _DropTable:
        """校验记录并构建按前缀长度分组的不可变查询表。"""
        if list_timestamp < 0:
            raise ValueError("清单 timestamp 不能为负数")
        if cached_at < 0:
            raise ValueError("缓存时间不能为负数")

        prefix_index: list[dict[int, _DropRecord]] = [
            {} for _ in range(33)
        ]
        records: list[_DropRecord] = []

        for record_number, raw_record in enumerate(raw_records, start=1):
            if not isinstance(raw_record, dict):
                raise ValueError(f"第 {record_number} 条记录不是对象")

            cidr = cls._require_string(raw_record, "cidr")
            sbl_id = cls._require_string(raw_record, "sblid")
            rir = cls._require_string(raw_record, "rir")

            try:
                network = ipaddress.ip_network(cidr, strict=True)
            except ValueError as exc:
                raise ValueError(
                    f"第 {record_number} 条记录包含非法 CIDR"
                ) from exc

            if not isinstance(network, ipaddress.IPv4Network):
                raise ValueError(f"第 {record_number} 条记录不是 IPv4 网段")

            prefix_length = network.prefixlen
            shift = 32 - prefix_length
            network_value = int(network.network_address)
            prefix_value = network_value >> shift if shift else network_value
            canonical_cidr = network.with_prefixlen

            if prefix_value in prefix_index[prefix_length]:
                raise ValueError(f"清单包含重复 CIDR：{canonical_cidr}")

            record = _DropRecord(
                cidr=canonical_cidr,
                prefix_length=prefix_length,
                prefix_value=prefix_value,
                sbl_id=sbl_id,
                rir=rir,
            )
            prefix_index[prefix_length][prefix_value] = record
            records.append(record)

        return _DropTable(
            records=tuple(records),
            prefix_index=tuple(prefix_index),
            list_timestamp=list_timestamp,
            cached_at=cached_at,
            cache_file=CACHE_FILE,
        )

    @staticmethod
    def _require_string(data: dict[str, Any], key: str) -> str:
        """读取必需的非空字符串字段。"""
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"字段 {key} 不是非空字符串")
        return value.strip()

    @staticmethod
    def _require_int(data: dict[str, Any], key: str) -> int:
        """读取必需的整数，显式拒绝布尔值。"""
        value = data.get(key)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"字段 {key} 不是整数")
        return value

    @staticmethod
    def _require_number(data: dict[str, Any], key: str) -> float:
        """读取必需的有限时间数值，显式拒绝布尔值。"""
        value = data.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"字段 {key} 不是数值")

        result = float(value)
        if result != result or result in (float("inf"), float("-inf")):
            raise ValueError(f"字段 {key} 不是有限数值")
        return result