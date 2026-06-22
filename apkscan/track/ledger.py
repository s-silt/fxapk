"""线索追踪台账 ``TrackingLedger``（两级：APK + 线索，JSON 台账为权威源）。

仿 ``apkscan.dynamic.ledger.AnalyzedLedger`` 的范式：JSON 存储、原子落盘、
坏文件当空 + logging、**绝不抛**给调用方。

数据结构（见设计 spec §2）::

    {
      "version": 1,
      "apks": {
        "<sha256>": {
          "package": "com.x", "label": "杀猪盘", "report_path": "...",
          "apk_status": "待处理", "apk_notes": "",
          "first_seen": "ISO8601", "updated_at": "ISO8601",
          "leads": {
            "<lead_key>": {
              "category": "DOMAIN", "value": "*.x.com", "subject": "...",
              "status": "待办", "notes": "",
              "history": [{"at": "ISO8601", "text": "已出函"}],
              "first_seen": "ISO8601", "updated_at": "ISO8601"
            }
          }
        }
      }
    }

合并铁律（``upsert_report``）：
- APK / 线索已存在 → **保留人工改过的** ``apk_status/apk_notes`` 与线索
  ``status/notes/history``；只刷新分析派生字段（package/label/report_path/
  category/value/subject/updated_at）。
- 新线索默认 ``status="待办"``。
- 本次分析里**消失的旧线索不删**（保留办案痕迹）。

并发：进程内 ``threading.Lock`` + 读改写后 ``os.replace`` 原子落盘。不引入跨进程
filelock（局域网小团队按单条更新，last-write-wins 已足够，见 spec §3/§10）。
"""

from __future__ import annotations

import copy
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from apkscan.core import device

if TYPE_CHECKING:
    from apkscan.core.models import Report

logger = logging.getLogger(__name__)

# 台账格式版本（结构升级时据此迁移；当前固定 1）。
LEDGER_VERSION = 1

# 默认台账位置：用户主目录、仓库之外，git pull / clean 永不覆盖（spec §6）。
_DEFAULT_RELATIVE = Path(".apkscan") / "tracking.json"

# 位置覆盖用的环境变量名。
ENV_TRACKING_DB = "FXAPK_TRACKING_DB"

# 新线索的默认办案状态。
_DEFAULT_LEAD_STATUS = "待办"
# 新 APK 的默认办案状态。
_DEFAULT_APK_STATUS = "待处理"


def _now_iso() -> str:
    """当前时间的 ISO8601 字符串（UTC，带时区）。"""
    return datetime.now(timezone.utc).isoformat()


def default_ledger_path() -> Path:
    """解析默认台账路径：``FXAPK_TRACKING_DB`` env 优先，否则 ``~/.apkscan/tracking.json``。"""
    env = os.environ.get(ENV_TRACKING_DB)
    if env:
        return Path(env).expanduser()
    return Path.home() / _DEFAULT_RELATIVE


def make_lead_key(category: str, value: str) -> str:
    """构造稳定 lead_key：``f"{category}:{value}"``（同一线索跨多次分析归一）。"""
    return f"{category}:{value}"


class TrackingLedger:
    """两级（APK + 线索）办案台账。坏文件/IO 失败一律吞成空 + logging，绝不抛。

    路径优先级：构造参数 ``path`` > ``FXAPK_TRACKING_DB`` env > ``~/.apkscan/tracking.json``。
    """

    def __init__(self, path: str | Path | None = None) -> None:
        if path is not None:
            self._path = Path(path).expanduser()
        else:
            self._path = default_ledger_path()
        self._lock = threading.Lock()
        self._data: dict[str, Any] = self._load()

    # ---- 路径 ----
    @property
    def path(self) -> Path:
        """台账文件的解析后绝对/相对路径。"""
        return self._path

    # ---- 读 ----
    def _load(self) -> dict[str, Any]:
        """读台账。坏 JSON / IO 失败 / 结构异常 → 当空 + logging，绝不抛。"""
        empty: dict[str, Any] = {"version": LEDGER_VERSION, "apks": {}}
        if not self._path.is_file():
            return empty
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            logger.warning("[track] 台账损坏/不可读，当空处理：%s", self._path, exc_info=True)
            return empty
        if not isinstance(raw, dict):
            logger.warning("[track] 台账顶层非 dict，当空处理：%s", self._path)
            return empty
        apks = raw.get("apks")
        if not isinstance(apks, dict):
            logger.warning("[track] 台账 apks 字段缺失/非 dict，当空处理：%s", self._path)
            return empty
        raw.setdefault("version", LEDGER_VERSION)
        return raw

    def load(self) -> dict[str, Any]:
        """重新从磁盘载入并返回全量台账（深合并不做，直接覆盖内存态）。"""
        with self._lock:
            self._data = self._load()
            return self._data

    def all(self) -> dict[str, Any]:
        """返回当前内存全量台账的**深拷贝**（供网页只读展示）。

        必须深拷贝：网页 ``GET /api/tracking`` 用 ``jsonify(ledger.all())``，flask（threaded=True）
        在请求处理中惰性序列化时已不持锁；若返回活引用，另一线程的 POST 改同一 dict 会触发
        ``RuntimeError: dictionary changed size during iteration``。拷贝代价对小台账可忽略。
        """
        with self._lock:
            return copy.deepcopy(self._data)

    # ---- 写（原子） ----
    def _save(self) -> None:
        """原子落盘：临时文件 + ``os.replace``。写失败记 error、不破坏既有文件，绝不抛。"""
        # 临时名带 pid+随机后缀：多进程并发写（并行 analyze / 网页另一进程编辑同一 ~/.apkscan
        # /tracking.json）各写各的 .tmp，再各自 os.replace（原子，最后一个胜出但永远是完整文件）；
        # 若用固定 .tmp，两进程会互踩同一临时文件、可能落出半截坏 JSON。
        tmp = self._path.with_suffix(self._path.suffix + f".{os.getpid()}.{uuid4().hex}.tmp")
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(
                json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            os.replace(tmp, self._path)  # 同目录原子替换，不留半截坏文件
        except OSError:
            logger.error("[track] 台账落盘失败（忽略，不破坏既有文件）：%s", self._path, exc_info=True)
            try:
                tmp.unlink(missing_ok=True)  # 清理可能残留的半截临时文件
            except OSError:
                logger.debug("[track] 清理临时台账文件失败：%s", tmp, exc_info=True)

    # ---- upsert（自动入账，含合并铁律） ----
    def upsert_report(self, report: Report, report_path: str | os.PathLike[str]) -> None:
        """从 ``Report`` 取 sha256/package/label/leads，upsert 进台账。绝不抛。

        合并规则见模块 docstring：保留人工改过的 status/notes/history、新线索默认待办、
        旧线索不删。包名来自样本不可信，``device.is_valid_package`` 校验失败则置空 package
        （不阻断入账，sha256 才是主键）。
        """
        try:
            self._upsert_report_impl(report, report_path)
        except Exception:  # noqa: BLE001 — 入账层绝不抛：任何意外都记日志后吞掉，不阻断主流程
            logger.error("[track] upsert_report 异常（已吞，不影响报告产出）", exc_info=True)

    def _upsert_report_impl(
        self, report: Report, report_path: str | os.PathLike[str]
    ) -> None:
        meta = getattr(report, "meta", None)
        if not isinstance(meta, dict):
            meta = {}

        sha = str(meta.get("sample_sha256") or "").strip()
        if not sha:
            logger.warning("[track] report 缺 sha256（meta.sample_sha256 空），跳过入账")
            return

        package = str(getattr(report, "package_name", "") or meta.get("package_name") or "")
        # 包名来自样本 manifest（attacker 可控），形态非法则不落 package（不阻断入账）。
        if package and not device.is_valid_package(package):
            logger.warning("[track] 包名形态非法，入账时置空 package：%r", package)
            package = ""

        label = str(meta.get("app_label") or meta.get("label") or "")
        now = _now_iso()

        leads = getattr(report, "leads", None)
        if not isinstance(leads, list):
            leads = []

        with self._lock:
            apks = self._data.setdefault("apks", {})
            apk = apks.get(sha)
            if apk is None or not isinstance(apk, dict):
                apk = {
                    "package": package,
                    "label": label,
                    "report_path": str(report_path),
                    "apk_status": _DEFAULT_APK_STATUS,
                    "apk_notes": "",
                    "first_seen": now,
                    "updated_at": now,
                    "leads": {},
                }
                apks[sha] = apk
            else:
                # 已存在：只刷新分析派生字段，保留人工改过的 apk_status/apk_notes。
                # package/label 仅在新值非空时覆盖——避免某次重分析包名非法被置空/label 取空时
                # 用空串覆盖此前已存的有效值（派生信息回退丢失）。
                if package:
                    apk["package"] = package
                if label:
                    apk["label"] = label
                apk["report_path"] = str(report_path)
                apk["updated_at"] = now
                apk.setdefault("apk_status", _DEFAULT_APK_STATUS)
                apk.setdefault("apk_notes", "")
                apk.setdefault("first_seen", now)
                if not isinstance(apk.get("leads"), dict):
                    apk["leads"] = {}

            lead_map = apk["leads"]
            for lead in leads:
                category = self._lead_category(lead)
                value = str(getattr(lead, "value", "") or "")
                subject = getattr(lead, "subject", None)
                subject = "" if subject is None else str(subject)
                key = make_lead_key(category, value)

                existing = lead_map.get(key)
                if existing is None or not isinstance(existing, dict):
                    lead_map[key] = {
                        "category": category,
                        "value": value,
                        "subject": subject,
                        "status": _DEFAULT_LEAD_STATUS,
                        "notes": "",
                        "history": [],
                        "first_seen": now,
                        "updated_at": now,
                    }
                else:
                    # 已存在：刷新派生字段，保留人工改过的 status/notes/history。
                    existing["category"] = category
                    existing["value"] = value
                    existing["subject"] = subject
                    existing["updated_at"] = now
                    existing.setdefault("status", _DEFAULT_LEAD_STATUS)
                    existing.setdefault("notes", "")
                    if not isinstance(existing.get("history"), list):
                        existing["history"] = []
                    existing.setdefault("first_seen", now)
                # 本次分析消失的旧线索：不删（spec §2/§3 保留办案痕迹）。

            self._save()

    @staticmethod
    def _lead_category(lead: Any) -> str:
        """从 Lead 取 category 的字符串名（LeadCategory 枚举 → .value，其它 → str）。"""
        cat = getattr(lead, "category", "")
        value = getattr(cat, "value", None)
        if value is not None:
            return str(value)
        return str(cat)

    # ---- 手动加线索（网页/CLI 人工补录，自动没抠到的线索进台账跟进） ----
    def add_lead(
        self,
        sha256: str,
        category: str,
        value: str,
        *,
        subject: str = "",
        status: str = _DEFAULT_LEAD_STATUS,
        notes: str = "",
    ) -> bool:
        """手动新增一条线索（spec §4）。绝不抛。

        - APK 不在台账 → 建最小 APK 壳（``apk_status`` 默认、package/label 空）。
        - ``lead_key = make_lead_key(category, value)``：已存在 → 返回 False（已跟踪，
          不覆盖）；不存在 → 建线索并**标 ``manual: true``**，``first_seen/updated_at``
          置当前。
        - 手动线索与自动入账线索同结构，后续重分析 upsert 命中同 key 走既有合并
          （保留人工 status/notes/history）。
        - 不自动喂图谱（本轮决策：手动线索只进台账）。

        返回是否新建并落盘成功；已存在 / 失败 → False。
        """
        try:
            sha = str(sha256 or "").strip()
            if not sha:
                logger.warning("[track] add_lead 缺 sha256，跳过")
                return False
            category = str(category or "")
            value = str(value or "")
            key = make_lead_key(category, value)
            now = _now_iso()

            with self._lock:
                apks = self._data.setdefault("apks", {})
                apk = apks.get(sha)
                if not isinstance(apk, dict):
                    # APK 不在台账：建最小壳（package/label 空，sha256 才是主键）。
                    apk = {
                        "package": "",
                        "label": "",
                        "report_path": "",
                        "apk_status": _DEFAULT_APK_STATUS,
                        "apk_notes": "",
                        "first_seen": now,
                        "updated_at": now,
                        "leads": {},
                    }
                    apks[sha] = apk
                lead_map = apk.get("leads")
                if not isinstance(lead_map, dict):
                    lead_map = {}
                    apk["leads"] = lead_map

                if key in lead_map and isinstance(lead_map[key], dict):
                    # 已跟踪：不覆盖人工/自动既有线索。
                    logger.info("[track] add_lead 线索已存在，不覆盖：%s / %s", sha, key)
                    return False

                lead_map[key] = {
                    "category": category,
                    "value": value,
                    "subject": str(subject),
                    "status": str(status),
                    "notes": str(notes),
                    "history": [],
                    "manual": True,
                    "first_seen": now,
                    "updated_at": now,
                }
                self._save()
                return True
        except Exception:  # noqa: BLE001 — 台账层绝不抛
            logger.error(
                "[track] add_lead 异常（已吞）：%s / %s:%s",
                sha256,
                category,
                value,
                exc_info=True,
            )
            return False

    # ---- 手动改（单字段，最小化覆盖面） ----
    def set_apk(
        self,
        sha256: str,
        *,
        status: str | None = None,
        notes: str | None = None,
    ) -> bool:
        """手动改某 APK 的办案 status/notes（None 表示不动该字段）。

        返回是否命中并落盘。sha256 不存在 → 记 warning 返回 False，绝不抛。
        """
        try:
            with self._lock:
                apk = self._data.get("apks", {}).get(sha256)
                if not isinstance(apk, dict):
                    logger.warning("[track] set_apk 未找到 APK：%s", sha256)
                    return False
                if status is not None:
                    apk["apk_status"] = status
                if notes is not None:
                    apk["apk_notes"] = notes
                apk["updated_at"] = _now_iso()
                self._save()
                return True
        except Exception:  # noqa: BLE001 — 台账层绝不抛
            logger.error("[track] set_apk 异常（已吞）：%s", sha256, exc_info=True)
            return False

    def set_lead(
        self,
        sha256: str,
        lead_key: str,
        *,
        status: str | None = None,
        notes: str | None = None,
    ) -> bool:
        """手动改某线索的办案 status/notes（None 表示不动该字段）。

        返回是否命中并落盘。APK / 线索不存在 → 记 warning 返回 False，绝不抛。
        """
        try:
            with self._lock:
                lead = self._find_lead(sha256, lead_key)
                if lead is None:
                    return False
                if status is not None:
                    lead["status"] = status
                if notes is not None:
                    lead["notes"] = notes
                lead["updated_at"] = _now_iso()
                self._save()
                return True
        except Exception:  # noqa: BLE001 — 台账层绝不抛
            logger.error(
                "[track] set_lead 异常（已吞）：%s / %s", sha256, lead_key, exc_info=True
            )
            return False

    def add_history(self, sha256: str, lead_key: str, text: str) -> bool:
        """给某线索追加一条带时间戳的进展（留痕，永不自动删改）。

        返回是否命中并落盘。APK / 线索不存在 → 记 warning 返回 False，绝不抛。
        """
        try:
            with self._lock:
                lead = self._find_lead(sha256, lead_key)
                if lead is None:
                    return False
                history = lead.get("history")
                if not isinstance(history, list):
                    history = []
                    lead["history"] = history
                history.append({"at": _now_iso(), "text": str(text)})
                lead["updated_at"] = _now_iso()
                self._save()
                return True
        except Exception:  # noqa: BLE001 — 台账层绝不抛
            logger.error(
                "[track] add_history 异常（已吞）：%s / %s", sha256, lead_key, exc_info=True
            )
            return False

    def _find_lead(self, sha256: str, lead_key: str) -> dict[str, Any] | None:
        """内部：定位某 APK 下的某条线索 dict（不存在记 warning 返回 None）。调用方持锁。"""
        apk = self._data.get("apks", {}).get(sha256)
        if not isinstance(apk, dict):
            logger.warning("[track] 未找到 APK：%s", sha256)
            return None
        lead = apk.get("leads", {}).get(lead_key)
        if not isinstance(lead, dict):
            logger.warning("[track] 未找到线索：%s / %s", sha256, lead_key)
            return None
        return lead
