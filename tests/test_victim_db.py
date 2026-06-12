"""第二波 VICTIM_DATA（运行时 SQLCipher/SQLite 落地库导出物证链）纯逻辑单测。

策略（与 test_credential / test_cryptohook / test_merge 同范式）：全程无设备/无 Frida，
只测可测纯函数——

- cryptohook.normalize_sqlcipher_event：规范化导出成功/降级事件、不抛。
- cryptohook.FRIDA_SQLCIPHER_HOOK_JS：Frida JS 常量完整性（多 fallback 类名、send 通道、
  sqlcipher_export、v3/v4 cipher_compatibility 适配）。
- merge.merge_runtime_databases：用标准库 sqlite3 在 tmp **真造**明文 .plain.db（建 account/
  message/contact 表填合成数据，含手机号/域名/IM 账号）→ 喂 merge → 断言产 VICTIM_DATA Lead、
  手机号脱敏、where_to_request 对、合规 notes；坏/不存在 db 不抛；空库不产 Lead。
- db_carve 启发式命中/不命中。
- 导出失败降级（合成"仅 key+路径"事件 → Lead.notes 带人工解密 playbook、不崩）。

真机部分（frida JS 注入 SQLCipher rawExecSQL + adb pull .plain.db）无法单测，由用户在 MuMu
复验，与现有 cryptohook 真机 JS 行为一致。
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from apkscan.core.models import LeadCategory, Report
from apkscan.dynamic import cryptohook, merge


# ---------------------------------------------------------------------------
# 合成帮助器
# ---------------------------------------------------------------------------


def _make_report(
    *,
    endpoints: list[Any] | None = None,
    leads: list[Any] | None = None,
    meta: dict[str, Any] | None = None,
) -> Report:
    return Report(
        package_name="com.test.app",
        meta=dict(meta or {}),
        leads=list(leads or []),
        endpoints=list(endpoints or []),
        findings=[],
        analyzer_status=[],
    )


def _sqlcipher_payload(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "type": cryptohook.SQLCIPHER_MSG_TYPE,
        "event": "exported",
        "db_path": "/data/data/com.test.app/databases/im.db",
        "plain_path": "/data/local/tmp/apkscan_db/im.db.plain.db",
        "key": "s3cr3tDbKey123456",
    }
    base.update(kw)
    return base


def _send(payload: dict[str, Any]) -> dict[str, Any]:
    return {"type": "send", "payload": payload}


def _build_plain_db(path: Path) -> None:
    """在 tmp 真造一个明文 .plain.db：account / message / contact 表 + 合成受害人数据。"""
    conn = sqlite3.connect(str(path))
    try:
        cur = conn.cursor()
        cur.execute(
            "CREATE TABLE account (id INTEGER PRIMARY KEY, username TEXT, mobile TEXT, token TEXT)"
        )
        cur.executemany(
            "INSERT INTO account (username, mobile, token) VALUES (?, ?, ?)",
            [
                ("victim01", "13800138000", "Abc123Xyz789Def456Ghi012Jkl345"),
                ("victim02", "13912345678", "Zyx987Wvu654Tsr321Qpo098Nml765"),
            ],
        )
        cur.execute(
            "CREATE TABLE message (id INTEGER PRIMARY KEY, content TEXT, im TEXT)"
        )
        cur.executemany(
            "INSERT INTO message (content, im) VALUES (?, ?)",
            [
                ("老师带你稳赚，访问 https://api.fraud-c2.cn/login 入金", "telegram_boss88"),
                ("加我微信 wxid_abc 对接上线", "wxid_abc"),
            ],
        )
        cur.execute(
            "CREATE TABLE contact (id INTEGER PRIMARY KEY, name TEXT, phone TEXT)"
        )
        cur.execute(
            "INSERT INTO contact (name, phone) VALUES (?, ?)", ("张三", "13700137000")
        )
        # 无关表（不应产生噪音线索）
        cur.execute("CREATE TABLE android_metadata (locale TEXT)")
        cur.execute("INSERT INTO android_metadata VALUES ('zh_CN')")
        conn.commit()
    finally:
        conn.close()


def _write_runtime_report(
    tmp_path: Path,
    *,
    sqlcipher_events: list[dict[str, Any]] | None = None,
) -> str:
    import json

    payload = {
        "package_name": "com.test.app",
        "sqlcipher_events": list(sqlcipher_events or []),
    }
    path = tmp_path / "runtime_report.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return str(path)


# ===========================================================================
# normalize_sqlcipher_event
# ===========================================================================


def test_normalize_sqlcipher_drops_non_dict_and_no_db_path() -> None:
    assert cryptohook.normalize_sqlcipher_event("x") is None
    assert cryptohook.normalize_sqlcipher_event(None) is None
    assert cryptohook.normalize_sqlcipher_event([]) is None
    # 缺 db_path → 无取证价值 → None
    assert cryptohook.normalize_sqlcipher_event({"event": "exported"}) is None


def test_normalize_sqlcipher_exported_keeps_paths_and_key() -> None:
    ev = cryptohook.normalize_sqlcipher_event(_sqlcipher_payload())
    assert ev is not None
    assert ev["event"] == "exported"
    assert ev["db_path"].endswith("im.db")
    assert ev["plain_path"].endswith(".plain.db")
    # key 是高敏：截断/脱敏，不留全文
    assert ev["key"]
    assert "s3cr3tDbKey123456" not in ev["key"]


def test_normalize_sqlcipher_degraded_event_no_plain_path() -> None:
    """导出失败降级事件：仅回传 key + 原库路径（无 plain_path），不崩、保留 event=key_only。"""
    ev = cryptohook.normalize_sqlcipher_event(
        _sqlcipher_payload(event="key_only", plain_path=None)
    )
    assert ev is not None
    assert ev["event"] == "key_only"
    assert ev["db_path"].endswith("im.db")
    assert not ev.get("plain_path")


def test_normalize_sqlcipher_never_raises_on_garbage() -> None:
    # key 类型错误也不抛
    ev = cryptohook.normalize_sqlcipher_event(_sqlcipher_payload(key=12345))
    assert ev is not None  # db_path 仍在
    assert cryptohook.normalize_sqlcipher_event({"db_path": 999}) is None


# ===========================================================================
# make_typed_handler 路由（复用现有工厂）
# ===========================================================================


def test_sqlcipher_typed_handler_routes_and_never_raises() -> None:
    sink: list[dict[str, Any]] = []
    handler = cryptohook.make_typed_handler(
        sink, cryptohook.SQLCIPHER_MSG_TYPE, cryptohook.normalize_sqlcipher_event
    )
    handler(_send(_sqlcipher_payload()), None)
    # 别的通道（crypto）→ 忽略
    handler(_send({"type": cryptohook.CRYPTO_MSG_TYPE, "src": "cipher"}), None)
    handler("garbage", None)  # type: ignore[arg-type]
    handler({"type": "send", "payload": "notadict"}, None)
    assert len(sink) == 1
    assert sink[0]["event"] == "exported"


# ===========================================================================
# Frida SQLCipher JS 常量完整性
# ===========================================================================


def test_frida_sqlcipher_hook_js_integrity() -> None:
    js = cryptohook.FRIDA_SQLCIPHER_HOOK_JS
    assert "Java.perform" in js
    # 多 fallback 类名（SQLCipher net.sqlcipher + 系统 android SQLite）
    assert "net.sqlcipher.database.SQLiteDatabase" in js
    assert "android.database.sqlite.SQLiteDatabase" in js
    # 导出关键：sqlcipher_export + ATTACH
    assert "sqlcipher_export" in js
    assert "ATTACH DATABASE" in js
    # v3/v4 KDF 适配
    assert "cipher_compatibility" in js
    assert "send(" in js  # 回传通道
    assert cryptohook.SQLCIPHER_MSG_TYPE in js  # 通道判别值与 Python 一致


# ===========================================================================
# db_carve 启发式（命中/不命中）
# ===========================================================================


def test_db_carve_table_hit_and_miss() -> None:
    assert cryptohook is not None  # 占位避免 lint
    assert merge._is_carve_table("account") is True
    assert merge._is_carve_table("im_message") is True
    assert merge._is_carve_table("t_user_contact") is True
    # 系统/无关表不命中
    assert merge._is_carve_table("android_metadata") is False
    assert merge._is_carve_table("sqlite_sequence") is False


def test_db_carve_column_hit_and_miss() -> None:
    assert merge._is_carve_column("mobile") is True
    assert merge._is_carve_column("user_phone") is True
    assert merge._is_carve_column("mchid") is True
    assert merge._is_carve_column("content") is True
    # 无物证价值列不命中
    assert merge._is_carve_column("created_at") is False
    assert merge._is_carve_column("id") is False


# ===========================================================================
# merge.merge_runtime_databases —— 真造 .plain.db 喂 merge
# ===========================================================================


def test_merge_databases_produces_victim_data_lead(tmp_path: Path) -> None:
    plain = tmp_path / "im.db.plain.db"
    _build_plain_db(plain)
    rr = _write_runtime_report(
        tmp_path,
        sqlcipher_events=[
            {
                "event": "exported",
                "db_path": "/data/data/com.test.app/databases/im.db",
                "plain_path": str(plain),
                "key": "s3c…3456",
            }
        ],
    )
    report = _make_report()
    stats = merge.merge_runtime_databases(report, rr)

    victim_leads = [
        lead for lead in report.leads if lead.category == LeadCategory.VICTIM_DATA
    ]
    assert victim_leads, "应至少产一条 VICTIM_DATA Lead"
    assert stats["victim_leads"] >= 1
    lead = victim_leads[0]
    # 合规提示：含受害人高敏个人信息处置
    assert "高敏" in lead.notes or "合规" in lead.notes
    # where_to_request：向 IM 平台/支付机构调证
    assert lead.where_to_request


def test_merge_databases_masks_phone_numbers(tmp_path: Path) -> None:
    """受害人手机号是高敏个人信息：抠出的值里手机号中间打码（不留全文）。"""
    plain = tmp_path / "im.db.plain.db"
    _build_plain_db(plain)
    rr = _write_runtime_report(
        tmp_path,
        sqlcipher_events=[
            {
                "event": "exported",
                "db_path": "/data/data/com.test.app/databases/im.db",
                "plain_path": str(plain),
            }
        ],
    )
    report = _make_report()
    merge.merge_runtime_databases(report, rr)

    blob = "\n".join(
        f"{lead.value} {lead.notes} {' '.join(e.snippet for e in lead.source_refs)}"
        for lead in report.leads
        if lead.category == LeadCategory.VICTIM_DATA
    )
    # 完整手机号不得出现（中间已打码）
    assert "13800138000" not in blob
    assert "13912345678" not in blob
    assert "13700137000" not in blob
    # 前后片段保留可比对
    assert "138" in blob and "8000" in blob


def test_merge_databases_records_sha256_for_integrity(tmp_path: Path) -> None:
    """合规护栏：拉回 .plain.db 落盘后算 SHA256 留存（取证完整性）。"""
    plain = tmp_path / "im.db.plain.db"
    _build_plain_db(plain)
    rr = _write_runtime_report(
        tmp_path,
        sqlcipher_events=[
            {
                "event": "exported",
                "db_path": "/data/data/com.test.app/databases/im.db",
                "plain_path": str(plain),
            }
        ],
    )
    report = _make_report()
    merge.merge_runtime_databases(report, rr)
    # meta 留存 SHA256 台账
    digests = report.meta.get("runtime_db_digests")
    assert isinstance(digests, dict) and digests
    # 至少一条是 64 位十六进制 SHA256
    assert any(len(str(v)) == 64 for v in digests.values())


def test_merge_databases_empty_db_no_lead(tmp_path: Path) -> None:
    """空库（无敏感表/数据）不产 Lead。"""
    plain = tmp_path / "empty.plain.db"
    conn = sqlite3.connect(str(plain))
    conn.execute("CREATE TABLE android_metadata (locale TEXT)")
    conn.commit()
    conn.close()
    rr = _write_runtime_report(
        tmp_path,
        sqlcipher_events=[
            {
                "event": "exported",
                "db_path": "/data/data/com.test.app/databases/empty.db",
                "plain_path": str(plain),
            }
        ],
    )
    report = _make_report()
    stats = merge.merge_runtime_databases(report, rr)
    assert stats["victim_leads"] == 0
    assert not [
        lead for lead in report.leads if lead.category == LeadCategory.VICTIM_DATA
    ]


def test_merge_databases_bad_db_file_never_raises(tmp_path: Path) -> None:
    """损坏的 db 文件（非 sqlite）不抛，单库失败不影响整体。"""
    bad = tmp_path / "broken.plain.db"
    bad.write_bytes(b"this is not a sqlite database at all")
    rr = _write_runtime_report(
        tmp_path,
        sqlcipher_events=[
            {
                "event": "exported",
                "db_path": "/data/data/com.test.app/databases/broken.db",
                "plain_path": str(bad),
            }
        ],
    )
    report = _make_report()
    stats = merge.merge_runtime_databases(report, rr)  # 不抛即通过
    assert stats["victim_leads"] == 0


def test_merge_databases_missing_plain_file_never_raises(tmp_path: Path) -> None:
    rr = _write_runtime_report(
        tmp_path,
        sqlcipher_events=[
            {
                "event": "exported",
                "db_path": "/data/data/com.test.app/databases/x.db",
                "plain_path": str(tmp_path / "nonexistent.plain.db"),
            }
        ],
    )
    report = _make_report()
    stats = merge.merge_runtime_databases(report, rr)
    assert stats["victim_leads"] == 0


def test_merge_databases_empty_when_no_events(tmp_path: Path) -> None:
    rr = _write_runtime_report(tmp_path, sqlcipher_events=[])
    report = _make_report()
    stats = merge.merge_runtime_databases(report, rr)
    assert stats["victim_leads"] == 0


def test_merge_databases_never_raises_on_missing_report() -> None:
    report = _make_report()
    stats = merge.merge_runtime_databases(report, "nonexistent_runtime_report.json")
    assert stats["victim_leads"] == 0


# ===========================================================================
# 导出失败降级（key_only 事件 → 人工解密 playbook 进 Lead.notes，不崩）
# ===========================================================================


def test_merge_databases_key_only_degraded_produces_playbook_lead(tmp_path: Path) -> None:
    """SQLCipher 导出失败降级：仅 key + 原库路径事件 → 产 Lead，notes 带人工解密 playbook。"""
    rr = _write_runtime_report(
        tmp_path,
        sqlcipher_events=[
            {
                "event": "key_only",
                "db_path": "/data/data/com.test.app/databases/im.db",
                "plain_path": None,
                "key": "s3c…3456",
            }
        ],
    )
    report = _make_report()
    stats = merge.merge_runtime_databases(report, rr)
    assert stats["victim_leads"] >= 1
    victim_leads = [
        lead for lead in report.leads if lead.category == LeadCategory.VICTIM_DATA
    ]
    assert victim_leads
    lead = victim_leads[0]
    # notes 含人工解密 playbook（sqlcipher / PRAGMA key 关键词）
    assert "sqlcipher" in lead.notes.lower() or "PRAGMA" in lead.notes
    # 诚实标注：launch-only 抓不全
    assert "launch" in lead.notes.lower() or "人工" in lead.notes


def test_merge_databases_dedups_same_db(tmp_path: Path) -> None:
    """同一原库多次导出事件 → 同一物证库去重，不重复刷线索。"""
    plain = tmp_path / "im.db.plain.db"
    _build_plain_db(plain)
    ev = {
        "event": "exported",
        "db_path": "/data/data/com.test.app/databases/im.db",
        "plain_path": str(plain),
    }
    rr = _write_runtime_report(tmp_path, sqlcipher_events=[dict(ev), dict(ev)])
    report = _make_report()
    merge.merge_runtime_databases(report, rr)
    # 同一 (db_path, table, column-value) 不应产生 2 倍线索
    victim_values = [
        lead.value
        for lead in report.leads
        if lead.category == LeadCategory.VICTIM_DATA
    ]
    assert len(victim_values) == len(set(victim_values))
