"""算法子域下发通道枚举（A4）：MD5(前缀+日期)+.基域 生成器 + week-year 坑 + CLI。零真实前缀/域名。"""
from __future__ import annotations

import hashlib
from datetime import date

from apkscan.config.algo_channel import date_window, md5_date_subdomains


def _md5(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def test_generates_expected_md5_subdomain() -> None:
    days = [date(2026, 7, 23)]
    out = md5_date_subdomains("BW-755-", "example-synthetic.test", days, path="/x.txt")
    assert len(out) == 1
    c = out[0]
    assert c["subdomain"] == f"{_md5('BW-755-20260723')}.example-synthetic.test"
    assert c["url"] == f"https://{c['subdomain']}/x.txt"
    assert c["year_kind"] == "calendar"


def test_week_year_boundary_yields_both_variants() -> None:
    """★week-year 坑：跨年周（如 2025-12-29 属 ISO 2026 周年）→ 同时产日历年与周年两种前缀串。"""
    days = [date(2025, 12, 29)]  # 日历年 2025、ISO 周年 2026
    out = md5_date_subdomains("p", "d-synthetic.test", days)
    tokens = {c["year_kind"] for c in out}
    assert tokens == {"calendar", "iso-week"}
    subs = {c["subdomain"] for c in out}
    assert f"{_md5('p20251229')}.d-synthetic.test" in subs   # 日历年
    assert f"{_md5('p20261229')}.d-synthetic.test" in subs   # ISO 周年


def test_non_boundary_date_single_variant() -> None:
    """普通日期（周年==日历年）→ 只一条（去重）。"""
    out = md5_date_subdomains("p", "d.test", [date(2026, 7, 23)])
    assert len(out) == 1 and out[0]["year_kind"] == "calendar"


def test_date_window_spans_correctly() -> None:
    w = date_window(date(2026, 7, 23), back=2, fwd=1)
    assert w == [date(2026, 7, 21), date(2026, 7, 22), date(2026, 7, 23), date(2026, 7, 24)]


def test_empty_domain_or_robust() -> None:
    assert md5_date_subdomains("p", "", [date(2026, 1, 1)]) == []
    assert md5_date_subdomains("p", ".d.test", [date(2026, 1, 1)])[0]["subdomain"].endswith(".d.test")


def test_cli_config_channel() -> None:
    from typer.testing import CliRunner

    from apkscan import cli

    r = CliRunner().invoke(cli.app, [
        "config-channel", "--prefix", "BW-755-", "--domain", "example-synthetic.test",
        "--path", "/x.txt", "--date", "2026-07-23", "--back", "0", "--fwd", "0",
    ])
    assert r.exit_code == 0, r.stdout
    import json
    payload = json.loads(r.stdout)
    assert payload["count"] == 1
    assert payload["candidates"][0]["subdomain"] == f"{_md5('BW-755-20260723')}.example-synthetic.test"
