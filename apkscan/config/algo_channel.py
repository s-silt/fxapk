"""算法生成的下发通道枚举（A4）：``MD5(前缀 + 日期) + "." + 基域 [+ 路径]`` 这类**运行时算法生成**的
配置/后端下发子域。

背景：部分涉诈家族不硬编码下发 URL，而是每天用 ``子域 = MD5(常量前缀 + yyyyMMdd)`` 拼出新子域去拉配置
（如 ``MD5("BW-755-" + 20260723) + ".sdfkjn755fvb.com" + "/x.txt"``）。这类 URL 静态不存在（跑起来才拼），
``discover.classify_config_url`` 认不出——但**前缀常量、基域、MD5+SimpleDateFormat 算法**都是可提取的静态事实。
本模块是**纯生成器框架**：给定组件（办案 agent 从样本里抠出、或从案件资料提供），按日期窗口枚举候选子域/URL，
供被动查询历史解析 / passive DNS / 证书透明度反查。**不含任何具体前缀/域名**（那是案件数据）。

★week-year 坑（务必）：Java ``SimpleDateFormat("YYYYMMdd")`` 的大写 ``YYYY`` 是**周年（ISO week-year）**，
在跨年周（12 月底 / 1 月初）与日历年不同。样本实际拼的是周年；为不漏，本模块对每个日期**同时**产日历年
（``%Y%m%d``）与周年（``<isoyear>%m%d``）两种前缀串、去重。纯函数、绝不联网、绝不抛。
"""
from __future__ import annotations

import hashlib
from datetime import date, timedelta


def _date_tokens(day: date) -> list[str]:
    """一个日期的 yyyyMMdd 串：日历年 + ISO 周年两种（跨年周不同，都产，去重保序）。"""
    cal = f"{day.year:04d}{day.month:02d}{day.day:02d}"
    iso_year = day.isocalendar()[0]
    wk = f"{iso_year:04d}{day.month:02d}{day.day:02d}"
    return [cal] if wk == cal else [cal, wk]


def md5_date_subdomains(
    prefix: str,
    base_domain: str,
    days: list[date],
    *,
    path: str = "",
    scheme: str = "https",
) -> list[dict[str, str]]:
    """枚举 ``MD5(prefix + yyyyMMdd)`` 子域候选。

    每个日期产 ``{date, year_kind, subdomain, url}``：``year_kind`` 为 ``calendar`` / ``iso-week``（跨年周才有第二种）。
    ``base_domain`` 去前导点归一；``path`` 空则 url 只到域名。按 (date, year_kind) 稳定排序、按 subdomain 去重。绝不抛。

    ★组件（prefix / base_domain）由调用方提供——本函数不判定"哪个常量是前缀"，那是案件/逆向所得。
    """
    pfx = str(prefix or "")
    base = str(base_domain or "").strip().lstrip(".").lower()
    p = str(path or "")
    sch = (scheme or "https").strip().lower() or "https"
    if not base:
        return []
    if p and not p.startswith("/"):
        p = "/" + p

    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for day in sorted(set(days)):
        tokens = _date_tokens(day)
        for idx, tok in enumerate(tokens):
            sub = hashlib.md5((pfx + tok).encode("utf-8")).hexdigest()  # noqa: S324 — 复刻样本算法，非安全用途
            fqdn = f"{sub}.{base}"
            if fqdn in seen:
                continue
            seen.add(fqdn)
            out.append({
                "date": day.isoformat(),
                "year_kind": "calendar" if idx == 0 else "iso-week",
                "subdomain": fqdn,
                "url": f"{sch}://{fqdn}{p}",
            })
    return out


def date_window(center: date, back: int = 0, fwd: int = 0) -> list[date]:
    """以 ``center`` 为中心、往前 ``back`` 天、往后 ``fwd`` 天的日期列表（含端点）。back/fwd 负值按 0。"""
    b = max(0, back)
    f = max(0, fwd)
    return [center + timedelta(days=d) for d in range(-b, f + 1)]


__all__ = ["md5_date_subdomains", "date_window"]
