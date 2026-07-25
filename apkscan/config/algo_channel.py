"""算法生成的下发通道枚举（A4）：``MD5(前缀 + 日期) + "." + 基域 [+ 路径]`` 这类**运行时算法生成**的
配置/后端下发子域。

背景：部分涉诈家族不硬编码下发 URL，而是每天用 ``子域 = MD5(常量前缀 + yyyyMMdd)`` 拼出新子域去拉配置
（如 ``MD5("BW-755-" + 20260723) + ".sdfkjn755fvb.com" + "/x.txt"``）。这类 URL 静态不存在（跑起来才拼），
``discover.classify_config_url`` 认不出——但**前缀常量、基域、MD5+SimpleDateFormat 算法**都是可提取的静态事实。
本模块是**纯生成器框架**：给定组件（办案 agent 从样本里抠出、或从案件资料提供），按日期窗口枚举候选子域/URL，
供被动查询历史解析 / passive DNS / 证书透明度反查。**不含任何具体前缀/域名**（那是案件数据）。

★week-year 坑（务必）：Java ``SimpleDateFormat("YYYYMMdd")`` 的大写 ``YYYY`` 是**周年（week-year）**，
在跨年周（12 月底 / 1 月初）与日历年不同，且其值取决于 formatter 所用 Calendar 的 **locale**——ISO
（周一起、首周 ≥4 天）与美式默认（周日起、首周 ≥1 天）在同一跨年日可能给出**不同**周年（如 2027-12-31：
ISO 记 2027、美式记 2028）。本模块无法预知样本 locale，故对**临近年界**的日期在日历年之外额外产**相邻年**
前缀（周年恒在 日历年 ±1 内），over-cover 所有 locale。纯函数、绝不联网、绝不抛。
"""
from __future__ import annotations

import hashlib
from datetime import date, timedelta


def _date_tokens(day: date) -> list[str]:
    """一个日期的 yyyyMMdd 串候选：日历年在前；距年界 ≤7 天再加**相邻年**（覆盖任意 locale 的 week-year）。

    大写 YYYY 是周年、跨年周随 locale 而变（见模块 docstring）。周年恒为 日历年 或 日历年 ±1，故：年初
    （1 月前 7 天）补上一年、年末（12 月后 7 天）补下一年——即覆盖 ISO / 美式 / 任意 locale 的周年取值。
    过量生成廉价（临界期多一个候选），漏则假阴，取前者。日历年恒居首（idx 0），去重保序。
    """
    mmdd = f"{day.month:02d}{day.day:02d}"
    years = [day.year]
    if day.month == 1 and day.day <= 7:       # 年初：周年可能落到上一年
        years.append(day.year - 1)
    elif day.month == 12 and day.day >= 25:   # 年末：周年可能落到下一年
        years.append(day.year + 1)
    out: list[str] = []
    seen: set[str] = set()
    for y in years:
        tok = f"{y:04d}{mmdd}"
        if tok not in seen:
            seen.add(tok)
            out.append(tok)
    return out


def md5_date_subdomains(
    prefix: str,
    base_domain: str,
    days: list[date],
    *,
    path: str = "",
    scheme: str = "https",
) -> list[dict[str, str]]:
    """枚举 ``MD5(prefix + yyyyMMdd)`` 子域候选。

    每个日期产 ``{date, year_kind, subdomain, url}``：``year_kind`` 为 ``calendar`` / ``week-year``（临近年界才有第二种）。
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
            # usedforsecurity=False：复刻样本算法、非安全用途；FIPS 受限的 Python 上不加此参数会直接抛
            # （违背本模块"绝不抛"契约、令候选枚举整体失败）。
            sub = hashlib.md5(  # noqa: S324 — 复刻样本算法，非安全用途
                (pfx + tok).encode("utf-8"), usedforsecurity=False
            ).hexdigest()
            fqdn = f"{sub}.{base}"
            if fqdn in seen:
                continue
            seen.add(fqdn)
            out.append({
                "date": day.isoformat(),
                "year_kind": "calendar" if idx == 0 else "week-year",
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
