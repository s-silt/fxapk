"""服务器辖区分流 + 取证路径（纯函数，零第三方依赖）。

默认有网（消费者 Codex 在联网环境），辖区以**富化归属国**为主信号、域名启发式兜底：

- **国内服务器 → 调证路径**：向境内云厂商 / IDC / 工信部 ICP 调取访问日志、登录记录、租户实名。
- **国外服务器 → 取证路径**：难直接调证；以拿到服务器**镜像 / 磁盘与日志**为目标，结合已识别的
  后台 / 管理端、技术栈已知漏洞方向、暴露的敏感路径研判（**被动情报指引，非主动攻击 / 扫描**）。
- **辖区未定 → 先定归属再分流**。

判据优先级：ICP 备案存在 → 国内（ICP 仅境内）；host .cn/.gov.cn → 国内；富化归属国含中国大陆
→ 国内；有归属国信号且非大陆 → 国外（含港澳台 / 境外，均难直接调证）；无任何信号 → 未知。
"""

from __future__ import annotations

from dataclasses import dataclass

JURIS_DOMESTIC = "国内"
JURIS_FOREIGN = "国外"
JURIS_UNKNOWN = "未知"


def _country_is_domestic(country: str) -> bool:
    """归属国是否为中国大陆（港澳台按境外/难直接调处理，故不计入）。"""
    c = (country or "").strip().lower()
    return c == "cn" or "china" in c or "中国" in c


def _countries(*dicts: object) -> list[str]:
    """从富化 dict（rdap/whois/dns/asn）抽出所有归属国字符串。"""
    out: list[str] = []
    for d in dicts:
        if not isinstance(d, dict):
            continue
        for key in ("country", "registrant_country", "country_code"):
            v = d.get(key)
            if v:
                out.append(str(v))
        for h in d.get("hosting") or []:
            if isinstance(h, dict) and h.get("country"):
                out.append(str(h["country"]))
    return out


def classify_jurisdiction(
    host: str,
    *,
    icp: object = None,
    rdap: object = None,
    whois: object = None,
    dns: object = None,
    asn: object = None,
) -> str:
    """据富化归属国 + 域名启发式判服务器辖区。返回 国内 / 国外 / 未知。绝不抛。"""
    if isinstance(icp, dict) and (icp.get("subject") or icp.get("license_no")):
        return JURIS_DOMESTIC
    h = (host or "").lower().strip().rstrip(".")
    if h.endswith(".cn") or h.endswith(".gov.cn") or h.endswith(".中国"):
        return JURIS_DOMESTIC
    countries = _countries(rdap, whois, dns, asn)
    if any(_country_is_domestic(c) for c in countries):
        return JURIS_DOMESTIC
    if countries:
        return JURIS_FOREIGN
    return JURIS_UNKNOWN


@dataclass(frozen=True)
class ForensicPath:
    """辖区对应的取证路径：展示标签 + 追加证据清单 + 一句说明。"""

    jurisdiction: str
    label: str
    evidence: tuple[str, ...]
    note: str


_PATHS = {
    JURIS_DOMESTIC: ForensicPath(
        JURIS_DOMESTIC,
        "国内服务器·可调证",
        ("向境内云厂商 / IDC / 工信部 ICP 备案系统调取该服务器访问日志、登录记录与租户实名",),
        "国内服务器：依法调证路径——向境内云厂商 / IDC / ICP 调取访问、登录日志与租户实名",
    ),
    JURIS_FOREIGN: ForensicPath(
        JURIS_FOREIGN,
        "国外服务器·取证为主",
        (
            "国外难直接调证：以获取服务器镜像 / 磁盘与访问日志为目标",
            "结合该服务器已识别的后台 / 管理端、技术栈已知漏洞方向、暴露的敏感路径研判（被动情报，非主动攻击）",
        ),
        "国外服务器：难直接调证——转取证路径，以拿到服务器镜像 / 磁盘与日志为目标",
    ),
    JURIS_UNKNOWN: ForensicPath(
        JURIS_UNKNOWN,
        "辖区未定",
        ("先据 whois 注册国 / IP ASN 归属国确定服务器辖区，再分流（国内调证 / 国外取证）",),
        "辖区未定：先定服务器归属国，再分流——国内走调证、国外走取证",
    ),
}


def forensic_path(jurisdiction: str) -> ForensicPath:
    """取辖区对应的取证路径；未知辖区兜底。"""
    return _PATHS.get(jurisdiction, _PATHS[JURIS_UNKNOWN])
