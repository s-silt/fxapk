"""apkscan 核心数据模型 — 以 Lead（调证线索）为中心。

所有分析器/富化器/报告共享这些类型。严格作为跨 agent 接口契约，禁止偏移。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """技术发现的严重程度。"""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(Enum):
    """线索的置信度。"""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class LeadCategory(Enum):
    """调证线索分类。"""

    DOMAIN = "DOMAIN"
    IP = "IP"
    SDK_SERVICE = "SDK_SERVICE"
    PAYMENT = "PAYMENT"
    PACKER = "PACKER"
    CONTACT = "CONTACT"
    SIGNING = "SIGNING"
    CHANNEL = "CHANNEL"
    CONFIG_KEY = "CONFIG_KEY"  # 调用插件 / 配置键值（具体 key=value，如 GETUI_APPID）
    CRYPTO_RECIPE = "CRYPTO_RECIPE"  # 应用层加密配方（算法/key/iv 推导/信封字段，凭此可解全部加密流量）
    RUNTIME_CREDENTIAL = "RUNTIME_CREDENTIAL"  # 运行时实测登录态/凭据（OkHttp 明文 token/手机号、SharedPrefs 落地凭据；含高敏个人信息）
    VICTIM_DATA = "VICTIM_DATA"  # 运行时落地库（SQLCipher/SQLite）导出的受害人物证（IM 账号/手机号/订单/商户号；含受害人高敏个人信息）


@dataclass
class Evidence:
    """可复现的取证依据：来源 + 位置 + 片段。"""

    source: str  # dex|resource|native|manifest|cert|runtime
    location: str  # 文件路径 / 类名 / 资源名（可复现）
    snippet: str = ""


@dataclass
class Endpoint:
    """网络端点（URL / 域名 / IP）及其富化结果。"""

    value: str
    kind: str  # url|domain|ip
    evidences: list[Evidence] = field(default_factory=list)
    is_cleartext: bool = False
    is_private: bool = False  # 内网/回环 IP
    is_suspicious: bool = False
    enrichment: dict = field(default_factory=dict)  # whois/icp/asn 结果


@dataclass
class Lead:
    """★ 报告的核心产出单元：一条可落地的调证线索。"""

    category: LeadCategory
    value: str  # "pay.xxx.com" / "极光推送 JPush"
    subject: str | None = None  # 归属主体（公司）
    where_to_request: str | None = None  # 向谁调：注册商/云厂商/SDK厂商/加固厂商
    evidence_to_obtain: list[str] = field(default_factory=list)  # 可调取的证据
    confidence: Confidence = Confidence.MEDIUM
    source_refs: list[Evidence] = field(default_factory=list)
    notes: str = ""
    # 调证研判建议："建议调证" / "无需调证" / "待核"。默认空串（未研判），
    # 由 pipeline 末尾兜底或 build_endpoint_leads 按 infra 分级赋值。
    advice: str = ""

    @property
    def is_c2(self) -> bool:
        """是否疑似诈骗 App 的 **C2 / 主控后端服务器**（调证最该盯的落点）。

        判定：网络端点（DOMAIN/IP）且研判为「建议调证」——即 App 自有后端，已排除 CDN /
        SDK / 公共服务（googleapis、地图、jsdelivr 等）/ 开源库内嵌站点。这类是 App 真实
        通信或硬编码的命令与后端服务器，是还原资金流 / 冒充关系 / 服务器归属的首要目标。
        """
        return self.category in (LeadCategory.DOMAIN, LeadCategory.IP) and self.advice == "建议调证"

    @property
    def is_runtime_seen(self) -> bool:
        """是否在**真机抓包**中被实际观测到（运行时真连了它 / 带回了加密信封）。

        来源 source 以 ``runtime`` 开头（runtime / runtime-decrypted）= 动态确认，比纯静态
        硬编码可信度更高——C2 若 ``is_runtime_seen`` 即「**已抓到通信的确认 C2**」。
        """
        return any(str(getattr(ev, "source", "")).startswith("runtime") for ev in self.source_refs)


@dataclass
class Finding:
    """技术发现（报告附录用）。"""

    id: str
    title: str
    severity: Severity
    category: str
    description: str
    recommendation: str = ""
    evidences: list[Evidence] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass
class CertInfo:
    """签名证书信息。"""

    subject: str
    issuer: str
    sha256: str
    not_before: str
    not_after: str
    is_debug: bool = False
    schemes: list[str] = field(default_factory=list)  # v1/v2/v3


@dataclass
class EnrichmentResult:
    """单个富化器对一个端点的查询结果。"""

    provider: str
    ok: bool
    data: dict = field(default_factory=dict)
    error: str | None = None


@dataclass
class AnalyzerResult:
    """单个分析器的产出。崩溃时记录 error，不抛出。"""

    analyzer: str
    leads: list[Lead] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    error: str | None = None


@dataclass
class Component:
    """单个 Android 组件（activity/service/receiver/provider）。"""

    name: str
    exported: bool
    kind: str = ""  # activity|service|receiver|provider


@dataclass
class ComponentSet:
    """APK 的全部四大组件集合。"""

    activities: list[Component] = field(default_factory=list)
    services: list[Component] = field(default_factory=list)
    receivers: list[Component] = field(default_factory=list)
    providers: list[Component] = field(default_factory=list)


@dataclass
class AnalysisConfig:
    """一次分析的运行配置。"""

    online: bool = True
    out_dir: str = "out"
    formats: list[str] = field(default_factory=lambda: ["html", "json"])


@dataclass
class Report:
    """最终报告：聚合全部线索/端点/发现/分析器状态。"""

    package_name: str
    meta: dict  # 版本/SDK/签名摘要/加固状态
    leads: list[Lead]
    endpoints: list[Endpoint]
    findings: list[Finding]
    analyzer_status: list[dict]  # 每个分析器：name/ran|skipped|error/reason
    # 每个富化器的聚合状态：provider/attempted/ok/failed/typical_error。
    # 默认空，便于离线/无富化时仍可构造。
    enricher_status: list[dict] = field(default_factory=list)
