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
    REMOTE_CONFIG = "REMOTE_CONFIG"  # 远程配置对象（App 运行时拉取的 OSS/COS/CDN 配置文件，多为加密；解开可得动态域名/IP 池）
    RUNTIME_CREDENTIAL = "RUNTIME_CREDENTIAL"  # 运行时实测登录态/凭据（OkHttp 明文 token/手机号、SharedPrefs 落地凭据；含高敏个人信息）
    VICTIM_DATA = "VICTIM_DATA"  # 运行时落地库（SQLCipher/SQLite）导出的受害人物证（IM 账号/手机号/订单/商户号；含受害人高敏个人信息）
    REMOTE_CONTROL = "REMOTE_CONTROL"  # 无障碍远控劫持的目标银行/支付 app（映射机构主体，指明向哪些银行调被害人流水）
    ADMIN_PANEL = "ADMIN_PANEL"  # 诈骗 App 的后台管理系统/控制台入口（团伙运营控制端；指明向云厂商/IDC 调后台服务器与运营日志）
    FOURTH_PARTY_PAYMENT = "FOURTH_PARTY_PAYMENT"  # 四方支付/跑分/代收代付/二清聚合支付平台（资金流重建，向支付/收单机构调进件实名与流水）
    SMS_FORWARDING = "SMS_FORWARDING"  # 短信/验证码转发服务（OTP 接管基础设施，向短信平台/运营商调转发目标与接收记录）
    CARD_MERCHANT = "CARD_MERCHANT"  # 卡商/料商/开户供应链（情报研判线索，默认待核，结合资金/通联落地）
    SELF_HOSTED_IM = "SELF_HOSTED_IM"  # 自建 IM/C2 控制信道（团伙落地强连边，向云厂商/IDC 调服务器归属与信道日志）
    WALLET_SECRET = "WALLET_SECRET"  # 钱包私钥/助记词（高敏，直接掌控资金；境外/链上路径：派生地址上链回溯+交易所冻结）
    BACKEND_CREDENTIAL = "BACKEND_CREDENTIAL"  # 硬编码后端/管理凭据（Basic-Auth/DB DSN/云AK；高敏，供有权机关依法登录取证、调服务器镜像/日志）


@dataclass
class Evidence:
    """可复现的取证依据：来源 + 位置 + 片段。"""

    source: str  # dex|resource|native|manifest|cert|runtime
    location: str  # 文件路径 / 类名 / 资源名（可复现）
    snippet: str = ""
    # 运行时观测的时间戳（Unix epoch 秒）：pcap Flow.first_ts / 探针行时间。静态证据无此概念留 None。
    # 回灌 runtime 观测时填，让「何时抓到」进证据链（时间线还原 / 与网关日志对齐）。
    observed_at: float | None = None


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


#: 运行时证据里 **真观测到「连去该端点自身 peer IP」** 的 observed-contact 子来源：``runtime``
#: （mitm 实测上游服务器 IP）/ ``runtime-pcap``（pcap 解出的真实 dst_ip）。其余 ``runtime*`` 子来源
#: ——手编 / 合成兜底的 ``runtime-derived``（见 ``dynamic.merge._RUNTIME_DERIVED_SOURCE``）、
#: ``*-decrypted``、``runtime-tshark`` 等——只证明「该值出现在 runtime 报告里」，不证明真接触。
#: **信任边界的单一真源**：办案人面的 :attr:`Lead.is_runtime_contact`「实连/确认 C2」徽标与机器面的
#: attribution 运行时行为角色门（``attribution.assemble`` 引用本常量）共用它，两面同口径、不各判一套。
#: allowlist 而非 denylist：新出现的 content-derived 来源默认**不算** observed-contact（守 no-over-
#: inference 契约的安全方向）。
OBSERVED_CONTACT_SOURCES: frozenset[str] = frozenset({"runtime", "runtime-pcap"})


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
        """是否在动态侧**出现过**（宽口径）：source 以 ``runtime`` 开头（runtime / runtime-pcap /
        runtime-decrypted / runtime-derived / …）即命中，比纯静态硬编码可信度更高。

        **注意**这是「动态侧出现」的宽口径信号，**不**等同于 observed-contact 级确认：手编 / 合成
        兜底的 ``runtime-derived`` 也 startswith ``runtime``、也命中本属性，但它只表示「该值出现在
        runtime 报告里」、不证明真接触。要「已抓到通信的确认 C2」这档最强断言，用严一档的
        :attr:`is_runtime_contact`（仅 :data:`OBSERVED_CONTACT_SOURCES`）。徽标分层即据此二者分档，
        避免把「出现在报告里」误呈成「实连」。
        """
        return any(str(getattr(ev, "source", "")).startswith("runtime") for ev in self.source_refs)

    @property
    def is_runtime_contact(self) -> bool:
        """是否**真机运行时观测到连去该端点自身 peer IP**（observed-contact，严于 is_runtime_seen）。

        仅当某条证据 source ∈ :data:`OBSERVED_CONTACT_SOURCES`（``runtime`` = mitm 实测上游 /
        ``runtime-pcap`` = pcap 解出真实 dst_ip）才为真——即真观测到了到该端点的网络流；``runtime-derived``
        （合成 / 非 runtime* 兜底）、``*-decrypted``、``runtime-tshark`` 等只算 :attr:`is_runtime_seen`
        的「运行时出现」、**不**算接触。C2 若 ``is_runtime_contact`` 即「**已抓到通信的确认 C2**」；
        仅 ``is_runtime_seen`` 而非 contact 只到「运行时出现、未确认接触」。与 attribution 运行时行为
        角色的信任门（``attribution.assemble`` 引用同一 :data:`OBSERVED_CONTACT_SOURCES`）**同口径**：
        办案人徽标与机器面角色统一以 observed-contact 源标签为准、不再各判一套。注意本属性只据 source
        **标签**分档——标签本身的诚实性由 producer 侧保证：合成 / 派生路径须钉 ``runtime-derived`` 等非
        contact 源（见 ``dynamic.merge._RUNTIME_DERIVED_SOURCE``），凡仍盖裸 ``runtime`` 的进程内生产者
        （如 dead-drop 从回包体抽出、App 未直连的二级 C2）会绕过本档、属 producer 侧待收紧项，非本属性能判。
        """
        return any(
            str(getattr(ev, "source", "")) in OBSERVED_CONTACT_SOURCES for ev in self.source_refs
        )


def merge_runtime_into_lead_dict(existing: dict, runtime_lead: dict) -> bool:
    """把一条 **runtime** 观测（已序列化的 lead dict）并进已存在的 lead dict，升为活体确认。

    回灌层（pcap_ingest / probe_ingest）在 ``report.json`` 上做原地字典合并：命中已存在
    ``(category, value)`` 时不丢弃，而是把新 lead 里 source 以 ``runtime`` 开头的 Evidence
    追加进已有 ``source_refs``（去重 by (source, location, snippet)），并据此重算
    ``is_runtime_seen``；若并入 / 已有任一 :data:`OBSERVED_CONTACT_SOURCES`（runtime / runtime-pcap）
    证据，同步升 ``is_runtime_contact``——否则 pcap 实抓（``runtime-pcap``）并进旧静态 lead 后，dict
    上的 ``is_runtime_contact`` 会陈旧为 ``false``，与 :attr:`Lead.is_runtime_contact` 属性重算值矛盾、
    下游按该字段筛「确认接触」会漏掉真确认的 C2。语义对齐 :attr:`Lead.is_runtime_seen` /
    :attr:`Lead.is_runtime_contact` 与 ``dynamic/merge.py`` 的「静态命中同名 → 追加 runtime 证据、升活体确认」。

    只搬 runtime Evidence（``existing`` 可能是静态 lead，静态证据原样保留）。

    Args:
        existing: report.json 里已存在的 lead dict（**原地**被改）。
        runtime_lead: 新 runtime lead 的序列化 dict。

    Returns:
        本次是否真的并入了新的 runtime 证据（True=发生合并/确认；False=无新 runtime 证据可并）。
    """
    incoming = runtime_lead.get("source_refs")
    if not isinstance(incoming, list):
        return False
    refs = existing.get("source_refs")
    if not isinstance(refs, list):
        refs = []
        existing["source_refs"] = refs
    seen = {
        (str(r.get("source")), str(r.get("location")), str(r.get("snippet")))
        for r in refs
        if isinstance(r, dict)
    }
    merged = False
    for ev in incoming:
        if not isinstance(ev, dict):
            continue
        if not str(ev.get("source", "")).startswith("runtime"):
            continue  # 只搬运行时证据，静态证据不动
        sig = (str(ev.get("source")), str(ev.get("location")), str(ev.get("snippet")))
        if sig in seen:
            continue
        seen.add(sig)
        refs.append(ev)
        merged = True
    if merged:
        # 有 runtime 证据 → 升为「运行时出现」（宽口径，与 Lead.is_runtime_seen 一致）。
        existing["is_runtime_seen"] = True
        # 若并入 / 已有任一 observed-contact 源（runtime / runtime-pcap），据全量 source_refs 重算并
        # 单调升 is_runtime_contact——与 Lead.is_runtime_contact 属性同口径，防 dict 上字段陈旧失真。
        if any(
            isinstance(r, dict) and str(r.get("source")) in OBSERVED_CONTACT_SOURCES for r in refs
        ):
            existing["is_runtime_contact"] = True
    return merged


#: Finding 的**主张类型**（复核 / Agent 据此区分「看到的」与「推断的」，别把弱推断当铁证）：
#: - observation：直接观测到的**原始事实**（运行时实测行为、清单里明写的标志等），无推理成分。
#: - inference（默认）：规则 / 启发式**推导**出的判断（多数静态 finding）。
#: - analyst_conclusion：人工研判结论（当前无自动来源，留给人工回灌 / 报告复核阶段填）。
FINDING_KIND_OBSERVATION = "observation"
FINDING_KIND_INFERENCE = "inference"
FINDING_KIND_ANALYST_CONCLUSION = "analyst_conclusion"
FINDING_KINDS: tuple[str, ...] = (
    FINDING_KIND_OBSERVATION,
    FINDING_KIND_INFERENCE,
    FINDING_KIND_ANALYST_CONCLUSION,
)


@dataclass
class Finding:
    """技术发现（报告附录用）。

    ``id`` 即该发现的**规则标识**（rule id）：规则驱动的分析器用 YAML 里的 ``id:``，代码内启发式
    用稳定常量。配合 report.meta 的 ``ruleset_digest`` / ``tool_version``，可回答「这条发现由哪条
    规则、哪套规则集、哪个版本的工具产出」——溯源闭环。
    """

    id: str
    title: str
    severity: Severity
    category: str
    description: str
    recommendation: str = ""
    evidences: list[Evidence] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    # ---- 溯源（谁、以多大把握、以什么性质产出这条发现）----
    #: 产出该发现的分析器名。在 pipeline 聚合处**集中盖章**（见 pipeline.run），分析器无需逐个改；
    #: 分析器若要标更细的子来源可自行赋值，集中盖章不覆盖已有值。
    analyzer: str = ""
    #: 置信度（多稳、多不像误报），与 severity（多严重）**正交**。默认 MEDIUM；纯启发式 / 统计类
    #: 发现应显式降为 LOW，供消费方（研判 / Agent）据此加权、抑制噪声。
    confidence: Confidence = Confidence.MEDIUM
    #: 主张类型（见 FINDING_KINDS）：observation（直接观测事实）| inference（规则推导，默认）|
    #: analyst_conclusion（人工结论）。运行时实测行为标 observation，静态规则推导默认 inference。
    kind: str = FINDING_KIND_INFERENCE


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


#: 分析网络模式。``passive``（默认）：只跑**被动**富化器（查第三方 OSINT 库，对目标零流量）；
#: ``authorized-active``：显式授权下才放行会**向目标发流量**的主动富化器（经
#: SaaS 实例 live 探测目标端口/SSL/HTTP）。默认被动，契合取证「不接触目标」定位——主动探测须操作者
#: 明确授权、且在报告中留痕。
ANALYSIS_MODE_PASSIVE = "passive"
ANALYSIS_MODE_AUTHORIZED_ACTIVE = "authorized-active"
ANALYSIS_MODES: tuple[str, ...] = (ANALYSIS_MODE_PASSIVE, ANALYSIS_MODE_AUTHORIZED_ACTIVE)


@dataclass
class AnalysisConfig:
    """一次分析的运行配置。"""

    online: bool = True
    out_dir: str = "out"
    formats: list[str] = field(default_factory=lambda: ["html", "json"])
    #: 网络模式（见 ANALYSIS_MODES）。默认 passive：主动富化器被 pipeline 代码层硬屏蔽。
    mode: str = ANALYSIS_MODE_PASSIVE


#: report.json 结构版本。消费方（AI / CI / 第三方工具）据此判断字段布局；发生破坏性字段变更时 bump。
REPORT_SCHEMA_VERSION = "1.0"

#: 分析完整度状态（Report.analysis_status）。
#: complete=无分析器报错；partial=有分析器报错但仍有成功产出；failed=无任何分析器成功跑完。
ANALYSIS_STATUS_COMPLETE = "complete"
ANALYSIS_STATUS_PARTIAL = "partial"
ANALYSIS_STATUS_FAILED = "failed"


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
    # ---- 结果可信度地基（消费方据此判断这份报告有多可信 / 是否完整）----
    #: 报告结构版本（见 REPORT_SCHEMA_VERSION）。
    schema_version: str = REPORT_SCHEMA_VERSION
    #: 分析完整度：complete | partial | failed（据 analyzer_status 聚合，见 pipeline._analysis_health）。
    analysis_status: str = ANALYSIS_STATUS_COMPLETE
    #: 完整度比例 0..1 = 成功跑完 ÷ (成功 + 报错) 的分析器数（能力/平台跳过的不计入分母）。
    completeness: float = 1.0
    #: 报错的**关键**分析器名（失败即报告核心不可信；--strict 据此非零退出）。
    critical_failures: list[str] = field(default_factory=list)
    #: 因缺能力 / 平台不适用被跳过的分析器名（环境门控，非故障；仅信息性、不计入 completeness）。
    skipped_analyzers: list[str] = field(default_factory=list)
