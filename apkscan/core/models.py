"""apkscan 核心数据模型 — 以 Lead（调证线索）为中心。

所有分析器/富化器/报告共享这些类型。严格作为跨 agent 接口契约，禁止偏移。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


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


#: ``Endpoint.enrichment`` 里存放「本域名只作为非标端口的 SNI 出现过」这一事实的键，
#: 值形如 ``{"carriers": ["ip:port/proto", ...]}``——承载它的那些端点。
#:
#: ★为什么这条事实必须挂在 **Endpoint** 上，而不只是留在产它的那条 pcap Lead 里：域名端点
#:   并入主报告后会被 :func:`apkscan.core.leads._domain_lead` 重新产一条 Lead，那个生产者只
#:   看得到 Endpoint 自身。事实不在 Endpoint 上，它就只能按「这是个陌生域名」判
#:   ``ADVICE_INVESTIGATE``，而 letters 的文书正是据此套打的。判据的产地（dynamic）与消费地
#:   （core）分处两层，故常量定义在两边都依赖的 models，不让 core 反向依赖 dynamic。
SNI_MASQUERADE_KEY: str = "sni_masquerade"


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
    #: 值的**字面形态本身**不足以证明它属于本类别，研判是靠外部佐证撑起来的。
    #:
    #: 目前唯一来源：低段位裸 IP 的托管佐证豁免（见 ``infra.classify_ip``）——四段全 ≤32 且
    #: 样本里未当地址用的字面，多半是版本号/序号，但真实公网后端也确实凑得出这种形态，故靠
    #: ASN 归属把它捞回"建议调证"。
    #:
    #: ★必须是结构化字段而非 notes 里的一句话：这条保留意见的**唯一意义**是让下游出口能看见
    #:   它。写进 notes 时曾以为"办案人发函前看得到"，实际 letters 全文不渲染 notes，承诺在
    #:   出口断裂——发出去的是一封干净的、没有任何存疑提示的调证函。
    shape_uncertain: bool = False
    #: 这条连接在 TLS 握手里**借用的**域名（非标端口上的 SNI，见 ``pcap_ingest.sni_camouflage_carriers``）。
    #:
    #: 语义与 :attr:`shape_uncertain` 相反——它**不是**减分项：非标端口 + 知名域名 SNI = 自建协议
    #: 混入背景流量，反而使本 IP 更值得查。它要走到出口是为了另一件事：**钉死调证方向**。被冒用的
    #: 那家公司（网易云音乐、有道、jsDelivr…）与本案无关，向它发函就是把无关企业写成嫌疑方——
    #: 本项目最重的那类错误。
    #:
    #: ★同样必须是结构化字段：这条警示原本只写在 ``notes`` 里，而 letters 全文不渲染 notes
    #:   （与 :attr:`shape_uncertain` 一模一样的断裂，见该字段注释）。走过一次的坑不走第二次。
    sni_masquerade: list[str] = field(default_factory=list)
    #: 判据链算出的**初始档**，不含任何后续抑制。``None`` 表示来源未知（旧报告，见下）。
    #:
    #: ★与 :attr:`advice` 的关系：``advice`` 是 ``base_advice`` 与 :attr:`downgrades` 共同
    #:   算出的**物化缓存**，不是第三个独立真源。要改档位就增删 downgrade，别直接写 advice。
    #:
    #: ★为什么允许 ``None`` 而不是回落成 ``advice``：旧报告里的「待核」可能出自分析器初判、
    #:   来源档降级、重打包隔离、伪装 SNI……这些来源已不可逆地丢失。把它写成
    #:   ``base_advice=<当前档>, downgrades={}`` 虽然当前档位没变，字段名却在暗示「这就是
    #:   原始判据结论」——将来有人据此自动解除抑制，就会把本该压着的线索放出去。
    #:   ``None`` 如实表达「这条的来源不可考」：此时档位改由 :attr:`legacy_effective_advice`
    #:   这张迁移快照兜底；两者都没有，:func:`effective_advice` 返回空串、由调用方原样沿用 advice。
    base_advice: str | None = None
    #: 可独立撤销的**抑制来源**：``{来源 id: 该来源的说明}``。
    #:
    #: ★存在的理由：档位此前是被多个机制**依次改写**出来的结果，谁也不知道「是谁降的」。
    #:   于是任一机制想撤销自己那次降档时，既不知道该恢复到哪一档，也会把别人的降档一起
    #:   冲掉——实测发生过：伪装 SNI 解除时把重打包隔离冲没了，被仿冒厂商的域名重新进了
    #:   文书出口。记下来源之后，撤销只删自己那条，其余照旧压着。
    #:
    #: ★说明文字存在这里、**不**并进 :attr:`notes`：notes 里还有离线状态、解析历史、辖区
    #:   等等非抑制信息，把两者混在一起就没法在撤销时精确删掉自己那句（那正是上一次把别的
    #:   机制的说明一起冲掉的原因）。展示层自行把 notes 与本字段的说明合起来渲染。
    #:
    #: 什么才算 downgrade：与基础判据**正交**、可能被后续证据独立撤销、且撤销时必须保留其它
    #: 机制效果的，才是。仅仅因为「代码里执行得晚」不算——那种应当直接算进 base。
    downgrades: dict[str, str] = field(default_factory=dict)
    #: **迁移恢复点**：本机制第一次抑制这条旧线索时，它当时的实际档位快照。仅旧报告用得上。
    #:
    #: ★与 :attr:`base_advice` 的语义边界（**别混用**）：``base_advice`` 是判据链的结论，权威、
    #:   可据以重算；本字段只是「被本机制接管前它长什么样」的一张快照，里面可能已经含了历史上
    #:   其它机制压下去的效果，**推不出**判据链原本判了什么。故撤销时只恢复到这张快照，不再往上。
    #:   命名带 ``legacy_`` 前缀正是为此：看见它就该想到「这是迁移遗留，不是判据结论」。
    #:
    #: ★为什么非要它不可：没有它，旧报告的线索一旦被压过一次就**永远解不开**——新证据来了也撤不掉，
    #:   等于线索被永久埋掉。有了它，撤销的落点是「被碰之前的既成状态」，数学上不产生任何新的暴露面。
    #:
    #: ★write-once：第二次抑制**绝不覆写**它。否则第二次拍到的是已被自己压过的档，恢复点会一路
    #:   往下滑（棘轮），最后恢复到的比原始状态还低。撤空账本后也不删——留作审计痕迹，也是再次
    #:   抑制时的锚点。
    legacy_effective_advice: str | None = None

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


#: 抑制来源 id。**写进 report.json，是对外契约的一部分——发布后不要改名**。
#:
#: ★命名描述**证据/原因**，不描述当前政策：政策（降到哪一档、界面怎么呈现）将来可能变，
#:   而「这条线索是因为样本被判为重打包件才被压着的」这个事实不会变。故用 ``repack_identity``
#:   而不是 ``repack_quarantine``。
#:
#: ★粒度：一种可独立撤销的判据一个 id。具体的 tier 名、承载端点、verdict 等动态细节放进
#:   说明文本，**不要**编进 id——那会产生一堆清不掉的动态键。
DOWNGRADE_REPACK_IDENTITY: str = "repack_identity"
DOWNGRADE_SNI_MASQUERADE: str = "sni_masquerade"
DOWNGRADE_SOURCE_TIER: str = "source_tier"

#: 研判建议三态，**全仓真源**。:mod:`apkscan.core.infra` 从这里再导出同名常量，因此判据层与
#: 展示层沿用多年的 ``infra.ADVICE_*`` 写法一处都不用改。
#:
#: ★真源为什么落在模型层而不是判据层：这三个字面是 :attr:`Lead.advice` 的**取值域**，属于数据
#:   模型自己的词汇；判据层只是往这个字段里写值的众多生产者之一。方向反过来（模型引判据）还会
#:   把 1300 行判据连同 network 包一起拖进本模块——它是全仓最底层的纯 stdlib 叶子，得保持这样。
ADVICE_INVESTIGATE: str = "建议调证"  # leak-scan: allow 档位取值的字面定义本身
ADVICE_SKIP: str = "无需调证"  # leak-scan: allow 档位取值的字面定义本身
ADVICE_REVIEW: str = "待核"

#: :attr:`Lead.advice` 的合法取值域。两处用它：反序列化时校验磁盘上的档位字段，以及决定一个
#: advice 能不能拍进 :attr:`Lead.legacy_effective_advice`——空串（未研判）或写坏的乱码拍下来
#: 只会造出一个没人认识的恢复点，不如不拍、维持不可撤销。
VALID_ADVICE: frozenset[str] = frozenset({ADVICE_INVESTIGATE, ADVICE_SKIP, ADVICE_REVIEW})


def effective_advice(
    base_advice: str | None,
    downgrades: "Mapping[str, str] | None",
    legacy_effective_advice: str | None = None,
) -> str:
    """由初始档与抑制来源算出**实际档位**。纯函数、绝不抛。

    规则只有一条：有任何抑制来源时，最高档压到 :data:`ADVICE_REVIEW`（待核）。

    - 最低档（已知第三方基础设施那一类）不受抑制影响——那是判据本身的结论，不是「暂时
      压着」，压了也没有再压的意义；
    - 已经在待核档的保持不变；
    - 两个锚点都没有（旧报告且从未被本机制碰过）时**返回空串**，由调用方回落到报告里既有的
      advice——绝不凭空替它推断一个初始档。

    ★锚点优先级：``base_advice``（判据链结论，权威）> ``legacy_effective_advice``（迁移快照，
      只是「被碰之前长什么样」）。两者都在时以前者为准——后者此时只剩审计价值。

    ★最后那条 ``return anchor`` 是**唯一**让最低档不被抬升的地方，别把它简化成「有 downgrades
      就返回待核」：那会把 :data:`ADVICE_SKIP` 档的线索因为一次降档动作反而**抬**成待核，方向
      正好反了。
    """
    anchor = base_advice or legacy_effective_advice
    if not anchor:
        return ""
    if anchor == ADVICE_INVESTIGATE and downgrades:
        return ADVICE_REVIEW
    return anchor


def recompute_advice(lead: "Lead") -> None:
    """按两个锚点与 ``downgrades`` 重算并就地写回 :attr:`Lead.advice`。

    两个锚点都没有时**不动** advice：那是从未被本机制碰过的旧数据，凭空推不出档位。
    """
    fresh = effective_advice(lead.base_advice, lead.downgrades, lead.legacy_effective_advice)
    if fresh:
        lead.advice = fresh


def apply_downgrade(lead: "Lead", reason_id: str, note: str) -> bool:
    """记一条抑制来源并压档；返回是否新增（已有同 id 则只更新说明、返回 False）。

    ★命中就记，**哪怕当前档位已经是「待核」**：档位相同不代表来源相同。若因为「反正已经
      是待核了」而不记，将来另一条来源被撤销时，本条不在字典里，档位就会错误地弹回最高档
      ——这正是本机制要防的那件事。

    ★``base_advice`` 不可考（旧报告）时**照样压档**：「存在抑制来源」这个事实本身是明确的，
      压档是保守方向。绝不能只把来源记进字典却不动档位——那样字典看着像「抑制已生效」，
      线索却照旧走到文书出口，是最危险的那种静默失败。

    ★压档之前先拍一张 :attr:`Lead.legacy_effective_advice`（迁移恢复点），这样旧报告的抑制
      **仍然撤得掉**：撤销的落点是「被碰之前的既成状态」，不比原状态更松，也就不产生新的暴露面。
      没有这张快照，第二刀一旦对旧报告 apply 一次，这条线索就永远解不开了——新证据来了也撤不掉。

    ★三个不拍快照的情形，每个都对应一种「拍了反而更糟」：

      - ``downgrades`` 非空却没有 ``base_advice``：这是畸形态（磁盘数据被手改或被别的工具写坏，
        或跳过本函数直写了字典）。此时的 advice 已经不知道被谁动过，拍下来等于给一个来路不明
        的值发**恢复凭证**，撤光之后线索就凭这张凭证进了文书出口。宁可维持不可撤销。
      - 快照已存在：**write-once**，第二次绝不覆写（否则拍到的是自己压过的档，恢复点一路下滑）。
      - advice 不在 :data:`VALID_ADVICE` 里（空串/乱码）：拍下来只会造出一个没人认识的档位。

      落到这三种情形时，行为退回第一刀那套「保守压档 + 不可撤销」，是安全的兜底而非最终状态。
    """
    # ★顺序：快照必须赶在写字典**之前**。颠倒过来 ``not lead.downgrades`` 恒为假，快照永远
    #   立不起来，整个机制会静默退化回「永远解不开」——而且档位表现完全正常，看不出来。
    if (
        lead.base_advice is None
        and not lead.downgrades
        and lead.legacy_effective_advice is None
        and lead.advice in VALID_ADVICE
    ):
        lead.legacy_effective_advice = lead.advice

    added = reason_id not in lead.downgrades
    lead.downgrades[reason_id] = note
    if lead.base_advice is None and lead.legacy_effective_advice is None:
        if lead.advice == ADVICE_INVESTIGATE:
            lead.advice = ADVICE_REVIEW
    else:
        recompute_advice(lead)
    return added


def lift_downgrade(lead: "Lead", reason_id: str) -> bool:
    """撤掉一条抑制来源并重算档位；返回是否真的撤掉了。

    只删自己那条。其余来源仍在时，档位照旧压着——这是与「整体重算 Lead」最关键的区别。

    ★返回 ``True`` 只表示「这条来源已经移除」，**不等于档位回升了**：快照本身就是待核时，撤光
      全部来源后档位仍是待核。判断档位请读 :attr:`Lead.advice`，别拿本函数的返回值当档位信号。

    ★两个锚点都没有时**拒绝撤销**（返回 ``False``、字典不动）：算不出该恢复到哪一档，硬撤只能
      靠猜，而猜错的方向是把本该压着的线索放进文书出口。宁可留着不撤。

    ★撤空账本后**不删快照**：它既是审计痕迹（这条曾被本机制接管过），也是将来再次抑制时的锚点。
    """
    if reason_id not in lead.downgrades:
        return False
    if lead.base_advice is None and lead.legacy_effective_advice is None:
        return False
    del lead.downgrades[reason_id]
    recompute_advice(lead)
    return True


def seal_base_advice(leads: "list[Lead]") -> int:
    """把本次运行**判据链刚算出**的 advice 封存为 :attr:`Lead.base_advice`；返回封了几条。

    调用点在管线的**接缝**上：所有判据链生产者都跑完、任何抑制机制动手之前。那一刻 ``advice``
    恰好就是「判据链的结论」，封下来即可，不必逐个改二三十处 ``Lead(advice=...)`` 构造。

    ★三条守卫缺一不可，任一不满足就跳过——它们共同保证「只封判据链结论，绝不把别的东西
      冒充成判据结论」：

      - ``base_advice`` 已有：别人已经显式填过（那些在接缝之前就要抑制的生产者），不覆盖；
      - ``downgrades`` 非空：这条已被抑制过，此刻的 advice 是**压过之后**的档，封了就把抑制
        效果烙进 base，撤销时再也回不去（棘轮）；
      - ``legacy_effective_advice`` 非空：这是旧报告，它的 advice 来源不可考，更不是判据结论。

      外加 ``advice`` 必须是合法档位——空串（未研判）或乱码封进 base 只会造出假档位。

    ★为什么不用 ``__post_init__`` 自动封：:func:`report_io.report_from_dict` 读旧报告时走的是
      同一个构造器，自动封会把旧报告的 advice 冒充成判据链结论——那正是 ``base_advice`` 允许
      为 ``None`` 要表达的东西（见该字段注释），一封就全毁了。
    """
    sealed = 0
    for lead in leads:
        if lead.base_advice is not None or lead.downgrades or lead.legacy_effective_advice is not None:
            continue
        if lead.advice not in VALID_ADVICE:
            continue
        lead.base_advice = lead.advice
        sealed += 1
    return sealed


def advice_is_consistent(lead: "Lead") -> bool:
    """``advice`` 是否与两个锚点 + ``downgrades`` 自洽。

    ``advice`` 是物化缓存，绕过 :func:`apply_downgrade` / :func:`lift_downgrade` 直写它就会
    与锚点失配，本函数把这种失配算出来。

    ★能查到什么、查不到什么——别把它当成「绕过就一定被逮住」的保证：

      - **有锚点**（``base_advice`` 或迁移快照至少一个在）时，直写 advice 会被查出来；
      - **两个锚点都没有**时恒判一致。那种 Lead 压根没有可比对的期望值，不是「查过了没问题」，
        是「无从查起」。
      - 而且它目前只是个**可供调用的判断**：还没有任何生产路径在写盘前拿它 fail-fast。要让
        「绕过写入必被拦下」成立，得等第二刀把它接到持久化边界上，那之前它只在测试里当断言用。
    """
    expected = effective_advice(lead.base_advice, lead.downgrades, lead.legacy_effective_advice)
    return not expected or expected == lead.advice


def merge_runtime_into_lead_dict(existing: dict, runtime_lead: dict) -> tuple[bool, bool]:
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

    ★抑制账本（``downgrades``）的合并**完全复用** :func:`apply_downgrade` 的语义：把 existing
      的档位状态装进一个临时 Lead、逐条灌 runtime 侧的账本、把结果写回 dict——旧报告的
      write-once 快照、压档方向、同 id 幂等全部由同一个 helper 保证，不在 dict 层另立规则。
      没有这段，运行时侧压出的账本在命中同键静态 lead 时会被整体丢弃、advice 也不重算：
      被冒用域名在合并后的报告里保持最高档，而 closure 目标选择与 HTML 的 C2 区块都按
      advice 走——letters 之外的出口全部失守。

    ★``base_advice`` 不从 runtime 侧采纳：runtime 侧的 base 是它那条判据链对同一个值的结论，
      existing 侧要么已有自己的结论、要么来源不可考（旧报告）——不可考时由 apply_downgrade
      拍迁移快照兜底，可撤销性不丢。跨侧的「等值才采纳」优化留给恢复凭据那一刀。

    Args:
        existing: report.json 里已存在的 lead dict（**原地**被改）。
        runtime_lead: 新 runtime lead 的序列化 dict。

    Returns:
        ``(evidence_merged, ledger_changed)`` 二元组，**两个语义不能合并成一个 bool**：
        前者=真并入了新的 runtime 证据（调用方据此计「活体确认」并升 runtime 位），
        后者=抑制账本/档位发生了变化（值得落盘，但**不是**确认——账本不是证据）。
        合成一个的话，仅账本变化的合并会被计进「runtime 确认 N 条」的日志与统计，语义失真。
    """
    incoming = runtime_lead.get("source_refs")
    if not isinstance(incoming, list):
        # 证据缺失/坏形状：没证据可搬，但**不能**在此直接返回——下面的伪装名并集与抑制账本
        # 合并对这样的输入同样必须生效（早退会把账本一起跳过，那正是本函数要防的丢失）。
        incoming = []
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
    # ★sni_masquerade 取并集，且**独立于 merged**：新观测到的伪装名即便没带来新证据
    #   （证据签名撞了）也必须并进去。它不是加分项、是「这封函不该发给谁」的硬警示，
    #   丢了就等于把无关企业写成受文机关——本字段存在的全部意义就是防这个。
    #   只搬运行时来源的 lead 的该字段（上面已按 runtime* 过滤证据，这里同一条 lead 语境）。
    incoming_masq = [
        str(name).strip()
        for name in (runtime_lead.get("sni_masquerade") or [])
        if isinstance(name, str) and str(name).strip()
    ]
    if incoming_masq:
        current = existing.get("sni_masquerade")
        current = [n for n in current if isinstance(n, str)] if isinstance(current, list) else []
        union = sorted(set(current) | set(incoming_masq))
        if union != current:
            existing["sni_masquerade"] = union

    # ★抑制账本合并（见 docstring）。``ledger_changed`` 独立于 ``merged``：账本不是 runtime
    #   证据，不能触发下面的 is_runtime_seen 升位——那两个布尔的语义是「动态侧真的出现过」。
    ledger_changed = False
    raw_incoming_dg = runtime_lead.get("downgrades")
    incoming_dg = {
        str(k).strip(): str(v)
        for k, v in raw_incoming_dg.items()
        if isinstance(k, str) and k.strip() and isinstance(v, str)
    } if isinstance(raw_incoming_dg, dict) else {}
    if incoming_dg:
        def _anchor(value: object) -> str | None:
            # 与 report_io 读盘同判据：只认合法档位，其余当「不可考」。
            return value.strip() if isinstance(value, str) and value.strip() in VALID_ADVICE else None

        raw_current_dg = existing.get("downgrades")
        current_dg = {
            str(k).strip(): str(v)
            for k, v in raw_current_dg.items()
            if isinstance(k, str) and k.strip() and isinstance(v, str)
        } if isinstance(raw_current_dg, dict) else {}
        current_advice = existing.get("advice")
        current_legacy = _anchor(existing.get("legacy_effective_advice"))
        shim = Lead(
            # category/value 仅为构造合法对象；apply_downgrade 不读它们。
            category=LeadCategory.DOMAIN,
            value=str(existing.get("value", "")),
            advice=current_advice if isinstance(current_advice, str) else "",
            base_advice=_anchor(existing.get("base_advice")),
            downgrades=dict(current_dg),
            legacy_effective_advice=current_legacy,
        )
        for reason_id, note in incoming_dg.items():
            apply_downgrade(shim, reason_id, note)
        if (
            shim.advice != (current_advice if isinstance(current_advice, str) else "")
            or shim.downgrades != current_dg
            or shim.legacy_effective_advice != current_legacy
        ):
            existing["advice"] = shim.advice
            existing["downgrades"] = shim.downgrades
            if shim.legacy_effective_advice is not None:
                # 旧报告被首次抑制时 helper 拍下的迁移快照——必须落回 dict，否则往返即丢、
                # 这条抑制退回「永远解不开」。base_advice 不写：shim 里的就是 existing 自己的。
                existing["legacy_effective_advice"] = shim.legacy_effective_advice
            ledger_changed = True

    if merged:
        # 有 runtime 证据 → 升为「运行时出现」（宽口径，与 Lead.is_runtime_seen 一致）。
        existing["is_runtime_seen"] = True
        # 若并入 / 已有任一 observed-contact 源（runtime / runtime-pcap），据全量 source_refs 重算并
        # 单调升 is_runtime_contact——与 Lead.is_runtime_contact 属性同口径，防 dict 上字段陈旧失真。
        if any(
            isinstance(r, dict) and str(r.get("source")) in OBSERVED_CONTACT_SOURCES for r in refs
        ):
            existing["is_runtime_contact"] = True
    return merged, ledger_changed


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
#:
#: 1.1 —— Lead 增加 ``base_advice`` / ``downgrades`` / ``legacy_effective_advice``（档位的可撤销
#:        来源，外加旧报告的迁移恢复点）。**向后兼容的扩展**：旧报告缺这三个字段照常读，``advice``
#:        原样沿用、行为逐字不变；新增字段只是让「档位是被谁压着的」变得可查、可单独撤销。
#:        故 bump 次版本号而非主版本号。
#:
#:        ★三个字段同属 1.1、不再往上 bump：1.1 至今**没有出过门**（截至 v1.4.0 的全部发布 tag
#:        写出的都是 ``"1.0"``），所以它还不是任何在野报告依赖的契约，仍可自由增补。将来若 1.1
#:        已随某个版本发布，再加字段就得开 1.2。
REPORT_SCHEMA_VERSION = "1.1"

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
