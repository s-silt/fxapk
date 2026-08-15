"""apkscan.report.letters — 把 report.json 的 leads 套打成「调证函 / 协查文书」草稿。

fxapk 的 Lead 已结构化 subject/where_to_request/evidence_to_obtain/value/source_refs，
离「一步生成可发的协查函草稿」只差一个模板引擎。本模块把可办案化的线索变成结构化文书
草稿（markdown 正文 + 字段 dict），让办案动作（向交易所发函冻结收款地址、向注册商调
WHOIS 实名、向云厂商调租户日志）有现成底稿。

铁律（与 report/ioc.py 一致）：纯函数层**禁** print/typer，对坏输入容错返回空/跳过，
**绝不抛**。唯一打印的地方是 cli 的 letters 命令。

严格过滤（核验明确要求，否则生成荒谬空壳函）——只对满足**全部**条件的 Lead 套打：
  1) advice == "建议调证"（只对建议调证的）；
  2) evidence_to_obtain 非空（没有可调取证据的不发函）；
  3) where_to_request 是**真实受文机关**——跳过含「非调证对象 / 无直接调证对象 /
     解密配方 / 跨样本关联」等标记的 Lead。背景：certificate 的 SIGNING Lead
     （where_to_request="证书指纹用于跨样本关联…无直接调证对象"）和 crypto_recipe 的 Lead
     （"（解密配方，非调证对象）…"）套进受文机关会生成空壳函，必须排除。
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from apkscan.core import infra
from apkscan.core.evidence_scope import project_serialized_leads
from apkscan.core.registry import load_rules
from apkscan.core.restore import restore_index, restored_sources_for

logger = logging.getLogger(__name__)

# 研判建议中代表「应套打调证函」的取值（过滤条件 1）。
_ADVICE_INVESTIGATE = "建议调证"

# where_to_request 命中任一标记即判定为「非真实受文机关」→ 跳过（过滤条件 3）。
# 这些是分析器对「无直接调证对象」类 Lead 的占位文案，套进受文机关会产生空壳函。
_NON_RECIPIENT_MARKERS: tuple[str, ...] = (
    "非调证对象",
    "无直接调证对象",
    "解密配方",
    "跨样本关联",
)

# 模板 YAML 名（apkscan/rules/letter_templates.yaml）。
_TEMPLATES_NAME = "letter_templates"

# 缺模板时的通用兜底键。
_DEFAULT_TEMPLATE_KEY = "_default"

# 文书顶部固定免责声明（法律措辞克制，不替办案单位下定性结论）。
DISCLAIMER: str = (
    "**本文书为线索建议草稿，需办案单位审核、依法定程序签发；"
    "受文机关为据线索推导的候选、非武断认定。**"
)

# 标的形态存疑时的额外警示（紧跟免责声明，在受文机关之前——发函的人必须先看到它）。
#
# ★这条警示的存在本身就是一次教训：产生它的那条判据原本只把保留意见写进 Lead.notes，并在
#   提交说明里声称"办案人发函前看得到"。而本模块全文不读 notes——发出去的是一封干净的、
#   指名某云厂商的调证函。保留意见必须自己走到出口，不能假定下游会去翻。
# ★出口中性的字句表示（唯一事实源）：每段标 ``em``（需强调）或 ``""``（普通）。
#
#   为什么不是一个 markdown 字符串：这套警示**有两个出口**——本模块（markdown）与 HTML 报告。
#   若各出口各存一份字面，改了一处忘另一处就是必然（本项目已在 notes→出口 上栽过两次，见
#   Lead.shape_uncertain / Lead.sni_masquerade 的注释）。字句只此一份，格式由各出口自己套。
EmphasisSpans = tuple[tuple[str, str], ...]

SHAPE_UNCERTAIN_WARNING_SPANS: EmphasisSpans = (
    ("em", "⚠ 标的形态存疑："),
    (
        "",
        " 该值四段数字均偏低、且在样本中未见以地址形式使用（无端口、"
        "不在 URL 内），形态上与版本号/序号无法区分；判定为地址是靠 ASN 归属落在云/IDC 托管段"
        "推得，非样本内的地址性证据。",
    ),
    ("em", "发函前请人工确认该值确系网络地址"),
    ("", "——若实为版本串，本函标的不存在，会向无关的云厂商索取一个并不存在的租户。"),
)


def spans_to_markdown(spans: EmphasisSpans) -> str:
    """强调段套 ``**``（markdown 出口）。"""
    return "".join(f"**{text}**" if kind == "em" else text for kind, text in spans)


def spans_to_plain(spans: EmphasisSpans) -> str:
    """丢掉强调、只留字句（供不吃 markdown 的出口做纯文本比对/降级展示）。"""
    return "".join(text for _, text in spans)


SHAPE_UNCERTAIN_WARNING: str = spans_to_markdown(SHAPE_UNCERTAIN_WARNING_SPANS)

# 人工放行警示（见 apkscan.core.restore）。与形态存疑并列渲染在受文机关之前。
#
# ★这是墓碑机制里最危险的那个消费面：这条线索本已被自动判据压住、不该套打，是**人**把它放
#   回来的。文书出口若不写这一句，产出的就是一份外观完全正常的函——读的人无从知道「机器本来
#   拦下了它、是有人放行的」，也就不会去追放行依据。墓碑不做真伪校验，可见性是唯一的保证，
#   而这里正是可见性最该落地的地方。
MANUAL_RESTORE_WARNING_SPANS: EmphasisSpans = (
    ("em", "⚠ 本条系人工放行："),
    (
        "",
        " 自动判据原本已将其降档、排除在本出口之外，是经人工核实后放回的（放行依据见报告的"
        " manual_restores 记录）。",
    ),
    ("em", "发函前请复核放行依据是否成立"),
    ("", "——放行记录不构成对该依据的核验，工具只如实记下有人放行过这件事。"),
)

MANUAL_RESTORE_WARNING: str = spans_to_markdown(MANUAL_RESTORE_WARNING_SPANS)


def manual_restore_warning(sources: list[str]) -> str:
    """有放行来源则给出警示字句，否则空串。"""
    return MANUAL_RESTORE_WARNING if sources else ""

# SNI 伪装警示（见 Lead.sni_masquerade）。与形态存疑并列渲染在受文机关之前。
#
# ★注意它**不质疑本函该不该发**——恰恰相反，伪装是加重信号。它防的是另一件事：读函的人看到
#   证据摘要里的 SNI 是个知名域名，顺手把函发给被冒用的那家公司。那是把无关企业写成嫌疑方。
def sni_masquerade_warning_spans(
    names: list[str], escape: Callable[[str], str] | None = None
) -> EmphasisSpans:
    """按借用的域名渲染伪装警示的**出口中性**字句段；空列表 → 空元组。

    ``escape`` 决定域名（来自样本流量的外部数据）如何中性化，由出口注入：markdown 出口传
    :func:`_md_safe`；HTML 出口传 ``None``——Jinja2 autoescape 会在渲染时转义，这里若再escape
    一次会双重转义（``&amp;lt;`` 那种）。**两个出口都必须转义，只是转义发生在不同层。**
    """
    safe = [(escape or (lambda s: s))(str(n)) for n in names if str(n).strip()]
    if not safe:
        return ()
    return (
        ("em", f"⚠ 该连接以 {'、'.join(safe)} 的名义握手："),
        ("", " 这些域名仅作为 SNI 出现在"),
        ("em", "非标准 TLS 端口"),
        ("", "上，系伪装、不代表本地址的运营方——被冒用域名的持有方与本案无关，"),
        ("em", "切勿向其发函"),
        ("", "。本函标的即上述 IP 与端口。伪装本身是自建协议混入背景流量的加重信号，非减分项。"),
    )


def sni_masquerade_warning(names: list[str]) -> str:
    """按借用的域名渲染伪装警示（markdown 出口）；名字来自样本流量，须 _md_safe 转义。空列表 → 空串。"""
    return spans_to_markdown(sni_masquerade_warning_spans(names, escape=_md_safe))

# 文件名安全化：去掉文件系统非法字符 + 控制字符。
_UNSAFE_FILENAME_CHARS = re.compile(r'[\\/:*?"<>|\x00-\x1f]+')

# markdown 中性化：折叠空白（含换行，堵住跳出单行结构造伪标题/伪字段的口子）+ 转义结构/行内语法字符。
_MD_WHITESPACE_RUN = re.compile(r"\s+")
_MD_SPECIAL_CHARS = re.compile(r"([\\`*_{}\[\]()#+\-.!|>&<])")


def _str_or_empty(value: Any) -> str:
    """把字段值转成字符串；None / 缺失 → 空串。"""
    if value is None:
        return ""
    return str(value)


def _md_collapse(value: str) -> str:
    """折叠所有空白（含换行）为单空格——堵住值里塞换行伪造新列表项/标题行的结构注入。
    用于本身是静态文案、无需字符级转义、但仍须防结构注入的字段（evidence_to_obtain）。"""
    return _MD_WHITESPACE_RUN.sub(" ", str(value)).strip()


def _code_safe(value: str) -> str:
    """把值安全嵌入单反引号 code span：折叠空白 + 中和反引号（防 code span 逃逸破坏 md）。

    用于 evidence_refs——其降级形态 ``source:location`` 的 location 是**样本派生路径**、攻击者可控，
    含反引号的路径会逃出 ``` `...` ``` 破坏生成的调证函草稿（codex C2）。反引号替为视觉近似的
    U+02CB(ˋ)，既杜绝逃逸又保留可读的锚点形态。
    """
    return _md_collapse(value).replace("`", "ˋ")


def _md_safe(value: str) -> str:
    """把可能来自不可信样本内容的字段值转成安全内嵌 markdown 文本。

    只对**攻击者可控字段**（Lead.value / Lead.subject，抽取自样本）调用——分析器自身固定
    文案（模板标题、evidence_to_obtain 等）不含样本内容，无需转义。
    折叠所有空白（含换行）为单空格，堵住"值里塞换行伪造新标题/字段行"的口子；再转义
    markdown 结构/行内语法字符，防止值被渲染成标题/加粗/链接/代码块而非纯文本。
    """
    collapsed = _MD_WHITESPACE_RUN.sub(" ", value).strip()
    return _MD_SPECIAL_CHARS.sub(r"\\\1", collapsed)


def _str_list(value: Any) -> list[str]:
    """把字段规整为非空 str 列表（容忍 None / 非 list / 含非 str / 空白元素）。"""
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
        elif item is not None and not isinstance(item, str):
            # 非 str（如数字）也尽力字符串化，避免丢证据项。
            text = str(item).strip()
            if text:
                out.append(text)
    return out


def _is_non_recipient(where_to_request: str) -> bool:
    """where_to_request 是否为「非真实受文机关」占位文案（命中任一标记即 True）。"""
    return any(marker in where_to_request for marker in _NON_RECIPIENT_MARKERS)


def _is_masqueraded_domain(lead: dict[str, Any]) -> bool:
    """本条 Lead 的标的自身是否为**被冒用**的域名（自己出现在自己的 sni_masquerade 里）。

    ★出口硬闸，与上游各级判据相互独立。上游任何一环判错，套打出来的就是一份指向被冒用服务
      持有方的文书——这是本项目最重的那类误判，必须在出口再挡一次，而不是信任链路上游。
      实测（1.4.0）上游三处同时失守，文书已真的生成，故补此闸。
    """
    if str(lead.get("category") or "").upper() != "DOMAIN":
        return False
    names = lead.get("sni_masquerade")
    if not isinstance(names, list):
        return False
    value = str(lead.get("value") or "").strip().lower().rstrip(".")
    if not value:
        return False
    return any(str(n).strip().lower().rstrip(".") == value for n in names)


def _is_actionable(lead: dict[str, Any]) -> bool:
    """该 Lead 是否可套打（满足全部 4 个条件）。"""
    if lead.get("advice") != _ADVICE_INVESTIGATE:
        return False  # 条件 1：只对建议调证的
    if not _str_list(lead.get("evidence_to_obtain")):
        return False  # 条件 2：必须有可调取证据
    recipient = _str_or_empty(lead.get("where_to_request")).strip()
    if not recipient:
        return False  # 无受文机关
    if _is_non_recipient(recipient):
        return False  # 条件 3：跳过非真实受文机关占位文案
    if _is_masqueraded_domain(lead):
        return False  # 条件 4：标的自身是被冒用的域名——绝不向其持有方发函
    return True


def _evidence_refs(lead: dict[str, Any]) -> list[str]:
    """从 source_refs 取每条 Evidence 的 evidence_id；无则降级为 source:location。

    report.json 的 Evidence 已带 evidence_id（report/json.py 注入）。坏形状容错跳过。
    """
    refs = lead.get("source_refs")
    if not isinstance(refs, list):
        return []
    out: list[str] = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        eid = ref.get("evidence_id")
        if isinstance(eid, str) and eid.strip():
            out.append(eid.strip())
            continue
        # 降级：source:location（与 ioc._first_source 同构）。
        source = _str_or_empty(ref.get("source"))
        location = _str_or_empty(ref.get("location"))
        if source or location:
            out.append(f"{source}:{location}")
    return out


def _load_templates() -> dict[str, dict[str, str]]:
    """读取 letter_templates.yaml，规整为 {category: {field: text}}；坏形状返回空 dict。"""
    data = load_rules(_TEMPLATES_NAME)
    if not isinstance(data, dict):
        logger.warning("letter_templates 顶层应为 dict，实际 %s；走通用兜底", type(data).__name__)
        return {}
    out: dict[str, dict[str, str]] = {}
    for key, value in data.items():
        if not isinstance(key, str) or not isinstance(value, dict):
            continue
        tmpl: dict[str, str] = {}
        for fk, fv in value.items():
            if isinstance(fk, str) and isinstance(fv, str):
                tmpl[fk] = fv
        out[key] = tmpl
    return out


def _template_for(category: str, templates: dict[str, dict[str, str]]) -> dict[str, str]:
    """取 category 模板；缺则走 _default 兜底；再缺则硬编码通用兜底，绝不崩。"""
    tmpl = templates.get(category) or templates.get(_DEFAULT_TEMPLATE_KEY)
    if tmpl:
        return tmpl
    return {
        "title": "协查函",
        "recipient_hint": "受文机关为据线索推导的候选机构",
        "target_desc": "涉案样本中提取的调证标的",
        "evidence_lead_in": "建议依法调取以下材料：",
    }


# 五层归因置信度 / edge 档位 → 中文。
_CONF_CN = {"high": "高", "medium": "中", "low": "低", "unknown": "未知"}
_EDGE_TIER_CN = {"confirmed": "确认", "probable": "较可能", "possible": "可能", "clustered": "聚类"}
# 调证函里每个标的最多展示的落地 IP 数（防 CDN 多 IP 把文书撑爆；完整见 report.json）。
_MAX_ATTR_IPS = 5


def _conf_cn(layer: dict[str, Any]) -> str:
    return _CONF_CN.get(str(layer.get("confidence") or "unknown"), "未知")


def _sub_dict(d: dict[str, Any], key: str) -> dict[str, Any]:
    """取子 dict（非 dict → 空 dict）。集中做类型收窄，供渲染层安全 .get，绝不抛。"""
    v = d.get(key)
    return v if isinstance(v, dict) else {}


def _attribution_index(report: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    """从 ``report['endpoints']`` 建 ``{(kind, 归一化 value): attribution}``（仅含真有五层归因的端点）。

    ★键必须走 :func:`infra.match_key`（IP 剥 ``:port/proto``）：Lead 值形如
      ``198.51.100.7:31861/tcp``，Endpoint 是裸 IP。此前按原值精确匹配，于是**恰恰是 pcap 实测
      到的真后端**——最该在调证函里写清归属的那个——永远关联不上五层归属链，正文只剩空壳。
      kind 一并入键，防域名与 IP 字面撞车。坏形状容错、绝不抛。

    ``kind`` 缺失/非串的端点（手工编辑过的 report.json、旧产物）**不丢**：改挂在通配 kind ``""``
    下、值只小写不剥端口（不知 kind 就无从判断该不该剥）。查找先精确后通配——归因是"这个标的
    归谁"的关键信息，宁可靠通配捞回来，也不能因为少个字段就静默消失。
    """
    index: dict[tuple[str, str], dict[str, Any]] = {}
    if not isinstance(report, dict):
        return index
    endpoints = report.get("endpoints")
    if not isinstance(endpoints, list):
        return index
    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        value = ep.get("value")
        kind = ep.get("kind")
        enr = ep.get("enrichment")
        if not (isinstance(value, str) and isinstance(enr, dict)):
            continue
        att = enr.get("attribution")
        if not (isinstance(att, dict) and isinstance(att.get("ips"), list) and att["ips"]):
            continue
        if isinstance(kind, str) and kind.strip():
            index[(kind.strip().lower(), infra.match_key(kind, value))] = att
        else:
            index[("", value.strip().lower())] = att
    return index


#: 五层归属链里「实际运营者」那一层的固定值。★恒为未知：五层模型里它**绝不**从基础设施
#: 归属推断，任何出口都必须原样展示这句免责，否则读者会把某层基础设施持有方当成 App 运营者。
SERVICE_OPERATOR_ROW: tuple[str, str] = (
    "实际运营者",
    "未知（★不从基础设施归属推断，须另行落查）",
)


def ip_chain_view(
    layer: dict[str, Any], escape: Callable[[str], str] | None = None
) -> tuple[str, tuple[tuple[str, str], ...]] | None:
    """把单个落地 IP 的五层拆成**出口中性**的 ``(ip, ((标签, 值), ...))``；坏输入 → ``None``。

    这是五层归属链字句的唯一事实源，本模块与 HTML 报告共用（此前只有本模块有，报告出口 0 命中）。
    未知层一律显式标注（"未知" / "未识别专属特征" / "待结案 RDAP 补全"）——留空会被读成"没这一层"。

    ``escape`` 由出口注入，用来中性化 RDAP/ASN org 名等**外部数据**：markdown 出口传
    :func:`_md_safe`；HTML 出口传 ``None``（Jinja2 autoescape 在渲染时转义，此处再转会双重转义）。
    标签与"未知"等字面是本模块自己的常量，不经 escape。
    """
    if not isinstance(layer, dict):
        return None
    esc = escape or (lambda s: s)
    rows: list[tuple[str, str]] = []

    rh = _sub_dict(layer, "resource_holder")
    rh_name = _str_or_empty(rh.get("name")).strip()
    if rh_name:
        src = esc(_str_or_empty(rh.get("source")) or "RDAP")
        rows.append(("资源登记方", f"{esc(rh_name)}（{src}，置信{_conf_cn(rh)}）"))
    elif rh.get("deferred") == "case_close":
        # ★analyze 阶段域名解析 IP 未查 IP-RDAP（结案逐个补）。显式标注"待补"而非笼统「未知」，
        #   免得读者把「未查询」与结案后真正的「查无登记方」（走下面 else 的未知）混同。
        rows.append(("资源登记方", "待结案 RDAP 补全（analyze 阶段未逐 IP 查询）"))
    else:
        rows.append(("资源登记方", "未知"))

    on = _sub_dict(layer, "origin_network")
    asn = on.get("asn")
    if isinstance(asn, int):
        org = _str_or_empty(on.get("organization")).strip()
        cat = _str_or_empty(on.get("category")).strip()
        org_part = f" {esc(org)}" if org else ""
        cat_part = f"，{esc(cat)}" if cat and cat != "unknown" else ""
        rows.append(("网络运营方(BGP ASN)", f"AS{asn}{org_part}{cat_part}（置信{_conf_cn(on)}）"))
    else:
        rows.append(("网络运营方(BGP ASN)", "未知"))

    hp = _sub_dict(layer, "hosting_provider")
    hp_name = _str_or_empty(hp.get("name")).strip()
    if hp_name:
        role = esc(_str_or_empty(hp.get("role")))
        rows.append(("托管商/IDC", f"{esc(hp_name)}（{role}，置信{_conf_cn(hp)}）"))
    else:
        rows.append(("托管商/IDC", "未知"))

    edge = _sub_dict(layer, "edge_provider")
    edge_name = _str_or_empty(edge.get("name")).strip()
    if edge_name:
        tier = _EDGE_TIER_CN.get(str(edge.get("tier") or ""), "")
        role = esc(_str_or_empty(edge.get("role")))
        tail = f"，{tier}" if tier else ""
        rows.append(("边缘/CDN/代理", f"{esc(edge_name)}（{role}{tail}）"))
    else:
        rows.append(("边缘/CDN/代理", "未识别专属特征"))

    rows.append(SERVICE_OPERATOR_ROW)
    return esc(_str_or_empty(layer.get("ip")).strip()), tuple(rows)


#: 归属链小标题字句（出口中性）。两个出口都必须带「勿据此认定 App 运营者」这半句。
ATTRIBUTION_CHAIN_HEADING: str = "基础设施归属链（待核，按落地 IP 分层，勿据此认定 App 运营者）："


def attribution_chain_view(
    attribution: dict[str, Any], escape: Callable[[str], str] | None = None
) -> tuple[list[tuple[str, tuple[tuple[str, str], ...]]], int]:
    """把端点五层归因拆成 ``([每个落地 IP 的 ip_chain_view, ...], 未展示的 IP 数)``。

    出口中性、且**限长在此统一施加**（:data:`_MAX_ATTR_IPS`）：CDN 动辄几十个解析 IP，
    本模块与 HTML 报告都会被撑爆。放在这里而不是各出口自己截，是为了两个出口的"另有 N 个"
    口径一致——否则一处截 5 一处不截，同一份归因在两个产物里数量不同。

    空/坏输入 → ``([], 0)``，绝不抛（本模块铁律）。
    """
    if not isinstance(attribution, dict):
        return [], 0
    ips = attribution.get("ips")
    if not isinstance(ips, list) or not ips:
        return [], 0
    # 只计有非空 IP 的落地记录（空 dict 等坏元素不占限长额度、不渲染垃圾）。
    valid = [x for x in ips if isinstance(x, dict) and _str_or_empty(x.get("ip")).strip()]
    if not valid:
        return [], 0
    views = []
    for layer in valid[:_MAX_ATTR_IPS]:
        view = ip_chain_view(layer, escape=escape)
        if view is not None:
            views.append(view)
    return views, len(valid) - min(len(valid), _MAX_ATTR_IPS)


def _render_attribution_chain(attribution: dict[str, Any]) -> list[str]:
    """把端点五层归因渲染成本模块「基础设施归属链」段的 markdown 行；空/坏输入 → 空 list，绝不抛。"""
    views, remaining = attribution_chain_view(attribution, escape=_md_safe)
    if not views:
        return []
    lines = [f"**{ATTRIBUTION_CHAIN_HEADING}**", ""]
    for ip, rows in views:
        lines.append(f"- 落地 IP `{ip}`：" if ip else "- 落地 IP（未知）：")
        lines.extend(f"  - {label}：{value}" for label, value in rows)
    if remaining > 0:
        lines.append(f"- （另有 {remaining} 个解析 IP 未列，完整见 report.json 的 enrichment.attribution）")
    lines.append("")
    return lines


def _build_body_md(
    *,
    template: dict[str, str],
    recipient: str,
    target: str,
    subject: str,
    evidence_items: list[str],
    evidence_refs: list[str],
    attribution_lines: list[str] | None = None,
    shape_uncertain: bool = False,
    masquerade_warning: str = "",
    manual_restore_warning: str = "",
) -> str:
    """套打 markdown 正文：顶部固定免责声明 → 受文机关 → 标的 → 待调取证据 → 出处。"""
    title = template.get("title", "协查函")
    recipient_hint = template.get("recipient_hint", "")
    target_desc = template.get("target_desc", "")
    evidence_lead_in = template.get("evidence_lead_in", "建议依法调取以下材料：")

    lines: list[str] = []
    # 1) 顶部显著免责（固定，最先出现）
    lines.append(f"> {DISCLAIMER}")
    lines.append("")
    # 1.4) 人工放行警示——与形态存疑同级、同样排在标题之前。★这是最危险的那个消费面：
    #      这条线索本已被自动判据压住、不该套打，是**人**把它放回来的。不写在正文里，
    #      一份外观完全正常的文书就掩盖了「放行依据是谁给的、核没核实过」这件事。
    if manual_restore_warning:
        lines.append(f"> {manual_restore_warning}")
        lines.append("")
    # 1.5) 标的形态存疑警示——必须在标题与受文机关之前：这封函要不要发，取决于它。
    if shape_uncertain:
        lines.append(f"> {SHAPE_UNCERTAIN_WARNING}")
        lines.append("")
    # 1.6) SNI 伪装警示——同样在受文机关之前：它决定这封函**不该发给谁**。
    if masquerade_warning:
        lines.append(f"> {masquerade_warning}")
        lines.append("")
    # 2) 标题
    lines.append(f"# {title}（标的：{target}）")
    lines.append("")
    # 3) 受文机关
    lines.append(f"**受文机关（候选）：** {recipient}")
    if recipient_hint:
        lines.append("")
        lines.append(recipient_hint)
    lines.append("")
    # 4) 标的归属（ICP/RDAP 域名注册方 = 公司/人）
    if subject:
        lines.append(f"**标的归属（待核）：** {subject}")
        lines.append("")
    # 4.5) 基础设施归属链（五层不塌缩：资源登记方→ASN→托管→边缘→运营者）——与"标的归属"互补，
    #      前者是域名注册方，后者是"IP 落在谁的网段/经谁家 CDN"。已在渲染层各自 _md_safe 转义。
    if attribution_lines:
        lines.extend(attribution_lines)
    lines.append(f"**调证标的：** {target}")
    if target_desc:
        lines.append("")
        lines.append(target_desc)
    lines.append("")
    # 5) 待调取证据清单
    lines.append(f"## 拟调取证据\n\n{evidence_lead_in}")
    lines.append("")
    for item in evidence_items:
        lines.append(f"- {_md_collapse(item)}")  # 静态文案，折叠空白防结构注入
    lines.append("")
    # 6) 证据出处（可回溯锚点）
    if evidence_refs:
        lines.append("## 证据出处（样本内锚点）")
        lines.append("")
        for ref in evidence_refs:
            lines.append(f"- `{_code_safe(ref)}`")  # location 样本派生，中和反引号防 code span 逃逸
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _lead_to_letter(
    lead: dict[str, Any],
    templates: dict[str, dict[str, str]],
    attr_index: dict[tuple[str, str], dict[str, Any]] | None = None,
    restored_index: set[tuple[str, str, str]] | None = None,
) -> dict[str, Any]:
    """把单条可办案化 Lead 套打成文书 dict（字段见模块 docstring）。

    ``attr_index``：``{(kind, 归一化 value): 五层归因}``（见 _attribution_index）。按 Lead 的
    category+value 同法归一化后关联，套进正文「基础设施归属链」段并作结构化字段 ``attribution``
    回带。缺/无匹配 → 不渲染该段。
    """
    category = _str_or_empty(lead.get("category"))
    recipient = _str_or_empty(lead.get("where_to_request")).strip()
    target = _str_or_empty(lead.get("value"))
    subject = _str_or_empty(lead.get("subject"))
    evidence_items = _str_list(lead.get("evidence_to_obtain"))
    evidence_refs = _evidence_refs(lead)
    template = _template_for(category, templates)

    # 关联用原始 value 且须为 str（endpoint 侧同样要求 str）——不字符串化，避免 123 与 "123" 串号。
    # 归一化与 _attribution_index 建键时同一把钥匙（IP 剥 :port/proto），否则实测后端关联不上。
    raw_value = lead.get("value")
    attribution = None
    if isinstance(attr_index, dict) and isinstance(raw_value, str):
        attribution = attr_index.get((category.strip().lower(), infra.match_key(category, raw_value)))
        if attribution is None:  # 端点侧缺 kind 时的通配兜底（见 _attribution_index）
            attribution = attr_index.get(("", infra.match_key(category, raw_value)))
    attribution_lines = _render_attribution_chain(attribution) if isinstance(attribution, dict) else []
    # 形态存疑：判定靠外部佐证而非样本内的地址性证据，正文顶部要显著警示（见 Lead.shape_uncertain）。
    shape_uncertain = bool(lead.get("shape_uncertain"))
    # SNI 伪装：正文顶部要警示"别发给被冒用的那家公司"（见 Lead.sni_masquerade）。
    masquerade = _str_list(lead.get("sni_masquerade"))
    masquerade_warning = sni_masquerade_warning(masquerade)
    # 人工放行：这条本已被自动判据压住、不该走到本出口，是人放回来的。必须写进正文。
    restored_sources = sorted(restored_sources_for(lead, restored_index or set()))
    restore_warning = manual_restore_warning(restored_sources)

    body_md = _build_body_md(
        template=template,
        recipient=_md_safe(recipient),
        target=_md_safe(target),
        subject=_md_safe(subject),
        evidence_items=evidence_items,
        evidence_refs=evidence_refs,
        attribution_lines=attribution_lines,
        shape_uncertain=shape_uncertain,
        masquerade_warning=masquerade_warning,
        manual_restore_warning=restore_warning,
    )
    return {
        # 结构化回带：消费方不必去正文里捞这句（与 sni_masquerade 同理）。
        "manually_restored": restored_sources,
        "category": category,
        "subject": subject,  # 标的归属（公司/人）
        "recipient": recipient,  # 受文机关（取自 where_to_request）
        "target": target,  # 标的 = Lead.value
        "evidence_items": evidence_items,  # = evidence_to_obtain
        "evidence_refs": evidence_refs,  # evidence_id 优先、降级 source:location
        "attribution": attribution,  # 五层基础设施归属链（结构化，无匹配为 None）
        # 结构化回带：消费方（HTML/PDF/人工筛选）不必去正文里捞这句警示
        "shape_uncertain": shape_uncertain,
        "sni_masquerade": masquerade,  # 借用的域名（空列表=无伪装）
        "title": f"{template.get('title', '协查函')}（标的：{target}）",
        "body_md": body_md,
    }


def build_letters(report: dict[str, Any]) -> list[dict[str, Any]]:
    """遍历 report 的 leads，对可办案化的 Lead 生成文书草稿 dict 列表。

    Args:
        report: report.json 解析出的 dict。坏输入（非 dict、缺 leads、leads 非 list、
            元素非 dict）一律容错——返回空列表或跳过坏元素，绝不抛。

    Returns:
        文书 dict 列表（字段见模块 docstring）；无可办案化 Lead → 空列表。
    """
    if not isinstance(report, dict):
        return []
    raw_leads = report.get("leads")
    if not isinstance(raw_leads, list):
        return []
    # This module consumes raw JSON dictionaries.  Never let a cached
    # ``advice=建议调证`` bypass Evidence.scope and become a real letter.
    # Projection is non-mutating and carries matching direct Endpoint refs
    # into network Leads for the valid case+batch scenario.
    leads = project_serialized_leads(report)

    templates = _load_templates()
    attr_index = _attribution_index(report)  # {端点 value: 五层归因}，按 Lead.value 关联进正文
    # 人工放行索引：文书正文要写「本条系人工放行」——最危险的消费面，必须显式。
    restored_index = restore_index(report.get("meta"))
    out: list[dict[str, Any]] = []
    for lead in leads:
        if not _is_actionable(lead):
            continue  # 严格过滤：不可办案化的不套打
        try:
            out.append(_lead_to_letter(lead, templates, attr_index, restored_index))
        except Exception:  # 单条套打异常不应炸掉整体；记录后跳过。
            logger.exception("套打单条文书失败：value=%r", lead.get("value"))
    return out


def _safe_filename(value: str, *, fallback: str = "letter") -> str:
    """把标的值清成安全文件名片段（去非法字符、压空白、截断、空则兜底）。"""
    cleaned = _UNSAFE_FILENAME_CHARS.sub("_", value)
    cleaned = re.sub(r"\s+", "_", cleaned).strip("_. ")
    if len(cleaned) > 60:
        cleaned = cleaned[:60].rstrip("_. ")
    return cleaned or fallback


def write_letters(letters: list[dict[str, Any]], out_dir: str) -> list[str]:
    """把文书写到 <out_dir>/letters/ 下，每份一个 md，再写 index.md 索引。

    文件名：<category>_<value安全名>.md（同名追加序号去重）。编码 UTF-8。
    即使 letters 为空也写一个 index.md（稳定输出）。返回写出的路径列表（含 index.md）。
    """
    base = Path(out_dir) / "letters"
    base.mkdir(parents=True, exist_ok=True)

    written: list[str] = []
    index_lines: list[str] = [
        f"> {DISCLAIMER}",
        "",
        "# 调证 / 协查文书索引",
        "",
        f"共 {len(letters)} 份文书草稿。",
        "",
    ]

    used_names: set[str] = set()
    for letter in letters:
        category = _safe_filename(_str_or_empty(letter.get("category")), fallback="LEAD")
        target = _str_or_empty(letter.get("target"))
        stem = f"{category}_{_safe_filename(target)}"
        # 同名去重：追加 -2 / -3…
        name = stem
        seq = 1
        while name in used_names:
            seq += 1
            name = f"{stem}-{seq}"
        used_names.add(name)

        filename = f"{name}.md"
        file_path = base / filename
        body = _str_or_empty(letter.get("body_md"))
        try:
            file_path.write_text(body, encoding="utf-8")
        except OSError:
            logger.exception("写出文书失败：%s", file_path)
            continue
        written.append(str(file_path))

        recipient = _str_or_empty(letter.get("recipient"))
        index_lines.append(
            f"- [{_md_safe(target)}]({filename}) — 受文机关（候选）：{_md_safe(recipient)}"
        )

    if not letters:
        index_lines.append("（本样本无可套打的调证线索。）")
    index_lines.append("")

    index_path = base / "index.md"
    index_path.write_text("\n".join(index_lines).rstrip() + "\n", encoding="utf-8")
    written.append(str(index_path))
    return written
