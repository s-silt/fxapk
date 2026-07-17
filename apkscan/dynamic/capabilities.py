"""抓包能力矩阵 —— 把「某抓包模式需要哪些能力」显式化，缺增强只降级、不失败。

★核心纪律（PCAP-first）：**floor 底座**（adb + 在线设备 + 设备侧 tcpdump + root 抓包权限）就绪即能产出
floor.pcap + 接入节点 + 报告；frida / mitmproxy 只是**明文增强**——缺了只降级到 floor、绝不判整个动态
环境失败（这正是外部评价 #1 点的问题：floor-only 用户不该被主机没装 frida 挡住）。

本模块是**纯逻辑地基**（不碰 adb / 不探真机，全离线可测）：
- `MODE_FLOOR_CAPS`：每种 capture 模式的**底座能力**（满足即能跑出该模式核心产物）。
- `PLAINTEXT_LADDER`：明文获取的**降级阶梯**（mitm → keylog → SSL hook → Cipher hook），每级带所需能力；
  上级不可达自动降到下级，PCAP 全程底座。对应动态明文路线文档的分层降级。
- `resolve(mode, available)`：给定模式 + 当前可用能力集 → 结构化 `CapabilityPlan`（ready / 缺什么 /
  降级到哪 / 明文能到哪层），供 doctor 分层体检、capture 起手门控、报告 meta 呈现共用同一判据。

能力探测（设备侧 tcpdump/root、CA 信任、keylog 可产出等）+ 接线到 capture/doctor 在后续 slice。
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ---- 能力名（与 core.registry.detect_capabilities 对齐；device_* 等为设备侧扩展，后续 slice 探测）----
CAP_ADB = "adb"                    # 主机侧 adb 可用
CAP_DEVICE = "device"              # 至少一台在线 adb 设备
CAP_DEVICE_TCPDUMP = "device_tcpdump"  # 设备侧有 tcpdump（已装或可 push）
CAP_ROOT_CAPTURE = "root_capture"  # 设备可 root 抓包（su -c id 出 uid=0）
CAP_FRIDA = "frida"                # 主机侧 frida CLI 可用
CAP_MITMPROXY = "mitmproxy"        # 主机侧 mitmproxy/mitmdump 可用
CAP_CA_TRUSTED = "ca_trusted"      # mitm CA 已装进设备系统信任库
CAP_TSHARK = "tshark"              # 主机侧 tshark 可用（keylog 深度解密）
CAP_TLS_KEYS = "tls_keys"          # 抓包产出了 NSS TLS Key Log

#: 支持的 capture 模式（与 cli.py capture --mode 对齐）。
CAPTURE_MODES: tuple[str, ...] = ("floor-only", "both", "mitm-only")

#: 每种模式的**底座能力**——全满足即该模式能产出核心产物（floor.pcap / 代理明文流）。
#: ★both 的底座 = floor（mitm 是增强）：缺 mitm/CA 时 both 自动等效降级为 floor-only，仍抓 pcap。
MODE_FLOOR_CAPS: dict[str, frozenset[str]] = {
    "floor-only": frozenset({CAP_ADB, CAP_DEVICE, CAP_DEVICE_TCPDUMP, CAP_ROOT_CAPTURE}),
    "both": frozenset({CAP_ADB, CAP_DEVICE, CAP_DEVICE_TCPDUMP, CAP_ROOT_CAPTURE}),
    "mitm-only": frozenset({CAP_ADB, CAP_DEVICE, CAP_MITMPROXY}),
}

#: both 模式的**增强能力**（缺则降级为等效 floor-only：仍抓 pcap，只是没代理明文）。★须含 CA_TRUSTED——
#: 代理明文实际需要 CA 已装进设备信任库，只有 mitmproxy 没 CA 时 mitm 明文拿不到，等效 floor-only。
_BOTH_ENHANCEMENT: frozenset[str] = frozenset({CAP_MITMPROXY, CAP_CA_TRUSTED})

#: 明文获取降级阶梯（从强到弱）：(层名, 该层所需能力)。上级不可达 → 降下级；floor pcap 是底座、不入阶梯
#: （它给的是"接入节点 IP:port"而非应用层明文）。对应明文路线文档的 both→keylog→SSL hook→Cipher hook。
PLAINTEXT_LADDER: tuple[tuple[str, frozenset[str]], ...] = (
    ("mitm", frozenset({CAP_MITMPROXY, CAP_CA_TRUSTED})),          # 代理明文：CA 受信 + 无 pinning
    ("tls_keylog", frozenset({CAP_FRIDA, CAP_TSHARK})),            # keylog 探针 + tshark 离线解密
    ("ssl_hook", frozenset({CAP_FRIDA})),                         # SSL_read/write 明文边界 hook
    ("cipher_hook", frozenset({CAP_FRIDA})),                       # App 层 Cipher/codec hook
)


@dataclass(frozen=True)
class CapabilityPlan:
    """一次 capture 的能力解析结果：该模式能不能跑、缺什么、降到哪、明文能到哪层。绝不含真机 IO。"""

    mode: str
    ready: bool                              # 该模式底座能力是否全满足（能否产出核心产物）
    required: frozenset[str]                 # 底座所需能力
    available: frozenset[str]                # 当前可用能力（入参归一）
    missing: frozenset[str]                  # 底座缺的能力（ready=False 时非空）
    degraded_to: str | None                  # 不 ready / 增强缺失时的降级目标；彻底跑不了 → None
    plaintext_reachable: tuple[str, ...]     # 明文阶梯里当前可达的层（强→弱）
    plaintext_best: str | None               # 最强可达明文层（无 → None，只有 floor 接入节点）
    notes: tuple[str, ...] = field(default_factory=tuple)  # 人读决策依据


def _plaintext_layers(available: frozenset[str]) -> tuple[str, ...]:
    """明文阶梯里当前可达的层（能力全满足即可达），强→弱顺序。"""
    return tuple(name for name, need in PLAINTEXT_LADDER if need <= available)


#: 底座不满足时的降级候选优先级（PCAP-first：floor pcap 底座优先于无 pcap 的纯代理 mitm-only）。
_FALLBACK_ORDER: tuple[str, ...] = ("floor-only", "mitm-only")


def _best_fallback(mode: str, available: frozenset[str]) -> str | None:
    """底座不满足时，按 PCAP-first 优先级找**其它**底座能满足的模式；都不满足 → None。

    ★覆盖"缺设备 tcpdump/root（floor 跑不了）但有 mitmproxy+CA"——此时可退 mitm-only（纯代理抓明文、
    无 pcap 底座），而非误判"无法抓包"。
    """
    for cand in _FALLBACK_ORDER:
        if cand != mode and MODE_FLOOR_CAPS[cand] <= available:
            return cand
    return None


def resolve(mode: str, available: set[str] | frozenset[str]) -> CapabilityPlan:
    """据模式 + 当前能力集产出结构化能力计划。未知模式回退按 floor-only 处理（保底、不抛）。"""
    avail = frozenset(available)
    m = mode if mode in MODE_FLOOR_CAPS else "floor-only"
    required = MODE_FLOOR_CAPS[m]
    missing = required - avail
    ready = not missing
    reachable = _plaintext_layers(avail)
    best = reachable[0] if reachable else None

    notes: list[str] = []
    degraded_to: str | None = None
    if ready:
        # both 缺增强(mitm/CA) → 记为等效 floor-only（仍抓 pcap，无代理明文）。
        if m == "both" and not (_BOTH_ENHANCEMENT <= avail):
            degraded_to = "floor-only"
            notes.append("both 缺 mitmproxy/CA 增强 → 等效 floor-only：仍抓 floor.pcap，无代理明文")
        notes.append(f"{m} 底座就绪：可产出核心产物（floor.pcap / 接入节点 / 报告）")
    else:
        # 底座不满足：按 PCAP-first 优先级找**其它**底座能满足的模式（floor-only 优先于纯代理 mitm-only）。
        degraded_to = _best_fallback(m, avail)
        if degraded_to:
            notes.append(f"{m} 底座缺 {_join(missing)} → 可降级到 {degraded_to}")
        else:
            notes.append(f"{m} 底座缺 {_join(missing)}，无其它模式的底座可满足 → 无法抓包")
    if best:
        notes.append(f"明文最强可达层：{best}（阶梯：{' → '.join(reachable)}）")
    else:
        notes.append("暂无可达明文层 → 只能靠 floor.pcap 拿接入节点 IP:port（仍是有效调证线索）")

    return CapabilityPlan(
        mode=m,
        ready=ready,
        required=required,
        available=avail,
        missing=frozenset(missing),
        degraded_to=degraded_to,
        plaintext_reachable=reachable,
        plaintext_best=best,
        notes=tuple(notes),
    )


def _join(caps: frozenset[str] | set[str]) -> str:
    """能力集 → 稳定排序的可读串（空集 → '无'）。"""
    return ", ".join(sorted(caps)) if caps else "无"
