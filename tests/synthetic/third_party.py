"""第三方生态样本（**反向**回归：不该报的别报）。

与 ``samples.py`` 正好相反：那边是「该检出的别漏」，这边是「**不该报的别报**」。

为什么需要这一网
----------------
判据大多是「形态启发式 + 关键词」，在熟悉的域内准确率尚可，**一出圈就大面积误报**：
一个 Web3 前端可同时触发资金类线索（实为 ethers.js 库常量）、硬编码密钥（实为 i18n
文案键名）、联系人邮箱（实为开源库作者）——形态都对得上，却没有一条指向真实资产。

误报的代价不是「多看几条」，而是产出会指向一个无关的主体。附注措辞还会反过来影响
人工复核：一句「疑为第三方 SDK 常量」就足以让复核者跳过一条本该跟进的线索。
所以误报治理要和护栏同等级——**做成回归网，而不是发现一个修一个**。

夹具来源与合规
--------------
全部取自**公开的开源库常量与生态固有形态**（ethers.js 的 keccak 空哈希、secp256k1 曲线参数、
Flutter/Unity 的产物命名、Go 库的截断域名…），**不含任何案件值、真实样本或 PII**。
这些值本身就印在千万个公开仓库里，不是任何人的资产。
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ThirdPartySample:
    """一份第三方生态内容 + 它**不得**产生的线索类。

    ``forbidden_categories`` 是「绝不能出现」（不相交判据）——断言实际检出与它无交集。
    不做全等断言：这些内容仍可能产生低档位的域名端点（那是正常的、留给人复核的），
    本网只守「**不得升到会进调证出口的类**」这条线。
    """

    name: str
    why: str                       # 这份内容在真实世界是什么，为什么曾被误判
    dex_strings: list[str] = field(default_factory=list)
    files: dict[str, bytes] = field(default_factory=dict)
    forbidden_categories: frozenset[str] = frozenset()


# --- ethers.js / web3 库常量 ------------------------------------------------
# 这些十六进制串是**库内置常量**，不是任何人的合约或钱包：
#   · keccak256("") —— 判空 code 用
#   · secp256k1 的曲线阶 N —— 椭圆曲线参数
#   · ERC-165 接口检测选择子
#   · 零地址 / 最大地址
# 真实误报：它们被 PAYMENT 判据当成「虚拟货币收款地址」，一份样本报出 21 条。
_ETHERS_CONSTANTS = [
    'if (hash === "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470") return "";',
    'const N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");',
    'data: "0x01ffc9a79061b92300000000000000000000000000000000000000000000000000000000"',
    'return "0x0000000000000000000000000000000000000000";',
    'const MaxUint160 = BigInt("0xffffffffffffffffffffffffffffffffffffffff");',
]

# --- i18n 文案键名 ----------------------------------------------------------
# 真实误报：键名含 token/secret 字样、值恰好 16 字符 → 被判「硬编码 AES-128 密钥」。
# 这类键在任何做多语言的前端里成片存在。
_I18N_KEYS = [
    '{"tokenomicsTitle":"Tokenomics Data","tokenomicsAllocation":"Community 40%"}',
    '{"secretQuestionLabel":"Security Q","accessKeyTitle":"API Access"}',
]

# --- 开源库作者 / 文档链接 ---------------------------------------------------
# 真实误报：库作者邮箱被判成「可定位注册主体的联系人」；文档域名进「建议调证」。
# js-sha3 / js-md5 的作者信息随库打包，出现在千万个 bundle 里。
_OSS_METADATA = [
    "@author Chen, Yi-Cyuan emn178@gmail.com",
    "see https://docs.soliditylang.org/en/latest/ and https://eips.ethereum.org/EIPS/eip-165",
    "https://exoplayer.dev/issues/cleartext-not-permitted",
]

# --- Go 库里的截断域名 -------------------------------------------------------
# 真实误报：Go 二进制的字符串表把 "github.com" 前一个字符连读，正则切出
# 2github.com / agithub.com 这类根本不存在的域名，一份样本报出 8 个。
_GO_TRUNCATED = [
    "modernc.org/sqlite2github.com/mattn/go-sqlite3github.com/pkg/errors",
    "go.uber.org/zapagithub.com/spf13/cobraprotobuf.dev/reference",
]

# --- Flutter 业务代码容器 ----------------------------------------------------
# libapp.so 是 Flutter 把**整个 Dart 业务代码**编译成的文件，不是第三方 SDK 的库。
# 真实误报：它必然引用多个第三方域名（地图/头像/CDN/文档），于是「带 ≥2 个已知基础设施
# 域名」的形态判据命中，把**同文件里的本 App 真后端**一并降成待核。
_FLUTTER_LIBAPP = "lib/arm64-v8a/libapp.so"

# --- WebGL / Three.js shader 变量 -------------------------------------------
# 真实误报：shader 里的 x09/x20 前缀变量名被域名正则切成 x09shadowcoord.xyz，
# 实测这些「域名」RDAP 查无、零解析——根本不存在。
_SHADER_VARS = [
    "varying vec3 x09shadowcoord.xyz; uniform vec4 x20envcolor.xyz;",
]

# --- 前端路由框架属性链 ------------------------------------------------------
# 真实误报：i.router.app.$nextTick 被当成域名（.app 是真 TLD）。
_ROUTER_CHAIN = ["i.router.app.$nextTick(function(){ e.beforeEach() })"]


#: 会进调证出口、误报代价最高的线索类——本网守的就是这几类不被第三方内容触发。
_HIGH_STAKES = frozenset({
    "PAYMENT", "FOURTH_PARTY_PAYMENT", "BACKEND_CREDENTIAL",
    "WALLET_SECRET", "CARD_MERCHANT", "ADMIN_PANEL",
})

THIRD_PARTY_SAMPLES: tuple[ThirdPartySample, ...] = (
    ThirdPartySample(
        name="ethers-js-library-constants",
        why="ethers.js 内置常量（keccak 空哈希 / secp256k1 阶 / ERC-165 选择子 / 零地址），"
            "曾被整批判成虚拟货币收款地址",
        dex_strings=_ETHERS_CONSTANTS,
        forbidden_categories=_HIGH_STAKES,
    ),
    ThirdPartySample(
        name="i18n-copy-keys",
        why="多语言文案键名，键含 token/secret 字样且值恰好 16 字符，曾被判硬编码 AES 密钥",
        dex_strings=_I18N_KEYS,
        forbidden_categories=frozenset({"BACKEND_CREDENTIAL", "WALLET_SECRET"}),
    ),
    ThirdPartySample(
        name="oss-author-and-docs",
        why="开源库作者邮箱与官方文档链接随库打包，曾被判可定位注册主体的联系人",
        dex_strings=_OSS_METADATA,
        forbidden_categories=_HIGH_STAKES,
    ),
    ThirdPartySample(
        name="go-truncated-domains",
        why="Go 字符串表连读切出的伪域名（2github.com 一类），实测零解析、不存在",
        dex_strings=_GO_TRUNCATED,
        forbidden_categories=_HIGH_STAKES,
    ),
    ThirdPartySample(
        name="webgl-shader-variables",
        why="shader 变量名被域名正则切出的伪域名，RDAP 查无、零解析",
        dex_strings=_SHADER_VARS,
        forbidden_categories=_HIGH_STAKES,
    ),
    ThirdPartySample(
        name="frontend-router-property-chain",
        why="vue-router 属性链 i.router.app.$nextTick，因 .app 是真 TLD 被当成域名",
        dex_strings=_ROUTER_CHAIN,
        forbidden_categories=_HIGH_STAKES,
    ),
)
