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
Flutter/Unity 的产物命名、Go 库的截断域名…），**不含任何案件值、真实样本或 PII**。  # leak-scan: allow 本网用途说明，描述判据要防的误报类型
这些值本身就印在千万个公开仓库里，不是任何人的资产。
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ThirdPartySample:
    """一份第三方生态内容 + 它**不得**产生的线索类。

    ``forbidden_categories`` 是「绝不能出现」（不相交判据）——断言实际检出与它无交集。
    不做全等断言：这些内容仍可能产生低档位的域名端点（那是正常的、留给人复核的），
    本网只守「**不得升到会进调证出口的类**」这条线。  # leak-scan: allow 夹具字段注释，说明禁止类的含义
    """

    name: str
    why: str                       # 这份内容在真实世界是什么，为什么曾被误判
    dex_strings: list[str] = field(default_factory=list)
    files: dict[str, bytes] = field(default_factory=dict)
    forbidden_categories: frozenset[str] = frozenset()
    #: 这些具体值**不得**落在"建议"档——它们是框架自带的东西，没有可查的主体。
    #:
    #: ★为什么不能只靠基线：基线记的是「检出了哪些线索类」，对档位是盲的。一个域名
    #:   从"无需"升成"建议"，类还是 DOMAIN，基线全绿——而那正是误报真正生效的形态。
    must_not_be_actionable: frozenset[str] = frozenset()


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
# 真实误报：库作者邮箱被判成「可定位注册主体的联系人」；文档域名进「建议调证」。  # leak-scan: allow 样本说明：ethers.js 库常量曾被判进资金类出口
# js-sha3 / js-md5 的作者信息随库打包，出现在千万个 bundle 里。
_OSS_METADATA = [
    "@author Chen, Yi-Cyuan emn178@gmail.com",  # leak-scan: allow 阴性夹具：js-sha3 开源库作者邮箱，随库打包非联系人
    "see https://docs.soliditylang.org/en/latest/ and https://eips.ethereum.org/EIPS/eip-165",  # leak-scan: allow 阴性夹具：Solidity/EIP 官方文档域，非资产
    "https://exoplayer.dev/issues/cleartext-not-permitted",
]

# --- Go 库里的截断域名 -------------------------------------------------------
# 真实误报：Go 二进制的字符串表把 "github.com" 前一个字符连读，正则切出
# 2github.com / agithub.com 这类根本不存在的域名，一份样本报出 8 个。  # leak-scan: allow 阴性夹具：Go 字符串表连读切出的伪域名，实测零解析
_GO_TRUNCATED = [
    "modernc.org/sqlite2github.com/mattn/go-sqlite3github.com/pkg/errors",  # leak-scan: allow 阴性夹具：同上，sqlite/errors 包名被连读
    "go.uber.org/zapagithub.com/spf13/cobraprotobuf.dev/reference",  # leak-scan: allow 阴性夹具：同上，zap/cobra 包名被连读
]

# --- Flutter 业务代码容器 ----------------------------------------------------
# libapp.so 是 Flutter 把**整个 Dart 业务代码**编译成的文件，不是第三方 SDK 的库。
# 真实误报：它必然引用多个第三方域名（地图/头像/CDN/文档），于是「带 ≥2 个已知基础设施
# 域名」的形态判据命中，把**同文件里的本 App 真后端**一并降成待核。
_FLUTTER_LIBAPP = "lib/arm64-v8a/libapp.so"

# --- WebGL / Three.js shader 变量 -------------------------------------------
# 真实误报：shader 里的 x09/x20 前缀变量名被域名正则切成 x09shadowcoord.xyz，  # leak-scan: allow 阴性夹具/说明文字里的第三方域 x09shadowcoord.xyz，非本方资产
# 实测这些「域名」RDAP 查无、零解析——根本不存在。
_SHADER_VARS = [
    "varying vec3 x09shadowcoord.xyz; uniform vec4 x20envcolor.xyz;",  # leak-scan: allow 阴性夹具/说明文字里的第三方域 x09shadowcoord.xyz，非本方资产；阴性夹具/说明文字里的第三方域 x20envcolor.xyz，非本方资产
]

# --- 前端路由框架属性链 ------------------------------------------------------
# 真实误报：i.router.app.$nextTick 被当成域名（.app 是真 TLD）。
_ROUTER_CHAIN = ["i.router.app.$nextTick(function(){ e.beforeEach() })"]

# --- 跨平台框架的自带内容 ----------------------------------------------------
# 下面四组共一个根因：这类框架把**整份业务代码**编译进单个产物文件，而框架自己的
# 官网、包管理器、示例服务器地址也一并烙在同一个文件里。于是「同一 .so 内出现多个
# 域名」这条形态判据成立，框架自带的域名与本 App 的真后端被混作一谈——两个方向的错
# 都会犯：把框架官网当资产（误报），或反过来把整个文件判成第三方 SDK 库而把真后端
# 一起降档（漏报）。真样本实证过后者。
#
# 这些域名是各框架的公开官网/包仓库，印在千万个公开构建产物里，不是任何人的资产。

# Flutter：Dart AOT 产物 libapp.so 里必然带框架官网与 pub 包的文档链接。
_FLUTTER_STRINGS = [  # leak-scan: allow 阴性夹具：Flutter 框架自带的公开官网/包仓库域名，非任何人的资产
    "package:flutter/src/widgets/framework.dart",
    "https://flutter.dev/docs/testing/errors",
    "https://api.flutter.dev/flutter/widgets/State/setState.html",
    "https://pub.dev/packages/url_launcher",
    "flutter.baseflow.com/permission-handler",  # leak-scan: allow 阴性夹具：Flutter 插件作者站，占位域名测不出该判据
    "https://dart.dev/go/non-promo-property",
]

# Unity：IL2CPP 元数据 + Unity Analytics/Ads 的固定端点。
_UNITY_STRINGS = [  # leak-scan: allow 阴性夹具：Unity 引擎自带的公开服务域名，随引擎打包
    "System.Collections.Generic.Dictionary`2[System.String,UnityEngine.Object]",
    "https://config.uca.cloud.unity3d.com/",  # leak-scan: allow 阴性夹具：Unity 引擎自带端点，占位域名测不出该判据
    "https://cdp.cloud.unity3d.com/v1/events",  # leak-scan: allow 阴性夹具：Unity 引擎自带端点，占位域名测不出该判据
    "auction.unityads.unity3d.com",  # leak-scan: allow 阴性夹具：Unity 引擎自带端点，占位域名测不出该判据
    "UnityEngine.Networking.UnityWebRequest::SetRequestHeader",
]

# React Native：Metro 打包器的本机开发地址 + 框架文档链接。
# ★真实误报：``localhost:8081`` / ``10.0.2.2`` 是**开发期**的打包服务器，不是后端。
#   10.0.2.2 更特殊——它是模拟器里指向宿主机的固定别名，指向不了任何真实主体。
_RN_STRINGS = [  # leak-scan: allow 阴性夹具：RN 开发期打包服务器地址与框架文档域，无对应主体
    "http://localhost:8081/index.bundle?platform=android&dev=true",
    "http://10.0.2.2:8081/debugger-proxy?role=client",
    "https://reactnative.dev/docs/network",
    "Unable to load script from assets 'index.android.bundle'",
    "com.facebook.react.bridge.ReadableNativeMap",
]

# Cordova / Ionic：白名单插件的 access origin 与框架文档。
# ★真实误报：``<access origin="*">`` 是**权限声明**里的通配符，不是端点；
#   file:///android_asset/www/ 是本地资源路径，被 URL 判据当成远端。
_CORDOVA_STRINGS = [  # leak-scan: allow 阴性夹具：Cordova 白名单通配与本地资源路径，非远端端点
    '<access origin="*" subdomains="true" />',
    "file:///android_asset/www/index.html",
    "https://cordova.apache.org/docs/en/latest/guide/appdev/whitelist/",
    "cordova-plugin-inappbrowser: gap://ready",
    "ionic.config.json",
]


#: 会进调证出口、误报代价最高的线索类——本网守的就是这几类不被第三方内容触发。  # leak-scan: allow 判据说明中的技术表述（调证），非案件语境
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
        why="Go 字符串表连读切出的伪域名（2github.com 一类），实测零解析、不存在",  # leak-scan: allow 阴性夹具/说明文字里的第三方域 2github.com，非本方资产
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
    ThirdPartySample(
        name="flutter-framework-strings",
        why="Flutter 把整份 Dart 代码编译进一个产物，框架官网与 pub 包文档一并烙在里面；"
            "同文件多域名会让形态判据把本 App 的真后端一起降档",
        dex_strings=_FLUTTER_STRINGS,
        forbidden_categories=_HIGH_STAKES,
        # dart.dev 曾漏在名单外：同一框架的其余域名都判无需，唯独它升档。
        must_not_be_actionable=frozenset({"flutter.dev", "api.flutter.dev", "pub.dev", "dart.dev", "flutter.baseflow.com"}),  # noqa: E501  # leak-scan: allow 阴性夹具：Flutter/Dart 官方域，测的正是它们不该升档
    ),
    ThirdPartySample(
        name="unity-il2cpp-strings",
        why="Unity 引擎自带的 Analytics/Ads 端点与 IL2CPP 元数据，随引擎打进每个游戏包",
        dex_strings=_UNITY_STRINGS,
        forbidden_categories=_HIGH_STAKES,
        must_not_be_actionable=frozenset({"config.uca.cloud.unity3d.com", "cdp.cloud.unity3d.com", "auction.unityads.unity3d.com"}),  # noqa: E501  # leak-scan: allow 阴性夹具：Unity 引擎自带服务域，测的正是它们不该升档
    ),
    ThirdPartySample(
        name="react-native-metro-strings",
        why="Metro 打包器的开发期地址（localhost:8081 / 模拟器别名 10.0.2.2）与框架文档，"
            "既不是后端也不对应任何主体",
        dex_strings=_RN_STRINGS,
        forbidden_categories=_HIGH_STAKES,
        # 10.0.2.2 是模拟器指向宿主机的固定别名，向谁都查不到。
        must_not_be_actionable=frozenset({"reactnative.dev", "10.0.2.2"}),  # leak-scan: allow 阴性夹具：RN 文档域与模拟器宿主机别名，测的正是它们不该升档
    ),
    ThirdPartySample(
        name="cordova-whitelist-strings",
        why="Cordova 白名单里的通配 origin 与 file:// 本地资源路径，是权限声明与本地路径，"
            "不是远端端点",
        dex_strings=_CORDOVA_STRINGS,
        forbidden_categories=_HIGH_STAKES,
    ),
)
