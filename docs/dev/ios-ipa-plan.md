# iOS IPA 支持开发任务书

本文件是**给执行 agent（本地 Codex）的实施任务书**，不是用户文档，也不是已实现能力的说明。
读本文前先读 [AGENTS.md](../../AGENTS.md)（授权与完成边界）与 [ARCHITECTURE.md](../../ARCHITECTURE.md)（分层与兼容边界）；
本文只在其之上补 iOS 这一条平台线的接口、边界与验收口径。

执行环境假设：Windows + Python 3.11+，有已授权的 Android 真机，**没有 iPhone、没有 macOS 主机**。
因此全部解析必须是纯 Python，不得调用 `codesign` / `security cms` / `otool` / `plutil` 等 macOS 专有工具。

## 1. 范围

| 分发形态 | 下载 | 静态解析 | 说明 |
| --- | --- | --- | --- |
| 企业签（in-house） | 是 | 是 | 落地页 → `itms-services://` → `manifest.plist` → `.ipa` |
| Ad-Hoc | 是 | 是 | 同上；描述文件里有设备清单 |
| 超级签 | 否（本期） | 仅 `.mobileconfig` | 签发前要先收到设备 UDID；伪造 UDID 不在本期范围 |
| App Store | 否 | 否 | 显式排除 |
| TestFlight | 否 | 否 | 显式排除 |

**非目标（写进实现注释，防后续漂移）**
- 不做 iOS 反编译、不做调用链、不做 class-dump 等价能力：本期 Mach-O 侧只做**结构解析 + 字符串抽取**。
- 不做 iOS 运行时采集：没有真机，`capture` / `auto` / Frida 这条线对 iOS 一律不适用，必须以平台门控 `skipped` 呈现，不得空跑出"未发现"。
- 不伪造设备 UDID、不向签名平台提交任何设备标识。
- 不打包 exe/GUI（AGENTS.md 既有约定）。粘贴链接即下载的窗口程序在**独立仓库 `s-silt/fxfetch`**，本仓库只提供可被它调用的命令行核心。

## 2. 分期

每期独立可验收，一期一个 PR，不得合并提交。

| 期 | 内容 | 能否完全离线验收 |
| --- | --- | --- |
| P1 | `IpaContext` + `load_ipa` + 平台门控 + `ios_signing` / `ios_plist` 两个分析器 | 是 |
| P2 | Mach-O 解析 + 通用分析器补 iOS 资源路径 + `ios_repack` | 是 |
| P3 | `fetch-ipa` 下载命令（授权门）+ `.mobileconfig` 解析 | 是（本地 mock HTTP 服务，不碰真实目标） |
| P4 | 与 Android 报告交叉印证 | 是 |

先做 P1：价值最高（签名身份是 APK 拿不到的增量）且全部可用合成夹具验收。

## 3. P1：加载层与平台门控

### 3.1 新增 `apkscan/core/ipa.py`

```python
class IpaContext:
    """AnalysisContext 的 iOS 实现，由 zipfile + plistlib 驱动。通过 load_ipa() 构造。"""

    platform: str = "ios"

    # --- AnalysisContext 协议成员 ---
    config: AnalysisConfig
    apk_path: str            # IPA 原始文件绝对路径（字段名沿用协议，不改名，注释说明它此时是 .ipa）
    extra_dex_paths: list[str] = []      # 恒空
    jadx_cache_root: str | None = None   # 恒 None
    jadx_baseline_index: str | None = None
    dex_available: bool = False          # 恒 False：iOS 无 DEX，报告须显式可见这一点

    @property
    def package_name(self) -> str: ...   # Info.plist 的 CFBundleIdentifier；读不到 → ""
    @property
    def manifest_xml(self) -> str: ...   # 恒 ""（iOS 无 AndroidManifest）

    def permissions(self) -> list[str]: ...   # 见 3.3
    def components(self) -> ComponentSet: ...  # 恒空 ComponentSet()
    def dex_strings(self) -> Iterator[str]: ...  # 恒空迭代器
    def list_files(self) -> list[str]: ...     # IPA zip 内全部条目（原始 zip 路径）
    def read_file(self, path: str) -> bytes | None: ...
    def declared_size(self, path: str) -> int | None: ...
    def native_libs(self) -> list[str]: ...    # 见 3.4
    def certificates(self) -> list[CertInfo]: ...  # 见 4.1

    # --- iOS 专有（消费方一律 getattr 兼容读取，不得改协议） ---
    @property
    def app_dir(self) -> str: ...        # "Payload/<Name>.app"；定位失败抛 IpaParseError
    @property
    def info_plist(self) -> dict: ...    # 解析后的 Info.plist；解不出 → {}
    @property
    def executable_path(self) -> str: ...  # app_dir + CFBundleExecutable


def load_ipa(path: str, config: AnalysisConfig) -> IpaContext:
    """加载 IPA 并构造 IpaContext。结构不可解析时抛 IpaParseError（对标 ApkParseError 的 fail fast）。"""
```

硬要求：
- **不解压到磁盘**。全程 `zipfile` 内有界读取。Windows 上 `.app` 内可能出现仅大小写不同的同名条目、超长路径、`CON`/`NUL`/`AUX` 这类保留名；一旦落盘就会互相覆盖或报错，证据完整性直接破坏。
- `read_file` 必须先过 `declared_size` 判据再解压，口径与 `core/apk.py` 的 `read_file` 一致（见 §6 上限表）。
- 条目路径穿越（`..`、绝对路径、盘符、反斜杠）一律拒绝并计数，不得静默跳过——计数写进 `meta.ipa_rejected_entries`。
- 单次加载的累计解压字节有总预算，对标 `core/apk.py` 的 `_MAX_TOTAL_CACHE_BYTES`，不得只限单条。
- `load_ipa` 不得 import androguard，`ipa.py` 不得被任何 analyzer 直接 import（分析器只依赖 `AnalysisContext`）。

### 3.2 `app_dir` 定位

- 只认 `Payload/<任意名>.app/` 这一层，取**字典序第一个**命中项，保证同样本同结果。
- 命中 0 个 → `IpaParseError`。命中多个 → 仍取第一个，但把全部候选写进 `meta.ipa_payload_candidates`，并在 `ios_signing` 产一条 MEDIUM finding（多 `.app` 根是重打包的常见形态，不得静默取一个了事）。
- `Payload/` 之外的 `.app`（如 `PlugIns/` 内的 appex）不作主 app。

### 3.3 `permissions()` 的 iOS 语义

iOS 没有 Android 权限清单，但有 `NS*UsageDescription`。做法：
- 返回值为 `Info.plist` 中全部 `NS*UsageDescription` 的**键名**（排序去重），如 `NSCameraUsageDescription`。
- **不得**把它们映射成 Android 权限名（`android.permission.CAMERA`）——那是造证据。
- 对应的**文案**（value）单独进 `ios_plist` 分析器的 meta，供人工读；文案里常有运营方自述的业务用途。

### 3.4 `native_libs()` 的 iOS 语义

返回 IPA 内全部 **Mach-O** 文件路径（按路径排序），覆盖：
- 主可执行文件 `app_dir/CFBundleExecutable`；
- `app_dir/Frameworks/*.framework/<name>`、`app_dir/Frameworks/*.dylib`；
- `app_dir/PlugIns/*.appex/<可执行文件>`。

判定依据是**文件头 magic**（`feedface` / `feedfacf` / `cafebabe` / `bebafeca` 及其反序），不是扩展名。
P1 可先只做 magic 判定与路径收集，真正的 load command 解析在 P2。

### 3.5 平台门控

`apkscan/core/registry.py`：

```python
_PLATFORM_CAPABILITIES: dict[str, frozenset[str]] = {
    "android": frozenset({"android", "apk"}),
    "ios": frozenset({"ios", "ipa"}),
    "web": frozenset({"web"}),
}
```

- `requires=["apk"]` 的 Android 专属分析器在 iOS 上自动落入 `skipped_analyzers`，reason 必须说明"平台不适用"，不计入 `completeness` 分母（`pipeline` 既有行为，不要改）。
- `pipeline.py` 第 431 行附近 `state.platform == "android" and ctx.dex_available is False` 的加固告警分支**不得**扩散到 iOS：iOS 的 `dex_available=False` 是平台事实、不是加固信号。必须加显式平台判断，并补一条 `visibility` 口径：iOS 的 `sources.dex` 记 `unavailable`，理由"平台无 DEX"，不是 `opaque`。
- 新分析器一律 `requires=["ipa"]`，不得用 `requires=["ios"]`（保持与 `apk`/`web` 同构：能力名指的是被分析物的容器）。

### 3.6 CLI 分流

- 不新增 `analyze-ipa` 命令。`analyze` 按**文件头 magic + 内部结构**判型：ZIP 且含 `Payload/*.app/` → `load_ipa`，否则 `load_apk`。不得只看扩展名（改名是常态）。
- 判型函数放 `apkscan/core/loader.py`（新增），返回 `"apk" | "ipa"`；`cli.py` 中 `analyze` 与 `diff` 两处 `load_apk` 调用点统一走它；`dynamic/` 下的调用点（`auto`/`unpack`/`repackage`）只收 APK，在命令入口拒绝 IPA（见下条）。
- `analyze` 对 iOS 样本的联网富化行为保持不变（默认联网、`--offline` 关）。
- `auto` / `capture` / `unpack` / `repackage` / `doctor` 遇到 iOS 样本直接 exit 2，提示"iOS 样本不支持动态流程"。**不得**退化成静默只跑静态。

## 4. P1 分析器

### 4.1 `apkscan/analyzers/ios_signing.py`（`requires=["ipa"]`）

读 `app_dir/embedded.mobileprovision`。该文件是 CMS（PKCS#7）签名容器，内层是 plist。

- 解析用 `asn1crypto`（已在 `requirements.lock`，androguard 传递引入；若直接依赖则进 `pyproject` 主依赖并说明理由）。**不验签**——我们要的是里面的声明内容和签名者身份，不是"这个描述文件有效"；报告里也必须这样写。
- 提取并进 `meta.ios_signing`：
  - `team_id`（`Entitlements.com.apple.developer.team-identifier`）、`team_name`、`app_id_name`、`profile_uuid`、`creation_date`、`expiration_date`、`platform`；
  - `provisions_all_devices`（真 → 企业签的强信号）；
  - `provisioned_device_count`（**只给数量**）；
  - `developer_certificates`：逐证书的 subject / issuer / sha256 / 有效期（复用 `CertInfo`，`schemes` 留空）；
  - `entitlements` 原样保留（有界）：`application-identifier`、`aps-environment`、`associated-domains`、`get-task-allow`、`keychain-access-groups`。
- `certificates()` 返回上面的 `developer_certificates`，使既有证书类分析器与 corpus 的 `--by sign_sha256` 反查能直接复用。
- `associated-domains` 里的 `applinks:` / `webcredentials:` 域名产 `Endpoint(kind="domain", evidences=[Evidence(source="ios_signing", location="embedded.mobileprovision")])`，由 pipeline 统一建 Lead。这是 App 自己声明的强关联域名，但**不等于**业务后端，advice 不得直接写"建议调证"。
- 签名类型判定只给三档并写明判据，不做更强断言：
  - `enterprise`：`ProvisionsAllDevices == true`；
  - `adhoc`：有 `ProvisionedDevices` 且 `get-task-allow == false`；
  - `development`：有 `ProvisionedDevices` 且 `get-task-allow == true`；
  - 其余 `unknown`。
- UDID **默认不进 digest、不进 HTML/PDF**，只在 `report.json` 的 `meta.ios_signing.provisioned_devices` 保留原值，并在 `core/redact.py` 的高敏类别里登记（digest 只显示数量）。理由：设备标识是第三方（可能含被害人）的硬标识。
- 口径铁律（写进模块 docstring 和报告 notes）：签名身份只证明"**谁的开发者账号签了这个包**"，不等于该账号就是运营者。调证对象是 Apple（企业账号主体 / 个人开发者账号注册人与付款信息）与超级签平台，不是从 Team ID 直接推人。

### 4.2 `apkscan/analyzers/ios_plist.py`（`requires=["ipa"]`）

读 `app_dir/Info.plist`（二进制 plist 与 XML plist 都要支持，`plistlib` 两种都能吃）。

- `meta.ios_app`：`CFBundleIdentifier`、`CFBundleDisplayName`、`CFBundleName`、`CFBundleShortVersionString`、`CFBundleVersion`、`MinimumOSVersion`、`DTPlatformVersion`、`DTXcodeBuild`、`CFBundleSupportedPlatforms`。
- `CFBundleURLTypes` 里的 scheme、`LSApplicationQueriesSchemes` → `meta.ios_url_schemes` / `meta.ios_queried_schemes`。被查询的 scheme 命中银行/钱包/支付类时产 MEDIUM finding；命中规则放 `rules/`，不写死在代码里（对标既有 `bank_packages`）。
- `NSAppTransportSecurity.NSExceptionDomains` 的键名是**域名**，产 `Endpoint(kind="domain")`，`NSExceptionAllowsInsecureHTTPLoads` 为真时附 finding（明文业务后端）。
- `NSBonjourServices`、`NSAppTransportSecurity.NSAllowsArbitraryLoads`、`UIBackgroundModes` 进 meta。
- 与 `manifest.plist`（下载期拿到的分发清单）交叉核对 bundle id 与版本：不一致产 MEDIUM finding"疑似换包"，但只说疑似。

### 4.3 `report` / `digest` 出口

- `digest` 新增 `ios_signing` 段：签名类型、Team ID、TeamName、证书 subject（按既有脱敏规则）、profile 有效期、设备数量、`associated-domains` 计数。**不列 UDID**。
- `report.meta.platform` 已由 pipeline 播种，确认 iOS 样本下为 `"ios"`，HTML 模板不要出现"APK 包名"这类写死的 Android 文案（模板里按 `meta.platform` 取词）。

## 5. P2 / P3 / P4

### 5.1 P2：Mach-O 与通用分析器

新增 `apkscan/core/macho.py`，纯 Python，只做结构解析：

```python
@dataclass(frozen=True)
class MachOSlice:
    cpu_type: str            # arm64 / arm64e / x86_64 ...
    file_type: str           # execute / dylib / bundle
    encrypted: bool          # LC_ENCRYPTION_INFO[_64].cryptid != 0
    linked_dylibs: list[str] # LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB / LC_REEXPORT_DYLIB
    rpaths: list[str]        # LC_RPATH
    uuid: str                # LC_UUID
    min_os: str
    sections: dict[str, tuple[int, int]]  # "__TEXT/__cstring" -> (offset, size)

def parse_macho(data: bytes) -> list[MachOSlice]:
    """thin 返回 1 片，fat 返回多片。解析失败返回 []（绝不抛）。"""
```

- load command 遍历必须有**条数上限**与**偏移/长度边界检查**，单条 `cmdsize` 为 0 或越界即停止并记截断（畸形 Mach-O 是对手可控输入，无界遍历 = DoS）。
- 字符串抽取只在 `__TEXT/__cstring`、`__DATA/__cfstring` 等**已声明节区范围内**做，不扫全文件，口径与 `endpoints.py` 的 `.so` 分块抽取一致（含块间重叠，防跨界截断）。
- `encrypted == true`（FairPlay）时：主二进制字符串面记 `visibility.sources.native = opaque`，并阻断"未发现 X"类穷尽性结论（对标 `DEX-STRING-POOL-OPAQUE` 的既有机制）。企业签/Ad-Hoc 包正常应为 false；为 true 说明拿到的是 App Store 包，与本期范围不符，须在报告里说清。
- 非系统路径（不以 `/System/`、`/usr/lib/` 开头）的 `LC_LOAD_DYLIB` 与 `@rpath` 异常项 → `ios_repack` 的 MEDIUM finding"疑似注入"。只说疑似。

既有通用分析器补 iOS 路径（**只加路径，不改判据**，每个都要有 iOS 用例）：
- `endpoints.py`：native 面从"只认 `.so`"改为按 `ctx.native_libs()` + magic 判型，Mach-O 走 `core/macho.py` 的节区抽取；资源面的 `_FALLBACK_RESOURCE_DIRS` 增加 app bundle 内的 `.plist` / `.json` / `.strings`。
- `js_bundle.py`：框架识别补 RN `main.jsbundle`、Cordova/uni-app `www/`、Flutter `Frameworks/App.framework/App` 与 `flutter_assets/`；`meta.js_framework` 的取值集合要同时适用两个平台。
- `app_framework.py` 当前 `requires=["apk"]`，不要改它；另出 iOS 的框架识别结论（放进 `ios_plist` 或新分析器），避免把 Android 的 DEX 判据硬套。
- `repack_identity.py` 的 iOS 等价：新增 `apkscan/analyzers/ios_repack.py`，判据是 `_CodeSignature/CodeResources` 里声明的文件哈希与包内实际文件不一致、`Payload/` 多 `.app`、非系统 dylib。口径仍是"疑似重签名"，**不说"植入了什么"**。

### 5.2 P3：`fetch-ipa` 与 `.mobileconfig`

新增命令 `fxapk fetch-ipa <url>`，与 `analyze` 完全解耦（`analyze` 永不下载）。

```
fxapk fetch-ipa <url> --out <dir> [--authorized-active] [--ua android|ios|both] [--max-bytes N]
```

- **默认零流量**：不带 `--authorized-active` 只打印将要访问的主机、解析到的 IP 与计划步骤，一个请求都不发。照搬 `config-probe` 的既有写法与提示文案。执行 agent **不得自行加** `--authorized-active`，必须由操作者确认授权（与 REA 开关同一规则，写进 AGENTS.md §1）。
- 识别与处理：直链 `.apk` / `.ipa`、`itms-services://?action=download-manifest&url=...`、`manifest.plist`（取 `assets[].url`，kind=`software-package`）、`.mobileconfig`（只保存与解析，**不**据其向任何地址回传设备标识）。
- 下载实现**不要**改 `apkscan/config/fetch.py` 的 5 MiB 上限（它服务的是远程配置对象，放大上限会扩大该路径的内存面）。新建 `apkscan/core/download.py`，复用 `config/fetch.py` 已有的 SSRF 判据函数（`_target_is_safe` / `_assert_peer_public` 提升为公开 API 后复用，不复制一份），但流式写盘：
  - 边下边算 SHA-256，不全量进内存；
  - `Content-Length` 预检 + 实际字节数双重判长，不一致要记录；
  - 默认上限 512 MiB，`--max-bytes` 可调，超限即中断并保留"已截断"状态，不删证据；
  - 落盘文件名用 `sha256` 命名，**不**用 URL 或 manifest 里的文件名（对手可控，Windows 保留名与路径穿越都走这条进来）。
- 逐跳留证（`<out>/fetch.json`）：每一跳的请求 URL、方法、UA、状态码、`Location`、响应头、**实连 peer IP**、TLS 证书指纹与有效期、UTC 时间；manifest/mobileconfig 原文一并存盘并记哈希。
- 重定向**不隐式跟随**：逐跳显式发起，每跳都重跑 SSRF 判据（既有 `allow_redirects=False` 的理由在这里同样成立），跳数上限 10。
- 多 UA：`--ua both` 时分别以 Android 与 iPhone 身份各走一遍同一入口，两条链路分别留档，**不合并**（同一 URL 在不同 UA 下返回不同内容本身就是证据）。
- 产出可直接交给 `fxapk analyze`（APK/IPA）或 `fxapk analyze-web`（落地页材料）。`fetch-ipa` 自己**不**调用 analyze。
- 失败分类不得混为一谈：`downloaded` / `not_found`（确实没有包）/ `blocked`（被挑战页、验证码或访问控制挡住，**内容未知**）/ `failed`（网络或 SSRF 拦截）。尤其 `blocked` 不得呈现为"未发现下载包"。
- `.mobileconfig` 解析（也是 CMS 容器）：`PayloadOrganization`、`PayloadDisplayName`、`PayloadIdentifier`、签名证书主体与指纹、`PayloadContent` 里的 URL（Web Clip 地址、注册/回传地址）。回传地址产 Endpoint，**不访问**。超级签样本在本期到此为止。

### 5.3 P4：与 Android 报告交叉印证

新增 `fxapk corpus link-candidates` 的 iOS 维度，或独立子命令（实现时二选一，在 PR 描述里说明理由）：
- 可比对的锚点：端点域名/IP、`associated-domains`、URL scheme、JS bundle 内的 C2 与配置、后台入口路径。
- **不可**比对、也不可继承的：签名身份（两平台证书体系不同）、包名与 bundle id（命名习惯相近不构成同一性）。
- 铁律：**Android 的运行时证据不得算作 iOS 包的运行时证据**。交叉命中只把该端点标为"双平台静态一致"，iOS 侧闭环仍为 `partial`，`gaps` 要写清缺的是 iOS 运行时证据。报告里两平台证据分列，不合并计数。

## 6. 安全上限（新增常量集中在 `core/ipa.py` / `core/macho.py` / `core/download.py`，不散落）

| 项 | 上限 | 理由 |
| --- | --- | --- |
| IPA 单条目声明解压大小 | 对齐 `core/apk.py` 既有单条目上限（`ZipEntryTooLargeError` 那套判据） | zip 炸弹 |
| 单次加载累计解压字节 | 对齐 `core/apk.py` 的 `_MAX_TOTAL_CACHE_BYTES`（256 MiB） | 多条目累加撑爆内存 |
| zip 条目总数 | 100000 | 条目数炸弹 |
| plist 解析输入 | 16 MiB，嵌套深度 64 | `plistlib` 对深嵌套输入无内建深度限制 |
| Mach-O load command 条数 | 4096 | 畸形头无界遍历 |
| Mach-O 单片解析字节 | 256 MiB | 超大二进制 |
| 字符串抽取单节区 | 对齐 `endpoints.py` 的 `.so` 分块上限 | 与既有口径一致 |
| 下载总字节 | 512 MiB（`--max-bytes` 可调） | IPA 实际体量 |
| 重定向跳数 | 10 | 跳转环 |
| 单次 `fetch-ipa` 墙钟 | 600 s | 慢速响应拖死进程 |

所有拒绝都要**计数并出现在报告里**，不得静默跳过——"被上限挡下"与"扫过没有"是两件事。

## 7. 夹具与验收

### 7.1 合成夹具（`tests/fixtures/ipa/` + 生成器）

**不得**向仓库提交真实 IPA、真实二进制或任何真实域名、IP、证书、UDID。参照 `tests/synthetic/samples.py` 的既有做法：

- 新增 `tests/ipa_fixtures.py`，用 `zipfile` + `plistlib` + 手工字节现场构造：
  - 最小可用 IPA：`Payload/Demo.app/Info.plist` + 空壳可执行文件；
  - `embedded.mobileprovision`：自签 CMS 容器（用 `cryptography` 现场生成测试证书，标记为合成），分别造企业签 / Ad-Hoc / development 三份；
  - Mach-O：手工拼 thin arm64 与 fat 两种头，含 `LC_LOAD_DYLIB`、`LC_ENCRYPTION_INFO_64`（cryptid 0/1 两版）、越界 `cmdsize` 的畸形版；
  - 攻击夹具：路径穿越条目、仅大小写不同的同名条目、Windows 保留名条目、声明大小撑爆的 zip 炸弹、深嵌套 plist。
- 夹具里的域名一律用 `*.evil-synthetic.test` 之类合成占位，地址用保留段，与既有合成样本同口径。
- 必测用例（每期对应部分）：Info.plist 解析 / mobileprovision 三类签名判定 / UDID 不进 digest / Mach-O 边界与 cryptid / 路径穿越与 zip 炸弹被拒且被计数 / Android 专属分析器在 iOS 上 `skipped` 且不计入 completeness / iOS 的 `dex_available=False` 不触发加固告警 / 下载上限与 SHA-256 / 重定向与 SSRF 与 DNS rebinding 防护（本地 mock server，**不连外网**，CI 在 HTTP 目标层本就拒绝外网）/ `blocked` 与 `not_found` 状态不混淆。

### 7.2 每期验收命令（三关必过，不得只跑其中一关）

```bash
python -m ruff check apkscan tests
python -m pyright apkscan
python -m pytest -q
python -m apkscan.cli leak-scan --base origin/master --strict
```

另需：
- `python -m pytest -q tests/test_architecture_boundaries.py`：确认 `ipa.py` / `macho.py` / `download.py` 没有反向依赖，分析器未直接 import 它们。
- 并行一致性：iOS 样本也要满足「串行 == 并行 逐字节一致」（`FXAPK_NO_PARALLEL=1` 跑一遍对比）。
- `python -m apkscan.cli selfcheck` 不因新增平台报错。
- 文档：`CHANGELOG.md` 记一条，说明本期**实际**做到哪一步；**不得**写成"已支持 iOS 分析"——1.2.0（#215）删掉旧 IPA 支持的理由正是"只做了 Info.plist 与 Mach-O 字符串提取、没有真实用例"，本期在拿到真实样本验收前同样不能对外宣称完成。

## 8. 已否决的方案（不要再提）

- **macOS 原生工具链**（`codesign` / `security cms` / `otool`）：目标环境是 Windows，不可用。
- **PlayCover 动态运行**：需要 Apple Silicon 的 Mac，环境不具备。
- **伪造 UDID 换取超级签包**：主动欺骗嫌疑服务器、会在对方开发者账号登记假设备、可能打草惊蛇；只有在单独、显式的授权下才作为独立功能讨论，不进本期。
- **验签 `embedded.mobileprovision` 并据此判"合法"**：Apple 根证书链的本地校验结果不构成取证结论，反而容易被读成"这个包是正规的"。
- **把 iOS 字符串当 DEX 字符串喂进既有链路**（`dex_strings()` 返回 Mach-O 字符串）：会让所有 DEX 判据与 visibility 口径对不上，等于伪造观察面。
- **把 Android 真机的运行时证据标成 iOS 证据**：直接违反证据闭环口径。
