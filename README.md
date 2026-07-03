# fxapk

[![CI](https://github.com/s-silt/fxapk/actions/workflows/ci.yml/badge.svg)](https://github.com/s-silt/fxapk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

*CLI 命令 `fxapk`（亦保留 `apkscan` 别名）；PyPI 包名 `fxapk`。* · **English**: [README.en.md](README.en.md)

> APK / iOS IPA **静态 + 动态分析 CLI** —— 提取应用真实配置、网络端点、第三方组件与加固指纹，
> 对域名 / IP 做归属富化，输出**结构化分析报告**；跨样本关联聚类。

`pip install` 即可运行核心功能，**零环境**（不需要 JDK / 模拟器 / 真机）。它抠出 App 里
**真实配置的 key 值**（AppID / AppKey / AppSecret / 渠道号 / uni-app 应用 ID），识别第三方 SDK
与加固厂商并映射到**注册主体 / 服务提供商**，对域名 / IP 做**归属分类**，把应用自有后端从
成百上千条库 / CDN 基础设施噪音里区分出来。

**识别维度**：后台管理入口、聚合支付平台标识、短信 / 验证码转发服务、特定供应链关键词、
自建 IM / 疑似控制信道、链上钱包私钥 / 助记词、硬编码后端凭据、运行时 hook / 反检测能力、
native 混淆特征。分析过的样本可持久化进**本地关系图谱**（嵌入式 Kuzu），跨样本 / 跨批次
**关联聚类**（`fxapk graph`，输出稳定 JSON 供程序 / agent 消费）；每条后端端点还按
**服务器归属地**自动分类——**境内**服务器 → 归属注册主体（境内云 / IDC / ICP）；
**境外**服务器 → **被动定位真实源站 IP + 提取标识**（RDAP / DNS / ASN / 证书透明度 / 历史解析
穿透 CDN），全程被动、不主动探测、不接触目标。

> 用途声明：本项目为**授权范围内的安全研究 / 分析**用途，仅做静态 / 动态分析与信息提取，
> **不提供任何针对第三方的攻击 / 漏洞利用 / 主动探测能力**。请在合法授权范围内使用。

---

## 它产出什么（核心区别）

普通工具只告诉你「检测到某推送 SDK」；fxapk 给你 **具体配置值 + 所属主体 + 归属分类**：

```
配置键值（CONFIG_KEY）
  PUSH_APPID     = aBcD1234EfGh5678        → 推送服务商（示例）        [应用自有·重点]
  PUSH_APPSECRET = zZ9yX8wV7uT6sR5q        → 推送服务商（示例）        [强凭据]
  UNIAPP_ID      = __UNI__A1B2C3D          → 跨端框架服务商（示例）    [重点]
   （示例值，均已脱敏）

应用自有 / 疑似后端域名（重点）
  *.api-xxxxx.vip        归属：注册商 / ICP 备案 / 云厂商
第三方基础设施（可忽略，默认折叠）
  map / 推送 / 公共 CDN 等共享域名 …

归属说明：凭上述配置值可追溯服务商侧的注册主体与应用注册信息。
```

实际渲染的 HTML 报告（**演示数据，已脱敏**）：

![报告示例](docs/images/report-demo.png)

---

## 安装

要求 **Python 3.11+**。

```bash
# 从 PyPI
python -m pip install fxapk

# 或从源码
git clone https://github.com/s-silt/fxapk.git
cd fxapk
python -m pip install -e .
```

核心依赖：`androguard`（解析 APK）、`jinja2`、`typer`、`python-whois`、`requests`、`pyyaml`、`psutil`（分析器进程池按可用内存封顶 worker 数防 OOM）。

> 单元测试**不依赖 androguard、不联网、不需要真机 / jadx / frida**（全部基于 `FakeContext` 合成数据）：
> ```bash
> python -m pip install jinja2 typer python-whois requests pyyaml pytest
> python -m pytest -q          # 跑全部单元测试（离线、不需真机）
> ```

可选依赖（缺失时对应能力**优雅降级**，核心不受影响、不报错）：

| 可选项 | 启用的能力 |
|---|---|
| `jadx`（PATH 外部命令） | `jadx` 深度反编译增强器，从反编译 Java 字面量补 androguard 漏掉的端点 / 密钥（不可用则自动跳过并在报告标注）。装好 `jadx` 在 PATH 即自动调用 |
| `frida-tools` + `frida-dexdump` | `unpack` 真机脱壳 |
| `mitmproxy` | `capture` 真机抓包流量解析 |
| `cryptography` | 自动解密抓到的 `{data,timestamp}` 加密信封（缺失则只报配方 + 保留密文，不崩） |
| `kuzu`（`pip install fxapk[graph]`） | 本地关系图谱关联（`fxapk graph` 子命令）；缺失时仅 `graph` 命令提示安装，核心分析不受影响 |
| `flask`（`pip install fxapk[track]`） | `fxapk track` 本地 / 局域网网页看结果 + 进度；缺失时仅 `track` 命令提示安装，台账写入与自动入账不受影响 |
| `apksigner` + `zipalign`（Android SDK build-tools） | `repackage` 去壳重打包重签名；缺失时该步 `skipped` 给手册，不影响其它 |
| Chrome / Edge / Chromium | `--fmt pdf` 报告导出（无头打印） |

---

## 快速开始

```bash
# 默认：联网富化归属，产出 HTML + JSON 到 out/
fxapk analyze app.apk --out out

# 离线（不联网），加导出 PDF
fxapk analyze app.apk --out out --offline --fmt html,json,pdf

# 只产 JSON（机器读 / 留档）
fxapk analyze app.apk --fmt json
```

**一键全自动**（接好真机 / 模拟器后，把体检→静态→脱壳→去壳重打包→抓包→合并串成一条）：

```bash
# 接上设备后先体检（缺 frida-server / CA 等可自动修，修不了给可复制命令）
fxapk doctor

# 一键：doctor → 静态 → 脱壳 → 去壳重打包 → 抓包（提示你在设备上操作 app）→ 合并一份总报告
fxapk auto app.apk --out out
# 无设备也能跑：自动跳过脱壳 / 抓包，仍产出静态报告
```

未安装为命令时等价用：`python -m apkscan.cli analyze app.apk --out out`。

### 命令一览

| 命令 | 作用 |
|---|---|
| `analyze APK` | 静态分析（零环境）产出结构化线索清单；加 `--dynamic` 且有设备时自动脱壳 + 抓包，并把运行时端点**并回主报告** |
| `auto APK` | 一键全自动：`doctor`→静态→脱壳→去壳重打包→抓包→合并一份总报告（无设备自动跳过动态步骤） |
| `doctor` | 环境体检：在线设备 / root / ABI / 主机 frida 版本 / 设备 frida-server / mitmproxy / CA 逐项 `[OK]`/`[FAIL]`，`--fix` 自动修（部署 frida-server、装 CA），关键项失败时退出码 1 |
| `unpack APK` | 真机脱壳：frida-dexdump dump 隐藏 DEX 回灌重分析 |
| `capture PACKAGE` | 真机抓包：mitmproxy + frida 绕证书绑定，抓运行时端点 |
| `repackage APK` | 脱壳后把**去壳版**重打包（zip 替 DEX + apksigner 重签）装回设备，使抓包抓**去壳版**（绕壳反 frida / 反调试）；`auto` 默认含此步（`--no-repackage` 关）。需 apksigner/zipalign + 设备；**四联判活**确认起得来才算成功、失败优雅降级回原版抓包。治不了 VMP / 重 native / 反模拟器壳 |
| `batch DIR` | 批量分析文件夹下所有 APK + 跨样本关联聚类（写 `case_correlation.json`），并持久化进本地关系图谱 |
| `letters REPORT.json` | 把结构化线索套打成**文书草稿**（markdown，带免责标注） |
| `probe-leads probe.log` | 把独立 frida 探针（[`docs/codex/frida-probes/`](docs/codex/frida-probes/)）`-l` 注入吐的 `[LEAD]` 散点聚成**结构化台账**（按类别分组 + 归属 + 完备性三轴诊断）；`--into report.json` 回灌进报告 leads，`--md`/`--json` 落盘 |
| `pcap-leads capture.pcap` | 从**带外 pcap**（网关 tcpdump / PCAPdroid 免 root / Wireshark）抽 **接入节点 IP:port + TLS SNI + DNS + JA3**——反 frida / pinning / 自建协议等普通抓包 `endpoint=0` 时，带外拿 IP/SNI 即穿透锚点（**解不开也有产出**）。纯标准库解析（零依赖）；`--into report.json` 回灌。见 [`capture-methods-beyond-frida.md`](docs/codex/capture-methods-beyond-frida.md) |
| `capture-plan report.json` | 据静态报告的规避信号（加固 / `endpoint=0` / 加密配方 / 自建 IM / 反检测工具）输出**针对该样本的抓包打法**（起手式带外 pcap → 脱壳 + 反检测 → native / pcap-leads / tls-keylog → 自建协议 → 静态去 pin → 回灌关联） |
| `digest REPORT.json` | 把 report.json 压成**紧凑摘要 JSON** 打到 stdout（按优先级排序、扁平字段，供任意 AI agent / 脚本低 token 直接决策；默认明文便于查看，`--redact` 喂云端 agent 时脱敏高敏值） |
| `selfcheck` | **自检诊断 JSON**：逐项报告各能力（图谱 / 解密 / jadx / 动态 / 联网富化 / web-check）通不通、怎么修——供任意 AI agent 驱动前自检 |
| `graph …` | 本地关系图谱关联（需 `fxapk[graph]`）：`ingest`（报告入图）/ `link <sha256>`（拉关联 APK）/ `query --kind --value`（按实体反查）/ `cluster`（聚类簇 + 置信分）/ `stats` / `cypher`（原始 Cypher）。默认输出稳定 JSON |
| `track` | 起**本地 / 局域网网页**追踪每个 APK 发现的线索 + **手动进度**（两级：APK 总进度 + 每条线索状态 / 备注 / 带时间戳进展留痕，需 `fxapk[track]`）；`analyze`/`auto` 默认自动入台账（`--no-track` 关）。`track ingest <report.json…>` 回填历史报告。台账在 `~/.apkscan/tracking.json`（仓库外，`git pull` 不覆盖） |

### 常用参数

| 参数 | 说明 |
|---|---|
| `--out DIR` | 报告输出目录（默认 `out`） |
| `--fmt html,json,pdf` | 输出格式，逗号分隔（默认 `html,json`；`pdf` 需 Chrome/Edge） |
| `--online` / `--offline` | 是否联网富化 WHOIS / ICP 备案 / IP-ASN（默认联网） |
| `--extra-dex PATH` | 并入脱壳 dump 出的 `.dex`（文件或目录）一起静态分析 |
| `--dynamic` | 静态分析后若探测到在线设备，自动跑 `unpack` + `capture` |

---

## 输出

- `out/report.html` —— 自包含单文件（CSS 内联，可直接分享 / 手机打开）
- `out/report.json` —— `Report` 完整序列化（机器读 / 二次处理）
- `out/report.pdf` —— `--fmt pdf` 时由本机 Chrome/Edge 无头打印生成

**报告版式**：概览（含加固 / uni-app 加密标记）→ **★调用插件 / 配置键值（具体值）**
→ 应用自有域名（重点）/ 第三方基础设施（折叠）→ 支付 · SDK · 联系方式 · 加固 · 签名线索
→ 网络端点全表（WHOIS/ICP/ASN 富化、明文 / 内网标记）→ 技术附录（权限 / 组件 / 证书 / crypto / 密钥）
→ 分析器与富化器运行状态（ran/skipped/error，透明不吞错）。

---

## 分析能力一览

**静态分析器（零环境，自动发现）**

| 分析器 | 产出 |
|---|---|
| `config_keys` ★ | manifest `<meta-data>` + uni-app 配置抠真实 `key=value`，映射注册主体；敏感凭据产 HIGH Finding |
| `sdk_fingerprint` | 第三方 SDK 指纹 → 服务商（支付 / 短信 / 推送 / 云存储 / IM / 统计 / 地图） |
| `payment` | 聚合支付 / 收款 / 商户号 / USDT / 钱包地址标识 |
| `admin_panel` | 后台管理系统 / 控制台入口（host 子域 + `/admin`、`/api/admin/`、wp-admin 等）→ 运营控制端，指明后端服务器与运营日志 |
| `fourth_party_payment` | 聚合 / 第三方支付平台标识（补主流支付盲区） |
| `sms_forwarding` | 短信 / 验证码转发服务标识（排除正规短信 SDK，只认接收 + 转发型） |
| `card_merchant` | 特定供应链 / 服务关键词标识（研判，默认待核） |
| `self_hosted_im` | 自建 IM / 疑似控制信道（硬编码非白名单 ws/wss/mqtt/xmpp 服务器 + IM 库指纹；排除公共推送 / MQTT） |
| `wallet_secret` | 钱包私钥 / 助记词（BIP-39 校验和 / WIF / 上下文门控 EVM 裸私钥）→ 高敏物证 |
| `backend_credential` | 硬编码后端 / 管理凭据（Basic-Auth / DB 连接串 / JDBC / 云 AccessKey）——**被动静态提取，不向任何远程服务器发起连接** |
| `endpoints` | dex / 资源 / native / manifest 全量抽 URL / 域名 / IP（严格降噪） |
| `js_bundle` | uni-app / H5 / RN 打包 JS **字符串字面量内**精确抽端点 + 硬编码密钥 |
| `crypto_recipe` ★ | 从打包 JS 反查应用层加密配方（CryptoJS AES/DES 算法 / 硬编码 key/iv 推导 / `{data,timestamp}` 信封）→ 凭此离线解密加密流量 |
| `re_toolkit` | 识别样本内置的**运行时 hook 框架 / 反调试 / 反分析能力**（防御性识别，不含任何利用能力）→ 研判是否具备运行时行为改写能力、**预判动态观测可行性**（内置直 syscall 类反检测时提示 frida 观测可能被绕过），并作技术画像关联 |
| `native_obfuscation` | native `.so` **加密 / 虚拟化启发式**（高熵 + 几乎无可读串）→ 提示原生逻辑静态不可得、宜转运行时观测；作技术画像关联（启发式信号，非精确判定，合法 DRM 亦可能） |
| `jadx` | （需 jadx）深度反编译补端点 / 密钥 |
| `packing` | 加固识别（主流商业加固厂商 + 开源自研壳）；**证据分级**：`.so` / 特征文件才判已加固，仅 dex 名词命中降级为提示，避免误报 |
| `certificate` | 签名证书 → 跨样本关联同一开发者 |
| `contacts` | QQ / 微信 / Telegram / 邮箱 / 手机号（带去误报） |
| `permissions` / `components` / `manifest` / `crypto` | 危险权限 / 导出组件 / 基础指纹 / 弱加密 |
| `ios_plist` ★ | （iOS IPA）解析 `Info.plist` → 显示名 / URL scheme 声明 / ATS 明文 HTTP / 支付 SDK 探测 / 敏感权限用途 |

> **iOS IPA**（多为 H5 壳）：传 `.ipa` 给 `fxapk analyze` 即按文件类型自动分流到**纯静态**分析，
> 复用 `endpoints` / `js_bundle` / `crypto_recipe` 等平台无关分析器 + `ios_plist`，从 `Payload/<App>.app/www/`
> 的 H5 包抠端点与加密配方，从 `Info.plist` 抠标识 / URL scheme / 权限用途 —— **不连设备、无需越狱**（Android 专属分析器在 IPA 上自动跳过）。

**富化器（默认联网，`--offline` 可关，结果缓存，对可疑端点**并发**查询提速）**：`rdap`（HTTPS 查注册商 / 注册时间 / 状态 / NS，比 port-43 whois 更可靠，失败自动回退 `whois`）、`whois`（注册人 / 注册商，作 rdap 兜底）、`icp`（ICP 备案主体）、`dns`（DoH 解析域名→IP 并查托管云厂商，定位真实后端）、`asn`（IP 归属云厂商 / IDC）、`webcheck`（**opt-in**：设环境变量 `FXAPK_WEBCHECK_URL` 指向自托管 web-check 实例后，对每个重点域名 / IP 再查一轮 OSINT——服务器地理 / SSL / DNS / 技术栈 / 开放端口 / 邮件配置 / 子域，结果进 `enrichment['webcheck']` 并喂**归属地分类**、**境外源站被动归属**（端口 / 技术栈作识别信号）、**关联**（子域 / 关联主机）；可用 `FXAPK_WEBCHECK_CHECKS` 定制检查项）。

**端点归属分级**（`core/infra.py`）：命中公有云 / 主流 SDK / 开源 CDN / 标准协议 / 运营商域名 → 「第三方基础设施」；私网 / 无效 → 「待核」；其余疑似 App 自有 → 「重点」。

---

## 真机动态补全（doctor / auto / unpack / capture）

已加固 App（DEX 加密、运行时还原）静态拿不到真实后端，需要在 root 真机 / 模拟器上脱壳 + 抓包。
**接好设备后推荐直接用一键 `fxapk auto`**；也可分步：

```bash
fxapk doctor                            # 环境体检：设备 / root / ABI / frida-server / CA 逐项检查，可自动修
fxapk auto app.apk --out out            # 一键：doctor→静态→脱壳→去壳重打包→抓包→合并一份总报告
fxapk unpack app.apk --out out          # 单独脱壳：frida-dexdump dump 隐藏 DEX，回灌重分析
fxapk repackage app.apk --out out       # 去壳重打包：脱壳 DEX 装回去壳版供抓包（auto 默认含；--no-repackage 关）
fxapk capture <package> --duration 60   # 单独抓包：mitmproxy + frida 绕证书绑定，抓运行时端点
```

**自动配环境**：`doctor`（及 `auto` 内部）能按设备 ABI + 主机 frida 版本**自动下载部署 frida-server**、**安装 mitmproxy CA 到系统信任库**（纯标准库下载，root 写入；装不了则如实降级并给命令——HTTPS 抓明文的命门绝不假成功）。
**去壳重打包（`repackage`，`auto` 默认含、`--no-repackage` 关）**：加固壳的反 frida / 反调试会让抓包抓不到去壳后逻辑。脱壳得到 DEX 后用 zipfile 把它替回原 APK 的 `classes*.dex`、`zipalign` + `apksigner` 重签、卸原包装去壳包，并经**四联判活**（装上 + `am start` + 进程存活非秒退 + frida 可附）确认起得来才算成功——装上起不来**绝不假成功**，优雅降级重装原包让抓包仍跑原版。需 apksigner/zipalign（Android SDK build-tools）+ 设备；治不了 VMP / 重 native / 带完整性自校验 / 反模拟器壳（多数样本预期降级）。
**运行时端点并回主报告**：`auto` / `analyze --dynamic` 会把抓到的运行时端点（`source=runtime`）并入同一张线索清单并重渲报告。
**无设备 / 缺工具时不报错**：相关步骤 `status=skipped` + 打印**可逐条复制的手册**；静态报告照常产出。脱壳得到的 DEX 也可用 `fxapk analyze app.apk --extra-dex <dump_dir>` 手动并入。

> ⚠️ **单设备假设**：`auto` / `capture` / `unpack` 假定**只接了一台目标设备**。同时在线多台设备时，
> adb 会作用到默认设备上（设全局代理、reverse 等可能打到非目标机且不还原）。请**只连目标设备**，
> 或先 `adb disconnect` / 拔掉其它设备再跑（多设备 `-s <serial>` 定向是后续计划项）。
>
> 设备 / 模拟器接入要点（adb 连接、root、ARM 兼容、frida 版本一致、CA 安装）见 [docs/dynamic-setup.md](docs/dynamic-setup.md)。
> 云端方案：在 root 真机 / 云手机（原生 ARM 安卓）上跑 frida-server，本工具部署在小 Linux VM 上经 ADB 驱动即可。

---

## 关系图谱关联 + 归属地分类

**本地关系图谱（`fxapk graph`，需 `pip install fxapk[graph]`）**：把每次分析的样本与强指纹（签名
证书 / 控制信道 / uni-appid / 收款地址 / 后台 host / 自建 IM 服务器 / 钱包凭据 …）持久化进嵌入式 Kuzu
属性图，**跨样本、跨批次**碰撞关联——同签名 = 同打包账号、同后台 / 收款 = 同后端与运营基础设施、
同钱包助记词 = 同操作者。`batch` 跑完自动入图；也可手动驱动（默认输出稳定 JSON，供程序 / agent 消费）：

```bash
fxapk graph ingest out/                     # 报告入图（batch 已自动入图）
fxapk graph link <sha256>                   # 拉出与该 APK 共享强实体的关联 APK（按权重排名）
fxapk graph cluster --min-shared 1          # 全图聚类簇 + 关联依据 + 置信分
fxapk graph query --kind sign --value <X>   # 反查：哪些 APK 用了这个指纹
fxapk graph stats                           # 图谱体检（节点 / 边 / 各 kind 计数）
```

**服务器归属地分类**：每条「重点」后端端点按富化归属国（ICP / whois 注册国 / IP ASN）自动
判归属地并附路径——**境内**服务器 → 归属注册主体（境内云 / IDC / ICP）；**境外**服务器 →
**被动定位真实源站 IP + 提取标识**：经 RDAP / whois / DNS / ASN / 证书透明度（crt.sh 子域）/
历史解析穿透 CDN，识别真实源站归属、技术栈指纹与关联子域用于关联，
**全程被动、对目标零流量、不主动探测 / 不攻击**。

> 硬编码后端凭据（被动提取）：`backend_credential` 从**样本自身**里抠出它硬编码的后端 / 管理
> 凭据——**只做静态提取，不向任何远程服务器发起连接**。

---

## 结果追踪 + 进度管理（track，本地 / 局域网网页）

分析只是起点，线索要**跟进**。`fxapk track` 起一个本地 / 局域网网页，集中看**每个 APK 发现的线索**并**手动记进度**——两级：APK 总进度（待处理 / 进行中 / 已归档 / 已完成）+ 每条线索状态（待办 / 已处理 / 已收数据 / 无果 / 忽略）+ 备注 + 带时间戳的进展留痕（预设词表，也可自定义）。

- **自动入账**：`analyze` / `auto` 跑完自动把该样本的线索写进台账（`--no-track` 关），合并时**保留你手改的状态 / 备注 / 进展**（重分析不覆盖）、新线索默认「待办」；同时顺带喂关系图谱（kuzu 可用时）。也可 `fxapk track ingest <report.json…>` 回填历史报告。
- **台账位置**：`~/.apkscan/tracking.json`（用户主目录、仓库之外，`git pull` / 重新 clone 都不覆盖你的数据）；`--ledger PATH` / 环境变量 `FXAPK_TRACKING_DB` 可改。
- **起网页**（需 `pip install fxapk[track]`，flask）：

```bash
fxapk track                       # 仅本机：http://127.0.0.1:8787
fxapk track --host 0.0.0.0        # 局域网共享：打印含访问令牌的 http://<本机IP>:8787/?token=...
```

  局域网共享自动启用**令牌鉴权**（台账含敏感信息，信任内网才 `--no-auth` 关）；多人查看 / 编辑按条更新落盘。

---

## 对接任意 AI agent（诊断 / 隐私 / agent 无关）

fxapk 的产出与控制面是**标准 JSON CLI**——agent（任意）直接 shell 调命令、解析 stdout JSON 即可驱动，不绑定任何单一 agent，也无需额外协议层：

- **自检诊断**：`fxapk selfcheck` 逐项报告各能力（图谱 / 解密 / jadx / 动态脱壳抓包 / 联网富化 / web-check）的状态（`ok` / `missing` / `disabled` / `unreachable`）+ 一句话修复指引。agent 跑之前先自检、按结果选路或提示用户装依赖，而非试错。
- **紧凑摘要**：`fxapk digest` 给按优先级排序的扁平 JSON，低 token 直接决策；要细节再读本地完整报告。
- **图谱关联**：`fxapk graph`（含只读 `cypher` 逃生口）默认输出稳定 JSON，供 agent 关联聚类。
- **隐私安全**：digest **默认明文**（查看需要看到钱包私钥 / 凭据等实际值）；要把摘要喂可能经云端模型处理的 agent 时用 `fxapk digest --redact`，对高敏值（钱包私钥 / 助记词、后端凭据、运行时登录态、敏感个人信息、加密配方）脱敏，明文始终在本地完整 `report.json`。联网富化默认仅查「重点」端点、缩小查询足迹；web-check 走**本地实例**；ip-api 明文 HTTP 风险见下方隐私提示。

---

## 项目结构

```
apkscan/
  core/       models / context / apk(androguard) / ipa / loader / registry(自动发现) / pipeline / infra / forensic(归属地分类) / redact(脱敏) / chainaddr / walletsecret / device
  selfcheck.py 自检诊断（AI 友好：能力 / 连通 / 修复指引）
  analyzers/  29 个静态分析器（见上表；含 iOS `ios_plist`，按 requires 能力门控自动分流 APK/IPA）
  graph/      本地关系图谱（嵌入式 Kuzu）：store / ingest / query / schema / weight（`fxapk graph` 关联）
  enrichers/  rdap / whois / icp / dns / asn / webcheck(opt-in OSINT)（默认联网，结果缓存）
  dynamic/    doctor / provision / unpack / repackage(去壳重打包) / capture / merge(运行时并回 + 会话时序) / correlate(聚类) / batch(批量) / fingerprint / auto(一键编排)
  track/      结果追踪台账 + 进度（ledger）+ 本地 / LAN 网页（web, flask 可选 extra）+ 自动入账(autoingest)
  report/     html / json / pdf / ioc(IOC CSV) / letters(文书草稿) / digest(紧凑摘要) + templates/
  rules/      *.yaml + bip39_english.txt（SDK / 加固 / 支付 / 配置键 / 权限 / 词表等规则库）
tests/        单元测试（FakeContext，离线，不需真机 / 网络）
docs/         文档
```

---

## 合规边界

本工具仅用于**授权的安全研究 / 分析**，只做分析与信息提取，**不提供任何针对第三方服务器的攻击 / 漏洞利用 / 主动探测能力**；
加固只识别不脱壳（脱壳为可选的真机步骤，只对**样本自身**在分析机上运行时观测，需操作者自备授权环境）。
境外服务器只做**被动归属**（RDAP / WHOIS / ICP 备案 / ASN / DNS / 证书透明度），定位真实源站 IP 与标识，
**绝不主动探测 / 不攻击任何第三方基础设施**。请在合法授权范围内使用。

> ⚠️ **隐私提示**：ASN 富化走 ip-api 免费档（**明文 HTTP**，免费档不支持 HTTPS），被查 IP
> 会以明文经过在途节点，暴露"正在核查哪个目标"的意图。敏感目标请用 `--offline` 关闭联网富化，
> 或自行接入支持 HTTPS 的权威源。WHOIS/ICP 走各自库 / 接口，不在此列。

## License

[MIT](LICENSE)
