# fxapk

[![CI](https://github.com/s-silt/fxapk/actions/workflows/ci.yml/badge.svg)](https://github.com/s-silt/fxapk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

*CLI 命令 `fxapk`（亦保留 `apkscan` 别名）；PyPI 包名 `fxapk`。* · **English**: [README.en.md](README.en.md)

> 面向**反诈调证**的 APK / iOS IPA 静态分析 CLI —— 不止列出 IP/域名，而是产出**调证线索清单**：
> 每条线索回答「**这是什么、归属哪家公司、能去找谁调取什么证据**」。

`pip install` 即可运行核心功能，**零环境**（不需要 JDK / 模拟器 / 真机）。专为涉诈 App 取证设计：
抠出 App 里**真实配置的 key 值**（AppID / AppKey / AppSecret / 渠道号 / uni-app 应用 ID），
识别第三方服务与加固厂商并映射到**可调证主体**，对域名/IP 做**「是否建议调证」分级**，
把真正的诈骗服务器从成百上千条库/CDN 噪音里浮出来。

**线索维度已扩展**到：后台管理系统、四方支付 / 跑分平台、短信验证码转发、卡商 / 料商、自建 IM/C2
信道、链上钱包私钥 / 助记词、硬编码后端凭据。分析过的样本可持久化进**本地案件图谱**（嵌入式 Kuzu），
跨样本 / 跨批次**串并团伙**（`fxapk graph`，输出稳定 JSON 供 Codex / 程序消费）；每条后端线索还按
**服务器辖区**自动分流取证路径——**国内**服务器→依法调证（向境内云 / IDC / ICP 调日志、租户实名）；
**国外**服务器→以漏洞获取服务器**镜像 / 日志**为主（被动情报指引，非主动攻击）。

---

## ⬇️ 下载即用（新手，无需装 Python）

不想碰命令行？到 **[Releases](https://github.com/s-silt/fxapk/releases/latest)** 下载
`fxapk-gui-vX.Y.Z-win64.zip`（64 位 Windows **自包含**包，内置 frida / mitmproxy / adb，**无需另装任何东西**）：

1. 下载并**解压出整个 `fxapk-gui` 文件夹**（依赖在 `_internal/`，别只拷 exe）。
2. 双击 **`fxapk-gui.exe`** → 在「APK（Android）」或「IPA（iOS）」栏选文件 → 点「静态分析」（APK 还可「一键全自动」；iOS IPA 仅静态、无需越狱）。
3. 要脱壳 / 抓包（仅 Android）：USB 接好**已 root 的手机或模拟器**（adb 已内置）→ 点「环境体检」自动配 frida-server 与证书 → 再「一键全自动」。
4. *(可选)* 想要更深的 jadx 反编译补漏：下载 **`fxapk-jadx-*.zip`**（自带便携 JRE，无需另装 Java）→ 点界面「🔌 启用 jadx」选这个 zip → 一键启用，之后静态/一键全自动自动用上 jadx。

> ⚠️ 未签名，首次运行 Windows SmartScreen / 杀软可能拦，点「更多信息 → 仍要运行」或加白名单。
> frida-server 由程序按设备 ABI 自动推到手机，无需手动准备。整个文件夹一起拷贝。

开发者 / 命令行用户走下面的 `pip install`。

---

## 它产出什么（核心区别）

普通工具告诉你「检测到个推 SDK」；fxapk 告诉你 **具体值 + 所属公司 + 调证建议**：

```
调用插件 / 配置键值（CONFIG_KEY）
  GETUI_APPID    = aBcD1234EfGh5678        → 每日互动股份有限公司（个推）     [建议调证]
  PUSH_APPSECRET = zZ9yX8wV7uT6sR5q        → 每日互动股份有限公司（个推）     [建议调证·强凭据]
  __UNI__        = __UNI__A1B2C3D          → 数字天堂（北京）网络技术有限公司（DCloud） [建议调证]
   （示例值，已脱敏）

主控域名（建议调证 —— App 自有/疑似 C2）
  *.api-xxxxx.vip        建议调证：向注册商 / ICP 备案 / 云厂商调归属与租户
通联域名 / IP（无需调证 —— 已知基础设施，默认折叠）
  api.map.baidu.com / *.myqcloud.com / getui.net …

调证建议：凭上述 AppSecret 向【个推】调开发者账号实名、应用注册主体、推送下发记录。
```

实际渲染的 HTML 报告（**演示数据，已脱敏**）：

![apkscan 报告示例](docs/images/report-demo.png)

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

> 单元测试**不依赖 androguard、不联网、不需要真机/jadx/frida**（全部基于 `FakeContext` 合成数据）：
> ```bash
> python -m pip install jinja2 typer python-whois requests pyyaml pytest
> python -m pytest -q          # 跑全部单元测试（离线、不需真机）
> ```

可选依赖（缺失时对应能力**优雅降级**，核心不受影响、不报错）：

| 可选项 | 启用的能力 |
|---|---|
| `jadx`（PATH 外部命令 **或** 独立插件包） | `jadx` 深度反编译增强器，从反编译 Java 字面量补 androguard 漏掉的端点/密钥（不可用则自动跳过并在报告标注）。GUI 用户**无需装 Java**：下载独立插件包 `fxapk-jadx-*.zip`（自带便携 JRE），点界面「🔌 启用 jadx」选 zip 即一键启用，之后静态/一键全自动自动调用 |
| `frida-tools` + `frida-dexdump` | `unpack` 真机脱壳 |
| `mitmproxy` | `capture` 真机抓包流量解析 |
| `cryptography` | C5b 自动解密抓到的 `{data,timestamp}` 加密信封（缺失则只报配方+保留密文，不崩） |
| `kuzu`（`pip install fxapk[graph]`） | 本地案件图谱串案（`fxapk graph` 子命令）；缺失时仅 `graph` 命令提示安装，核心分析不受影响 |
| `flask`（`pip install fxapk[track]`） | `fxapk track` 本地/局域网网页看线索 + 办案进度；缺失时仅 `track` 命令提示安装，台账写入与自动入账不受影响 |
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

**一键全自动**（接好真机/模拟器后，把体检→静态→脱壳→去壳重打包→抓包→合并串成一条）：

```bash
# 接上设备后先体检（缺 frida-server / CA 等可自动修，修不了给可复制命令）
fxapk doctor

# 一键：doctor → 静态 → 脱壳 → 去壳重打包 → 抓包（提示你在设备上操作 app）→ 合并一份总报告
fxapk auto app.apk --out out
# 无设备也能跑：自动跳过脱壳/抓包，仍产出静态报告
```

未安装为命令时等价用：`python -m apkscan.cli analyze app.apk --out out`。

### 命令一览

| 命令 | 作用 |
|---|---|
| `analyze APK` | 静态分析（零环境）产出调证线索清单；加 `--dynamic` 且有设备时自动脱壳+抓包，并把运行时端点**并回主报告** |
| `auto APK` | 一键全自动：`doctor`→静态→脱壳→去壳重打包→抓包→合并一份总报告（无设备自动跳过动态步骤） |
| `doctor` | 环境体检：在线设备 / root / ABI / 主机 frida 版本 / 设备 frida-server / mitmproxy / CA 逐项 `[OK]`/`[FAIL]`，`--fix` 自动修（部署 frida-server、装 CA），关键项失败时退出码 1 |
| `unpack APK` | 真机脱壳：frida-dexdump dump 隐藏 DEX 回灌重分析 |
| `capture PACKAGE` | 真机抓包：mitmproxy + frida 绕证书绑定，抓运行时端点 |
| `repackage APK` | 脱壳后把**去壳版**重打包（zip 替 DEX + apksigner 重签）装回设备，使抓包抓**去壳版**（绕壳反 frida/反调试）；`auto` 默认含此步（`--no-repackage` 关）。需 apksigner/zipalign + 设备；**四联判活**确认起得来才算成功、失败优雅降级回原版抓包。治不了 VMP/重 native/反模拟器壳 |
| `batch DIR` | 批量分析文件夹下所有 APK + 跨样本团伙聚类（写 `case_correlation.json`），并持久化进本地案件图谱 |
| `letters REPORT.json` | 把可办案化线索套打成「调证函 / 协查文书」草稿（markdown，带免责标注） |
| `digest REPORT.json` | 把 report.json 压成**紧凑调证摘要 JSON** 打到 stdout（按优先级排序、扁平字段，供任意 AI agent / 脚本低 token 直接决策；默认明文便于取证查看，`--redact` 喂云端 agent 时脱敏高敏值） |
| `selfcheck` | **自检诊断 JSON**：逐项报告各能力（图谱/解密/jadx/动态/联网富化/web-check）通不通、怎么修——供任意 AI agent 驱动前自检 |
| `graph …` | 本地案件图谱串案（需 `fxapk[graph]`）：`ingest`（报告入图）/ `link <sha256>`（拉关联 APK）/ `query --kind --value`（按实体反查）/ `cluster`（团伙簇+置信分）/ `stats` / `cypher`（原始 Cypher）。默认输出稳定 JSON |
| `track` | 起**本地/局域网网页**追踪每个 APK 发现的线索 + **手动办案进度**（两级：APK 总进度 + 每条线索状态/备注/带时间戳进展留痕，需 `fxapk[track]`）；`analyze`/`auto` 默认自动入台账（`--no-track` 关）。`track ingest <report.json…>` 回填历史报告。台账在 `~/.apkscan/tracking.json`（仓库外，`git pull` 不覆盖） |
| `gui` | 图形界面（tkinter 单窗口：体检 / 静态 / 一键全自动） |

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

- `out/report.html` —— 自包含单文件（CSS 内联，可直接分享/手机打开）
- `out/report.json` —— `Report` 完整序列化（机器读 / 二次处理）
- `out/report.pdf` —— `--fmt pdf` 时由本机 Chrome/Edge 无头打印生成

**报告版式（按调证视角）**：概览（含加固/uni-app 加密标记）→ **★调用插件/配置键值（具体值）**
→ 主控域名（建议调证）/ 通联域名·IP（无需调证，折叠）→ 支付·SDK·联系方式·加固·签名线索
→ 网络端点全表（WHOIS/ICP/ASN 富化、明文/内网标记）→ 技术附录（权限/组件/证书/crypto/密钥）
→ 分析器与富化器运行状态（ran/skipped/error，透明不吞错）。

---

## 分析能力一览

**静态分析器（零环境，自动发现）**

| 分析器 | 产出 |
|---|---|
| `config_keys` ★ | manifest `<meta-data>` + uni-app 配置抠真实 `key=value`，映射调证主体；敏感凭据产 HIGH Finding |
| `sdk_fingerprint` | 第三方 SDK 指纹 → 厂商（支付/短信/推送/云存储/IM/统计/地图） |
| `payment` | 聚合支付/收款/商户号/USDT/钱包地址 → 资金线索 |
| `admin_panel` | 后台管理系统 / 控制台入口（host 子域 + `/admin`、`/api/admin/`、wp-admin 等）→ 团伙运营控制端，指明调后台服务器与运营日志 |
| `fourth_party_payment` | 四方支付 / 跑分 / 代收代付 / 二清聚合支付平台（补主流支付盲区）→ 资金流重建 |
| `sms_forwarding` | 短信 / 验证码转发服务（OTP 接管基础设施；排除正规短信 SDK，只认接收+转发窃取） |
| `card_merchant` | 卡商 / 料商 / 开户供应链关键词（情报研判，默认待核） |
| `self_hosted_im` | 自建 IM/C2 信道（硬编码非白名单 ws/wss/mqtt/xmpp 服务器 + IM 库指纹；排除公共推送/MQTT） |
| `wallet_secret` | 钱包私钥 / 助记词（BIP-39 校验和 / WIF / 上下文门控 EVM 裸私钥）→ 直接掌控资金的高敏物证 |
| `backend_credential` | 硬编码后端 / 管理凭据（Basic-Auth / DB 连接串 / JDBC / 云 AccessKey）→ 供有权机关依法登录取证（被动提取，非爆破） |
| `endpoints` | dex/资源/native/manifest 全量抽 URL/域名/IP（严格降噪） |
| `js_bundle` | uni-app/H5/RN 打包 JS **字符串字面量内**精确抽端点 + 硬编码密钥 |
| `crypto_recipe` ★ | 从打包 JS 反查应用层加密配方（CryptoJS AES/DES 算法/硬编码 key/iv 推导/`{data,timestamp}` 信封）→ 高价值线索，凭此离线解密全部加密流量 |
| `jadx` | （需 jadx）深度反编译补端点/密钥 |
| `packing` | 加固厂商识别（梆梆/爱加密/360/腾讯乐固/娜迦/百度/网易易盾/阿里聚安全/几维）；**证据分级**：`.so`/特征文件才判已加固，仅 dex 名词命中降级为提示，避免误报 |
| `certificate` | 签名证书 → 跨样本关联同一开发者 |
| `contacts` | QQ/微信/Telegram/邮箱/手机号（带去误报） |
| `permissions` / `components` / `manifest` / `crypto` | 危险权限/导出组件/基础指纹/弱加密 |
| `ios_plist` ★ | （iOS IPA）解析 `Info.plist` → 冒充品牌（显示名）/ URL scheme 攻击面 / ATS 明文 HTTP / 探测支付宝·微信 / 敏感权限用途 |

> **iOS IPA**（涉诈包多为 H5 壳）：传 `.ipa` 给 `fxapk analyze` 即按文件类型自动分流到**纯静态**分析，
> 复用 `endpoints` / `js_bundle` / `crypto_recipe` 等平台无关分析器 + `ios_plist`，从 `Payload/<App>.app/www/`
> 的 H5 包抠端点与加密配方，从 `Info.plist` 抠攻击面 —— **不连设备、无需越狱**（Android 专属分析器在 IPA 上自动跳过）。

**富化器（默认联网，`--offline` 可关，结果缓存，对可疑端点**并发**查询提速）**：`rdap`（HTTPS 查注册商/注册时间/状态/NS，比 port-43 whois 更可靠，失败自动回退 `whois`）、`whois`（注册人/注册商，作 rdap 兜底）、`icp`（ICP 备案主体）、`dns`（DoH 解析域名→IP 并查托管云厂商，定位真实后端）、`asn`（IP 归属云厂商/IDC）、`webcheck`（**opt-in**：设环境变量 `FXAPK_WEBCHECK_URL` 指向自托管 [web-check](https://github.com/Lissy93/web-check) 实例后，对每个建议调证的域名/IP 再查一轮 OSINT——服务器地理 / SSL / DNS / 技术栈 / 开放端口 / 邮件配置 / 威胁情报 / 子域，结果进 `enrichment['webcheck']` 并喂**辖区分流**（地理→国内/国外）、**国外取证攻击面**（端口/技术栈）、**串案**（子域/关联主机）；可用 `FXAPK_WEBCHECK_CHECKS` 定制检查项）。

**「是否建议调证」分级**（`core/infra.py`）：命中公有云/主流 SDK/开源 CDN/标准协议/运营商域名 → 「无需调证」；私网/无效 → 「待核」；其余疑似 App 自有 → 「建议调证」。

---

## 真机动态补全（doctor / auto / unpack / capture）

真加固 App（DEX 加密、运行时还原）静态拿不到真实 C2，需要在 root 真机/模拟器上脱壳 + 抓包。
**接好设备后推荐直接用一键 `fxapk auto`**；也可分步：

```bash
fxapk doctor                            # 环境体检：设备/root/ABI/frida-server/CA 逐项检查，可自动修
fxapk auto app.apk --out out            # 一键：doctor→静态→脱壳→去壳重打包→抓包→合并一份总报告
fxapk unpack app.apk --out out          # 单独脱壳：frida-dexdump dump 隐藏 DEX，回灌重分析
fxapk repackage app.apk --out out       # 去壳重打包：脱壳 DEX 装回去壳版供抓包（auto 默认含；--no-repackage 关）
fxapk capture <package> --duration 60   # 单独抓包：mitmproxy + frida 绕证书绑定，抓运行时端点
```

**自动配环境**：`doctor`（及 `auto` 内部）能按设备 ABI + 主机 frida 版本**自动下载部署 frida-server**、**安装 mitmproxy CA 到系统信任库**（纯标准库下载，root 写入；装不了则如实降级并给命令——HTTPS 抓明文的命门绝不假成功）。
**去壳重打包（`repackage`，`auto` 默认含、`--no-repackage` 关）**：加固壳的反 frida/反调试会让抓包抓不到去壳后逻辑。脱壳得到 DEX 后用 zipfile 把它替回原 APK 的 `classes*.dex`、`zipalign` + `apksigner` 重签、卸原包装去壳包，并经**四联判活**（装上 + `am start` + 进程存活非秒退 + frida 可附）确认起得来才算成功——装上起不来**绝不假成功**，优雅降级重装原包让抓包仍跑原版。需 apksigner/zipalign（Android SDK build-tools）+ 设备；治不了 VMP/重 native/带完整性自校验/反模拟器壳（多数样本预期降级）。
**运行时端点并回主报告**：`auto` / `analyze --dynamic` 会把抓到的运行时端点（真·C2，`source=runtime`）并入同一张调证线索清单并重渲报告。
**无设备/缺工具时不报错**：相关步骤 `status=skipped` + 打印**可逐条复制的取证手册**；静态报告照常产出。脱壳得到的 DEX 也可用 `fxapk analyze app.apk --extra-dex <dump_dir>` 手动并入。

> ⚠️ **单设备假设**：`auto` / `capture` / `unpack` 假定**只接了一台目标设备**。同时在线多台设备时，
> adb 会作用到默认设备上（设全局代理、reverse 等可能打到非目标机且不还原）。请**只连目标设备**，
> 或先 `adb disconnect` / 拔掉其它设备再跑（多设备 `-s <serial>` 定向是后续计划项）。
>
> 设备/模拟器接入要点（adb 连接、root、ARM 兼容、frida 版本一致、CA 安装）见 [docs/dynamic-setup.md](docs/dynamic-setup.md)。
> 云端方案：在 root 真机 / 云手机（华为云手机、阿里无影等原生 ARM 安卓）上跑 frida-server，apkscan 部署在小 Linux VM 上经 ADB 驱动即可。

---

## 案件图谱串案 + 辖区取证分流

**本地案件图谱（`fxapk graph`，需 `pip install fxapk[graph]`）**：把每次分析的样本与强指纹（签名
证书 / C2 / uni-appid / 收款地址 / 后台 host / 自建 IM 服务器 / 钱包凭据 …）持久化进嵌入式 Kuzu
属性图，**跨样本、跨批次**碰撞团伙——同签名 = 同打包账号、同后台 / 收款 = 同资金与运营基础设施、
同钱包助记词 = 同操作者。`batch` 跑完自动入图；也可手动驱动（默认输出稳定 JSON，供 Codex / 程序消费）：

```bash
fxapk graph ingest out/                     # 报告入图（batch 已自动入图）
fxapk graph link <sha256>                   # 拉出与该 APK 共享强实体的关联 APK（按权重排名）
fxapk graph cluster --min-shared 1          # 全图团伙簇 + 并案依据 + 置信分
fxapk graph query --kind sign --value <X>   # 反查：哪些 APK 用了这个指纹
fxapk graph stats                           # 图谱体检（节点 / 边 / 各 kind 计数）
```

**服务器辖区取证分流**：每条「建议调证」的后端线索按富化归属国（ICP / whois 注册国 / IP ASN）自动
判辖区并附取证路径——**国内**服务器 → 依法调证（向境内云 / IDC / ICP 调访问日志、登录记录、租户
实名）；**国外**服务器（难直接调证）→ 以获取服务器**镜像 / 磁盘与日志**为目标，结合已识别的后台 /
管理端、暴露面、技术栈已知漏洞方向研判（**被动情报指引，非主动扫描 / 攻击**）。

> 合规版「弱口令」：不主动爆破远程服务器，而是 `backend_credential` 从**已扣押样本**里抠出它自己
> 硬编码的后端 / 管理凭据（App 自带的凭据十有八九就是那台服务器在用的），供有权机关依法登录取证。

---

## 线索追踪 + 办案进度（track，本地/局域网网页）

分析只是起点，线索要**跟进办案**。`fxapk track` 起一个本地/局域网网页，集中看**每个 APK 发现的线索**并**手动记办案进度**——两级：APK 总进度（待处理 / 调查中 / 已移送 / 已结案）+ 每条线索状态（待办 / 已出函 / 已收数据 / 无果 / 不调证）+ 备注 + 带时间戳的进展留痕（预设词表，也可自定义）。

- **自动入账**：`analyze` / `auto` 跑完自动把该样本的线索写进台账（`--no-track` 关），合并时**保留你手改的状态 / 备注 / 进展**（重分析不覆盖）、新线索默认「待办」；同时顺带喂案件图谱（kuzu 可用时）。也可 `fxapk track ingest <report.json…>` 回填历史报告。
- **台账位置**：`~/.apkscan/tracking.json`（用户主目录、仓库之外，`git pull` / 重新 clone 都不覆盖你的办案数据）；`--ledger PATH` / 环境变量 `FXAPK_TRACKING_DB` 可改。
- **起网页**（需 `pip install fxapk[track]`，flask）：

```bash
fxapk track                       # 仅本机：http://127.0.0.1:8787
fxapk track --host 0.0.0.0        # 局域网共享：打印含访问令牌的 http://<本机IP>:8787/?token=...
```

  局域网共享自动启用**令牌鉴权**（台账含受害人 PII，信任内网才 `--no-auth` 关）；多人查看 / 编辑按条更新落盘。

---

## 对接任意 AI agent（诊断 / 隐私 / agent 无关）

fxapk 的产出与控制面是**标准 JSON CLI**——agent（Codex / Claude / 其它）直接 shell 调命令、解析 stdout JSON 即可驱动，不绑定任何单一 agent，也无需额外协议层：

- **自检诊断**：`fxapk selfcheck` 逐项报告各能力（图谱 / 解密 / jadx / 动态脱壳抓包 / 联网富化 / web-check）的状态（`ok` / `missing` / `disabled` / `unreachable`）+ 一句话修复指引。agent 跑之前先自检、按结果选路或提示用户装依赖，而非试错。
- **紧凑摘要**：`fxapk digest` 给按优先级排序的扁平 JSON，低 token 直接决策；要细节再读本地完整报告。
- **图谱串案**：`fxapk graph`（含只读 `cypher` 逃生口）默认输出稳定 JSON，供 agent 串并团伙。
- **隐私安全**：digest **默认明文**（取证查看需要看到钱包私钥 / 凭据等实际值）；要把摘要喂可能经云端模型处理的 agent 时用 `fxapk digest --redact`，对高敏物证（钱包私钥 / 助记词、后端凭据、运行时登录态、受害人 PII、加密配方）脱敏，明文始终在本地完整 `report.json`。联网富化默认仅查「建议调证」端点缩小暴露面；web-check 走**本地实例**；ip-api 明文 HTTP 风险见下方隐私提示。

---

## 项目结构

```
apkscan/
  core/       models / context / apk(androguard) / ipa / loader / registry(自动发现) / pipeline / infra / forensic(辖区分流) / redact(脱敏) / chainaddr / walletsecret / device
  selfcheck.py 自检诊断（AI 友好：能力 / 连通 / 修复指引）
  analyzers/  28 个静态分析器（见上表；含 iOS `ios_plist`，按 requires 能力门控自动分流 APK/IPA）
  graph/      本地案件图谱（嵌入式 Kuzu）：store / ingest / query / schema / weight（`fxapk graph` 串案）
  enrichers/  rdap / whois / icp / dns / asn / webcheck(opt-in OSINT)（默认联网，结果缓存）
  dynamic/    doctor / provision / unpack / repackage(去壳重打包) / capture / merge(运行时并回+会话时序) / correlate(团伙聚类) / batch(批量) / fingerprint / auto(一键编排)
  track/      线索追踪台账 + 办案进度（ledger）+ 本地/LAN 网页（web, flask 可选 extra）+ 自动入账(autoingest)
  report/     html / json / pdf / ioc(IOC CSV) / letters(调证函) / digest(紧凑摘要) + templates/
  rules/      *.yaml + bip39_english.txt（SDK/加固/支付/配置键/权限/银行包名/词表等规则库）
tests/        单元测试（FakeContext，离线，不需真机 / 网络）
docs/         设计文档
```

---

## 合规边界

本工具仅用于**授权的反诈调证 / 安全研究**，只做分析与线索提取，**不提供任何攻击、绕过、规避检测能力**；
加固只识别不脱壳（脱壳为可选的真机取证步骤，需操作者自备授权环境），联网富化仅查公开的
WHOIS / ICP 备案 / ASN 信息。请在合法授权范围内使用。

> ⚠️ **隐私提示**：ASN 富化走 ip-api 免费档（**明文 HTTP**，免费档不支持 HTTPS），被查 IP（疑似 C2）
> 会以明文经过在途节点，暴露"正在核查哪个目标"的侦查意图。敏感目标请用 `--offline` 关闭联网富化，
> 或自行接入支持 HTTPS 的权威源。WHOIS/ICP 走各自库/接口，不在此列。

## License

[MIT](LICENSE)
