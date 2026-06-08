# apkscan

涉诈 APK 调证分析 CLI。对涉诈 APK 做静态分析 + 网络端点/服务归属提取，产出**调证线索清单**——每条线索回答“归属哪家公司、能去找谁调取什么证据”。零环境即可跑核心功能（`pip install` 即可，不需要 JDK / 模拟器）。

## 安装

```bash
python -m pip install -e .
```

依赖：`androguard`（解析 APK）、`jinja2`、`typer`、`python-whois`、`requests`、`pyyaml`。
运行测试只需后五者 + `pytest`：单元测试全部基于 `FakeContext` 合成数据，**不依赖 androguard、不联网、不需要真机/jadx/frida**。

```bash
python -m pip install jinja2 typer python-whois requests pyyaml pytest
python -m pytest -q
```

可选依赖（缺失时对应能力优雅降级，核心 import 不受影响、不报错）：

- `jsbeautifier`：美化压缩 JS，提升 `js_bundle` 端点/密钥抽取质量（缺失则直接扫原始 bundle）。
- `frida-tools` + `frida-dexdump`：真机脱壳（`unpack` 命令）。
- `mitmproxy`：真机抓包流量解析（`capture` 命令）。
- `jadx`（外部命令，在 PATH 即可）：深度反编译能力探测；缺失时相关增强器在报告中记“已跳过（缺少能力）”，不静默。

## 用法

```bash
apkscan analyze app.apk --out out            # 默认联网富化，产出 HTML + JSON 到 out/
apkscan analyze app.apk --out out --offline  # 关闭联网富化
apkscan analyze app.apk --fmt json           # 只产 JSON（默认 html,json）
apkscan analyze app.apk --extra-dex dump/    # 并入脱壳 dump 出的 .dex 一起静态分析
apkscan analyze app.apk --dynamic            # 静态后若探测到在线设备，自动 unpack + capture
```

产物：`out/report.html`（自包含单文件，CSS 内联，可直接分享）与 `out/report.json`（`Report` 完整序列化）。
也可直接 `python -m apkscan.cli analyze app.apk --out out`。

`--extra-dex`：逗号分隔的 `.dex` 文件或含 `.dex` 的目录（通常是脱壳 dump 产物）。其字符串并入 `dex_strings()`，使脱壳后才可见的隐藏端点/SDK/配置键也能被静态分析命中。单个 dex 解析失败只跳过该文件，不影响主流程。

### 报告版式（按调证视角重排）

概览（含加固/uni-app 加密标记）→ **★调用插件 / 配置键值（CONFIG_KEY）**：抠出的真实 `key=value` 具体值（如 `GETUI_APPID=...` / `PUSH_APPSECRET=...` / `__UNI__...`），每条绑定到可调证厂商 → 网络线索分区：**主控域名（建议调证）** 与 **通联域名/IP（无需调证，可折叠）** 按 `advice` 分级展示 → 其余线索清单（支付/SDK/联系方式/加固/签名/渠道，按类别分组、置信度排序）→ 网络端点全表（含 WHOIS/ICP/ASN 富化、明文/内网标记）→ 技术附录（权限/组件/证书/crypto/密钥 Finding）→ 分析器与富化器运行状态（ran/skipped/error，透明不吞错）。

`advice`（是否建议调证）分级由 `core/infra.py` 的已知正规基础设施清单驱动：命中公有云/主流 SDK/开源 CDN/标准协议域名 → “无需调证”；私网/无效字面 → “待核”；其余疑似 App 自有服务 → “建议调证”。

### 新增静态分析器

- **`config_keys`（最高价值）**：从 `manifest <meta-data>`、uni-app `manifest.json`、`dcloud_control.xml` / `dcloud_uniplugins.json` / `strings.xml` 抠出真实配置 `key=value`，按 `rules/config_keys.yaml` 把每个键绑定到调证主体（个推/DCloud/腾讯/友盟/极光/各厂商推送…），产出 CONFIG_KEY 线索（含具体值）；名字含 SECRET/APPKEY/TOKEN 等的额外产 HIGH Finding。uni-app `confusion`（代码加密）→ MEDIUM Finding。
- **`js_bundle`**：识别打包框架（uni-app / Cordova / React Native / 通用 H5），**只在字符串字面量内部**精确抽取真实 URL / 域名 / IP / 相对 API 路径（避开 `a.length` / `rect.top` 这类误判），并扫描硬编码密钥（appid/appkey/secret/AES key/JWT/PEM）。仅产端点（domain/IP 的 Lead 由 pipeline 统一生成），密钥产 Finding。

## `--offline` 说明

- 默认 `--online`：对域名查 WHOIS / ICP 备案，对 IP 查 ASN 归属，结果缓存到 `.apkscan_cache/` 避免重复查询。
- `--offline`：跳过全部联网富化，报告里归属字段标“需人工核”。静态分析（端点/SDK/加固/证书/权限/组件/crypto）不受影响，照常产出。
- ICP 备案无稳定免费公开 API，默认 provider 不可用时优雅降级为“需人工核”，并在报告里附工信部官网与域名直查链接（可子类覆写 `IcpEnricher._provider_url` 接入自有 provider）。
- 富化失败/超时只把该字段标失败，不阻塞主流程。

## 加固识别 + 真机动态补全（unpack / capture）

- **加固识别**：识别并标注加固厂商（梆梆/爱加密/360/腾讯乐固/娜迦/百度/网易易盾/阿里聚安全/几维）。命中即产 HIGH Finding 告警“静态端点不完整，建议脱壳或真机动态补全”，同时把加固厂商列为高价值调证目标（可调未加固原始包、开发者实名、打包/操作日志）。

- **`unpack`（真机脱壳）**：root 设备 + `frida` + `frida-dexdump` 自动 dump 解密后的 DEX，并回灌 `analyze --extra-dex` 重新静态分析，写出 `out/unpacked_report.{json,html}`。

  ```bash
  apkscan unpack app.apk --out out                 # 脱壳后自动重分析（默认）
  apkscan unpack app.apk --out out --no-reanalyze  # 只 dump，不重分析
  ```

- **`capture`（真机抓包）**：`mitmproxy` + frida 通用 SSL unpinning + adb 代理，抓运行时真实流量，提取运行时端点（`source=runtime`）写出 `out/runtime_report.json`。

  ```bash
  apkscan capture <package> --out out --duration 60
  ```

- **缺设备/缺工具时**：`unpack` / `capture` 不报错、不崩——返回 `status=skipped` 并打印**可逐条复制执行的手册（playbook）**（装 frida-server、推 CA、注入 unpinning、回灌 `--extra-dex` 等完整取证步骤），`reason` 写明缺什么。两个命令都通过 CLI 惰性导入，相关可选依赖未装时打印“该功能未安装”后优雅退出。

## 合规边界

本工具仅用于**授权的反诈调证**，只做分析与线索提取，不提供任何攻击/绕过/规避检测能力；加固只识别不脱壳，联网富化仅查公开的 WHOIS/备案/ASN 信息。
