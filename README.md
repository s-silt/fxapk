# fxapk

[![CI](https://github.com/s-silt/fxapk/actions/workflows/ci.yml/badge.svg)](https://github.com/s-silt/fxapk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

*CLI 命令 `fxapk`（保留 `apkscan` 别名）· PyPI 包名 `fxapk`* · **English**: [README.en.md](README.en.md)

APK **静态 + 动态分析 CLI**：抠出应用真实配置（AppID / AppKey / 渠道号 / uni-app 应用 ID 等）、网络端点、第三方组件与加固指纹；打通**加密远程配置链**（发现 OSS / CDN 配置对象、多层解码 / 解密其中的动态后端域名 / IP 池、拼成单一控制链，对识别不出标准解密 API 的混淆样本给出**待解密线索**含完整密文供人工 / AI 恢复）；对域名 / IP 做**五层不塌缩的基础设施归属**（资源登记方 → BGP ASN → 云 / IDC → CDN / 边缘代理 → 运营者，每层带来源与置信、查不到即标未知）；动态走 **PCAP-first** 抓包（TLS / QUIC 握手解析 + 按五元组的 socket 精确归因），输出**结构化 HTML / JSON 报告**。

`pip install` 即可跑核心分析，**零环境**（不需要 JDK / 模拟器 / 真机）。加固样本的脱壳、抓包是可选的真机步骤。

## 安装

要求 **Python 3.11+**。

```bash
pip install fxapk

# 或从源码
git clone https://github.com/s-silt/fxapk.git && cd fxapk && pip install -e .
```

动态脱壳 / 抓包、样本库等能力按需安装可选依赖；缺失时对应命令给出提示，核心分析不受影响。

> 在线富化的 API Key、动态分析外部工具、以及围绕报告的配套脚本 / MCP / 探针库均**自备、本项目不提供**——见 [COMPANION-TOOLS.md](COMPANION-TOOLS.md)。

## 用法

```bash
# 静态分析，产出 HTML + JSON 到 out/
fxapk analyze app.apk --out out

# 已落盘的网页证据也是一级输入：递归读 .html / .body / .js / .headers，不联网重取
fxapk analyze-web <证据目录> --out out

# 一键全自动（接好 root 真机 / 模拟器）：体检 → 静态 → 脱壳 → 抓包 → 合并 → 案件闭环
fxapk auto app.apk --out out

# 严格验收：complete=0、partial=5、failed=6（无设备仍可跑，但动态证据不作必选门）
fxapk auto app.apk --out out --strict-case

# 对已有 JSON 报告补跑多源富化、五层归因和闭环验收（默认严格退出码）
fxapk case close out/app.json

# 同一批样本换版后，检出到底变好还是变坏（先把两版报告都 corpus add 入库）
fxapk corpus regress --corpus <库目录>

# 哪些样本出自同一套开发环境（构建路径是编译期烙进 native 库的，改名/重打包/换服务器都动不了）
fxapk corpus shared-build-env

# 批量被动富化一份目标清单（每行一个 IP / 域名）——默认 --dry-run 只估算各源配额、不发请求
fxapk enrich batch -t targets.txt -o enrich_out
```

主要命令：`analyze`（静态）、`analyze-web`（已落盘网页证据）、`auto`（一键分析并闭环）、`case close`（已有报告严格闭环）、`capture`（真机抓包）、`doctor`（设备环境体检 + 自动修）、`enrich batch`（批量被动富化，可续跑）、`corpus`（样本库：历次报告入库、跨版本回归、按值反查串案、按构建环境找同源样本）。完整命令与参数见 `fxapk --help`。

闭环状态写入 `report.meta.closure`：`complete` 表示主目标的运行时证据、资源登记、BGP 宣告、托管/分发和最终调证对象五层均有证据；`partial` 表示仍有显式缺口；`failed` 表示静态关键失败、要求动态但没有业务流量，或没有可闭环主目标。CDN / 防红前端未定位 Origin 时不会判为 `complete`。

### 先看「哪里没看见」，再看结论

报告与 `fxapk digest` 都会带 `visibility` 段，且**排在线索之前**——它回答的是「基于本次实际看到的
输入，哪些结论有资格下」。加固样本的 DEX 往往只剩壳桩，此时「未发现网络端点」说明的是**没看见**，
不是不存在；`blocked_claims` 会明确列出无资格下的那几条穷尽性结论，`next_actions` 给出补法
（该脱壳、该抓包，还是授权后重跑取远程配置）。

这一段与 `analysis_status` 是两回事：后者是**工具执行**是否健康，前者是**样本内容**是否看得见。
分析器全部跑成功、`analysis_status=complete`，与「DEX 是壳桩、六条结论没资格下」可以同时为真。

### 判样本形态：自研马甲包，还是正版被重打包

`repack_identity` 给出三态判定。这一步必须先做——两种形态的**接口 / 域名 / 构建路径归属完全相反**：
自研包的是团伙自建资产，可直接作线索；正版重打包件的属于**被仿冒的厂商**，列进调证清单会向
无关企业发函。

判为重打包时，工具只声明「疑似被重签名」，**不会**声称「植入了什么」——那需要与官方同版本包
逐文件差分才能认定，样本自身给不出。

未安装为命令时用 `python -m apkscan.cli <…>` 等价调用。

## 输出

- `out/report.html` —— 自包含单文件报告（可直接分享 / 手机打开）
- `out/report.json` —— 完整结构化数据（机器读 / 二次处理）
- `report.meta.closure` —— 闭环状态、五层证据、来源覆盖、缺口与下一步动作
- `--fmt pdf` 可选导出 PDF（需本机 Chrome / Edge）

## 从源码开发

clone 后跑一次，启用提交前的敏感信息扫描：

```bash
git config core.hooksPath .githooks
```

它只看**已 staged 的新增行**：疑似真实地址、疑似凭据、无理由豁免三类默认阻断；域名与语境词
如实报告但不阻断（`FXAPK_LEAK_SCAN_STRICT=1` 可一并阻断）。放行单行需写明理由——行内加
`leak-scan: allow <理由>`。CI 会对 PR diff 再扫一遍，所以 `--no-verify` 绕不过最终门禁。

测试夹具一律使用文档保留段（`192.0.2.0/24` / `198.51.100.0/24` / `203.0.113.0/24` /
`2001:db8::/32` / `example.com`）。真实地址一旦推上远端就**不可撤销**——改写历史也删不掉平台
侧的缓存副本，唯一可靠的办法是源头不写进去。

## 合规边界

仅用于**授权范围内**的安全研究与分析，只做静态 / 动态分析与信息提取，**不提供任何针对第三方的攻击 / 漏洞利用 / 主动探测能力**。**默认被动**：境外服务器只做被动归属（RDAP / WHOIS / DNS / ASN / 证书透明度），对目标零主动流量；少数需向目标发起请求的能力（如获取样本引用的配置对象）默认关闭，仅在 `--mode authorized-active` 显式授权下启用。脱壳仅对**样本自身**在自备授权环境的分析机上运行时进行。请在合法授权范围内使用。

## License

[MIT](LICENSE)
