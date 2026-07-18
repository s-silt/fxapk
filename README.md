# fxapk

[![CI](https://github.com/s-silt/fxapk/actions/workflows/ci.yml/badge.svg)](https://github.com/s-silt/fxapk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

*CLI 命令 `fxapk`（保留 `apkscan` 别名）· PyPI 包名 `fxapk`* · **English**: [README.en.md](README.en.md)

APK / iOS IPA **静态 + 动态分析 CLI**：抠出应用真实配置（AppID / AppKey / 渠道号 / uni-app 应用 ID 等）、网络端点、第三方组件与加固指纹；打通**加密远程配置链**（发现 OSS / CDN 配置对象、多层解码 / 解密其中的动态后端域名 / IP 池、拼成单一控制链，对识别不出标准解密 API 的混淆样本给出**待解密线索**含完整密文供人工 / AI 恢复）；对域名 / IP 做**五层不塌缩的基础设施归属**（资源登记方 → BGP ASN → 云 / IDC → CDN / 边缘代理 → 运营者，每层带来源与置信、查不到即标未知）；动态走 **PCAP-first** 抓包（TLS / QUIC 握手解析 + 按五元组的 socket 精确归因），输出**结构化 HTML / JSON 报告**。

`pip install` 即可跑核心分析，**零环境**（不需要 JDK / 模拟器 / 真机）。加固样本的脱壳、抓包是可选的真机步骤。

## 安装

要求 **Python 3.11+**。

```bash
pip install fxapk

# 或从源码
git clone https://github.com/s-silt/fxapk.git && cd fxapk && pip install -e .
```

动态脱壳 / 抓包、样本库等能力按需安装可选依赖；缺失时对应命令给出提示，核心分析不受影响。

## 用法

```bash
# 静态分析，产出 HTML + JSON 到 out/
fxapk analyze app.apk --out out

# 一键全自动（接好 root 真机 / 模拟器）：体检 → 静态 → 脱壳 → 抓包 → 合并 → 案件闭环
fxapk auto app.apk --out out

# 严格验收：complete=0、partial=5、failed=6（无设备仍可跑，但动态证据不作必选门）
fxapk auto app.apk --out out --strict-case

# 对已有 JSON 报告补跑多源富化、五层归因和闭环验收（默认严格退出码）
fxapk case close out/app.json
```

主要命令：`analyze`（静态）、`auto`（一键分析并闭环）、`case close`（已有报告严格闭环）、`capture`（真机抓包）、`doctor`（设备环境体检 + 自动修）、`corpus`（样本库：历次报告入库、跨版本回归、按值反查串案）。完整命令与参数见 `fxapk --help`。

闭环状态写入 `report.meta.closure`：`complete` 表示主目标的运行时证据、资源登记、BGP 宣告、托管/分发和最终调证对象五层均有证据；`partial` 表示仍有显式缺口；`failed` 表示静态关键失败、要求动态但没有业务流量，或没有可闭环主目标。CDN / 防红前端未定位 Origin 时不会判为 `complete`。

未安装为命令时用 `python -m apkscan.cli <…>` 等价调用。

## 输出

- `out/report.html` —— 自包含单文件报告（可直接分享 / 手机打开）
- `out/report.json` —— 完整结构化数据（机器读 / 二次处理）
- `report.meta.closure` —— 闭环状态、五层证据、来源覆盖、缺口与下一步动作
- `--fmt pdf` 可选导出 PDF（需本机 Chrome / Edge）

![报告示例](docs/images/report-demo.png)

## 合规边界

仅用于**授权范围内**的安全研究与分析，只做静态 / 动态分析与信息提取，**不提供任何针对第三方的攻击 / 漏洞利用 / 主动探测能力**。**默认被动**：境外服务器只做被动归属（RDAP / WHOIS / DNS / ASN / 证书透明度），对目标零主动流量；少数需向目标发起请求的能力（如获取样本引用的配置对象）默认关闭，仅在 `--mode authorized-active` 显式授权下启用。脱壳仅对**样本自身**在自备授权环境的分析机上运行时进行。请在合法授权范围内使用。

## License

[MIT](LICENSE)
