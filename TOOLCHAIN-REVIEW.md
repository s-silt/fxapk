# 工具链复核（2026-10-02）

当前已发布版本为 **1.17.0**，源码标签、GitHub 附件与 PyPI 版本对应。
本页记录发布时的配置和验证边界，不是第三方工具“最新版本”清单。

## 配置真源

- Python 支持范围、运行依赖和可选 extra：[pyproject.toml](pyproject.toml)。
- 取证复现锁：[requirements.lock](requirements.lock)。普通依赖解析环境与锁环境分开，
  不能把普通安装称为按锁复现；锁也不覆盖设备、外部服务或所有可选工具。
- Python 设备工具固定为 Androguard 4.1.4、Frida 17.18.0、frida-tools 14.10.4、
  frida-dexdump 2.0.1，来源为 [tools/toolchain-requirements.txt](tools/toolchain-requirements.txt)。
- mitmproxy 隔离环境与原生工具路径配置见 [tools/TOOLCHAIN.md](tools/TOOLCHAIN.md)。
  这些固定值不是用户本机实际安装状态，也不是自动升级建议。
- PCAP 深度解密通过 `fxapk[pcap]` / `fxapk[dynamic]` 声明；可选 ML 通过 `fxapk[ml]`。

## 发布验证与限制

1.17.0 集成阶段记录了本地 Ruff、Pyright、7330 项测试通过（14 项跳过），以及旧 workflow
161 项兼容测试通过。这些是该次执行记录，不是每次运行应保持的测试数量。
发布候选的跨平台、泄漏和产物检查见 [PR CI](https://github.com/s-silt/fxapk/actions/runs/37006902961)，
发行构建见 [Release workflow](https://github.com/s-silt/fxapk/actions/runs/37007666701)。
[发布页](https://github.com/s-silt/fxapk/releases/tag/v1.17.0) 提供校验和；安装前核对下载文件。

本次文档审校不升级依赖、不重新签发历史发行物，也没有执行真实 APK、真机或第三方账户验收。
CI 与合成测试不能证明全部设备兼容、所有可选能力可用或无已知漏洞。
正式使用前核对主机/server 版本、指定设备、root、Java bridge、证书/代理与恢复路径；
版本号一致和进程可枚举不能代替实际 attach/hook 验证。
