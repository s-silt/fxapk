# 工具链复核（2026-10-02）

本候选版本为 **1.17.0.dev0**，尚未发布；基底是 master 1.16.0。
新增功能使用已有运行依赖，没有引入浏览器自动化、大模型或新付费服务依赖。

## 运行依赖

- 正常解析环境：Python 3.12.14、cryptography 50.0.2、requests 2.34.2、
  urllib3 2.8.0、typer 0.27.2
- 取证锁环境：仍按 requirements.lock，cryptography 49.0.0、requests 2.34.2、
  urllib3 2.7.0、typer 0.27.0；不改历史复现锁来掩盖兼容问题
- 两环境依赖一致性检查通过；锁环境相关 193 项定向回归通过
- CI 固定 Ruff 0.15.15 已单独执行通过；类型检查目标 Python 3.11
- 这不是全库漏洞扫描结论，也不表示所有平台和可选功能已经验收

## 设备工具

- Androguard 4.1.4：仓库固定值与 [PyPI 当前版本](https://pypi.org/project/androguard/)一致
- frida-tools 14.10.4：与 [PyPI 当前版本](https://pypi.org/project/frida-tools/)一致
- Frida：仓库设备工具链仍为 17.18.0；[PyPI 已有 17.19.0](https://pypi.org/project/frida/)
  新版本存在不等于有必要直接替换。主机 Frida、设备 frida-server、工具包/Java bridge
  必须配套做真机验收，本轮未修改设备或自动升级该固定值
- JADX：[官方发布页](https://github.com/skylot/jadx/releases)显示 1.5.6；
  该信息不等于用户本机当前已安装版本，未擅自替换本机工具
- frida-dexdump 2.0.1 保持仓库固定值；未作真机脱壳成功保证

正式部署时用隔离虚拟环境安装；不要把最新解析环境误称为按历史锁复现。
运行前核对设备选择、样本 SHA、主机/server 版本、证书与代理状态及还原路径。
可选 PCAP 深度解密依赖继续通过 fxapk[pcap] / fxapk[dynamic] 声明。
