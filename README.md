<h1 align="center">fxapk</h1>

<p align="center">
  APK 调证取证分析 CLI<br>
  <sub>从样本、流量和已有网页证据中整理线索，保留来源、覆盖范围与待核验事项。<br>工具产物支持复核，不替代原始证据与人工归属判断。</sub>
</p>

<p align="center"><strong>中文</strong> &nbsp;·&nbsp; <a href="README.en.md">English</a></p>
<p align="center">
  <a href="https://github.com/s-silt/fxapk/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/s-silt/fxapk/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/s-silt/fxapk/releases/tag/v1.25.0">v1.25.0</a> &nbsp;·&nbsp; Python 3.11+ &nbsp;·&nbsp; <a href="LICENSE">MIT</a>
</p>

`fxapk`（别名 `apkscan`）从 APK、授权设备流量和已有网页材料中提取线索，记录来源、归属与覆盖缺口。提供 Python CLI，不提供 exe 或 GUI。

## 快速开始

```bash
python -m pip install "fxapk==1.25.0"
fxapk selfcheck
fxapk analyze app.apk --offline --out out
fxapk digest out/app.json
```

静态分析不需要设备。发行附件及校验和见[发布页](https://github.com/s-silt/fxapk/releases/tag/v1.25.0)；源码安装、密钥配置与可选工具见 [USAGE.md](USAGE.md)。

## 常用入口

| 任务 | 命令 |
| --- | --- |
| 分析已保存网页 | `fxapk analyze-web <目录> --out out` |
| 接入 fxfetch 任务包 | `fxapk intake-fetch <ZIP> --fxfetch <可信本机CLI> --out <新目录>` |
| 定点离线复核 | `fxapk evidence-review <清单> --out <新目录>` |
| 无损归档与校验 | `fxapk evidence pack <目录> --out evidence.zip` · `fxapk evidence verify evidence.zip` |
| 检查设备环境 | `fxapk doctor --no-fix` |

`analyze` 默认联网；`doctor` 默认修设备，`auto` 会安装并运行样本，均须对应授权。`digest` 仅有限脱敏，报告和归档可能保留原值，详见[隐私边界](USAGE.md#隐私与输出)。正式判断须回查原始证据；存储校验、分析完成、案件闭环与人工接受是独立状态。

## 文档

- [命令与参数](USAGE.md) · [AI 操作指南](AGENTS.md) · [工具准备](tools/TOOLCHAIN.md)
- [证据归档](EVIDENCE-ARCHIVE.md) · [离线复核](OFFLINE-REVIEW.md) · [定点恢复](RECOVERY-PIPELINE.md) · [报告前工作流](PRE-REPORT-WORKFLOW.md)
- [可选插件与配套工具](COMPANION-TOOLS.md) · [开发架构](ARCHITECTURE.md) · [更新记录](CHANGELOG.md)
