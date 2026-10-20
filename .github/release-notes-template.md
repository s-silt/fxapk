## 更新说明

本次发行版本为 **$tag**。功能变更、兼容要求与能力边界见[版本记录](https://github.com/$repository/blob/$tag/CHANGELOG.md)和[中文项目首页](https://github.com/$repository/blob/$tag/README.md)。发布说明默认使用中文；命令、版本号与接口标识符保持原样。

### 本版变更

$changes

## 安装包

核心 **fxapk $core_version** 提供 wheel 与源码归档，并由本流程发布到 PyPI。可选插件均为独立版本，仅通过本页附件分发，不发布到 PyPI：**fxapk-android-ui $plugin_version**（Android CLI 与 adb 自备）、**fxapk-rea $rea_version**（默认关闭，需在进程环境显式设置 `FXAPK_ENABLE_REA=1`；`trace` 另装 `[trace]` extra）、**fxapk-asc $asc_version**（`fxapk dex` 隔离 worker，macOS 上以 `memory_limit_unavailable` 拒绝执行）。核心要求 Python $requires_python，插件要求以其包元数据为准。

```bash
python -m pip install "fxapk==$core_version"
python -m pip install ./fxapk_android_ui-$plugin_version-py3-none-any.whl
python -m pip install ./fxapk_rea-$rea_version-py3-none-any.whl
python -m pip install ./fxapk_asc-$asc_version-py3-none-any.whl
fxapk --version
fxapk ui --help
fxapk dex --help
```

以上命令在下载附件所在目录执行；仅安装需要的插件即可。REA 安装后保持关闭，
需明确启用时才为该进程设置 `FXAPK_ENABLE_REA=1` 并运行 `fxapk rea --help`。
`trace` 的可选依赖可通过
`python -m pip install "./fxapk_rea-$rea_version-py3-none-any.whl[trace]"` 安装。
插件不会自动启动浏览器、查询第三方或连接设备。

安装前用附件 `SHA256SUMS.txt` 核对全部归档。它们不是完整离线依赖包，安装可能下载声明依赖。许可见各归档内的 MIT 声明，第三方工具和依赖遵循各自许可。[安卓 UI 指南](https://github.com/$repository/blob/$tag/ANDROID-UI.md)。

## 来源与使用边界

本版标签对应提交 [`$commit`](https://github.com/$repository/commit/$commit)。验证范围以该提交的 CI、版本契约和实际发布结果为准，不据流程成功宣称真机或服务商账户已验收。

设备操作与第三方查询须在对应授权内执行；安装插件不会自动为 `auto`/`capture` CLI 接入 UI 观察。截图、布局、报告与诊断可能含敏感原值，`digest` 的有限脱敏不保证这些材料可直接外发。账户额度和权限以实际来源回执为准。
