## 更新说明

本次发行版本为 **$tag**。功能变更、兼容要求与能力边界见[版本记录](https://github.com/$repository/blob/$tag/CHANGELOG.md)和[中文项目首页](https://github.com/$repository/blob/$tag/README.md)。发布说明默认使用中文；命令、版本号与接口标识符保持原样。

### 本版变更

$changes

## 安装包

核心 **fxapk $core_version** 提供 wheel 与源码归档，并由本流程发布到 PyPI。可选 **fxapk-android-ui $plugin_version** 独立版本，仅通过本页附件分发；Android CLI 和 adb 由使用者另行准备。核心要求 Python $requires_python，插件要求以其包元数据为准。

```bash
python -m pip install "fxapk==$core_version"
python -m pip install ./fxapk_android_ui-$plugin_version-py3-none-any.whl
fxapk --version
fxapk ui --help
```

安装前用附件 `SHA256SUMS.txt` 核对四个归档。它们不是完整离线依赖包，安装可能下载声明依赖。许可见各归档内的 MIT 声明，第三方工具和依赖遵循各自许可。[安卓 UI 指南](https://github.com/$repository/blob/$tag/ANDROID-UI.md)。

## 来源与使用边界

本版标签对应提交 [`$commit`](https://github.com/$repository/commit/$commit)。验证范围以该提交的 CI、版本契约和实际发布结果为准，不据流程成功宣称真机或服务商账户已验收。

设备操作与第三方查询须在对应授权内执行；安装插件不会自动为 `auto`/`capture` CLI 接入 UI 观察。截图、布局、报告与诊断可能含敏感原值，`digest` 的有限脱敏不保证这些材料可直接外发。账户额度和权限以实际来源回执为准。
