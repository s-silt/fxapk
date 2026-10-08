# fxapk-android-ui

**中文** · [English](README.en.md)

可选的 Android CLI UI 观察插件，独立版本 0.1.0，适用于 fxapk 1.18.0+ 与 Python 3.11+。

核心与插件安装在同一环境。在 fxapk 源码根目录运行：

```bash
python -m pip install .
python -m pip install ./plugins/fxapk-android-ui
fxapk ui --help
```

插件提供 `ui capabilities`、`ui snapshot` 和 `ui run-plan`。adb 与 Google Android CLI
须另行准备，不随插件分发。显式指定获授权的设备与包名，每次观察或计划使用新的输出目录。

安装插件不会自动将 UI 观察接入 auto/capture 命令。截图、布局与诊断输出可能包含敏感原值，
digest 的脱敏范围不覆盖这些文件。

安装、合成计划、权限、输出与抓包接入见[中文指南](https://github.com/s-silt/fxapk/blob/v1.18.0/ANDROID-UI.md)
与 [English guide](https://github.com/s-silt/fxapk/blob/v1.18.0/ANDROID-UI.en.md)。

许可：[MIT](LICENSE)。第三方工具与依赖遵循各自许可。
