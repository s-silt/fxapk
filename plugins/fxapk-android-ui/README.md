# fxapk-android-ui

Optional Android CLI UI observation plugin, version 0.1.0, for fxapk 1.18.0+ and Python 3.11+.

Install the core and plugin in the same environment. From the fxapk source root:

```bash
python -m pip install .
python -m pip install ./plugins/fxapk-android-ui
fxapk ui --help
```

The plugin provides `ui capabilities`, `ui snapshot` and `ui run-plan`. It requires adb and Google's Android CLI, neither of which is bundled. Use an explicitly authorized device and package, and a new output directory per observation or plan.

Installation does not automatically attach UI observations to auto/capture commands. Screenshots, layouts and diagnostic output may contain sensitive values; digest redaction does not cover these files.

Installation, sample plans, permissions, outputs and capture integration: [English guide](https://github.com/s-silt/fxapk/blob/v1.18.0/ANDROID-UI.en.md) · [中文指南](https://github.com/s-silt/fxapk/blob/v1.18.0/ANDROID-UI.md).

License: [MIT](LICENSE). Third-party tools and dependencies retain their own licenses.
