# fxapk-asc

可选插件。`fxapk dex query` 通过隔离进程调用固定版本的 ASC（droidasc 0.1.1.post5，
修订 d3d75ab7a3c092345102d2ec66ab614ad4a6cc75）。核心包不依赖本插件。

未安装时 `fxapk dex capabilities` 返回 `provider_unavailable`。本插件不注册进
`fxapk.plugins` 进程内加载表，避免宿主导入 ASC。

## 安装

从所选 GitHub Release 下载核心及 ASC 的 wheel，并按该发行的 `SHA256SUMS.txt`
校验文件。使用 Python 3.11+ 的独立虚拟环境，先安装该发行的核心，再安装同页
`fxapk_asc-0.1.1-py3-none-any.whl`：

```powershell
python -m pip install ./fxapk_asc-0.1.1-py3-none-any.whl
fxapk dex --help
```

插件附件不是完整离线依赖包；pip 会解析并下载下列固定依赖。安装插件不会运行
查询，不会连接设备。`dex query` 仍需显式调用，并在隔离进程中执行。
插件源码采用 MIT 许可（见 `LICENSE`）；第三方依赖遵循各自许可。

依赖锁定见 `requirements.lock`。Linux 的 `RLIMIT_AS` 已在代码里实现，但本仓库的
实跑记录只覆盖 Windows 作业对象。macOS 上 `RLIMIT_AS` 不可用，`dex query` 以
`memory_limit_unavailable` 拒绝执行，不降级运行。
