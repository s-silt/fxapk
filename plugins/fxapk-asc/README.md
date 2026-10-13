# fxapk-asc

可选插件。`fxapk dex query` 通过隔离进程调用固定版本的 ASC（droidasc 0.1.1.post5，
修订 d3d75ab7a3c092345102d2ec66ab614ad4a6cc75）。核心包不依赖本插件。

未安装时 `fxapk dex capabilities` 返回 `provider_unavailable`。本插件不注册进
`fxapk.plugins` 进程内加载表，避免宿主导入 ASC。

依赖锁定见 `requirements.lock`。Linux 的 `RLIMIT_AS` 已在代码里实现，但本仓库的
实跑记录只覆盖 Windows 作业对象。macOS 上 `RLIMIT_AS` 不可用，`dex query` 以
`memory_limit_unavailable` 拒绝执行，不降级运行。
