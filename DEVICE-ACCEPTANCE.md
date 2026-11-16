# 授权真机验收（手动）

CI 只覆盖合成回归与跨平台单测，不碰设备。本流程补的是真实运行证据，**不进每个 PR**：
只在采集路径（`fxapk/dynamic/`、`doctor`、`capture`、`auto`、`merge`）有改动，或准备发版时手动跑。

## 前置条件（缺一不跑）

- 设备是**专用测试机**，且本次验收已获得对该设备安装样本、部署 frida-server、装抓包 CA 的授权。
  专用测试机身份本身不等于清数据或行为修改授权（见 `AGENTS.md` §1–§2）。
- 测试 APK 是**自有或已授权**的样本，不使用案件检材。记录其 SHA-256。
- 只观察原版运行，不加 `--allow-behavior-modification`；旁路轮不在本验收范围。
- 运行目录在工作树外，产物不提交到仓库。

## 固定步骤

在已安装待验版本的环境中执行（`<serial>`、`<apk>`、`<pkg>` 为本次授权的设备和样本）：

```bash
fxapk --version                                   # 1. 记录版本
fxapk doctor --serial <serial> --no-fix           # 2. 只读体检，记录退出码与缺项
fxapk doctor --serial <serial> --profile floor-only --no-fix
fxapk analyze <apk> --offline --out run/static    # 3. 静态基线
fxapk capture <pkg> --serial <serial> --mode floor-only --duration 60 --out run/floor
fxapk capture <pkg> --serial <serial> --duration 60 --out run/full   # 需要 frida 时
fxapk case close run/static/<名>.json --offline    # 4. 闭环判定（离线，不触发第三方查询）
fxapk evidence pack run --out run-evidence.zip     # 5. 归档并校验
fxapk evidence verify run-evidence.zip
```

`doctor` 不加 `--no-fix` 会修改设备；只有在授权覆盖该操作时才去掉。
`capture` 运行期间需要人工操作 App 触发业务请求，操作内容写进记录。

## 记录（每次一份，存工作树外）

| 项 | 内容 |
|---|---|
| 日期、操作人 | |
| fxapk 版本 / 提交 | `fxapk --version`、tag 或 commit |
| 主机 | OS、Python、frida、tshark 版本 |
| 设备 | 型号、Android 版本、ABI、root 方式（序列号脱敏） |
| 样本 | 包名、SHA-256、来源授权 |
| 每步退出码 | doctor / analyze / capture×2 / case close / evidence verify |
| 实际覆盖 | capture 报告的 `status`、`frida_bridges`、PCAP 是否非空、TLS keylog 是否产出、`runtime_observed` 端点数 |
| 闭环 | `report.meta.closure.status` 与 `gaps` 原文 |
| 未验证项 | 本次没跑到的模式或 hook 族、失败但未排查的步骤 |
| 产物 | 归档文件名与 `archive_sha256` |

结果按原样记录：`capture status=done` 只说明采集流程跑完，不代表抓到了业务流量；
`partial`/`failed` 不改写成通过。本流程通过也不等于案件证据闭环。
