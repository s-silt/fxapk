# 无损证据归档与按需读取

证据目录默认保存为 ZIP64/Zstandard 6 归档，兼顾体积与读取速度；也可选 DEFLATE 6。
使用标准 ZIP 方法 93，每个文件独立压缩，可直接定位选中成员。文件正文逐字节保留，原始 manifest、
文件 SHA-256 和案件 package_id 不因存储压缩而改变。新增存储索引
`__fxapk_evidence_index__.json` 不替代案件清单；存储校验通过不代表采集成功、
样本归属已证实或案件闭环。

## 归档既有证据

```powershell
fxapk evidence pack evidence-directory --out evidence.zip
fxapk evidence pack evidence-directory --out compatible.zip --compression deflate
fxapk evidence verify evidence.zip
fxapk evidence extract evidence.zip --out restored-directory
fxapk evidence extract evidence.zip --out selected-directory --member traffic.pcap
```

`--compression zstd|deflate` 默认 `zstd`，`--level` 默认 6（Zstd 支持 1–9，DEFLATE 支持 0–9）。
Python 3.11–3.13 正常安装项目会同时安装 `backports.zstd>=1.8,<2`；Python 3.14+ 使用
标准库 `compression.zstd`。不升级系统 Python，不修改全局 zipfile。旧 DEFLATE 包仍可直接读。
缺少 Zstd 支持时返回 `archive_zstd_dependency_missing`，不会悄悄换算法。交给旧解压工具时
显式选择 `--compression deflate`；原包保持不变，也可校验提取后另建兼容包。

Zstd ZIP 需要支持方法 93 的工具，旧 Python zipfile 和部分系统解压器不支持。
格式与 API 参考：[Python ZIP 文档](https://docs.python.org/3.14/library/zipfile.html)、
[Zstandard 标准库接口](https://docs.python.org/3.14/library/compression.zstd.html)、
[标准库接口回移植](https://github.com/Rogdham/backports.zstd)。

归档输出必须在源目录外且尚不存在。先冻结输入；程序记录路径、大小、SHA-256、
mtime_ns、mode 和空目录，检查源文件及目录清单变化，写入临时包，再逐文件流式解码
校验后原子发布。`pack` 从不删除源目录，也不覆盖已有归档。`verify` 不落地展开文件。
`extract` 只接受新目录；失败时可能留下部分输出，必须以退出状态判断是否完整。
POSIX 发布要求目标文件系统支持硬链接；不支持时返回 `archive_atomic_publish_unsupported`，
不降级为可能覆盖目标的写法，源目录或本次暂存材料保留。

“无损”指文件正文及原有清单字节，不是文件系统镜像还原：ACL、NTFS 备用数据流、
xattr 未保存，提取也不恢复记录的时间及权限。需要这些信息时应把原始文件系统镜像
作为文件归档。索引含源目录提示以解析原清单的绝对路径；归档仍属受控证据，未经脱敏
不得当作公开代码发布。无签名索引只提供内部一致性，不能独立证明来源真实性。

## 采集或处理后自动归档

以下命令的 `--archive-out` 与 `--out` 二选一：

```powershell
fxapk capture com.example.synthetic --archive-out capture.zip
fxapk recover-runtime recovery-plan.json --archive-out recovery.zip
fxapk intake-fetch saved-task.zip --archive-out intake.zip
fxapk evidence-review review-plan.json --archive-out review.zip
```

上述四个入口均默认 Zstd 6；追加 `--archive-compression deflate` 可输出兼容包。
归档回执记录实际算法、级别及 ZIP 方法号，业务状态仍单独保留。

程序在归档旁创建本次专属暂存目录。流程正常返回后，即使业务状态是 failed/partial，
也保留该状态并归档已有结果。仅在归档发布且全部成员校验通过后清理本次暂存目录。
生成、归档或校验失败时保留暂存材料，并写入 `<archive>.receipt.json` 标明原因、
归档是否发布及仍保留的目录；清理失败也显式记录。已有证据目录从不自动删除。
控制台结果路径转换为 `archive.zip::member`，归档内原始回执不改字节。

自动归档的复核会保留实际读取的输入，并生成派生 `replay-plan.json`，原始 manifest
单独保留。直接复核的重放清单在根目录，恢复链在 `reviewed/`，fxfetch 适用的定向复核
在 `targeted-review/`。重放只覆盖实际取得的输入，不把跳过或无法读取的任务补成成功。

## 从归档继续分析

```powershell
fxapk evidence-review review.zip --archive-member replay-plan.json --out rereview
fxapk evidence analyze evidence.zip --member sample.apk --out analysis
fxapk intake-fetch evidence.zip --archive-member saved-task.zip --out intake
fxapk pcap-leads "capture.zip::capture.pcap" --json pcap-result.json
```

通用成员引用格式是 `archive.zip::relative/member`。复核清单中的相对路径在该归档内
解析；旧绝对路径只能通过索引中的源目录提示映射回包内，外部路径失败，不能回退读取
本机文件。PCAP 与 socket/UID 命令读取、运行时 JSON 的程序接口已接入此读取层；运行时 JSON
暂没有接受成员引用的独立 CLI 参数。PCAP 的 UID 自动发现
只检查同一成员目录，不跨案件目录拼接。

每个选中成员在分析器拿到数据前完成大小及 SHA-256 校验。要求文件路径的工具只临时
展开选中成员，用后清理，不预先展开整个包。APK 入口固定运行现有离线分析流水线；
`archive-analysis.json`、report JSON、digest 和 HTML 记录读取校验状态与实际分析结果。
复核的 per-task receipt、feedback、report、digest、HTML 保留读取失败原因。
上述报告投影只覆盖归档输入分析/复核；四个 `--archive-out` 的输出存储状态见控制台及
旁侧 `.receipt.json`。macOS 不支持这些命令使用的强制内存限额子进程，`evidence analyze`
不会启动 APK 分析子进程，回执保留 `platform_memory_limit_unavailable` 并退出失败；
纯归档、校验及提取不受该子进程限制。

单成员成功不表示其他成员已校验；整包完整性须执行 `evidence verify`。原始压缩 APK、
图片、视频的压缩收益可能很小，实际体积以归档回执为准。

## 案件包原有校验

```powershell
fxapk evidence case-verify case.zip --member manifest.json
```

该入口在受限临时目录完整展开，再调用原有 `verify_case_package`，保留身份、哈希、
schema 及 REA 校验规则。原 manifest 不改字节，package_id 沿用原值。此入口需要整包
展开空间，是按需读取的明确例外；结束后清理临时目录。

新包记录原始报告 JSON 的 schema；验包同时接受原 schema 与由相同冻结字节确定的迁移版本，
兼容 1.22–1.24 曾写入迁移 schema 的清单。无关版本声明仍拒绝。
软件升级不会要求重写旧包；原有身份、内容哈希与案件证据门继续校验。

## 冻结归档入 corpus

```powershell
fxapk evidence corpus-add case.zip --manifest-member case-package.json --corpus C:\evidence-corpus
```

此入口完整临时展开并通过原案件包校验，再复用现有 `corpus add --package`：
逐字节保存原报告，绑定清单中的 case_id/package_id，保留幂等、冲突与库目录边界。
任一校验失败时不入库。它也需要整包展开空间；corpus 保存报告与检索索引，
原始证据仍保留在归档中。该命令不会移动归档、替换现有 case 目录或删除原包。

长期保存建议每个冻结 revision 独立归档，另保留归档 SHA-256、原案件清单及可查询的
报告索引，迁移与使用时核验；维持另一份独立备份。不能以压缩校验替代备份与恢复演练。
目前未自动迁移 handoff case、改写外部材料索引或配置定期校验任务。

## 边界与可见失败

存储层默认上限：归档 256 GiB、累计文件正文 256 GiB、单成员 64 GiB、文件和目录各
100,000 个、索引与中央目录各 32 MiB、单次操作 3,600 秒。分析器原有更小限制继续生效，
例如复核输入 32 MiB、PCAP 256 MiB、fxfetch ZIP 2 GiB，压缩不绕过这些限制。
Zstd 解码窗口最多 64 MiB；Zstd 与 DEFLATE 单次输出最多 1 MiB，同时核验完整流结束、压缩跨度、CRC、
正文长度及 SHA-256。即使截断流已吐出全部正文，缺少完整帧尾也判失败；成员后的额外帧或数据拒绝。
符号链接、reparse point、特殊文件、路径逃逸、Windows 保留名称、大小写或 Unicode
名称冲突、重复成员、加密及不支持的 ZIP 算法均拒绝。

损坏、截断、CRC/SHA 不匹配、资源超限及输出冲突返回稳定错误码，例如
`archive_member_hash_mismatch`、`archive_decode_failed`、`archive_member_budget`，
不转成零命中或无记录。独立复核任务可继续，失败任务在结果中保留。
`pack/verify/extract/case-verify` 成功退出 0，失败退出 6；离线 APK 分析还可返回 partial 5。
已有采集、复核、恢复和 intake 命令保留其业务退出语义；输出归档失败退出 6，
参数或前置读取错误按各入口既有规则处理（复核、恢复、intake 为 2）。

回归覆盖合成证据的逐字节还原、ZIP64、资源边界、坏包、发布竞争、失败保留、复核重放、
PCAP/运行时读取、原案件校验及真实离线 APK 子进程。设备采集以模拟回执验证归档衔接，
不据此声明真实设备或真实案件验收。
