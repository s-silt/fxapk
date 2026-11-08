# fxapk 仓库指令（Copilot code review 与 coding agent 通用）

fxapk 是 APK 静态/动态分析 CLI（Python 3.11+，发行包名 `fxapk`，导入包名 `apkscan`）。审查与写代码时按下列
优先级执行；**数据红线 > 正确性 > 工程约定**。

## 数据红线（逐行严查新增内容）

1. **测试与文档只允许保留值**：域名用 `example.com` / `.test` / `.invalid`；IP 用文档保留段
   `192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`、`2001:db8::/32`；测试需要
   `not is_private` 语义时可用 `100.64.0.0/10`（RFC 6598，共享地址空间，`is_global=False`，不是公网或文档保留段）。**新增行禁止**引入真实可注册 TLD
   的编造域名（`.cn`/`.shop`/`.vip` 等属历史遗留，不得新增）。
2. 不得出现任何真实服务标识：真实后端域名/IP、存储桶名、AppKey、凭据、个人信息。
   合成夹具值必须一眼可辨为合成。
3. 行内豁免写 `leak-scan:` + `allow` + **具体的逐行理由**；同一理由批量豁免多行是红旗，
   应改值而不是豁免。
4. 面向公开的文本（注释/文档/输出文案）保持中性技术表述。

## 正确性纪律（本仓库特有，违反即阻断级意见）

5. **宁可漏，不可造**：静态/被动分析路径上的启发式，若可能凭随机或密文字节产出
   看似权威的结果（IP、域名、端点），一律拒绝——分析工具伪造证据是一票否决。
6. **缺失不是阴性**：分析器 timeout / partial / skipped / 输入不可见时，「未发现」不得
   被解释或消费为「不存在」；相关结论必须进 visibility / blocked_claims 体系。
7. **确定性输出**：分析器结果不得依赖 set/dict 遍历序或文件系统序（跨进程
   PYTHONHASHSEED 不同）；截断前先排序。串行与并行路径必须逐字节一致。
8. **接线锁**：守门测试必须走真实入口（pipeline 等），并能证明「删掉被测修复该测试变红」；
   只调私有函数的单测锁不住接线。断言的期望值写字面量，不与实现共享常量。
9. 富化器继承 `BaseEnricher`，失败转 `EnrichmentResult(ok=False)`，不抛异常、
   不裸 `except`、不吞日志。

恢复链另核 `intake-fetch` / `evidence-review` / `recover-runtime` 的真实 CLI、worker、回执与 report/digest/HTML 接线：报告健康字段在顶层 `analysis_status`，不从 meta 猜测；失败、超时、零命中、依赖未执行与来源未绑定不得被后续成功覆盖。哈希一致与模拟成功不证明原 APK 来源、完整方法语义或案件闭环；真实设备验收与合成测试分开报告。

## 工程约定

10. Python type hints 必须；测试用 pytest（不用 unittest）。
11. 新增可选依赖必须进 `pyproject` 对应 extra，且 `ci.yml` 相应 job 安装；依赖可选 extra 的
    测试在模块顶部 `pytest.importorskip`。
12. `tests/synthetic/baselines/` 语义快照只经 `tools/update_synthetic_baseline.py` 更新；
    类别检出 `baseline.json` 按该目录 README 的独立流程生成。两者须审阅并提交 diff，CI 不得改写。
13. Commit 用 conventional 前缀，中文正文可；PR 保持单一主题。

归档变更须核验 `evidence pack/verify/extract` 与四个 `--archive-out` 入口：压缩流完整结束、原文件哈希、成员边界与失败保留均不能省；存储成功不升级业务状态。归档引用不得回退本机外部路径；冻结案件 schema 按原报告 JSON 判断，详见 `EVIDENCE-ARCHIVE.md`。
