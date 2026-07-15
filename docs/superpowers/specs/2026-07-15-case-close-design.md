# fxapk Case Close 闭环编排器设计

## 1. 目标

新增代码级 `fxapk case close` 闭环编排器，把目前分散的静态分析、PCAP-first、运行时端点合并、联网富化、五层归因和报告生成串成可验收流程。

完成条件不再等同于“命令执行结束”或“报告文件存在”。每份报告必须带结构化 `meta.closure`，明确回答：

1. 静态分析是否可信；
2. 有设备时是否取得目标应用的有效动态业务候选；
3. 运行时端点是否重新完成联网富化；
4. 每个主目标的办案五层是否有证据；
5. 可用的多源平台是否实际执行，并区分命中、无记录、失败、跳过和未配置；
6. CDN/边缘场景是否取得 Origin，未取得时卡在哪一层、下一步向谁调什么；
7. 最终服务器商和调证对象是否落实，还是只能明确标记未闭环。

## 2. 非目标

- 不把基础设施提供商推断成涉案 App 实际运营者。
- 不主动扫描、爆破、利用或绕过目标认证；所有新增外部查询默认是被动查库。
- 不把案件样本、真实 IP/域名、PCAP、账号、令牌、API 密钥、运行目录或个人协作路径写入代码、测试和文档。
- 不移除现有 `analyze`、`auto` 的尽力而为产出；通过新增闭环状态和严格模式提高可判定性。

## 3. 当前缺口

### 3.1 运行时端点没有重新富化

`dynamic.merge.merge_runtime_endpoints()` 只合并端点并生成 Lead；`merge_and_rerender()` 随后直接写报告。运行时主业务 IP 不会重新经过 `core.enrichment` 和 `core.attribution`，因此静态端点可能有归属信息，而动态主业务 IP 只有浅层 Lead。

### 3.2 “五层”与办案闭环语义不一致

当前 `core.attribution` 的五层是：资源登记方、Origin ASN、托管商、边缘服务商、实际站点运营者。最后一层按设计恒为未知；域名解析 IP 也明确不跑逐 IP RDAP。

办案所需五层应独立建模为：

1. 运行时证据；
2. IP 资源登记；
3. BGP 宣告；
4. 承载产品、机房和转租链；
5. 最终服务器商与租户调证对象。

实际站点运营者保留为独立字段，只有直接证据时才填写。

### 3.3 PCAP 成功判据过松

当前只要代理通道成立或拉回一个有效文件头的 floor PCAP，即使没有报文、端点或目标 UID 归属，也可能返回 `done`。这能表达“采集通道启动成功”，不能表达“案件动态闭环完成”。

### 3.4 多源要求没有统一执行与状态

现有正式 Enricher 只覆盖 DNS、WHOIS/RDAP、ASN、ICP、Shodan、证书透明度和 web-check。其它已配置平台没有统一适配器；报告也缺少逐目标、逐来源的状态矩阵。

### 3.5 完整度只覆盖静态分析器

`Report.analysis_status/completeness` 只按静态 Analyzer 成功率计算；`analyze --strict` 不检查动态、富化、多源、Origin 或最终调证对象。`auto` 只打印各步骤，没有顶层闭环状态和严格退出码。

## 4. 总体架构

采用独立闭环层，避免继续扩大 `dynamic.auto` 和 `dynamic.merge` 的职责。

### 4.1 新模块

- `apkscan/core/closure.py`
  - 主目标选择；
  - 运行时端点再富化；
  - 办案五层组装；
  - 多源覆盖矩阵；
  - 闭环状态计算；
  - 结果写入 `report.meta["closure"]`。
- `apkscan/core/report_io.py`
  - 把 report.json 安全反序列化为 `Report`；
  - 保留现有状态字段和未知扩展字段；
  - 原子写回 JSON，按需重渲同名 HTML。
- `apkscan/commands/case.py`
  - Typer 子命令 `fxapk case close`；
  - 统一参数、终端摘要和严格退出码。
- `apkscan/enrichers/multisource.py`
  - key-gated 被动平台适配器；
  - 统一请求边界、脱敏错误和 `SourceOutcome` 状态；
  - 标记为 `case_close_only=True`，防止普通静态流水线对所有端点消耗配额。

### 4.2 现有模块改动

- `apkscan/core/registry.py`：允许 Enricher 声明 `case_close_only`。
- `apkscan/core/enrichment.py`：暴露可复用的端点富化入口；普通静态阶段跳过 `case_close_only`，闭环阶段显式启用。
- `apkscan/core/attribution.py`：保留现有基础设施归因，补充逐解析 IP 的 IP-RDAP/BGP 信号接线；不改变 `service_operator` 的保守语义。
- `apkscan/dynamic/capture.py`：新增采集质量结构，不再把“通道启动成功”当作“闭环完成”。
- `apkscan/dynamic/auto.py`：动态合并后调用闭环服务，返回顶层 `closure` 和 `status`。
- `apkscan/cli.py`：注册 `case` 子命令，并为 `auto` 增加 `--strict-case`。
- 报告 JSON/HTML/digest：展示闭环摘要、逐来源状态、逐目标缺口和下一步。

## 5. 数据模型

闭环数据放在 `report.meta["closure"]`，保持 Report 顶层向后兼容。

```json
{
  "schema_version": "1.0",
  "status": "complete",
  "checks": [
    {
      "id": "dynamic_evidence",
      "status": "pass",
      "reason": "observed target-app runtime endpoint",
      "evidence_refs": ["runtime-pcap:flow-1"]
    }
  ],
  "targets": [
    {
      "value": "198.51.100.10",
      "kind": "ip",
      "status": "complete",
      "layers": {
        "runtime_evidence": {"status": "complete", "evidence": []},
        "resource_registration": {"status": "complete", "evidence": {}},
        "bgp_announcement": {"status": "complete", "evidence": {}},
        "hosting_delivery": {"status": "complete", "evidence": {}},
        "request_target": {"status": "complete", "evidence": {}}
      },
      "source_status": {},
      "origin": {"required": false, "status": "not_applicable"},
      "gaps": []
    }
  ],
  "source_summary": {},
  "gaps": [],
  "next_actions": []
}
```

### 5.1 状态枚举

- 闭环：`complete | partial | failed`。
- 检查项：`pass | warn | fail | not_applicable`。
- 五层：`complete | partial | missing | not_applicable`。
- 多源：`hit | no_record | failed | skipped | disabled`。

`disabled` 表示平台未配置，不得写成“已查无记录”；`no_record` 表示请求成功但没有目标记录；`failed` 必须保留无密钥的脱敏错误类型，不保留 URL 查询串、请求头或响应正文中的敏感字段。

## 6. 主目标选择

闭环不对所有静态字符串无差别消耗外部配额。候选只来自 `advice=建议调证` 的 domain/IP，并按以下顺序稳定排序：

1. 有目标应用 UID/进程归属的运行时端点；
2. 有双向 payload 的运行时端点；
3. 有 SNI/HTTP Host 的运行时端点；
4. 其它运行时端点；
5. 静态高可信 C2/后端端点。

默认最多处理 6 个主目标，可用 `--max-targets` 调整。排序必须确定，不能依赖 set/hash 顺序。

## 7. PCAP-first 质量门槛

采集通道和案件动态完成度分开记录：

- `channel_ready`：代理、reverse 或 floor 抓包通道已启动；
- `pcap_valid`：文件格式有效且包含至少一个数据包；
- `business_candidate_count`：排除私网、广播、已知拦截和系统基础设施后，至少一个公网业务候选；
- `target_attributed_count`：候选能通过 UID/socket 时间线归属目标应用；
- `dynamic_status`：
  - `complete`：至少一个目标归属业务候选；
  - `partial`：有业务候选但无法唯一归属目标应用；
  - `failed`：空 PCAP、无业务候选或抓包通道失败。

现有 `capture.run()` 的 `done` 可继续表示采集命令完成，但闭环器不得据此单独判定动态完成。

## 8. 运行时端点再富化

闭环器从 endpoint evidence 识别运行时端点，对选中的主目标重新执行：

1. DNS/IP-RDAP/WHOIS/ASN/ICP；
2. BGP prefix/origin/upstream；
3. Shodan、证书透明度；
4. 已配置的 FOFA、Quake、Hunter、ZoomEye、Censys、VT、OTX、urlscan、被动 DNS；
5. 重新调用基础设施 attribution；
6. 组装办案五层；
7. 更新对应 Lead 的调证对象、证据清单和“待核/未闭环”说明。

幂等要求：重复执行 `case close` 不重复 Lead、不重复 evidence、不覆盖人工备注；允许刷新联网来源状态。

## 9. 多源适配器

### 9.1 安全边界

- 默认 `passive`，只调用第三方数据库/API，不直接访问目标。
- 所有凭据只从环境变量读取；日志、报告和异常中不得出现值。
- HTTP 超时、429、401/403、404、空结果和解析失败分别归类。
- 原始 API 响应只在显式指定的本地证据目录保存；默认报告只保留规范化摘要。

### 9.2 第一版来源

- 无密钥：RDAP/WHOIS、DNS、RIPEstat BGP、crt.sh、urlscan 搜索。
- 密钥可选：Shodan、FOFA、Quake、Hunter、ZoomEye、Censys、VirusTotal、AlienVault OTX。
- web-check 保持现有主动/被动模式边界，不因闭环器绕过 `authorized-active` 门控。

每个适配器必须声明：`name`、`applies_to`、`case_close_only`、所需环境变量和 `active=False`。

## 10. 办案五层组装

### 10.1 运行时证据

从 PCAP、SNI/Host、IP:port、payload、连接频次、时间段和 UID/socket 归属提取。只有静态命中时标 `partial`，不能标完整。

### 10.2 IP 资源登记

必须包含 IP、CIDR/起止地址、netname/resource holder、国家、RDAP handle/remarks。域名目标要对每个解析 IP 单独查询，不能沿用域名 WHOIS 充当 IP 登记。

### 10.3 BGP 宣告

必须包含 origin ASN、ASN holder 和宣告前缀；上游拿不到时允许该层 `partial`，但必须说明缺失字段。

### 10.4 承载产品、机房和转租

综合 ASN、PTR、平台 banner/hostname、云产品指纹、region、RDAP customer/reassigned remarks、IDC/转售证据。只凭父段 ASN 时标 `partial`。

### 10.5 最终服务器商与调证对象

必须是可执行对象：具体云/IDC/运营商/平台法律实体或仍需先调取的边缘服务商，并列出实例绑定、端口/安全组、租户实名、付款、控制台登录、Origin 配置、访问/回源日志等字段。

若只定位到 CDN/边缘，Origin 未取得，则第五层为 `partial`，闭环总状态不得为 `complete`；下一步明确写向边缘服务商调客户账号和 Origin/回源日志。

## 11. CLI

```text
fxapk case close REPORT_JSON [--online/--offline]
                              [--mode passive|authorized-active]
                              [--max-targets 6]
                              [--strict/--no-strict]
                              [--refresh]
```

- `--strict` 默认开启：`partial` 退出 5，`failed` 退出 6，`complete` 退出 0。
- `--refresh` 忽略已有成功缓存，重新查询；默认复用现有缓存。
- 命令原子写回 JSON；同名 HTML 存在时重渲，不凭空生成 PDF。
- 摘要只显示状态、目标数、缺口和下一步，不打印完整 API 响应。

`fxapk auto` 新增 `--strict-case/--no-strict-case`，默认关闭以保持兼容；无论是否严格，结构化返回都必须包含 `status` 和 `closure`。

## 12. 闭环判定

### 12.1 complete

- 静态分析没有关键失败；
- 有设备且执行动态时，动态状态为 `complete`；
- 每个主目标的五层均为 `complete`；
- 所有已配置且适用于目标的必需来源均为 `hit` 或 `no_record`；
- 边缘/CDN 目标已取得 Origin；仅有可执行的边缘服务商调证对象、仍需通过其日志取得 Origin 时，只能判为 `partial`；
- 每个主目标都有具体调证对象和证据字段。

### 12.2 partial

报告和部分证据可用，但存在任一非致命缺口，例如动态无法唯一归属、BGP/承载层缺字段、配置来源查询失败、Origin 未取得或最终服务器商只能落到上游平台。

### 12.3 failed

报告不可解析、静态关键分析失败、要求动态但无有效 PCAP/业务候选，或闭环器自身关键阶段失败。

## 13. 测试策略

所有测试使用保留地址、`.test` 域名和假凭据。

### 13.1 单元测试

- 五层每层完整、部分、缺失的判定；
- CDN 无 Origin 时总状态不能 complete；
- `hit/no_record/failed/skipped/disabled` 严格区分；
- 错误和输出不泄漏环境变量值；
- 主目标排序和上限确定；
- 重复 close 幂等；
- report.json 反序列化保留状态字段。

### 13.2 集成测试

- 运行时新增 IP 合并后会执行富化并生成五层；
- 空 PCAP 或仅文件头不能通过动态闭环；
- 有业务候选但 UID 歧义时为 partial；
- `case close --strict` 的 0/5/6 退出码；
- `auto` 返回顶层状态，动态失败不能伪装 complete；
- 普通 `analyze` 不调用 `case_close_only` 平台，防配额放大。

### 13.3 合并前质量门槛

```text
python -m ruff check apkscan tests
python -m pyright apkscan
python -m pytest -q
```

另外运行一次脱敏扫描，拒绝提交案件姓名、真实样本哈希、真实 IP/域名、个人路径和疑似密钥。

## 14. 兼容性与迁移

- `meta.closure` 为新增字段，旧消费者可忽略。
- 保留现有 `analysis_status/completeness` 的静态语义，避免破坏 API；案件闭环一律读取 `meta.closure.status`。
- 保留现有 infrastructure attribution 供旧报告和调证函使用；办案五层作为 closure 目标结构新增，不复用 `service_operator` 伪装完成。
- 普通 `auto` 默认仍尽力而为，但必须显式返回 partial/failed；严格退出仅由 `--strict-case` 启用。

## 15. 提交边界

允许进入 GitHub：

- 通用源码、规则、合成测试；
- 本设计及通用 CLI 文档；
- 不含真实目标的示例 JSON。

禁止进入 GitHub：

- `.env`、密钥、token、账号；
- APK/DEX/PCAP、报告、案件名称和真实目标；
- 本机记忆、本地启动说明、个人目录和协作平台路径；
- 临时脚本、缓存和外部 API 原始响应。
