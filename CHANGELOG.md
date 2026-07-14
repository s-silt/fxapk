# Changelog

Notable changes to fxapk. Versioning is semantic; **behavior changes that
affect automated / CI / agent callers are called out explicitly**.

## Unreleased（0.10.0 开发中）

Theme: **PCAP-first 网络证据 + 五层基础设施归属 + 资产沉淀**——动态从"HTTP 代理式抓包"
转向零注入的 PCAP 底座解析；把"IP 归属"从扁平的所属公司升级为五层不塌缩的归因链；
把历次分析的 report.json 沉淀成可查询、可回归、可重建的语料库。

### New — 五层基础设施归属（`core/attribution`）

- 每个域名 / IP 端点富化后组装成**五层不塌缩**归因链，写进 `endpoints[].enrichment["attribution"]`：
  `resource_holder`（IP 资源登记方，IP-RDAP）→ `origin_network`（BGP Origin ASN）→ `hosting_provider`
  （云 / IDC）→ `edge_provider`（CDN / WAF / 边缘代理，多信号加权指纹）→ `service_operator`
  （实际运营者，**恒 unknown，绝不从 ASN / RDAP 推断**）。域名按解析到的每个 IP 逐个产链（per-IP，不合并）。
- edge 指纹为多信号加权：`confirmed` 须 ≥2 个独立强信号（单一响应头可伪造，最多 `probable`），
  负证据（只命中公有云 ASN / 通用 X-Cache / nginx）抑制"租了公有云就当代理坐实"的误判。
- 新增 `ip_rdap` 富化器（`rdap.org/ip` 查网段登记方）填 `resource_holder`——仅认 RDAP `registrant` 实体，
  不拿 abuse / technical 联系人或域名注册方冒充 IP 资源持有方。
- 调证函（`fxapk letters`）新增「基础设施归属链」段，按落地 IP 分层展示，直接支撑"向谁调证"。

### New — 动态 PCAP-first 网络证据

- 零注入 PCAP 解析：TLS ClientHello 跨 TCP 段恢复 + SNI / ALPN 提取、QUIC v1 Initial 解密与 SNI 提取。
- socket 精确归因：TCP / UDP / IPv4 / IPv6、持续 socket 时间线、多 UID 候选时输出**歧义**而非硬猜一个。
- TLS Key Log + tshark 解密链路；HTTP/1.1 · HTTP/2 凭据（Authorization / Cookie）提取与脱敏。
- `floor-only` 模式不再误依赖 Frida；`doctor` 体检覆盖 PCAP 深度能力（QUIC 元数据 / 解密 / tshark 就绪度）；
  报告记录 `build_commit` 溯源。

### New — `fxapk corpus`（样本库）

- **`corpus add REPORT... [--case] [--corpus]`** —— 把一份/多份 report.json
  入库：报告原样字节存进 `reports/<sample_sha256>/<tool_version>_<ruleset_digest>.report.json`，
  并登记进 `manifest.jsonl` 派生索引。库内主键 = `(sample_sha256, tool_version,
  ruleset_digest)`：同样本同版本同规则重复入库**幂等跳过**，换版本/换规则则并存新报告
  （天然做跨版本回归基线）。旧报告缺 `sample_sha256` 时按内容派生 `nosha-` 占位身份、不塌缩。
- **`corpus seen VALUE [--by sample_sha256|package_name|sign_sha256]`** ——
  「见过没」反查；`--by sign_sha256` 按共享签名证书一击串案。
- **`corpus ls [--package|--case|--packer|--type]`** —— 过滤列举。
- **`corpus reindex`** —— 扫 `reports/` 全量重建 manifest（自愈索引；report.json 是唯一
  事实源，只从旧 manifest 继承人工 `case_id`）。
- **`corpus events SHA256`** —— 复用 `report_to_events` 把库内报告吐成 JSONL 喂 agent。
- 地基不引入任何新存储引擎/依赖（不复活图谱/SQLite 台账）；`manifest.jsonl` 是可重建缓存、
  非事实源。

### Safety

- 语料库含真实案件数据（IOC/案件号），根目录**必须**经 `--corpus` 或环境变量
  `FXAPK_CORPUS` 显式指向库外（OneDrive），二者皆缺即**拒跑**（exit 2），绝不默认 `./corpus`；
  且根目录若落在 git 工作树内一律拒跑（防案件数据随 `git add` 混进公开仓库）。
- CI 守卫 + `.gitignore` 覆盖真正的 PII 载荷 `*.report.json`（报告全文），而不仅是派生索引
  `manifest.jsonl` / `ioc_index.jsonl`——git 跟踪的文件里出现任一即 CI 红。
- **取证字节保真**：报告原样存证（`corpus add` 读侧 `read_bytes` + 原子写禁用换行翻译），
  落盘字节 == 原文；不同主键净化后落同一路径时，写盘前**拒绝覆盖**已入库的取证字节（路径碰撞守卫）。

## 0.9.0 — 2026-07-13

Theme: **result credibility, the passive/active network boundary, and
release hardening** — moving fxapk from "what it can detect" toward "why it
judged this, whether the run was complete, and which network behavior is
permitted". (33 commits since 0.8.0.)

### ⚠️ Behavior changes (read before upgrading automation)

- **`--mode passive|authorized-active` (default `passive`)** on `analyze`,
  `auto`, and `batch`. In the default passive mode, enrichers that send
  traffic to the **target** (the web-check active prober) are blocked at the
  pipeline layer, and the Telegram `getMe` probe is not sent. Pass
  `--mode authorized-active` to allow active probing — this requires
  explicit operator authorization. **If you relied on web-check enrichment,
  you must now pass `--mode authorized-active`.**
- **`--strict`** on `analyze`: non-zero exit when the analysis is
  incomplete — exit code **4** if a *critical* analyzer failed, **3**
  otherwise. Default (non-strict) is unchanged: best-effort, exit **0**.
- **Report schema** gained top-level fields — `schema_version` ("1.0"),
  `analysis_status` (`complete|partial|failed`), `completeness` (0..1),
  `critical_failures`, `skipped_analyzers` — and `meta` keys: `mode`,
  `tool_version`, `ruleset_digest`, `stage_status`, `active_enrichers_*`.
  Existing fields are unchanged; consumers should key off `schema_version`.

### Added

- **Passive/active network mode** enforced in code across config → pipeline
  gate → CLI, fail-closed to passive. `web-check` is the sole active
  enricher and is labelled as such; skipped/enabled active enrichers are
  recorded in `meta` for audit.
- **Report credibility layer**: `analysis_status`, `completeness`
  (capability/platform skips excluded from the denominator),
  `critical_failures`, and `ruleset_digest` (a stable, EOL-normalized
  sha256 over the rule files — reproducibility anchor) + `tool_version`.
- **Finding provenance**: central `analyzer` attribution (stamped in the
  pipeline, no per-analyzer churn) and a `confidence` axis orthogonal to
  severity; explicitly heuristic findings default to LOW confidence.
- **Staged pipeline execution** with per-stage `stage_status` and
  stage-level resilience — a crashing stage no longer aborts the whole run;
  an `analyze`-stage crash marks the report `failed`, other stage crashes at
  least `partial`.
- **Anti-forensic / hardening detection**: open-source packer & hardening
  toolchain signatures, native `.so` symbol/string scanning (rename-
  resistant), ELF PT_NOTE hijack + local high-entropy heuristics,
  Xposed/LSPosed module identity from manifest meta-data, and additional
  hook / anti-detection signatures.
- **Dynamic capture hardening**: out-of-band floor pcap automation, explicit
  frida hook-readiness signal, capture-mode flags (`both/floor-only/
  mitm-only`) + `--serial`, degraded status (no fake "done"), UID socket
  snapshot at the capture window.
- **CI release gates**: OS matrix (Linux / macOS / Windows), 80% coverage
  floor, wheel build + clean-install smoke test (`fxapk --version` + rules
  load from the wheel), and `pip-audit` over the isolated fxapk dependency
  tree.

### Fixed

- Zip-bomb declared-size guard applied to the **parallel** analysis path
  (previously serial-only).
- Connectivity probe no longer false-negatives behind restrictive networks
  — mixed domestic + foreign **numeric** anchors over TCP:443 (no DNS
  dependency, bounded latency).
- Manifest-bomb / manifest-poison parsing robustness (no crash on tag
  namespace; string-pool package-name fallback).
- Review follow-ups: unified effective config (analyzer vs pipeline), audit
  scoped to the project dependency tree.

### Changed

- `run()` refactored into a staged `_PipelineState` pipeline
  (behavior-preserving).

---

Earlier releases (≤ 0.8.0) predate this changelog; see the git history and
GitHub release notes.
