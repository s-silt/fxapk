<!-- 个人安全研究 / 测试用途；如发现涉诈线索可提供给相关部门依法处置。 -->

# fxapk · Claude ↔ Codex 异步信箱协议（飞书 + OneDrive）

两台机、不同网络，通过「云端集合点」**异步对讲**（不是实时直连）。

- **飞书群 `FXAPK`** = 对讲机：状态 / 问答 / 交接（小消息）。脚本 `feishu_handoff.py`。
- **OneDrive `fxapk-handoff/`** = 附件柜：report.json / pcap / apk / PDF（大或结构化文件）。

## 分工

- **Codex（机 B + 真机）**：真机取证 —— `fxapk analyze / capture`、frida / pcap / adb，产出 report.json + 散点线索 + pcap。
- **Claude（机 A）**：核实 / 降噪 / 归属（RDAP·反查）/ 串案 / 出 PDF 报告 / 写下一步抓包任务。

## 一个回合

1. **Codex 干完** → 产出放 OneDrive `fxapk-handoff/<案子>/` → 发飞书交接：
   ```
   python docs/codex/handoff/feishu_handoff.py send --from CODEX "<案子> 取证完; 文件 OneDrive/fxapk-handoff/<案子>/; 需核实: <...>; 球→CLAUDE"
   ```
2. **Claude（自己 pull + 读 OneDrive）** → 核实 / 串案 / 出报告 → 结果写回 OneDrive → 发飞书：
   ```
   python docs/codex/handoff/feishu_handoff.py send --from CLAUDE "<案子> 核实完; 报告 OneDrive/.../报告.pdf; 下一步抓: <...>; 球→CODEX"
   ```
3. **各自开工先读对方最新**：
   ```
   python docs/codex/handoff/feishu_handoff.py read --limit 10
   ```

## 消息约定

- 前缀 `[CLAUDE]` / `[CODEX]`（脚本 `--from` 自动加，读时据此分辨谁说的）。
- 交接用「**球→CLAUDE / 球→CODEX**」标明轮到谁。
- **大文件不进消息**，只写 `文件名 + OneDrive 路径 (+ SHA256)` 当指针。

## 两台机各自要配的

1. **`.env`（各自本地，不入库）** 放同一份飞书凭据：
   ```
   FXAPK_FEISHU_APP_ID=cli_xxxx
   FXAPK_FEISHU_APP_SECRET=xxxx
   FXAPK_FEISHU_CHAT_ID=oc_xxxx
   ```
2. **OneDrive**：两台机同步同一个 `fxapk-handoff` 文件夹（同一微软账号，或把文件夹共享给对方账号）。
3. **脚本** `docs/codex/handoff/feishu_handoff.py` 随 `git pull` 更新，两边共用（不含密钥）。

> 飞书走国内直连（脚本已绕系统代理），不用梯子；OneDrive 登录若报「无网络 / 0x8019xxxx」，临时关系统代理或梯子切全局再登。

## 给 Codex 的一键 prompt（整段粘给 Codex）

```
你和 Claude（另一台机）通过「飞书 + OneDrive」异步协作取证。每回合：
1) 先同步并读对方最新：
   cd <fxapk仓库> && git pull && pip install -e . --upgrade
   python docs/codex/handoff/feishu_handoff.py read --limit 10
2) 按 [CLAUDE] 的「下一步 / 球→CODEX」在真机做取证：
   fxapk capture-plan report.json → 按打法 fxapk analyze/capture、探针 probe-leads、带外 pcap-leads。
3) 产出 report.json / pcap / leads 放 OneDrive 的 fxapk-handoff/<案子>/；大文件只放 OneDrive，不发飞书。
4) 发交接给 Claude：
   python docs/codex/handoff/feishu_handoff.py send --from CODEX "<案子>进展; OneDrive文件路径; 需Claude核实啥; 球→CLAUDE"
红线不变：探针只读、唯一出口 console.log、落盘仅设备临时目录；带外 pcap 不碰 App；
待核 / 编码伪域名不调证、不回溯；主动探测仅对「建议调证」目标。
前置：本机 .env 要有飞书三件套(FXAPK_FEISHU_APP_ID/APP_SECRET/CHAT_ID)，没有找用户要；
OneDrive 要同步同一个 fxapk-handoff 文件夹。
```
