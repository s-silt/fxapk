<!-- 个人安全研究 / 测试用途；如发现涉诈线索可提供给相关部门依法处置。 -->

# fxapk · Claude ↔ Codex 异步信箱协议（飞书）

两台机、不同网络，**全程走飞书**异步对讲 + 传文件（免梯子、免 OneDrive 共享）。

- **飞书群 `FXAPK`** = 对讲机：状态 / 问答 / 交接（`feishu_handoff.py send / read`）。
- **飞书云空间** = 附件柜：report.json / pcap / apk / PDF（`sendfile` 上传 → 消息自动带 `file_token`；对方 `getfile` 取回）。**同一个 app 两边直接存取，无需共享文件夹。**
  > 飞书免费租户单文件 ≤ 20MB → 脚本自动切块上传、下载拼回（已验 26MB SHA256 一致）。容量有限，**取完用 `delfile` 清理**。

## 分工

- **Codex（机 B + 真机）**：真机取证 —— `fxapk analyze / capture`、frida / pcap / adb，产出 report.json + 散点线索 + pcap。
- **Claude（机 A）**：核实 / 降噪 / 归属（RDAP·反查）/ 串案 / 出 PDF 报告 / 写下一步抓包任务。

## 一个回合

1. **Codex 干完** → 上传产出 + 发交接：
   ```
   python docs/codex/handoff/feishu_handoff.py sendfile --from CODEX ./刘冰震_report.json
   python docs/codex/handoff/feishu_handoff.py send --from CODEX "刘冰震 取证完; report 见上条 file_token; 需核实 8.x; 球→CLAUDE"
   ```
2. **Claude** → 读 → 取产出 → 核实 / 出报告 → 上传报告 + 发交接：
   ```
   python docs/codex/handoff/feishu_handoff.py read --limit 10
   python docs/codex/handoff/feishu_handoff.py getfile <token> --out 刘冰震_report.json
   # ...核实、出 PDF...
   python docs/codex/handoff/feishu_handoff.py sendfile --from CLAUDE ./刘冰震_报告.pdf
   python docs/codex/handoff/feishu_handoff.py send --from CLAUDE "刘冰震 核实完; 报告见 file_token; 下一步抓 6722 明文; 球→CODEX"
   ```
3. **各自开工先 `read` 看对方最新。**

## 消息约定

- 前缀 `[CLAUDE]` / `[CODEX]`（`--from` 自动加）。
- 交接用「**球→CLAUDE / 球→CODEX**」。
- 文件用 `sendfile`，消息自动带 `file_token`（多块逗号分隔）；对方 `getfile <token...> --out <名>` 取回，用完 `delfile` 清。

## 命令速查

```
send     --from CLAUDE "..."                 发消息
read     [--limit 10]                        读最近消息(旧->新)
sendfile --from CODEX ./x.pcap [--note ...]  上传文件(>18MB 自动切块)+发指针
getfile  <token[,token2]> --out x.pcap       下载(多块自动拼回)
delfile  <token[,token2]>                    删云空间文件(清容量)
```

## 两台机要配的（就一件）

- **`.env`（各自本地，不入库）** 放同一份飞书凭据：
  ```
  FXAPK_FEISHU_APP_ID=cli_xxxx
  FXAPK_FEISHU_APP_SECRET=xxxx
  FXAPK_FEISHU_CHAT_ID=oc_xxxx
  ```
- 脚本 `docs/codex/handoff/feishu_handoff.py` 随 `git pull` 更新，两边共用（不含密钥）。
- **不再需要 OneDrive / 共享文件夹** —— 文件走飞书云空间，同 app 直接存取。

## 给 Codex 的一键 prompt（整段粘给 Codex）

```
你和 Claude（另一台机）通过飞书异步协作取证（对讲 + 传文件全在飞书）。每回合：
1) 先同步并读对方最新：
   cd <fxapk仓库> && git pull && pip install -e . --upgrade
   python docs/codex/handoff/feishu_handoff.py read --limit 10
2) 按 [CLAUDE] 的「下一步 / 球→CODEX」在真机取证：
   fxapk capture-plan report.json → 按打法 fxapk analyze/capture、探针 probe-leads、带外 pcap-leads。
3) 产出上传飞书云空间 + 发交接（大文件自动切块，不用 OneDrive）：
   python docs/codex/handoff/feishu_handoff.py sendfile --from CODEX ./<案子>_report.json
   python docs/codex/handoff/feishu_handoff.py send --from CODEX "<案子>进展; 文件见 file_token; 需Claude核实啥; 球→CLAUDE"
红线不变：探针只读、唯一出口 console.log、落盘仅设备临时目录；带外 pcap 不碰 App；
待核 / 编码伪域名不调证、不回溯；主动探测仅对「建议调证」目标。
前置：本机 .env 要有飞书三件套(FXAPK_FEISHU_APP_ID/APP_SECRET/CHAT_ID)，没有找用户要。
飞书免费版单文件 ≤20MB(脚本自动切块)、容量有限，取完文件用 delfile 清。
```
