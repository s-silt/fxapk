<!-- 个人安全研究 / 测试用途；如发现异常线索可提供给授权方依规处置。 -->

# fxapk · Claude ↔ Codex 异步信箱协议（飞书对讲 + OneDrive 附件）

两台机、不同网络，异步对讲（不是实时直连）。

- **飞书群 `FXAPK`** = 对讲机：状态 / 问答 / 交接（`feishu_handoff.py send / read`）。
- **OneDrive `fxapk-handoff/`** = 附件柜：report.json / pcap / apk / PDF **一律放这里**。两台机同步同一个文件夹，消息里只写文件的 OneDrive 路径。**文件不走飞书云空间。**

## 分工

- **Codex（机 B + 真机）**：真机取证 —— `fxapk analyze / capture`、frida / pcap / adb，产出 report.json + 散点线索 + pcap。
- **Claude（机 A）**：核实 / 降噪 / 归属（RDAP·反查）/ 跨样本关联 / 出 PDF 报告 / 写下一步抓包任务。

## 一个回合

1. **Codex 干完** → 产出放 OneDrive `fxapk-handoff/<案子>/` → 发飞书交接：
   ```
   python docs/codex/handoff/feishu_handoff.py send --from CODEX "<案子> 取证完; 文件 OneDrive/fxapk-handoff/<案子>/; 需核实 8.x; 球→CLAUDE"
   ```
2. **Claude（自己读本地 OneDrive 同步盘）** → 核实 / 跨样本关联 / 出报告 → 结果写回 OneDrive → 发飞书：
   ```
   python docs/codex/handoff/feishu_handoff.py read --limit 10
   # 读 OneDrive/fxapk-handoff/<案子>/ 里的 report.json、pcap ...
   python docs/codex/handoff/feishu_handoff.py send --from CLAUDE "<案子> 核实完; 报告 OneDrive/.../报告.pdf; 下一步抓 6722 明文; 球→CODEX"
   ```
3. **各自开工先 `read` 看对方最新。**

## 消息约定

- 前缀 `[CLAUDE]` / `[CODEX]`（`--from` 自动加）。
- 交接用「**球→CLAUDE / 球→CODEX**」。
- **大文件不进消息**，只写 `文件名 + OneDrive 相对路径 (+ SHA256)` 当指针。

## 命令速查

```
send  --from CLAUDE "..."        对讲：发消息
read  [--limit 10]               对讲：读最近消息(旧->新)
# 文件一律走 OneDrive(见上)。下面三条是飞书云空间应急工具，默认不用：
sendfile --from CODEX ./x.pcap   (应急)上传飞书云空间(>18MB 自动切块)+发指针
getfile  <token[,token2]> --out x.pcap
delfile  <token[,token2]>        删云空间
```

## 两台机要配的

1. **`.env`（各自本地，不入库）** 放同一份飞书凭据：
   ```
   FXAPK_FEISHU_APP_ID=cli_xxxx
   FXAPK_FEISHU_APP_SECRET=xxxx
   FXAPK_FEISHU_CHAT_ID=oc_xxxx
   ```
2. **OneDrive**：两台机同步同一个 `fxapk-handoff` 文件夹（同一微软账号，或把文件夹共享给对方账号）。
   > B 机 OneDrive 登录若报「无网络 / 0x8019xxxx」：临时关系统代理或梯子切全局再登（飞书走直连不受影响）。
3. **脚本** `docs/codex/handoff/feishu_handoff.py` 随 `git pull` 更新，两边共用（不含密钥）。

## 给 Codex 的一键 prompt（整段粘给 Codex）

```
你和 Claude（另一台机）通过「飞书对讲 + OneDrive 附件」异步协作取证。每回合：
1) 先同步并读对方最新：
   cd <fxapk仓库> && git pull && pip install -e . --upgrade
   python docs/codex/handoff/feishu_handoff.py read --limit 10
2) 按 [CLAUDE] 的「下一步 / 球→CODEX」在真机取证：
   fxapk capture-plan report.json → 按打法 fxapk analyze/capture、探针 probe-leads、带外 pcap-leads。
3) 产出 report.json / pcap / leads 放 OneDrive 的 fxapk-handoff/<案子>/；大文件只放 OneDrive，不发飞书。
4) 发交接给 Claude：
   python docs/codex/handoff/feishu_handoff.py send --from CODEX "<案子>进展; OneDrive文件路径; 需Claude核实啥; 球→CLAUDE"
红线不变：探针只读、唯一出口 console.log、落盘仅设备临时目录；带外 pcap 不碰 App；
待核 / 编码伪域名不溯源、不回溯；主动探测仅对「建议调证」目标。
前置：本机 .env 要有飞书三件套(FXAPK_FEISHU_APP_ID/APP_SECRET/CHAT_ID)；
OneDrive 要同步同一个 fxapk-handoff 文件夹(B 机首次登录若报无网络，临时关代理/梯子全局再登)。
```
