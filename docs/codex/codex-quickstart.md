<!-- 个人安全研究 / 测试用途；如发现涉诈线索可提供给相关部门依法处置。 -->

# Codex 一键命令 / 快速上手（驱动 fxapk 做反诈 APK 取证）

> 把下面「一键提示词」整段贴给 Codex 即可。所有资料（探针 / 指导书 / playbook / 方法目录 / CLI）随 fxapk 仓库 `git pull` 更新——**不再手递压缩包**。

## 一键提示词（贴给 Codex）

```
你驱动 fxapk（仓库 s-silt/fxapk）做反诈 APK 取证。每次开工先自助更新：
  cd <fxapk仓库> && git pull && pip install -e . --upgrade

【静态】fxapk analyze / auto 出 report.json（端点 / IP / 标识符 + 富化 + 调证分级 advice）。

【抓包/动态：先看打法，再抓】
  fxapk capture-plan report.json        # 据样本规避信号(加固/endpoint=0/加密配方/自建IM)给针对性抓包打法链
按打法选：
  · 探针库 docs/codex/frida-probes/（46 个现成 frida 探针 + 指导书.md，按 §2「症状→选探针」决策表挑）：
      frida -U -f <包名> -l probe-templates/anti-detection-hook.js -l probe-templates/ssl-unpinning-hook.js \
            -l probe-templates/<业务探针>.js -o probe.log -q
      抓完回灌：fxapk probe-leads probe.log --into report.json
  · frida 上不去 / 解不开（反 frida 秒退 / TLS pinning / MTProto 等自建协议 endpoint_total=0）→ 不碰 App 带外抓 pcap
    （PCAPdroid 免 root 导出 / 网关 tcpdump / Wireshark），照样拿接入节点 IP/SNI/DNS（穿透锚点，解不开也能办案）：
      fxapk pcap-leads capture.pcap --into report.json
    更多方法见 docs/codex/capture-methods-beyond-frida.md（旁路抓包 / 静态去 pin / 非 frida 注入 / 非网络取证）。

【排噪音（重要，吃过亏）】线索的 advice 若是「待核」且 reason 含"疑似编码 / hex / base64 / 随机串 / 伪域名"——
  这是 base64/hex 串里夹了点被误当成域名，调证不可回溯。**绝不拿去调证、不主动探测、不回溯，人工核即可。**
  fxapk 已自动把这类降级为「待核」；你严格按 advice 只对「建议调证」目标动作，「待核 / 无需调证」一律不动手。

【回灌串案】探针线索 / pcap 线索都 `--into` 同一 report.json，合并后：
  fxapk graph 串并团伙、fxapk letters 套打调证 / 协查文书草稿。
  probe-leads 台账末尾「取证完备性」诊断 定人 / 穿透 / 固证 三轴缺哪类 → 照提示补抓，直到三轴齐。

深度归因 / 调证报告按 docs/codex/deep-attribution-playbook.md 四铁律产出。
红线：探针唯一出口 console.log、落盘仅设备临时目录、只读不操控；主动探测仅对「建议调证」目标。
```

## 新增能力速查（自上次同步以来）

- **探针库 23 → 46**（`docs/codex/frida-probes/probe-templates/`，按指导书 §2 决策表 ⑲–㊵ 选）：
  - 资金链 `pay-sdk` / C2 指令 `push-c2-inbound` / 卡农 `sms-forward-outbound`
  - Telegram 改包 `telegram-mtproto` + `activity-nav`（绕加载页→视频→登录门控）+ `netstat`
  - 协议栈/RTC `cronet-quic-http3` / `rn-bridge-native` / `mqtt-xmpp-im` / `protobuf-grpc` / `rtc-join`
  - 凭据/原生 `native-crypto-key` / `keystore-alias-tracer` / `mmkv-realm-wcdb-key` / `register-natives`
  - 取证·毁证·数据外泄·远控 `evidence-wipe-interceptor` / `self-uninstall-guard` / `sensitive-data-access` / `accessibility-abuse` / `nfc-hce-relay` / `multiopen-virtualapp-detect`
  - 冷启动锚点 `sdk-appkey` / `objstore-config`
- **新命令**：
  - `fxapk probe-leads probe.log [--into report.json]` —— 探针 `[LEAD]` 散点 → 调证台账 + 取证完备性诊断 + 回灌
  - `fxapk pcap-leads capture.pcap [--into report.json]` —— 带外 pcap → 接入节点 IP:port + SNI + DNS（纯标准库、零依赖；解不开也能办案）
  - `fxapk capture-plan report.json` —— 据规避信号给针对该样本的抓包打法链
- **排噪音**：`classify_domain` 自动把 base64/hex/随机串「编码伪域名」降级为「待核」+ 标原因（不静默丢弃，可人工核）。
