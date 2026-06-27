# Codex 深度归因与调证 Playbook —《技术侦查与调证建议报告》标准

> 给驱动 fxapk 的 agent（Codex）用：拿到 fxapk 报告里「建议调证」的后端**域名 / IP / 标识符**后，对服务器基础设施做**深度归因 + 调证建议**，产出一份《技术侦查与调证建议报告》。**向下挖，不复述** fxapk / 上游 PDF 的结论。
>
> 何时触发：用户要"深挖某域名/IP""做归因/调证报告""找真实源站/运营主体"，或 fxapk 给出建议调证端点后要进一步落到**可调证对象**时。
>
> 性质声明：本项目为**个人安全研究 / 测试**用途；分析中如发现涉诈线索，可提供给**相关部门**依法处置。文中"调证 / 协查 / 办案机关"等仅说明合法取证路径，不代表任何官方身份。

## 四条铁律（不可破）

1. **证据分级**：每个结论必须标 `【证据】`、`【推理】`、`【可信度 高/中/低】`，并区分三档来源——
   - `实测·高`：本会话直连源站 / 权威数据库直接取得的硬证据；
   - `开放OSINT`：crt.sh / urlscan / RDAP / 公开威胁库多源交叉、且经对抗核验未被推翻；
   - `推断`：结构性推理或单一来源，须持证调取核实。
2. **对抗式核验**：主动**推翻自己和上游**（PDF / fxapk）的结论；单一来源不算定论；过度归因（如"路径三段式=某框架独有"）要降可信度或明确推翻并写明纠偏。
3. **绝不编造**：分清能实查 vs 只能给语句——
   - **web-check（操作机自托管，无需 key）= 实测级**，可直接取正文；
   - **Shodan 可实查**（Codex 环境有 `FXAPK_SHODAN_KEY`）；
   - Censys / FOFA / Hunter / ZoomEye / VirusTotal / 微步 等取不到正文时，**只给「建议调取语句」，绝不臆造结果**。
4. **授权与留痕**：仅在授权范围内做轻量被动/主动侦察；直连源站可能被对方边缘日志记录，注意取证留痕风险。

## 工具与数据源（操作机已装两件套，优先用这俩，别空跑外部付费源）

**① fxapk（本仓库 `s-silt/fxapk`）** — APK 取证主入口：`analyze`/`auto` 出端点 / IP / 标识符 + 富化（rdap/whois/icp/dns/asn/shodan/webcheck）；`digest` 取重点；`graph` 串案；`track` 台账。深度归因的输入来自它的 `report.json`（`endpoints[].enrichment`、`attack_surface`、`leads`）。

**② web-check（`lissy93/web-check`，自托管，无需 key = 实测级）** — 对域名 / IP 一把抓 OSINT。两种用法：
- **优先 · 经 fxapk 自动集成**：设 `FXAPK_WEBCHECK_URL=http://localhost:3000`（按本机实际端口），fxapk 的 webcheck 富化器即对「建议调证」端点自动跑 curated 检查（location/get-ip/whois/dns/dnssec/ssl/http-security/tech-stack/ports/mail-config/threats/subdomains/redirects/archives/firewall），结果直接进辖区分流 / 攻击面 / 串案 / `report.json`。→ **Codex 先把这个环境变量设上，跑 fxapk 就顺带拿到 web-check 数据。**
- **深挖 · 直接打 API**：对单个可疑目标逐项 `curl 'http://localhost:3000/api/<check>?url=<域名或IP>'`。

**侦察动作 → 工具映射**：

| 要查什么 | web-check check | 补充 |
|---|---|---|
| 注册 / 解析 / NS | `whois` `dns` `dns-server` `txt-records` | RDAP 直查、历史 WHOIS |
| 证书 / SAN / TLS | `ssl` `tls-cipher` `tls-handshake` | crt.sh 查轮换域池 / CT 历史 |
| HTTP / CDN / WAF 指纹 | `headers` `http-security` `firewall` `hsts` `redirects` `tech-stack` | 对 ESA/acw_tc/via:ens-cache/AmazonS3 等见下文特征表 |
| 归属 / 地理 / 端口 | `location` `ip-info` `get-ip` `ports` `trace-route` | ASN/BGP 走 RIPEstat |
| 关联 / 子域 / 历史 | `hosts`（subdomains）`archives` | 被动 DNS / urlscan 补历史解析与站群 |
| 威胁情报 | `threats` `blocks` | VT / 微步（key-gated）给语句 |
| 邮件配置（找源站线索） | `mail-config` | SPF/DKIM/DMARC 可能泄真实邮件服务器 |

**web-check 不覆盖的**（被动 DNS 历史、CT 全量轮换池、ASN-BGP 深查、Shodan/Censys/FOFA/Hunter/ZoomEye）→ crt.sh 直查 + **Shodan 实查（Codex 有 key）** + 其余 key-gated 给「建议调取语句」。

## 动态抓包抓不到目标：诊断 + 自写探针（绝不"抓不到就算了"）

`fxapk capture` 已内置 mitmproxy + frida SSL unpinning（OkHttp3 / SSLContext / TrustManagerImpl）+ frida-core 运行时密钥 hook + JS-bridge 事件 + OkHttp 加密前明文 token + SQLCipher 落库明文。**先确认这些已生效**（看 capture 日志的 hook 命中）。关键目标（客服后端 / 聊天会话 / 加密请求体）若仍没抓到——**不要停**。

**先查现成探针库**（`git pull` 更新，别动手写重复轮子）：本仓库 `docs/codex/frida-probes/` 有 **46 个现成 frida 探针** + 指导书（`指导书.md`）。按指导书 §2「症状 → 选哪个探针」决策表挑，直接 `frida -U -f <包名> -l probe-templates/<探针>.js -q` 注入。覆盖：Telegram/MTProto 改包、QUIC/Cronet、RN/Flutter、MQTT/gRPC、RTC 裸聊、支付 SDK 商户号、推送 C2、短信马、AndroidKeyStore/MMKV 解密 key、native 接入节点、敏感数据窃取/无障碍远控/NFC 盗刷/毁证抢救/多开识别等。**确实没有覆盖的症状，再按下表诊断写针对性探针**：

| 症状 | 大概率原因 | 探针怎么写 |
|---|---|---|
| 抓到 HTTPS 但请求体是密文/乱码 | 应用层加密（CryptoJS/AES `{data,timestamp}` 信封） | 优先用 fxapk 抠的 `crypto_recipe`（算法/key/iv）离线解密；或 hook `javax.crypto.Cipher.doFinal` / 应用自身加解密·签名函数，dump 明文 + URL |
| 聊天/实时消息不在流量里 | 走 **WebSocket**（socket.js / OkHttp `WebSocket` / WebView 内 JS） | hook `okhttp3.WebSocket` / `WebSocketListener.onMessage`、WebView `evaluateJavascript` / JS-bridge、或 H5 里 `WebSocket.prototype.send`+`onmessage`，dump 收发帧 |
| 端点只在点了某功能后才出现 | UI 触发型（要进客服会话才发请求） | 驱动 app 走到该功能（点客服/发消息）再抓；必要时录操作脚本复现 |
| 完全没流量 / 进程秒退 | pinning 没绕过 / 反 frida / 非 OkHttp 栈 / native 发包 | 加强 unpinning + spawn 模式 + 反检测；非标准栈则 hook 其发送函数（`java.net.*`、native `send`/JNI） |

**写探针标准做法**：写一段 frida JS hook 上述方法，把**明文 URL / 参数 / WS 帧 / 解密后体**打到 console（探针在命中高价值锚点处打 `[tag][LEAD-...]` 标记）；`frida -U -f <包名> -l probe.js -o probe.log -q` 启动并触发对应功能、**落盘** `probe.log`。

**回灌进调证线索（一条命令）**：
```
fxapk probe-leads probe.log                     # 聚成调证台账（按 LeadCategory 分组 + 调证落点 + 取证完备性诊断）
fxapk probe-leads probe.log --into report.json  # 直接把探针线索回灌进 fxapk 报告的 leads（去重、source=runtime-probe）
```
台账末尾的「**取证完备性**」会诊断**定人 / 穿透 / 固证**三轴哪类没抓到、该补跑哪个探针——照它补抓。回灌后探针线索与 fxapk 静态/动态线索同构，一起进报告渲染、串案、套打调证函（`fxapk letters`）。

**循环**：选库探针/写探针 → 抓到明文 → `probe-leads` 看台账缺哪类 → 按完备性诊断补跑 → 直到三轴齐、拿到后端端点与聊天内容。**这是默认要求，不是可选**——标准抓包抓不到的客服系统/自建协议，就靠探针库 + 自写探针 hook 才拿下。

## 标准侦察动作（够用即止，按线索取）

- **注册/解析**：RDAP（rdap.org / verisign）、whois、历史 WHOIS、NS。`Gname 等境外注册商 + Cloudflare DNS-only` 是灰产高频组合信号。
- **证书 CT**：crt.sh → SAN / 通配符 / 关联子域 / **轮换域池**（`al{6}.xxx` 这类批量集中签发 = 抗封堵轮换，被拦一个换一个）；90 天短效证书 = 证据时效短。`openssl s_client` 直连取叶证书序列号 / SAN（同证书=同集群）。
- **被动DNS/历史**：urlscan、被动 DNS 库 → 历史解析 / 历史代理 / 关联站群。
- **HTTP/TLS 指纹**：`curl -I` 看 `Server` / cookie / `via` / `x-*` 头识别 CDN/WAF/源站（见下表）。
- **归属**：ASN/BGP（RIPEstat/RDAP）→ **持有方 vs 真实承租方**。省网整段分配里看不到具体租户，往往说明那段 IP 是云厂商作为租户向运营商租用的**边缘节点**，穿透真实运营者要回到云厂商后台。
- **CDN 穿透找源站**：历史 DNS / CT 里的 SAN / 源站泄露 / SSRF / 错配 / 邮件头。

## CDN / 云识别特征表

| 厂商 | 识别特征 | 含义 |
|---|---|---|
| 阿里云 ESA/ENS | `Server: ESA`、`acw_tc`/`cdn_sec_tc` cookie、`EagleId`、`via: ens-cache*`、`x-site-cache-status` | 落地的"电信/联通 IP"多是 ENS 边缘节点，**非真实回源**；真实源站被屏蔽 |
| Cloudflare | NS `*.ns.cloudflare.com`；代理段 104.21/172.67/188.114；DNS-only 时 A 记录直指非 CF 段 | 区分"仅权威 DNS" vs "代理回源" |
| 腾讯云 EdgeOne / 网宿 / 白山 / 华为云 CDN | 各自 HTTP 头特征 | 无对应特征即判"无证据" |
| AWS CloudFront vs 裸 S3 | CloudFront：自定义证书 / `x-amz-cf-*`；S3：`Server: AmazonS3`、`x-amz-request-id`、404 体 `NoSuchBucket` | 区分加速层与静态桶；桶删则 content 不可得 |

★ 核心：**识别"边缘/代理层"≠"真实源站"**。务必标注真实回源是否被屏蔽（被屏蔽则只能靠调证穿透）。

## 调证优先级（辖区驱动——本办案核心口径）

按"现实可行性 + 能否穿透隐源"排，**不是按技术显眼度**。每条注：调证对象 / 法律路径 / 现实可行性。

| 优先级 | 调证对象 | 法律路径 | 现实可行性 |
|---|---|---|---|
| **P0** | **境内云/IDC 实例运营方 / 承租主体**（阿里云/腾讯云/华为云…，含 ESA/ENS/ECS） | 境内办案机关依《反电诈法》《网安法》协查函直接调取 | 高（境内直达；能解出**真实回源 IP + 实名账户 + 支付流水 + 全部轮换域 + 访问日志**——穿透隐源的钥匙） |
| P1 | 境内 IDC / 运营商（电信·联通·移动省网） | 境内办案机关协查 IP 承租记录 | 高（承租方常指向云厂商，与 P0 联动穿透） |
| P2 | 属地办案机关（经侦 / 反诈） | 受害人立即报案 | 高（启动一切刑事调证的前提） |
| P3 | 境外注册商 / 客服平台（Gname / Amazon Registrar / Qiabot 等） | 滥用举报促下架 + 持租户 ID 调后台；实名披露走司法协助 | 举报高 / 披露中 |
| P4 | Cloudflare / AWS | 执法门户 + MLAT/OIA | 低-中（多为账户/付款，无流量日志；删桶后 content 不可得） |
| P5 | 其它境外（关联站群所在国，如 MOACK/JT） | 对应国司法协助 | 低（跨境，关联案非主案） |

★ 与 fxapk 一致：**国内登记/承租主体 = 最高调证价值**；境外服务器不走调证、走攻击面取证 + 找源站。即便某端点被 fxapk 标「无需调证」，只要其 ASN/ICP 登记主体是境内提供商，也要捞出来列为调证目标。

## 标识符语义研判

`bid / eid / csBid / groupid / agentid` → 商户 / 租户 / 坐席 / 分组 / 渠道 ID。判定：GitHub code search + 搜索引擎**零命中 = 每次部署独立生成的一次性私有 token（反溯源），不是可复用库常量**。价值：持这些 ID 向客服/平台后台调取本租户的坐席账号、**完整聊天记录**（= 诈骗话术直接证据）、访客信息、登录 IP。

## 固定输出结构《技术侦查与调证建议报告》

开头：**证据层级说明** + **执行摘要**（相较上游有哪些深化/修正，≤3 条）。

- **A. 基础归因**：注册商 / 注册时间 / 权威 NS / 真实承载 / 可信度。
- **B. 网络基础设施图谱**（ASCII）：标清**边缘层 vs 真实源站**、轮换池、排除项（如运营商 sinkhole/拦截 IP）。
- **C. 云服务商判断**：逐项 ✅/❌ + 证据 + 可信度。
- **D. 关联域名列表**　**E. 关联 IP 列表**（归属 + 角色：边缘 vs 回源）　**F. ASN 列表**（持有方 vs 真实运营商/承租方）。
- **G. 系统架构判定**：自建 / 二开 / 第三方；含**对抗核验纠偏**段（写明推翻了哪些原判及依据）。
- **H. 潜在运营主体 + 标识符语义**。
- **I. 潜在调证对象 + 调证优先级**（P0–P5 + 法律路径 + 现实可行性）。
- **J. 调证后最可能获得的数据**（来源 / 可得数据 / 价值星级 ★）。
- **K. 建议调取语句**：FOFA / Hunter / ZoomEye / Shodan / Censys / crt.sh / VT / urlscan / 微步 + 指纹比对（**Shodan 有 key 可附实查结果**，其余给语句）。
- **L. 没做到 / 风险 / 下一步**：风险重点写**证据灭失**（短效证书 / 每日轮换域 / 删桶 → 尽快固证）；下一步固定三条——① 立即报案并固证本报告 ② 向 P0（境内云）调证穿透隐源 ③ 持 ID 调聊天记录与坐席。

## 禁止

编造 key-gated 源的结果；停留在表层复述上游；把边缘节点当真实源站；把可信度「高」乱标在单一来源/推断上；按技术显眼度而非现实可行性排调证优先级。
