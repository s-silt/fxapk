<!-- 由 fxapk 方法调研工作流生成；个人安全研究/测试用途，发现可疑线索可提供给授权方处置。 -->

# 反分析目标 App —— frida 探针之外的抓包/取证方法目录

> 适用对象：分析人员/Codex 驱动取证。前提：**全部操作须在合法授权下，对己方受控样本与隔离取证设备/测试网进行**；改写版样本不得外流；落地个人信息按合规要求留存处置。
> 北极星：**即便密文/协议解不开，只要拿到真实接入节点 IP:port + SNI/JA3(JA4) + DNS + 时序，就是向云厂商/IDC 调主机租户实名的穿透锚点。抓包 ≠ 必须解密。**

---

## 一、按规避类型的决策树

判样本属于哪一类规避，按"先试 → 退到"链路走。所有链路的**兜底终点都是带外 pcap 拿 IP/SNI**（§3 专章）。

```
                          ┌─────────────────────────────────────────┐
                          │ 起手式(任何样本都先挂)：旁路 pcap 被动抓     │
                          │  PCAPdroid(免root) 或 网关/root tcpdump     │
                          │  → 先保底拿 IP:port + SNI + DNS + 时序       │
                          └───────────────────┬─────────────────────┘
                                              │ 同时判规避类型 ↓
   ┌──────────────────────┬──────────────────┼────────────────────┬─────────────────────┐
   ▼                      ▼                  ▼                    ▼                     ▼
①反frida秒退         ②TLS pinning       ③MTProto/自建协议      ④加固壳            ⑤反模拟器
                                         endpoint=0
先试: 不注入旁路      先试: 系统CA模块    先试: 旁路pcap只取      先试: 运行期脱壳     先试: 真机/云手机
 (PCAPdroid/网关)     (AlwaysTrust-      IP/SNI/时序(§3)        (frida-dexdump/    (避开容器特征)
 + 系统CA注入解密     UserCerts)+        + JA4 指纹聚类         BlackDex) 拿真DEX
                     mitmproxy透明代理                          ↓
退到: Xposed注入面    退到: 静态去pin     退到: tls-keylog       退到: 静态去pin+    退到: redroid+
 (LSPosed+TrustMe-    (apk-mitm/smali    (friTap)解TLS内层      重打包(对真DEX)     Shamiko/Zygisk-
 Already) 或          删pin-set)         若是私有非TLS加密 →                       Assistant 硬化
 Zygisk gadget       退到: tls-keylog    内存dump抓会话key(§6) 退到: IL2CPP dump   退到: Xposed hook
 (ZygiskFrida)        (friTap,不替证书)   退到: native send      (Unity样本)         门控/检测函数放行
退到: 改名server      退到: QUIC逼回TCP   hook(Stalker trace)   退到: 内存dump      退到: 磁盘勘验/data
 (strongR/Florida)    或 QUIC keylog                            抓运行期已解密DEX
退到: 带外pcap兜底    退到: 带外只取IP/SNI 退到: 带外IP/SNI兜底   退到: 带外IP/SNI    (§6 冷数据)
```

**快速判别信号：**
- frida 一 attach 就秒退 / TracerPid 检测 → 走**非注入旁路**(§2 第一层)或**换注入面**(Xposed/Zygisk)，不要硬刚 frida-server。
- mitmproxy 起了但 `endpoint_total=0` 且证书没报错 → 多半是 **native 直发/QUIC/MTProto**，转 §3 带外 + tls-keylog/QUIC 专项。
- 装了 user CA 仍 0 流量 / 证书指纹告警 → 真 **pinning**，走系统CA救不了，必须 §2 静态去pin 或 tls-keylog（不替证书）。
- App 卡在视频/加载页不进登录 → **环境门控**，先 §5 隐藏 root/反模拟器让链路放行，再抓。

---

## 二、方法分级目录

分四层：**A 不碰 App 本体的旁路抓包 → B 静态改包去 pinning → C 非frida注入 / 对抗式frida → D 非网络取证**。每条给：工具 / 破哪种规避 / 拿到什么 / 溯源价值 / 与 fxapk 怎么配 / 坑。

### A 层 · 不碰 App 本体的旁路抓包（对①②③⑤⑥免疫，取证最干净、可法庭复现）

**A1. 设备端 VpnService 抓包（PCAPdroid，免 root）——首选起手式**
- 工具：PCAPdroid（F-Droid / GitHub emanuele-f，2025 活跃）。装样本同机，本地回环 VpnService，按 UID 只抓目标 App；导出 pcap / SSLKEYLOGFILE。要解密再装其内置 mitmproxy add-on + user CA。
- 破：①反frida ⑥native直发（不注入、不hook，只接管路由层，检测不到）。开 mitm 解密时仍被 ②pinning 挡。
- 拿到：目标 UID 的远端 IP:port、SNI、DNS、HTTP 明文 URL、pcap；无 pinning 时拿 HTTPS body。
- 溯源：现场 1 分钟部署，**按 App 精确归因**连了哪些节点；明文 URL 常含上报域名/落地参数。
- 配 fxapk：作 capture 的**免-root 旁路替身**——目标机上不了 frida 时，PCAPdroid 出 pcap+SSLKEYLOG，喂 `apkscan.dynamic.pcap_ingest` → probe-leads 抽 IP/SNI/DNS。repackage 去 pinning 后再开其 mitm add-on 拿明文，形成"脱壳→旁路解密"链。
- 坑：部分样本检测 VpnService/代理即门控（⑧），此时**只用被动 dump 别开 mitm**；免 root 解密对 pinning/native TLS 无能为力——**别承诺解密，北极星仍是 IP/SNI**。

**A2. 网关/旁路由 tcpdump 被动镜像（OpenWrt/Linux 上游）——最干净的法庭级旁路**
- 工具：OpenWrt 22.03+/23.05 `opkg install tcpdump-mini`，`tcpdump -i br-lan -s0 -w cap.pcap host <设备IP>`；无存储管道直推 `... -U -w - | nc <PC> 9000`，PC 端 `nc -l 9000 | wireshark -k -i -`。交换机端口镜像可用 `port-mirroring`(TEE/TZSP)。手机走该网关 Wi-Fi，App 零改动。
- 破：①②③⑤⑥ 全免疫（完全不碰 App、不注入、不改证书库）。真机/模拟器一视同仁。
- 拿到：真实对端 IP:port（含 MTProto/native 接入节点）、明文 SNI、完整 DNS、连接时序/流量节律、五元组。TLS 默认不解（无密钥），可对接 tls-keylog 离线解。
- 溯源：**最高穿透锚点价值**——接入 IP:port + SNI 直接调云厂商租户实名/定机房；对 HTTP 抓包 endpoint=0 的样本是唯一可靠数据源；可长期挂机抓节点轮换。
- 配 fxapk：与 capture 互补（capture 走 mitm+frida 拿明文，旁路同时落 pcap 拿带外 IP/SNI 交叉印证，防 frida 被秒退时仍有数据）。pcap → `pcap_ingest` → probe-leads。
- 坑：需控上游网关（自有测试网/取证实验室旁路由），**不得在他人网络嗅探**；QUIC/HTTP3 增多，UDP/443 只能拿 IP+QUIC SNI；App 用 DoH/DoT 时 DNS 看不到明文。

**A3. WireGuard 透明代理热点（mitmproxy --mode wireguard）——一机一档，可选解密**
- 工具：mitmproxy 9+，PC/树莓派 `mitmweb --mode wireguard` 生成 WG 配置/二维码；样本机装官方 WireGuard 客户端扫码连入，全流量经 mitmproxy；用户态、无需 root/改路由表；可只代理指定 App（WG allowed-apps）。纯被动可关 TLS 拦截只看连接事件。
- 破：①②(无pin的HTTPS) ⑤ ⑥(标准socket)。硬 pinning/native TLS 解不开但仍带外拿 IP/SNI。
- 拿到：对端 IP:port/SNI/DNS/时序；装 CA 且无 pinning 时拿 HTTPS 明文；native 非 TLS 流量也完整落 pcap。
- 溯源：比 ARP MITM 干净可控、比网关灵活（无需控路由器）；一条隧道集中一机全流量，**适合批量过样本一机一档**。
- 配 fxapk：作 capture 的"带外+可选解密"承载层；同进程既出明文流又出 pcap；addon 可对接密钥hook 思路在 mitm 侧落 SSLKEYLOG。
- 坑：WG 是**显式 VPN，App 可探测接口存在并门控**（⑧）；硬 pinning 退回 IP/SNI；IPv6 路由不完整（只走 IPv4）；UDP/QUIC 拦截有限。

**A4. ARP MITM 透明嗅探（bettercap）——无网关控制权时的应急补位（优先级最低）**
- 工具：bettercap（Go，2025 活跃）。同子网 `set arp.spoof.targets <IP>; arp.spoof on; net.sniff on`，流量牵引经本机用 tcpdump/mitmproxy 落盘；dissector 直接打印 HTTPS 主机(SNI)/URL/Cookie。
- 破：①②(无pin) ⑤⑥（纯网络层中间人）。
- 拿到：IP:port、SNI、DNS、HTTP 明文、pcap。
- 溯源：只要同 Wi-Fi 就能牵流量拿锚点；dissector 实时显示连了哪些主机，适合快速判活。
- 配 fxapk：把流量牵到跑 capture 同款 mitmproxy 的取证机；SNI/IP + pcap 喂 probe-leads。**多作应急，优先级低于 A1/A2/A3**。
- 坑：**侵入性最强、最易留痕**，损害"证据未被篡改"论证，仅在隔离测试网用；现代交换机 DAI/静态 ARP 会让它失效；不解 pinning。

**A5. pcap 离线指纹与情报富化（JA3/JA4 + Zeek + tshark）——把"解不开的密文"变可串并情报**
- 工具：FoxIO JA4+（GitHub FoxIO-LLC/ja4，2025；Python/Rust/Zeek/Wireshark 插件，提 JA4/JA4S/JA4H/JA4L/JA4X）；Zeek 7.x + 官方 JA4 包出 conn/ssl/ja4 日志；tshark 提 `tls.handshake.extensions_server_name`/`ip.dst`/`dns.qry.name`。对上面任意 pcap 后处理。
- 破：③（靠指纹而非明文绕过"解不开"困境）；JA4 覆盖 TLS/TCP/QUIC/SSH，JA4T 连无 TLS 的 TCP 握手都能指纹，对 cipher-stunting/扩展乱序比 JA3 抗规避。
- 拿到：每流 IP:port/SNI/DNS/JA3/JA4(C)客户端指纹/JA4S 服务端指纹/JA4L 时延/ALPN/TLS版本；聚合出节点清单与指纹聚类。
- 溯源：**JA4 指纹跨样本/跨节点聚类同一家 SDK/打包器**，IP+SNI+JA4 三元组是调租户 + 把多个马甲 App 关联到同一来源的硬锚点。
- 配 fxapk：是 probe-leads 的天然后端（任一旁路 pcap → JA4/Zeek/tshark 抽取 → 归一线索表）。**建议在 fxapk 增 pcap→leads 富化步骤**，让 capture/旁路两路汇入同一线索库交叉关联。
- 坑：需先有 pcap；JA4 是"家族/工具"指纹非唯一身份，结论需多锚点佐证；TLS1.3/QUIC 下 SNI 可能被 **ECH 加密**导致拿不到明文 SNI（退回纯 IP+JA4）。

### B 层 · 静态去 pinning + 重打包（无 frida 运行期，绕反frida/反调试/反模拟器）

**B1. apk-mitm 一键自动改包（自动改 NSC + 摘 pinning + 重签）——流水线初轮快路径**
- 工具：`npx apk-mitm app.apk` → `app-patched.apk`，自动反编译→注入信任 user CA 的 NSC→禁用常见 CertificatePinner/pin-set→内置 apktool+uber-apk-signer 回编重签；支持 `.xapk`/split，`--keep-tmp-dir` 留产物供人工接管。
- 破：NSC 默认不信 user CA + 主流 OkHttp/pin-set；①反frida ⑤反模拟器（无 frida、真机可跑）。
- 拿到：对其能识别的 pinning，一条命令出可抓包 patched APK → 全量 HTTPS 明文。
- 溯源：**分钟级**拿可抓包样本，先批量捞明文 endpoint/IP/SNI 作初筛，硬骨头再上重手段。
- 配 fxapk：作 repackage 的"快路径"分支（入口先试 apk-mitm，失败再落手工 smali/DEX 流程）；明文喂 probe-leads。
- 坑：加固壳常导致回编失败或改到空壳（**壳没脱**）；自写/native pinning 处理不了；**重签触发签名完整性自检的 App 自杀**；版本与 apktool/JDK 兼容偶有坑（先对齐 `node -v`/`java -version`）。

**B2. apktool 手动改 network_security_config 注入 user trust-anchors（仅改资源，最稳）**
- 工具：apktool 3.0.2（2026-04，已切 aapt2）`apktool d -s app.apk -o work`（`-s` 跳 baksmali 只解资源，只改 NSC 时更稳快）。改/建 `res/xml/network_security_config.xml` 加 `<base-config><trust-anchors><certificates src="system"/><certificates src="user"/></trust-anchors></base-config>`（无则在 manifest `<application>` 加 `android:networkSecurityConfig`）；`apktool b work -o patched.apk` → `uber-apk-signer -a patched.apk --allowResign`（内置 keystore+zipalign+v1/v2/v3/v4+verify）。
- 破：A7+ user CA 忽略；①反frida ⑤反模拟器；对仅靠 NSC 默认/OkHttp 默认 TrustManager 的 App 一击即中。
- 拿到：完整 HTTPS 明文（URL/header/body/token/接入域名）。
- 溯源：endpoint_total 从 0 变正的第一杠杆；改一次永久生效，产物哈希可复现固证。
- 配 fxapk：作 repackage 的"资源层补丁"前置（在 `_replace_dex_in_zip` 前后插一步把 NSC 写进 zip，或调 apktool 全量回编）；打完包先于 frida unpinning 跑。**建议 repackage 增 `--netsec-user-ca` 选项**。
- 坑：App 自己声明 `<pin-set>` 时加 user 信任也被拒，**必须连同删 pin-set**（见 B3）；加固壳真实校验在运行期 DEX 里，改静态资源不触达；重签触发完整性自检则失效。

**B3. smali 层删除/中性化 pinning 代码（pin-set / OkHttp CertificatePinner / 自写 X509TrustManager / TrustKit）**
- 工具：`apktool d app.apk -o work`（出 smali）→ `grep -rl 'CertificatePinner\|X509TrustManager\|checkServerTrusted\|TrustKit\|<pin-set' work/` 定位 → (a) NSC 删 `<pin-set>`；(b) smali 把 `CertificatePinner$Builder->add` NOP，或把校验方法体改 `return-void`/`return v0`；(c) 复杂样本用 jadx-gui(1.5.x) 反 Java 读懂校验点再回 smali。`apktool b` → `uber-apk-signer --allowResign`。
- 破：②证书绑定（OkHttp/TrustKit/自写 TrustManager/NSC pin-set 四类主流实现全覆盖）；①反frida ⑤反模拟器。
- 拿到：被 pin 域的完整 HTTPS 明文（pin 域往往正是核心业务/资金/C2 通道）。
- 溯源：**最关键接入节点 IP:port + 明文协议，溯源锚点最硬**。
- 配 fxapk：天然接 repackage 脱壳产物——现流程 `_collect_dump_dex` 从 `out_dir/dump` 收脱壳 DEX，可在 zip 替换前对这些 DEX 反编译扫 pinning 点 patch 再回灌（"去壳"与"去 pin"合并成一次重打包）；静态没扫净时运行期再上 ssl-unpinning 探针补漏。
- 坑：加固壳下真实 pinning 在脱壳后 DEX 里，**必须先 unpack 拿真 DEX**否则改的是空壳；native 层 pinning（BoringSSL 硬编码）smali 改不到（走 §4/tls-keylog）；RASP 校验代码完整性改字节码后自杀；**多处冗余校验漏一处即失败**。

**B4. Magisk 系统CA注入 + 零改包（objection/apk-mitm 的 NSC 副作用对照 / AlwaysTrustUserCerts）——取证最友好**
- 工具：① NVISOsecurity/AlwaysTrustUserCerts（Magisk/KernelSU 模块，开机自动把 user CA 提到系统层，支持 A14+ APEX）；② zygisk_cacerts_authority（Zygisk 进程级注入，对抗只读 APEX）；③ Magisk-Modules-Alt-Repo/custom-certificate-authorities；④ Conscrypt-Trust-User-Certs。装法：Magisk→Modules→Install from Storage→选 zip→重启。
- 破：A7+ user CA 忽略、A14 APEX 只读；③绝大多数依赖系统 trust store + 默认 TrustManager 的普通 TLS；①反frida 完全规避（纯 root/挂载，不注入，样本检测不到 frida）。
- 拿到：**App 字节码零改动**→不触发任何代码完整性自检（相对 B1/B2/B3 更不易被 RASP 反制）→全机 HTTPS 明文。
- 溯源：对**签名+代码双重完整性自检**的样本是唯一不改包的明文路径；适合长期蹲守同一样本。
- 配 fxapk：与 capture 的 SSL unpinning 探针形成层级——先用本法（改证书信任、零改包）看 endpoint 是否就出来，出来则证明是**假性 pinning**（其实只是 user CA 不被信，实测占比不低），根本不必动 frida。**建议 capture 增 `--proxy-only`/`--no-frida` 档**：只起 mitmproxy + 设系统代理，CA 信任交给模块。
- 坑：真自定义 pinning（指纹/公钥钉死）不吃系统 CA，仍 0 流量需叠 unpinning；native 自带 BoringSSL 自校验链无效；需 root（配 Shamiko/Zygisk DenyList 隐藏）；A15+/部分 ROM APEX 挂载更严，认准维护中的模块。

**B5. 加固壳正确次序：先脱壳取真实 DEX → 再静态去 pin → 四联判活验真**
- 工具：脱壳用 fxapk unpack（运行期 dump）或 BlackDex/FRIDA-DEXDump 把运行期释放的真 DEX dump 到 `out_dir/dump`；再走 B2(NSC)+B3(jadx 读+apktool 改 pin)；回灌用 repackage 现成 `_replace_dex_in_zip`+`_zipalign`+`_ensure_keystore_and_sign`；验真用**四联判活**（install Success + am start + 进程非秒退 + frida 可附 + logcat 无 FATAL）。
- 破：④加固壳（运行期释放 DEX）+ ②pinning 组合。
- 拿到：脱壳+去pin 的可抓包 APK → 全量明文；过程中 dump 的真 DEX 本身也是物证（明文字符串、硬编码 IP/域名/密钥）。
- 溯源：**极高**——加固目标样本核心逻辑与硬编码 C2/源站/密钥常藏壳内 DEX，脱壳即固证；去 pin 后抓明文形成"代码+流量"双锚点。
- 配 fxapk：这正是 repackage 主干——在 DEX 替换前后插入"NSC 注入 + smali 去 pin"两步，把"去壳"升级为"去壳+去pin 一次成型"；四联判活复用 `_verdict_app_alive`，失败按现有 S10 降级重装原包，capture 退回 frida。
- 坑：**VMP/dex2c/虚拟化壳 dump 出空壳→整条链失效（成功率约 35-50%）**，止步则走 A 层带外 IP/SNI；DEX→classes*.dex 映射是启发式（按大小），错则装上即崩→靠四联判活降级不假成功；多 dex/split 需逐一处理。

### C 层 · 非frida注入框架 / 对抗式frida（换注入面 or 改名隐形，应对反frida秒退）

**C1. LSPosed(Vector) + JustTrustMe/TrustMeAlready 解 pinning（整机级、零 frida-server）**
- 工具：原 LSPosed 仓 2024-01 归档，活体 fork 是 **JingMatrix/Vector**（v1.11.0，2026-01，支持 Android16、hide dex2oat hook 痕迹），配 **JingMatrix/NeoZygisk**（替代已归档 Zygisk Next）。流程：装 NeoZygisk → 刷 Vector → 勾选 TrustMeAlready(ViRb3) 或 JustTrustMe(Fuzion24) → 对目标包启用 → 重启 → mitmproxy CA 装为系统证书（配 AlwaysTrustUserCerts）。
- 破：②TLS pinning（OkHttp/TrustManager/Conscrypt 自实现）；部分①反frida（整链不依赖 frida-server/27042/gum，**只测 frida 特征的样本此路完全隐形**）。
- 拿到：解 pinning 后 mitmproxy 拿 HTTP(S) 明文 body+header+endpoint（endpoint_total 0→非0）+ DNS/Host/SNI。拿不到 MTProto 等非 HTTP 自建协议（仍走带外）。
- 溯源：明文 endpoint = 直接定位接入域名/接口/回传字段（账号/IMEI/银行卡）；明文里常含落地库/后台面板 URL。
- 配 fxapk：替换 capture 当前 `_start_frida_session` 这条强依赖 frida-server 的链——**capture 增 `backend=xposed`**：检测到设备已装 Vector+TrustMeAlready 时跳过 frida 注入，直接 mitmdump+adb 代理抓流量喂回 endpoints/self_hosted_im 分析器与 probe-leads；doctor 加一项"Vector/LSPosed 是否激活+模块对目标包启用"。
- 坑：TrustMeAlready/JustTrustMe 原仓 2019 老代码，对 2024+ 新版 OkHttp/Conscrypt/cronet 覆盖可能不全，**native BoringSSL 直校验它不管**（转 native-ssl/keylog）；CA 必须装系统级（A14+ APEX 更麻烦）；LSPosed 自身可被检测（需配 C3 隐藏）。

**C2. Zygisk 注 gadget（ZygiskFrida / ksu-frida）——不改 APK、不破签名、不 ptrace（最干净的注入面）**
- 工具：lico-n/ZygiskFrida（Magisk Zygisk 模块，含启动延迟/子进程 gating）、gmh5225/zygisk-ZygiskFrida 镜像、electrondefuser/ksu-frida（KernelSU 版）。Magisk(开Zygisk)/KSU install zip → 配目标包名 + 延迟 → 重启注入 gadget。
- 破：①反frida（无端口/无ptrace/无APK改动）；**反篡改/签名完整性自检全过（相对重打包 gadget 的关键优势）**；可借延迟绕反frida 启动体检。不破 pinning/native 语义（仍需 hook）。
- 拿到：进程内全量 hook——明文、密钥、connect/SNI 处 IP:port+SNI、JS bridge；可让主机 frida 远程 attach 跑全套 46 探针。
- 溯源：**APK 一字未改（哈希不变），动态观测与"原样样本"对应清楚，证据链最干净**；IP/SNI 可直接调云厂商租户。
- 配 fxapk：与 provision/device 层互补——provision 现只 push frida-server，**新增"Zygisk 路径"**：检测设备已装 Magisk+Zygisk（provision 已有 `_su_run` 兼容 Magisk）则部署 ZygiskFrida 模块 + 配目标包名，跳过 `/data/local/tmp/frida-server`；46 个探针脚本零改沿用；anti-detection 探针先探明 App 查不查签名完整性，查则优先此路而非重打包。
- 坑：依赖 root+Zygisk；gadget 仍需**改名版**（内置 gadget 建议替换为 hluda/strongR 产物）否则线程名 gmain/gum-js-loop 露馅；隐藏 root（DenyList）要配好；模块对 Android/Zygisk 版本有兼容窗口，搭 NeoZygisk 而非已归档 Zygisk Next。

**C3. 改名/改符号的 anti-detection frida-server（strongR / Florida / hluda）——零脚本改造成本绕字符串级反frida**
- 工具：hzzheyang/strongR-frida-android（跟 upstream 自动 patch 重编，含 arm64/arm/x86_64）、Ylarod/Florida、zer0def/undetected-frida（meta 仓，melded strongR+Florida，产 hluda-server + Magisk/KSU 模块）。按 ABI+主机 frida 版本下对应 release，push `/data/local/tmp`、`chmod 755`、su 拉起；主机仍用原版 frida-tools attach。patch：把 `frida`/`gum-js-loop`/`gmain`/`frida-agent` 改名、改 RPC pipe 名/线程名、抹 `/proc/maps` 里 frida-agent 段名。
- 破：①反frida（字符串/段名/线程名/文件名指纹）、部分反调试。**不破** pinning/脱壳/native直发/MTProto。
- 拿到：进程内任意 hook——明文（hook 加解密前后取参）、密钥（hook keystore/SecretKeySpec）、接入节点（hook connect/getaddrinfo/SNI）、JS bridge。
- 溯源：**绕过 80% 字符串级反frida**；即便只 hook 到 `connect()` 也能固证真实 IP:port+SNI。
- 配 fxapk：**最贴合现有架构**——`apkscan/dynamic/provision.py` 的 `ensure_frida_server` 现按 ABI+主机版本拼 GitHub releases URL 下原版 server。只需**扩一个 server 源开关（bundled / strongR / florida）**把下载 URL 指向 strongR/undetected-frida release、保持文件名与 `_FRIDA_SERVER_REMOTE` 路径不变，capture 与 46 探针全部零改沿用；先跑 anti-detection 探针确认用了哪类检测再决定换哪个 fork。
- 坑：版本必须与主机 frida CLI 严格对齐否则握手失败；第三方 release 需校验体积/来源防投毒（provision 已有体积下限校验可复用）；**仍是 server 形态，仍 ptrace、仍监听端口，遇 TracerPid 自检/端口扫描型/私有特征仍被抓**（转 C2 Zygisk gadget）。

**C4. magisk-frida / MagiskHluda（开机自起 server + 隐藏root + 改名server）——批量流水线底座**
- 工具：ViRb3/magisk-frida（开机自起 server，跟版稳）、Exo1i/MagiskHluda（起更难检测的 hluda-server）、FriRebuild/magisk-strongR-frida。Magisk install module 重启即就绪；配 DenyList 隐藏 root。
- 破：反root（Magisk 生态）、①反frida（hluda/strongR 变体）、⑤反模拟器（真机+隐藏root）。**不破** ptrace 型反调试/端口握手检测/pinning。
- 拿到：与 C3 相同进程内产出——明文/密钥/IP:port+SNI/DNS(hook getaddrinfo)/JS bridge。
- 溯源：提供**稳定可复现的 root+frida 真机底座**，是批量溯源流水线基础设施。
- 配 fxapk：作 provision 的"设备就绪前置"——device.py 已能判 `frida_server_running` 与 root 能力，文档把 magisk-frida/MagiskHluda 列为推荐预置方式，设备装好后 `ensure_frida_server` 多数直接命中"已在跑"分支。
- 坑：仍 server 形态，反 ptrace 样本要转 C2；自动跟版可能拉到与主机不一致版本需固定；隐藏 root 没配好会被反root先杀。

**C5. Stalker 指令级追踪 + 延迟/无早期 attach（规避 inline-hook 自检 + 攻 native 直发包）**
- 工具：Frida 官方 Stalker（`Stalker.follow()`/`Stalker.exclude()`，frida.re/docs/stalker）。配改名 server/gadget 用：不在启动早期 hook，等反frida 自检窗口过去（或目标 native 库 dlopen 后）再 attach + `Stalker.follow` 目标线程，逐指令 trace 加解密/发包路径。
- 破：①反frida（inline-hook/代码段CRC自检/启动期一次性体检）、⑥native直发（指令级看清 socket/SSL_write 调用点）。**不破** pinning 本身/脱壳。
- 拿到：native 直发场景的明文（trace 到 `SSL_write`/`send` 前 buffer）、真实接入节点（trace `connect`/`getaddrinfo` 实参 IP:port、SNI 设置点）、加解密落点。**对不走 OkHttp、native 自实现协议的样本尤其关键**。
- 溯源：针对最硬的 native 直发 + MTProto；即便协议私有，也能在 send/connect 处带外取 IP:port+SNI+时序。
- 配 fxapk：属探针策略层——在 46 探针基础上**增一类 Stalker-trace 探针**（针对 native 直发样本），由 anti-detection 探针先判明用了代码段CRC/inline-hook 自检后再启用；"延迟 attach + `Stalker.follow connect/SSL_write`"注入；trace 出的 IP:port/SNI 喂 probe-leads。
- 坑：**不能单独用——必须叠 C3/C2 先 attach 成功**；性能与数据量大，必须 `Stalker.exclude` 噪声模块、只 follow 目标线程；时序判断（自检窗口何时结束）靠经验；对纯 ptrace 检测无效。

**C6. frida-gadget 重打包注入（无 root 真机可用，但破签名）**
- 工具：`objection patchapk -s app.apk`（自动塞 libgadget.so + 改 smali loadLibrary）、badadaf/apkpatcher；配 apktool + uber-apk-signer。gadget config 可 listen/script 模式自动加载 hook JS + 放开 user CA。
- 破：①反frida（无server/端口/ptrace）、反root（无需root）、⑤反模拟器。**不破** 签名/完整性自检（最大坑）、pinning。
- 拿到：同 server 的进程内 hook；listen 模式让主机 frida 远程 attach 跑 ssl-unpinning/tls-keylog 探针。
- 溯源：**无 root 严苛样本的少数可行路径**；明文/endpoint 可作锚点，但改包事实需在取证链说明（动态观测副本，固证仍以带外 IP/SNI 为准）。
- 配 fxapk：直接对接 repackage——脱壳去壳后在重打包阶段顺手注入 gadget + config（指向 capture 的 mitm CA 与 ssl-unpinning 脚本），产出"自带探针"包；listen 起来后 capture 走 `attach` 不变。
- 坑：**签名校验/完整性自检是头号障碍**（目标加固包几乎都查）→改用 C2 Zygisk；加固包重打包可能脱壳不全崩溃；必须用**改名 gadget**否则线程名露馅；报告须标注"动态分析副本"。

> 隐藏层（与注入正交，必配）：**NeoZygisk + Zygisk-Assistant（替代已归档 Shamiko/Zygisk Next）**对抗反root/反Zygisk/部分反模拟器/环境门控。它不产数据，但解锁后续——很多 `endpoint_total=0` 不是加密而是**环境门控没放行真实链路**；隐藏层让配置下发/登录回传真正发生，才能观测到样本自身的接入节点与多云对象存储下发源。并入 fxapk doctor 的"环境就绪"前置检查。坑：Play Integrity strong/hardware、SafetyNet 强校验、TEE 绑定不是用户态隐藏能完全绕的。

### D 层 · 非网络取证（完全在 frida 之外，反frida样本零影响）

**D1. TLS keylog 主密钥导出 → Wireshark 离线解（含 QUIC/HTTP3，不替证书所以 pinning 无从触发）**
- 工具：① fkie-cad/friTap（`friTap -m -k keys.log <pkg>`，自动 hook OpenSSL/BoringSSL/NSS/GnuTLS；**BoringSecretHunter** 用字节模式定位静态链接 BoringSSL；新版支持 QUIC keylog + 导出 pcap）；② saleemrashid/frida-sslkeylog；③ Wireshark/tshark ≥4.x TLS→(Pre)-Master-Secret log（QUIC 自动用同文件）；④ JSSE(OkHttp 自带栈)不认 SSLKEYLOGFILE，需 jSSLKeyLog/extract-tls-secrets java agent。conscrypt 即 libssl.so=BoringSSL，friTap 主打这条。
- 破：②所有自定义 pinning（不替证书，校验自然通过，旁路导密钥）、⑥native BoringSSL 直发、QUIC/HTTP3（同 TLS1.3 密钥）。注：friTap 走 frida 仍受反frida 影响——但可用其 **patch-APK/静态注入模式**把 keylog 逻辑打进 APK，不跑 frida-server。
- 拿到：原始 pcap + 主密钥 → Wireshark 解全明文（HTTP/2/3 body、自建协议在 TLS 内的明文层），pcap 本身带 IP:port/SNI/JA3/DNS/时序。
- 溯源：**极高**——既拿明文落地数据，又因是真实流量 pcap 完整保留接入节点元数据作固证；对 pinning+native直发+QUIC 这套"最难解"组合是少数能同时拿明文+元数据的路子。
- 配 fxapk：与现有 **tls-keylog 探针同源，可升级为 friTap 后端**——capture 增 `--keylog` 档，同时 tcpdump 抓 pcap + friTap 导 keylog，产 pcapng；遇反frida 秒退改用 friTap patch-APK 模式注入 keylog 交给 repackage 重打包签名落地（与流水线天然衔接）；pcap 抽 IP/SNI/JA3 入线索，Wireshark 解出的明文 endpoint 回灌。
- 坑：静态/内联 BoringSSL 需 BoringSecretHunter 重新生成字节模式（魔改/裁剪 BoringSSL 可能失配）；魔改 TLS 库可能拿不到回调；**keylog 必须与 pcap 同会话同时段对齐**才解得开；ECH 进一步加密握手内层；**私有协议(非TLS) keylog 无效**（走 D2 内存 dump 或 §3 元数据）。

**D2. QUIC/HTTP3 专项：逼回 TCP 或 QUIC keylog（补齐 UDP/443 盲区）**
- 工具：① mitmproxy `--set http3=false` / `--intercept '~udp...'`；② iptables/nftables drop UDP/443 逼回 TCP；③ friTap QUIC keylog + Wireshark 解 HTTP3；④ tcpdump/PCAPdroid 抓 UDP/443 原始包（PCAPdroid 解 QUIC 受限，抓元数据可用）。
- 破：⑥native若走QUIC、任何 HTTP3 接入；补齐被 QUIC 吃掉的 `endpoint_total=0`。
- 拿到：逼回 TCP→明文（配 CA）；QUIC keylog→Wireshark 解 HTTP3 明文；兜底→QUIC Initial 明文 SNI + 目标 IP:port + 时序 + JA4。
- 溯源：QUIC 的 SNI（Initial 包明文）+ 源站 IP:port + JA4 即便不解密也是强锚点；很多新目标样本特意走 QUIC 规避普通抓包，本法点亮盲区。
- 配 fxapk：netstat/native-ssl 探针发现 UDP/443 外联但 capture endpoint=0 时**自动触发**——capture 增 `--quic block|keylog` 档；probe-leads 不解密时也从 QUIC Initial 抽 SNI/IP/JA4，确保 QUIC-only 样本不漏接入节点。
- 坑：**硬编码只走 QUIC 无 TCP 回落的样本，block UDP 后直接断网**（只能 keylog 或固证元数据）；Chrome/部分栈对 HTTP3 不信 user CA（MITM 路不通须走 keylog）；Wireshark 须新版才稳解 QUIC。

**D3. 内存 dump 抓 key / 明文（对私有协议与 SQLCipher 落地库）**
- 工具：整机 RAM——LiME(LKM)→Volatility(2/3 Android 插件)；进程级——root 读 `/proc/<pid>/maps`+`/proc/<pid>/mem` dump 段，或 GDB/lldb attach；SQLCipher 专项——Ackcent 公开 Frida 取 raw key 法（2025 仍有效），拿 key 后用 sqlcipher CLI / DB Browser(SQLCipher 版)开库；商业 Cellebrite 有 RAM-dump 解 SQLCipher。
- 破：③私有/自建协议密文（key 在内存，不依赖解协议）、SQLCipher 落地库、④加固壳（内存里是已解密 DEX 可 dump，与脱壳互补）、pinning/反抓包（完全绕开网络层）。
- 拿到：SQLCipher/MTProto 会话 key、即将发/刚收的明文 payload、内存中真实配置/对象存储 URL、账号口令、已解密真实 DEX。
- 溯源：**内容级铁证**——解开落地库=拿到联系人/交易/聊天；内存 key 让网络密文事后可解；dump 真 DEX 让静态分析拿到真业务逻辑。
- 配 fxapk：与 repackage 互补（静态脱壳失败时内存 dump 抓运行期已解密 DEX）；cryptohook 取不到密钥时内存 dump 兜底；dump 出的 key/明文 URL 人工核实后经 probe-leads 并入 report.json。
- 坑：LiME 需内核匹配常要重编内核（真机难）；**内存易失，dump 时机错过（App 已清 key/退出）就抓不到**；全内存 dump 体积大、key 定位耗时（需熵分析/已知结构）；部分加固在内存里也对 key 做混淆。

**D4. 磁盘勘验落地库 + root 后 /data 全量（冷数据闭环）**
- 工具：`adb root && adb pull /data/data/<pkg>` 或 `tar` 打包 /data 再 pull；Cellebrite/Magnet AXIOM 镜像级提取；ALEAPP 解析 artifacts、sqlite3/DB Browser 读库、SQLCipher 版开加密库。
- 破：所有网络层规避对冷数据无效（配置落盘即可读）；加固释放的真 DEX 可能落 cache；视频门控不影响已落盘数据。
- 拿到：落地明文/加密库（联系人/交易/聊天）、shared_prefs 里接入域名/对象存储 endpoint/token、files 里配置 json 与缓存明文、真 DEX。
- 溯源：**最直接的内容级证据与穿透锚点**——落盘对象存储/接入域名补全"多云抗封堵"下发源清单；冷数据可重复勘验、链路完整、法庭采信度高。
- 配 fxapk：与 unpack/capture 同设备会话顺序执行——抓包后立即全量 pull /data 留存；落盘域名/endpoint 人工核实后 merge 进 report.json leads，与 `pcap_ingest` 网络锚点交叉印证（网络看到的 IP ↔ 落盘配置里的域名）形成闭环。
- 坑：必须 root 才能读 `/data/data`；**重打包/重签会清 /data（先 pull 再 repackage）**；WAL 未 checkpoint 需连 `-wal`/`-shm` 一起拉；SQLCipher 库无 key 时只是高熵字节（必须先有 D3 的 key）。

**D5. DNS 日志侧录 + /proc/net/tcp 连接快照（带外补全锚点 + 名称解析）**
- 工具：DNS——Pi-hole(可跑闲置 Android/树莓派)+Unbound 详细 query log，或 dnsmasq/CoreDNS query logging，网关抓 53/853；连接快照——root `adb shell 'while true; do cat /proc/net/tcp /proc/net/tcp6; date; sleep 1; done'`（十六进制 IP:port 小端解码），或 fxapk 的 netstat-hook 探针在 App 内列 socket。
- 破：②pinning/③私有协议/⑥native直连（DNS 与 /proc/net 都在解密之外）、①反frida（完全不注入）、多云抗封堵（DNS 日志列出所有下发域名）。**绕不过 DoH/DoT**（App 自带加密 DNS 时 Pi-hole 看不到，需端口侧 IP 兜底）。
- 拿到：带时间戳 DNS 查询域名清单、IP↔域名映射、`/proc/net` 远端 IP:port 与连接状态、socket↔pid 归属。无明文 payload。
- 溯源：DNS 日志是独立、低成本、可长期留存的锚点，补全 pcap 看不全的域名维度（尤其对象存储多域名抗封堵）；`/proc/net` 抓 native 短连接补 pcap 漏抓；与 pcap 的 IP/SNI 三方交叉——"同时刻问了域名 X→连了 IP Y→SNI Z"形成强时序闭环。
- 配 fxapk：DNS 域名、`/proc/net` 解码 IP:port 整理成 leads 经 probe-leads `merge_into_report_json` 并入 report.json，与 `pcap_ingest` 的 SNI/IP 同口径去重交叉；netstat-hook 探针的 `[LEAD]` 输出本就走 probe-leads；`apkscan.dynamic.correlate` 做 IP↔域名↔时序关联。
- 坑：App 用 DoH/DoT 时看不到查询（需出口按 IP/SNI 兜底或阻断加密 DNS 逼回明文）；`/proc/net` 是快照（采样间隔内短连接漏，需高频或配 pcap）；十六进制 IP:port **字节序易解错（小端）**；多设备共网需按源 IP 区分被测机。

---

## 三、"解不开也能追溯"专章 —— 旁路 pcap 闭环到溯源

> 核心命题：**当密文/协议都解不开（VMP/dex2c、签名+代码双完整性自检、native 直发、MTProto），靠传输层元数据 + 落地库即可单独完成闭环。**

**穿透锚点全集（密文不解也成立）：**
```
真实接入节点 dst IP:port  ──→ 向云厂商/IDC 调主机租户实名、备案、计费主体
TLS/QUIC 明文 SNI         ──→ 佐证"同一基础设施"、定位 vhost
JA3/JA4(C/S) 指纹         ──→ 跨样本/跨节点聚类同一 SDK/打包器，关联多个马甲到同一来源
DNS 查询域名 + 映射        ──→ 列出多云对象存储抗封堵的全部下发域名
连接/心跳时序 + 包长指纹    ──→ 节点轮换画像、活动画像
落地库/shared_prefs        ──→ 落盘的对象存储 endpoint/token/域名（与网络 IP 交叉印证）
```

**闭环操作链（全程不解密）：**
1. **采集**：PCAPdroid（免root，按 UID）/ 网关 tcpdump（法庭级）/ root tcpdump 落 pcap；同机 Pi-hole 侧录 DNS；root 高频 dump `/proc/net/tcp` 抓 native 短连接。
2. **抽取富化**：pcap → fxapk `apkscan.dynamic.pcap_ingest`（tests/test_pcap_ingest.py 已证：解析 TLS SNI、native 端点 IP:port、DNS query，**私网 IP 自动过滤，native IP:port 自动标"穿透"类 IP lead**）→ 再过 JA4+/Zeek/tshark 补 JA3/JA4 指纹与 JA4S/JA4L。
3. **交叉印证**：`correlate` 做"DNS 域名 X ↔ 连接 IP Y ↔ SNI Z ↔ 同时刻 /proc/net socket↔pid"的时序关联；网络看到的 IP ↔ D4 落盘配置里的域名互证。
4. **汇成台账**：所有线索经 probe-leads `merge_into_report_json` 回灌 report.json 的 leads，与 capture/探针线索**同口径去重合并**；netstat-hook 探针的 `[LEAD]` 输出本就走 probe-leads 聚合。
5. **定人/穿透**：拿 IP:port 调云厂商租户实名 → 备案/计费主体 → 定人；JA4 三元组把多马甲关联；DNS+时序做节点轮换与活动画像。

**收口要点：** ECH 普及后 SNI 可能被加密 → 退到 **IP+JA4+DNS**；CDN/多云会让落地 IP 指向云厂商而非目标自有机 → 必须**结合时序与租户溯源**，别只看 IP 段；元数据含个人信息按合规要求留存。

---

## 四、最高 ROI 三招（探针之外只选 3 种先上）

对"刻意反分析的目标样本"，若只先上 3 种 frida 探针之外的方法，按"覆盖面 × 抗规避 × 部署成本"排序：

**第 1 招：PCAPdroid 被动旁路抓 pcap（A1，→ pcap_ingest → probe-leads）**
- 为什么第一：**免 root、1 分钟部署、按 UID 归因、对①②③⑤⑥ 全免疫**。任何样本第一步就先把它挂上——哪怕后面所有解密都失败，IP/SNI/DNS/时序锚点已经到手，北极星先保底。fxapk 已有 `pcap_ingest` 直接消化，零额外开发即闭环。是"抓包≠必须解密"的落点。

**第 2 招：Magisk 系统CA注入 + 零改包预检（B4，capture --proxy-only/--no-frida）**
- 为什么第二：**实测占比不低的样本是"假性 pinning"（其实只是 user CA 不被信）**。零改包 + 不注入 frida，一个系统CA模块就让整机 HTTPS 明文化，且**不触发任何代码/签名完整性自检**，对反frida 秒退、双完整性自检样本是唯一不改包的明文路径。一旦 endpoint 出来就证明根本不必动 frida，极大降本。fxapk 只需加一个 `--proxy-only` 档。

**第 3 招：tls-keylog（friTap）+ 旁路 pcap → Wireshark 离线解（D1）**
- 为什么第三：**当真 pinning + native 直发 + QUIC 这套"最难解"组合出现时，这是少数能同时拿明文 + 元数据的方法**。不替证书所以 pinning 无从触发、QUIC/HTTP3 通吃；遇反frida 秒退可切 friTap patch-APK 模式注入 keylog 交给 repackage 落地（绕开运行期反frida）。与 fxapk 现有 tls-keylog 探针同源，升级为 friTap 后端即可。

> 三招分工：**A1 保底拿锚点（永远先上）→ B4 低成本试明文（多数样本一击命中）→ D1 攻最硬组合（拿明文+元数据双锚点）**。三招都不依赖"硬刚 frida-server"，对反frida 秒退的目标样本天然友好；换注入面（C1/C2）与脱壳去pin（B5）作为这三招打不动时的第二梯队。

---

**fxapk 落地改造清单（汇总，给 Codex 排期）：**
- `provision.py`：扩 server 源开关 `bundled/strongR/florida`（C3，零探针改动）；新增 Zygisk 路径部署 ZygiskFrida（C2）。
- `capture.py`：增 `--proxy-only/--no-frida`（B4）、`backend=xposed`（C1）、`--keylog`（D1）、`--quic block|keylog`（D2）档。
- `repackage`：增 `--netsec-user-ca`（B2）、DEX 替换前后插 smali 去pin（B3/B5）、可选注入 gadget/keylog 回调（C6/D1）。
- `doctor.py`：增"Vector/LSPosed 激活 + 模块对目标包启用""Zygisk-Assistant/NeoZygisk 激活 + DenyList""Play Integrity 基本判定"环境就绪检查。
- pcap 富化：在 `pcap_ingest` 后增 JA4+/Zeek 富化步骤（A5），让 capture/旁路两路数据同口径汇入 probe-leads。
- 探针层：增 Stalker-trace 探针（C5）、IL2CPP dump 分支（Unity 样本）。