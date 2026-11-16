# 服务商产品指纹与 CDN 后续核查

官方资料核对日期：2026-09-23。规则见同目录 `providers.yaml`，由
`core.attribution.score_edge_provider` 使用；下列域名仅为产品后缀，不是案件目标。

## 已接入规则

| 产品 | 可用指纹 | 官方依据 |
| --- | --- | --- |
| 腾讯 EdgeOne | Server 精确值 TencentEdgeOne；EO-Cache-Status；EO-LOG-UUID | [默认响应头](https://cloud.tencent.com/document/product/1552/87655) | <!-- leak-scan: allow 公开厂商文档或产品地址约定说明，非案件值：cloud.tencent.com -->
| 腾讯云 CDN | cdn.dnsv1.com / dsa.dnsv1.com CNAME；X-NWS-LOG-UUID | [CNAME](https://intl.cloud.tencent.com/zh/document/product/228/5734)、[请求定位](https://intl.cloud.tencent.com/ind/document/product/228/42177) | <!-- leak-scan: allow 公开厂商文档或产品地址约定说明，非案件值：cdn.dnsv1.com, dsa.dnsv1.com, intl.cloud.tencent.com -->
| 华为云 CDN | c.cdnhwc1.com CNAME；X-HCS-Proxy-Type 的 0/1 值 | [接入域名](https://support.huaweicloud.com/cdn_faq/cdn_faq_0111.html)、[缓存标识](https://support.huaweicloud.com/cdn_faq/cdn_faq_0245.html) | <!-- leak-scan: allow 公开厂商文档或产品地址约定说明，非案件值：c.cdnhwc1.com, support.huaweicloud.com -->
| 火山引擎 CDN | X-Bdcdn-Logid；X-Bdcdn-Cache-Status | [保留响应头](https://www.volcengine.com/docs/6454/1319866) | <!-- leak-scan: allow 公开厂商文档或产品地址约定说明，非案件值：www.volcengine.com -->
| 百度 BOS CDN | cdn.bcebos.com CNAME，仅覆盖 BOS 加速地址 | [自定义域名](https://cloud.baidu.com/doc/BOS/s/ckaqihkra-en) | <!-- leak-scan: allow 公开厂商文档或产品地址约定说明，非案件值：cdn.bcebos.com, cloud.baidu.com -->
| 七牛云 CDN | qiniudns.com CNAME | [域名管理](https://developer.qiniu.com/fusion/13363/fusion-api-domain-management) | <!-- leak-scan: allow 公开厂商文档或产品地址约定说明，非案件值：developer.qiniu.com, qiniudns.com -->
| 又拍云 CDN | b0.aicdn.com CNAME，仅覆盖静态加速示例后缀 | [CDN 入门](https://help.upyun.com/knowledge-base/cdn-quick-start/) | <!-- leak-scan: allow 公开厂商文档或产品地址约定说明，非案件值：b0.aicdn.com, help.upyun.com -->
| 金山云 CDN | ksyuncdn.com CNAME | [配置 CNAME](https://docs.ksyun.com/documents/41418) | <!-- leak-scan: allow 公开厂商文档或产品地址约定说明，非案件值：docs.ksyun.com, ksyuncdn.com -->
| 华为云 WAF | vip1.huaweicloudwaf.com CNAME，仅覆盖已核实例后缀 | [接入参数](https://support.huaweicloud.com/eu/api-waf/CreateHost.html) | <!-- leak-scan: allow 公开厂商文档或产品地址约定说明，非案件值：support.huaweicloud.com, vip1.huaweicloudwaf.com -->
| 腾讯云 WAF | qcloudwzgj.com CNAME，仅覆盖已核实例后缀 | [接入域名](https://cloud.tencent.com/document/product/627/43213) | <!-- leak-scan: allow 公开厂商文档或产品地址约定说明，非案件值：cloud.tencent.com, qcloudwzgj.com -->

保留已有 ESA、阿里 CDN/DCDN、Cloudflare、加速乐规则。单个 CNAME 命中通常为 probable；
多个 HTTP 头仍属同一信号面。confirmed 是引擎对产品指纹的等级，不是实际运营人、源站 IP 或租户实名确认。
响应头可配置或伪造，CNAME 可残留；输入必须绑定同一业务 Host/SNI、地址、采集时段和原始证据。
未命中不排除使用对应产品；这份规则不是各厂商全部接入域名的穷举。

同一次观测可以出现多个产品指纹。主候选保留原有档位和评分排序，其他达阈值候选进入
`edge_provider.other_candidates`；`selection_scope` 明示排序不是唯一归属，也不是链路先后关系。
多命中可能来自串接、源站头透传、历史观测混合或同厂商规则重叠，应回查原始记录。
旧展示程序可能仍只显示主候选，复核时需要查看完整归属 JSON。

## 还能识别的产品，暂不混入 CDN 规则

| 产品 | 有依据的线索 | 处理范围 |
| --- | --- | --- |
| 阿里 OSS | Server: AliyunOSS、X-Oss-Request-Id | [官方头定义](https://help.aliyun.com/zh/oss/developer-reference/common-http-headers)；识别存储产品，不能把透传头归为当前边缘 IP 的托管商 | <!-- leak-scan: allow 公开厂商文档或产品地址约定说明，非案件值：help.aliyun.com -->
| 腾讯 COS | Server: tencent-cos、X-Cos-Request-Id | [GET Object](https://intl.cloud.tencent.com/document/product/436/7753)；EdgeOne 官方明确可透传 COS Server 头 | <!-- leak-scan: allow 公开厂商文档或产品地址约定说明，非案件值：intl.cloud.tencent.com -->
| 华为 OBS | Server: OBS、X-Obs-Request-Id | [API 文档](https://support.huaweicloud.com/intl/en-us/api-obs/obs-api-en-pdf.pdf)；结合 OBS 访问地址和请求记录，避免单独使用短通用 Server 值 | <!-- leak-scan: allow 公开厂商文档或产品地址约定说明，非案件值：support.huaweicloud.com -->

存储产品地址现由 `core/origin_check.py` 分别识别，并接入下述候选核验流程；不会混入 CDN 规则。通用 S3 错误结构或
X-Amz-* 也可能来自兼容实现，不能仅凭接口兼容性确认 AWS。
X-Cache、Age、X-Cache-Lookup、nginx/openresty、泛化的 volces.com/bcebos.com 不单独用于锁定 CDN。 <!-- leak-scan: allow 公开厂商文档或产品地址约定说明，非案件值：bcebos.com, volces.com -->
管理 API 文档中的示例头不是业务数据面指纹：例如百度域名配置 API 的 Server: BCE-CDN，
该头不作为业务站点规则。

## 遇到 CDN 后继续查什么

目标分别记录为“边缘产品”“源站候选”“源站关联验证”“服务商调证方向”；识别出 CDN 后不直接结束调查。
以下是证据驱动的核查路线。内置入口只对指定候选做有界核验，不枚举发现源站。

1. 保存实际业务请求的时间及时区、完整 CNAME 链、连接 IP/端口、Host/SNI、路径、状态码、响应头、
   请求 ID 和证据文件哈希。EagleId、EO-LOG-UUID、X-NWS-LOG-UUID 等保留完整原值在受控证据中，
   可供相应服务商匹配日志；不能仅凭 ID 反解源站或客户身份。
2. 从 APK 静态/JADX 已有结果及动态请求中核查 API、WebSocket、下载/更新、备用地址和重定向。
   单独记录第三方 SDK、图片存储与业务接口，不能将所有联系地址都当成同一源站。
3. 使用当前授权、预算和来源状态，查询历史 DNS、证书及 Hunter/FOFA 等被动画像。
   历史 IP、同证书、同 favicon/标题只作候选；保留观测时间、覆盖范围、分页与过期可能。
   CDN 共享证书、共享节点、同 ASN 不作为串案主体一致的证据。
4. 对源站候选回查已有请求/响应、业务路径、业务内容和时间关系，逐项注明支持与冲突。
   不将历史 A 记录或内容相似直接升级成当前源站；缺乏足够关联证据时保留 candidate/partial。
   当前域名经 CDN 返回的 DNS 地址属于边缘，不因为所在 ASN 是某云厂商就重新标成源站。
5. 无法从现有证据确认时，仍形成可执行线索：厂商/产品候选、业务域名、精确时段、请求 ID、
   证据锚和需要核验的加速配置、回源记录、账号关系。具备相应手续时由获授权的调查方向服务商调取，
   技术侧不以“找不到源站”否定已发现的服务商线索，也不自动完成对外发送。

上述官方资料的核对日期保留在文首；它不保证厂商当前接入约定未变。规则回归使用合成输入，
不是对实际服务或案件目标的联网验收。

## 候选核验接入现有接口

`fxapk origin-check` 读取既有 `report.json`，校验参考域名已存在于端点或线索中；有 case_id 时核对身份。
仅核验由证据给出的一个候选，不扫描 IP 段、端口或猜测 Bucket。

```powershell
fxapk origin-check --report report.json --case-id fixture --source-note "APK 配置文件及证据定位" --reference-url "https://cdn.example.test/object" --candidate-url "https://origin.example.test/object" --candidate-ip "192.0.2.10" --out origin-output
```

默认 passive 只验证参数和报告绑定，零 DNS/HTTP/富化请求。以上是合成示例；保留地址不能用于实际执行。
在已有目标访问授权内，加 `--mode authorized-active` 执行两次 GET（参考和候选各一次），随后默认查询
`dns,asn,ip_rdap`。通过 `--enrich-providers` 指定现有精确源名（例如已有权限的 Hunter/FOFA），沿用
`enrich batch` 的预算预检、目标上限、配置和来源回执。空字符串表示跳过，结果记录 not_requested。
第三方仅收到所选域名/IP，业务 URL 的路径和查询参数不作为富化标的。

IP 候选使用 `--candidate-ip` 固定连接地址，`--candidate-url` 的域名决定 Host 和 SNI；HTTPS 仍验证证书。
两侧路径可以不同，以适应 CDN 回源重写，原始 URL 分别留存。指定存储 Bucket 地址时通常不填 candidate-ip，
由其 DNS 得到连接地址。所有请求只 GET，不跟随跳转，不继承代理、Cookie 或认证，单响应保存上限 2 MiB，
套接字超时 15 秒；大文件截断、非 200、空正文或失败均不评为完整内容匹配。

| 平台 | 地址处理差异 |
| --- | --- |
| 阿里 OSS | 区分 Bucket.oss-区域.aliyuncs.com 与裸 Endpoint；不自动推算 ECS 地址 |
| 腾讯 COS | 保留 Bucket-APPID.cos.区域.myqcloud.com 的完整桶名；不删 APPID |
| 华为 OBS | Bucket.obs.区域.myhuaweicloud.com；不把裸地域地址当具体桶 |
| 火山 TOS | 单独匹配 tos-区域.volces.com 与 S3 兼容地址；不将所有 volces.com 当存储 | <!-- leak-scan: allow 公开厂商文档或产品地址约定说明，非案件值：volces.com -->
| 百度 BOS | 本次覆盖 bj/gz/su 的桶地址示例；cdn.bcebos.com 仍属于 CDN 规则 | <!-- leak-scan: allow 公开厂商文档或产品地址约定说明，非案件值：cdn.bcebos.com -->
| 金山 KS3 | 匹配 ks3-区域.ksyuncs.com；307 保留为跳转未验证，不自动追随 |
| 七牛、又拍及其他自定义源站 | 支持输入有证据的自定义 URL/IP 比对；不根据加速域名猜桶名或生成下载地址，产品身份交由实际 DNS/多源证据 |

各次结果写入新的 origin-check-* 目录，保留原报告。产物连接关系：

1. `origin-check.json` 与原始 body：请求、Host/SNI、连接地址、时刻、响应头、完整性和内容 SHA-256。
2. `enrichment-targets.txt` → 现有 `enrich batch` 预检和执行 → coverage/records/原始响应；失败也保留状态。
3. 新 `report.json`：端点 enrichment、分层 attribution、Lead/source_refs、Finding 和 meta.origin_checks；
   不将核验器连接标作 APK 实连。已有线索研判不被升级，新候选保持待核。
4. 现有 digest 接收状态与覆盖统计；HTML/PDF 增加源站核验小节；IOC CSV 末列追加 origin_check_summary，原列位置不变。
5. 自建清单/XLSX 集成是可选外部步骤，不随核心发布、也不是运行该命令的前置条件。
   集成前应将回执、正文、富化快照与 coverage 作为 evidence 注册到新包并验包；
   不伪造 Phase2 复核，不直接覆盖共享清单。

PDF 生成失败会返回非零并记录 projection-status；清单尚未投影时明确记录 requires_verified_package_projection。
resource_match 只表示完整响应正文相同；content_differs 不排除缓存、重写与动态内容；所有结果均保留源站未确认。
服务商查询按资源登记、网络机构、托管候选和边缘产品分层展示，禁止据此自动确认账号或运营主体。
