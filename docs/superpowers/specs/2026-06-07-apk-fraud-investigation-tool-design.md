# APK 涉诈调证分析工具 — 设计文档

- 日期:2026-06-07
- 代号:`apkscan`
- 目标用户:反诈调证人员
- 定位:Python 编排现有工具,对涉诈 APK 做静态分析 + 网络端点/服务归属提取,产出**调证线索清单**

---

## 1. 目标与非目标

### 目标
- 输入一个 APK,产出"**这条线索归属哪家公司、能去找谁调取什么证据**"的结构化报告。
- 零环境即可运行核心功能(`pip install` 即可,不需要 JDK / 模拟器)。
- 默认联网富化归属信息(WHOIS / ICP 备案 / IP-ASN),`--offline` 可关闭。
- CLI 运行 `apkscan analyze app.apk`,产出自包含 HTML 报告 + JSON。

### 非目标(本期)
- 不做真·运行时抓包(架构预留 `requires=["adb"]` 插件位,P3 再做)。
- 不做脱壳(加固只检测并标注,提示人工脱壳/真机补全)。
- 不做 Web UI。

---

## 2. 架构:插件式流水线

```
apkscan/
  cli.py                  # 入口:typer 命令,参数 → pipeline → report
  core/
    models.py             # 数据模型:Severity/Confidence/LeadCategory/Evidence/Finding/Endpoint/Lead/AnalyzerResult/Report
    context.py            # AnalysisContext(Protocol + 实现):分析器共享上下文,依赖倒置便于测试
    apk.py                # androguard APK 加载,构造 AnalysisContext
    registry.py           # BaseAnalyzer/BaseEnricher + 自动发现 + 能力探测
    pipeline.py           # 跑分析器(逐个 try/except 记错,不吞)→ 跑富化器 → 聚合成 Report → 生成 Lead
  analyzers/              # 静态分析器(零环境,永远可用)
    manifest.py certificate.py packing.py endpoints.py
    sdk_fingerprint.py payment.py contacts.py
    permissions.py components.py crypto.py
  enrichers/              # 富化器(默认联网)
    whois.py asn.py icp.py
  report/
    html.py json.py templates/report.html.j2
  rules/                  # YAML 规则:sdk 指纹、加固特征、密钥/支付正则
tests/                    # pytest;每模块一个 test_*.py;conftest.py 提供 FakeContext
```

### 关键抽象
```python
class BaseAnalyzer(ABC):
    name: str
    requires: list[str]                # 需要的能力(空=永远可用);registry 探测后决定是否运行
    @abstractmethod
    def analyze(self, ctx: "AnalysisContext") -> "AnalyzerResult": ...

class BaseEnricher(ABC):
    name: str
    def enrich(self, endpoint: "Endpoint") -> "EnrichmentResult": ...
```
- `registry` 用 `pkgutil` 自动发现 `analyzers/`、`enrichers/` 下的子类 → **新增模块无需改任何中心文件**。
- 能力探测:检查外部工具是否在 PATH(jadx/adb)、网络是否启用(`--online`)。不满足 `requires` 的分析器 → 报告里记"已跳过(原因)",不静默。

### 依赖倒置(可测试性核心)
`AnalysisContext` 先定义为 Protocol,分析器**只依赖其公开方法**,不直接 import androguard:
```python
class AnalysisContext(Protocol):
    package_name: str
    manifest_xml: str
    config: AnalysisConfig                 # online: bool, out_dir, ...
    def permissions(self) -> list[str]: ...
    def components(self) -> ComponentSet: ...      # activities/services/receivers/providers + exported 标志
    def dex_strings(self) -> Iterator[str]: ...    # DEX 字符串池
    def list_files(self) -> list[str]: ...         # APK 内所有文件路径
    def read_file(self, path: str) -> bytes | None: ...
    def native_libs(self) -> list[str]: ...        # .so 路径
    def certificates(self) -> list[CertInfo]: ...
```
测试用 `FakeContext`(conftest.py)实现同一接口 → 单测**无需 androguard、无需联网**。

---

## 3. 数据模型(以 Lead 为中心)

```python
class Severity(Enum): INFO LOW MEDIUM HIGH CRITICAL
class Confidence(Enum): LOW MEDIUM HIGH
class LeadCategory(Enum):
    DOMAIN IP SDK_SERVICE PAYMENT PACKER CONTACT SIGNING CHANNEL

@dataclass
class Evidence:
    source: str        # dex|resource|native|manifest|cert|runtime
    location: str      # 文件路径 / 类名 / 资源名(可复现)
    snippet: str = ""

@dataclass
class Endpoint:
    value: str
    kind: str          # url|domain|ip
    evidences: list[Evidence]
    is_cleartext: bool = False
    is_private: bool = False        # 内网/回环 IP
    is_suspicious: bool = False
    enrichment: dict = field(default_factory=dict)   # whois/icp/asn 结果

@dataclass
class Lead:                          # ★ 报告的核心产出单元
    category: LeadCategory
    value: str                      # "pay.xxx.com" / "极光推送 JPush"
    subject: str | None = None      # 归属主体(公司)
    where_to_request: str | None = None   # 向谁调:注册商/云厂商/SDK厂商/加固厂商
    evidence_to_obtain: list[str] = field(default_factory=list)  # 可调取的证据
    confidence: Confidence = Confidence.MEDIUM
    source_refs: list[Evidence] = field(default_factory=list)
    notes: str = ""

@dataclass
class Finding:                       # 技术发现(附录用)
    id: str; title: str; severity: Severity; category: str
    description: str; recommendation: str = ""
    evidences: list[Evidence] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

@dataclass
class AnalyzerResult:
    analyzer: str
    leads: list[Lead] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    error: str | None = None        # 该分析器崩溃时记录,不抛出

@dataclass
class Report:
    package_name: str
    meta: dict                      # 版本/SDK/签名摘要/加固状态
    leads: list[Lead]
    endpoints: list[Endpoint]
    findings: list[Finding]
    analyzer_status: list[dict]     # 每个分析器:ran/skipped/error + 原因
```

---

## 4. 分析器职责

| 模块 | 产出 | 调证价值 |
|---|---|---|
| `manifest` | 包名/版本/min&targetSDK/debuggable/allowBackup | 基础指纹 |
| `certificate` | 签名证书(主体/指纹/有效期/调试证书/v1v2v3) | **跨 App 关联同一开发者** |
| `packing` | 加固厂商识别(梆梆/爱加密/360/腾讯乐固/娜迦/百度/网易易盾) | 加壳→端点不全告警 + **加固厂商=高价值调证目标** |
| `endpoints` | dex+资源+native+manifest 全量 URL/域名/IP,明文/内网标记 | 网络落地 |
| `sdk_fingerprint` | 第三方 SDK/服务识别 → 厂商映射 | **每个 SDK 绑定一家可调证公司** |
| `payment` | 聚合支付/收款/商户号线索 | **资金流核心** |
| `contacts` | QQ/微信/Telegram/邮箱/手机号 | 直接落地线索 |
| `permissions` | 危险权限 → Finding | 风险佐证(附录) |
| `components` | 导出的 activity/service/receiver/provider | 攻击面 + 风险佐证(附录) |
| `crypto` | 弱加密(MD5/ECB/硬编码 IV) | 风险佐证(附录) |

### SDK 指纹库(高价值,YAML 驱动,覆盖国内主流)
- 支付:支付宝、微信支付、银联、各聚合支付
- 短信:阿里云短信、腾讯云短信、容联云、Mob
- 推送:极光 JPush、个推、友盟推送、华为/小米/OPPO/vivo 厂商推送
- 云/存储/CDN:阿里云 OSS、腾讯云 COS、七牛、又拍云、华为云
- IM/客服:融云、环信、网易云信、容联七陌
- 统计:友盟、TalkingData、神策
- 地图:高德、百度地图
每条指纹:`name / vendor / category / 匹配特征(包名前缀/类名/资源/字符串/so 名) / 可调取证据 / 调证对象`。

加固特征库同理(按 so 名 / 特征文件 / 类名识别)。

---

## 5. 富化器(默认联网,可缓存,尊重 --offline)

| 模块 | 输入 | 输出 | 备注 |
|---|---|---|---|
| `whois` | 域名 | 注册人/注册商/注册时间 | python-whois |
| `icp` | 中国域名 | ICP 备案主体(**实名**)/备案号 | 可插拔 provider;反爬,失败则标注"需人工核" |
| `asn` | IP | 归属 ASN/云厂商/IDC/地理 | ip-api.com 之类;限速 |
- 结果缓存到本地(避免重复查询)。失败/超时 → 字段标"查询失败",不阻塞主流程。
- `--offline` 时全部跳过,报告标注归属待人工核。

---

## 6. 报告结构(HTML + JSON)

1. **概览**:包名/版本/签名主体/**加固状态**/线索数量摘要
2. ★ **调证线索清单**(核心):按 `LeadCategory` 分组,按 `confidence` 排序;每条显示 value / 归属主体 / 向谁调 / 可调取证据 / 取证依据(APK 内位置)
3. **网络端点全表**:域名/IP + WHOIS/ICP/ASN 富化 + 明文/内网标记
4. **第三方服务 / SDK → 厂商清单**
5. **支付/资金线索** · **联系方式线索**
6. **技术附录**:权限 / 组件 / 证书 / crypto findings
7. **分析器运行状态**:每个分析器 ran/skipped/error + 原因(透明,不吞错)

HTML 用 Jinja2 单模板,CSS 内联 → 单文件自包含可分享。JSON 为 `Report` 的完整序列化。

---

## 7. 错误处理

- 单分析器异常 → `AnalyzerResult.error` 记录 + 报告"分析器运行状态"展示,流水线继续。**不 swallow、不裸 except pass**(符合个人规范:try/except 里不静默)。
- 联网富化失败/超时 → 该字段标失败,继续。
- APK 无法解析(损坏/非 APK)→ fail fast,清晰报错。
- 加固导致 DEX 不可见 → `packing` 醒目告警"静态端点不完整"。

---

## 8. 测试

- pytest(非 unittest),type hints 全程。
- 每个分析器:用 `FakeContext` 喂合成数据(合成 manifest XML / 字符串列表 / 文件字典)做单测,**不依赖 androguard/网络**。
- 富化器:mock 网络层做单测。
- 1 个 `apk.py` 集成测试(若环境有 androguard;否则 skip 标注)。

---

## 9. 分期

- **P1(本次构建,零环境可跑)**:CLI + core(models/context/apk/registry/pipeline)+ 全部静态分析器 + Lead 模型 + HTML/JSON 报告 + 单测。
- **P2(本次一并做)**:whois/asn/icp 富化器(默认联网,--offline 可关)。
- **P3(预留,不在本次)**:真·抓包插件(adb + mitmproxy);jadx 深度反编译增强;FlowDroid 污点。

---

## 10. 合规边界

本工具用于**授权的反诈调证**场景。仅做分析与线索提取,不提供攻击/绕过/规避检测能力。加固只识别不脱壳。联网富化仅查公开的 WHOIS/备案/ASN 信息。
