# fxapk

[![CI](https://github.com/s-silt/fxapk/actions/workflows/ci.yml/badge.svg)](https://github.com/s-silt/fxapk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

*CLI 命令 `fxapk`（保留 `apkscan` 别名）· PyPI 包名 `fxapk`* · **English**: [README.en.md](README.en.md)

APK 分析工具，一条命令出一份报告。它主要做四件事：

**翻出应用真正在用的配置。** AppID、AppKey、渠道号、uni-app 的应用 ID 这些，包括塞在资源文件和
native 库里的。

**看它跟哪些服务器说话。** 域名、IP、端口先静态抠一遍；接了设备就再抓一遍包，两边对上。

**顺着加密的远程配置往下追。** 有些应用不把后端地址写死在包里，而是加密后丢在 OSS 或 CDN 上，
启动时拉下来解密。工具会找到那个对象、一层层解出里面的域名和 IP 池，拼成完整的一条链。碰上认不出
解密方式的混淆样本，它不硬猜，把密文原样交出来让人或 AI 接着解。

**查域名和 IP 是谁的。** 分五层写：谁登记的、走哪个 AS、放在哪家云或机房、前面有没有套 CDN、
实际运营者是谁。每层都带来源，查不到就写不知道 —— 不会拿上一层的答案顶下一层，那是这类工具最
容易出错的地方。

装完就能跑静态分析，不需要 JDK、模拟器或真机。要给加固样本脱壳、要抓包，才需要接一台 root 过的
安卓机。

## 安装

需要 Python 3.11+。

```bash
pip install fxapk

# 或从源码
git clone https://github.com/s-silt/fxapk.git && cd fxapk && pip install -e .
```

脱壳、抓包、样本库这些是可选依赖，用到哪个装哪个。没装的话对应命令会提示你，不影响核心分析。

> 联网查询用的 API Key、动态分析要的外部工具、以及围绕报告的那些配套脚本 / MCP / 探针库，都要自己
> 准备，本项目不提供。见 [COMPANION-TOOLS.md](COMPANION-TOOLS.md)。

### 想让同一个样本跑出同一份报告

结论是解析出来的，而解析归上游库管。androguard 换个版本，dex 里读出来的东西就可能不一样；报告也就
跟着不一样了。所以仓里放了一份 [`requirements.lock`](requirements.lock)，把整棵运行时依赖钉死：

```bash
python -m venv .venv-forensic
.venv-forensic/bin/pip install -r requirements.lock
.venv-forensic/bin/pip install --no-deps .
```

第二条命令的 `--no-deps` 别省 —— 省了 pip 会重新算一遍依赖，把刚锁住的版本又升上去。

平时随便装就行，用不着这个。只有要复现一份旧报告、或者要让两个人跑出一模一样的结果时才需要。报告
自己也记着当时实际用的版本（`meta.dependency_versions`），跟这份锁对一下就知道环境一不一样。

## 用法

```bash
# 静态分析，HTML + JSON 输出到 out/
fxapk analyze app.apk --out out

# 手上只有存下来的网页文件（.html / .body / .js / .headers）也能分析，不会联网重新抓
fxapk analyze-web <证据目录> --out out

# 接好 root 机后一把梭：体检 → 静态 → 脱壳 → 抓包 → 合并成一份报告
fxapk auto app.apk --out out

# 同上，但把结论当验收门用：complete 退 0、partial 退 5、failed 退 6
# 没设备也能跑，此时不拿动态证据卡门
fxapk auto app.apk --out out --strict-case

# 已有报告想补齐：多源查询、五层归属、重新验收
fxapk case close out/app.json

# 换了版本，检出到底变好还是变坏（先把两版报告都 corpus add 入库）
fxapk corpus regress --corpus <库目录>

# 哪些样本出自同一套开发环境
# 构建路径是编译时烙进 native 库的，改名、重打包、换服务器都动不了它
fxapk corpus shared-build-env

# 批量查一份目标清单（每行一个 IP 或域名）
# 默认 --dry-run，只估算各源要花多少配额，一个请求都不发
fxapk enrich batch -t targets.txt -o enrich_out
```

常用命令：`analyze` 静态分析、`analyze-web` 分析存下来的网页、`auto` 一把梭、`case close` 给已有
报告补齐、`capture` 真机抓包、`doctor` 设备体检顺带自动修、`enrich batch` 批量查询（能续跑）、
`corpus` 样本库（报告入库、跨版本回归、按值反查、按构建环境找同源样本）。完整参数看 `fxapk --help`。

没装成命令的话，`python -m apkscan.cli <…>` 一样用。

验收结论写在 `report.meta.closure`：`complete` 是指主目标那五层都拿到了证据（运行时、资源登记、
BGP 宣告、托管分发、最终归属对象）；`partial` 是还有明确缺口；`failed` 是静态就跪了、或者要求动态
却没抓到业务流量、或者压根没有能收口的主目标。前面套着 CDN、源站还没定位出来的，不会判 complete。

### 报告先告诉你哪些东西没看着

报告和 `fxapk digest` 里都有一段 `visibility`，位置在线索前面。它回答的是：这一趟到底看到了什么，
所以哪些话能说、哪些说不了。

这段挺要紧。加固过的应用，DEX 常常只剩个壳，真代码要跑起来才解密出来。这时候报告里写「没发现网络
端点」，意思是没看着，不是没有。`blocked_claims` 会点名哪几条「翻遍了都没有」的结论现在不能下，
`next_actions` 说怎么补：该脱壳的脱壳、该抓包的抓包，或者拿到授权后重跑去取远程配置。

别把它和 `analysis_status` 弄混。后者说的是工具跑得顺不顺，前者说的是样本内容看不看得见。分析器
全部成功、`analysis_status=complete`，同时 DEX 是个壳、六条结论一条都不能下 —— 这两件事完全可以
同时成立。

### 先分清：自己写的包，还是正版被人改过

`repack_identity` 会给三种判定，这一步得先做，因为两种情况下接口、域名、构建路径的归属正好相反。
自己写的包，这些都是开发方自己的；正版被重打包的，这些属于被冒名的那家厂商 —— 照着去查就会找错
对象，找到一家毫不相干的公司头上。

判成重打包时，工具只说「看起来被重新签过名」，不会说「植入了什么」。想认定植入，得拿官方同版本的
包逐个文件比对，光看这个样本本身给不出这种结论。

## 输出

- `out/report.html` — 单文件报告，直接发人或手机上打开都行
- `out/report.json` — 完整数据，给机器读或者接着加工
- `report.meta.closure` — 验收结论、五层证据、来源覆盖、缺口和下一步该干什么
- 加 `--fmt pdf` 可以导 PDF（要本机装了 Chrome 或 Edge）

## 从源码改代码

clone 完先跑一次，把提交前的检查装上：

```bash
git config core.hooksPath .githooks
```

它只看你这次 staged 的新增行。像真实 IP、像密钥、写了豁免却没给理由的，直接拦下不让提交；域名和
一些敏感词只提示不拦（想连这些一起拦，加 `FXAPK_LEAK_SCAN_STRICT=1`）。确实要放行某一行，就在行内
写 `leak-scan: allow <理由>`，理由必须写。CI 会再扫一遍 PR diff，所以 `--no-verify` 只绕得过本地
这道。

测试数据一律用文档保留段：`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`、`2001:db8::/32`、
`example.com`。真实地址推上去就收不回来了，改写历史也删不掉平台那边的缓存副本，唯一靠谱的办法是
一开始就别写进去。

## 合规边界

仅用于授权范围内的安全研究与分析。工具只做静态、动态分析和信息提取，不提供任何针对第三方的攻击、
漏洞利用或主动探测能力。

默认被动：境外服务器只做被动归属（RDAP / WHOIS / DNS / ASN / 证书透明度），对目标零主动流量。少数
确实要向目标发请求的能力（比如去取样本自己引用的那个配置对象）默认关着，只有显式加
`--mode authorized-active` 才启用。脱壳只针对样本自身，在你自己的授权分析机上进行。

请在合法授权范围内使用。

## License

[MIT](LICENSE)
