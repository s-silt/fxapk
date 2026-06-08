# 动态分析接入手册（真机 / 模拟器）

apkscan 的动态能力（脱壳 `unpack`、抓包 `capture`、`analyze --dynamic`）需要一台 **已 root、装好 frida-server、信任了 mitmproxy CA** 的 Android 设备。本手册覆盖真机与主流模拟器（夜神 / MuMu / 雷电 / AVD）各自的 adb 连接、root、ARM 兼容、frida 版本一致、CA 安装要点。

> 先跑体检：`fxapk doctor`（或 `python -m apkscan.cli doctor`）会逐项检查并尽量自动修复，修不了的给出可逐条复制的命令。本手册即 doctor 各检查项背后的原理与手动步骤。

---

## 0. 一条命令先体检

```bash
fxapk doctor            # 自动修能修的（部署 frida-server、装 CA）
fxapk doctor --no-fix   # 只读体检，不动设备
fxapk doctor --serial emulator-5554   # 指定设备
```

输出形如：

```
[OK]   在线设备：emulator-5554（共 1 台）
[OK]   设备 root：su -c id → uid=0
[OK]   设备 ABI：x86_64
[OK]   主机 frida CLI 版本：16.5.9
[FAIL] 设备 frida-server 运行且版本匹配：设备 frida-server 未运行
       建议命令：
         frida-ps -U  # 验证；或开启 --fix 自动部署
[OK]   mitmproxy/mitmdump 已安装
[FAIL] CA 已信任：CA 未装入系统信任库：无 root，HTTPS 只能抓密文
       建议命令：
         # 开启 --fix 自动安装，或参考 docs/dynamic-setup.md 手动装 CA
```

七个检查项与本手册章节对应：

| doctor 检查项 | 含义 | 见本手册 |
|---|---|---|
| 在线设备 | `adb devices` 有 device 状态条目 | §1 §2 |
| 设备 root | `adb shell su -c id` → uid=0 | §3 |
| 设备 ABI | `getprop ro.product.cpu.abi`，决定 frida-server 选包 | §4 |
| 主机 frida 版本 | 主机 `frida --version`，决定下载哪版 frida-server | §5 |
| 设备 frida-server 运行且版本匹配 | 设备端 frida-server 在跑且版本==主机 | §5 |
| mitmproxy 已安装 | 主机 `mitmdump` 在 PATH | §6 |
| CA 已信任 | mitmproxy CA 装入设备**系统**信任库 | §6 |

---

## 1. 主机前置（一次性）

```bash
pip install frida-tools mitmproxy      # frida CLI + mitmdump
# 可选：CA subject_hash 计算退路依赖（无 openssl CLI 时）
pip install cryptography
```

- `adb` 来自 Android platform-tools，需在 PATH。
- frida-server 下载只用 stdlib（urllib + lzma），无需额外包；但**内网/无外网环境**会失败，见 §5 离线方案。

---

## 2. 各形态 adb 连接

| 形态 | 连接方式 | 默认端口 |
|---|---|---|
| **真机（USB）** | 开发者选项 → USB 调试 → `adb devices` | — |
| **真机（无线）** | `adb tcpip 5555` 后 `adb connect <手机IP>:5555` | 5555 |
| **夜神 Nox** | `adb connect 127.0.0.1:62001`（多开 +1：62025…） | 62001 |
| **MuMu（网易）** | `adb connect 127.0.0.1:7555`（新版 16384） | 7555 / 16384 |
| **雷电 LDPlayer** | `adb connect 127.0.0.1:5555`（多开 +2：5557…） | 5555 |
| **AVD（标准模拟器）** | 启动后自动出现在 `adb devices`，序列号 `emulator-5554` | 5554 |

连接后用 `adb devices` 确认状态是 `device`（不是 `offline` / `unauthorized`）。多设备时所有命令加 `-s <serial>`，apkscan 用 `--serial`。

> 排障：`adb kill-server && adb start-server` 重置；模拟器自带的 adb 与系统 adb 冲突时，统一用一个版本（把 platform-tools 的 adb 放 PATH 最前）。

---

## 3. Root

| 形态 | Root 现状 | 取得 root shell |
|---|---|---|
| 夜神 / MuMu / 雷电 | 多为**默认 root**（设置里有 root 开关，打开即可） | `adb shell su -c id` → uid=0 |
| 真机 | 需自行解锁 BL + 刷 Magisk | Magisk 授权 shell |
| AVD（Google APIs，非 Google Play 镜像） | `adb root` 可直接拿 root；Google Play 镜像**不可** root | `adb root` |

验证：

```bash
adb shell su -c id     # 期望 uid=0(root)
# 或（AVD Google APIs 镜像）
adb root && adb shell id
```

无 root 的影响：**装不了系统 CA（HTTPS 只能抓到密文）**，也起不了 frida-server。doctor 把 root 列为非关键项，但 CA / frida-server 这两个关键项会因此连带失败。

---

## 4. ABI 与「x86 跑 ARM 加固 App」

`adb shell getprop ro.product.cpu.abi` 给出设备首选 ABI，决定下载哪个 frida-server 包：

| 设备 ABI | frida-server 包后缀 |
|---|---|
| arm64-v8a | `android-arm64` |
| armeabi-v7a / armeabi | `android-arm` |
| x86_64 | `android-x86_64` |
| x86 | `android-x86` |

**关键坑：x86/x86_64 模拟器跑 ARM-only 加固 App。**
夜神 / 雷电 / 标准 AVD 多是 x86/x86_64 架构。很多加固 App（梆梆、爱加密、360 等）只带 ARM 的 .so，在 x86 上要靠 **ARM 翻译层（houdini / NativeBridge）** 才能跑：

- **首选 ARM 镜像**：MuMu / 雷电 / 夜神 部分版本提供「ARM 版」或在设置里开「兼容/ARM 翻译」，最省事。
- **x86 + 翻译层**：能跑起来 App，但此时**进程是 x86，frida-server 必须用 x86/x86_64 包**（按 `getprop` 实测 ABI 选，别按 App 的 .so 架构选）；翻译层下 frida 注入 ARM 函数 hook 偶发不稳定。
- **真机最稳**：arm64 真机没有翻译层问题，加固样本行为最接近真实，建议关键样本用真机复核。

> apkscan 的 `provision.ensure_frida_server` 按 `getprop` 实测 ABI 选包，无需手动指定；未知 ABI 不臆测，会直接给手动下载提示。

---

## 5. frida-server：版本必须与主机一致

frida 的注入协议**主机 CLI 与设备 frida-server 版本必须完全相同**（如同为 16.5.9），否则注入失败或行为诡异。`fxapk doctor --fix` / `provision.ensure_frida_server` 会：

1. 读主机 `frida --version` 与设备 ABI；
2. 拼 GitHub releases URL：
   `https://github.com/frida/frida/releases/download/<ver>/frida-server-<ver>-android-<abi>.xz`
3. urllib 下载 + lzma 解压，`adb push` 到 `/data/local/tmp/frida-server`，`chmod 755`，`su -c` 后台启动；
4. 轮询 `frida-ps -U` 验证。

### 手动 / 离线部署（内网无外网时）

doctor / provision 会区分「无网络」与「该版本·ABI 不存在(404)」并给出完整手动命令。在另一台能上网的机器下载后拷进来：

```bash
# 1) 确认版本与 ABI
frida --version                              # 例 16.5.9（主机）
adb shell getprop ro.product.cpu.abi         # 例 x86_64

# 2) 浏览器下载（版本/ABI 替换为上面的实测值）
#    https://github.com/frida/frida/releases/download/16.5.9/frida-server-16.5.9-android-x86_64.xz

# 3) 解压并部署
xz -d frida-server-16.5.9-android-x86_64.xz  # 得到无后缀文件
adb push frida-server-16.5.9-android-x86_64 /data/local/tmp/frida-server
adb shell su -c 'chmod 755 /data/local/tmp/frida-server'
# 后台启动务必 setsid/nohup + 重定向 std{out,err}，否则 adb shell 会被长驻进程挂住：
adb shell su -c 'setsid /data/local/tmp/frida-server >/dev/null 2>&1 &'

# 4) 验证
frida-ps -U                                  # 能列进程即 OK
```

> 主机若没装 frida：`pip install frida-tools`。
> 版本不一致时，capture 不会硬阻断（仍尝试注入），但会在 reason / playbook 写明「版本不一致，注入可能失败」——这是设计上的「不假成功」。

---

## 6. mitmproxy CA：HTTPS 能否抓到明文的命门

不把 mitmproxy 的 CA 装进设备**系统**信任库，HTTPS 流量只会是密文（Android 7+ 用户证书默认不被 App 信任）。`fxapk doctor --fix` / `provision.ensure_mitm_ca` 自动完成；原理与手动步骤如下。

### 6.1 CA 文件与 subject_hash_old 命名

- CA 文件：`~/.mitmproxy/mitmproxy-ca-cert.pem`（首次跑一次 `mitmdump` 即生成）。
- Android 系统信任库文件名是 `<subject_hash_old>.0`，其中 hash =
  `openssl x509 -inform PEM -subject_hash_old -in mitmproxy-ca-cert.pem -noout`
  （无 openssl 时退路：`cryptography` 算 `MD5(规范化 DER subject)` 前 4 字节小端 hex）。

### 6.2 推入信任库（按形态分路）

**主路（有 root 且 /system 可写：夜神 / 雷电 / 旧 Android / 已 remount 真机）：**

```bash
HASH=$(openssl x509 -inform PEM -subject_hash_old -in ~/.mitmproxy/mitmproxy-ca-cert.pem -noout)
adb root                                              # best-effort
adb shell su -c 'mount -o rw,remount /system'        # 夜神/雷电常需这步
adb push ~/.mitmproxy/mitmproxy-ca-cert.pem /sdcard/$HASH.0
adb shell su -c "cp /sdcard/$HASH.0 /system/etc/security/cacerts/$HASH.0"
adb shell su -c "chmod 644 /system/etc/security/cacerts/$HASH.0"
adb reboot                                            # 部分形态需重启生效
```

**退路（Android 10+ /system 只读、Magisk）：**

```bash
adb shell su -c "mkdir -p /data/misc/user/0/cacerts-added"
adb push ~/.mitmproxy/mitmproxy-ca-cert.pem /data/local/tmp/$HASH.0
adb shell su -c "cp /data/local/tmp/$HASH.0 /data/misc/user/0/cacerts-added/$HASH.0 && chmod 644 /data/misc/user/0/cacerts-added/$HASH.0"
# 需配合 Magisk「Move Certificates / Always Trust User Certs」类模块，可能需重启
```

> **退路不等于已信任**：仅把证书 cp 到 `cacerts-added` 在 Android 10+ 默认并不生效，
> 必须配套上述 Magisk 模块且通常需重启，App 才会信任该 CA、HTTPS 才抓得到明文。
> 因此 `provision.ensure_mitm_ca` 在这条路上返回 `ok=False`（`action=installed_user_store`、
> `verified=False`），`doctor` 的「CA 已信任」项也会**显示 [FAIL]+待生效说明而非 [OK]**——
> 这是刻意的「不假成功」：装 Magisk 模块/重启后请重跑 `doctor` 复检。

### 6.3 各形态备注

| 形态 | /system 可写性 | 路线 |
|---|---|---|
| 夜神 / MuMu / 雷电（x86，自带 root） | 多可 `mount -o rw,remount` | 主路 |
| 标准 AVD（非 `-writable-system` 启动） | /system 只读 | 需 `emulator -writable-system` + `adb root` + `adb remount`，否则走退路 |
| Android 10+ 真机 / Magisk | /system 只读 | 退路（用户库 + Magisk 模块） |

> 无 root / 两路皆败时，doctor 会明确写「无法把 CA 装入系统信任库，HTTPS 将只抓到密文」——**不假成功**。此时只能抓 HTTP 明文，或换一台可 root 的设备。

---

## 7. 跑动态分析

环境就绪（doctor 全绿）后：

```bash
fxapk capture com.target.app --duration 60          # 单独抓包
fxapk unpack target.apk                              # 单独脱壳
fxapk analyze target.apk --dynamic                  # 静态 + 有设备则自动脱壳+抓包+并回报告
```

`analyze --dynamic` 会在抓包完成后，把运行时端点（真·C2 / 资金回调）去重并入主 `report.endpoints`、按 infra 分级生成线索、重渲 `report.html` / `report.json`，让运行时发现进入主线索清单而非游离在 `runtime_report.json`。

---

## 8. 无设备时怎么办

`capture` / `unpack` 在缺前置条件时返回 `status=skipped` 并附 **playbook**（可手动照做复现的完整取证步骤）；`doctor` 给每个失败项可复制的 `fix_cmd`。这些都是结构化数据，将来 GUI 可直接渲成可复制按钮。

> 本手册的模拟器 remount / su / 翻译层等细节为基于文档与经验的设计，**首次在某具体形态真机/模拟器上接入时请按 `doctor` 输出实测核验**（端口、root 方式、/system 可写性各形态略有差异）。
