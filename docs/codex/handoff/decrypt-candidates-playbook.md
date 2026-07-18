<!-- 个人安全研究 / 授权取证；仅对自有 / 授权样本；如发现异常线索可提供给授权方依规处置。 -->

# 待解密线索打法（config-chain `decrypt_candidates` → 恢复后端配置）

> 给**任意 AI 模型（GLM / Codex / Kimi / Claude）/ 操作员**的说明。
> fxapk 只**确定性定位并打包**加密配置串，实际解密交给你——工具做能确定性做的（定位密文 + 疑似解密函数 + 已知配方自动解），你做一步解密推理。
> 口径：授权取证——解**自有 / 授权**样本里硬编码的密文，非攻击。

## 一句话
重度混淆的涉诈 APK 常把后端地址 / 配置**硬编码成密文**，运行时由一个（被 jadx 改名的）helper 解开。`string_graph` 把这些密文 + 疑似解密函数打成**机器可读清单**；配方已知的 fxapk 已自动解，剩下的就是你的活——**一次一条，原子任务**。

## 清单在报告哪
- `report.meta["decrypt_candidates"]` —— 待解密线索，每条 `{ciphertext（完整密文）, consumer（疑似改名的解密 helper）, method, location, standard_decrypt, sinks}`。
- `report.meta["decrypt_candidates_auto"]` —— **Tier A**：fxapk 已用已知配方自动解的结果（`decrypted:true` 的直接用、别重复解）。
- `report.meta["crypto_recipe"]` —— 已提取到的解密配方（若有）。

## 一次一条（任何模型都能做，无需多工具编排）
对 `decrypt_candidates` 里**每一条**：

1. **先查 Tier A**：该 `ciphertext` 在 `decrypt_candidates_auto` 里已 `decrypted:true`？→ 用现成明文，跳过。
2. **凑配方**（三来源，易→难）：
   - `meta["crypto_recipe"]`（现成，最省事）；
   - 报告 `findings` 里的硬编码密钥（secret / `CONFIG_KEY` 线索）当 key 试；
   - **读反编译源码里 `consumer` 那个函数**（jadx sources，看 `<consumer>()` 里的 `Cipher.getInstance` / key / iv / mode —— 那就是改名 helper 的真身；`AbstractXxx.m1136x` 之类）。
3. **解**（用 fxapk 自带 `appcrypto`，或标准库 / 自己推理）：
   ```bash
   python -c "from apkscan.core.appcrypto import CryptoRecipe, decrypt_envelope; \
   r=CryptoRecipe.from_meta({'algo':'AES','mode':'CBC','padding':'Pkcs7','key':'<key>','key_encoding':'utf8','iv_derive':'fixed','iv_value':'<iv>','payload_encoding':'base64'}); \
   print(decrypt_envelope('<ciphertext>', r, 0))"
   ```
   `iv_derive` 常见取值：`fixed`（配 `iv_value`）/ `none`（ECB）/ `same_as_key` / `md5(key+ts)[:16]`（需运行时 ts，静态多半解不出→转动态）。
4. **判明文**：
   - 解出 **URL / 域名 / JSON 配置** → 就是后端配置：域名 / IP 交给五层归因，OSS 配置 URL 当新的 remote_config 候选（可能还套一层 gzip/base64，喂 `config.decode.decode_config_blob`）。
   - 解出**乱码** → 配方不对（换 key/iv/mode 再试一两组），或 iv 依赖运行时 ts → **转动态**。

## 静态解不出 → 转动态（Codex 真机）
key/iv 在 native、或 `iv=md5(key+运行时ts)` 静态凑不齐 → 交 **Codex 真机 hook `consumer` 函数的返回值**（`dynamic/cryptohook` / frida，只读返回值），直接拿解密后的明文，**不用逆配方**。

## 衔接飞书 handoff（见 `PROTOCOL.md`）
- **Claude（机 A）**：读报告 `decrypt_candidates` → 凑配方 + `appcrypto` 静态解 → 解出的域名走归因 / 出报告。
- **Codex（机 B 真机）**：静态解不出的 → hook `consumer` 拿明文。
- 交接照旧：`球→CODEX 待hook <consumer>` / `球→CLAUDE 已解出 <域名>`。

## 红线
- 只解**自有 / 授权**样本里的密文；解出的后端 URL / 域名走既有「建议调证」被动流程，不主动攻击。
- **不臆造**：解出乱码就是没解出，别硬凑成"疑似域名"——留 `unrecoverable → 需动态` 比编一个假的强。
