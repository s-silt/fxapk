"""apkscan.dynamic.cryptohook — 运行时密钥 hook（P0）：Frida 抓活体 AES key/明文。

为什么需要它（补 C5a 静态配方之不足）：
  C5a（``analyzers/crypto_recipe.py``）从打包 JS 静态反查加密配方，但当 **key 在运行时
  计算/服务端下发**（而非硬编码）时，静态拿不到真实 key。本模块在真机抓包时用 Frida
  hook ``javax.crypto.Cipher``（init/doFinal）+ ``SecretKeySpec``/``IvParameterSpec`` +
  ``Mac`` + WebView 内 CryptoJS，把**活体 key / iv / 明文 / 密文**经 ``send()`` 回传
  Python，再由 merge 用「运行时实测配方优先」对抓到的 ``{data,timestamp}`` 信封解密。

职责边界（贴合现有架构、不另起炉灶）：
  - 本模块只做**纯逻辑**：持有 Frida JS 常量、解析 ``send()`` 消息、从活体事件反推
    ``crypto_recipe`` meta（喂回 ``appcrypto.CryptoRecipe.from_meta``）、抽冒充品牌线索。
  - 真机编排（建会话/注入/收尾）在 ``capture.py``；本模块无 I/O 副作用（除 logging），
    便于无设备全 mock 单测。
  - **不新增 LeadCategory**：运行时实测只是把 CRYPTO_RECIPE 从「静态推定」升级为
    「活体实证」（merge 侧体现），避免模型契约漂移。

设计铁律（与 dynamic 一致）：
  - 绝不把异常抛给调用方（on_message 在 Frida 回调线程触发，抛了会炸会话）。
  - 不静默吞错：每个 except 必 logging。
  - 全程 type hints。
  - 二进制一律 hex/base64 字符串（JS 侧已转），绝不裸塞 JSON（否则 UTF-8 损坏）。
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

#: ``send()`` payload 的通道判别值（JS 与 Python 两端约定）。
CRYPTO_MSG_TYPE = "apkscan-crypto"
#: P1 运行时 JS-bridge 追踪通道（hook WebView.addJavascriptInterface + 暴露方法调用）。
JSBRIDGE_MSG_TYPE = "apkscan-jsbridge"
#: P1 运行时敏感 API 追踪通道（hook TelephonyManager/SmsManager/… 实际调用）。
SENSITIVE_API_MSG_TYPE = "apkscan-api"
#: P3 反检测绕过通道（绕过 root/模拟器/frida 检测，并把检测尝试本身作为反分析行为上报）。
ANTIDETECT_MSG_TYPE = "apkscan-antidetect"
#: 第二波：运行时登录态/明文凭据采集通道（OkHttp 加密前明文 dump + SharedPrefs 落地凭据）。
CREDENTIAL_MSG_TYPE = "apkscan-credential"
#: 第二波：运行时 SQLCipher/SQLite 落地库导出通道（库路径 + key + 明文导出库路径）。
SQLCIPHER_MSG_TYPE = "apkscan-sqlcipher"

#: sink 累积上限：高频加密（每帧/每请求）会刷爆，超限丢弃 + 记一次 warning。
_SINK_CAP = 4000

#: 明文/密文回传字符上限（JS 侧已截断，Python 侧再兜底防御）。
_MAX_FIELD_CHARS = 64 * 1024

#: 冒充对象常出现在明文 JSON 的这些键里（反诈视角：还原"冒充谁"）。
_BRAND_KEYS: tuple[str, ...] = (
    "webname",
    "appname",
    "platformname",
    "sitename",
    "companyname",
    "brand",
    "title",
    "name",
    "company",
)

#: 冒充对象常含这些行业词（值里命中即视为品牌线索候选）。
_BRAND_HINT_TOKENS: tuple[str, ...] = (
    "证券",
    "银行",
    "基金",
    "交易所",
    "钱包",
    "理财",
    "投资",
    "资管",
    "金融",
    "期货",
    "信托",
    "保险",
)


# ---------------------------------------------------------------------------
# Frida JS：javax.crypto.Cipher / Mac / SecretKeySpec / IvParameterSpec + WebView CryptoJS
# ---------------------------------------------------------------------------
#
# 与 capture.FRIDA_UNPINNING_JS 拼接成单一脚本（session.create_script）。所有 hook 各自
# try/catch，单点失败不影响 unpinning 与其它 hook（沿用 capture 的 best-effort 风格）。
# 二进制一律 b2hex/Base64 转字符串塞 payload；按 (src,transformation,key_hex,iv_hex) 去重
# init、按计数上限封顶 doFinal，避免刷爆 send 通道。
FRIDA_CRYPTO_HOOK_JS: str = r"""
// apkscan 运行时密钥 hook（best-effort）：抓活体 AES key/iv/明文/密文回传 Python。
Java.perform(function () {
    var _seen = {};
    var _count = 0;
    var _CAP = 4000;          // 与 Python _SINK_CAP 对齐
    var _MAXB = 65536;        // 明文/密文回传字节上限

    function b2hex(bytes) {
        if (bytes === null || bytes === undefined) return null;
        try {
            var out = '';
            for (var i = 0; i < bytes.length; i++) {
                var b = bytes[i] & 0xff;
                out += ('0' + b.toString(16)).slice(-2);
            }
            return out;
        } catch (e) { return null; }
    }
    function b2b64(bytes) {
        if (bytes === null || bytes === undefined) return null;
        try {
            var B64 = Java.use('android.util.Base64');
            return B64.encodeToString(bytes, 2 /* NO_WRAP */);
        } catch (e) { return null; }
    }
    function clip(bytes) {
        // 超大体（上传/下载）截断到 _MAXB，避免刷爆通道。
        if (bytes === null || bytes === undefined) return null;
        try {
            if (bytes.length > _MAXB) {
                var sub = Java.array('byte', Array.prototype.slice.call(bytes, 0, _MAXB));
                return sub;
            }
        } catch (e) {}
        return bytes;
    }
    function emit(p) {
        try {
            if (_count >= _CAP) return;
            if (p.event === 'init') {
                var k = (p.src || '') + '|' + (p.transformation || '') + '|' +
                        (p.key_hex || '') + '|' + (p.iv_hex || '');
                if (_seen[k]) return;
                _seen[k] = true;
            }
            _count += 1;
            p.type = 'apkscan-crypto';
            send(p);
        } catch (e) { /* 回传失败不得炸会话 */ }
    }

    // --- javax.crypto.Cipher：init 抓 key/iv，doFinal 抓明文/密文 ---------
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        var System = Java.use('java.lang.System');
        var _state = {};  // identityHashCode -> {opmode,transformation,key_hex,iv_hex}

        Cipher.init.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var args = arguments;
                try {
                    var opmode = (args.length > 0) ? args[0] : 0;
                    var transformation = '';
                    try { transformation = this.getAlgorithm(); } catch (e) {}
                    var key_hex = null, iv_hex = null;
                    for (var i = 1; i < args.length; i++) {
                        var a = args[i];
                        if (a === null || a === undefined) continue;
                        try { if (a.getEncoded) { var enc = a.getEncoded(); if (enc !== null) key_hex = b2hex(enc); } } catch (e) {}
                        try { if (a.getIV) { var iv = a.getIV(); if (iv !== null) iv_hex = b2hex(iv); } } catch (e) {}
                    }
                    var id = System.identityHashCode(this);
                    _state[id] = {opmode: opmode, transformation: transformation, key_hex: key_hex, iv_hex: iv_hex};
                    emit({src: 'cipher', event: 'init', transformation: transformation,
                          opmode: opmode, key_hex: key_hex, iv_hex: iv_hex, ts: Date.now()});
                } catch (e) {}
                return ov.apply(this, args);
            };
        });

        Cipher.doFinal.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var args = arguments;
                var out = ov.apply(this, args);
                try {
                    var id = System.identityHashCode(this);
                    var st = _state[id] || {};
                    var inb = (args.length > 0 && args[0] !== null && args[0] !== undefined &&
                               args[0].length !== undefined) ? args[0] : null;
                    var outb = (out !== null && out !== undefined && out.length !== undefined) ? out : null;
                    var plaintext_b64 = null, ciphertext_hex = null;
                    if (st.opmode === 2 /* DECRYPT */) {
                        plaintext_b64 = b2b64(clip(outb));
                        ciphertext_hex = b2hex(clip(inb));
                    } else { /* ENCRYPT 或未知：入=明文 出=密文 */
                        plaintext_b64 = b2b64(clip(inb));
                        ciphertext_hex = b2hex(clip(outb));
                    }
                    emit({src: 'cipher', event: 'doFinal', transformation: st.transformation || '',
                          opmode: st.opmode || 0, key_hex: st.key_hex || null, iv_hex: st.iv_hex || null,
                          plaintext_b64: plaintext_b64, ciphertext_hex: ciphertext_hex, ts: Date.now()});
                    // doFinal 即终结：清掉本实例状态，避免对象被 GC 后 identityHashCode 复用导致
                    // 新对象错读旧 key（cipher 复用须先 re-init，会重填 _state）。
                    try { delete _state[id]; } catch (e2) {}
                } catch (e) {}
                return out;
            };
        });
        console.log('[apkscan] javax.crypto.Cipher hooked');
    } catch (e) {
        console.log('[apkscan] Cipher hook skip: ' + e);
    }

    // --- SecretKeySpec.$init：构造期抓原始 key bytes（覆盖 getEncoded 被混淆/返回 null）---
    try {
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (keyBytes, algo) {
            try {
                emit({src: 'secretkeyspec', event: 'init', transformation: '' + algo,
                      key_hex: b2hex(keyBytes), ts: Date.now()});
            } catch (e) {}
            return this.$init(keyBytes, algo);
        };
        // 带 offset/length 的构造（部分库用此形式，否则漏 key）。
        SecretKeySpec.$init.overload('[B', 'int', 'int', 'java.lang.String').implementation =
            function (keyBytes, off, len, algo) {
                try {
                    var sub = null;
                    try { sub = Java.array('byte', Array.prototype.slice.call(keyBytes, off, off + len)); } catch (e3) { sub = keyBytes; }
                    emit({src: 'secretkeyspec', event: 'init', transformation: '' + algo,
                          key_hex: b2hex(sub), ts: Date.now()});
                } catch (e) {}
                return this.$init(keyBytes, off, len, algo);
            };
        console.log('[apkscan] SecretKeySpec hooked');
    } catch (e) {
        console.log('[apkscan] SecretKeySpec hook skip: ' + e);
    }

    // --- IvParameterSpec.$init：抓 iv bytes -------------------------------
    try {
        var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
        IvParameterSpec.$init.overload('[B').implementation = function (ivBytes) {
            try {
                emit({src: 'ivspec', event: 'init', iv_hex: b2hex(ivBytes), ts: Date.now()});
            } catch (e) {}
            return this.$init(ivBytes);
        };
        console.log('[apkscan] IvParameterSpec hooked');
    } catch (e) {
        console.log('[apkscan] IvParameterSpec hook skip: ' + e);
    }

    // --- javax.crypto.Mac：HMAC 签名 key（反诈常用签名）------------------
    try {
        var Mac = Java.use('javax.crypto.Mac');
        function _emitMacKey(self, key) {
            try {
                var transformation = '';
                try { transformation = self.getAlgorithm(); } catch (e) {}
                var key_hex = null;
                try { if (key.getEncoded) { var enc = key.getEncoded(); if (enc !== null) key_hex = b2hex(enc); } } catch (e) {}
                emit({src: 'mac', event: 'init', transformation: transformation, key_hex: key_hex, ts: Date.now()});
            } catch (e) {}
        }
        Mac.init.overload('java.security.Key').implementation = function (key) {
            _emitMacKey(this, key);
            return this.init(key);
        };
        Mac.init.overload('java.security.Key', 'java.security.spec.AlgorithmParameterSpec')
            .implementation = function (key, spec) {
                _emitMacKey(this, key);
                return this.init(key, spec);
            };
        console.log('[apkscan] Mac hooked');
    } catch (e) {
        console.log('[apkscan] Mac hook skip: ' + e);
    }

    // --- WebView 内 CryptoJS（uni-app/H5 壳，纯 JS 加密不落 Cipher）-------
    // best-effort 注入包装：onPageFinished 时 evaluateJavascript 包裹 CryptoJS.AES.encrypt，
    // 把 key/iv/明文/密文经 console 回传（抓不到只 console.log，不阻断）。Java Cipher hook
    // 为主路径，本段为补充（多数 uni-app 最终仍走 native Cipher）。
    try {
        var WebView = Java.use('android.webkit.WebView');
        var injectJs =
            "(function(){try{" +
            "if(window.__apkscanCJ||!window.CryptoJS||!CryptoJS.AES)return;" +
            "window.__apkscanCJ=1;var _e=CryptoJS.AES.encrypt;" +
            "CryptoJS.AES.encrypt=function(m,k,c){var r=_e.apply(this,arguments);try{" +
            "console.log('[apkscan-cryptojs] '+JSON.stringify({" +
            "key:(k&&k.toString)?k.toString():''," +
            "iv:(c&&c.iv&&c.iv.toString)?c.iv.toString():''," +
            "pt:(m&&m.toString)?m.toString():''}));}catch(e){}return r;};" +
            "}catch(e){}})();";
        WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
            try { this.evaluateJavascript(injectJs, null); } catch (e) {}
            return this.loadUrl(url);
        };
        console.log('[apkscan] WebView CryptoJS wrapper armed');
    } catch (e) {
        console.log('[apkscan] WebView CryptoJS hook skip: ' + e);
    }
});
"""


# ---------------------------------------------------------------------------
# P1：运行时 JS-bridge 追踪 —— hook WebView.addJavascriptInterface 列暴露接口 + 调用
# ---------------------------------------------------------------------------
FRIDA_JSBRIDGE_HOOK_JS: str = r"""
// apkscan 运行时 JS-bridge 追踪（best-effort）：列出 H5 可调用的原生桥接面与实际调用。
Java.perform(function () {
    var _jb_count = 0;
    function jbEmit(p) {
        try {
            if (_jb_count >= 2000) return;
            _jb_count += 1;
            p.type = 'apkscan-jsbridge';
            send(p);
        } catch (e) {}
    }
    function brief(v) {
        try {
            if (v === null || v === undefined) return null;
            var s = '' + v;
            return s.length > 256 ? s.slice(0, 256) : s;
        } catch (e) { return null; }
    }
    try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.addJavascriptInterface.overload('java.lang.Object', 'java.lang.String')
            .implementation = function (obj, name) {
                try {
                    var cls = '';
                    try { cls = obj.getClass().getName(); } catch (e) {}
                    // 列出该桥对象上 @JavascriptInterface 可被 H5 调用的方法名（暴露面）。
                    var methodNames = [];
                    try {
                        var methods = obj.getClass().getDeclaredMethods();
                        for (var i = 0; i < methods.length && i < 64; i++) {
                            methodNames.push('' + methods[i].getName());
                        }
                    } catch (e) {}
                    jbEmit({event: 'register', iface: '' + name, object_class: cls,
                            methods: methodNames.join(','), ts: Date.now()});
                } catch (e) {}
                return this.addJavascriptInterface(obj, name);
            };
        console.log('[apkscan] WebView.addJavascriptInterface hooked');
    } catch (e) {
        console.log('[apkscan] addJavascriptInterface hook skip: ' + e);
    }
    // DSBridge：统一桥接调用入口 callSync/call（覆盖常见框架的方法分发）。
    try {
        var DSB = Java.use('wendu.dsbridge.DWebView');
        if (DSB.callHandler) {
            DSB.callHandler.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    try { jbEmit({event: 'call', iface: 'dsbridge', method: brief(arguments[0]), ts: Date.now()}); } catch (e) {}
                    return ov.apply(this, arguments);
                };
            });
        }
        console.log('[apkscan] DSBridge hooked');
    } catch (e) {
        console.log('[apkscan] DSBridge hook skip: ' + e);
    }
});
"""


# ---------------------------------------------------------------------------
# P1：运行时敏感 API 追踪 —— hook TelephonyManager/SmsManager/… 实际调用
# ---------------------------------------------------------------------------
FRIDA_SENSITIVE_API_HOOK_JS: str = r"""
// apkscan 运行时敏感 API 追踪（best-effort）：记录设备标识/短信/通讯录/剪贴板等实际调用。
Java.perform(function () {
    var _api_count = 0;
    function apiEmit(api, ret) {
        try {
            if (_api_count >= 2000) return;
            _api_count += 1;
            var rs = null;
            try { if (ret !== null && ret !== undefined) { rs = ('' + ret).slice(0, 128); } } catch (e) {}
            send({type: 'apkscan-api', event: 'call', api: api, result_summary: rs, ts: Date.now()});
        } catch (e) {}
    }
    function hook(cls, method, label) {
        try {
            var C = Java.use(cls);
            if (!C[method]) return;
            C[method].overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var ret = ov.apply(this, arguments);
                    apiEmit(label, ret);
                    return ret;
                };
            });
            console.log('[apkscan] hooked ' + label);
        } catch (e) {
            console.log('[apkscan] hook skip ' + label + ': ' + e);
        }
    }
    var TM = 'android.telephony.TelephonyManager';
    hook(TM, 'getDeviceId', 'TelephonyManager.getDeviceId');
    hook(TM, 'getImei', 'TelephonyManager.getImei');
    hook(TM, 'getSubscriberId', 'TelephonyManager.getSubscriberId');
    hook(TM, 'getSimSerialNumber', 'TelephonyManager.getSimSerialNumber');
    hook(TM, 'getLine1Number', 'TelephonyManager.getLine1Number');
    hook(TM, 'getSimOperator', 'TelephonyManager.getSimOperator');
    hook(TM, 'getSimOperatorName', 'TelephonyManager.getSimOperatorName');
    hook('android.telephony.SmsManager', 'sendTextMessage', 'SmsManager.sendTextMessage');
    hook('android.content.ContentResolver', 'query', 'ContentResolver.query');
    hook('android.content.ClipboardManager', 'getPrimaryClip', 'ClipboardManager.getPrimaryClip');
    hook('android.location.LocationManager', 'getLastKnownLocation', 'LocationManager.getLastKnownLocation');
});
"""


# ---------------------------------------------------------------------------
# P3：反检测绕过 —— 绕过 root/模拟器/frida 检测让样本能跑，并把检测尝试作为反分析行为上报
# ---------------------------------------------------------------------------
#
# 双重价值：① 绕过让检测 MuMu/root/frida 的涉诈样本仍能动态分析（否则秒退、抓不到任何东西）；
# ② 检测尝试本身就是「反取证/反分析」行为（正经 app 极少探测 su/qemu/frida），作为涉诈/木马
# 的研判信号上报（kind=root|emulator|frida，probe=被探测的具体特征）。每个 hook best-effort
# 独立 try/catch，单点失败不影响其它，绝不因绕过逻辑炸 app（绕过失败顶多样本照常秒退）。
FRIDA_ANTIDETECT_JS: str = r"""
// apkscan 反检测绕过（best-effort）：绕过 root/模拟器/frida 检测 + 上报反分析探测行为。
Java.perform(function () {
    var _ad_count = 0;
    function adEmit(kind, probe) {
        try {
            if (_ad_count >= 1000) return;
            _ad_count += 1;
            send({type: 'apkscan-antidetect', kind: kind, probe: ('' + probe).slice(0, 200),
                  bypassed: true, ts: Date.now()});
        } catch (e) {}
    }
    function classify(path) {
        var p = ('' + path).toLowerCase();
        if (p.indexOf('su') >= 0 || p.indexOf('magisk') >= 0 || p.indexOf('superuser') >= 0 ||
            p.indexOf('busybox') >= 0 || p.indexOf('xposed') >= 0) return 'root';
        if (p.indexOf('qemu') >= 0 || p.indexOf('goldfish') >= 0 || p.indexOf('ranchu') >= 0 ||
            p.indexOf('genymotion') >= 0 || p.indexOf('vbox') >= 0 || p.indexOf('/dev/socket/qemud') >= 0 ||
            p.indexOf('android0') >= 0 || p.indexOf('ttvm') >= 0 || p.indexOf('nox') >= 0) return 'emulator';
        if (p.indexOf('frida') >= 0 || p.indexOf('gum-js') >= 0 || p.indexOf('27042') >= 0 ||
            p.indexOf('linjector') >= 0) return 'frida';
        return '';
    }

    // --- File.exists：对 su/root/模拟器/frida 特征路径返回 false（并上报探测）---
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            try {
                var path = this.getAbsolutePath();
                var kind = classify(path);
                if (kind) { adEmit(kind, 'File.exists: ' + path); return false; }
            } catch (e) {}
            return this.exists();
        };
        console.log('[apkscan] File.exists anti-detect hooked');
    } catch (e) {
        console.log('[apkscan] File.exists hook skip: ' + e);
    }

    // --- Runtime.exec：拦 su / which su / mount 等 root 探测命令 ---
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            try {
                var c = ('' + cmd).toLowerCase();
                if (c.indexOf('su') >= 0 || c.indexOf('which') >= 0 || c.indexOf('busybox') >= 0 ||
                    c.indexOf('magisk') >= 0) {
                    adEmit('root', 'Runtime.exec: ' + cmd);
                    return this.exec('echo');  // 无害化：返回空输出
                }
            } catch (e) {}
            return this.exec(cmd);
        };
        console.log('[apkscan] Runtime.exec anti-detect hooked');
    } catch (e) {
        console.log('[apkscan] Runtime.exec hook skip: ' + e);
    }

    // --- Build 静态字段：把模拟器特征值改成真实机型（goldfish/generic/unknown → 三星）---
    try {
        var Build = Java.use('android.os.Build');
        function looksEmu(v) {
            var s = ('' + v).toLowerCase();
            return s.indexOf('generic') >= 0 || s.indexOf('goldfish') >= 0 || s.indexOf('ranchu') >= 0 ||
                   s.indexOf('emulator') >= 0 || s.indexOf('sdk') >= 0 || s.indexOf('vbox') >= 0 ||
                   s === 'unknown' || s.indexOf('mumu') >= 0 || s.indexOf('android-build') >= 0;
        }
        var spoof = {
            FINGERPRINT: 'samsung/dreamqltesq/dreamqltesq:9/PPR1.180610.011/G950USQU9DTI2:user/release-keys',
            MODEL: 'SM-G950U', MANUFACTURER: 'samsung', BRAND: 'samsung',
            PRODUCT: 'dreamqltesq', DEVICE: 'dreamqltesq', HARDWARE: 'qcom',
            BOARD: 'msm8998', HOST: 'SWHD5807', TAGS: 'release-keys'
        };
        var changed = [];
        for (var f in spoof) {
            try {
                if (Build[f] && looksEmu(Build[f].value)) {
                    Build[f].value = spoof[f];
                    changed.push(f);
                }
            } catch (e) {}
        }
        // TAGS 含 test-keys 一律改（root 镜像特征）。
        try {
            if (Build.TAGS && ('' + Build.TAGS.value).indexOf('test-keys') >= 0) {
                Build.TAGS.value = 'release-keys';
                if (changed.indexOf('TAGS') < 0) changed.push('TAGS');
            }
        } catch (e) {}
        if (changed.length) adEmit('emulator', 'Build fields spoofed: ' + changed.join(','));
        console.log('[apkscan] Build fields spoofed: ' + changed.join(','));
    } catch (e) {
        console.log('[apkscan] Build spoof skip: ' + e);
    }

    // --- SystemProperties.get：屏蔽 qemu/goldfish 等模拟器属性 ---
    try {
        var SP = Java.use('android.os.SystemProperties');
        SP.get.overload('java.lang.String').implementation = function (key) {
            var real = this.get(key);
            try {
                var k = ('' + key).toLowerCase();
                if (k.indexOf('qemu') >= 0 || k.indexOf('goldfish') >= 0 || k === 'ro.hardware' ||
                    k.indexOf('ro.kernel.qemu') >= 0 || k.indexOf('init.svc.qemud') >= 0) {
                    if (classify(real) === 'emulator' || k.indexOf('qemu') >= 0) {
                        adEmit('emulator', 'SystemProperties.get: ' + key + '=' + real);
                        return k === 'ro.hardware' ? 'qcom' : '';
                    }
                }
            } catch (e) {}
            return real;
        };
        console.log('[apkscan] SystemProperties.get anti-detect hooked');
    } catch (e) {
        console.log('[apkscan] SystemProperties hook skip: ' + e);
    }

    // --- PackageManager.getPackageInfo：对已知 root/管理类包抛 NameNotFound（隐藏）---
    try {
        var PM = Java.use('android.app.ApplicationPackageManager');
        var rootPkgs = ['com.topjohnwu.magisk', 'eu.chainfire.supersu', 'com.koushikdutta.superuser',
                        'com.noshufou.android.su', 'de.robv.android.xposed.installer', 'com.saurik.substrate'];
        PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
            try {
                if (rootPkgs.indexOf('' + pkg) >= 0) {
                    adEmit('root', 'PackageManager.getPackageInfo: ' + pkg);
                    var NameNotFound = Java.use('android.content.pm.PackageManager$NameNotFoundException');
                    throw NameNotFound.$new('' + pkg);
                }
            } catch (e) {
                if (('' + e).indexOf('NameNotFound') >= 0) throw e;
            }
            return this.getPackageInfo(pkg, flags);
        };
        console.log('[apkscan] PackageManager root-pkg hide hooked');
    } catch (e) {
        console.log('[apkscan] PackageManager hook skip: ' + e);
    }
});
"""


# ---------------------------------------------------------------------------
# 第二波：OkHttp interceptor-before 明文 dump —— 拿加密前明文 + 真实业务后端 host
# ---------------------------------------------------------------------------
#
# 价值（补抓包/cryptohook 之不足）：抓包拿到的是 app 自己的签名/加密 interceptor **之后**
# 的密文请求；本 hook 在 OkHttp 调用链最外层（RealCall.execute/enqueue、RealInterceptorChain
# .proceed 的首个 request）dump **加密前的明文** request —— 真实业务后端 host、Authorization/
# Bearer/JWT token、登录账号/手机号，直接定位「向谁登录、带的什么凭据」。
#
# R8 混淆护栏：OkHttp 类名随版本（3.x/4.x okhttp3.* vs internal.http.*）与混淆而变，需多
# fallback 类名 + best-effort 跳过（hook 不到只 console.log、绝不崩）。每个 hook 独立 try/catch。
# 高敏值（token/手机号）在 JS 侧先截断回传（Python 侧 normalize 再脱敏兜底），不留全文。
FRIDA_OKHTTP_HOOK_JS: str = r"""
// apkscan 运行时凭据采集（best-effort）：OkHttp 加密前明文 request dump（真实 host + token）。
Java.perform(function () {
    var _cred_count = 0;
    var _CRED_CAP = 1500;
    function credEmit(p) {
        try {
            if (_cred_count >= _CRED_CAP) return;
            _cred_count += 1;
            p.type = 'apkscan-credential';
            p.source = 'okhttp';
            send(p);
        } catch (e) { /* 回传失败不得炸会话 */ }
    }
    function clipStr(s, n) {
        try {
            if (s === null || s === undefined) return null;
            var t = '' + s;
            return t.length > n ? t.slice(0, n) : t;
        } catch (e) { return null; }
    }
    // 从 okhttp3.Request 提取 url/method/headers/body 明文（best-effort，逐项 try/catch）。
    function dumpRequest(req, where) {
        try {
            if (req === null || req === undefined) return;
            var url = null, method = null, headersObj = {}, bodyText = null;
            try { url = '' + req.url().toString(); } catch (e) {}
            try { method = '' + req.method(); } catch (e) {}
            // headers：抓 Authorization/Cookie/token 类敏感头（全量回传上限保护）。
            try {
                var hs = req.headers();
                var n = hs.size();
                for (var i = 0; i < n && i < 40; i++) {
                    var hn = '' + hs.name(i);
                    var hv = '' + hs.value(i);
                    headersObj[hn] = clipStr(hv, 512);
                }
            } catch (e) {}
            // body：把 RequestBody 写进 Buffer 取明文（仅文本类，超大跳过）。
            try {
                var body = req.body();
                if (body !== null && body !== undefined) {
                    var Buffer = Java.use('okio.Buffer');
                    var buf = Buffer.$new();
                    body.writeTo(buf);
                    var len = -1;
                    try { len = buf.size(); } catch (e) {}
                    if (len < 0 || len <= 262144) {
                        bodyText = clipStr('' + buf.readUtf8(), 8192);
                    }
                }
            } catch (e) {}
            credEmit({url: url, method: method, headers: headersObj, body: bodyText,
                      where: where, ts: Date.now()});
        } catch (e) {}
    }

    // --- 主路径：okhttp3.RealCall.execute()/getResponseWithInterceptorChain 前的原始 request ---
    // RealCall 持有最外层（未经 app interceptor 加密）的 originalRequest。
    var realCallNames = ['okhttp3.RealCall', 'okhttp3.internal.connection.RealCall'];
    var hookedRealCall = false;
    realCallNames.forEach(function (cn) {
        if (hookedRealCall) return;
        try {
            var RealCall = Java.use(cn);
            if (RealCall.execute) {
                RealCall.execute.implementation = function () {
                    try {
                        var req = null;
                        try { req = this.request(); } catch (e) {}
                        if (req === null) { try { req = this.originalRequest.value; } catch (e2) {} }
                        dumpRequest(req, cn + '.execute');
                    } catch (e) {}
                    return this.execute();
                };
                hookedRealCall = true;
                console.log('[apkscan] OkHttp ' + cn + '.execute hooked');
            }
        } catch (e) {
            console.log('[apkscan] OkHttp ' + cn + ' hook skip: ' + e);
        }
    });

    // --- 备路径：RealInterceptorChain.proceed(request) 的首个 request（app interceptor 之前）---
    // 仅在最外层（index 小）dump，避免每个 interceptor 都回传一遍同一请求。
    var chainNames = ['okhttp3.internal.http.RealInterceptorChain',
                      'okhttp3.internal.connection.RealInterceptorChain'];
    chainNames.forEach(function (cn) {
        try {
            var Chain = Java.use(cn);
            if (Chain.proceed && Chain.proceed.overload) {
                try {
                    Chain.proceed.overload('okhttp3.Request').implementation = function (request) {
                        try {
                            var idx = -1;
                            try { idx = this.index.value; } catch (e) {}
                            // 只在调用链最外层（index<=0）dump 一次原始 request。
                            if (idx <= 0) dumpRequest(request, cn + '.proceed');
                        } catch (e) {}
                        return this.proceed(request);
                    };
                    console.log('[apkscan] OkHttp ' + cn + '.proceed hooked');
                } catch (e) {
                    console.log('[apkscan] OkHttp ' + cn + '.proceed overload skip: ' + e);
                }
            }
        } catch (e) {
            console.log('[apkscan] OkHttp ' + cn + ' chain hook skip: ' + e);
        }
    });
});
"""


# ---------------------------------------------------------------------------
# 第二波：SQLCipher/SQLite 落地库导出 —— hook openDatabase 抓库路径+key，导明文库回传
# ---------------------------------------------------------------------------
#
# 物证价值（全工程最高之一）：诈骗 app 本地落地库（SQLCipher 加密）藏 IM 聊天/话术剧本、
# 通讯录、account/会员表、订单/入金缓存——导成明文 = 受害人名单 + 话术 + 上下线对接人。
#
# 机制：hook net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase（SQLCipher 加密库）
# 与 android.database.sqlite.SQLiteDatabase.openDatabase（普通 SQLite），抓**库路径 + password/
# raw key**；对 SQLCipher 库随即用 rawExecSQL 注入
#   ATTACH DATABASE '<tmp>/<name>.plain.db' AS plain KEY ''; SELECT sqlcipher_export('plain'); DETACH plain;
# 把明文库导到设备临时目录，send() 回传 {plain_path, db_path, key}。
#
# v3/v4 KDF 适配（核验坑）：SQLCipher v3/v4 默认 KDF 迭代数不同，导出前先按 v4 默认尝试，
# 失败则 `PRAGMA cipher_compatibility = 3` 再试。导出失败必降级（event=key_only，仅回传
# key + 原库路径，由 merge 写人工解密 playbook 进 Lead.notes），**不崩、不假成功**。
#
# 时序依赖（核验坑）：sqlcipher_export 需库**已被 app 打开**——hook 在 openDatabase 回调里
# 即时导出（库此刻已开），但 launch-only 抓不全未触发打开的库。merge/文档侧诚实标注。
#
# R8 混淆护栏：SQLCipher 类名随版本/混淆而变，多 fallback 类名 + 每步 try/catch，hook 不到
# 只 console.log、绝不崩。
FRIDA_SQLCIPHER_HOOK_JS: str = r"""
// apkscan 运行时落地库导出（best-effort）：hook SQLCipher/SQLite openDatabase，导明文库回传。
Java.perform(function () {
    var _db_count = 0;
    var _DB_CAP = 200;
    var _seen_db = {};        // 同一库路径只导一次（避免反复 export 刷爆 + 重复磁盘 IO）
    var _TMP_DIR = '/data/local/tmp/apkscan_db';

    function dbEmit(p) {
        try {
            if (_db_count >= _DB_CAP) return;
            _db_count += 1;
            p.type = 'apkscan-sqlcipher';
            send(p);
        } catch (e) { /* 回传失败不得炸会话 */ }
    }
    function clipStr(s, n) {
        try {
            if (s === null || s === undefined) return null;
            var t = '' + s;
            return t.length > n ? t.slice(0, n) : t;
        } catch (e) { return null; }
    }
    function baseName(p) {
        try {
            var s = '' + p;
            var i = s.lastIndexOf('/');
            return i >= 0 ? s.slice(i + 1) : s;
        } catch (e) { return 'db'; }
    }
    // 确保设备临时导出目录存在（best-effort，失败照常尝试导出，导不出再降级）。
    function ensureTmpDir() {
        try {
            var JFile = Java.use('java.io.File');
            var d = JFile.$new(_TMP_DIR);
            if (!d.exists()) { try { d.mkdirs(); } catch (e2) {} }
        } catch (e) {}
    }
    // 对一个已打开的 SQLCipher db 句柄注入 ATTACH+sqlcipher_export，导明文库。
    // 返回明文库设备路径（成功）或 null（失败 → 调用方降级 key_only）。
    function exportPlain(db, dbPath, key) {
        if (db === null || db === undefined) return null;
        if (!db.rawExecSQL) return null;        // 非 SQLCipher 句柄（普通 SQLite）→ 不导，交收尾 adb pull
        ensureTmpDir();
        var plainPath = _TMP_DIR + '/' + baseName(dbPath) + '.plain.db';
        // 先按 SQLCipher v4 默认尝试；失败再降到 v3 KDF 兼容模式重试。
        var compat = [4, 3];
        for (var ci = 0; ci < compat.length; ci++) {
            try {
                try { db.rawExecSQL('PRAGMA cipher_compatibility = ' + compat[ci] + ';'); } catch (eC) {}
                // 目标明文库 KEY '' = 不加密（明文）。
                db.rawExecSQL("ATTACH DATABASE '" + plainPath + "' AS plain KEY '';");
                db.rawExecSQL("SELECT sqlcipher_export('plain');");
                db.rawExecSQL("DETACH DATABASE plain;");
                return plainPath;   // 任一兼容档导出成功即返回
            } catch (eExp) {
                // 本档失败：清掉可能半导出的目标，换下一档重试。
                try { db.rawExecSQL("DETACH DATABASE plain;"); } catch (eD) {}
            }
        }
        return null;   // v4/v3 都失败 → 降级
    }

    function handleOpen(db, dbPath, key, where) {
        try {
            var path = '' + dbPath;
            if (_seen_db[path]) return;
            _seen_db[path] = true;
            var plainPath = null;
            try { plainPath = exportPlain(db, path, key); } catch (eX) { plainPath = null; }
            if (plainPath) {
                dbEmit({event: 'exported', db_path: path, plain_path: plainPath,
                        key: clipStr(key, 128), where: where, ts: Date.now()});
            } else {
                // 导出失败 / 普通 SQLite（无 rawExecSQL）：降级，仅回传 key + 原库路径。
                // merge 侧据此写人工解密 playbook；普通 SQLite 由收尾 adb pull databases 拉回。
                dbEmit({event: 'key_only', db_path: path, plain_path: null,
                        key: clipStr(key, 128), where: where, ts: Date.now()});
            }
        } catch (e) {}
    }

    // --- SQLCipher：net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase ---
    // 多 fallback 类名（不同 SQLCipher 版本/打包）。
    var cipherNames = ['net.sqlcipher.database.SQLiteDatabase',
                       'net.zetetic.database.sqlcipher.SQLiteDatabase'];
    cipherNames.forEach(function (cn) {
        try {
            var SDB = Java.use(cn);
            if (SDB.openOrCreateDatabase) {
                SDB.openOrCreateDatabase.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        var db = ov.apply(this, arguments);
                        try {
                            var args = arguments;
                            // 形参形态多样：(String path, ...) 或 (File file, ...)；key 多为第 2 参。
                            var dbPath = null, key = null;
                            try { dbPath = (args.length > 0) ? ('' + args[0]) : null; } catch (e1) {}
                            try {
                                if (args.length > 1 && args[1] !== null && args[1] !== undefined) {
                                    key = '' + args[1];   // password（String 或 char[]）
                                }
                            } catch (e2) {}
                            handleOpen(db, dbPath, key, cn + '.openOrCreateDatabase');
                        } catch (e) {}
                        return db;
                    };
                });
                console.log('[apkscan] SQLCipher ' + cn + '.openOrCreateDatabase hooked');
            }
        } catch (e) {
            console.log('[apkscan] SQLCipher ' + cn + ' hook skip: ' + e);
        }
    });

    // --- 普通 SQLite：android.database.sqlite.SQLiteDatabase.openDatabase（无 key）---
    // 普通库无 sqlcipher_export，handleOpen 走 key_only 降级；真正拉回交收尾 adb pull databases。
    try {
        var ADB = Java.use('android.database.sqlite.SQLiteDatabase');
        if (ADB.openDatabase) {
            ADB.openDatabase.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var db = ov.apply(this, arguments);
                    try {
                        var dbPath = (arguments.length > 0) ? ('' + arguments[0]) : null;
                        if (dbPath && ('' + dbPath).indexOf('.db') >= 0) {
                            handleOpen(db, dbPath, null, 'android.SQLiteDatabase.openDatabase');
                        }
                    } catch (e) {}
                    return db;
                };
            });
            console.log('[apkscan] android SQLiteDatabase.openDatabase hooked');
        }
    } catch (e) {
        console.log('[apkscan] android SQLiteDatabase hook skip: ' + e);
    }
});
"""


# ---------------------------------------------------------------------------
# on_message handler：把 Frida send() 的 crypto 事件规范化进 sink
# ---------------------------------------------------------------------------


def make_message_handler(sink: list[dict[str, Any]]) -> Callable[[dict[str, Any], Any], None]:
    """构造 Frida ``script.on('message', handler)`` 回调，把 crypto 事件存进 ``sink``。

    handler 只认 ``message['type']=='send'`` 且 ``payload['type']==CRYPTO_MSG_TYPE`` 的消息；
    其它（非本通道 send / error）忽略。``message['type']=='error'`` 记 warning（JS 异常诊断）。

    **绝不抛**：on_message 在 Frida 回调线程触发，抛异常会炸整个会话。

    Args:
        sink: 共享列表（CPython ``list.append`` 原子，无需锁）；收尾时由 capture 读取落盘。

    Returns:
        ``handler(message, _data)``。第二参是 send 的 ArrayBuffer→bytes；本设计二进制都走
        payload 字符串，该参一般为 None，留参（``_data``）以符合 Frida 回调签名。
    """

    def handler(message: Any, _data: Any = None) -> None:
        try:
            if not isinstance(message, dict):
                return
            mtype = message.get("type")
            if mtype == "error":
                logger.warning(
                    "[cryptohook] Frida JS 异常：%s",
                    message.get("description") or message.get("stack") or message,
                )
                return
            if mtype != "send":
                return
            payload = message.get("payload")
            if not isinstance(payload, dict) or payload.get("type") != CRYPTO_MSG_TYPE:
                return
            event = normalize_crypto_event(payload)
            if event is None:
                return
            if len(sink) >= _SINK_CAP:
                if len(sink) == _SINK_CAP:
                    logger.warning("[cryptohook] crypto 事件达上限 %d，后续丢弃", _SINK_CAP)
                    sink.append({"_capped": True})  # 触发一次性 warning 后停
                return
            sink.append(event)
        except Exception:  # noqa: BLE001 — 回调绝不抛（否则炸 Frida 会话）
            logger.exception("[cryptohook] 处理 Frida 消息异常（已忽略该条）")

    return handler


def make_typed_handler(
    sink: list[dict[str, Any]],
    msg_type: str,
    normalizer: Callable[[Any], dict[str, Any] | None],
) -> Callable[[dict[str, Any], Any], None]:
    """通用 on_message 工厂：只收 ``payload['type']==msg_type`` 的 send 消息进 ``sink``。

    与 ``make_message_handler`` 同范式（绝不抛、sink 封顶），但通道/规范化可参数化，供
    crypto/jsbridge/sensitive_api 三通道复用。本工厂**不记 error 日志**（避免多 handler
    重复刷；error 由 crypto 通道的 make_message_handler 统一记一次）。
    """

    def handler(message: Any, _data: Any = None) -> None:
        try:
            if not isinstance(message, dict) or message.get("type") != "send":
                return
            payload = message.get("payload")
            if not isinstance(payload, dict) or payload.get("type") != msg_type:
                return
            event = normalizer(payload)
            if event is None:
                return
            if len(sink) >= _SINK_CAP:
                if len(sink) == _SINK_CAP:
                    logger.warning("[cryptohook] %s 事件达上限 %d，后续丢弃", msg_type, _SINK_CAP)
                    sink.append({"_capped": True})
                return
            sink.append(event)
        except Exception:  # noqa: BLE001 — 回调绝不抛
            logger.exception("[cryptohook] 处理 %s 消息异常（已忽略该条）", msg_type)

    return handler


def normalize_crypto_event(payload: Any) -> dict[str, Any] | None:
    """把 JS 侧 crypto payload 规范化为稳定 schema 条目；非 dict/非法 → None。

    **crypto_event 权威 schema**（producer=Frida JS、本函数=normalizer、consumer=recipe_from_events
    /brand_hints/merge 三方共识的单一定义；落进 runtime_report.json['crypto_events']）：

    - ``src``: ``cipher|secretkeyspec|ivspec|mac|cryptojs`` —— 来源 hook。
    - ``event``: ``init|doFinal|encrypt|decrypt``。
    - ``transformation``: 如 ``AES/CFB/PKCS5Padding``（Java=完整串；CryptoJS=algo）。
    - ``opmode``: ``1=ENCRYPT 2=DECRYPT 0=未知`` —— **取证元数据**，JS 侧据此判定 doFinal
      的入/出哪个是明文（决定 plaintext_b64 的取向）；Python 侧目前不消费，留作研判线索。
    - ``key_hex`` / ``iv_hex``: 小写 hex 串或 None（非合法 hex 一律 None）。
    - ``plaintext_b64``: 明文 base64；``ciphertext_hex``: 密文 hex（均可能 None）。
    - ``ts``: JS Date.now()（int 或 None），仅排序/去重，不参与 iv 派生。

    所有字符串字段截断到 ``_MAX_FIELD_CHARS``；类型不符的字段置 None。
    """
    if not isinstance(payload, dict):
        return None
    src = _as_clean_str(payload.get("src"))
    event = _as_clean_str(payload.get("event"))
    if not src or not event:
        return None
    return {
        "src": src,
        "event": event,
        "transformation": _as_clean_str(payload.get("transformation")) or "",
        "opmode": payload.get("opmode") if isinstance(payload.get("opmode"), int) else 0,
        "key_hex": _as_hex_str(payload.get("key_hex")),
        "iv_hex": _as_hex_str(payload.get("iv_hex")),
        "plaintext_b64": _as_clean_str(payload.get("plaintext_b64"), _MAX_FIELD_CHARS),
        "ciphertext_hex": _as_clean_str(payload.get("ciphertext_hex"), _MAX_FIELD_CHARS),
        "ts": payload.get("ts") if isinstance(payload.get("ts"), int) else None,
    }


def _as_clean_str(value: Any, limit: int = 4096) -> str | None:
    """把字段转成截断后的字符串；None/空/非 str→None（数字会被拒，保持字段语义纯净）。"""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    return text[:limit]


def _as_hex_str(value: Any) -> str | None:
    """把 key_hex/iv_hex 字段规整为小写 hex 串；非合法 hex→None。"""
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text:
        return None
    try:
        bytes.fromhex(text)
    except ValueError:
        return None
    return text


def normalize_jsbridge_event(payload: Any) -> dict[str, Any] | None:
    """规范化 JS-bridge 事件：register（暴露接口+方法）/ call（H5 实际调用）。"""
    if not isinstance(payload, dict):
        return None
    event = _as_clean_str(payload.get("event"))
    iface = _as_clean_str(payload.get("iface"))
    if not event or not iface:
        return None
    return {
        "event": event,  # register | call
        "iface": iface,
        "object_class": _as_clean_str(payload.get("object_class")) or "",
        "methods": _as_clean_str(payload.get("methods")) or "",
        "method": _as_clean_str(payload.get("method")) or "",
        "ts": payload.get("ts") if isinstance(payload.get("ts"), int) else None,
    }


def normalize_sensitive_api_event(payload: Any) -> dict[str, Any] | None:
    """规范化敏感 API 调用事件：api（<类>.<方法>）+ 结果摘要。"""
    if not isinstance(payload, dict):
        return None
    api = _as_clean_str(payload.get("api"))
    if not api:
        return None
    return {
        "event": _as_clean_str(payload.get("event")) or "call",
        "api": api,
        "result_summary": _as_clean_str(payload.get("result_summary")) or "",
        "ts": payload.get("ts") if isinstance(payload.get("ts"), int) else None,
    }


def normalize_antidetect_event(payload: Any) -> dict[str, Any] | None:
    """规范化反检测事件：kind（root|emulator|frida|debugger）+ probe（被探测的特征）。"""
    if not isinstance(payload, dict):
        return None
    kind = _as_clean_str(payload.get("kind"))
    probe = _as_clean_str(payload.get("probe"))
    if not kind or not probe:
        return None
    return {
        "kind": kind,
        "probe": probe,
        "bypassed": bool(payload.get("bypassed", False)),
        "ts": payload.get("ts") if isinstance(payload.get("ts"), int) else None,
    }


# ---------------------------------------------------------------------------
# 第二波：运行时凭据规范化 —— 高敏个人信息脱敏/截断 + token 形态闸
# ---------------------------------------------------------------------------
#
# 合规护栏（横切硬要求）：token / 账号 / 手机号是受害人/高敏个人信息，回传与落盘必须截断、
# 不留全文；手机号中间打码、token 只留前后几位。本模块的规范化与抽取统一执行这一脱敏口径。

#: 凭据来源（与 JS 侧约定）：okhttp=加密前明文请求；sharedprefs=落地凭据 xml。
_CREDENTIAL_SOURCES: frozenset[str] = frozenset({"okhttp", "sharedprefs"})

#: 高敏 header 名（命中即整值脱敏，只留前后片段）。
_SENSITIVE_HEADER_KEYS: frozenset[str] = frozenset(
    {"authorization", "cookie", "token", "access-token", "x-token", "x-auth-token", "x-access-token"}
)

#: SharedPrefs 里视为「登录态/凭据」的敏感键名子串（小写匹配；命中即抠出）。
_SHAREDPREFS_SENSITIVE_KEYS: tuple[str, ...] = (
    "token",
    "access_token",
    "accesstoken",
    "refresh_token",
    "session",
    "sessionid",
    "auth",
    "jwt",
    "ticket",
    "merchant",      # 商户号
    "merchant_no",
    "mch_id",
    "invite",        # 邀请码
    "invite_code",
    "invitecode",
    "mobile",        # 登录手机号
    "phone",
    "account",
    "username",
    "uid",
    "userid",
    "login_status",  # 登录态
    "is_login",
    "islogin",
    "logined",
)

#: SharedPrefs xml 中 <string name="...">value</string> 的提取正则。
_PREFS_STRING_RE = re.compile(
    r'<string\s+name="([^"]+)"\s*>(.*?)</string>', re.IGNORECASE | re.DOTALL
)
#: <int/long/boolean name="..." value="..." /> 形态（登录态多为 int/boolean）。
_PREFS_SCALAR_RE = re.compile(
    r'<(?:int|long|boolean)\s+name="([^"]+)"\s+value="([^"]*)"\s*/>', re.IGNORECASE
)

#: 手机号（中国大陆 11 位）打码用：保留前 3 后 4，中间 ****。
_PHONE_RE = re.compile(r"(?<!\d)(1\d{2})(\d{4})(\d{4})(?!\d)")

#: 高敏值回传/落盘的截断上限（远小于全文，确保不留全凭据）。
_CRED_VALUE_HEAD = 6
_CRED_VALUE_TAIL = 4
_CRED_VALUE_MAX = 24

# 形态闸规则惰性缓存（避免每条事件重读 rules/secrets.yaml）。
_SECRET_RULES_CACHE: Any = None


def _secret_rules() -> Any:
    """惰性加载 secrets 形态闸规则（与 js_bundle/jadx 同口径）；加载失败 → 兜底规则。"""
    global _SECRET_RULES_CACHE
    if _SECRET_RULES_CACHE is not None:
        return _SECRET_RULES_CACHE
    try:
        from apkscan.core.secrets import load_secret_rules

        _SECRET_RULES_CACHE = load_secret_rules()
    except Exception:  # noqa: BLE001 — 规则不可用不阻断，用兜底 SecretRules
        logger.exception("[credential] 加载 secrets 形态闸规则失败，用兜底")
        from apkscan.core.secrets import SecretRules

        _SECRET_RULES_CACHE = SecretRules()
    return _SECRET_RULES_CACHE


def _looks_like_credential(value: str) -> bool:
    """value 是否像真实凭据形态（复用 secrets 形态/熵闸，过滤占位/常量名）。绝不抛。"""
    try:
        from apkscan.core.secrets import looks_like_secret_value

        return looks_like_secret_value(value, _secret_rules())
    except Exception:  # noqa: BLE001 — 形态闸异常按"非凭据"保守处理（不泄明文）
        logger.exception("[credential] 形态闸判定异常，按非凭据处理")
        return False


def _mask_phone_numbers(text: str) -> str:
    """把文本里的手机号中间四位打码（前 3 后 4 保留）。绝不抛。"""
    try:
        return _PHONE_RE.sub(lambda m: f"{m.group(1)}****{m.group(3)}", text)
    except Exception:  # noqa: BLE001
        logger.exception("[credential] 手机号打码异常")
        return text


def _truncate_secret(value: str) -> str:
    """高敏凭据值截断：只留前 ``_CRED_VALUE_HEAD`` 后 ``_CRED_VALUE_TAIL`` 位，中间省略号。

    短值（<= head+tail）整体保留（本就不含全文风险）；长值截断不留全文。
    """
    v = value.strip()
    if len(v) <= _CRED_VALUE_HEAD + _CRED_VALUE_TAIL:
        return v[:_CRED_VALUE_MAX]
    return f"{v[:_CRED_VALUE_HEAD]}…{v[-_CRED_VALUE_TAIL:]}"


def _desensitize_header(name: str, value: str) -> str:
    """header 值脱敏：高敏头（Authorization/Cookie/token 类）整值截断；其余仅手机号打码。

    Authorization 形如 ``Bearer <token>``：保留方案前缀（Bearer/Basic）+ token 前后几位。
    """
    if not isinstance(value, str):
        return ""
    low = name.strip().lower()
    if low in _SENSITIVE_HEADER_KEYS:
        parts = value.split(" ", 1)
        if len(parts) == 2 and parts[0].lower() in ("bearer", "basic", "token", "jwt"):
            return f"{parts[0]} {_truncate_secret(parts[1])}"
        return _truncate_secret(value)
    return _mask_phone_numbers(value)[:512]


def normalize_credential_event(payload: Any) -> dict[str, Any] | None:
    """把 JS/SharedPrefs 侧 credential payload 规范化为稳定 schema；非法 → None（绝不抛）。

    **credential_event 权威 schema**（producer=Frida OkHttp JS / SharedPrefs 抽取，
    consumer=merge_runtime_credentials；落进 runtime_report.json['credential_events']）：

    - ``source``: ``okhttp`` | ``sharedprefs``（区分加密前明文请求 / 落地凭据）。
    - okhttp：``url`` / ``method`` / ``headers``（dict，高敏头脱敏）/ ``body``（手机号打码、截断）。
    - sharedprefs：``name``（键名）/ ``value``（经形态闸 + 截断）/ ``file``（来源 xml）。
    - ``ts``: JS Date.now()（int 或 None）。

    合规护栏：所有高敏值（token/手机号/账号）一律脱敏或截断，绝不回传/落盘全文。
    """
    if not isinstance(payload, dict):
        return None
    source = _as_clean_str(payload.get("source"))
    if source not in _CREDENTIAL_SOURCES:
        return None

    if source == "okhttp":
        return _normalize_okhttp_credential(payload)
    return _normalize_sharedprefs_credential(payload)


def _normalize_okhttp_credential(payload: dict[str, Any]) -> dict[str, Any] | None:
    """规范化 OkHttp 明文请求事件：url 必有；headers 高敏脱敏、body 手机号打码 + 截断。"""
    url = _as_clean_str(payload.get("url"))
    if not url:
        return None  # 无 url 的 okhttp 事件无取证价值

    headers_raw = payload.get("headers")
    headers: dict[str, str] = {}
    if isinstance(headers_raw, dict):
        for k, v in headers_raw.items():
            key = str(k)
            headers[key] = _desensitize_header(key, str(v) if v is not None else "")

    body_raw = _as_clean_str(payload.get("body"), 8192)
    body = _mask_phone_numbers(body_raw) if body_raw else ""

    return {
        "source": "okhttp",
        "url": url,
        "method": _as_clean_str(payload.get("method")) or "",
        "headers": headers,
        "body": body,
        "ts": payload.get("ts") if isinstance(payload.get("ts"), int) else None,
    }


def _normalize_sharedprefs_credential(payload: dict[str, Any]) -> dict[str, Any] | None:
    """规范化 SharedPrefs 落地凭据：name 必有；value 经形态闸（占位→占位标记）+ 截断/打码。"""
    name = _as_clean_str(payload.get("name"))
    if not name:
        return None
    raw_value = payload.get("value")
    value = _gate_and_mask_value(name, str(raw_value) if raw_value is not None else "")
    return {
        "source": "sharedprefs",
        "name": name,
        "value": value,
        "file": _as_clean_str(payload.get("file")) or "",
        "ts": payload.get("ts") if isinstance(payload.get("ts"), int) else None,
    }


def _gate_and_mask_value(name: str, value: str) -> str:
    """对 SharedPrefs 值施加形态闸 + 脱敏：

    - 登录态布尔/小整数（如 login_status=1）：直接保留（非个人信息、是状态量）。
    - 手机号/账号形态：打码后截断。
    - token 类长值：先过形态闸——像真凭据 → 截断保留前后位；不像（占位/常量名）→ 占位标记
      （``<非凭据形态>``，不回传非凭据明文，也避免把 deviceToken 之类当真 token）。
    """
    v = value.strip()
    if not v:
        return ""
    # 状态量（登录态）：短布尔/数字直接留（是状态、非高敏个人信息）。
    low_name = name.lower()
    if any(tok in low_name for tok in ("login", "status", "is_login", "logined")):
        if v.lower() in ("0", "1", "true", "false", "yes", "no") or (v.isdigit() and len(v) <= 4):
            return v
    # 手机号/账号：打码后截断。
    masked = _mask_phone_numbers(v)
    if masked != v:
        return masked[:_CRED_VALUE_MAX]
    # token/secret 类：形态闸过占位。
    if _looks_like_credential(v):
        return _truncate_secret(v)
    # 不像凭据（占位/SDK 常量名 deviceToken 等）→ 占位标记，不回传非凭据明文。
    return "<非凭据形态>"


def extract_sharedprefs_credentials(xml_text: str, file_name: str) -> list[dict[str, Any]]:
    """从单个 shared_prefs xml 文本抠出敏感键（token/商户号/邀请码/手机号/登录态）。绝不抛。

    返回 ``[{"source":"sharedprefs","name":..,"value":..(脱敏/截断),"file":file_name}]``。
    供 capture 收尾对 adb pull 回的每个 xml 调用、产 credential_events；merge 侧据此产 Lead。
    """
    creds: list[dict[str, Any]] = []
    if not isinstance(xml_text, str) or not xml_text.strip():
        return creds
    seen: set[str] = set()
    try:
        pairs: list[tuple[str, str]] = []
        pairs.extend(_PREFS_STRING_RE.findall(xml_text))
        pairs.extend(_PREFS_SCALAR_RE.findall(xml_text))
        for name, value in pairs:
            name = name.strip()
            low = name.lower()
            if not any(tok in low for tok in _SHAREDPREFS_SENSITIVE_KEYS):
                continue
            if name in seen:
                continue
            seen.add(name)
            ev = _normalize_sharedprefs_credential(
                {"source": "sharedprefs", "name": name, "value": value, "file": file_name}
            )
            if ev is not None:
                creds.append(ev)
    except Exception:  # noqa: BLE001 — 单个 xml 解析失败不影响其它，绝不抛
        logger.exception("[credential] 解析 shared_prefs xml 失败（已忽略）：%s", file_name)
    return creds


# ---------------------------------------------------------------------------
# 第二波：SQLCipher/SQLite 落地库导出事件规范化（key 截断 + 路径校形）
# ---------------------------------------------------------------------------
#
# 合规护栏：db key 是高敏（凭它可解全库受害人物证），回传/落盘截断不留全文（与 token 同口径）。

#: 落地库事件类型（与 JS 侧约定）：exported=已导出明文库；key_only=导出失败降级仅 key+路径。
_SQLCIPHER_EVENTS: frozenset[str] = frozenset({"exported", "key_only"})


def normalize_sqlcipher_event(payload: Any) -> dict[str, Any] | None:
    """把 JS 侧 SQLCipher/SQLite 落地库事件规范化为稳定 schema；非法 → None（绝不抛）。

    **sqlcipher_event 权威 schema**（producer=Frida FRIDA_SQLCIPHER_HOOK_JS，
    consumer=merge_runtime_databases；落进 runtime_report.json['sqlcipher_events']）：

    - ``event``: ``exported``（已导出明文 .plain.db）| ``key_only``（导出失败降级，仅 key+路径）。
    - ``db_path``: 设备上原加密库路径（必有，否则无取证价值 → None）。
    - ``plain_path``: 导出的明文库设备路径（exported 才有；key_only 为空）。
    - ``key``: 库密钥（**高敏**，截断不留全文，凭它可人工解密原库）。
    - ``where``: 来源 hook 标记。
    - ``ts``: JS Date.now()（int 或 None）。

    合规护栏：key 截断/脱敏，绝不回传/落盘全文。
    """
    if not isinstance(payload, dict):
        return None
    db_path = _as_clean_str(payload.get("db_path"), 1024)
    if not db_path:
        return None  # 无原库路径的事件无取证价值

    event = _as_clean_str(payload.get("event"))
    if event not in _SQLCIPHER_EVENTS:
        event = "exported" if _as_clean_str(payload.get("plain_path")) else "key_only"

    plain_path = _as_clean_str(payload.get("plain_path"), 1024)
    raw_key = payload.get("key")
    key = _truncate_secret(str(raw_key)) if isinstance(raw_key, str) and raw_key.strip() else ""

    return {
        "event": event,
        "db_path": db_path,
        "plain_path": plain_path or "",
        "key": key,
        "where": _as_clean_str(payload.get("where")) or "",
        "ts": payload.get("ts") if isinstance(payload.get("ts"), int) else None,
    }


# ---------------------------------------------------------------------------
# 从活体事件反推 crypto_recipe meta（喂回 appcrypto.CryptoRecipe.from_meta）
# ---------------------------------------------------------------------------


def recipe_from_events(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    """从运行时 crypto 事件反推「实测配方」meta dict（供 merge 用作解密首选）。

    核心价值：拿到**权威 key**（静态可能逆错/逆不到）。返回 dict 只含**有把握**的字段，
    由 merge 浅合并到静态配方上（实测覆盖、缺省回退静态），避免无依据地改写静态推断。

    iv 处理（关键，见 risk）：
      - 实测 iv **恒定且可表示** → ``iv_derive='fixed'`` + ``iv_value``（仅此一招对所有信封成立）。
      - 实测 iv **变化**（如 md5(key+ts) 每请求不同）→ **不设 fixed**：仅反哺 key，iv 仍交
        静态推导（``md5(key+ts)[:16]``）；否则把单次 iv 当 fixed 会解错其它信封。

    Args:
        events: ``make_message_handler`` 收集的事件列表。

    Returns:
        实测配方 meta dict（键与 ``appcrypto.CryptoRecipe.from_meta`` 兼容）；无可用 key → None。
    """
    if not isinstance(events, list) or not events:
        return None

    key_hex = _dominant_key_hex(events)
    if not key_hex:
        logger.info("[cryptohook] 运行时事件无可用 key，跳过实测配方反推")
        return None

    recipe: dict[str, Any] = {}

    # key + key_encoding：key bytes 若是可见 ASCII（CryptoJS enc.Utf8.parse 口径）→ utf8 串；
    # 否则 hex。与 appcrypto._build_key 的两种解析口径对齐。
    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        return None
    if _bytes_printable_ascii(key_bytes):
        recipe["key"] = key_bytes.decode("ascii")
        recipe["key_encoding"] = "utf8"
    else:
        recipe["key"] = key_hex
        recipe["key_encoding"] = "hex"

    # algo/mode/padding：从 transformation 解析（取首个非空 cipher transformation）。
    transformation = _dominant_transformation(events)
    if transformation:
        algo, mode, padding = transformation_parts(transformation)
        if algo:
            recipe["algo"] = algo
        if mode:
            recipe["mode"] = mode
        if padding:
            recipe["padding"] = padding

    # iv：仅在恒定且可按 key_encoding 表示时设 fixed（否则交静态推导）。
    iv_value = _constant_iv_value(events, recipe["key_encoding"])
    if iv_value is not None:
        recipe["iv_derive"] = "fixed"
        recipe["iv_value"] = iv_value

    return recipe


def _dominant_key_hex(events: list[dict[str, Any]]) -> str:
    """取出现最多的 key_hex（优先 cipher/secretkeyspec 来源；Mac 的 HMAC key 仅兜底）。"""
    counts: dict[str, int] = {}
    mac_counts: dict[str, int] = {}
    for ev in events:
        if not isinstance(ev, dict):
            continue
        kh = ev.get("key_hex")
        if not isinstance(kh, str) or not kh:
            continue
        if ev.get("src") == "mac":
            mac_counts[kh] = mac_counts.get(kh, 0) + 1
        else:
            counts[kh] = counts.get(kh, 0) + 1
    pool = counts or mac_counts
    if not pool:
        return ""
    # 出现次数降序、长度降序（偏好更长 key，如 AES-256 32B），稳定。
    return sorted(pool.items(), key=lambda kv: (-kv[1], -len(kv[0])))[0][0]


def _dominant_transformation(events: list[dict[str, Any]]) -> str:
    """取 cipher 事件里出现最多的非空 transformation。"""
    counts: dict[str, int] = {}
    for ev in events:
        if not isinstance(ev, dict) or ev.get("src") != "cipher":
            continue
        t = ev.get("transformation")
        if isinstance(t, str) and t:
            counts[t] = counts.get(t, 0) + 1
    if not counts:
        return ""
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


def _constant_iv_value(events: list[dict[str, Any]], key_encoding: str) -> str | None:
    """实测 iv 恒定且可按 key_encoding 表示时返回 iv_value 串；变化/不可表示/无 → None。

    - key_encoding=='hex'：iv_value 直接用 hex 串（appcrypto fixed 分支按 hex 解析）。
    - key_encoding=='utf8'：仅当 iv bytes 是可见 ASCII 才用 ascii 串；否则不可表示 → None。
    """
    ivs: set[str] = set()
    for ev in events:
        if not isinstance(ev, dict):
            continue
        iv = ev.get("iv_hex")
        if isinstance(iv, str) and iv:
            ivs.add(iv)
    if len(ivs) != 1:
        return None  # 0=无 iv；>1=变化（如 md5(key+ts)），都不设 fixed
    iv_hex = next(iter(ivs))
    if key_encoding == "hex":
        return iv_hex
    # utf8：iv 须可见 ASCII 才能按 utf8 串表示（appcrypto fixed+utf8 走 .encode('utf-8')）。
    try:
        iv_bytes = bytes.fromhex(iv_hex)
    except ValueError:
        return None
    if _bytes_printable_ascii(iv_bytes):
        return iv_bytes.decode("ascii")
    return None


def transformation_parts(transformation: str) -> tuple[str, str, str]:
    """把 ``AES/CFB/PKCS5Padding`` 拆成 (algo, mode, padding)，规整成 appcrypto 口径。

    单段（如 ``AES``）→ 只有 algo，mode/padding 空（交静态/默认补）。未知值原样上抛大写。
    """
    if not transformation:
        return "", "", ""
    parts = [p.strip() for p in transformation.split("/")]
    algo = _norm_algo(parts[0]) if parts and parts[0] else ""
    mode = _norm_mode(parts[1]) if len(parts) > 1 and parts[1] else ""
    padding = _norm_padding(parts[2]) if len(parts) > 2 and parts[2] else ""
    return algo, mode, padding


def _norm_algo(raw: str) -> str:
    low = raw.strip().lower()
    if low == "aes":
        return "AES"
    if low in ("desede", "tripledes", "3des", "des3"):
        return "3DES"
    if low == "des":
        return "DES"
    return raw.strip().upper()


def _norm_mode(raw: str) -> str:
    low = raw.strip().lower()
    for mode in ("cfb", "cbc", "ecb", "ctr", "ofb", "gcm"):
        if low.startswith(mode):
            return mode.upper()
    return raw.strip().upper()


def _norm_padding(raw: str) -> str:
    low = raw.strip().lower()
    if low in ("pkcs5padding", "pkcs7padding", "pkcs5", "pkcs7"):
        return "Pkcs7"
    if low in ("nopadding", "none", ""):
        return "NoPadding"
    return raw.strip()


def _bytes_printable_ascii(data: bytes) -> bool:
    """非空且全为可见 ASCII（0x20..0x7e）→ True（用于判 key/iv 是否 utf8 文本口径）。"""
    return len(data) > 0 and all(0x20 <= c <= 0x7e for c in data)


# ---------------------------------------------------------------------------
# 从活体明文抽冒充品牌线索（反诈视角）
# ---------------------------------------------------------------------------


def brand_hints_from_events(events: list[dict[str, Any]]) -> list[str]:
    """从 doFinal 捕获的明文里抽冒充对象（webName/品牌名/行业词），去重保序。

    解 ``plaintext_b64`` → UTF-8 文本 → 若是 JSON 取 _BRAND_KEYS 的值；并对所有字符串值
    扫 _BRAND_HINT_TOKENS（证券/银行/…）命中即收。任何一步失败只跳过该条，绝不抛。
    """
    hints: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        v = value.strip()
        if v and v not in seen and len(v) <= 80:
            seen.add(v)
            hints.append(v)

    for ev in events:
        if not isinstance(ev, dict):
            continue
        text = _plaintext_of(ev)
        if not text:
            continue
        try:
            obj = json.loads(text)
        except (ValueError, TypeError):
            obj = None
        if obj is not None:
            for key, val in _walk_strings(obj):
                if key.lower() in _BRAND_KEYS:
                    _add(val)
                if any(tok in val for tok in _BRAND_HINT_TOKENS):
                    _add(val)
        else:
            if any(tok in text for tok in _BRAND_HINT_TOKENS):
                # 非 JSON 明文：截一段含行业词的上下文。
                _add(text[:80])
    return hints


def _plaintext_of(event: dict[str, Any]) -> str:
    """把事件的 plaintext_b64 解成 UTF-8 文本；缺/坏 → 空串（不抛）。"""
    b64 = event.get("plaintext_b64")
    if not isinstance(b64, str) or not b64:
        return ""
    try:
        raw = base64.b64decode(b64, validate=False)
    except (binascii.Error, ValueError):
        return ""
    return raw.decode("utf-8", errors="ignore")


def _walk_strings(obj: Any, key: str = "") -> list[tuple[str, str]]:
    """递归收集 JSON 里的 (key, str_value) 对（与 merge._walk_json_strings 同范式）。"""
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_walk_strings(v, str(k)))
    elif isinstance(obj, list):
        for item in obj:
            out.extend(_walk_strings(item, key))
    elif isinstance(obj, str):
        out.append((key, obj))
    return out


def jsbridge_hints_from_events(events: list[dict[str, Any]]) -> list[str]:
    """从 JS-bridge 事件抽「接口名（+方法）」线索，去重保序。

    register → ``<iface>``（及暴露方法概览）；call → ``<iface>.<method>``。供 merge 把
    运行时实际暴露/调用的桥接面并回报告（确认静态 webview_jsbridge 的桥接面）。
    """
    hints: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        v = value.strip()
        if v and v not in seen and len(v) <= 120:
            seen.add(v)
            hints.append(v)

    for ev in events:
        if not isinstance(ev, dict):
            continue
        iface = str(ev.get("iface", "")).strip()
        if not iface:
            continue
        if ev.get("event") == "call" and ev.get("method"):
            _add(f"{iface}.{str(ev.get('method')).strip()}")
        else:
            _add(iface)
    return hints


def sensitive_api_hints_from_events(events: list[dict[str, Any]]) -> list[str]:
    """从敏感 API 事件抽「<类>.<方法>」清单，去重保序（供 merge 确认静态 sensitive_api）。"""
    hints: list[str] = []
    seen: set[str] = set()
    for ev in events:
        if not isinstance(ev, dict):
            continue
        api = str(ev.get("api", "")).strip()
        if api and api not in seen:
            seen.add(api)
            hints.append(api)
    return hints


def antidetect_kinds_from_events(events: list[dict[str, Any]]) -> dict[str, int]:
    """统计反检测探测的种类计数（root/emulator/frida/…），供报告呈现反分析行为画像。"""
    counts: dict[str, int] = {}
    for ev in events:
        if not isinstance(ev, dict):
            continue
        kind = str(ev.get("kind", "")).strip()
        if kind:
            counts[kind] = counts.get(kind, 0) + 1
    return counts


__all__ = [
    "FRIDA_CRYPTO_HOOK_JS",
    "FRIDA_JSBRIDGE_HOOK_JS",
    "FRIDA_SENSITIVE_API_HOOK_JS",
    "FRIDA_ANTIDETECT_JS",
    "FRIDA_OKHTTP_HOOK_JS",
    "FRIDA_SQLCIPHER_HOOK_JS",
    "CRYPTO_MSG_TYPE",
    "JSBRIDGE_MSG_TYPE",
    "SENSITIVE_API_MSG_TYPE",
    "ANTIDETECT_MSG_TYPE",
    "CREDENTIAL_MSG_TYPE",
    "SQLCIPHER_MSG_TYPE",
    "make_message_handler",
    "make_typed_handler",
    "normalize_crypto_event",
    "normalize_jsbridge_event",
    "normalize_sensitive_api_event",
    "normalize_antidetect_event",
    "normalize_credential_event",
    "normalize_sqlcipher_event",
    "extract_sharedprefs_credentials",
    "recipe_from_events",
    "brand_hints_from_events",
    "jsbridge_hints_from_events",
    "sensitive_api_hints_from_events",
    "antidetect_kinds_from_events",
    "transformation_parts",
]
