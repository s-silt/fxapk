
// 取证用途：对取证样本自身在分析机上做运行时观测，产出端点/密钥/独特串等线索，不面向任何第三方基础设施。
// apkscan 运行时密钥 hook（best-effort）：抓活体 AES key/iv/明文/密文回传 Python。
var _coverage = (typeof globalThis !== 'undefined' && globalThis.__fxapkProbeCoverage) || {
    perform: function (_family, callback) {
        try { if (typeof Java !== 'undefined' && (!('available' in Java) || Java.available)) Java.perform(callback); } catch (_) {}
    },
    attempted: function () {}, installed: function () {}, registrationError: function () {},
    trigger: function () {}, drop: function () {}, truncated: function () {}
};
_coverage.perform('crypto', function () {
    var _seen = {};
    var _count = 0;
    var _CAP = 4000;          // 与 Python _SINK_CAP 对齐
    var _MAXB = 65536;        // 明文/密文回传字节上限

    function b2hex(bytes) {
        if (bytes === null || bytes === undefined) return null;
        try {
            var out = '';
            var length = bytes.length;
            if (length > _MAXB) {
                _coverage.truncated('crypto', 'events');
                length = _MAXB;
            }
            for (var i = 0; i < length; i++) {
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
                _coverage.truncated('crypto', 'events');
                var sub = Java.array('byte', Array.prototype.slice.call(bytes, 0, _MAXB));
                return sub;
            }
        } catch (e) {}
        return bytes;
    }
    function emit(p) {
        try {
            if (_count >= _CAP) { _coverage.drop('crypto', 'events'); return; }
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
            _coverage.attempted('crypto', 'cipher_init');
            ov.implementation = function () {
                _coverage.trigger('crypto', 'cipher_init');
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
            _coverage.installed('crypto', 'cipher_init');
        });

        Cipher.doFinal.overloads.forEach(function (ov) {
            _coverage.attempted('crypto', 'cipher_final');
            ov.implementation = function () {
                _coverage.trigger('crypto', 'cipher_final');
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
            _coverage.installed('crypto', 'cipher_final');
        });
        console.log('[apkscan] javax.crypto.Cipher hooked');
    } catch (e) {
        _coverage.registrationError('crypto', 'cipher_init');
        _coverage.registrationError('crypto', 'cipher_final');
        console.log('[apkscan] Cipher hook skip: ' + e);
    }

    // --- SecretKeySpec.$init：构造期抓原始 key bytes（覆盖 getEncoded 被混淆/返回 null）---
    try {
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        var secretKey = SecretKeySpec.$init.overload('[B', 'java.lang.String');
        _coverage.attempted('crypto', 'secret_key');
        secretKey.implementation = function (keyBytes, algo) {
            _coverage.trigger('crypto', 'secret_key');
            try {
                emit({src: 'secretkeyspec', event: 'init', transformation: '' + algo,
                      key_hex: b2hex(keyBytes), ts: Date.now()});
            } catch (e) {}
            return this.$init(keyBytes, algo);
        };
        _coverage.installed('crypto', 'secret_key');
        // 带 offset/length 的构造（部分库用此形式，否则漏 key）。
        var secretKeySlice = SecretKeySpec.$init.overload(
            '[B', 'int', 'int', 'java.lang.String'
        );
        _coverage.attempted('crypto', 'secret_key');
        secretKeySlice.implementation = function (keyBytes, off, len, algo) {
                _coverage.trigger('crypto', 'secret_key');
                try {
                    var sub = null;
                    try { sub = Java.array('byte', Array.prototype.slice.call(keyBytes, off, off + len)); } catch (e3) { sub = keyBytes; }
                    emit({src: 'secretkeyspec', event: 'init', transformation: '' + algo,
                          key_hex: b2hex(sub), ts: Date.now()});
                } catch (e) {}
                return this.$init(keyBytes, off, len, algo);
            };
        _coverage.installed('crypto', 'secret_key');
        console.log('[apkscan] SecretKeySpec hooked');
    } catch (e) {
        _coverage.registrationError('crypto', 'secret_key');
        console.log('[apkscan] SecretKeySpec hook skip: ' + e);
    }

    // --- IvParameterSpec.$init：抓 iv bytes -------------------------------
    try {
        var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
        var ivSpec = IvParameterSpec.$init.overload('[B');
        _coverage.attempted('crypto', 'iv_spec');
        ivSpec.implementation = function (ivBytes) {
            _coverage.trigger('crypto', 'iv_spec');
            try {
                emit({src: 'ivspec', event: 'init', iv_hex: b2hex(ivBytes), ts: Date.now()});
            } catch (e) {}
            return this.$init(ivBytes);
        };
        _coverage.installed('crypto', 'iv_spec');
        console.log('[apkscan] IvParameterSpec hooked');
    } catch (e) {
        _coverage.registrationError('crypto', 'iv_spec');
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
        var macInit = Mac.init.overload('java.security.Key');
        _coverage.attempted('crypto', 'mac_init');
        macInit.implementation = function (key) {
            _coverage.trigger('crypto', 'mac_init');
            _emitMacKey(this, key);
            return this.init(key);
        };
        _coverage.installed('crypto', 'mac_init');
        var macInitSpec = Mac.init.overload(
            'java.security.Key', 'java.security.spec.AlgorithmParameterSpec'
        );
        _coverage.attempted('crypto', 'mac_init');
        macInitSpec.implementation = function (key, spec) {
                _coverage.trigger('crypto', 'mac_init');
                _emitMacKey(this, key);
                return this.init(key, spec);
            };
        _coverage.installed('crypto', 'mac_init');
        console.log('[apkscan] Mac hooked');
    } catch (e) {
        _coverage.registrationError('crypto', 'mac_init');
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
        var webViewLoadUrl = WebView.loadUrl.overload('java.lang.String');
        _coverage.attempted('crypto', 'webview_load_url');
        webViewLoadUrl.implementation = function (url) {
            _coverage.trigger('crypto', 'webview_load_url');
            try { this.evaluateJavascript(injectJs, null); } catch (e) {}
            return this.loadUrl(url);
        };
        _coverage.installed('crypto', 'webview_load_url');
        console.log('[apkscan] WebView CryptoJS wrapper armed');
    } catch (e) {
        _coverage.registrationError('crypto', 'webview_load_url');
        console.log('[apkscan] WebView CryptoJS hook skip: ' + e);
    }
});
