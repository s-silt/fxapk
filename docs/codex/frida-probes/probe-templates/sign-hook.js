// sign-hook.js — hook MessageDigest/Mac 抓请求签名算法+HMAC密钥+被签明文，逆出 sign 参数怎么算
// 适用：请求带 sign/sig/signature 参数、抓包只见结果不知算法；想登录前自造合法签名请求逼真源站；签名错服务端不下发配置
// 跑：frida -U -f <包名> -l sign-hook.js -q
// 改：BC/Conscrypt 自带摘要走 org.bouncycastle.crypto.Digest；native(OpenSSL)算签名换 native-ssl-hook.js；签名工具类(如 com.xxx.SignUtil.sign)可直接 hook 那个静态方法看入参拼接串
'use strict';
Java.perform(function () {
    var _CAP = 3000;       // 总回传封顶，防高频签名刷爆
    var _count = 0;
    var _seen = {};        // (算法|明文) 去重，同一签名重复算不重复回传
    var _MAXB = 16384;     // 被签明文回传上限(签名串通常不长，超大截断)

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
    // 被签明文优先按 UTF-8 还原(签名串多为可读 a=b&c=d)，含不可打印字节则退回 hex 避免乱码
    function bytesToText(bytes) {
        if (bytes === null || bytes === undefined) return null;
        try {
            var printable = 0, total = bytes.length;
            for (var i = 0; i < total && i < 256; i++) {
                var b = bytes[i] & 0xff;
                if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127) || b >= 0xC0) printable++;
            }
            if (total > 0 && printable / Math.min(total, 256) > 0.85) {
                var Str = Java.use('java.lang.String');
                return '' + Str.$new(bytes, 'UTF-8');
            }
        } catch (e) {}
        return null;
    }
    function clipBytes(bytes) {
        if (bytes === null || bytes === undefined) return null;
        try {
            if (bytes.length > _MAXB) {
                return Java.array('byte', Array.prototype.slice.call(bytes, 0, _MAXB));
            }
        } catch (e) {}
        return bytes;
    }
    // 把被签明文打全：可读串直接打文本，否则 hex(+base64)，二进制绝不盲 UTF-8
    function logPlain(tag, algo, bytes) {
        try {
            var c = clipBytes(bytes);
            var text = bytesToText(c);
            var key = algo + '|' + (text !== null ? text : b2hex(c));
            if (_seen[key]) return;
            _seen[key] = true;
            if (_count >= _CAP) return;
            _count += 1;
            if (text !== null) {
                console.log('[sign] ' + tag + ' algo=' + algo + ' plaintext(被签明文)= ' + text);
            } else {
                console.log('[sign] ' + tag + ' algo=' + algo + ' plaintext(hex)= ' + b2hex(c));
                console.log('[sign] ' + tag + ' algo=' + algo + ' plaintext(b64)= ' + b2b64(c));
            }
        } catch (e) {}
    }

    // ===== java.security.MessageDigest：MD5/SHA 系列(最常见的请求签名) =====
    // 机制：app 多用 md5(拼接串+密钥)/sha256(...) 当 sign。MessageDigest 公有 update/digest 不是
    // 抽象方法——它们转发到内部 MessageDigestSpi(engineUpdate/engineDigest)，故 hook 公有方法对
    // 走 JCA 的实现(含 Delegate 包装)普遍命中。须按实例攒 update 字节，digest 时一次性回传被签明文。
    try {
        var MD = Java.use('java.security.MessageDigest');
        var System = Java.use('java.lang.System');
        var _mdBuf = {};     // identityHashCode -> 已 update 的字节(用 ByteArrayOutputStream 攒)

        function mdAlgo(self) {
            try { return '' + self.getAlgorithm(); } catch (e) { return 'MessageDigest'; }
        }
        function mdBufOf(id) {
            var BAOS = _mdBuf[id];
            if (!BAOS) { BAOS = Java.use('java.io.ByteArrayOutputStream').$new(); _mdBuf[id] = BAOS; }
            return BAOS;
        }
        // 统一用 write(byte[],int,int)(BAOS 自有重载)，不依赖继承自 OutputStream 的 write(byte[])
        function mdAppend(self, bytes, off, len) {
            try {
                if (bytes === null || bytes === undefined) return;
                var id = System.identityHashCode(self);
                var BAOS = mdBufOf(id);
                if (off !== undefined && len !== undefined) { BAOS.write(bytes, off, len); }
                else { BAOS.write(bytes, 0, bytes.length); }
            } catch (e) {}
        }
        function mdEmit(self) {
            var id = null;
            try {
                id = System.identityHashCode(self);
                var BAOS = _mdBuf[id];
                if (BAOS) {
                    var all = BAOS.toByteArray();
                    if (all !== null && all.length > 0) logPlain('MessageDigest', mdAlgo(self), all);
                }
            } catch (e) {}
            // digest 即终结：清本实例 buffer，防 identityHashCode 被 GC 复用后串到新实例
            try { if (id !== null) delete _mdBuf[id]; } catch (e2) {}
        }

        // update([B)
        try {
            MD.update.overload('[B').implementation = function (b) {
                mdAppend(this, b);
                return this.update(b);
            };
        } catch (e) { console.log('[sign] MessageDigest.update([B) skip: ' + e); }
        // update([B,int,int)
        try {
            MD.update.overload('[B', 'int', 'int').implementation = function (b, off, len) {
                mdAppend(this, b, off, len);
                return this.update(b, off, len);
            };
        } catch (e) { console.log('[sign] MessageDigest.update([B,int,int) skip: ' + e); }
        // digest()
        try {
            MD.digest.overload().implementation = function () {
                mdEmit(this);
                return this.digest();
            };
        } catch (e) { console.log('[sign] MessageDigest.digest() skip: ' + e); }
        // digest([B)：有的直接 digest(input)，input 即被签明文(覆盖未走 update 的情形)
        // 注：原实现内部会调公有 update→公有 digest()(均被 hook)，可能重复 emit 一次，已被去重吸收；
        // 这里先清掉该实例可能残留的旧 buffer，避免 input 与上一轮残留串混。
        try {
            MD.digest.overload('[B').implementation = function (input) {
                try {
                    var id = System.identityHashCode(this);
                    if (_mdBuf[id]) { try { delete _mdBuf[id]; } catch (eClr) {} }
                    if (input !== null) logPlain('MessageDigest', mdAlgo(this), input);
                } catch (e) {}
                return this.digest(input);
            };
        } catch (e) { console.log('[sign] MessageDigest.digest([B) skip: ' + e); }
        console.log('[sign] java.security.MessageDigest hooked');
    } catch (e) {
        console.log('[sign] MessageDigest hook skip(未命中——可能走 BouncyCastle/Conscrypt 或 native，见头注释): ' + e);
    }

    // ===== javax.crypto.Mac：HMAC 签名(HmacSHA256/HmacMD5 等)——init 抓 key，doFinal 抓被签明文 =====
    // HMAC key 是【强凭据】：拿到就能离线对任意请求生成合法签名，自造请求逼真源站不依赖登录。
    try {
        var Mac = Java.use('javax.crypto.Mac');
        var SystemM = Java.use('java.lang.System');
        var _macKey = {};    // identityHashCode(Mac) -> {algo, key_hex}
        var _macBuf = {};    // identityHashCode(Mac) -> ByteArrayOutputStream(分段 update 攒)

        function macAlgo(self) {
            try { return '' + self.getAlgorithm(); } catch (e) { return 'HMAC'; }
        }
        function macInitEmit(self, key) {
            try {
                var algo = macAlgo(self);
                var key_hex = null, key_b64 = null;
                try {
                    if (key !== null && key !== undefined && key.getEncoded) {
                        var enc = key.getEncoded();
                        if (enc !== null) { key_hex = b2hex(enc); key_b64 = b2b64(enc); }
                    }
                } catch (e) {}
                var id = SystemM.identityHashCode(self);
                _macKey[id] = {algo: algo, key_hex: key_hex};
                // HMAC 密钥同时给 hex 与 base64(很多服务端密钥就是 base64 串)
                console.log('[sign] HMAC init algo=' + algo + ' key(hex/签名密钥强线索)= ' + key_hex);
                if (key_b64) console.log('[sign] HMAC init algo=' + algo + ' key(b64)= ' + key_b64);
            } catch (e) {}
        }
        try {
            Mac.init.overload('java.security.Key').implementation = function (key) {
                macInitEmit(this, key); return this.init(key);
            };
        } catch (e) { console.log('[sign] Mac.init(Key) skip: ' + e); }
        try {
            Mac.init.overload('java.security.Key', 'java.security.spec.AlgorithmParameterSpec')
                .implementation = function (key, spec) {
                    macInitEmit(this, key); return this.init(key, spec);
                };
        } catch (e) { console.log('[sign] Mac.init(Key,Spec) skip: ' + e); }
        // doFinal([B)：入参即被签明文(HMAC 的消息体)，结合上面的 key 就是完整签名配方
        try {
            Mac.doFinal.overload('[B').implementation = function (input) {
                try {
                    var id = SystemM.identityHashCode(this);
                    var st = _macKey[id] || {algo: macAlgo(this)};
                    if (input !== null) logPlain('HMAC', st.algo + (st.key_hex ? '(key=' + st.key_hex + ')' : ''), input);
                } catch (e) {}
                return this.doFinal(input);
            };
        } catch (e) { console.log('[sign] Mac.doFinal([B) skip: ' + e); }
        // update([B) + doFinal()：分段喂入的 HMAC，按实例攒；用 write(b,0,len) 不依赖继承重载
        try {
            Mac.update.overload('[B').implementation = function (b) {
                try {
                    if (b !== null && b !== undefined) {
                        var id = SystemM.identityHashCode(this);
                        var BAOS = _macBuf[id];
                        if (!BAOS) { BAOS = Java.use('java.io.ByteArrayOutputStream').$new(); _macBuf[id] = BAOS; }
                        BAOS.write(b, 0, b.length);
                    }
                } catch (e) {}
                return this.update(b);
            };
        } catch (e) { console.log('[sign] Mac.update([B) skip: ' + e); }
        try {
            Mac.doFinal.overload().implementation = function () {
                var id = null;
                try {
                    id = SystemM.identityHashCode(this);
                    var st = _macKey[id] || {algo: macAlgo(this)};
                    var BAOS = _macBuf[id];
                    if (BAOS) {
                        var all = BAOS.toByteArray();
                        if (all !== null && all.length > 0) logPlain('HMAC', st.algo + (st.key_hex ? '(key=' + st.key_hex + ')' : ''), all);
                    }
                } catch (e) {}
                try { if (id !== null) delete _macBuf[id]; } catch (e2) {}
                return this.doFinal();
            };
        } catch (e) { console.log('[sign] Mac.doFinal() skip: ' + e); }
        console.log('[sign] javax.crypto.Mac hooked');
    } catch (e) {
        console.log('[sign] Mac hook skip: ' + e);
    }

    // ===== java.security.Signature：RSA/ECDSA 数字签名(向服务器证明身份/防篡改) =====
    // initSign 抓算法+(托管密钥)alias；update 攒被签明文；sign 出签名值。托管私钥不可导，但 alias 可凭以调证密钥用途/审计。
    try {
        var Sig = Java.use('java.security.Signature');
        var SystemS = Java.use('java.lang.System');
        var _sigBuf = {};   // id -> ByteArrayOutputStream
        var _sigMeta = {};  // id -> {algo, alias}
        function sigAlgo(self) { try { return '' + self.getAlgorithm(); } catch (e) { return 'Signature'; } }
        function sigInit(self, key, mode) {
            try {
                var id = SystemS.identityHashCode(self), alias = '';
                try { if (key && key.getKeystoreAlias) alias = '' + key.getKeystoreAlias(); } catch (e) {}
                if (!alias) { try { alias = '' + key.getClass().getName(); } catch (e) {} }
                _sigMeta[id] = { algo: sigAlgo(self), alias: alias };
                console.log('[sign] Signature.' + mode + ' algo=' + sigAlgo(self) + ' key/alias=' + alias);
            } catch (e) {}
        }
        function sigAppend(self, b, off, len) {
            try {
                if (b === null || b === undefined) return;
                var id = SystemS.identityHashCode(self), BAOS = _sigBuf[id];
                if (!BAOS) { BAOS = Java.use('java.io.ByteArrayOutputStream').$new(); _sigBuf[id] = BAOS; }
                if (off !== undefined && len !== undefined) BAOS.write(b, off, len); else BAOS.write(b, 0, b.length);
            } catch (e) {}
        }
        function sigEmit(self, sigBytes) {
            var id = null;
            try {
                id = SystemS.identityHashCode(self);
                var meta = _sigMeta[id] || { algo: sigAlgo(self), alias: '' };
                var BAOS = _sigBuf[id];
                if (BAOS) { var all = BAOS.toByteArray(); if (all !== null && all.length > 0) logPlain('Signature', meta.algo + (meta.alias ? '(alias=' + meta.alias + ')' : ''), all); }
                if (sigBytes !== null && sigBytes !== undefined) console.log('[sign] Signature OUT algo=' + meta.algo + ' signature(b64)= ' + b2b64(sigBytes));
            } catch (e) {}
            try { if (id !== null) delete _sigBuf[id]; } catch (e2) {}
        }
        try { Sig.initSign.overloads.forEach(function (ov) { ov.implementation = function () { sigInit(this, arguments[0], 'initSign'); return ov.apply(this, arguments); }; }); } catch (e) { console.log('[sign] Signature.initSign skip: ' + e); }
        try { Sig.initVerify.overloads.forEach(function (ov) { ov.implementation = function () { sigInit(this, arguments[0], 'initVerify'); return ov.apply(this, arguments); }; }); } catch (e) { console.log('[sign] Signature.initVerify skip: ' + e); }
        try { Sig.update.overload('[B').implementation = function (b) { sigAppend(this, b); return this.update(b); }; } catch (e) {}
        try { Sig.update.overload('[B', 'int', 'int').implementation = function (b, o, l) { sigAppend(this, b, o, l); return this.update(b, o, l); }; } catch (e) {}
        try { Sig.sign.overload().implementation = function () { var r = this.sign(); sigEmit(this, r); return r; }; } catch (e) {}
        try { Sig.verify.overload('[B').implementation = function (s) { var ok = this.verify(s); try { sigEmit(this, s); console.log('[sign] Signature.verify -> ' + ok); } catch (e) {} return ok; }; } catch (e) {}
        console.log('[sign] java.security.Signature hooked');
    } catch (e) { console.log('[sign] Signature hook skip: ' + e); }

    console.log('[sign] sign-hook armed —— 触发一次登录前的请求(配置拉取/企业号查询/验证码)看 [sign] 行；');
    console.log('[sign] 重点看 plaintext(被签明文) 与 HMAC key：明文里的拼接顺序+盐值=签名算法，key=离线自造签名的凭据');
    console.log('[sign] 若全程无 [sign] 输出：签名可能走 BC/Conscrypt/native 或自写工具类——改 hook 点见文件头注释');
});
