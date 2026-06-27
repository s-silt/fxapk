// encoding-hook.js — hook Base64/URLEncoder/Gson/JSONObject 抓加密前·解密后 model 层明文信封，重建 API 契约
// 适用：HTTPS 体是密文/Base64 看不懂；想抓加密前对象长啥样、字段名；要重建『企业号→配置』请求明文结构以便登录前自造请求
// 跑：frida -U -f <包名> -l encoding-hook.js -q
// 改：app 用 fastjson 换 com.alibaba.fastjson.JSON.toJSONString/parseObject；Moshi 换 com.squareup.moshi.JsonAdapter.toJson；Jackson 换 com.fasterxml.jackson.databind.ObjectMapper.writeValueAsString
'use strict';
Java.perform(function () {
    var _CAP = 4000;
    var _count = 0;
    var _seen = {};        // 按内容去重(Base64/JSON 高频，同串只回传一次)
    var _MIN = 8;          // 最小长度过滤：太短的 Base64/JSON 多为噪声(图标/枚举)，丢弃
    var _MAX = 16384;      // 单条回传字符上限

    function clip(s) {
        try {
            if (s === null || s === undefined) return null;
            var t = '' + s;
            return t.length > _MAX ? (t.slice(0, _MAX) + '…(截断' + t.length + ')') : t;
        } catch (e) { return null; }
    }
    // 统一回传：tag 区分来源，content 是明文信封/字段。按内容去重 + 长度过滤 + 封顶
    function emit(tag, content) {
        try {
            if (content === null || content === undefined) return;
            var s = '' + content;
            if (s.length < _MIN) return;                 // 过滤短噪声
            var k = tag + '|' + (s.length > 128 ? s.slice(0, 128) + s.length : s);
            if (_seen[k]) return;
            _seen[k] = true;
            if (_count >= _CAP) return;
            _count += 1;
            console.log('[enc] ' + tag + ' :: ' + clip(s));
        } catch (e) {}
    }
    function b2hex(bytes) {
        if (bytes === null || bytes === undefined) return null;
        try { var o = ''; for (var i = 0; i < bytes.length; i++) { var b = bytes[i] & 0xff; o += ('0' + b.toString(16)).slice(-2); } return o; } catch (e) { return null; }
    }
    // byte[] → 可读文本优先，含不可打印则给 hex(绝不盲 UTF-8)
    function bytesToText(bytes) {
        if (bytes === null || bytes === undefined) return null;
        try {
            var printable = 0, total = bytes.length;
            for (var i = 0; i < total && i < 256; i++) {
                var b = bytes[i] & 0xff;
                if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127) || b >= 0xC0) printable++;
            }
            if (total > 0 && printable / Math.min(total, 256) > 0.85) {
                return '' + Java.use('java.lang.String').$new(bytes, 'UTF-8');
            }
        } catch (e) {}
        return 'hex:' + b2hex(bytes);
    }

    // ===== android.util.Base64：encode 入参=加密前明文/被编码凭据；decode 出参=解码后密钥/配置 =====
    try {
        var B64 = Java.use('android.util.Base64');
        // encodeToString([B,int)：入参 byte[] 即编码前明文(常是加密后密文或原始凭据)
        try {
            B64.encodeToString.overload('[B', 'int').implementation = function (input, flags) {
                try { if (input !== null) emit('Base64.encode(入参/编码前)', bytesToText(input)); } catch (e) {}
                return this.encodeToString(input, flags);
            };
        } catch (e) { console.log('[enc] Base64.encodeToString([B,int) skip: ' + e); }
        // encodeToString([B,int,int,int)：(input, offset, len, flags)
        try {
            B64.encodeToString.overload('[B', 'int', 'int', 'int').implementation = function (input, off, len, flags) {
                try {
                    if (input !== null) {
                        var sub = input;
                        try { sub = Java.array('byte', Array.prototype.slice.call(input, off, off + len)); } catch (eSub) { sub = input; }
                        emit('Base64.encode(入参/编码前)', bytesToText(sub));
                    }
                } catch (e) {}
                return this.encodeToString(input, off, len, flags);
            };
        } catch (e) { console.log('[enc] Base64.encodeToString([B,int,int,int) skip: ' + e); }
        // decode(String,int)：出参 byte[] 即解码后内容(常是 key/iv/配置/密文)
        try {
            B64.decode.overload('java.lang.String', 'int').implementation = function (str, flags) {
                var out = this.decode(str, flags);
                try { if (out !== null) emit('Base64.decode(出参/解码后)', bytesToText(out)); } catch (e) {}
                return out;
            };
        } catch (e) { console.log('[enc] Base64.decode(String,int) skip: ' + e); }
        console.log('[enc] android.util.Base64 hooked');
    } catch (e) {
        console.log('[enc] Base64 hook skip(可能用 java.util.Base64，见下一段): ' + e);
    }

    // ===== java.util.Base64(API26+/纯 Java 库常用)：兜底另一套 Base64 实现 =====
    try {
        var JEnc = Java.use('java.util.Base64$Encoder');
        JEnc.encodeToString.overload('[B').implementation = function (input) {
            try { if (input !== null) emit('java.Base64.encode(入参/编码前)', bytesToText(input)); } catch (e) {}
            return this.encodeToString(input);
        };
        console.log('[enc] java.util.Base64$Encoder hooked');
    } catch (e) { console.log('[enc] java.util.Base64$Encoder skip(可能 API<26): ' + e); }
    try {
        var JDec = Java.use('java.util.Base64$Decoder');
        JDec.decode.overload('java.lang.String').implementation = function (str) {
            var out = this.decode(str);
            try { if (out !== null) emit('java.Base64.decode(出参/解码后)', bytesToText(out)); } catch (e) {}
            return out;
        };
        console.log('[enc] java.util.Base64$Decoder hooked');
    } catch (e) { console.log('[enc] java.util.Base64$Decoder skip(可能 API<26): ' + e); }

    // ===== java.net.URLEncoder.encode：拼进 URL 的明文参数(企业号/标识符/查询键值) =====
    try {
        var URLEnc = Java.use('java.net.URLEncoder');
        URLEnc.encode.overload('java.lang.String', 'java.lang.String').implementation = function (s, enc) {
            try { emit('URLEncoder.encode(URL 明文参数)', s); } catch (e) {}
            return this.encode(s, enc);
        };
        console.log('[enc] java.net.URLEncoder hooked');
    } catch (e) { console.log('[enc] URLEncoder hook skip: ' + e); }

    // ===== com.google.gson.Gson：toJson=加密前请求信封；fromJson=解密后响应对象(真实后端字段) =====
    // 这是重建 {data,timestamp,enterprise,sign} 契约的主路径——toJson 出来的串通常下一步就被加密发出。
    try {
        var Gson = Java.use('com.google.gson.Gson');
        // toJson(Object)：入参对象 → 出参 JSON 串(加密前的完整请求信封)
        try {
            Gson.toJson.overload('java.lang.Object').implementation = function (obj) {
                var json = this.toJson(obj);
                try { emit('Gson.toJson(加密前请求信封)', json); } catch (e) {}
                return json;
            };
        } catch (e) { console.log('[enc] Gson.toJson(Object) skip: ' + e); }
        // fromJson(String, Class)：入参 JSON 串就是解密后的真实响应(后端下发的客服/支付/配置)
        try {
            Gson.fromJson.overload('java.lang.String', 'java.lang.Class').implementation = function (json, cls) {
                try { emit('Gson.fromJson(解密后响应)', json); } catch (e) {}
                return this.fromJson(json, cls);
            };
        } catch (e) { console.log('[enc] Gson.fromJson(String,Class) skip: ' + e); }
        try {
            Gson.fromJson.overload('java.lang.String', 'java.lang.reflect.Type').implementation = function (json, typ) {
                try { emit('Gson.fromJson(解密后响应)', json); } catch (e) {}
                return this.fromJson(json, typ);
            };
        } catch (e) { console.log('[enc] Gson.fromJson(String,Type) skip: ' + e); }
        console.log('[enc] com.google.gson.Gson hooked');
    } catch (e) {
        console.log('[enc] Gson hook skip(可能用 fastjson/Moshi/Jackson，见文件头改 hook 点): ' + e);
    }

    // ===== org.json.JSONObject：手搓 JSON 信封的另一主路径(toString=信封，put=逐字段) =====
    try {
        var JO = Java.use('org.json.JSONObject');
        // toString()：整个信封序列化(加密前/上报前)
        try {
            JO.toString.overload().implementation = function () {
                var s = this.toString();   // 调原始实现，结果已是 String，emit 不会再触发本 hook
                try { emit('JSONObject.toString(明文信封)', s); } catch (e) {}
                return s;
            };
        } catch (e) { console.log('[enc] JSONObject.toString() skip: ' + e); }
        // put(String, Object)：逐字段看键名(字段名本身就是契约线索，如 enterprise/appId/sign/timestamp)
        try {
            JO.put.overload('java.lang.String', 'java.lang.Object').implementation = function (k, v) {
                try {
                    var vs = (v === null || v === undefined) ? 'null' : ('' + v);
                    if (vs.length > 256) vs = vs.slice(0, 256) + '…';
                    emit('JSONObject.put(字段)', k + ' = ' + vs);
                } catch (e) {}
                return this.put(k, v);
            };
        } catch (e) { console.log('[enc] JSONObject.put(String,Object) skip: ' + e); }
        console.log('[enc] org.json.JSONObject hooked');
    } catch (e) { console.log('[enc] JSONObject hook skip: ' + e); }

    console.log('[enc] encoding-hook armed —— 触发登录前请求(企业号查询/配置拉取/验证码)看 [enc] 行；');
    console.log('[enc] Gson.toJson/JSONObject.toString = 加密前请求信封(重建 API 契约)，fromJson/decode = 解密后真实后端内容');
    console.log('[enc] 若想自造请求逼真源站：照 toJson 的字段结构 + sign-hook 抓的签名算法，离线拼一个合法请求拉企业号配置');
    console.log('[enc] 若全程无业务相关 [enc]：可能整体走 native/Flutter 序列化或 fastjson/Moshi——改 hook 点见文件头注释');
});
