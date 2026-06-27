// objstore-config-hook.js — 识别多云对象存储(阿里OSS/百度BOS/天翼ZOS/腾讯COS)的「配置/资源下发」，抓 bucket名/账户锚点[OBJSTORE锚点] + 把下发配置正文打全 + 正则抽里头真后端域名/IP/wss[BACKEND]
// 适用：杀猪盘改包冷启动从对象存储多云分散(抗封堵)拉配置/资源，真后端常只写在「下发配置正文」里；对象存储域是分发层≠源站，但 bucket名/账户=可调证锚点，配置正文=穿透到真源站
// 跑：frida -U -f <包名> -l objstore-config-hook.js -q   （必须 -f spawn：配置下发在 Application 极早期，attach 会漏掉冷启动那几次拉取）
// 改：(1) OBJSTORE_HOST_RE 现场按命中的对象存储域增删；(2) BACKEND_RE 按目标配置里的字段名(base_url/wss/line/node)调；(3) 响应读取兜底已覆盖 OkHttp/URLConnection/InputStream/String，仍空→配 native-ssl-hook.js(密文)/cipher-hook.js(配置加密)
'use strict';

// ============================================================
// 重入保护：本探针 hook 了 java.lang.String.<init>（D 段）。一旦 hook 上，本脚本内部任何
// 经 Java 构造 String 的调用(如 String.$new(bytes,'UTF-8'))都会再次落回这个 <init> hook → 死循环/爆栈。
// 用一个标志位：进入"我们自己"要构造/检查文本的逻辑时置 true，构造完清掉；<init> hook 里见到
// true 就只透传原构造、绝不再做正文扫描。这样既保留库内 String.$new 解码习惯，又不自食其尾。
// ============================================================
var _IN_HOOK = false;

// ============================================================
// 通用工具：bytes -> hex / base64 / 安全预览（明文给文本，二进制走 hex+b64，绝不盲 UTF-8）
// ============================================================
function _hex(bytes) {
    try {
        var out = '';
        for (var i = 0; i < bytes.length; i++) {
            var b = bytes[i] & 0xff;
            out += (b < 16 ? '0' : '') + b.toString(16);
        }
        return out;
    } catch (e) { return '<hex-fail:' + e + '>'; }
}
function _b64(bytes) {
    try {
        var B64 = Java.use('android.util.Base64');
        return B64.encodeToString(bytes, 2 /*NO_WRAP*/);
    } catch (e) { return '<b64-fail>'; }
}
// 纯 JS 的 UTF-8 解码（不经 Java String 构造 → 不会落回 <init> hook，<init> 处理器里专用，安全）。
// 仅做最小可用的 UTF-8 解析；解析失败的字节用占位符，绝不抛。
function _bytesToJsTextRaw(bytes) {
    var out = '';
    var i = 0, n = bytes.length;
    while (i < n) {
        var b0 = bytes[i] & 0xff;
        if (b0 < 0x80) { out += String.fromCharCode(b0); i += 1; }
        else if (b0 >= 0xC0 && b0 < 0xE0 && i + 1 < n) {
            var b1 = bytes[i + 1] & 0xff;
            out += String.fromCharCode(((b0 & 0x1f) << 6) | (b1 & 0x3f)); i += 2;
        } else if (b0 >= 0xE0 && b0 < 0xF0 && i + 2 < n) {
            var c1 = bytes[i + 1] & 0xff, c2 = bytes[i + 2] & 0xff;
            out += String.fromCharCode(((b0 & 0x0f) << 12) | ((c1 & 0x3f) << 6) | (c2 & 0x3f)); i += 3;
        } else if (b0 >= 0xF0 && i + 3 < n) {
            // 4 字节(补充平面) → 正文里极少，简单转 U+FFFD 占位即可
            out += String.fromCharCode(0xFFFD); i += 4;
        } else { out += String.fromCharCode(0xFFFD); i += 1; }
    }
    return out;
}
// 是否"看着像可读文本"（printable>85%）。只看头部 64 字节做启发，绝不盲解二进制。
function _looksText(bytes) {
    if (!bytes || bytes.length === 0) return false;
    var printable = 0, n = Math.min(bytes.length, 64);
    for (var i = 0; i < n; i++) {
        var b = bytes[i] & 0xff;
        if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127)) printable++;
    }
    return printable / n > 0.85;
}
// printable>85% 给 UTF-8 文本（配置正文几乎都是 JSON 文本），否则给 hex+b64（密文/二进制资源不盲解）。
// 注意：用 String.$new 解码 → 进来前后用 _IN_HOOK 包住，防止 D 段 <init> hook 自递归。
function _preview(bytes, cap) {
    try {
        if (!bytes || bytes.length === 0) return '<empty>';
        if (_looksText(bytes)) {
            _IN_HOOK = true;
            var s;
            try { s = '' + Java.use('java.lang.String').$new(bytes, 'UTF-8'); }
            finally { _IN_HOOK = false; }
            return s.length > cap ? s.substring(0, cap) + '...<+' + (s.length - cap) + '字节略>' : s;
        }
        return 'hex:' + _hex(bytes).substring(0, cap * 2) + (bytes.length > cap ? '...' : '') + '  b64:' + _b64(bytes).substring(0, 64);
    } catch (e) { return '<preview-fail:' + e + '>'; }
}
// 拿到"可读文本"时才做后端正则抽取（二进制不抽，避免乱命中）。同样用 _IN_HOOK 包住 String.$new。
function _asText(bytes) {
    try {
        if (!_looksText(bytes)) return null;
        _IN_HOOK = true;
        var s;
        try { s = '' + Java.use('java.lang.String').$new(bytes, 'UTF-8'); }
        finally { _IN_HOOK = false; }
        return s;
    } catch (e) { return null; }
}

// ============================================================
// 识别规则
// ============================================================
// 对象存储 host 识别：阿里OSS(含加速)、百度BOS、天翼ZOS、腾讯COS。现场命中新域照此增删。
var OBJSTORE_HOST_RE = /(\.aliyuncs\.com|oss-accelerate|\.bcebos\.com|\.zos\.ctyun\.cn|\.myqcloud\.com|cos[.-][a-z0-9-]*\.myqcloud)/i;
// 从对象存储 host 提取「bucket / 账户锚点」：<bucket>.<region>.<provider> 里最左段就是 bucket(=调证最关键锚点)。
// 例: f3f14c7c42079085.oss-accelerate.aliyuncs.com -> bucket=f3f14c7c42079085
//     ba63692667a911cc.gz.bcebos.com               -> bucket=ba63692667a911cc
//     206af95ca203dfe6.jiangsu-10.zos.ctyun.cn     -> bucket=206af95ca203dfe6
//     xxx.cos.ap-shanghai.myqcloud.com             -> bucket=xxx (含 appid 后缀=腾讯COS账户)
function _bucketOf(host) {
    try {
        var h = ('' + host).toLowerCase();
        var m = h.match(/^([a-z0-9][a-z0-9._-]*?)\.(oss-accelerate|oss-[a-z0-9-]+|[a-z0-9-]+\.zos|[a-z0-9-]+\.bcebos|cos[.-]|[a-z0-9-]+\.myqcloud)/);
        if (m && m[1]) return m[1];
        // 兜底：取首段（host 至少三段时）
        var parts = h.split('.');
        if (parts.length >= 3) return parts[0];
        return null;
    } catch (e) { return null; }
}
function _providerOf(host) {
    var h = ('' + host).toLowerCase();
    if (/aliyuncs\.com|oss-accelerate/.test(h)) return '阿里OSS';
    if (/\.bcebos\.com/.test(h)) return '百度BOS';
    if (/\.zos\.ctyun\.cn/.test(h)) return '天翼ZOS';
    if (/myqcloud/.test(h)) return '腾讯COS';
    return '对象存储';
}
// 从「下发配置正文」里抽真后端线索：base_url/host/域名/IP/wss/接入节点/ip:port。
var BACKEND_RE = /("?(base_?url|api_?url|host|domain|ws_?url|wss?_?url|chat|kefu|im_?url|pay|gateway|server|cdn|line|node|endpoint|backend|addr|proxy)"?\s*[:=]\s*"?[^"\s,}\]]+)/ig;
// 直接的 URL / wss / 裸 ip:port（再从正文里捞一层，补字段名没覆盖到的）。
var RAW_TARGET_RE = /((?:https?|wss?):\/\/[^\s"'<>,}\]]+|(?:\d{1,3}\.){3}\d{1,3}:\d{2,5})/ig;

// ============================================================
// 内存账本：去重 + 收尾统一汇总（一眼看全 桶锚点 + 抽到的真后端）
// ============================================================
var SEEN = {};
var ANCHORS = [];   // [{provider, bucket, host, url}]  对象存储锚点
var BACKENDS = [];  // 从配置正文抽到的真后端线索
function _once(key) {
    if (!key) return false;
    if (SEEN[key]) return false;
    SEEN[key] = 1;
    return true;
}
function _hostOf(u) {
    try { var m = ('' + u).match(/^[a-z]+:\/\/([^\/:?#]+)/i); return m ? m[1] : null; } catch (e) { return null; }
}
function _isObjStore(u) {
    try { return OBJSTORE_HOST_RE.test('' + u); } catch (e) { return false; }
}
// 命中一个对象存储 URL → 记 [OBJSTORE锚点]（bucket名/账户 = 向云厂商调 bucket 创建者实名/对象上传日志/访问 IP 的最关键锚点）
function _noteObjStore(url, where) {
    try {
        if (!_isObjStore(url)) return false;
        var host = _hostOf(url) || ('' + url);
        var bucket = _bucketOf(host);
        var prov = _providerOf(host);
        if (_once('objstore|' + url)) {
            console.log('\n[objstore][' + prov + '][OBJSTORE锚点] (' + where + ') ' + url);
            console.log('[objstore]   bucket/账户锚点: ' + (bucket || '<未解析出, 看完整 host>') + '   host: ' + host);
            console.log('[objstore]   -> 调证: 向' + prov + '调 bucket「' + (bucket || host) + '」创建者实名 + 对象上传/删除日志 + 访问 IP/UA(拉过的设备=受害设备) + 绑定域名/回源');
            ANCHORS.push({ provider: prov, bucket: bucket || '?', host: host, url: '' + url });
        }
        return true;
    } catch (e) { console.log('[objstore] noteObjStore skip: ' + e); return false; }
}
// 从「下发配置正文」抽真后端 → [BACKEND]（穿透对象存储分发层、落到真源站候选）
function _scanBackend(text, srcUrl) {
    try {
        if (!text) return;
        var t = '' + text;
        var hits = {};
        var m;
        BACKEND_RE.lastIndex = 0;
        while ((m = BACKEND_RE.exec(t)) !== null) { if (m[1]) hits[m[1].trim()] = 1; if (BACKEND_RE.lastIndex === m.index) BACKEND_RE.lastIndex++; }
        RAW_TARGET_RE.lastIndex = 0;
        while ((m = RAW_TARGET_RE.exec(t)) !== null) {
            var v = m[1];
            // 排除「指向对象存储自身」的 URL（那是分发层、不是真后端），只留疑似真源站
            if (v && !_isObjStore(v)) hits['raw: ' + v] = 1;
            if (RAW_TARGET_RE.lastIndex === m.index) RAW_TARGET_RE.lastIndex++;
        }
        var keys = Object.keys(hits);
        for (var i = 0; i < keys.length; i++) {
            if (_once('backend|' + keys[i])) {
                console.log('[objstore][BACKEND] 下发配置正文里的真后端线索: ' + keys[i] + '   <- 来自 ' + srcUrl);
                BACKENDS.push({ hit: keys[i], src: '' + srcUrl });
            }
        }
        if (keys.length === 0) {
            console.log('[objstore]   (本段配置正文未正则命中后端字段；正文已打印在上，请人工核 base_url/wss/接入节点；若是密文→配 cipher-hook.js)');
        }
    } catch (e) { console.log('[objstore] scanBackend skip: ' + e); }
}

// ============================================================
// 工具：安全取方法「最佳重载」并替换（重载歧义/隐藏重载兜底，见指导书 §5）
// ============================================================
function _hookMethod(clazz, methodName, argSigs, impl, tag) {
    try {
        var mm = clazz[methodName];
        if (!mm) { console.log('[objstore][' + tag + '] ' + methodName + ' 不存在 skip'); return false; }
        var target = null;
        if (argSigs) { try { target = mm.overload.apply(mm, argSigs); } catch (e) { target = null; } }
        if (!target && mm.overloads && mm.overloads.length === 1) target = mm.overloads[0];
        if (target) { target.implementation = impl; }
        else { mm.implementation = impl; }
        return true;
    } catch (e) { console.log('[objstore][' + tag + '] hook ' + methodName + ' skip: ' + e); return false; }
}

Java.perform(function () {

    // ============ A. OkHttp3：拉对象存储配置的最常见路径（3.x/4.x 类名都试） ============
    // 抓 Request(URL 判对象存储) + Response(body 就是下发配置正文，里头藏真后端)。
    (function hookOkHttp() {
        var RealCall = null, usedClass = null;
        var candidates = ['okhttp3.RealCall', 'okhttp3.internal.connection.RealCall'];
        for (var i = 0; i < candidates.length; i++) {
            try { RealCall = Java.use(candidates[i]); usedClass = candidates[i]; break; } catch (e) { /* 试下一个 */ }
        }
        if (!RealCall) {
            console.log('[objstore][http] OkHttp3 RealCall 未找到(试了 ' + candidates.join(' / ') + ')，可能非 OkHttp 栈 → 看下面 URLConnection / InputStream 兜底');
            return;
        }
        var ok = _hookMethod(RealCall, 'execute', [], function () {
            var resp = this.execute();
            try {
                var req = this.request();
                var url = '' + req.url();
                if (!_isObjStore(url)) return resp;   // 只关心对象存储域，其它出站交给 coldstart-config-hook.js
                _noteObjStore(url, 'okhttp');
                // peekBody 不消费原 body，业务照常跑；上限 512KB 防大资源刷爆。
                try {
                    var peek = resp.peekBody(1024 * 512);
                    var rbytes = peek.bytes();
                    console.log('[objstore][http]   <- ' + resp.code() + ' 下发配置正文(' + rbytes.length + 'B): ' + _preview(rbytes, 2000));
                    _scanBackend(_asText(rbytes), url);
                } catch (e2) { console.log('[objstore][http]   resp-body skip(可能流式/二进制): ' + e2); }
            } catch (e) { console.log('[objstore][http] inspect skip: ' + e); }
            return resp;
        }, 'http');
        if (ok) console.log('[objstore][http] OkHttp3 ' + usedClass + '.execute hooked');
    })();

    // ============ B. java.net.URL.openConnection 兜底（HttpURLConnection 拉配置） ============
    try {
        var URL = Java.use('java.net.URL');
        var openImpl = function () {
            try {
                var u = '' + this.toString();
                if (_isObjStore(u)) _noteObjStore(u, 'URLConnection');
            } catch (e) {}
            return this.openConnection();
        };
        var doneU = _hookMethod(URL, 'openConnection', [], openImpl, 'url');
        if (doneU) console.log('[objstore][url] java.net.URL.openConnection hooked');
    } catch (e) { console.log('[objstore][url] URL hook skip: ' + e); }

    // ============ C. URLConnection.getInputStream 兜底：把对象存储响应流的正文读出来 ============
    // OkHttp 没命中、走 HttpURLConnection 时，配置正文要从 InputStream 读。这里只在 URL 命中对象存储时打。
    // 注意：HttpURLConnection 是抽象类，运行时实例多为 com.android.okhttp.internal.huc.* 子类；
    // 直接 hook 抽象类的 getInputStream 在多数 ART 上能命中子类实现(虚方法分发)，命不中则看 [stream] skip，
    // 此时正文兜底交给 A(OkHttp) / D(new String) 段，本段仅做"命中对象存储流"的标注。
    try {
        var HUC = Java.use('java.net.HttpURLConnection');
        var doneC = _hookMethod(HUC, 'getInputStream', [], function () {
            var is = this.getInputStream();
            try {
                var u = '' + this.getURL().toString();
                if (_isObjStore(u)) {
                    _noteObjStore(u, 'HttpURLConnection.getInputStream');
                    console.log('[objstore][stream] 命中对象存储响应流 <- ' + u + '   (正文经下面 D 段 new String / A 段 OkHttp 读取打印)');
                }
            } catch (e) {}
            return is;
        }, 'stream');
        if (doneC) console.log('[objstore][stream] HttpURLConnection.getInputStream hooked');
    } catch (e) { console.log('[objstore][stream] HttpURLConnection hook skip: ' + e); }

    // ============ D. 通用读流兜底：String(bytes,...) 构造里捞「含对象存储域/后端字段」的配置文本 ============
    // 很多样本把对象存储响应一次性 new String(byte[]) 解出来再解析；这里在构造 String 时旁路扫一眼，
    // 只对"文本且含对象存储 host 或后端字段"的内容报，避免刷屏。
    // 关键：<init> hook 里【绝不再构造任何 Java String】(否则自递归爆栈)。文本一律用纯 JS 解码 _bytesToJsTextRaw，
    // 并用 _IN_HOOK 跳过"本脚本自己"触发的构造(_preview/_asText 内部那次 String.$new)。
    try {
        var JStr = Java.use('java.lang.String');
        // 旁路扫描：只读 bytes，纯 JS 解码，绝不构造 Java String。返回值无人用，纯副作用打印。
        function _sideScan(bytes) {
            try {
                if (_IN_HOOK) return;                                  // 是本脚本自己在构造 String → 不扫，直接放行
                if (!bytes || bytes.length <= 8 || bytes.length >= 1024 * 512) return;
                if (!_looksText(bytes)) return;                        // 二进制不盲解
                var txt = _bytesToJsTextRaw(bytes);                    // 纯 JS UTF-8 解码，不落回 <init>
                if (!(OBJSTORE_HOST_RE.test(txt) || /("?(base_?url|wss?_?url|im_?url|gateway|node|endpoint|line)"?\s*[:=])/i.test(txt))) return;
                if (!_once('strbody|' + txt.substring(0, 120) + '|' + bytes.length)) return;
                console.log('\n[objstore][strbody] new String(byte[]) 解出疑似对象存储配置正文(' + bytes.length + 'B): ' + _preview(bytes, 2000));
                // 文本里若直接含对象存储 URL，登记锚点
                var um = txt.match(/(https?:\/\/[^\s"'<>,}\]]*(?:aliyuncs\.com|oss-accelerate|bcebos\.com|zos\.ctyun\.cn|myqcloud\.com)[^\s"'<>,}\]]*)/i);
                if (um && um[1]) _noteObjStore(um[1], 'new String(byte[])');
                _scanBackend(txt, 'new String(byte[]) 配置正文');
            } catch (e) { /* 旁路失败绝不影响原构造 */ }
        }
        // String(byte[], String charsetName)：先旁路扫，再调原构造(this.$init)。绝不调 $new。
        try {
            JStr.$init.overload('[B', 'java.lang.String').implementation = function (b, cs) {
                try { _sideScan(b); } catch (e) {}
                return this.$init(b, cs);
            };
        } catch (e) { console.log('[objstore][strbody] String([B,String) hook skip: ' + e); }
        // String(byte[], Charset)
        try {
            JStr.$init.overload('[B', 'java.nio.charset.Charset').implementation = function (b, cs) {
                try { _sideScan(b); } catch (e) {}
                return this.$init(b, cs);
            };
        } catch (e) { console.log('[objstore][strbody] String([B,Charset) hook skip: ' + e); }
        // String(byte[])：默认 charset 的一次性解码也很常见，一并兜上(同样只旁路、不构造)。
        try {
            JStr.$init.overload('[B').implementation = function (b) {
                try { _sideScan(b); } catch (e) {}
                return this.$init(b);
            };
        } catch (e) { console.log('[objstore][strbody] String([B) hook skip: ' + e); }
        console.log('[objstore][strbody] new String(byte[]) 构造旁路 hooked (只报含对象存储域/后端字段的文本；纯JS解码不自递归)');
    } catch (e) { console.log('[objstore][strbody] String hook skip: ' + e); }

    // ============ E. DNS 兜底：对象存储域名 → 解析到的边缘 IP（标注分发层、非源站） ============
    // 即使响应抓不到，命中对象存储域的 DNS 也固化了 bucket host = 调证锚点。
    try {
        var InetAddress = Java.use('java.net.InetAddress');
        var dnsImpl = function (host) {
            var res = this.getAllByName(host);
            try {
                var h = '' + host;
                if (_isObjStore(h) && _noteObjStore('http://' + h + '/', 'dns')) {
                    for (var i = 0; i < res.length; i++) {
                        var ip = '' + res[i].getHostAddress();
                        console.log('[objstore][dns]   ' + h + ' -> ' + ip + '   (对象存储边缘 IP=分发层、非源站；锚点用 bucket/账户，不写成真源站)');
                    }
                }
            } catch (e) {}
            return res;
        };
        var doneDns = _hookMethod(InetAddress, 'getAllByName', ['java.lang.String'], dnsImpl, 'dns');
        if (doneDns) console.log('[objstore][dns] InetAddress.getAllByName(String) hooked');
    } catch (e) { console.log('[objstore][dns] InetAddress hook skip: ' + e); }

    // ============ 汇总：随时 kill 前 / REPL 手动触发，把对象存储锚点 + 抽到的真后端打一遍 ============
    // 全程纯 JS(读账本 + console.log)，不调 Java 方法，可安全从 setTimeout 回调跑。
    function dumpObjStore() {
        console.log('\n========== [objstore] 多云对象存储「配置下发」锚点 + 穿透到真后端 ==========');
        console.log('[objstore][SUMMARY] [OBJSTORE锚点] 命中对象存储 bucket/账户 (' + ANCHORS.length + '):');
        for (var i = 0; i < ANCHORS.length; i++) {
            var a = ANCHORS[i];
            console.log('[objstore][SUMMARY]   [' + a.provider + '] bucket=' + a.bucket + '  host=' + a.host);
            console.log('[objstore][SUMMARY]       -> 调' + a.provider + ' bucket 创建者实名 + 对象上传/删除日志 + 访问 IP/UA + 绑定域名');
        }
        console.log('[objstore][SUMMARY] [BACKEND] 下发配置正文里抽到的真后端线索 (' + BACKENDS.length + '):');
        for (var j = 0; j < BACKENDS.length; j++) {
            console.log('[objstore][SUMMARY]   ' + BACKENDS[j].hit + '   <- ' + BACKENDS[j].src);
        }
        if (ANCHORS.length === 0) {
            console.log('[objstore][SUMMARY][未命中] 冷启动没抓到任何对象存储(OSS/BOS/ZOS/COS)请求。下一步：');
            console.log('[objstore][SUMMARY]   1) 确认用了 -f spawn（attach 会漏掉冷启动那几次配置拉取）');
            console.log('[objstore][SUMMARY]   2) 配置可能走 native/Flutter 栈 → 加 native-ssl-hook.js 看 SSL_read 明文 + socket-hook.js 看连接目标 IP');
            console.log('[objstore][SUMMARY]   3) 用 dns-hook.js / coldstart-config-hook.js 看是否有 *.aliyuncs/*.bcebos/*.zos.ctyun/*.myqcloud 的 DNS，再回头按命中域改 OBJSTORE_HOST_RE');
        } else if (BACKENDS.length === 0) {
            console.log('[objstore][SUMMARY][部分命中] 抓到对象存储锚点但配置正文没抽出后端：正文可能是加密的/二进制资源。');
            console.log('[objstore][SUMMARY]   下一步：配 cipher-hook.js(配置解密明文) / encoding-hook.js(Base64/JSON 信封) 还原正文，再人工核 base_url/wss/接入节点');
        }
        console.log('[objstore] 真源站提示：对象存储域是「多云分散的分发层」(抗封堵)，非真源站。');
        console.log('[objstore]   两类调证落点：① [OBJSTORE锚点] bucket名/账户 → 向云厂商调实名/上传日志(谁布的配置)；② [BACKEND] 配置正文里的真后端 → 穿透到真源站候选，人工并入台账复核。');
        console.log('========== [objstore] END ==========\n');
    }
    globalThis.dumpObjStore = dumpObjStore;
    setTimeout(dumpObjStore, 8000);
    console.log('[objstore] 已就绪。冷启动跑完(约8s)自动汇总一次；想随时汇总在 frida REPL 里输入: dumpObjStore()');
    console.log('[objstore] 识别域: 阿里OSS(*.aliyuncs.com/oss-accelerate) / 百度BOS(*.bcebos.com) / 天翼ZOS(*.zos.ctyun.cn) / 腾讯COS(*.myqcloud.com)');
});