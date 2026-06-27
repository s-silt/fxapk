// coldstart-config-hook.js — 冷启动/无账号阶段聚合记录所有出站URL+响应体+DNS/SNI/connect目标+内嵌配置，专捞登录前可见域名/IP/配置端点并标注疑似租户配置端点
// 适用：杀猪盘冷启动先拉一圈配置(CDN/OSS/配置中心)，真后端只在按企业号下发的配置响应里；无账号想把登录前能拿的域名/IP/配置端点一次抓全
// 跑：frida -U -f <包名> -l coldstart-config-hook.js -q   （必须 -f spawn，attach 已起进程会漏掉最早几个请求）
// 改：(1) TENANT_HINT_RE/RESP_BACKEND_RE 现场按目标参数名调；(2) 纯Flutter/native看 [conn] socket兜底给IP；(3) 密文响应配 cipher-hook.js / native-ssl-hook.js；(4) ASSET_NAME_RE 放宽可全量dump assets；(5) OkHttp 类名按版本：3.x=okhttp3.RealCall，4.x=okhttp3.internal.connection.RealCall（本脚本两者都试）
'use strict';

// ---- 通用工具：bytes -> hex / base64 / 安全预览 ----
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
// 文本预览：可打印就给 UTF-8，否则给 hex（绝不盲 UTF-8 二进制）。
function _preview(bytes, cap) {
    try {
        if (!bytes || bytes.length === 0) return '<empty>';
        var printable = 0, n = Math.min(bytes.length, 64);
        for (var i = 0; i < n; i++) {
            var b = bytes[i] & 0xff;
            if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127)) printable++;
        }
        if (printable / n > 0.85) {
            var s = Java.use('java.lang.String').$new(bytes, 'UTF-8');
            s = '' + s;
            return s.length > cap ? s.substring(0, cap) + '...<+' + (s.length - cap) + '>' : s;
        }
        return 'hex:' + _hex(bytes).substring(0, cap * 2) + (bytes.length > cap ? '...' : '') + ' b64:' + _b64(bytes).substring(0, 64);
    } catch (e) { return '<preview-fail:' + e + '>'; }
}

// ---- 启发式：哪个端点像「按企业号下发的配置端点」 ----
// URL/参数里含租户语义 关键词 → 疑似输入企业号即触发的配置拉取入口。
var TENANT_HINT_RE = /(tenant|corp|company|enterprise|merchant|agent|invite|channel|appid|app_id|app-id|\bcode\b|orgid|org_id|biz|brand|config|init|bootstrap|gateway|domain)/i;
// 响应体里出现「真后端线索」关键词 → 这个配置响应确实在下发源站。
var RESP_BACKEND_RE = /("?(base_?url|api_?url|host|domain|wss?:|ws_?url|chat|kefu|im_?url|pay|gateway|server|cdn|line|node|backend)"?\s*[:=])/i;
// assets 里疑似配置文件（默认只看这些，避免全量刷屏）。
var ASSET_NAME_RE = /(config|setting|conf|\.json$|\.cfg$|\.properties$|\.xml$|env|host|domain|server|init|bootstrap|app\.|api)/i;

// ---- 内存账本：去重 + 收尾时统一汇总（登录前全集一眼可看）----
var SEEN = { url: {}, host: {}, ip: {}, asset: {}, sp: {}, tenant: {} };
function _note(bucket, key, extra) {
    if (!key) return false;
    if (SEEN[bucket][key]) return false;
    SEEN[bucket][key] = extra || true;
    return true;
}
function _hostOf(u) {
    try { var m = ('' + u).match(/^[a-z]+:\/\/([^\/:?#]+)/i); return m ? m[1] : null; } catch (e) { return null; }
}
function _flagTenant(url, where) {
    if (url && TENANT_HINT_RE.test('' + url)) {
        if (_note('tenant', '' + url, where)) {
            console.log('[coldstart][TENANT?] 疑似按企业号下发的配置端点 (' + where + '): ' + url);
            console.log('[coldstart]            -> 交给 tenant-enum-helper.js：用案卷里/枚举的企业号打这个端点，对比不同企业号返回的真后端');
        }
    }
}

// ---- 工具：安全拿一个方法的「最佳重载」并替换 implementation ----
// 若方法只有 1 个重载，直接 .implementation 也行；但部分系统类有同名隐藏/桥接重载，
// 直接 .implementation 会抛 'has more than one overload'。本函数优先按给定签名取 overload，
// 取不到再退回「唯一重载」或最后退回 .implementation，保证不因重载问题整段失效。
function _hookMethod(clazz, methodName, argSigs, impl, tag) {
    try {
        var m = clazz[methodName];
        if (!m) { console.log('[' + tag + '] ' + methodName + ' 不存在 skip'); return false; }
        var target = null;
        if (argSigs) {
            try { target = m.overload.apply(m, argSigs); } catch (e) { target = null; }
        }
        if (!target) {
            // 退回：唯一重载用 overloads[0]，多重载且没给签名则用 .implementation（可能抛，已被外层 catch 兜住）
            if (m.overloads && m.overloads.length === 1) target = m.overloads[0];
        }
        if (target) { target.implementation = impl; }
        else { m.implementation = impl; }
        return true;
    } catch (e) {
        console.log('[' + tag + '] hook ' + methodName + ' skip: ' + e);
        return false;
    }
}

Java.perform(function () {

    // ============ A. 出站请求：OkHttp3（最常见，3.x/4.x 类名都试） ============
    // 抓 Request(URL/header/body) + Response(body)，body 是按企业号下发真后端的关键载体。
    (function hookOkHttp() {
        var RealCall = null, usedClass = null;
        var candidates = ['okhttp3.RealCall', 'okhttp3.internal.connection.RealCall'];
        for (var i = 0; i < candidates.length; i++) {
            try { RealCall = Java.use(candidates[i]); usedClass = candidates[i]; break; } catch (e) { /* 试下一个 */ }
        }
        if (!RealCall) {
            console.log('[coldstart][http] OkHttp3 RealCall 未找到(试了 ' + candidates.join(' / ') + ')，可能非OkHttp栈，看下面 URLConnection / socket 兜底');
            return;
        }
        var Buffer = Java.use('okio.Buffer');
        function _reqBody(req) {
            try {
                var body = req.body();
                if (body === null) return null;
                var buf = Buffer.$new();
                body.writeTo(buf);
                return buf.readByteArray();
            } catch (e) { return null; }
        }
        // execute()/enqueue() 都走 getResponseWithInterceptorChain；hook execute() 同步取响应最稳。
        var ok = _hookMethod(RealCall, 'execute', [], function () {
            var resp = this.execute();
            try {
                var req = this.request();
                var url = '' + req.url();
                var method = '' + req.method();
                if (_note('url', method + ' ' + url)) {
                    console.log('\n[coldstart][http] ' + method + ' ' + url);
                    var hh = req.headers();
                    for (var i = 0; i < hh.size(); i++) {
                        console.log('[coldstart][http]   ' + hh.name(i) + ': ' + hh.value(i));
                    }
                    var rb = _reqBody(req);
                    if (rb) console.log('[coldstart][http]   req-body: ' + _preview(rb, 600));
                }
                _note('host', _hostOf(url));
                _flagTenant(url, 'okhttp-url');
                // 响应体：peekBody 不消费原 body，业务照常跑。
                try {
                    var peek = resp.peekBody(1024 * 256); // 256KB 上限（long 参数，JS number 自动转）
                    var rbytes = peek.bytes();
                    var pv = _preview(rbytes, 1200);
                    console.log('[coldstart][http]   <- ' + resp.code() + ' resp-body: ' + pv);
                    if (RESP_BACKEND_RE.test(pv)) {
                        console.log('[coldstart][http][BACKEND!] 响应体含真后端线索(host/url/wss/pay) <- ' + url);
                    }
                } catch (e2) { console.log('[coldstart][http]   resp-body skip: ' + e2); }
            } catch (e) { console.log('[coldstart][http] inspect skip: ' + e); }
            return resp;
        }, 'coldstart][http');
        if (ok) console.log('[coldstart][http] OkHttp3 ' + usedClass + '.execute hooked');
    })();

    // ============ B. 出站请求：java.net.URL / HttpURLConnection 兜底 ============
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function () {
            try {
                var u = '' + this.toString();
                if (_note('url', 'URLConn ' + u)) {
                    console.log('[coldstart][url] openConnection: ' + u);
                    _note('host', _hostOf(u));
                    _flagTenant(u, 'urlconnection');
                }
            } catch (e) {}
            return this.openConnection();
        };
        console.log('[coldstart][url] java.net.URL.openConnection hooked');
    } catch (e) { console.log('[coldstart][url] URL hook skip: ' + e); }

    // ============ C. DNS / SNI：真实解析到的域名/IP（旁路 CDN 的直连后端）============
    // InetAddress.getAllByName(static)：域名 -> 解析出的真实 IP，落地可查归属/机房/备案。
    // 显式 .overload('java.lang.String') 防部分 ROM 暴露包私有 getAllByName(String,InetAddress) 触发 'more than one overload'。
    try {
        var InetAddress = Java.use('java.net.InetAddress');
        var hookImpl = function (host) {
            var res = this.getAllByName(host);
            try {
                if (_note('host', '' + host)) console.log('[coldstart][dns] resolve: ' + host);
                for (var i = 0; i < res.length; i++) {
                    var ip = '' + res[i].getHostAddress();
                    if (_note('ip', host + ' -> ' + ip)) console.log('[coldstart][dns]   -> ' + ip + '  (查IP归属/机房/备案 = 后端线索)');
                }
            } catch (e) {}
            return res;
        };
        var done = _hookMethod(InetAddress, 'getAllByName', ['java.lang.String'], hookImpl, 'coldstart][dns');
        if (done) console.log('[coldstart][dns] InetAddress.getAllByName(String) hooked');
    } catch (e) { console.log('[coldstart][dns] InetAddress hook skip: ' + e); }

    // ============ D. 真实 connect 目标：socket 兜底（Flutter/native/非OkHttp 也能给 IP）============
    // 即使加密栈看不到明文，connect 的目标 IP:port 永远拿得到 → 直连后端线索。
    try {
        var Socket = Java.use('java.net.Socket');
        Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function (addr, to) {
            try {
                var s = '' + addr;
                if (_note('ip', 'conn ' + s)) console.log('[coldstart][conn] socket.connect -> ' + s + '  (真实出站目标 IP:port)');
            } catch (e) {}
            return this.connect(addr, to);
        };
        console.log('[coldstart][conn] Socket.connect hooked');
    } catch (e) { console.log('[coldstart][conn] Socket hook skip: ' + e); }

    // ============ E. 内嵌配置：assets / raw 资源（硬编码 baseUrl/appId/默认企业号）============
    try {
        var AssetManager = Java.use('android.content.res.AssetManager');
        AssetManager.open.overload('java.lang.String').implementation = function (name) {
            try {
                var n = '' + name;
                if (ASSET_NAME_RE.test(n) && _note('asset', n)) {
                    console.log('[coldstart][asset] app 读取内嵌资源: ' + n + '  (可能含硬编码 baseUrl/appId/默认企业号 -> 用 adb pull/解包 看全文)');
                    _flagTenant(n, 'asset-name');
                }
            } catch (e) {}
            return this.open(name);
        };
        console.log('[coldstart][asset] AssetManager.open hooked');
    } catch (e) { console.log('[coldstart][asset] AssetManager hook skip: ' + e); }

    // ============ F. SharedPreferences 读：冷启动期已写入的 baseUrl/host/企业号 ============
    try {
        var SPImpl = Java.use('android.app.SharedPreferencesImpl');
        SPImpl.getString.implementation = function (key, def) {
            var val = this.getString(key, def);
            try {
                var k = '' + key;
                if (val !== null && /(url|host|domain|server|api|tenant|corp|company|enterprise|appid|code|gateway|chat|pay|ws)/i.test(k)) {
                    if (_note('sp', k + '=' + val)) {
                        console.log('[coldstart][sp] prefs ' + k + ' = ' + val);
                        if (/^[a-z]+:\/\//i.test('' + val)) { _note('host', _hostOf(val)); _flagTenant(val, 'sharedprefs'); }
                    }
                }
            } catch (e) {}
            return val;
        };
        console.log('[coldstart][sp] SharedPreferences.getString hooked');
    } catch (e) { console.log('[coldstart][sp] SharedPreferences hook skip: ' + e); }

    // ============ 汇总：随时 kill 前/手动触发，把登录前全集打一遍 ============
    // 注意：本函数全程纯 JS(读 SEEN + console.log)，不调任何 Java 方法，故可安全从 setTimeout 回调里跑（无需再 Java.perform）。
    function dumpColdstart() {
        function keys(o) { var a = []; for (var k in o) a.push(k); return a; }
        console.log('\n========== [coldstart] 登录前可见全集（无账号能拿到的分发层 + 枚举入口） ==========');
        console.log('[coldstart][SUMMARY] 域名 hosts (' + keys(SEEN.host).length + '): ' + keys(SEEN.host).join(', '));
        console.log('[coldstart][SUMMARY] IP/connect (' + keys(SEEN.ip).length + '): ' + keys(SEEN.ip).join(' | '));
        console.log('[coldstart][SUMMARY] URL端点 (' + keys(SEEN.url).length + '):');
        keys(SEEN.url).forEach(function (u) { console.log('[coldstart][SUMMARY]   ' + u); });
        console.log('[coldstart][SUMMARY][TENANT?] 疑似按企业号下发的配置端点 (' + keys(SEEN.tenant).length + '):');
        keys(SEEN.tenant).forEach(function (u) { console.log('[coldstart][SUMMARY][TENANT?]   ' + u); });
        console.log('[coldstart][SUMMARY] 内嵌配置 assets: ' + keys(SEEN.asset).join(', '));
        console.log('[coldstart][SUMMARY] prefs: ' + keys(SEEN.sp).join(' | '));
        if (keys(SEEN.url).length === 0 && keys(SEEN.ip).length === 0) {
            console.log('[coldstart][SUMMARY][未命中] 冷启动没抓到任何出站/连接。下一步：');
            console.log('[coldstart][SUMMARY]   1) 确认用了 -f spawn（attach 会漏最早请求）');
            console.log('[coldstart][SUMMARY]   2) 纯 native/Flutter 栈 -> 加 native-ssl-hook.js 看 SSL_write，并看本脚本 [conn] 是否给了 IP');
            console.log('[coldstart][SUMMARY]   3) 有 pinning/反frida 秒退 -> 先上 unpinning，再重跑本脚本');
        }
        console.log('========== [coldstart] END ==========\n');
        console.log('[coldstart] 真源站提示：以上是「无账号可见的配置分发层」。真业务后端(客服/聊天/支付)常只在「按有效企业号下发的配置响应」里 -> 拿 [TENANT?] 端点交 tenant-enum-helper.js 枚举/重放。');
    }
    // 暴露给 REPL（在 frida 提示符里输入 dumpColdstart() 手动汇总）。
    global.dumpColdstart = dumpColdstart;
    setTimeout(dumpColdstart, 8000);
    console.log('[coldstart] 已就绪。冷启动跑完(约8s)自动汇总一次；想随时汇总在 frida REPL 里输入: dumpColdstart()');
});