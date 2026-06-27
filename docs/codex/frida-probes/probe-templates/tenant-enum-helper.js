// tenant-enum-helper.js — 用已知/枚举的企业号重放 coldstart 标出的配置端点，对比不同企业号下发的真实后端(客服/聊天/支付)，把配置分发层穿透到源站
// 适用：无账号只拿到 CDN/OSS 配置分发层；已定位「按企业号下发的配置端点」，想用不同企业号逼出每个租户对应的真源站
// 跑：frida -U -f <包名> -l tenant-enum-helper.js -q   然后在 frida REPL 里：enumTenants()   （先把下面 CONFIG_ENDPOINT/TENANT_LIST 等改成现场实际值）
// 改：CONFIG_ENDPOINT/HTTP_METHOD/CONTENT_TYPE/TENANT_PARAM/BODY_TEMPLATE/EXTRA_HEADERS/buildBody 全部按 coldstart 抓到的端点真实结构改；签名字段从 cipher-hook.js 反推
//
// ========================= 合规红线（主动 recon，必读，违规即停） =========================
// 1) 仅限【有合法授权】的办案场景，针对已立案目标 app 的配置端点；非授权目标禁止运行本脚本。
// 2) 枚举=主动外联，会在对方服务器留日志、可能触发风控/打草惊蛇。务必先评估是否惊动嫌疑人；
//    【优先用案卷里已知的真实企业号】，盲爆字典是下策且可能徒劳(无效号不下发)。
// 3) 只读配置：不高频请求、不做破坏性/写操作、不下单不发起任何业务动作。
// 4) 全程在授权设备/授权网络；请求与响应原文按证据规范留存(本脚本 console 全量打印即为留痕)。
// ========================================================================================
'use strict';

// ====== 现场必改：把 coldstart-config-hook.js 抓到的端点结构填到这里 ======
var CONFIG_ENDPOINT = 'https://CHANGE-ME.example.com/api/config';  // coldstart 里标 [TENANT?] 的那个 URL（去掉 query 里的企业号，由脚本拼）
var HTTP_METHOD     = 'POST';                                       // 'GET' 或 'POST'，按抓到的实际
var CONTENT_TYPE    = 'application/json';                           // POST 时的 body 类型
var TENANT_PARAM    = 'tenant';                                     // 企业号参数名（如 corp/company/appId/code），GET 拼 query / POST 进 body
var BODY_TEMPLATE   = '{"' + 'tenant' + '":"__TENANT__"}';          // POST body 模板，__TENANT__ 会被替换；多字段/签名就改这里或改 buildBody
var EXTRA_HEADERS   = { /* 'X-App-Version': '1.2.3', 'User-Agent': '...' */ }; // coldstart 抓到的关键头，原样照抄

// 企业号清单：!!! 优先填案卷里【已知真实企业号】(受害人输入过的) !!! 字典枚举为下策。
var TENANT_LIST = [
    // 'flyno5', 'flyno6', ...   <- 现场填，案卷号码优先
];

// 响应里「真后端线索」字段：命中即说明这个企业号有效、下发了源站。
var BACKEND_RE = /("?(base_?url|api_?url|host|domain|wss?:|ws_?url|chat|kefu|im_?url|pay|gateway|server|line|node|backend)"?\s*[:=]\s*"?)([^"\s,}]+)/ig;

// 节流：每个企业号之间至少间隔(ms)，避免高频触发风控(红线#3)。
var THROTTLE_MS = 800;

function _extractBackends(text) {
    var found = [], m;
    BACKEND_RE.lastIndex = 0;
    while ((m = BACKEND_RE.exec(text)) !== null) {
        found.push(m[2] + m[3]);
        if (BACKEND_RE.lastIndex === m.index) BACKEND_RE.lastIndex++;
    }
    return found;
}

// ---- 现场可改：构造 body（多字段/加签名时在这里改）。默认按 BODY_TEMPLATE 替换 __TENANT__。----
function buildBody(tenant) {
    return BODY_TEMPLATE.replace('__TENANT__', tenant);
    // 若端点要签名：var ts = Date.now(); var sign = ...(从 cipher-hook.js 反推算法); return JSON.stringify({tenant:tenant, ts:ts, sign:sign});
}
function buildUrl(tenant) {
    if (HTTP_METHOD === 'GET') {
        var sep = CONFIG_ENDPOINT.indexOf('?') >= 0 ? '&' : '?';
        return CONFIG_ENDPOINT + sep + TENANT_PARAM + '=' + encodeURIComponent(tenant);
    }
    return CONFIG_ENDPOINT;
}

// ---- 兼容 OkHttp3.x(create(MediaType,String)) 与 OkHttp4.x(create(String,MediaType)) 两种重载顺序 ----
function _makeBody(RequestBody, MediaType, ctype, bodyStr) {
    var mt = null;
    try { mt = MediaType.parse(ctype); } catch (e) { mt = null; } // parse 非法 ctype 可能返回 null
    // 先试 3.x 顺序 create(MediaType, String)
    try { return RequestBody.create(mt, bodyStr); } catch (e3) {}
    // 再试 4.x 顺序 create(String, MediaType)
    try { return RequestBody.create(bodyStr, mt); } catch (e4) {}
    // 兜底：用 byte[] 重载 create(MediaType, byte[]) / create(byte[], MediaType)
    try {
        var bytes = Java.use('java.lang.String').$new(bodyStr).getBytes('UTF-8');
        try { return RequestBody.create(mt, bytes); } catch (eb3) {}
        return RequestBody.create(bytes, mt);
    } catch (eb) {
        throw new Error('RequestBody.create 三种重载都不可用: ' + eb);
    }
}

Java.perform(function () {
    // 仅做存在性探测；真正的 Java 调用都在 Java.perform 内的 tick 里做（见 enumTenants）。
    var hasOkHttp = false;
    try {
        Java.use('okhttp3.OkHttpClient');
        Java.use('okhttp3.Request$Builder');
        Java.use('okhttp3.MediaType');
        Java.use('okhttp3.RequestBody');
        hasOkHttp = true;
    } catch (e) {
        console.log('[tenant] 未找到 okhttp3（目标可能非 OkHttp 栈）。skip 内重放；改用 printCurlTemplate() 输出 curl 模板，在授权设备外部重放。 err=' + e);
    }

    // 单个企业号重放：!!! 必须在 Java.perform 作用域内调用 !!!（由 step() 保证）
    function fireOne(tenant) {
        try {
            var OkHttpClient = Java.use('okhttp3.OkHttpClient');
            var RequestB     = Java.use('okhttp3.Request$Builder');
            var MediaType    = Java.use('okhttp3.MediaType');
            var RequestBody  = Java.use('okhttp3.RequestBody');
            // 复用 app 自己的 OkHttpClient 类：继承其默认证书/代理栈，最不易被对方风控识别为异常客户端。
            var client = OkHttpClient.$new();

            var rb = RequestB.$new();
            rb.url(buildUrl(tenant));
            for (var h in EXTRA_HEADERS) { rb.header(h, EXTRA_HEADERS[h]); }
            if (HTTP_METHOD === 'POST') {
                var body = _makeBody(RequestBody, MediaType, CONTENT_TYPE, buildBody(tenant));
                rb.post(body);
            } else {
                rb.get();
            }
            var req = rb.build();
            var resp = client.newCall(req).execute();
            var code = resp.code();
            var text = '' + resp.body().string();
            var backends = _extractBackends(text);
            console.log('\n[tenant] === 企业号 ' + tenant + ' -> HTTP ' + code + ' ===');
            if (backends.length > 0) {
                console.log('[tenant][HIT] 有效企业号！下发的真实后端线索:');
                backends.forEach(function (b) { console.log('[tenant][HIT]   ' + b + '   (= 该租户源站: 客服/聊天/支付，落地查域名/IP归属)'); });
            } else {
                console.log('[tenant][miss] 未下发后端(可能无效号/默认配置)。响应前 600 字:');
            }
            console.log('[tenant]   resp: ' + (text.length > 600 ? text.substring(0, 600) + '...<+' + (text.length - 600) + '>' : text));
        } catch (e) {
            console.log('[tenant] 企业号 ' + tenant + ' 重放失败 skip: ' + e + '  (检查 CONFIG_ENDPOINT/签名/header 是否按 coldstart 抓到的真实结构改对)');
        }
    }

    // REPL 入口：enumTenants()。逐个、带节流地打端点。
    // 关键修复：setTimeout 回调运行在【未自动 attach 到 VM】的线程上下文，直接调 Java 方法会抛
    // 'this thread is not attached to the VM'。因此每个 tick 都必须用 Java.perform 重新进入 VM 作用域。
    function enumTenants() {
        if (!hasOkHttp) {
            console.log('[tenant][skip] 非 OkHttp 栈，内重放不可用。用 printCurlTemplate() 在授权设备外部重放。');
            return;
        }
        if (TENANT_LIST.length === 0) {
            console.log('[tenant][未配置] TENANT_LIST 为空。先填案卷里已知的真实企业号(优先)或授权字典，再调 enumTenants()。');
            console.log('[tenant] 提醒红线：枚举=主动外联会留日志/触风控，确认已授权且不会惊动嫌疑人再跑。');
            return;
        }
        if (CONFIG_ENDPOINT.indexOf('CHANGE-ME') >= 0) {
            console.log('[tenant][未配置] CONFIG_ENDPOINT 还是占位符。先用 coldstart-config-hook.js 抓到真实端点结构填进来。');
            return;
        }
        console.log('[tenant] 开始枚举 ' + TENANT_LIST.length + ' 个企业号 @ ' + CONFIG_ENDPOINT + ' (节流 ' + THROTTLE_MS + 'ms/个)');
        var idx = 0;
        function step() {
            // 每个 tick 重新进入 Java.perform：保证当前线程已 attach VM，否则 fireOne 里的 Java 调用必崩。
            Java.perform(function () {
                if (idx >= TENANT_LIST.length) {
                    console.log('\n[tenant] 枚举结束。把所有 [HIT] 的后端域名/IP 汇总 = 该团伙在跑的源站清单；同后端被多个企业号共用 = 同一摊子归并证据。');
                    return;
                }
                fireOne(TENANT_LIST[idx]);
                idx++;
                setTimeout(step, THROTTLE_MS);
            });
        }
        step();
    }

    global.enumTenants = enumTenants;
    global.printCurlTemplate = _printCurl;
    console.log('[tenant] 已就绪。红线已知悉后，确认 CONFIG_ENDPOINT/TENANT_LIST 填妥，在 frida REPL 里输入: enumTenants()');
    console.log('[tenant] 离线/换设备重放备份模板：printCurlTemplate()');
});

// curl 重放模板（内重放不可用/想换设备时的备份；同样受合规红线约束）。
function _printCurl() {
    console.log('\n[tenant] ===== curl 重放模板（授权设备外部重放；__TENANT__ 换成企业号）=====');
    console.log('# 红线：仅授权目标、低频、只读配置、留存响应原文');
    if (typeof HTTP_METHOD !== 'undefined' && HTTP_METHOD === 'GET') {
        console.log('curl -sS "' + CONFIG_ENDPOINT + (CONFIG_ENDPOINT.indexOf('?') >= 0 ? '&' : '?') + TENANT_PARAM + '=__TENANT__" \\');
        console.log('  -H "User-Agent: <抄 coldstart 抓到的 UA>"');
    } else {
        console.log('curl -sS -X POST "' + CONFIG_ENDPOINT + '" \\');
        console.log('  -H "Content-Type: ' + CONTENT_TYPE + '" \\');
        console.log('  -H "User-Agent: <抄 coldstart 抓到的 UA>" \\');
        console.log('  --data \'' + BODY_TEMPLATE + '\'');
    }
    console.log('# 对比每个 __TENANT__ 的响应里 base_url/host/wss/pay 字段 = 各租户真源站');
    console.log('[tenant] ===== END curl 模板 =====');
}