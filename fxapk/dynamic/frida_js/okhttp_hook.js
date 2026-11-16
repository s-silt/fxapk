
// 取证用途：对取证样本自身在分析机上做运行时观测，产出端点/密钥/独特串等线索，不面向任何第三方基础设施。
// apkscan 运行时凭据采集（best-effort）：OkHttp 加密前明文 request dump（真实 host + token）。
var _coverage = (typeof globalThis !== 'undefined' && globalThis.__fxapkProbeCoverage) || {
    perform: function (_family, callback) {
        try { if (typeof Java !== 'undefined' && (!('available' in Java) || Java.available)) Java.perform(callback); } catch (_) {}
    },
    attempted: function () {}, installed: function () {}, registrationError: function () {},
    trigger: function () {}, drop: function () {}, truncated: function () {}
};
_coverage.perform('okhttp', function () {
    var _cred_count = 0;
    var _CRED_CAP = 1500;
    function credEmit(p) {
        try {
            if (_cred_count >= _CRED_CAP) { _coverage.drop('okhttp', 'events'); return; }
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
            if (t.length > n) _coverage.truncated('okhttp', 'events');
            return t.length > n ? t.slice(0, n) : t;
        } catch (e) { return null; }
    }
    // 从 okhttp3.Request 提取 url/method/headers/body 明文（best-effort，逐项 try/catch）。
    function dumpRequest(req, where) {
        try {
            if (req === null || req === undefined) return;
            if (_cred_count >= _CRED_CAP) { _coverage.drop('okhttp', 'events'); return; }
            var url = null, method = null, headersObj = {}, bodyText = null;
            try { url = '' + req.url().toString(); } catch (e) {}
            try { method = '' + req.method(); } catch (e) {}
            // headers：抓 Authorization/Cookie/token 类敏感头（全量回传上限保护）。
            try {
                var hs = req.headers();
                var n = hs.size();
                if (n > 40) _coverage.truncated('okhttp', 'events');
                for (var i = 0; i < n && i < 40; i++) {
                    var hn = '' + hs.name(i);
                    var hv = '' + hs.value(i);
                    headersObj[hn] = clipStr(hv, 512);
                }
            } catch (e) {}
            // RequestBody may consume a stream or retain its sink. Never replay it.
            credEmit({url: url, method: method, headers: headersObj, body: bodyText,
                      body_capture_status: 'not_read_non_interference',
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
                _coverage.attempted('okhttp', 'execute');
                RealCall.execute.implementation = function () {
                    _coverage.trigger('okhttp', 'execute');
                    try {
                        var req = null;
                        try { req = this.request(); } catch (e) {}
                        if (req === null) { try { req = this.originalRequest.value; } catch (e2) {} }
                        dumpRequest(req, cn + '.execute');
                    } catch (e) {}
                    return this.execute();
                };
                _coverage.installed('okhttp', 'execute');
                hookedRealCall = true;
                console.log('[apkscan] OkHttp ' + cn + '.execute hooked');
            } else _coverage.registrationError('okhttp', 'execute');
        } catch (e) {
            _coverage.registrationError('okhttp', 'execute');
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
                    var proceed = Chain.proceed.overload('okhttp3.Request');
                    _coverage.attempted('okhttp', 'proceed');
                    proceed.implementation = function (request) {
                        _coverage.trigger('okhttp', 'proceed');
                        try {
                            var idx = -1;
                            try { idx = this.index.value; } catch (e) {}
                            // 只在调用链最外层（index<=0）dump 一次原始 request。
                            if (idx <= 0) dumpRequest(request, cn + '.proceed');
                        } catch (e) {}
                        return this.proceed(request);
                    };
                    _coverage.installed('okhttp', 'proceed');
                    console.log('[apkscan] OkHttp ' + cn + '.proceed hooked');
                } catch (e) {
                    _coverage.registrationError('okhttp', 'proceed');
                    console.log('[apkscan] OkHttp ' + cn + '.proceed overload skip: ' + e);
                }
            } else _coverage.registrationError('okhttp', 'proceed');
        } catch (e) {
            _coverage.registrationError('okhttp', 'proceed');
            console.log('[apkscan] OkHttp ' + cn + ' chain hook skip: ' + e);
        }
    });
});
