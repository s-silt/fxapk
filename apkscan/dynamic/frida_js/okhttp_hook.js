
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
