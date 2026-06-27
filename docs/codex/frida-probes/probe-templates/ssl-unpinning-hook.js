// ssl-unpinning-hook.js — 通用 SSL/证书脱钩:拆 pinning 让 HTTPS 在中间人代理可见(其它抓包探针的前置)。
// 适用:症状④另一面——装了系统 CA + 配了代理 app 仍连不上/代理只见 CONNECT 不见明文/fxapk 内置脱钩没拦住自定义 pinning。
// 跑:frida -U -f <包名> -l ssl-unpinning-hook.js -q   (须配套:系统 CA 信任 + 中间人代理 mitmproxy/Charles/burp,否则脱了钩也无处看流量)
// 改:① TrustManagerImpl.verifyChain 随版本多 overload,本探针全通杀;② native(.so/BoringSSL)层钉扎 Java 脱不掉,改用 native-ssl-hook.js 直接抓 SSL_read/SSL_write;③ 和 anti-detection-hook.js 一起注入。
//
// 线索导向:本探针不直接产线索,但脱钩+中间人后,http-url-hook.js 才能看见明文 URL/host ->
// 真实源站域名/IP、按企业号下发配置的真实业务后端(客服/支付/聊天)、登录前配置拉取的真实 URL。绝不假装脱钩——脱不到的面打"未命中"并指向 native 探针。

Java.perform(function () {
    // 统一日志:每拆一处钉扎打一行,便于现场确认"到底哪条 pinning 被绕过了"。
    function ok(where) { try { console.log('[unpin] OK   ' + where); } catch (e) {} }
    function miss(where, e) { try { console.log('[unpin] MISS ' + where + ' skip: ' + e); } catch (e2) {} }

    // 改:全信任 TM / AllowAll HostnameVerifier 在脚本顶层"只注册一次"并复用——
    //     原写法把 registerClass 放在各自 hook 闭包里,同名类重复注册会抛 'class already registered',
    //     一旦抛出该 hook 整段 MISS。提前注册一次,后面所有 hook 共用。
    var TrustAllTM = null, AllowAllHV = null;
    try {
        var X509TM = Java.use('javax.net.ssl.X509TrustManager');
        TrustAllTM = Java.registerClass({
            name: 'com.apkscan.TrustAllManager',
            implements: [X509TM],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},  // 不抛 = 全信任
                getAcceptedIssuers: function () { return Java.array('java.security.cert.X509Certificate', []); }
            }
        });
    } catch (e) { miss('registerClass TrustAllManager', e); }
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        AllowAllHV = Java.registerClass({
            name: 'com.apkscan.AllowAllHostnameVerifier',
            implements: [HostnameVerifier],
            methods: { verify: function (hostname, session) { return true; } }
        });
    } catch (e) { miss('registerClass AllowAllHostnameVerifier', e); }

    // --- 1) OkHttp3 CertificatePinner.check:最常见的 pinning 入口,直接放空 ---
    // app 用 CertificatePinner.add(host, "sha256/...") 钉扎;check 抛异常即断连。全 overload 改成 no-op。
    try {
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        var hookedCP = false;
        // check(String, List) / check(String, Certificate[]) 等 —— 全 overload 通杀。
        CertPinner.check.overloads.forEach(function (ov) {
            try {
                ov.implementation = function () {
                    try { console.log('[unpin] OkHttp CertificatePinner.check bypassed: ' + (arguments.length ? arguments[0] : '')); } catch (e) {}
                    return;  // 不抛 = 钉扎通过
                };
                hookedCP = true;
            } catch (e) {}
        });
        // 老接口 check$okhttp(部分 4.x 内部名)—— 存在才 hook,.overloads 通杀。
        try {
            var cpk = CertPinner['check$okhttp'];
            if (cpk && cpk.overloads) { cpk.overloads.forEach(function (ov) { try { ov.implementation = function () { return; }; } catch (e) {} }); }
        } catch (e) {}
        if (hookedCP) ok('okhttp3.CertificatePinner.check');
    } catch (e) { miss('okhttp3.CertificatePinner', e); }

    // --- 2) X509TrustManager:自定义 TrustManager(app 自己比对证书链)通杀 ---
    // 很多 app 不用 CertificatePinner,而是 new 一个 X509TrustManager 在 checkServerTrusted 里手写比对。
    // 把 SSLContext.init 的 TrustManager 数组整体换成上面注册的全信任 TM(覆盖面最广的一招)。全 overload 通杀。
    try {
        if (!TrustAllTM) throw new Error('TrustAllManager 未注册,跳过 SSLContext.init 注入');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManagers = [TrustAllTM.$new()];
        var hookedInit = false;
        SSLContext.init.overloads.forEach(function (ov) {
            // 只接管标准三参重载 init(KeyManager[], TrustManager[], SecureRandom);其它重载(罕见)放行。
            if (ov.argumentTypes.length !== 3) return;
            try {
                ov.implementation = function (km, tm, sr) {
                    try { console.log('[unpin] SSLContext.init -> TrustAllManager 注入'); } catch (e) {}
                    return ov.call(this, km, TrustManagers, sr);
                };
                hookedInit = true;
            } catch (e) {}
        });
        if (hookedInit) ok('javax.net.ssl.X509TrustManager (SSLContext.init 全信任)');
        else miss('SSLContext.init', '无三参重载可 hook');
    } catch (e) { miss('X509TrustManager/SSLContext.init', e); }

    // --- 3) TrustManagerImpl.verifyChain:Android 系统默认 TM 的链校验(系统层兜底)---
    // 即便 app 没自定义 TM,系统的 TrustManagerImpl.verifyChain 仍会校验;签名随 API 版本变,全 overload 通杀,
    // 返回原始证书链(untrustedChain,第 1 参)= 认为链可信。改:某版本签名特殊就在这里加对应 overload。
    try {
        var TMImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        var hookedVC = false;
        TMImpl.verifyChain.overloads.forEach(function (ov) {
            try {
                ov.implementation = function () {
                    try { console.log('[unpin] TrustManagerImpl.verifyChain bypassed (host=' + (arguments.length >= 4 ? arguments[3] : '?') + ')'); } catch (e) {}
                    return arguments[0];  // 返回传入的 untrustedChain = 链照单全收
                };
                hookedVC = true;
            } catch (e) {}
        });
        // 老路径 checkTrustedRecursive(部分 ROM)—— 改:用 .overloads 通杀,避免裸 .overload 在无该方法时抛。
        try {
            var ctr = TMImpl.checkTrustedRecursive;
            if (ctr && ctr.overloads) {
                var ArrayList = Java.use('java.util.ArrayList');
                ctr.overloads.forEach(function (ov) { try { ov.implementation = function () { return ArrayList.$new(); }; } catch (e) {} });
            }
        } catch (e) {}
        if (hookedVC) ok('conscrypt.TrustManagerImpl.verifyChain');
    } catch (e) { miss('TrustManagerImpl.verifyChain', e); }

    // --- 4) Conscrypt Platform.checkServerTrusted:部分 app 走 Conscrypt 的额外校验面 ---
    try {
        var Platform = Java.use('com.android.org.conscrypt.Platform');
        var hookedPlat = false;
        var pcst = Platform['checkServerTrusted'];
        if (pcst && pcst.overloads) {
            pcst.overloads.forEach(function (ov) { try { ov.implementation = function () { return; }; hookedPlat = true; } catch (e) {} });
        }
        if (hookedPlat) ok('conscrypt.Platform.checkServerTrusted');
    } catch (e) { miss('conscrypt.Platform', e); }

    // --- 5) HostnameVerifier:host 名校验(SAN/CN 比对)放空,防 host 不匹配断连 ---
    try {
        if (!AllowAllHV) throw new Error('AllowAllHostnameVerifier 未注册');
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        // 静态默认 verifier
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (v) {
            try { console.log('[unpin] HttpsURLConnection.setDefaultHostnameVerifier -> AllowAll'); } catch (e) {}
            return this.setDefaultHostnameVerifier(AllowAllHV.$new());
        };
        // 实例级 setHostnameVerifier(部分 API 有,缺则 try 兜住)
        try {
            HttpsURLConnection.setHostnameVerifier.implementation = function (v) {
                return this.setHostnameVerifier(AllowAllHV.$new());
            };
        } catch (e) {}
        ok('javax.net.ssl.HostnameVerifier (AllowAll)');
    } catch (e) { miss('HostnameVerifier', e); }

    // --- 6) OkHttp HostnameVerifier (OkHostnameVerifier.verify):OkHttp 自带 host 校验 ---
    // 改:用 .overloads 通杀——OkHttp 各版本有 verify(String,SSLSession) 与 verify(String,X509Certificate) 两套。
    try {
        var OkHV = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
        var hookedOk = false;
        OkHV.verify.overloads.forEach(function (ov) {
            try {
                ov.implementation = function () {
                    try { console.log('[unpin] OkHostnameVerifier.verify bypassed: ' + (arguments.length ? arguments[0] : '')); } catch (e) {}
                    return true;
                };
                hookedOk = true;
            } catch (e) {}
        });
        if (hookedOk) ok('okhttp3 OkHostnameVerifier.verify');
    } catch (e) { miss('OkHostnameVerifier', e); }

    // --- 7) WebViewClient.onReceivedSslError:H5 端的证书错误(杀猪盘多是 WebView 壳)---
    // app 重写 onReceivedSslError 后若没 proceed,H5 站点 TLS 错误就白屏;这里强制 proceed() 放行。
    try {
        var WVClient = Java.use('android.webkit.WebViewClient');
        WVClient.onReceivedSslError.overload(
            'android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError'
        ).implementation = function (view, handler, error) {
            try { console.log('[unpin] WebViewClient.onReceivedSslError -> proceed (H5 钉扎绕过)'); } catch (e) {}
            try { handler.proceed(); } catch (e) {}  // 强制信任,H5 继续加载
            return;
        };
        ok('android.webkit.WebViewClient.onReceivedSslError');
    } catch (e) { miss('WebViewClient.onReceivedSslError', e); }

    // --- 8) TrustKit / 第三方 pinning 库(部分金融/诈骗 app 引入)---
    try {
        var TK = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        TK.verify.overloads.forEach(function (ov) { try { ov.implementation = function () { return true; }; } catch (e) {} });
        ok('TrustKit OkHostnameVerifier');
    } catch (e) { miss('TrustKit (未引入即正常)', e); }

    // --- 收尾:没脱到的面 -> 指向 native 探针,绝不假装全脱钩 ---
    try {
        console.log('[unpin] 脱钩布防完毕。若注入后 HTTPS 仍连不上/代理无明文:');
        console.log('[unpin]   1) 确认已装系统 CA + 配好中间人代理(mitmproxy/Charles/burp)——脱钩只拆 app 侧校验,流量得有代理接;');
        console.log('[unpin]   2) 上面全 MISS = 该 app 不走 Java TLS,钉扎在 native(.so/BoringSSL)层 -> 换 native-ssl-hook.js 直接抓 SSL_read/SSL_write 明文,绕开钉扎本身;');
        console.log('[unpin]   3) Flutter app 用自带 BoringSSL,Java 脱钩对它无效,同样走 native-ssl-hook.js(hook libflutter.so 的 ssl_verify)。');
    } catch (e) {}
});
