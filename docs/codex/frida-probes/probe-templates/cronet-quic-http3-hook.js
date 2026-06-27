// 用途：只读取证探针——抓 Chromium Cronet(QUIC/HTTP3)收发明文(URL/头/请求体/响应体)，覆盖头条/快手系等不走 OkHttp 的栈，做后端穿透+固证。
// 适用：已 root+frida-server 的真机/模拟器；目标 App 用 org.chromium.net.* (Cronet)联网；系统抓包只见加密 UDP/443 QUIC 时首选。
// 跑：frida -U -f <包名> -l cronet-quic-http3-hook.js --no-pause   (或 attach 后 frida -U <pid> -l 本文件)；落盘仅 adb pull /data/local/tmp，本探针不写盘不外发。
// 改：Cronet 常被 R8 relocate 混淆——若 [cronet] MISS，看启动日志 enumerateLoadedClasses 候选，把 CFG.builder/info/provider 回填；Callback 是抽象类、App 子类化覆盖了回调，本探针对实例「真实子类」下钩(不钩抽象基类，否则永不触发)。

'use strict';

// ===== 可回填的混淆类名(默认官方包名；被 relocate 后按启动扫描结果改这里) =====
// 注意：UrlRequest$Callback 不在此处直接 Java.use 钩——它是抽象类，App 必子类化并 @Override 回调，
//       钩抽象基类的方法实现「永不触发」(虚分派走子类)。本探针改为：在 Builder.build()/setUploadDataProvider
//       拿到 Callback / Provider 实例后，对其 $className(真实子类)下钩。
var CFG = {
    builder:  'org.chromium.net.UrlRequest$Builder',  // 含 addHeader/setHttpMethod/setUploadDataProvider/build
    info:     'org.chromium.net.UrlResponseInfo'       // getUrl/getHttpStatusCode/getAllHeaders(响应行/头取证用)
    // provider/callback 不写死类名：按实例真实子类动态钩(见下)
};

var TAG = '[cronet]';
var reqSeq = 0;                 // 给每笔请求编号
var ridByCallback = {};         // callback 实例 hashCode -> rid，跨回调串联(不污染 Java 对象，避免 this._x 在新 wrapper 上丢失)
var hookedClasses = {};         // 去重：同一真实子类只钩一次

// ---------- 工具：ByteBuffer -> Java byte[]，用 duplicate 只读副本，绝不动原 buffer 指针 ----------
function bbToBytes(bb) {
    try {
        var dup = bb.duplicate();          // 只读副本，原 buffer 的 position/limit 不受影响
        var n = dup.remaining();
        if (n <= 0) return null;
        var cap = n > 65536 ? 65536 : n;   // 防爆日志，单次最多取 64KB
        // 目标缓冲必须是真 Java byte[]；用 fill(0) 避免 undefined 元素被 marshalling 成异常字节
        var js = new Array(cap);
        for (var i = 0; i < cap; i++) js[i] = 0;
        var out = Java.array('byte', js);
        dup.get(out, 0, cap);              // ByteBuffer.get(byte[],int,int) 把 [pos,pos+cap) 写进 out(操作的是 dup，不碰原 bb)
        return { bytes: out, total: n, taken: cap };
    } catch (e) {
        console.log(TAG + ' bbToBytes skip: ' + e);
        return null;
    }
}
function bytesToHex(arr) {
    var s = '';
    for (var i = 0; i < arr.length; i++) {
        var v = arr[i] & 0xff;            // Java byte 有符号，& 0xff 还原 0..255
        s += (v < 16 ? '0' : '') + v.toString(16);
    }
    return s;
}
function bytesToB64(arr) {
    try {
        var B64 = Java.use('android.util.Base64');
        // arr 已是 Java byte[]，直接传；不要再 Java.array('byte', arr) 二次包裹(会对已是 Java 数组的对象抛错)
        return B64.encodeToString(arr, 2 /* NO_WRAP */);
    } catch (e) { return 'b64_err:' + e; }
}
function dumpBytes(label, info) {
    // hex+base64 双给，不盲 UTF-8(可能是 protobuf/密文/压缩流)
    if (!info) { console.log(TAG + ' ' + label + ' empty'); return; }
    var more = info.total > info.taken ? (' (+' + (info.total - info.taken) + 'B 截断)') : '';
    console.log(TAG + ' ' + label + ' len=' + info.total + more +
        ' hex=' + bytesToHex(info.bytes) + ' b64=' + bytesToB64(info.bytes));
}

// ---------- 混淆兜底：按关键字扫候选类名并打印回填 ----------
function enumerateCandidates(kw, label) {
    console.log(TAG + ' MISS: ' + label + ' 默认类未命中，enumerateLoadedClassesSync 扫候选(可能被 relocate)…');
    var hits = [];
    try {
        Java.enumerateLoadedClassesSync().forEach(function (cn) {
            if (kw.test(cn)) hits.push(cn);
        });
    } catch (e) { console.log(TAG + ' enumerate skip: ' + e); return; }
    if (hits.length) {
        console.log(TAG + ' 候选(回填后重跑)：');
        hits.slice(0, 40).forEach(function (h) { console.log(TAG + '   -> ' + h); });
    } else {
        console.log(TAG + ' 仍无候选：样本可能是纯 native Cronet(无 Java 封装层)。下一步：');
        console.log(TAG + '   Module.enumerateExports("libcronet*.so") 找 Cronet_UrlRequest_* / Cronet_UploadDataProvider_* 导出，Interceptor.attach 抓 native 层。');
        console.log(TAG + '   (libcronet 找法：Process.enumerateModules() 看名字含 cronet 的 .so，再 Module.enumerateExportsSync(name)。)');
    }
}

// ---------- 取对象 identity hash，用于跨回调串 rid(不写入 Java 对象本身) ----------
function idHash(obj) {
    try { return '' + Java.use('java.lang.System').identityHashCode(obj); }
    catch (e) { return null; }
}

Java.perform(function () {

    // ============ 0) UploadDataSink.onReadSucceeded —— 请求体最可靠落点 ============
    // provider.read() 返回 void 且常为异步：read 内只「发起」读取，真正数据由 App 写进 buffer 后调用
    // sink.onReadSucceeded(finalChunk) 告知 Cronet 本次写入字节数。此刻 buffer 已被 App flip(position=0,limit=本段长)，
    // 直接 duplicate 只读即可拿到本次上送的请求体——比在 read() 返回后猜 position 可靠得多。
    // 我们在下面拿到 ByteBuffer 引用后，于 onReadSucceeded 时机读它。
    // 实现：hookProviderRead 里在 read() 拦截时记下本次 byteBuffer，并钩该 provider 实例所属 sink 类的 onReadSucceeded。

    // ============ 1) UrlRequest$Builder：请求方法 + 请求头 + 注册 provider/callback 实例钩子 ============
    (function hookBuilder() {
        var Builder;
        try {
            Builder = Java.use(CFG.builder);
        } catch (e) {
            console.log(TAG + ' Builder skip(load fail): ' + e);
            enumerateCandidates(/UrlRequest\$Builder|UrlRequest_Builder|(cronet.*Builder)/i, 'UrlRequest$Builder');
            return;
        }

        // 1a) addHeader(String,String) —— 请求头(token/设备指纹/签名常在此)
        try {
            Builder.addHeader.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
                try { console.log(TAG + ' addHeader ' + k + ': ' + v); }
                catch (e) { console.log(TAG + ' addHeader log skip: ' + e); }
                return this.addHeader(k, v);
            };
            console.log(TAG + ' UrlRequest$Builder.addHeader hooked');
        } catch (e) { console.log(TAG + ' addHeader hook skip: ' + e); }

        // 1b) setHttpMethod(String) —— 请求方法(GET/POST…)
        try {
            Builder.setHttpMethod.overload('java.lang.String').implementation = function (m) {
                try { console.log(TAG + ' setHttpMethod ' + m); }
                catch (e) { console.log(TAG + ' method log skip: ' + e); }
                return this.setHttpMethod(m);
            };
            console.log(TAG + ' UrlRequest$Builder.setHttpMethod hooked');
        } catch (e) { console.log(TAG + ' setHttpMethod hook skip: ' + e); }

        // 1c) setUploadDataProvider(UploadDataProvider, Executor) —— 拿 provider 实例，转手钩其真实子类 read
        //     overload 第一参用接口全名 'org.chromium.net.UploadDataProvider'(签名按接口声明，混淆后接口名可能变——
        //     若该 overload 抛错，对 Builder enumerateMethods 看 setUploadDataProvider 真实参数类型回填)
        try {
            Builder.setUploadDataProvider.overload('org.chromium.net.UploadDataProvider', 'java.util.concurrent.Executor')
                .implementation = function (provider, exec) {
                try {
                    console.log(TAG + ' setUploadDataProvider provider=' +
                        (provider ? provider.$className : 'null') + ' (请求体走 provider.read/onReadSucceeded)');
                    if (provider) hookProviderRead(provider.$className);
                } catch (e) { console.log(TAG + ' provider attach skip: ' + e); }
                return this.setUploadDataProvider(provider, exec);
            };
            console.log(TAG + ' UrlRequest$Builder.setUploadDataProvider hooked');
        } catch (e) {
            console.log(TAG + ' setUploadDataProvider hook skip: ' + e +
                ' (overload 参数可能被混淆：Builder enumerateMethods 看 setUploadDataProvider 真实签名回填)');
        }

        // 1d) build()/构造里传入的 Callback —— 是请求响应回调，必须钩实例真实子类(抽象基类钩不到)
        //     不同版本 Callback 经由 UrlRequest$Builder 构造器或 build 传入；这里 hook 构造器拿首参 Callback 实例。
        //     若你的版本 Callback 经别处传入，按 [cronet] MISS 提示用 enumerateCandidates 的候选定位。
        try {
            var ctors = Builder.$init.overloads;
            var armed = 0;
            ctors.forEach(function (ov) {
                try {
                    ov.implementation = function () {
                        var args = Array.prototype.slice.call(arguments);
                        try {
                            for (var i = 0; i < args.length; i++) {
                                var a = args[i];
                                if (a && a.$className && /Callback/i.test(a.$className)) {
                                    hookCallbackInstance(a.$className);
                                }
                            }
                        } catch (e) { console.log(TAG + ' ctor scan skip: ' + e); }
                        return ov.apply(this, args);
                    };
                    armed++;
                } catch (e) {}
            });
            console.log(TAG + ' UrlRequest$Builder.<init> hooked (' + armed + ' overloads) —— 用于捕获 Callback 实例真实子类');
        } catch (e) {
            console.log(TAG + ' Builder.<init> hook skip: ' + e +
                ' —— 若 Callback 未被钩到，[cronet] MISS 用 enumerateCandidates 候选定位 Callback 子类后手动 hookCallbackInstance(类名)');
            enumerateCandidates(/UrlRequest\$Callback|Cronet.*Callback|cronet.*Callback/i, 'UrlRequest$Callback');
        }
    })();

    // ============ provider.read 真实子类钩(抓请求体明文) ============
    function hookProviderRead(clsName) {
        if (!clsName || hookedClasses['P:' + clsName]) return;
        hookedClasses['P:' + clsName] = true;
        var pcls;
        try { pcls = Java.use(clsName); }
        catch (e) { console.log(TAG + ' provider.read load skip(' + clsName + '): ' + e); return; }

        // read(UploadDataSink, ByteBuffer) 返回 void；同步 provider 在 read 内填好并 sink.onReadSucceeded，
        // 异步 provider 则 read 返回时 buffer 仍空——所以两点都覆盖：read 后即时尝试 + 钩 sink.onReadSucceeded 兜异步。
        try {
            pcls.read.overload('org.chromium.net.UploadDataSink', 'java.nio.ByteBuffer')
                .implementation = function (sink, byteBuffer) {
                var posBefore = -1;
                try { posBefore = byteBuffer.position(); } catch (e) {}
                // 钩本次 sink 的 onReadSucceeded(兜异步同步两种)：在它触发时 buffer 已 flip，读到的就是本段请求体
                try { if (sink) hookSinkOnReadSucceeded(sink.$className, byteBuffer, posBefore); } catch (e) {}
                this.read(sink, byteBuffer);     // void 方法，放行；不要用返回值
                // 同步 provider 兜底：read 返回时若 position 已前移，[posBefore,posAfter) 即本次写入
                try {
                    var dup = byteBuffer.duplicate();
                    var posAfter = dup.position();
                    if (posBefore >= 0 && posAfter > posBefore) {
                        dup.position(posBefore);
                        dup.limit(posAfter);
                        dumpBytes('uploadBody(sync)', bbToBytes(dup));
                    } else {
                        console.log(TAG + ' uploadBody: read 返回时无新增字节(异步 provider，等 onReadSucceeded)，pos ' +
                            posBefore + '->' + posAfter);
                    }
                } catch (e) { console.log(TAG + ' uploadBody sync read skip: ' + e); }
                return; // read 原型为 void
            };
            console.log(TAG + ' provider.read hooked on ' + clsName);
        } catch (e) {
            console.log(TAG + ' provider.read hook skip(' + clsName + '): ' + e +
                ' (子类 read 参数可能不同：Java.use("' + clsName + '") 后 enumerateMethods 看 read 真实 overload 回填)');
        }
    }

    // ---- 异步请求体兜底：钩 sink 实例真实类的 onReadSucceeded，触发时读已 flip 的 buffer ----
    function hookSinkOnReadSucceeded(sinkCls, byteBuffer, posBefore) {
        if (!sinkCls || hookedClasses['S:' + sinkCls]) return;
        hookedClasses['S:' + sinkCls] = true;
        try {
            var scls = Java.use(sinkCls);
            // onReadSucceeded(boolean finalChunk)
            scls.onReadSucceeded.overload('boolean').implementation = function (fin) {
                try {
                    // 触发时 App 已把请求体写进 byteBuffer 并(通常)flip；duplicate 只读，从 0..limit 取
                    var dup = byteBuffer.duplicate();
                    var lim = dup.limit(), pos = dup.position();
                    if (lim > pos) {
                        dumpBytes('uploadBody(async,final=' + fin + ')', bbToBytes(dup));
                    } else if (posBefore >= 0) {
                        // 未 flip 的实现：尝试读 [posBefore, current limit)
                        try { dup.position(posBefore); dumpBytes('uploadBody(async2)', bbToBytes(dup)); }
                        catch (e2) { console.log(TAG + ' uploadBody async2 skip: ' + e2); }
                    } else {
                        console.log(TAG + ' uploadBody(async): buffer 无可读区间 pos=' + pos + ' lim=' + lim);
                    }
                } catch (e) { console.log(TAG + ' uploadBody async log skip: ' + e); }
                return this.onReadSucceeded(fin);
            };
            console.log(TAG + ' UploadDataSink.onReadSucceeded hooked on ' + sinkCls);
        } catch (e) {
            console.log(TAG + ' onReadSucceeded hook skip(' + sinkCls + '): ' + e +
                ' (sink onReadSucceeded 签名可能不同：enumerateMethods 看真实参数回填)');
        }
    }

    // ============ 2) Callback 真实子类：响应行/头(onResponseStarted) + 响应体(onReadCompleted) ============
    function hookCallbackInstance(cbCls) {
        if (!cbCls || hookedClasses['C:' + cbCls]) return;
        hookedClasses['C:' + cbCls] = true;
        var Cb;
        try { Cb = Java.use(cbCls); }
        catch (e) { console.log(TAG + ' Callback load skip(' + cbCls + '): ' + e); return; }

        // 2a) onResponseStarted(UrlRequest, UrlResponseInfo) —— 响应行 + 全部响应头；按 callback identity 派 rid
        try {
            Cb.onResponseStarted.overload('org.chromium.net.UrlRequest', CFG.info)
                .implementation = function (req, info) {
                try {
                    var key = idHash(this);
                    var rid = ++reqSeq;
                    if (key) ridByCallback[key] = rid;   // 存在外部 map，不写 Java 对象(this._x 在新 wrapper 上会丢)
                    var url = info.getUrl();
                    var code = info.getHttpStatusCode();
                    console.log(TAG + ' [#' + rid + '] onResponseStarted url=' + url + ' status=' + code);
                    var headers = info.getAllHeaders();  // Map<String, List<String>>
                    if (headers) {
                        var it = headers.entrySet().iterator();
                        var MapEntry = Java.use('java.util.Map$Entry');
                        while (it.hasNext()) {
                            var en = Java.cast(it.next(), MapEntry);
                            console.log(TAG + ' [#' + rid + '] respHeader ' + en.getKey() + ': ' + en.getValue());
                        }
                    }
                } catch (e) { console.log(TAG + ' onResponseStarted log skip: ' + e); }
                return this.onResponseStarted(req, info);
            };
            console.log(TAG + ' Callback.onResponseStarted hooked on ' + cbCls);
        } catch (e) { console.log(TAG + ' onResponseStarted hook skip(' + cbCls + '): ' + e); }

        // 2b) onReadCompleted(UrlRequest, UrlResponseInfo, ByteBuffer) —— 响应体明文(分段到来)
        //     此回调时 buffer 由 Cronet flip(position=0,limit=本段长)，duplicate 只读直接取；按 rid 串接
        try {
            Cb.onReadCompleted.overload('org.chromium.net.UrlRequest', CFG.info, 'java.nio.ByteBuffer')
                .implementation = function (req, info, byteBuffer) {
                try {
                    var key = idHash(this);
                    var rid = (key && ridByCallback[key]) ? ridByCallback[key] : '?';
                    var url = '';
                    try { url = info.getUrl(); } catch (e) {}
                    console.log(TAG + ' [#' + rid + '] onReadCompleted url=' + url + ' (响应体分段，按 #rid 串接)');
                    dumpBytes('[#' + rid + '] respChunk', bbToBytes(byteBuffer));
                } catch (e) { console.log(TAG + ' onReadCompleted log skip: ' + e); }
                return this.onReadCompleted(req, info, byteBuffer);
            };
            console.log(TAG + ' Callback.onReadCompleted hooked on ' + cbCls);
        } catch (e) { console.log(TAG + ' onReadCompleted hook skip(' + cbCls + '): ' + e); }
    }

    // 暴露到全局，便于真机首跑后按 enumerateCandidates 打印的子类名手动补钩：
    //   在 frida REPL 里(本脚本已注入)调用：hookCallbackInstance('a.b.c'); hookProviderRead('d.e.f');
    try { globalThis.hookCallbackInstance = hookCallbackInstance; } catch (e) {}
    try { globalThis.hookProviderRead = hookProviderRead; } catch (e) {}

    console.log(TAG + ' armed. 若多为 skip/MISS：1) Cronet 被 relocate→按候选回填 CFG / 手动 hookCallbackInstance|hookProviderRead；');
    console.log(TAG + '   2) 纯 native Cronet→Module.enumerateExports("libcronet*.so") 抓 Cronet_UrlRequest_*。');
    console.log(TAG + '   抓到什么→调证：addHeader/respHeader=token/设备指纹/签名(定人)；method+url=真后端端点(穿透);');
    console.log(TAG + '   uploadBody=上送内容(受害人数据/指令)；respChunk=回包(下发话术/收款户)。hex+b64 落 /data/local/tmp 固证。');
});
