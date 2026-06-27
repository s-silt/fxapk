// 用途：只读取证——抓 React Native 经典桥 JS→native 调用，固证 module名+methodId+实参(手机号/金额/baseURL/appKey)，尽力反查方法名。
// 适用：RN 0.6x–0.73 经典桥(Bridge)样本(assets 有 index.android.bundle、有 libreactnativejni.so)；0.74+ Bridgeless/TurboModule(JSI) 不适用,见末尾未命中告警。
// 跑：frida -U -f <包名> -l rn-bridge-native-hook.js --no-pause   或   frida -U -l rn-bridge-native-hook.js <包名>   (落盘: frida ... | tee /data/local/tmp/rn_bridge.log)
// 改：类名被加固改→看 [rn-bridge] 候选类 提示回填 TARGET;方法名反查不出→按打印的 getMethods() 索引人工对照;静默抓空→样本是新架构,回退 native-ssl/socket(见 notes)。
'use strict';

// 经典桥目标类:com.facebook.react.bridge.JavaModuleWrapper
// 关键:现代 RN(0.6x+) 签名是 invoke(int methodId, ReadableNativeArray parameters) —— 两参,无 JSInstance(仅极早期 RN 才有三参形)。
//      本脚本不靠固定形参下标,改为对 arguments 类型嗅探,两参/三参重载都兼容。
// 现场定位(被加固/混淆时):
//   Java.perform(function(){ Java.enumerateLoadedClasses({onMatch:function(n){ if(n.indexOf('JavaModuleWrapper')>=0) console.log(n); }, onComplete:function(){}}); });
var TARGET = 'com.facebook.react.bridge.JavaModuleWrapper';

Java.perform(function () {
    var _invokeCount = 0;          // invoke 命中计数:用于 30s 后判断「未命中→新架构」
    var _CAP = 4000;               // 打印条数上限,防刷爆 console
    var _emitted = 0;
    var _ARG_MAXB = 4096;          // 单个 byte[] 参数 hex 上限,超则截断(防御性,见 notes:ReadableArray 实际不产出 byte[])

    // --- 判断 toString 是否是无意义的 默认 Object@hex 形态(用于识别"反查没拿到真名") ---
    function isJunkToString(s) {
        if (s === null || s === undefined) return true;
        // 形如 com.facebook.react.bridge.JavaMethodWrapper@1a2b3c4d 视为无效方法名
        return /@[0-9a-fA-F]+$/.test('' + s);
    }

    // --- 二进制→hex / base64:明文/key/byte[] 一律走此,绝不盲 UTF-8(防御性保留,见 notes) ---
    function b2hex(bytes, max) {
        if (bytes === null || bytes === undefined) return null;
        try {
            var n = bytes.length, lim = (max && n > max) ? max : n, out = '';
            for (var i = 0; i < lim; i++) {
                var b = bytes[i] & 0xff;
                out += ('0' + b.toString(16)).slice(-2);
            }
            if (lim < n) out += '..(+' + (n - lim) + 'B truncated)';
            return out;
        } catch (e) { return '[b2hex err:' + e + ']'; }
    }
    function b2b64(bytes) {
        if (bytes === null || bytes === undefined) return null;
        try {
            var B64 = Java.use('android.util.Base64');
            return B64.encodeToString(bytes, 2 /* NO_WRAP */);
        } catch (e) { return null; }
    }

    // --- ReadableNativeArray → 取证用 JS 值:按类型如实读 ---
    // ReadableNativeArray: size()/getType(i)/getString/getDouble/getBoolean/getArray/getMap。
    // getType 返回 com.facebook.react.bridge.ReadableType 枚举:Null/Boolean/Number/String/Map/Array(无 byte[] 类型,故 b2hex 在此不会触发)。
    function dumpReadableArray(arr, depth) {
        var res = [];
        if (arr === null || arr === undefined) return res;
        try {
            var size = arr.size();
            for (var i = 0; i < size; i++) {
                res.push(dumpReadableValue(arr, i, depth));
            }
        } catch (e) {
            res.push('[array dump err:' + e + ']');
        }
        return res;
    }
    function dumpReadableValue(arr, i, depth) {
        try {
            var t = '' + arr.getType(i);   // toString → "Null"/"Boolean"/"Number"/"String"/"Map"/"Array"
            if (t === 'Null') return null;
            if (t === 'Boolean') return arr.getBoolean(i);
            if (t === 'Number') {
                // 金额/手机号常以 Number 下发:原样保留,不做精度裁剪
                return arr.getDouble(i);
            }
            if (t === 'String') {
                // 业务明文主战场:手机号/baseURL/appKey/订单号/token 多为 String,原样固证
                return '' + arr.getString(i);
            }
            if (t === 'Map') {
                if (depth >= 4) return '[Map depth>4 omitted]';
                return dumpReadableMap(arr.getMap(i), depth + 1);
            }
            if (t === 'Array') {
                if (depth >= 4) return '[Array depth>4 omitted]';
                return dumpReadableArray(arr.getArray(i), depth + 1);
            }
            return '[type=' + t + ']';
        } catch (e) {
            return '[value err idx=' + i + ':' + e + ']';
        }
    }
    function dumpReadableMap(map, depth) {
        var obj = {};
        if (map === null || map === undefined) return obj;
        try {
            var it = map.keySetIterator();
            while (it.hasNextKey()) {
                var k = '' + it.nextKey();
                try {
                    var t = '' + map.getType(k);
                    if (t === 'Null') obj[k] = null;
                    else if (t === 'Boolean') obj[k] = map.getBoolean(k);
                    else if (t === 'Number') obj[k] = map.getDouble(k);
                    else if (t === 'String') obj[k] = '' + map.getString(k);
                    else if (t === 'Map') obj[k] = (depth >= 4) ? '[Map depth>4]' : dumpReadableMap(map.getMap(k), depth + 1);
                    else if (t === 'Array') obj[k] = (depth >= 4) ? '[Array depth>4]' : dumpReadableArray(map.getArray(k), depth + 1);
                    else obj[k] = '[type=' + t + ']';
                } catch (e2) { obj[k] = '[key err:' + e2 + ']'; }
            }
        } catch (e) {
            obj['__dump_err__'] = '' + e;
        }
        return obj;
    }

    // --- methodId → 方法名反查:从 module 的 getMethods() 列表按索引取 ---
    // 关键事实:JavaModuleWrapper.getMethods() 返回 List<JavaMethodWrapper>,JavaMethodWrapper 没有公开 getName();
    //   原始脚本直接 nm.getName() 必抛 → 退到 ''+nm 打出无用的 Object@hash 还自称成功。此处分层取真名,拿不到就如实报"反查失败"。
    function resolveModuleAndMethod(wrapper, methodId) {
        var moduleName = null, methodName = null;
        // module 名:wrapper.getModule().getName()(NativeModule.getName() 是公开方法)
        try {
            var mod = wrapper.getModule();
            if (mod !== null && mod !== undefined) {
                try { moduleName = '' + mod.getName(); } catch (e1) {}
                if (moduleName === null) {
                    try { moduleName = '' + mod.getClass().getName(); } catch (e2) {}
                }
            }
        } catch (e) {}
        if (moduleName === null) {
            try { moduleName = '' + wrapper.getName(); } catch (e3) {}   // 退路
        }
        // method 名:getMethods() 下标取 JavaMethodWrapper,尽力反射出底层 reflect.Method 的名字
        try {
            var methods = wrapper.getMethods();   // List<JavaMethodWrapper>
            if (methods === null || methods === undefined) {
                methodName = '[getMethods() 返回 null,方法名反查失败:methodId=' + methodId + ',按 module 的 getMethods() 索引人工对照]';
            } else {
                var size = methods.size();
                if (methodId < 0 || methodId >= size) {
                    methodName = '[methodId ' + methodId + ' 越界(size=' + size + '),反查失败:按 module 的 getMethods() 索引人工对照]';
                } else {
                    var nm = methods.get(methodId);
                    methodName = extractMethodName(nm, methodId);
                }
            }
        } catch (e) {
            methodName = '[getMethods 反查失败:' + e + ';按 module 的 getMethods() 索引人工对照]';
        }
        return { module: moduleName, method: methodName };
    }

    // 从一个 JavaMethodWrapper 元素尽力抠出真实方法名;抠不到就如实报失败,不返回 Object@hash 污染证据。
    function extractMethodName(nm, methodId) {
        if (nm === null || nm === undefined) {
            return '[methods[' + methodId + '] 为 null,反查失败:按 getMethods() 索引人工对照]';
        }
        // 尝试 1:直接 getName()(多数 RN 版本 JavaMethodWrapper 无此公开方法,会抛,正常)
        try {
            var n1 = '' + nm.getName();
            if (!isJunkToString(n1)) return n1;
        } catch (e1) {}
        // 尝试 2:反射底层 java.lang.reflect.Method —— 遍历 JavaMethodWrapper 的字段找 Method 类型,取其 getName()
        try {
            var jClass = nm.getClass();
            var fields = jClass.getDeclaredFields();
            var MethodCls = Java.use('java.lang.reflect.Method');
            for (var i = 0; i < fields.length; i++) {
                var f = fields[i];
                try {
                    f.setAccessible(true);
                    var val = f.get(nm);
                    if (val !== null && val !== undefined) {
                        // 是不是 reflect.Method?用 isInstance 判定,避免误读其它字段
                        var isMethod = false;
                        try { isMethod = MethodCls.class.isInstance(val); } catch (ei) {}
                        if (isMethod) {
                            var castM = Java.cast(val, MethodCls);
                            var rn = '' + castM.getName();
                            if (!isJunkToString(rn)) return rn;
                        }
                    }
                } catch (ef) {}
            }
        } catch (e2) {}
        // 尝试 3:退而求其次看 toString 里有没有可读名字;若是默认 Object@hex 则判失败
        try {
            var s = '' + nm;
            if (!isJunkToString(s)) return '[原始toString] ' + s;
        } catch (e3) {}
        return '[methodId ' + methodId + ' 方法名反查失败:JavaMethodWrapper 无可读名(版本差异),按 module 的 getMethods() 索引人工对照]';
    }

    // --- 主 hook:JavaModuleWrapper.invoke ---
    try {
        var Wrapper = Java.use(TARGET);
        // 用 overloads.forEach 容版本差异(两参 / 极早期三参 都覆盖);不靠固定形参下标,改为对 arguments 类型嗅探。
        Wrapper.invoke.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var args = arguments;
                var self = this;
                // 只读:先如实固证,再原样放行,绝不改写参数与返回
                try {
                    if (_emitted < _CAP) {
                        _invokeCount += 1;
                        var methodId = -1, params = null;
                        // 类型嗅探:number → methodId;有 size()/getType() 的对象 → ReadableNativeArray(忽略 JSInstance/CatalystInstance 等)
                        for (var i = 0; i < args.length; i++) {
                            var a = args[i];
                            if (typeof a === 'number') { methodId = a; }
                            else if (a !== null && a !== undefined && a.size && a.getType) { params = a; }
                        }
                        var mm = resolveModuleAndMethod(self, methodId);
                        var dumped = dumpReadableArray(params, 0);
                        var rec = {
                            tag: 'rn-bridge',
                            module: mm.module,
                            methodId: methodId,
                            method: mm.method,
                            args: dumped,         // 手机号/金额/baseURL/appKey 等业务明文落在此
                            ts: Date.now()
                        };
                        // 唯一出口:console.log;外部 frida -l 可重定向到 /data/local/tmp 落盘
                        console.log('[rn-bridge] ' + JSON.stringify(rec));
                        _emitted += 1;
                        if (_emitted === _CAP) {
                            console.log('[rn-bridge] 已达打印上限 ' + _CAP + ' 条,后续不再打印(防刷爆);如需更多调高 _CAP。');
                        }
                    }
                } catch (e) {
                    console.log('[rn-bridge] skip: invoke 固证失败(不影响样本运行):' + e);
                }
                // 原样放行:Frida overload 对象可调用,apply 调原实现,不改参不改返回
                return ov.apply(self, args);
            };
        });
        console.log('[rn-bridge] JavaModuleWrapper.invoke hooked (' + TARGET + ');等待 JS→native 调用…');
    } catch (e) {
        console.log('[rn-bridge] skip: 找不到 ' + TARGET + ' → ' + e);
        // 类找不到→枚举候选回填,或样本根本不是经典桥
        try {
            var hits = [];
            Java.enumerateLoadedClassesSync().forEach(function (n) {
                if (n.indexOf('JavaModuleWrapper') >= 0) hits.push(n);
            });
            if (hits.length > 0) {
                console.log('[rn-bridge] 候选类(疑被加固/重打包改名,回填 TARGET 后重跑):');
                hits.forEach(function (h) { console.log('[rn-bridge]   候选 -> ' + h); });
            } else {
                console.log('[rn-bridge] 未发现任何 JavaModuleWrapper 类:样本很可能不是 RN 经典桥(见下方未命中分支)。');
            }
        } catch (e2) {
            console.log('[rn-bridge] skip: 候选类枚举失败:' + e2);
        }
    }

    // --- 30s 未命中诚实告警:不假装成功,直接给回退路线 ---
    setTimeout(function () {
        if (_invokeCount === 0) {
            console.log('[rn-bridge] 未命中:30s 内 JavaModuleWrapper.invoke 一次都没触发。');
            console.log('[rn-bridge] 判断:样本极可能是 RN 0.74+ Bridgeless/新架构(TurboModule+JSI),JS→native 直接走 C++ JSI,不经 Java 桥,本探针静默抓空。');
            console.log('[rn-bridge] 现场快速确认架构:');
            console.log('[rn-bridge]   - adb shell run-as <包名> 看 assets 有无 index.android.bundle;bundle 头/字符串含 "TurboModule"/"bridgeless" 多为新架构。');
            console.log('[rn-bridge]   - 进程内: Process.enumerateModules() 看有无 libhermes.so / libjsi.so / libreactnative.so(新架构常见聚合 so)。');
            console.log('[rn-bridge] 下一步(回退 native 层,绕开桥差异):');
            console.log('[rn-bridge]   1) native-ssl-unpinning + SSL_write/SSL_read hook → 抓明文 HTTP body(手机号/金额/baseURL 都在请求体)。');
            console.log('[rn-bridge]   2) native-socket hook(libc send/recv 或 java Socket)→ 抓非 HTTP 通道。');
            console.log('[rn-bridge]   3) 高难度:Interceptor.attach JSI HostFunction 调用点(需对 libreactnative/libhermes enumerateExports 定位 facebook::jsi 符号,多被 strip)。');
        } else {
            console.log('[rn-bridge] 命中正常:已固证 ' + _invokeCount + ' 次 invoke(打印 ' + _emitted + ' 条)。');
        }
    }, 30000);
});
