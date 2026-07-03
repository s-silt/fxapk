/*
 * 用途: [只读取证] 抓非 SQLCipher 加密库(MMKV/Realm/WCDB)的运行时密钥, hex+base64 固证, 供脱机解密整库 IM/转账记录。纯被动, 不改写/不外发。
 * 适用: rooted 安卓, 样本本地用 MMKV/Realm/WCDB 加密落库(会话/流水/账本), 常规 SQLCipher PRAGMA key hook 不命中时。
 * 跑:  frida -U -f <包名> -l mmkv-realm-wcdb-key-hook.js --no-pause   (或 frida -U <pid> -l ...); 输出只在 console, 落盘仅 /data/local/tmp。
 * 改:  类名/方法被混淆或 native strip→sqlite3_key 返 null 时, 按各 hook 注释里的 enumerateLoadedClasses / enumerateMethods / enumerateExports 现场定位后回填。
 */
'use strict';

var TAG = '[lib-key]';

// ---- 工具: Java byte[] → hex, 绝不盲 UTF-8 ----
// 说明: Frida 里 Java byte[] 入参是 array-like, 有 .length 且可索引; Java byte 有符号(-128..127), &0xff 归一。
function bytesToHex(bytes) {
    try {
        if (bytes === null || bytes === undefined) return null;
        var out = '';
        for (var i = 0; i < bytes.length; i++) {
            var b = bytes[i] & 0xff;
            out += ('0' + b.toString(16)).slice(-2);
        }
        return out;
    } catch (e) { return '<hex-fail:' + e + '>'; }
}

// ---- 工具: Java String → hex(取 UTF-16 码元), 不盲 UTF-8 ----
// 注意: MMKV cryptKey 可能是二进制塞进 String, 码元 hex 为最佳努力; 二进制 key 优先以 native 段 sqlite3_key 为准。
function strToHex(s) {
    try {
        if (s === null || s === undefined) return null;
        var out = '';
        for (var i = 0; i < s.length; i++) {
            var c = s.charCodeAt(i);
            if (c > 0xff) { out += ('000' + c.toString(16)).slice(-4); }
            else { out += ('0' + c.toString(16)).slice(-2); }
        }
        return out;
    } catch (e) { return '<hex-fail:' + e + '>'; }
}

// 简易 base64(基于 hex), 无外部依赖
function hexToB64(hex) {
    try {
        if (hex === null || hex === undefined) return null;
        var tbl = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        var bytes = [];
        for (var i = 0; i + 1 < hex.length; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
        var out = '';
        for (var j = 0; j < bytes.length; j += 3) {
            var b0 = bytes[j], b1 = (j + 1 < bytes.length) ? bytes[j + 1] : 0, b2 = (j + 2 < bytes.length) ? bytes[j + 2] : 0;
            out += tbl[b0 >> 2];
            out += tbl[((b0 & 3) << 4) | (b1 >> 4)];
            out += (j + 1 < bytes.length) ? tbl[((b1 & 15) << 2) | (b2 >> 6)] : '=';
            out += (j + 2 < bytes.length) ? tbl[b2 & 63] : '=';
        }
        return out;
    } catch (e) { return '<b64-fail:' + e + '>'; }
}

// dumpKey: hex===null 表示"未传 key"; hex===''(len=0) 表示"传了空 key / 未加密", 二者区分打印
function dumpKey(label, hex) {
    if (hex === null || hex === undefined) { console.log(TAG + ' ' + label + ' key=<未传/null>'); return; }
    var len = (hex.length / 2) | 0;
    if (len === 0) { console.log(TAG + ' ' + label + ' key=<空串 len=0 → 该实例未加密>'); return; }
    console.log(TAG + ' ' + label + ' len=' + len + ' hex=' + hex + ' b64=' + hexToB64(hex));
}

// 打印 Java 调用栈(辅助判库类型/落库路径), 失败不阻断
function javaStack() {
    try {
        return Java.use('android.util.Log').getStackTraceString(
            Java.use('java.lang.Exception').$new());
    } catch (e) { return '<stack-skip:' + e + '>'; }
}

Java.perform(function () {

    // ============ MMKV: com.tencent.mmkv.MMKV (mmkvWithID / defaultMMKV / reKey 携带 cryptKey) ============
    // 抓到什么: MMKV 实例的 cryptKey 明文(脱机用它解 mmkv/<id> 二进制文件, 还原 KV 会话/配置)
    // 溯源线索: key 即交付物→脱机解 MMKV 整库; 命中即确认用了 MMKV→腾讯系存储, 归属可分析
    // 混淆/未命中: 类名被改→Java.enumerateLoadedClasses() 搜 'mmkv'(忽略大小写)回填类名;
    //              方法签名变动→jadx 看 mmkvWithID/defaultMMKV 重载, 对照下方 overload 参数回填。
    try {
        var MMKV = Java.use('com.tencent.mmkv.MMKV');

        // 重载1: mmkvWithID(String id, int mode, String cryptKey)
        try {
            MMKV.mmkvWithID.overload('java.lang.String', 'int', 'java.lang.String')
                .implementation = function (id, mode, cryptKey) {
                try {
                    console.log(TAG + ' MMKV.mmkvWithID(id=' + id + ', mode=' + mode + ')');
                    dumpKey('MMKV[' + id + '] cryptKey', strToHex(cryptKey));
                } catch (e) { console.log(TAG + ' MMKV.mmkvWithID(3) skip: ' + e); }
                return this.mmkvWithID(id, mode, cryptKey);   // 原样透传, 不改 key
            };
        } catch (e) { console.log(TAG + ' MMKV.mmkvWithID(3) bind skip: ' + e); }

        // 重载2: mmkvWithID(String id, int mode, String cryptKey, String rootPath)
        try {
            MMKV.mmkvWithID.overload('java.lang.String', 'int', 'java.lang.String', 'java.lang.String')
                .implementation = function (id, mode, cryptKey, rootPath) {
                try {
                    console.log(TAG + ' MMKV.mmkvWithID(id=' + id + ', mode=' + mode + ', rootPath=' + rootPath + ')');
                    dumpKey('MMKV[' + id + '] cryptKey', strToHex(cryptKey));
                } catch (e) { console.log(TAG + ' MMKV.mmkvWithID(4) skip: ' + e); }
                return this.mmkvWithID(id, mode, cryptKey, rootPath);
            };
        } catch (e) { console.log(TAG + ' MMKV.mmkvWithID(4) bind skip: ' + e); }

        // 重载3: defaultMMKV(int mode, String cryptKey) —— 默认实例的加密入口, 常被使用
        try {
            MMKV.defaultMMKV.overload('int', 'java.lang.String')
                .implementation = function (mode, cryptKey) {
                try {
                    console.log(TAG + ' MMKV.defaultMMKV(mode=' + mode + ')');
                    dumpKey('MMKV[default] cryptKey', strToHex(cryptKey));
                } catch (e) { console.log(TAG + ' MMKV.defaultMMKV(2) skip: ' + e); }
                return this.defaultMMKV(mode, cryptKey);
            };
        } catch (e) { console.log(TAG + ' MMKV.defaultMMKV(2) bind skip: ' + e); }

        // 兜底: reKey(String) 运行时换密钥, 也抓
        try {
            MMKV.reKey.overload('java.lang.String').implementation = function (newKey) {
                try { dumpKey('MMKV reKey(new)', strToHex(newKey)); }
                catch (e) { console.log(TAG + ' MMKV.reKey skip: ' + e); }
                return this.reKey(newKey);
            };
        } catch (e) { console.log(TAG + ' MMKV.reKey bind skip: ' + e); }

    } catch (e) {
        console.log(TAG + ' MMKV class skip: ' + e +
            '  | 未命中→下一步: Java.enumerateLoadedClasses 搜 mmkv 确认是否加载/改名, 或样本未用 MMKV。');
    }

    // ============ Realm: io.realm.RealmConfiguration$Builder.encryptionKey(byte[64]) ============
    // 抓到什么: Realm 库的 64 字节 encryptionKey(脱机用它打开 .realm 文件还原对象/记录)
    // 溯源线索: key 即交付物→脱机解 Realm 整库; 命中即确认用了 Realm 加密存储
    // 混淆/未命中: 类名被 shrink→Java.enumerateLoadedClasses 搜 'RealmConfiguration';
    //              方法名混淆→jadx 找传入 byte[] 且校验 length==64 的 Builder 方法回填。
    try {
        var Builder = Java.use('io.realm.RealmConfiguration$Builder');
        Builder.encryptionKey.overload('[B').implementation = function (key) {
            try {
                var hex = bytesToHex(key);
                var len = key ? key.length : 0;
                console.log(TAG + ' Realm encryptionKey len=' + len + (len === 64 ? '' : ' (注意: 标准 Realm 要求 64 字节)'));
                dumpKey('Realm encryptionKey', hex);
            } catch (e) { console.log(TAG + ' Realm encryptionKey skip: ' + e); }
            return this.encryptionKey(key);   // 透传, 不改
        };
    } catch (e) {
        console.log(TAG + ' Realm RealmConfiguration$Builder skip: ' + e +
            '  | 未命中→下一步: Java.enumerateLoadedClasses 搜 RealmConfiguration, 或样本未用 Realm。');
    }

    // ============ WCDB(Java 侧): 真实密钥入口是 openOrCreateDatabase(..., byte[] password, ...) 与 SQLiteCipherSpec ============
    // 注意: WCDB 的 com.tencent.wcdb.database.SQLiteDatabase 并【没有 setCipherKey 方法】, 密钥经
    //       openOrCreateDatabase 的 byte[]/char[] password 形参或 SQLiteOpenHelper(byte[]) 传入。
    // 抓到什么: WCDB 的 cipher key(脱机用它解 WCDB/SQLCipher 库, 还原 IM/转账表); 二进制 key 走 bytesToHex。
    // 溯源线索: key 即交付物→脱机解 WCDB 整库; 命中即确认腾讯 WCDB 加密存储
    // 混淆/未命中: WCDB 类名/方法可能被改→Java.enumerateLoadedClasses 搜 'wcdb' 列真实类,
    //   再对目标类 Java.use(clz); var m = clz.class.getDeclaredMethods() 或 frida 的
    //   clz.<方法名>.overloads 看签名, 找形参含 byte[]/char[] password 的方法回填到下表。
    //   兜底: native 段 sqlite3_key 是所有 WCDB 加密的最终汇聚点, 它必中。
    var wcdbCandidates = [
        // [类名, 方法名]; 自适应遍历该方法的所有 overload, 凡形参里出现 byte[]/char[]/String(疑似 password) 的就抓
        ['com.tencent.wcdb.database.SQLiteDatabase', 'openOrCreateDatabase'],
        ['com.tencent.wcdb.database.SQLiteDatabase', 'openDatabase'],
        ['com.tencent.wcdb.room.db.WCDBOpenHelperFactory', 'create'],
        ['com.tencent.wcdb.database.SQLiteOpenHelper', 'getWritableDatabase']
    ];
    wcdbCandidates.forEach(function (c) {
        var clzName = c[0], mName = c[1];
        try {
            var clz = Java.use(clzName);
            var m = clz[mName];
            if (!m || !m.overloads) { console.log(TAG + ' WCDB ' + clzName + '.' + mName + ' no-such-method, skip'); return; }
            m.overloads.forEach(function (ov) {
                try {
                    var argTypes = ov.argumentTypes.map(function (t) { return t.className; });
                    // 仅 hook 形参里含 byte[]/char[]/String 的重载(可能携带 password); 其余跳过避免无谓挂钩
                    var keyIdx = -1;
                    for (var i = 0; i < argTypes.length; i++) {
                        if (argTypes[i] === '[B' || argTypes[i] === '[C' || argTypes[i] === 'java.lang.String') { keyIdx = i; break; }
                    }
                    if (keyIdx === -1) return;
                    ov.implementation = function () {
                        try {
                            var a = arguments[keyIdx];
                            var hex;
                            if (a === null || a === undefined) hex = null;
                            else if (typeof a === 'string') hex = strToHex(a);
                            else hex = bytesToHex(a);   // byte[]/char[] 包装均可 .length/索引
                            dumpKey('WCDB ' + clzName + '.' + mName + ' arg#' + keyIdx + '(' + argTypes[keyIdx] + ')', hex);
                        } catch (e) { console.log(TAG + ' WCDB ' + mName + ' onCall skip: ' + e); }
                        return ov.apply(this, arguments);   // 透传, 不改 key
                    };
                    console.log(TAG + ' WCDB hooked ' + clzName + '.' + mName + '(' + argTypes.join(',') + ') key@arg#' + keyIdx);
                } catch (e) { console.log(TAG + ' WCDB ' + clzName + '.' + mName + ' overload bind skip: ' + e); }
            });
        } catch (e) {
            console.log(TAG + ' WCDB ' + clzName + '.' + mName + ' class/bind skip: ' + e);
        }
    });
});

// ============ WCDB/SQLCipher native: sqlite3_key(db, pKey, nKey) / sqlite3_key_v2 ============
// 抓到什么: 直达 SQLCipher 内核的原始密钥字节(arg=key 指针 + key 长度)
// 溯源线索: 这是最底层 key, 任何 WCDB/SQLCipher/MMKV(若走 sqlcipher) 封装最终都走它→脱机解整库, 交付物级证据, 必抓。
// 混淆/降级: 静态链接 + strip 时 Module.findExportByName(null,'sqlite3_key') 返 null→自动降级跳过。
//   回填: 先 Process.enumerateModules() 找 libwcdb.so/libsqlcipher.so/app 自身 .so,
//         再 Module.enumerateExports('<lib>.so') 搜 sqlite3_key / sqlite3_key_v2; 若全 strip,
//         nm -D / readelf 也搜不到→只能靠上面 Java 层入口, native 段如实打"降级"。
(function () {
    'use strict';
    try {
        var addrs = [];
        ['sqlite3_key', 'sqlite3_key_v2'].forEach(function (sym) {
            var a = Module.findExportByName(null, sym);   // 跨 frida 14-16 可用; null=全模块搜
            if (a) addrs.push([sym, a]);
        });

        if (addrs.length === 0) {
            console.log(TAG + ' native sqlite3_key/_v2 未命中(strip 或静态链接降级)。' +
                ' 下一步: Process.enumerateModules() 定位 lib*sqlcipher*/lib*wcdb*.so, ' +
                'Module.enumerateExports("<so>") 搜 sqlite3_key 回填地址; 全 strip 则改用 Java 层入口。');
            return;
        }

        addrs.forEach(function (pair) {
            var sym = pair[0], addr = pair[1];
            try {
                Interceptor.attach(addr, {
                    onEnter: function (args) {
                        try {
                            // sqlite3_key(sqlite3* db, const void* pKey, int nKey)
                            // sqlite3_key_v2(sqlite3* db, const char* zDbName, const void* pKey, int nKey)
                            var pKey, nKey;
                            if (sym === 'sqlite3_key_v2') { pKey = args[2]; nKey = args[3].toInt32(); }
                            else { pKey = args[1]; nKey = args[2].toInt32(); }

                            if (pKey.isNull() || nKey <= 0 || nKey > 4096) {
                                console.log(TAG + ' native ' + sym + ' key=<null/len异常 len=' + nKey + '>');
                                return;
                            }
                            var raw = Memory.readByteArray(pKey, nKey);
                            var bytes = new Uint8Array(raw);
                            var hex = '';
                            for (var i = 0; i < bytes.length; i++) hex += ('0' + bytes[i].toString(16)).slice(-2);
                            dumpKey('native ' + sym, hex);
                        } catch (e) { console.log(TAG + ' native ' + sym + ' onEnter skip: ' + e); }
                    }
                });
                console.log(TAG + ' native hooked ' + sym + ' @ ' + addr);
            } catch (e) { console.log(TAG + ' native ' + sym + ' attach skip: ' + e); }
        });
    } catch (e) {
        console.log(TAG + ' native section skip: ' + e);
    }
})();

console.log(TAG + ' loaded. 仅观测+console.log, 不改密钥/不外发; 落盘只 /data/local/tmp。');