// 用途：只读取证——hook native OpenSSL/BoringSSL 对称加密初始化，固证 AES key/iv（离线解密缴获流量/配置）。
// 适用：目标样本把 AES 密钥下沉到 .so（libcrypto.so 或自有 native 库静态链接 BoringSSL），Java 层 Cipher hook 抓不到 key。
// 跑：frida -U -f <包名> -l native-crypto-key-hook.js   或   frida -U <包名> -l native-crypto-key-hook.js（落盘只往 /data/local/tmp）。
// 改：符号被 strip → 把下方 LIBS 换成真实 so 名；静态链接进 app 自有 .so → 看「未命中」提示用 enumerateModules/enumerateExports 回填地址。
'use strict';

// ── 取证出口：唯一 console.log，便于 frida -l ... -o /data/local/tmp/native-crypto.log 落盘 ──
function out(tag, obj) {
    try {
        var line = '[native-crypto][' + tag + '] ';
        var parts = [];
        for (var k in obj) { if (obj.hasOwnProperty(k)) parts.push(k + '=' + obj[k]); }
        console.log(line + parts.join(' '));
    } catch (e) { console.log('[native-crypto][emit] skip: ' + e); }
}

// ── 二进制只给 hex（+base64），绝不盲 UTF-8（key/iv 多为乱码字节）──
function readHex(ptr, len) {
    if (ptr === null || ptr.isNull() || len <= 0) return null;
    try {
        var bytes = ptr.readByteArray(len);   // 实例式读法，frida 16/17 通用；跨不可读尾页时抛→兜到 null 不崩
        if (bytes === null) return null;
        var u8 = new Uint8Array(bytes);
        var hex = '';
        for (var i = 0; i < u8.length; i++) hex += ('0' + u8[i].toString(16)).slice(-2);
        return hex;
    } catch (e) { return null; }
}
function hex2b64(hex) {
    if (!hex) return null;
    try {
        var bin = '';
        for (var i = 0; i < hex.length; i += 2) bin += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
        if (typeof btoa === 'function') return btoa(bin);
        // frida GumJS 无 btoa（典型）→ 手搓 base64
        var T = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        var o = '', j;
        for (j = 0; j < bin.length; j += 3) {
            var c1 = bin.charCodeAt(j), c2 = bin.charCodeAt(j + 1), c3 = bin.charCodeAt(j + 2);
            var e1 = c1 >> 2, e2 = ((c1 & 3) << 4) | (c2 >> 4);
            var e3 = isNaN(c2) ? 64 : (((c2 & 15) << 2) | (c3 >> 6)), e4 = isNaN(c3) ? 64 : (c3 & 63);
            o += T.charAt(e1) + T.charAt(e2) + (e3 === 64 ? '=' : T.charAt(e3)) + (e4 === 64 ? '=' : T.charAt(e4));
        }
        return o;
    } catch (e) { return null; }
}

// ── 符号定位：先在候选 libcrypto/自有 so 里找；strip/静态链接时给「下一步」提示 ──
// 现场若 libcrypto.so 改名/打进 app 自有库：先在 frida REPL 跑
//   Process.enumerateModules().forEach(m => console.log(m.name, m.base))
// 找到可疑 .so 后逐个跑 Module 实例的 enumerateExports() 看有没有 EVP_*/AES_set_*，把 so 名补进 LIBS。
var LIBS = ['libcrypto.so', 'libssl.so', 'libcrypto_static.so', 'libnative-lib.so'];

// resolveExport：兼容 frida 16（静态 Module.findExportByName）与 frida 17（移除静态形式，改实例/全局式）。
// 每条路径各自 try/catch，任一版本下都不崩；全找不到返回 null 由调用方打 [miss]+下一步。
function resolveExport(sym) {
    // 1) frida 17：全局导出表（等价旧 findExportByName(null, ...)）
    try {
        if (typeof Module.getGlobalExportByName === 'function') {
            var pg = Module.getGlobalExportByName(sym);
            if (pg && !pg.isNull()) return pg;
        }
    } catch (e0) {}
    // 2) frida 16：静态 findExportByName(null, sym)（17 已移除，会 throw→被 catch 吞）
    try {
        if (typeof Module.findExportByName === 'function') {
            var p = Module.findExportByName(null, sym);
            if (p && !p.isNull()) return p;
        }
    } catch (e1) {}
    // 3) 逐候选 so：优先 frida 17 实例式 Process.findModuleByName(lib).findExportByName(sym)，
    //    回落 frida 16 静态 Module.findExportByName(lib, sym) 与实例 enumerateExports 模糊扫。
    for (var i = 0; i < LIBS.length; i++) {
        var lib = LIBS[i];
        // 3a) frida 17 实例式
        try {
            var mod = null;
            if (typeof Process.findModuleByName === 'function') mod = Process.findModuleByName(lib);
            if (mod && typeof mod.findExportByName === 'function') {
                var pe = mod.findExportByName(sym);
                if (pe && !pe.isNull()) return pe;
            }
        } catch (e2) {}
        // 3b) frida 16 静态式
        try {
            if (typeof Module.findExportByName === 'function') {
                var pe2 = Module.findExportByName(lib, sym);
                if (pe2 && !pe2.isNull()) return pe2;
            }
        } catch (e3) {}
        // 3c) enumerateExports 模糊扫（精确匹配兜底；兼容 16 静态与 17 实例两种写法）
        try {
            var exps = null;
            if (typeof Module.enumerateExports === 'function') {
                exps = Module.enumerateExports(lib);                 // frida 16 静态
            } else if (typeof Process.findModuleByName === 'function') {
                var m2 = Process.findModuleByName(lib);
                if (m2 && typeof m2.enumerateExports === 'function') exps = m2.enumerateExports(); // frida 17 实例
            }
            if (exps) {
                for (var k = 0; k < exps.length; k++) {
                    if (exps[k].name === sym) return exps[k].address;
                }
            }
        } catch (e4) {}
    }
    return null;
}

// ── 只读查询函数缓存：避免每次 onEnter 重新 resolveExport + new NativeFunction（热路径开销）──
// 这些都是纯查询、无副作用的 OpenSSL/BoringSSL 导出，符合「只读取证、不改写样本行为」。
var _fn = {};
function nf(sym, retType, argTypes) {
    if (_fn.hasOwnProperty(sym)) return _fn[sym];       // 命中缓存（含「找过但没有」的 null）
    var fn = null;
    try {
        var a = resolveExport(sym);
        if (a) fn = new NativeFunction(a, retType, argTypes);
    } catch (e) { fn = null; }
    _fn[sym] = fn;
    return fn;
}

// EVP_CIPHER 指针 → 名字（取证只需大致算法，拿不到名字不影响 key/iv 固证）。
// 注意：仅当 evpCipherPtr 非 NULL 时才调 native——分步 Init 补 key 那次 type=NULL，绝不能传 NULL 进 native（会解引用崩进程）。
function cipherName(evpCipherPtr) {
    if (!evpCipherPtr || evpCipherPtr.isNull()) return null;
    try {
        var nidFn = nf('EVP_CIPHER_nid', 'int', ['pointer']);
        if (!nidFn) return null;
        var nid = nidFn(evpCipherPtr);
        var nameFn = nf('OBJ_nid2sn', 'pointer', ['int']);
        if (nameFn) {
            var sn = nameFn(nid);
            if (sn && !sn.isNull()) return sn.readUtf8String();
        }
        return 'nid:' + nid;
    } catch (e) { return null; }
}

// ── hook 1：EVP_EncryptInit_ex / EVP_DecryptInit_ex / EVP_CipherInit_ex ───────
// 签名：int EVP_*Init_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl,
//                        const unsigned char *key, const unsigned char *iv [, int enc])
//   arg0=ctx  arg1=type(算法→定 key 长 16/24/32B)  arg2=engine  arg3=key  arg4=iv  (CipherInit 多一个 arg5=enc 方向)
// 关键：分步 Init——先 EVP_*Init_ex(ctx,type,impl,NULL,NULL) 建上下文，再 EVP_*Init_ex(ctx,NULL,NULL,key,iv) 补 key。
//      补 key 那次 type(arg1)=NULL，必须先 isNull 守卫，绝不可把 NULL 传进 EVP_CIPHER_*_length（否则 native 解引用崩）。
// 抓到什么 → 溯源线索：对称 key+iv 当场固证 → 离线解密缴获的加密流量/本地加密配置 →
//            复原真后端域名/IP/接口锚点（定人、资金穿透、固证三合一）。
function hookEvpInit(sym, kind) {
    var addr = resolveExport(sym);
    if (!addr) {
        out('miss', { sym: sym, hint: '未命中→Process.enumerateModules()找可疑so，再(实例).enumerateExports()确认符号，补进LIBS或直接Interceptor.attach(地址)' });
        return;
    }
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    var typePtr = args[1];
                    var keyPtr = args[3];
                    var ivPtr = args[4];
                    var typeValid = (typePtr && !typePtr.isNull());   // 分步 Init 补 key 那次为 false
                    var name = typeValid ? cipherName(typePtr) : null;
                    // BoringSSL/OpenSSL：key/iv 长度随算法。仅 type 有效时才查 EVP_CIPHER_*_length，否则按名/默认兜底。
                    var keyLen = 0, ivLen = 0;
                    if (typeValid) {
                        try {
                            var klFn = nf('EVP_CIPHER_key_length', 'int', ['pointer']);
                            if (klFn) keyLen = klFn(typePtr);
                            var ilFn = nf('EVP_CIPHER_iv_length', 'int', ['pointer']);
                            if (ilFn) ivLen = ilFn(typePtr);
                        } catch (eL) { keyLen = 0; ivLen = 0; }
                    }
                    if (!keyLen || keyLen <= 0 || keyLen > 64) {
                        // 拿不到长度（含 type=NULL 的分步补key那次）：按算法名兜底，名也没有→默认读 32B（AES-256 上限，宁多读不漏）。
                        keyLen = (name && /128/.test(name)) ? 16 : (name && /192/.test(name)) ? 24 : 32;
                    }
                    if (!ivLen || ivLen < 0 || ivLen > 16) ivLen = 16;
                    var keyHex = (keyPtr && !keyPtr.isNull()) ? readHex(keyPtr, keyLen) : null;
                    var ivHex = (ivPtr && !ivPtr.isNull()) ? readHex(ivPtr, ivLen) : null;
                    out(kind, {
                        sym: sym,
                        algo: name || '(未知/分步init补key)',
                        key_len: keyLen,
                        key_hex: keyHex || '(null,可能此次为建上下文,key在后续补key调用)',
                        key_b64: keyHex ? hex2b64(keyHex) : '-',
                        iv_len: ivLen,
                        iv_hex: ivHex || '(null/ECB无iv)',
                        iv_b64: ivHex ? hex2b64(ivHex) : '-'
                    });
                } catch (e) { out('skip', { sym: sym, e: '' + e }); }
            }
        });
        out('ready', { sym: sym, addr: addr });
    } catch (e) { out('skip', { sym: sym, e: '' + e }); }
}

// ── hook 2：AES_set_encrypt_key / AES_set_decrypt_key（低层 AES 直用，绕过 EVP）──
// 签名：int AES_set_*crypt_key(const unsigned char *userKey, const int bits, AES_KEY *key)
//   arg0=userKey(原始 key)  arg1=bits(128/192/256 字面量→定长度)  arg2=AES_KEY(展开后轮密钥表，非原始)
// 抓到什么 → 溯源线索：原始对称 key 当场固证 → 同上离线解密 → 锚定真后端。
// 注意：必须读 arg0(userKey)，arg2 是轮密钥扩展表不可直接当 key（否则固证错误密钥，分析侧解不开）。
function hookAesSetKey(sym, kind) {
    var addr = resolveExport(sym);
    if (!addr) {
        out('miss', { sym: sym, hint: '未命中→同上enumerateModules/(实例)enumerateExports定位；低层AES常被静态链接进自有.so' });
        return;
    }
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    var keyPtr = args[0];
                    var bits = args[1].toInt32();          // 字面量 128/192/256
                    var keyLen = (bits > 0 && bits % 8 === 0 && bits <= 256) ? (bits / 8) : 32;
                    var keyHex = (keyPtr && !keyPtr.isNull()) ? readHex(keyPtr, keyLen) : null;
                    out(kind, {
                        sym: sym,
                        bits: bits,
                        key_len: keyLen,
                        key_hex: keyHex || '(null)',
                        key_b64: keyHex ? hex2b64(keyHex) : '-',
                        note: 'arg0=原始key;arg2=AES_KEY轮密钥表(非原始,不取);iv在调用方加密时另传'
                    });
                } catch (e) { out('skip', { sym: sym, e: '' + e }); }
            }
        });
        out('ready', { sym: sym, addr: addr });
    } catch (e) { out('skip', { sym: sym, e: '' + e }); }
}

// ── 装载 ──────────────────────────────────────────────────────────────────────
try {
    out('boot', { libs: LIBS.join(','), tip: '所有命中hook打[encrypt]/[decrypt]/[aes-*];未命中打[miss]+下一步' });

    hookEvpInit('EVP_EncryptInit_ex', 'encrypt');
    hookEvpInit('EVP_DecryptInit_ex', 'decrypt');
    // 部分 BoringSSL 走统一入口 EVP_CipherInit_ex（enc 标志位 arg5 决定方向），有就一并抓。
    if (resolveExport('EVP_CipherInit_ex')) hookEvpInit('EVP_CipherInit_ex', 'cipher');

    hookAesSetKey('AES_set_encrypt_key', 'aes-enc');
    hookAesSetKey('AES_set_decrypt_key', 'aes-dec');

    out('armed', { note: '若全部[miss]:样本可能用mbedTLS/wolfSSL/自实现AES,改hook对应符号或在加密前后内存断点抓key' });
} catch (e) {
    out('fatal', { e: '' + e });
}