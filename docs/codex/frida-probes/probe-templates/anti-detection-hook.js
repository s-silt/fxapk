// anti-detection-hook.js — 绕 root/frida/模拟器/调试检测,让秒退的目标样本能被动态分析(其它探针的前置)。
// 适用:症状④——点开秒退/注入即死/弹"检测到风险环境"自杀,导致 5 个抓包探针全抓不到。
// 跑:frida -U -f <包名> -l anti-detection-hook.js -q   (通常和 ssl-unpinning-hook.js 一起 -l 多文件注入)
// 改:① classify() 的 token 表按现场样本补;② Build spoof 表改成你靶机真机机型;③ 纯 native 检测靠下面 native 段,符号现场可调;④ 绕过后仍秒退就先注释 ptrace 段二分定位。
//
// 线索导向:本探针不直接产线索,但(a)不绕则一切探针无效;(b)每条 [anti] ... BYPASS 记下被探特征
// (su 路径/frida 端口/qemu 属性) = 样本反取证行为佐证。绝不假装绕过成功——拦到就打 BYPASS,拦不到的检测面打"未拦截"提示换探针点。

'use strict';

// ======================================================================
// 第一部分:Java 层检测绕过 (Java.perform)
// ======================================================================
Java.perform(function () {
    // 被探即"反分析行为"——统一打日志(取证佐证),不静默。
    function rep(kind, probe) {
        try { console.log('[anti] BYPASS ' + kind + ' <- ' + ('' + probe).slice(0, 200)); } catch (e) {}
    }
    // 路径/命令/属性值归类:root / emulator / frida。命中则视为检测特征。
    function classify(s) {
        var p = ('' + s).toLowerCase();
        if (p.indexOf('/su') >= 0 || p.indexOf('busybox') >= 0 || p.indexOf('magisk') >= 0 ||
            p.indexOf('superuser') >= 0 || p.indexOf('supersu') >= 0 || p.indexOf('xposed') >= 0 ||
            p.indexOf('substrate') >= 0 || p.indexOf('/system/bin/su') >= 0 ||
            p.indexOf('/system/xbin/su') >= 0 || p.indexOf('daemonsu') >= 0) return 'root';
        if (p.indexOf('qemu') >= 0 || p.indexOf('goldfish') >= 0 || p.indexOf('ranchu') >= 0 ||
            p.indexOf('genymotion') >= 0 || p.indexOf('vbox') >= 0 || p.indexOf('ttvm') >= 0 ||
            p.indexOf('nox') >= 0 || p.indexOf('mumu') >= 0 || p.indexOf('andy') >= 0 ||
            p.indexOf('bluestacks') >= 0 || p.indexOf('/dev/socket/qemud') >= 0 ||
            p.indexOf('android-build') >= 0) return 'emulator';
        if (p.indexOf('frida') >= 0 || p.indexOf('gum-js') >= 0 || p.indexOf('gmain') >= 0 ||
            p.indexOf('linjector') >= 0 || p.indexOf('27042') >= 0 || p.indexOf('27047') >= 0 ||
            p.indexOf('re.frida') >= 0) return 'frida';
        return '';
    }

    // --- File.exists:对 su/root/frida/qemu 特征路径返回 false ---
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            try {
                var path = this.getAbsolutePath();
                var k = classify(path);
                if (k) { rep(k, 'File.exists: ' + path); return false; }
            } catch (e) {}
            return this.exists();
        };
        console.log('[anti] File.exists hooked');
    } catch (e) { console.log('[anti] File.exists skip: ' + e); }

    // --- Runtime.exec:拦 su / which su / mount / getprop 等 root 探测命令,无害化返回 ---
    try {
        var Runtime = Java.use('java.lang.Runtime');
        function isProbeCmd(cmd) {
            var c = ('' + cmd).toLowerCase();
            return c.indexOf('su') >= 0 || c.indexOf('which') >= 0 || c.indexOf('busybox') >= 0 ||
                   c.indexOf('magisk') >= 0 || c.indexOf('mount') >= 0 ||
                   (c.indexOf('getprop') >= 0 && (c.indexOf('qemu') >= 0 || c.indexOf('ro.') >= 0));
        }
        // exec(String) —— 改:无害化用 'true'(POSIX 内建/必存在),'echo' 不一定在 PATH 里。
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            try { if (isProbeCmd(cmd)) { rep(classify(cmd) || 'root', 'Runtime.exec: ' + cmd); return this.exec('true'); } } catch (e) {}
            return this.exec(cmd);
        };
        // exec(String[]) —— 数组形式(很多 root 库用 new String[]{"which","su"})
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdArr) {
            try {
                var joined = '';
                try { for (var i = 0; i < cmdArr.length; i++) joined += ('' + cmdArr[i]) + ' '; } catch (e2) {}
                if (isProbeCmd(joined)) { rep(classify(joined) || 'root', 'Runtime.exec[]: ' + joined); return this.exec('true'); }
            } catch (e) {}
            return this.exec(cmdArr);
        };
        console.log('[anti] Runtime.exec hooked');
    } catch (e) { console.log('[anti] Runtime.exec skip: ' + e); }

    // --- ProcessBuilder.start:exec 的另一面(部分库走 ProcessBuilder 探 su)---
    try {
        var PB = Java.use('java.lang.ProcessBuilder');
        PB.start.implementation = function () {
            try {
                var cmds = this.command();
                var joined = '';
                try { var it = cmds.iterator(); while (it.hasNext()) joined += ('' + it.next()) + ' '; } catch (e2) {}
                var lc = joined.toLowerCase();
                if (lc.indexOf('su') >= 0 || lc.indexOf('which') >= 0 || lc.indexOf('mount') >= 0 || lc.indexOf('magisk') >= 0) {
                    rep('root', 'ProcessBuilder.start: ' + joined);
                    // 改:command(List) 重载——构造 ArrayList<String>{"true"} 安全替换,避免 JS 数组与重载歧义。
                    try {
                        var AL = Java.use('java.util.ArrayList');
                        var newCmd = AL.$new();
                        newCmd.add('true');
                        this.command(newCmd);
                    } catch (e3) {}
                }
            } catch (e) {}
            return this.start();
        };
        console.log('[anti] ProcessBuilder.start hooked');
    } catch (e) { console.log('[anti] ProcessBuilder skip: ' + e); }

    // --- Build 静态字段:模拟器特征值 -> 真实机型(默认三星 SM-G950U,现场可改靶机机型)---
    try {
        var Build = Java.use('android.os.Build');
        function looksEmu(v) {
            var s = ('' + v).toLowerCase();
            return s.indexOf('generic') >= 0 || s.indexOf('goldfish') >= 0 || s.indexOf('ranchu') >= 0 ||
                   s.indexOf('emulator') >= 0 || s.indexOf('sdk') >= 0 || s.indexOf('vbox') >= 0 ||
                   s === 'unknown' || s.indexOf('mumu') >= 0 || s.indexOf('android-build') >= 0 ||
                   s.indexOf('test-keys') >= 0;
        }
        // 改:现场如靶机只放行特定机型,把整张 spoof 表换成你真机的 Build 值。
        var spoof = {
            FINGERPRINT: 'samsung/dreamqltesq/dreamqltesq:9/PPR1.180610.011/G950USQU9DTI2:user/release-keys',
            MODEL: 'SM-G950U', MANUFACTURER: 'samsung', BRAND: 'samsung',
            PRODUCT: 'dreamqltesq', DEVICE: 'dreamqltesq', HARDWARE: 'qcom',
            BOARD: 'msm8998', HOST: 'SWHD5807', TAGS: 'release-keys', TYPE: 'user'
        };
        var changed = [];
        for (var f in spoof) {
            try {
                var fld = Build[f];
                if (!fld) continue;                       // 该 ROM 无此字段,跳过
                var cur = '' + fld.value;
                // 改:逻辑简化为"当前值像模拟器 OR 是 TAGS/TYPE(总要规整成 release-keys/user)就覆盖",
                //     去掉原 continue 互相打架的死分支。
                if (looksEmu(cur) || f === 'TAGS' || f === 'TYPE') {
                    fld.value = spoof[f];
                    changed.push(f);
                }
            } catch (e) {}
        }
        if (changed.length) { rep('emulator', 'Build spoofed: ' + changed.join(',')); }
        console.log('[anti] Build spoofed: ' + (changed.join(',') || '(无字段命中)'));
    } catch (e) { console.log('[anti] Build spoof skip: ' + e); }

    // --- SystemProperties.get:屏蔽 qemu/goldfish 等模拟器属性 ---
    try {
        var SP = Java.use('android.os.SystemProperties');
        SP.get.overload('java.lang.String').implementation = function (key) {
            var real = this.get(key);
            try {
                var k = ('' + key).toLowerCase();
                if (k.indexOf('qemu') >= 0 || k.indexOf('goldfish') >= 0 || k.indexOf('ranchu') >= 0 ||
                    k === 'ro.kernel.qemu' || k.indexOf('init.svc.qemud') >= 0) {
                    rep('emulator', 'SystemProperties.get: ' + key + '=' + real);
                    return '';
                }
                if (k === 'ro.hardware' && classify(real) === 'emulator') { rep('emulator', 'ro.hardware=' + real); return 'qcom'; }
            } catch (e) {}
            return real;
        };
        console.log('[anti] SystemProperties.get hooked');
    } catch (e) { console.log('[anti] SystemProperties skip: ' + e); }

    // --- PackageManager.getPackageInfo:对 root/管理类包抛 NameNotFound(隐藏已装 magisk/xposed)---
    // 改:原写法在同一 try 内 throw、又被同段 catch 吞掉再靠 indexOf 脆弱重抛——
    //     现把"是否要隐藏"的判断与 throw 分离:命中即在 try/catch 之外抛,绝不自吞。
    try {
        var PM = Java.use('android.app.ApplicationPackageManager');
        var NNF = Java.use('android.content.pm.PackageManager$NameNotFoundException');
        var hidePkgs = ['com.topjohnwu.magisk', 'eu.chainfire.supersu', 'com.koushikdutta.superuser',
                        'com.noshufou.android.su', 'de.robv.android.xposed.installer', 'com.saurik.substrate',
                        'com.zachspong.temprootremovejb', 'com.ramdroid.appquarantine', 'io.va.exposed'];
        PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
            var hide = false;
            try { hide = hidePkgs.indexOf('' + pkg) >= 0; } catch (e) {}
            if (hide) {
                rep('root', 'PackageManager.getPackageInfo: ' + pkg);
                throw NNF.$new('' + pkg);   // 在任何 try/catch 之外抛,模拟"未安装"
            }
            return this.getPackageInfo(pkg, flags);
        };
        console.log('[anti] PackageManager root-pkg hide hooked');
    } catch (e) { console.log('[anti] PackageManager skip: ' + e); }

    // --- Debug.isDebuggerConnected:反调试自检 -> false ---
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () { rep('debug', 'Debug.isDebuggerConnected'); return false; };
        console.log('[anti] Debug.isDebuggerConnected hooked');
    } catch (e) { console.log('[anti] Debug skip: ' + e); }
});

// ======================================================================
// 第二部分:Native 层检测绕过 —— 纯 native(.so/JNI)检测 Java hook 拦不住,靠这里
// ======================================================================
// 注:某些样本在 .so 里直接 access("/system/bin/su")/openat /proc/self/maps/读端口 27042 探 frida,
// Java 层完全看不到。下面 hook libc 的 fopen/openat/access/strstr,把检测面在 native 层堵死。
// 符号现场可调:个别 ROM 走 __openat 等变体;统一加 Module.findExportByName(null,...) 兜底找真实符号。
(function () {
    'use strict';
    function rep(kind, probe) {
        try { console.log('[anti-native] BYPASS ' + kind + ' <- ' + ('' + probe).slice(0, 200)); } catch (e) {}
    }
    // 改:统一符号解析——先查 libc.so,再全模块兜底(null),个别 ROM 'libc.so' 直查为 null。
    function resolve(name) {
        try {
            var p = Module.findExportByName('libc.so', name);
            if (p) return p;
        } catch (e) {}
        try { return Module.findExportByName(null, name); } catch (e2) {}
        return null;
    }
    function safeCStr(p) {
        try { if (p && !p.isNull()) return p.readCString(); } catch (e) {}
        return null;
    }
    function isRootPath(p) {
        var s = ('' + p).toLowerCase();
        return s.indexOf('/su') >= 0 || s.indexOf('magisk') >= 0 || s.indexOf('busybox') >= 0 ||
               s.indexOf('superuser') >= 0 || s.indexOf('xposed') >= 0 || s.indexOf('/system/bin/su') >= 0 ||
               s.indexOf('/system/xbin/su') >= 0 || s.indexOf('daemonsu') >= 0 || s.indexOf('substrate') >= 0;
    }
    function isFridaPath(p) {
        var s = ('' + p).toLowerCase();
        return s.indexOf('frida') >= 0 || s.indexOf('gum-js') >= 0 || s.indexOf('linjector') >= 0 ||
               s.indexOf('re.frida') >= 0 || s.indexOf('gadget') >= 0;
    }

    // --- fopen:对 su/frida/maps 路径返回 NULL(检测"文件能否打开")---
    try {
        var fopen = resolve('fopen');
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter: function (args) {
                    this.block = false;
                    var path = safeCStr(args[0]);
                    if (path === null) return;
                    if (isRootPath(path)) { rep('root', 'fopen: ' + path); this.block = true; }
                    else if (isFridaPath(path) || path.indexOf('/proc/self/maps') >= 0) { rep('frida', 'fopen: ' + path); this.block = true; }
                },
                onLeave: function (retval) { if (this.block) retval.replace(ptr(0)); }
            });
            console.log('[anti-native] fopen hooked');
        } else { console.log('[anti-native] fopen 未找到符号 —— Module.enumerateExports("libc.so") 找真实名'); }
    } catch (e) { console.log('[anti-native] fopen skip: ' + e); }

    // --- open / openat / __openat:syscall 包装层(很多检测绕过 fopen 直接 open)---
    ['open', 'openat', '__openat'].forEach(function (sym) {
        try {
            var p = resolve(sym);
            if (!p) return;
            Interceptor.attach(p, {
                onEnter: function (args) {
                    this.block = false;
                    // open(path,...) 路径在 args[0];openat/__openat(dirfd,path,...) 路径在 args[1]
                    var pathArg = (sym === 'open') ? args[0] : args[1];
                    var path = safeCStr(pathArg);
                    if (path === null) return;
                    if (isRootPath(path)) { rep('root', sym + ': ' + path); this.block = true; }
                    else if (isFridaPath(path)) { rep('frida', sym + ': ' + path); this.block = true; }
                },
                onLeave: function (retval) { if (this.block) retval.replace(ptr(-1)); }  // -1 = open 失败
            });
            console.log('[anti-native] ' + sym + ' hooked');
        } catch (e) { console.log('[anti-native] ' + sym + ' skip: ' + e); }
    });

    // --- access:F_OK 探"/system/bin/su 是否存在"(root 探测最常见的一招)---
    try {
        var access = resolve('access');
        if (access) {
            Interceptor.attach(access, {
                onEnter: function (args) {
                    this.block = false;
                    var path = safeCStr(args[0]);
                    if (path === null) return;
                    if (isRootPath(path)) { rep('root', 'access: ' + path); this.block = true; }
                    else if (isFridaPath(path)) { rep('frida', 'access: ' + path); this.block = true; }
                },
                onLeave: function (retval) { if (this.block) retval.replace(ptr(-1)); }  // -1 = 不可访问
            });
            console.log('[anti-native] access hooked');
        }
    } catch (e) { console.log('[anti-native] access skip: ' + e); }

    // --- strstr:对 /proc/self/maps 扫"frida"/"gum-js"的检测返回 NULL(未命中)---
    // 注:strstr 极高频,只对 needle 含 frida 特征的调用动手,其它放行,避免拖垮 app。
    try {
        var strstr = resolve('strstr');
        if (strstr) {
            Interceptor.attach(strstr, {
                onEnter: function (args) {
                    this.block = false;
                    var needle = safeCStr(args[1]);
                    if (needle === null) return;
                    var n = needle.toLowerCase();
                    if (n.indexOf('frida') >= 0 || n.indexOf('gum-js') >= 0 || n.indexOf('gmain') >= 0 ||
                        n.indexOf('linjector') >= 0 || n.indexOf('gum') === 0) {
                        rep('frida', 'strstr needle: ' + needle); this.block = true;
                    }
                },
                onLeave: function (retval) { if (this.block) retval.replace(ptr(0)); }  // NULL = 子串未找到
            });
            console.log('[anti-native] strstr (frida-needle) hooked');
        }
    } catch (e) { console.log('[anti-native] strstr skip: ' + e); }

    // --- ptrace:反调试 self-ptrace(PTRACE_TRACEME)让 frida 附不上 -> 永远返回 0(成功)---
    // 改:绕过后若样本仍秒退,先把本段注释掉二分定位——个别样本据 ptrace 返回值判活。
    try {
        var ptrace = resolve('ptrace');
        if (ptrace) {
            Interceptor.replace(ptrace, new NativeCallback(function (request, pid, addr, data) {
                rep('debug', 'ptrace request=' + request);
                return 0;  // 假装 ptrace 成功,反调试逻辑失效
            }, 'long', ['int', 'int', 'pointer', 'pointer']));
            console.log('[anti-native] ptrace neutralized');
        }
    } catch (e) { console.log('[anti-native] ptrace skip: ' + e); }

    // --- 兜底提示 ---
    try {
        console.log('[anti-native] 已布防 native 检测面。若注入后仍秒退:');
        console.log('[anti-native]   1) Module.enumerateExports("libc.so") 找被样本用的真实符号(open 变体);');
        console.log('[anti-native]   2) Module.enumerateLoadedModules() 看是否有自带检测 .so;');
        console.log('[anti-native]   3) 端口检测(connect 127.0.0.1:27042)可加 hook connect 改 frida-server 端口规避。');
    } catch (e) {}
})();
