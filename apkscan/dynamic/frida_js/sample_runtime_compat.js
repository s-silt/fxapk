
// apkscan 取证运行时兼容层（best-effort）：中和样本对 root/模拟器/frida 的自我检测，
// 使加固/反分析样本能在取证机上正常运行并被观测；仅作用于样本自身进程，不接触任何第三方。
// 副产物——样本每一次自我检测尝试都作为反取证/反分析研判信号上报（消息 type=apkscan-antidetect）。
Java.perform(function () {
    var _ad_count = 0;
    function adEmit(kind, probe) {
        try {
            if (_ad_count >= 1000) return;
            _ad_count += 1;
            send({type: 'apkscan-antidetect', kind: kind, probe: ('' + probe).slice(0, 200),
                  bypassed: true, ts: Date.now()});
        } catch (e) {}
    }
    function classify(path) {
        var p = ('' + path).toLowerCase();
        if (p.indexOf('su') >= 0 || p.indexOf('magisk') >= 0 || p.indexOf('superuser') >= 0 ||
            p.indexOf('busybox') >= 0 || p.indexOf('xposed') >= 0) return 'root';
        if (p.indexOf('qemu') >= 0 || p.indexOf('goldfish') >= 0 || p.indexOf('ranchu') >= 0 ||
            p.indexOf('genymotion') >= 0 || p.indexOf('vbox') >= 0 || p.indexOf('/dev/socket/qemud') >= 0 ||
            p.indexOf('android0') >= 0 || p.indexOf('ttvm') >= 0 || p.indexOf('nox') >= 0) return 'emulator';
        if (p.indexOf('frida') >= 0 || p.indexOf('gum-js') >= 0 || p.indexOf('27042') >= 0 ||
            p.indexOf('linjector') >= 0) return 'frida';
        return '';
    }

    // --- File.exists：对 su/root/模拟器/frida 特征路径返回 false，中和样本自我检测（并记录该检测尝试）---
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            try {
                var path = this.getAbsolutePath();
                var kind = classify(path);
                if (kind) { adEmit(kind, 'File.exists: ' + path); return false; }
            } catch (e) {}
            return this.exists();
        };
        console.log('[apkscan] File.exists runtime-compat hooked');
    } catch (e) {
        console.log('[apkscan] File.exists hook skip: ' + e);
    }

    // --- Runtime.exec：拦 su / which su / mount 等 root 探测命令，中和样本自我检测 ---
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            try {
                var c = ('' + cmd).toLowerCase();
                if (c.indexOf('su') >= 0 || c.indexOf('which') >= 0 || c.indexOf('busybox') >= 0 ||
                    c.indexOf('magisk') >= 0) {
                    adEmit('root', 'Runtime.exec: ' + cmd);
                    return this.exec('echo');  // 无害化：返回空输出
                }
            } catch (e) {}
            return this.exec(cmd);
        };
        console.log('[apkscan] Runtime.exec runtime-compat hooked');
    } catch (e) {
        console.log('[apkscan] Runtime.exec hook skip: ' + e);
    }

    // --- Build 静态字段：把模拟器特征值改成真实机型（goldfish/generic/unknown → 三星）---
    try {
        var Build = Java.use('android.os.Build');
        function looksEmu(v) {
            var s = ('' + v).toLowerCase();
            return s.indexOf('generic') >= 0 || s.indexOf('goldfish') >= 0 || s.indexOf('ranchu') >= 0 ||
                   s.indexOf('emulator') >= 0 || s.indexOf('sdk') >= 0 || s.indexOf('vbox') >= 0 ||
                   s === 'unknown' || s.indexOf('mumu') >= 0 || s.indexOf('android-build') >= 0;
        }
        var spoof = {
            FINGERPRINT: 'samsung/dreamqltesq/dreamqltesq:9/PPR1.180610.011/G950USQU9DTI2:user/release-keys',
            MODEL: 'SM-G950U', MANUFACTURER: 'samsung', BRAND: 'samsung',
            PRODUCT: 'dreamqltesq', DEVICE: 'dreamqltesq', HARDWARE: 'qcom',
            BOARD: 'msm8998', HOST: 'SWHD5807', TAGS: 'release-keys'
        };
        var changed = [];
        for (var f in spoof) {
            try {
                if (Build[f] && looksEmu(Build[f].value)) {
                    Build[f].value = spoof[f];
                    changed.push(f);
                }
            } catch (e) {}
        }
        // TAGS 含 test-keys 一律改（root 镜像特征）。
        try {
            if (Build.TAGS && ('' + Build.TAGS.value).indexOf('test-keys') >= 0) {
                Build.TAGS.value = 'release-keys';
                if (changed.indexOf('TAGS') < 0) changed.push('TAGS');
            }
        } catch (e) {}
        if (changed.length) adEmit('emulator', 'Build fields spoofed: ' + changed.join(','));
        console.log('[apkscan] Build fields spoofed: ' + changed.join(','));
    } catch (e) {
        console.log('[apkscan] Build spoof skip: ' + e);
    }

    // --- SystemProperties.get：屏蔽 qemu/goldfish 等模拟器属性 ---
    try {
        var SP = Java.use('android.os.SystemProperties');
        SP.get.overload('java.lang.String').implementation = function (key) {
            var real = this.get(key);
            try {
                var k = ('' + key).toLowerCase();
                if (k.indexOf('qemu') >= 0 || k.indexOf('goldfish') >= 0 || k === 'ro.hardware' ||
                    k.indexOf('ro.kernel.qemu') >= 0 || k.indexOf('init.svc.qemud') >= 0) {
                    if (classify(real) === 'emulator' || k.indexOf('qemu') >= 0) {
                        adEmit('emulator', 'SystemProperties.get: ' + key + '=' + real);
                        return k === 'ro.hardware' ? 'qcom' : '';
                    }
                }
            } catch (e) {}
            return real;
        };
        console.log('[apkscan] SystemProperties.get runtime-compat hooked');
    } catch (e) {
        console.log('[apkscan] SystemProperties hook skip: ' + e);
    }

    // --- PackageManager.getPackageInfo：对已知 root/管理类包抛 NameNotFound（隐藏）---
    try {
        var PM = Java.use('android.app.ApplicationPackageManager');
        var rootPkgs = ['com.topjohnwu.magisk', 'eu.chainfire.supersu', 'com.koushikdutta.superuser',
                        'com.noshufou.android.su', 'de.robv.android.xposed.installer', 'com.saurik.substrate'];
        PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
            try {
                if (rootPkgs.indexOf('' + pkg) >= 0) {
                    adEmit('root', 'PackageManager.getPackageInfo: ' + pkg);
                    var NameNotFound = Java.use('android.content.pm.PackageManager$NameNotFoundException');
                    throw NameNotFound.$new('' + pkg);
                }
            } catch (e) {
                if (('' + e).indexOf('NameNotFound') >= 0) throw e;
            }
            return this.getPackageInfo(pkg, flags);
        };
        console.log('[apkscan] PackageManager root-pkg hide hooked');
    } catch (e) {
        console.log('[apkscan] PackageManager hook skip: ' + e);
    }
});
