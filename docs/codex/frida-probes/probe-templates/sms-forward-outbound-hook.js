/*
 * 用途: [只读取证] hook android.telephony.SmsManager(+遗留 android.telephony.gsm.SmsManager)的
 *       sendTextMessage / sendMultipartTextMessage,如实记录样本把敏感个人信息(验证码/银行 OTP)转发给
 *       "谁(收件号码)+什么正文",供溯源固证。只 hook+console.log,绝不发送/拦截/修改/外发(过投毒安检)。
 * 适用: 短信转发/接码类目标样本(P0⑥),OTP 实时倒卖人锚点取证;系统类 SmsManager 不混淆,通常即挂即用。
 * 跑:   frida -U -f <包名> -l sms-forward-outbound-hook.js   (推荐 launch-only,出站短信由业务流主动触发,多能抓)
 *       或   frida -U -n <进程名> -l sms-forward-outbound-hook.js   (attach 已运行进程)
 * 改:   1) 类名被混淆/样本自封装发送门面 → Java.perform 内先 enumerateLoadedClasses 定位真实类名,回填"可选:自封装门面"段;
 *       2) 落盘改 console.log 重定向到 /data/local/tmp(唯一允许落盘位),勿外联;
 *       3) 走 native socket 直发短信网关绕过本 Java hook → 配 socket-hook / native-ssl。
 */

Java.perform(function () {
    var TAG = '[sms-fwd]';

    // ---- 工具: 拿 java byte[] 一次,hex 与 base64 都从同一 UTF-8 字节派生,两视图互相 round-trip 一致 ----
    var _JStr = null, _B64 = null;
    try { _JStr = Java.use('java.lang.String'); } catch (e) { console.log(TAG + ' java.lang.String use skip: ' + e); }
    try { _B64 = Java.use('android.util.Base64'); } catch (e) { _B64 = null; }

    // 字符串 → UTF-8 字节(JS 数组,元素 0..255);取不到则返回 null(绝不盲转)
    function strToUtf8Bytes(s) {
        if (s === null || s === undefined) return null;
        try {
            if (_JStr === null) return null;
            var jb = _JStr.$new.overload('java.lang.String').call(_JStr, String(s)).getBytes('UTF-8'); // java byte[]
            var n = jb.length;
            var out = new Array(n);
            for (var i = 0; i < n; i++) out[i] = jb[i] & 0xff;   // java byte 有符号 → 无符号
            return out;
        } catch (e) { return null; }
    }
    function bytesToHex(bytes) {
        if (bytes === null || bytes === undefined) return null;
        var out = '';
        for (var i = 0; i < bytes.length; i++) {
            out += ('0' + (bytes[i] & 0xff).toString(16)).slice(-2);
        }
        return out;
    }
    function bytesToB64(bytes) {
        if (bytes === null || bytes === undefined || _B64 === null) return null;
        try {
            // 把 JS 字节数组写回 java byte[] 再 NO_WRAP(flag=2) 编码,保证与 hex 同源
            var jbuf = Java.array('byte', bytes.map(function (v) { return (v << 24) >> 24; })); // 转回有符号 java byte
            return _B64.encodeToString(jbuf, 2);
        } catch (e) { return null; }
    }
    // 明文 → {hex,b64} 同源双视图
    function dual(s) {
        var b = strToUtf8Bytes(s);
        return { hex: bytesToHex(b), b64: bytesToB64(b) };
    }

    // ---- 6 位数字验证码模式: 两侧非数字边界,7 位连号不误判;命中则额外标 [LEAD-OTP] ----
    var OTP_RE = /(?:^|[^0-9])([0-9]{6})(?:[^0-9]|$)/;
    function otpHit(text) {
        if (text === null || text === undefined) return null;
        try {
            var m = OTP_RE.exec(String(text));
            return m ? m[1] : null;
        } catch (e) { return null; }
    }

    // ---- 发起方 Java 调用栈: 定位是哪个类发起的转发 ----
    function callStack() {
        try {
            var Log = Java.use('android.util.Log');
            var Throwable = Java.use('java.lang.Throwable');
            return Log.getStackTraceString(Throwable.$new());
        } catch (e) {
            return '(stack skip: ' + e + ')';
        }
    }

    // ---- 统一打印一条出站短信取证记录(纯只读,不回写 invocation) ----
    function report(api, dest, text, extra) {
        try {
            var otp = otpHit(text);
            var dd = dual(dest);
            var bd = dual(text);
            console.log(TAG + ' ============================================================');
            console.log(TAG + ' [OUTBOUND-SMS] api=' + api + '  ts=' + Date.now() +
                        '  (' + new Date().toISOString() + ')');
            // 收件号码 = lead = 上家/接码平台号码 → 凭此向运营商调机主实名定人;hex/b64 同源(UTF-8)互证
            console.log(TAG + ' [LEAD] destinationAddress=' + dest +
                        '  utf8_hex=' + dd.hex + '  b64=' + dd.b64);
            console.log(TAG + ' [BODY] text=' + text);
            console.log(TAG + ' [BODY] utf8_hex=' + bd.hex + '  b64=' + bd.b64 + '  (hex/b64 同源 UTF-8,可互相解码核对)');
            if (extra) console.log(TAG + ' [INFO] ' + extra);
            if (otp !== null) {
                // OTP 命中: 与"本机同时刻收到银行 OTP"成对落盘 = 实时倒卖物证
                console.log(TAG + ' [LEAD-OTP] 正文命中6位验证码=' + otp +
                            '  → 与受害人收到银行/平台OTP时间戳交叉,固证OTP实时倒卖');
            }
            console.log(TAG + ' [FROM] 发起方调用栈(定位发起转发的类):');
            console.log(callStack());
        } catch (e) {
            console.log(TAG + ' report skip: ' + e);
        }
    }

    // 把 ArrayList<String>(parts) 拼成可读正文,逐段也单独可见,并报原始分段数量(固证)
    function partsToText(parts) {
        if (parts === null || parts === undefined) return { text: null, count: 0 };
        try {
            var n = parts.size();
            var arr = [];
            for (var i = 0; i < n; i++) {
                var seg = parts.get(i);
                arr.push(seg === null ? '' : String(seg));
            }
            return { text: arr.join(''), count: n };
        } catch (e) {
            return { text: '(parts decode skip: ' + e + ')', count: -1 };
        }
    }

    // ========================================================================
    // 通用挂载器: 对给定 SmsManager 类(标准 / 遗留 gsm)挂 send(Multipart)TextMessage 全重载
    //   三种取实例方式(getDefault / getSystemService(SmsManager.class) /
    //   getSmsManagerForSubscriptionId)最终都调 SmsManager 实例方法,故只挂类方法即全覆盖。
    //   签名(arg0=收件号码, arg2=正文/parts):
    //     sendTextMessage(String dest, String sc, String text, PendingIntent sent, PendingIntent deliv [, long msgId])
    //     sendMultipartTextMessage(String dest, String sc, ArrayList<String> parts,
    //                              ArrayList<PendingIntent> sent, ArrayList<PendingIntent> deliv [, long msgId])
    // ========================================================================
    function armSmsManager(className) {
        var Cls = null;
        try {
            Cls = Java.use(className);
        } catch (e) {
            console.log(TAG + ' ' + className + ' 未命中(skip: ' + e + ')');
            return false;
        }
        console.log(TAG + ' ' + className + ' located, arming hooks...');

        // ---- sendTextMessage(各重载) ----
        try {
            var ov1 = Cls.sendTextMessage.overloads;
            ov1.forEach(function (ov) {
                try {
                    ov.implementation = function () {
                        try {
                            var dest = (arguments.length > 0) ? arguments[0] : null;
                            var text = (arguments.length > 2) ? arguments[2] : null;
                            report('sendTextMessage(' + ov.argumentTypes.length + 'args)@' + className,
                                   dest === null ? null : String(dest),
                                   text === null ? null : String(text),
                                   null);
                        } catch (e) {
                            console.log(TAG + ' sendTextMessage read skip: ' + e);
                        }
                        // 只读: 原样放行,绝不修改参数/返回值;ov.apply 调原始避免递归
                        return ov.apply(this, arguments);
                    };
                } catch (eOv) { console.log(TAG + ' [' + className + '] sendTextMessage overload bind skip: ' + eOv); }
            });
            console.log(TAG + ' [' + className + '] sendTextMessage hooked (' + ov1.length + ' overloads)');
        } catch (e) {
            console.log(TAG + ' [' + className + '] sendTextMessage hook skip: ' + e);
        }

        // ---- sendMultipartTextMessage(各重载) ----
        try {
            var ov2 = Cls.sendMultipartTextMessage.overloads;
            ov2.forEach(function (ov) {
                try {
                    ov.implementation = function () {
                        try {
                            var dest = (arguments.length > 0) ? arguments[0] : null;
                            var parts = (arguments.length > 2) ? arguments[2] : null;
                            var pt = partsToText(parts);
                            report('sendMultipartTextMessage(' + ov.argumentTypes.length + 'args)@' + className,
                                   dest === null ? null : String(dest),
                                   pt.text,
                                   'multipart 原始分段数=' + pt.count + ' (已拼接为完整正文)');
                        } catch (e) {
                            console.log(TAG + ' sendMultipartTextMessage read skip: ' + e);
                        }
                        // 只读: 原样放行
                        return ov.apply(this, arguments);
                    };
                } catch (eOv) { console.log(TAG + ' [' + className + '] sendMultipartTextMessage overload bind skip: ' + eOv); }
            });
            console.log(TAG + ' [' + className + '] sendMultipartTextMessage hooked (' + ov2.length + ' overloads)');
        } catch (e) {
            console.log(TAG + ' [' + className + '] sendMultipartTextMessage hook skip: ' + e);
        }
        return true;
    }

    // ---- 主挂载: 标准类 + 遗留 gsm 类(独立 Class,老样本仍可能用;缺失即静默 skip) ----
    var hitStd = armSmsManager('android.telephony.SmsManager');
    var hitGsm = armSmsManager('android.telephony.gsm.SmsManager');
    if (!hitStd && !hitGsm) {
        console.log(TAG + ' 两个 SmsManager 类均未命中。');
        console.log(TAG + ' 下一步: Java.perform 内 Java.enumerateLoadedClasses 搜 "Sms"/"SmsManager"' +
                    ',确认是否被裁剪;或样本走自封装门面/native 直发 → 配 socket-hook/native-ssl。');
    }

    // ========================================================================
    // 可选: 自封装门面(样本自带 SmsSender/forward 等)
    //   现场定位: 取消注释,把 enumerateLoadedClasses 命中的真实类名/方法回填。
    //   仍是只读: 仅打印,不改参不拦截。
    // ------------------------------------------------------------------------
    // try {
    //     Java.enumerateLoadedClasses({
    //         onMatch: function (name) {
    //             if (/sms|Sms|forward|Forward|sender|Sender/.test(name)) {
    //                 console.log(TAG + ' [candidate-class] ' + name);
    //             }
    //         },
    //         onComplete: function () {}
    //     });
    //     // 回填示例:
    //     // var Foo = Java.use('com.evil.sms.SmsForwarder');
    //     // Foo.forward.overloads.forEach(function (ov) {
    //     //     ov.implementation = function () {
    //     //         report('SmsForwarder.forward', String(arguments[0]), String(arguments[1]), 'custom facade');
    //     //         return ov.apply(this, arguments);   // 只读放行
    //     //     };
    //     // });
    // } catch (e) { console.log(TAG + ' facade enumerate skip: ' + e); }

    console.log(TAG + ' armed. 等待出站短信(launch-only 多能自然触发);未命中则样本可能 native 直发 → 配 socket-hook/native-ssl。');
});
