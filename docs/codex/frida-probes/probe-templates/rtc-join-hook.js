// 用途: 只读取证——抓音视频 RTC 入会参数(裸聊/视频认证杀猪盘)。声网/腾讯/即构入会 token+房间号+uid 如实固证，绝不改写/外发。
// 适用: 涉诈样本含声网 io.agora.rtc(2) / 腾讯 com.tencent.trtc.TRTCCloud / 即构 im.zego ZegoExpressEngine；真机 frida -U -f <pkg> -l rtc-join-hook.js --no-pause
// 跑:   frida -U -f <包名> -l rtc-join-hook.js  (或 attach 已启动进程)；落盘示例: frida ... -l rtc-join-hook.js -o /data/local/tmp/rtc.log
// 改:   类名/方法被混淆或 SDK 版本不同→看下方各 hook 内的 enumerateLoadedClasses 注释自查回填；命中不到时按"未命中+下一步"提示扩查。

'use strict';

// ── 唯一出口：统一前缀，便于 grep 落盘(仅写 /data/local/tmp，本探针自身不落盘，由 frida -o 落) ──
function out(line) {
    console.log('[rtc-join] ' + line);
}

// ── 取一个粗时间戳，给 join↔leave 配对算起止(仅辅助；权威时间轴仍以 logcat 为准) ──
function ts() {
    try {
        return new Date().toISOString();
    } catch (e) {
        return '<ts-fail:' + e + '>';
    }
}

// ── byte[] / 二进制 → hex，绝不盲 UTF-8（token/userSig 若为 byte[] 可能含非可见字符）──
// 入参可为 Java byte[](frida 映射成 JS 有符号 int 数组)、char[] 或 ArrayBuffer。
function bytesToHex(bytes) {
    try {
        if (bytes === null || bytes === undefined) return '<null>';
        var u8;
        if (bytes instanceof ArrayBuffer) {
            u8 = new Uint8Array(bytes);
        } else {
            // Java byte[]/char[]：frida 给出类数组(元素为 number)。length 已存在。
            u8 = bytes;
        }
        if (u8.length === undefined) return '<not-array>';
        var hex = '';
        for (var i = 0; i < u8.length; i++) {
            var b = u8[i] & 0xff; // byte 取低 8 位；char[] 多为 ASCII，超 255 部分丢高位仅作核对
            hex += ('0' + b.toString(16)).slice(-2);
        }
        return hex;
    } catch (e) {
        return '<hex-fail:' + e + '>';
    }
}

function hexToB64(hexStr) {
    try {
        if (!hexStr || hexStr.indexOf('<') === 0) return '';
        var bin = '';
        for (var i = 0; i < hexStr.length; i += 2) {
            bin += String.fromCharCode(parseInt(hexStr.substr(i, 2), 16));
        }
        // 旧版 frida 无 btoa 时降级，base64 仅作辅助核对，缺了不致命
        if (typeof btoa === 'function') return btoa(bin);
        return '';
    } catch (e) {
        return '';
    }
}

// ── 判定一个 frida 实参是否是 Java 数组(byte[]/char[]/…)：有数字 length、不带 $className、不是字符串 ──
function isJavaArray(a) {
    return a !== null && a !== undefined
        && typeof a === 'object'
        && typeof a.length === 'number'
        && a.$className === undefined; // Java 对象包装会带 $className，数组不带
}

// token/userSig 类长凭据：
//   · 字符串(Agora/TRTC/ZEGO 的 token/userSig 绝大多数是 Java String) → 原文 + 长度，如实固证不二次 UTF-8 破坏。
//   · byte[]/char[](少数版本) → hex(+base64)，绝不盲 UTF-8。
function dumpCred(name, val) {
    try {
        if (val === null || val === undefined) {
            out('  ' + name + ' = <null>');
            return;
        }
        if (isJavaArray(val)) {
            var hex = bytesToHex(val);
            var b64 = hexToB64(hex);
            out('  ' + name + ' (byte[]/char[] len=' + val.length + ') hex=' + hex
                + (b64 ? '  b64=' + b64 : ''));
            return;
        }
        var s = '' + val;
        out('  ' + name + ' = ' + s + '  (len=' + s.length + ')');
    } catch (e) {
        out('  ' + name + ' skip: ' + e);
    }
}

// 通用实参打印：Java 对象打类名+toString；byte[]/char[] 走 hex；其余直打。
function dumpAny(name, a) {
    try {
        if (a === null || a === undefined) {
            out('  ' + name + ' = <null>');
            return;
        }
        if (isJavaArray(a)) {
            var hex = bytesToHex(a);
            var b64 = hexToB64(hex);
            out('  ' + name + ' (array len=' + a.length + ') hex=' + hex
                + (b64 ? '  b64=' + b64 : ''));
            return;
        }
        if (typeof a === 'object' && a.$className) {
            out('  ' + name + '<' + a.$className + '> = ' + a);
            return;
        }
        out('  ' + name + ' = ' + a);
    } catch (e) {
        out('  ' + name + ' skip: ' + e);
    }
}

function dumpScalar(name, val) {
    try {
        out('  ' + name + ' = ' + val);
    } catch (e) {
        out('  ' + name + ' skip: ' + e);
    }
}

// ── 容错读 Java 字段：从对象自身类逐级向上爬 superclass 找 getDeclaredField，
//    覆盖「字段声明在父类」与加固壳改继承层级的情况；找不到回 {ok:false} 由调用方打 skip 不静默。 ──
function readField(JavaUse, obj, fieldName) {
    try {
        var cls = JavaUse.class; // java.lang.Class
        for (var depth = 0; depth < 12 && cls !== null; depth++) {
            try {
                var f = cls.getDeclaredField(fieldName);
                f.setAccessible(true);
                return { ok: true, value: f.get(obj) };
            } catch (notHere) {
                cls = cls.getSuperclass(); // 当前层没有就上溯一层
            }
        }
        return { ok: false, err: 'field not found up the hierarchy' };
    } catch (e) {
        return { ok: false, err: '' + e };
    }
}

Java.perform(function () {

    // ════════════════════════════════════════════════════════════════════
    // 1) 声网 Agora —— io.agora.rtc.RtcEngine（rtc1 旧版）
    //    joinChannel(token, channelName, optionalInfo, uid) 等多 overload
    //    抓到什么 → 调证线索：
    //      · token 内含 appId(声网鉴权 token 前缀编码) → 持 token/appId 向声网(上海兆言)调实名/绑定主体(定人)
    //      · channelName → 受害人与话务员同房间名 = 同一裸聊会话 → 绑双方(固证)
    //      · joinChannel 时刻 = 裸聊/视频认证会话开始物证(配 logcat 时间轴)
    //    类名被加固壳重打包→ Java.enumerateLoadedClasses({onMatch:function(c){if(/agora\.rtc\./.test(c))console.log(c)},onComplete:function(){}}) 回填
    // ════════════════════════════════════════════════════════════════════
    (function hookAgoraRtc1() {
        try {
            var Cls = Java.use('io.agora.rtc.RtcEngine');
            var n = 0;
            Cls.joinChannel.overloads.forEach(function (ov) {
                try {
                    ov.implementation = function () {
                        n++;
                        out('=== Agora rtc1 RtcEngine.joinChannel #' + n
                            + ' argc=' + arguments.length + ' @' + ts() + ' ===');
                        // 经典签名: (String token, String channelName, String optionalInfo, int uid)
                        // overload 顺序可能变，按位逐个 dump，不假设固定槽位。
                        for (var i = 0; i < arguments.length; i++) {
                            var a = arguments[i];
                            if (i === 0 && !isJavaArray(a) && (a === null || typeof a !== 'object')) {
                                dumpCred('token', a);
                            } else {
                                dumpAny('arg[' + i + ']', a);
                            }
                        }
                        out('  -> 线索: token含appId可向声网调主体实名(定人)；channelName绑同房间双方(固证)；本次=入会时刻物证');
                        return ov.apply(this, arguments);
                    };
                } catch (e) {
                    out('[agora-rtc1.joinChannel.overload] skip: ' + e);
                }
            });
            out('hooked io.agora.rtc.RtcEngine.joinChannel ('
                + Cls.joinChannel.overloads.length + ' overloads)');
        } catch (e) {
            out('[agora-rtc1] skip: ' + e
                + ' | 未命中——下一步: Java.enumerateLoadedClasses({onMatch:function(c){if(/agora\\.rtc\\./.test(c))console.log(c)},onComplete:function(){}}) 看实际 rtc1 类名后回填');
        }
    })();

    // ════════════════════════════════════════════════════════════════════
    // 2) 声网 Agora —— io.agora.rtc2.RtcEngine（rtc2 新版，4.x）
    //    joinChannel(token, channelId, uid, ChannelMediaOptions) 等
    //    线索同上(token→appId→声网实名；channelId→同房间绑双方；uid→账号标识)
    // ════════════════════════════════════════════════════════════════════
    (function hookAgoraRtc2() {
        try {
            var Cls = Java.use('io.agora.rtc2.RtcEngine');
            var n = 0;
            Cls.joinChannel.overloads.forEach(function (ov) {
                try {
                    ov.implementation = function () {
                        n++;
                        out('=== Agora rtc2 RtcEngine.joinChannel #' + n
                            + ' argc=' + arguments.length + ' @' + ts() + ' ===');
                        for (var i = 0; i < arguments.length; i++) {
                            var a = arguments[i];
                            if (i === 0 && !isJavaArray(a) && (a === null || typeof a !== 'object')) {
                                dumpCred('token', a);
                            } else if (i === 1 && (a === null || typeof a !== 'object')) {
                                dumpScalar('channelId', a);
                            } else if (i === 2 && (typeof a === 'number')) {
                                dumpScalar('uid', a);
                            } else {
                                // ChannelMediaOptions 等对象走 dumpAny 打类名；
                                // 需读 publishMic/Camera 等字段时改这里:用上方 readField(Java.use(a.$className), a, 'fieldName')。
                                dumpAny('arg[' + i + ']', a);
                            }
                        }
                        out('  -> 线索: token/appId向声网调实名(定人)；channelId=同房间=同会话绑双方(固证)；uid=账号标识；本次=入会时刻物证');
                        return ov.apply(this, arguments);
                    };
                } catch (e) {
                    out('[agora-rtc2.joinChannel.overload] skip: ' + e);
                }
            });
            out('hooked io.agora.rtc2.RtcEngine.joinChannel ('
                + Cls.joinChannel.overloads.length + ' overloads)');

            // leaveChannel = 会话结束时刻物证（与 join 配对算时长）
            try {
                Cls.leaveChannel.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        out('=== Agora rtc2 leaveChannel (会话结束时刻物证) @' + ts() + ' ===');
                        return ov.apply(this, arguments);
                    };
                });
            } catch (e) {
                out('[agora-rtc2.leaveChannel] skip: ' + e);
            }
        } catch (e) {
            out('[agora-rtc2] skip: ' + e
                + ' | 未命中——下一步: 该样本可能只用 rtc1，或类名被加固壳重打包，跑 enumerateLoadedClasses 过滤 /agora\\.rtc2/ 确认');
        }
    })();

    // ════════════════════════════════════════════════════════════════════
    // 3) 腾讯 TRTC —— com.tencent.trtc.TRTCCloud.enterRoom(TRTCParams, scene)
    //    TRTCParams 字段: sdkAppId(int) / userId(String) / roomId(int)|strRoomId(String) / userSig(String) / role(int)
    //    抓到什么 → 调证线索:
    //      · sdkAppId → 腾讯云控制台主体(实名+支付绑卡) 调证(定人，穿透到注册主体)
    //      · userId → 话务员/受害人在该 app 内的账号标识(绑人)
    //      · roomId/strRoomId → 同房间 = 同一裸聊会话(绑双方·固证)
    //      · userSig → 该 userId 的鉴权签名(可证身份归属，配 sdkAppId 验签)
    //    反射读字段已用 readField() 上溯父类容错；字段缺失打 skip 不静默。
    // ════════════════════════════════════════════════════════════════════
    (function hookTrtc() {
        try {
            var Cls = Java.use('com.tencent.trtc.TRTCCloud');
            var n = 0;
            Cls.enterRoom.overloads.forEach(function (ov) {
                try {
                    ov.implementation = function () {
                        n++;
                        out('=== TRTC TRTCCloud.enterRoom #' + n
                            + ' argc=' + arguments.length + ' @' + ts() + ' ===');
                        var params = arguments[0];
                        if (params !== null && typeof params === 'object' && params.$className) {
                            out('  TRTCParams<' + params.$className + '>:');
                            var P = Java.use(params.$className);
                            ['sdkAppId', 'userId', 'roomId', 'strRoomId', 'userSig', 'role'].forEach(function (f) {
                                var r = readField(P, params, f);
                                if (!r.ok) {
                                    // 字段不存在(版本差异/混淆)就跳，不噪也不静默
                                    out('  [field ' + f + '] skip: ' + r.err);
                                    return;
                                }
                                if (f === 'userSig') {
                                    dumpCred(f, r.value);
                                } else {
                                    dumpScalar(f, r.value);
                                }
                            });
                        } else {
                            dumpAny('arg[0]', params);
                        }
                        if (arguments.length > 1) dumpScalar('scene', arguments[1]);
                        out('  -> 线索: sdkAppId向腾讯云调主体实名(定人/穿透)；roomId/strRoomId绑同房间双方(固证)；userSig=身份签名物证');
                        return ov.apply(this, arguments);
                    };
                } catch (e) {
                    out('[trtc.enterRoom.overload] skip: ' + e);
                }
            });
            out('hooked com.tencent.trtc.TRTCCloud.enterRoom ('
                + Cls.enterRoom.overloads.length + ' overloads)');

            try {
                Cls.exitRoom.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        out('=== TRTC exitRoom (会话结束时刻物证) @' + ts() + ' ===');
                        return ov.apply(this, arguments);
                    };
                });
            } catch (e) {
                out('[trtc.exitRoom] skip: ' + e);
            }
        } catch (e) {
            out('[trtc] skip: ' + e
                + ' | 未命中——下一步: TRTCCloud 常被反射加载，跑 Java.enumerateLoadedClasses 过滤 /tencent\\.trtc/ ；或样本未集成腾讯，看声网/即构段是否命中');
        }
    })();

    // ════════════════════════════════════════════════════════════════════
    // 4) 即构 ZEGO —— im.zego.zegoexpress.ZegoExpressEngine.loginRoom(roomID, user, config)
    //    user = ZegoUser{userID, userName}；roomID=房间号
    //    抓到什么 → 调证线索:
    //      · roomID → 同房间=同一裸聊会话(绑双方·固证)
    //      · ZegoUser.userID → 账号标识(绑人)
    //      · appID(在 createEngine 时传，loginRoom 拿不到)→ 见下方 createEngine hook
    //    反射读 ZegoUser 字段已用 readField() 上溯父类容错。
    // ════════════════════════════════════════════════════════════════════
    (function hookZego() {
        var hooked = false;
        // 即构包名历经 im.zego.zegoexpress.* 变更，主用类名做兜底枚举提示
        ['im.zego.zegoexpress.ZegoExpressEngine'].forEach(function (cn) {
            try {
                var Cls = Java.use(cn);
                var n = 0;
                Cls.loginRoom.overloads.forEach(function (ov) {
                    try {
                        ov.implementation = function () {
                            n++;
                            out('=== ZEGO ' + cn + '.loginRoom #' + n
                                + ' argc=' + arguments.length + ' @' + ts() + ' ===');
                            dumpScalar('roomID', arguments[0]);
                            var user = arguments[1];
                            if (user !== null && typeof user === 'object' && user.$className) {
                                out('  ZegoUser<' + user.$className + '>:');
                                var U = Java.use(user.$className);
                                ['userID', 'userName'].forEach(function (f) {
                                    var r = readField(U, user, f);
                                    if (!r.ok) {
                                        out('  [field ' + f + '] skip: ' + r.err);
                                        return;
                                    }
                                    dumpScalar(f, r.value);
                                });
                            } else {
                                dumpAny('arg[1]', user);
                            }
                            for (var i = 2; i < arguments.length; i++) {
                                dumpAny('arg[' + i + ']', arguments[i]);
                            }
                            out('  -> 线索: roomID绑同房间双方(固证)；userID绑人；appID需看 createEngine hook(向即构调主体实名)');
                            return ov.apply(this, arguments);
                        };
                    } catch (e) {
                        out('[zego.loginRoom.overload] skip: ' + e);
                    }
                });
                out('hooked ' + cn + '.loginRoom (' + Cls.loginRoom.overloads.length + ' overloads)');
                hooked = true;

                // appID 在 createEngine(appID, appSign|token, ...) 传入 → 向即构调主体实名(定人/穿透)
                ['createEngine', 'createEngineWithProfile'].forEach(function (m) {
                    try {
                        // 静态方法在 Java.use 包装上以同名属性暴露；不存在则为 undefined
                        if (Cls[m] && Cls[m].overloads) {
                            Cls[m].overloads.forEach(function (ov) {
                                try {
                                    ov.implementation = function () {
                                        out('=== ZEGO ' + cn + '.' + m + '(含appID, 调即构实名定人) @' + ts() + ' ===');
                                        for (var i = 0; i < arguments.length; i++) {
                                            // appID 通常是第 0 个 long，appSign/token 是凭据(可能 String 或 byte[])
                                            dumpAny('arg[' + i + ']', arguments[i]);
                                        }
                                        out('  -> 线索: appID向即构(深圳众至)调注册主体实名(定人/穿透)');
                                        return ov.apply(this, arguments);
                                    };
                                } catch (oe) {
                                    out('[zego.' + m + '.overload] skip: ' + oe);
                                }
                            });
                        }
                    } catch (e) {
                        out('[zego.' + m + '] skip: ' + e);
                    }
                });
            } catch (e) {
                out('[zego ' + cn + '] skip: ' + e);
            }
        });
        if (!hooked) {
            out('[zego] 未命中——下一步: 即构类名随版本变(im.zego.zegoexpress / im.zego.zegoexpress.* )，'
                + '跑 Java.enumerateLoadedClasses({onMatch:function(c){if(/zego.*Engine/i.test(c))console.log(c)},onComplete:function(){}}) 定位真实类名回填上方数组');
        }
    })();

    out('rtc-join-hook 已就绪：等待样本入会(诱导真人裸聊/视频认证才会触发，launch-only 可能抓不到)');
    out('★ 穿透提示: 媒体流走 native UDP，本 Java hook 拿不到边缘节点 IP:port —— 穿透基本落空，'
        + '需配 `netstat -tunp`/`/proc/<pid>/net/udp` + 抓包侧 SDP/ICE 取真实对端，见 notes');
});