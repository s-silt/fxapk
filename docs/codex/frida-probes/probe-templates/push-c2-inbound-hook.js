// push-c2-inbound-hook.js — P0② C2 指令反向入口：从推送 SDK 收消息回调抓服务器下发的指令/C2。
// 适用：装死/无明显回连、C2 走 FCM/个推/极光下发的目标样本；带 GMS/对应厂商推送框架的 root 真机。
// 跑：frida -U -l push-c2-inbound-hook.js -f <包名>  （或 -F 附加已运行进程；建议样本完成推送注册后再注入）
// 改：类名被混淆/SDK 版本漂移→改 CFG 里的类名/方法名（用 jadx 核对样本真实符号）；脚本已 enumerateLoadedClasses 兜底找 *MessagingService 子类回填。
'use strict';

// ===== 现场可改配置（类名随 SDK 版本/混淆漂移，jadx 核对后回填）=====
var CFG = {
    fcmBase:        'com.google.firebase.messaging.FirebaseMessagingService',
    remoteMessage:  'com.google.firebase.messaging.RemoteMessage',
    getuiService:   'com.igexin.sdk.GTIntentService',
    getuiMsg:       'com.igexin.sdk.message.GTTransmitMessage',
    jpushReceiver:  'cn.jpush.android.service.JPushMessageReceiver',
    jpushIface:     'cn.jpush.android.api.JPushInterface',
    getuiManagerHelper: 'com.igexin.sdk.PushManager',
    // payload 文本里命中即标 [LEAD-C2] 的关键词（域名:port / wss:// / ip:port / 指令）
    c2Tokens:  ['wss://', 'ws://', 'cmd=', 'switchDomain', 'startTransfer', 'showOverlay', 'selfDestruct', 'newDomain', 'c2', 'server='],
    cmdTokens: ['startTransfer', 'showOverlay', 'switchDomain', 'selfDestruct', 'startRecord', 'lockScreen', 'forwardSms', 'uploadContacts']
};

Java.perform(function () {
    var TAG = '[push-c2]';

    // ---------- 公共工具：byte[] 不盲 UTF-8，同时给 hex+base64；文本另扫 C2 线索 ----------
    function b2hex(bytes) {
        try {
            if (bytes === null || bytes === undefined) return null;
            var out = '';
            for (var i = 0; i < bytes.length; i++) {
                var b = bytes[i] & 0xff;
                out += ('0' + b.toString(16)).slice(-2);
            }
            return out;
        } catch (e) { return '<hex-err:' + e + '>'; }
    }
    function b2b64(bytes) {
        try {
            if (bytes === null || bytes === undefined) return null;
            var B64 = Java.use('android.util.Base64');
            return B64.encodeToString(bytes, 2 /*NO_WRAP*/);
        } catch (e) { return '<b64-err:' + e + '>'; }
    }
    // 仅用于「人看的线索扫描」，绝不替代 hex/base64；解不出文本就返回 null。
    function tryText(bytes) {
        try {
            if (bytes === null || bytes === undefined) return null;
            return Java.use('java.lang.String').$new(bytes, 'UTF-8').toString();
        } catch (e) { return null; }
    }
    function lc(s) { try { return ('' + s).toLowerCase(); } catch (e) { return ''; } }

    function safeUse(name) {
        try { return Java.use(name); } catch (e) { return null; }
    }

    // 单方法可能有多重载：直挂 .implementation 会被 Frida 拒绝（"has more than one overload"）。
    // 此辅助：1 个重载→直挂；多重载→逐个 overload 挂同一实现；0 个→返回 false。
    // impl 是普通 function（用 this + arguments），逐重载复用。
    function hookAllOverloads(cls, methodName, impl) {
        try {
            var m = cls[methodName];
            if (!m) return false;
            var ovs = m.overloads;
            if (!ovs || ovs.length === 0) return false;
            for (var i = 0; i < ovs.length; i++) {
                try { ovs[i].implementation = impl; }
                catch (ie) { console.log(TAG + ' hook overload[' + i + '] ' + methodName + ' skip: ' + ie); }
            }
            return true;
        } catch (e) {
            console.log(TAG + ' hookAllOverloads ' + methodName + ' skip: ' + e);
            return false;
        }
    }

    // 对任意文本扫 域名:port / wss:// / ip:port / cmd= 等 → 命中打 [LEAD-C2]，指令打 [EVIDENCE-REMOTE-CONTROL]
    function scanLeads(where, text) {
        try {
            if (text === null || text === undefined) return;
            var low = lc(text);
            var hitC2 = [];
            for (var i = 0; i < CFG.c2Tokens.length; i++) {
                if (low.indexOf(lc(CFG.c2Tokens[i])) >= 0) hitC2.push(CFG.c2Tokens[i]);
            }
            // ip:port / host:port 正则（粗筛，供人工核验，不做拦截）
            var reHostPort = /([a-z0-9.-]+\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3}):\d{2,5}/gi;
            var hp = ('' + text).match(reHostPort);
            if (hp && hp.length) {
                console.log(TAG + ' [LEAD-C2] ' + where + ' host:port → ' + JSON.stringify(hp)
                    + '  ⟶ 调证：疑似真 C2 下发面，热替换/穿透该域名找真源站');
            }
            if (hitC2.length) {
                console.log(TAG + ' [LEAD-C2] ' + where + ' 关键词命中=' + JSON.stringify(hitC2)
                    + '  ⟶ 调证：服务器下发面/远程切换域名线索');
            }
            var hitCmd = [];
            for (var j = 0; j < CFG.cmdTokens.length; j++) {
                if (low.indexOf(lc(CFG.cmdTokens[j])) >= 0) hitCmd.push(CFG.cmdTokens[j]);
            }
            if (hitCmd.length) {
                console.log(TAG + ' [EVIDENCE-REMOTE-CONTROL] ' + where + ' 明文指令=' + JSON.stringify(hitCmd)
                    + '  ⟶ 调证：服务器「远程下令/操控」直接物证（固证 REMOTE_CONTROL）');
            }
        } catch (e) {
            console.log(TAG + ' scanLeads skip: ' + e);
        }
    }

    // ======================================================================
    // 1) FCM：onMessageReceived(RemoteMessage) + onNewToken(String)
    //    R8 常把不调 super 的子类混淆改名 → 必须枚举运行时具体 FirebaseMessagingService 子类逐个挂，
    //    光挂抽象基类会漏。基类本身也兜底挂一份。onNewToken 同坑：子类不调 super 也会漏 → 一并逐子类挂。
    // ======================================================================

    // 预解析 Map$Entry，避免循环内反复 Java.use。
    var MapEntry = safeUse('java.util.Map$Entry');

    function hookFcmMessage(clsName) {
        try {
            var cls = Java.use(clsName);
            if (!cls.onMessageReceived) {
                return false;
            }
            // onMessageReceived 一般单重载(RemoteMessage)；用 overloads 兜底防多重载报错。
            var ok = hookAllOverloads(cls, 'onMessageReceived', function (rm) {
                try {
                    console.log(TAG + ' [FCM] ===== onMessageReceived 命中：' + clsName + ' =====');
                    try { console.log(TAG + ' [FCM] from=' + rm.getFrom()); } catch (e) { console.log(TAG + ' [FCM] getFrom skip: ' + e); }
                    try { console.log(TAG + ' [FCM] messageId=' + rm.getMessageId()); } catch (e) { console.log(TAG + ' [FCM] getMessageId skip: ' + e); }
                    try {
                        var data = rm.getData(); // Map<String,String>
                        if (data) {
                            var it = data.entrySet().iterator();
                            while (it.hasNext()) {
                                var rawEn = it.next();
                                var en = MapEntry ? Java.cast(rawEn, MapEntry) : rawEn;
                                var k = '' + en.getKey();
                                var v = '' + en.getValue();
                                console.log(TAG + ' [FCM] data[' + k + ']=' + v);
                                scanLeads('FCM.data[' + k + ']', v);
                            }
                        } else {
                            console.log(TAG + ' [FCM] data=null（可能纯 notification 体，查 getNotification）');
                        }
                    } catch (e) { console.log(TAG + ' [FCM] getData skip: ' + e); }
                } catch (e) {
                    console.log(TAG + ' [FCM] onMessageReceived dump skip: ' + e);
                }
                // 只读取证：原样放行，绝不拦截/修改下发消息。
                return this.onMessageReceived(rm);
            });
            if (ok) console.log(TAG + ' [fcm] hooked onMessageReceived @ ' + clsName);
            return ok;
        } catch (e) {
            console.log(TAG + ' [fcm] hook message ' + clsName + ' skip: ' + e);
            return false;
        }
    }

    function hookFcmToken(clsName) {
        try {
            var cls = Java.use(clsName);
            if (!cls.onNewToken) return false;
            var ok = hookAllOverloads(cls, 'onNewToken', function (tok) {
                try {
                    console.log(TAG + ' [REGID][FCM] onNewToken token=' + tok + ' @ ' + clsName
                        + '  ⟶ 调证：定人锚点，凭 token+FirebaseProjectId 向 Google 调注册主体');
                } catch (e) { console.log(TAG + ' [FCM] onNewToken dump skip: ' + e); }
                return this.onNewToken(tok);
            });
            if (ok) console.log(TAG + ' [fcm] hooked onNewToken @ ' + clsName);
            return ok;
        } catch (e) {
            console.log(TAG + ' [fcm] hook token ' + clsName + ' skip: ' + e);
            return false;
        }
    }

    var fcmHooked = 0;
    var fcmBaseCls = safeUse(CFG.fcmBase);
    // 1a) 先挂抽象基类（部分实现确实调 super，能兜到；onNewToken 同理）。
    if (fcmBaseCls) {
        if (hookFcmMessage(CFG.fcmBase)) fcmHooked++;
        hookFcmToken(CFG.fcmBase);
    } else {
        console.log(TAG + ' [fcm] 基类 ' + CFG.fcmBase + ' 未加载（样本可能未用 FCM 或类未加载）');
    }

    // 1b) 枚举运行时已加载的具体 FirebaseMessagingService 子类（抓被混淆/不调 super 的子类）。
    //     用 isAssignableFrom 严格判定是 FCM 子类，避免误挂同名无关类；onMessageReceived/onNewToken 都逐子类挂。
    try {
        var seen = {};
        var baseClass = fcmBaseCls ? fcmBaseCls.class : null;
        Java.enumerateLoadedClasses({
            onMatch: function (name) {
                try {
                    if (name === CFG.fcmBase) return;
                    if (name.indexOf('MessagingService') < 0) return;
                    if (seen[name]) return;
                    var c = safeUse(name);
                    if (!c) return;
                    // 严格：必须是 FirebaseMessagingService 的子类。
                    if (baseClass) {
                        try { if (!baseClass.isAssignableFrom(c.class)) return; }
                        catch (ae) { /* isAssignableFrom 失败则放宽到方法存在判定 */ if (!c.onMessageReceived) return; }
                    } else {
                        if (!c.onMessageReceived) return;
                    }
                    seen[name] = 1;
                    if (hookFcmMessage(name)) fcmHooked++;
                    hookFcmToken(name);
                } catch (e) { /* 单类失败不影响枚举 */ }
            },
            onComplete: function () {
                console.log(TAG + ' [fcm] FirebaseMessagingService 子类枚举完成，累计挂上 ' + fcmHooked + ' 个 onMessageReceived');
                if (fcmHooked === 0) {
                    console.log(TAG + ' [fcm] 未命中 FCM。下一步：1) 确认设备有 GMS；2) 样本完成推送注册后再注入；'
                        + '3) jadx 搜 extends FirebaseMessagingService 找真实子类名回填 CFG.fcmBase 或直接 Java.use 挂；'
                        + '4) 反复运行（类可能尚未加载）。');
                }
            }
        });
    } catch (e) {
        console.log(TAG + ' [fcm] enumerateLoadedClasses skip: ' + e);
    }

    // ======================================================================
    // 2) 个推：GTIntentService.onReceiveMessageData(Context, GTTransmitMessage)
    //    payload 是 byte[] → hex+base64 不盲 UTF-8；文本另扫 C2。
    //    版本漂移：新版第 2 参是 GTTransmitMessage，老版可能直接是 byte[] → 两个重载都尝试。
    // ======================================================================
    function dumpGetuiPayloadBytes(where, payload) {
        try {
            if (payload) {
                console.log(TAG + ' [GETUI] payload.len=' + payload.length);
                console.log(TAG + ' [GETUI] payload.hex=' + b2hex(payload));
                console.log(TAG + ' [GETUI] payload.b64=' + b2b64(payload));
                var txt = tryText(payload);
                if (txt !== null) {
                    console.log(TAG + ' [GETUI] payload.text(仅供线索扫描)=' + txt);
                    scanLeads(where, txt);
                } else {
                    console.log(TAG + ' [GETUI] payload 非 UTF-8 文本（可能加密/protobuf），见上 hex/b64，下一步解密后再扫');
                }
            } else {
                console.log(TAG + ' [GETUI] payload=null');
            }
        } catch (e) { console.log(TAG + ' [GETUI] dump payload skip: ' + e); }
    }

    try {
        var gt = safeUse(CFG.getuiService);
        if (gt && gt.onReceiveMessageData) {
            var ovs = gt.onReceiveMessageData.overloads;
            var gotGetui = false;
            for (var gi = 0; gi < ovs.length; gi++) {
                try {
                    var argTypes = ovs[gi].argumentTypes.map(function (t) { return t.className; });
                    ovs[gi].implementation = function () {
                        try {
                            console.log(TAG + ' [GETUI] ===== onReceiveMessageData 命中（argc=' + arguments.length + '）=====');
                            // 找第 2 参：可能是 GTTransmitMessage 对象，也可能直接是 byte[]。
                            var second = arguments.length >= 2 ? arguments[1] : (arguments.length >= 1 ? arguments[0] : null);
                            if (second === null || second === undefined) {
                                console.log(TAG + ' [GETUI] 无消息参数');
                            } else if (second.getPayload) {
                                // GTTransmitMessage 对象路径。
                                try { console.log(TAG + ' [GETUI] messageId=' + second.getMessageId()); } catch (e) { console.log(TAG + ' [GETUI] getMessageId skip: ' + e); }
                                try { console.log(TAG + ' [GETUI] taskId=' + second.getTaskId()); } catch (e) { console.log(TAG + ' [GETUI] getTaskId skip: ' + e); }
                                try { dumpGetuiPayloadBytes('GETUI.payload', second.getPayload()); }
                                catch (e) { console.log(TAG + ' [GETUI] getPayload skip: ' + e); }
                            } else if (typeof second.length === 'number') {
                                // 老版 byte[] 直传路径。
                                dumpGetuiPayloadBytes('GETUI.payload[byte]', second);
                            } else {
                                // 未知对象：toString 兜底扫一遍。
                                try { scanLeads('GETUI.arg2.toString', '' + second.toString()); } catch (e) {}
                            }
                        } catch (e) {
                            console.log(TAG + ' [GETUI] dump skip: ' + e);
                        }
                        return this.onReceiveMessageData.apply(this, arguments);
                    };
                    console.log(TAG + ' [getui] hooked onReceiveMessageData 重载[' + gi + '] args=' + JSON.stringify(argTypes));
                    gotGetui = true;
                } catch (ie) {
                    console.log(TAG + ' [getui] hook 重载[' + gi + '] skip: ' + ie);
                }
            }
            if (!gotGetui) {
                console.log(TAG + ' [getui] onReceiveMessageData 无可挂重载。下一步：jadx 核对签名回填。');
            }
        } else {
            console.log(TAG + ' [getui] ' + CFG.getuiService + ' 未加载或无 onReceiveMessageData。'
                + '下一步：jadx 搜 extends GTIntentService 核对类名/方法签名（个推 SDK 版本漂移），回填 CFG.getuiService/getuiMsg。');
        }
    } catch (e) {
        console.log(TAG + ' [getui] hook skip: ' + e);
    }

    // 个推定人锚点：PushManager.getClientid(Context) → clientid（cid），向个推调注册主体。
    try {
        var pm = safeUse(CFG.getuiManagerHelper);
        if (pm && pm.getClientid) {
            hookAllOverloads(pm, 'getClientid', function () {
                var cid = this.getClientid.apply(this, arguments);
                try {
                    console.log(TAG + ' [REGID][GETUI] clientid=' + cid
                        + '  ⟶ 调证：定人锚点，凭 clientid+个推 AppID 向个推调注册主体/付费实名');
                } catch (e) { console.log(TAG + ' [GETUI] getClientid dump skip: ' + e); }
                return cid;
            });
            console.log(TAG + ' [getui] hooked getClientid');
        }
    } catch (e) { console.log(TAG + ' [getui] getClientid hook skip: ' + e); }

    // ======================================================================
    // 3) 极光：JPushMessageReceiver.onNotifyMessageArrived / onMessage（读 message/extra）。
    //    类名/方法随极光版本漂移，现场 jadx 核对。方法可能多重载 → 逐重载挂。
    // ======================================================================
    function dumpJpushMsgObj(prefix, obj) {
        try {
            if (obj === null || obj === undefined) { console.log(TAG + ' ' + prefix + ' msg=null'); return; }
            // 极光 NotificationMessage/CustomMessage 字段名随版本变，反射读常见字段；
            // getDeclaredField 只看本类 → 同时沿继承链向上找（R8 可能把字段留在父类）。
            var fields = ['notificationContent', 'message', 'notificationExtras', 'extra', 'notificationTitle', 'msgId', 'messageId'];
            var startCls = obj.getClass();
            for (var i = 0; i < fields.length; i++) {
                var fname = fields[i];
                var cur = startCls;
                var read = false;
                while (cur !== null && !read) {
                    try {
                        var f = cur.getDeclaredField(fname);
                        f.setAccessible(true);
                        var val = f.get(obj);
                        if (val !== null && val !== undefined) {
                            var sv = '' + val;
                            console.log(TAG + ' ' + prefix + ' ' + fname + '=' + sv);
                            scanLeads('JPUSH.' + fname, sv);
                        }
                        read = true; // 找到该字段（不论值是否 null）即停沿链。
                    } catch (ie) {
                        try { cur = cur.getSuperclass(); } catch (se) { cur = null; }
                    }
                }
            }
            // 兜底：整体 toString 也扫一遍（部分版本字段名全变）。
            try {
                var ts = '' + obj.toString();
                scanLeads('JPUSH.toString', ts);
            } catch (te) { /* ignore */ }
        } catch (e) {
            console.log(TAG + ' ' + prefix + ' dump skip: ' + e);
        }
    }
    try {
        var jr = safeUse(CFG.jpushReceiver);
        if (jr) {
            // onNotifyMessageArrived(Context, NotificationMessage) —— 可能多重载，逐个挂。
            if (jr.onNotifyMessageArrived) {
                var okNA = hookAllOverloads(jr, 'onNotifyMessageArrived', function () {
                    try {
                        console.log(TAG + ' [JPUSH] ===== onNotifyMessageArrived 命中（argc=' + arguments.length + '）=====');
                        if (arguments.length >= 2) dumpJpushMsgObj('[JPUSH]', arguments[1]);
                        else if (arguments.length >= 1) dumpJpushMsgObj('[JPUSH]', arguments[0]);
                    } catch (e) { console.log(TAG + ' [JPUSH] onNotifyMessageArrived dump skip: ' + e); }
                    return this.onNotifyMessageArrived.apply(this, arguments);
                });
                if (okNA) console.log(TAG + ' [jpush] hooked onNotifyMessageArrived');
            }
            // onMessage(Context, CustomMessage) —— 透传自定义消息（C2 常走这条）。
            if (jr.onMessage) {
                var okOM = hookAllOverloads(jr, 'onMessage', function () {
                    try {
                        console.log(TAG + ' [JPUSH] ===== onMessage 命中（argc=' + arguments.length + '）=====');
                        if (arguments.length >= 2) dumpJpushMsgObj('[JPUSH]', arguments[1]);
                        else if (arguments.length >= 1) dumpJpushMsgObj('[JPUSH]', arguments[0]);
                    } catch (e) { console.log(TAG + ' [JPUSH] onMessage dump skip: ' + e); }
                    return this.onMessage.apply(this, arguments);
                });
                if (okOM) console.log(TAG + ' [jpush] hooked onMessage');
            }
        } else {
            console.log(TAG + ' [jpush] ' + CFG.jpushReceiver + ' 未加载。'
                + '下一步：jadx 搜 extends JPushMessageReceiver 核对真实子类/方法（极光版本漂移），回填 CFG.jpushReceiver。');
        }
    } catch (e) {
        console.log(TAG + ' [jpush] hook skip: ' + e);
    }

    // 极光定人锚点：JPushInterface.getRegistrationID(Context) → regId，向极光调注册主体。
    try {
        var ji = safeUse(CFG.jpushIface);
        if (ji && ji.getRegistrationID) {
            hookAllOverloads(ji, 'getRegistrationID', function () {
                var rid = this.getRegistrationID.apply(this, arguments);
                try {
                    console.log(TAG + ' [REGID][JPUSH] registrationID=' + rid
                        + '  ⟶ 调证：定人锚点，凭 regId+极光 AppKey 向极光调注册主体/付费实名');
                } catch (e) { console.log(TAG + ' [JPUSH] getRegistrationID dump skip: ' + e); }
                return rid;
            });
            console.log(TAG + ' [jpush] hooked getRegistrationID');
        }
    } catch (e) { console.log(TAG + ' [jpush] getRegistrationID hook skip: ' + e); }

    console.log(TAG + ' 探针已就位（只读）：等推送下发触发回调即落证。'
        + ' 若长时间无输出 → 1) 确认推送通道在用（FCM 需 GMS / 小米华为 push 裸 AOSP 静默失败）；'
        + ' 2) 样本完成注册后再注入；3) jadx 核对被混淆类名回填 CFG。绝不外发/不拦截/不修改任何消息。');
});