// sdk-appkey-hook.js — hook 安装归因/统计/推送 SDK 初始化，抓 appKey/租户标识 + 绑定包名 + 回调/host（OpenInstall/DeepInstall/友盟/Firebase/个推/极光）
// 适用：杀猪盘改包常挂安装归因(OpenInstall)做分发追踪、挂统计/推送做留存——appKey 是平台内唯一租户标识，凭它向 SDK 服务商调开发者账户/绑定包名/渠道/安装日志=分发链定人
// 跑：frida -U -f <包名> -l sdk-appkey-hook.js -q   （必须 -f spawn：SDK init 在 Application.onCreate 极早期，attach 已起进程会漏）
// 改：各 SDK 类名/方法名随版本与混淆变；本脚本按"类存在性"逐个 try，命中即 hook、不命中打未命中。改时按报告里实际 SDK 包名增删 BLOCK；混淆样本类名被改 → 退回 cipher-hook/sharedprefs-hook 看落盘的 appKey
'use strict';

// ---- 内存账本：去重 + 收尾汇总（一眼看全所有抓到的租户锚点）----
var SEEN = {};               // 去重键
var ANCHORS = [];            // [{sdk, kind, value, note}]  收尾统一汇总
function _once(key) {
    if (!key) return false;
    if (SEEN[key]) return false;
    SEEN[key] = 1;
    return true;
}
// 记一条调证锚点：sdk=哪个SDK，kind=appKey/channel/packageName/host/callback...，value=值，note=调证线索
function _anchor(sdk, kind, value, note) {
    var v = (value === null || value === undefined) ? '<null>' : ('' + value);
    if (!_once(sdk + '|' + kind + '|' + v)) return;
    ANCHORS.push({ sdk: sdk, kind: kind, value: v, note: note || '' });
    console.log('[sdk][' + sdk + '] ' + kind + ' = ' + v + (note ? '   -> ' + note : ''));
}

// ---- 工具：安全转字符串（参数可能是 null / 非 String 对象）----
function _s(x) {
    try { return (x === null || x === undefined) ? '<null>' : ('' + x); } catch (e) { return '<tostr-fail>'; }
}
// 当前进程包名（用于把 appKey 绑定到具体包名 = 调证时核验 SDK 后台登记的绑定包名是否一致）
// 注意：spawn 极早期 currentApplication() 可能尚为 null，已 try 兜底返回 <pkg-unknown>，不影响后续 hook。
function _pkg() {
    try {
        var ctx = Java.use('android.app.ActivityThread').currentApplication();
        if (ctx) return '' + ctx.getPackageName();
    } catch (e) {}
    return '<pkg-unknown>';
}

// ---- 工具：一个方法不论几个重载都挂上同一 onEnter 取参（SDK init 常有多重载）----
// 不改返回值、不改业务，只读参数做取证；每个重载各自 try，单个失败不影响其余。
// 调原始实现用闭包捕获的 ov.apply(this, arguments)：Frida 的 overload 对象 .implementation 替换后，
// 其 .call/.apply 调的是原始实现、不递归（与库内 activity-nav-hook.js 的 sa=overload(...)+sa.call(this,...) 同模式，已验证）。
function _hookAllOverloads(clazz, methodName, onArgs, tag) {
    try {
        var m = clazz[methodName];
        if (!m) { console.log('[sdk][' + tag + '] ' + methodName + ' 不存在 skip'); return false; }
        // 取到的若不是方法包装器（没有 overloads 数组）则放弃，避免对字段/属性误挂。
        if (!m.overloads || typeof m.overloads.length !== 'number') {
            console.log('[sdk][' + tag + '] ' + methodName + ' 非方法(无 overloads) skip');
            return false;
        }
        var n = m.overloads.length, hooked = 0;
        for (var i = 0; i < n; i++) {
            (function (ov) {
                try {
                    ov.implementation = function () {
                        try { onArgs(Array.prototype.slice.call(arguments), this); }
                        catch (e) { console.log('[sdk][' + tag + '] ' + methodName + ' read-args skip: ' + e); }
                        return ov.apply(this, arguments);   // 调原始实现，不改业务
                    };
                    hooked++;
                } catch (e) { console.log('[sdk][' + tag + '] ' + methodName + ' overload hook skip: ' + e); }
            })(m.overloads[i]);
        }
        if (hooked > 0) console.log('[sdk][' + tag + '] ' + methodName + ' hooked (' + hooked + '/' + n + ' overloads)');
        return hooked > 0;
    } catch (e) { console.log('[sdk][' + tag + '] hook ' + methodName + ' skip: ' + e); return false; }
}

// ---- 工具：hook 某 getter，读其返回值做取证（保存 overload 引用，避免多重载时 this[mn]() 抛歧义）----
// 修正点：原稿 FirebaseOptions getter 用 this[mn]() 调原始，若该 getter 恰有重载会抛 'more than one overload'；
// 这里逐 overload 保存引用、用 ov.apply(this, arguments) 调原始，稳健覆盖单/多重载。
function _hookGetterReturn(clazz, methodName, onRet, tag) {
    try {
        var m = clazz[methodName];
        if (!m || !m.overloads) { return false; }
        var n = m.overloads.length, hooked = 0;
        for (var i = 0; i < n; i++) {
            (function (ov) {
                try {
                    ov.implementation = function () {
                        var r = ov.apply(this, arguments);
                        try { onRet(r, this); } catch (e) { console.log('[sdk][' + tag + '] ' + methodName + ' read-ret skip: ' + e); }
                        return r;
                    };
                    hooked++;
                } catch (e) { console.log('[sdk][' + tag + '] ' + methodName + ' getter hook skip: ' + e); }
            })(m.overloads[i]);
        }
        return hooked > 0;
    } catch (e) { console.log('[sdk][' + tag + '] hook getter ' + methodName + ' skip: ' + e); return false; }
}

// ---- 工具：某类是否存在（用于按 SDK 存在性决定是否挂）----
function _has(cls) { try { Java.use(cls); return true; } catch (e) { return false; } }

Java.perform(function () {

    var PKG = _pkg();
    console.log('[sdk] 当前包名: ' + PKG + '   (调证时核验 SDK 后台登记的绑定包名是否与此一致)');

    // ============ A. OpenInstall（安装归因/渠道追踪）——本案命中 appKey ehahb5 ============
    // OpenInstall：知道每个受害人从哪个渠道/短链来 → appKey 是平台唯一租户标识。
    // 调证：凭 appKey 向 openinstall.com 运营方调开发者账户实名/注册手机号邮箱/付款/绑定包名/渠道包/短链落地页/回调URL/安装点击日志=分发链定人。
    // 抓到 appKey → 这就是"P1 实调"的锚点(报告 H2)；本案 ehahb5，其它案见 wfjmj8。
    (function hookOpenInstall() {
        // (1) OpenInstall.init(Context) / init(Context, Configuration[, AppInstallAdapter])：appKey 可能从 manifest 的 meta-data 读，也可能在 Configuration 里
        if (_has('com.fm.openinstall.OpenInstall')) {
            try {
                var OI = Java.use('com.fm.openinstall.OpenInstall');
                _hookAllOverloads(OI, 'init', function (args) {
                    _anchor('OpenInstall', 'init调用', 'init(' + args.length + '参数)', '安装归因初始化触发，下面看 appKey/Configuration');
                    for (var i = 0; i < args.length; i++) {
                        var a = args[i];
                        if (a === null) continue;
                        var cn = '';
                        try { cn = '' + a.getClass().getName(); } catch (e) {}
                        // Configuration 对象 → 解析其内部 appKey（见 (2)，多由其构造/Builder 传入或 getAppKey 读出）
                        if (cn.indexOf('Configuration') >= 0) _anchor('OpenInstall', 'Configuration对象', cn, '见下方 appKey 字段');
                    }
                }, 'openinstall');
            } catch (e) { console.log('[sdk][openinstall] OpenInstall.init hook skip: ' + e); }
        } else {
            console.log('[sdk][openinstall] com.fm.openinstall.OpenInstall 未命中(本样本可能未挂 OpenInstall，或类名被混淆)');
        }

        // (2) Configuration：真实 OpenInstall 多版本 appKey 走【构造】new Configuration(String appKey) 或 Builder，少数版本才 setAppKey。
        //     —— 故对 $init / setAppKey / getAppKey 全覆盖，本案 ehahb5 最可能由 $init 或 getAppKey 命中。
        if (_has('com.fm.openinstall.Configuration')) {
            try {
                var Conf = Java.use('com.fm.openinstall.Configuration');
                // 构造：new Configuration(appKey) —— 主流写法，必挂
                _hookAllOverloads(Conf, '$init', function (args) {
                    for (var i = 0; i < args.length; i++) {
                        var sv = _s(args[i]);
                        // appKey 一般是短 token（本案 ehahb5），不是 Context/对象；取其中像字符串的实参
                        if (args[i] !== null && sv !== '<null>' && sv.length > 0 && sv.length < 64 && sv.indexOf('@') < 0 && sv.indexOf(' ') < 0) {
                            _anchor('OpenInstall', 'appKey(构造)', sv, 'P1实调: 向 openinstall.com 调开发者账户实名+绑定包名(' + PKG + ')+渠道+安装/点击日志=分发链定人');
                        }
                    }
                }, 'openinstall');
                // setAppKey(String)（部分版本）
                if (Conf.setAppKey) {
                    _hookAllOverloads(Conf, 'setAppKey', function (args) {
                        _anchor('OpenInstall', 'appKey(setAppKey)', _s(args[0]), 'P1实调: 向 openinstall.com 调开发者账户实名+绑定包名(' + PKG + ')+渠道+安装/点击日志=分发链定人');
                    }, 'openinstall');
                }
                // getAppKey()：SDK init 内部读 Configuration.getAppKey() 时把值兜出来（覆盖 manifest 注入到 Configuration 的情形）
                if (Conf.getAppKey) {
                    _hookGetterReturn(Conf, 'getAppKey', function (r) {
                        var sv = _s(r);
                        if (sv !== '<null>' && sv.length > 0) _anchor('OpenInstall', 'appKey(getAppKey)', sv, 'P1实调: 同上，向 openinstall.com 调开发者账户+绑定包名+渠道/安装日志');
                    }, 'openinstall');
                }
            } catch (e) { console.log('[sdk][openinstall] Configuration hook skip: ' + e); }
            // Builder（如存在）：Configuration$Builder.appKey(String)
            try {
                var Builder = Java.use('com.fm.openinstall.Configuration$Builder');
                if (Builder.appKey) {
                    _hookAllOverloads(Builder, 'appKey', function (args) {
                        _anchor('OpenInstall', 'appKey(Builder)', _s(args[0]), 'P1实调: 同上，向 openinstall.com 调开发者账户+绑定包名+渠道日志');
                    }, 'openinstall');
                }
            } catch (e) { /* 该版本无 Builder，正常 */ }
        } else {
            console.log('[sdk][openinstall] com.fm.openinstall.Configuration 未命中');
        }

        // (3) 兜底：appKey 常写在 AndroidManifest meta-data，名为 "com.openinstall.APP_KEY"，
        //     SDK 内部多用 ApplicationInfo.metaData.get/getString(key) 读 → 见 G 段统一 hook Bundle.get/getString。
    })();

    // ============ B. DeepInstall（另一安装归因/深链 SDK，类名按现场调）============
    // DeepInstall 类名各家不一，常见 com.deepshare / com.deeplink / io.deepinstall 等；命中 init/setAppKey 即抓。
    (function hookDeepInstall() {
        var cands = [
            'com.deepshare.DeepShare', 'com.deeplink.DeepLink',
            'io.deepinstall.DeepInstall', 'com.deepinstall.DeepInstall'
        ];
        var any = false;
        cands.forEach(function (cls) {
            if (!_has(cls)) return;
            any = true;
            try {
                var C = Java.use(cls);
                ['init', 'setAppKey', 'setAppId', 'initialize'].forEach(function (mn) {
                    if (C[mn]) _hookAllOverloads(C, mn, function (args) {
                        _anchor('DeepInstall', mn + '参数', args.map(_s).join(' | '),
                            '深链/归因SDK初始化，提取其中的 appKey/appId 向服务商调绑定包名+渠道+安装日志');
                    }, 'deepinstall');
                });
            } catch (e) { console.log('[sdk][deepinstall] ' + cls + ' hook skip: ' + e); }
        });
        if (!any) console.log('[sdk][deepinstall] 未命中常见 DeepInstall 类(' + cands.join(' / ') + ')；若报告里见到深链SDK，把真实类名加进 cands');
    })();

    // ============ C. 友盟 UMeng（统计 SDK）——抓 appKey/channel ============
    // UMConfigure.init(Context, appKey, channel, deviceType, pushSecret)：友盟 appKey 是友盟后台唯一应用标识，channel=渠道。
    // 调证：凭 appKey 向友盟(及阿里，友盟属阿里)调应用注册者实名/绑定包名/渠道分布/日活设备 → 渠道分布可佐证分发规模与人群。
    (function hookUMeng() {
        if (_has('com.umeng.commonsdk.UMConfigure')) {
            try {
                var UM = Java.use('com.umeng.commonsdk.UMConfigure');
                _hookAllOverloads(UM, 'init', function (args) {
                    // 典型签名 init(Context, String appKey, String channel, int deviceType, String pushSecret)
                    if (args.length >= 3) {
                        _anchor('UMeng', 'appKey', _s(args[1]), '向友盟(阿里旗下)调应用注册者实名+绑定包名(' + PKG + ')+渠道分布');
                        _anchor('UMeng', 'channel', _s(args[2]), '渠道标识=分发来源，佐证分发规模/对照 OpenInstall 渠道');
                    } else {
                        _anchor('UMeng', 'init参数', args.map(_s).join(' | '), '解析其中 appKey/channel');
                    }
                    if (args.length >= 5 && args[4] !== null) _anchor('UMeng', 'pushSecret', _s(args[4]), '推送密钥，关联友盟推送通道');
                }, 'umeng');
                // 老接口 preInit(Context, appKey, channel)
                if (UM.preInit) _hookAllOverloads(UM, 'preInit', function (args) {
                    if (args.length >= 3) {
                        _anchor('UMeng', 'appKey(preInit)', _s(args[1]), '同上');
                        _anchor('UMeng', 'channel(preInit)', _s(args[2]), '渠道标识');
                    }
                }, 'umeng');
            } catch (e) { console.log('[sdk][umeng] UMConfigure hook skip: ' + e); }
        } else {
            console.log('[sdk][umeng] com.umeng.commonsdk.UMConfigure 未命中(无友盟统计SDK，或老版本 com.umeng.analytics.MobclickAgent)');
            // 老版友盟兜底：MobclickAgent + UMGameAgent 的 appKey 多走 manifest，由 G 段 Bundle 兜底捕获
        }
    })();

    // ============ D. Firebase（境外）——抓 apiKey/applicationId/projectId ============
    // FirebaseOptions 持 apiKey/applicationId/projectId/gcmSenderId/storageBucket：projectId 是 Google 项目唯一标识。
    // 调证：凭 projectId/applicationId 对 Google/Firebase 发保全(境外协查)，调项目创建者/管理员/账单/登录IP(报告 P2)。本案见 nebulachat3。
    (function hookFirebase() {
        // (1) FirebaseOptions.Builder.setApiKey/setApplicationId/setProjectId（手动构造时）
        if (_has('com.google.firebase.FirebaseOptions$Builder')) {
            try {
                var FB = Java.use('com.google.firebase.FirebaseOptions$Builder');
                var map = {
                    'setApiKey': 'apiKey', 'setApplicationId': 'applicationId',
                    'setProjectId': 'projectId', 'setGcmSenderId': 'gcmSenderId',
                    'setStorageBucket': 'storageBucket', 'setDatabaseUrl': 'databaseUrl'
                };
                Object.keys(map).forEach(function (mn) {
                    if (FB[mn]) _hookAllOverloads(FB, mn, function (args) {
                        var note = (map[mn] === 'projectId' || map[mn] === 'applicationId')
                            ? 'P2境外协查: 凭此对 Google/Firebase 调项目创建者/管理员/账单/登录IP'
                            : 'Firebase 项目字段，串 projectId 一并调证';
                        _anchor('Firebase', map[mn], _s(args[0]), note);
                    }, 'firebase');
                });
            } catch (e) { console.log('[sdk][firebase] FirebaseOptions$Builder hook skip: ' + e); }
        }
        // (2) FirebaseOptions.fromResource(Context)：值多从 google-services.json 生成的资源读 → hook getApiKey/getProjectId 读已构造对象
        //     修正点：用 _hookGetterReturn 保存 overload 引用调原始，避免 getter 偶有重载时抛歧义。
        if (_has('com.google.firebase.FirebaseOptions')) {
            try {
                var FO = Java.use('com.google.firebase.FirebaseOptions');
                [['getApiKey', 'apiKey'], ['getApplicationId', 'applicationId'], ['getProjectId', 'projectId'], ['getGcmSenderId', 'gcmSenderId'], ['getStorageBucket', 'storageBucket']].forEach(function (pair) {
                    var mn = pair[0], kind = pair[1];
                    if (FO[mn]) _hookGetterReturn(FO, mn, function (r) {
                        var note = (kind === 'projectId' || kind === 'applicationId')
                            ? 'P2境外协查: 凭此对 Google/Firebase 调项目创建者/管理员/账单/登录IP'
                            : 'Firebase 项目字段';
                        _anchor('Firebase', kind, _s(r), note);
                    }, 'firebase');
                });
                console.log('[sdk][firebase] FirebaseOptions getter hooked（init 时读 google-services.json 生成值即触发）');
            } catch (e) { console.log('[sdk][firebase] FirebaseOptions hook skip: ' + e); }
        }
        if (!_has('com.google.firebase.FirebaseOptions')) console.log('[sdk][firebase] FirebaseOptions 未命中(无 Firebase，或仅静态资源 google-services.json — 改用 jadx 看 res/values/strings.xml 的 google_app_id/firebase_database_url)');
    })();

    // ============ E. 个推 com.igexin（推送 SDK）——抓 appId/appKey/appSecret ============
    // 个推 PushManager.initialize(Context)，appId/appKey/appSecret 多走 manifest meta-data。
    // 调证：凭个推 appId 向个推(每日互动)调注册应用实名/绑定包名/推送下发记录 → 谁在给这批设备推内容。
    (function hookGetui() {
        var cands = ['com.igexin.sdk.PushManager', 'com.igexin.sdk.PushService'];
        var any = false;
        cands.forEach(function (cls) {
            if (!_has(cls)) return;
            any = true;
            try {
                var C = Java.use(cls);
                ['initialize', 'registerPushIntentService'].forEach(function (mn) {
                    if (C[mn]) _hookAllOverloads(C, mn, function (args) {
                        _anchor('Getui', mn + '调用', cls, '个推初始化触发；appId/appKey 多在 manifest，见下方 G 段 meta-data 兜底');
                    }, 'getui');
                });
            } catch (e) { console.log('[sdk][getui] ' + cls + ' hook skip: ' + e); }
        });
        if (!any) console.log('[sdk][getui] com.igexin.* 未命中(无个推)');
    })();

    // ============ F. 极光 cn.jpush（推送 SDK）——抓 appKey ============
    // 极光 JPushInterface.init(Context)，appKey 走 manifest meta-data "JPUSH_APPKEY"。
    // 调证：凭极光 appKey 向极光(和讯)调注册应用实名/绑定包名/推送记录。
    (function hookJpush() {
        if (_has('cn.jpush.android.api.JPushInterface')) {
            try {
                var JP = Java.use('cn.jpush.android.api.JPushInterface');
                ['init', 'setDebugMode'].forEach(function (mn) {
                    if (JP[mn]) _hookAllOverloads(JP, mn, function (args) {
                        if (mn === 'init') _anchor('JPush', 'init调用', '触发', '极光初始化；appKey 在 manifest meta-data JPUSH_APPKEY，见 G 段兜底');
                    }, 'jpush');
                });
                // 部分集成走 JCoreInterface
            } catch (e) { console.log('[sdk][jpush] JPushInterface hook skip: ' + e); }
        } else {
            console.log('[sdk][jpush] cn.jpush.android.api.JPushInterface 未命中(无极光)');
        }
    })();

    // ============ G. 兜底：manifest meta-data 读取（个推/极光/OpenInstall 的 appKey 多藏这里）============
    // 很多 SDK 的 appKey 不经代码传参，而是 SDK 内部用 PackageManager 读 AndroidManifest 的 <meta-data> 到 ApplicationInfo.metaData(Bundle)，
    // 再 bundle.get(key)/getString(key)/getInt(key) 取值。故同时 hook Bundle.get(String) 与 getString(...)：
    //   - getString：值是字符串型 meta-data 时命中；
    //   - get(Object)：兜住 SDK 用 metaData.get("com.openinstall.APP_KEY") 且值被 manifest 解析成非纯 String（如带前缀/数字）时 getString 返 null 的情形（OpenInstall 常见）。
    // 性能告警：Bundle.get/getString 是高频系统调用，implementation 替换会拖慢冷启动；已用 META_RE 关键词 + 去重 + 短路（key 不匹配立即返回）压噪与降耗。
    //   若发现拖慢导致 ANR/抓不全，可注释掉本段、改走 A~F 的具体 SDK hook + 静态 apktool 读 manifest。
    (function hookMetaData() {
        // 关键词：覆盖 OpenInstall/友盟/个推/极光/Firebase 常见 meta-data key
        var META_RE = /(openinstall|umeng|UMENG|getui|igexin|PUSH_?APPID|PUSH_?APPKEY|PUSH_?APPSECRET|JPUSH_?APPKEY|JPUSH_?CHANNEL|APP_?KEY|APP_?ID|APP_?SECRET|google_app_id|firebase|gcm|channel|CHANNEL)/i;
        try {
            var Bundle = Java.use('android.os.Bundle');
            // (1) getString(String) / getString(String,String)：字符串型 meta-data
            if (Bundle.getString) {
                _hookAllOverloads(Bundle, 'getString', function (args, self) {
                    try {
                        var k = _s(args[0]);
                        if (!META_RE.test(k)) return;                 // 短路：key 不匹配立即返回，降高频开销
                        var v = null;
                        try { v = self.getString(args[0]); } catch (e) {}
                        if (v !== null && _once('meta|' + k + '|' + v)) {
                            _anchor('meta-data', k, _s(v), '从 AndroidManifest meta-data 读出的 SDK 标识，按 key 前缀判定归属SDK并调对应服务商');
                        }
                    } catch (e) {}
                }, 'meta');
                console.log('[sdk][meta] Bundle.getString hooked（捕获 manifest meta-data 型 appKey）');
            }
            // (2) get(Object/String)：兜住 metaData.get(key) 返回非纯 String（OpenInstall APP_KEY 常被解析成非 String，getString 会返 null）
            if (Bundle.get) {
                _hookGetterReturn(Bundle, 'get', function (r, self) {
                    // get 的返回值即为 meta-data 值；但 onRet 拿不到入参 key，故在此重新判定不便——改为只在值像 token 且账本未记过时补记。
                    // 为拿到 key，这里改用 onArgs 模式更准：见下方 _hookAllOverloads 版本同时覆盖。
                }, 'meta');
                // 用 onArgs 形式精确拿 key+value（get 单参，返回 Object）
                _hookAllOverloads(Bundle, 'get', function (args, self) {
                    try {
                        var k = _s(args[0]);
                        if (!META_RE.test(k)) return;                 // 短路降耗
                        var v = null;
                        try { v = self.get(args[0]); } catch (e) {}
                        var sv = _s(v);
                        if (v !== null && sv !== '<null>' && _once('metaget|' + k + '|' + sv)) {
                            _anchor('meta-data', k + '(get)', sv, '从 AndroidManifest meta-data(get) 读出的 SDK 标识；OpenInstall APP_KEY 常走此路命中');
                        }
                    } catch (e) {}
                }, 'meta');
                console.log('[sdk][meta] Bundle.get hooked（兜 metaData.get 型 appKey，覆盖 getString 返 null 的非 String 值）');
            }
        } catch (e) { console.log('[sdk][meta] Bundle meta-data hook skip: ' + e); }
    })();

    // ============ 汇总：收尾把所有抓到的租户锚点打一遍（一眼出调证清单）============
    function dumpAnchors() {
        console.log('\n========== [sdk] 安装归因/统计/推送 SDK 租户锚点汇总（调证清单） ==========');
        console.log('[sdk][SUMMARY] 绑定包名: ' + PKG + '   (向各 SDK 服务商核验后台登记的绑定包名是否一致)');
        if (ANCHORS.length === 0) {
            console.log('[sdk][SUMMARY][未命中] 没抓到任何 SDK 初始化 appKey/租户标识。下一步：');
            console.log('[sdk][SUMMARY]   1) 确认用了 -f spawn（SDK init 在 Application 极早期，attach 必漏）');
            console.log('[sdk][SUMMARY]   2) 类名被混淆 → 用 jadx 搜 "openinstall/umeng/jpush/igexin/firebase" 字符串定位真实类名，回填本脚本 cands/类名');
            console.log('[sdk][SUMMARY]   3) appKey 走 manifest 但 Bundle.get/getString 没命中 → adb pull APK 后 apktool 解 AndroidManifest.xml 直接读 <meta-data>');
            console.log('[sdk][SUMMARY]   4) appKey 已写入本地 → 配 sharedprefs-hook.js / sqlite-hook.js 看落盘值');
        } else {
            console.log('[sdk][SUMMARY] 共 ' + ANCHORS.length + ' 条锚点：');
            ANCHORS.forEach(function (a) {
                console.log('[sdk][SUMMARY]   [' + a.sdk + '] ' + a.kind + ' = ' + a.value + (a.note ? '   -> ' + a.note : ''));
            });
            console.log('[sdk][SUMMARY] 调证落点：appKey/projectId/租户标识 = 向 SDK 服务商调开发者账户实名+绑定包名+渠道/安装日志=分发链定人(报告 H2/J)。');
            console.log('[sdk][SUMMARY] 本案参照：OpenInstall appKey=ehahb5（P1 实调），其它案见 wfjmj8。');
        }
        console.log('========== [sdk] END ==========\n');
    }
    globalThis.dumpAnchors = dumpAnchors;   // frida REPL 里随时输入 dumpAnchors() 手动汇总
    setTimeout(dumpAnchors, 8000);
    console.log('[sdk] armed —— SDK init 在冷启动极早期；约 8s 后自动汇总一次。想随时汇总在 frida REPL 输入: dumpAnchors()');
});