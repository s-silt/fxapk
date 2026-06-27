// activity-nav-hook.js — Activity 跳转流 + 列全 Activity + fxGoto 强跳 + 视频/倒计时层强制跳过，绕「加载页→视频→登录页」多级门控直达登录/聊天链路
// 适用：加固改包(如 Telegram/MTProto 二开)卡 splash→视频引导→登录页(LoginNewActivity 之类)进不去抓包；视频是"播完才进登录"型门控。hook 框架基类，子类名混淆也命中
// 跑：frida -U -f <包名> -l activity-nav-hook.js -q  （spawn；先看 [acts] 全表/[nav] 流；卡视频默认自动 seekTo 末尾跳过，不行就 REPL 输 fxEndVideo()/fxSkipGate('登录类名')；强跳 fxGoto('类名')）
// 改：(1) SPLASH_RE 按 [nav] 实际类名调；(2) 视频跳不过→fxEndVideo() 手动触发完成回调、或 fxFragments() 看单 Activity 内的登录 View/Fragment；(3) SKIP_VIDEO/SKIP_COUNTDOWN/KILL_SPLASH 三档力度按需开
'use strict';

// ---- 现场可调：疑似 splash/loading/引导/视频层 的类名特征（命中才动它，默认只打印不 finish）----
var SPLASH_RE = /(splash|launch|loading|guide|welcome|video|advert|\bad\b|boot|start(up)?)/i;
var KILL_SPLASH = false;      // true: 命中 SPLASH_RE 的 Activity onCreate 后立即 finish（最猛，可能打断"播完→进登录"，先 false 观察）
var SKIP_COUNTDOWN = false;   // true: 中和倒计时(CountDownTimer/postDelayed 长延时)，让 splash 尽快走完（比 finish 温和）
var SKIP_VIDEO = true;        // true: 视频引导层让其立刻"播完"——start() 后 seekTo 到结尾触发真实 onCompletion，app 自己的"进登录"逻辑就会跑（对跳 Activity / 单页内切 View 都有效）。仅在真有视频播放时生效，benign。
var VIDEO_MAX_MS = 60000;     // 只对时长 <= 此值的媒体自动 seek 末尾（典型引导视频几秒~几十秒），避免误伤长内容/直播流

// 最近一个进入 onCreate 的 Activity 实例 —— fxGoto/fxFragments 没有别的 context 时用它。
var LAST_ACT = null;
// 去重账本：onCreate / startActivity 流水太吵，相同条目只打一次。
var SEEN = {};
function _once(k) { if (SEEN[k]) return false; SEEN[k] = true; return true; }

// ---- 从 Intent 里抽出「目标组件/动作」做可读打印 ----
function _intentStr(intent) {
    try {
        if (intent === null) return '<null-intent>';
        var comp = null;
        try { var c = intent.getComponent(); if (c !== null) comp = '' + c.getClassName(); } catch (e) {}
        var act = null;
        try { act = '' + intent.getAction(); } catch (e) {}
        var data = null;
        try { var d = intent.getDataString(); if (d !== null) data = '' + d; } catch (e) {}
        var parts = [];
        if (comp) parts.push('cls=' + comp);
        if (act && act !== 'null') parts.push('action=' + act);
        if (data) parts.push('data=' + data);     // deeplink 落点，常含拉起参数
        return parts.length ? parts.join(' ') : ('' + intent);
    } catch (e) { return '<intent-fail:' + e + '>'; }
}

// 把函数挂到 REPL 全局：Frida 运行时(V8/QuickJS)只有 globalThis，没有 Node 的 global。
function _expose(name, fn) {
    try { globalThis[name] = fn; } catch (e) { console.log('[nav] expose ' + name + ' skip: ' + e); }
}

Java.perform(function () {

    // ============ A. Activity.onCreate：看清启动后到底走了哪些页（跳转流第一手）============
    // 抓到什么 -> 真实的 splash/视频/登录/主页 类名全链(hook 基类，混淆子类也命中)，对照案卷找登录页(如 LoginNewActivity$PasswordView 的宿主 Activity)
    try {
        var Activity = Java.use('android.app.Activity');
        Activity.onCreate.overload('android.os.Bundle').implementation = function (b) {
            try {
                var cls = '' + this.getClass().getName();
                LAST_ACT = this;   // 记下最近 Activity 实例，fxGoto/fxFragments 兜底用
                if (_once('onCreate:' + cls)) {
                    var isSplash = SPLASH_RE.test(cls);
                    console.log('[nav] onCreate  ' + cls + (isSplash ? '   <== 疑似 splash/loading/视频层' : ''));
                    if (isSplash && KILL_SPLASH) {
                        try { this.finish(); console.log('[nav] -> 已 finish() 该 splash（KILL_SPLASH=true）。若主页没起来，关掉 KILL_SPLASH 改用 fxEndVideo()/fxGoto 直跳'); }
                        catch (e2) { console.log('[nav] finish splash skip: ' + e2); }
                    }
                }
            } catch (e) { console.log('[nav] onCreate inspect skip: ' + e); }
            return this.onCreate(b);
        };
        console.log('[nav] Activity.onCreate hooked（看 [nav] onCreate 流确认有哪些页）');
    } catch (e) { console.log('[nav] Activity.onCreate hook skip: ' + e); }

    // ============ B. startActivity：跳转流的「边」（谁拉起了谁，含 deeplink data）============
    function _wrapStart(holderName, tag) {
        try {
            var Holder = Java.use(holderName);
            var ovs = Holder.startActivity.overloads;
            var hooked = 0;
            ovs.forEach(function (ov) {
                try {
                    var argc = ov.argumentTypes.length;
                    if (argc < 1 || ov.argumentTypes[0].className !== 'android.content.Intent') return;
                    ov.implementation = function () {
                        try {
                            var from = '' + this.getClass().getName();
                            var to = _intentStr(arguments[0]);
                            if (_once('startActivity:' + from + '->' + to)) {
                                console.log('[' + tag + '] startActivity  ' + from + '  -->  ' + to);
                            }
                        } catch (e) { console.log('[' + tag + '] startActivity inspect skip: ' + e); }
                        return ov.apply(this, arguments);   // 透传原始所有参数，跨重载安全
                    };
                    hooked++;
                } catch (e) { console.log('[' + tag + '] startActivity overload skip: ' + e); }
            });
            console.log('[' + tag + '] ' + holderName + '.startActivity hooked (' + hooked + ' overload)');
        } catch (e) { console.log('[' + tag + '] ' + holderName + '.startActivity hook skip: ' + e); }
    }
    _wrapStart('android.app.Activity', 'nav');          // B1: Activity 自身的拉起
    _wrapStart('android.content.ContextWrapper', 'nav'); // B2: Application/Service/库等非 Activity launcher 的拉起

    // ============ C.（可选）跳过倒计时：中和 CountDownTimer / 长延时 postDelayed ============
    if (SKIP_COUNTDOWN) {
        try {
            var CDT = Java.use('android.os.CountDownTimer');
            CDT.$init.overload('long', 'long').implementation = function (total, interval) {
                try { console.log('[nav][skip] CountDownTimer(' + total + 'ms) -> 压到 1ms'); } catch (e) {}
                return this.$init(1, 1);
            };
            console.log('[nav][skip] CountDownTimer 压缩 hooked（SKIP_COUNTDOWN=true）');
        } catch (e) { console.log('[nav][skip] CountDownTimer hook skip: ' + e); }
        try {
            var Handler = Java.use('android.os.Handler');
            Handler.postDelayed.overload('java.lang.Runnable', 'long').implementation = function (r, delay) {
                try { if (delay > 1200) { console.log('[nav][skip] postDelayed ' + delay + 'ms -> 50ms'); delay = 50; } } catch (e) {}
                return this.postDelayed(r, delay);
            };
            console.log('[nav][skip] Handler.postDelayed 长延时压缩 hooked');
        } catch (e) { console.log('[nav][skip] Handler.postDelayed hook skip: ' + e); }
    }

    // ============ F. 视频/媒体引导层强制跳过（SKIP_VIDEO）============
    // 套路：splash 之后播一段 mp4 引导视频，"视频播完"的回调里才 startActivity 登录页（或在单 Activity 内切到登录 View/Fragment）。
    // 直接 finish 视频页会打断"播完→进登录"导航；正确做法=让视频立刻"播完"：
    //   ① start() 后 seekTo 到结尾 → 触发【真实】onCompletion（最稳，跑的是 app 自己的进登录逻辑）；
    //   ② 同时捕获完成监听，供 fxEndVideo() 在 seek 不灵（流媒体/不可 seek）时手动补触发。
    var _vidListeners = [];   // {l, mp} 捕获的 OnCompletionListener
    var _exoListeners = [];   // {l} 捕获的 ExoPlayer Player.Listener（best-effort）
    var _OnCompletion = null;
    try { _OnCompletion = Java.use('android.media.MediaPlayer$OnCompletionListener'); } catch (e) {}

    function _fireCompletion() {
        var n = 0;
        _vidListeners.forEach(function (rec) {
            try {
                var L = (_OnCompletion ? Java.cast(rec.l, _OnCompletion) : rec.l);
                L.onCompletion(rec.mp);   // rec.mp 可能为 null（VideoView），监听器不用 mp 时无碍
                n++;
            } catch (e) { console.log('[nav][video] fire onCompletion skip: ' + e); }
        });
        if (n) console.log('[nav][video] 已强制触发 ' + n + ' 个视频完成回调 → app 应据此进登录页 / 切登录 View');
        return n;
    }
    function _fireExoEnded() {
        var n = 0;
        _exoListeners.forEach(function (rec) {
            try { rec.l.onPlaybackStateChanged(4); n++; }   // Player.STATE_ENDED = 4
            catch (e) { try { rec.l.onPlayerStateChanged(true, 4); n++; } catch (e2) { console.log('[nav][video] fire exo ended skip: ' + e2); } }
        });
        if (n) console.log('[nav][video] 已对 ' + n + ' 个 ExoPlayer 监听触发 STATE_ENDED');
        return n;
    }

    if (SKIP_VIDEO) {
        // F1. android.widget.VideoView
        try {
            var VV = Java.use('android.widget.VideoView');
            try {
                VV.setOnCompletionListener.implementation = function (l) {
                    try { if (l !== null) { _vidListeners.push({ l: l, mp: null }); console.log('[nav][video] VideoView 完成监听已捕获'); } } catch (e) {}
                    return this.setOnCompletionListener(l);
                };
            } catch (e) { console.log('[nav][video] VideoView.setOnCompletionListener hook skip: ' + e); }
            try {
                VV.start.implementation = function () {
                    var r = this.start();
                    try {
                        var self = this;
                        setTimeout(function () { Java.perform(function () {
                            try { var d = self.getDuration(); if (d > 0 && d <= VIDEO_MAX_MS) { self.seekTo(d > 400 ? (d - 200) : d); console.log('[nav][video] VideoView seekTo 末尾(' + d + 'ms) 触发播完'); } } catch (e) {}
                        }); }, 300);
                    } catch (e) {}
                    return r;
                };
            } catch (e) { console.log('[nav][video] VideoView.start hook skip: ' + e); }
            console.log('[nav][video] VideoView hooked');
        } catch (e) { /* 无 VideoView，跳过 */ }

        // F2. android.media.MediaPlayer
        try {
            var MP = Java.use('android.media.MediaPlayer');
            try {
                MP.setOnCompletionListener.implementation = function (l) {
                    try { if (l !== null) { _vidListeners.push({ l: l, mp: this }); console.log('[nav][video] MediaPlayer 完成监听已捕获'); } } catch (e) {}
                    return this.setOnCompletionListener(l);
                };
            } catch (e) { console.log('[nav][video] MediaPlayer.setOnCompletionListener hook skip: ' + e); }
            try {
                MP.start.implementation = function () {
                    var r = this.start();
                    try {
                        var self = this;
                        setTimeout(function () { Java.perform(function () {
                            try { var d = self.getDuration(); if (d > 500 && d <= VIDEO_MAX_MS) { self.seekTo(d - 200); console.log('[nav][video] MediaPlayer seekTo 末尾(' + d + 'ms) 触发播完'); } } catch (e) {}
                        }); }, 300);
                    } catch (e) {}
                    return r;
                };
            } catch (e) { console.log('[nav][video] MediaPlayer.start hook skip: ' + e); }
            console.log('[nav][video] MediaPlayer hooked');
        } catch (e) { /* 无 MediaPlayer，跳过 */ }

        // F3. ExoPlayer / media3（best-effort：捕获 addListener，供 fxEndVideo 触发 STATE_ENDED）
        ['com.google.android.exoplayer2.SimpleExoPlayer', 'com.google.android.exoplayer2.ExoPlayerImpl',
         'androidx.media3.exoplayer.ExoPlayerImpl'].forEach(function (cn) {
            try {
                var P = Java.use(cn);
                if (!P.addListener) return;
                P.addListener.overloads.forEach(function (ov) {
                    try {
                        if (ov.argumentTypes.length !== 1) return;
                        ov.implementation = function (l) {
                            try { if (l !== null) { _exoListeners.push({ l: l }); console.log('[nav][video] ExoPlayer 监听已捕获 (' + cn + ')'); } } catch (e) {}
                            return ov.apply(this, arguments);
                        };
                    } catch (e) {}
                });
            } catch (e) { /* 该 ExoPlayer 实现类不存在，跳过 */ }
        });
        console.log('[nav][video] SKIP_VIDEO 已启用：检测到视频播放会自动 seekTo 末尾跳过；跳不过就 REPL 输 fxEndVideo()');
    }

    // ============ D. 列出全部 Activity：PackageManager.getPackageInfo(GET_ACTIVITIES) ============
    function listActivities() {
        try {
            var ActivityThread = Java.use('android.app.ActivityThread');
            var app = ActivityThread.currentApplication();
            if (app === null) { console.log('[acts] currentApplication 还是 null（进程刚起？稍后再调 fxListActivities()）'); return; }
            var ctx = app.getApplicationContext();
            var pm = ctx.getPackageManager();
            var pkg = '' + ctx.getPackageName();
            var GET_ACTIVITIES = 1;
            var pi = pm.getPackageInfo(pkg, GET_ACTIVITIES);
            var acts = pi.activities.value;
            if (acts === null) { console.log('[acts] activities 为 null（清单未声明或被加固隐藏 -> 看 [nav] onCreate 流补全）'); return; }
            console.log('\n========== [acts] ' + pkg + ' 全部 Activity (' + acts.length + ') ==========');
            for (var i = 0; i < acts.length; i++) {
                try {
                    var name = '' + acts[i].name.value;
                    var hint = SPLASH_RE.test(name) ? '   [splash?]' :
                               (/(login|signin|sign_in|password|auth|verify|pwd|account)/i.test(name) ? '   [LEAD-> 登录页? fxGoto 强进它]' :
                               (/(chat|message|im|conversation|session|kefu|service|main|home)/i.test(name) ? '   [LEAD-> 聊天/主页? 登录后链路]' : ''));
                    console.log('[acts]   ' + name + hint);
                } catch (e) {}
            }
            console.log('========== [acts] END（挑 [LEAD-> 登录页] 类名，REPL 里 fxGoto(\'类名\') 强进；若登录是单页内切换→fxFragments()）==========\n');
        } catch (e) { console.log('[acts] listActivities skip: ' + e + '（加固壳可能动态注册 Activity -> 看 [nav] onCreate 流补全）'); }
    }

    // ============ E. fxGoto('完整类名')：用当前 context startActivity(Intent) 强跳目标页 ============
    function fxGoto(targetCls) {
        if (!targetCls) { console.log('[goto] 用法: fxGoto(\'com.x.LoginNewActivity\')  先看 [acts] 全表或 [nav] 流挑类名'); return; }
        var done = false;
        Java.perform(function () {
            try {
                var ctx = null, fromAct = null;
                try {
                    var ActivityThread = Java.use('android.app.ActivityThread');
                    var app = ActivityThread.currentApplication();
                    if (app !== null) ctx = app.getApplicationContext();
                } catch (e) {}
                if (ctx === null && LAST_ACT !== null) { ctx = LAST_ACT; fromAct = true; }
                if (ctx === null) { console.log('[goto] 拿不到 context（application 与 LAST_ACT 都为 null）。先让 app 进任意一页再 fxGoto'); return; }

                var Intent = Java.use('android.content.Intent');
                var intent = Intent.$new();
                var pkg = '' + ctx.getPackageName();
                intent.setClassName(pkg, '' + targetCls);
                intent.addFlags(0x10000000 /*FLAG_ACTIVITY_NEW_TASK*/);
                ctx.startActivity(intent);
                console.log('[goto] 已强跳 -> ' + targetCls + '（launcher=' + (fromAct ? 'LAST_ACT' : 'appContext') + '）');
                console.log('[goto] 看 [nav] onCreate 是否出现该类名确认进入；进了就让 cipher/http/websocket/telegram-mtproto 探针抓登录/聊天明文');
                done = true;
            } catch (e) {
                console.log('[goto] startActivity 失败 skip: ' + e);
                console.log('[goto] 下一步：(1) 类名/包名核对 [acts] 全表；(2) 目标 exported=false 或要特定 Intent 参数 -> 看 [nav] 里它平时被谁用什么 Intent 拉起照抄；(3) 若登录是单 Activity 内切 View/Fragment（如 LoginNewActivity$PasswordView）→ 用 fxEndVideo() 让视频播完触发切换、或 fxFragments() 看 Fragment 名');
            }
        });
        return done;
    }

    // ============ G. fxEndVideo / fxSkipGate / fxFragments：过门控的现场手动操作 ============
    // fxEndVideo()：seek 自动跳过失灵时，手动触发已捕获的视频完成回调（跑 app 自己的进登录逻辑）。
    function fxEndVideo() {
        var n = 0;
        Java.perform(function () { n = _fireCompletion() + _fireExoEnded(); });
        if (!n) console.log('[nav][video] 未捕获到视频完成监听 —— 该视频可能用 SurfaceView/TextureView 自解码或其它播放器。下一步：fxListActivities() 找登录页 fxGoto 直跳；或看 [nav] 流里"视频页 startActivity 了谁"照抄');
        return n;
    }
    // fxSkipGate('登录类名')：一键过「倒计时→视频→登录」——逼视频播完跑原生导航，再可选强跳登录页兜底。
    function fxSkipGate(loginCls) {
        Java.perform(function () {
            console.log('[nav] === fxSkipGate：一键过门控（视频→登录）===');
            _fireCompletion(); _fireExoEnded();          // 1) 逼视频"播完"，跑 app 自己的进登录逻辑（对单页内切 View 也有效）
            if (loginCls) { fxGoto(loginCls); }          // 2) 已知登录页类名→直接强跳兜底
            else console.log('[nav] 若仍没到登录页：fxListActivities() 看 [LEAD-> 登录页]，再 fxSkipGate(\'登录类名\') 或 fxGoto(\'登录类名\')');
        });
    }
    // fxFragments()：列当前前台 Activity 的 Fragment —— 登录是「单 Activity 内切 View/Fragment」时用（如 LoginNewActivity$PasswordView）。
    function fxFragments() {
        Java.perform(function () {
            try {
                if (LAST_ACT === null) { console.log('[frag] 还没有前台 Activity（先让 app 进任意页）'); return; }
                var got = false;
                ['androidx.fragment.app.FragmentActivity', 'android.support.v4.app.FragmentActivity'].forEach(function (fa) {
                    if (got) return;
                    try {
                        var FA = Java.use(fa);
                        var act = Java.cast(LAST_ACT, FA);
                        var frags = act.getSupportFragmentManager().getFragments();
                        var n = frags.size();
                        console.log('[frag] 前台 ' + LAST_ACT.getClass().getName() + ' 现有 Fragment(' + n + '):');
                        for (var i = 0; i < n; i++) { try { console.log('[frag]   ' + frags.get(i).getClass().getName()); } catch (e) {} }
                        got = true;
                    } catch (e) {}
                });
                if (!got) console.log('[frag] 非 androidx/support FragmentActivity 或无 Fragment（登录可能是自定义 View 切换：看 [nav] 流里"视频播完调了谁"，或 fxEndVideo() 触发原生切换）');
            } catch (e) { console.log('[frag] skip: ' + e); }
        });
    }

    // ---- 暴露到 frida REPL（提示符里直接调）----
    _expose('fxGoto', fxGoto);                    // 强跳某 Activity
    _expose('fxListActivities', listActivities);  // 重列全表（首次自动列一次）
    _expose('fxEndVideo', fxEndVideo);            // 手动触发视频完成回调
    _expose('fxSkipGate', fxSkipGate);            // 一键过门控（视频→登录）
    _expose('fxFragments', fxFragments);          // 列前台 Fragment（单页内切登录用）

    setTimeout(listActivities, 3000);
    console.log('[nav] 已就绪：');
    console.log('[nav]   - [nav] onCreate / startActivity = 实时跳转流（splash→视频→登录 整链，含 deeplink data）');
    console.log('[nav]   - 约 3s 后自动 [acts] 全部 Activity；重列: fxListActivities()');
    console.log('[nav]   - 卡视频：默认自动 seekTo 末尾跳过；不行→ fxEndVideo()（手动触发"播完"回调，跑原生进登录逻辑）');
    console.log('[nav]   - 一键过门控: fxSkipGate(\'登录类名\')  ｜ 直接强跳: fxGoto(\'登录类名\')  ｜ 单页内切登录: fxFragments()');
    console.log('[nav]   - 三档力度: SKIP_VIDEO(默认开,温和) < SKIP_COUNTDOWN < KILL_SPLASH(最猛,先观察再开)');
});
