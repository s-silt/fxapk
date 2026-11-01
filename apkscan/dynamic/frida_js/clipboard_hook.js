
// 取证用途：对取证样本自身在分析机上做运行时观测，产出端点/密钥/独特串等线索，不面向任何第三方基础设施。
// apkscan 运行时剪贴板链上地址采集（best-effort）：hook ClipboardManager 抓实际剪贴板文本回传。
var _coverage = (typeof globalThis !== 'undefined' && globalThis.__fxapkProbeCoverage) || {
    perform: function (_family, callback) {
        try { if (typeof Java !== 'undefined' && (!('available' in Java) || Java.available)) Java.perform(callback); } catch (_) {}
    },
    attempted: function () {}, installed: function () {}, registrationError: function () {},
    trigger: function () {}, drop: function () {}, truncated: function () {}
};
_coverage.perform('clipboard', function () {
    var _cb_count = 0;
    var _CB_CAP = 1000;
    var _CB_MAX = 8192;       // 剪贴板文本回传字符上限（地址不长，截断不影响抽取）
    var _cb_seen = {};        // 同一文本只回传一次（剪贴板读多次很常见，避免刷爆）

    function cbEmit(text) {
        try {
            if (_cb_count >= _CB_CAP) { _coverage.drop('clipboard', 'events'); return; }
            if (text === null || text === undefined) return;
            var t = '' + text;
            if (!t) return;
            if (t.length > _CB_MAX) {
                _coverage.truncated('clipboard', 'events');
                t = t.slice(0, _CB_MAX);
            }
            if (_cb_seen[t]) return;
            _cb_seen[t] = true;
            _cb_count += 1;
            // 只回传文本；地址抽取与全文丢弃由 Python normalize_clipboard_event 负责（隐私护栏）。
            send({type: 'apkscan-clipboard', event: 'read', text: t, ts: Date.now()});
        } catch (e) { /* 回传失败不得炸会话 */ }
    }

    // 从 ClipData 取首个 item 的文本（coerceToText 兜底 getText）。
    function textFromClip(clip, ctx) {
        try {
            if (clip === null || clip === undefined) return null;
            var n = 0;
            try { n = clip.getItemCount(); } catch (e) { n = 0; }
            if (n <= 0) return null;
            var item = clip.getItemAt(0);
            if (item === null || item === undefined) return null;
            var txt = null;
            // coerceToText 需 Context；拿不到 Context 时退回 getText（纯文本剪贴足够）。
            try {
                if (ctx !== null && ctx !== undefined && item.coerceToText) {
                    txt = item.coerceToText(ctx);
                }
            } catch (e) {}
            if (txt === null || txt === undefined) {
                try { if (item.getText) txt = item.getText(); } catch (e) {}
            }
            return txt;
        } catch (e) { return null; }
    }

    // --- android.content.ClipboardManager.getPrimaryClip：取回 ClipData → 抽文本 ---
    try {
        var CM = Java.use('android.content.ClipboardManager');
        if (CM.getPrimaryClip) {
            _coverage.attempted('clipboard', 'primary_clip');
            CM.getPrimaryClip.implementation = function () {
                _coverage.trigger('clipboard', 'primary_clip');
                var clip = this.getPrimaryClip();
                try {
                    var ctx = null;
                    // best-effort 取一个 Context 供 coerceToText（拿不到也能退回 getText）。
                    try { ctx = Java.use('android.app.ActivityThread').currentApplication(); } catch (e) {}
                    cbEmit(textFromClip(clip, ctx));
                } catch (e) {}
                return clip;
            };
            _coverage.installed('clipboard', 'primary_clip');
        } else _coverage.registrationError('clipboard', 'primary_clip');
        // 旧 API：getText() 直接返回 CharSequence。
        if (CM.getText) {
            _coverage.attempted('clipboard', 'get_text');
            CM.getText.implementation = function () {
                _coverage.trigger('clipboard', 'get_text');
                var t = this.getText();
                try { cbEmit(t); } catch (e) {}
                return t;
            };
            _coverage.installed('clipboard', 'get_text');
        } else _coverage.registrationError('clipboard', 'get_text');
        console.log('[apkscan] ClipboardManager clipboard hook armed');
    } catch (e) {
        _coverage.registrationError('clipboard', 'get_text');
        console.log('[apkscan] ClipboardManager clipboard hook skip: ' + e);
    }

    // --- ClipData.Item.coerceToText：兜底另一常见读取面（部分 app 直接对 item 取文本）---
    try {
        var Item = Java.use('android.content.ClipData$Item');
        if (Item.coerceToText) {
            _coverage.attempted('clipboard', 'coerce_text');
            Item.coerceToText.implementation = function (ctx) {
                _coverage.trigger('clipboard', 'coerce_text');
                var t = this.coerceToText(ctx);
                try { cbEmit(t); } catch (e) {}
                return t;
            };
            _coverage.installed('clipboard', 'coerce_text');
        } else _coverage.registrationError('clipboard', 'coerce_text');
        console.log('[apkscan] ClipData.Item.coerceToText hook armed');
    } catch (e) {
        _coverage.registrationError('clipboard', 'coerce_text');
        console.log('[apkscan] ClipData.Item hook skip: ' + e);
    }
});
