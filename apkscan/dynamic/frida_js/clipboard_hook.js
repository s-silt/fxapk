
// 取证用途：对取证样本自身在分析机上做运行时观测，产出端点/密钥/独特串等线索，不面向任何第三方基础设施。
// apkscan 运行时剪贴板链上地址采集（best-effort）：hook ClipboardManager 抓实际剪贴板文本回传。
Java.perform(function () {
    var _cb_count = 0;
    var _CB_CAP = 1000;
    var _CB_MAX = 8192;       // 剪贴板文本回传字符上限（地址不长，截断不影响抽取）
    var _cb_seen = {};        // 同一文本只回传一次（剪贴板读多次很常见，避免刷爆）

    function cbEmit(text) {
        try {
            if (_cb_count >= _CB_CAP) return;
            if (text === null || text === undefined) return;
            var t = '' + text;
            if (!t) return;
            if (t.length > _CB_MAX) t = t.slice(0, _CB_MAX);
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
            CM.getPrimaryClip.implementation = function () {
                var clip = this.getPrimaryClip();
                try {
                    var ctx = null;
                    // best-effort 取一个 Context 供 coerceToText（拿不到也能退回 getText）。
                    try { ctx = Java.use('android.app.ActivityThread').currentApplication(); } catch (e) {}
                    cbEmit(textFromClip(clip, ctx));
                } catch (e) {}
                return clip;
            };
        }
        // 旧 API：getText() 直接返回 CharSequence。
        if (CM.getText) {
            CM.getText.implementation = function () {
                var t = this.getText();
                try { cbEmit(t); } catch (e) {}
                return t;
            };
        }
        console.log('[apkscan] ClipboardManager clipboard hook armed');
    } catch (e) {
        console.log('[apkscan] ClipboardManager clipboard hook skip: ' + e);
    }

    // --- ClipData.Item.coerceToText：兜底另一常见读取面（部分 app 直接对 item 取文本）---
    try {
        var Item = Java.use('android.content.ClipData$Item');
        if (Item.coerceToText) {
            Item.coerceToText.implementation = function (ctx) {
                var t = this.coerceToText(ctx);
                try { cbEmit(t); } catch (e) {}
                return t;
            };
        }
        console.log('[apkscan] ClipData.Item.coerceToText hook armed');
    } catch (e) {
        console.log('[apkscan] ClipData.Item hook skip: ' + e);
    }
});
