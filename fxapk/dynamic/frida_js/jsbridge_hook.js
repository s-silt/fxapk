
// 取证用途：对取证样本自身在分析机上做运行时观测，产出端点/密钥/独特串等线索，不面向任何第三方基础设施。
// apkscan 运行时 JS-bridge 追踪（best-effort）：列出 H5 可调用的原生桥接面与实际调用。
var _coverage = (typeof globalThis !== 'undefined' && globalThis.__fxapkProbeCoverage) || {
    perform: function (_family, callback) {
        try { if (typeof Java !== 'undefined' && (!('available' in Java) || Java.available)) Java.perform(callback); } catch (_) {}
    },
    attempted: function () {}, installed: function () {}, registrationError: function () {},
    trigger: function () {}, drop: function () {}, truncated: function () {}
};
_coverage.perform('jsbridge', function () {
    var _jb_count = 0;
    function jbEmit(p) {
        try {
            if (_jb_count >= 2000) { _coverage.drop('jsbridge', 'events'); return; }
            _jb_count += 1;
            p.type = 'apkscan-jsbridge';
            send(p);
        } catch (e) {}
    }
    function brief(v) {
        try {
            if (v === null || v === undefined) return null;
            var s = '' + v;
            if (s.length > 256) _coverage.truncated('jsbridge', 'events');
            return s.length > 256 ? s.slice(0, 256) : s;
        } catch (e) { return null; }
    }
    try {
        var WebView = Java.use('android.webkit.WebView');
        var addInterface = WebView.addJavascriptInterface.overload(
            'java.lang.Object', 'java.lang.String'
        );
        _coverage.attempted('jsbridge', 'add_interface');
        addInterface.implementation = function (obj, name) {
                _coverage.trigger('jsbridge', 'add_interface');
                try {
                    var cls = '';
                    try { cls = obj.getClass().getName(); } catch (e) {}
                    // 列出该桥对象上 @JavascriptInterface 可被 H5 调用的方法名（暴露面）。
                    var methodNames = [];
                    try {
                        var methods = obj.getClass().getDeclaredMethods();
                        for (var i = 0; i < methods.length && i < 64; i++) {
                            methodNames.push('' + methods[i].getName());
                        }
                        if (methods.length > 64) _coverage.truncated('jsbridge', 'events');
                    } catch (e) {}
                    jbEmit({event: 'register', iface: '' + name, object_class: cls,
                            methods: methodNames.join(','), ts: Date.now()});
                } catch (e) {}
                return this.addJavascriptInterface(obj, name);
            };
        _coverage.installed('jsbridge', 'add_interface');
        console.log('[apkscan] WebView.addJavascriptInterface hooked');
    } catch (e) {
        _coverage.registrationError('jsbridge', 'add_interface');
        console.log('[apkscan] addJavascriptInterface hook skip: ' + e);
    }
    // DSBridge：统一桥接调用入口 callSync/call（覆盖常见框架的方法分发）。
    try {
        var DSB = Java.use('wendu.dsbridge.DWebView');
        if (DSB.callHandler && DSB.callHandler.overloads && DSB.callHandler.overloads.length) {
            DSB.callHandler.overloads.forEach(function (ov) {
                _coverage.attempted('jsbridge', 'dsbridge_call');
                ov.implementation = function () {
                    _coverage.trigger('jsbridge', 'dsbridge_call');
                    try { jbEmit({event: 'call', iface: 'dsbridge', method: brief(arguments[0]), ts: Date.now()}); } catch (e) {}
                    return ov.apply(this, arguments);
                };
                _coverage.installed('jsbridge', 'dsbridge_call');
            });
        } else _coverage.registrationError('jsbridge', 'dsbridge_call');
        console.log('[apkscan] DSBridge hooked');
    } catch (e) {
        _coverage.registrationError('jsbridge', 'dsbridge_call');
        console.log('[apkscan] DSBridge hook skip: ' + e);
    }
});
