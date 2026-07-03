// webview-hook.js — 抓 H5 端点 + JS 桥（WebView 壳类 app 常见）
// 适用：app 是 H5/uni-app 壳，逻辑在 WebView 里
// 跑：frida -U -f <包名> -l webview-hook.js -q
Java.perform(function () {
  try {
    var WV = Java.use('android.webkit.WebView');

    try {
      WV.loadUrl.overloads.forEach(function (ov) {
        ov.implementation = function () {
          try { console.log('[webview] loadUrl ' + arguments[0]); } catch (e) {}
          return ov.apply(this, arguments);
        };
      });
    } catch (e) { console.log('[webview] loadUrl skip: ' + e); }

    try {
      WV.evaluateJavascript.overload('java.lang.String', 'android.webkit.ValueCallback')
        .implementation = function (js, cb) {
          try { console.log('[webview] evaluateJavascript:\n' + js); } catch (e) {}
          return this.evaluateJavascript(js, cb);
        };
    } catch (e) {}

    try {
      WV.addJavascriptInterface.implementation = function (obj, name) {
        try {
          var cls = '?';
          try { cls = obj.getClass().getName(); } catch (e2) {}
          console.log('[webview] addJavascriptInterface name=' + name + ' class=' + cls);
        } catch (e) {}
        return this.addJavascriptInterface(obj, name);
      };
    } catch (e) { console.log('[webview] addJavascriptInterface skip: ' + e); }

    console.log('[webview] hooked (loadUrl / evaluateJavascript / addJavascriptInterface)');
  } catch (e) { console.log('[webview] skip: ' + e); }

  // 提示：要抓 H5 内 WebSocket / fetch，在上面 evaluateJavascript 注入一段 JS 覆写
  // WebSocket.prototype.send / window.fetch / XMLHttpRequest.open 把 URL+payload console.log 出来。
});
