// webview-inject-js.js — 往 WebView 页面注入 JS，抓 H5 内真实流量（WebSocket / fetch / XHR）
// 适用：症状⑦ uni-app / H5 壳——业务逻辑和真实后端在网页渲染层，Java 探针抓不到
// 跑：frida -U -f <包名> -l webview-inject-js.js -q   （H5 壳务必 spawn，否则错过首屏注入）
// 改：app 子类覆盖了 onConsoleMessage 不调 super 时，看本探针打印的 WebChromeClient 实际类名，改 hook 那个子类；
//     页面有 CSP 拦 inline JS 时改用 addJavascriptInterface 桥回传。
Java.perform(function () {
  // 注入的 JS：覆写 fetch / XHR / WebSocket，把 URL+payload 经 console.log('[FXJS]...') 回吐（幂等、可重复注入）
  var INJECT = "(function(){if(window.__fxInjected)return;window.__fxInjected=true;" +
    "function R(t,o){try{console.log('[FXJS] '+t+' '+JSON.stringify(o));}catch(e){console.log('[FXJS] '+t+' <unstringifiable>');}}" +
    "try{if(window.fetch){var of=window.fetch;window.fetch=function(u,opt){R('fetch',{url:''+u,method:opt&&opt.method,body:opt&&typeof opt.body==='string'?opt.body:undefined});return of.apply(this,arguments);};}}catch(e){}" +
    "try{if(window.XMLHttpRequest){var op=XMLHttpRequest.prototype.open,os=XMLHttpRequest.prototype.send;" +
    "XMLHttpRequest.prototype.open=function(m,u){this.__m=m;this.__u=u;return op.apply(this,arguments);};" +
    "XMLHttpRequest.prototype.send=function(b){R('xhr',{method:this.__m,url:this.__u,body:typeof b==='string'?b:undefined});return os.apply(this,arguments);};}}catch(e){}" +
    "try{if(window.WebSocket){var OW=window.WebSocket;var NW=function(url,p){R('ws.open',{url:url});var ws=p?new OW(url,p):new OW(url);var osd=ws.send;" +
    "ws.send=function(d){R('ws.send',{url:url,data:typeof d==='string'?d:'<bin>'});return osd.apply(this,arguments);};" +
    "try{ws.addEventListener('message',function(ev){R('ws.recv',{url:url,data:typeof ev.data==='string'?ev.data:'<bin>'});});}catch(e){}return ws;};" +
    "NW.prototype=OW.prototype;NW.CONNECTING=OW.CONNECTING;NW.OPEN=OW.OPEN;NW.CLOSING=OW.CLOSING;NW.CLOSED=OW.CLOSED;window.WebSocket=NW;}}catch(e){}" +
    "console.log('[FXJS] injected @ '+location.href);})();";

  function inject(webview, where) {
    try {
      Java.scheduleOnMainThread(function () {
        try { webview.evaluateJavascript(INJECT, null); }
        catch (e) { console.log('[wvinject] evaluateJavascript skip(' + where + '): ' + e); }
      });
    } catch (e) { console.log('[wvinject] schedule skip: ' + e); }
  }

  var WV = Java.use('android.webkit.WebView');

  // 开调试 + 确保 JS 开启（很多壳默认没开 setWebContentsDebuggingEnabled，开了还能配 chrome://inspect）
  try { WV.setWebContentsDebuggingEnabled(true); } catch (e) {}

  // loadUrl：navigate 时排注入（含 SPA 路由切换）
  WV.loadUrl.overloads.forEach(function (ov) {
    ov.implementation = function () {
      try { this.getSettings().setJavaScriptEnabled(true); } catch (e) {}
      console.log('[wvinject] loadUrl ' + arguments[0]);
      var r = ov.apply(this, arguments);
      inject(this, 'loadUrl');
      return r;
    };
  });
  try {
    WV.loadDataWithBaseURL.implementation = function (base, data, mime, enc, hist) {
      console.log('[wvinject] loadDataWithBaseURL base=' + base);
      var r = this.loadDataWithBaseURL(base, data, mime, enc, hist);
      inject(this, 'loadData');
      return r;
    };
  } catch (e) {}

  // onPageStarted 时机最早（页面脚本跑之前），但 app 子类常覆盖；hook 基类尽力 + 打印实际类名
  try {
    var WVC = Java.use('android.webkit.WebViewClient');
    WVC.onPageStarted.implementation = function (view, url, favicon) {
      console.log('[wvinject] onPageStarted ' + url);
      inject(view, 'onPageStarted');
      return this.onPageStarted(view, url, favicon);
    };
  } catch (e) { console.log('[wvinject] WebViewClient.onPageStarted skip: ' + e); }

  // 把注入 JS 的 console.log('[FXJS]...') 经 onConsoleMessage 转回 frida（基类；子类覆盖见下方类名提示）
  try {
    var WCC = Java.use('android.webkit.WebChromeClient');
    WCC.onConsoleMessage.overload('android.webkit.ConsoleMessage').implementation = function (cm) {
      try { var m = cm.message(); if (m && m.indexOf('[FXJS]') === 0) console.log('[H5] ' + m); } catch (e) {}
      return this.onConsoleMessage(cm);
    };
    try {
      WCC.onConsoleMessage.overload('java.lang.String', 'int', 'java.lang.String').implementation = function (msg, line, src) {
        try { if (msg && msg.indexOf('[FXJS]') === 0) console.log('[H5] ' + msg); } catch (e) {}
        return this.onConsoleMessage(msg, line, src);
      };
    } catch (e) {}
    console.log('[wvinject] WebChromeClient.onConsoleMessage hooked');
  } catch (e) { console.log('[wvinject] WebChromeClient skip: ' + e); }

  // 打印 app 实际设的 client 类名——若上面基类 hook 不命中，按这俩类名改 hook
  try { WV.setWebViewClient.implementation = function (c) { try { console.log('[wvinject] setWebViewClient = ' + c.$className); } catch (e) {} return this.setWebViewClient(c); }; } catch (e) {}
  try { WV.setWebChromeClient.implementation = function (c) { try { console.log('[wvinject] setWebChromeClient = ' + c.$className); } catch (e) {} return this.setWebChromeClient(c); }; } catch (e) {}

  console.log('[wvinject] ready（H5 内 fetch/XHR/WebSocket 将以 [H5] [FXJS] 前缀回吐）');
});
