// http-url-hook.js — dump 所有出站 HTTP 请求的 URL + 头 + 明文体（最先跑这个摸清网络栈）
// 跑：frida -U -f <包名> -l http-url-hook.js -q
// 改：若 app 不用 OkHttp，看 console 哪个 hook 命中；不命中就换到它实际用的栈。
Java.perform(function () {
  function _bodyStr(req) {
    try {
      var body = req.body();
      if (!body) return '';
      var Buffer = Java.use('okio.Buffer');
      var buf = Buffer.$new();
      body.writeTo(buf);
      return buf.readUtf8();
    } catch (e) { return '<body 读不出: ' + e + '>'; }
  }

  // 1) OkHttp（最常见）
  try {
    var Client = Java.use('okhttp3.OkHttpClient');
    Client.newCall.implementation = function (req) {
      try {
        console.log('\n[http] ' + req.method() + ' ' + req.url().toString());
        var h = req.headers().toString();
        if (h && h.length) console.log('[http] headers:\n' + h.trim());
        var b = _bodyStr(req);
        if (b && b.length) console.log('[http] body: ' + b);
      } catch (e) { console.log('[http] dump err: ' + e); }
      return this.newCall(req);
    };
    console.log('[http] OkHttp newCall hooked');
  } catch (e) { console.log('[http] OkHttp skip: ' + e); }

  // 2) java.net.HttpURLConnection 兜底
  try {
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function () {
      try { console.log('[http] URL.openConnection ' + this.toString()); } catch (e) {}
      return this.openConnection();
    };
    console.log('[http] java.net.URL hooked');
  } catch (e) { console.log('[http] URL skip: ' + e); }
});
