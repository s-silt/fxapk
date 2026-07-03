// websocket-hook.js — 抓聊天/实时消息帧（WebSocket）
// 适用：聊天/实时消息不在普通 HTTP 流量里 → 走 WebSocket
// 跑：frida -U -f <包名> -l websocket-hook.js -q
// 注：H5 页面内的 WebSocket 在 WebView 渲染层（不是 Java），用 webview-hook.js 从页面 JS 抓。
Java.perform(function () {
  // okhttp3 WebSocket 发送（不同版本类名不同，逐个尝试）
  ['okhttp3.RealWebSocket', 'okhttp3.internal.ws.RealWebSocket'].forEach(function (cls) {
    try {
      var RWS = Java.use(cls);
      RWS.send.overloads.forEach(function (ov) {
        ov.implementation = function () {
          try { console.log('[ws SEND][' + cls + '] ' + arguments[0]); } catch (e) {}
          return ov.apply(this, arguments);
        };
      });
      console.log('[ws] hooked send on ' + cls);
    } catch (e) { /* 该版本无此类，跳过 */ }
  });

  // WebSocketListener.onMessage 收消息（app 子类覆盖时这里不一定拦得到，尽力）
  try {
    var WSL = Java.use('okhttp3.WebSocketListener');
    WSL.onMessage.overloads.forEach(function (ov) {
      ov.implementation = function () {
        try { console.log('[ws RECV] ' + arguments[1]); } catch (e) {}
        return ov.apply(this, arguments);
      };
    });
    console.log('[ws] WebSocketListener.onMessage hooked');
  } catch (e) { console.log('[ws] WebSocketListener skip: ' + e); }

  // org.java_websocket（部分 app 用）
  try {
    var JWS = Java.use('org.java_websocket.client.WebSocketClient');
    JWS.send.overload('java.lang.String').implementation = function (t) {
      try { console.log('[ws SEND][java_websocket] ' + t); } catch (e) {}
      return this.send(t);
    };
    console.log('[ws] org.java_websocket hooked');
  } catch (e) { /* 无则跳过 */ }
});
