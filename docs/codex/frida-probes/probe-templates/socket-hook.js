// socket-hook.js — hook java.net.Socket 与 libc connect/send/recv，抓裸 TCP/UDP 目标 IP:port 与原始字节
// 适用：症状④没流量/秒退/聊天心跳不在 HTTP 里——自建 IM/C2/私有支付走裸 socket，不经 OkHttp
// 跑：frida -U -f <包名> -l socket-hook.js -q
// 改：native 符号所在模块按目标调（libc.so / 直接 null 兜底）；要按 fd 过滤或加大 dump 上限改 DUMP_MAX；若 send 全空说明走 SSL_write→切 native-ssl-hook.js
'use strict';

var DUMP_MAX = 256; // 每次 send/recv 最多 dump 字节数，刷屏就调小、要全量就调大

/* ---------- 工具 ---------- */
var _B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function hx(buf) { try { return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ('0' + b.toString(16)).slice(-2); }).join(''); } catch (e) { return '<hex err ' + e + '>'; } }
// 纯 JS base64：frida 运行时没有 btoa/atob 全局，必须自己编码，否则每次 dump 都抛
function b64(buf) {
  try {
    var u = new Uint8Array(buf); var out = ''; var i;
    for (i = 0; i + 2 < u.length; i += 3) {
      var n = (u[i] << 16) | (u[i + 1] << 8) | u[i + 2];
      out += _B64[(n >> 18) & 63] + _B64[(n >> 12) & 63] + _B64[(n >> 6) & 63] + _B64[n & 63];
    }
    var rem = u.length - i;
    if (rem === 1) { var a = u[i]; out += _B64[(a >> 2) & 63] + _B64[(a << 4) & 63] + '=='; }
    else if (rem === 2) { var b = u[i]; var c = u[i + 1]; out += _B64[(b >> 2) & 63] + _B64[((b << 4) | (c >> 4)) & 63] + _B64[(c << 2) & 63] + '='; }
    return out;
  } catch (e) { return '<b64 err ' + e + '>'; }
}
function dumpPtr(ptr, len) { try { if (len <= 0) return; var n = Math.min(len, DUMP_MAX); var bytes = Memory.readByteArray(ptr, n); if (bytes === null) { console.log('[socket]   dump null'); return; } console.log('[socket]   hex(' + n + '/' + len + ')=' + hx(bytes)); console.log('[socket]   b64=' + b64(bytes)); } catch (e) { console.log('[socket]   dump skip: ' + e); } }

// 解析 struct sockaddr* → "ip:port"（AF_INET=2 / AF_INET6=10/30），端口是网络字节序
function parseSockaddr(sa) {
  try {
    if (sa === null || sa.isNull()) return null;
    var fam = sa.readU16() & 0xffff; // sa_family_t（host 序，LE 机器低字节即 AF_*）
    var lo = fam & 0xff;
    var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8(); // ntohs：端口恒网络字节序
    if (lo === 2) { // AF_INET
      var ip = sa.add(4).readU8() + '.' + sa.add(5).readU8() + '.' + sa.add(6).readU8() + '.' + sa.add(7).readU8();
      return ip + ':' + port;
    }
    if (lo === 10 || lo === 30) { // AF_INET6（Linux=10 / 部分 BSD 派生=30）
      var parts = [];
      for (var i = 0; i < 16; i += 2) parts.push(((sa.add(8 + i).readU8() << 8) | sa.add(8 + i + 1).readU8()).toString(16));
      return '[' + parts.join(':') + ']:' + port;
    }
    return '<af=' + lo + '>';
  } catch (e) { return '<sockaddr err ' + e + '>'; }
}

/* ========== Java 层：java.net.Socket / SocketChannel ========== */
Java.perform(function () {
  // Socket.connect(SocketAddress, int) —— 拿到 InetSocketAddress 即真实后端 host/IP:port
  try {
    var Socket = Java.use('java.net.Socket');
    Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function (addr, to) {
      try { console.log('[socket][java] Socket.connect -> ' + addr.toString()); } catch (e) {}
      return this.connect(addr, to);
    };
    console.log('[socket] java.net.Socket.connect hooked');
  } catch (e) { console.log('[socket] Socket.connect hook skip: ' + e); }

  // SocketOutputStream.socketWrite —— 出站裸字节（私有协议帧 / 心跳 / 凭据）
  // 注意：实现里的 b 已是包装好的 Java byte[]，直接 b[i] 索引取值，切勿再 Java.array 包一层（会抛）
  try {
    var SOS = Java.use('java.net.SocketOutputStream');
    SOS.socketWrite.overload('[B', 'int', 'int').implementation = function (b, off, len) {
      try {
        console.log('[socket][java] SocketOutputStream.write len=' + len);
        var view = []; var n = Math.min(len, DUMP_MAX);
        for (var i = 0; i < n; i++) { var v = b[off + i] & 0xff; view.push(('0' + v.toString(16)).slice(-2)); }
        console.log('[socket][java]   hex(' + n + '/' + len + ')=' + view.join(''));
      } catch (ee) { console.log('[socket][java]   dump skip: ' + ee); }
      return this.socketWrite(b, off, len);
    };
    console.log('[socket] SocketOutputStream.socketWrite hooked');
  } catch (e) { console.log('[socket] SocketOutputStream hook skip(版本可能无此私有方法): ' + e); }

  // SocketChannelImpl.connect —— NIO/Netty 自建 IM 常走这条；不同 Android 重载签名不同，逐个试
  try {
    var SCI = Java.use('sun.nio.ch.SocketChannelImpl');
    var hooked = false;
    ['java.net.SocketAddress'].forEach(function (sig) {
      try {
        SCI.connect.overload(sig).implementation = function (addr) {
          try { console.log('[socket][java] SocketChannel.connect -> ' + addr.toString()); } catch (e) {}
          return this.connect(addr);
        };
        hooked = true;
      } catch (ee) {}
    });
    console.log('[socket] SocketChannelImpl.connect ' + (hooked ? 'hooked' : '未命中此重载(版本签名不同，可 .overloads 自查)'));
  } catch (e) { console.log('[socket] SocketChannelImpl hook skip: ' + e); }
});

/* ========== native 层：libc connect / send / sendto / recv / recvfrom ========== */
// 直接用 Module.getExportByName(null,...) 让链接器在全进程找符号，跨 ROM 兜底
function hookExport(name, onEnter, onLeave) {
  try {
    var p = Module.getExportByName(null, name);
    if (p === null) { console.log('[socket][native] ' + name + ' 未命中(符号不在导出表) — 下一步：试 Module.enumerateExportsSync("libc.so") 找符号或换静态偏移'); return; }
    Interceptor.attach(p, { onEnter: onEnter, onLeave: onLeave });
    console.log('[socket][native] ' + name + ' hooked @ ' + p);
  } catch (e) { console.log('[socket][native] ' + name + ' hook skip: ' + e); }
}

// int connect(int fd, const struct sockaddr* addr, socklen_t len) —— 出站连接的真实 IP:port，连失败也打
hookExport('connect', function (args) {
  try {
    this.fd = args[0].toInt32();
    var dst = parseSockaddr(args[1]);
    if (dst) console.log('[socket][native] connect fd=' + this.fd + ' -> ' + dst);
  } catch (e) { console.log('[socket][native] connect onEnter skip: ' + e); }
});

// ssize_t send(int fd, const void* buf, size_t n, int flags)
hookExport('send', function (args) {
  try { var len = args[2].toInt32(); console.log('[socket][native] send fd=' + args[0].toInt32() + ' len=' + len); dumpPtr(args[1], len); } catch (e) { console.log('[socket][native] send skip: ' + e); }
});

// ssize_t sendto(int fd, const void* buf, size_t n, int flags, const struct sockaddr* to, socklen_t)
hookExport('sendto', function (args) {
  try {
    var len = args[2].toInt32();
    var dst = parseSockaddr(args[4]);
    console.log('[socket][native] sendto fd=' + args[0].toInt32() + ' len=' + len + (dst ? ' -> ' + dst : '') );
    dumpPtr(args[1], len);
  } catch (e) { console.log('[socket][native] sendto skip: ' + e); }
});

// ssize_t recv(int fd, void* buf, size_t n, int flags) —— onLeave 拿真实读到长度再 dump
hookExport('recv', function (args) { this.buf = args[1]; }, function (ret) {
  try { var n = ret.toInt32(); if (n > 0) { console.log('[socket][native] recv len=' + n); dumpPtr(this.buf, n); } } catch (e) { console.log('[socket][native] recv skip: ' + e); }
});

// ssize_t recvfrom(int fd, void* buf, size_t n, int flags, struct sockaddr* from, socklen_t*)
hookExport('recvfrom', function (args) { this.buf = args[1]; this.from = args[4]; }, function (ret) {
  try { var n = ret.toInt32(); if (n > 0) { var src = parseSockaddr(this.from); console.log('[socket][native] recvfrom len=' + n + (src ? ' <- ' + src : '')); dumpPtr(this.buf, n); } } catch (e) { console.log('[socket][native] recvfrom skip: ' + e); }
});

console.log('[socket] armed —— 若 connect 有命中但 send/recv 全空，多半数据走 SSL_write/SSL_read，请改用 native-ssl-hook.js');
