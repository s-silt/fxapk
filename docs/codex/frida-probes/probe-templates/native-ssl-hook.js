// native-ssl-hook.js — 抓 native / Flutter 层 TLS 明文（BoringSSL SSL_read / SSL_write）+ 对端五元组
// 适用：app 走 Flutter / 纯 native 发包、无 OkHttp、Java 层探针抓不到明文（packed shell 常见）
// 跑：frida -U -f <包名> -l native-ssl-hook.js -q
// 原理：BoringSSL（libssl.so，或编进 libflutter.so / app 自带 .so）的
//   SSL_write(ssl, buf, num) 入参 buf 是出站明文；SSL_read(ssl, buf, num) 返回后 buf 是入站明文。
//   再用 SSL_get_fd(ssl)+getpeername(fd) 把每段明文关联到真实对端 IP:port（= 直接溯源线索）。
// 改：符号被 strip 见末尾提示；只要明文不要五元组可忽略 [peer] 段
'use strict';

// ---- 对端五元组解析：SSL* → fd → getpeername → ip:port ----
var _sslGetFd = null, _getpeername = null;
try { var gp = Module.findExportByName(null, 'getpeername'); if (gp) _getpeername = new NativeFunction(gp, 'int', ['int', 'pointer', 'pointer']); } catch (e) {}
function bindGetFd(mod) { try { var p = Module.findExportByName(mod, 'SSL_get_fd'); if (p && !_sslGetFd) _sslGetFd = new NativeFunction(p, 'int', ['pointer']); } catch (e) {} }
function peerOf(sslPtr) {
  try {
    if (!_sslGetFd || !_getpeername || sslPtr.isNull()) return '';
    var fd = _sslGetFd(sslPtr); if (fd < 0) return '';
    var sa = Memory.alloc(128), len = Memory.alloc(4); len.writeU32(128);
    if (_getpeername(fd, sa, len) !== 0) return '';
    var fam = sa.readU16() & 0xff;
    var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
    if (fam === 2) return ' [peer ' + sa.add(4).readU8() + '.' + sa.add(5).readU8() + '.' + sa.add(6).readU8() + '.' + sa.add(7).readU8() + ':' + port + ']';
    if (fam === 10) { var h = []; for (var i = 0; i < 16; i += 2) h.push(((sa.add(8 + i).readU8() << 8) | sa.add(8 + i + 1).readU8()).toString(16)); return ' [peer [' + h.join(':') + ']:' + port + ']'; }
    return '';
  } catch (e) { return ''; }
}

function preview(p, len) {
  var n = Math.min(len, 0x2000);
  try { var s = p.readUtf8String(n); if (s && s.length) return s; } catch (e) {}
  try { return '\n' + hexdump(p, { length: Math.min(len, 0x200), ansi: false }); } catch (e) { return '<read err>'; }
}

function hookPair(label, sslRead, sslWrite) {
  if (sslWrite) {
    Interceptor.attach(sslWrite, {
      onEnter: function (a) {
        try {
          var len = a[2].toInt32();
          if (len > 0) console.log('\n[native TLS][' + label + '][SSL_write len=' + len + ']' + peerOf(a[0]) + ' ' + preview(a[1], len));
        } catch (e) { console.log('[native] SSL_write onEnter skip: ' + e); }
      }
    });
    console.log('[native] hooked SSL_write @ ' + label);
  }
  if (sslRead) {
    Interceptor.attach(sslRead, {
      onEnter: function (a) { try { this.ssl = a[0]; this.buf = a[1]; } catch (e) { this.ssl = null; this.buf = null; } },
      onLeave: function (ret) {
        try {
          var n = ret.toInt32();
          if (n > 0 && this.buf && !this.buf.isNull())
            console.log('\n[native TLS][' + label + '][SSL_read len=' + n + ']' + peerOf(this.ssl) + ' ' + preview(this.buf, n));
        } catch (e) { console.log('[native] SSL_read onLeave skip: ' + e); }
      }
    });
    console.log('[native] hooked SSL_read @ ' + label);
  }
}

var hit = false;

// 1) 常见承载模块直接按导出名挂
['libssl.so', 'libflutter.so', 'libboringssl.so', 'libconscrypt_jni.so', 'libcronet.so', 'libmonochrome.so'].forEach(function (m) {
  try {
    var rd = Module.findExportByName(m, 'SSL_read');
    var wr = Module.findExportByName(m, 'SSL_write');
    if (rd || wr) { bindGetFd(m); hookPair(m, rd, wr); hit = true; }
  } catch (e) {}
});

// 2) 兜底：枚举所有已载入模块的导出，找 SSL_read / SSL_write（静态链进 app 自带 .so 时）
if (!hit) {
  console.log('[native] 标准模块未命中，枚举全部模块导出 …');
  Process.enumerateModules().forEach(function (mod) {
    try {
      var rd = null, wr = null;
      mod.enumerateExports().forEach(function (e) {
        if (e.name === 'SSL_read') rd = e.address;
        if (e.name === 'SSL_write') wr = e.address;
      });
      if (rd || wr) { bindGetFd(mod.name); hookPair(mod.name, rd, wr); hit = true; }
    } catch (e) {}
  });
}

// 3) 仍无 → 符号被 strip（静态链 BoringSSL）。给下一步而不是假装抓到。
if (!hit) {
  console.log('[native] 未找到导出的 SSL_read/SSL_write —— 符号可能被 strip。下一步：');
  console.log('  · frida-trace -U -f <包名> -i "*SSL_read*" -i "*SSL_write*"  （模糊匹配定位）');
  console.log('  · 或用 tls-keylog.js 导 SSLKEYLOGFILE + pcap 在 Wireshark 离线解（不需符号）；');
  console.log('  · Dart 直发(无 BoringSSL) → 用 socket-hook.js 看原始字节。');
}
