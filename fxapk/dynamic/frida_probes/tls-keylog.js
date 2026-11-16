// tls-keylog.js — 导出 TLS 会话密钥到 SSLKEYLOGFILE，Wireshark 离线解密任意栈密文
// 适用：抓到 HTTPS/密文但解不开（Flutter 自带 BoringSSL / QUIC / 自定义 TLS / 非 OkHttp）——
//       不脱 pin、不解应用层加密，直接导 TLS 主密钥，配 pcap 在 Wireshark 里解明文
// 跑：frida -U -f <包名> -l tls-keylog.js -q   （同时另开一路抓 pcap，或用 socket-hook 落字节）
// 取证用法：adb pull /data/local/tmp/fx_sslkeylog.txt → Wireshark «TLS»→(Pre)-Master-Secret log filename 指它
// 原理：在每个新建的 SSL_CTX 上装我们自己的 keylog 回调，BoringSSL/OpenSSL 会把 "CLIENT_RANDOM <hex> <hex>" 喂进来
// 改：符号被 strip 时见末尾提示；要换落盘路径改 KEYLOG_PATH
'use strict';

// ---- Frida 16/17 双向兼容的导出符号解析（内联，勿抽公共模块：探针单文件加载、无 import）----
// 契约：resolveExport(moduleName|null, symbolName) -> NativePointer | null
//   · 保 null 语义——模块或符号缺失一律返 null、绝不抛（缺符号的 strip ROM 上探针不能崩）。
//   · 特性探测选路、不 sniff 版本号：Frida 17 移除了静态 Module.getExportByName/findExportByName，
//     改用 Process.(get|find)ModuleByName 的实例方法 + Module.(get|find)GlobalExportByName 全局解析；
//     16 及以下仍走静态 Module.findExportByName。
function resolveExport(moduleName, symbolName) {
  try {
    if (typeof Module.getGlobalExportByName === 'function') {
      // Frida 17+：静态 Module.findExportByName 已被移除
      if (moduleName === null) {
        return Module.findGlobalExportByName(symbolName);      // 全局：缺失返 null，不抛
      }
      var m = Process.findModuleByName(moduleName);            // 模块缺失返 null，不抛
      return m ? m.findExportByName(symbolName) : null;        // 符号缺失返 null，不抛
    }
  } catch (e) { return null; }
  // Frida ≤16：老静态 API（17 下上面已 return，走不到这里）
  try { return Module.findExportByName(moduleName, symbolName); } catch (e) { return null; }
}

var KEYLOG_PATH = '/data/local/tmp/fx_sslkeylog.txt';
var _kf = null;
function writeKey(line) {
  try {
    if (_kf === null) _kf = new File(KEYLOG_PATH, 'a');
    _kf.write(line + '\n'); _kf.flush();
    console.log('[keylog] ' + line.split(' ')[0] + ' …（已写 ' + KEYLOG_PATH + '）');
  } catch (e) { console.log('[keylog] 写文件失败: ' + e + ' | ' + line); }
}

// keylog 回调：void cb(const SSL* ssl, const char* line)
var keylogCb = new NativeCallback(function (ssl, linePtr) {
  try { var s = linePtr.readCString(); if (s) writeKey(s); } catch (e) {}
}, 'void', ['pointer', 'pointer']);

var installed = 0;
function arm(mod) {
  var ctxNew = resolveExport(mod, 'SSL_CTX_new');
  var setCb = resolveExport(mod, 'SSL_CTX_set_keylog_callback');
  if (!ctxNew || !setCb) return false;
  var SSL_CTX_set_keylog_callback = new NativeFunction(setCb, 'void', ['pointer', 'pointer']);
  // 每个新建 SSL_CTX 都装上我们的回调
  Interceptor.attach(ctxNew, {
    onLeave: function (retval) {
      try { if (!retval.isNull()) { SSL_CTX_set_keylog_callback(retval, keylogCb); installed++; } } catch (e) {}
    }
  });
  console.log('[keylog] armed @ ' + mod + '（SSL_CTX_new + set_keylog_callback）');
  return true;
}

var hit = false;
['libssl.so', 'libflutter.so', 'libboringssl.so', 'libconscrypt_jni.so', 'libcronet.so', 'libmonochrome.so'].forEach(function (m) {
  try { if (arm(m)) hit = true; } catch (e) {}
});
if (!hit) {
  // 兜底：遍历所有模块找带 SSL_CTX_set_keylog_callback 的
  Process.enumerateModules().forEach(function (mod) {
    try {
      if (!hit && resolveExport(mod.name, 'SSL_CTX_set_keylog_callback')) { if (arm(mod.name)) hit = true; }
    } catch (e) {}
  });
}

if (!hit) {
  console.log('[keylog] 未找到 SSL_CTX_set_keylog_callback —— 该 BoringSSL 可能裁了 keylog 接口（Flutter 常见）。下一步：');
  console.log('  · 用 ssl-unpinning-flutter 思路 pattern-scan libflutter.so 的 ssl_log_secret，或 reFlutter 重打包；');
  console.log('  · 或退而求其次：native-ssl-hook.js 直接 hook SSL_read/SSL_write 拿明文（不需密钥）。');
} else {
  console.log('[keylog] ready —— 触发 app 网络后 adb pull ' + KEYLOG_PATH + ' 喂 Wireshark 解密');
}
