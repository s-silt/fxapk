// dns-hook.js — hook InetAddress.getByName/getAllByName 与 native getaddrinfo，列全 app 查询过的后端域名
// 适用：症状④/无账号触达——域名解析发生在连接之前，连失败也查过 DNS，是登录前拿到最多后端域的层
// 跑：frida -U -f <包名> -l dns-hook.js -q
// 改：okhttp3.Dns 系统实现类名跨版本不同，已遍历候选类名兜底；要去重在 seen 里加判断；OkHttp 自定义 Dns 实现可另 hook 其 lookup
'use strict';

var seen = {}; // host -> 1，去重避免刷屏；想看每次解析把下面的去重判断去掉即可
function mark(host, tag) {
  if (!host) return true;
  if (seen[host]) return false;
  seen[host] = 1;
  console.log('[dns]' + (tag ? '[' + tag + ']' : '') + ' 新域名: ' + host);
  return true;
}

/* ========== Java 层：java.net.InetAddress ========== */
Java.perform(function () {
  try {
    var InetAddress = Java.use('java.net.InetAddress');

    // getByName(String) -> InetAddress
    try {
      InetAddress.getByName.overload('java.lang.String').implementation = function (host) {
        mark(host, 'getByName');
        var r = this.getByName(host);
        try { if (r !== null) console.log('[dns]   ' + host + ' -> ' + r.getHostAddress()); } catch (e) {}
        return r;
      };
      console.log('[dns] InetAddress.getByName hooked');
    } catch (e) { console.log('[dns] getByName hook skip: ' + e); }

    // getAllByName(String) -> InetAddress[]
    try {
      InetAddress.getAllByName.overload('java.lang.String').implementation = function (host) {
        mark(host, 'getAllByName');
        var arr = this.getAllByName(host);
        try {
          if (arr !== null) {
            var ips = [];
            for (var i = 0; i < arr.length; i++) ips.push(arr[i].getHostAddress());
            console.log('[dns]   ' + host + ' -> [' + ips.join(', ') + ']');
          }
        } catch (e) {}
        return arr;
      };
      console.log('[dns] InetAddress.getAllByName hooked');
    } catch (e) { console.log('[dns] getAllByName hook skip: ' + e); }
  } catch (e) { console.log('[dns] InetAddress hook skip: ' + e); }

  // OkHttp 系统 Dns.lookup(String) —— 实现类名跨版本不稳，遍历候选逐个试，命中即 hook
  // 说明：OkHttp 系统 DNS 最终也调 InetAddress.getAllByName，所以即便这里全不命中，上面已兜住
  try {
    var dnsCandidates = ['okhttp3.Dns$Companion$DnsSystem', 'okhttp3.Dns$1', 'okhttp3.internal.Util$1'];
    var dnsHooked = false;
    dnsCandidates.forEach(function (cls) {
      try {
        var C = Java.use(cls);
        if (C.lookup) {
          C.lookup.overload('java.lang.String').implementation = function (host) {
            mark(host, 'okhttp.Dns');
            var r = this.lookup(host);
            try { if (r !== null) console.log('[dns]   (okhttp) ' + host + ' -> ' + r.toString()); } catch (e) {}
            return r;
          };
          dnsHooked = true;
          console.log('[dns] ' + cls + '.lookup hooked');
        }
      } catch (ee) {}
    });
    if (!dnsHooked) console.log('[dns] okhttp 系统 Dns 未命中候选类名(版本不同/无 okhttp) — 无妨，已由 InetAddress.getAllByName 兜住');
  } catch (e) { console.log('[dns] okhttp Dns hook skip: ' + e); }
});

/* ========== native 层：getaddrinfo / android_getaddrinfofornet ========== */
function hookGai(name) {
  try {
    var p = Module.getExportByName(null, name);
    if (p === null) { console.log('[dns][native] ' + name + ' 未命中(符号不在导出表)'); return; }
    Interceptor.attach(p, {
      onEnter: function (args) {
        try {
          var host = args[0].isNull() ? null : args[0].readCString();
          if (host) mark(host, name);
        } catch (e) { console.log('[dns][native] ' + name + ' onEnter skip: ' + e); }
      }
    });
    console.log('[dns][native] ' + name + ' hooked @ ' + p);
  } catch (e) { console.log('[dns][native] ' + name + ' hook skip: ' + e); }
}

// 标准 POSIX 入口 + Android 实际底层入口，双保险兜住绕过 Java 栈的解析（Flutter/native）
hookGai('getaddrinfo');
hookGai('android_getaddrinfofornet');

console.log('[dns] armed —— 若只列出域名没有后续请求，是正常的：说明需触发功能或提供有效企业号才下发真源站，按需配合 http-url-hook.js / socket-hook.js');
