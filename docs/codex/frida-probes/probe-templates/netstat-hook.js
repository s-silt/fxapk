// netstat-hook.js — 周期解析 /proc/net/tcp(6) + hook libc connect，抓全部出站对端 IP:port 与连接状态
// 适用：症状④普通抓包 endpoint=0 / 自建协议（MTProto/私有 IM/C2）不走 HTTP——无应用层 hook 也能抓 native 接入节点（如 :30113 SYN_SENT）
// 跑：frida -U -f <包名> -l netstat-hook.js -q   （建议先触发登录/聊天再看周期 dump）
// 改：只看本进程连接默认按 UID 过滤(SELF_UID_ONLY)；改 DUMP_INTERVAL 调采样周期；改 PORT_FOCUS 高亮关注端口；落盘 SNAP_PATH 仅 /data/local/tmp
'use strict';

var DUMP_INTERVAL = 3000;   // ms，/proc/net/tcp(6) 周期采样间隔；刷屏调大、怕漏短连接调小
var SELF_UID_ONLY = true;   // true=只打本 app UID 的连接（降噪）；false=打设备全量（含系统/其它 app）
var PORT_FOCUS = [];        // 关注端口高亮，如 [30113, 8888]；命中打 ★，便于在刷屏里抓接入节点
var SNAP_PATH = '/data/local/tmp/fx_netstat.log'; // 去重后的连接快照落盘（仅本机临时目录）；置 null 关闭落盘

/* ---------- TCP 状态码（/proc/net/tcp 第 4 列，十六进制）---------- */
// 调证锚点：SYN_SENT=只发了握手未建连（如刘超泉案 :30113，"连接尝试"而非"已登录")；ESTABLISHED=已建连有会话
var TCP_STATE = {
  '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV', '04': 'FIN_WAIT1',
  '05': 'FIN_WAIT2', '06': 'TIME_WAIT', '07': 'CLOSE', '08': 'CLOSE_WAIT',
  '09': 'LAST_ACK', '0A': 'LISTEN', '0B': 'CLOSING', '0C': 'NEW_SYN_RECV'
};
function stateName(hex) { var k = (hex || '').toUpperCase(); return (TCP_STATE[k] || ('?' + k)); }

/* ---------- 本进程 UID（用于 SELF_UID_ONLY 过滤）---------- */
var SELF_UID = -1;
try {
  // /proc/self/status 的 "Uid:" 行第 1 个字段就是 real uid
  var st = new File('/proc/self/status', 'r'); var line;
  while ((line = st.readLine()) !== null) {
    if (line.indexOf('Uid:') === 0) {
      var m = line.replace(/\s+/g, ' ').trim().split(' '); // "Uid: 10025 10025 10025 10025"
      if (m.length >= 2) SELF_UID = parseInt(m[1], 10);
      break;
    }
  }
  st.close();
  console.log('[netstat] self uid=' + SELF_UID + (SELF_UID_ONLY ? '（仅打本 app 连接，改 SELF_UID_ONLY=false 看全量）' : '（打设备全量连接）'));
} catch (e) { console.log('[netstat] 读 /proc/self/status uid skip: ' + e + '（将退化为全量打印）'); SELF_UID_ONLY = false; }

/* ---------- hex addr 解析 ---------- */
// /proc/net/tcp 的 local/rem 字段格式： "AABBCCDD:PPPP"
//   IPv4：8 hex = 4 字节、按小端存放（主机字节序），需逐字节倒序还原成点分十进制
//   端口：4 hex、网络字节序（大端），直接当大端整数读
function parseV4(hexAddr) {
  try {
    // hexAddr 形如 "9215356A"（小端）→ 还原 106.53.21.146
    var b = [
      parseInt(hexAddr.substr(0, 2), 16),
      parseInt(hexAddr.substr(2, 2), 16),
      parseInt(hexAddr.substr(4, 2), 16),
      parseInt(hexAddr.substr(6, 2), 16)
    ];
    return b[3] + '.' + b[2] + '.' + b[1] + '.' + b[0]; // 小端：倒序
  } catch (e) { return '<v4 err ' + e + '>'; }
}
// IPv6：32 hex = 16 字节，内核按每 4 字节(32bit word)小端存放、word 间顺序不变。
// 实测稳妥做法：把 32 个 hex 字符按字节读出后，每 4 字节一组组内倒序，再拼成 8 段冒号格式。
function parseV6(hexAddr) {
  try {
    if (hexAddr.length !== 32) return '<v6 len ' + hexAddr.length + '>';
    var bytes = [];
    for (var i = 0; i < 16; i++) bytes.push(parseInt(hexAddr.substr(i * 2, 2), 16));
    // 每 4 字节(1 个 32bit word)组内小端 → 倒序还原
    var fixed = [];
    for (var w = 0; w < 4; w++) {
      var base = w * 4;
      fixed.push(bytes[base + 3], bytes[base + 2], bytes[base + 1], bytes[base]);
    }
    // 拼 8 段，顺手识别 ::ffff: 映射的 IPv4（v4-mapped，常见）
    var segs = [];
    for (var j = 0; j < 16; j += 2) segs.push(((fixed[j] << 8) | fixed[j + 1]).toString(16));
    var full = segs.join(':');
    if (segs.slice(0, 5).join(':') === '0:0:0:0:0' && segs[5] === 'ffff') {
      return '[::ffff:' + fixed[12] + '.' + fixed[13] + '.' + fixed[14] + '.' + fixed[15] + ']';
    }
    return '[' + full + ']';
  } catch (e) { return '<v6 err ' + e + '>'; }
}
function parsePort(hexPort) { try { return parseInt(hexPort, 16); } catch (e) { return -1; } }
function focusMark(port) { for (var i = 0; i < PORT_FOCUS.length; i++) if (PORT_FOCUS[i] === port) return ' ★关注端口'; return ''; }

/* ---------- /proc/net/tcp(6) 一次性解析 ---------- */
// 列：sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid ...
function readProcNet(path, isV6) {
  var rows = [];
  try {
    var f = new File(path, 'r'); var line; var first = true;
    while ((line = f.readLine()) !== null) {
      if (first) { first = false; continue; } // 跳表头
      var parts = line.replace(/^\s+/, '').split(/\s+/);
      if (parts.length < 10) continue;
      var local = parts[1].split(':'), rem = parts[2].split(':');
      var st = parts[3], uid = parseInt(parts[7], 10);
      var localIp = isV6 ? parseV6(local[0]) : parseV4(local[0]);
      var remIp = isV6 ? parseV6(rem[0]) : parseV4(rem[0]);
      rows.push({
        proto: isV6 ? 'tcp6' : 'tcp',
        local: localIp + ':' + parsePort(local[1]),
        rem: remIp + ':' + parsePort(rem[1]),
        remPort: parsePort(rem[1]),
        state: stateName(st),
        uid: uid
      });
    }
    f.close();
  } catch (e) { console.log('[netstat] 读 ' + path + ' skip: ' + e); }
  return rows;
}

/* ---------- 周期 dump（去重）---------- */
var _seen = {};   // "proto rem state" -> 1，去重避免每周期重复刷
var _snapFile = null;
function snap(line) {
  if (!SNAP_PATH) return;
  try { if (_snapFile === null) _snapFile = new File(SNAP_PATH, 'a'); _snapFile.write(line + '\n'); _snapFile.flush(); }
  catch (e) { /* 落盘失败不影响 console 输出，只提示一次 */ if (!snap._warned) { console.log('[netstat] 落盘 ' + SNAP_PATH + ' 失败: ' + e); snap._warned = true; } }
}
function dumpOnce() {
  try {
    var rows = readProcNet('/proc/net/tcp', false).concat(readProcNet('/proc/net/tcp6', true));
    var newCount = 0, total = 0;
    rows.forEach(function (r) {
      if (SELF_UID_ONLY && SELF_UID >= 0 && r.uid !== SELF_UID) return;
      // 远端 0.0.0.0:0 / [::]:0 是 LISTEN/未连接，对调证无意义，跳过
      if (r.remPort === 0) return;
      total++;
      var key = r.proto + ' ' + r.rem + ' ' + r.state;
      if (_seen[key]) return;
      _seen[key] = 1; newCount++;
      var msg = '[netstat][proc] ' + r.proto + ' ' + r.local + ' -> ' + r.rem +
                ' [' + r.state + '] uid=' + r.uid + focusMark(r.remPort);
      console.log(msg);
      snap(new Date().toISOString() + ' ' + msg);
    });
    if (newCount === 0 && total === 0) {
      console.log('[netstat][proc] 本周期无' + (SELF_UID_ONLY ? '本 app ' : '') + '出站连接 —— 未命中。下一步：先在 app 内触发登录/聊天/支付再等几轮；或置 SELF_UID_ONLY=false 看全量，确认 UID 是否取错');
    }
  } catch (e) { console.log('[netstat] dumpOnce skip: ' + e); }
  setTimeout(dumpOnce, DUMP_INTERVAL); // 周期复采，自我续命
}

/* ---------- native: libc connect ----------
   int connect(int fd, const struct sockaddr* addr, socklen_t len)
   出站连接发起点，连失败也走这里——比 /proc 周期采样更早、更全（短连接不漏）。
   sockaddr_in：  family(2,LE) port(2,网络序) addr(4,网络序)
   sockaddr_in6： family(2,LE) port(2,网络序) flowinfo(4) addr(16,网络序) ... */
function parseSockaddr(sa) {
  try {
    if (sa === null || sa.isNull()) return null;
    var fam = sa.readU16() & 0xffff;
    var lo = fam & 0xff; // LE 机器低字节即 AF_*
    var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8(); // 端口恒网络字节序，手工 ntohs
    if (lo === 2) { // AF_INET
      var ip = sa.add(4).readU8() + '.' + sa.add(5).readU8() + '.' + sa.add(6).readU8() + '.' + sa.add(7).readU8();
      return { addr: ip + ':' + port, port: port };
    }
    if (lo === 10 || lo === 30) { // AF_INET6（Linux=10）
      var p = [];
      for (var i = 0; i < 16; i += 2) p.push(((sa.add(8 + i).readU8() << 8) | sa.add(8 + i + 1).readU8()).toString(16));
      // v4-mapped 识别
      if (p.slice(0, 5).join(':') === '0:0:0:0:0' && p[5] === 'ffff') {
        var b = []; for (var k = 12; k < 16; k++) b.push(sa.add(8 + k).readU8());
        return { addr: '[::ffff:' + b.join('.') + ']:' + port, port: port };
      }
      return { addr: '[' + p.join(':') + ']:' + port, port: port };
    }
    if (lo === 1) return { addr: '<AF_UNIX 本地域，非网络出站>', port: -1 }; // 不是远端节点，提示但不当线索
    return { addr: '<af=' + lo + '>', port: -1 };
  } catch (e) { return { addr: '<sockaddr err ' + e + '>', port: -1 }; }
}

var _connSeen = {}; // 出站对端去重，避免重连刷屏
try {
  var pConnect = Module.getExportByName(null, 'connect');
  if (pConnect === null) {
    console.log('[netstat][native] connect 未命中(符号不在导出表) — 下一步：Module.enumerateExportsSync("libc.so") 找符号，或仅靠上面的 /proc 周期采样兜底');
  } else {
    Interceptor.attach(pConnect, {
      onEnter: function (args) {
        try {
          var fd = args[0].toInt32();
          var r = parseSockaddr(args[1]);
          if (!r || r.port === 0) return;            // 端口 0 无意义
          if (r.addr.indexOf('AF_UNIX') >= 0) return; // 本地域 socket 不是出站节点
          var key = r.addr;
          if (_connSeen[key]) return;
          _connSeen[key] = 1;
          console.log('[netstat][connect] fd=' + fd + ' -> ' + r.addr + focusMark(r.port) +
                      '（出站发起，连成功与否看后续 /proc 状态）');
          snap(new Date().toISOString() + ' [connect] -> ' + r.addr);
        } catch (e) { console.log('[netstat][native] connect onEnter skip: ' + e); }
      }
    });
    console.log('[netstat][native] connect hooked @ ' + pConnect);
  }
} catch (e) { console.log('[netstat][native] connect hook skip: ' + e); }

/* ---------- 启动 ---------- */
console.log('[netstat] armed —— /proc/net/tcp(6) 每 ' + DUMP_INTERVAL + 'ms 采样 + libc connect 实时记录');
console.log('[netstat] 抓到什么→线索：每条「-> IP:port [状态]」即一个 native 出站对端。');
console.log('[netstat]   · SYN_SENT = 设备只发了握手、未确认建连（如 :30113 接入节点候选，写"连接尝试"勿写"已登录"）；');
console.log('[netstat]   · ESTABLISHED = 已建连有会话；远端 IP:port 即调证锚点 → 调云主机/弹性 IP 租户实名 + 该端口入站连接日志 + 同账号资源。');
if (SNAP_PATH) console.log('[netstat] 去重快照落盘 ' + SNAP_PATH + ' —— 取证：adb pull ' + SNAP_PATH);
dumpOnce(); // 立即跑第一轮，之后自周期续
