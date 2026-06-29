// anti-detection-native.js — native 层反检测绕过（补 anti-detection-hook 的 Java 层缺口）
// 适用：仍秒退/检测到 frida——壳在 native 层(JNI_OnLoad/.init_array)读 /proc/self/maps、TracerPid、线程名(comm)、扫 27042/扫 /data/local/tmp 找 frida-server
// 跑：最先注入，且必须 spawn：frida -U -f <包名> -l anti-detection-native.js -l anti-detection-hook.js ...（attach 上去时检测早跑完，必退）
// 改：BLOCK_27042 控制是否真让 app 连 frida 端口失败；命中刷屏调 HIT_CAP；仍秒退见文末提示（多半是 frida-server 本身被扫，需改名/改端口 server 或 gadget 重打包或换 LSPosed，或直接走带外 pcap）
'use strict';

var HIT_CAP = 60, hits = 0;
var BLOCK_27042 = true; // app 连 27042/27043 探 frida-server 时让其失败（绕过）；只想观测改 false
var FRIDA_MARK = ['frida', 'gum-js', 'gmain', 'gdbus', 'linjector', 're.frida', 'frida-agent', 'frida-server', 'gum_', 'pool-frida', 'gjs'];
// /data/local/tmp 下 frida-server 常见文件名/路径特征（壳 access/stat 探测）
var FRIDA_FILES = ['re.frida.server', 'frida-server', 'frida-agent', 'frida-gadget', 'linjector'];
function emit(kind, detail) { if (hits++ < HIT_CAP) console.log('[antidet-native][' + kind + '] ' + detail); }
function hasMark(s) { if (!s) return false; for (var i = 0; i < FRIDA_MARK.length; i++) if (s.indexOf(FRIDA_MARK[i]) !== -1) return true; return false; }
function hasFile(s) { if (!s) return false; for (var i = 0; i < FRIDA_FILES.length; i++) if (s.indexOf(FRIDA_FILES[i]) !== -1) return true; return false; }
function classifyPath(p) {
  if (!p) return null;
  if (p.indexOf('maps') !== -1) return 'maps';
  if (p.indexOf('/proc/') !== -1) {
    if (p.indexOf('/status') !== -1) return 'status';
    if (p.indexOf('/comm') !== -1) return 'comm';
  }
  return null;
}

var flaggedFILE = {}; // FILE*  → 'maps'|'status'|'comm'（stdio 路径）
var flaggedFD = {};   // int fd → 'maps'|'status'|'comm'（裸 syscall 路径）

// ============ A. stdio：fopen/fopen64 + fgets（原有，保留并扩 comm）============
['fopen', 'fopen64'].forEach(function (name) {
  try {
    var p = Module.findExportByName(null, name); if (!p) return;
    Interceptor.attach(p, {
      onEnter: function (a) { try { this.path = a[0].isNull() ? '' : a[0].readCString(); } catch (e) { this.path = ''; } },
      onLeave: function (ret) { try { if (ret.isNull() || !this.path) return; var k = classifyPath(this.path); if (k) { flaggedFILE[ret.toString()] = k; emit('open', k + '(stdio): ' + this.path); } } catch (e) {} }
    });
  } catch (e) {}
});
try {
  var fg = Module.findExportByName(null, 'fgets');
  if (fg) Interceptor.attach(fg, {
    onEnter: function (a) { this.buf = a[0]; this.stream = a[2]; },
    onLeave: function (ret) {
      try {
        if (ret.isNull() || this.buf.isNull()) return;
        var kind = flaggedFILE[this.stream.toString()]; if (!kind) return;
        var line = this.buf.readCString();
        if (kind === 'maps' && hasMark(line)) { this.buf.writeUtf8String('\n'); emit('hide', 'maps 行已抹: ' + (line || '').trim().slice(0, 60)); }
        else if (kind === 'status' && line && line.indexOf('TracerPid:') === 0 && line.indexOf('TracerPid:\t0') !== 0) { this.buf.writeUtf8String('TracerPid:\t0\n'); emit('hide', 'TracerPid → 0'); }
        else if (kind === 'comm' && hasMark(line)) { this.buf.writeUtf8String('main\n'); emit('hide', 'comm 线程名已改: ' + (line || '').trim()); }
      } catch (e) {}
    }
  });
} catch (e) {}
try { var fc = Module.findExportByName(null, 'fclose'); if (fc) Interceptor.attach(fc, { onEnter: function (a) { try { delete flaggedFILE[a[0].toString()]; } catch (e) {} } }); } catch (e) {}

// ============ B. 裸 syscall：open/openat 标记 fd + read 过滤（补 stdio 缺口，关键）============
['open', 'open64'].forEach(function (name) {
  try {
    var p = Module.findExportByName(null, name); if (!p) return;
    Interceptor.attach(p, {
      onEnter: function (a) { try { this.path = a[0].isNull() ? '' : a[0].readCString(); } catch (e) { this.path = ''; } },
      onLeave: function (ret) { try { var fd = ret.toInt32(); if (fd < 0 || !this.path) return; var k = classifyPath(this.path); if (k) { flaggedFD[fd] = k; emit('open', k + '(fd=' + fd + '): ' + this.path); } } catch (e) {} }
    });
  } catch (e) {}
});
try {
  var oa = Module.findExportByName(null, 'openat');
  if (oa) Interceptor.attach(oa, {
    onEnter: function (a) { try { this.path = a[1].isNull() ? '' : a[1].readCString(); } catch (e) { this.path = ''; } },
    onLeave: function (ret) { try { var fd = ret.toInt32(); if (fd < 0 || !this.path) return; var k = classifyPath(this.path); if (k) { flaggedFD[fd] = k; emit('open', k + '(openat fd=' + fd + '): ' + this.path); } } catch (e) {} }
  });
} catch (e) {}
try {
  var rd = Module.findExportByName(null, 'read');
  if (rd) Interceptor.attach(rd, {
    onEnter: function (a) { this.fd = a[0].toInt32(); this.buf = a[1]; },
    onLeave: function (ret) {
      try {
        var kind = flaggedFD[this.fd]; if (!kind) return;
        var n = ret.toInt32(); if (n <= 0 || this.buf.isNull()) return;
        var content = this.buf.readUtf8String(n); if (content === null) return;
        var cleaned = content;
        if (kind === 'maps') {
          var keep = []; var lines = content.split('\n'); var changed = false;
          for (var i = 0; i < lines.length; i++) { if (hasMark(lines[i])) { changed = true; continue; } keep.push(lines[i]); }
          if (changed) cleaned = keep.join('\n');
        } else if (kind === 'status') {
          cleaned = content.replace(/TracerPid:\t\d+/g, 'TracerPid:\t0');
        } else if (kind === 'comm') {
          if (hasMark(content)) cleaned = 'main\n';
        }
        if (cleaned !== content) {
          this.buf.writeUtf8String(cleaned);
          ret.replace(ptr(cleaned.length));   // 返回新长度（≤原长，app 读到更短但干净）
          emit('hide', kind + '(read fd=' + this.fd + ') 已净化 ' + n + '→' + cleaned.length + 'B');
        }
      } catch (e) {}
    }
  });
} catch (e) {}
try { var cl = Module.findExportByName(null, 'close'); if (cl) Interceptor.attach(cl, { onEnter: function (a) { try { delete flaggedFD[a[0].toInt32()]; } catch (e) {} } }); } catch (e) {}

// ============ C. 线程名：pthread_getname_np / prctl(PR_GET_NAME) 返回 frida 名 → 改 main ============
try {
  var gn = Module.findExportByName(null, 'pthread_getname_np');
  if (gn) Interceptor.attach(gn, {
    onEnter: function (a) { this.buf = a[1]; },
    onLeave: function () { try { if (this.buf && !this.buf.isNull()) { var nm = this.buf.readCString(); if (hasMark(nm)) { this.buf.writeUtf8String('main'); emit('thread', 'pthread_getname "' + nm + '" → main'); } } } catch (e) {} }
  });
} catch (e) {}
try {
  var pr = Module.findExportByName(null, 'prctl');
  if (pr) Interceptor.attach(pr, {
    onEnter: function (a) { this.op = a[0].toInt32(); this.arg = a[1]; },
    onLeave: function () { try { if (this.op === 16 /*PR_GET_NAME*/ && this.arg && !this.arg.isNull()) { var nm = this.arg.readCString(); if (hasMark(nm)) { this.arg.writeUtf8String('main'); emit('thread', 'prctl PR_GET_NAME "' + nm + '" → main'); } } } catch (e) {} }
  });
} catch (e) {}

// ============ D. 文件探测：access/faccessat + stat 系列 → frida 文件假装不存在 ============
['access', 'faccessat'].forEach(function (name) {
  try {
    var p = Module.findExportByName(null, name); if (!p) return;
    var pathIdx = (name === 'faccessat') ? 1 : 0;
    Interceptor.attach(p, {
      onEnter: function (a) { try { this.path = a[pathIdx].isNull() ? '' : a[pathIdx].readCString(); } catch (e) { this.path = ''; } },
      onLeave: function (ret) { try { if (hasFile(this.path) && ret.toInt32() === 0) { ret.replace(ptr(-1)); emit('file', name + '("' + this.path + '") → 不存在'); } } catch (e) {} }
    });
  } catch (e) {}
});
['stat', 'stat64', 'lstat', 'lstat64', '__xstat', '__lxstat'].forEach(function (name) {
  try {
    var p = Module.findExportByName(null, name); if (!p) return;
    // __xstat/__lxstat 第 0 参是 version、路径在第 1；其余路径在第 0。
    var pathIdx = (name.indexOf('xstat') !== -1) ? 1 : 0;
    Interceptor.attach(p, {
      onEnter: function (a) { try { this.path = a[pathIdx].isNull() ? '' : a[pathIdx].readCString(); } catch (e) { this.path = ''; } },
      onLeave: function (ret) { try { if (hasFile(this.path) && ret.toInt32() === 0) { ret.replace(ptr(-1)); emit('file', name + '("' + this.path + '") → 不存在'); } } catch (e) {} }
    });
  } catch (e) {}
});

// ============ E. 字符串函数中和：strstr/strcasestr/strcmp/strncmp/memmem needle=frida 串 → 不命中 ============
try {
  var ss = Module.findExportByName(null, 'strstr');
  if (ss) Interceptor.attach(ss, {
    onEnter: function (a) { try { this.needle = a[1].isNull() ? '' : a[1].readCString(); } catch (e) { this.needle = ''; } },
    onLeave: function (ret) { try { if (this.needle && hasMark(this.needle) && !ret.isNull()) { emit('neutralize', 'strstr("' + this.needle + '") → NULL'); ret.replace(ptr(0)); } } catch (e) {} }
  });
} catch (e) {}
try {
  var sci = Module.findExportByName(null, 'strcasestr');
  if (sci) Interceptor.attach(sci, {
    onEnter: function (a) { try { this.needle = a[1].isNull() ? '' : a[1].readCString(); } catch (e) { this.needle = ''; } },
    onLeave: function (ret) { try { if (this.needle && hasMark(this.needle) && !ret.isNull()) { emit('neutralize', 'strcasestr("' + this.needle + '") → NULL'); ret.replace(ptr(0)); } } catch (e) {} }
  });
} catch (e) {}
['strcmp', 'strncmp', 'strcasecmp'].forEach(function (name) {
  try {
    var p = Module.findExportByName(null, name); if (!p) return;
    Interceptor.attach(p, {
      onEnter: function (a) { try { this.s1 = a[0].isNull() ? '' : a[0].readCString(); this.s2 = a[1].isNull() ? '' : a[1].readCString(); } catch (e) { this.s1 = ''; this.s2 = ''; } },
      onLeave: function (ret) { try { if ((hasMark(this.s1) || hasMark(this.s2)) && ret.toInt32() === 0) { emit('neutralize', name + ' frida 串相等 → 改不等'); ret.replace(ptr(1)); } } catch (e) {} }
    });
  } catch (e) {}
});

// ============ F. connect：app 连 27042/27043 探 frida-server → 观测；BLOCK 时让其失败 ============
try {
  var cn = Module.findExportByName(null, 'connect');
  if (cn) Interceptor.attach(cn, {
    onEnter: function (a) {
      try { var sa = a[1]; if (sa.isNull()) { this.port = 0; return; } var fam = sa.readU16() & 0xff; this.port = (fam === 2 || fam === 10) ? ((sa.add(2).readU8() << 8) | sa.add(3).readU8()) : 0; } catch (e) { this.port = 0; }
    },
    onLeave: function (ret) { try { if (this.port === 27042 || this.port === 27043) { emit('port', '连 frida 端口 ' + this.port + (BLOCK_27042 ? ' → 阻断' : ' (仅观测)')); if (BLOCK_27042) ret.replace(ptr(-1)); } } catch (e) {} }
  });
} catch (e) {}

console.log('[antidet-native] ready（maps/status/comm: stdio+裸read 双覆盖 | 线程名 | /data/local/tmp 文件 | strstr/strcmp 系列 | 27042 ' + (BLOCK_27042 ? '阻断' : '观测') + '）');
console.log('[antidet-native] 仍秒退？检测多半在我们 hook 之前(壳 .init_array/JNI_OnLoad)或扫 frida-server 本身——换路子：');
console.log('[antidet-native]   ① 带外 pcap(不注入,App 碰不到): PCAPdroid 导出 → fxapk pcap-leads（最稳，拿接入节点 IP/SNI）');
console.log('[antidet-native]   ② 改名/改端口 frida-server(strongR-frida/Florida) 或 frida-gadget 重打包(不跑 server) 或 换 LSPosed 注入面');
console.log('[antidet-native]   ③ 确认用了 -f spawn 且本脚本最先 -l（attach 必晚）');
