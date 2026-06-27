// anti-detection-native.js — native 层反检测绕过（补 anti-detection-hook 的 Java 层缺口）
// 适用：仍秒退/检测到 frida——壳在 native 层(JNI_OnLoad/.init_array)读 /proc/self/maps、TracerPid、扫 27042 端口
// 跑：最先注入，且要 spawn：frida -U -f <包名> -l anti-detection-native.js -l anti-detection-hook.js ...
// 取证定位：这是绕过、不是产线索；但命中会打 [antidet-native] 告诉你壳用了哪种 native 检测（研判加固强度）
// 改：BLOCK_27042 控制是否真的让 app 连 frida 端口失败；命中刷屏调 HIT_CAP
'use strict';

var HIT_CAP = 40, hits = 0;
var BLOCK_27042 = true; // app 连 27042/27043 探 frida-server 时让其失败（绕过）；只想观测改 false
var FRIDA_MARK = ['frida', 'gum-js', 'gmain', 'gdbus', 'linjector', 're.frida', 'frida-agent', 'frida-server'];
function emit(kind, detail) { if (hits++ < HIT_CAP) console.log('[antidet-native][' + kind + '] ' + detail); }
function hasMark(s) { if (!s) return false; for (var i = 0; i < FRIDA_MARK.length; i++) if (s.indexOf(FRIDA_MARK[i]) !== -1) return true; return false; }

var flagged = {}; // FILE* → 'maps' | 'status'

// fopen/fopen64：标记打开 /proc/self/maps 与 status 的 FILE*
['fopen', 'fopen64'].forEach(function (name) {
  try {
    var p = Module.findExportByName(null, name); if (!p) return;
    Interceptor.attach(p, {
      onEnter: function (a) { try { this.path = a[0].isNull() ? '' : a[0].readCString(); } catch (e) { this.path = ''; } },
      onLeave: function (ret) {
        try {
          if (ret.isNull() || !this.path) return;
          if (this.path.indexOf('maps') !== -1) { flagged[ret.toString()] = 'maps'; emit('open', 'maps: ' + this.path); }
          else if (this.path.indexOf('/status') !== -1 && this.path.indexOf('/proc/') === 0) { flagged[ret.toString()] = 'status'; emit('open', 'status: ' + this.path); }
        } catch (e) {}
      }
    });
  } catch (e) {}
});

// fgets：对 maps 行抹掉含 frida 的行；对 status 把 TracerPid 改成 0
try {
  var fg = Module.findExportByName(null, 'fgets');
  if (fg) Interceptor.attach(fg, {
    onEnter: function (a) { this.buf = a[0]; this.stream = a[2]; },
    onLeave: function (ret) {
      try {
        if (ret.isNull() || this.buf.isNull()) return;
        var kind = flagged[this.stream.toString()]; if (!kind) return;
        var line = this.buf.readCString();
        if (kind === 'maps' && hasMark(line)) { this.buf.writeUtf8String('\n'); emit('hide', 'maps 行已抹: ' + (line || '').trim().slice(0, 60)); }
        else if (kind === 'status' && line && line.indexOf('TracerPid:') === 0 && line.indexOf('TracerPid:\t0') !== 0) { this.buf.writeUtf8String('TracerPid:\t0\n'); emit('hide', 'TracerPid → 0 (原: ' + line.trim() + ')'); }
      } catch (e) {}
    }
  });
} catch (e) {}

// fclose：清理标记
try { var fc = Module.findExportByName(null, 'fclose'); if (fc) Interceptor.attach(fc, { onEnter: function (a) { try { delete flagged[a[0].toString()]; } catch (e) {} } }); } catch (e) {}

// strstr：针对性中和——needle 是 frida 串时返回 NULL（壳常用 strstr(maps_buf,"frida") 探测）
try {
  var ss = Module.findExportByName(null, 'strstr');
  if (ss) Interceptor.attach(ss, {
    onEnter: function (a) { try { this.needle = a[1].isNull() ? '' : a[1].readCString(); } catch (e) { this.needle = ''; } },
    onLeave: function (ret) { try { if (this.needle && hasMark(this.needle) && !ret.isNull()) { emit('neutralize', 'strstr(needle="' + this.needle + '") → NULL'); ret.replace(ptr(0)); } } catch (e) {} }
  });
} catch (e) {}

// connect：app 连 27042/27043 探 frida-server → 观测；BLOCK 时让其失败
try {
  var cn = Module.findExportByName(null, 'connect');
  if (cn) Interceptor.attach(cn, {
    onEnter: function (a) {
      try {
        var sa = a[1]; if (sa.isNull()) { this.port = 0; return; }
        var fam = sa.readU16() & 0xff;
        this.port = (fam === 2 || fam === 10) ? ((sa.add(2).readU8() << 8) | sa.add(3).readU8()) : 0;
      } catch (e) { this.port = 0; }
    },
    onLeave: function (ret) { try { if (this.port === 27042 || this.port === 27043) { emit('port', '连接 frida 端口 ' + this.port + (BLOCK_27042 ? ' → 阻断' : ' (仅观测)')); if (BLOCK_27042) ret.replace(ptr(-1)); } } catch (e) {} }
  });
} catch (e) {}

console.log('[antidet-native] ready（maps/status 抹改 + strstr 中和 + 27042 ' + (BLOCK_27042 ? '阻断' : '观测') + '）');
