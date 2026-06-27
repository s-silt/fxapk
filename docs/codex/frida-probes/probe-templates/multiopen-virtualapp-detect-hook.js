// multiopen-virtualapp-detect-hook.js — 识别样本是否跑在「多开/虚拟化宿主」里(群控/卡农工业化克隆)
// 适用：怀疑团伙用多开/虚拟框架批量克隆运行同一涉诈 App。纯只读检测：只读路径/maps 判定并打印，不改任何行为。
// 跑：frida -U -f <包名> -l multiopen-virtualapp-detect-hook.js -q
// 改：HOST_MARKERS 现场补宿主包名/特征；命中即 [LEAD] 固证「批量克隆」并露宿主厂商→可顺线追群控后台
'use strict';

// 多开/虚拟化宿主特征（包名/路径段/框架名）；命中即强信号
var HOST_MARKERS = [
  'com.lody.virtual', 'io.virtualapp', 'com.bly.dkplat', 'com.lbe.parallel', 'com.lbe.doubleagent',
  'com.qihoo.magic', 'com.excelliance.dualaper', 'com.ludashi.dualspace', 'com.parallel.space',
  'multiapp', 'doubleopen', 'dualspace', 'virtualcore', 'com.by.kpswitch', '/virtual/', 'VirtualApp',
];

function readProc(path) {
  try {
    var _open = new NativeFunction(Module.getExportByName(null, 'open'), 'int', ['pointer', 'int']);
    var _read = new NativeFunction(Module.getExportByName(null, 'read'), 'long', ['int', 'pointer', 'ulong']);
    var _close = new NativeFunction(Module.getExportByName(null, 'close'), 'int', ['int']);
    var fd = _open(Memory.allocUtf8String(path), 0); if (fd.toInt32() < 0) return '';
    var buf = Memory.alloc(16384), out = '';
    while (true) { var n = _read(fd, buf, 16384).toInt32(); if (n <= 0) break; out += buf.readUtf8String(n); }
    _close(fd); return out;
  } catch (e) { return ''; }
}

function hitMarker(s) {
  if (!s) return null;
  var low = s.toLowerCase();
  for (var i = 0; i < HOST_MARKERS.length; i++) if (low.indexOf(HOST_MARKERS[i].toLowerCase()) >= 0) return HOST_MARKERS[i];
  return null;
}

Java.perform(function () {
  var hits = [];

  // ---- 信号1：app 私有目录被重定向到含宿主特征/`/virtual/` 的真实沙箱路径 ----
  try {
    var ActivityThread = Java.use('android.app.ActivityThread');
    var app = ActivityThread.currentApplication();
    if (app !== null) {
      var ctx = app.getApplicationContext();
      var pkg = '' + ctx.getPackageName();
      var filesPath = '' + ctx.getFilesDir().getAbsolutePath();
      console.log('[multiopen] 包名=' + pkg + '  filesDir=' + filesPath);
      // 正常应是 /data/user/0/<pkg>/files；多开后常变成 .../virtual/<uid>/<pkg>/... 或宿主包名段
      var m = hitMarker(filesPath);
      if (m) { hits.push('filesDir 含宿主特征「' + m + '」'); }
      if (filesPath.indexOf('/data/user/0/' + pkg) !== 0 && filesPath.indexOf('/data/data/' + pkg) !== 0) {
        hits.push('filesDir 不在标准 /data/data/' + pkg + ' 下（疑被多开框架重定向）：' + filesPath);
      }
      // applicationInfo.dataDir 同理核对
      try {
        var dataDir = '' + ctx.getApplicationInfo().dataDir;
        if (hitMarker(dataDir) || (dataDir.indexOf(pkg) < 0)) hits.push('applicationInfo.dataDir 异常：' + dataDir);
      } catch (e) {}
    }
  } catch (e) { console.log('[multiopen] 路径检测 skip: ' + e); }

  // ---- 信号2：/proc/self/maps 里加载了宿主框架 .so / 宿主包路径 ----
  try {
    var maps = readProc('/proc/self/maps');
    var seen = {};
    maps.split('\n').forEach(function (line) {
      var m = hitMarker(line);
      if (m && !seen[m]) { seen[m] = 1; hits.push('maps 加载宿主特征「' + m + '」'); }
    });
  } catch (e) { console.log('[multiopen] maps 检测 skip: ' + e); }

  // ---- 信号3：/proc/self/cmdline 与包名不一致（宿主进程托管子进程）----
  try {
    var cmd = readProc('/proc/self/cmdline').replace(/\x00/g, ' ').trim();
    var m2 = hitMarker(cmd);
    if (m2) hits.push('进程 cmdline 含宿主「' + m2 + '」：' + cmd);
  } catch (e) {}

  // ---- 汇总 ----
  if (hits.length > 0) {
    console.log('\n========== [multiopen][LEAD-固证] 疑似运行在多开/虚拟化宿主内（工业化批量克隆）==========');
    hits.forEach(function (h) { console.log('[multiopen]   ★ ' + h); });
    console.log('[multiopen]   调证价值：固证「同一 App 被多开框架批量克隆运行」+ 露出宿主厂商 → 顺线追群控/卡农后台与设备农场。');
    console.log('========== [multiopen] END ==========\n');
  } else {
    console.log('[multiopen] 未命中宿主特征 —— 可能：① 非多开运行；② 宿主用了未知框架(把其包名/路径段补进 HOST_MARKERS 再跑)；③ maps 尚未加载完(进程跑起来后重注入)。');
  }
});
