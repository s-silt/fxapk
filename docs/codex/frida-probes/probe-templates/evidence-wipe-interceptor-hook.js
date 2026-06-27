// evidence-wipe-interceptor-hook.js — 取证抢救：样本删库/删缓存前先抢救一份 + 记录"谁在删什么"，堵证据灭失链
// 适用：怀疑样本会自毁聊天/转账/被远控记录(db/缓存)；要在删除真正落盘前留存物证。默认 observe-and-preserve：dump 后放行，不改样本行为。
// 跑：frida -U -f <包名> -l evidence-wipe-interceptor-hook.js -q  （抢救件落在 app 私有目录 files/apkscan_rescue/，取证 adb pull /data/data/<包名>）
// 改：PRESERVE=false 只记录不抢救；BLOCK=true 才真正阻止删除(默认关，house 红线)；RESCUE_DIR 现场可改；SUFFIX_WHITELIST 控抢救范围防噪
'use strict';

var PRESERVE = true;    // true: 删除前先抢救一份到 RESCUE_DIR；false: 只记录调用不抢救
var BLOCK = false;      // true: 阻止删除(改样本行为，默认关；只在确认要保活某文件时临时开)。house 红线：默认只观察放行。
var MAX_RESCUE = 200;   // 抢救件数封顶，防 rename/atomic-write 噪声刷爆
var SUFFIX_WHITELIST = ['.db', '.db-wal', '.db-shm', '.sqlite', '.realm', '.mmkv', '.xml', '.json', '.dat', '.log', '.txt', '.jpg', '.png'];

var RESCUE_DIR = null;  // 运行时解析为 <app files>/apkscan_rescue，拿不到退 /data/local/tmp
var rescued = 0;
var seenPath = {};

// ---- libc 原语：可靠读 /proc 外文件 + 复制（任何线程可用）----
var _open = null, _read = null, _write = null, _close = null, _mkdir = null;
try {
  _open  = new NativeFunction(Module.getExportByName(null, 'open'),  'int',  ['pointer', 'int', 'int']);
  _read  = new NativeFunction(Module.getExportByName(null, 'read'),  'long', ['int', 'pointer', 'ulong']);
  _write = new NativeFunction(Module.getExportByName(null, 'write'), 'long', ['int', 'pointer', 'ulong']);
  _close = new NativeFunction(Module.getExportByName(null, 'close'), 'int',  ['int']);
  _mkdir = new NativeFunction(Module.getExportByName(null, 'mkdir'), 'int',  ['pointer', 'int']);
} catch (e) { console.log('[wipe] libc 原语解析 skip: ' + e); }

function resolveRescueDir() {
  if (RESCUE_DIR !== null) return RESCUE_DIR;
  try {
    var ActivityThread = Java.use('android.app.ActivityThread');
    var app = ActivityThread.currentApplication();
    if (app !== null) {
      var d = '' + app.getApplicationContext().getFilesDir().getAbsolutePath() + '/apkscan_rescue';
      RESCUE_DIR = d;
    }
  } catch (e) {}
  if (RESCUE_DIR === null) RESCUE_DIR = '/data/local/tmp/apkscan_rescue';  // app uid 多半写不进，仅兜底
  try { if (_mkdir) _mkdir(Memory.allocUtf8String(RESCUE_DIR), 0x1c0 /*0700*/); } catch (e) {}
  console.log('[wipe] 抢救目录 = ' + RESCUE_DIR + '（取证 adb pull）');
  return RESCUE_DIR;
}

function whitelisted(path) {
  if (!path) return false;
  var p = path.toLowerCase();
  for (var i = 0; i < SUFFIX_WHITELIST.length; i++) if (p.indexOf(SUFFIX_WHITELIST[i]) === p.length - SUFFIX_WHITELIST[i].length) return true;
  return false;
}

function copyViaLibc(src) {
  if (!PRESERVE || !_open || rescued >= MAX_RESCUE) return false;
  if (!whitelisted(src)) return false;
  if (seenPath[src]) return false; seenPath[src] = 1;
  try {
    var dir = resolveRescueDir();
    var base = src.replace(/[\/\\]/g, '_').replace(/^_+/, '');
    var dst = dir + '/' + (rescued) + '_' + base;
    var sfd = _open(Memory.allocUtf8String(src), 0 /*O_RDONLY*/, 0);
    if (sfd.toInt32() < 0) return false;
    var dfd = _open(Memory.allocUtf8String(dst), 0x241 /*O_WRONLY|O_CREAT|O_TRUNC*/, 0x180 /*0600*/);
    if (dfd.toInt32() < 0) { _close(sfd); return false; }
    var buf = Memory.alloc(65536), total = 0;
    while (true) { var n = _read(sfd, buf, 65536).toInt32(); if (n <= 0) break; _write(dfd, buf, n); total += n; }
    _close(sfd); _close(dfd);
    rescued++;
    console.log('[wipe][RESCUE] 已抢救 ' + src + ' (' + total + 'B) -> ' + dst + (rescued >= MAX_RESCUE ? '（达上限，后续只记录）' : ''));
    return true;
  } catch (e) { console.log('[wipe] copy skip: ' + e); return false; }
}

function stack() { try { return Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new()); } catch (e) { return '<no-stack>'; } }

Java.perform(function () {
  resolveRescueDir();

  // ============ A. Java 层删除：File.delete / deleteRecursively / deleteDatabase ============
  try {
    var JFile = Java.use('java.io.File');
    JFile.delete.implementation = function () {
      try {
        var p = '' + this.getAbsolutePath();
        if (whitelisted(p)) { console.log('[wipe][delete] File.delete ' + p + '\n' + stack()); copyViaLibc(p); if (BLOCK) { console.log('[wipe] BLOCK=on 阻止删除'); return false; } }
      } catch (e) { console.log('[wipe] File.delete inspect skip: ' + e); }
      return this.delete();
    };
    console.log('[wipe] File.delete hooked');
  } catch (e) { console.log('[wipe] File.delete hook skip: ' + e); }

  try {
    var Ctx = Java.use('android.content.ContextWrapper');
    Ctx.deleteDatabase.implementation = function (name) {
      try {
        console.log('[wipe][delete] Context.deleteDatabase ' + name + '\n' + stack());
        var dbf = this.getDatabasePath(name); copyViaLibc('' + dbf.getAbsolutePath());
        if (BLOCK) { console.log('[wipe] BLOCK=on 阻止 deleteDatabase'); return false; }
      } catch (e) { console.log('[wipe] deleteDatabase inspect skip: ' + e); }
      return this.deleteDatabase(name);
    };
    console.log('[wipe] Context.deleteDatabase hooked');
  } catch (e) { console.log('[wipe] deleteDatabase hook skip: ' + e); }

  // ============ B. SQL 清表：execSQL 命中 DROP/DELETE/VACUUM ============
  try {
    var SQLite = Java.use('android.database.sqlite.SQLiteDatabase');
    SQLite.execSQL.overloads.forEach(function (ov) {
      try {
        ov.implementation = function () {
          try {
            var sql = '' + arguments[0];
            if (/\b(DROP|DELETE\s+FROM|VACUUM|TRUNCATE)\b/i.test(sql)) {
              console.log('[wipe][sql] execSQL 清数据: ' + sql);
              try { copyViaLibc('' + this.getPath()); } catch (e) {}   // 先抢救整库文件
            }
          } catch (e) { console.log('[wipe] execSQL inspect skip: ' + e); }
          return ov.apply(this, arguments);   // 默认放行（不阻断业务）
        };
      } catch (e) {}
    });
    console.log('[wipe] SQLiteDatabase.execSQL hooked');
  } catch (e) { console.log('[wipe] execSQL hook skip: ' + e); }

  // ============ C. native 删除：libc unlink/unlinkat/remove/rename ============
  ['unlink', 'remove'].forEach(function (sym) {
    try {
      var p = Module.findExportByName(null, sym);
      if (!p) return;
      Interceptor.attach(p, { onEnter: function (a) {
        try { var path = a[0].readUtf8String(); if (whitelisted(path)) { console.log('[wipe][native] ' + sym + ' ' + path); copyViaLibc(path); } } catch (e) {}
      } });
      console.log('[wipe][native] ' + sym + ' hooked');
    } catch (e) { console.log('[wipe][native] ' + sym + ' hook skip: ' + e); }
  });
  try {
    var pUnlinkat = Module.findExportByName(null, 'unlinkat');
    if (pUnlinkat) Interceptor.attach(pUnlinkat, { onEnter: function (a) {
      try { var path = a[1].readUtf8String(); if (whitelisted(path)) { console.log('[wipe][native] unlinkat ' + path); copyViaLibc(path); } } catch (e) {}
    } });
  } catch (e) { console.log('[wipe][native] unlinkat skip: ' + e); }
  try {
    var pRename = Module.findExportByName(null, 'rename');
    if (pRename) Interceptor.attach(pRename, { onEnter: function (a) {
      try { var from = a[0].readUtf8String(); if (whitelisted(from)) { console.log('[wipe][native] rename ' + from + ' -> ' + a[1].readUtf8String()); copyViaLibc(from); } } catch (e) {}
    } });
  } catch (e) { console.log('[wipe][native] rename skip: ' + e); }

  console.log('[wipe] 已就绪（PRESERVE=' + PRESERVE + ' BLOCK=' + BLOCK + '）：删 db/缓存前先抢救+记调用方，默认放行不改样本行为。');
  console.log('[wipe] 抓不到→样本用 native 自实现 IO 或 SAF/MediaStore 删：看 [native] 段或回退 process-exec/memdex。');
  console.log('[wipe] 取证：抢救件在 ' + RESCUE_DIR + '，连同 /data/data/<包名> 一并 adb pull 固证。');
});
