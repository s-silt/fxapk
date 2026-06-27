// dexload-hook.js — 抓动态加载/二次释放的 DEX 路径与字节，dump 回灌静态分析
// 适用：壳/加固 app 在运行时才释放真实代码（DexClassLoader / InMemoryDexClassLoader）；静态分析看不到真实逻辑
// 跑：frida -U -f <包名> -l dexload-hook.js -q
// 改：InMemory 的 ByteBuffer 想落盘改 DUMP_DIR；只想看路径不落盘删 dumpBuffer 调用
Java.perform(function () {
  var DUMP_DIR = '/data/local/tmp/fx_dex'; // adb pull 它回灌：fxapk analyze <壳apk> --extra-dex <这些.dex>

  function mkdir() { try { Java.use('java.io.File').$new(DUMP_DIR).mkdirs(); } catch (e) {} }

  // 把 InMemoryDexClassLoader 的 ByteBuffer 落盘
  function dumpBuffer(buf, tag) {
    try {
      mkdir();
      var bb = Java.cast(buf, Java.use('java.nio.ByteBuffer'));
      var n = bb.remaining();
      var arr = Java.array('byte', Array(n).fill(0));
      bb.mark(); bb.get(arr); bb.reset();
      var path = DUMP_DIR + '/' + tag + '_' + n + '.dex';
      var fos = Java.use('java.io.FileOutputStream').$new(path);
      fos.write(arr); fos.close();
      console.log('[dexload] 已落盘 InMemory dex (' + n + ' B) → ' + path + '  （adb pull 回灌静态）');
    } catch (e) { console.log('[dexload] dumpBuffer skip: ' + e); }
  }

  // 1) DexClassLoader / PathClassLoader —— dexPath 是磁盘上的 .dex/.jar/.apk
  ['dalvik.system.DexClassLoader', 'dalvik.system.PathClassLoader'].forEach(function (cls) {
    try {
      var C = Java.use(cls);
      C.$init.overloads.forEach(function (ov) {
        ov.implementation = function () {
          try { console.log('[dexload] ' + cls + ' dexPath=' + arguments[0]); } catch (e) {}
          return ov.apply(this, arguments);
        };
      });
      console.log('[dexload] ' + cls + ' hooked');
    } catch (e) { console.log('[dexload] ' + cls + ' skip: ' + e); }
  });

  // 2) InMemoryDexClassLoader（API 26+）—— 字节在内存，必须落盘才拿得到
  try {
    var IM = Java.use('dalvik.system.InMemoryDexClassLoader');
    IM.$init.overloads.forEach(function (ov) {
      ov.implementation = function () {
        try {
          var a0 = arguments[0];
          if (a0 && a0.remaining) dumpBuffer(a0, 'inmem');                    // 单 ByteBuffer
          else if (a0 && a0.length !== undefined) {                            // ByteBuffer[]
            for (var i = 0; i < a0.length; i++) dumpBuffer(a0[i], 'inmem' + i);
          }
        } catch (e) { console.log('[dexload] InMemory dump skip: ' + e); }
        return ov.apply(this, arguments);
      };
    });
    console.log('[dexload] InMemoryDexClassLoader hooked');
  } catch (e) { console.log('[dexload] InMemoryDexClassLoader skip: ' + e); }

  // 3) DexFile.loadDex（老接口兜底）
  try {
    var DF = Java.use('dalvik.system.DexFile');
    DF.loadDex.implementation = function (src, out, flags) {
      console.log('[dexload] DexFile.loadDex src=' + src + ' out=' + out);
      return this.loadDex(src, out, flags);
    };
    console.log('[dexload] DexFile.loadDex hooked');
  } catch (e) {}

  console.log('[dexload] ready —— 释放的 dex 路径/落盘后 adb pull 回灌：fxapk analyze <apk> --extra-dex <dex...>');
});
