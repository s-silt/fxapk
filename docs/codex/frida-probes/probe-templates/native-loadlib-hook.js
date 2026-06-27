// native-loadlib-hook.js — 列出 app 加载的 .so（System.loadLibrary / load / dlopen）
// 适用：① 定位承载 BoringSSL/加密的 native 模块名（喂给 native-ssl-hook.js）；② 抓壳释放并加载的 payload .so
// 跑：frida -U -f <包名> -l native-loadlib-hook.js -q
// 改：想在某 .so 加载后立刻挂它的导出，在 dlopen onLeave 里按 path 触发对应 hook
Java.perform(function () {
  // Java 层：System.loadLibrary(短名) / System.load(全路径)
  try {
    var Sys = Java.use('java.lang.System');
    Sys.loadLibrary.implementation = function (name) { console.log('[loadlib][System.loadLibrary] ' + name); return this.loadLibrary(name); };
    Sys.load.implementation = function (path) { console.log('[loadlib][System.load] ' + path); return this.load(path); };
    console.log('[loadlib] System.loadLibrary/load hooked');
  } catch (e) { console.log('[loadlib] System.* skip: ' + e); }

  // Runtime.loadLibrary0（System.loadLibrary 最终落点，部分壳直接调它绕过 System）
  try {
    var Rt = Java.use('java.lang.Runtime');
    Rt.loadLibrary0.overloads.forEach(function (ov) {
      ov.implementation = function () {
        try { console.log('[loadlib][Runtime.loadLibrary0] ' + arguments[arguments.length - 1]); } catch (e) {}
        return ov.apply(this, arguments);
      };
    });
  } catch (e) {}

  // native 层：dlopen / android_dlopen_ext —— 最全，含 app 内部 dlopen 释放的 .so
  ['dlopen', 'android_dlopen_ext'].forEach(function (name) {
    try {
      var p = Module.getExportByName(null, name);
      if (p === null) return;
      Interceptor.attach(p, {
        onEnter: function (args) { try { this.path = args[0].isNull() ? '' : args[0].readCString(); } catch (e) { this.path = '<?>'; } },
        onLeave: function (ret) {
          if (this.path && this.path.indexOf('.so') !== -1)
            console.log('[loadlib][native][' + name + '] ' + this.path + (ret.isNull() ? ' (FAILED)' : ''));
        }
      });
      console.log('[loadlib] native ' + name + ' hooked');
    } catch (e) {}
  });

  console.log('[loadlib] ready —— 把承载加密/TLS 的 .so 名喂给 native-ssl-hook.js 的模块列表');
});
