// process-exec-hook.js — 抓 app 执行的 shell 命令 / 二次 payload（Runtime.exec / ProcessBuilder / libc）
// 适用：app 跑外部命令（探测 root/装包/拉起子进程/释放执行 so 或脚本）；排查运营端动作与二次释放
// 跑：frida -U -f <包名> -l process-exec-hook.js -q
// 改：只关心 native 层就留 libc 段；命令刷屏改 console 为落文件
Java.perform(function () {
  function arr2str(a) { try { if (!a) return ''; if (a.length === undefined) return '' + a; var r = []; for (var i = 0; i < a.length; i++) r.push('' + a[i]); return r.join(' '); } catch (e) { return '<arr?>'; } }

  // Runtime.exec —— 全重载（String / String[] / 带 envp / 带 dir）
  try {
    var Rt = Java.use('java.lang.Runtime');
    Rt.exec.overloads.forEach(function (ov) {
      ov.implementation = function () {
        try { console.log('[exec][Runtime.exec] ' + arr2str(arguments[0])); } catch (e) {}
        return ov.apply(this, arguments);
      };
    });
    console.log('[exec] Runtime.exec hooked');
  } catch (e) { console.log('[exec] Runtime.exec skip: ' + e); }

  // ProcessBuilder.start —— this.command() 即完整命令行
  try {
    var PB = Java.use('java.lang.ProcessBuilder');
    PB.start.implementation = function () {
      try { console.log('[exec][ProcessBuilder] ' + this.command().toString()); } catch (e) {}
      return this.start();
    };
    console.log('[exec] ProcessBuilder.start hooked');
  } catch (e) { console.log('[exec] ProcessBuilder.start skip: ' + e); }

  // libc 层兜底：system() / execve()（Java 之外直接跑命令）
  ['system', 'execve', 'execv', 'execvp', 'popen'].forEach(function (name) {
    try {
      var p = Module.getExportByName(null, name);
      if (p === null) return;
      Interceptor.attach(p, {
        onEnter: function (args) {
          try {
            if (name === 'execve' || name === 'execv' || name === 'execvp') console.log('[exec][native][' + name + '] ' + args[0].readCString());
            else console.log('[exec][native][' + name + '] ' + args[0].readCString());
          } catch (e) {}
        }
      });
      console.log('[exec] native ' + name + ' hooked');
    } catch (e) {}
  });

  console.log('[exec] ready');
});
