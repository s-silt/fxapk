// self-uninstall-guard-hook.js — 设备级毁证告警：抓 wipeData/自卸载/移除设备管理器，给取证人员留 adb pull 时间窗
// 适用：怀疑样本收到指令后清数据/自卸载毁证。纯只读告警：命中即打调用栈+上下文，默认放行不阻断(BLOCK 默认关，house 红线)。
// 跑：frida -U -f <包名> -l self-uninstall-guard-hook.js -q  （命中后立刻 adb pull /data/data/<包名> 固证）
// 改：BLOCK=true 才真正拦截毁证调用(改样本行为，仅在确认要保设备时临时开)；其余只记录
'use strict';

var BLOCK = false;   // house 红线：默认 false=只告警放行。true=拦截 wipeData/卸载(改行为，慎用)。

function stack() { try { return Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new()); } catch (e) { return '<no-stack>'; } }
function alarm(what, detail) {
  console.log('\n========== [self-wipe][LEAD-固证] ' + what + ' ==========');
  console.log('[self-wipe]   ' + detail);
  console.log('[self-wipe]   ★ 立刻 adb pull /data/data/<包名> 固证（聊天/转账/被远控记录）；调用栈定位触发点：');
  console.log(stack());
  console.log('[self-wipe]   ★ 若由推送指令触发→配 push-c2-inbound-hook 抓「远程下令毁证」物证链。');
  console.log('========== [self-wipe] END ==========\n');
}

Java.perform(function () {

  // ============ A. DevicePolicyManager.wipeData / wipeDevice：恢复出厂/清数据 ============
  try {
    var DPM = Java.use('android.app.admin.DevicePolicyManager');
    if (DPM.wipeData) DPM.wipeData.overloads.forEach(function (ov) {
      try {
        ov.implementation = function () {
          alarm('DevicePolicyManager.wipeData 调起（清数据/恢复出厂=最强毁证）', 'flags=' + (arguments.length ? arguments[0] : '?'));
          if (BLOCK) { console.log('[self-wipe] BLOCK=on 拦截 wipeData'); return; }
          return ov.apply(this, arguments);
        };
      } catch (e) {}
    });
    if (DPM.wipeDevice) DPM.wipeDevice.overloads.forEach(function (ov) {
      try { ov.implementation = function () { alarm('DevicePolicyManager.wipeDevice 调起', 'flags=' + (arguments.length ? arguments[0] : '?')); if (BLOCK) return; return ov.apply(this, arguments); }; } catch (e) {}
    });
    // 移除设备管理器(常是自卸载前置)
    if (DPM.removeActiveAdmin) DPM.removeActiveAdmin.implementation = function (cn) {
      alarm('DevicePolicyManager.removeActiveAdmin（解绑设备管理器，常为自卸载前置）', 'admin=' + cn);
      return this.removeActiveAdmin(cn);
    };
    console.log('[self-wipe] DevicePolicyManager hooked');
  } catch (e) { console.log('[self-wipe] DPM hook skip: ' + e); }

  // ============ B. PackageInstaller.uninstall：编程式卸载（含自卸载）============
  try {
    var PI = Java.use('android.content.pm.PackageInstaller');
    if (PI.uninstall) PI.uninstall.overloads.forEach(function (ov) {
      try {
        ov.implementation = function () {
          try {
            var target = '' + arguments[0];
            var self = '';
            try { self = '' + Java.use('android.app.ActivityThread').currentApplication().getPackageName(); } catch (e) {}
            alarm('PackageInstaller.uninstall 调起', 'target=' + target + (target.indexOf(self) >= 0 ? '  ★自卸载(==本包)' : ''));
          } catch (e) {}
          if (BLOCK) { console.log('[self-wipe] BLOCK=on 拦截 uninstall'); return; }
          return ov.apply(this, arguments);
        };
      } catch (e) {}
    });
    console.log('[self-wipe] PackageInstaller.uninstall hooked');
  } catch (e) { console.log('[self-wipe] PackageInstaller hook skip: ' + e); }

  // ============ C. Intent 卸载/删除动作（ACTION_UNINSTALL_PACKAGE / ACTION_DELETE）============
  try {
    var Intent = Java.use('android.content.Intent');
    Intent.setAction.implementation = function (a) {
      try {
        var act = '' + a;
        if (act.indexOf('UNINSTALL_PACKAGE') >= 0 || act === 'android.intent.action.DELETE') {
          alarm('Intent 卸载动作：' + act, '（拉起系统卸载界面诱导用户卸载）');
        }
      } catch (e) {}
      return this.setAction(a);
    };
    console.log('[self-wipe] Intent.setAction(卸载动作) hooked');
  } catch (e) { console.log('[self-wipe] Intent hook skip: ' + e); }

  // ============ D. shell 毁证：Runtime.exec("pm uninstall"/"rm -rf <自身>") ============
  try {
    var RT = Java.use('java.lang.Runtime');
    RT.exec.overloads.forEach(function (ov) {
      try {
        ov.implementation = function () {
          try {
            var c = arguments[0];
            var cmd = (c && c.$className && c.$className.indexOf('[') === 0) ? Java.use('java.util.Arrays').toString(c) : ('' + c);
            if (/pm\s+uninstall|rm\s+-rf|pm\s+clear/i.test(cmd)) alarm('Runtime.exec 毁证命令', cmd);
          } catch (e) {}
          return ov.apply(this, arguments);
        };
      } catch (e) {}
    });
    console.log('[self-wipe] Runtime.exec(毁证命令) hooked');
  } catch (e) { console.log('[self-wipe] Runtime.exec hook skip: ' + e); }

  console.log('[self-wipe] 已就绪（BLOCK=' + BLOCK + '，默认只告警放行）：抓 wipeData/自卸载/解绑管理器/卸载命令，命中即留时间窗固证。');
  console.log('[self-wipe] 抓不到→毁证走 native unlink/自实现：配 evidence-wipe-interceptor-hook 的 native 段。');
});
