// accessibility-abuse-hook.js — 固证无障碍(AccessibilityService)被滥用做自动点击/读屏/远控转账
// 适用：远控类/盗刷类涉诈样本用无障碍自动操作(自动点"确认转账"、读屏抓验证码、模拟手势)。纯只读检测：只记录它做了什么，不注入/不操控。
// 跑：frida -U -l accessibility-abuse-hook.js -F  （建议无障碍服务已启用后 attach；spawn 也可，服务起来后才有事件）
// 改：onAccessibilityEvent 在 app 的 AccessibilityService 子类里→脚本 enumerateLoadedClasses 找子类挂；GACT_MAP 可补
'use strict';

var GACT_MAP = { 1: 'BACK', 2: 'HOME', 3: 'RECENTS', 4: 'NOTIFICATIONS', 5: 'QUICK_SETTINGS', 6: 'POWER_DIALOG', 8: 'TAKE_SCREENSHOT', 9: 'KEYCODE_HEADSETHOOK', 16: 'LOCK_SCREEN' };
var NACT_MAP = { 1: 'FOCUS', 16: 'CLICK', 32: 'LONG_CLICK', 2097152: 'SET_TEXT', 64: 'ACCESSIBILITY_FOCUS', 4096: 'SCROLL_FORWARD' };
function stack() { try { return Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new()); } catch (e) { return ''; } }

Java.perform(function () {

  // ============ A.「操作」侧（最具指证性）：performGlobalAction / dispatchGesture ============
  try {
    var AS = Java.use('android.accessibilityservice.AccessibilityService');
    if (AS.performGlobalAction) AS.performGlobalAction.implementation = function (a) {
      try { console.log('[a11y][LEAD-固证] performGlobalAction ' + (GACT_MAP[a] || a) + ' ← 程序模拟系统操作'); } catch (e) {}
      return this.performGlobalAction(a);
    };
    if (AS.dispatchGesture) AS.dispatchGesture.overloads.forEach(function (ov) {
      try {
        ov.implementation = function () {
          try {
            console.log('[a11y][LEAD-固证] dispatchGesture ← 模拟手势(自动点击/滑动，常用于自动确认转账/授权)');
            var g = arguments[0];
            try { var n = g.getStrokeCount(); for (var i = 0; i < n; i++) { var p = g.getStrokeAt(i).getPath(); console.log('[a11y]   stroke#' + i + ' path=' + p.toString()); } } catch (e) {}
            console.log('[a11y]   ' + (stack().split('\n')[3] || '').trim());
          } catch (e) {}
          return ov.apply(this, arguments);
        };
      } catch (e) {}
    });
    console.log('[a11y] AccessibilityService 操作侧 hooked');
  } catch (e) { console.log('[a11y] AccessibilityService hook skip: ' + e); }

  // ============ B. 节点级自动操作：AccessibilityNodeInfo.performAction ============
  try {
    var ANI = Java.use('android.view.accessibility.AccessibilityNodeInfo');
    ANI.performAction.overloads.forEach(function (ov) {
      try {
        ov.implementation = function () {
          try {
            var act = arguments[0];
            var txt = ''; try { var t = this.getText(); if (t) txt = '' + t; } catch (e) {}
            var vid = ''; try { var v = this.getViewIdResourceName(); if (v) vid = '' + v; } catch (e) {}
            console.log('[a11y][LEAD] performAction ' + (NACT_MAP[act] || act) + ' on [' + vid + '] text="' + txt + '" ← 自动操作目标控件');
          } catch (e) {}
          return ov.apply(this, arguments);
        };
      } catch (e) {}
    });
    console.log('[a11y] AccessibilityNodeInfo.performAction hooked');
  } catch (e) { console.log('[a11y] performAction hook skip: ' + e); }

  // ============ C.「读屏」侧：枚举 app 的 AccessibilityService 子类挂 onAccessibilityEvent ============
  // onAccessibilityEvent 是抽象方法、实现在 app 子类里(R8 混淆) → 枚举已加载类找 AccessibilityService 子类
  try {
    var ASBase = Java.use('android.accessibilityservice.AccessibilityService');
    var hooked = 0;
    Java.enumerateLoadedClasses({
      onMatch: function (name) {
        try {
          if (name.indexOf('android.') === 0 || name.indexOf('androidx.') === 0) return;
          var C; try { C = Java.use(name); } catch (e) { return; }
          if (!ASBase.class.isAssignableFrom(C.class)) return;
          if (!C.onAccessibilityEvent) return;
          C.onAccessibilityEvent.implementation = function (ev) {
            try {
              var pkg = ''; try { pkg = '' + ev.getPackageName(); } catch (e) {}
              var txt = ''; try { var l = ev.getText(); if (l && l.size() > 0) txt = '' + l.toString(); } catch (e) {}
              var et = ''; try { et = '' + ev.getEventType(); } catch (e) {}
              if (txt) console.log('[a11y][LEAD-固证] 读屏 onAccessibilityEvent pkg=' + pkg + ' type=' + et + ' text=' + txt + ' ← 抓取屏上内容(验证码/输入)');
            } catch (e) { console.log('[a11y] onEvent inspect skip: ' + e); }
            return this.onAccessibilityEvent(ev);
          };
          hooked++;
        } catch (e) {}
      },
      onComplete: function () {
        console.log(hooked > 0 ? '[a11y] onAccessibilityEvent 子类 hooked (' + hooked + ')'
                               : '[a11y] 未找到 AccessibilityService 子类 — 下一步：先在系统设置启用该无障碍服务、跑起来后再注入；或 jadx 找子类名手挂');
      }
    });
  } catch (e) { console.log('[a11y] onAccessibilityEvent 枚举 skip: ' + e); }

  console.log('[a11y] 已就绪：固证无障碍被用于自动点击/手势/读屏(远控转账、抓验证码)。纯只读，不注入不操控。');
});
