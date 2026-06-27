// sensitive-data-access-hook.js — 固证 App 偷读了哪些受害人数据：通讯录/短信/通话/位置/剪贴板/IMEI/手机号
// 适用：研判涉诈样本的数据收割面(隐私窃取/精准诈骗素材)。纯只读检测：只记录"读了什么"，不修改/不外发任何数据。
// 跑：frida -U -f <包名> -l sensitive-data-access-hook.js -q
// 改：URI_MAP 现场可补；剪贴板/IMEI 命中即 [LEAD] 固证窃取
'use strict';

// ContentProvider URI → 数据类别（读这些 = 在收割对应隐私）
var URI_MAP = [
  ['contacts', '通讯录'], ['com.android.contacts', '通讯录'], ['sms', '短信'], ['mms', '彩信'],
  ['call_log', '通话记录'], ['calls', '通话记录'], ['media', '相册/媒体'], ['images', '相册'],
  ['video', '视频'], ['downloads', '下载文件'], ['calendar', '日历'], ['icc/adn', 'SIM联系人'],
];
function classifyUri(u) { var s = (u || '').toLowerCase(); for (var i = 0; i < URI_MAP.length; i++) if (s.indexOf(URI_MAP[i][0]) >= 0) return URI_MAP[i][1]; return null; }
function b2hex(bytes) { try { var o = ''; for (var i = 0; i < bytes.length; i++) { o += ('0' + (bytes[i] & 0xff).toString(16)).slice(-2); } return o; } catch (e) { return '<hex err>'; } }
function stack() { try { return Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new()); } catch (e) { return ''; } }
var seen = {};
function once(k) { if (seen[k]) return false; seen[k] = true; return true; }

Java.perform(function () {

  // ============ A. ContentResolver.query：读通讯录/短信/通话/相册 ============
  try {
    var CR = Java.use('android.content.ContentResolver');
    CR.query.overloads.forEach(function (ov) {
      try {
        ov.implementation = function () {
          try {
            var uri = '' + arguments[0];
            var cat = classifyUri(uri);
            if (cat && once('q:' + cat + uri)) {
              console.log('[sens][LEAD-固证] 读取' + cat + ' ← ContentResolver.query ' + uri);
              console.log('[sens]   ' + (stack().split('\n')[3] || '').trim());
            }
          } catch (e) { console.log('[sens] query inspect skip: ' + e); }
          return ov.apply(this, arguments);
        };
      } catch (e) {}
    });
    console.log('[sens] ContentResolver.query hooked');
  } catch (e) { console.log('[sens] query hook skip: ' + e); }

  // ============ B. 剪贴板读取：收款码/钱包地址劫持 ============
  try {
    var CM = Java.use('android.content.ClipboardManager');
    ['getPrimaryClip', 'getText'].forEach(function (mn) {
      try {
        if (!CM[mn]) return;
        CM[mn].implementation = function () {
          var r = this[mn]();
          try {
            var txt = '';
            if (mn === 'getText') { txt = r ? ('' + r) : ''; }
            else if (r !== null) { var n = r.getItemCount(); for (var i = 0; i < n; i++) { var t = r.getItemAt(i).coerceToText(this === undefined ? null : Java.use('android.app.ActivityThread').currentApplication()); if (t) txt += ('' + t); } }
            if (txt) console.log('[sens][LEAD-固证] 读剪贴板内容(' + mn + ')：' + txt + '  ★收款码/钱包地址劫持嫌疑');
          } catch (e) { console.log('[sens] clipboard read skip: ' + e); }
          return r;
        };
      } catch (e) { console.log('[sens] clipboard ' + mn + ' skip: ' + e); }
    });
    console.log('[sens] ClipboardManager hooked');
  } catch (e) { console.log('[sens] clipboard hook skip: ' + e); }

  // ============ C. 设备标识/手机号采集：IMEI/IMSI/手机号/SIM ============
  try {
    var TM = Java.use('android.telephony.TelephonyManager');
    [['getDeviceId', 'IMEI/设备ID'], ['getImei', 'IMEI'], ['getMeid', 'MEID'], ['getSubscriberId', 'IMSI'],
     ['getLine1Number', '本机手机号'], ['getSimSerialNumber', 'SIM序列号'], ['getSimOperator', '运营商']].forEach(function (pair) {
      try {
        var mn = pair[0]; if (!TM[mn]) return;
        TM[mn].overloads.forEach(function (ov) {
          ov.implementation = function () {
            var r = ov.apply(this, arguments);
            try { if (r !== null && once('tm:' + mn)) console.log('[sens][LEAD] 采集' + pair[1] + ' (' + mn + ') = ' + r + ' → 设备指纹/定位受害人'); } catch (e) {}
            return r;
          };
        });
      } catch (e) {}
    });
    console.log('[sens] TelephonyManager hooked');
  } catch (e) { console.log('[sens] TM hook skip: ' + e); }

  // ============ D. 定位采集 ============
  try {
    var LM = Java.use('android.location.LocationManager');
    ['getLastKnownLocation', 'requestLocationUpdates'].forEach(function (mn) {
      try {
        if (!LM[mn]) return;
        LM[mn].overloads.forEach(function (ov) {
          ov.implementation = function () {
            try { if (once('loc:' + mn)) console.log('[sens][LEAD-固证] 采集地理位置(' + mn + ' provider=' + (arguments.length ? arguments[0] : '?') + ')'); } catch (e) {}
            var r = ov.apply(this, arguments);
            try { if (mn === 'getLastKnownLocation' && r !== null) console.log('[sens]   位置 = ' + r.getLatitude() + ',' + r.getLongitude()); } catch (e) {}
            return r;
          };
        });
      } catch (e) {}
    });
    console.log('[sens] LocationManager hooked');
  } catch (e) { console.log('[sens] location hook skip: ' + e); }

  // ============ E. 录屏：MediaProjection.createVirtualDisplay（远程查看屏幕）============
  try {
    var MP = Java.use('android.media.projection.MediaProjection');
    if (MP.createVirtualDisplay) MP.createVirtualDisplay.overloads.forEach(function (ov) {
      try { ov.implementation = function () { try { console.log('[sens][LEAD-固证] MediaProjection.createVirtualDisplay → 录屏/远程查看屏幕'); console.log('[sens]   ' + (stack().split('\n')[3] || '').trim()); } catch (e) {} return ov.apply(this, arguments); }; } catch (e) {}
    });
    console.log('[sens] MediaProjection hooked');
  } catch (e) { console.log('[sens] MediaProjection hook skip: ' + e); }

  console.log('[sens] 已就绪：固证样本读取了哪些受害人数据(通讯录/短信/通话/位置/剪贴板/IMEI/手机号/录屏)。纯只读，不改不发。');
  console.log('[sens] 抓不到→数据走 native/SAF 读或未触发：先在 App 内点对应功能，或回退 sqlite/process-exec。');
});
