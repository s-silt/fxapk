// sharedprefs-hook.js — hook SharedPreferences 读写，抠登录前落盘的真实后端/租户标识/凭据（含 MMKV 兜底）
// 适用：真源站不在抓包里(只见CDN/OSS配置层) / 端点点功能才出现 / 想在无账号冷启动就拿到 base_url、token、agent_id 等
// 跑：frida -U -f <包名> -l sharedprefs-hook.js -q
// 改：非标准存储看 hookMMKV(MMKV) 或自行加 DataStore；KEY_HINTS / valueLooksInteresting 现场按目标 app 的键名调

Java.perform(function () {
  'use strict';

  // —— 取证关注的键名线索：落地的真后端 / 租户标识 / 凭据 ——
  var KEY_HINTS = [
    'base_url', 'baseurl', 'server', 'host', 'domain', 'api', 'endpoint', 'gateway', 'cdn', 'oss',
    'line', 'kf', 'cs', 'service', 'chat', 'im', 'ws', 'socket', 'pay', 'cashier',
    'token', 'access_token', 'refresh_token', 'auth', 'cookie', 'session', 'sid', 'jwt', 'sign', 'secret',
    'agent', 'agent_id', 'agentid', 'csbid', 'bid', 'eid', 'uid', 'merchant', 'mch', 'tenant',
    'group', 'groupid', 'channel', 'app_id', 'appid', 'app_key', 'appkey', 'device', 'deviceid'
  ];

  function lc(s) { try { return ('' + s).toLowerCase(); } catch (e) { return ''; } }

  function keyLooksInteresting(k) {
    var s = lc(k);
    for (var i = 0; i < KEY_HINTS.length; i++) {
      if (s.indexOf(KEY_HINTS[i]) !== -1) return true;
    }
    return false;
  }

  function valueLooksInteresting(v) {
    if (v == null) return false;
    var s = lc(v);
    // URL / IP / 长 token / JSON 配置 都值得看
    return s.indexOf('http') !== -1 || s.indexOf('ws') === 0 || s.indexOf('://') !== -1 ||
           /\d+\.\d+\.\d+\.\d+/.test(s) || s.length >= 24 || s.indexOf('{') !== -1;
  }

  function show(tag, op, key, val) {
    try {
      var k = '' + key;
      var hit = keyLooksInteresting(k) || valueLooksInteresting(val);
      // 只打印有取证价值的，避免淹没；想看全部把下一行的 if 去掉
      if (!hit) return;
      var vs = (val == null) ? 'null' : ('' + val);
      if (vs.length > 4000) vs = vs.slice(0, 4000) + '…(截断)';
      console.log('[' + tag + '] ' + op + ' key=' + k + '  val=' + vs);
      // base_url / host / agent 类直接点名，方便回灌溯源
      var lk = lc(k);
      if (lk.indexOf('url') !== -1 || lk.indexOf('host') !== -1 || lk.indexOf('server') !== -1 ||
          lk.indexOf('domain') !== -1 || lk.indexOf('api') !== -1 || lk.indexOf('endpoint') !== -1 ||
          lk.indexOf('line') !== -1 || lk.indexOf('cdn') !== -1 || lk.indexOf('oss') !== -1) {
        console.log('[' + tag + '][LEAD->后端] ' + k + ' = ' + vs);
      }
      if (lk.indexOf('agent') !== -1 || lk.indexOf('csbid') !== -1 || lk.indexOf('bid') !== -1 ||
          lk.indexOf('eid') !== -1 || lk.indexOf('uid') !== -1 || lk.indexOf('group') !== -1 ||
          lk.indexOf('merchant') !== -1 || lk.indexOf('tenant') !== -1 || lk.indexOf('channel') !== -1) {
        console.log('[' + tag + '][LEAD->租户/坐席] ' + k + ' = ' + vs);
      }
      if (lk.indexOf('token') !== -1 || lk.indexOf('cookie') !== -1 || lk.indexOf('session') !== -1 ||
          lk.indexOf('auth') !== -1 || lk.indexOf('jwt') !== -1) {
        console.log('[' + tag + '][LEAD->凭据] ' + k + ' = ' + vs);
      }
      // secret/appKey 类 SDK 密钥材料同属高价值凭据锚点，补 LEAD 免入库漏掉
      if (lk.indexOf('secret') !== -1 || lk.indexOf('appkey') !== -1 || lk.indexOf('app_key') !== -1) {
        console.log('[' + tag + '][LEAD->凭据] ' + k + ' = ' + vs);
      }
    } catch (e) {
      console.log('[' + tag + '] show skip: ' + e);
    }
  }

  // —— hook 标准 SharedPreferences 实现(读) ——
  try {
    var SPImpl = Java.use('android.app.SharedPreferencesImpl');

    try {
      SPImpl.getString.overload('java.lang.String', 'java.lang.String').implementation = function (key, def) {
        var r = this.getString(key, def);
        show('prefs', 'getString', key, r);
        return r;
      };
    } catch (e) { console.log('[prefs] getString skip: ' + e); }
    try {
      SPImpl.getStringSet.overload('java.lang.String', 'java.util.Set').implementation = function (key, def) {
        var r = this.getStringSet(key, def);
        show('prefs', 'getStringSet', key, r);
        return r;
      };
    } catch (e) { console.log('[prefs] getStringSet skip: ' + e); }

    // getAll：一次性把整个 prefs 文件倒出来——冷启动后最值钱
    try {
      SPImpl.getAll.implementation = function () {
        var r = this.getAll();
        try {
          var it = r.entrySet().iterator();
          console.log('[prefs] ===== getAll dump 开始 =====');
          while (it.hasNext()) {
            var ent = Java.cast(it.next(), Java.use('java.util.Map$Entry'));
            show('prefs', 'getAll', ent.getKey(), ent.getValue());
          }
          console.log('[prefs] ===== getAll dump 结束 =====');
        } catch (e) { console.log('[prefs] getAll dump skip: ' + e); }
        return r;
      };
    } catch (e) { console.log('[prefs] getAll hook skip: ' + e); }
  } catch (e) {
    console.log('[prefs] SharedPreferencesImpl(读) hook skip: ' + e);
  }

  // —— hook Editor(写)：很多真后端是写入瞬间才第一次出现 ——
  // EditorImpl 是 SharedPreferencesImpl 的内部类，Frida 用 $ 连接：android.app.SharedPreferencesImpl$EditorImpl
  try {
    var EditorImpl = Java.use('android.app.SharedPreferencesImpl$EditorImpl');

    try {
      EditorImpl.putString.overload('java.lang.String', 'java.lang.String').implementation = function (key, val) {
        show('prefs', 'putString', key, val);
        return this.putString(key, val);
      };
    } catch (e) { console.log('[prefs] putString skip: ' + e); }
    try {
      EditorImpl.putStringSet.overload('java.lang.String', 'java.util.Set').implementation = function (key, val) {
        show('prefs', 'putStringSet', key, val);
        return this.putStringSet(key, val);
      };
    } catch (e) { console.log('[prefs] putStringSet skip: ' + e); }
  } catch (e) {
    console.log('[prefs] EditorImpl(写) hook skip: ' + e);
  }

  // —— 兜底：MMKV 等非标准存储 ——
  // 很多目标 app 用 MMKV 存配置，标准 SP hook 一片空白时看这里。
  // 关键修正：MMKV 真实公开方法是 decodeString(1/2参) / getString(SharedPreferences适配) 读；
  //          encode(String,String) / putString(String,String[,int]) 写。
  //          没有公开的 encodeString(String,String)——java 层 encodeString 是 private native(long,String,String)，hook 不到也无业务意义，本版不挂。
  (function hookMMKV() {
    var MMKV;
    try {
      MMKV = Java.use('com.tencent.mmkv.MMKV');
    } catch (e) {
      console.log('[mmkv] 未发现 MMKV(没用或类名不同)：' + e + '  →下一步:frida 里 Java.enumerateLoadedClasses 搜 MMKV/Prefs/DataStore 换 hook 点');
      return;
    }

    // —— 读：decodeString(String,String) ——
    try {
      MMKV.decodeString.overload('java.lang.String', 'java.lang.String').implementation = function (key, def) {
        var r = this.decodeString(key, def);
        show('mmkv', 'decodeString', key, r);
        return r;
      };
    } catch (e) { console.log('[mmkv] decodeString(2) skip: ' + e); }
    // —— 读：decodeString(String) ——
    try {
      MMKV.decodeString.overload('java.lang.String').implementation = function (key) {
        var r = this.decodeString(key);
        show('mmkv', 'decodeString', key, r);
        return r;
      };
    } catch (e) { console.log('[mmkv] decodeString(1) skip: ' + e); }
    // —— 读：getString(String,String)（MMKV 实现了 SharedPreferences，很多代码走这条）——
    try {
      MMKV.getString.overload('java.lang.String', 'java.lang.String').implementation = function (key, def) {
        var r = this.getString(key, def);
        show('mmkv', 'getString', key, r);
        return r;
      };
    } catch (e) { console.log('[mmkv] getString skip: ' + e); }

    // —— 写：encode(String,String)（核心写入口）——
    try {
      MMKV.encode.overload('java.lang.String', 'java.lang.String').implementation = function (key, val) {
        show('mmkv', 'encode', key, val);
        return this.encode(key, val);
      };
    } catch (e) { console.log('[mmkv] encode(String,String) skip: ' + e); }
    // —— 写：encode(String,String,int) 带过期时间 ——
    try {
      MMKV.encode.overload('java.lang.String', 'java.lang.String', 'int').implementation = function (key, val, exp) {
        show('mmkv', 'encode(exp)', key, val);
        return this.encode(key, val, exp);
      };
    } catch (e) { /* 老版本无此 overload，忽略 */ }
    // —— 写：putString(String,String)（SharedPreferences.Editor 适配路径）——
    try {
      MMKV.putString.overload('java.lang.String', 'java.lang.String').implementation = function (key, val) {
        show('mmkv', 'putString', key, val);
        return this.putString(key, val);
      };
    } catch (e) { console.log('[mmkv] putString skip: ' + e); }

    console.log('[mmkv] MMKV hook 已挂上(读 decodeString/getString，写 encode/putString)');
  })();

  console.log('[prefs] sharedprefs-hook 就绪：触发首屏/拉配置/进客服，看 [prefs]/[mmkv] 与 [LEAD->*]。若全程无输出→可能用 native/DataStore 存储，按注释换 hook 点');
});
