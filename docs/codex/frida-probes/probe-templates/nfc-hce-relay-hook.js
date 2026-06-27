// nfc-hce-relay-hook.js — 固证 NFC 卡中继盗刷(Ghost Tap/NGate)：抓 IsoDep/HCE 的 APDU 交互
// 适用：NFC 中继类涉诈(把受害人银行卡 APDU 转发到远端 POS)。纯只读检测：只记录 APDU 报文，不发送/不中继/不改写。
// 跑：frida -U -l nfc-hce-relay-hook.js -F  （NFC tap 时相关类才加载，建议贴卡那一刻 attach/已运行后注入）
// 改：HostApduService 的 processCommandApdu 在 app 子类→脚本 enumerateLoadedClasses 找子类挂
'use strict';

function b2hex(b) { try { if (!b) return ''; var o = ''; for (var i = 0; i < b.length; i++) o += ('0' + (b[i] & 0xff).toString(16)).slice(-2); return o.toUpperCase(); } catch (e) { return '<hex err>'; } }
// APDU 浅解读：抓 SELECT AID（00 A4 04 00 Lc AID）= 卡应用标识，可关联卡组织/发卡行
function readApdu(hex) {
  try {
    if (!hex || hex.length < 8) return '';
    var ins = hex.substr(2, 2), p1 = hex.substr(4, 2);
    if (ins === 'A4' && p1 === '04') {
      var lc = parseInt(hex.substr(8, 2), 16);
      var aid = hex.substr(10, lc * 2);
      return '  [LEAD-定人] SELECT AID=' + aid + '（卡应用标识→关联卡组织/发卡行；A000000003=Visa A000000004=MasterCard A000000333=银联）';
    }
    if (ins === 'B2' || ins === 'B0') return '  [READ RECORD/BINARY → 读卡数据(可能含 PAN/磁道)]';
    return '';
  } catch (e) { return ''; }
}
function stack() { try { return Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new()); } catch (e) { return ''; } }

Java.perform(function () {

  // ============ A. IsoDep.transceive：读「物理卡」侧 APDU（中继的取数端）============
  try {
    var IsoDep = Java.use('android.nfc.tech.IsoDep');
    IsoDep.transceive.implementation = function (cmd) {
      var resp = null;
      try {
        var chex = b2hex(cmd);
        console.log('[nfc][LEAD-固证] IsoDep.transceive >>> ' + chex + readApdu(chex));
      } catch (e) { console.log('[nfc] transceive cmd skip: ' + e); }
      resp = this.transceive(cmd);   // 只读放行，绝不改写/拦截 APDU
      try { console.log('[nfc]   <<< ' + b2hex(resp)); } catch (e) {}
      return resp;
    };
    console.log('[nfc] IsoDep.transceive hooked');
  } catch (e) { console.log('[nfc] IsoDep hook skip: ' + e); }

  // 其它 tech 兜底（NfcA/NfcB 也有 transceive）
  ['android.nfc.tech.NfcA', 'android.nfc.tech.NfcB', 'android.nfc.tech.NfcF'].forEach(function (cn) {
    try {
      var T = Java.use(cn);
      if (!T.transceive) return;
      T.transceive.implementation = function (cmd) {
        try { console.log('[nfc][' + cn.split('.').pop() + '] >>> ' + b2hex(cmd)); } catch (e) {}
        var r = this.transceive(cmd);
        try { console.log('[nfc]   <<< ' + b2hex(r)); } catch (e) {}
        return r;
      };
    } catch (e) {}
  });

  // ============ B. HostApduService.processCommandApdu：HCE「模拟卡」侧（中继的吐数端）============
  // processCommandApdu 是抽象方法、实现在 app 子类(R8 混淆)→枚举 AccessibilityService 同理找子类
  try {
    var HceBase = Java.use('android.nfc.cardemulation.HostApduService');
    var hooked = 0;
    Java.enumerateLoadedClasses({
      onMatch: function (name) {
        try {
          if (name.indexOf('android.') === 0) return;
          var C; try { C = Java.use(name); } catch (e) { return; }
          if (!HceBase.class.isAssignableFrom(C.class)) return;
          if (!C.processCommandApdu) return;
          C.processCommandApdu.implementation = function (apdu, extras) {
            var chex = '';
            try { chex = b2hex(apdu); console.log('[nfc][HCE][LEAD-固证] processCommandApdu <<< (来自POS/读卡器) ' + chex + readApdu(chex)); } catch (e) {}
            var resp = this.processCommandApdu(apdu, extras);   // 只读放行
            try { console.log('[nfc][HCE]   >>> (回给POS) ' + b2hex(resp)); } catch (e) {}
            return resp;
          };
          hooked++;
        } catch (e) {}
      },
      onComplete: function () {
        console.log(hooked > 0 ? '[nfc] HostApduService 子类 hooked (' + hooked + ')'
                               : '[nfc] 未找到 HCE 子类 — NFC tap 时该类才加载：贴卡那刻再注入，或 jadx 找 HostApduService 子类手挂');
      }
    });
  } catch (e) { console.log('[nfc] HCE 枚举 skip: ' + e); }

  console.log('[nfc] 已就绪：抓 IsoDep/HCE 的 APDU 交互(中继盗刷取数/吐数两端)。SELECT AID→卡组织/发卡行(定人)；纯只读不中继。');
  console.log('[nfc] 抓不到→未发生 NFC 交互或走 native libnfc：贴卡触发后看日志，或配 native-loadlib 找 nfc so。');
});
