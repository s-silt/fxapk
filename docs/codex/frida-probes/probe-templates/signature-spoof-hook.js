// signature-spoof-hook.js — 配合 repackage 使用：让目标样本查自己签名/包信息时看到与重打包前一致的值。
// 适用：repackage（去壳重打包重签名）后样本自校验签名一致性（PackageManager.getPackageInfo /
//       SigningInfo / checkSignatures）而拒绝正常运行/自毁/改变行为，导致重打包后无法继续动态分析。
// 跑：frida -U -f <包名> -l anti-detection-hook.js -l signature-spoof-hook.js -l <业务探针>.js -o probe.log -q
// 改：ORIGINAL_SIGNATURE_HEX 现场填「重打包前」原始 APK 的签名证书 DER 字节 hex——
//     `keytool -printcert -jarfile original.apk` 看 SHA-256 之余，或用
//     `apksigner verify --print-certs original.apk` / fxapk report 的 certificate 分析结果对应样本
//     里能拿到证书文件路径后 `openssl x509 -inform DER -in cert.rsa -outform DER | xxd -p | tr -d '\n'`。
//     **为空则只记录检测到的查询、不做任何伪造**（安全默认，跟 tenant-enum-helper.js 的
//     TENANT_LIST 默认空同一原则——不误导使用者以为"装好脚本就自动生效"）。
'use strict';

var ORIGINAL_SIGNATURE_HEX = ''; // 例如 '308203a1...'（原始未重打包 APK 的签名证书 DER hex，现场必填才生效）

function hexToJavaByteArray(hex) {
  var arr = [];
  for (var i = 0; i < hex.length; i += 2) {
    var b = parseInt(hex.substr(i, 2), 16);
    if (b > 127) b -= 256; // Java byte 有符号（-128~127），十六进制高位需转补码
    arr.push(b);
  }
  return Java.array('byte', arr);
}

Java.perform(function () {
  function rep(what) { try { console.log('[sigspoof] ' + what); } catch (e) {} }

  var configured = !!ORIGINAL_SIGNATURE_HEX;
  if (!configured) {
    rep('ORIGINAL_SIGNATURE_HEX 未配置——仅记录探针检测到的签名查询点，不做任何伪造回填。');
  }

  var selfPkg = '';
  try { selfPkg = '' + Java.use('android.app.ActivityThread').currentApplication().getPackageName(); } catch (e) {}

  var spoofedSig = null;
  function getSpoofedSignature() {
    if (spoofedSig === null && configured) {
      try {
        var Signature = Java.use('android.content.pm.Signature');
        spoofedSig = Signature.$new(hexToJavaByteArray(ORIGINAL_SIGNATURE_HEX));
      } catch (e) { rep('构造 Signature 失败（ORIGINAL_SIGNATURE_HEX 格式不对？）: ' + e); }
    }
    return spoofedSig;
  }

  // --- 旧 API：getPackageInfo(pkg, GET_SIGNATURES=0x40) → PackageInfo.signatures ---
  try {
    var PM = Java.use('android.app.ApplicationPackageManager');
    var GET_SIGNATURES = 0x40;
    PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
      var info = this.getPackageInfo(pkg, flags);
      try {
        if (pkg === selfPkg && (flags & GET_SIGNATURES) !== 0) {
          var sig = getSpoofedSignature();
          if (sig) {
            rep('拦截 getPackageInfo(GET_SIGNATURES) for ' + pkg + ' → 回填原始签名');
            info.signatures.value = Java.array('android.content.pm.Signature', [sig]);
          } else {
            rep('检测到 getPackageInfo(GET_SIGNATURES) for ' + pkg + '（未配置回填值，原样放行）');
          }
        }
      } catch (e) { rep('回填 GET_SIGNATURES 处理 skip: ' + e); }
      return info;
    };
    console.log('[sigspoof] getPackageInfo(GET_SIGNATURES) hooked');
  } catch (e) { console.log('[sigspoof] getPackageInfo(GET_SIGNATURES) skip: ' + e); }

  // --- 新 API（API 28+）：SigningInfo.getApkContentsSigners / getSigningCertificateHistory ---
  try {
    var SI = Java.use('android.content.pm.SigningInfo');
    ['getApkContentsSigners', 'getSigningCertificateHistory'].forEach(function (mn) {
      try {
        if (!SI[mn]) return;
        SI[mn].implementation = function () {
          var sig = getSpoofedSignature();
          if (!sig) { rep('检测到 SigningInfo.' + mn + '()（未配置回填值，原样放行）'); return this[mn](); }
          rep('拦截 SigningInfo.' + mn + '() → 回填原始签名');
          return Java.array('android.content.pm.Signature', [sig]);
        };
      } catch (e) {}
    });
    console.log('[sigspoof] SigningInfo hooked');
  } catch (e) { console.log('[sigspoof] SigningInfo skip: ' + e); }

  // --- PackageManager.checkSignatures(selfPkg, selfPkg) → 强制 SIGNATURE_MATCH(0) ---
  try {
    var PM2 = Java.use('android.app.ApplicationPackageManager');
    PM2.checkSignatures.overload('java.lang.String', 'java.lang.String').implementation = function (p1, p2) {
      if (configured && p1 === p2 && p1 === selfPkg) {
        rep('checkSignatures(' + p1 + ', ' + p2 + ') → 强制返回 SIGNATURE_MATCH');
        return 0;
      }
      if (p1 === p2 && p1 === selfPkg) { rep('检测到 checkSignatures(' + p1 + ', ' + p2 + ')（未配置回填值，原样放行）'); }
      return this.checkSignatures(p1, p2);
    };
    console.log('[sigspoof] checkSignatures hooked');
  } catch (e) { console.log('[sigspoof] checkSignatures skip: ' + e); }

  console.log(
    '[sigspoof] 已就绪（' + (configured ? '回填模式' : '仅观测模式，填 ORIGINAL_SIGNATURE_HEX 才生效') +
    '）：配合 repackage 场景使用，让重打包后的签名自校验查询结果与原始一致。'
  );
});
