// keystore-alias-tracer-hook.js — 列 AndroidKeyStore 每个 key 的安全级别+用途，裁决「key 能否拷走脱机解密证据」
// 适用：样本用 AndroidKeyStore 托管密钥加密聊天/转账/配置。判定 key 在软件层(可拷)还是 TEE/StrongBox(不可导出)→决定脱机解密还是在机解密路线。纯只读枚举，不导出/不改密钥。
// 跑：frida -U -f <包名> -l keystore-alias-tracer-hook.js -q  （key 多在用到时才生成→跑起来后在 REPL 调 fxKeystoreScan() 重扫）
// 改：默认扫 "AndroidKeyStore"；新 key 创建参数由 KeyGenParameterSpec$Builder hook 抓
'use strict';

// KeyProperties 常量（用途位 / 安全级别），避免依赖目标加载顺序
var PURPOSE = [[1, 'ENCRYPT'], [2, 'DECRYPT'], [4, 'SIGN'], [8, 'VERIFY'], [16, 'DERIVE_KEY'], [32, 'WRAP_KEY'], [64, 'AGREE_KEY'], [128, 'ATTEST_KEY']];
var SECLEVEL = { '-2': 'UNKNOWN_SECURE', '-1': 'UNKNOWN', '0': '软件(可拷走→脱机解密)', '1': 'TEE可信环境(不可导出)', '2': 'StrongBox安全芯片(不可导出)' };

function purposesStr(bits) { var o = []; for (var i = 0; i < PURPOSE.length; i++) if (bits & PURPOSE[i][0]) o.push(PURPOSE[i][1]); return o.join('|') || ('0x' + bits.toString(16)); }

function dumpKeyInfo(alias, info, kind, alg) {
  try {
    var sl = null, hw = null, purp = null, keysize = null;
    try { sl = info.getSecurityLevel(); } catch (e) {}                 // API31+
    try { hw = info.isInsideSecureHardware(); } catch (e) {}           // API23+(deprecated)
    try { purp = info.getPurposes(); } catch (e) {}
    try { keysize = info.getKeySize(); } catch (e) {}
    var slStr = (sl !== null) ? (SECLEVEL['' + sl] || ('lvl' + sl)) : (hw === true ? '硬件(TEE/SB，不可导出)' : (hw === false ? '软件(可拷走→脱机解密)' : '未知'));
    var extractable = (sl === 0) || (sl === null && hw === false);
    console.log('[ks][' + (extractable ? 'LEAD-固证:可拷脱机解密' : '硬件key:走在机解密链') + '] alias="' + alias + '" 类型=' + kind + ' 算法=' + alg + ' 位数=' + keysize +
                ' 安全级别=' + slStr + ' 用途=' + (purp !== null ? purposesStr(purp) : '?'));
    if (extractable) console.log('[ks]   ★软件级对称 key → 配 cipher-hook.js dump 明文，或导出 key 脱机解 OSS/库证据。');
  } catch (e) { console.log('[ks] dumpKeyInfo skip(' + alias + '): ' + e); }
}

function scanKeystore() {
  console.log('\n========== [ks] 枚举 AndroidKeyStore ==========');
  try {
    var KeyStore = Java.use('java.security.KeyStore');
    var ks = KeyStore.getInstance('AndroidKeyStore');
    ks.load(null);
    var aliasesEnum = ks.aliases();
    var n = 0;
    while (aliasesEnum.hasMoreElements()) {
      var alias = '' + aliasesEnum.nextElement();
      n++;
      try {
        var key = ks.getKey(alias, null);
        if (key === null) { console.log('[ks] alias="' + alias + '" getKey=null(可能是证书项)'); continue; }
        var alg = '' + key.getAlgorithm();
        var clsName = '' + key.getClass().getName();
        // 对称(SecretKey) vs 非对称(PrivateKey)走不同 KeyFactory 取 KeyInfo
        var info = null, kind = '?';
        try {
          if (clsName.toLowerCase().indexOf('private') >= 0 || alg === 'EC' || alg === 'RSA') {
            kind = '非对称私钥';
            var KF = Java.use('java.security.KeyFactory').getInstance(alg, 'AndroidKeyStore');
            info = KF.getKeySpec(Java.cast(key, Java.use('java.security.PrivateKey')), Java.use('android.security.keystore.KeyInfo').class);
          } else {
            kind = '对称密钥';
            var SKF = Java.use('javax.crypto.SecretKeyFactory').getInstance(alg, 'AndroidKeyStore');
            info = SKF.getKeySpec(Java.cast(key, Java.use('javax.crypto.SecretKey')), Java.use('android.security.keystore.KeyInfo').class);
          }
        } catch (e) { console.log('[ks] alias="' + alias + '" 取 KeyInfo skip: ' + e); }
        if (info !== null) dumpKeyInfo(alias, Java.cast(info, Java.use('android.security.keystore.KeyInfo')), kind, alg);
        else console.log('[ks] alias="' + alias + '" 算法=' + alg + ' 类型=' + clsName + '（KeyInfo 取不到）');
      } catch (e) { console.log('[ks] alias="' + alias + '" 处理 skip: ' + e); }
    }
    if (n === 0) console.log('[ks] AndroidKeyStore 当前为空 —— key 多在用到时才生成：跑起业务后在 REPL 调 fxKeystoreScan() 重扫。');
  } catch (e) { console.log('[ks] 枚举 keystore skip: ' + e); }
  console.log('========== [ks] END ==========\n');
}

Java.perform(function () {
  // 暴露重扫
  try { globalThis.fxKeystoreScan = function () { Java.perform(scanKeystore); }; } catch (e) {}

  // 抓「新 key 创建」参数：KeyGenParameterSpec$Builder（看 setKeySize/purposes/是否要求硬件）
  try {
    var B = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
    if (B.setKeySize) B.setKeySize.implementation = function (s) { try { console.log('[ks][new] KeyGenParameterSpec.setKeySize ' + s); } catch (e) {} return this.setKeySize(s); };
    if (B.setIsStrongBoxBacked) B.setIsStrongBoxBacked.implementation = function (v) { try { console.log('[ks][new] setIsStrongBoxBacked ' + v + '（true=要求 StrongBox 芯片，key 不可导出）'); } catch (e) {} return this.setIsStrongBoxBacked(v); };
    if (B.$init) B.$init.overloads.forEach(function (ov) {
      try { ov.implementation = function () { try { if (arguments.length >= 2) console.log('[ks][new] 创建 key alias="' + arguments[0] + '" purposes=' + purposesStr(arguments[1])); } catch (e) {} return ov.apply(this, arguments); }; } catch (e) {}
    });
    console.log('[ks] KeyGenParameterSpec$Builder hooked（抓新建 key 的用途/位数/是否硬件）');
  } catch (e) { console.log('[ks] KeyGenParameterSpec hook skip: ' + e); }

  // 启动先扫一次，3s 后再扫一次（捕捉冷启动期生成的 key）
  scanKeystore();
  setTimeout(function () { Java.perform(scanKeystore); }, 3000);
  console.log('[ks] 已就绪：软件级 key=[LEAD-固证:可拷脱机解密]，硬件级=走在机解密链。纯只读枚举，不导出/不改密钥。REPL 重扫：fxKeystoreScan()');
});
