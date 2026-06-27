// cipher-hook.js — 抓应用层加解密明文 + AES key/iv（= 运行时 crypto_recipe）
// 适用：抓到 HTTPS 但请求体密文/乱码（CryptoJS/AES {data,timestamp} 信封）
// 跑：frida -U -f <包名> -l cipher-hook.js -q
// 改：自研加密函数名不同时改 Cipher 之外的目标类；CryptoJS 在 WebView 内则配 webview-hook.js
Java.perform(function () {
  var JString = Java.use('java.lang.String');
  function hex(b) { if (!b) return ''; var s = ''; for (var i = 0; i < b.length; i++) s += ('0' + (b[i] & 0xff).toString(16)).slice(-2); return s; }
  function b64(b) { try { return Java.use('android.util.Base64').encodeToString(b, 2); } catch (e) { return ''; } } // 2 = NO_WRAP
  function txt(b) { try { return JString.$new(b, 'UTF-8'); } catch (e) { return ''; } }
  function dump(tag, b) {
    if (!b || b.length === undefined) return;
    var t = txt(b);
    console.log('[' + tag + '] len=' + b.length + ' hex=' + hex(b) + (t ? (' utf8=' + t) : '') + ' b64=' + b64(b));
  }
  function sliceJ(b, off, len) { // 从 java byte[] 截 off..off+len，返回 JS 数组（仅供 hex；txt/b64 会优雅失败）
    try { var r = []; for (var i = 0; i < len; i++) r.push(b[off + i]); return r; } catch (e) { return b; }
  }

  var Cipher = Java.use('javax.crypto.Cipher');

  // 算法/模式/padding
  try { Cipher.getInstance.overload('java.lang.String').implementation = function (t) { console.log('[cipher] getInstance ' + t); return this.getInstance(t); }; } catch (e) {}

  // init：抓 opmode(1=ENCRYPT 2=DECRYPT) 标方向；从 Key dump key 字节
  Cipher.init.overloads.forEach(function (ov) {
    ov.implementation = function () {
      try {
        var mode = arguments[0];
        this._fxDir = (mode === 1 ? 'ENC' : mode === 2 ? 'DEC' : ('m' + mode));
        if (arguments.length > 1 && arguments[1]) {
          var key = arguments[1];
          try {
            var enc = key.getEncoded();
            if (enc) { console.log('[key@init ' + this._fxDir + ']'); dump('key', enc); }
            else {
              // 托管密钥（AndroidKeyStore RSA/EC）导不出字节，价值在 alias —— 持 alias 可查密钥用途/审计
              var alias = '';
              try { alias = key.getKeystoreAlias ? key.getKeystoreAlias() : ''; } catch (e) {}
              if (!alias) { try { alias = '' + key.getClass().getName(); } catch (e) {} }
              console.log('[key@init ' + this._fxDir + '] 托管密钥(不可导出) alias/类=' + alias);
            }
          } catch (e) {}
        }
      } catch (e) {}
      return ov.apply(this, arguments);
    };
  });

  // doFinal / update 全重载：按 offset/len 切片，标方向
  ['doFinal', 'update'].forEach(function (m) {
    Cipher[m].overloads.forEach(function (ov) {
      ov.implementation = function () {
        var ret = ov.apply(this, arguments);
        try {
          var dir = this._fxDir || '?';
          var inb = null;
          if (arguments.length >= 3 && typeof arguments[1] === 'number' && typeof arguments[2] === 'number')
            inb = sliceJ(arguments[0], arguments[1], arguments[2]);            // (byte[] in, int off, int len[, ...])
          else if (arguments.length >= 1 && arguments[0] && arguments[0].length !== undefined)
            inb = arguments[0];                                               // (byte[] in)
          if (inb !== null) dump('cipher.' + m + '.IN[' + dir + ']', inb);
          if (ret && ret.length !== undefined) dump('cipher.' + m + '.OUT[' + dir + ']', ret);
        } catch (e) {}
        return ret;
      };
    });
  });
  console.log('[cipher] Cipher init/doFinal/update hooked');

  // updateAAD —— GCM/CCM 的附加认证数据（离线复现解密需要）
  try {
    Cipher.updateAAD.overloads.forEach(function (ov) {
      ov.implementation = function () {
        try {
          if (arguments.length >= 3 && typeof arguments[1] === 'number') dump('cipher.AAD', sliceJ(arguments[0], arguments[1], arguments[2]));
          else if (arguments[0] && arguments[0].length !== undefined) dump('cipher.AAD', arguments[0]);
        } catch (e) {}
        return ov.apply(this, arguments);
      };
    });
  } catch (e) {}

  // GCMParameterSpec —— iv + tagLen（GCM 离线解密必需）
  try {
    var GCM = Java.use('javax.crypto.spec.GCMParameterSpec');
    GCM.$init.overload('int', '[B').implementation = function (t, iv) { console.log('[iv] GCM tagLen=' + t + ' bit'); dump('iv', iv); return this.$init(t, iv); };
    try { GCM.$init.overload('int', '[B', 'int', 'int').implementation = function (t, iv, o, l) { console.log('[iv] GCM tagLen=' + t + ' bit'); dump('iv', sliceJ(iv, o, l)); return this.$init(t, iv, o, l); }; } catch (e) {}
  } catch (e) {}

  // SecretKeySpec 两个重载
  var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
  SKS.$init.overload('[B', 'java.lang.String').implementation = function (k, a) { console.log('[key] SecretKeySpec alg=' + a); dump('key', k); return this.$init(k, a); };
  try { SKS.$init.overload('[B', 'int', 'int', 'java.lang.String').implementation = function (k, o, l, a) { console.log('[key] SecretKeySpec(off) alg=' + a); dump('key', sliceJ(k, o, l)); return this.$init(k, o, l, a); }; } catch (e) {}

  // IvParameterSpec 两个重载
  var IPS = Java.use('javax.crypto.spec.IvParameterSpec');
  IPS.$init.overload('[B').implementation = function (iv) { dump('iv', iv); return this.$init(iv); };
  try { IPS.$init.overload('[B', 'int', 'int').implementation = function (iv, o, l) { dump('iv', sliceJ(iv, o, l)); return this.$init(iv, o, l); }; } catch (e) {}
});
