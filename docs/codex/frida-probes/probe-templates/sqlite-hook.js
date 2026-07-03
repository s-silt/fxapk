// sqlite-hook.js — hook SQLite/SQLCipher 读写，抓聊天/交易落库明文 + 抠 SQLCipher 解库密钥(含 char[]/byte[] key)
// 适用：聊天/交易不在流量里(写了本地库，常 SQLCipher 加密) / 要固定聊天内容、敏感个人信息(PII)、资金流水作物证 / 顺手拿解库 key
// 跑：frida -U -f <包名> -l sqlite-hook.js -q
// 改：明文库=android.database.sqlite.SQLiteDatabase；加密库=net.sqlcipher.database.SQLiteDatabase(两套都挂)；密钥点在 openOrCreateDatabase/changePassword/rawExecSQL PRAGMA key

Java.perform(function () {
  'use strict';

  var TABLE_HINTS = ['msg', 'message', 'chat', 'im', 'conversation', 'session', 'contact', 'friend',
                     'user', 'order', 'trade', 'pay', 'bill', 'record', 'transfer', 'account', 'wallet'];

  function preview(s, n) {
    try {
      var t = '' + s;
      return t.length > (n || 3000) ? t.slice(0, n || 3000) + '…(截断)' : t;
    } catch (e) { return '<unprintable>'; }
  }

  function looksHotTable(sql) {
    try {
      var s = ('' + sql).toLowerCase();
      for (var i = 0; i < TABLE_HINTS.length; i++) if (s.indexOf(TABLE_HINTS[i]) !== -1) return true;
      return false;
    } catch (e) { return false; }
  }

  function dumpArgs(args) {
    try {
      if (args == null) return '';
      var out = [];
      var n = args.length;
      for (var i = 0; i < n; i++) out.push(args[i] == null ? 'null' : ('' + args[i]));
      return '  args=[' + out.join(', ') + ']';
    } catch (e) { return ''; }
  }

  function logSql(tag, op, sql, args) {
    try {
      var hot = looksHotTable(sql);
      console.log('[' + tag + ']' + (hot ? '[LEAD->聊天/交易物证]' : '') + ' ' + op + ': ' + preview(sql) + dumpArgs(args));
    } catch (e) { console.log('[' + tag + '] logSql skip: ' + e); }
  }

  // —— 把一个可能是 String / char[] / byte[] 的密码参数安全转成可读字符串 ——
  // 这是密钥提取的关键：char[]/byte[] 直接 '+' 拼接得到的是 [C@.. / [B@.. 垃圾，必须逐元素解码
  function decodePassword(a) {
    try {
      if (a == null) return 'null';
      var cls = '';
      try { cls = a.$className || ''; } catch (e) {}
      if (cls === '[C' || cls === '[B') {
        // char[]：元素是 char code；byte[]：元素是有符号字节
        var chars = [];
        var hex = [];
        for (var i = 0; i < a.length; i++) {
          var v = a[i];
          var code = (v < 0) ? (v + 256) : v; // byte 负值修正
          chars.push(String.fromCharCode(code & 0xff));
          var h = (code & 0xff).toString(16);
          hex.push(h.length === 1 ? '0' + h : h);
        }
        return chars.join('') + '  (hex=' + hex.join('') + ')';
      }
      return '' + a;
    } catch (e) {
      try { return '' + a; } catch (e2) { return '<unprintable password>'; }
    }
  }

  // —— 通用：给某个 SQLiteDatabase 类挂读写 hook，tag 区分明文/加密 ——
  function hookDb(className, tag) {
    var DB;
    try {
      DB = Java.use(className);
    } catch (e) {
      console.log('[' + tag + '] 未发现 ' + className + '(没用或类名不同): ' + e);
      return;
    }

    // execSQL(String) / execSQL(String, Object[])
    try {
      DB.execSQL.overload('java.lang.String').implementation = function (sql) {
        logSql(tag, 'execSQL', sql, null);
        return this.execSQL(sql);
      };
    } catch (e) { console.log('[' + tag + '] execSQL(1) skip: ' + e); }
    try {
      DB.execSQL.overload('java.lang.String', '[Ljava.lang.Object;').implementation = function (sql, a) {
        logSql(tag, 'execSQL', sql, a);
        return this.execSQL(sql, a);
      };
    } catch (e) { console.log('[' + tag + '] execSQL(2) skip: ' + e); }

    // rawQuery(String, String[]) —— 读聊天/交易最常走这条
    try {
      DB.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function (sql, a) {
        logSql(tag, 'rawQuery', sql, a);
        return this.rawQuery(sql, a);
      };
    } catch (e) { console.log('[' + tag + '] rawQuery(String[]) skip: ' + e); }
    // rawQuery(String, Object[]) —— SQLCipher 有这个 overload，框架库一般没有，挂不上就 skip
    try {
      DB.rawQuery.overload('java.lang.String', '[Ljava.lang.Object;').implementation = function (sql, a) {
        logSql(tag, 'rawQuery', sql, a);
        return this.rawQuery(sql, a);
      };
    } catch (e) { /* 框架库无此 overload，正常 */ }

    // query(table, columns, selection, selectionArgs, groupBy, having, orderBy) —— 7参，明文与SQLCipher均有
    try {
      DB.query.overload('java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;',
                        'java.lang.String', 'java.lang.String', 'java.lang.String').implementation =
        function (table, cols, sel, selArgs, groupBy, having, orderBy) {
          try {
            var hot = looksHotTable(table);
            console.log('[' + tag + ']' + (hot ? '[LEAD->聊天/交易物证]' : '') +
              ' query table=' + table + ' where=' + preview(sel, 500) + dumpArgs(selArgs));
          } catch (e) { console.log('[' + tag + '] query log skip: ' + e); }
          return this.query(table, cols, sel, selArgs, groupBy, having, orderBy);
        };
    } catch (e) { console.log('[' + tag + '] query(7) skip: ' + e); }

    // insert(table, nullColHack, ContentValues) —— 写入瞬间拿到落库明文
    try {
      DB.insert.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues').implementation =
        function (table, hack, values) {
          try {
            var hot = looksHotTable(table);
            console.log('[' + tag + ']' + (hot ? '[LEAD->聊天/交易物证]' : '') +
              ' insert table=' + table + ' values=' + preview(values, 3000));
          } catch (e) { console.log('[' + tag + '] insert log skip: ' + e); }
          return this.insert(table, hack, values);
        };
    } catch (e) { console.log('[' + tag + '] insert skip: ' + e); }

    console.log('[' + tag + '] ' + className + ' 读写 hook 已挂上');
  }

  // 明文库
  hookDb('android.database.sqlite.SQLiteDatabase', 'sqlite');
  // SQLCipher 库(类名同名但包不同！)
  hookDb('net.sqlcipher.database.SQLiteDatabase', 'sqlcipher');

  // —— SQLCipher 解库密钥：这是把加密库变可导出明文的关键 ——
  (function hookSqlcipherKey() {
    var SC;
    try {
      SC = Java.use('net.sqlcipher.database.SQLiteDatabase');
    } catch (e) {
      console.log('[sqlcipher][key] 未发现 SQLCipher(没用或换了库): ' + e + '  →若聊天库打不开，frida 搜 sqlcipher/wcdb/PRAGMA 换 hook 点');
      return;
    }

    // openOrCreateDatabase(...) 是静态方法，各 overload 的 password 参数 = 解库 key（String / char[] / byte[]）
    // 路径参数可能是 String 或 java.io.File
    try {
      SC.openOrCreateDatabase.overloads.forEach(function (ov) {
        try {
          ov.implementation = function () {
            try {
              for (var i = 0; i < arguments.length; i++) {
                var a = arguments[i];
                if (a == null) continue;
                var cls = '';
                try { cls = a.$className || ''; } catch (e) {}
                // 路径：java.io.File
                if (cls === 'java.io.File') {
                  try { console.log('[sqlcipher][key] db路径(File) arg' + i + '=' + a.getAbsolutePath()); }
                  catch (e2) { console.log('[sqlcipher][key] db路径(File) arg' + i + '=' + a); }
                  continue;
                }
                // 路径：String(含 .db /) 或 String 密码
                if (cls === 'java.lang.String') {
                  var t = '' + a;
                  if (t.indexOf('.db') !== -1 || t.indexOf('/') !== -1) {
                    console.log('[sqlcipher][key] db路径 arg' + i + '=' + t);
                  } else if (t.length > 0 && t.length < 256) {
                    console.log('[sqlcipher][key][LEAD->解库密钥] openOrCreateDatabase password(String) arg' + i + '=' + t);
                  }
                  continue;
                }
                // char[] / byte[] 密码：必须解码，否则只拿到 [C@ 垃圾
                if (cls === '[C' || cls === '[B') {
                  console.log('[sqlcipher][key][LEAD->解库密钥] openOrCreateDatabase password(' + cls + ') arg' + i + '=' + decodePassword(a));
                  continue;
                }
              }
            } catch (e) { console.log('[sqlcipher][key] open log skip: ' + e); }
            return ov.apply(this, arguments);
          };
        } catch (e) { console.log('[sqlcipher][key] open overload skip: ' + e); }
      });
    } catch (e) { console.log('[sqlcipher][key] openOrCreateDatabase skip: ' + e); }

    // changePassword(String) —— 改密时也能拿到新 key
    try {
      SC.changePassword.overload('java.lang.String').implementation = function (k) {
        console.log('[sqlcipher][key][LEAD->解库密钥] changePassword(String) key=' + k);
        return this.changePassword(k);
      };
    } catch (e) { console.log('[sqlcipher][key] changePassword(String) skip: ' + e); }
    // changePassword(char[]) —— SQLCipher 同时有 char[] overload，很多库用 char[] 持密
    try {
      SC.changePassword.overload('[C').implementation = function (k) {
        console.log('[sqlcipher][key][LEAD->解库密钥] changePassword(char[]) key=' + decodePassword(k));
        return this.changePassword(k);
      };
    } catch (e) { console.log('[sqlcipher][key] changePassword(char[]) skip: ' + e); }

    // rawExecSQL('PRAGMA key=...') / rawExecSQL('PRAGMA rekey=...') —— 有些库用裸 PRAGMA 设 key
    try {
      SC.rawExecSQL.overload('java.lang.String').implementation = function (sql) {
        try {
          var s = '' + sql;
          var ls = s.toLowerCase();
          if (ls.indexOf('pragma') !== -1 && (ls.indexOf('key') !== -1 || ls.indexOf('rekey') !== -1)) {
            console.log('[sqlcipher][key][LEAD->解库密钥] rawExecSQL ' + s);
          } else {
            console.log('[sqlcipher] rawExecSQL ' + preview(s, 500));
          }
        } catch (e) { console.log('[sqlcipher][key] rawExecSQL log skip: ' + e); }
        return this.rawExecSQL(sql);
      };
    } catch (e) { console.log('[sqlcipher][key] rawExecSQL skip: ' + e); }

    console.log('[sqlcipher][key] 密钥 hook 已挂上：触发进聊天/客服，拿到 key 后 adb pull 该 .db 离线解(注意 v3=64000 / v4=256000 KDF，版本对不上解库会失败)');
  })();

  console.log('[sqlite] sqlite-hook 就绪：进会话/客服/订单页触发落库。无 [sqlite]/[sqlcipher] 输出→可能用 WCDB/Realm/ObjectBox/MMKV 或纯 native，按注释换 hook 点');
});
