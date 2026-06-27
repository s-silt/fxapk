// telegram-mtproto-hook.js — 在 Telegram/TLRPC 层抓登录账号+聊天明文+MTProto 接入节点，不破 MTProto 加密
// 适用：杀猪盘大量 Telegram/XIN 二开改包(im.xtvslvextn.* / im.rightkinghts.messenger 等)；普通抓包 endpoint=0(MTProto 自建协议、HTTP 代理看不见)
// 跑：frida -U -f <包名> -l telegram-mtproto-hook.js -q   （改包加固时配 memdex-dump.js 先释放真实 DEX，类才挂得上）
// 改：类名被混淆/换包名→脚本自动 enumerateLoadedClasses 匹配含 ConnectionsManager/TL_auth 的真实类；命中后把 console 里打印的真实类名填进 CAND_* 数组即可稳定复跑
'use strict';

/* ============================================================
 *  对应刘超泉案：qq888999 触发 TL_auth_signIn 明文 + sendRequest，
 *  登录后设备 SYN_SENT 到 106.53.21.146:30113 / 8.148.153.143:30113。
 *  本探针只在 Java/TLRPC 对象层 + Datacenter/getCurrentAddress + native connect 抓"明文字段+接入节点"，
 *  MTProto 的加密握手一概不碰(不解密、不改包、不外联)。唯一出口 console.log。
 *
 *  对抗式核验修正记录：
 *   - bytesText() 原把 UTF-8 续字节(0x80-0xBF)判为不可打印，导致中文聊天/用户名被误杀只剩 hex；
 *     已改为 >=0x80 统计为可读，正确放行 UTF-8 多字节。
 *   - getDatacenterAddress 在原版 org.telegram.tgnet.ConnectionsManager 上并不存在(空挂会给假"就位")；
 *     现改为按方法名整表扫 getDatacenter* 与 getCurrentAddress* ，并补 Datacenter 类兜底；
 *     接入节点 IP:port 的权威来源是文件尾部 native connect 钩子。
 *   - native connect 符号解析跨 Frida 版本健壮(新版 getExportByName 找不到会抛异常而非返 null)，
 *     加 findExportByName + libc.so 整表兜底。
 * ============================================================ */

Java.perform(function () {
  var CAP = 4000;        // 总回传封顶，聊天高频时防刷爆
  var emitted = 0;
  function over() { if (emitted >= CAP) return true; emitted++; return false; }

  /* ---------- 编码工具：明文同时给 hex(+base64)，二进制不盲 UTF-8 ---------- */
  function b2hex(bytes) {
    if (!bytes) return null;
    try { var o = ''; for (var i = 0; i < bytes.length; i++) o += ('0' + (bytes[i] & 0xff).toString(16)).slice(-2); return o; }
    catch (e) { return '<hex err ' + e + '>'; }
  }
  function b2b64(bytes) {
    if (!bytes) return null;
    try { return Java.use('android.util.Base64').encodeToString(bytes, 2 /* NO_WRAP */); }
    catch (e) { return '<b64 err ' + e + '>'; }
  }
  // 可打印占比高才按 UTF-8 还原(聊天/账号多为可读)，否则只给 hex 避免乱码误导。
  // 修正：原版只把 ASCII 可见 + UTF-8 首字节(>=0xC0)记为可读，漏掉续字节(0x80-0xBF)，
  //       一个中文=1 首字节+2 续字节，旧逻辑只 ~1/3 达标→中文明文被误判二进制丢成 hex。
  //       现把 >=0x80 全记为可读(覆盖 UTF-8 全部非 ASCII 字节)，只排除 ASCII 控制字符。
  function bytesText(bytes) {
    if (!bytes) return null;
    try {
      var printable = 0, n = Math.min(bytes.length, 512);
      for (var i = 0; i < n; i++) {
        var b = bytes[i] & 0xff;
        if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127) || b >= 0x80) printable++;
      }
      if (n > 0 && printable / n > 0.85) return Java.use('java.lang.String').$new(bytes, 'UTF-8');
      return null;
    } catch (e) { return null; }
  }
  // 对一段 byte[] 统一三格输出
  function dumpBytes(tag, bytes) {
    try {
      if (!bytes || bytes.length === 0) { console.log(tag + ' <empty>'); return; }
      var t = bytesText(bytes);
      if (t !== null) console.log(tag + ' utf8=' + t);
      console.log(tag + ' hex=' + b2hex(bytes));
      console.log(tag + ' b64=' + b2b64(bytes));
    } catch (e) { console.log(tag + ' dump skip: ' + e); }
  }

  /* ---------- 类名定位：改包必混淆，先按候选名 use，命中不了就全表匹配子串 ---------- */
  // 现场把这里发现的真实类名填回来即可稳定复跑(注释见每个数组上方)
  // 原版 org.telegram.* ；二开常整体换包名(im.xtvslvextn.* / im.rightkinghts.messenger.* 等)，故只匹配类"短名/子串"
  var CAND_CM = [   // ConnectionsManager(发请求统一入口)
    'org.telegram.tgnet.ConnectionsManager'
  ];
  var CM_SUBSTR = ['ConnectionsManager'];           // 全表匹配兜底子串
  var DC_SUBSTR = ['Datacenter'];                   // DC/接入节点类兜底子串(getCurrentAddress 在这上面)
  var AUTH_SUBSTR = ['TL_auth_signIn', 'TL_auth_sentCode', 'TL_auth_signUp', 'TL_auth_signInWithPassword', 'TL_auth_checkPassword'];

  function safeUse(name) { try { return Java.use(name); } catch (e) { return null; } }

  // 用 enumerateLoadedClasses 在已载入类里按子串找真实类名(加固释放 DEX 后类才在表里)
  function findClassesBySubstr(substrs, limit) {
    var hits = [], seen = {};
    try {
      Java.enumerateLoadedClassesSync().forEach(function (cn) {
        if (hits.length >= (limit || 40)) return;
        for (var i = 0; i < substrs.length; i++) {
          if (cn.indexOf(substrs[i]) !== -1 && !seen[cn]) { seen[cn] = 1; hits.push(cn); break; }
        }
      });
    } catch (e) { console.log('[tg] enumerateLoadedClasses skip: ' + e); }
    return hits;
  }

  // 列出一个 Java.use 包装类上、可见的实例/静态方法名(用于按名字找混淆后的目标方法)
  function methodNames(C) {
    var names = [];
    try {
      // Frida 包装类把方法名挂在 .class 反射上更可靠(混淆后包装属性可能含 $ 重载占位)
      var ms = C.class.getDeclaredMethods();
      for (var i = 0; i < ms.length; i++) { try { names.push(ms[i].getName()); } catch (e) {} }
    } catch (e) {}
    return names;
  }

  /* ---------- 反射 dump 一个 TLObject 的所有字段(账号/手机号/code/password 就在里面) ---------- */
  // 不依赖具体字段名(改包会重命名)，整体反射；命中关键词的字段高亮成 [LEAD]
  var LEAD_KW = ['phone', 'username', 'user_name', 'code', 'password', 'pwd', 'hash', 'token', 'email', 'first_name', 'last_name', 'message', 'msg'];
  function isLeadField(fname) {
    var l = fname.toLowerCase();
    for (var i = 0; i < LEAD_KW.length; i++) if (l.indexOf(LEAD_KW[i]) !== -1) return true;
    return false;
  }
  function dumpTLObject(prefix, obj) {
    if (!obj) { console.log(prefix + ' <null>'); return; }
    try {
      var jcls = obj.getClass();
      var clsName = jcls.getName();
      console.log(prefix + ' class=' + clsName);
      // 逐层(含父类)取字段，改包字段散在父类里
      var seenF = {};
      var cur = jcls;
      var depth = 0;
      while (cur !== null && depth < 6) {
        var fields;
        try { fields = cur.getDeclaredFields(); } catch (e) { break; }
        for (var i = 0; i < fields.length; i++) {
          try {
            var f = fields[i];
            f.setAccessible(true);
            var fn = f.getName();
            if (seenF[fn]) continue; seenF[fn] = 1;
            var v = f.get(obj);
            var lead = isLeadField(fn) ? '[LEAD] ' : '';
            if (v === null) { continue; }
            var vs;
            try { vs = '' + v; } catch (e) { vs = '<toString err>'; }
            if (vs.length > 512) vs = vs.substring(0, 512) + '…(' + vs.length + ')';
            console.log(prefix + '   ' + lead + fn + ' = ' + vs);
          } catch (e) { /* 单字段失败不影响其它字段 */ }
        }
        try { cur = cur.getSuperclass(); } catch (e) { break; }
        depth++;
      }
    } catch (e) { console.log(prefix + ' dump skip: ' + e); }
  }

  /* ========== 1) ConnectionsManager.sendRequest —— 所有出站 TL 请求的统一入口 ========== */
  // 抓到：每个发出去的请求对象(登录/发消息/拉更新都从这过) → 调证锚点=登录账号/手机号、聊天内容
  // 注意：原版 sendRequest 第 1 参恒为 TLObject 请求体；改包可能把方法重命名/拆出 sendRequestInternal，
  //       故除 sendRequest 外，再按方法名扫含 sendRequest 的混淆变体一并挂。
  function hookOneMethodByName(C, mn, tag) {
    var hookedAny = false;
    try {
      if (!C[mn]) return false;
      var ovs = C[mn].overloads;
      ovs.forEach(function (ov) {
        try {
          ov.implementation = function () {
            try {
              if (!over()) {
                var req = arguments.length > 0 ? arguments[0] : null;
                // 仅当第 1 参看起来像 TLObject(有 getClass) 才 dump，避免把 int token 之类当对象
                if (req !== null && req !== undefined && typeof req.getClass === 'function') {
                  console.log('\n[tg][' + tag + '][LEAD->出站请求] ' + mn + ' ============================');
                  dumpTLObject('[tg][' + tag + ']', req);
                }
              }
            } catch (e) { console.log('[tg][' + tag + '] dump skip: ' + e); }
            return ov.apply(this, arguments);
          };
          hookedAny = true;
        } catch (e) { console.log('[tg][' + tag + '] 单重载 hook skip: ' + e); }
      });
      if (hookedAny) console.log('[tg] ' + tag + ' hooked: ' + mn + ' (' + ovs.length + ' overloads)');
    } catch (e) { console.log('[tg][' + tag + '] ' + mn + ' hook skip: ' + e); }
    return hookedAny;
  }
  function hookSendRequest(CM) {
    if (!CM) return false;
    var any = hookOneMethodByName(CM, 'sendRequest', 'sendRequest');
    // 混淆/拆分变体：方法名里含 sendRequest 的都挂(去掉已挂的精确名)
    try {
      var seen = { 'sendRequest': 1 };
      methodNames(CM).forEach(function (mn) {
        if (mn.toLowerCase().indexOf('sendrequest') !== -1 && !seen[mn]) {
          seen[mn] = 1;
          if (hookOneMethodByName(CM, mn, 'sendRequest*')) any = true;
        }
      });
    } catch (e) { console.log('[tg][sendRequest] 变体扫描 skip: ' + e); }
    if (!any) console.log('[tg][sendRequest][未命中] 该类无 sendRequest 可挂；接入节点改看 [tg][native] connect / [tg][DC] 行。');
    return any;
  }

  /* ========== 2) DC 接入节点 IP:port(= 30113 那类锚点) ========== */
  // 修正：原版 org.telegram.tgnet.ConnectionsManager 上并无 getDatacenterAddress 方法(原脚本空挂=假就位)。
  //       真实 DC 地址解析在 native(libtmessages.*.so) 与 Datacenter 类。这里：
  //       (a) 在 CM 上按方法名扫任何含 getDatacenter / getCurrentAddress / nativeGetDatacenter 的方法挂返回值；
  //       (b) 兜底挂 Datacenter 类的 getCurrentAddress / getCurrentPort；
  //       权威来源仍是文件尾部 native connect(任何走 socket 的真实 IP:port 都抓得到，连失败的 SYN_SENT 也算锚点)。
  function hookRetMethodByName(C, mn, tag) {
    try {
      if (!C[mn]) return;
      C[mn].overloads.forEach(function (ov) {
        try {
          ov.implementation = function () {
            var ret = ov.apply(this, arguments);
            try {
              if (!over()) {
                var argStr = '';
                try { argStr = Array.prototype.join.call(arguments, ','); } catch (e) {}
                console.log('[tg][DC][LEAD->接入节点] ' + tag + '.' + mn + '(' + argStr + ') = ' + ret);
              }
            } catch (e) {}
            return ret;
          };
        } catch (e) {}
      });
      console.log('[tg] ' + tag + '.' + mn + ' hooked (DC 接入节点)');
    } catch (e) { console.log('[tg][DC] ' + tag + '.' + mn + ' hook skip: ' + e); }
  }
  function hookDcAddress(CM) {
    var dcKw = ['getdatacenter', 'getcurrentaddress', 'getcurrentport', 'nativegetdatacenter', 'getaddress'];
    // (a) ConnectionsManager 上按名字扫(混淆后名字可能变，但子串通常保留;若全被换名则此处空，靠 native connect)
    var hitCM = false;
    if (CM) {
      try {
        methodNames(CM).forEach(function (mn) {
          var l = mn.toLowerCase();
          for (var i = 0; i < dcKw.length; i++) {
            if (l.indexOf(dcKw[i]) !== -1) { hookRetMethodByName(CM, mn, 'CM'); hitCM = true; break; }
          }
        });
      } catch (e) { console.log('[tg][DC] CM 方法扫描 skip: ' + e); }
    }
    if (!hitCM) console.log('[tg][DC] ConnectionsManager 上未发现 getDatacenter/getCurrentAddress 类方法(原版即如此/或被换名)，接入节点以 native connect 为准。');
    // (b) Datacenter 类兜底
    var dcHits = findClassesBySubstr(DC_SUBSTR, 10);
    if (dcHits.length) {
      console.log('[tg][DC] Datacenter 候选类: ' + dcHits.join(' | '));
      dcHits.forEach(function (cn) {
        var D = safeUse(cn);
        if (!D) return;
        try {
          methodNames(D).forEach(function (mn) {
            var l = mn.toLowerCase();
            if (l.indexOf('getcurrentaddress') !== -1 || l.indexOf('getcurrentport') !== -1 || l.indexOf('getaddress') !== -1) {
              hookRetMethodByName(D, mn, cn.split('.').pop());
            }
          });
        } catch (e) { console.log('[tg][DC] ' + cn + ' 方法扫描 skip: ' + e); }
      });
    }
  }

  /* ========== 3) 直接 hook 关键登录 TLObject 的 serializeToStream(更稳：不管走不走 sendRequest 都抓得到字段) ========== */
  // 改包把登录搬到 username/password(报告 checkEnterInfo) —— 反射 dump 已覆盖；这里再挂 serializeToStream
  // 抓 TL_auth_* 序列化时的真实字段(phone_number/phone_code/phone_code_hash/username/password)
  function hookAuthSerialize(clsName) {
    var C = safeUse(clsName);
    if (!C) return;
    try {
      if (!C.serializeToStream) { console.log('[tg][TL_auth] ' + clsName + ' 无 serializeToStream(可能被内联/改名)，已靠 sendRequest 覆盖'); return; }
      C.serializeToStream.overloads.forEach(function (ov) {
        try {
          ov.implementation = function (stream) {
            try {
              if (!over()) {
                console.log('\n[tg][TL_auth][LEAD->登录明文] ============================');
                dumpTLObject('[tg][' + clsName.split('.').pop() + ']', this);
              }
            } catch (e) { console.log('[tg][TL_auth] dump skip: ' + e); }
            return ov.apply(this, arguments);
          };
        } catch (e) {}
      });
      console.log('[tg] ' + clsName + '.serializeToStream hooked (登录明文)');
    } catch (e) { console.log('[tg] ' + clsName + ' serialize hook skip: ' + e); }
  }

  /* ========== 4) NativeByteBuffer dump —— TL 收发都过这个缓冲，兜底抓原始帧明文部分 ========== */
  // 注意：这里是"序列化前/反序列化后"的应用层缓冲，不是 MTProto 加密后的密文；只读不改
  function hookNativeByteBuffer() {
    // 原版类名 org.telegram.tgnet.NativeByteBuffer；改包同样可能换包名
    var cands = ['org.telegram.tgnet.NativeByteBuffer'];
    var extra = findClassesBySubstr(['NativeByteBuffer'], 5);
    extra.forEach(function (c) { if (cands.indexOf(c) === -1) cands.push(c); });
    cands.forEach(function (cn) {
      var NBB = safeUse(cn);
      if (!NBB) return;
      // writeString / writeByteArray 是把明文写进缓冲的点(账号串/消息体常走这)
      ['writeString', 'writeByteArray', 'writeByteArrayWithOffset'].forEach(function (mn) {
        try {
          if (!NBB[mn]) return;
          NBB[mn].overloads.forEach(function (ov) {
            try {
              ov.implementation = function () {
                try {
                  if (!over() && arguments.length > 0) {
                    var a0 = arguments[0];
                    if (mn === 'writeString' && a0 !== null) {
                      console.log('[tg][NBB][LEAD] writeString = ' + a0);
                    } else if (a0 !== null && typeof a0 === 'object' && a0.length !== undefined) {
                      // byte[] —— 走统一三格输出，不盲 UTF-8
                      dumpBytes('[tg][NBB][' + mn + ']', a0);
                    }
                  }
                } catch (e) { console.log('[tg][NBB] ' + mn + ' dump skip: ' + e); }
                return ov.apply(this, arguments);
              };
            } catch (e) {}
          });
        } catch (e) { console.log('[tg][NBB] ' + mn + ' hook skip: ' + e); }
      });
      console.log('[tg] NativeByteBuffer hooked @ ' + cn);
    });
  }

  /* ========== 串起来：先定位 ConnectionsManager，再挂各点 ========== */
  // 防重复挂(三次重挂 + REPL 手动重扫时，同一方法重复替换 implementation 虽不抛但会叠日志)
  var DONE = {};
  function once(key) { if (DONE[key]) return true; DONE[key] = 1; return false; }

  function locateAndHook() {
    // (a) ConnectionsManager
    var CM = null, cmName = null;
    for (var i = 0; i < CAND_CM.length; i++) { CM = safeUse(CAND_CM[i]); if (CM) { cmName = CAND_CM[i]; break; } }
    if (!CM) {
      var cmHits = findClassesBySubstr(CM_SUBSTR, 20);
      if (cmHits.length) {
        console.log('[tg] 候选 ConnectionsManager 未直接命中，全表匹配到: ' + cmHits.join(' | '));
        for (var j = 0; j < cmHits.length; j++) { CM = safeUse(cmHits[j]); if (CM) { cmName = cmHits[j]; break; } }
      }
    }
    if (CM) {
      console.log('[tg][命中] ConnectionsManager = ' + cmName + '  (改包请把它填进脚本 CAND_CM 数组稳定复跑)');
      if (!once('CM:' + cmName)) { hookSendRequest(CM); hookDcAddress(CM); }
    } else {
      // DC 兜底即使没找到 CM 也跑一次(Datacenter 类可能独立可见)
      if (!once('DC:nocm')) hookDcAddress(null);
      console.log('[tg][未命中] 没找到 ConnectionsManager 类。下一步：');
      console.log('  · 加固/二级加载未释放→先跑 memdex-dump.js 或 dexload-hook.js 让真实 DEX 进表，再挂；');
      console.log('  · 接入节点(:30113 那类)此刻仍可从文件尾部 [tg][native] connect 行看到；');
      console.log('  · 或在 REPL 调 fxTgScan() 看当前已载入、含 TL_auth/ConnectionsManager 的类名清单。');
    }

    // (b) 登录 TLObject —— 候选名 + 全表匹配双保险
    var authHits = findClassesBySubstr(AUTH_SUBSTR, 30);
    if (authHits.length) {
      console.log('[tg][命中] TL_auth 类: ' + authHits.join(' | '));
      authHits.forEach(function (cn) { if (!once('AUTH:' + cn)) hookAuthSerialize(cn); });
    } else {
      console.log('[tg][登录类未命中] 未在已载入类里找到 TL_auth_*；多为加固未释放或字段被整体重命名。');
      console.log('  · 报告里的 LoginNewActivity$PasswordView/checkEnterInfo 走 sendRequest，已被(1)覆盖；');
      console.log('  · 真实类名出现后填进脚本 AUTH_SUBSTR 即可。');
    }

    // (c) NativeByteBuffer 兜底
    if (!once('NBB')) hookNativeByteBuffer();
  }

  // 暴露给 REPL：加固解密有延迟，可手动重扫定位
  globalThis.fxTgScan = function () {
    console.log('[tg] === 当前已载入、含关键字的类名 ===');
    findClassesBySubstr(['ConnectionsManager', 'Datacenter', 'TL_auth', 'TL_message', 'TL_updates', 'NativeByteBuffer'], 80)
      .forEach(function (c) { console.log('  ' + c); });
  };
  // REPL 强制重挂(无视 once 去重)：加固晚释放后想再挂一遍时用
  globalThis.fxTgRehook = function () { DONE = {}; locateAndHook(); };

  // 立即挂一次；改包加固常延迟释放 DEX，再延迟两次重挂(once 去重，已挂的类不会叠日志/重复替换)
  locateAndHook();
  setTimeout(function () { console.log('[tg] 二次定位(3s，等加固释放 DEX)…'); locateAndHook(); }, 3000);
  setTimeout(function () { console.log('[tg] 三次定位(12s)…'); locateAndHook(); }, 12000);

  console.log('[tg] armed —— Telegram/TLRPC 层探针就位(不破 MTProto 加密)。');
  console.log('[tg] 抓不到时：先 memdex-dump.js 释放真实 DEX，再在 REPL 调 fxTgScan() 看真实类名、fxTgRehook() 重挂；接入节点(:30113 那类)看 [tg][DC] 或 [tg][native] connect 行。');
});

/* ============================================================
 *  native 兜底：org.telegram.tgnet 的核心走 libtmessages.*.so(JNI)，
 *  Java 层 sendRequest 若被改包绕过，可在 native connect 抓接入节点 IP:port。
 *  这里只读对端地址(= 接入节点调证锚点)，不碰 MTProto 加密数据。
 *  接入节点 IP:port 的权威来源就是这里——任何真实出站连接(含连失败 SYN_SENT)都打。
 * ============================================================ */
(function () {
  'use strict';
  // 解析 sockaddr* → ip:port。sin_family 是 host 序 unsigned short；ARM Android 恒小端，低字节即 AF_*。
  // 端口 sin_port / sin6_port 恒网络字节序(大端)，按字节手动 ntohs。
  function parseSockaddr(sa) {
    try {
      if (sa === null || sa.isNull()) return null;
      var fam = sa.readU16() & 0xffff;            // sa_family_t
      var lo = fam & 0xff;
      var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();   // ntohs
      if (lo === 2) { // AF_INET：sin_addr 在偏移 4，4 字节
        return sa.add(4).readU8() + '.' + sa.add(5).readU8() + '.' + sa.add(6).readU8() + '.' + sa.add(7).readU8() + ':' + port;
      }
      if (lo === 10 || lo === 30) { // AF_INET6(Linux=10/部分派生=30)：sin6_addr 在偏移 8，16 字节
        var p = [];
        for (var i = 0; i < 16; i += 2) p.push(((sa.add(8 + i).readU8() << 8) | sa.add(8 + i + 1).readU8()).toString(16));
        return '[' + p.join(':') + ']:' + port;
      }
      return '<af=' + lo + '>';
    } catch (e) { return '<sockaddr err ' + e + '>'; }
  }

  // 跨 Frida 版本健壮解析导出符号：
  //   新版 Frida(17+) Module.getExportByName 找不到会"抛异常"而非返 null；旧版返 null。
  //   故 try getExportByName → catch 后 findExportByName(返 null) → 再 enumerateExportsSync('libc.so') 整表兜底。
  function resolveExport(name) {
    // 1) 全进程导出表(快路径)
    try { var p = Module.getExportByName(null, name); if (p && !p.isNull()) return p; } catch (e) {}
    try { if (Module.findExportByName) { var p2 = Module.findExportByName(null, name); if (p2 && !p2.isNull()) return p2; } } catch (e) {}
    // 2) 显式 libc.so 兜底(某些 ROM 全局表里查不到，但 libc 模块内有)
    try {
      var hit = null;
      Module.enumerateExportsSync('libc.so').forEach(function (ex) {
        if (hit) return;
        if (ex.name === name) hit = ex.address;
      });
      if (hit) return hit;
    } catch (e) {}
    return null;
  }

  // libc connect 兜底：MTProto 接入节点(报告 :30113)的真实出站地址，连失败也打(SYN_SENT 也算锚点)
  try {
    var c = resolveExport('connect');
    if (c === null) {
      console.log('[tg][native] connect 符号未命中(全局表+libc.so 均无) — 下一步：Module.enumerateModules() 找含 connect 的 libc/bionic 模块，或换静态偏移');
    } else {
      Interceptor.attach(c, {
        onEnter: function (args) {
          try {
            var dst = parseSockaddr(args[1]);
            // 只打 MTProto 关心的非本地连接；30113 这类自建接入端口尤其留意
            if (dst && dst.indexOf('127.0.0.1') === -1 && dst.indexOf('[::1]') === -1 && dst.indexOf('<af=') === -1) {
              var flag = (dst.indexOf(':30113') !== -1) ? ' [LEAD->疑似 MTProto 接入节点(对照报告 :30113)]' : '';
              console.log('[tg][native] connect fd=' + args[0].toInt32() + ' -> ' + dst + flag);
            }
          } catch (e) { console.log('[tg][native] connect onEnter skip: ' + e); }
        }
      });
      console.log('[tg][native] connect hooked @ ' + c + ' (抓 MTProto 接入节点 IP:port)');
    }
  } catch (e) { console.log('[tg][native] connect hook skip: ' + e); }

  console.log('[tg][native] armed —— connect 兜底就位。Java sendRequest 没命中时，接入节点仍可从这里看到。');
})();