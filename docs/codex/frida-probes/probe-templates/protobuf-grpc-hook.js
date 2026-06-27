/*
 * 用途: 反诈取证-在 protobuf 序列化边界只读截获 gRPC/protobuf 明文 body，手写浅解析打印 field号/wiretype/hex(固证，不改写不外发)
 * 适用: 用 gRPC(over HTTP2) / protobuf-lite 通信的安卓涉诈样本；动态抓包只见 HTTP2 二进制帧/protobuf 乱码时用本探针在内存边界取明文
 * 跑:   frida -U -f <包名> -l protobuf-grpc-hook.js  (或 attach: frida -U <包名> -l protobuf-grpc-hook.js)；落盘 frida ... -l x.js -o /data/local/tmp/proto.log
 * 改:   类被 R8/混淆改名→看末尾"未命中下一步"用 enumerateLoadedClasses 找 toByteArray/parseFrom 宿主回填 TARGETS；只想看上行→把 SCAN_SUBCLASS_PARSE 置 false 并注掉 hookParseHelpers
 */
'use strict';

// 扫描具体消息子类的 parseFrom([B) 会遍历全部已加载类，开销略大；设备卡顿可置 false(只留静态辅助方法的下行 hook)
var SCAN_SUBCLASS_PARSE = true;

// 轻量再入护栏: 一次逻辑反序列化可能既走子类 parseFrom([B) 又走 GeneratedMessageLite.parseFrom(T,[B)，避免对同一 byte[] 重复打印
var inParse = false;

// ============ 工具: byte[] → hex / base64 (明文/key/byte[] 一律 hex，不盲 UTF-8) ============
function toJByteArrayJs(jbytes) {
  // 把 Java byte[] 拷成 JS 普通数组(0~255)，失败返回 null
  try {
    if (jbytes === null || typeof jbytes === 'undefined') return null;
    var len = jbytes.length;
    var out = new Array(len);
    for (var i = 0; i < len; i++) {
      var b = jbytes[i];
      out[i] = b < 0 ? b + 256 : b; // Java byte 有符号 → 无符号
    }
    return out;
  } catch (e) {
    return null;
  }
}

function bytesToHex(arr, max) {
  if (arr === null) return '<null>';
  var lim = (typeof max === 'number' && arr.length > max) ? max : arr.length;
  var s = '';
  for (var i = 0; i < lim; i++) {
    var h = (arr[i] & 0xff).toString(16);
    if (h.length < 2) h = '0' + h;
    s += h;
  }
  if (lim < arr.length) s += '..(+' + (arr.length - lim) + 'B)';
  return s;
}

function bytesToB64(arr, max) {
  // 标准 base64，纯本地转码不外发；超 max 不转(避免日志爆)
  try {
    if (arr === null) return '<null>';
    if (typeof max === 'number' && arr.length > max) return '<skip b64: ' + arr.length + 'B>';
    var tbl = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var out = '';
    for (var i = 0; i < arr.length; i += 3) {
      var b0 = arr[i] & 0xff;
      var b1 = (i + 1 < arr.length) ? (arr[i + 1] & 0xff) : 0;
      var b2 = (i + 2 < arr.length) ? (arr[i + 2] & 0xff) : 0;
      out += tbl[b0 >> 2];
      out += tbl[((b0 & 0x03) << 4) | (b1 >> 4)];
      out += (i + 1 < arr.length) ? tbl[((b1 & 0x0f) << 2) | (b2 >> 6)] : '=';
      out += (i + 2 < arr.length) ? tbl[b2 & 0x3f] : '=';
    }
    return out;
  } catch (e) {
    return '<b64 err: ' + e + '>';
  }
}

// 可见 ASCII 试探: 仅给"线索预判"(看着像手机号/json/账号)，不取代 hex；非全可见返回 null
function asciiPeek(arr, off, len) {
  try {
    var s = '';
    for (var i = off; i < off + len && i < arr.length; i++) {
      var c = arr[i] & 0xff;
      if (c >= 0x20 && c <= 0x7e) s += String.fromCharCode(c);
      else return null; // 含不可见字节→不当字符串
    }
    return s;
  } catch (e) {
    return null;
  }
}

// ============ protobuf 浅解析: 手写 varint + tag→wire-type 走表(R8 stripped 拿不到字段名→只给 tag/wiretype/hex) ============
var WIRE = { 0: 'varint', 1: 'i64', 2: 'len-delim', 3: 'sgroup', 4: 'egroup', 5: 'i32' };

function readVarint(arr, pos) {
  // 返回 {value(JS number,>53bit会失精→调用方对长度/tag 另给 hex 兜底), next}；失败抛
  // 注: JS 位运算是 32bit 有符号，<<28 起会触到符号位污染 → shift<28 才用 |<<，>=28 改用浮点累加保正确性
  var shift = 0;
  var result = 0;
  var start = pos;
  while (true) {
    if (pos >= arr.length) throw new Error('varint truncated@' + start);
    var b = arr[pos] & 0xff;
    if (shift < 28) result |= (b & 0x7f) << shift;
    else result += (b & 0x7f) * Math.pow(2, shift); // shift>=28 避免 32bit 符号位/溢出污染
    pos++;
    if ((b & 0x80) === 0) break;
    shift += 7;
    if (shift > 70) throw new Error('varint too long@' + start);
  }
  // result 可能因 |<< 在 28 边界落成负数残留？上面已用 shift<28 守住，<28 累加恒为非负小值；此处 >>>0 归一化低位
  if (result < 0) result = result >>> 0;
  return { value: result, next: pos };
}

// 浅解析(只解一层；len-delim 给 hex+base64+ascii预判，不递归避免误判嵌套 vs bytes)
function shallowParse(arr, indent) {
  var lines = [];
  var pos = 0;
  var guard = 0;
  try {
    while (pos < arr.length) {
      if (++guard > 4096) { lines.push(indent + '[stop] 字段过多，截断'); break; }
      var tagInfo = readVarint(arr, pos);
      pos = tagInfo.next;
      var tag = tagInfo.value;
      var fieldNo = Math.floor(tag / 8); // tag >> 3，避大数位运算
      var wt = tag % 8;                  // tag & 0x07，用 % 防 tag 为浮点时位运算丢高位
      var wtName = WIRE[wt] || ('?' + wt);

      if (wt === 0) { // varint
        var v = readVarint(arr, pos);
        pos = v.next;
        lines.push(indent + 'field#' + fieldNo + ' [' + wtName + '] = ' + v.value);
      } else if (wt === 1) { // 64-bit
        if (pos + 8 > arr.length) throw new Error('i64 truncated');
        lines.push(indent + 'field#' + fieldNo + ' [' + wtName + '] = 0x' + bytesToHex(arr.slice(pos, pos + 8)));
        pos += 8;
      } else if (wt === 5) { // 32-bit
        if (pos + 4 > arr.length) throw new Error('i32 truncated');
        lines.push(indent + 'field#' + fieldNo + ' [' + wtName + '] = 0x' + bytesToHex(arr.slice(pos, pos + 4)));
        pos += 4;
      } else if (wt === 2) { // length-delimited: string/bytes/嵌套 message/packed
        var ln = readVarint(arr, pos);
        pos = ln.next;
        var dlen = ln.value;
        if (dlen < 0 || pos + dlen > arr.length) throw new Error('len-delim truncated need=' + dlen);
        var seg = arr.slice(pos, pos + dlen);
        pos += dlen;
        var ascii = asciiPeek(seg, 0, Math.min(seg.length, 64));
        var line = indent + 'field#' + fieldNo + ' [' + wtName + ' ' + dlen + 'B] hex=' + bytesToHex(seg, 64);
        line += ' b64=' + bytesToB64(seg, 96);
        if (ascii !== null) line += ' ascii~="' + ascii + '"'; // 仅预判(手机号/json/账号线索)
        lines.push(line);
      } else { // group(已废弃)或未知 wire-type
        lines.push(indent + 'field#' + fieldNo + ' [' + wtName + '] (group/unknown，停止解析剩余 hex=' + bytesToHex(arr.slice(pos), 64) + ')');
        break;
      }
    }
  } catch (e) {
    // 浅解析失败大概率: 这段不是裸 protobuf(可能含 gRPC 5字节前缀/已加密/嵌套被当顶层)
    lines.push(indent + '[parse stop] ' + e + ' @pos=' + pos + '；剩余 raw hex=' + bytesToHex(arr.slice(pos), 96));
  }
  return lines;
}

// gRPC over HTTP2: body 常带 5字节长度前缀(1B compressedFlag + 4B big-endian length)；探测并剥离后再解
function maybeStripGrpcPrefix(arr) {
  try {
    if (arr.length >= 5) {
      var flag = arr[0] & 0xff;
      // 4B big-endian length；用 *2^n 而非 <<24 防 32bit 符号位污染(长度本就非负)
      var len = (arr[1] & 0xff) * 16777216 + (arr[2] & 0xff) * 65536 + (arr[3] & 0xff) * 256 + (arr[4] & 0xff);
      // 前缀自洽: flag∈{0,1} 且 声明长度==剩余长度 → 判定为 gRPC framed
      if ((flag === 0 || flag === 1) && len === arr.length - 5) {
        return { framed: true, compressed: flag === 1, payload: arr.slice(5) };
      }
    }
  } catch (e) { /* 探测失败按裸 protobuf 走 */ }
  return { framed: false, compressed: false, payload: arr };
}

function dumpProto(dir, hostClass, arr) {
  // dir: 'OUT(toByteArray-上行)' / 'IN(parseFrom-下行)'
  console.log('================ [protobuf ' + dir + '] ================');
  console.log('  宿主类: ' + hostClass + '  长度: ' + (arr ? arr.length : 0) + 'B');
  if (arr === null || arr.length === 0) { console.log('  (空 body)'); return; }
  console.log('  原始 hex(前128B): ' + bytesToHex(arr, 128));
  console.log('  原始 b64(<=256B): ' + bytesToB64(arr, 256));

  var g = maybeStripGrpcPrefix(arr);
  var body = arr;
  if (g.framed) {
    console.log('  >> 命中 gRPC 5字节前缀: compressed=' + g.compressed + ' payloadLen=' + g.payload.length + 'B');
    if (g.compressed) {
      console.log('  >> payload 被 gRPC 压缩(gzip/deflate)，浅解析会失败；下一步: 同时 hook 解压点或在 parseFrom 内层(已解压)取，本探针只标记不强解');
    }
    body = g.payload;
  }

  if (!g.framed || !g.compressed) {
    console.log('  --- 浅解析(field# / wire-type / 值；R8 stripped 无字段名，按 field号对 .proto 回填) ---');
    var lines = shallowParse(body, '    ');
    if (lines.length === 0) console.log('    (无字段或解析为空)');
    for (var i = 0; i < lines.length; i++) console.log(lines[i]);
  }

  // 调用栈: 定位是哪个业务接口/RPC 在收发，帮"定接口→定人"(过滤 protobuf 框架帧；本 JS 文件名不会出现在 Java 栈，无需过滤)
  try {
    var ex = Java.use('java.lang.Throwable').$new();
    var st = ex.getStackTrace();
    var show = [];
    for (var k = 0; k < st.length && show.length < 8; k++) {
      var f = st[k].toString();
      if (f.indexOf('com.google.protobuf') === -1) show.push(f);
    }
    console.log('  调用栈(去 protobuf 框架，定 RPC/业务接口):');
    for (var j = 0; j < show.length; j++) console.log('    at ' + show[j]);
  } catch (e) {
    console.log('  [stack] skip: ' + e);
  }
  console.log('========================================================');
}

// ============ Java hook 主体 ============
Java.perform(function () {

  // toByteArray 由 AbstractMessageLite(及其父)提供并被所有 message 继承 → 挂基类即可全覆盖上行；
  // 注意 parseFrom([B) 的"公开版"是按具体 message 子类生成的静态方法，基类上没有，
  // 基类只有受保护的静态辅助 parseFrom(T defaultInstance, byte[]...) / parsePartialFrom(...) →
  // 故下行分两路打: (a)挂基类静态辅助方法 (b)按需枚举具体子类的公开 parseFrom([B)。
  // R8 重命名/shade 后名字都可能变 → 命中失败时按末尾"未命中下一步"现场定位回填。
  var TBA_TARGETS = [
    'com.google.protobuf.AbstractMessageLite',  // toByteArray 宿主(lite)
    'com.google.protobuf.GeneratedMessageLite',
    'com.google.protobuf.AbstractMessage',      // full runtime(非 lite)兜底
    'com.google.protobuf.GeneratedMessageV3'
  ];
  // 反序列化静态辅助方法的宿主(基类侧)
  var PARSE_HELPER_TARGETS = [
    'com.google.protobuf.GeneratedMessageLite',
    'com.google.protobuf.GeneratedMessageV3',
    'com.google.protobuf.AbstractParser'        // parsePartialFrom/parseFrom 也常落在 Parser 上
  ];

  // ---- 上行: toByteArray() → byte[]，序列化即将"对外提交"的 message ----
  function hookToByteArray(clsName) {
    try {
      var Cls = Java.use(clsName);
      if (typeof Cls.toByteArray === 'undefined' || !Cls.toByteArray) { console.log('[toByteArray] skip: ' + clsName + ' 无 toByteArray'); return false; }
      // toByteArray() 是无参实例方法 → .overload() 选无参重载
      Cls.toByteArray.overload().implementation = function () {
        var ret = this.toByteArray(); // 先调原方法，绝不改写返回值
        try {
          var hostName = clsName;
          try { hostName = clsName + '→' + this.getClass().getName(); } catch (e0) { /* getClass 偶失败不致命 */ }
          var arr = toJByteArrayJs(ret);
          dumpProto('OUT(toByteArray-上行/样本提交)', hostName, arr);
        } catch (e) {
          console.log('[toByteArray dump] skip: ' + e);
        }
        return ret; // 原样返回，不污染样本数据
      };
      console.log('[+] hooked ' + clsName + '.toByteArray()');
      return true;
    } catch (e) {
      console.log('[toByteArray] skip: ' + clsName + ' : ' + e);
      return false;
    }
  }

  // 通用: 对某类的 parseFrom/parsePartialFrom 所有重载里"含 byte[] 参数"的逐个挂，读那个 byte[]
  function hookParseLikeMethod(Cls, clsName, methodName) {
    var hooked = 0;
    var m = Cls[methodName];
    if (typeof m === 'undefined' || !m) return 0;
    var overloads = m.overloads;
    for (var i = 0; i < overloads.length; i++) {
      (function (ov) {
        try {
          var argTypes = ov.argumentTypes;
          var byteArgIdx = -1;
          for (var a = 0; a < argTypes.length; a++) {
            if (argTypes[a].className === '[B') { byteArgIdx = a; break; }
          }
          if (byteArgIdx === -1) return; // 该重载不含 byte[]，跳过(可能是 InputStream/ByteString/CodedInputStream 版)
          ov.implementation = function () {
            // 再入护栏: 子类 parseFrom([B) 内部会再调基类 parseFrom(T,[B)，同一 body 只打一次
            var owns = false;
            if (!inParse) { inParse = true; owns = true; }
            try {
              if (owns) {
                var raw = arguments[byteArgIdx];
                var arr = toJByteArrayJs(raw);
                dumpProto('IN(' + methodName + '-下行/样本接收)', clsName, arr);
              }
            } catch (e) {
              console.log('[' + methodName + ' dump] skip: ' + e);
            }
            try {
              return ov.apply(this, arguments); // 原样回放参数，只读
            } finally {
              if (owns) inParse = false;
            }
          };
          hooked++;
          console.log('[+] hooked ' + clsName + '.' + methodName + '(... [B@' + byteArgIdx + ' ...) argc=' + argTypes.length);
        } catch (e2) {
          console.log('[' + methodName + ' overload] skip: ' + e2);
        }
      })(overloads[i]);
    }
    return hooked;
  }

  // ---- 下行(a): 基类静态辅助方法 parseFrom(T,byte[]) / parsePartialFrom ----
  function hookParseHelpers(clsName) {
    try {
      var Cls = Java.use(clsName);
      var n = 0;
      n += hookParseLikeMethod(Cls, clsName, 'parseFrom');
      n += hookParseLikeMethod(Cls, clsName, 'parsePartialFrom');
      if (n === 0) console.log('[parseHelper] ' + clsName + ' 无含 byte[] 的 parseFrom/parsePartialFrom 重载(可能仅 CodedInputStream 版，下行走子类扫描或 hook mergeFrom)');
      return n > 0;
    } catch (e) {
      console.log('[parseHelper] skip: ' + clsName + ' : ' + e);
      return false;
    }
  }

  // ---- 下行(b): 枚举已加载的具体 message 子类，挂其公开 parseFrom([B) ----
  function scanSubclassParseFrom() {
    var hookedClasses = 0;
    try {
      var names = Java.enumerateLoadedClassesSync();
      for (var i = 0; i < names.length; i++) {
        var n = names[i];
        // 粗筛: 跳过明显非业务类，降低开销与误挂(framework/android/系统包)
        if (n.indexOf('android.') === 0 || n.indexOf('java.') === 0 ||
            n.indexOf('javax.') === 0 || n.indexOf('kotlin') === 0 ||
            n.indexOf('com.google.protobuf.') === 0) continue;
        var Cls;
        try { Cls = Java.use(n); } catch (e0) { continue; }
        try {
          // 只挂"同时具备 parseFrom 且是 GeneratedMessageLite/AbstractMessageLite 后代"的类，避免误挂同名方法
          if (typeof Cls.parseFrom === 'undefined' || !Cls.parseFrom) continue;
          var isMsg = false;
          try { isMsg = Cls.class.getName && isProtoMessage(Cls); } catch (e1) { isMsg = false; }
          if (!isMsg) continue;
          var got = hookParseLikeMethod(Cls, n, 'parseFrom');
          if (got > 0) hookedClasses++;
        } catch (e2) { /* 单类失败跳过，不静默到全局 */ }
      }
    } catch (e) {
      console.log('[scanSubclass] skip: ' + e);
    }
    return hookedClasses;
  }

  // 判定一个 Java.use 包装类是否 protobuf message(继承自 GeneratedMessageLite / AbstractMessageLite)
  function isProtoMessage(Cls) {
    try {
      var sup = Cls.class.getSuperclass();
      var depth = 0;
      while (sup !== null && depth < 12) {
        var sn = sup.getName();
        if (sn === 'com.google.protobuf.GeneratedMessageLite' ||
            sn === 'com.google.protobuf.AbstractMessageLite' ||
            sn === 'com.google.protobuf.GeneratedMessageV3' ||
            sn === 'com.google.protobuf.AbstractMessage') return true;
        sup = sup.getSuperclass();
        depth++;
      }
    } catch (e) { /* 取不到父类按非 message */ }
    return false;
  }

  // ---- 编排 ----
  var tbaHit = false;
  for (var t = 0; t < TBA_TARGETS.length; t++) {
    try {
      Java.use(TBA_TARGETS[t]); // 探测类是否存在(不存在抛异常)
      if (hookToByteArray(TBA_TARGETS[t])) tbaHit = true;
    } catch (e) {
      console.log('[tba target] skip(未加载): ' + TBA_TARGETS[t]);
    }
  }

  var parseHit = false;
  for (var p = 0; p < PARSE_HELPER_TARGETS.length; p++) {
    try {
      Java.use(PARSE_HELPER_TARGETS[p]);
      if (hookParseHelpers(PARSE_HELPER_TARGETS[p])) parseHit = true;
    } catch (e) {
      console.log('[parse target] skip(未加载): ' + PARSE_HELPER_TARGETS[p]);
    }
  }

  var subHit = 0;
  if (SCAN_SUBCLASS_PARSE) {
    console.log('[*] 扫描已加载具体 message 子类的 parseFrom([B)...(设备卡可把 SCAN_SUBCLASS_PARSE 置 false)');
    subHit = scanSubclassParseFrom();
    console.log('[*] 子类 parseFrom([B) 命中 ' + subHit + ' 个类');
  }

  if (!tbaHit && !parseHit && subHit === 0) {
    // 全部未命中 = protobuf runtime 被 R8 重命名 / shade 进 app 包 / 还没加载
    console.log('========================================================');
    console.log('[!] 未命中任何 protobuf 宿主(toByteArray/parseFrom 全空)。可能: R8 重命名 / 被 shade 进 app 自有包名 / 时机太早未加载。');
    console.log('    下一步(现场定位回填 TARGETS):');
    console.log('    Java.perform(function(){');
    console.log('      Java.enumerateLoadedClassesSync().forEach(function(n){');
    console.log('        try{ var c=Java.use(n);');
    console.log('          if(c.toByteArray && c.toByteArray.overload){ console.log("候选 toByteArray 宿主:", n); }');
    console.log('          if(c.parseFrom){ console.log("候选 parseFrom 宿主:", n); }');
    console.log('        }catch(e){} });');
    console.log('    });');
    console.log('    或对 native libprotobuf-cpp: Module.enumerateExports("libprotobuf*.so") 找 SerializeTo*/ParsePartialFrom*(C++ 侧)。');
    console.log('========================================================');
  } else {
    console.log('[*] protobuf-grpc-hook 就绪。toByteArray命中=' + tbaHit + ' 基类parse命中=' + parseHit + ' 子类parse命中=' + subHit + '。等待样本收发 gRPC/protobuf body...');
    console.log('[*] 提示: 只看上行(样本提交什么)看 OUT(toByteArray)；只看下行(C2 下发什么)看 IN(parseFrom/parsePartialFrom)。');
    if (!parseHit && subHit === 0) {
      console.log('[*] 注意: 下行(parseFrom)一个都没挂上 → 若需看下行，检查 reflection 是否走 CodedInputStream/mergeFrom，或现场 hook 具体 message 子类。');
    }
  }
});