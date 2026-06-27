/*
 * 用途: 只读 hook libart.so 的 RegisterNatives，落「方法名 签名 → fnPtr 所在 so!offset」，定位加固样本无符号 native 真入口。
 * 适用: A11+ strip / 加固壳动态注册 JNI 的样本；需先让反检测/反frida探针生效，且务必 spawn 启动(-f)才能抓全 JNI_OnLoad 期注册。
 * 跑:   frida -U -f <包名> -l register-natives-hook.js  (必须 spawn；attach 上去 RegisterNatives 早已执行完，抓不到)
 * 改:   符号被 strip 抓不到时，按下方注释用 enumerateExports 回填 _ZN3art...RegisterNatives 跨版本符号，或改走 JNIEnv 函数表第 215 槽(见 hookViaVtable)。
 */
'use strict';

// ============================================================================
// 唯一出口：所有取证结果只走 console.log（落盘请用 frida -o 或重定向到 /data/local/tmp）
// 本探针绝不主动写文件、绝不外联、绝不修改任何寄存器/返回值/内存——纯只读检测仪。
// ============================================================================

var TAG = '[register-natives]';

// JNINativeMethod 在 32/64 位下的字段布局：
//   struct { char* name; char* signature; void* fnPtr; }
// 64 位每字段 8 字节、stride 24；32 位每字段 4 字节、stride 12。
var PSIZE = Process.pointerSize;
var STRIDE = PSIZE * 3;

// 防御：壳可能投毒一个非法的 nMethods（极大值/负值）让探针狂读越界内存。
// 注册表合法条目数通常 < 数千，这里设一个宽松上限做硬钳制，超限只读前 N 条并打提示。
var MAX_METHODS = 4096;

// ---- 工具：把 fnPtr 解析成 module!offset（核心取证产物）----------------------
function resolveFnPtr(fnPtr) {
  try {
    if (fnPtr.isNull()) return 'fnPtr=NULL(未绑定/动态生成?)';
    var m = Process.findModuleByAddress(fnPtr);
    if (m === null) {
      // 落不到 module：典型是壳把代码搬到匿名可执行内存(VMP/抽取壳)，
      // 这本身就是线索——记下绝对地址，后续可 dump 这段 RX 内存逆向。
      var prot = '?';
      try {
        var r = Process.findRangeByAddress(fnPtr);
        if (r !== null) prot = r.protection;
      } catch (eR) { prot = '?(range_err:' + eR + ')'; }
      return 'fnPtr=' + fnPtr + ' (不属任何so, 匿名内存 prot=' + prot + ' → 疑壳抽取/VMP, dump该段RX逆向)';
    }
    var off = fnPtr.sub(m.base);
    return m.name + '!0x' + off.toString(16) + '  (fnPtr=' + fnPtr + ' base=' + m.base + ')';
  } catch (e) {
    return 'fnPtr=' + fnPtr + ' resolve_err:' + e;
  }
}

function readCStr(p) {
  try { return p.isNull() ? '<null>' : p.readCString(); }
  catch (e) { return '<read_err:' + e + '>'; }
}

// ---- 核心：解析并落一张 RegisterNatives 注册表 -------------------------------
// 抓到什么: 每条 (name, signature, fnPtr)；jclass 仅打句柄(早期无法即时解析类名)。
// → 调证线索: name#signature 锚业务语义，fnPtr→so!offset 锚 native 真实现位置，
//   该 offset 直接作为 native-ssl/native-crypto-key 的 Interceptor.attach 落点(定逻辑/固证)。
//   类名留待业务触发后用 Java.enumerateLoadedClasses 按 fnPtr/方法名 反查回填(见 notes)。
function dumpRegistration(envPtr, clazz, methodsPtr, count) {
  try {
    // count 是 jint，从 onEnter 拿到的是 NativePointer，用 .toInt32() 取 32 位有符号值。
    var n = count.toInt32();
    var capped = false;
    if (n < 0) {
      // 负数 = 壳投毒/读错；当作 0 条但打出来留证。
      console.log(TAG + ' >>> RegisterNatives env=' + envPtr + ' jclass=' + clazz +
                  ' count=' + n + ' (非法负值, 疑投毒, 跳过遍历)');
      return;
    }
    if (n > MAX_METHODS) {
      capped = true;
      console.log(TAG + ' !! count=' + n + ' 超上限(' + MAX_METHODS +
                  '), 疑壳投毒非法 nMethods；只读前 ' + MAX_METHODS + ' 条以防越界。');
      n = MAX_METHODS;
    }

    console.log(TAG + ' >>> RegisterNatives env=' + envPtr +
                ' jclass=' + clazz + ' count=' + (capped ? (n + '(已钳制)') : n));

    for (var i = 0; i < n; i++) {
      try {
        var base = methodsPtr.add(i * STRIDE);
        var namePtr = base.readPointer();
        var sigPtr = base.add(PSIZE).readPointer();
        var fnPtr = base.add(PSIZE * 2).readPointer();

        var name = readCStr(namePtr);
        var sig = readCStr(sigPtr);
        console.log(TAG + '   [' + i + '] ' + name + '  ' + sig +
                    '  ->  ' + resolveFnPtr(fnPtr));
      } catch (eRow) {
        // 单条解析失败不静默、不中断，继续抓下一条
        console.log(TAG + '   [' + i + '] skip:' + eRow);
      }
    }
  } catch (e) {
    console.log(TAG + ' dump skip:' + e);
  }
}

// ---- 工具：兼容新旧 frida 的 module 导出枚举/查找 ----------------------------
// 新 frida(>=16) 推荐用 Module 实例方法；老版本是 Module 静态方法。两条都兜。
function getLibart() {
  try {
    if (typeof Process.findModuleByName === 'function') {
      return Process.findModuleByName('libart.so'); // Module|null
    }
  } catch (e) { /* 落到静态路径 */ }
  return null;
}

function findExport(symName) {
  // 优先实例方法(新 frida)，回落静态方法(老 frida)，全部包 try。
  try {
    var lib = getLibart();
    if (lib && typeof lib.findExportByName === 'function') {
      var a = lib.findExportByName(symName);
      if (a !== null) return a;
    }
  } catch (e1) { /* 回落 */ }
  try {
    if (typeof Module.findExportByName === 'function') {
      return Module.findExportByName('libart.so', symName);
    }
  } catch (e2) { /* null */ }
  return null;
}

function enumExports() {
  try {
    var lib = getLibart();
    if (lib && typeof lib.enumerateExports === 'function') {
      return lib.enumerateExports();
    }
  } catch (e1) { /* 回落 */ }
  try {
    if (typeof Module.enumerateExports === 'function') {
      return Module.enumerateExports('libart.so');
    }
  } catch (e2) { /* [] */ }
  return [];
}

// ---- 路径 A：直接 hook libart.so 导出的 RegisterNatives（首选）---------------
// 符号现场定位（被混淆/跨版本时回填用）：
//   enumExports().filter(function(e){return e.name.indexOf('RegisterNatives')>=0;})
// 常见 mangled 名（随 Android 版本变化，抓不到就用上面 enumExports 回填本数组）：
//   art::JNI<true>::RegisterNatives        -> 新版本模板特化
//   art::JNI<false>::RegisterNatives
//   _ZN3art3JNIILb1EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
//   _ZN3art3JNIILb0EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
//   _ZN3art9CheckJNI...RegisterNatives...   (CheckJNI 包装层)
function hookViaExport() {
  var CANDIDATES = [
    '_ZN3art3JNIILb1EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi',
    '_ZN3art3JNIILb0EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi'
  ];
  var hooked = false;

  // 先按已知符号试
  for (var c = 0; c < CANDIDATES.length; c++) {
    try {
      var addr = findExport(CANDIDATES[c]);
      if (addr !== null) {
        attachRegisterNatives(addr, 'export:' + CANDIDATES[c]);
        hooked = true;
      }
    } catch (e) {
      console.log(TAG + ' export-try skip(' + CANDIDATES[c] + '):' + e);
    }
  }

  // 已知符号没命中→运行时枚举导出表兜底（strip 后多半失败，但 demangle 名有时仍在）
  if (!hooked) {
    try {
      var exps = enumExports();
      for (var k = 0; k < exps.length; k++) {
        var nm = exps[k].name;
        if (nm.indexOf('RegisterNatives') >= 0 && nm.indexOf('JNI') >= 0) {
          attachRegisterNatives(exps[k].address, 'enum:' + nm);
          hooked = true;
        }
      }
    } catch (e2) {
      console.log(TAG + ' enumExports skip:' + e2);
    }
  }
  return hooked;
}

function attachRegisterNatives(addr, srcDesc) {
  try {
    Interceptor.attach(addr, {
      // 签名: RegisterNatives(JNIEnv* env, jclass clazz, const JNINativeMethod* methods, jint nMethods)
      onEnter: function (args) {
        dumpRegistration(args[0], args[1], args[2], args[3]);
      }
      // onLeave 故意不实现：只读探针不碰返回值
    });
    console.log(TAG + ' hooked RegisterNatives @ ' + addr + '  via ' + srcDesc);
  } catch (e) {
    console.log(TAG + ' attach skip(' + srcDesc + '):' + e);
  }
}

// ---- 路径 B：走 JNIEnv 函数表第 215 槽（符号全 strip 时的硬兜底）-------------
// JNINativeInterface 中 RegisterNatives 是第 215 个函数指针（index 215，0-based，跨主流 Android 稳定）。
// 取法：env(JNIEnv*) 指向 const JNINativeInterface*；vtable = *env；slot = vtable + 215*PSIZE；fn = *slot。
// JNIEnv* 来源：Java.vm.getEnv().handle（需 Java.available 且 JavaVM 已就绪）。
// spawn 早期 vm 可能未就绪，故整体包 try；可在业务触发后于 REPL 手动调用本函数重挂。
function hookViaVtable() {
  try {
    if (!Java.available) {
      console.log(TAG + ' vtable[215] skip: Java 未就绪(Java.available=false), 业务触发后再 hookViaVtable()');
      return false;
    }
    var env = Java.vm.getEnv();        // frida Env 包装
    var envPtr = env.handle;           // JNIEnv*  (NativePointer)
    var vtable = envPtr.readPointer(); // const JNINativeInterface*
    var slot = vtable.add(215 * PSIZE);// 第 215 槽
    var fn = slot.readPointer();
    if (fn.isNull()) {
      console.log(TAG + ' vtable[215] skip: 槽位为 NULL(疑表被改/越界), 用 enumExports 反查实际槽位');
      return false;
    }
    attachRegisterNatives(fn, 'vtable[215]');
    console.log(TAG + ' vtable[215] RegisterNatives=' + fn + ' (env=' + envPtr + ')');
    return true;
  } catch (e) {
    console.log(TAG + ' vtable[215] skip:' + e +
                '  (JavaVM 未就绪很正常, 业务触发后可手动 hookViaVtable())');
    return false;
  }
}

// ---- 编排 -------------------------------------------------------------------
(function main() {
  console.log(TAG + ' loaded. ptrSize=' + PSIZE + ' stride=' + STRIDE +
              '  (务必 spawn -f 启动, 否则 JNI_OnLoad 已过, 抓不到注册)');

  var ok = false;
  try {
    ok = hookViaExport();
  } catch (e) {
    console.log(TAG + ' hookViaExport skip:' + e);
  }

  if (!ok) {
    console.log(TAG + ' 未命中: libart.so 导出表无 RegisterNatives 符号(已 strip)。');
    console.log(TAG + ' 下一步1: 改走函数表 → 尝试 hookViaVtable() 第215槽');
    try { ok = hookViaVtable(); } catch (e) { console.log(TAG + ' vtable skip:' + e); }
  }

  if (!ok) {
    console.log(TAG + ' 未命中: vtable 路径也失败(JavaVM 早期未就绪)。');
    console.log(TAG + ' 下一步2: 确认已 spawn(-f) 且反检测/反frida探针先生效(壳可能拦 libart 解析);');
    console.log(TAG + ' 下一步3: 业务功能触发后(发包/登录), 在 REPL 手动调 hookViaVtable() 重挂;');
    console.log(TAG + ' 下一步4: 仍不行 → enumExports() 人工回填 RegisterNatives mangled 名到 CANDIDATES[].');
  } else {
    console.log(TAG + ' armed. 触发样本登录/发包/算签, 注册一条落一条 so!offset。');
  }
})();