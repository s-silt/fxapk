// memdex-dump.js — 内存扫描 dex magic，dump 加固壳运行时自解密的真实 DEX
// 适用：dexload-hook 抓不到（壳不走标准 ClassLoader，mmap 解密执行：梆梆/爱加密/360/乐固/通付盾等）
// 跑：frida -U -f <包名> -l memdex-dump.js -q   （壳要先解密：等 app 起来跑一会儿，或 attach 后手动多扫几次）
// 触发再扫：在 frida REPL 里调 fxDump()（本脚本暴露的全局），或等内置 3s/15s 两次自动扫
// 取证：adb pull /data/local/tmp/fx_dex/ → jadx 反编译抠真实类名/域名/key；或 fxapk analyze <apk> --extra-dex *.dex 回灌
// 改：扫不到就多等会儿再 fxDump()（壳解密有延迟）；落盘路径改 DUMP_DIR
'use strict';

var DUMP_DIR = '/data/local/tmp/fx_dex';
var seen = {}; // size:firstU32 去重

function mkdir() { try { var f = new File(DUMP_DIR + '/.keep', 'w'); f.write('x'); f.close(); } catch (e) {} }

// 校验 dex 头：magic "dex\n0xx\0" + header_size==0x70 + endian_tag==0x12345678 + file_size 合理
function looksLikeDex(base) {
  try {
    var m = base.readByteArray(8); if (m === null) return 0;
    var b = new Uint8Array(m);
    if (b[0] !== 0x64 || b[1] !== 0x65 || b[2] !== 0x78 || b[3] !== 0x0a || b[7] !== 0x00) return 0; // 'dex\n' .. \0
    if (b[4] !== 0x30) return 0; // '0'
    var fileSize = base.add(0x20).readU32();
    var headerSize = base.add(0x24).readU32();
    var endian = base.add(0x28).readU32();
    if (headerSize !== 0x70 || endian !== 0x12345678) return 0;
    if (fileSize < 0x70 || fileSize > 0x4000000) return 0; // 112B .. 64MB 合理区间
    return fileSize;
  } catch (e) { return 0; }
}

function dump(base, size) {
  try {
    var key = size + ':' + base.readU32();
    if (seen[key]) return; seen[key] = 1;
    // 兜不可读：确保整段可读
    try { Memory.protect(base, size, 'r--'); } catch (e) {}
    var data = base.readByteArray(size);
    if (data === null) { console.log('[memdex] 读不出 @ ' + base + ' size=' + size); return; }
    mkdir();
    var path = DUMP_DIR + '/dump_' + base.toString().replace(/^0x/, '') + '_' + size + '.dex';
    var f = new File(path, 'wb'); f.write(data); f.close();
    console.log('[memdex][LEAD->真实代码] dump dex ' + size + 'B @ ' + base + ' → ' + path);
  } catch (e) { console.log('[memdex] dump skip @ ' + base + ': ' + e); }
}

function scan() {
  var n = 0, found = 0;
  // 扫可读匿名/堆内存；跳过明显的系统库与 AOT 缓存，降噪降误报
  Process.enumerateRanges('r--').forEach(function (r) {
    try {
      var fp = r.file ? r.file.path : '';
      if (fp && (fp.indexOf('/system/') === 0 || fp.indexOf('/apex/') === 0 || fp.indexOf('.oat') !== -1 || fp.indexOf('.art') !== -1 || fp.indexOf('.vdex') !== -1)) return;
      if (r.size > 0x6000000) return; // 跳超大段省时间
      n++;
      Memory.scanSync(r.base, r.size, '64 65 78 0a').forEach(function (hitObj) {
        var sz = looksLikeDex(hitObj.address);
        if (sz) { found++; dump(hitObj.address, sz); }
      });
    } catch (e) {}
  });
  console.log('[memdex] 扫描完成：' + n + ' 段，命中 dex ' + found + ' 处（累计 dump ' + Object.keys(seen).length + '）');
}

// 暴露给 REPL：壳解密有延迟，可手动多扫
globalThis.fxDump = scan;

// 自动两次（覆盖大多数壳的解密时机），不够再手动 fxDump()
setTimeout(function () { console.log('[memdex] 第 1 次扫描（3s）…'); scan(); }, 3000);
setTimeout(function () { console.log('[memdex] 第 2 次扫描（15s）…'); scan(); }, 15000);
console.log('[memdex] ready —— 自动扫 2 次（3s/15s）；壳解密慢就在 REPL 里手动调 fxDump()');
