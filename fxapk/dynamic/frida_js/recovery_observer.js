// Observation only. No replacements, return-value changes, bypasses or lazy Java bridge.
// The host supplies bounded CONFIG, persists every error and owns session teardown.
'use strict';
let sequence = 0, emitted = 0, bytes = 0;
const attached = new Set();
function event(type, fields, blob) {
  if (++emitted > CONFIG.event_limit) return;
  send(Object.assign({type: type, seq: ++sequence, run_id: CONFIG.run_id}, fields || {}), blob);
}
function error(code) { event('error', {reason_code: code}); }
function boundedString(address, limit) {
  // Frida-owned registration strings may be cloaked from range enumeration.
  // Stop at NUL without reading a whole arbitrary buffer past the string.
  for (let length = 0; length < limit; length++) {
    if (address.add(length).readU8() === 0) return address.readUtf8String(length);
  }
  throw new Error('unterminated');
}
function observeFunction(address, name, signature, module) {
  if (attached.has(address.toString()) || attached.size >= 128) return;
  if (CONFIG.modules.length && CONFIG.modules.indexOf(module) === -1) return;
  attached.add(address.toString());
  try {
    Interceptor.attach(address, {
      onEnter(args) {
        event('jni_call', {phase: 'enter', name: name, signature: signature,
          address: address.toString(), module: module, thread_id: this.threadId,
          arguments: [args[0].toString(), args[1].toString(), args[2].toString(), args[3].toString()]});
      },
      onLeave(value) {
        event('jni_call', {phase: 'leave', name: name, address: address.toString(),
          module: module, thread_id: this.threadId, return_pointer: value.toString()});
      }
    });
    event('hook_installed', {hook: 'jni_function', module: module, address: address.toString()});
  } catch (_) { error('jni_function_attach_failed'); }
}
event('start', {pid: Process.id, arch: Process.arch, frida_version: Frida.version}); // leak-scan: allow Frida JavaScript property access, not network host literals.
if (CONFIG.jni) {
  try {
    const art = Process.getModuleByName('libart.so');
    const symbols = art.enumerateSymbols().filter(s => s.name.indexOf('RegisterNatives') !== -1 && s.name.indexOf('JNIEnv') !== -1 && s.type === 'function');
    const seen = new Set();
    symbols.slice(0, 32).forEach(symbol => {
      if (seen.has(symbol.address.toString())) return;
      seen.add(symbol.address.toString());
      Interceptor.attach(symbol.address, {onEnter(args) {
        let phase = 'count';
        try {
          const count = args[3].toInt32();
          if (count < 0 || count > 256) { error('jni_registration_budget'); return; }
          for (let i = 0; i < count; i++) {
            phase = 'method_row';
            const row = args[2].add(i * Process.pointerSize * 3);
            phase = 'name';
            const name = boundedString(row.readPointer(), 256);
            phase = 'signature';
            const signature = boundedString(row.add(Process.pointerSize).readPointer(), 512);
            phase = 'function';
            const address = row.add(2 * Process.pointerSize).readPointer();
            const owner = Process.findModuleByAddress(address);
            const module = owner ? owner.name : 'unmapped';
            event('jni_registration', {name: name, signature: signature, address: address.toString(),
              module: module, module_offset: owner ? address.sub(owner.base).toString() : null});
            observeFunction(address, name, signature, module);
          }
        } catch (failure) { event('error', {reason_code: 'jni_registration_read_failed', phase: phase,
          exception: String(failure).slice(0, 160), symbol: symbol.name}); }
      }});
      event('hook_installed', {hook: 'RegisterNatives', address: symbol.address.toString()});
    });
    if (!seen.size) error('register_natives_symbol_missing');
  } catch (_) { error('libart_or_registration_unavailable'); }
  CONFIG.modules.forEach(name => {
    try {
      const module = Process.getModuleByName(name);
      module.enumerateExports().filter(e => e.type === 'function' && e.name.startsWith('Java_'))
        .slice(0, 128).forEach(e => observeFunction(e.address, e.name, 'exported_signature_unknown', name));
    } catch (_) { error('requested_module_unavailable'); }
  });
}
let dexCount = 0;
CONFIG.ranges.forEach(range => {
  try {
    const base = ptr(range.address);
    Memory.scanSync(base, range.size, '64 65 78 0a 30 ?? ?? 00').slice(0, 32).forEach(hit => {
      const size = hit.address.add(32).readU32();
      if (size < 112 || size > CONFIG.max_dex_size || hit.address.add(size).compare(base.add(range.size)) > 0) {
        error('dex_outside_selected_range'); return;
      }
      if (dexCount >= 32 || bytes + size > CONFIG.byte_limit) { error('dex_capture_budget'); return; }
      const raw = hit.address.readByteArray(size);
      if (raw === null) { error('dex_read_failed'); return; }
      bytes += size;
      event('dex', {address: hit.address.toString(), size: size, ordinal: dexCount++}, raw);
    });
  } catch (_) { error('memory_scan_failed'); }
});
event('scan_complete', {dex_count: dexCount, captured_bytes: bytes});
rpc.exports = {finish() {
  // Always deliver an end frame; an exhausted event budget remains visible.
  const truncated = emitted >= CONFIG.event_limit;
  send({type: 'end', seq: ++sequence, run_id: CONFIG.run_id, truncated: truncated});
  return {truncated: truncated, event_count: sequence, dex_count: dexCount};
}};
