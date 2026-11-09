'use strict';
const vm = require('vm'), fs = require('fs'), crypto = require('crypto'), assert = require('assert');
const scenario = process.argv[3], events = [], statuses = [], originalError = new Error('original socket exception');
let activeCall = null, originalCallsOnce = true, argumentIdentityPreserved = true, returnPreserved = true;
class Ref { constructor(object) { this.object = object; } isNull() { return false; } }
class JBase {
    constructor(name) { this.$className = name; this.$h = new Ref(this); }
    $dispose() {}
    getClass() { return {getName: () => this.$className}; }
}
class JString extends JBase {
    constructor(text = '') { super('java.lang.String'); this.text = text; }
    toString() { return this.text; }
    getBytes() { return bytes(Buffer.from(this.text, 'utf8')); }
}
class JObject extends JBase {
    constructor(map = {}) { super('org.json.JSONObject'); this.map = map; }
    keys() { const list = Object.keys(this.map).sort(); let i = 0; return {hasNext: () => i < list.length, next: () => new JString(list[i++])}; }
}
class JArray extends JBase {
    constructor(items) { super('org.json.JSONArray'); this.items = items; }
    length() { return this.items.length; }
}
class Socket extends JBase {
    constructor() { super('java.net.Socket'); this.port = 0; this.connected = false; }
    isConnected() { return this.connected; }
    getPort() { return this.port; }
    getInetAddress() { return {getHostAddress: () => '192.0.2.1'}; }
}
function bytes(data) { const array = Array.from(data); array.$h = new Ref(array); array.$dispose = () => {}; return array; }
function wrap(value) {
    if (typeof value === 'string') return new JString(value);
    if (Array.isArray(value)) return new JArray(value.map(wrap));
    if (value && typeof value === 'object') return new JObject(Object.fromEntries(Object.entries(value).map(([k, v]) => [k, wrap(v)])));
    return value;
}
function objectWrapper(value) {
    if (!(value instanceof JObject) && !(value instanceof JArray)) return value;
    return {$h: value.$h, getClass: () => value.getClass(), $dispose: () => {}};
}
function method(types, original, returnsString = false) {
    const value = {implementation: null, argumentTypes: types.map(name => ({className: name, type: 'pointer',
        fromJni: obj => name === 'java.lang.String' ? obj.object.text : obj.object,
        toJni: obj => name === 'java.lang.String' && typeof obj === 'string' ? new JString(obj) : obj}))};
    value.returnType = returnsString ? {className: 'java.lang.String', type: 'pointer',
        fromJni: ref => ref.object.text, toJni: obj => typeof obj === 'string' ? new JString(obj) : obj} : {className: 'void'};
    value.nativeCall = (receiver, ...nativeArgs) => {
        if (activeCall && activeCall.method === value) {
            activeCall.count++;
            nativeArgs.forEach((arg, i) => { if (arg !== activeCall.args[i]) argumentIdentityPreserved = false; });
        }
        const returned = original(receiver, ...nativeArgs);
        if (returnsString && activeCall && activeCall.method === value) activeCall.returned = returned;
        return returned;
    };
    value.call = (receiver, ...args) => {
        const returned = value.nativeCall(receiver, ...args.map((a, i) => value.argumentTypes[i].toJni(a)));
        return returnsString ? value.returnType.fromJni(returned.$h) : returned;
    };
    return value;
}
const stringInit = method(['[B', 'java.lang.String'], (self, raw) => { self.text = Buffer.from(raw).toString('utf8'); });
const stringFactory = method(['[B', 'java.lang.String'], (_self, raw) => new JString(Buffer.from(raw).toString('utf8')), true);
const jsonInit = method(['java.lang.String'], (self, text) => { self.map = wrap(JSON.parse(String(text))).map; });
const objectGet = method(['java.lang.String'], (self, key) => objectWrapper(self.map[String(key)]));
const arrayGet = method(['int'], (self, index) => objectWrapper(self.items[index]));
const socketInit = method(['java.lang.String', 'int'], (self, host, port) => {
    if (scenario === 'socket_failure') throw originalError;
    self.connected = true; self.port = port; self.originalHost = host;
});
const methods = [stringInit, stringFactory, jsonInit, objectGet, arrayGet, socketInit];
const classes = {
    'java.lang.String': {$init: {overload: (...args) => { assert.deepStrictEqual(args, ['[B', 'java.lang.String']); return stringInit; }}, class: {isInstance: v => v instanceof JString},
        valueOf: {overload: () => ({returnType: {}})}, toString: {overload: () => ({returnType: {}})}},
    'org.json.JSONObject': {$init: {overload: () => jsonInit}, get: {overload: () => objectGet}, class: {isInstance: v => v && v.$h && v.$h.object instanceof JObject}},
    'org.json.JSONArray': {get: {overload: () => arrayGet}, class: {isInstance: v => v && v.$h && v.$h.object instanceof JArray}},
    'java.net.Socket': {$init: {overload: () => socketInit}},
    'java.security.MessageDigest': {getInstance: () => ({digest: raw => Array.from(crypto.createHash('sha256').update(Buffer.from(raw)).digest())})}
};
if (scenario.startsWith('android_factory')) classes['java.lang.StringFactory'] = {newStringFromBytes: {overload: () => stringFactory}};
if (scenario === 'android_factory_shared') classes['java.lang.String'].toString.overload = () => ({returnType: stringFactory.returnType});
const coverage = {perform: (_family, fn) => fn(), attempted: () => {}, installed: () => {}, trigger: () => {},
    drop: () => statuses.push('dropped'), registrationError: () => statuses.push('registration_failed')};
const context = {__fxapkProbeCoverage: coverage, Java: {
    use: name => { if (!classes[name]) throw Error('unsupported class'); return classes[name]; },
    cast: ref => ref.object || ref.$h.object, retain: object => object,
    vm: {getEnv: () => scenario === 'unsupported_bridge' ? {} : {isSameObject: (a, b) => a.object === b.object}}
}, send: row => { if (scenario === 'send_failure') throw Error('transport failure'); events.push(row); }};
vm.createContext(context); vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), context);
function invoke(method, receiver, ...args) {
    const before = activeCall, current = {method, args, count: 0}; activeCall = current;
    try {
        const marshaled = args.map((a, i) => a && a.$h ? method.argumentTypes[i].fromJni(a.$h) : a);
        let result = method.implementation ? method.implementation.apply(receiver, marshaled) : method.nativeCall(receiver, ...args);
        if (method.implementation && method.returnType.className === 'java.lang.String') {
            result = method.returnType.toJni(result);
            returnPreserved = returnPreserved && result === current.returned;
        }
        return result;
    } finally { originalCallsOnce = originalCallsOnce && current.count === 1; activeCall = before; }
}
const raw = bytes(Buffer.from(scenario === 'nested_array' ? '{"items":[{"host":"api.example.test"}]}' : '{"host":"api.example.test"}'));
if (scenario === 'budget') for (let i = 0; i < 300; i++) context.__fxapkConfigConsumer.observeBody({declared_length: raw.length}, bytes(raw));
context.__fxapkConfigConsumer.observeBody({declared_length: raw.length + (scenario === 'prefix_body' ? 1 : 0)}, raw);
if (scenario === 'mutated_bytes') raw[9] = 98;
let text = new JString();
const json = new JObject(), socket = new Socket();
if (scenario === 'json_subclass') json.$className = 'test.example.CustomJSONObject';
if (scenario === 'socket_subclass') socket.$className = 'test.example.CustomSocket';
if (scenario.startsWith('android_factory')) text = invoke(stringFactory, null, raw, new JString('UTF-8'));
else invoke(stringInit, text, raw, new JString('UTF-8'));
if (scenario === 'android_factory_clone') text = new JString(String(text));
invoke(jsonInit, json, text);
if (scenario === 'changed_field') json.map.host = new JString(String(json.map.host));
const container = scenario === 'nested_array' ? json.map.items.items[0] : scenario === 'transplanted_field' ? new JObject({host: json.map.host}) : json;
let value = invoke(objectGet, container, new JString('host'));
returnPreserved = returnPreserved && value === container.map.host;
if (scenario === 'repeated_read') invoke(objectGet, json, new JString('host'));
if (scenario === 'different_string_object') value = new JString(String(value));
try { invoke(socketInit, socket, value, 443); assert.notStrictEqual(scenario, 'socket_failure'); }
catch (error) { if (scenario !== 'socket_failure' || error !== originalError) throw error; }
assert.strictEqual(socket.originalHost === value || scenario === 'socket_failure', true);
if (scenario === 'unsupported_bridge' || scenario === 'android_factory_shared') assert(methods.every(m => m.implementation === null));
console.log(JSON.stringify({events, statuses, original_calls_once: originalCallsOnce,
    argument_identity_preserved: argumentIdentityPreserved, return_and_exception_preserved: returnPreserved}));
