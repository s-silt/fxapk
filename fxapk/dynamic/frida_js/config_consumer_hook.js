// fxapk-config-consumer-v1: bounded, opt-in byte[] -> UTF-8 String -> org.json -> Socket.
// No value-based origin matching, general taint, request replay, or Go PC hooks.
(function (root) {
    'use strict';
    var coverage = root.__fxapkProbeCoverage;
    if (!coverage) return;
    var entries = [], sequence = 0, events = 0, total = 0, stopped = false, inspecting = false;
    var MAX_REFS = 256, MAX_EVENTS = 256, MAX_BODY = 512 * 1024, MAX_TOTAL = 5 * 1024 * 1024;
    var env, JString, JObject, JArray, Digest, objectGet, arrayGet;

    function same(a, b) {
        return a !== null && b !== null && a.$h !== undefined && b.$h !== undefined && env().isSameObject(a.$h, b.$h);
    }
    function exact(object, name) { return String(object.getClass().getName()) === name; }
    function drop() {
        stopped = true;
        coverage.drop('config_consumer', 'events');
        entries.forEach(function (e) { try { e.ref.$dispose(); } catch (_) {} });
        entries = [];
    }
    function inspect(fn) {
        if (stopped || inspecting) return;
        inspecting = true;
        try { fn(); } catch (_) { drop(); } finally { inspecting = false; }
    }
    function lookup(role, object) {
        for (var i = 0; i < entries.length; i++)
            if (entries[i].role === role && same(entries[i].ref, object)) return entries[i];
        return null;
    }
    function retain(role, object, data) {
        if (entries.length >= MAX_REFS) { drop(); return null; }
        var item = {role: role, ref: Java.retain(object), data: data, id: 'object-' + (++sequence)};
        entries.push(item);
        return item;
    }
    function hash(bytes) {
        var digest = Digest.getInstance('SHA-256').digest(bytes), text = '';
        for (var i = 0; i < digest.length; i++) text += ('0' + (digest[i] & 255).toString(16)).slice(-2);
        return text;
    }
    function host(value) {
        var text = String(value).toLowerCase();
        return text.length <= 253 && /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/.test(text) && text.indexOf('.') > 0 ? text : null;
    }
    function emit(row) {
        if (stopped || events >= MAX_EVENTS) { drop(); return null; }
        row.type = 'fxapk-addressing-event-v1';
        row.observer_kind = 'org_json_socket';
        row.sequence = ++sequence;
        row.event_id = 'event-' + row.sequence;
        row.observed_at = new Date().toISOString();
        row.source_binding = 'direct_object_origin';
        try { send(row); events++; return row; } catch (_) { drop(); return null; }
    }
    function snapshot(object, sha) {
        var pending = [{object: object, path: '$', depth: 0}], seen = [], leaves = [];
        while (pending.length) {
            var node = pending.pop(), value = node.object;
            if (node.depth > 16 || seen.length + leaves.length > 128) throw new Error('snapshot_budget');
            if (JString.class.isInstance(value)) {
                if (host(value)) leaves.push({ref: value, path: node.path, parent: node.parent, key: node.key});
                continue;
            }
            if (seen.some(function (other) { return same(other, value); })) throw new Error('aliased_json');
            seen.push(value);
            if (JObject.class.isInstance(value)) {
                if (!exact(value, 'org.json.JSONObject')) throw new Error('custom_json_class');
                value = Java.cast(value, JObject);
                var iterator = value.keys(), keys = [];
                while (iterator.hasNext()) {
                    if (keys.length >= 128) throw new Error('key_budget');
                    keys.push(String(iterator.next()));
                }
                keys.sort().reverse().forEach(function (key) {
                    var child = objectGet.call(value, key);
                    if (child !== null && (JString.class.isInstance(child) || JObject.class.isInstance(child) || JArray.class.isInstance(child))) {
                        var suffix = /^[A-Za-z_][A-Za-z0-9_]*$/.test(key) ? '.' + key : '[' + JSON.stringify(key) + ']';
                        pending.push({object: child, path: node.path + suffix, depth: node.depth + 1, parent: value, key: key});
                    }
                });
            } else if (JArray.class.isInstance(value)) {
                if (!exact(value, 'org.json.JSONArray')) throw new Error('custom_json_class');
                value = Java.cast(value, JArray);
                if (value.length() > 128) throw new Error('array_budget');
                for (var n = value.length() - 1; n >= 0; n--) {
                    var child = arrayGet.call(value, n);
                    if (child !== null && (JString.class.isInstance(child) || JObject.class.isInstance(child) || JArray.class.isInstance(child)))
                        pending.push({object: child, path: node.path + '[' + n + ']', depth: node.depth + 1, parent: value, key: String(n)});
                }
            }
        }
        if (leaves.some(function (leaf, i) { return leaves.some(function (other, j) { return i !== j && same(leaf.ref, other.ref); }); }))
            throw new Error('ambiguous_field_object');
        leaves.sort(function (a, b) { return a.path < b.path ? -1 : a.path > b.path ? 1 : 0; });
        leaves.forEach(function (leaf) {
            if (lookup('field', leaf.ref)) throw new Error('reused_parser_object');
            var container = lookup('container', leaf.parent) || retain('container', leaf.parent, {});
            if (container && !stopped) retain('field', leaf.ref, {sha: sha, path: leaf.path, parent: container.ref, key: leaf.key});
        });
    }
    function readField(container, key, value) {
        var field = lookup('field', value);
        if (!field || !same(field.data.parent, container) || field.data.key !== String(key)) return;
        if (lookup('read', value)) { lookup('read', value).data.ambiguous = true; return; }
        var row = emit({kind: 'config_field_read', artifact_sha256: field.data.sha, field_path: field.data.path,
                        value: host(value), object_id: field.id}); // leak-scan: allow JavaScript object property, not a hostname
        if (row) retain('read', value, {event: row, ambiguous: false});
    }
    root.__fxapkConfigConsumer = {
        observeBody: function (meta, bytes) {
            inspect(function () {
                if (!Digest || bytes === null || bytes.length > MAX_BODY || meta.declared_length !== bytes.length || bytes.$h === undefined) return;
                if (total + bytes.length > MAX_TOTAL || lookup('body', bytes)) { drop(); return; }
                total += bytes.length;
                retain('body', bytes, {sha: hash(bytes)});
                coverage.trigger('config_consumer', 'body_origin');
            });
        }
    };
    coverage.perform('config_consumer', function () {
        var installed = [], converters = [], returnConverters = [];
        try {
            env = function () { return Java.vm.getEnv(); };
            if (typeof env().isSameObject !== 'function') throw new Error('identity_api_unavailable');
            JString = Java.use('java.lang.String'); JObject = Java.use('org.json.JSONObject');
            JArray = Java.use('org.json.JSONArray'); Digest = Java.use('java.security.MessageDigest');
            var Socket = Java.use('java.net.Socket');
            var stringInit = JString.$init.overload('[B', 'java.lang.String');
            var factory = null;
            try { factory = Java.use('java.lang.StringFactory'); } catch (_) {}
            var stringMethod = factory ? factory.newStringFromBytes.overload('[B', 'java.lang.String') : stringInit;
            var jsonInit = JObject.$init.overload('java.lang.String');
            objectGet = JObject.get.overload('java.lang.String'); arrayGet = JArray.get.overload('int');
            var socketInit = Socket.$init.overload('java.lang.String', 'int');
            var methods = [stringMethod, jsonInit, objectGet, arrayGet, socketInit];
            // Frida unboxes String arguments by default. Use per-method converters,
            // never mutate shared type descriptors or reconstruct application strings.
            methods.forEach(function (method) {
                if (method.implementation || method.argumentTypes !== method.argumentTypes || !Array.isArray(method.argumentTypes))
                    throw new Error('incompatible_or_owned_hook');
                method.argumentTypes.forEach(function (type, i) {
                    if (type.className !== 'java.lang.String') return;
                    if (type.type !== 'pointer' || typeof type.fromJni !== 'function' || typeof type.toJni !== 'function')
                        throw new Error('unsupported_string_converter');
                    var custom = Object.assign({}, type, {fromJni: function (handle) {
                        return handle.isNull() ? null : Java.cast(handle, JString);
                    }});
                    converters.push({method: method, index: i, original: type});
                    method.argumentTypes[i] = custom;
                    if (method.argumentTypes[i] !== custom) throw new Error('converter_not_retained');
                });
            });
            // ART redirects String constructors to StringFactory. Keep its exact
            // returned Java String, too. Fail closed if this bridge shares the
            // descriptor with unrelated String methods or will not retain it.
            if (factory) {
                var resultType = stringMethod.returnType;
                if (resultType.className !== 'java.lang.String' || resultType.type !== 'pointer'
                        || typeof resultType.fromJni !== 'function' || typeof resultType.toJni !== 'function'
                        || resultType === JString.valueOf.overload('java.lang.Object').returnType
                        || resultType === JString.toString.overload().returnType
                        || methods.some(function (method) { return method.argumentTypes.indexOf(resultType) >= 0; }))
                    throw new Error('unsupported_return_converter');
                returnConverters.push({type: resultType, original: resultType.fromJni});
                var fromJni = function (handle) { return handle.isNull() ? null : Java.cast(handle, JString); };
                resultType.fromJni = fromJni;
                if (stringMethod.returnType.fromJni !== fromJni) throw new Error('return_converter_not_retained');
            }
            function install(method, hook, observe) {
                coverage.attempted('config_consumer', hook);
                method.implementation = function () {
                    var self = this, args = Array.prototype.slice.call(arguments);
                    var result = method.call.apply(method, [self].concat(args));
                    inspect(function () { observe(self, args, result); });
                    return result;
                };
                installed.push(method);
                coverage.installed('config_consumer', hook);
            }
            install(stringMethod, 'string_origin', function (self, args, result) {
                var body = lookup('body', args[0]);
                if (!body || !/^utf-?8$/i.test(String(args[1]))) return;
                var text = factory ? result : self;
                if (hash(args[0]) !== body.data.sha || hash(text.getBytes('UTF-8')) !== body.data.sha) return;
                retain('text', text, body.data);
                coverage.trigger('config_consumer', 'string_origin');
            });
            install(jsonInit, 'json_origin', function (self, args) {
                var text = lookup('text', args[0]);
                if (text) snapshot(self, text.data.sha);
            });
            install(objectGet, 'field_read', function (self, args, result) { if (result !== null) readField(self, args[0], result); });
            install(arrayGet, 'field_read', function (self, args, result) { if (result !== null) readField(self, args[0], result); });
            install(socketInit, 'socket_argument', function (self, args) {
                var read = lookup('read', args[0]);
                if (!read || read.data.ambiguous || !exact(self, 'java.net.Socket') || !self.isConnected() || self.getPort() !== args[1]) return;
                var row = read.data.event;
                emit({kind: 'network_argument', value: host(args[0]), origin_event_id: row.event_id,
                      origin_object_id: row.object_id, protocol: 'tcp', port: args[1], host: host(args[0]),
                      host_status: 'socket_argument', sni: null, sni_status: 'not_applicable', socket_connected: true,
                      peer_ip: String(self.getInetAddress().getHostAddress()), network_api: 'java.net.Socket.<init>(java.lang.String,int)'});
                coverage.trigger('config_consumer', 'socket_argument');
            });
        } catch (_) {
            installed.forEach(function (method) { try { method.implementation = null; } catch (_) {} });
            converters.forEach(function (c) { c.method.argumentTypes[c.index] = c.original; });
            returnConverters.forEach(function (c) { c.type.fromJni = c.original; });
            drop();
            coverage.registrationError('config_consumer', 'events');
        }
    });
})(globalThis);
