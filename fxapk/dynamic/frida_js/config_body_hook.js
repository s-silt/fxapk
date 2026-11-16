// Opt-in observer: copies bytes only after the app's own ResponseBody.bytes() call.
// No peek, stream drain, request replay, or replacement return value.
(function () {
    'use strict';
    var coverage = (typeof globalThis !== 'undefined' && globalThis.__fxapkProbeCoverage) || {
        perform: function (_family, callback) {
            if (typeof Java !== 'undefined' && Java.available) Java.perform(callback);
        },
        attempted: function () {}, installed: function () {}, registrationError: function () {},
        trigger: function () {}, drop: function () {}, truncated: function () {}
    };
    var tracked = [], sent = 0, total = 0;
    var LIMIT = 512 * 1024, TOTAL = 5 * 1024 * 1024, COUNT = 40;
    function emit(meta, bytes) {
        if (sent >= COUNT || total >= TOTAL) { coverage.drop('config_body', 'events'); return; }
        var payload = Object.assign({type: 'fxapk-config-body-v1'}, meta);
        payload.observed_at = new Date().toISOString();
        payload.body_complete = bytes !== null && bytes.length === meta.declared_length;
        try {
            if (bytes === null) send(payload);
            else {
                var length = Math.min(bytes.length, LIMIT, TOTAL - total);
                var copy = new Uint8Array(length);
                for (var i = 0; i < length; i++) copy[i] = bytes[i] & 255;
                if (length !== bytes.length) {
                    payload.body_complete = false;
                    coverage.truncated('config_body', 'events');
                }
                send(payload, copy.buffer);
                total += length;
            }
            sent += 1;
        } catch (_) { coverage.drop('config_body', 'events'); }
    }
    coverage.perform('config_body', function () {
        try {
            var Body = Java.use('okhttp3.ResponseBody');
            var bytesMethod = Body.bytes.overload();
            coverage.attempted('config_body', 'body_bytes');
            bytesMethod.implementation = function () {
                var bytes = bytesMethod.call(this);
                coverage.trigger('config_body', 'body_bytes');
                try {
                    for (var i = 0; i < tracked.length; i++) {
                        if (Java.vm.getEnv().isSameObject(this.$h, tracked[i].body.$h)) {
                            emit(tracked[i].meta, bytes);
                            if (globalThis.__fxapkConfigConsumer) globalThis.__fxapkConfigConsumer.observeBody(tracked[i].meta, bytes);
                            tracked[i].body.$dispose();
                            tracked.splice(i, 1);
                            break;
                        }
                    }
                } catch (_) {}
                return bytes;
            };
            coverage.installed('config_body', 'body_bytes');
            var hookedResponse = false, attemptedResponse = false;
            ['okhttp3.RealCall', 'okhttp3.internal.connection.RealCall'].forEach(function (name) {
                if (hookedResponse) return;
                try {
                    var Call = Java.use(name);
                    // OkHttp 4 exposes Kotlin's internal method with a module suffix.
                    var responseMethod = Call.getResponseWithInterceptorChain || Call['getResponseWithInterceptorChain$okhttp'];
                    if (!responseMethod) return;
                    var method = responseMethod.overload();
                    attemptedResponse = true;
                    coverage.attempted('config_body', 'response');
                    method.implementation = function () {
                        var response = method.call(this);
                        coverage.trigger('config_body', 'response');
                        try {
                            if (tracked.length < COUNT && sent < COUNT) {
                                var request = response.request(), headers = response.headers(), values = {};
                                for (var i = 0; i < Math.min(headers.size(), 64); i++)
                                    values[String(headers.name(i))] = String(headers.value(i)).slice(0, 4096);
                                var body = response.body();
                                var meta = {source_url: String(request.url()).slice(0, 8192),
                                    method: String(request.method()), response_headers: values,
                                    declared_length: body === null ? -1 : Number(body.contentLength())};
                                emit(meta, null); // Unread/streamed/string bodies remain explicitly incomparable.
                                if (body !== null) tracked.push({body: Java.retain(body), meta: meta});
                            } else coverage.drop('config_body', 'events');
                        } catch (_) {}
                        return response;
                    };
                    hookedResponse = true;
                    coverage.installed('config_body', 'response');
                } catch (_) {
                    if (attemptedResponse) coverage.registrationError('config_body', 'response');
                }
            });
            if (!hookedResponse) {
                if (!attemptedResponse) coverage.attempted('config_body', 'response');
                coverage.registrationError('config_body', 'response');
            }
        } catch (_) { coverage.registrationError('config_body', 'body_bytes'); }
    });
})();
