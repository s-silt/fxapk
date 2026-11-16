(function (root) {
    'use strict';
    if (root.__fxapkProbeCoverage) return;

    var hooks = {
        config_body: ['body_bytes', 'response', 'events'],
        config_consumer: ['body_origin', 'string_origin', 'json_origin', 'field_read', 'socket_argument', 'events'],
        crypto: ['cipher_init', 'cipher_final', 'secret_key', 'iv_spec', 'mac_init', 'webview_load_url', 'events'],
        jsbridge: ['add_interface', 'dsbridge_call', 'events'],
        sensitive_api: ['sensitive_api', 'events'],
        okhttp: ['execute', 'proceed', 'events'],
        sqlcipher: ['cipher_open', 'sqlite_open', 'events'],
        clipboard: ['primary_clip', 'get_text', 'coerce_text', 'events'],
        accessibility: ['event_package', 'node_package', 'dispatch_gesture', 'global_action', 'screencapture', 'events'],
        java_bridge: []
    };
    var families = Object.keys(hooks);
    var validStatuses = [
        'installed', 'unsupported', 'partial', 'installation_failed', 'triggered',
        'dropped', 'truncated', 'api_unavailable', 'registration_failed',
        'ready', 'java_unavailable'
    ];
    var reasons = ['java_unavailable', 'api_unavailable', 'registration_failed'];
    var states = {};
    var messageCount = 0;
    var MAX_MESSAGES = 256;
    var MAX_KNOWN = 128;
    var bridgeReported = false;

    function validFamily(family) {
        return typeof family === 'string' && families.indexOf(family) >= 0;
    }
    function validHook(family, hook) {
        return validFamily(family) && typeof hook === 'string' &&
            hooks[family].indexOf(hook) >= 0;
    }
    function stateFor(family) {
        if (!validFamily(family) || family === 'java_bridge') return null;
        if (!states[family]) {
            states[family] = {
                attempted: 0, installed: 0, failed: 0, unavailable: 0,
                registrationSent: false, triggers: {}, drops: {}, truncations: {},
                reasons: {}, overflow: false
            };
        }
        return states[family];
    }
    function emit(family, status, hook, reason) {
        if (!validFamily(family) || validStatuses.indexOf(status) < 0 ||
                (hook !== undefined && !validHook(family, hook)) ||
                (reason !== undefined && reasons.indexOf(reason) < 0) ||
                messageCount >= MAX_MESSAGES) return;
        var payload = {type: 'apkscan-probe-status', family: family, status: status};
        if (hook !== undefined) payload.hook = hook;
        if (reason !== undefined) payload.reason = reason;
        if (status === 'dropped') {
            payload.dropped_count_lower_bound = 1;
            payload.drop_count_semantics = 'lower_bound';
        }
        if (status === 'truncated') payload.event_completeness = 'not_attested';
        try {
            send(payload);
            messageCount += 1;
        } catch (_) {}
    }
    function bridgeStatus(ready) {
        if (bridgeReported) return;
        bridgeReported = true;
        emit('java_bridge', ready ? 'ready' : 'java_unavailable',
            undefined, ready ? undefined : 'java_unavailable');
    }
    function finish(family) {
        var state = stateFor(family);
        if (!state || state.registrationSent) return;
        state.registrationSent = true;
        var status;
        if (state.attempted === 0 && state.failed === 0) {
            status = 'unsupported';
        } else if (state.failed > 0 || state.attempted > state.installed) {
            status = state.installed > 0 ? 'partial' : 'installation_failed';
        } else {
            status = 'installed';
        }
        emit(family, status);
    }
    function recordReason(family, hook, reason) {
        var state = stateFor(family);
        if (!state || !validHook(family, hook)) return;
        var key = hook + ':' + reason;
        var known = Object.keys(state.reasons).length;
        if (!state.reasons[key] && known >= MAX_KNOWN) {
            state.overflow = true;
            return;
        }
        if (state.reasons[key]) return;
        state.reasons[key] = true;
        if (reason === 'registration_failed') state.failed += 1;
        else state.unavailable += 1;
        emit(family, reason, hook, reason);
    }

    root.__fxapkProbeCoverage = {
        perform: function (family, callback) {
            var state = stateFor(family);
            if (!state || typeof callback !== 'function') return;
            var available = false;
            try {
                available = typeof Java !== 'undefined' && !!Java && !!Java.available;
            } catch (_) {}
            if (!available) {
                bridgeStatus(false);
                recordReason(family, 'events', 'java_unavailable');
                finish(family);
                return;
            }
            try {
                Java.perform(function () {
                    bridgeStatus(true);
                    try {
                        callback();
                    } catch (_) {
                        if (state.attempted > state.installed) {
                            recordReason(family, 'events', 'registration_failed');
                        } else {
                            recordReason(family, 'events', 'api_unavailable');
                        }
                    } finally {
                        finish(family);
                    }
                });
            } catch (_) {
                recordReason(family, 'events', 'registration_failed');
                finish(family);
            }
        },
        attempted: function (family, hook) {
            var state = stateFor(family);
            if (!state || !validHook(family, hook)) return;
            if (state.attempted >= MAX_KNOWN) {
                state.overflow = true;
                state.failed += 1;
                return;
            }
            state.attempted += 1;
        },
        installed: function (family, hook) {
            var state = stateFor(family);
            if (!state || !validHook(family, hook)) return;
            if (state.installed >= MAX_KNOWN) {
                state.overflow = true;
                state.failed += 1;
                return;
            }
            state.installed += 1;
        },
        registrationError: function (family, hook) {
            var state = stateFor(family);
            if (!state || !validHook(family, hook)) return;
            recordReason(
                family,
                hook,
                state.attempted > state.installed ? 'registration_failed' : 'api_unavailable'
            );
        },
        trigger: function (family, hook) {
            var state = stateFor(family);
            if (!state || !validHook(family, hook) || state.triggers[hook]) return;
            if (Object.keys(state.triggers).length >= MAX_KNOWN) {
                state.overflow = true;
                return;
            }
            state.triggers[hook] = true;
            emit(family, 'triggered', hook);
        },
        drop: function (family, hook) {
            var state = stateFor(family);
            if (!state || !validHook(family, hook) || state.drops[hook]) return;
            if (Object.keys(state.drops).length >= MAX_KNOWN) {
                state.overflow = true;
                return;
            }
            state.drops[hook] = true;
            emit(family, 'dropped', hook);
        },
        truncated: function (family, hook) {
            var state = stateFor(family);
            if (!state || !validHook(family, hook) || state.truncations[hook]) return;
            if (Object.keys(state.truncations).length >= MAX_KNOWN) {
                state.overflow = true;
                return;
            }
            state.truncations[hook] = true;
            emit(family, 'truncated', hook);
        }
    };
})(globalThis);
