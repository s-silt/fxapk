
// 取证用途：对取证样本自身在分析机上做运行时观测，产出端点/密钥/独特串等线索，不面向任何第三方基础设施。
// apkscan 运行时敏感 API 追踪（best-effort）：记录设备标识/短信/通讯录/剪贴板等实际调用。
var _coverage = (typeof globalThis !== 'undefined' && globalThis.__fxapkProbeCoverage) || {
    perform: function (_family, callback) {
        try { if (typeof Java !== 'undefined' && (!('available' in Java) || Java.available)) Java.perform(callback); } catch (_) {}
    },
    attempted: function () {}, installed: function () {}, registrationError: function () {},
    trigger: function () {}, drop: function () {}, truncated: function () {}
};
_coverage.perform('sensitive_api', function () {
    var _api_count = 0;
    function apiEmit(api, ret) {
        try {
            if (_api_count >= 2000) { _coverage.drop('sensitive_api', 'events'); return; }
            _api_count += 1;
            var rs = null;
            try {
                if (ret !== null && ret !== undefined) {
                    var text = '' + ret;
                    if (text.length > 128) _coverage.truncated('sensitive_api', 'events');
                    rs = text.slice(0, 128);
                }
            } catch (e) {}
            send({type: 'apkscan-api', event: 'call', api: api, result_summary: rs, ts: Date.now()});
        } catch (e) {}
    }
    function hook(cls, method, label) {
        try {
            var C = Java.use(cls);
            if (!C[method]) {
                _coverage.registrationError('sensitive_api', 'sensitive_api');
                return;
            }
            if (!C[method].overloads || C[method].overloads.length === 0) {
                _coverage.registrationError('sensitive_api', 'sensitive_api');
                return;
            }
            C[method].overloads.forEach(function (ov) {
                _coverage.attempted('sensitive_api', 'sensitive_api');
                ov.implementation = function () {
                    _coverage.trigger('sensitive_api', 'sensitive_api');
                    var ret = ov.apply(this, arguments);
                    apiEmit(label, ret);
                    return ret;
                };
                _coverage.installed('sensitive_api', 'sensitive_api');
            });
            console.log('[apkscan] hooked ' + label);
        } catch (e) {
            _coverage.registrationError('sensitive_api', 'sensitive_api');
            console.log('[apkscan] hook skip ' + label + ': ' + e);
        }
    }
    var TM = 'android.telephony.TelephonyManager';
    hook(TM, 'getDeviceId', 'TelephonyManager.getDeviceId');
    hook(TM, 'getImei', 'TelephonyManager.getImei');
    hook(TM, 'getSubscriberId', 'TelephonyManager.getSubscriberId');
    hook(TM, 'getSimSerialNumber', 'TelephonyManager.getSimSerialNumber');
    hook(TM, 'getLine1Number', 'TelephonyManager.getLine1Number');
    hook(TM, 'getSimOperator', 'TelephonyManager.getSimOperator');
    hook(TM, 'getSimOperatorName', 'TelephonyManager.getSimOperatorName');
    hook('android.telephony.SmsManager', 'sendTextMessage', 'SmsManager.sendTextMessage');
    hook('android.content.ContentResolver', 'query', 'ContentResolver.query');
    hook('android.content.ClipboardManager', 'getPrimaryClip', 'ClipboardManager.getPrimaryClip');
    hook('android.location.LocationManager', 'getLastKnownLocation', 'LocationManager.getLastKnownLocation');
});
