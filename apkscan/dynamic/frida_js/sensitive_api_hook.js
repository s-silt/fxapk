
// 取证用途：对取证样本自身在分析机上做运行时观测，产出端点/密钥/独特串等线索，不面向任何第三方基础设施。
// apkscan 运行时敏感 API 追踪（best-effort）：记录设备标识/短信/通讯录/剪贴板等实际调用。
Java.perform(function () {
    var _api_count = 0;
    function apiEmit(api, ret) {
        try {
            if (_api_count >= 2000) return;
            _api_count += 1;
            var rs = null;
            try { if (ret !== null && ret !== undefined) { rs = ('' + ret).slice(0, 128); } } catch (e) {}
            send({type: 'apkscan-api', event: 'call', api: api, result_summary: rs, ts: Date.now()});
        } catch (e) {}
    }
    function hook(cls, method, label) {
        try {
            var C = Java.use(cls);
            if (!C[method]) return;
            C[method].overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var ret = ov.apply(this, arguments);
                    apiEmit(label, ret);
                    return ret;
                };
            });
            console.log('[apkscan] hooked ' + label);
        } catch (e) {
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
