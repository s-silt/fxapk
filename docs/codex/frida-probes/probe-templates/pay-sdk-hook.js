// pay-sdk-hook.js — P0① 资金链取证：hook 第三方支付 SDK 调起，抓资金接收方锚点(商户号/seller_id/notify_url)
// 适用：涉诈样本拉起支付宝/微信/银联收款。纯只读检测仪——只 hook+console.log 记录调起参数，绝不发起/拦截/修改任何支付。
// 跑：frida -U -f <包名> -l pay-sdk-hook.js -q  （建议 spawn；进到支付/充值页触发一次调起）
// 改：类名被混淆/换 SDK 版本→用 jadx 搜 'alipay/PayTask'、'opensdk/PayReq'、'UPPayAssistEx' 核对真实类名回填 CFG；微信走 IWXAPI 实现类，下方已枚举候选+遍历已加载类兜底
'use strict';

// ===== 现场可改：类名随 SDK 版本/混淆漂移，jadx 核对后回填 =====
var CFG = {
    aliPayTask: 'com.alipay.sdk.app.PayTask',                       // 支付宝：payV2/pay 第一个 String 参 = orderInfo
    wxPayReq:   'com.tencent.mm.opensdk.modelpay.PayReq',           // 微信：sendReq 的支付请求对象
    wxImplCands: [                                                  // 微信 IWXAPI 是接口，实现类候选(挂实现类的 sendReq)
        'com.tencent.mm.opensdk.openapi.WXApiImplV10',
        'com.tencent.mm.opensdk.openapi.WXApiImplComm',
    ],
    unionPay:   'com.unionpay.UPPayAssistEx',                       // 银联：startPay 参数里含 tn(交易流水号)
};

// 资金锚点关键词：命中即高亮（支付宝 orderInfo / biz_content 里的字段）
var ALI_KEYS = ['app_id', 'partner', 'seller_id', 'pid', 'out_trade_no', 'total_amount', 'subject', 'notify_url', 'return_url'];

function emit(line) { try { console.log(line); } catch (e) {} }

// 从支付宝 orderInfo(形如 a=b&c="d"&biz_content={...}) 里抽锚点，原文也整段打出
function dumpAliOrder(orderInfo) {
    try {
        emit('[pay][alipay] orderInfo(原文) = ' + orderInfo);
        for (var i = 0; i < ALI_KEYS.length; i++) {
            var k = ALI_KEYS[i];
            // 兼容 k=v / k="v" / JSON 里 "k":"v"
            var re = new RegExp('[?&"\\s]' + k + '"?\\s*[=:]\\s*"?([^&"}]+)', 'i');
            var m = re.exec('&' + orderInfo);
            if (m && m[1]) {
                var tag = (k === 'seller_id' || k === 'pid' || k === 'partner') ? '  [LEAD-定人:收款主体→向支付宝调实名结算账户]'
                        : (k === 'notify_url' || k === 'return_url') ? '  [LEAD-穿透:真后端]' : '';
                emit('[pay][alipay]   ' + k + ' = ' + m[1] + tag);
            }
        }
        // 兜底：任何 http(s) 链接都可能是 notify/真后端
        var urls = orderInfo.match(/https?:\/\/[^&"'\s}]+/gi);
        if (urls) for (var j = 0; j < urls.length; j++) emit('[pay][alipay]   [LEAD-穿透:URL] ' + urls[j]);
    } catch (e) { emit('[pay][alipay] 解析 orderInfo skip: ' + e); }
}

Java.perform(function () {

    // ============ 支付宝 PayTask.payV2 / pay ============
    // 抓到什么 -> server 签好的 orderInfo 里 seller_id/partner=收款商户、notify_url=真后端
    try {
        var PayTask = Java.use(CFG.aliPayTask);
        ['payV2', 'pay'].forEach(function (mName) {
            try {
                if (!PayTask[mName]) return;
                PayTask[mName].overloads.forEach(function (ov) {
                    try {
                        ov.implementation = function () {
                            try {
                                for (var i = 0; i < arguments.length; i++) {
                                    if (typeof arguments[i] === 'string' && arguments[i].indexOf('=') >= 0) {
                                        emit('[pay][alipay] PayTask.' + mName + ' 调起：');
                                        dumpAliOrder(arguments[i]);
                                        break;
                                    }
                                }
                            } catch (e) { emit('[pay][alipay] ' + mName + ' inspect skip: ' + e); }
                            return ov.apply(this, arguments);   // 只读放行，绝不改写/拦截支付
                        };
                    } catch (e) { emit('[pay][alipay] ' + mName + ' overload skip: ' + e); }
                });
            } catch (e) { emit('[pay][alipay] ' + mName + ' hook skip: ' + e); }
        });
        emit('[pay][alipay] PayTask hooked');
    } catch (e) { emit('[pay][alipay] PayTask 未命中(' + e + ') — 下一步：jadx 搜 com.alipay.sdk 核对类名；或支付走 H5 收银台→回退 webview-hook/http-url-hook'); }

    // ============ 微信 IWXAPI 实现类.sendReq(BaseReq) ============
    // 抓到什么 -> PayReq.partnerId=商户号、prepayId、sign；微信支付定收款商户
    function readWxPayReq(req) {
        try {
            var PayReq = Java.use(CFG.wxPayReq);
            var cls = '' + req.getClass().getName();
            if (cls.indexOf('PayReq') < 0) return false;     // 只关心支付请求，其它 BaseReq(分享/登录)忽略
            var pr = Java.cast(req, PayReq);
            emit('[pay][wechat] IWXAPI.sendReq(PayReq)：');
            ['appId', 'partnerId', 'prepayId', 'nonceStr', 'timeStamp', 'packageValue', 'sign', 'extData'].forEach(function (f) {
                try {
                    if (pr[f] === undefined) return;
                    var v = pr[f].value;
                    if (v === null || v === undefined) return;
                    var tag = (f === 'partnerId') ? '  [LEAD-定人:商户号→向财付通/微信支付调实名结算账户]'
                            : (f === 'appId') ? '  [LEAD:微信开放平台 appId→调注册主体]' : '';
                    emit('[pay][wechat]   ' + f + ' = ' + v + tag);
                } catch (e) {}
            });
            return true;
        } catch (e) { emit('[pay][wechat] 读 PayReq skip: ' + e); return false; }
    }
    var wxHooked = 0;
    function hookWxImpl(clsName) {
        try {
            var Impl = Java.use(clsName);
            if (!Impl.sendReq) return;
            Impl.sendReq.overloads.forEach(function (ov) {
                try {
                    if (ov.argumentTypes.length < 1) return;
                    ov.implementation = function () {
                        try { if (arguments[0] !== null) readWxPayReq(arguments[0]); }
                        catch (e) { emit('[pay][wechat] sendReq inspect skip: ' + e); }
                        return ov.apply(this, arguments);   // 只读放行
                    };
                    wxHooked++;
                } catch (e) { emit('[pay][wechat] ' + clsName + ' overload skip: ' + e); }
            });
        } catch (e) { /* 该实现类不存在，下面再枚举兜底 */ }
    }
    try {
        CFG.wxImplCands.forEach(hookWxImpl);
        if (wxHooked === 0) {
            // 兜底：遍历已加载类，找实现 IWXAPI 且有 sendReq 的实现类
            Java.enumerateLoadedClasses({
                onMatch: function (name) {
                    if (wxHooked === 0 && name.indexOf('opensdk.openapi') >= 0 && name.indexOf('Impl') >= 0) hookWxImpl(name);
                },
                onComplete: function () {}
            });
        }
        emit(wxHooked > 0 ? '[pay][wechat] IWXAPI 实现类 sendReq hooked (' + wxHooked + ')'
                          : '[pay][wechat] 未命中 IWXAPI 实现类 — 下一步：样本注册微信支付后再注入；或 jadx 搜 opensdk.openapi.*Impl 回填 CFG.wxImplCands');
    } catch (e) { emit('[pay][wechat] hook skip: ' + e); }

    // ============ 银联 UPPayAssistEx.startPay ============
    // 抓到什么 -> 参数里的 tn(交易流水号)→向银联调订单/收款方
    try {
        var UP = Java.use(CFG.unionPay);
        if (UP.startPay) {
            UP.startPay.overloads.forEach(function (ov) {
                try {
                    ov.implementation = function () {
                        try {
                            emit('[pay][unionpay] UPPayAssistEx.startPay 调起：');
                            for (var i = 0; i < arguments.length; i++) {
                                if (typeof arguments[i] === 'string') {
                                    var v = arguments[i];
                                    var tag = (/^[0-9A-Za-z]{8,}$/.test(v) && v.length >= 10) ? '  [LEAD:疑似 tn 交易流水号→向银联调订单/收款方]' : '';
                                    emit('[pay][unionpay]   arg' + i + ' = ' + v + tag);
                                }
                            }
                        } catch (e) { emit('[pay][unionpay] inspect skip: ' + e); }
                        return ov.apply(this, arguments);   // 只读放行
                    };
                } catch (e) { emit('[pay][unionpay] overload skip: ' + e); }
            });
            emit('[pay][unionpay] UPPayAssistEx.startPay hooked');
        }
    } catch (e) { emit('[pay][unionpay] 未命中(' + e + ') — 银联 SDK 未用或类名变化，jadx 搜 com.unionpay 核对'); }

    emit('[pay] 已就绪：进支付/充值页触发一次调起，看 [LEAD-定人]=收款商户号/seller_id、[LEAD-穿透]=notify_url/真后端。');
    emit('[pay] 抓不到→支付多走 H5 收银台/聚合第四方(通联/收钱吧/汇付)不用官方 SDK：回退 webview-hook.js / http-url-hook.js 抓创建订单接口。');
    emit('[pay] 本探针只读：仅 hook+打印调起参数，不发起/不拦截/不修改任何支付。');
});
