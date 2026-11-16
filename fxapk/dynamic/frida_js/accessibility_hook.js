
// 取证用途：对取证样本自身在分析机上做运行时观测，产出端点/密钥/独特串等线索，不面向任何第三方基础设施。
// apkscan 无障碍远控指令与目标银行清单采集（best-effort）：hook AccessibilityService 回调 +
// dispatchGesture/performGlobalAction（远控指令，限流）+ MediaProjection（屏幕录制）。
var _coverage = (typeof globalThis !== 'undefined' && globalThis.__fxapkProbeCoverage) || {
    perform: function (_family, callback) {
        try { if (typeof Java !== 'undefined' && (!('available' in Java) || Java.available)) Java.perform(callback); } catch (_) {}
    },
    attempted: function () {}, installed: function () {}, registrationError: function () {},
    trigger: function () {}, drop: function () {}, truncated: function () {}
};
_coverage.perform('accessibility', function () {
    var _rc_count = 0;
    var _RC_CAP = 2000;          // 总事件封顶（避免刷爆 send 通道）
    var _gesture_count = 0;
    var _GESTURE_CAP = 200;      // dispatchGesture 高频 → 单独限流（采样上限）
    var _seen_pkg = {};          // 同一目标包名只回传一次（onAccessibilityEvent 极高频）

    function rcEmit(p) {
        try {
            if (_rc_count >= _RC_CAP) { _coverage.drop('accessibility', 'events'); return; }
            _rc_count += 1;
            p.type = 'apkscan-accessibility';
            send(p);
        } catch (e) { /* 回传失败不得炸会话 */ }
    }
    // 目标包名去重回传（被劫持的银行/支付 app 清单）。
    function emitTargetPackage(pkg) {
        try {
            if (pkg === null || pkg === undefined) return;
            var s = ('' + pkg).trim();
            if (!s || _seen_pkg[s]) return;
            _seen_pkg[s] = true;
            rcEmit({event: 'accessibility_event', package: s, ts: Date.now()});
        } catch (e) {}
    }
    function emitGesture(action) {
        try {
            if (_gesture_count >= _GESTURE_CAP) {
                _coverage.drop('accessibility', 'dispatch_gesture');
                return;
            }
            _gesture_count += 1;
            var text = '' + action;
            if (text.length > 200) _coverage.truncated('accessibility', 'events');
            rcEmit({event: 'gesture', action: text.slice(0, 200), ts: Date.now()});
        } catch (e) {}
    }

    // --- AccessibilityService（抽象基类）onAccessibilityEvent：抓被操作 app 包名 ----------
    // 抽象类——hook 基类回调 best-effort（命中与否随 ROM/版本），hook 不到不崩。
    try {
        var AccSvc = Java.use('android.accessibilityservice.AccessibilityService');
        if (AccSvc.onAccessibilityEvent) {
            var onEvent = AccSvc.onAccessibilityEvent.overload(
                'android.view.accessibility.AccessibilityEvent'
            );
            _coverage.attempted('accessibility', 'event_package');
            onEvent.implementation = function (event) {
                _coverage.trigger('accessibility', 'event_package');
                try {
                    if (event !== null && event !== undefined && event.getPackageName) {
                        emitTargetPackage(event.getPackageName());
                    }
                } catch (e) {}
                return this.onAccessibilityEvent(event);
            };
            _coverage.installed('accessibility', 'event_package');
            console.log('[apkscan] AccessibilityService.onAccessibilityEvent hooked (abstract best-effort)');
        } else _coverage.registrationError('accessibility', 'event_package');
    } catch (e) {
        _coverage.registrationError('accessibility', 'event_package');
        console.log('[apkscan] AccessibilityService hook skip: ' + e);
    }

    // --- AccessibilityNodeInfo.getPackageName：补充面（hook 不到基类回调时从控件树拿目标包名）---
    try {
        var Node = Java.use('android.view.accessibility.AccessibilityNodeInfo');
        if (Node.getPackageName) {
            _coverage.attempted('accessibility', 'node_package');
            Node.getPackageName.implementation = function () {
                _coverage.trigger('accessibility', 'node_package');
                var pkg = this.getPackageName();
                try { emitTargetPackage(pkg); } catch (e) {}
                return pkg;
            };
            _coverage.installed('accessibility', 'node_package');
            console.log('[apkscan] AccessibilityNodeInfo.getPackageName hooked');
        } else _coverage.registrationError('accessibility', 'node_package');
    } catch (e) {
        _coverage.registrationError('accessibility', 'node_package');
        console.log('[apkscan] AccessibilityNodeInfo hook skip: ' + e);
    }

    // --- AccessibilityService.dispatchGesture：下发自动手势 = 远控指令（高频，限流）---------
    try {
        var AccSvc2 = Java.use('android.accessibilityservice.AccessibilityService');
        if (AccSvc2.dispatchGesture) {
            AccSvc2.dispatchGesture.overloads.forEach(function (ov) {
                _coverage.attempted('accessibility', 'dispatch_gesture');
                ov.implementation = function () {
                    _coverage.trigger('accessibility', 'dispatch_gesture');
                    try { emitGesture('dispatchGesture'); } catch (e) {}
                    return ov.apply(this, arguments);
                };
                _coverage.installed('accessibility', 'dispatch_gesture');
            });
            console.log('[apkscan] AccessibilityService.dispatchGesture hooked (rate-limited)');
        } else _coverage.registrationError('accessibility', 'dispatch_gesture');
        // performGlobalAction：返回/HOME/最近任务等全局动作（远控指令的另一形态）。
        if (AccSvc2.performGlobalAction) {
            var globalAction = AccSvc2.performGlobalAction.overload('int');
            _coverage.attempted('accessibility', 'global_action');
            globalAction.implementation = function (action) {
                _coverage.trigger('accessibility', 'global_action');
                try { emitGesture('performGlobalAction:' + action); } catch (e) {}
                return this.performGlobalAction(action);
            };
            _coverage.installed('accessibility', 'global_action');
            console.log('[apkscan] AccessibilityService.performGlobalAction hooked');
        } else _coverage.registrationError('accessibility', 'global_action');
    } catch (e) {
        _coverage.registrationError('accessibility', 'global_action');
        console.log('[apkscan] dispatchGesture/performGlobalAction hook skip: ' + e);
    }

    // --- MediaProjectionManager.createVirtualDisplay：屏幕录制开启（操盘端可视化远控）-------
    try {
        var MP = Java.use('android.media.projection.MediaProjection');
        if (MP.createVirtualDisplay) {
            MP.createVirtualDisplay.overloads.forEach(function (ov) {
                _coverage.attempted('accessibility', 'screencapture');
                ov.implementation = function () {
                    _coverage.trigger('accessibility', 'screencapture');
                    try {
                        rcEmit({event: 'screencapture', action: 'createVirtualDisplay', ts: Date.now()});
                    } catch (e) {}
                    return ov.apply(this, arguments);
                };
            _coverage.installed('accessibility', 'screencapture');
            });
            console.log('[apkscan] MediaProjection.createVirtualDisplay hooked');
        } else _coverage.registrationError('accessibility', 'screencapture');
    } catch (e) {
        _coverage.registrationError('accessibility', 'screencapture');
        console.log('[apkscan] MediaProjection hook skip: ' + e);
    }
});
