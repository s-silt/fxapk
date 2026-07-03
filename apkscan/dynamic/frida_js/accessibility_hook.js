
// 取证用途：对取证样本自身在分析机上做运行时观测，产出端点/密钥/独特串等线索，不面向任何第三方基础设施。
// apkscan 无障碍远控指令与目标银行清单采集（best-effort）：hook AccessibilityService 回调 +
// dispatchGesture/performGlobalAction（远控指令，限流）+ MediaProjection（屏幕录制）。
Java.perform(function () {
    var _rc_count = 0;
    var _RC_CAP = 2000;          // 总事件封顶（避免刷爆 send 通道）
    var _gesture_count = 0;
    var _GESTURE_CAP = 200;      // dispatchGesture 高频 → 单独限流（采样上限）
    var _seen_pkg = {};          // 同一目标包名只回传一次（onAccessibilityEvent 极高频）

    function rcEmit(p) {
        try {
            if (_rc_count >= _RC_CAP) return;
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
            if (_gesture_count >= _GESTURE_CAP) return;   // 高频限流
            _gesture_count += 1;
            rcEmit({event: 'gesture', action: ('' + action).slice(0, 200), ts: Date.now()});
        } catch (e) {}
    }

    // --- AccessibilityService（抽象基类）onAccessibilityEvent：抓被操作 app 包名 ----------
    // 抽象类——hook 基类回调 best-effort（命中与否随 ROM/版本），hook 不到不崩。
    try {
        var AccSvc = Java.use('android.accessibilityservice.AccessibilityService');
        if (AccSvc.onAccessibilityEvent) {
            AccSvc.onAccessibilityEvent.overload(
                'android.view.accessibility.AccessibilityEvent'
            ).implementation = function (event) {
                try {
                    if (event !== null && event !== undefined && event.getPackageName) {
                        emitTargetPackage(event.getPackageName());
                    }
                } catch (e) {}
                return this.onAccessibilityEvent(event);
            };
            console.log('[apkscan] AccessibilityService.onAccessibilityEvent hooked (abstract best-effort)');
        }
    } catch (e) {
        console.log('[apkscan] AccessibilityService hook skip: ' + e);
    }

    // --- AccessibilityNodeInfo.getPackageName：补充面（hook 不到基类回调时从控件树拿目标包名）---
    try {
        var Node = Java.use('android.view.accessibility.AccessibilityNodeInfo');
        if (Node.getPackageName) {
            Node.getPackageName.implementation = function () {
                var pkg = this.getPackageName();
                try { emitTargetPackage(pkg); } catch (e) {}
                return pkg;
            };
            console.log('[apkscan] AccessibilityNodeInfo.getPackageName hooked');
        }
    } catch (e) {
        console.log('[apkscan] AccessibilityNodeInfo hook skip: ' + e);
    }

    // --- AccessibilityService.dispatchGesture：下发自动手势 = 远控指令（高频，限流）---------
    try {
        var AccSvc2 = Java.use('android.accessibilityservice.AccessibilityService');
        if (AccSvc2.dispatchGesture) {
            AccSvc2.dispatchGesture.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    try { emitGesture('dispatchGesture'); } catch (e) {}
                    return ov.apply(this, arguments);
                };
            });
            console.log('[apkscan] AccessibilityService.dispatchGesture hooked (rate-limited)');
        }
        // performGlobalAction：返回/HOME/最近任务等全局动作（远控指令的另一形态）。
        if (AccSvc2.performGlobalAction) {
            AccSvc2.performGlobalAction.overload('int').implementation = function (action) {
                try { emitGesture('performGlobalAction:' + action); } catch (e) {}
                return this.performGlobalAction(action);
            };
            console.log('[apkscan] AccessibilityService.performGlobalAction hooked');
        }
    } catch (e) {
        console.log('[apkscan] dispatchGesture/performGlobalAction hook skip: ' + e);
    }

    // --- MediaProjectionManager.createVirtualDisplay：屏幕录制开启（操盘端可视化远控）-------
    try {
        var MP = Java.use('android.media.projection.MediaProjection');
        if (MP.createVirtualDisplay) {
            MP.createVirtualDisplay.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    try {
                        rcEmit({event: 'screencapture', action: 'createVirtualDisplay', ts: Date.now()});
                    } catch (e) {}
                    return ov.apply(this, arguments);
                };
            });
            console.log('[apkscan] MediaProjection.createVirtualDisplay hooked');
        }
    } catch (e) {
        console.log('[apkscan] MediaProjection hook skip: ' + e);
    }
});
