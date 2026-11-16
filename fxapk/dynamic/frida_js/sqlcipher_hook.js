
// 取证用途：对取证样本自身在分析机上做运行时观测，产出端点/密钥/独特串等线索，不面向任何第三方基础设施。
// Observe database opens without issuing SQL on the application's connection.
var _coverage = (typeof globalThis !== 'undefined' && globalThis.__fxapkProbeCoverage) || {
    perform: function (_family, callback) {
        try { if (typeof Java !== 'undefined' && (!('available' in Java) || Java.available)) Java.perform(callback); } catch (_) {}
    },
    attempted: function () {}, installed: function () {}, registrationError: function () {},
    trigger: function () {}, drop: function () {}, truncated: function () {}
};
_coverage.perform('sqlcipher', function () {
    var _db_count = 0;
    var _DB_CAP = 200;
    var _seen_db = {};

    function dbEmit(p) {
        try {
            if (_db_count >= _DB_CAP) { _coverage.drop('sqlcipher', 'events'); return; }
            _db_count += 1;
            p.type = 'apkscan-sqlcipher';
            send(p);
        } catch (e) { /* 回传失败不得炸会话 */ }
    }
    function clipStr(s, n) {
        try {
            if (s === null || s === undefined) return null;
            var t = '' + s;
            if (t.length > n) _coverage.truncated('sqlcipher', 'events');
            return t.length > n ? t.slice(0, n) : t;
        } catch (e) { return null; }
    }
    function handleOpen(db, dbPath, key, where) {
        try {
            if (_db_count >= _DB_CAP) { _coverage.drop('sqlcipher', 'events'); return; }
            var path = '' + dbPath;
            if (_seen_db[path]) return;
            _seen_db[path] = true;
            dbEmit({event: 'key_only', db_path: path, plain_path: null,
                    export_status: 'not_attempted_non_interference',
                    key: clipStr(key, 128), where: where, ts: Date.now()});
        } catch (e) {}
    }

    // --- SQLCipher：net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase ---
    // 多 fallback 类名（不同 SQLCipher 版本/打包）。
    var cipherNames = ['net.sqlcipher.database.SQLiteDatabase',
                       'net.zetetic.database.sqlcipher.SQLiteDatabase'];
    cipherNames.forEach(function (cn) {
        try {
            var SDB = Java.use(cn);
            if (SDB.openOrCreateDatabase) {
                SDB.openOrCreateDatabase.overloads.forEach(function (ov) {
                    _coverage.attempted('sqlcipher', 'cipher_open');
                    ov.implementation = function () {
                        _coverage.trigger('sqlcipher', 'cipher_open');
                        var db = ov.apply(this, arguments);
                        try {
                            var args = arguments;
                            // 形参形态多样：(String path, ...) 或 (File file, ...)；key 多为第 2 参。
                            var dbPath = null, key = null;
                            try { dbPath = (args.length > 0) ? ('' + args[0]) : null; } catch (e1) {}
                            try {
                                if (args.length > 1 && args[1] !== null && args[1] !== undefined) {
                                    key = '' + args[1];   // password（String 或 char[]）
                                }
                            } catch (e2) {}
                            handleOpen(db, dbPath, key, cn + '.openOrCreateDatabase');
                        } catch (e) {}
                        return db;
                    };
                    _coverage.installed('sqlcipher', 'cipher_open');
                });
                console.log('[apkscan] SQLCipher ' + cn + '.openOrCreateDatabase hooked');
            } else _coverage.registrationError('sqlcipher', 'cipher_open');
        } catch (e) {
            _coverage.registrationError('sqlcipher', 'cipher_open');
            console.log('[apkscan] SQLCipher ' + cn + ' hook skip: ' + e);
        }
    });

    // --- 普通 SQLite：android.database.sqlite.SQLiteDatabase.openDatabase（无 key）---
    // 普通库只记录路径；已有落盘材料的只读采集由宿主负责。
    try {
        var ADB = Java.use('android.database.sqlite.SQLiteDatabase');
        if (ADB.openDatabase) {
            ADB.openDatabase.overloads.forEach(function (ov) {
                _coverage.attempted('sqlcipher', 'sqlite_open');
                ov.implementation = function () {
                    _coverage.trigger('sqlcipher', 'sqlite_open');
                    var db = ov.apply(this, arguments);
                    try {
                        var dbPath = (arguments.length > 0) ? ('' + arguments[0]) : null;
                        if (dbPath && ('' + dbPath).indexOf('.db') >= 0) {
                            handleOpen(db, dbPath, null, 'android.SQLiteDatabase.openDatabase');
                        }
                    } catch (e) {}
                    return db;
                };
                _coverage.installed('sqlcipher', 'sqlite_open');
            });
            console.log('[apkscan] android SQLiteDatabase.openDatabase hooked');
        } else _coverage.registrationError('sqlcipher', 'sqlite_open');
    } catch (e) {
        _coverage.registrationError('sqlcipher', 'sqlite_open');
        console.log('[apkscan] android SQLiteDatabase hook skip: ' + e);
    }
});
