
// 取证用途：对取证样本自身在分析机上做运行时观测，产出端点/密钥/独特串等线索，不面向任何第三方基础设施。
// apkscan 运行时落地库导出（best-effort）：hook SQLCipher/SQLite openDatabase，导明文库回传。
Java.perform(function () {
    var _db_count = 0;
    var _DB_CAP = 200;
    var _seen_db = {};        // 同一库路径只导一次（避免反复 export 刷爆 + 重复磁盘 IO）
    var _TMP_DIR = '/data/local/tmp/apkscan_db';

    function dbEmit(p) {
        try {
            if (_db_count >= _DB_CAP) return;
            _db_count += 1;
            p.type = 'apkscan-sqlcipher';
            send(p);
        } catch (e) { /* 回传失败不得炸会话 */ }
    }
    function clipStr(s, n) {
        try {
            if (s === null || s === undefined) return null;
            var t = '' + s;
            return t.length > n ? t.slice(0, n) : t;
        } catch (e) { return null; }
    }
    function baseName(p) {
        try {
            var s = '' + p;
            var i = s.lastIndexOf('/');
            return i >= 0 ? s.slice(i + 1) : s;
        } catch (e) { return 'db'; }
    }
    // 确保设备临时导出目录存在（best-effort，失败照常尝试导出，导不出再降级）。
    function ensureTmpDir() {
        try {
            var JFile = Java.use('java.io.File');
            var d = JFile.$new(_TMP_DIR);
            if (!d.exists()) { try { d.mkdirs(); } catch (e2) {} }
        } catch (e) {}
    }
    // 对一个已打开的 SQLCipher db 句柄注入 ATTACH+sqlcipher_export，导明文库。
    // 返回明文库设备路径（成功）或 null（失败 → 调用方降级 key_only）。
    function exportPlain(db, dbPath, key) {
        if (db === null || db === undefined) return null;
        if (!db.rawExecSQL) return null;        // 非 SQLCipher 句柄（普通 SQLite）→ 不导，交收尾 adb pull
        ensureTmpDir();
        var plainPath = _TMP_DIR + '/' + baseName(dbPath) + '.plain.db';
        // 先按 SQLCipher v4 默认尝试；失败再降到 v3 KDF 兼容模式重试。
        var compat = [4, 3];
        for (var ci = 0; ci < compat.length; ci++) {
            try {
                try { db.rawExecSQL('PRAGMA cipher_compatibility = ' + compat[ci] + ';'); } catch (eC) {}
                // 目标明文库 KEY '' = 不加密（明文）。
                db.rawExecSQL("ATTACH DATABASE '" + plainPath + "' AS plain KEY '';");
                db.rawExecSQL("SELECT sqlcipher_export('plain');");
                db.rawExecSQL("DETACH DATABASE plain;");
                return plainPath;   // 任一兼容档导出成功即返回
            } catch (eExp) {
                // 本档失败：清掉可能半导出的目标，换下一档重试。
                try { db.rawExecSQL("DETACH DATABASE plain;"); } catch (eD) {}
            }
        }
        return null;   // v4/v3 都失败 → 降级
    }

    function handleOpen(db, dbPath, key, where) {
        try {
            var path = '' + dbPath;
            if (_seen_db[path]) return;
            _seen_db[path] = true;
            var plainPath = null;
            try { plainPath = exportPlain(db, path, key); } catch (eX) { plainPath = null; }
            if (plainPath) {
                dbEmit({event: 'exported', db_path: path, plain_path: plainPath,
                        key: clipStr(key, 128), where: where, ts: Date.now()});
            } else {
                // 导出失败 / 普通 SQLite（无 rawExecSQL）：降级，仅回传 key + 原库路径。
                // merge 侧据此写人工解密 playbook；普通 SQLite 由收尾 adb pull databases 拉回。
                dbEmit({event: 'key_only', db_path: path, plain_path: null,
                        key: clipStr(key, 128), where: where, ts: Date.now()});
            }
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
                    ov.implementation = function () {
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
                });
                console.log('[apkscan] SQLCipher ' + cn + '.openOrCreateDatabase hooked');
            }
        } catch (e) {
            console.log('[apkscan] SQLCipher ' + cn + ' hook skip: ' + e);
        }
    });

    // --- 普通 SQLite：android.database.sqlite.SQLiteDatabase.openDatabase（无 key）---
    // 普通库无 sqlcipher_export，handleOpen 走 key_only 降级；真正拉回交收尾 adb pull databases。
    try {
        var ADB = Java.use('android.database.sqlite.SQLiteDatabase');
        if (ADB.openDatabase) {
            ADB.openDatabase.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var db = ov.apply(this, arguments);
                    try {
                        var dbPath = (arguments.length > 0) ? ('' + arguments[0]) : null;
                        if (dbPath && ('' + dbPath).indexOf('.db') >= 0) {
                            handleOpen(db, dbPath, null, 'android.SQLiteDatabase.openDatabase');
                        }
                    } catch (e) {}
                    return db;
                };
            });
            console.log('[apkscan] android SQLiteDatabase.openDatabase hooked');
        }
    } catch (e) {
        console.log('[apkscan] android SQLiteDatabase hook skip: ' + e);
    }
});
