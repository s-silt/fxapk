/*
 * 用途: 只读取证——hook MQTT(Paho/HiveMQ)与 XMPP(Smack) 私有 IM 客户端,固证 broker 地址/登录凭据/收发消息明文,供反诈调证(定人·穿透·固证)。仅打印,不改写不外发。
 * 适用: 涉诈 APK 用自建 MQTT(1883/8883)或 XMPP(5222/5223) 做指令下发/数据回传; 动态抓包见私有 TLS 长连接但 payload 不可读时点亮。
 * 跑:   frida -U -f <包名> -l mqtt-xmpp-im-hook.js --no-pause   (落盘: frida ... -l mqtt-xmpp-im-hook.js 2>&1 | tee /data/local/tmp/im_evi.log)
 * 改:   类名被混淆 → 用文末 enumerateLoadedClasses 正则自查回填真实类名; HiveMQ API 面随版本变,未命中先跑 dump 自查可用方法名再补 hook。
 */
'use strict';

// ---- 工具: 统一出口 + 编码(明文/key/byte[] 一律 hex(+base64),不盲 UTF-8) ----
function log(tag, msg) { console.log('[' + tag + '] ' + msg); }
function skip(tag, e) { console.log('[' + tag + '] skip: ' + e); }

// 判定一个 frida Java 句柄是否为 byte[]( $className==='[B' 最可靠; 空数组也能过 )
function isJavaByteArray(obj) {
  try {
    if (obj === null || typeof obj === 'undefined') return false;
    if (obj.$className === '[B') return true;
  } catch (e) {}
  return false;
}

// ---- 判定 Java String[] ( topic 过滤器数组 ) ----
function isJavaStringArray(obj) {
  try {
    if (obj === null || typeof obj === 'undefined') return false;
    return obj.$className === '[Ljava.lang.String;';
  } catch (e) { return false; }
}

function bytesToHex(bytes) {
  try {
    if (bytes === null) return 'null';
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
      var b = bytes[i] & 0xff;
      out += ('0' + b.toString(16)).slice(-2);
    }
    return out;
  } catch (e) { return 'hex-fail:' + e; }
}

// base64: 入参必须是 Java byte[]。若是 JS 普通数组(如 byteBuffer 取出),转成 Java byte[] 再编码。
function bytesToB64(bytes) {
  try {
    if (bytes === null) return 'null';
    var B64 = Java.use('android.util.Base64');
    var jb = bytes;
    if (!isJavaByteArray(bytes)) {
      try {
        var arr = [];
        for (var i = 0; i < bytes.length; i++) { var v = bytes[i] & 0xff; arr.push(v > 127 ? v - 256 : v); }
        jb = Java.array('byte', arr);
      } catch (e1) { return 'b64-fail:not-bytes:' + e1; }
    }
    return B64.encodeToString(jb, 2 /* NO_WRAP */);
  } catch (e) { return 'b64-fail:' + e; }
}

// char[] (password) → Java byte[] 再走 hex/base64; 不直接 UTF-8 拼字符串
function charsToBytes(chars) {
  try {
    if (chars === null) return null;
    var StringCls = Java.use('java.lang.String');
    var s = StringCls.$new(chars);              // char[] -> String (仅本地编码,不外发)
    var raw = s.getBytes('UTF-8');
    return raw;
  } catch (e) { return null; }
}

// ByteBuffer → Java byte[]( duplicate 不破坏原 position )
function byteBufferToBytes(bb) {
  try {
    var dup = bb.duplicate();
    var rem = dup.remaining();
    var arr = Java.array('byte', new Array(rem).fill(0));
    dup.get(arr);
    return arr;
  } catch (e) { return null; }
}

// 任意 byte[]/String/CharSequence payload → {hex, b64, len}
function dumpPayload(tag, obj) {
  try {
    if (obj === null || typeof obj === 'undefined') { log(tag, 'payload=null'); return; }
    var bytes = null;
    if (isJavaByteArray(obj)) { bytes = obj; }   // 用 $className 判定,空数组也成立
    if (bytes === null) {
      try {
        var StringCls = Java.use('java.lang.String');
        var s = StringCls.$new(obj);
        bytes = s.getBytes('UTF-8');
      } catch (e2) { bytes = null; }
    }
    if (bytes === null) { log(tag, 'payload(未解码,原始 toString)=' + obj); return; }
    log(tag, 'payload len=' + bytes.length + ' hex=' + bytesToHex(bytes) + ' b64=' + bytesToB64(bytes));
  } catch (e) { skip(tag, e); }
}

// ---- Smack stanza 统一打印: to/from + Message body + 完整 XML(toXML 跨版本签名探测) ----
function stanzaToXml(stanza) {
  // 不硬编码参数,枚举 toXML 重载按参数个数安全调用(toXML()/toXML(String)/toXML(XmlEnvironment) 均可)
  try {
    var ovs = stanza.toXML.overloads;
    for (var i = 0; i < ovs.length; i++) {
      try {
        var argc = ovs[i].argumentTypes.length;
        if (argc === 0) { return '' + stanza.toXML(); }
        if (argc === 1) { return '' + ovs[i].call(stanza, null); } // String enclosingNamespace / XmlEnvironment 均接受 null
      } catch (e) {}
    }
  } catch (e) {}
  return null;
}

function logStanza(tag, stanza, peerKind, implName) {
  try {
    if (stanza === null) { log(tag, 'stanza=null'); return; }
    var peer = '';
    try { peer = '' + (peerKind === 'from' ? stanza.getFrom() : stanza.getTo()); } catch (e) {}
    var body = '';
    try {
      var Msg = Java.use('org.jivesoftware.smack.packet.Message');
      if (Msg.class.isInstance(stanza)) { body = '' + Java.cast(stanza, Msg).getBody(); }
    } catch (e) {}
    var xml = stanzaToXml(stanza);
    var msg = peerKind + '=' + peer + ' body=' + body;
    if (xml !== null) msg += ' xml=' + xml;
    if (implName) msg += ' @' + implName;
    log(tag, msg);
  } catch (e) { skip(tag, e); }
}

Java.perform(function () {

  // ============================================================
  // 1) Paho MQTT v3 —— org.eclipse.paho.client.mqttv3
  //    抓到什么: broker URI 列表 + userName + password(char[]) → 定人/穿透; publish/messageArrived 的 topic+payload → 固证
  // ============================================================

  // 1.1 MqttConnectOptions: 登录凭据与 broker 集合的总入口
  try {
    var MCO = Java.use('org.eclipse.paho.client.mqttv3.MqttConnectOptions');

    // setServerURIs(String[]) —— 显式设置 broker 列表(host:port,穿透线索)
    try {
      MCO.setServerURIs.overload('[Ljava.lang.String;').implementation = function (uris) {
        try {
          if (uris !== null) {
            for (var i = 0; i < uris.length; i++) log('PAHO/broker', 'setServerURIs[' + i + ']=' + uris[i]);
          }
        } catch (e) { skip('PAHO/broker', e); }
        return this.setServerURIs(uris);
      };
    } catch (e) { skip('PAHO/broker', e); }

    // setUserName(String) —— 登录账号(定人)
    try {
      MCO.setUserName.overload('java.lang.String').implementation = function (u) {
        try { log('PAHO/auth', 'userName=' + u); } catch (e) { skip('PAHO/auth', e); }
        return this.setUserName(u);
      };
    } catch (e) { skip('PAHO/auth', e); }

    // setPassword(char[]) —— 口令,char[] 走 hex+base64,不盲 UTF-8
    try {
      MCO.setPassword.overload('[C').implementation = function (pw) {
        try {
          var raw = charsToBytes(pw);
          if (raw === null) log('PAHO/auth', 'password=<null/解码失败>');
          else log('PAHO/auth', 'password(char[]->utf8 bytes) len=' + raw.length + ' hex=' + bytesToHex(raw) + ' b64=' + bytesToB64(raw));
        } catch (e) { skip('PAHO/auth', e); }
        return this.setPassword(pw);
      };
    } catch (e) { skip('PAHO/auth', e); }

    // getServerURIs/getUserName/getPassword 也 hook,捕获从配置/反序列化读回的凭据
    try {
      MCO.getServerURIs.implementation = function () {
        var r = this.getServerURIs();
        try { if (r !== null) for (var i = 0; i < r.length; i++) log('PAHO/broker', 'getServerURIs[' + i + ']=' + r[i]); } catch (e) { skip('PAHO/broker', e); }
        return r;
      };
    } catch (e) { skip('PAHO/broker', e); }
    try {
      MCO.getUserName.implementation = function () {
        var r = this.getUserName();
        try { log('PAHO/auth', 'getUserName=' + r); } catch (e) { skip('PAHO/auth', e); }
        return r;
      };
    } catch (e) { skip('PAHO/auth', e); }
    try {
      MCO.getPassword.implementation = function () {
        var r = this.getPassword();
        try {
          var raw = charsToBytes(r);
          if (raw !== null) log('PAHO/auth', 'getPassword len=' + raw.length + ' hex=' + bytesToHex(raw) + ' b64=' + bytesToB64(raw));
        } catch (e) { skip('PAHO/auth', e); }
        return r;
      };
    } catch (e) { skip('PAHO/auth', e); }
  } catch (e) {
    log('PAHO/MqttConnectOptions', '未命中: org.eclipse.paho.client.mqttv3.MqttConnectOptions 未加载。下一步: 文末 enumerateLoadedClasses 搜 /paho|mqttv3/ 确认是否 shade 改名后回填。e=' + e);
  }

  // 1.2 broker 真实连接地址: MqttAsyncClient/MqttClient 构造的 serverURI(tcp://host:port / ssl://host:port)
  ['org.eclipse.paho.client.mqttv3.MqttAsyncClient',
   'org.eclipse.paho.client.mqttv3.MqttClient'].forEach(function (cn) {
    try {
      var Cli = Java.use(cn);
      Cli.$init.overloads.forEach(function (ov) {
        try {
          ov.implementation = function () {
            try {
              // 第一个 String 形参约定为 serverURI
              if (arguments.length > 0 && arguments[0] !== null && ('' + arguments[0]).indexOf('://') > -1) {
                log('PAHO/broker', cn.split('.').pop() + ' serverURI=' + arguments[0] + '  (穿透: 调证该 host:port 服务器归属)');
              }
            } catch (e) { skip('PAHO/broker', e); }
            return ov.apply(this, arguments);
          };
        } catch (e) { skip('PAHO/broker', e); }
      });

      // publish(topic, MqttMessage) —— 样本对外发了什么(指令/回传)
      try {
        Cli.publish.overload('java.lang.String', 'org.eclipse.paho.client.mqttv3.MqttMessage').implementation = function (topic, msg) {
          try {
            log('PAHO/publish', 'topic=' + topic + (msg !== null ? ' qos=' + msg.getQos() + ' retained=' + msg.isRetained() : ''));
            if (msg !== null) dumpPayload('PAHO/publish', msg.getPayload());
          } catch (e) { skip('PAHO/publish', e); }
          return this.publish(topic, msg);
        };
      } catch (e) { skip('PAHO/publish', e); }

      // publish(topic, byte[], int qos, boolean retained) —— 另一重载
      try {
        Cli.publish.overload('java.lang.String', '[B', 'int', 'boolean').implementation = function (topic, payload, qos, retained) {
          try {
            log('PAHO/publish', 'topic=' + topic + ' qos=' + qos + ' retained=' + retained);
            dumpPayload('PAHO/publish', payload);
          } catch (e) { skip('PAHO/publish', e); }
          return this.publish(topic, payload, qos, retained);
        };
      } catch (e) { skip('PAHO/publish', e); }

      // subscribe(topic, ...) —— 订了哪些 topic,反推它在监听什么指令通道
      try {
        Cli.subscribe.overloads.forEach(function (ov) {
          try {
            ov.implementation = function () {
              try {
                if (arguments.length > 0) {
                  var t = arguments[0];
                  // 第一个参数可能是 String 或 String[](topic 过滤器数组)
                  if (isJavaStringArray(t)) {
                    for (var i = 0; i < t.length; i++) log('PAHO/subscribe', 'topic=' + t[i]);
                  } else { log('PAHO/subscribe', 'topic=' + t); }
                }
              } catch (e) { skip('PAHO/subscribe', e); }
              return ov.apply(this, arguments);
            };
          } catch (e) { skip('PAHO/subscribe', e); }
        });
      } catch (e) { skip('PAHO/subscribe', e); }
    } catch (e) {
      log('PAHO/client', '未命中 ' + cn + '。下一步: enumerateLoadedClasses 搜 /MqttAsyncClient|MqttClient/ 回填。e=' + e);
    }
  });

  // 1.3 收到的消息: 回调 messageArrived(topic, MqttMessage) —— 接收侧固证(下发指令/回执)
  //     接收点在样本自定义 MqttCallback / IMqttMessageListener 实现类里,类名混淆不可静态确定。
  //     Java.choose 按【已加载到堆上的实例】扫描; 对接口名 frida 做 instanceof 过滤(较新版本),
  //     但 -l 注入时机若早于实例创建则扫不到。失败/为空各自 try/catch,不崩,并给"下一步"。
  ['org.eclipse.paho.client.mqttv3.MqttCallback',
   'org.eclipse.paho.client.mqttv3.IMqttMessageListener'].forEach(function (iface) {
    try {
      var chosenAny = false;
      Java.choose(iface, {
        onMatch: function (inst) {
          try {
            chosenAny = true;
            var implName = inst.$className;
            var Impl = Java.use(implName);
            // 两个接口的 messageArrived 签名一致: (String, MqttMessage)
            try {
              Impl.messageArrived.overload('java.lang.String', 'org.eclipse.paho.client.mqttv3.MqttMessage').implementation = function (topic, m) {
                try { log('PAHO/recv', 'messageArrived topic=' + topic); if (m !== null) dumpPayload('PAHO/recv', m.getPayload()); } catch (e) { skip('PAHO/recv', e); }
                return this.messageArrived(topic, m);
              };
              log('PAHO/recv', 'hooked messageArrived @ ' + implName + ' (via ' + iface.split('.').pop() + ')');
            } catch (e) { skip('PAHO/recv', e); }
          } catch (e) { skip('PAHO/recv', e); }
        },
        onComplete: function () {
          if (!chosenAny) {
            log('PAHO/recv', '未命中 ' + iface.split('.').pop() + ' 的堆上实例(可能注入早于回调注册)。下一步: 实例创建后在 REPL 重跑文末 dumpCallback(),或对自查到的实现类名手动 hook 其 messageArrived。');
          }
        }
      });
    } catch (e) {
      skip('PAHO/recv', e + ' (' + iface.split('.').pop() + '; 部分 frida 版本对纯接口 Java.choose 报错,可忽略,用 dumpCallback 自查实现类)');
    }
  });

  // ============================================================
  // 2) HiveMQ MQTT Client —— com.hivemq.client.mqtt (Mqtt5/Mqtt3 API 面不同,一并处理)
  //    类名/方法名随版本变化大,这里 hook 稳定的 builder 入口 + 凭据/连接 simple builder。
  //    抓到什么: serverHost/serverPort → 穿透; simpleAuth username/password(byte[]/ByteBuffer) → 定人; publishWith payload → 固证
  // ============================================================

  // 2.1 连接地址: MqttClientBuilder.serverHost / serverPort (接口实现类在 internal 包,名字会变)
  try {
    var hiveBuilderHooked = false;
    Java.enumerateLoadedClassesSync().forEach(function (cn) {
      try {
        if (cn.indexOf('com.hivemq.client') === -1) return;
        if (cn.indexOf('Builder') === -1) return;
        var C = Java.use(cn);
        // serverHost(String)
        try {
          if (C.serverHost) {
            C.serverHost.overload('java.lang.String').implementation = function (h) {
              try { log('HIVEMQ/broker', cn.split('.').pop() + '.serverHost=' + h); } catch (e) { skip('HIVEMQ/broker', e); }
              return this.serverHost(h);
            };
            hiveBuilderHooked = true;
          }
        } catch (e) {}
        // serverPort(int)
        try {
          if (C.serverPort) {
            C.serverPort.overload('int').implementation = function (p) {
              try { log('HIVEMQ/broker', cn.split('.').pop() + '.serverPort=' + p + '  (穿透: serverHost:serverPort 即 broker)'); } catch (e) { skip('HIVEMQ/broker', e); }
              return this.serverPort(p);
            };
            hiveBuilderHooked = true;
          }
        } catch (e) {}
      } catch (e) {}
    });
    if (!hiveBuilderHooked) {
      log('HIVEMQ/broker', '未命中 HiveMQ Builder。下一步: 跑文末 dumpHiveMQ() 列出已加载 com.hivemq.client.* 类与方法,回填 serverHost/serverPort 真实承载类。');
    }
  } catch (e) { skip('HIVEMQ/broker', e); }

  // 2.2 凭据: Mqtt5SimpleAuth / 用户名口令 builder。username(MqttUtf8String|String)、password(ByteBuffer|byte[])
  try {
    var hiveAuthHooked = false;
    Java.enumerateLoadedClassesSync().forEach(function (cn) {
      try {
        if (cn.indexOf('com.hivemq.client') === -1) return;
        if (cn.indexOf('Auth') === -1) return;   // 含 SimpleAuth / *AuthBuilder
        var C = Java.use(cn);
        // username(...)
        try {
          if (C.username) {
            C.username.overloads.forEach(function (ov) {
              try {
                ov.implementation = function () {
                  try { if (arguments.length > 0) log('HIVEMQ/auth', 'username=' + arguments[0]); } catch (e) { skip('HIVEMQ/auth', e); }
                  return ov.apply(this, arguments);
                };
              } catch (e) {}
            });
            hiveAuthHooked = true;
          }
        } catch (e) {}
        // password(ByteBuffer / byte[]) → hex+base64
        try {
          if (C.password) {
            C.password.overloads.forEach(function (ov) {
              try {
                ov.implementation = function () {
                  try {
                    var a = arguments.length > 0 ? arguments[0] : null;
                    if (a === null) { log('HIVEMQ/auth', 'password=null'); }
                    else if (isJavaByteArray(a)) {
                      log('HIVEMQ/auth', 'password(byte[]) len=' + a.length + ' hex=' + bytesToHex(a) + ' b64=' + bytesToB64(a));
                    } else {
                      // ByteBuffer: 复制出 byte[] 不破坏 position
                      var arr = byteBufferToBytes(a);
                      if (arr !== null) log('HIVEMQ/auth', 'password(ByteBuffer) len=' + arr.length + ' hex=' + bytesToHex(arr) + ' b64=' + bytesToB64(arr));
                      else log('HIVEMQ/auth', 'password(未解码)=' + a);
                    }
                  } catch (e) { skip('HIVEMQ/auth', e); }
                  return ov.apply(this, arguments);
                };
              } catch (e) {}
            });
            hiveAuthHooked = true;
          }
        } catch (e) {}
      } catch (e) {}
    });
    if (!hiveAuthHooked) {
      log('HIVEMQ/auth', '未命中 HiveMQ SimpleAuth。下一步: dumpHiveMQ() 找 *SimpleAuthBuilder,确认 username/password 方法签名后回填。');
    }
  } catch (e) { skip('HIVEMQ/auth', e); }

  // 2.3 发布: *MqttPublishBuilder.topic(...) / payload(byte[]|ByteBuffer)
  try {
    var hivePubHooked = false;
    Java.enumerateLoadedClassesSync().forEach(function (cn) {
      try {
        if (cn.indexOf('com.hivemq.client') === -1) return;
        if (cn.indexOf('PublishBuilder') === -1 && cn.indexOf('Publish') === -1) return;
        var C = Java.use(cn);
        try {
          if (C.topic) {
            C.topic.overloads.forEach(function (ov) {
              try {
                ov.implementation = function () {
                  try { if (arguments.length > 0) log('HIVEMQ/publish', 'topic=' + arguments[0]); } catch (e) { skip('HIVEMQ/publish', e); }
                  return ov.apply(this, arguments);
                };
              } catch (e) {}
            });
            hivePubHooked = true;
          }
        } catch (e) {}
        try {
          if (C.payload) {
            C.payload.overloads.forEach(function (ov) {
              try {
                ov.implementation = function () {
                  try {
                    var a = arguments.length > 0 ? arguments[0] : null;
                    if (a !== null && isJavaByteArray(a)) {
                      log('HIVEMQ/publish', 'payload(byte[]) len=' + a.length + ' hex=' + bytesToHex(a) + ' b64=' + bytesToB64(a));
                    } else if (a !== null) {
                      var arr = byteBufferToBytes(a);
                      if (arr !== null) log('HIVEMQ/publish', 'payload(ByteBuffer) len=' + arr.length + ' hex=' + bytesToHex(arr) + ' b64=' + bytesToB64(arr));
                      else log('HIVEMQ/publish', 'payload(未解码)=' + a);
                    }
                  } catch (e) { skip('HIVEMQ/publish', e); }
                  return ov.apply(this, arguments);
                };
              } catch (e) {}
            });
            hivePubHooked = true;
          }
        } catch (e) {}
      } catch (e) {}
    });
    if (!hivePubHooked) {
      log('HIVEMQ/publish', '未命中 HiveMQ PublishBuilder。下一步: dumpHiveMQ() 找 *MqttPublishBuilder,确认 topic/payload 签名回填; 接收侧搜 *MqttPublish.getPayloadAsBytes 补 hook。');
    }
  } catch (e) { skip('HIVEMQ/publish', e); }

  // 2.4 HiveMQ 接收侧: Mqtt*Publish.getPayloadAsBytes() —— 抓收到的消息(混淆下方法名稳定)
  try {
    var hiveRecvHooked = false;
    Java.enumerateLoadedClassesSync().forEach(function (cn) {
      try {
        if (cn.indexOf('com.hivemq.client') === -1) return;
        if (cn.indexOf('Publish') === -1) return;
        var C = Java.use(cn);
        if (C.getPayloadAsBytes) {
          C.getPayloadAsBytes.overload().implementation = function () {
            var r = this.getPayloadAsBytes();
            try {
              var topic = '';
              try { topic = '' + this.getTopic(); } catch (e) {}
              if (r !== null) log('HIVEMQ/recv', 'getPayloadAsBytes topic=' + topic + ' len=' + r.length + ' hex=' + bytesToHex(r) + ' b64=' + bytesToB64(r));
            } catch (e) { skip('HIVEMQ/recv', e); }
            return r;
          };
          hiveRecvHooked = true;
        }
      } catch (e) {}
    });
    if (!hiveRecvHooked) log('HIVEMQ/recv', '未命中 HiveMQ getPayloadAsBytes。下一步: dumpHiveMQ() 搜 *Publish 类的取 payload 方法回填。');
  } catch (e) { skip('HIVEMQ/recv', e); }

  // ============================================================
  // 3) XMPP —— Smack (org.jivesoftware.smack) : 自建 XMPP 也常做 IM 式 C2
  //    抓到什么: connect host:port → 穿透; login(user,pass) → 定人(JID=user@domain); sendStanza/Message body → 固证
  // ============================================================

  // 3.1 连接服务器: AbstractXMPPConnection 子类的 host/port 来自 ConnectionConfiguration
  try {
    var CC = Java.use('org.jivesoftware.smack.ConnectionConfiguration');
    try {
      CC.getHost.implementation = function () {
        var r = this.getHost();
        try { log('XMPP/server', 'getHost=' + r); } catch (e) { skip('XMPP/server', e); }
        return r;
      };
    } catch (e) { skip('XMPP/server', e); }
    try {
      CC.getPort.implementation = function () {
        var r = this.getPort();
        try { log('XMPP/server', 'getPort=' + r + '  (穿透: host:port 即 XMPP 服务器)'); } catch (e) { skip('XMPP/server', e); }
        return r;
      };
    } catch (e) { skip('XMPP/server', e); }
  } catch (e) {
    log('XMPP/server', '未命中 ConnectionConfiguration。下一步: enumerateLoadedClasses 搜 /smack/ 确认 Smack 是否在用; 不在用可忽略本段。e=' + e);
  }

  // 3.2 登录凭据: AbstractXMPPConnection.login(CharSequence user, String pass) —— 直接定人
  try {
    var AXC = Java.use('org.jivesoftware.smack.AbstractXMPPConnection');
    AXC.login.overloads.forEach(function (ov) {
      try {
        ov.implementation = function () {
          try {
            if (arguments.length >= 1) log('XMPP/auth', 'login user=' + arguments[0] + '  (JID user@domain → 定人)');
            if (arguments.length >= 2 && arguments[1] !== null) {
              // 口令: 转 bytes 走 hex+base64( 仅本地编码,不外发 )
              try {
                var StringCls = Java.use('java.lang.String');
                var s = StringCls.$new('' + arguments[1]);
                var raw = s.getBytes('UTF-8');
                log('XMPP/auth', 'login password len=' + raw.length + ' hex=' + bytesToHex(raw) + ' b64=' + bytesToB64(raw));
              } catch (e2) { log('XMPP/auth', 'login password(未解码)'); }
            }
          } catch (e) { skip('XMPP/auth', e); }
          return ov.apply(this, arguments);
        };
      } catch (e) { skip('XMPP/auth', e); }
    });
  } catch (e) {
    log('XMPP/auth', '未命中 AbstractXMPPConnection.login。下一步: enumerateLoadedClasses 搜 /XMPPConnection/ 回填子类(如 XMPPTCPConnection)。e=' + e);
  }

  // 3.3 收发消息: sendStanza(Stanza) 发送 + Message.getBody() 内容固证
  try {
    var AXC2 = Java.use('org.jivesoftware.smack.AbstractXMPPConnection');
    try {
      AXC2.sendStanza.implementation = function (stanza) {
        try { logStanza('XMPP/send', stanza, 'to'); } catch (e) { skip('XMPP/send', e); }
        return this.sendStanza(stanza);
      };
    } catch (e) { skip('XMPP/send', e); }
  } catch (e) { skip('XMPP/send', e); }

  // 3.4 接收消息: StanzaListener.processStanza —— 收到的指令/回执。监听器是样本自定义,用 Java.choose 抓实现类
  try {
    var recvChosen = false;
    Java.choose('org.jivesoftware.smack.StanzaListener', {
      onMatch: function (inst) {
        try {
          recvChosen = true;
          var implName = inst.$className;
          var Impl = Java.use(implName);
          Impl.processStanza.implementation = function (stanza) {
            try { logStanza('XMPP/recv', stanza, 'from', implName); } catch (e) { skip('XMPP/recv', e); }
            return this.processStanza(stanza);
          };
          log('XMPP/recv', 'hooked processStanza @ ' + implName);
        } catch (e) { skip('XMPP/recv', e); }
      },
      onComplete: function () {
        if (!recvChosen) log('XMPP/recv', '未命中 StanzaListener 堆上实例(注入早于监听器注册)。下一步: 监听器注册后在 REPL 重跑 Java.choose(\'...StanzaListener\') 找实现类名再 hook processStanza。');
      }
    });
  } catch (e) { skip('XMPP/recv', e); }

  log('IM-PROBE', 'mqtt-xmpp-im-hook 已挂载。若某栈全程无日志=样本未用该栈或类被 shade 改名,按各 tag 的"下一步"自查回填。');
});

/* ============================================================
 * 自查回填工具(类名/方法被混淆或 shade 改名时,先在 frida REPL 里跑这些定位,再把真实类名填回上面对应 hook):
 *
 * // A) 确认 MQTT/XMPP 栈是否加载、被 shade 成什么名:
 * Java.perform(function(){
 *   Java.enumerateLoadedClasses({
 *     onMatch:function(n){ if(/paho|mqttv3|hivemq|mqtt|smack|xmpp/i.test(n)) console.log(n); },
 *     onComplete:function(){}
 *   });
 * });
 *
 * // B) dumpHiveMQ(): 列出 com.hivemq.client.* 类的方法名,回填 serverHost/serverPort/username/password/topic/payload 真实承载类:
 * function dumpHiveMQ(){ Java.perform(function(){
 *   Java.enumerateLoadedClassesSync().forEach(function(cn){
 *     if(cn.indexOf('com.hivemq.client')===-1) return;
 *     try{ var C=Java.use(cn); var ms=C.class.getDeclaredMethods();
 *       var names=[]; for(var i=0;i<ms.length;i++) names.push(ms[i].getName());
 *       console.log(cn+' :: '+names.join(',')); }catch(e){}
 *   });
 * });}
 *
 * // C) dumpCallback(): 找 Paho MqttCallback 实现类(接收侧 messageArrived 在其中):
 * function dumpCallback(){ Java.perform(function(){
 *   Java.choose('org.eclipse.paho.client.mqttv3.MqttCallback',{
 *     onMatch:function(o){ console.log('MqttCallback impl = '+o.$className); },
 *     onComplete:function(){}
 *   });
 * });}
 *
 * // D) ssl:// 私有 TLS 抓不到明文时: broker 已固证 host:port → 旁路用该端口做 TLS 拦截或在本探针 payload(hook 点已在加密前) 取明文。
 * ============================================================ */