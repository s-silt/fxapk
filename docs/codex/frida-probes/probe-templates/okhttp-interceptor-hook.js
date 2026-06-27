// okhttp-interceptor-hook.js — 往 OkHttp Interceptor 链注入探针，拿成对的 API 路径/参数 + 完整响应体
// 适用：症状①密文体之外/想要请求+响应成对——http-url 只看 Request，真源站/配置常在 Response body 里
// 跑：frida -U -f <包名> -l okhttp-interceptor-hook.js -q
// 改：要看 app 自带加密拦截器之后的密文，把 addInterceptor 换 addNetworkInterceptor；非 OkHttp 请转 socket-hook.js/native-ssl-hook.js
'use strict';

var PEEK_MAX = 1024 * 1024; // peekBody 上限 1MB，避免大文件/下载流刷爆

Java.perform(function () {
  /* ---------- 注入一个自定义 Interceptor 到 Builder ---------- */
  try {
    var Interceptor = Java.use('okhttp3.Interceptor');
    var Builder = Java.use('okhttp3.OkHttpClient$Builder');
    var Buffer = Java.use('okio.Buffer');

    // 动态实现 okhttp3.Interceptor 接口；已注册则复用，避免 build 被反复调时二次 registerClass 抛 already registered
    var Probe;
    try {
      Probe = Java.use('com.fxapk.OkProbeInterceptor');
    } catch (e) {
      Probe = Java.registerClass({
        name: 'com.fxapk.OkProbeInterceptor',
        implements: [Interceptor],
        methods: {
          intercept: function (chain) {
            var request = chain.request();
            // ---- 请求侧：最终 URL / method / 头 / 明文体 ----
            try {
              console.log('[okint] >>> ' + request.method() + ' ' + request.url().toString());
              var headers = request.headers();
              for (var i = 0; i < headers.size(); i++) console.log('[okint]   H ' + headers.name(i) + ': ' + headers.value(i));
              var body = request.body();
              if (body !== null) {
                try {
                  var buf = Buffer.$new();
                  body.writeTo(buf);
                  console.log('[okint]   req-body: ' + buf.readUtf8());
                } catch (be) { console.log('[okint]   req-body dump skip(可能二进制/一次性体): ' + be); }
              }
            } catch (e) { console.log('[okint] request dump skip: ' + e); }

            // ---- 放行，拿响应 ----
            var response = chain.proceed(request);

            // ---- 响应侧：状态 + peekBody(不消费原 body) ----
            // ResponseBody.string() 是无参方法、自动按 Content-Type 推断字符集——
            // 切勿传 Charset（无该重载，会 overload 解析失败抛错）
            try {
              console.log('[okint] <<< ' + response.code() + ' ' + request.url().toString());
              var peek = response.peekBody(PEEK_MAX);
              console.log('[okint]   resp-body: ' + peek.string());
            } catch (e) { console.log('[okint]   resp-body peek skip(可能是二进制/流): ' + e); }

            return response;
          }
        }
      });
    }

    // hook Builder.build()：在真正构建前把我们的 Interceptor 加进链
    Builder.build.implementation = function () {
      try {
        this.addInterceptor(Probe.$new());
        console.log('[okint] probe interceptor 已注入到 OkHttpClient.Builder');
      } catch (e) { console.log('[okint] addInterceptor skip: ' + e); }
      return this.build();
    };
    console.log('[okint] okhttp3.OkHttpClient$Builder.build hooked');
  } catch (e) { console.log('[okint] OkHttp interceptor 注入 skip(可能非 okhttp3 或已混淆): ' + e); }

  /* ---------- 可选：Retrofit 接口类名 -> 业务含义 ---------- */
  try {
    var Retrofit = Java.use('retrofit2.Retrofit');
    // create(Class) 进来的接口，反混淆调用语义；用 .overload('java.lang.Class') 精确定位
    Retrofit.create.overload('java.lang.Class').implementation = function (service) {
      try { console.log('[okint][retrofit] create service: ' + service.getName()); } catch (e) {}
      return this.create(service);
    };
    console.log('[okint] retrofit2.Retrofit.create hooked');
  } catch (e) { console.log('[okint] retrofit hook skip(无 retrofit 或类名不同): ' + e); }

  console.log('[okint] armed —— 若全程无 [okint] 输出，说明 app 不走 okhttp3(可能 HttpURLConnection/cronet/native)，请转 socket-hook.js / native-ssl-hook.js');
});
