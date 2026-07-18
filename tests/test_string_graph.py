"""config-chain 层②：方法作用域 string→decrypt→sink 启发式绑定测试（纯离线、不需 jadx）。

重点验证「方法级」相对盲窗的意义：密文与解密调用**须同一方法体内**才绑链（跨方法不误绑），以及括号配对
对字符串/注释里的花括号免疫（不被提前闭合）。
"""

from __future__ import annotations

from apkscan.config.string_graph import (
    StringChain,
    _looks_ciphertext,
    _match_block,
    scan_java_source,
)

_SECRET = "abcdef0123456789abcdef0123456789abcdef01"  # 40 hex → 密文候选


def test_looks_ciphertext() -> None:
    assert _looks_ciphertext(_SECRET) is True  # hex 40
    assert _looks_ciphertext("QUFCQkNDRERFRUZGR0dISElKS0w=") is True  # base64
    assert _looks_ciphertext("hello") is False  # 太短/明文
    assert _looks_ciphertext("/api/login") is False
    assert _looks_ciphertext("") is False


def test_chain_bound_when_ciphertext_and_decrypt_in_same_method() -> None:
    src = f'''
    public class C {{
        public String decryptConfig() {{
            String data = "{_SECRET}";
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] out = c.doFinal(Base64.decode(data, 0));
            return new String(out);
        }}
    }}
    '''
    chains = scan_java_source(src, "com/x/C.java")
    assert len(chains) == 1
    ch = chains[0]
    assert isinstance(ch, StringChain)
    assert ch.method == "decryptConfig"
    assert ch.secret == _SECRET
    assert any("doFinal" in d or "getInstance" in d for d in ch.decrypt_calls)
    assert ch.sinks == ()  # 该方法无 sink
    assert ch.location == "com/x/C.java"


def test_sink_captured_as_context() -> None:
    src = f'''
    public String fetch() {{
        String data = "{_SECRET}";
        byte[] p = cipher.doFinal(x);
        java.net.URL u = new URL(new String(p));
        return u.toString();
    }}
    '''
    chains = scan_java_source(src, "loc")
    assert len(chains) == 1
    assert any("URL" in s for s in chains[0].sinks)


def test_no_chain_without_decrypt() -> None:
    # 密文串但方法内无解密调用 → 不绑链（避免把任意 base64 常量当密文）
    src = f'public void store() {{ String k = "{_SECRET}"; prefs.put("k", k); }}'
    assert scan_java_source(src, "loc") == []


def test_method_scoping_ciphertext_and_decrypt_in_different_methods() -> None:
    # ★方法级核心证明：密文在方法 a、解密在方法 b → 不绑链（盲窗会误绑，方法级不会）
    src = f'''
    public void a() {{ String data = "{_SECRET}"; log(data); }}
    public void b() {{ byte[] out = cipher.doFinal(payload); }}
    '''
    assert scan_java_source(src, "loc") == []


def test_braces_in_string_and_comment_do_not_break_method_scope() -> None:
    # 括号配对须跳过字符串/注释里的花括号，否则方法体被提前截断、漏掉后面的解密调用
    src = f'''
    public void m() {{
        String noise = "has }} a brace";
        // trailing }} comment brace
        /* block }} brace */
        if (flag) {{ helper(); }}
        String data = "{_SECRET}";
        cipher.doFinal(data.getBytes());
    }}
    '''
    chains = scan_java_source(src, "loc")
    assert len(chains) == 1 and chains[0].method == "m"


def test_match_block_handles_nesting_and_literals() -> None:
    text = 'x { a { "b}" } /* } */ c }'
    open_idx = text.index("{")
    end_idx = _match_block(text, open_idx)
    assert end_idx is not None and text[end_idx] == "}"
    assert end_idx == len(text) - 1  # 最外层闭合在末尾


def test_match_block_unbalanced_returns_none() -> None:
    assert _match_block("{ unclosed", 0) is None


def test_control_keyword_blocks_not_treated_as_methods() -> None:
    # 纯控制块（含密文+解密但在方法外不可能；这里确保 if(...) 不被当方法起点从而错误产链）
    src = f'if (cond) {{ String d = "{_SECRET}"; cipher.doFinal(d); }}'
    # if 块被排除为方法 → 不产链（该场景实际不会脱离方法出现，此处仅验证 _CONTROL_KW 排除）
    assert scan_java_source(src, "loc") == []


def test_bad_input() -> None:
    assert scan_java_source("", "loc") == []
    assert scan_java_source(None, "loc") == []  # type: ignore[arg-type]
    assert scan_java_source("no methods here just text", "loc") == []


# --------------------------------------------------------------------------- #
# 复审回归：掩码 / 匿名类 / 证书-路径-URL 误报 / AES 常量表
# --------------------------------------------------------------------------- #
def test_comment_pseudo_method_does_not_create_phantom_scope() -> None:
    """复审 P2：注释里的 name(){ 曾被当方法起点、幻影作用域吞真方法致跨方法误绑。掩码后 → 0 链。"""
    src = f'''
    public class C {{
        /* legacy (disabled):
        private String decode(String s) {{
        */
        private void store() {{ String data = "{_SECRET}"; }}
        private void net() {{ byte[] out = cipher.doFinal(key); }}
    }}
    '''
    assert scan_java_source(src, "loc") == []  # store 有密文无解密、net 有解密无密文，不跨方法误绑


def test_line_comment_pseudo_method_masked() -> None:
    src = f'''
    // TODO restore: init(ctx) {{
    void store() {{ String d = "{_SECRET}"; }}
    void net() {{ cipher.doFinal(k); }}
    '''
    assert scan_java_source(src, "loc") == []


def test_anonymous_class_field_initializer_not_phantom_method() -> None:
    """复审 P2：字段初始化器匿名类 new X(){ 曾被当伪方法（名=类型名）、误并兄弟方法。前邻 new 排除后 → 0 链。"""
    src = f'''
    public class C {{
        private WebViewClient client = new WebViewClient() {{
            public void onPageFinished(WebView v, String u) {{ String d = "{_SECRET}"; }}
            private void other() {{ byte[] o = cipher.doFinal(k); }}
        }};
    }}
    '''
    chains = scan_java_source(src, "loc")
    assert chains == []  # onPageFinished 密文仅存不消费、other 有解密无密文；无伪方法误绑
    assert not any(c.method == "WebViewClient" for c in chains)


def test_embedded_certificate_not_flagged_as_ciphertext() -> None:
    """复审 P2：内嵌证书(MII…)+Base64.decode+sink 曾产完整假链。MII 前缀免疫后 → 0 链。"""
    cert = "MIIDdzCCAl8gAwIBAgIERnd0aGlzSXNBRmFrZUNlcnRCYXNlNjRTdHJpbmcxMjM0NTY3ODkw"
    src = f'''
    public java.net.URLConnection load() {{
        String certB64 = "{cert}";
        byte[] der = Base64.decode(certB64, 0);
        return new URL(base).openConnection();
    }}
    '''
    assert scan_java_source(src, "loc") == []


def test_class_path_and_url_not_ciphertext() -> None:
    """复审 P2：类路径(含 / 落 base64 字符类)/URL 曾被判密文。补熵下限 + 排 :// 后不判密文。"""
    assert _looks_ciphertext("com/google/android/gms/common/api/internal/Handler") is False  # 低熵路径
    assert _looks_ciphertext("https://api.example.com/user/AbCdEf123456/profile") is False  # URL
    # 端到端：类路径 + Base64.decode 同方法 → 不绑链
    src = '''
    public void reflect() {
        String cls = "com/google/android/gms/common/api/internal/HandlerImpl";
        Object x = Base64.decode(cls, 0);
    }
    '''
    assert scan_java_source(src, "loc") == []


def test_algorithm_constant_table_not_a_decrypt_call() -> None:
    """复审 nit：仅存放 "AES/CBC/PKCS5Padding" 常量的方法曾被 AES/ 误判有解密。移除 AES/ 后 → 0 链。"""
    src = f'''
    public String algoTable() {{
        String algo = "AES/CBC/PKCS5Padding";
        String seed = "{_SECRET}";
        return algo + seed;
    }}
    '''
    assert scan_java_source(src, "loc") == []


def test_pure_base64_c2_config_still_chains() -> None:
    """正向回归：真 base64 密文（无 / 高熵、非免疫前缀）+ 解密 仍绑链——修误报没误杀真阳性。"""
    b64 = "QUFCQkNDRERFRUZHSElKS0xNTk9QUVJTVFVWV1hZWjEyMzQ1Njc4OQ=="
    src = f'''
    public String c2() {{
        String data = "{b64}";
        byte[] p = cipher.doFinal(Base64.decode(data, 0));
        return new String(p);
    }}
    '''
    chains = scan_java_source(src, "loc")
    assert len(chains) == 1 and chains[0].secret == b64


# --------------------------------------------------------------------------- #
# AI 辅助解密线索：密文被直接传进改名的解密 helper（重度混淆样本，真机验证过）
# --------------------------------------------------------------------------- #
_CT = "aB3xK9mP2qR7sT5vW1yZ4nL6jH8gF0dS/cV+eXbMkQwErTyUiOpAsDfGhJkLzXcVbNm=="  # base64 密文形态


def test_camelcase_identifier_not_ciphertext() -> None:
    """全月语料回归：纯字母 camelCase 标识符（无数字无 +/=）不当密文——某混淆样本 showMethodErrorToast(\"方法名\")
    那类误报（标识符如 getUserDisplayNameAVChatKit …落 base64 字母表但非密文）。"""
    for ident in (
        "getUserDisplayNameAVChatKit", "isRunningInsideShellClose", "onViewInitFinishedDDApplication",
        "getTeamMemberDisplayNameAVChatKit",
    ):
        assert _looks_ciphertext(ident) is False, ident
    assert _looks_ciphertext("z3G2E737gj6gbdUZ4uR2zw==") is True  # 真 base64 密文（含数字+==）仍认
    # 端到端：标识符传进函数不绑链（否则每个混淆 app 冒几十条假链）
    assert scan_java_source('void a(){ showMethodErrorToast("getUserDisplayNameAVChatKit"); }', "loc") == []


def test_field_constant_ciphertext_recall() -> None:
    """字段常量召回：``static K = 密文``（类级、方法体外）+ 某方法里 ``dec(K)`` → 类作用域绑上，method=class:名。"""
    src = f'class C {{ static String K = "{_CT}"; void m() {{ String u = dec(K); }} }}'
    chains = scan_java_source(src, "x")
    assert len(chains) == 1
    assert chains[0].method == "class:C" and chains[0].consumer == "dec"
    assert chains[0].secret == _CT


def test_class_scope_no_cross_method_false_bind_via_decrypts() -> None:
    """精度：类里有某解密调用**不**把无关的字段密文全绑上——类作用域只走"该密文被消费"、不看类级 decrypts。
    否则盲窗在类粒度复活（跨方法误绑）。"""
    # bg 是密文字段但**没被任何调用消费**；另有方法含 doFinal → 不绑（类作用域忽略 decrypts）
    src = f'class C {{ String bg = "{_CT}"; void x() {{ byte[] o = cipher.doFinal(y); }} }}'
    assert scan_java_source(src, "x") == []


def test_obfuscated_decrypt_helper_binds_as_ai_lead() -> None:
    """密文被直接传进改名 helper m1136x() → 绑链(consumer=m1136x, 无标准解密)，完整密文保留供 AI 解密。"""
    src = f'public void run() {{ String u = AbstractC0421d.m1136x("{_CT}"); conn.get(u); }}'
    chains = scan_java_source(src, "loc")
    assert len(chains) == 1
    c = chains[0]
    assert c.consumer == "m1136x"
    assert c.decrypt_calls == ()  # 混淆改名 → 认不出标准 crypto API
    assert c.secret == _CT  # ★完整密文保留（不截断），供下游 AI/appcrypto 解密


def test_ciphertext_to_denylisted_consumer_not_bound() -> None:
    """密文传进 equals/Log/put/append 等明显非解密方法 → 不绑（denylist 降 AI 线索误报）。"""
    for fn in ("equals", "d", "put", "append", "valueOf"):
        assert scan_java_source(f'void m() {{ x.{fn}("{_CT}"); }}', "loc") == [], fn


def test_ciphertext_only_stored_still_not_bound() -> None:
    """密文只是赋值存着、既没被消费也没解密 → 不绑（避免纯常量误报）。"""
    assert scan_java_source(f'void m() {{ String k = "{_CT}"; }}', "loc") == []


def test_assign_then_decrypt_local_var_bound() -> None:
    """召回补强：``var = 密文; helper(var)``（先赋值再解密，混淆最常见写法）→ 绑链，consumer=被调函数。"""
    chains = scan_java_source(f'void a() {{ String s = "{_CT}"; String u = dec(s); }}', "loc")
    assert len(chains) == 1 and chains[0].consumer == "dec"
    # 多参也认（密文变量在实参列表里）
    chains2 = scan_java_source(f'void a() {{ String s = "{_CT}"; String u = decrypt(ctx, s, 0); }}', "loc")
    assert len(chains2) == 1 and chains2[0].consumer == "decrypt"


def test_nested_method_same_ciphertext_deduped_to_one() -> None:
    """嵌套方法/匿名类里同一串密文只出一条（按密文去重，而非按方法）——避免同串重复进 decrypt 清单。"""
    src = f'''
    void outer() {{
        new Runnable() {{
            public void run() {{ String u = dec("{_CT}"); }}
        }}.run();
    }}
    '''
    chains = scan_java_source(src, "loc")
    assert len(chains) == 1  # outer + run 两个作用域都含该密文，去重后一条
    assert chains[0].secret == _CT


def test_assign_then_denylisted_or_unused_not_bound() -> None:
    """赋值后只传给 denylist 方法（存储/日志）或根本没用到 → 不绑。"""
    assert scan_java_source(f'void a() {{ String s = "{_CT}"; map.put("k", s); }}', "loc") == []
    assert scan_java_source(f'void a() {{ String s = "{_CT}"; return; }}', "loc") == []


def test_full_ciphertext_not_truncated() -> None:
    """完整密文保留（旧版截断到 120 会丢解密载荷）：>120 的密文经改名 helper 仍全量带出。"""
    long_ct = "aB3xK9mP2qR7sT5vW1yZ4nL6jH8gF0dS" * 7  # 224 chars, 无 / 高熵形态
    chains = scan_java_source(f'void run() {{ dec.x("{long_ct}"); }}', "loc")
    assert len(chains) == 1 and chains[0].secret == long_ct and len(chains[0].secret) == 224


def test_ai_decrypt_lead_finding_and_meta_candidates(tmp_path) -> None:
    """jadx 集成：改名 helper 案例 → 'AI 辅助解密线索' Finding（证据带完整密文）+ meta.decrypt_candidates。"""
    from apkscan.analyzers.jadx import _FINDING_STRING_CHAIN, JadxAnalyzer

    (tmp_path / "C.java").write_text(
        f'public void run() {{ String u = AbstractC0421d.m1136x("{_CT}"); }}', encoding="utf-8")
    _eps, findings, _n, candidates = JadxAnalyzer()._scan_java(tmp_path)
    chain = [f for f in findings if f.id == _FINDING_STRING_CHAIN]
    assert len(chain) == 1
    assert "AI 辅助解密" in chain[0].title
    assert "m1136x" in chain[0].description
    assert chain[0].evidences[0].snippet == _CT  # 证据带完整密文（AI 可直接解）
    assert len(candidates) == 1
    assert candidates[0]["ciphertext"] == _CT
    assert candidates[0]["consumer"] == "m1136x"
    assert candidates[0]["standard_decrypt"] == []


def test_jadx_scan_java_emits_string_chain_finding(tmp_path) -> None:
    """jadx 集成：喂 .java 给 _scan_java（不跑真 jadx），产 STRING-CHAIN-DECRYPT Finding 且诚实标注。"""
    from apkscan.analyzers.jadx import _FINDING_STRING_CHAIN, JadxAnalyzer
    from apkscan.core.models import FINDING_KIND_INFERENCE, Confidence

    (tmp_path / "C.java").write_text(
        f'public class C {{ public String d() {{ String x = "{_SECRET}"; '
        f'return new String(cipher.doFinal(Base64.decode(x, 0))); }} }}',
        encoding="utf-8",
    )
    _eps, findings, _n, _cand = JadxAnalyzer()._scan_java(tmp_path)
    chain = [f for f in findings if f.id == _FINDING_STRING_CHAIN]
    assert len(chain) == 1
    assert chain[0].confidence is Confidence.LOW  # 启发式 → 低置信
    assert chain[0].kind == FINDING_KIND_INFERENCE  # 非数据流证明 → inference
    assert "d" in chain[0].description  # 方法名进描述


# ── 精度回归：真实 jadx 输出形态的四类误报 ───────────────────────────────────────
# 一次真实样本跑出 36 条 decrypt_candidates，其中 34 条不是密文；换个样本 31 条全错。
# 四类误报里 3 类经 _looks_ciphertext 的 infra.looks_like_encoding 兜底放行——那个函数
# 是给「点分域名逐 label 找编码伪域名」写的，按 `.` 切标签后只看单个标签，于是整串含
# 空格/冒号也不设防，长 camelCase 类名（熵 4.0-4.2）必然过门。#191 的 binary-hint+熵
# 护栏只挂在 _B64_RE 整串分支上，管不到兜底路径。


def test_jadx_not_decompiled_placeholder_is_not_ciphertext() -> None:
    """jadx 对每个反编译失败的方法都吐 ``throw new UnsupportedOperationException("Method not
    decompiled: …")``——密文侧与 consumer 侧同源自这一行错误，是反编译器噪音而非密文。"""
    ph = "Method not decompiled: e.LayoutInflaterFactory2C0126E.G(e.D, android.view.KeyEvent):void"
    assert _looks_ciphertext(ph) is False


def test_dotted_java_qualified_name_is_not_ciphertext() -> None:
    """点分 Java 限定名（框架 Bundle key 常量、Class.forName 目标）不是密文。"""
    for s in (
        "androidx.view.accessibility.AccessibilityNodeInfoCompat.PANE_TITLE_KEY",
        "org.bouncycastle.jsse.provider.BouncyCastleJsseProvider",
        "org/slf4j/impl/StaticLoggerBinder.class",
    ):
        assert _looks_ciphertext(s) is False, s


def test_base64_alphabet_constant_is_not_ciphertext() -> None:
    """base64 标准/URL-safe 字母表常量本身：熵恰为最大值 6.0——满熵是字母表的特征、不是
    密文的特征，熵下限护栏数学上不可能拦住它，必须显式排除。"""
    for alphabet in (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    ):
        assert _looks_ciphertext(alphabet) is False, alphabet


def test_resource_path_and_name_not_ciphertext() -> None:
    """classpath 资源路径与 Android 资源名（无二进制特征）不是密文。"""
    assert _looks_ciphertext("/okhttp3/internal/publicsuffix/") is False
    assert _looks_ciphertext("config_showMenuShortcutsWhenKeyboardPresent") is False


def test_real_ciphertext_survives_precision_guards() -> None:
    """★护栏不得误杀真密文：这两条来自同一真实样本，consumer 均为混淆改名的单字母方法。
    第二条只有 22+2 字符（短于 _B64_RE 的 24 门槛），过去正是靠兜底分支才被收进来。"""
    assert _looks_ciphertext("z3G2E737gj6gbdUZ4uR2zw==") is True
    assert _looks_ciphertext(
        "iKZGmV5javjz4SVEg22YXUSIfF9ENCuJrwoq/iK7MQflPvAn5JTQe+E63qiIkLtmEt2FBrWUw=="
    ) is True


def test_end_to_end_jadx_noise_does_not_bind() -> None:
    """端到端：喂逐字复刻的真实 jadx 输出形态，一条链都不该产。"""
    src = """
    public void G(D d, KeyEvent e) {
        throw new UnsupportedOperationException("Method not decompiled: e.LayoutInflaterFactory2C0126E.G(e.D, android.view.KeyEvent):void");
    }
    public void load() {
        Class<?> c = Class.forName("org.bouncycastle.jsse.provider.BouncyCastleJsseProvider");
    }
    public void bundle(Bundle b) {
        b.putCharSequence("androidx.view.accessibility.AccessibilityNodeInfoCompat.PANE_TITLE_KEY", s);
    }
    """
    assert scan_java_source(src, "loc") == []


def test_exception_constructor_is_never_a_decrypt_consumer() -> None:
    """纵深：异常构造器不是解密 helper——即便实参真的像密文也不绑。"""
    src = f'''
    public void boom() {{
        throw new IllegalStateException("{_SECRET}");
    }}
    '''
    assert scan_java_source(src, "loc") == []


def test_framework_accessor_is_not_a_decrypt_consumer() -> None:
    """纵深：getX/putX/setX 形态的框架访问器是存取不是解密；混淆改名的 helper 通常是
    1-3 字符（本样本两条真密文的 consumer 都是 ``x``），不受此规则影响。"""
    for call in ("putCharSequence", "getCharSequence", "getInt", "getParcelable", "getIdentifier"):
        src = f'public void m() {{ b.{call}("{_SECRET}"); }}'
        assert scan_java_source(src, "loc") == [], call
    src_ok = f'public void m() {{ x("{_SECRET}"); }}'
    assert len(scan_java_source(src_ok, "loc")) == 1  # 单字母改名 helper 仍照常命中


def test_identifier_constants_with_digits_are_not_ciphertext() -> None:
    """SCREAMING_SNAKE / 扩展名常量靠内嵌数字擦过 binary-hint，但既无 base64 标记、熵也只有 4.1-4.3。
    ★这类与短真密文（熵 4.08）的熵完全重叠，只卡熵会误杀真密文——须靠 base64 标记区分。"""
    for const in (
        "EGL_EXT_gl_colorspace_bt2020_hlg",
        "EGL_EXT_gl_colorspace_bt2020_pq",
        "TEMORARILY_DISABLE_PROTOBUF_VERSION_CHECK",
    ):
        assert _looks_ciphertext(const) is False, const


def test_unpadded_base64url_payload_still_recognised() -> None:
    """无 ``=`` 填充的 base64url 载荷没有 base64 标记，靠熵（5.0+）仍被收下——不能被上一条误杀。"""
    assert _looks_ciphertext("aB3-dEf_GhIjKl9mNoPqR2sTuV5wXyZ0-bC_dE") is True
