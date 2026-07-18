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


def test_jadx_scan_java_emits_string_chain_finding(tmp_path) -> None:
    """jadx 集成：喂 .java 给 _scan_java（不跑真 jadx），产 STRING-CHAIN-DECRYPT Finding 且诚实标注。"""
    from apkscan.analyzers.jadx import _FINDING_STRING_CHAIN, JadxAnalyzer
    from apkscan.core.models import FINDING_KIND_INFERENCE, Confidence

    (tmp_path / "C.java").write_text(
        f'public class C {{ public String d() {{ String x = "{_SECRET}"; '
        f'return new String(cipher.doFinal(Base64.decode(x, 0))); }} }}',
        encoding="utf-8",
    )
    _eps, findings, _n = JadxAnalyzer()._scan_java(tmp_path)
    chain = [f for f in findings if f.id == _FINDING_STRING_CHAIN]
    assert len(chain) == 1
    assert chain[0].confidence is Confidence.LOW  # 启发式 → 低置信
    assert chain[0].kind == FINDING_KIND_INFERENCE  # 非数据流证明 → inference
    assert "d" in chain[0].description  # 方法名进描述
