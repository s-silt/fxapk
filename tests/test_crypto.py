"""CryptoAnalyzer 的单测：用 conftest 的 FakeContext 喂合成弱加密 / 硬编码特征。

覆盖：
- 基本属性 name/requires。
- 不命中（普通字符串 / 资源）→ 空产出，无 error。
- MD5 / SHA-1 命中 → Finding(category=crypto, MEDIUM, references 含 CWE-327)。
- DES / 3DES 命中。
- AES/ECB transformation 命中（"AES/ECB/PKCS5Padding"）。
- 裸 getInstance("AES") 默认 ECB 命中。
- RC4 命中。
- 资源文件（read_file）中的弱算法命中（source=resource）。
- 硬编码密钥 / IV 启发式：命名提示 + 定长十六进制常量同现 → 命中；纯命名无常量不命中。
- 大块 Base64 常量命中；短 Base64 不命中。
- 多特征同时出现 → 多条 Finding（每规则一条）。
- 所有 crypto Finding 的 references 都含 CWE-327。
- meta 字段（strings_scanned / resources_scanned / findings / finding_ids）。
- 鲁棒性：dex_strings() / list_files() 抛异常时单源失败不炸整个 analyze。
"""

from __future__ import annotations

from apkscan.analyzers.crypto import CryptoAnalyzer
from apkscan.core.models import AnalyzerResult, Severity

from tests.conftest import FakeContext


def _analyze(
    *,
    dex_strings: list[str] | None = None,
    files: dict[str, bytes] | None = None,
) -> AnalyzerResult:
    ctx = FakeContext(dex_strings=dex_strings, files=files)
    return CryptoAnalyzer().analyze(ctx)


def _finding_ids(result: AnalyzerResult) -> set[str]:
    return {f.id for f in result.findings}


# --- 基本属性 -------------------------------------------------------------


def test_analyzer_name_and_requires() -> None:
    analyzer = CryptoAnalyzer()
    assert analyzer.name == "crypto"
    assert analyzer.requires == []


# --- 不命中 ---------------------------------------------------------------


def test_no_weak_crypto_yields_empty() -> None:
    result = _analyze(
        dex_strings=[
            "com.example.app.MainActivity",
            "https://example.com/api",
            "Cipher.getInstance(\"AES/GCM/NoPadding\")",  # 安全配置，不应命中
            "MessageDigest.getInstance(\"SHA-256\")",  # 安全摘要，不应命中
        ],
        files={"assets/config.json": b'{"timeout": 30, "name": "ok"}'},
    )
    assert result.error is None
    assert result.findings == []
    assert result.leads == []
    assert result.endpoints == []
    assert result.meta["findings"] == 0


def test_aes_gcm_not_flagged() -> None:
    # 明确安全的 AES/GCM 不应被任何规则命中（低误报）。
    result = _analyze(dex_strings=["Cipher.getInstance(\"AES/GCM/NoPadding\")"])
    assert result.findings == []


# --- MD5 / SHA-1 ----------------------------------------------------------


def test_md5_detected() -> None:
    result = _analyze(dex_strings=["MessageDigest.getInstance(\"MD5\")"])
    assert result.error is None
    assert "CRYPTO-MD5" in _finding_ids(result)
    finding = next(f for f in result.findings if f.id == "CRYPTO-MD5")
    assert finding.category == "crypto"
    assert finding.severity == Severity.MEDIUM
    assert any("CWE-327" in r for r in finding.references)
    assert finding.evidences
    assert finding.evidences[0].source == "dex"


def test_sha1_detected() -> None:
    result = _analyze(dex_strings=["val md = MessageDigest.getInstance(\"SHA-1\")"])
    assert "CRYPTO-SHA1" in _finding_ids(result)


# --- DES / 3DES -----------------------------------------------------------


def test_des_detected() -> None:
    result = _analyze(dex_strings=["Cipher.getInstance(\"DES/CBC/PKCS5Padding\")"])
    ids = _finding_ids(result)
    # DES/CBC 命中 DES 规则
    assert "CRYPTO-DES" in ids


def test_triple_des_cipher_detected() -> None:
    result = _analyze(dex_strings=["Cipher.getInstance(\"DESede\")"])
    ids = _finding_ids(result)
    # 裸 DESede 命中 DES-CIPHER 规则
    assert "CRYPTO-DES-CIPHER" in ids


# --- AES/ECB --------------------------------------------------------------


def test_aes_ecb_transformation_detected() -> None:
    result = _analyze(
        dex_strings=["Cipher.getInstance(\"AES/ECB/PKCS5Padding\")"]
    )
    assert "CRYPTO-ECB" in _finding_ids(result)
    finding = next(f for f in result.findings if f.id == "CRYPTO-ECB")
    assert finding.severity == Severity.MEDIUM
    assert any("CWE-327" in r for r in finding.references)


def test_aes_default_ecb_detected() -> None:
    # 裸 getInstance("AES") → 默认 ECB
    result = _analyze(dex_strings=["Cipher.getInstance(\"AES\")"])
    assert "CRYPTO-AES-DEFAULT-ECB" in _finding_ids(result)


def test_rc4_detected() -> None:
    result = _analyze(dex_strings=["Cipher.getInstance(\"RC4\")"])
    assert "CRYPTO-RC4" in _finding_ids(result)


# --- 大小写不敏感 ---------------------------------------------------------


def test_match_case_insensitive() -> None:
    # needle 是 "AES/ECB/"，用全大写资源文本也应命中。
    result = _analyze(
        files={"assets/c.txt": b"cipher.getinstance(\"aes/ecb/pkcs5padding\")"}
    )
    assert "CRYPTO-ECB" in _finding_ids(result)


# --- 资源文件命中（source=resource）--------------------------------------


def test_weak_crypto_in_resource_file() -> None:
    result = _analyze(
        files={
            "assets/crypto.js": b'var algo = "DES/ECB/NoPadding"; // legacy',
        }
    )
    ids = _finding_ids(result)
    assert "CRYPTO-ECB" in ids or "CRYPTO-DES" in ids
    finding = result.findings[0]
    assert any(ev.source == "resource" for f in result.findings for ev in f.evidences)
    assert finding.evidences[0].location == "assets/crypto.js"


def test_binary_resource_not_scanned() -> None:
    # 图片等非文本后缀不扫描，即便字节里含算法名也不命中。
    result = _analyze(files={"res/drawable/icon.png": b'AES/ECB/PKCS5Padding'})
    assert result.findings == []
    assert result.meta["resources_scanned"] == 0


# --- 硬编码密钥 / IV 启发式 ----------------------------------------------


def test_hardcoded_key_detected() -> None:
    # 命名提示 "aeskey" + 32 位十六进制常量同现 → 可疑硬编码密钥。
    result = _analyze(
        dex_strings=[
            'String aesKey = "0123456789abcdef0123456789abcdef";',
        ]
    )
    assert "CRYPTO-HARDCODED-KEY" in _finding_ids(result)
    finding = next(f for f in result.findings if f.id == "CRYPTO-HARDCODED-KEY")
    assert finding.severity == Severity.MEDIUM
    assert any("CWE-327" in r for r in finding.references)


def test_hardcoded_iv_detected() -> None:
    result = _analyze(
        files={
            "res/raw/conf.properties": b'iv=1234567890abcdef1234567890abcdef\n',
        }
    )
    assert "CRYPTO-HARDCODED-KEY" in _finding_ids(result)


def test_key_name_without_constant_not_flagged() -> None:
    # 仅有命名提示但无定长常量 → 不命中（降误报）。
    result = _analyze(dex_strings=['getString("aesKey")', "aeskey lookup"])
    assert "CRYPTO-HARDCODED-KEY" not in _finding_ids(result)


def test_constant_without_key_name_not_flagged() -> None:
    # 有十六进制常量但无密钥相关命名 → 不命中。
    result = _analyze(dex_strings=["0123456789abcdef0123456789abcdef"])
    assert "CRYPTO-HARDCODED-KEY" not in _finding_ids(result)


# --- 大块 Base64 ----------------------------------------------------------


def test_large_base64_blob_detected() -> None:
    blob = "QQ" + "ABCDabcd1234efGH" * 20  # 远超 256 字符的纯 Base64 块
    result = _analyze(dex_strings=[blob])
    assert "CRYPTO-BASE64-BLOB" in _finding_ids(result)
    finding = next(f for f in result.findings if f.id == "CRYPTO-BASE64-BLOB")
    assert finding.severity == Severity.LOW
    assert "base64[len=" in finding.evidences[0].snippet


def test_short_base64_not_flagged() -> None:
    # 短 Base64（< 256）不应触发 blob 规则。
    result = _analyze(dex_strings=["aGVsbG8gd29ybGQ="])  # "hello world"
    assert "CRYPTO-BASE64-BLOB" not in _finding_ids(result)


# --- 多特征同时出现 -------------------------------------------------------


def test_multiple_findings_one_per_rule() -> None:
    result = _analyze(
        dex_strings=[
            "MessageDigest.getInstance(\"MD5\")",
            "Cipher.getInstance(\"AES/ECB/PKCS5Padding\")",
            "Cipher.getInstance(\"DES/CBC/PKCS5Padding\")",
        ]
    )
    ids = _finding_ids(result)
    assert {"CRYPTO-MD5", "CRYPTO-ECB", "CRYPTO-DES"} <= ids
    # 每条规则至多一个 Finding（同一 id 不重复）。
    seen_ids = [f.id for f in result.findings]
    assert len(seen_ids) == len(set(seen_ids))


def test_all_crypto_findings_have_cwe327() -> None:
    result = _analyze(
        dex_strings=[
            "MessageDigest.getInstance(\"MD5\")",
            "Cipher.getInstance(\"AES/ECB/PKCS5Padding\")",
            'String aesKey = "0123456789abcdef0123456789abcdef";',
        ]
    )
    assert result.findings
    for finding in result.findings:
        assert finding.category == "crypto"
        assert any("CWE-327" in r for r in finding.references), finding.id


# --- meta -----------------------------------------------------------------


def test_meta_counts() -> None:
    result = _analyze(
        dex_strings=["MessageDigest.getInstance(\"MD5\")", "plain string"],
        files={"assets/a.json": b"{}", "assets/b.txt": b"hello"},
    )
    assert result.meta["strings_scanned"] == 2
    assert result.meta["resources_scanned"] == 2
    assert result.meta["findings"] == len(result.findings)
    assert "CRYPTO-MD5" in result.meta["finding_ids"]


# --- 鲁棒性：单数据源抛异常不炸整个 analyze ------------------------------


def test_dex_strings_failure_still_scans_resources() -> None:
    class _Ctx(FakeContext):
        def dex_strings(self):  # type: ignore[override]
            raise RuntimeError("boom dex_strings")

    ctx = _Ctx(files={"assets/c.txt": b'Cipher.getInstance("MD5")'})
    result = CryptoAnalyzer().analyze(ctx)
    # dex 源失败被吞并记录，但资源源仍命中。
    assert result.error is None
    assert "CRYPTO-MD5" in {f.id for f in result.findings}
    assert result.meta["strings_scanned"] == 0


def test_list_files_failure_still_scans_dex() -> None:
    class _Ctx(FakeContext):
        def list_files(self):  # type: ignore[override]
            raise RuntimeError("boom list_files")

    ctx = _Ctx(dex_strings=["MessageDigest.getInstance(\"SHA-1\")"])
    result = CryptoAnalyzer().analyze(ctx)
    assert result.error is None
    assert "CRYPTO-SHA1" in {f.id for f in result.findings}
    assert result.meta["resources_scanned"] == 0


def test_read_file_failure_does_not_crash() -> None:
    class _Ctx(FakeContext):
        def read_file(self, path: str):  # type: ignore[override]
            raise RuntimeError("boom read_file")

    ctx = _Ctx(
        files={"assets/c.txt": b'Cipher.getInstance("MD5")'},
        dex_strings=["MessageDigest.getInstance(\"MD5\")"],
    )
    result = CryptoAnalyzer().analyze(ctx)
    # 单文件读取失败被吞，dex 源仍命中。
    assert result.error is None
    assert "CRYPTO-MD5" in {f.id for f in result.findings}


# --- fixture 样例上下文不应误报 -------------------------------------------


def test_fixture_ctx_not_flagged(fake_ctx) -> None:
    # conftest 的样例 ctx（普通 URL / JPush 类名）不含弱加密，不应命中。
    result = CryptoAnalyzer().analyze(fake_ctx)
    assert result.error is None
    assert result.findings == []
