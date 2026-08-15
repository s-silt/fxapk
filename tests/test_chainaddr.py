"""链上地址校验+判链（apkscan.core.chainaddr）测试。

核心价值=校验和把随机 hex/base58 误报砍到可用，从而敢把 BTC legacy 等重新纳入。
全部用公开测试向量：EIP-55 spec / BIP-173 / TRON USDT-TRC20 合约 / BTC 创世地址。

EIP-55 依赖 Keccak-256（≠ 标准库 sha3_256，padding 不同），故纯 Python 自实现，
先用空串已知向量锁死原语。
"""

from __future__ import annotations

from apkscan.core.chainaddr import ChainAddress, find_addresses, keccak256, validate_address

# ---- 公开测试向量 ----
TRON_OK = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"  # USDT-TRC20 合约，合法 Base58Check
TRON_BAD = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6X"  # 末位改动 → 校验和失败
EVM_EIP55 = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"  # EIP-55 官方向量（混合大小写）
EVM_LOWER = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"  # 全小写（无法校验）
EVM_BAD = "0x5Aaeb6053f3e94c9b9a09f33669435e7ef1beaed"  # 混合大小写但校验和错
BTC_BECH32 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"  # BIP-173 P2WPKH 向量
BTC_LEGACY = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"  # BTC 创世地址，合法 Base58Check

_KECCAK_EMPTY = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


def test_keccak256_empty_vector() -> None:
    """锁死 Keccak-256 原语：空串的 Keccak-256（非 SHA3-256）已知值。"""
    assert keccak256(b"").hex() == _KECCAK_EMPTY


def test_validate_tron_ok() -> None:
    a = validate_address(TRON_OK)
    assert a is not None
    assert a.chain == "TRON"
    assert a.checksum_verified is True
    assert a.value == TRON_OK


def test_validate_tron_bad_checksum_rejected() -> None:
    assert validate_address(TRON_BAD) is None  # 校验和失败 → 拒绝（降噪核心）


def test_validate_evm_eip55_ok() -> None:
    a = validate_address(EVM_EIP55)
    assert a is not None
    assert a.chain == "EVM"
    assert a.checksum_verified is True


def test_validate_evm_all_lowercase_unverified() -> None:
    """全小写 EVM 地址无法 EIP-55 校验 → 仍判合法但 checksum_verified=False（低可信，不一票杀）。"""
    a = validate_address(EVM_LOWER)
    assert a is not None
    assert a.chain == "EVM"
    assert a.checksum_verified is False


def test_validate_evm_mixed_bad_checksum_rejected() -> None:
    assert validate_address(EVM_BAD) is None  # 混合大小写但 EIP-55 校验错 → 拒绝


def test_validate_btc_bech32_ok() -> None:
    a = validate_address(BTC_BECH32)
    assert a is not None
    assert a.chain == "BTC"
    assert a.checksum_verified is True


def test_validate_btc_legacy_ok() -> None:
    a = validate_address(BTC_LEGACY)
    assert a is not None
    assert a.chain == "BTC"
    assert a.checksum_verified is True


def test_validate_empty_and_garbage_rejected() -> None:
    assert validate_address("") is None
    assert validate_address("not_an_address") is None
    assert validate_address("0xdeadbeef") is None  # 形态不符（非 40 hex）
    # base58 标识符撞前缀但校验失败
    assert validate_address("T" + "1" * 33) is None


def test_find_addresses_extracts_and_filters_by_checksum() -> None:
    text = f"收款地址 {TRON_OK} 噪声 {TRON_BAD} 以及 {EVM_EIP55} 结束"
    found = find_addresses(text)
    values = {a.value for a in found}
    assert TRON_OK in values
    assert EVM_EIP55 in values
    assert TRON_BAD not in values  # 校验和过滤掉随机串
    assert isinstance(found[0], ChainAddress)
