"""core.textutil 单测：C4 is_noise_bare_ip 扩展（bogon/保留段）。

注意：noise_ips denylist（1.2.3.4 / 13.3.3.7 等版本号/占位）由调用方（endpoints/
js_bundle/jadx）处理，textutil 保持零规则依赖，故此处只验证 bogon/保留段判定。
"""

from __future__ import annotations

from apkscan.core.textutil import is_noise_bare_ip


def test_zero_first_or_last_octet_is_noise():
    assert is_noise_bare_ip("0.0.0.0") is True
    assert is_noise_bare_ip("10.0.0.0") is True
    assert is_noise_bare_ip("3.2.16.0") is True
    assert is_noise_bare_ip("0.1.2.3") is True


def test_private_loopback_linklocal_reserved_are_noise():
    for ip in (
        "10.0.0.5",
        "192.168.1.100",
        "172.16.5.9",
        "127.0.0.1",
        "169.254.1.1",
        "240.0.0.1",      # 保留段 (class E)
        "224.0.0.1",      # 多播
    ):
        assert is_noise_bare_ip(ip) is True, f"{ip} 应判噪音（bogon/保留段）"


def test_real_public_ips_not_noise():
    # 真实公网 IP（全球可达）不是 bogon/保留段 → 非噪音（不得误杀）。
    for ip in ("8.8.8.8", "139.59.12.34", "1.1.1.1", "104.16.5.7"):
        assert is_noise_bare_ip(ip) is False, f"{ip} 不应判噪音"


def test_doc_testnet_ranges_are_noise():
    # RFC5737 文档示例段（192.0.2/24 / 198.51.100/24 / 203.0.113/24）在 Python 3.12+
    # is_private=True，裸出现作示例数据噪音被过滤（URL host 内仍走 host 通道）。
    for ip in ("192.0.2.5", "198.51.100.7", "203.0.113.45"):
        assert is_noise_bare_ip(ip) is True, f"{ip} 应判文档示例段噪音"


def test_version_like_ips_not_caught_by_bogon():
    # 13.3.3.7 / 2.1.5.1 / 3.2.16.7 / 1.2.3.4 不属任何保留段
    # （靠 noise_ips denylist 在调用方过滤，textutil 本身不挡）。
    for ip in ("13.3.3.7", "2.1.5.1", "3.2.16.7", "1.2.3.4"):
        assert is_noise_bare_ip(ip) is False


def test_non_ipv4_returns_false():
    assert is_noise_bare_ip("not.an.ip") is False
    assert is_noise_bare_ip("1.2.3") is False
    assert is_noise_bare_ip("999.1.1.1") is False
