"""分析器写入 ``Report.meta`` 的运行时契约。

这里是分析器 meta 准入与合并策略的权威来源。静态扫描器在契约测试中反向核对生产写入，
避免新增键只改分析器、忘记登记；pipeline 不在运行时解析源码，安装包形态下也保持稳定。
"""

from __future__ import annotations

from dataclasses import dataclass

MERGE_REPLACE = "replace"
MERGE_BOOLEAN_OR = "boolean_or"
PIPELINE_OWNER = "pipeline"


@dataclass(frozen=True)
class MetaKeyContract:
    """一个 meta 键的所有者与聚合策略。"""

    owners: frozenset[str]
    merge: str = MERGE_REPLACE


# 模块内直接写入的键。共享 helper 与有限键族在下方显式补入各自的真实 owner。
_DIRECT: dict[str, frozenset[str]] = {
    "admin_panel": frozenset({"admin_panel_count"}),
    "api_surface": frozenset({"api_surface"}),
    "backend_credential": frozenset({"backend_credential_count"}),
    "build_provenance": frozenset({"build_provenance"}),
    "card_merchant": frozenset({"card_merchant_count"}),
    "certificate": frozenset({"cert_count", "certificates", "schemes", "sign_sha256", "sign_subject"}),
    "components": frozenset({"all_activities", "component_totals", "components", "exported_counts", "exported_total"}),
    "config_keys": frozenset({"config_key_count", "config_keys_input_errors", "uni_app_name", "uni_appid", "uni_encrypted"}),
    "contacts": frozenset({"contacts", "telegram_bot_tokens"}),
    "crypto": frozenset({"finding_ids", "findings", "resources_scanned", "strings_scanned"}),
    "crypto_recipe": frozenset({"crypto_recipe", "crypto_recipe_count", "crypto_recipe_files_scanned"}),
    "deeplink_surface": frozenset({"browsable_deeplink_count", "deeplink_count", "deeplinks"}),
    "dex_obfuscation": frozenset({"dex_string_pool"}),
    "dns_bypass": frozenset({"dns_bypass"}),
    "endpoints": frozenset({"cleartext_count", "dex_scanned", "domain_count", "endpoint_total", "ip_count", "native_files_scanned", "private_count", "resource_files_read_failed", "resource_files_scanned", "resource_listing_failed", "url_count"}),
    "favicon": frozenset({"favicon_mmh3"}),
    "firebase": frozenset({"firebase", "firebase_project_id"}),
    "fourth_party_payment": frozenset({"fourth_party_payment_count"}),
    "jadx": frozenset({"decrypt_candidates", "decrypt_candidates_suppressed", "jadx_endpoint_count", "jadx_java_files", "jadx_status"}),
    "js_bundle": frozenset({"js_domain_count", "js_endpoint_count", "js_files_scanned", "js_framework", "js_ip_count", "js_path_count", "js_secret_count", "js_url_count"}),
    "manifest": frozenset({"allow_backup", "debuggable", "manifest_anomaly", "min_sdk", "network_security_config", "package_name", "suspicious_version_hits", "suspicious_version_name", "target_sdk", "uses_cleartext_traffic", "version_code", "version_name", "xposed_markers", "xposed_module"}),
    "native_config_channel": frozenset({"native_config_channel"}),
    "native_fingerprint": frozenset({"native_lib_hashes"}),
    "native_obfuscation": frozenset({"native_obfuscation"}),
    "packing": frozenset({"container_decoy_entries", "denial_bomb_entries", "dex_scanned", "hardening_structural", "is_hardened", "packed", "packer", "packers"}),
    "payment": frozenset({"crypto_addresses", "dex_scanned", "payment_keywords", "payment_sdks"}),
    "permissions": frozenset({"dangerous_count", "dangerous_matched", "permission_count", "permissions"}),
    "re_toolkit": frozenset({"anti_frida", "hook_frameworks", "re_toolkit"}),
    "remote_config": frozenset({"remote_config_candidate_count", "remote_config_source_scope"}),
    "repack_identity": frozenset({"api_paths", "content_profile", "repack_identity", "signals", "signature", "stack", "verdict"}),
    "sdk_fingerprint": frozenset({"dex_scanned", "sdk_categories", "sdks"}),
    "self_hosted_im": frozenset({"self_hosted_im_channel_count", "self_hosted_im_fingerprints"}),
    "sensitive_api": frozenset({"dex_scanned", "sensitive_api_count", "sensitive_apis"}),
    "sms_forwarding": frozenset({"sms_forwarding_count"}),
    "wallet_secret": frozenset({"wallet_secret_count"}),
    "web_inline_config": frozenset({"web_inline_config_count"}),
    "web_redirect_chain": frozenset({"web_redirect_chain"}),
    "web_request_recipe": frozenset({"web_request_recipe"}),
    "webview_jsbridge": frozenset({"dex_scanned", "webview_signal_count", "webview_signals"}),
}

_DEX_TRUNCATION_OWNERS = frozenset({
    "admin_panel", "api_surface", "backend_credential", "build_provenance", "card_merchant",
    "contacts", "crypto", "dex_obfuscation", "dns_bypass", "endpoints", "fourth_party_payment",
    "packing", "payment", "re_toolkit", "remote_config", "repack_identity", "sdk_fingerprint",
    "self_hosted_im", "sensitive_api", "sms_forwarding", "wallet_secret", "webview_jsbridge",
})


def _build_registry() -> dict[str, MetaKeyContract]:
    owners_by_key: dict[str, set[str]] = {}
    for owner, keys in _DIRECT.items():
        for key in keys:
            owners_by_key.setdefault(key, set()).add(owner)

    # 网页覆盖键是封闭键族；键名与分析器取值域均由生产端权威迭代器给出。
    # 这里不再手抄后缀或三个 web owner，避免 fail-closed 白名单反向吞掉合法信号。
    from apkscan.analyzers.web_evidence import COVERAGE_SUFFIXES, iter_coverage_meta_keys

    for key in iter_coverage_meta_keys():
        suffix = next(s for s in COVERAGE_SUFFIXES if key.endswith(f"_{s}"))
        owner = key.removesuffix(f"_{suffix}")
        owners_by_key.setdefault(key, set()).add(owner)

    registry = {
        key: MetaKeyContract(
            owners=frozenset(owners),
        )
        for key, owners in owners_by_key.items()
    }
    registry["dex_strings_truncated"] = MetaKeyContract(
        owners=_DEX_TRUNCATION_OWNERS,
        merge=MERGE_BOOLEAN_OR,
    )
    # pipeline 派生键也走普通注册：分析器 owner 集为空，因此不能直接产出。
    registry["dex_strings_truncated_by"] = MetaKeyContract(
        owners=frozenset({PIPELINE_OWNER}),
    )
    return registry


META_KEY_REGISTRY: dict[str, MetaKeyContract] = _build_registry()


def allowed_meta_keys(analyzer_name: str) -> frozenset[str]:
    """返回某分析器获准产出的键集合。未知分析器默认无权限（fail closed）。"""

    return frozenset(
        key
        for key, contract in META_KEY_REGISTRY.items()
        if analyzer_name in contract.owners and PIPELINE_OWNER not in contract.owners
    )
