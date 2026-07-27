"""native 控制面通道：地址是算出来的，不是静态串。

★为什么这个分析器必须存在：config-chain 一直假设控制面地址以 http(s) URL 形态摆在
DEX 里，remote_config / config_probe 都只扫具体 URL。实测样本的地址由
``MD5(日期+AppName+SDKVersion+云厂商盐)`` 每天现算，静态里只有 ``%s`` 模板——被动发现
路径抓不到它，报告里 remote_config 与 config_probe_plan 全空，读的人会以为这个样本
没有远程配置通道。
"""

from __future__ import annotations

import base64
import hashlib

from apkscan.analyzers.native_config_channel import NativeConfigChannelAnalyzer
from apkscan.core.gobuildinfo import _INFO_END, _INFO_START

_FAKE_KEY_B64 = base64.b64encode(
    b"-----BEGIN RSA PRIVATE KEY-----\n" + b"A" * 1200 + b"\n-----END RSA PRIVATE KEY-----\n"
).decode()


def _go_lib(
    *,
    templates: tuple[bytes, ...] = (
        b"https://%s.gz.bcebos.com/%s.dat",
        b"https://%s.oss-accelerate.aliyuncs.com/%s.dat",
        b"https://%s.jiangsu-10.zos.ctyun.cn/%s.dat",
    ),
    control: tuple[bytes, ...] = (
        b"resolveControlPlane", b"buildNodeDataURLs", b"fetchFastest", b"decryptNodeData",
    ),
    runtime_inputs: bool = True,
    with_buildinfo: bool = True,
) -> bytes:
    parts = [b"\x7fELF", b"go1.25.0"]
    parts.extend(templates)
    parts.extend(control)
    parts.extend((b"tryDecryptGCM", b"tryDecryptCBC", b"shortMD5", b"pkcs7Unpad"))
    if runtime_inputs:
        parts.extend((
            b"_cgoexp_b055ef97884c_proxysdk_SecretPayload_AppName_Set",
            b"_cgoexp_b055ef97884c_proxysdk_SecretPayload_SDKVersion_Get",
        ))
    if with_buildinfo:
        modinfo = (
            "path\tgobind/gobind\n"
            "mod\tgobind\t(devel)\n"
            "=>\tD:\\workspace\\control_sdk\n"
            f'build\t-ldflags="-X sdk.EmbeddedPrivateKeyB64={_FAKE_KEY_B64}"\n'
        ).encode()
        parts.extend((_INFO_START, modinfo, _INFO_END))
    return b"\x00".join(parts)


class _Ctx:
    platform = "android"

    def __init__(self, libs: dict[str, bytes]) -> None:
        self._libs = libs

    def native_libs(self) -> list[str]:
        return list(self._libs)

    def list_files(self) -> list[str]:
        return list(self._libs)

    def declared_size(self, path: str) -> int:
        return len(self._libs[path])

    def read_file(self, path: str) -> bytes:
        return self._libs[path]

    def dex_strings(self) -> list[str]:
        return []


def _analyze(libs: dict[str, bytes]):
    return NativeConfigChannelAnalyzer().analyze(_Ctx(libs))  # type: ignore[arg-type]


def test_recovers_templates_and_providers() -> None:
    result = _analyze({"lib/arm64-v8a/libgojni.so": _go_lib()})
    ch = result.meta["native_config_channel"]
    providers = {t["provider"] for t in ch["templates"]}
    assert len(ch["templates"]) == 3
    assert "百度智能云 BOS" in providers
    assert "阿里云 OSS 全球加速" in providers
    assert "天翼云 ZOS" in providers


def test_reports_missing_runtime_inputs_instead_of_guessing() -> None:
    """★缺输入就说缺——不拿猜的值拼出一串看着像结论的 URL。"""
    result = _analyze({"lib/arm64-v8a/libgojni.so": _go_lib()})
    ch = result.meta["native_config_channel"]
    assert set(ch["missing_inputs"]) == {"AppName", "SDKVersion"}
    assert ch["url_derivable"] is False
    assert any("动态" in a for a in ch["next_actions"])


def test_produces_finding_but_no_lead() -> None:
    """URL path 与模板都没有可发函的主体，不该产 Lead。"""
    result = _analyze({"lib/arm64-v8a/libgojni.so": _go_lib()})
    assert result.leads == []
    assert [f.id for f in result.findings] == ["NATIVE-CONFIG-CHANNEL"]


def test_injected_private_key_only_as_fingerprint() -> None:
    """★注入的凭据只留指纹，原值不得出现在分析结果的任何角落。"""
    result = _analyze({"lib/arm64-v8a/libgojni.so": _go_lib()})
    blob = repr(result.meta) + repr([f.description for f in result.findings])
    assert _FAKE_KEY_B64 not in blob
    assert _FAKE_KEY_B64[:64] not in blob
    injected = result.meta["native_config_channel"]["build"]["injected"]
    assert injected[0]["sha256"] == hashlib.sha256(_FAKE_KEY_B64.encode()).hexdigest()
    assert "value" not in injected[0]


def test_buildinfo_replace_path_is_carried() -> None:
    ch = _analyze({"lib/arm64-v8a/libgojni.so": _go_lib()}).meta["native_config_channel"]
    assert ch["build"]["replaces"] == ["D:\\workspace\\control_sdk"]


def test_templates_without_control_symbols_are_not_a_channel() -> None:
    """★只有几个像模板的串不算通道——必须有实现它的函数符号，否则是巧合。"""
    result = _analyze({"lib/arm64-v8a/libmedia.so": _go_lib(control=(b"resolveControlPlane",))})
    assert "native_config_channel" not in result.meta


def test_control_symbols_without_templates_are_not_a_channel() -> None:
    result = _analyze({"lib/arm64-v8a/libx.so": _go_lib(templates=())})
    assert "native_config_channel" not in result.meta


def test_plain_library_yields_nothing() -> None:
    result = _analyze({"lib/arm64-v8a/libplain.so": b"\x7fELF" + b"\x00" * 4096})
    assert result.meta == {}
    assert result.findings == []


def test_never_raises_on_unreadable_library() -> None:
    class _Broken(_Ctx):
        def read_file(self, path: str) -> bytes:
            raise OSError("unreadable")

    result = NativeConfigChannelAnalyzer().analyze(  # type: ignore[arg-type]
        _Broken({"lib/arm64-v8a/libgojni.so": _go_lib()})
    )
    assert result.error is None
