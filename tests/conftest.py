"""测试夹具：FakeContext 实现 AnalysisContext 全部接口，单测无需 androguard / 网络。

★ 接口契约：FakeContext 的构造签名固定，所有分析器测试都依赖它。
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from apkscan.core.context import AnalysisContext
from apkscan.core.models import (
    AnalysisConfig,
    CertInfo,
    Component,
    ComponentSet,
)


class FakeContext:
    """AnalysisContext 的测试实现，喂合成数据。

    构造签名（契约，禁止偏移）：
        FakeContext(package_name="com.test.app", manifest_xml="",
                    permissions=None, files=None, dex_strings=None,
                    native_libs=None, certificates=None, components=None,
                    online=False, apk_path="")

    - files:        dict[str, bytes]
    - dex_strings:  list[str]
    - native_libs / certificates / permissions: list
    - components:   ComponentSet | None
    - apk_path:     APK 原始文件绝对路径（jadx/unpack 等增强器需要；默认空串）
    """

    def __init__(
        self,
        package_name: str = "com.test.app",
        manifest_xml: str = "",
        permissions: list[str] | None = None,
        files: dict[str, bytes] | None = None,
        dex_strings: list[str] | None = None,
        native_libs: list[str] | None = None,
        certificates: list[CertInfo] | None = None,
        components: ComponentSet | None = None,
        online: bool = False,
        apk_path: str = "",
        platform: str = "android",
    ) -> None:
        self.package_name = package_name
        self.manifest_xml = manifest_xml
        self.config = AnalysisConfig(online=online)
        self.apk_path = apk_path
        self.platform = platform

        self._permissions = list(permissions or [])
        self._files = dict(files or {})
        self._dex_strings = list(dex_strings or [])
        self._native_libs = list(native_libs or [])
        self._certificates = list(certificates or [])
        self._components = components if components is not None else ComponentSet()

    def permissions(self) -> list[str]:
        return list(self._permissions)

    def components(self) -> ComponentSet:
        return self._components

    def dex_strings(self) -> Iterator[str]:
        return iter(self._dex_strings)

    def list_files(self) -> list[str]:
        return list(self._files.keys())

    def read_file(self, path: str) -> bytes | None:
        return self._files.get(path)

    def native_libs(self) -> list[str]:
        return list(self._native_libs)

    def certificates(self) -> list[CertInfo]:
        return list(self._certificates)


# 确保 FakeContext 与协议契约一致（结构化校验，运行期断言）。
_PROTOCOL_CHECK: type[AnalysisContext] = FakeContext  # noqa: F841


@pytest.fixture
def fake_ctx() -> FakeContext:
    """带少量样例数据的 FakeContext。"""
    manifest = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.test.app">\n'
        '  <uses-permission android:name="android.permission.INTERNET"/>\n'
        '  <application>\n'
        '    <activity android:name=".MainActivity" android:exported="true"/>\n'
        '    <service android:name=".SyncService" android:exported="false"/>\n'
        '  </application>\n'
        '</manifest>\n'
    )
    components = ComponentSet(
        activities=[Component(name="com.test.app.MainActivity", exported=True, kind="activity")],
        services=[Component(name="com.test.app.SyncService", exported=False, kind="service")],
    )
    cert = CertInfo(
        subject="CN=Test Dev, O=Test Co",
        issuer="CN=Test Dev, O=Test Co",
        sha256="a" * 64,
        not_before="2024-01-01T00:00:00",
        not_after="2049-01-01T00:00:00",
        is_debug=False,
        schemes=["v1", "v2"],
    )
    return FakeContext(
        package_name="com.test.app",
        manifest_xml=manifest,
        permissions=["android.permission.INTERNET"],
        files={
            "AndroidManifest.xml": manifest.encode("utf-8"),
            "assets/config.json": b'{"api":"https://pay.example.com/notify"}',
            "lib/arm64-v8a/libnative.so": b"\x7fELF",
        },
        dex_strings=[
            "https://pay.example.com/notify",
            "http://1.2.3.4:8080/api",
            "cn.jpush.android.api.JPushInterface",
        ],
        native_libs=["lib/arm64-v8a/libnative.so"],
        certificates=[cert],
        components=components,
        online=False,
    )
