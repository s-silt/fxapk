"""测试夹具：FakeContext 实现 AnalysisContext 全部接口，单测无需 androguard / 网络。

★ 接口契约：FakeContext 的构造签名固定，所有分析器测试都依赖它。
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

import apkscan.enrichers._ipinfo as _ipinfo_mod
from apkscan.core.context import AnalysisContext
from apkscan.core.models import (
    AnalysisConfig,
    CertInfo,
    Component,
    ComponentSet,
)


@pytest.fixture(autouse=True)
def _reset_ipinfo_shared_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """每个测试前重置 _ipinfo 进程级共享状态（避免跨测试污染）。

    _ipinfo 的共享内存缓存 + 限速时钟是进程级单例，若不重置：上一个测试缓存的 IP 会让
    下一个测试的 lookup_ip 命中缓存而不触网（断言 client.get 调用次数即失败），限速时钟
    也会带入上次 monotonic。同时把 _ipinfo 的限速 sleep 置空（限速已集中到此模块），否则
    多次真实查询会触发真实 sleep 把测试墙钟拖到秒级。

    ★ 只 patch _ipinfo 模块级的 _SLEEP 间接函数，**不** clobber stdlib 全局 time.sleep——
    后者会把进程里别处的 time.sleep（如 test_enrich_concurrency 的 _DelayEnricher）也置空，
    令依赖真实 sleep 的不变量测试退化成恒真。
    """
    _ipinfo_mod.reset_state()
    monkeypatch.setattr(_ipinfo_mod, "_SLEEP", lambda *_a, **_k: None)


@pytest.fixture(autouse=True)
def _no_real_adb(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> None:
    """全套测试一律看不见 adb —— 测试结果与耗时不得取决于开发机装没装 adb。

    ★这条是被真事逼出来的：本机跑 3300+ 用例 60 秒全绿，另一台装了 adb 的机器上同一份代码
      跑到 1204 秒超时（exit 124）。差别只在 PATH 里有没有 adb —— 有 adb 的机器上，那些没把
      设备层 mock 干净的用例（如 ``doctor.run(serial="dev1")`` 只 mock 了 ensure_frida_server，
      其余检查项照跑）会真的去 shell out，对一个并不存在的设备逐条命令等到超时。
      ``read_network_state`` 一次要跑 4 条 shell、每条 su + 回退两次调用，单次就是 8 × 5s。

    ★于是「我这儿是绿的」不是结论，是环境巧合。把 adb 统一挡掉，两台机器才在比同一件事。
      实测：装了假 adb（每次调用 3s）后摘掉本夹具，三个设备测试文件跑满 10 分钟未结束；
      带上夹具则秒级完成。

    要测真调用路径的用例自行 monkeypatch ``device._run`` / ``_adb_root_command`` 即可——
    它们本来就是这么写的，本夹具不影响（见 test_no_real_adb.py 最后一条）。

    ★``adb_path`` 自身的单测（test_tools.py）要的正是这个函数的真实行为，
      用 ``@pytest.mark.real_adb_path`` 标记即可退出本夹具。
    """
    from apkscan.core import tools

    if request.node.get_closest_marker("real_adb_path") is not None:
        return
    monkeypatch.setattr(tools, "adb_path", lambda: "")


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
    - extra_dex_paths: 脱壳 dump 的额外 .dex 路径列表（jadx 一并反编译；默认空列表）
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
        manifest_anomaly: str | None = None,
        declared_sizes: dict[str, int] | None = None,
        extra_dex_paths: list[str] | None = None,
        jadx_cache_root: str | None = None,
        jadx_baseline_index: str | None = None,
    ) -> None:
        self.package_name = package_name
        self.manifest_xml = manifest_xml
        self.config = AnalysisConfig(online=online)
        self.apk_path = apk_path
        # 脱壳 dump 的额外 .dex 路径（jadx 增强器一并反编译用；默认空列表）。
        self.extra_dex_paths = list(extra_dex_paths or [])
        # jadx 持久索引 cache root（opt-in；None=不启用，测试也可 setattr 事后挂）。
        self.jadx_cache_root = jadx_cache_root
        # 调用方断言为官方参照的 jadx 索引 key（opt-in，须同时启用 cache root）。
        self.jadx_baseline_index = jadx_baseline_index
        self.platform = platform
        self.manifest_anomaly = manifest_anomaly

        self._permissions = list(permissions or [])
        self._files = dict(files or {})
        # 显式声明大小（模拟 zip 中央目录元数据；用于测 read_file 前置 size 门：可与实际字节脱钩造「小压缩巨解压」）
        self._declared_sizes = dict(declared_sizes or {})
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

    def declared_size(self, path: str) -> int | None:
        """显式声明大小优先（测 size 门用）；否则退回实际字节长度；查不到 → None。"""
        if path in self._declared_sizes:
            return self._declared_sizes[path]
        b = self._files.get(path)
        return len(b) if b is not None else None

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
