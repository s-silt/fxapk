"""分析器共享上下文的依赖倒置抽象。

分析器**只准依赖** AnalysisContext 的公开成员，禁止直接 import androguard。
测试用 FakeContext（tests/conftest.py）实现同一接口 → 单测无需 androguard、无需联网。
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol, runtime_checkable

from apkscan.core.models import AnalysisConfig, CertInfo, ComponentSet


@runtime_checkable
class AnalysisContext(Protocol):
    """分析器共享上下文协议。

    实现：apkscan.core.apk.ApkContext（真实，androguard 驱动）
          tests.conftest.FakeContext（测试，合成数据）
    """

    # package_name / manifest_xml 声明为只读 property：既能被实现方用普通属性
    # （FakeContext）满足，也能被 @cached_property（ApkContext 惰性解析）满足。
    @property
    def package_name(self) -> str:
        """APK 包名。"""
        ...

    @property
    def manifest_xml(self) -> str:
        """解码后的 AndroidManifest.xml 文本（解不出 → 空串）。"""
        ...

    @property
    def platform(self) -> str:
        """包平台（当前仅 ``"android"``）。

        消费方一律 ``getattr(ctx, "platform", "android")`` 兼容读取（对标 ``dex_available``
        的既有做法），故不强制破坏现有构造契约。
        """
        ...

    config: AnalysisConfig
    apk_path: str  # APK 原始文件绝对路径（jadx/unpack 等增强器需要；无则空串）
    #: 脱壳 dump 的额外 .dex 文件路径列表（供 jadx 一并反编译；无则空列表）。
    #: 消费方一律 ``getattr(ctx, "extra_dex_paths", None) or []`` 兼容读取（对标 apk_path 的
    #: 既有做法），故不强制破坏手搓 ctx 的构造契约。
    extra_dex_paths: list[str]
    #: jadx 持久索引的 cache root（opt-in：None/空串 = 不启用，jadx 增强器保持现行为）。
    #: 消费方一律 ``getattr(ctx, "jadx_cache_root", None)`` 兼容读取，手搓 ctx 可不带此属性。
    jadx_cache_root: str | None

    def permissions(self) -> list[str]:
        """声明的权限列表。"""
        ...

    def components(self) -> ComponentSet:
        """四大组件集合（含 exported 标志）。"""
        ...

    def dex_strings(self) -> Iterator[str]:
        """DEX 字符串池（惰性迭代）。"""
        ...

    def list_files(self) -> list[str]:
        """APK 内所有文件路径。"""
        ...

    def read_file(self, path: str) -> bytes | None:
        """按路径读取 APK 内文件，缺失返回 None。"""
        ...

    def declared_size(self, path: str) -> int | None:
        """zip 中央目录声明的解压后大小（纯元数据、不解压）；查不到/不适用返回 None。

        供分析器在 ``read_file`` 前拦截超大/zip 炸弹条目——避免把「小压缩、巨解压」的文件
        先膨胀进内存再判长。返回 None 表示「无法判断」，调用方应保守放行、退回读后判长。
        """
        ...

    def native_libs(self) -> list[str]:
        """.so 原生库路径列表。"""
        ...

    def certificates(self) -> list[CertInfo]:
        """签名证书列表。"""
        ...
