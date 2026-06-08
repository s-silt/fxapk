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
        """解码后的 AndroidManifest.xml 文本。"""
        ...

    config: AnalysisConfig
    apk_path: str  # APK 原始文件绝对路径（jadx/unpack 等增强器需要；无则空串）

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

    def native_libs(self) -> list[str]:
        """.so 原生库路径列表。"""
        ...

    def certificates(self) -> list[CertInfo]:
        """签名证书列表。"""
        ...
