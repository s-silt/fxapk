"""应用框架识别：这份样本是用什么框架写的，以及**它自己的业务代码落在哪个文件**。

为什么单独一个模块
------------------
判据里散着一堆「这个 .so 是不是第三方的」判断，而答案取决于框架：Flutter 把整份 Dart
业务代码编译进 ``libapp.so``、Unity 把 C# 经 IL2CPP 编译进 ``libil2cpp.so``——这两个文件
是**本应用自己的代码**，与之并列的引擎库才是第三方。不知道框架就分不清，判据只能靠打补丁。

实测踩过：``libapp.so`` 因为「同文件里带了多个已知基础设施域名」被判成第三方 SDK 库，
于是同一文件里本应用的真实后端被一并降档——而那个域名多，恰恰因为它装着整个应用的业务代码。

与 ``repack_identity`` 的分工
-----------------------------
那边的 ``_COMMERCIAL_STACKS`` 是为「重打包判定」数商业栈族数（族越多越像重打包），
回答的是「用了多少现成能力」。本模块回答的是**另一个问题**：业务代码在哪、哪些文件属于
框架运行时。两者判据可以重叠，用途不同，故不合并——把「数族数」和「定位业务代码」
塞进一个结构，下一个人必然会用错其中一个。

判据只用**编译产物的固定命名**（框架自身的构建规则决定，不是靠名字猜厂商），
且要求**引擎在场**才认定框架——只有一个 ``libapp.so`` 而无 ``libflutter.so`` 时不下结论。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

__all__ = [
    "APP_OWN_CODE_LIBS",
    "META_KEY",
    "AppFramework",
    "detect_framework",
    "framework_from_meta",
    "is_app_own_code",
]

#: 分析器落在 ``report.meta`` 下的键。定义在这里而不是分析器里，是为了让**消费方**
#: （pipeline、报告）不必反向 import 分析器模块就能取到结果。
META_KEY = "app_framework"


@dataclass(frozen=True)
class AppFramework:
    """框架识别结果。

    ``name`` 为空串表示「未识别」——不是「原生 Android」。二者的区别很重要：
    未识别时下游判据应当保持原有行为，而不是按原生的假设去推断。
    """

    name: str = ""
    #: 承载本应用自身业务代码的文件（basename，小写）。原生/未识别时为空。
    own_code_libs: tuple[str, ...] = ()
    #: 属于框架运行时的文件（basename，小写）——这些是第三方。
    runtime_libs: tuple[str, ...] = ()
    #: 判定依据，供报告与人工复核追溯。
    evidence: tuple[str, ...] = field(default_factory=tuple)

    @property
    def identified(self) -> bool:
        return bool(self.name)


#: 框架 → (引擎库前缀, 业务代码库 basename)。
#:
#: ★引擎前缀是**认定框架**的依据；业务代码 basename 是**这个模块存在的理由**。
#:   要求引擎在场才认定：单看到 libapp.so 不足以断定 Flutter（别的东西也可能叫这个名）。
_FRAMEWORKS: Mapping[str, tuple[tuple[str, ...], tuple[str, ...]]] = MappingProxyType({
    # Flutter：Dart 代码经 AOT 编译进 libapp.so，引擎是 libflutter.so。
    "flutter": (("libflutter",), ("libapp.so",)),
    # Unity：C# 经 IL2CPP 转成 C++ 编译进 libil2cpp.so，引擎是 libunity.so。
    "unity": (("libunity",), ("libil2cpp.so",)),
    # React Native：JS 业务代码不在 .so 里（在 assets 的 bundle），故 own_code_libs 为空——
    # 这不是遗漏：RN 的业务代码本就不是 native 库，下游按 assets 找。
    "react_native": (("libhermes", "libjsi", "libfbjni", "libreactnativejni"), ()),
})

#: 所有框架的业务代码容器（并集，小写 basename）。判据可直接用它做「这不是第三方库」的判断。
APP_OWN_CODE_LIBS: frozenset[str] = frozenset(
    lib for _engines, own in _FRAMEWORKS.values() for lib in own
)


def _basename(path: str) -> str:
    return str(path or "").replace("\\", "/").rsplit("/", 1)[-1].lower()


def detect_framework(native_libs: "list[str] | tuple[str, ...]") -> AppFramework:
    """按 native 库清单识别框架。识别不出返回空 ``AppFramework``（不猜、不默认原生）。

    多框架并存时（少见但存在：Unity 游戏内嵌 RN 页面）``name`` 取**业务代码容器非空**的那个，
    但 ``own_code_libs`` 收**所有在场框架**的容器——判据关心的是「哪些文件装着本应用的代码」，
    那是个集合，不该因为要给样本贴一个名字就丢掉另一个框架的容器。

    ★这里曾经只返回一个框架的容器，于是 Unity+Flutter 并存时落选那个的业务代码
      反而失去保护，比不做框架识别时（全局并集无条件生效）更窄——把降噪做成了降档。

    仍然要求**引擎在场**才算数：单 Unity 样本里一个真叫 ``libapp.so`` 的第三方库，因为没有
    ``libflutter.so``，不会被收进 own_code_libs——精确口径的价值正在于此，没有被这次放宽。
    """
    bases = {_basename(p) for p in (native_libs or []) if p}
    if not bases:
        return AppFramework()

    matched: list[AppFramework] = []
    for name, (engine_stems, own_libs) in _FRAMEWORKS.items():
        engines = sorted(b for b in bases if any(b.startswith(s) for s in engine_stems))
        if not engines:
            continue
        present_own = tuple(sorted(lib for lib in own_libs if lib in bases))
        matched.append(AppFramework(
            name=name,
            own_code_libs=present_own,
            runtime_libs=tuple(engines),
            evidence=tuple(f"引擎库 {e}" for e in engines)
            + tuple(f"业务代码容器 {o}" for o in present_own),
        ))
    if not matched:
        return AppFramework()
    matched.sort(key=lambda f: (not f.own_code_libs, f.name))
    primary = matched[0]
    if len(matched) == 1:
        return primary
    # 并存：主框架定名，容器取并集，证据留全（让人看得出这个包里不止一个框架）。
    all_own = tuple(sorted({lib for f in matched for lib in f.own_code_libs}))
    others = ", ".join(f.name for f in matched[1:])
    return AppFramework(
        name=primary.name,
        own_code_libs=all_own,
        runtime_libs=primary.runtime_libs,
        evidence=tuple(e for f in matched for e in f.evidence)
        + (f"同包内并存框架：{others}（其业务代码容器一并计入）",),
    )


def framework_from_meta(meta: object) -> AppFramework:
    """从 ``report.meta['app_framework']`` 复原结果，供**消费方**使用。

    输入不是预期形状（缺键、类型不对、根本没跑过这个分析器）时返回空 ``AppFramework``，
    也就是「未识别」——消费方据此保持原有行为。不抛异常：判据链上游的形状问题不该
    让一次分析整体失败。
    """
    if not isinstance(meta, dict) or not meta.get("identified"):
        return AppFramework()
    name = meta.get("name")
    if not isinstance(name, str) or not name:
        return AppFramework()

    def _strs(key: str) -> tuple[str, ...]:
        raw = meta.get(key)
        if not isinstance(raw, (list, tuple)):
            return ()
        return tuple(_basename(x) for x in raw if isinstance(x, str) and x)

    evidence = meta.get("evidence")
    return AppFramework(
        name=name,
        own_code_libs=_strs("own_code_libs"),
        runtime_libs=_strs("runtime_libs"),
        evidence=tuple(x for x in evidence if isinstance(x, str))
        if isinstance(evidence, (list, tuple))
        else (),
    )


def is_app_own_code(lib_basename: str, framework: "AppFramework | None" = None) -> bool:
    """该 native 库是否承载**本应用自身**的业务代码（而非第三方运行时）。

    给了 ``framework`` 就按识别结果判（准确）；没给则退回全局并集（宽口径，
    用于拿不到框架上下文的调用点）。宽口径的代价是可能把一个真叫 libapp.so 的
    第三方库误当自有——但那个方向的错误是「少降一档」，比反过来把真后端降掉安全。
    """
    base = _basename(lib_basename)
    if framework is not None and framework.identified:
        return base in framework.own_code_libs
    return base in APP_OWN_CODE_LIBS
