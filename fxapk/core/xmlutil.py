"""安全 XML 解析 —— 封堵 XXE / billion-laughs 的共享实现。

manifest / config_keys 等分析器都需要把 AndroidManifest / strings.xml 等文本安全
解析为 ElementTree。spec 要求用 xml.etree、不得引入 defusedxml 等额外依赖。
CPython 3.12 的 ET.XMLParser 走 C 加速实现、不暴露可改的 expat 钩子，故这里直接用
xml.parsers.expat 创建解析器并安装拒绝处理器：
  - 关闭参数实体解析（SetParamEntityParsing(NEVER)）→ 阻断外部 DTD 拉取（XXE）；
  - 任何 <!ENTITY> 定义（内部/外部/未解析）→ 直接抛错（封堵 billion-laughs）；
  - <!NOTATION>、外部实体引用 → 抛错。
元素/文本/属性事件转发给 ET.TreeBuilder，产出标准 ET.Element。
正常 manifest / strings.xml 不含 DTD/实体，不受影响。

安全敏感代码收敛到单一可信实现。全程 type hints。
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
import xml.parsers.expat as expat

# Android 资源命名空间；ElementTree 会把 android:foo 展开为 {NS}foo。
ANDROID_NS = "http://schemas.android.com/apk/res/android"


class UnsafeXmlError(ValueError):
    """XML 中出现 DTD/实体声明（XXE / billion-laughs 攻击面），拒绝解析。"""


def safe_fromstring(xml_text: str) -> ET.Element:
    """用 stdlib expat + ElementTree.TreeBuilder 安全解析，封堵 XXE / billion-laughs。

    关闭参数实体解析、拒绝任何实体/记法/外部引用声明，其余事件转发给 ET.TreeBuilder。
    正常 manifest / strings.xml 不含 DTD/实体，不受影响。
    """
    builder = ET.TreeBuilder()
    parser = expat.ParserCreate()

    def _reject(*_args: object, **_kwargs: object) -> None:
        raise UnsafeXmlError("XML 含 DTD/实体声明或外部引用，已拒绝解析")

    # 阻断外部 DTD / 参数实体（XXE 主路径）。
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    # 任何实体声明/记法/外部实体引用一律拒绝。
    parser.EntityDeclHandler = _reject
    parser.UnparsedEntityDeclHandler = _reject
    parser.NotationDeclHandler = _reject
    parser.ExternalEntityRefHandler = _reject  # type: ignore[assignment]

    # 转发解析事件到 ElementTree TreeBuilder。
    parser.StartElementHandler = builder.start
    parser.EndElementHandler = builder.end
    parser.CharacterDataHandler = builder.data

    parser.Parse(xml_text, True)
    return builder.close()


def android_attr(elem: ET.Element, name: str) -> str | None:
    """读取 android:<name> 属性；兼容已展开命名空间与裸属性两种形态。"""
    val = elem.get(f"{{{ANDROID_NS}}}{name}")
    if val is not None:
        return val
    # 部分上游（如 androguard 反编译出的字符串）可能不带命名空间前缀。
    return elem.get(f"android:{name}", elem.get(name))
