"""TLD 判定策略的单一真源：**刻意的双轨**，不是待统一的冗余。

两档口径针对的是两种完全不同的输入，绝不能合并成一个集合：

- ``BARE_STRICT_TLDS``（窄集，36 条）治**裸域名 token**——反编译源 / 压缩 JS 的
  字面量里出现的裸点分串。``top``/``cc``/``info``/``online``/``live``/``work`` 等
  被**故意**排除：``rect.top`` / ``console.info`` / ``f32.store`` 这类代码标识符  # leak-scan: allow 判据要求带热门 TLD 的裸 token 字面：换 example.com 则 .com 本就在窄集内、测不到边界；这是 JS 属性访问形态不是域名
  与它们高频撞车，收进来会爆量误报。这些 TLD 的真域名仍可经字面量里完整 URL
  （``http(s)://``）的 host 通道抽到，裸通道漏掉它们是可接受的代价。

- ``URL_HOST_TLDS``（宽集，65 条）治 **URL 派生 host**——``http://`` 前缀已确立
  域名性，代码标识符不会长成 ``http://rect.top`` 的形态；此处若错用窄集，会把  # leak-scan: allow 判据要求带热门 TLD 的裸 token 字面：换 example.com 则 .com 本就在窄集内、测不到边界；这是 JS 属性访问形态不是域名
  ``.top``/``.cc``/``.info`` 等真 C2 常用 TLD 的域名误杀，与「宁可漏、不可造」里
  更该守的「不可误杀真线索」冲突。宽集的存在意义正是兜住窄集刻意放走的那批。

★后人注意：看到「两个集合差 29 条」不要动手"统一"——差集就是设计本身。
唯一允许的演进是各档独立增删条目（并递增 ``POLICY_VERSION``），
两档的**适用通道**（裸 token → 窄集，URL host → 宽集）不许交叉。
"""

from __future__ import annotations

POLICY_VERSION: str = "1"

# 裸域名安全 TLD 白名单：字面量内的裸点分串只有末段属此集合才认域名。
# 刻意剔除与代码标识符 / 压缩 JS 高频撞车的短 TLD（top/cc/info/id/to/me/in/so/ai/
# im/store/online/work/link/live/win/...）——见模块 docstring。
BARE_STRICT_TLDS: frozenset[str] = frozenset(
    {
        "com", "cn", "net", "org", "gov", "edu", "biz", "io", "co",
        "xyz", "vip", "club", "shop", "site", "app", "tech", "cloud",
        "fun", "ltd", "pro", "wang", "ren", "mobi", "asia", "icu",
        "hk", "tw", "mo", "jp", "kr", "sg", "us", "uk", "ru", "de", "fr",
    }
)

# URL 派生 host 的常见 TLD 全集：末段命中即认可为域名（URL 语境已排除代码标识符）。
URL_HOST_TLDS: frozenset[str] = frozenset(
    {
        # RFC 2606 / RFC 6761 保留 TLD：永不进入根区、永不解析，故零误报风险。
        # 收进来是为了让「刻意用保留 TLD 保证绝不撞真实域名」的测试夹具与文档示例
        # 照常被识别为域名。
        "test",
        "example",
        "invalid",
        "localhost",

        "com", "cn", "net", "org", "gov", "edu", "info", "biz", "co",
        "io", "me", "tv", "cc", "top", "xyz", "vip", "club", "shop",
        "site", "online", "app", "wang", "ltd", "pro", "asia", "mobi",
        "ren", "win", "link", "live", "fun", "work", "store", "tech",
        "icu", "cloud",
        "hk", "tw", "mo", "jp", "kr", "sg", "us", "uk", "ru", "de", "fr",
        "in", "ph", "my", "th", "vn", "id",
        "to", "ws", "la", "im",
        "so",  # 注意：.so 文件已在各消费方的资源目标判定 / 上游排除
        "gg", "ai", "dev",
    }
)


def url_host_tld_ok(host: str) -> bool:
    """URL 派生 host 是否有**可信的 TLD**——专治 .so 里被截断的 URL 残片。

    ★实测理由（多份真样本）：native ASCII 串被按块切分时，``http://www.<词>...`` 会在
    中途断掉，留下 ``http://www.hortcut`` / ``http://www.years`` 这种残片。裸域名通道有
    严格判定挡着，URL 通道若不设 TLD 门，``http://www.任意小写词`` 都能派生出一个
    "域名端点"，直接污染调证清单。

    判据用 :data:`URL_HOST_TLDS`（65 条，含 top/cc/info/me/online/xyz 等真 C2 常用 TLD）
    而**不用**更窄的 :data:`BARE_STRICT_TLDS`（36 条，缺 top/cc/info）——后者会把真 C2
    误杀。多段 host 只看末段。
    """
    labels = host.lower().rsplit(".", 1)
    return len(labels) == 2 and labels[-1] in URL_HOST_TLDS
