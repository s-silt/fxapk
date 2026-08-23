"""TLD 策略单一真源（core.tld_policy）测试。

三条各守一个边界：
1. 单一真源：三个消费模块的集合必须是 tld_policy 里的**同一对象**（`is`，非 `==`）——
   今天内容相同可能只是运气，对象同一才防得住将来某处又抄一份字面量的漂移。
2. jadx URL-host 通道走宽集：``https://<域>.top/...`` 这类 URL 派生 host 必须产 domain
   端点（修复前错用窄集把 .top/.cc/.info 等真 C2 常用 TLD 全部误杀）。
3. jadx 裸 token 通道仍走窄集：``rect.top`` 这类裸点分代码标识符绝不产 domain 端点。  # leak-scan: allow 判据要求带热门 TLD 的裸 token 字面：换 example.com 则 .com 本就在窄集内、测不到边界；这是 JS 属性访问形态不是域名
   这条守住修复的边界——URL 放宽绝不许外溢到裸域名通道。

夹具域名全用合成值（c2-fixture.*），不含任何真实案件值。
"""

from __future__ import annotations

import pytest

from apkscan.analyzers import endpoints, jadx, js_bundle
from apkscan.analyzers.jadx import JadxAnalyzer
from apkscan.core import tld_policy
from apkscan.core.models import Endpoint


def test_tld_sets_are_single_source() -> None:
    """三模块的 TLD 集合与 tld_policy 是同一对象（`is`），杜绝字面量漂移。"""
    assert jadx._SAFE_BARE_TLDS is tld_policy.BARE_STRICT_TLDS
    assert endpoints._SAFE_BARE_TLDS is tld_policy.BARE_STRICT_TLDS
    assert js_bundle._SAFE_BARE_TLDS is tld_policy.BARE_STRICT_TLDS
    assert endpoints._COMMON_TLDS is tld_policy.URL_HOST_TLDS


@pytest.mark.parametrize("tld", ["top", "cc", "info", "online", "live", "work"])
def test_jadx_url_host_accepts_common_tld(tld: str) -> None:
    """jadx 的 URL 派生 host 走宽集：窄集缺席的 6 个真 C2 常用 TLD 必须产 domain 端点。"""
    assert tld not in tld_policy.BARE_STRICT_TLDS  # 前提：确在两集差集里，测的是宽集生效
    host = f"c2-fixture.{tld}"
    collector: dict[str, Endpoint] = {}
    JadxAnalyzer()._scan_literal(f"https://{host}/api", "Lcom/example/App;", collector)
    domains = {v for v, ep in collector.items() if ep.kind == "domain"}
    assert host in domains


def test_jadx_bare_token_still_rejected() -> None:
    """jadx 的裸 token 通道仍走窄集：rect.top（无 scheme）不产 domain 端点。"""  # leak-scan: allow 判据要求带热门 TLD 的裸 token 字面：换 example.com 则 .com 本就在窄集内、测不到边界；这是 JS 属性访问形态不是域名
    collector: dict[str, Endpoint] = {}
    JadxAnalyzer()._scan_literal("rect.top", "Lcom/example/App;", collector)  # leak-scan: allow 判据要求带热门 TLD 的裸 token 字面：换 example.com 则 .com 本就在窄集内、测不到边界；这是 JS 属性访问形态不是域名
    assert not any(ep.kind == "domain" for ep in collector.values())
