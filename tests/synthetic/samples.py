"""合成样本定义（零真实 PII）——每个样本 = 植入 FakeContext 的合成内容 + 期望检出的 LeadCategory 集。

★所有域名/凭据均为合成占位（``*.evil-synthetic.test`` / 明显假凭据），不含任何真实样本、受害人或嫌疑人信息。
新增样本见本目录 ``README.md``；触发内容参照各分析器单测里已验证的最小触发串。
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SyntheticSample:
    """一个合成样本：植入 pipeline 的内容 + 期望**必被检出**的 LeadCategory 名集合。

    ``expected_categories`` 是"至少要检出"（子集判据）——回归测试断言它 ⊆ 实际检出集，
    从而抓住"改规则掉了某类检出"的回归；不做全等断言（植入的 URL 亦会被端点抽取产生附带线索）。
    """

    name: str
    dex_strings: list[str] = field(default_factory=list)
    files: dict[str, bytes] = field(default_factory=dict)
    expected_categories: frozenset[str] = frozenset()


#: 合成样本清单。刻意小而稳：每个样本只植入触发**一类**线索的最小合成内容。
SAMPLES: tuple[SyntheticSample, ...] = (
    SyntheticSample(
        name="admin-panel-login-url",
        dex_strings=["base=https://api.evilbackend-synthetic.test/api/admin/login"],
        expected_categories=frozenset({"ADMIN_PANEL"}),
    ),
    SyntheticSample(
        name="backend-credential-db-dsn",
        dex_strings=["db=mysql://root:pass123@db.evil-synthetic.test:3306/app"],
        expected_categories=frozenset({"BACKEND_CREDENTIAL"}),
    ),
    SyntheticSample(
        name="self-hosted-im-websocket",
        dex_strings=['url="wss://im.evilbroker-synthetic.test/socket"'],
        expected_categories=frozenset({"SELF_HOSTED_IM"}),
    ),
)
