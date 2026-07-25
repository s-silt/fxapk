"""合成样本检出回归夹具（零真实 PII）。

见 ``README.md``：用 FakeContext 植入**合成**内容驱动真实 pipeline，断言各 LeadCategory 仍被检出——
让规则改动可回归（改一条规则若掉了某类检出，CI 即红）。所有内容均为合成域名/凭据，无任何真实样本或 PII。
"""
