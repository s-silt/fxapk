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
    #: 跑 pipeline 前是否把 dex_strings 填充到 stub 阈值之上（填充发生在
    #: ``tests/synthetic/snapshot.py`` 的 FakeContext 构造处，不改本声明的最小触发内容）。
    #: ★默认 True：不填充的话所有样本都 < _STUB_MAX_DEX_STRINGS，会被结构判据误判「疑加固」、
    #:   dex 可见性掉成 stub_only、7 条穷尽性主张全被阻断——快照锁的就不是正常样本的语义了。
    #: ★stub 样本必须设 False：它锁的恰是「桩 DEX → stub 判定 → 主张全阻断」这条链，
    #:   被填充后 stub_only→complete、blocked 7→5、findings 清空，锁的链就没了（实测）。
    pad_dex_strings: bool = True


#: BIP-39 测试向量助记词（公开测试向量，非任何真实钱包）——触发 WALLET_SECRET。
_TEST_MNEMONIC = "legal winner thank year wave sausage worth useful legal winner thank yellow"

#: 合成 JS：CryptoJS AES-CFB + 硬编码 key + iv=MD5(key+ts) + {timestamp,data} 信封——触发 CRYPTO_RECIPE。
#: 形态复刻真样本，**值全为合成**（key 是 0123456789abcdef 重复串，非任何真实密钥）。
_SYNTHETIC_CRYPTO_JS = """
var cu = CryptoJS;
var wl = "0123456789abcdef0123456789abcdef";
function vu(e){ return cu.MD5(e).toString().substring(0,16); }
function yu(e,t,n){
  const i=cu.enc.Utf8.parse(t), o=cu.enc.Utf8.parse(n);
  return cu.AES.decrypt(e,i,{iv:o,mode:cu.mode.CFB,padding:cu.pad.Pkcs7}).toString(cu.enc.Utf8);
}
request.use((async e=>{
  const t=function(e,t){
    const n=(new Date).getTime(), i=vu(t+n), o=cu.enc.Utf8.parse(t), r=cu.enc.Utf8.parse(i);
    return {timestamp:n, data:cu.AES.encrypt(e,o,{iv:r,mode:cu.mode.CFB,padding:cu.pad.Pkcs7}).toString()};
  }(JSON.stringify(e.data), wl);
  e.data={data:t.data, timestamp:t.timestamp};
}));
"""

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
    SyntheticSample(
        name="wallet-secret-mnemonic",
        dex_strings=[f"backup seed = {_TEST_MNEMONIC} ;"],
        expected_categories=frozenset({"WALLET_SECRET"}),
    ),
    SyntheticSample(
        name="fourth-party-payment-gateway",
        dex_strings=["跑分平台下单 https://pay.evilgw-synthetic.test/api/pay/notify?mch_id=8801"],
        expected_categories=frozenset({"FOURTH_PARTY_PAYMENT"}),
    ),
    SyntheticSample(
        name="crypto-recipe-cryptojs-envelope",
        files={"assets/apps/__UNI__X/www/app-service.js": _SYNTHETIC_CRYPTO_JS.encode("utf-8")},
        expected_categories=frozenset({"CRYPTO_RECIPE"}),
    ),
    SyntheticSample(
        name="card-merchant-keyword",
        dex_strings=["欢迎光临本站，专业卡商一手货源"],
        expected_categories=frozenset({"CARD_MERCHANT"}),
    ),
    SyntheticSample(
        name="payment-sdk-alipay",
        dex_strings=["com.alipay.sdk.app.PayTask", "随便一条无关字符串"],
        expected_categories=frozenset({"PAYMENT"}),
    ),
    # ★第 9 号：加固壳桩样本（唯一 pad_dex_strings=False）。expected_categories 为空不是漏写——
    #   它不锁检出，锁的是「pipeline.run 真入口 → stub 结构判定 → dex 可见性 stub_only →
    #   7 条穷尽性主张全阻断 → corpus/digest 出口」这条**接线**（见 tests/test_synthetic_snapshots.py）。
    #   既有单测（test_packing 走 analyze()、test_p2_wiring 手喂 meta 调 assess）各自盖住分析器
    #   内部与求值函数本身；pipeline 聚合 meta 之后的链此前没锁——实测在聚合处丢掉
    #   is_hardened/hardening_structural 两键，既有网 73 条照样全绿，只有本样本的快照变红。
    #   形态：20 条串（< _STUB_MAX_DEX_STRINGS=1000）+ 一个假 ELF .so。★.so 是形态保真 + 防御：
    #   放行分支（packing.py _flag_stub_dex）要求"无 .so **且确有 .dex 文件**"，FakeContext 根本
    #   没有 .dex 文件条目，故当下即使删掉 .so 也仍判 stub（突变实测）；留着它是复刻真实壳样本
    #   形态，并防 FakeContext 将来补上 .dex 条目后本样本被按极简 App 放行。内容全合成。
    SyntheticSample(
        name="hardened-unidentified-stub",
        dex_strings=[f"stub only string {i}" for i in range(20)],
        files={"lib/arm64-v8a/libshellstub-synthetic.so": b"\x7fELF" + b"\x00" * 64},
        expected_categories=frozenset(),
        pad_dex_strings=False,
    ),
)
