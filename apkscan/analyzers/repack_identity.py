"""自研马甲包 vs 正版应用被重打包——归属方向判别（P0：防把正版资产错归到样本运营方）。

为什么是 P0：两种形态下，样本里提取的接口 / 域名 / 构建路径的**归属方向完全相反**——
  - 自研马甲包 → 接口是样本运营方自建后端，可直接作调证线索；
  - 正版应用被重打包 → 接口是**被仿冒正版应用自己的**，直接列为线索会向无关企业发函（严重误伤）。
实测中曾把一个正版钱包类应用的 156 条接口错当成样本运营方资产，本分析器就是为堵住这个错。

已实证判据（真实语料，一个 100MB 级钱包类样本的两个发布件）：
  1. 签名形态：正版常见 META-INF/CERT.RSA 或厂商固定别名；重打包件是**随机 8 位大写字母**别名，
     且同一母包出现两个不同签名（9 个 DEX 大小逐一相同、.so 清单完全一致、证书指纹不同）→ 重签发布。
  2. 技术栈完整度：成熟商业应用具完整产品栈（RN + OpenCV + 银行卡识别 + SQLCipher 多族并存）；
     自研样本通常单一框架、功能单一（语料 24 个样本中自研全部 ≤1 族）。

★ 必须守住的边界（比检出更重要）：仅凭样本自身**只能确定「是否被重签名」，无法确定改了什么**。
要确定改动内容必须持官方同版本母包做逐文件差分。因此 Finding 措辞只到「疑似正版应用重打包，
其接口/域名不应直接作为调证线索」，绝不断言改动内容——这是有意克制，不是保守。

三态 verdict（不许二元塌缩）：
  - repack_suspected：随机重签别名 **且** 完整商业栈同时命中——单一信号都不足（随机别名也见于
    个别自研签名习惯；完整栈也可能是正主自己的正常发布件）；
  - self_built：无重打包信号 + 技术栈单薄 + 至少一个自研正向标记（品牌缩写别名 / 调试证书）；
  - unknown：其余一律不判——两个方向的误判都伤（重打包判成自研 → 误伤正版厂商；
    自研判成重打包 → 漏掉真线索），宁 unknown 不硬判。

与兄弟模块的分工：证书主体/有效期形态见 certificate.py；构建机路径分层见 build_provenance.py；
本模块只看「签名文件名形态 + 证书数量摘要 + 技术栈画像」这组归属方向判据。
纯静态；只读 zip 目录元数据（list_files / declared_size）、证书元数据与 dex 字符串池，
**不读任何文件内容**——IO 天然有界（dex 字符串池另有条数上限），绝不抛。
"""
from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from typing import TYPE_CHECKING

from apkscan.analyzers._common import (
    collect_dex_strings,
    collect_file_paths,
    collect_so_basenames,
)
from apkscan.core.models import (
    AnalyzerResult,
    Confidence,
    Evidence,
    Finding,
    Severity,
)
from apkscan.core.registry import BaseAnalyzer

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 阈值（标定语料：24 个真实样本；依据见各行注释）
# ---------------------------------------------------------------------------

_MAX_DEX_STRINGS = 200_000

#: 随机重签别名最短长度。标定：实测重打包件两个发布件的别名均为 8 位全大写随机串；语料中自研
#: 样本的别名（品牌缩写 / 词形）全部 ≤6 位。7 位留作缓冲带不判（宁 unknown 不误判）。
_RANDOM_ALIAS_MIN_LEN = 8
#: 品牌缩写别名长度带（2~6 位大写字母数字）。标定：语料自研样本别名 3~6 位，是国内自研应用
#: keystore 别名的常见形态（品牌/项目缩写）。
_SHORT_ALIAS_MAX_LEN = 6

#: 「完整商业栈」最少命中族数。标定：实测重打包件命中 4 族（RN+OpenCV+银行卡识别+SQLCipher），
#: 语料中全部自研样本 ≤1 族；取 3 在两者之间留 1 族余量。
_RICH_STACK_MIN_FAMILIES = 3
#: 「技术栈单薄」上限（自研方向判据之一，与上面的 3 之间同样留缓冲带：2 族不参与任何方向）。
_THIN_STACK_MAX_FAMILIES = 1

#: 版本化接口路径（/api/v<N>/... 多级带版本）计为「成熟产品命名规范」的最少去重条数。
#: ★弱信号：只进 meta / signals 供人工复核，**绝不参与 verdict**——加壳样本的 dex 字符串池
#: 只见壳、看不到业务串，据此判型会系统性偏差（壳内正版与壳内自研都显示为 0 条）。
_VERSIONED_API_MIN = 5
_MAX_API_PATHS = 200
_MAX_API_EXAMPLES = 5

_MAX_EVIDENCE = 6
#: content_profile 各清单上限：该画像供跨样本「同母包、不同签名」双胞胎比对（同 DEX 大小清单 +
#: 同 .so 清单 + 不同证书指纹 = 同源重签），超限部分只是重复噪声。
_MAX_PROFILE_DEX = 30
_MAX_PROFILE_SO = 80

VERDICT_SELF_BUILT = "self_built"
VERDICT_REPACK_SUSPECTED = "repack_suspected"
VERDICT_UNKNOWN = "unknown"

#: v1 签名块文件（META-INF 顶层 ``<别名>.RSA/DSA/EC``；别名即 keystore key alias，签名工具原样落名，
#: 故文件名形态直接暴露签名人的别名习惯）。
_SIG_FILE_RE = re.compile(r"^META-INF/([^/]+)\.(?:RSA|DSA|EC)$", re.IGNORECASE)

#: 常规 / 工具默认别名：CERT（apksigner / Android Studio 默认）；ANDROID / PLATFORM / TESTKEY /
#: MEDIA / SHARED（AOSP 平台与测试键）；SIGNAPK / RELEASE / UPLOAD（常见发布习惯名）。
#: 命中即既非随机、也不按品牌缩写计。
_CONVENTIONAL_ALIASES: frozenset[str] = frozenset(
    {"CERT", "ANDROID", "PLATFORM", "TESTKEY", "MEDIA", "SHARED", "SIGNAPK", "RELEASE", "UPLOAD"}
)

#: 包名中的通用段（TLD / 惯用前缀），不作品牌 token——否则 "APP"/"COM" 这类别名会被误认作品牌词。
_GENERIC_PKG_SEGMENTS: frozenset[str] = frozenset(
    {"com", "cn", "org", "net", "io", "co", "app", "www", "android", "mobi"}
)

#: 知名商业 SDK / 框架族 → .so basename 前缀（判定依据全部是公开、稳定的官方库名）：
#:   react_native：libhermes（Hermes JS 引擎）/ libjsi / libfbjni / libreactnativejni——RN 运行时组件；
#:   flutter：libflutter——Flutter 引擎；
#:   opencv：libopencv_java4 等——OpenCV 视觉库（前缀匹配吃掉版本后缀）；
#:   cardio：libcardioDecider / libcardioRecognizer——card.io 银行卡识别（商业收单场景专用）；
#:   sqlcipher：libsqlcipher——SQLCipher 加密数据库。
#: ★只收「产品级能力栈」：mmkv / bugly / marsxlog 等工具库自研样本同样大量使用，计入会把自研
#: 误推向 repack（正是本模块要防的误伤方向），故有意不收。
_COMMERCIAL_STACKS: dict[str, tuple[str, ...]] = {
    "react_native": ("libhermes", "libjsi", "libfbjni", "libreactnativejni"),
    "flutter": ("libflutter",),
    "opencv": ("libopencv",),
    "cardio": ("libcardiodecider", "libcardiorecognizer"),
    "sqlcipher": ("libsqlcipher",),
}

_RANDOM_ALIAS_RE = re.compile(r"[A-Z]{%d,}" % _RANDOM_ALIAS_MIN_LEN)
_SHORT_ALIAS_RE = re.compile(r"[A-Z][A-Z0-9]{1,%d}" % (_SHORT_ALIAS_MAX_LEN - 1))
_VERSIONED_API_RE = re.compile(r"/api/v\d+/[A-Za-z0-9_./\-]+")
_DEX_NAME_RE = re.compile(r"classes\d*\.dex")


# ---------------------------------------------------------------------------
# 纯函数（便于单测）
# ---------------------------------------------------------------------------


def _package_tokens(package_name: str) -> set[str]:
    """包名的品牌 token（小写；剔除 TLD / 通用段与超短段）。"""
    return {
        seg.lower()
        for seg in (package_name or "").split(".")
        if len(seg) >= 3 and seg.lower() not in _GENERIC_PKG_SEGMENTS
    }


def classify_sig_alias(alias: str, package_name: str) -> str:
    """签名块文件别名分类：conventional / package-brand / random-like / short-alias / neutral。

    ★ package-brand 检查先于 random-like：正版应用常以品牌词作别名，8+ 位大写品牌词形同随机串，
    但品牌词通常与包名段相关，据此豁免；豁免不掉的残余误报由「签名信号单独不定 verdict」兜底
    （见 :func:`decide_verdict`——随机别名必须与完整商业栈同时命中才判 repack）。
    """
    up = alias.upper()
    if up in _CONVENTIONAL_ALIASES:
        return "conventional"
    low = alias.lower()
    for token in _package_tokens(package_name):
        if low == token:
            return "package-brand"
        # 双向包含只在双方都够长时算（缩写别名 vs 完整品牌段，反向亦然）；短串包含太廉价会误豁免。
        if len(low) >= 4 and len(token) >= 4 and (low in token or token in low):
            return "package-brand"
    if _RANDOM_ALIAS_RE.fullmatch(alias):
        return "random-like"
    if _SHORT_ALIAS_RE.fullmatch(alias):
        return "short-alias"
    return "neutral"


def profile_stack(so_basenames: Iterable[str]) -> dict[str, list[str]]:
    """按 .so basename 前缀识别商业 SDK 族，返回 {族名: 命中的 basename 列表}。

    只用 zip 目录里的文件名、不读内容：框架 / SDK 的 .so 即使 DEX 被加壳也留在 lib/ 下原样可见，
    所以该画像对加壳样本仍然成立（这是它比 dex 串判据可靠的原因）。
    """
    hits: dict[str, list[str]] = {}
    bases = sorted({b.lower() for b in so_basenames if isinstance(b, str)})
    for family, stems in _COMMERCIAL_STACKS.items():
        matched = [b for b in bases if any(b.startswith(stem) for stem in stems)]
        if matched:
            hits[family] = matched
    return hits


def decide_verdict(
    *,
    has_random_alias: bool,
    has_short_alias: bool,
    family_count: int,
    has_debug_cert: bool,
) -> str:
    """三态判定（纯函数）。规则刻意保守：

    - repack_suspected 要求随机别名 **与** 完整商业栈同时命中：随机别名单独出现也见于自研签名
      习惯（语料中即有 8 位随机别名 + 单薄栈的样本），完整栈单独出现无法区分正主发布件；
    - self_built 要求「无随机别名 + 栈单薄 + 至少一个正向标记」：单一框架的正版应用被常规名
      重签后与自研不可分，故仅凭栈单薄不判自研；
    - 其余一律 unknown。
    """
    if has_random_alias and family_count >= _RICH_STACK_MIN_FAMILIES:
        return VERDICT_REPACK_SUSPECTED
    if (
        not has_random_alias
        and family_count <= _THIN_STACK_MAX_FAMILIES
        and (has_short_alias or has_debug_cert)
    ):
        return VERDICT_SELF_BUILT
    return VERDICT_UNKNOWN


# ---------------------------------------------------------------------------
# 分析器
# ---------------------------------------------------------------------------


class RepackIdentityAnalyzer(BaseAnalyzer):
    """判别自研马甲包 vs 正版应用被重打包，给出三态 verdict 与命中明细。"""

    name: str = "repack_identity"
    requires: list[str] = ["apk"]  # Android 专属（签名形态 + .so 栈画像）

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        # 失败安全方向：任何一步塌了都保底 unknown 的 meta（不误导下游把缺数据当成已判型）。
        meta: dict = {
            "verdict": VERDICT_UNKNOWN,
            "signals": [],
            "signature": {},
            "stack": {"families": {}, "family_count": 0},
        }
        result.meta["repack_identity"] = meta
        try:
            files = collect_file_paths(ctx, self.name)
            signature = self._signature_view(ctx, files)
            so_map = collect_so_basenames(ctx, self.name)
            stack_hits = profile_stack(so_map.keys())
            api_view = self._api_path_view(ctx, result)

            verdict = decide_verdict(
                has_random_alias=bool(signature["random_aliases"]),
                has_short_alias=bool(signature["short_aliases"]),
                family_count=len(stack_hits),
                has_debug_cert=bool(signature["debug_cert"]),
            )
            meta.update(
                {
                    "verdict": verdict,
                    "signals": _build_signals(signature, stack_hits, api_view),
                    "signature": signature,
                    "stack": {"families": stack_hits, "family_count": len(stack_hits)},
                    "api_paths": api_view,
                    "content_profile": self._content_profile(ctx, files, so_map),
                }
            )
            if verdict == VERDICT_REPACK_SUSPECTED:
                result.findings.append(self._repack_finding(signature, stack_hits, so_map))
            elif verdict == VERDICT_SELF_BUILT:
                result.findings.append(self._self_built_finding(signature, stack_hits))
            else:
                logger.info("[%s] 判据不足，verdict=unknown（明细见 meta.repack_identity）", self.name)
        except Exception:
            logger.exception("[%s] 判别失败，保底 verdict=unknown", self.name)
            result.error = "repack_identity 判别失败（已保底 unknown）"
        return result

    # ------------------------------------------------------------------
    # 数据视图
    # ------------------------------------------------------------------

    def _signature_view(self, ctx: "AnalysisContext", files: list[str]) -> dict:
        """签名形态视图：META-INF 签名块文件名分类 + 证书数量/摘要（证书信息用 ctx 现成接口）。"""
        try:
            pkg = getattr(ctx, "package_name", "") or ""
        except Exception:
            logger.debug("[%s] 读取包名失败，品牌 token 豁免不可用", self.name, exc_info=True)
            pkg = ""
        sig_files: list[str] = []
        alias_classes: dict[str, str] = {}
        for path in files:
            m = _SIG_FILE_RE.match(path.replace("\\", "/"))
            if m is None:
                continue
            sig_files.append(path)
            alias = m.group(1)
            alias_classes[alias] = classify_sig_alias(alias, pkg)

        try:
            certs = list(ctx.certificates() or [])
        except Exception:
            logger.exception("[%s] 读取证书失败，签名摘要仅据文件名", self.name)
            certs = []
        return {
            "sig_files": sorted(sig_files),
            "alias_classes": alias_classes,
            "random_aliases": sorted(a for a, c in alias_classes.items() if c == "random-like"),
            "short_aliases": sorted(a for a, c in alias_classes.items() if c == "short-alias"),
            "cert_count": len(certs),
            "cert_sha256s": [
                (getattr(c, "sha256", "") or "").strip() for c in certs
            ][:8],
            "debug_cert": any(getattr(c, "is_debug", False) for c in certs),
        }

    def _api_path_view(self, ctx: "AnalysisContext", result: AnalyzerResult) -> dict:
        """版本化接口路径统计（弱信号，仅记录）。collect_dex_strings 自带条数上限与异常兜底。

        ★传 ``result`` 是为了把"扫描被截断"带回去：本视图数的是版本化接口路径条数，截断会让
        计数偏低，而它参与 verdict 的弱信号判断——没扫全却不吭声，等于用不完整的计数下判断。
        """
        _ok, strings = collect_dex_strings(
            ctx, self.name, max_strings=_MAX_DEX_STRINGS, result=result
        )
        found: set[str] = set()
        for s in strings:
            if len(found) >= _MAX_API_PATHS:
                break
            if "/api/v" not in s:
                continue
            for m in _VERSIONED_API_RE.finditer(s):
                found.add(m.group(0))
                if len(found) >= _MAX_API_PATHS:
                    break
        return {"versioned_count": len(found), "examples": sorted(found)[:_MAX_API_EXAMPLES]}

    def _content_profile(
        self, ctx: "AnalysisContext", files: list[str], so_map: dict[str, str]
    ) -> dict:
        """母包内容画像（纯 zip 目录元数据，不解压）：DEX 大小清单 + .so 清单。

        用途：跨样本反查「同母包、不同签名」双胞胎——实测两个重打包发布件 9 个 DEX 大小逐一
        相同、.so 清单完全一致、证书指纹不同，凭该画像 + cert_sha256s 即可在语料库里配对。
        """
        dex_sizes: list[list[object]] = []
        for path in files:
            if _DEX_NAME_RE.fullmatch(path) is None:
                continue
            try:
                size = ctx.declared_size(path)
            except Exception:
                logger.debug("[%s] 查 DEX 声明大小失败：%s", self.name, path, exc_info=True)
                size = None
            dex_sizes.append([path, size])
        # classes.dex, classes2.dex … classes10.dex 的自然序（先长度后字典序）。
        dex_sizes.sort(key=lambda kv: (len(str(kv[0])), str(kv[0])))
        return {
            "dex_sizes": dex_sizes[:_MAX_PROFILE_DEX],
            "so_count": len(so_map),
            "so_names": sorted(so_map.keys())[:_MAX_PROFILE_SO],
        }

    # ------------------------------------------------------------------
    # Finding
    # ------------------------------------------------------------------

    def _repack_finding(
        self, signature: dict, stack_hits: dict[str, list[str]], so_map: dict[str, str]
    ) -> Finding:
        aliases = "、".join(signature["random_aliases"][:4])
        families = "、".join(sorted(stack_hits))
        evidences = [
            Evidence(source="resource", location=p, snippet="签名块文件（随机大写重签别名）")
            for p in signature["sig_files"][:2]
        ]
        for family, bases in sorted(stack_hits.items()):
            evidences.append(
                Evidence(
                    source="native",
                    location=so_map.get(bases[0], bases[0]),
                    snippet=f"商业技术栈：{family}",
                )
            )
        return Finding(
            id="REPACK-IDENTITY-SUSPECTED",
            title="疑似正版应用重打包——接口/域名归属须先差分核实",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            category="signing",
            description=(
                f"签名块文件名为随机大写别名（{aliases}），同时具备完整商业技术栈（{families}）——"
                "符合成熟商业应用被第三方重新签名发布的形态，而非从零自研。\n"
                "★ 本样本的接口/域名可能属于被仿冒的正版应用，作为调证线索前须与官方包差分核实；"
                "直接列为线索会把正版厂商的资产错误归属到样本运营方，向无关企业发函（严重误伤）。\n"
                "★ 边界：仅凭样本自身只能确定「被重签名」，无法确定重打包时改动了什么；"
                "确定改动内容必须取官方同版本母包做逐文件差分（DEX 大小清单 / .so 清单 / 证书对比）。"
            ),
            recommendation=(
                "① 从官方渠道获取同版本母包做逐文件差分，确认本样本相对母包的改动集；"
                "② 差分核实前，本样本提取的接口/域名按「疑似正版资产」隔离，不直接进线索清单；"
                "③ 用 meta.repack_identity.content_profile（DEX 大小 + .so 清单）与 cert_sha256s "
                "跨样本反查「同母包、不同签名」的其他发布件（同大小清单 + 不同证书指纹 = 同源重签）。"
            ),
            evidences=evidences[:_MAX_EVIDENCE],
        )

    def _self_built_finding(self, signature: dict, stack_hits: dict[str, list[str]]) -> Finding:
        markers: list[str] = []
        if signature["short_aliases"]:
            markers.append("品牌缩写式签名别名（" + "、".join(signature["short_aliases"][:3]) + "）")
        if signature["debug_cert"]:
            markers.append("调试证书签名")
        detail = "；".join(markers) or "无"
        evidences = [
            Evidence(source="resource", location=p, snippet="签名块文件（品牌缩写式别名）")
            for p in signature["sig_files"][:_MAX_EVIDENCE]
        ]
        return Finding(
            id="REPACK-IDENTITY-SELF-BUILT",
            title="签名与技术栈符合自研应用形态",
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            category="signing",
            description=(
                f"自研正向标记：{detail}；商业 SDK 族命中 {len(stack_hits)} 个、无重签名形态信号——"
                "符合单一框架、功能单一的自研应用形态。其接口/域名可按样本自有后端方向研判"
                "（仍须常规排除 CDN / 公共服务 / 第三方 SDK 端点）。\n"
                "★ 这是启发式倾向而非确证：若存在同名正版应用，仍应取官方包差分复核。"
            ),
            recommendation=(
                "按常规端点研判流程处理；以证书指纹（meta.repack_identity.signature.cert_sha256s）"
                "聚类同签名指纹的其他样本。"
            ),
            evidences=evidences,
        )


# ---------------------------------------------------------------------------
# signals 组装（命中明细：让复核者能回答「为什么是这个 verdict」）
# ---------------------------------------------------------------------------


def _build_signals(
    signature: dict, stack_hits: dict[str, list[str]], api_view: dict
) -> list[dict]:
    signals: list[dict] = []
    if signature["random_aliases"]:
        signals.append(
            {
                "id": "random-signature-alias",
                "direction": "repack",
                "detail": "、".join(signature["random_aliases"]),
            }
        )
    if len(signature["sig_files"]) >= 2:
        # 单包多签名块本身少见；只记录供人核，不参与 verdict（合法多 signer 存在）。
        signals.append(
            {
                "id": "multiple-signature-files",
                "direction": "neutral",
                "detail": "、".join(signature["sig_files"]),
            }
        )
    if len(stack_hits) >= _RICH_STACK_MIN_FAMILIES:
        signals.append(
            {
                "id": "rich-commercial-stack",
                "direction": "repack",
                "detail": "、".join(sorted(stack_hits)),
            }
        )
    if len(stack_hits) <= _THIN_STACK_MAX_FAMILIES:
        signals.append(
            {
                "id": "thin-commercial-stack",
                "direction": "self_built",
                "detail": f"{len(stack_hits)} family",
            }
        )
    if signature["short_aliases"]:
        signals.append(
            {
                "id": "short-brand-alias",
                "direction": "self_built",
                "detail": "、".join(signature["short_aliases"]),
            }
        )
    if signature["debug_cert"]:
        signals.append({"id": "debug-certificate", "direction": "self_built", "detail": "is_debug"})
    if api_view.get("versioned_count", 0) >= _VERSIONED_API_MIN:
        # 弱信号：仅记录（加壳样本看不到业务串，缺席不说明什么），绝不参与 verdict。
        signals.append(
            {
                "id": "versioned-api-paths",
                "direction": "repack-weak",
                "detail": f"{api_view['versioned_count']} distinct",
            }
        )
    return signals
