"""native 控制面通道 —— 从 Go 产物里还原「配置对象地址是怎么算出来的」。

为什么单列一个分析器：config-chain 一直假设控制面地址是**静态串**（某个 http(s) URL 摆在
DEX 里），于是 remote_config / config_probe 都只扫具体 URL。实测样本用的是另一种形态——
地址由一个**每天现算的哈希子域**承载，静态里只有 ``%s`` 模板和算法本身，一条真实 URL
都没有。被动发现路径天然抓不到它，报告里 remote_config 与 config_probe_plan 全是空的，
读的人会以为这个样本没有远程配置通道。

这一层做的是：把**模板 + 算法 + 缺哪些变量**还原成结构化事实，并说清补齐的路子。
它不产可发函 Lead —— 当日 URL 静态算不出来，没有可指向的调证主体。

★不做的事：不猜 AppName/SDKVersion（它们由宿主运行时经 gobind 注入，编译期不落值），
不生成候选 URL 去探测（那属 authorized-active，且需要先补齐变量）。宁可说"缺两个输入"，
也不拿猜的值拼出一串看着像结论的 URL。
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import TYPE_CHECKING

from apkscan.analyzers._common import app_so_paths
from apkscan.core.gobuildinfo import parse_go_buildinfo
from apkscan.core.models import AnalyzerResult, Evidence, Finding, Severity
from apkscan.core.registry import BaseAnalyzer

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_MAX_LIBS = 40
_MAX_LIB_BYTES = 96 * 1024 * 1024
_MAX_TOTAL_LIB_BYTES = 256 * 1024 * 1024

#: 含 printf 占位符的对象存储 URL 模板。``%s`` 出现在 host 段说明子域是算出来的，
#: 这正是「地址不是静态串」的直接证据。
_TEMPLATE_RE = re.compile(
    rb"https?://%[sv][A-Za-z0-9._%+-]*\.[A-Za-z0-9.-]+/[A-Za-z0-9._%+-]*"
)

#: 已知对象存储 host 家族 → 服务商（用于说明该向谁调证）。
_PROVIDERS: tuple[tuple[str, str], ...] = (
    ("bcebos.com", "百度智能云 BOS"),
    ("oss-accelerate.aliyuncs.com", "阿里云 OSS 全球加速"),
    ("aliyuncs.com", "阿里云 OSS"),
    ("zos.ctyun.cn", "天翼云 ZOS"),
    ("myqcloud.com", "腾讯云 COS"),
    ("obs.myhuaweicloud.com", "华为云 OBS"),
    ("r2.cloudflarestorage.com", "Cloudflare R2"),
    ("amazonaws.com", "AWS S3"),
)

#: 控制面解析 / 取配置 / 解密的函数符号。命中即说明这套通道确实被实现了，
#: 而不是几个碰巧长得像模板的字符串。
_CONTROL_SYMBOLS: tuple[bytes, ...] = (
    b"resolveControlPlane", b"buildNodeDataURLs", b"fetchFastest",
    b"fetchByHeadThenGet", b"decryptNodeData", b"nodeGroupsFrom",
)
_CRYPTO_SYMBOLS: tuple[bytes, ...] = (
    b"tryDecryptGCM", b"tryDecryptCBC", b"pkcs7Unpad", b"normalizeAESKey", b"shortMD5",
)
#: 运行时注入的输入（cgo 导出的 setter/getter），命中即说明该变量静态取不到。
_RUNTIME_INPUT_RE = re.compile(rb"_cgoexp_[0-9a-f]+_[A-Za-z0-9_]*?_(AppName|SDKVersion|AESKey)_(?:Set|Get)")

#: 至少要有这么多控制面符号命中才认这条通道——单个符号可能是巧合。
_MIN_CONTROL_SYMBOLS = 2


def _provider_for(host: str) -> str:
    low = host.lower()
    for suffix, name in _PROVIDERS:
        if suffix in low:
            return name
    return "未识别对象存储服务商"


class NativeConfigChannelAnalyzer(BaseAnalyzer):
    """还原 native 侧的「算出来的」控制面地址通道：模板 / 算法 / 缺失输入。"""

    name: str = "native_config_channel"
    requires: list[str] = ["apk"]

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        try:
            channel = self._scan(ctx)
        except Exception:
            logger.exception("[%s] 扫描 native 控制面失败", self.name)
            return result
        if channel is None:
            logger.info("[%s] 未发现 native 控制面通道", self.name)
            return result

        result.meta["native_config_channel"] = channel
        result.findings.append(self._finding(channel))
        logger.info(
            "[%s] 命中 native 控制面：%d 条对象存储模板，缺 %d 个运行时输入",
            self.name, len(channel["templates"]), len(channel["missing_inputs"]),
        )
        return result

    def _scan(self, ctx: "AnalysisContext") -> dict | None:
        budget = _MAX_TOTAL_LIB_BYTES
        for so_path in app_so_paths(ctx, self.name, max_libs=_MAX_LIBS):
            if budget <= 0:
                logger.info("[%s] .so 累计读入达上限，剩余库未扫", self.name)
                break
            try:
                declared = ctx.declared_size(so_path)
            except Exception:
                logger.debug("[%s] 查声明大小失败：%s", self.name, so_path, exc_info=True)
                declared = None
            if declared is not None and declared > _MAX_LIB_BYTES:
                continue
            try:
                data = ctx.read_file(so_path)
            except Exception:
                logger.debug("[%s] 读 .so 失败，跳过：%s", self.name, so_path, exc_info=True)
                continue
            if not data or len(data) > _MAX_LIB_BYTES:
                continue
            budget -= len(data)

            control_hits = [s.decode() for s in _CONTROL_SYMBOLS if s in data]
            if len(control_hits) < _MIN_CONTROL_SYMBOLS:
                continue
            templates = self._templates(data)
            if not templates:
                continue
            return self._build(so_path, data, control_hits, templates)
        return None

    @staticmethod
    def _templates(data: bytes) -> list[dict[str, str]]:
        seen: dict[str, dict[str, str]] = {}
        for m in _TEMPLATE_RE.finditer(data):
            try:
                url = m.group(0).decode("ascii")
            except UnicodeDecodeError:
                continue
            host = url.split("//", 1)[-1].split("/", 1)[0]
            seen.setdefault(url, {
                "url_template": url,
                "host_family": host.split("%s", 1)[-1].lstrip("."),
                "provider": _provider_for(host),
            })
        return list(seen.values())

    def _build(
        self,
        so_path: str,
        data: bytes,
        control_hits: list[str],
        templates: list[dict[str, str]],
    ) -> dict:
        missing = sorted({m.group(1).decode() for m in _RUNTIME_INPUT_RE.finditer(data)})
        crypto_hits = [s.decode() for s in _CRYPTO_SYMBOLS if s in data]

        build: dict[str, object] = {}
        info = parse_go_buildinfo(data)
        if info is not None:
            build = {
                "go_version": info.go_version,
                "main_module": info.main_module,
                "replaces": info.replaces,
                # ldflags_x 里的敏感值已在解析处换成指纹，此处直接带上。
                "injected": info.ldflags_x,
            }

        return {
            "schema_version": "1.0",
            "source": {"lib": so_path, "so_sha256": hashlib.sha256(data).hexdigest()},
            "templates": templates,
            "control_symbols": sorted(control_hits),
            "crypto_symbols": sorted(crypto_hits),
            "missing_inputs": missing,
            "build": build,
            "url_derivable": not missing,
            "next_actions": self._next_actions(missing),
        }

    @staticmethod
    def _next_actions(missing: list[str]) -> list[str]:
        if not missing:
            return ["模板与输入齐备：可在授权下按算法拼出当日对象地址并取回配置。"]
        names = "、".join(missing)
        return [
            f"静态先试：在 DEX/资源里找 {names} 的赋值点（常等于应用名或编译期版本常量）。",
            "静态拿不到 → 动态一次：hook 注入这些值的桥函数，或直接观测对对象存储的实际请求。",
            "取到当日对象地址后，按 authorized-active 取回配置并解码，动态域名/IP 池回灌端点集。",
        ]

    @staticmethod
    def _finding(channel: dict) -> Finding:
        providers = sorted({t["provider"] for t in channel["templates"]})
        missing = channel["missing_inputs"]
        return Finding(
            id="NATIVE-CONFIG-CHANNEL",
            title="native 控制面：配置对象地址按算法逐日生成",
            severity=Severity.MEDIUM,
            category="backend_surface",
            description=(
                f"native 库内实现了控制面解析通道，配置对象散在 {len(providers)} 家对象存储"
                f"（{'、'.join(providers)}），地址由算法按日期生成而非硬编码。"
                + (
                    f"　★当日地址静态**算不出来**：缺 {'、'.join(missing)}，"
                    "它们由宿主在运行时注入，编译期不落值。"
                    if missing else "　模板与输入齐备，可在授权下推出当日地址。"
                )
                + "　这解释了为什么静态端点集里没有控制面域名——它本来就不是静态串。"
            ),
            recommendation=(
                "按 next_actions 先补齐运行时输入，再在授权下取回配置对象；"
                "配置解码后的动态域名/IP 池才是真正的调证目标。"
                "对象存储服务商本身可作为调证节点（调桶所有者实名与对象访问日志）。"
            ),
            evidences=[
                Evidence(
                    source="native",
                    location=str(channel["source"]["lib"]),
                    snippet=t["url_template"],
                )
                for t in channel["templates"][:6]
            ],
        )
