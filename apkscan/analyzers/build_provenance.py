"""构建来源路径提取——编译产物里泄露的开发/构建机绝对路径（``__FILE__`` 类字符串）。

为什么值得提：native 编译器把 ``__FILE__`` 原样编进断言/日志字符串，DEX 中也偶见
构建期路径。这些路径描摹**构建机**的目录结构，是跨样本关联的硬锚——同一私有打包
平台产出的不同样本会复现同一构建根与批次标识。实测语料 24 个样本中 23 个含此类路径。

★ 头号风险（本模块分层设计的存在理由）：第三方 SDK / 开源项目的路径随源码或预编译
库**继承**进样本——Telegram 官方客户端作者的 macOS 主目录、RTC SDK 的 CI 构建账号、
Go 工具链、GitHub Actions 公共 CI 等在本批语料中大量出现（如 13/24 样本含同一
Telegram 作者路径）。把这些当成本样本作者的机器，会把无关的开源作者写进研判结论。
因此：

  - **分层标注**（third_party_known / self_hosted_suspected / unknown），不做二元断言；
  - 判据**只看构建根**（路径前几段），不看整条路径：私有构建根下常挂第三方源码
    （``…/jni/libtgvoip/webrtc_dsp/…``），若按路径中出现的开源项目名判第三方，
    会把私有平台误判掉——这是实测踩过的坑，测试固化为回归；
  - 提取到的**用户名**默认只进 meta 供人工复核、不进 Finding 正文：国内 SDK 常以
    开发者拼音命名构建机，疑似真人姓名写进结论风险太大。

不产 Lead：构建路径不是可发函的调证对象，只作情报/关联维度。纯静态、有界、绝不抛。
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from apkscan.analyzers._common import app_so_paths, collect_dex_strings
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
# 上限（对齐 native_obfuscation 的有界读范式）
# ---------------------------------------------------------------------------

_MAX_DEX_STRINGS = 200_000
#: 单个 .so 读入上限：超此跳过（防超大 / zip-bomb .so 撑爆内存）。.so 可合法较大，故取 64MB。
_MAX_LIB_BYTES = 64 * 1024 * 1024
#: 全部 .so 累计读入预算：达此停止扫描剩余库（多库累计防线，对齐 native_obfuscation 范式）。
_MAX_TOTAL_LIB_BYTES = 256 * 1024 * 1024
#: 单样本最多评估的 .so 数（app_so_paths 已排除系统/引擎白名单库）。
_MAX_LIBS = 60
#: 全样本保留的**去重后**路径上限：构建路径按构建根聚合后信息趋同，超此只是重复噪声。
_MAX_PATHS = 400
#: Finding 附带证据条数上限 / meta 各分组展示的示例路径上限（全量太长，人核看代表即可）。
_MAX_EVIDENCE = 5
_MAX_GROUP_PATHS = 5

# ---------------------------------------------------------------------------
# 提取
# ---------------------------------------------------------------------------

#: 路径续接字符集：常见 __FILE__ 路径字符。不含空格/引号/冒号 → 在自然语句或日志前后缀处自然截断。
_PATH_CHAR = r"[A-Za-z0-9_\-./+~]"

#: Unix 形态构建根。★负向 lookbehind 要求前一个字符不是路径字符：URL 路径段
#: （``x.com/home/y``）、Java 描述符（``com/foo/opt/…``）里的 ``/home`` ``/opt`` 前面
#: 必是路径字符，据此整类排除；真实 __FILE__ 串前面通常是 NUL / 空格 / 冒号。
_UNIX_RE = re.compile(
    (
        r"(?<!" + _PATH_CHAR + r")"
        r"/(?:opt|home|Users|root|mnt|workspace|Volumes|build|srv)/" + _PATH_CHAR + r"+"
    ).encode("ascii"),
    re.IGNORECASE,
)

#: Windows 形态：任意盘符根，不再限定 ``Users``——实测 Go 的 module replace 指令里
#: 内嵌的开发机项目根是 ``D:\im_sdk2\sdk_app2`` 这种自定义盘符目录，旧正则整类漏掉。
#: 不吃空格：带空格的构建路径少见，吃空格会把后续日志文本整段吞进来（宁截断不误吞），
#: 顺带让 ``C:\Program Files\…`` 在 ``Program`` 处自然断开、不会被当成深层项目路径。
_WIN_RE = re.compile(
    rb"(?<![A-Za-z0-9_\-.\\/+~])[A-Za-z]:[\\/][A-Za-z0-9_\-.\\/+~]+",
    re.IGNORECASE,
)

#: 最少 ``/`` 数（归一化后）：``/root/x.c`` 这类两段路径信息量太低且易撞设备路径，
#: 要求根下至少还有两段（如 ``/home/u/proj``），实测构建路径远深于此、不损召回。
_MIN_SLASHES = 3

#: Windows 路径的等价门槛：``D:/x/y`` 与 ``/home/u/proj`` 段数相同，但前者没有前导斜杠，
#: 用同一个 ``_MIN_SLASHES`` 会把 Windows 项目根整类挡掉。
_MIN_SLASHES_WIN = _MIN_SLASHES - 1

#: 盘符根形态（归一化后），用于挑出该用哪个斜杠门槛。
_WIN_DRIVE_RE = re.compile(r"^[a-z]:/", re.IGNORECASE)

#: Android **设备运行时**挂载点前缀（小写）——这些是 App 跑在手机上访问的路径，
#: 不是构建机路径，形态却同为 ``/mnt/…``，必须排除（否则把存储目录当"构建来源"）。
_DEVICE_RUNTIME_PREFIXES: tuple[str, ...] = (
    "/mnt/sdcard", "/mnt/media_rw", "/mnt/asec", "/mnt/obb", "/mnt/expand",
    "/mnt/user", "/mnt/runtime", "/mnt/secure", "/mnt/shell", "/mnt/vendor",
    "/mnt/product", "/mnt/pass_through", "/mnt/installer",
)

# ---------------------------------------------------------------------------
# 分层
# ---------------------------------------------------------------------------

TIER_THIRD_PARTY = "third_party_known"
TIER_SELF_HOSTED = "self_hosted_suspected"
TIER_UNKNOWN = "unknown"

#: 已知第三方构建根清单（前缀小写、以 / 收尾做 startswith 匹配）。
#: 标定依据：24 个实测样本的人工核对——这些根来自公开 SDK / 开源项目 / 公共 CI，
#: 路径随源码或预编译产物继承进样本，与样本作者的构建环境无关。
#: ★只允许**路径前缀**匹配（startswith），绝不做子串匹配：私有构建根下挂第三方源码时
#:   （``/opt/work/<id>/…/webrtc_dsp/…``）子串匹配会把私有平台误归第三方。
_KNOWN_THIRD_PARTY_ROOTS: tuple[tuple[str, str], ...] = (
    ("/users/drklo/", "Telegram 官方 Android 客户端作者（路径随官方开源代码继承）"),
    ("/users/dkaraush/", "Telegram 开源贡献者（路径随官方开源代码继承）"),
    ("/home/pano/", "第三方 RTC SDK 的 CI 构建账号（jenkins/onertc 等构建产物）"),
    ("/users/pano/", "同上 RTC SDK 的 macOS 构建机（与 /home/pano 同一 SDK 来源，实测同批出现）"),
    ("/users/scw/", "Go 工具链构建机（Go runtime 编译产物内嵌路径）"),
    ("/users/dhmac/", "第三方 SDK 构建机（实测语料人工核对）"),
    ("/users/jbrateman/", "第三方 SDK 构建机（实测语料人工核对）"),
    ("/home/runner/work/", "GitHub Actions 公共 CI 默认工作目录"),
    ("/home/vcloudqa/", "商用 RTC SDK 厂商 CI 构建账号"),
    ("/volumes/android/buildbot/", "Android NDK 官方发布构建机"),
    # 公共工具链安装位：人人相同、零身份信息。若不收录，/opt 前缀会把它们误判为
    # "私有工作区"——与本模块要防的方向相反，故并入第三方（=非本样本作者）清单。
    ("/opt/hostedtoolcache/", "GitHub Actions 托管工具缓存目录"),
    ("/opt/homebrew/", "macOS Homebrew 默认安装位（Apple Silicon）"),
    ("/opt/local/", "macOS MacPorts 默认安装位"),
    # 实测 24 样本验真补录：NDK sysroot/断言路径以 SDK 安装位开头（识别构建标识会得出
    # "ndk" 这类无身份信息的假标识），属工具链安装位而非私有工作区。
    ("/opt/android-sdk/", "Android SDK/NDK 常用安装位（CI 容器/构建机公共路径）"),
    ("/opt/android/", "Android SDK/NDK 常用安装位变体"),
    ("/opt/ndk/", "Android NDK 常用安装位变体"),
    ("/opt/rh/", "RHEL/CentOS devtoolset 安装位（大量第三方预编译库的构建环境）"),
)

#: 包管理器的依赖缓存布局。命中即判第三方：这些目录下**全部**是下载来的依赖源码，
#: 路径里的名字是依赖作者的，与样本作者无关。
#:
#: ★这是本模块唯一允许的**子串**匹配，与 ``_KNOWN_THIRD_PARTY_ROOTS`` 只许前缀匹配的
#:   纪律不冲突——那条纪律防的是"私有构建根下挂了第三方源码"（``/opt/work/<id>/…/webrtc_dsp/``
#:   会被子串匹配误归第三方），而这里的情形正相反：缓存目录下没有一行作者自己的代码。
#: ★为什么非做不可：实测样本里有 ``/Users/1/go/pkg/mod/github.com/refraction-networking/utls``，
#:   若它停在 unknown 而被谁当成线索，指向的是一位真实的开源项目作者。
_DEPENDENCY_CACHE_MARKERS: tuple[tuple[str, str], ...] = (
    ("/go/pkg/mod/", "Go 模块缓存（下载的依赖源码，路径里的名字属依赖作者）"),
    ("/.cargo/registry/", "Cargo 依赖缓存"),
    ("/.m2/repository/", "Maven 本地仓库"),
    ("/.gradle/caches/", "Gradle 依赖缓存"),
    ("/node_modules/", "npm 依赖目录"),
    ("/.pub-cache/", "Dart/Flutter 依赖缓存"),
    ("/site-packages/", "Python 依赖安装位"),
    ("/vendor/github.com/", "Go vendor 目录（依赖随源码一起提交）"),
)

#: Windows 工具链 / 系统安装位（盘符归一为小写后按 ``<drive>:/<段>/`` 匹配的**第二段**）。
#: 放开非 ``Users`` 的盘符根后必须同时立这道墙：``D:\go\src\…``、``C:\msys64\…`` 这类
#: 是编译器与包管理器的默认位、人人相同、零身份信息，若被判成"自建构建环境"，
#: 干净样本会凭空多出一条归属结论——与本模块要防的方向正相反。
#: ★匹配的是盘符后的**首段**而非整条路径：私有工作区下挂个 ``tools`` 子目录不该整条改判。
_WIN_TOOLCHAIN_SEGMENTS: frozenset[str] = frozenset({
    "windows", "winnt", "program files", "program files (x86)", "programdata",
    "go", "golang", "gopath", "goroot",
    "msys64", "msys32", "mingw", "mingw64", "mingw32", "cygwin", "cygwin64",
    "python", "python27", "python3", "python310", "python311", "python312", "python313",
    "ruby", "perl", "strawberry", "tdm-gcc", "llvm", "cmake", "ninja",
    "androidsdk", "android-sdk", "android-ndk", "androidstudio",
    "jdk", "jre", "java", "gradle", "maven", "tools", "toolchains", "sdk", "ndk",
    "vcpkg", "conan", "chocolatey", "scoop", "hostedtoolcache",
    "buildtools", "buildagent", "agent", "jenkins", "actions-runner",
})

#: 具备"私有构建工作区"结构资格的根家族。
#:
#: ★``/workspace`` 与 ``/build`` **不在此列**：它们是公共约定目录而非自管位——
#: ``/workspace`` 是 Google Cloud Build 的默认工作目录、也是多数 CI 容器的挂载点，
#: ``/build`` 是构建镜像的惯用目录。实测把它们当私有工作区时，
#: ``/workspace/src/grpc/...``（任何在 Cloud Build 上编译的合法 SDK）会被判成"自建构建环境"，
#: 让干净 App 凭空多出一条取证结论。这类路径降级 unknown：拿不准就别下判断。
_SELF_HOSTED_FAMILIES = frozenset({"opt", "srv"})

#: CI / 构建代理的标志物：出现在**构建根**里即说明该目录属某个持续集成系统，
#: 不是"某人自管的工作区"。做成关键词而非根路径清单——CI 的安装位各家各异
#: （``/opt/jenkins`` ``/srv/jenkins`` ``/var/lib/jenkins`` 都常见），逐个列举是打地鼠。
#: ★只在**构建根**上匹配，不在完整路径上：私有工作区下面挂个名叫 jenkins 的目录
#: 不该让整条路径改判（同"只看构建根"那条纪律）。
_CI_MARKERS: tuple[str, ...] = (
    "jenkins", "gitlab-runner", "buildkite", "teamcity", "bamboo", "atlassian",
    "circleci", "travis", "drone", "woodpecker", "concourse", "gocd", "bitrise",
    "codebuild", "cloudbuild", "azure-pipelines", "actions-runner", "buildagent",
    "hostedtoolcache", "toolcache", "gradle", "maven", "conan", "vcpkg",
)


@dataclass
class ClassifiedPath:
    """一条构建路径的分层结果（root 为小写归一，identifier/username 保留原样大小写）。"""

    path: str
    tier: str
    root: str
    identifier: str | None = None
    username: str | None = None
    origin: str | None = None  # 第三方清单命中时的依据说明


def extract_paths(blob: bytes, *, limit: int = _MAX_PATHS) -> list[str]:
    """从二进制/文本坨中提取候选构建路径（反斜杠归一为 ``/``、剥尾部 ``./``、去重保序）。"""
    out: list[str] = []
    seen: set[str] = set()
    for regex in (_UNIX_RE, _WIN_RE):
        for m in regex.finditer(blob):
            if len(out) >= limit:
                return out
            norm = m.group(0).decode("ascii").replace("\\", "/").rstrip("./")
            floor = _MIN_SLASHES_WIN if _WIN_DRIVE_RE.match(norm) else _MIN_SLASHES
            if norm.count("/") < floor:
                continue
            low = norm.lower()
            if low.startswith(_DEVICE_RUNTIME_PREFIXES):
                continue
            if low in seen:
                continue
            seen.add(low)
            out.append(norm)
    return out


def _split_root(path: str) -> tuple[str, str | None, str | None, bool]:
    """拆构建根：返回 ``(root 小写, 标识原样, 用户名原样, 是否具私有工作区结构)``。

    构建标识取**构建根下第一段**（通用规则）：``/opt/<workdir>/<标识>/<项目>/…``。
    "具私有工作区结构" 要求标识后至少还有一段（项目/源码目录）——只有根+标识两层的
    路径（如 ``/opt/soft/nginx``）更像软件安装位而非构建工作区。
    """
    segs = [s for s in path.split("/") if s]
    if not segs:
        return "", None, None, False
    head = segs[0].lower()
    if head.endswith(":"):  # Windows 盘符
        if len(segs) < 2:
            return head, None, None, False
        second = segs[1].lower()
        if second == "users":
            # ``C:\Users\<user>\…``：根取到用户目录，用户名即身份线索本身，
            # 不另给"私有工作区"资格（与 Unix 的 /home/<user> 同构）。
            if len(segs) >= 3:
                return f"{head}/users/{segs[2].lower()}", None, segs[2], False
            return f"{head}/users", None, None, False
        # 非 Users 的盘符根：``D:\im_sdk2\sdk_app2`` 这类自定义项目根。工具链/系统位
        # 单独挡在 classify_path 里（此处只负责拆），标识取根下第一段。
        root = f"{head}/{second}"
        identifier = segs[2] if len(segs) >= 3 else None
        return root, identifier, None, len(segs) >= 3
    if head in ("home", "users"):
        if len(segs) >= 2:
            return f"/{head}/{segs[1].lower()}", None, segs[1], False
        return f"/{head}", None, None, False
    if head == "root":
        return "/root", None, "root", False
    if head == "opt":
        root = f"/opt/{segs[1].lower()}" if len(segs) >= 2 else "/opt"
        identifier = segs[2] if len(segs) >= 3 else None
        return root, identifier, None, len(segs) >= 4
    if head == "srv":
        # 与 /opt 同构：根取到二级（``/srv/<工作区>``），标识取三级。二级并入根，CI 标志物
        # 才检得到（``/srv/jenkins/…`` 的 jenkins 在二级；只取 ``/srv`` 会让它漏网）。
        root = f"/srv/{segs[1].lower()}" if len(segs) >= 2 else "/srv"
        identifier = segs[2] if len(segs) >= 3 else None
        return root, identifier, None, len(segs) >= 4
    if head in ("build", "workspace"):
        # 公共约定目录（Cloud Build 默认工作区 / 构建镜像惯用位）：仍记录路径，但不给
        # 私有工作区资格——见 _SELF_HOSTED_FAMILIES 处的说明。
        return f"/{head}", segs[1] if len(segs) >= 2 else None, None, False
    if head in ("mnt", "volumes"):
        root = f"/{head}/{segs[1].lower()}" if len(segs) >= 2 else f"/{head}"
        return root, None, None, False
    return f"/{head}", None, None, False


def classify_path(path: str) -> ClassifiedPath:
    """按**构建根**分层（绝不看整条路径里的项目名——见模块 docstring 的踩坑记录）。"""
    low = path.lower()
    root, identifier, username, eligible = _split_root(path)
    for prefix, origin in _KNOWN_THIRD_PARTY_ROOTS:
        if low.startswith(prefix):
            return ClassifiedPath(
                path=path, tier=TIER_THIRD_PARTY, root=root, username=username, origin=origin
            )
    # 依赖缓存：路径本身在作者机器上，但内容全是下载来的依赖，里面的名字属依赖作者。
    for marker, origin in _DEPENDENCY_CACHE_MARKERS:
        if marker in low:
            return ClassifiedPath(
                path=path, tier=TIER_THIRD_PARTY, root=root, username=username, origin=origin
            )
    # CI/构建代理的安装位不是"某人自管的工作区"。只在**构建根**上匹配，不看整条路径——
    # 私有工作区下面挂个叫 gradle 的目录不该让整条路径改判（同"只看构建根"那条纪律）。
    if any(marker in root for marker in _CI_MARKERS):
        return ClassifiedPath(path=path, tier=TIER_UNKNOWN, root=root, username=username)

    if root[:1].isalpha() and root[1:2] == ":":
        # Windows 盘符根。工具链/系统安装位人人相同、零身份信息 → 第三方（=非本样本作者），
        # 否则自定义项目根（``D:/im_sdk2/…``）具私有工作区资格。
        second = root.split("/", 1)[1] if "/" in root else ""
        if second in _WIN_TOOLCHAIN_SEGMENTS:
            return ClassifiedPath(
                path=path, tier=TIER_THIRD_PARTY, root=root, username=username,
                origin="Windows 工具链/系统安装位（编译器、SDK、包管理器默认位，非作者工作区）",
            )
        if eligible and identifier:
            return ClassifiedPath(
                path=path, tier=TIER_SELF_HOSTED, root=root,
                identifier=identifier, username=username,
            )
        return ClassifiedPath(path=path, tier=TIER_UNKNOWN, root=root, username=username)

    family = root.lstrip("/").split("/", 1)[0]
    if eligible and identifier and family in _SELF_HOSTED_FAMILIES:
        return ClassifiedPath(
            path=path, tier=TIER_SELF_HOSTED, root=root, identifier=identifier, username=username
        )
    return ClassifiedPath(path=path, tier=TIER_UNKNOWN, root=root, username=username)


def parse_build_identifier(raw: str) -> dict[str, str | None]:
    """尽力解析构建标识为 ``<批次>-<代号>-<业务>``；拆不出三段就原样保留。

    ★不硬编码特定批次前缀格式（Env####/CC## 只是已见平台的写法）：通用规则是
    "``-`` 分隔且 ≥3 段才按 批次-代号-业务 拆"，业务段可含余下全部（如 ``AV-BBDUN-MM``）。
    """
    parts = raw.split("-")
    if len(parts) >= 3 and all(parts[:3]):
        return {"raw": raw, "batch": parts[0], "code": parts[1], "business": "-".join(parts[2:])}
    return {"raw": raw, "batch": None, "code": None, "business": None}


# ---------------------------------------------------------------------------
# 分析器
# ---------------------------------------------------------------------------


class BuildProvenanceAnalyzer(BaseAnalyzer):
    """提取构建来源路径并分层：第三方继承 / 私有平台疑似 / 未知。"""

    name: str = "build_provenance"
    requires: list[str] = ["apk"]

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        # 去重键 = 归一化小写路径；值保留首见 (原样路径, source, location) 供证据引用。
        hits: dict[str, tuple[str, str, str]] = {}
        try:
            self._collect_dex(ctx, hits, result)
        except Exception:
            logger.exception("[%s] DEX 侧构建路径提取失败，仅据 .so 判定", self.name)
        try:
            self._collect_native(ctx, hits)
        except Exception:
            logger.exception("[%s] native 侧构建路径提取失败", self.name)

        classified = [(classify_path(p), src, loc) for p, src, loc in hits.values()]
        meta, self_hosted_ev = self._summarize(classified)
        result.meta["build_provenance"] = meta

        if not classified:
            logger.info("[%s] 未提取到构建来源路径", self.name)
            return result
        result.findings.append(self._summary_finding(meta))
        if meta["self_hosted"]:
            result.findings.append(self._self_hosted_finding(meta, self_hosted_ev))
        return result

    # ---- 采集 ----

    def _collect_dex(
        self,
        ctx: "AnalysisContext",
        hits: dict[str, tuple[str, str, str]],
        result: AnalyzerResult,
    ) -> None:
        """从 DEX 字符串里捞构建路径。

        ★``result`` 是为了把"扫描被截断"这个事实带回去：本分析器扫 DEX 正是为了找构建标识，
        截断意味着可能漏掉跨案锚点——而漏掉时报告若不吭声，读的人会以为"这个样本没有自建构建
        路径"，实际只是没扫到那一段。
        """
        _ok, strings = collect_dex_strings(
            ctx, self.name, max_strings=_MAX_DEX_STRINGS, result=result
        )
        # 预筛含分隔符的串再拼坨：字符串池绝大多数与路径无关，先筛掉省一遍正则扫描量。
        blob = "\n".join(s for s in strings if "/" in s or "\\" in s).encode("utf-8", "replace")
        for path in extract_paths(blob, limit=max(0, _MAX_PATHS - len(hits))):
            hits.setdefault(path.lower(), (path, "dex", "dex-strings"))

    def _collect_native(
        self, ctx: "AnalysisContext", hits: dict[str, tuple[str, str, str]]
    ) -> None:
        """全量（非采样）扫 App 自有 .so：__FILE__ 串散布于 .rodata 各处，三窗采样会漏。

        有界：单库 ``_MAX_LIB_BYTES``（读前先查 zip 声明大小拦截炸弹）、累计
        ``_MAX_TOTAL_LIB_BYTES``、库数 ``_MAX_LIBS``、路径总数 ``_MAX_PATHS``。绝不抛。
        """
        budget = _MAX_TOTAL_LIB_BYTES
        for so_path in app_so_paths(ctx, self.name, max_libs=_MAX_LIBS):
            if len(hits) >= _MAX_PATHS:
                break
            if budget <= 0:
                logger.info("[%s] .so 累计读入达上限，剩余库未扫", self.name)
                break
            try:
                declared = ctx.declared_size(so_path)
            except Exception:
                logger.debug("[%s] 查声明大小失败：%s", self.name, so_path, exc_info=True)
                declared = None
            if declared is not None and declared > _MAX_LIB_BYTES:
                continue  # 超大库不读、不膨胀
            try:
                data = ctx.read_file(so_path)
            except Exception:
                logger.debug("[%s] 读 .so 失败，跳过：%s", self.name, so_path, exc_info=True)
                continue
            if not data or len(data) > _MAX_LIB_BYTES:
                continue
            budget -= len(data)
            for path in extract_paths(data, limit=max(0, _MAX_PATHS - len(hits))):
                hits.setdefault(path.lower(), (path, "native", so_path))

    # ---- 聚合 ----

    def _summarize(
        self, classified: list[tuple[ClassifiedPath, str, str]]
    ) -> tuple[dict, list[Evidence]]:
        """按 (tier, root, identifier) 聚合出 meta；顺带收集 self-hosted 证据（含来源定位）。"""
        groups: dict[tuple[str, str, str], dict] = {}
        usernames: dict[tuple[str, str], dict] = {}
        identifiers: dict[str, dict] = {}
        self_hosted_ev: list[Evidence] = []
        for cp, src, loc in sorted(classified, key=lambda t: t[0].path.lower()):
            key = (cp.tier, cp.root, cp.identifier or "")
            g = groups.setdefault(
                key,
                {"root": cp.root, "identifier": cp.identifier, "origin": cp.origin,
                 "count": 0, "paths": []},
            )
            g["count"] += 1
            if len(g["paths"]) < _MAX_GROUP_PATHS:
                g["paths"].append(cp.path)
            if cp.username:
                # 用户名分级跟随其所在路径的分层（third_party 优先）：同名账号既见于
                # 已知第三方根又见于未知根时，按更有解释力的第三方归类。
                u = usernames.setdefault(
                    (cp.username.lower(), cp.root),
                    {"name": cp.username, "root": cp.root, "classification": cp.tier},
                )
                if cp.tier == TIER_THIRD_PARTY:
                    u["classification"] = TIER_THIRD_PARTY
            if cp.tier == TIER_SELF_HOSTED and cp.identifier:
                identifiers.setdefault(
                    cp.identifier, {**parse_build_identifier(cp.identifier), "root": cp.root}
                )
                if len(self_hosted_ev) < _MAX_EVIDENCE:
                    self_hosted_ev.append(Evidence(source=src, location=loc, snippet=cp.path))
        meta = {
            "self_hosted": [
                {k: v for k, v in g.items() if k != "origin"}
                for (tier, _r, _i), g in sorted(groups.items())
                if tier == TIER_SELF_HOSTED
            ],
            "third_party": [
                {k: v for k, v in g.items() if k != "identifier"}
                for (tier, _r, _i), g in sorted(groups.items())
                if tier == TIER_THIRD_PARTY
            ],
            "identifiers": [identifiers[k] for k in sorted(identifiers)],
            "unknown": [
                {"root": g["root"], "count": g["count"], "paths": g["paths"]}
                for (tier, _r, _i), g in sorted(groups.items())
                if tier == TIER_UNKNOWN
            ],
            # 用户名只进 meta 供人核，不进 Finding 正文（可能是第三方 SDK 开发者的名字）。
            "usernames": [usernames[k] for k in sorted(usernames)],
        }
        return meta, self_hosted_ev

    # ---- Finding ----

    def _summary_finding(self, meta: dict) -> Finding:
        n_sh = sum(g["count"] for g in meta["self_hosted"])
        n_tp = sum(g["count"] for g in meta["third_party"])
        n_unk = sum(g["count"] for g in meta["unknown"])
        return Finding(
            id="BUILD-PROVENANCE-PATHS",
            title=(
                f"编译产物泄露构建来源路径 {n_sh + n_tp + n_unk} 条"
                f"（第三方继承 {n_tp} / 私有平台疑似 {n_sh} / 未知 {n_unk}）"
            ),
            severity=Severity.INFO,   # 情报维度，不是威胁
            confidence=Confidence.MEDIUM,
            category="provenance",
            description=(
                "编译器把源码文件的绝对路径（__FILE__ 断言/日志串）原样编进产物，泄露构建机目录结构。"
                "已按**构建根**分层（详单见 meta.build_provenance）：\n"
                "★ third_party_known 段随第三方 SDK / 开源项目源码**继承**而来（如 Telegram 官方源码、"
                "RTC SDK 预编译库、公共 CI），与本样本的构建环境**无关**，不得作为归属依据；\n"
                "★ unknown 段既可能是样本自有构建机、也可能是未收录的第三方来源，仅供人工复核；\n"
                "★ 路径中的账户名一律不列入本发现正文，仅存 meta 供人工核对。"
            ),
            recommendation=(
                "只有 self_hosted_suspected 段值得进一步研判；third_party_known 段直接忽略。"
                "unknown 段复核后若确认为公开 SDK 来源，应回补进第三方清单。"
            ),
        )

    def _self_hosted_finding(self, meta: dict, evidences: list[Evidence]) -> Finding:
        idents = meta["identifiers"]
        shown: list[str] = []
        for info in idents[:3]:
            if info["batch"]:
                shown.append(
                    f"{info['raw']}（批次 {info['batch']} / 代号 {info['code']}"
                    f" / 业务 {info['business']}）"
                )
            else:
                shown.append(str(info["raw"]))
        roots = "、".join(sorted({g["root"] for g in meta["self_hosted"]}))
        return Finding(
            id="BUILD-PROVENANCE-SELF-HOSTED",
            title="编译产物含私有构建平台路径（跨样本关联锚点）",
            severity=Severity.LOW,    # 情报信号：关联价值高，但本身不是威胁行为
            confidence=Confidence.MEDIUM,
            category="provenance",
            description=(
                f"构建根 {roots} 不在已知第三方来源清单内，且具有"
                "「构建根/<标识>/<项目>/…」的私有工作区结构，疑似定制打包平台。"
                f"提取到构建标识：{'；'.join(shown)}。"
                "同一构建标识在多个样本中复现即为强关联信号（同一打包环境产出）。\n"
                "★ 分层为 suspected 而非断言：不排除该根来自尚未收录的第三方来源，"
                "结论前应结合签名证书、资源指纹等独立维度互证。"
            ),
            recommendation=(
                "用该构建标识做跨样本检索（corpus / 历史报告全文），"
                "标识可拆出的批次序号与业务字段可用于梳理同平台的其他产出。"
            ),
            evidences=evidences,
        )
