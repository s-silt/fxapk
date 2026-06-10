"""jadx 深度反编译增强器：用 jadx CLI 反编译 APK，从 Java 字符串字面量补端点 / 密钥。

为什么需要：androguard 的 DEX 字符串池有时拿不全（被混淆 / 拆分 / 加固残留）；
jadx 反编译出可读 Java 后，真实接口与硬编码密钥往往在字符串字面量里更完整。

约束：
- ``requires=["jadx"]``：registry 探测到 PATH 有 jadx 才运行，否则 pipeline 自动 skipped。
- 用 ctx.apk_path 定位 APK；为空 → 优雅跳过（error 写明，不崩）。
- subprocess 设超时；临时目录 finally 清理（ignore_errors）。
- 只在 Java 字符串字面量（"..."）内抽取，并对裸域名用安全 TLD 白名单，降误报。
- 任何失败 → 记日志 + meta['jadx_status']，不抛、不静默吞错。
"""

from __future__ import annotations

import ipaddress
import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from apkscan.core.models import (
    AnalyzerResult,
    Endpoint,
    Evidence,
    Finding,
    Severity,
)
from apkscan.core import infra
from apkscan.core.registry import BaseAnalyzer
from apkscan.core.secrets import (
    SecretRules,
    is_sdk_constant,
    load_secret_rules,
    looks_like_secret_value,
)
from apkscan.core.textutil import is_noise_bare_ip as _is_noise_bare_ip

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

# jadx 反编译大 APK 较慢，给足超时（秒）。
_TIMEOUT = 300.0
_MAX_JAVA_FILES = 5000
_MAX_FILE_BYTES = 4 * 1024 * 1024
_SNIPPET_MAX = 200

# 裸域名安全 TLD 白名单（与 js_bundle / endpoints 同口径，剔除与代码撞车的伪 TLD）。
_SAFE_BARE_TLDS: frozenset[str] = frozenset(
    {
        "com", "cn", "net", "org", "gov", "edu", "biz", "io", "co",
        "xyz", "vip", "club", "shop", "site", "app", "tech", "cloud",
        "fun", "ltd", "pro", "wang", "ren", "mobi", "asia", "icu",
        "hk", "tw", "mo", "jp", "kr", "sg", "us", "uk", "ru", "de", "fr",
    }
)
_PACKAGE_ROOTS: frozenset[str] = frozenset(
    {"com", "cn", "org", "net", "io", "edu", "android", "androidx",
     "java", "javax", "kotlin", "kotlinx", "dalvik"}
)
_CODE_WORDS: frozenset[str] = frozenset(
    {"this", "self", "length", "value", "name", "type", "style", "path",
     "data", "config", "prototype", "exports", "target", "state", "props"}
)

# Java 双引号字符串字面量（容忍转义）。
_STR_LIT_RE = re.compile(r'"([^"\\\n]*(?:\\.[^"\\\n]*)*)"')
_URL_RE = re.compile(r"""https?://[^\s"'`<>()\[\]{}\\^|,;]+""", re.IGNORECASE)
_IPV4_RE = re.compile(r"""(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?(?![\w.])""")
_DOMAIN_RE = re.compile(
    r"""(?<![\w@./-])((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24})(?![\w.-])"""
)
# 硬编码密钥键值：key = "value" / "key":"value"。
_SECRET_KV_RE = re.compile(
    r"""["']?(?P<key>[A-Za-z_][A-Za-z0-9_]*)["']?\s*[:=]\s*["'](?P<val>[^"'\n]{8,512})["']"""
)
_SECRET_HINTS: tuple[str, ...] = (
    "secret", "appkey", "app_key", "appsecret", "app_secret", "access_key",
    "accesskey", "api_key", "apikey", "private_key", "privatekey", "aes_key",
    "aeskey", "token", "client_secret", "mch_key", "sign_key", "signkey",
)
_SECRET_DENY: frozenset[str] = frozenset(
    {"token_type", "tokentype", "keyword", "keywords", "keycode", "keyboard"}
)
_PLACEHOLDER: frozenset[str] = frozenset(
    {"your_app_id", "yourappid", "your_app_key", "your_secret", "xxxxxxxx",
     "test", "demo", "none", "null", "undefined", "example"}
)

_FINDING_SECRET = "JADX-HARDCODED-SECRET"


class JadxAnalyzer(BaseAnalyzer):
    """jadx 反编译后从 Java 字符串字面量补端点 / 密钥（requires=["jadx"]）。"""

    name: str = "jadx"
    requires: list[str] = ["jadx", "apk"]  # jadx 反编 DEX，IPA 无 DEX → 缺 apk 能力 skipped

    def __init__(self) -> None:
        # 每次 analyze 重新加载（见下）；这里给默认值供类型检查与兜底。
        self._secret_rules: SecretRules = SecretRules()
        self._noise_ips: frozenset[str] = frozenset()

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        apk_path = (getattr(ctx, "apk_path", "") or "").strip()
        if not apk_path:
            logger.info("[jadx] 无 apk_path，跳过 jadx 反编译")
            result.error = "无 apk_path，跳过 jadx 反编译"
            result.meta["jadx_status"] = "no_apk_path"
            return result

        # C2/C4 规则一次性加载（缺失走内置兜底，离线不崩）。
        self._secret_rules = load_secret_rules()
        self._noise_ips = _load_noise_ips()

        tmp = tempfile.mkdtemp(prefix="apkscan_jadx_")
        try:
            status = self._run_jadx(apk_path, tmp)
            result.meta["jadx_status"] = status
            # timeout/failed 仍尽量扫已生成产物（jadx 常非零退出但已产出部分源码）。
            eps, findings, n_files = self._scan_java(Path(tmp))
            result.endpoints = eps
            result.findings = findings
            result.meta["jadx_java_files"] = n_files
            result.meta["jadx_endpoint_count"] = len(eps)
            logger.info(
                "[jadx] status=%s java=%d 端点=%d 密钥Finding=%d",
                status, n_files, len(eps), len(findings),
            )
        except Exception as exc:  # noqa: BLE001 - 任何异常转 error，不抛给 pipeline
            logger.exception("[jadx] 反编译/扫描异常")
            result.error = f"jadx 增强异常：{exc}"
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return result

    # ------------------------------------------------------------------

    def _run_jadx(self, apk_path: str, out_dir: str) -> str:
        """跑 jadx --no-res -d <out> <apk>。返回 ok|partial|timeout|failed（不抛）。"""
        cmd = ["jadx", "--no-res", "-d", out_dir, apk_path]
        logger.info("[jadx] 执行：%s", " ".join(cmd))
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=_TIMEOUT, check=False
            )
        except subprocess.TimeoutExpired:
            logger.warning("[jadx] 反编译超时（%ss）：%s", _TIMEOUT, apk_path)
            return "timeout"
        except Exception:
            logger.exception("[jadx] 启动 jadx 失败：%s", apk_path)
            return "failed"
        if proc.returncode != 0:
            # jadx 对部分类反编译失败时返回非零，但通常已产出大部分 .java。
            logger.warning(
                "[jadx] 非零退出（%s），按部分产物继续扫描。stderr 尾部：%s",
                proc.returncode,
                (proc.stderr or "")[-1000:],
            )
            return "partial"
        return "ok"

    def _scan_java(self, root: Path) -> tuple[list[Endpoint], list[Finding], int]:
        """扫 root 下所有 .java，从字符串字面量抽端点，从键值抽密钥。"""
        collector: dict[str, Endpoint] = {}
        secret_hits: dict[tuple[str, str], Finding] = {}
        n_files = 0
        for java in root.rglob("*.java"):
            if n_files >= _MAX_JAVA_FILES:
                logger.warning("[jadx] .java 文件数超过上限 %d，截断扫描", _MAX_JAVA_FILES)
                break
            try:
                data = java.read_bytes()
            except Exception:
                logger.exception("[jadx] 读取 .java 失败，跳过：%s", java)
                continue
            if not data:
                continue
            if len(data) > _MAX_FILE_BYTES:
                data = data[:_MAX_FILE_BYTES]
            n_files += 1
            text = data.decode("utf-8", errors="ignore")
            rel = str(java.relative_to(root))
            try:
                self._scan_text(text, rel, collector, secret_hits)
            except Exception:
                logger.exception("[jadx] 扫描 .java 失败，跳过：%s", rel)
        return list(collector.values()), list(secret_hits.values()), n_files

    def _scan_text(
        self,
        text: str,
        location: str,
        collector: dict[str, Endpoint],
        secret_hits: dict[tuple[str, str], Finding],
    ) -> None:
        # 1) 端点：只在字符串字面量内抽。
        for m in _STR_LIT_RE.finditer(text):
            lit = m.group(1)
            if not lit or len(lit) > 4096:
                continue
            self._scan_literal(lit, location, collector)
        # 2) 硬编码密钥（键值上下文，全文）。
        for m in _SECRET_KV_RE.finditer(text):
            self._consider_secret(m.group("key"), m.group("val"), location, secret_hits)

    def _scan_literal(
        self, lit: str, location: str, collector: dict[str, Endpoint]
    ) -> None:
        for m in _URL_RE.finditer(lit):
            url = _strip_tail(m.group())
            host = _host_from_url(url)
            if not url or not host:
                continue
            _add(collector, url, "url", location,
                 is_cleartext=url.lower().startswith("http://"))
            ip = _parse_ipv4(host)
            if ip is not None:
                _add(collector, host, "ip", location, is_private=_ip_private(ip))
            elif _safe_domain(host):
                _add(collector, host, "domain", location,
                     tier=infra.domain_source_tier(location, len(lit)))
        for m in _IPV4_RE.finditer(lit):
            ip_str = m.group(1)
            ip = _parse_ipv4(ip_str)
            if ip is None:
                continue
            # C4：裸 IP 去噪，与 endpoints/js_bundle 共享判定（bogon/保留段 +
            #   占位/版本号 denylist），消除三处不一致。URL 内 IP 走上面 host 通道不受限。
            if ip_str in self._noise_ips or _is_noise_bare_ip(ip_str):
                continue
            _add(collector, ip_str, "ip", location, is_private=_ip_private(ip))
        for m in _DOMAIN_RE.finditer(lit):
            dom = m.group(1).rstrip(".").lower()
            if _safe_domain(dom):
                _add(collector, dom, "domain", location,
                     tier=infra.domain_source_tier(location, len(lit)))

    def _consider_secret(
        self, key: str, val: str, location: str, hits: dict[tuple[str, str], Finding]
    ) -> None:
        low = key.lower()
        if low in _SECRET_DENY or not any(h in low for h in _SECRET_HINTS):
            return
        v = val.strip()
        if v.lower() in _PLACEHOLDER or len(set(v)) <= 2 or " " in v:
            return
        if v.startswith(("/", "http://", "https://", "./", "../")) or any(c in v for c in "{}$<>"):
            return
        # C2 三道闸（杀 SDK 常量名误报）：
        #  ① value==key / 已知 SDK 常量名/值 → drop（MIPUSH_APPKEY=MIPUSH_APPKEY、
        #     KEY_DEVICE_TOKEN=deviceToken、METHOD_CHECK_APPKEY=dc_checkappkey）。
        if is_sdk_constant(key, v, self._secret_rules):
            return
        #  ② value 不像凭据形态（无数字/非 hex/无 base64 字符）→ drop（deviceToken 类）。
        #     真凭据（Abc123Xyz789Def456 等）全 looks_keyish=True，不误杀。
        if not looks_like_secret_value(v, self._secret_rules):
            return
        dedup = (location, f"{low}:{v[:48]}")
        if dedup in hits:
            return
        hits[dedup] = Finding(
            id=_FINDING_SECRET,
            title="jadx 反编译发现硬编码密钥 / 凭证",
            severity=Severity.HIGH,
            category="secret",
            description=(
                f"jadx 反编译的 Java 中出现硬编码凭证：键 '{key}' 配置了明文常量。"
                "可被逆向直接读取并冒用访问后端 / 第三方服务。"
            ),
            recommendation="核实该凭证对应服务，向厂商调取调用记录与绑定主体；提示吊销。",
            evidences=[Evidence(source="jadx", location=location, snippet=_short(f"{key}={v}"))],
            references=["CWE-798"],
        )


# ---------------------------------------------------------------------------
# 模块级工具
# ---------------------------------------------------------------------------

# 噪音 IP 兜底（C4：与 endpoints/js_bundle 同口径）。
_FALLBACK_NOISE_IPS: tuple[str, ...] = (
    "1.2.3.4", "0.0.0.0", "13.3.3.7", "2.1.5.1", "3.2.16.7",
)


def _load_noise_ips() -> frozenset[str]:
    """从 endpoints.yaml 读 noise_ips（C4 单一数据源；缺失走内置兜底）。"""
    try:
        from apkscan.core.registry import load_rules
        from apkscan.core.textutil import as_str_list

        data = load_rules("endpoints")
    except Exception:  # noqa: BLE001 — 规则读取失败不应炸掉 analyze
        logger.exception("[jadx] 读取 endpoints 规则（noise_ips）失败，用兜底")
        return frozenset(_FALLBACK_NOISE_IPS)
    if isinstance(data, dict):
        nips = as_str_list(data.get("noise_ips"))
        if nips:
            return frozenset(ip.strip() for ip in nips)
    return frozenset(_FALLBACK_NOISE_IPS)


def _add(
    collector: dict[str, Endpoint],
    value: str,
    kind: str,
    location: str,
    *,
    is_cleartext: bool = False,
    is_private: bool = False,
    tier: str | None = None,
) -> None:
    ep = collector.get(value)
    if ep is None:
        ep = Endpoint(
            value=value,
            kind=kind,
            evidences=[Evidence(source="jadx", location=location, snippet=_short(value))],
            is_cleartext=is_cleartext,
            is_private=is_private,
        )
        if tier is not None:
            ep.enrichment["tier"] = tier
        collector[value] = ep
        return
    ep.is_cleartext = ep.is_cleartext or is_cleartext
    ep.is_private = ep.is_private or is_private
    if tier is not None:
        # 域名来源可信度档（C1）：多来源取最可信档（app 优先）。
        current = ep.enrichment.get("tier")
        ep.enrichment["tier"] = infra.best_tier(current, tier) if current else tier
    if all(ev.location != location for ev in ep.evidences):
        ep.evidences.append(Evidence(source="jadx", location=location, snippet=_short(value)))


def _safe_domain(domain: str) -> bool:
    labels = domain.lower().split(".")
    if len(labels) < 2 or labels[-1] not in _SAFE_BARE_TLDS:
        return False
    sld = labels[-2]
    if len(sld) < 2 or sld in _CODE_WORDS or labels[0] in _PACKAGE_ROOTS:
        return False
    return True


def _parse_ipv4(s: str) -> ipaddress.IPv4Address | None:
    parts = s.split(".")
    if len(parts) != 4 or any((not p.isdigit() or len(p) > 3 or int(p) > 255) for p in parts):
        return None
    try:
        return ipaddress.IPv4Address(s)
    except ValueError:
        return None


def _ip_private(ip: ipaddress.IPv4Address) -> bool:
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_unspecified or ip.is_reserved or ip.is_multicast)


def _host_from_url(url: str) -> str:
    try:
        after = url.split("://", 1)[1]
    except IndexError:
        return ""
    for sep in ("/", "?", "#"):
        idx = after.find(sep)
        if idx != -1:
            after = after[:idx]
    if "@" in after:
        after = after.rsplit("@", 1)[1]
    if ":" in after:
        after = after.split(":", 1)[0]
    return after.strip().rstrip(".").lower()


def _strip_tail(url: str) -> str:
    url = url.strip()
    while url and url[-1] in ".,;:'\")]}>":
        url = url[:-1]
    return url


def _short(text: str, limit: int = _SNIPPET_MAX) -> str:
    return text if len(text) <= limit else text[:limit] + "…"
