"""批量被动富化：给一个目标列表（每行一个 IP / 域名），跑已有富化器，回灌 CSV + NDJSON。

为什么单独一层：仓库既有富化都在 analyze 管线内**按端点**触发，没有「拿一份目标清单
批量查、断点续跑、先估配额」的入口。本模块只做**调度与序列化**，判定与请求全部复用
``core/enrichment.enrich_selected_targets`` 与 ``enrichers/`` 下既有富化器——不另写一套查询。

铁律（与 ``report/ioc.py`` / ``core/corpus.py`` 一致）：本模块是纯逻辑层，**禁** print/typer，
坏输入容错返回空/跳过，**绝不抛**（IO 异常由 ``commands/enrich.py`` 那层管）。

三条设计要点：

1. **dry-run 绝不发请求**。``estimate_budget`` 只按目标数 × ``applies_to`` × ``required_env``
   静态估算，代码路径上根本不碰 ``enrich_selected_targets``。这是防误烧配额的闸门，
   不是提示信息。
2. **断点续跑靠本层账本**。``_PassiveLookupEnricher`` 那一支（FOFA/Quake/AbuseIPDB…）
   **没有**文件缓存，指望富化器自己记住是错的；本层按 ``target + provider`` 记录成功/
   查无记录的终态。失败、缺 key、主动模式阻断都不算完成，补 key 或重跑时只补缺失源。
3. **限频现状是分化的**，多数 key-gated 源不自限频。本层的保护只有两件：dry-run 预算
   与保守的单次运行上限（``DEFAULT_MAX_TARGETS``）。不声称"复用各源已有限频"。
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from apkscan.core.json_contract import (
    parse_finite_json_float,
    reject_nonfinite_json_constant,
)
from apkscan.core.models import ANALYSIS_MODE_PASSIVE, Endpoint
from apkscan.core.source_status import (
    normalize_source_status,
    normalize_source_status_map,
    source_status_value,
)
from apkscan.report.ioc import _csv_safe

logger = logging.getLogger(__name__)

#: 单次运行的目标上限。key-gated 源多数不自限频，靠这个保守闸门兜住"一口气烧掉整天配额"。
#: 需要更多就显式抬高（命令行 ``--max-targets``），让抬高这件事是**有意识的**。
DEFAULT_MAX_TARGETS = 200

#: 账本 / 明细 NDJSON 每行的固定键。``target`` 是续跑判重的主键。
LEDGER_KEY = "target"

#: 账本读取的三道硬上限。★为什么必须有：``enrich.ndjson`` 是 **append-only** 事件账本，
#: 每轮都往里加行、永不重写，长期只会变大；而它同时是续跑判据，每轮开跑前都要整份读一遍。
#: 一次性 ``read_text()`` 把整份读进内存 + 再 ``splitlines()`` 复制一份，账本涨到几百 MB
#: 时读它本身就成了故障点。三道上限各挡一个资源维度：
#: 文件总字节（整份体量）、单行字节（一条被写坏/被拼接的巨行）、记录数（对象数量）。
MAX_LEDGER_BYTES = 64 * 1024 * 1024
MAX_LEDGER_LINE_BYTES = 1 * 1024 * 1024
MAX_LEDGER_RECORDS = 200_000

#: 逐块读账本的块大小（只影响 IO 次数，不影响语义）。
_LEDGER_CHUNK_BYTES = 256 * 1024

#: 只有这两种状态说明该 provider 对该 target 已经完成；failed/disabled/skipped 都可重试。
LEDGER_COMPLETE_STATUSES: frozenset[str] = frozenset({"hit", "no_record"})

#: CSV 固定前缀列；其后按 provider 名字典序各占一列（值=状态 + 归一化富化响应）。
BASE_COLUMNS: tuple[str, ...] = ("target", "kind")

#: 目标行注释前缀（方便清单里写分组说明）。
_COMMENT_PREFIXES = ("#", "//")

#: 域名判据：至少两段、每段 1-63 位字母数字或连字符、末段为字母。故意不查 IANA 全表——
#: 这里只需把"明显不是域名的输入"挡掉，真伪由富化结果说话。
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)

#: 预算行状态。``would_query`` = 会真发请求并计配额；``disabled`` = 缺 key 不会跑；
#: ``not_applicable`` = 该源不吃这种目标（如 abuseipdb 只吃 ip）；
#: ``already_done`` = 该源对全部适用目标都已在续跑账本里完成，本次不再发请求。
#:
#: ★``already_done`` 与 ``not_applicable`` 必须分开：二者都表现为「本次 0 请求」，
#:   但含义相反——前者是"查过了"，后者是"压根不该查"。合成一个状态会输出自相矛盾的
#:   预算行（一个只吃 ip 的源、目标就是 IP、上次刚查成功，却被标成"不吃这种目标"），
#:   读的人无从判断预算对不对。
BUDGET_STATUSES = ("would_query", "disabled", "not_applicable", "already_done")


def _not_applicable_reason(applies_to: list[str]) -> str:
    """说清「为什么这个源不适用」——区分「不吃这种 kind」与「有意不声明」。

    ★空 ``applies_to`` **不是遗漏**：仓内至少 ``whois`` 是有意留空的（见
      ``enrichers/whois.py`` 的注释——域名注册归属已收敛到 ``rdap``，``rdap`` 内部再拿
      ``whois.query_whois`` 兜底；两边都声明就会对同一域名双查）。

      此前这里统一输出「只吃 （未声明）」，把一个深思熟虑的决定说成疏漏。后果是**读的人很可能
      "顺手补上" applies_to，把双查重新引进来**——而双查不报错、只静默多烧一倍配额，极难发现。
      所以这句话必须自带"别补回来"的提示：**输出里的措辞会引导下一个人的修改方向。**
    """
    if applies_to:
        return "只吃 " + ", ".join(str(k) for k in applies_to)
    return (
        "applies_to 为空——有意不参与批量路由，非遗漏"
        "（如 whois：域名注册归属已收敛到 rdap，补回会造成双查）"
    )


@dataclass(frozen=True)
class Target:
    """一个规范化后的富化目标。"""

    value: str
    kind: str  # "ip" | "domain"


@dataclass(frozen=True)
class BudgetLine:
    """dry-run 预算的一行：某个源会对多少目标发请求。"""

    provider: str
    status: str
    targets: int
    reason: str = ""


def classify_target(raw: object) -> Target | None:
    """把一行输入规范化成 :class:`Target`；无法判型 → ``None``（调用方跳过、不猜）。

    只认 IP 与域名两种：IP 走 ``ipaddress`` 严格解析（顺带排除 ``1.2.3`` 这类简写），
    域名走 :data:`_DOMAIN_RE`。带 scheme 的 URL、端口、路径一律**不**在此拆解——
    批量清单的语义是"一行一个可查目标"，猜测式拆解容易把 ``example.com/b`` 当域名查错。
    """
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text or text.startswith(_COMMENT_PREFIXES):
        return None
    try:
        ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        return Target(value=text, kind="ip")
    lowered = text.lower()
    if _DOMAIN_RE.match(lowered):
        return Target(value=lowered, kind="domain")
    return None


def parse_targets(text: object) -> tuple[list[Target], list[str]]:
    """解析目标清单文本 → （去重后的目标, 判不了型的原始行）。

    去重保序：同一个值出现多次只查一次（配额只花一份），顺序按首次出现——
    输出稳定、便于与输入清单逐行对照。
    """
    if not isinstance(text, str):
        return [], []
    targets: list[Target] = []
    seen: set[str] = set()
    skipped: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(_COMMENT_PREFIXES):
            continue
        target = classify_target(stripped)
        if target is None:
            skipped.append(stripped)
            continue
        if target.value in seen:
            continue
        seen.add(target.value)
        targets.append(target)
    return targets, skipped


def _provider_name(enricher: object) -> str:
    return str(getattr(enricher, "name", "") or type(enricher).__name__)


def _required_env(enricher: object) -> tuple[str, ...]:
    raw = getattr(enricher, "required_env", ())
    if not isinstance(raw, (list, tuple)):
        return ()
    return tuple(str(name) for name in raw if str(name))


def _is_configured(enricher: object, env: Mapping[str, str]) -> bool:
    required = _required_env(enricher)
    return not required or any((env.get(name) or "").strip() for name in required)


def estimate_budget(
    targets: Sequence[Target],
    enrichers: Sequence[object],
    env: Mapping[str, str],
    completed: Mapping[str, set[str]] | None = None,
) -> list[BudgetLine]:
    """静态估算每个源会发多少请求。**绝不调用富化器、绝不发请求。**

    这是 dry-run 的全部实现：只看目标数、``applies_to`` 与 ``required_env``。
    调用方（CLI）在 ``--dry-run`` 下只走到这里就返回，物理上不可能烧配额。
    """
    lines: list[BudgetLine] = []
    progress = completed or {}
    for enricher in sorted(enrichers, key=_provider_name):
        provider = _provider_name(enricher)
        applies_to = getattr(enricher, "applies_to", []) or []
        # ★「本源适用的目标数」与「本次还要查的目标数」分开算。二者都可能为 0，但原因不同：
        #   applicable == 0 → 这个源不吃这种 kind（或有意不声明 applies_to）
        #   applicable > 0 而 matched == 0 → 都在续跑账本里查过了
        #   混成一个 `matched == 0` 分支，就会把"查过了"报成"不吃这种目标"。
        applicable = sum(1 for target in targets if target.kind in applies_to)
        matched = sum(
            1
            for target in targets
            if target.kind in applies_to and provider not in progress.get(target.value, set())
        )
        if not applicable:
            lines.append(
                BudgetLine(
                    provider=provider,
                    status="not_applicable",
                    targets=0,
                    reason=_not_applicable_reason(applies_to),
                )
            )
            continue
        if not matched:
            lines.append(
                BudgetLine(
                    provider=provider,
                    status="already_done",
                    targets=0,
                    reason=f"{applicable} 个适用目标均已在续跑账本里完成（--no-resume 可强制重查）",
                )
            )
            continue
        if not _is_configured(enricher, env):
            lines.append(
                BudgetLine(
                    provider=provider,
                    status="disabled",
                    targets=0,
                    reason="缺 " + " / ".join(_required_env(enricher)),
                )
            )
            continue
        lines.append(BudgetLine(provider=provider, status="would_query", targets=matched))
    return lines


def budget_total(lines: Iterable[BudgetLine]) -> int:
    """会真发出的请求总数（只计 ``would_query``）。"""
    return sum(line.targets for line in lines if line.status == "would_query")


@dataclass(frozen=True)
class LedgerScan:
    """一次账本读取的完整结果：有效记录 + 坏行数 + **超限告警**。

    为什么把告警单独拎出来而不是只回条数：超限意味着"账本没被完整读回"，续跑判据因此
    不完整、本轮会重查一部分已完成的 provider（花配额）。这件事必须能被 CLI 打印出来，
    不能只体现在"怎么又查了一遍"里。
    """

    records: list[dict[str, Any]]
    bad_lines: int
    limit_warnings: tuple[str, ...] = ()
    #: 账本是否**没被读完**（总字节 / 记录数上限触发了提前 break）。
    #:
    #: ★为什么必须是独立布尔而不是"告警里有没有'上限'字样"：这两类超限的语义完全不同——
    #: 超长**单行**只毒它自己那一行（其余行照常读完，续跑判据仍然完整），而总字节 / 记录数
    #: 上限会让扫描**中途停止**，账本后半段的完成记录集体不可见。调用方要据此决定"能不能
    #: 继续联网"，靠匹配告警文本判断等于把安全判据挂在措辞上，改一个字就静默 fail-open。
    resume_incomplete: bool = False

    @property
    def resume_complete(self) -> bool:
        """续跑判据是否完整可用；供 CLI 输出稳定的正向机器可读状态。"""
        return not self.resume_incomplete


def _iter_ledger_lines(handle: Any) -> "Iterable[tuple[bytes, bool, int]]":
    """二进制逐行产出 ``(行字节, 是否超长, 该行原始字节数)``，单行**永不**无界增长。

    超长行的字节直接丢弃（不进内存）、只以 ``是否超长=True`` 标出，调用方据此计坏行，
    不去尝试解析半截 JSON。第三项如实记该行**原始**长度（含被丢弃的部分），供调用方按
    真实读入量判总字节上限——否则丢弃的巨行会让总量计数偏小，上限形同没有。
    """
    buffer = bytearray()
    raw_len = 0
    overflow = False
    while True:
        chunk = handle.read(_LEDGER_CHUNK_BYTES)
        if not chunk:
            break
        start = 0
        while True:
            index = chunk.find(b"\n", start)
            if index < 0:
                break
            raw_len += index - start
            if not overflow:
                # ★这道检查必须也在**换行分支**上：整条巨行落在同一个读块里时根本走不到
                #   下面的块尾分支，只在块尾判等于"没有上限"。
                if raw_len > MAX_LEDGER_LINE_BYTES:
                    overflow = True
                    buffer.clear()
                else:
                    buffer += chunk[start:index]
            if overflow:
                yield b"", True, raw_len + 1
            else:
                yield bytes(buffer), False, raw_len + 1
            buffer.clear()
            raw_len = 0
            overflow = False
            start = index + 1
        rest = chunk[start:]
        raw_len += len(rest)
        if overflow:
            continue
        if raw_len > MAX_LEDGER_LINE_BYTES:
            # 超限即刻丢弃已积累的前缀：留着它就是把上限抬到"上限 + 一个块"。
            overflow = True
            buffer.clear()
            continue
        buffer += rest
    if overflow:
        yield b"", True, raw_len
    elif buffer:
        yield bytes(buffer), False, raw_len


def scan_ledger(path: object) -> LedgerScan:
    """有界读取 NDJSON 账本 → :class:`LedgerScan`。**绝不抛。**

    ★为什么必须二进制逐行、每行独立严格解码：此前实现是
    ``Path(path).read_text(encoding="utf-8")`` + ``except UnicodeDecodeError: return [], 0``。
    账本里只要有**一行**含非法 UTF-8 字节（写盘中途被杀、外部工具追加了 latin-1 内容），
    整份解码就失败，函数返回 ``records=[]、bad_lines=0`` —— 于是：
      ①``read_ledger`` 得到空 ``done``，**所有**已完成 provider 下一轮全部重查（真金白银的配额）；
      ②``bad_lines=0`` 让摘要显示"账本干净"，坏文件这件事完全不可见；
      ③新记录继续 append 到这份坏文件后面，坏行永远在，每轮都重烧一次。
    现在坏字节只毒它自己那一行：可解析的有效行照常保留，坏行计入 ``bad_lines``。

    三道上限（见 :data:`MAX_LEDGER_BYTES` 等）里，总字节与记录数两道会让扫描**中途停止**，
    账本后半段的完成记录集体不可见 —— 此时 :attr:`LedgerScan.resume_incomplete` 置真，
    调用方**必须**据此在联网前 fail closed（见 :mod:`apkscan.commands.enrich`）。
    保住能读回的那部分记录仍有价值（dry-run 报告、CSV 重建都用得上），但它**不足以**
    支撑"跳过已完成"这个判据：读不全就等于不知道哪些查过了，继续联网必然重烧配额。
    超长**单行**只毒它自己那一行，其余行照常读完，故不置该标志。
    """
    if not isinstance(path, (str, Path)):
        return LedgerScan([], 0)
    target = Path(path)
    records: list[dict[str, Any]] = []
    bad_lines = 0
    warnings: list[str] = []
    truncated = False
    consumed = 0
    try:
        with open(target, "rb") as handle:
            for raw_line, overlong, raw_len in _iter_ledger_lines(handle):
                consumed += raw_len
                if consumed > MAX_LEDGER_BYTES:
                    warnings.append(
                        f"账本超过读取上限 {MAX_LEDGER_BYTES} 字节，其余未读入"
                        "（续跑判据不完整，本轮可能重查部分已完成来源）"
                    )
                    truncated = True
                    break
                if overlong:
                    bad_lines += 1
                    warnings.append(f"账本存在超过 {MAX_LEDGER_LINE_BYTES} 字节的单行，已跳过")
                    continue
                if len(records) >= MAX_LEDGER_RECORDS:
                    warnings.append(
                        f"账本记录数超过上限 {MAX_LEDGER_RECORDS}，其余未读入"
                        "（续跑判据不完整，本轮可能重查部分已完成来源）"
                    )
                    truncated = True
                    break
                try:
                    text = raw_line.decode("utf-8")
                except UnicodeDecodeError:
                    # 只毒这一行：整份 decode 失败曾导致"已完成记录全部失忆 + 重烧配额"。
                    bad_lines += 1
                    logger.debug("批量富化账本存在非 UTF-8 行，已跳过")
                    continue
                stripped = text.strip()
                if not stripped:
                    continue
                try:
                    record = json.loads(
                        stripped,
                        parse_constant=reject_nonfinite_json_constant,
                        parse_float=parse_finite_json_float,
                    )
                except (ValueError, TypeError):
                    bad_lines += 1
                    logger.debug("批量富化账本存在坏行，已跳过")
                    continue
                if not isinstance(record, dict):
                    bad_lines += 1
                    continue
                records.append(record)
    except FileNotFoundError:
        # ★账本不存在 = **首轮**，不是"读不全"：这里置 resume_incomplete 会让每一次全新运行
        #   都被 fail-closed 拦下（没有任何已完成记录可丢，也就没有重烧配额的风险）。
        logger.debug("批量富化账本尚不存在：%s", target)
        return LedgerScan([], bad_lines, tuple(dict.fromkeys(warnings)))
    except OSError:
        # ★账本**存在**但读到一半 IO 失败：已读回的记录只是个前缀，后半段完成记录不可见，
        #   继续联网就会重查那部分（花配额），故这一支置 resume_incomplete。
        logger.debug("批量富化账本读取失败：%s", target, exc_info=True)
        warnings.append(
            "账本读取中途失败（IO 错误），其余未读入"
            "（续跑判据不完整，本轮可能重查部分已完成来源）"
        )
        return LedgerScan(records, bad_lines, tuple(dict.fromkeys(warnings)), True)
    # 同一条上限只报一次，且顺序稳定（超长行可能触发多次）。
    deduped = tuple(dict.fromkeys(warnings))
    return LedgerScan(records, bad_lines, deduped, truncated)


def read_ledger_records(path: object) -> tuple[list[dict[str, Any]], int]:
    """容错读取 NDJSON，返回（有效记录，坏行数）。有界读取见 :func:`scan_ledger`。"""
    scan = scan_ledger(path)
    return scan.records, scan.bad_lines


def completed_from_records(
    records: Sequence[Mapping[str, Any]],
) -> dict[str, set[str]]:
    """把账本记录压成已完成的 ``target → providers``。

    与 :func:`read_ledger` 分开，是为了让调用方能**只读一次**账本就同时拿到续跑判据与
    :attr:`LedgerScan.limit_warnings`——否则想看告警就得再扫一遍文件。
    """
    done: dict[str, set[str]] = {}
    for record in records:
        value = record.get(LEDGER_KEY)
        statuses = record.get("source_status")
        if not isinstance(value, str) or not value or not isinstance(statuses, Mapping):
            continue
        completed = {
            str(provider)
            for provider, status in statuses.items()
            if source_status_value(status) in LEDGER_COMPLETE_STATUSES
        }
        if completed:
            done.setdefault(value, set()).update(completed)
    return done


def read_ledger(path: object) -> dict[str, set[str]]:
    """读回 NDJSON 中已完成的 ``target → providers``（续跑用）。

    只有 ``hit`` / ``no_record`` 是终态；``failed`` / ``disabled`` / ``skipped`` 仍应在
    后续重试。多行同一目标按 provider 取并集，支持补 key 后只查询新增来源。

    容错：文件不存在 / 坏行 / 非 UTF-8 行 / 非 dict / 缺 ``target`` 或状态一律跳过。
    **绝不抛**——账本损坏最坏结果是重查一次（花配额），不能让它中断整轮富化。

    想同时拿到 :attr:`LedgerScan.limit_warnings` 的调用方请直接用 :func:`scan_ledger`
    ＋ :func:`completed_from_records`，避免为了看告警把账本扫两遍。
    """
    return completed_from_records(scan_ledger(path).records)


def pending_enrichers(
    target: Target,
    enrichers: Sequence[object],
    env: Mapping[str, str],
    completed: Mapping[str, set[str]] | None = None,
) -> list[object]:
    """返回该目标当前**确实需要查询**的被动源。

    不适用、未配置、账本已完成的 provider 都排除。因而补一个新 key 后，它会自动成为待补源；
    已成功的其它付费源不会被重复查询。
    """
    done = (completed or {}).get(target.value, set())
    return [
        enricher
        for enricher in enrichers
        if target.kind in (getattr(enricher, "applies_to", []) or [])
        and _is_configured(enricher, env)
        and _provider_name(enricher) not in done
    ]


def _status_map(endpoint: Endpoint) -> dict[str, dict[str, Any]]:
    """Return the canonical provider outcome map for a new ledger event."""

    return normalize_source_status_map(endpoint.enrichment.get("source_status"))


def _provider_payloads(endpoint: Endpoint) -> dict[str, Any]:
    """端点上各 provider 的归一化数据（剔掉 ``source_status`` 这类调度元数据）。"""
    return {
        key: value
        for key, value in endpoint.enrichment.items()
        if key != "source_status" and isinstance(key, str)
    }


def enrich_targets(
    targets: Sequence[Target],
    enrichers: Sequence[object],
    *,
    mode: str = ANALYSIS_MODE_PASSIVE,
    env: Mapping[str, str] | None = None,
    completed: Mapping[str, set[str]] | None = None,
) -> list[dict[str, Any]]:
    """逐目标跑富化，返回每目标一条明细记录。

    ``include_case_close=True``：批量富化本质就是"有界目标集上的结案式查询"，不开这个开关
    则 FOFA / Quake / AbuseIPDB 这些 ``case_close_only`` 源根本不会跑，批量入口也就失去意义。

    逐目标（而非一次传全部）调度：单个目标炸掉不连坐其余目标，且明细可以边跑边落盘（续跑）。
    """
    from apkscan.core.enrichment import enrich_selected_targets

    records: list[dict[str, Any]] = []
    configured_env = env or {}
    for target in targets:
        typed = [
            enricher
            for enricher in pending_enrichers(target, enrichers, configured_env, completed)
            if hasattr(enricher, "enrich")
        ]
        if not typed:
            continue
        endpoint = Endpoint(value=target.value, kind=target.kind, is_suspicious=True)
        try:
            enrich_selected_targets(
                [endpoint],
                typed,  # type: ignore[arg-type]
                mode=mode,
                include_case_close=True,
            )
        except Exception:  # noqa: BLE001 — 单目标失败不得中断整轮；如实记 error 供复查
            logger.exception("批量富化目标 %s 失败", target.kind)
            failed_status = {
                _provider_name(enricher): {
                    "status": "failed",
                    "error_type": "enrich_failed",
                }
                for enricher in sorted(typed, key=_provider_name)
            }
            records.append(
                {
                    LEDGER_KEY: target.value,
                    "kind": target.kind,
                    "source_status": failed_status,
                    "enrichment": {},
                    "error": "enrich_failed",
                }
            )
            continue
        records.append(
            {
                LEDGER_KEY: target.value,
                "kind": target.kind,
                "source_status": _status_map(endpoint),
                "enrichment": _provider_payloads(endpoint),
            }
        )
    return records


def csv_columns(records: Sequence[Mapping[str, Any]]) -> list[str]:
    """CSV 列 = ``target,kind`` + 出现过的 provider（字典序，输出确定）。"""
    providers: set[str] = set()
    for record in records:
        statuses = record.get("source_status")
        if isinstance(statuses, Mapping):
            providers.update(str(key) for key in statuses)
        enrichment = record.get("enrichment")
        if isinstance(enrichment, Mapping):
            providers.update(str(key) for key in enrichment)
    return [*BASE_COLUMNS, *sorted(providers)]


def records_to_csv_rows(records: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    """把明细记录压成“每源一列”的表格行。

    provider 单元格是稳定 JSON：``{"status": ..., "data": ...}``。这样既保留调度状态，也真正
    回灌归一化富化响应；只写 ``hit`` 会让 CSV 对人工表格没有任何信息价值。

    ★所有单元格过 ``_csv_safe``：``target`` 来自用户清单、provider 数据来自外部响应，
    未转义的 ``=``/``+``/``-``/``@`` 开头值在 Excel/WPS 里会被当公式执行。
    """
    # NDJSON 是 append-only 事件账本；补 key/失败重试会让同一 target 出现多行。
    # CSV 是“当前快照”，必须按 target 合并为一行，provider 采用最后一次记录。
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        target = record.get(LEDGER_KEY)
        kind = record.get("kind")
        if not isinstance(target, str) or not target:
            continue
        key = (target, str(kind or ""))
        current = merged.setdefault(
            key,
            {LEDGER_KEY: target, "kind": kind, "source_status": {}, "enrichment": {}},
        )
        incoming_status = record.get("source_status")
        status_now = incoming_status if isinstance(incoming_status, Mapping) else {}
        incoming_payload = record.get("enrichment")
        payload_now = incoming_payload if isinstance(incoming_payload, Mapping) else {}
        # ★status 与 data 必须**成对**取最后一次事件。分别 ``update`` 是错的：``--no-resume``
        #   重查把 hit 覆盖成 no_record 时，旧 payload 因为本次事件里压根没有该键而留存，
        #   CSV 单元格就成了「查无记录、却带着上一次的数据」——人工照它写进线索清单
        #   等于伪造证据。故本次事件提到的 provider 一律**整格替换**：本次没带 payload
        #   （no_record / failed / 无归一化响应）就把旧 payload 一并清掉。
        #   本次没提到的 provider 保持原样（补 key 后只跑缺失源，不能把已完成的源抹掉）。
        for provider in sorted({*status_now, *payload_now}, key=str):
            name = str(provider)
            if provider in status_now:
                current["source_status"][name] = status_now[provider]
            else:
                current["source_status"].pop(name, None)
            if provider in payload_now:
                current["enrichment"][name] = payload_now[provider]
            else:
                current["enrichment"].pop(name, None)

    snapshots = list(merged.values())
    columns = csv_columns(snapshots)
    rows: list[dict[str, str]] = []
    for record in snapshots:
        statuses = record.get("source_status")
        status_map = statuses if isinstance(statuses, Mapping) else {}
        enrichment = record.get("enrichment")
        payload_map = enrichment if isinstance(enrichment, Mapping) else {}
        row = {
            "target": _csv_safe(record.get(LEDGER_KEY)),
            "kind": _csv_safe(record.get("kind")),
        }
        for column in columns[len(BASE_COLUMNS) :]:
            status = status_map.get(column)
            payload = payload_map.get(column)
            if status is None and payload is None:
                cell = ""
            else:
                canonical = normalize_source_status(status)
                try:
                    cell = json.dumps(
                        {**canonical, "data": payload},
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    )
                except (TypeError, ValueError):
                    # A provider-owned cyclic/non-finite payload must never make
                    # the CSV contain non-standard JSON or abort the whole batch.
                    cell = json.dumps(
                        {
                            "status": "failed",
                            "error_type": "invalid_payload",
                            "reason": "provider payload is not strict JSON",
                            "data": None,
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    )
            row[column] = _csv_safe(cell)
        rows.append(row)
    return rows
