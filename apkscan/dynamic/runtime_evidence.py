"""apkscan.dynamic.runtime_evidence — 运行时归因判定的**唯一**真源。

"这个远端属不属于目标 App" 这条判据此前在两个模块各写了一份：``pcap_ingest`` 的
``_endpoint_source`` / ``_aggregate_source``，与 ``capture`` 里手写的等价量词，
靠注释"两边保持一致"同步。历史上已经因此出过两次事故——一边改了聚合量词、另一边不动，
同一份 pcap 经不同路径得到相反的 observed-contact 结论。本模块把判据收敛成一处，
两边都消费它，那条漂移通道就不存在了。

★**三态不可塌缩**，这是整块设计的地基：

- 归因表 ``None`` = 本轮**没执行过**归因（没给 socket 快照）；
- 归因表 ``{}`` = **执行过、但这份采集没有可归因的远端**（例如纯 DNS 采集）；
- 表非空但某个键不在表内 = 该端点**没拿到结论**（信息缺失）。

前两者都不是"判定不属于目标"。把缺信息写成否定，就会把真后端当背景噪音丢掉。

★**run 级与对象级是两个层次，禁止用同一个判据服务两者**：``{}`` 在 run 级是"执行过"
（:func:`attribution_ran` 为真），但对每一个具体端点都是"没拿到结论"。曾经把两者混判，
结果空表那一轮把已确证判否的端点又升回了"已确认接触"。

★``DENIED`` 的口径是"**在表内且 ``is_target_app`` 不为 True**"，
明确**包含** ``ambiguous`` / ``unattributed``（它们的 ``is_target_app`` 是 ``None``）。
写成"全部明确为 False 才算否定"会让这两类退回保留 contact，等于把过度断言放回来。
"""

from collections.abc import Iterable
from enum import Enum


__all__ = [
    "AttributionVerdict",
    "attribution_ran",
    "verdict_for_endpoint",
    "verdict_for_carriers",
    "is_denied",
]


class AttributionVerdict(str, Enum):
    """运行时证据对目标 App 归属的四态判定。"""

    NOT_RUN = "not_run"
    UNKNOWN_OR_PARTIAL = "unknown_or_partial"
    TARGET = "target"
    DENIED = "denied"


def attribution_ran(app_attr: dict[str, dict] | None) -> bool:
    """判断本轮是否执行过归因。

    空字典代表归因流程已经运行，只是没有发现可归因的远端；只有
    ``None`` 才代表本轮根本没有拿到归因快照。这里不能使用 ``bool``，
    否则会把“已运行但无结果”和“尚未运行”错误地合并。
    """
    if app_attr is None:
        return False

    # 类型标注约束正常调用者，但运行时仍防御异常输入，避免分析流程因
    # 外部数据形状错误而中断。非字典不具备归因表的语义，因此不视为已运行。
    return isinstance(app_attr, dict)


def _lookup(
    app_attr: dict[str, dict],
    key: str,
) -> dict | None:
    """安全读取归因记录，避免异常映射对象破坏取证流程。"""
    try:
        hit = app_attr.get(key)
    except Exception:
        # 公开 API 要求对异常输入不抛错；读取失败只能按缺信息处理。
        return None

    return hit if isinstance(hit, dict) else None


def _record_is_target(hit: dict) -> bool | None:
    """读取记录中的目标标志。

    - ``True``：明确属于目标（``is_target_app is True``）；
    - ``False``：**字段缺失、或值不是 True**（含 ``False`` / ``None``，即
      ambiguous / unattributed）——按模块头的口径它们都归 ``DENIED``；
    - ``None``：**仅**表示读取过程本身抛异常，不是一种判定结果。

    ★"字段缺失算 False"是有意的，与模块头声明的 ``DENIED := 在表内且 is_target_app 不为 True``
      一致：记录既然进了归因表，就是"问过了"，缺字段不该退回成"没问过"。
    """
    try:
        return hit.get("is_target_app") is True
    except Exception:
        return None


def verdict_for_endpoint(
    app_attr: dict[str, dict] | None,
    proto: str,
    ip: str,
    port: object,
) -> AttributionVerdict:
    """返回单个远端端点的归因判定。

    端点使用与归因表相同的裸键格式；这里保留端点级粒度，因为空表只
    能说明归因流程运行过，不能说明任意具体端点已经被判定。

    ★``port`` 标注为 ``object`` 而非 ``int``：调用方（``RemoteEndpoint.port`` 等）
      的字段类型本就是宽松的，而下面的 ``isinstance`` 防御若在类型层面不可达，
      就成了永远跑不到的死代码——那等于把"绝不抛异常"的承诺架空。
      宽签名让防御真正生效，代价只是调用处少一层静态检查。
    """
    if app_attr is None:
        return AttributionVerdict.NOT_RUN

    if not isinstance(app_attr, dict):
        return AttributionVerdict.UNKNOWN_OR_PARTIAL

    # bool 虽然是 int 的子类，但不可能是合法端口；拒绝它可避免异常输入
    # 生成一个看似合法、实际没有取证意义的键。
    if (
        not isinstance(proto, str)
        or not isinstance(ip, str)
        or not isinstance(port, int)
        or isinstance(port, bool)
    ):
        return AttributionVerdict.UNKNOWN_OR_PARTIAL

    try:
        if not app_attr:
            return AttributionVerdict.UNKNOWN_OR_PARTIAL
        key = f"{proto}/{ip}:{port}"
    except Exception:
        return AttributionVerdict.UNKNOWN_OR_PARTIAL

    hit = _lookup(app_attr, key)
    if hit is None:
        # 表为空或键不存在都不能推出“不是目标”；前者尤其容易被误当成
        # 已确认否定，正是三态语义中需要单独保留的边界。
        return AttributionVerdict.UNKNOWN_OR_PARTIAL

    target = _record_is_target(hit)
    if target is None:
        return AttributionVerdict.UNKNOWN_OR_PARTIAL
    if target:
        return AttributionVerdict.TARGET
    return AttributionVerdict.DENIED


def verdict_for_carriers(
    app_attr: dict[str, dict] | None,
    carriers: Iterable[str],
) -> AttributionVerdict:
    """返回一组承载端点的聚合归因判定。

    聚合遵循保守量词：所有承载端点都必须已知，且至少一个端点属于
    目标 App 才能得到 TARGET；只要有一个端点缺失，就不能用其余端点
    的否定结果覆盖信息缺口。
    """
    if app_attr is None:
        return AttributionVerdict.NOT_RUN

    if not isinstance(app_attr, dict):
        return AttributionVerdict.UNKNOWN_OR_PARTIAL

    try:
        carrier_list = list(carriers)
    except Exception:
        return AttributionVerdict.UNKNOWN_OR_PARTIAL

    # 空承载集合没有可供量词求值的对象。它不是“全都已归因且否定”，
    # 否则会把没有证据错误降级为 DENIED。
    if not carrier_list:
        return AttributionVerdict.UNKNOWN_OR_PARTIAL

    # 先验证整个集合，而不是边遍历边返回 TARGET。集合中任何非字符串
    # 都意味着调用方提供的对象不完整，必须保留 UNKNOWN_OR_PARTIAL。
    if any(not isinstance(carrier, str) for carrier in carrier_list):
        return AttributionVerdict.UNKNOWN_OR_PARTIAL

    try:
        if not app_attr:
            return AttributionVerdict.UNKNOWN_OR_PARTIAL

        hits: list[dict] = []
        for carrier in carrier_list:
            hit = _lookup(app_attr, carrier)
            if hit is None:
                return AttributionVerdict.UNKNOWN_OR_PARTIAL
            hits.append(hit)
    except Exception:
        return AttributionVerdict.UNKNOWN_OR_PARTIAL

    # 缺失判断必须先于 TARGET 判断：一个已命中的承载端点不能掩盖
    # 另一个未归因端点，这与原有聚合逻辑的保守语义保持一致。
    for hit in hits:
        target = _record_is_target(hit)
        if target is None:
            return AttributionVerdict.UNKNOWN_OR_PARTIAL

    if any(_record_is_target(hit) is True for hit in hits):
        return AttributionVerdict.TARGET

    return AttributionVerdict.DENIED


def is_denied(verdict: AttributionVerdict) -> bool:
    """判断判定是否为明确否定。"""
    return verdict is AttributionVerdict.DENIED