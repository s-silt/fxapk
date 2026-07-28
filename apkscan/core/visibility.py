"""证据可见性求值：这份报告**看到了什么、没看到什么**，因而哪些「未发现」不可解读为「不存在」。

## 为什么需要这一层

各分析器已经各自记录了自己的可见性事实——``dex_available``（DEX 能否解析）、``is_hardened`` /
``hardening_structural``（加壳）、``dex_string_pool``（字符串池不透明度）、``native_obfuscation``
（原生层混淆）、``artifact_lineage``（脱壳结果是否已回灌）——但**没有任何下游消费它们**。
于是一份「壳桩样本」的报告会平静地写着「未发现网络端点」，读的人（尤其是 AI）无从知道那是
「扫过了确实没有」还是「压根看不见」。

本模块把这些散落事实归一成一个可消费的视图，回答一个问题：
**基于本次实际看到的输入，哪些结论有资格下、哪些没有。**

## 三条设计纪律

1. **不重载 ``analysis_status`` / ``completeness``**。那两个字段的既定语义是「分析器执行健康度」
   （成功数 ÷ 成功+报错数），``--strict`` 的退出码依赖它。样本加固是**样本**的属性，不是
   工具跑挂了；混进去会让正常跑完的加固样本表现成「分析失败」，并冲击既有指标基线。
   可见性是**正交的第三个维度**。

2. **落到「主张」而非「分析器」**。``endpoints`` 同时扫 DEX、manifest、资源、native——DEX 不可见时
   不能把它的全部产出标成不可信：manifest 里声明的域名照样可用，运行时 pcap 实测的连接照样是硬证据。
   不可下的只是「端点已穷尽」这类**需要完整可见性**的主张。

3. **只标注，不封顶**。本模块不改 closure、不改退出码，只提供求值结果；由消费方按自己的主张
   相关性决定要不要被某条 blocker 影响。全局一刀切封顶会把真实可办案的动态证据一起降级掉。

纯函数、可离线、绝不联网、绝不抛。
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# --- 来源可见性取值 -------------------------------------------------------
VIS_COMPLETE = "complete"        # 该来源完整可见
VIS_PARTIAL = "partial"          # 可见但有截断/部分不可读
VIS_STUB_ONLY = "stub_only"      # 只看得到壳桩，真实内容被加密/隐藏
VIS_OPAQUE = "opaque"            # 可读到字节，但内容被混淆/加密（如字符串池不透明）
VIS_UNAVAILABLE = "unavailable"  # 完全不可见（解析失败 / 缺失）
VIS_UNKNOWN = "unknown"          # 无从判断

#: 补救状态：脱壳这类动作**做成功**与**结果已成为当前报告的输入**是两回事，必须分开。
REM_NOT_ATTEMPTED = "not_attempted"
REM_FAILED = "failed"
REM_REANALYZED = "reanalyzed_with_extra_dex"

#: 需要「该来源完整可见」才有资格下的主张 → 依赖的来源。
#: ★只列**穷尽性/否定性**主张。肯定性主张（"发现了 X"）不受可见性影响——看见了就是看见了。
_CLAIM_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "static_endpoint_exhaustive": ("dex", "native", "resource"),
    "no_contact_harvesting": ("dex",),
    "no_sms_interception": ("dex",),
    "no_remote_config": ("dex", "resource"),
    "config_chain_complete": ("dex", "resource"),
    "no_hardcoded_credential": ("dex", "native", "resource"),
    # ★动态独有：静态再完整也证不了「跑起来到底连了谁」。加固样本尤其如此——真实后端往往
    #   只在运行时由配置下发，静态里根本不存在。没做运行时观测就下这个结论是空口。
    "runtime_contact_observed": ("runtime",),
}

#: 主张的人读名（进报告/digest 给人看）。
_CLAIM_LABELS: dict[str, str] = {
    "static_endpoint_exhaustive": "静态端点已穷尽",
    "no_contact_harvesting": "未发现通讯录窃取",
    "no_sms_interception": "未发现短信拦截/转发",
    "no_remote_config": "未发现远程配置下发",
    "config_chain_complete": "配置链已追全",
    "no_hardcoded_credential": "未发现硬编码凭据",
    "runtime_contact_observed": "已掌握运行时实连去向",
}

#: 视为「不足以支撑穷尽性主张」的可见性取值。
#: ★``partial``（扫描被截断）也在内：本表里的主张**全部是穷尽性/否定性**的，"扫了一半"支撑不了
#: "已穷尽"。这条最容易被放过——分析器跑成功、状态全绿，只是没扫完。
_INSUFFICIENT = frozenset({VIS_PARTIAL, VIS_STUB_ONLY, VIS_OPAQUE, VIS_UNAVAILABLE})
#: 公开别名：closure 判断「这一维是不是**确证盲区**」时用同一份定义，别各写各的。
INSUFFICIENT = _INSUFFICIENT


def _meta(report: Any) -> dict:
    if not isinstance(report, dict):
        return {}
    m = report.get("meta")
    return m if isinstance(m, dict) else {}


def _dex_visibility(meta: dict) -> tuple[str, list[str]]:
    """DEX 层可见性 + 判定依据。

    ★``packed`` 为空**不等于**未加固：结构性判据（stub-dex 等）命中时 ``packed`` 仍是 None 而
    ``is_hardened`` 为 True——以 ``packed`` 是否有值来判加固会漏掉全部未识别厂商的壳。
    """
    why: list[str] = []
    if meta.get("dex_available") is False:
        why.append("DEX 解析失败（dex_available=False）")
        return VIS_UNAVAILABLE, why

    structural = meta.get("hardening_structural")
    if isinstance(structural, dict) and structural.get("reason"):
        why.append(f"结构判据命中加固：{structural.get('reason')}")
        return VIS_STUB_ONLY, why
    if meta.get("is_hardened"):
        why.append(f"加固判定 is_hardened=True（厂商：{meta.get('packed') or '未识别'}）")
        return VIS_STUB_ONLY, why

    pool = meta.get("dex_string_pool")
    if isinstance(pool, dict) and pool.get("suspicious"):
        why.append("字符串池不透明度超阈（编译期字符串混淆）")
        return VIS_OPAQUE, why

    # ★脱壳产物没全并进来，同样是 DEX 面的缺口，而且极易被读成"已完整分析"：
    #   实测两个样本各 dump 33 个 DEX，androguard 因不认 Android 10+ 的 hidden-api flag
    #   各只解析成功 10 个，而控制台写的是"33 个并入静态分析"、分析器状态 error=0。
    #   ——先于截断判定，因为"两成输入没进来"比"字符串扫到一半"缺得更多。
    extra = meta.get("extra_dex_visibility")
    if isinstance(extra, dict) and int(extra.get("failed") or 0) > 0:
        by_error = extra.get("failures_by_error")
        kinds = (
            "，".join(f"{k}×{v}" for k, v in list(by_error.items())[:3])
            if isinstance(by_error, dict) and by_error
            else ""
        )
        why.append(
            f"额外 DEX 请求 {extra.get('requested')} 个、仅并入 {extra.get('loaded')} 个，"
            f"{extra.get('failed')} 个解析失败（{kinds}）——脱壳产物未全部进入分析"
        )
        return VIS_PARTIAL, why

    # ★扫描截断同样是可见性缺口，而且最隐蔽：分析器"跑成功了"、状态一切正常，只是没扫完。
    #   实测一个 100MB 样本的 DEX 字符串超过 20 万条上限被截断——此时"未发现某接口"完全可能
    #   只是因为它排在截断线之后。上限本身是必要的（防内存爆），但截断的**事实**必须传下去。
    if meta.get("dex_strings_truncated"):
        by = meta.get("dex_strings_truncated_by")
        who = f"（{', '.join(str(x) for x in by[:6])}）" if isinstance(by, list) and by else ""
        why.append(f"DEX 字符串数超上限被截断，后段未扫（分析器成功但未扫全）{who}")
        return VIS_PARTIAL, why
    if meta.get("dex_scanned") is False:
        why.append("DEX 未被扫描（dex_scanned=False）")
        return VIS_UNAVAILABLE, why
    return VIS_COMPLETE, why


def _native_visibility(meta: dict) -> tuple[str, list[str]]:
    """native 层可见性。

    ★``meta["native_obfuscation"]`` 是 **list**（``native_obfuscation`` 分析器写的疑似库明细，
      无命中时为空列表），不是 dict。此前这里判的是 ``isinstance(obf, dict)`` 并从中取
      ``suspected``/``libraries`` 键——那个分支在生产里一次都没成立过，于是装着 5 个虚拟化
      .so 的样本照样读作 native 完整可见。分析器辛苦标出来的疑似库，下游没人接。
    """
    obf = meta.get("native_obfuscation")
    if isinstance(obf, list):
        if obf:
            return VIS_OPAQUE, [f"{len(obf)} 个 .so 疑加密/虚拟化，其中字符串不可读"]
        return VIS_COMPLETE, []
    if isinstance(obf, dict):
        # 兼容曾出现过的 dict 形态（旧报告 / 手编）：取任一已知明细键。
        libs = obf.get("suspected") or obf.get("libraries") or []
        if libs:
            return VIS_OPAQUE, [f"{len(libs)} 个 .so 疑加密/虚拟化，其中字符串不可读"]
        return VIS_COMPLETE, []
    return VIS_COMPLETE, []


def _attribution_caveat(meta: dict) -> list[str]:
    """归属层的告警：本样本的端点/域名到底归不归得到嫌疑方。

    ★这不是"可见性"问题而是"归属"问题，但后果同样是方向性的，且同样此前无人消费：
    正版应用被重打包时，它的接口与域名属于**被仿冒的正版厂商**，照单列进调证清单会向无关企业
    发函。仅凭样本自身只能确定"被重签名"，确定注入物必须与官方同版本包做差分。
    """
    notes: list[str] = []
    rid = meta.get("repack_identity")
    if not isinstance(rid, dict):
        return notes
    verdict = rid.get("verdict")
    if verdict == "repack_suspected":
        notes.append(
            "⚠ 疑似正版应用重打包：本样本的接口/域名可能属于被仿冒的正版厂商，"
            "作为调证线索前须与官方同版本包差分核实（仅凭样本自身只能确定被重签名）"
        )
        return notes

    # ★判不出重打包 ≠ 排除重打包。调试证书在场时尤其要提醒：它只证"非原厂正式发布签名"，
    #   自研批量打包与第三方 apktool 重签正版都会留下它；再叠加 v2/v3-only 包没有签名别名
    #   （别名只能从 v1 签名块的文件名取），判据这时候是**结构性缺失**而非"查过没有"。
    #   此前这两种 verdict 下归属告警完全缺席，报告里没有任何东西把人往差分核实上拉。
    signature = rid.get("signature")
    has_debug = isinstance(signature, dict) and bool(signature.get("debug_cert"))
    if has_debug and verdict in ("self_built", "unknown"):
        notes.append(
            "⚠ 本样本以调试证书签名：该特征对「自研批量打包」与「第三方重签正版应用」同样常见，"
            "不指示归属方向；若样本外观与某正版应用相似，作为调证线索前须与官方同版本包差分核实"
        )
    return notes


def _resource_visibility(meta: dict) -> tuple[str, list[str]]:
    """资源层（assets/res 里的配置、JS、加密配置文件）看到了多少。

    ★此前这一维是**硬编码 unknown**，注释写着"没有信号不等于已确认完整"，
      但资格判定只拦 ``_INSUFFICIENT``、不拦 unknown——于是「从未评估过资源面」
      照样能签发「静态端点已穷尽」「未发现远程配置」。本域最典型的手法之一正是
      把接口藏在加密资源里，那恰恰是这一维该说话的地方。

    判据按保守优先级排：确证不可读 > 部分不可读 > 扫过了 > 没信号。

    ★"扫过了"必须是"全扫过了"。此前只看成功计数 ``resource_files_scanned > 0``，于是
      「命中 100 个资源目标、99 个因坏 CRC 读不出、只读成 1 个」与「100 个全读成」在数据上
      完全一样，都判 complete。畸形 zip 条目是本域在用的反分析手法，不是偶发噪声——把被
      跳读的那个 assets 当成"看过了"，正是"未发现"被读成"已穷尽"。
    """
    why: list[str] = []
    if meta.get("uni_encrypted"):
        why.append("uni-app 代码加密（confusion）：业务 JS 与接口在资源层不可读")
        return VIS_OPAQUE, why
    # ★列举整体失败是**本次实测到的故障**，不是"没做这一维"：必须落进 _INSUFFICIENT 档去
    #   封顶，而不是混进 unknown 那条专供旧报告/未评估的豁免通道。
    if meta.get("resource_listing_failed"):
        return VIS_UNAVAILABLE, ["资源列举失败：本次分析未能枚举包内资源，该层完全未看"]
    recipe = meta.get("crypto_recipe")
    if isinstance(recipe, dict) and recipe:
        why.append("资源层存在已识别的加密配置文件；在解密并入之前该部分不可读")
        return VIS_PARTIAL, why
    read_failed = meta.get("resource_files_read_failed")
    if isinstance(read_failed, int) and read_failed > 0:
        why.append(
            f"{read_failed} 个文本资源命中扫描目标却读取失败（坏 CRC / 畸形条目 / 超尺寸），"
            "其内容未进入本次分析"
        )
        return VIS_PARTIAL, why
    scanned = meta.get("resource_files_scanned")
    if isinstance(scanned, int) and scanned > 0:
        # 措辞只认领**文本**资源：二进制资产（图片/字体/so 之外的 blob）本就不在文本扫描面内，
        # 说成"资源层完整可见"会把没扫的那部分也算进已穷尽。
        why.append(f"文本资源文件已扫描 {scanned} 个（二进制资产不在文本扫描面内）")
        return VIS_COMPLETE, why
    return VIS_UNKNOWN, ["资源层无扫描信号（旧报告，或资源扫描未运行）"]


def _runtime_visibility(meta: dict) -> tuple[str, list[str]]:
    """运行时观测这条路走到哪一步 —— 它是静态盲区的**独立补救渠道**。

    ★为什么要单列这一维：静态看不见时，唯一还能拿到真实后端的路子就是运行时观测（字符串在
    被使用的那一刻必然以明文存在于内存、连接必然出现在网络上）。若不记录"动态跑了没有、
    拿到了什么"，一份壳桩样本的报告只会说"静态瞎了"，读的人无从判断**这个缺口补没补**。

    与 DEX/native 那两维不同，这里 ``unavailable`` 不代表出错，而是"这条路没走"——
    纯静态分析本就没有运行时证据，那是选择不是故障。
    """
    why: list[str] = []
    if not (meta.get("runtime_merged") or meta.get("capture_quality") or meta.get("capture_signals")):
        return VIS_UNAVAILABLE, ["未做运行时观测（纯静态分析）"]

    quality = meta.get("capture_quality")
    if isinstance(quality, dict):
        status = str(quality.get("dynamic_status") or "")
        if status == "complete":
            why.append("运行时采集完整且有目标归因的业务候选")
            return VIS_COMPLETE, why
        if status:
            why.append(f"运行时采集质量：{status}（{quality.get('reason') or '无说明'}）")
            return VIS_PARTIAL, why
    why.append("已并入运行时数据，但采集质量未评估")
    return VIS_PARTIAL, why


def _remediation(meta: dict) -> tuple[str, list[str]]:
    """脱壳补救到了哪一步。

    ★区分「脱壳成功」与「脱壳结果已成为当前报告的输入」：前者只说 DEX dump 出来了，后者才说明
    这份报告看到了那些 DEX。二者混同时，「步骤显示脱壳成功、报告却还是壳桩」从数据上看不出来。
    """
    lineage = meta.get("artifact_lineage")
    if isinstance(lineage, dict) and lineage.get("active_input") == "unpacked":
        n = lineage.get("unpacked_dex_count") or 0
        return REM_REANALYZED, [f"脱壳回灌已生效（{n} 个 DEX 进入本次分析）"]
    if meta.get("unpacked"):
        return REM_REANALYZED, ["报告自身即脱壳回灌产物"]
    return REM_NOT_ATTEMPTED, []


def _next_actions(sources: dict, remediation: str, meta: dict) -> list[str]:
    """针对每个盲区给出**可执行的**补法。

    ★只说"这里瞎了"是半截活：读的人（尤其是 AI）拿到一份 degraded 报告，需要知道下一步该做
    什么才能把缺口补上。补法按缺口类型分——静态看不见就转运行时，配置链断了就去取配置。
    """
    actions: list[str] = []
    dex = sources.get("dex", {}).get("visibility")
    runtime = sources.get("runtime", {}).get("visibility")

    if dex in (VIS_STUB_ONLY, VIS_UNAVAILABLE) and remediation != REM_REANALYZED:
        actions.append(
            "DEX 不可见且未脱壳回灌：跑 `fxapk unpack <apk>`（真机 + frida-dexdump）后重新分析——"
            "字符串在被使用时必然以明文存在于内存，这是静态看不见时唯一能拿到真实后端的路"
        )
    if dex == VIS_PARTIAL:
        actions.append("DEX 字符串被截断：调高扫描上限或分片重跑，确认截断段内无遗漏端点")
    if dex in _INSUFFICIENT and runtime == VIS_UNAVAILABLE:
        actions.append(
            "静态受限且未做运行时观测：跑 `fxapk capture <包名>` 抓包——"
            "真实后端往往只在运行时由配置下发，静态里根本不存在"
        )
    plan = meta.get("config_probe_plan")
    if isinstance(plan, dict) and plan.get("candidates"):
        actions.append(
            f"已生成 {len(plan['candidates'])} 条配置接口候选 URL（meta.config_probe_plan）："
            "确认授权后以 `--mode authorized-active` 重跑可下载解码，取回下发的域名/IP 池"
        )

    # native 控制面：地址是按算法逐日算出来的，静态端点集里本来就不会有它。
    # 缺运行时输入时这条是**最有价值的补法**——比继续挖静态划算得多。
    channel = meta.get("native_config_channel")
    if isinstance(channel, dict) and channel.get("templates"):
        missing = channel.get("missing_inputs") or []
        if missing:
            actions.append(
                f"native 侧发现控制面通道（{len(channel['templates'])} 条对象存储模板），"
                f"但当日地址算不出来：缺 {'、'.join(str(m) for m in missing)}——"
                "这些值由宿主运行时注入，须动态取或从 DEX 常量补齐"
                "（详见 meta.native_config_channel.next_actions）"
            )
        else:
            actions.append(
                "native 控制面模板与输入齐备：授权后可按算法推出当日对象地址并取回配置"
            )
    return actions


def _derive_claims(sources: dict) -> tuple[dict[str, dict], list[str]]:
    """由各源的可见性档位推出每条主张的资格。返回 ``(claims, blocked)``。

    单列出来是因为它有两个调用方：:func:`assess` 正算，以及 closure 重算后回填了源值时的
    重推——主张资格是 sources 的**派生值**，改了源不重推就会出现「dex 记着 stub_only、
    却仍宣称静态端点已穷尽」这种自相矛盾的快照。
    """
    claims: dict[str, dict] = {}
    blocked: list[str] = []
    for claim, needs in _CLAIM_REQUIREMENTS.items():
        def _vis(src: str, _s: dict = sources) -> str | None:
            info = _s.get(src)
            return info.get("visibility") if isinstance(info, dict) else None

        missing = [s for s in needs if _vis(s) in _INSUFFICIENT]
        # ★「未评估」单列，不并进 missing：两者都不足以支撑穷尽性主张，
        #   但在报告措辞与 closure 封顶决策上必须分得开——
        #   「查过、确实看不见」是本次分析的实际缺口，该封顶 partial；
        #   「这一维压根没评估」不该让整份报告为之降级（同 runtime 那条豁免）。
        #   此前 unknown 既不进 missing 也不阻断，等于被当成 complete 放行了。
        unassessed = [s for s in needs if _vis(s) == VIS_UNKNOWN]
        eligible = not missing and not unassessed
        claims[claim] = {
            "label": _CLAIM_LABELS.get(claim, claim),
            "eligible": eligible,
            "missing_sources": missing,
            "unassessed_sources": unassessed,
        }
        if not eligible:
            blocked.append(claim)
    return claims, blocked


def reassess_claims(assessment: dict) -> dict:
    """按当前 ``sources`` 重推 claims / blocked_claims / degraded，返回新的 assessment。

    供 closure 在回填了源值之后调用（见 ``closure._preserve_confirmed_gaps``）。
    ``notes`` 里的人读结论一并按新的 blocked 集重写，免得措辞与结构化字段各说各话。
    """
    sources = assessment.get("sources")
    if not isinstance(sources, dict):
        return assessment
    claims, blocked = _derive_claims(sources)
    notes = [n for n in (assessment.get("notes") or []) if not str(n).startswith("★以下结论")]
    if blocked:
        labels = "、".join(_CLAIM_LABELS.get(c, c) for c in blocked)
        notes.append(
            f"★以下结论**无资格下**（相关输入不可见）：{labels}。"
            "此处的「未发现」只说明本次没看到，不能解读为不存在。"
        )
    return {
        **assessment,
        "claims": claims,
        "blocked_claims": sorted(blocked),
        "notes": notes,
        "degraded": bool(blocked),
    }


def assess(report: Any) -> dict[str, Any]:
    """求值一份报告的证据可见性与主张资格。绝不抛；坏输入 → 全 unknown 的保守结果。

    Returns:
        ``{"sources": {...}, "claims": {...}, "blocked_claims": [...], "remediation": ...,
        "notes": [...], "degraded": bool}``
    """
    try:
        meta = _meta(report)
        dex_vis, dex_why = _dex_visibility(meta)
        nat_vis, nat_why = _native_visibility(meta)
        rem, rem_why = _remediation(meta)

        # 脱壳回灌已生效 → DEX 重新可见（此时的 is_hardened 描述的是**原包**，不是当前输入）
        if rem == REM_REANALYZED and dex_vis == VIS_STUB_ONLY:
            dex_vis = VIS_COMPLETE
            dex_why.append("★上述加固结论属被取代的原包；当前输入为脱壳回灌产物")

        rt_vis, rt_why = _runtime_visibility(meta)
        res_vis, res_why = _resource_visibility(meta)
        sources = {
            "dex": {"visibility": dex_vis, "why": dex_why},
            "native": {"visibility": nat_vis, "why": nat_why},
            "resource": {"visibility": res_vis, "why": res_why},
            "runtime": {"visibility": rt_vis, "why": rt_why},
        }

        claims, blocked = _derive_claims(sources)

        notes: list[str] = []
        for src, info in sources.items():
            for w in info["why"]:
                notes.append(f"[{src}] {w}")
        notes.extend(rem_why)
        notes.extend(_attribution_caveat(meta))
        next_actions = _next_actions(sources, rem, meta)
        if blocked:
            labels = "、".join(_CLAIM_LABELS.get(c, c) for c in blocked)
            notes.append(
                f"★以下结论**无资格下**（相关输入不可见）：{labels}。"
                "此处的「未发现」只说明本次没看到，不能解读为不存在。"
            )

        return {
            "schema_version": "1.0",
            "sources": sources,
            "claims": claims,
            "blocked_claims": sorted(blocked),
            "remediation": rem,
            "notes": notes,
            "next_actions": next_actions,
            "degraded": bool(blocked),
        }
    except Exception:  # noqa: BLE001 — 求值失败不得影响主流程；返回保守的"全未知"
        logger.exception("[visibility] 可见性求值异常，返回保守结果")
        return {
            "schema_version": "1.0",
            "sources": {k: {"visibility": VIS_UNKNOWN, "why": []}
                        for k in ("dex", "native", "resource")},
            "claims": {}, "blocked_claims": sorted(_CLAIM_REQUIREMENTS),
            "remediation": REM_NOT_ATTEMPTED,
            "notes": ["可见性求值异常，全部穷尽性结论按无资格处理"],
            "next_actions": [],
            "degraded": True,
        }


def blocks_claim(assessment: Any, claim: str) -> bool:
    """某条主张是否被可见性阻断。消费方（closure/digest/preflight）用这个问，而不是自己读一堆 meta 键。

    ★这是"按主张相关性"消费的入口：与当前结论无关的 blocker 不该影响它。例如 DEX 不可见时，
    「pcap 实测连接过某 IP」照样成立——那条主张不依赖 DEX。
    """
    if not isinstance(assessment, dict):
        return False
    return claim in (assessment.get("blocked_claims") or [])


__all__ = [
    "INSUFFICIENT",
    "REM_FAILED",
    "REM_NOT_ATTEMPTED",
    "REM_REANALYZED",
    "VIS_COMPLETE",
    "VIS_OPAQUE",
    "VIS_PARTIAL",
    "VIS_STUB_ONLY",
    "VIS_UNAVAILABLE",
    "VIS_UNKNOWN",
    "assess",
    "blocks_claim",
]
