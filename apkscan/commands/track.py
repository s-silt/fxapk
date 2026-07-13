"""线索追踪台账 CLI 子命令（``track_app``）。

从 cli.py 物理拆出（纯搬移、逻辑不变）：追踪台账网页服务（track）+ 报告批量入账（ingest，含喂图谱）。
``track_app`` 由 cli.py `app.add_typer(track_app, name="track")` 挂到主 app——add_typer 留 cli.py 以
引用主 app、避免本模块反向 import cli 造成循环。
"""

from __future__ import annotations

import logging
from pathlib import Path

import typer

logger = logging.getLogger(__name__)


track_app = typer.Typer(
    add_completion=False,
    invoke_without_command=True,  # 裸 `fxapk track`（不带子命令）→ 回调里起网页
    help="线索追踪 / 办案进度：裸 track 起网页；track ingest 把历史报告回填进台账（+图谱）。",
)


@track_app.callback()
def track(
    ctx: typer.Context,
    host: str = typer.Option(
        "127.0.0.1", "--host", help="绑定地址。默认 127.0.0.1（仅本机）；0.0.0.0 暴露到局域网。"
    ),
    port: int = typer.Option(8787, "--port", help="监听端口。"),
    ledger: str = typer.Option(
        "", "--ledger", help="台账路径（默认 ~/.apkscan/tracking.json，或 FXAPK_TRACKING_DB env）。"
    ),
    no_auth: bool = typer.Option(
        False,
        "--no-auth",
        help="关闭令牌鉴权（信任封闭内网）。默认绑定到非 loopback 时自动启用令牌。",
    ),
) -> None:
    """起线索追踪 / 办案进度网页（flask）：本机或局域网查看与编辑台账。

    带子命令（如 ``track ingest``）时本回调不起网页，交由子命令处理。裸 ``track``
    才起网页。绑定到非 loopback（如 0.0.0.0）时自动生成访问令牌并强制校验（--no-auth 关闭）。
    flask 未安装时打印 ``pip install -e .[track]`` 提示并退出，不崩。
    """
    # 有子命令（ingest 等）时回调只负责注册公共选项，不起网页。
    if ctx.invoked_subcommand is not None:
        return

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        import flask  # noqa: F401  # flask 是可选 extra，缺失则优雅退出（不在顶层强依赖）
        from apkscan.track import web as _web
    except ImportError:
        typer.echo(
            "该功能未安装：flask 不可用。请安装：pip install -e .[track]", err=True
        )
        raise typer.Exit(code=1) from None

    from apkscan.track import TrackingLedger

    led = TrackingLedger(ledger or None)
    _web.serve(host=host, port=port, ledger=led, no_auth=no_auth)


@track_app.command("ingest")
def track_ingest(
    reports: list[Path] = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="历史 report.json 路径（可多个），回填进追踪台账（+案件图谱）。",
    ),
    ledger: str = typer.Option(
        "", "--ledger", help="台账路径（默认 ~/.apkscan/tracking.json，或 FXAPK_TRACKING_DB env）。"
    ),
    track_graph: bool = typer.Option(
        True,
        "--graph/--no-graph",
        help="同时喂案件图谱（kuzu 不可用时静默跳过）。默认开。",
    ),
) -> None:
    """把历史 report.json 回填进追踪台账（便于存量数据补登）+ 喂案件图谱。

    入账层 never-throw：单份报告坏 JSON / 缺 sha256 只记 warning 跳过，不中断其余报告。
    kuzu 缺失时图谱喂入静默跳过。
    """
    import json as _json

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    from apkscan.track import TrackingLedger

    led = TrackingLedger(ledger or None)
    typer.echo(f"台账：{led.path}")

    ok = 0
    failed = 0
    for rp in reports:
        try:
            raw = rp.read_text(encoding="utf-8")
            report_dict = _json.loads(raw)
        except (OSError, ValueError) as exc:
            failed += 1
            typer.echo(f"[ERR]  {rp}：读取/解析失败（{exc}）", err=True)
            continue
        if not isinstance(report_dict, dict):
            failed += 1
            typer.echo(f"[ERR]  {rp}：报告顶层非 JSON 对象，跳过", err=True)
            continue

        # 台账入账：用一个轻量 Report-like 适配器，复用 upsert_report 的合并铁律。
        if _ingest_one_report_dict(led, report_dict, str(rp)):
            ok += 1
            typer.echo(f"[OK]   {rp}")
        else:
            failed += 1
            typer.echo(f"[SKIP] {rp}（缺 sha256 或无可入账内容）", err=True)

        # 图谱喂入（best-effort，kuzu 缺失静默跳过）。
        if track_graph:
            _ingest_one_report_dict_to_graph(report_dict, str(rp))

    typer.echo(f"回填完成：入账 {ok} 份，失败/跳过 {failed} 份。")


def _ingest_one_report_dict(ledger: object, report_dict: dict, report_path: str) -> bool:
    """把一份 report.json dict 回填进台账。返回是否入账了该 APK。绝不抛。

    复用 ledger.upsert_report 的合并铁律：用一个最小 Report-like 适配器承载
    package_name / meta / leads（report.json 里 category 已是 .value 字符串，口径与
    analyze 路径一致）。
    """
    try:
        meta = report_dict.get("meta")
        if not isinstance(meta, dict):
            meta = {}
        sha = str(meta.get("sample_sha256") or "").strip()
        if not sha:
            return False

        adapter = _ReportAdapter(report_dict)
        ledger.upsert_report(adapter, report_path)  # type: ignore[attr-defined]
        # 确认该 sha 真入账了（upsert_report never-throw，可能内部跳过）。
        return sha in ledger.all().get("apks", {})  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 — 回填旁路绝不抛
        logger.warning("[track] 回填报告入账异常（已跳过）：%s", report_path, exc_info=True)
        return False


def _ingest_one_report_dict_to_graph(report_dict: dict, report_path: str) -> None:
    """把一份 report.json dict 喂进案件图谱（kuzu 缺失静默跳过）。绝不抛。"""
    try:
        from apkscan.graph import GraphStore, ingest_report

        meta = report_dict.get("meta")
        sha = str(meta.get("sample_sha256") or "") if isinstance(meta, dict) else ""
        store = GraphStore()
        try:
            ingest_report(report_dict, store, report_path=report_path, sha256=sha)
        finally:
            store.close()
    except ImportError:
        logger.debug("[graph] kuzu 未安装，跳过回填喂图谱：%s", report_path)
    except Exception:  # noqa: BLE001 — 图谱旁路绝不抛
        logger.warning("[graph] 回填喂图谱失败（已忽略）：%s", report_path, exc_info=True)


class _ReportAdapter:
    """把 report.json dict 适配成 ledger.upsert_report 所需的最小 Report-like 接口。

    upsert_report 只取 ``meta`` / ``package_name`` / ``leads``，且对 leads 用 getattr
    取 ``category`` / ``value`` / ``subject``（category 再取 .value 或 str）。这里用
    一个轻量对象承载，避免反序列化整个 Report dataclass（dict → Report 无现成入口）。
    """

    __slots__ = ("meta", "package_name", "leads")

    def __init__(self, report_dict: dict) -> None:
        meta = report_dict.get("meta")
        self.meta = meta if isinstance(meta, dict) else {}
        self.package_name = str(report_dict.get("package_name") or "")
        raw_leads = report_dict.get("leads")
        leads: list[_LeadAdapter] = []
        if isinstance(raw_leads, list):
            for item in raw_leads:
                if isinstance(item, dict):
                    leads.append(_LeadAdapter(item))
        self.leads = leads


class _LeadAdapter:
    """把 report.json 里的单条 lead dict 适配成 ledger 取数所需的最小接口。

    ``category`` 在 report.json 里已是字符串（Enum 序列化为 .value），直接承载；
    ledger._lead_category 会对其取 ``.value``（字符串无此属性 → 回退 str），口径一致。
    """

    __slots__ = ("category", "value", "subject")

    def __init__(self, lead_dict: dict) -> None:
        self.category = lead_dict.get("category", "")
        self.value = lead_dict.get("value", "")
        self.subject = lead_dict.get("subject")


# ===== graph 子命令：本地图谱串案（摄入 → 关联 → 团伙聚类，默认输出稳定 JSON 供 Codex 消费） =====
