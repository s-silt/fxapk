"""线索追踪 + 办案进度的局域网网页（flask，可选 extra）。

提供一个轻量 flask app（工厂 ``create_app``）+ 路由：

- ``GET  /``              → jinja2 渲染单页（按 APK 列出 → 展开线索表格）。
- ``GET  /api/tracking``  → 全量台账 JSON（只读）。
- ``POST /api/apk``       ``{sha256, status?, notes?}``       → ``set_apk``。
- ``POST /api/lead``      ``{sha256, lead_key, status?, notes?}`` → ``set_lead``。
- ``POST /api/history``   ``{sha256, lead_key, text}``        → ``add_history``。
- ``POST /api/lead/add``  ``{sha256, category, value, subject?, status?, notes?}`` → ``add_lead``（人工补线索）。

图谱（可选 kuzu；缺失/异常一律优雅降级 ``{ok:false}``，绝不 500、不连累线索面板）：

- ``GET  /api/graph?sha256=`` → ``query_link``（该 APK 的关联 APK + 共享强实体）。
- ``POST /api/graph/entity``  ``{sha256, kind, value}``  → ``upsert_entity`` + ``link``。
- ``POST /api/graph/delete_entity`` ``{kind, value}``     → ``delete_entity``（全局删实体+边）。
- ``POST /api/graph/unlink``  ``{sha256, kind, value}``  → ``unlink``（只断本 APK 这条边）。

绑定与鉴权（spec §5）：
- 绑定到**非 loopback**（如 ``0.0.0.0`` / 具体网卡 IP）时**自动启用令牌**：启动生成随机
  token，URL 带 ``?token=...`` 打印；每个请求校验 token（query ``?token=`` 或
  ``X-Track-Token`` 头），不符 401。``--no-auth`` 显式关闭。loopback 默认不强制。
- flask 开发服务器 ``threaded=True`` 支撑多人并发只读 + 偶发编辑（非公网部署）。

错误处理（铁律）：按条 POST 单字段更新（不整盘覆盖）；坏入参返结构化 JSON 错误 + 4xx；
台账层本身绝不抛。flask 缺失由 CLI 侧惰性导入兜住（本模块顶层不强依赖 flask）。
"""

from __future__ import annotations

import ipaddress
import logging
import secrets
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from flask import Flask

from apkscan.track.ledger import TrackingLedger

logger = logging.getLogger(__name__)

# 请求头令牌名（也支持 query ?token=）。
TOKEN_HEADER = "X-Track-Token"
# query 参数令牌名。
TOKEN_QUERY = "token"

# 预设状态词表（UI 下拉用；自定义输入仍可任意覆盖）。
APK_STATUS_PRESETS = ["待处理", "调查中", "已移送", "已结案"]
LEAD_STATUS_PRESETS = ["待办", "已出函", "已收数据", "无果", "不调证"]

# 图谱「未启用」统一提示（kuzu 可选 extra 缺失时返此，前端面板降级展示）。
_GRAPH_DISABLED_MSG = "图谱未启用（pip install fxapk[graph]）"


def _lead_category_presets() -> list[str]:
    """手动加线索的 category 下拉词表（LeadCategory 枚举值）。导入失败兜底空表，绝不崩。"""
    try:
        from apkscan.core.models import LeadCategory

        return [c.value for c in LeadCategory]
    except Exception:  # noqa: BLE001 — 仅供 UI 下拉，缺失不应连累网页
        logger.warning("[track] 载入 LeadCategory 失败（线索下拉降级为空）", exc_info=True)
        return []


def _is_loopback(host: str) -> bool:
    """host 是否 loopback（127.0.0.0/8 / ::1 / localhost）。无法解析的当**非** loopback（从严）。"""
    h = (host or "").strip()
    if not h:
        return False
    if h.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        # 不是字面 IP（如主机名）：从严当非 loopback，触发令牌鉴权。
        return False


def create_app(
    ledger: TrackingLedger,
    *,
    token: str | None = None,
    graph_db: str = "",
) -> Flask:
    """flask app 工厂。

    :param ledger: 已构造好的 :class:`TrackingLedger`（权威台账，绝不抛）。
    :param token: 非空则对每个请求强制令牌校验（query ``?token=`` 或 ``X-Track-Token`` 头）；
        ``None`` 表示不鉴权（loopback 自用 / ``--no-auth``）。
    :param graph_db: 图谱 Kuzu DB 路径（空 → ``GraphStore`` 默认 ``.apkscan_cache/cases.kuzu``）。
        kuzu 未装时图谱路由优雅降级，不连累线索面板。
    """
    from flask import Flask, abort, jsonify, render_template, request

    app = Flask(__name__)
    # 把 ledger / token 挂到 app，便于测试取用。
    app.config["TRACK_LEDGER"] = ledger
    app.config["TRACK_TOKEN"] = token
    app.config["TRACK_GRAPH_DB"] = graph_db

    def _with_graph(fn: Any) -> tuple[Any, bool]:
        """打开 GraphStore 跑 ``fn(store)``，用完必 close。

        返回 ``(result, ok)``：kuzu 缺失（ImportError）/ 任何异常 → ``(None, False)`` + logging，
        **绝不抛**（图谱可选，缺失/异常不连累线索面板与主流程，约束 §7）。
        ``ok=False`` 时调用方返回 ``{"ok": False, "error": _GRAPH_DISABLED_MSG}``。
        """
        from apkscan.graph import GraphStore

        store = GraphStore(graph_db) if graph_db else GraphStore()
        try:
            # 先探活：kuzu 缺失时 ensure_ready 抛 ImportError（不吞），统一走下方降级。
            # 关键——delete_entity/unlink 自身 except 吞 ImportError 返 0，若不在此探活，
            # 这两条路由会把「kuzu 没装」误报成「已删除 0 条」(ok=true)。探活让四路一致降级。
            store.ensure_ready()
            return fn(store), True
        except Exception:  # noqa: BLE001 — 含 ImportError(kuzu 缺失)：图谱路由绝不 500
            logger.warning("[track] 图谱操作失败（已降级 ok=false）", exc_info=True)
            return None, False
        finally:
            try:
                store.close()
            except Exception:  # noqa: BLE001 — close 已 never-throw，这里再兜一层
                logger.debug("[track] 关闭 GraphStore 失败（已忽略）", exc_info=True)

    def _check_token() -> None:
        """令牌校验：token 配置非空时，请求须带匹配 token（query 或头），否则 401。"""
        if not token:
            return
        supplied = request.args.get(TOKEN_QUERY) or request.headers.get(TOKEN_HEADER) or ""
        # 常数时间比较，避免计时侧信道。
        if not secrets.compare_digest(str(supplied), str(token)):
            abort(401, description="令牌缺失或不匹配")

    @app.before_request
    def _auth() -> None:  # pyright: ignore[reportUnusedFunction]
        _check_token()

    @app.errorhandler(400)
    def _bad_request(exc: Any):  # pyright: ignore[reportUnusedFunction]
        return jsonify({"ok": False, "error": getattr(exc, "description", "bad request")}), 400

    @app.errorhandler(401)
    def _unauthorized(exc: Any):  # pyright: ignore[reportUnusedFunction]
        return jsonify({"ok": False, "error": getattr(exc, "description", "unauthorized")}), 401

    @app.errorhandler(404)
    def _not_found(exc: Any):  # pyright: ignore[reportUnusedFunction]
        return jsonify({"ok": False, "error": getattr(exc, "description", "not found")}), 404

    @app.errorhandler(500)
    def _server_error(exc: Any):  # pyright: ignore[reportUnusedFunction]
        # spec §7：任何意外异常也返结构化 JSON（而非 flask 默认 HTML），服务不崩。
        logger.error("[track] 网页处理未预期异常", exc_info=exc)
        return jsonify({"ok": False, "error": "internal error"}), 500

    @app.get("/")
    def index() -> str:
        """渲染单页：注入令牌（前端 fetch 带上）+ 预设状态词表。台账数据由前端再拉 /api/tracking。"""
        return render_template(
            "track.html",
            token=token or "",
            apk_status_presets=APK_STATUS_PRESETS,
            lead_status_presets=LEAD_STATUS_PRESETS,
            lead_category_presets=_lead_category_presets(),
        )

    @app.get("/api/tracking")
    def api_tracking():
        """全量台账 JSON（只读）。"""
        return jsonify(ledger.all())

    @app.post("/api/apk")
    def api_apk():
        """单条更新某 APK 的 status/notes（不整盘覆盖）。"""
        data = _json_body()
        sha256 = _require_str(data, "sha256")
        status = _opt_str(data, "status")
        notes = _opt_str(data, "notes")
        if status is None and notes is None:
            abort(400, description="status / notes 至少给一个")
        ok = ledger.set_apk(sha256, status=status, notes=notes)
        if not ok:
            abort(404, description=f"未找到 APK：{sha256}")
        return jsonify({"ok": True})

    @app.post("/api/lead")
    def api_lead():
        """单条更新某线索的 status/notes（不整盘覆盖）。"""
        data = _json_body()
        sha256 = _require_str(data, "sha256")
        lead_key = _require_str(data, "lead_key")
        status = _opt_str(data, "status")
        notes = _opt_str(data, "notes")
        if status is None and notes is None:
            abort(400, description="status / notes 至少给一个")
        ok = ledger.set_lead(sha256, lead_key, status=status, notes=notes)
        if not ok:
            abort(404, description=f"未找到线索：{sha256} / {lead_key}")
        return jsonify({"ok": True})

    @app.post("/api/history")
    def api_history():
        """给某线索追加一条进展（留痕）。"""
        data = _json_body()
        sha256 = _require_str(data, "sha256")
        lead_key = _require_str(data, "lead_key")
        text = _require_str(data, "text")
        ok = ledger.add_history(sha256, lead_key, text)
        if not ok:
            abort(404, description=f"未找到线索：{sha256} / {lead_key}")
        return jsonify({"ok": True})

    # ---- 手动加线索（人工补录自动没抠到的线索） ------------------------------
    @app.post("/api/lead/add")
    def api_lead_add():
        """人工新增一条线索（不覆盖已存在 key）。category/value 必填，其余可选。"""
        data = _json_body()
        sha256 = _require_sha256(data)
        category = _require_str(data, "category")
        value = _require_str(data, "value")
        subject = _opt_str(data, "subject") or ""
        status = _opt_str(data, "status") or LEAD_STATUS_PRESETS[0]
        notes = _opt_str(data, "notes") or ""
        ok = ledger.add_lead(
            sha256, category, value, subject=subject, status=status, notes=notes
        )
        if not ok:
            abort(400, description="线索已存在或新增失败（同 category:value 已跟踪）")
        return jsonify({"ok": True})

    # ---- 图谱（可选 kuzu；缺失/异常优雅降级 ok=false，绝不 500） --------------
    @app.get("/api/graph")
    def api_graph():
        """读该 APK 的图谱关联（共享强实体 + 关联 APK）。kuzu 缺失 → ok=false。"""
        sha256 = (request.args.get("sha256") or "").strip()
        if not _is_sha256(sha256):
            abort(400, description="缺少或非法字段：sha256")

        from apkscan.graph import query_link

        result, ok = _with_graph(lambda store: query_link(store, sha256))
        if not ok:
            return jsonify({"ok": False, "error": _GRAPH_DISABLED_MSG})
        return jsonify({"ok": True, "graph": result})

    @app.post("/api/graph/entity")
    def api_graph_entity():
        """加一个实体并连到本 APK（upsert_entity + link）。kuzu 缺失 → ok=false。"""
        data = _json_body()
        sha256 = _require_sha256(data)
        kind = _require_str(data, "kind")
        value = _require_str(data, "value")

        from apkscan.graph import get_weight

        def _do(store: Any) -> None:
            store.upsert_entity(kind, value)
            store.link(sha256, kind, value, weight=get_weight(kind))

        _result, ok = _with_graph(_do)
        if not ok:
            return jsonify({"ok": False, "error": _GRAPH_DISABLED_MSG})
        return jsonify({"ok": True})

    @app.post("/api/graph/delete_entity")
    def api_graph_delete_entity():
        """全局删除一个实体及其所有边。kuzu 缺失 → ok=false。返回删除数。"""
        data = _json_body()
        kind = _require_str(data, "kind")
        value = _require_str(data, "value")
        result, ok = _with_graph(lambda store: store.delete_entity(kind, value))
        if not ok:
            return jsonify({"ok": False, "error": _GRAPH_DISABLED_MSG})
        return jsonify({"ok": True, "deleted": int(result or 0)})

    @app.post("/api/graph/unlink")
    def api_graph_unlink():
        """只断本 APK 与某实体的这条边（不动节点）。kuzu 缺失 → ok=false。返回删除边数。"""
        data = _json_body()
        sha256 = _require_sha256(data)
        kind = _require_str(data, "kind")
        value = _require_str(data, "value")
        result, ok = _with_graph(lambda store: store.unlink(sha256, kind, value))
        if not ok:
            return jsonify({"ok": False, "error": _GRAPH_DISABLED_MSG})
        return jsonify({"ok": True, "removed": int(result or 0)})

    return app


def _json_body() -> dict[str, Any]:
    """解析请求 JSON body 为 dict；非法 / 非 dict → 400。"""
    from flask import abort, request

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        abort(400, description="请求体须为 JSON 对象")
    return data


def _require_str(data: dict[str, Any], key: str) -> str:
    """取必填字符串字段；缺失 / 非字符串 / 空白 → 400。"""
    from flask import abort

    val = data.get(key)
    if not isinstance(val, str) or not val.strip():
        abort(400, description=f"缺少或非法字段：{key}")
    return val


def _is_sha256(val: str) -> bool:
    """是否 64 位十六进制 sha256（spec §5：写路由 sha256 须 hex 校验，挡畸形脏引用）。"""
    import re

    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", val or ""))


def _require_sha256(data: dict[str, Any], key: str = "sha256") -> str:
    """取必填 sha256 字段：非空字符串 + 64 位 hex，否则 400。"""
    from flask import abort

    val = _require_str(data, key)
    if not _is_sha256(val):
        abort(400, description=f"字段须为 64 位十六进制 sha256：{key}")
    return val


def _opt_str(data: dict[str, Any], key: str) -> str | None:
    """取可选字符串字段；缺失 → None（不动该字段）；存在但非字符串 → 400。"""
    from flask import abort

    if key not in data:
        return None
    val = data.get(key)
    if not isinstance(val, str):
        abort(400, description=f"字段须为字符串：{key}")
    return val


def serve(
    host: str = "127.0.0.1",
    port: int = 8787,
    *,
    ledger: TrackingLedger | None = None,
    no_auth: bool = False,
    graph_db: str = "",
) -> None:
    """起 flask 服务（阻塞）。打印访问网址（绑定非 loopback 时含令牌）。

    :param host: 绑定地址。默认 ``127.0.0.1``（仅本机）；``0.0.0.0`` 暴露到 LAN。
    :param port: 端口，默认 8787。
    :param ledger: 台账实例；``None`` 则按默认路径构造。
    :param no_auth: 显式关闭令牌鉴权（可信封闭内网）。
    :param graph_db: 图谱 Kuzu DB 路径（空 → 默认 ``.apkscan_cache/cases.kuzu``）。

    鉴权策略：绑定到**非 loopback** 且未 ``--no-auth`` → 自动生成随机 token 并强制校验；
    loopback 默认不强制。
    """
    if ledger is None:
        ledger = TrackingLedger()

    token: str | None = None
    if not no_auth and not _is_loopback(host):
        token = secrets.token_urlsafe(24)

    app = create_app(ledger, token=token, graph_db=graph_db)

    # 打印访问网址：非 loopback 时给一个可点的 URL（host 是 0.0.0.0 时提示用本机网卡 IP）。
    shown_host = host if host not in ("0.0.0.0", "::") else "<本机网卡IP>"
    base_url = f"http://{shown_host}:{port}/"
    print(f"[track] 台账：{ledger.path}")
    if token:
        print(f"[track] 已启用令牌鉴权（绑定到非 loopback）。访问：{base_url}?token={token}")
        print(f"[track]   或在请求头带 {TOKEN_HEADER}: {token}")
    else:
        if not no_auth:
            print(f"[track] loopback 本机自用，未强制令牌。访问：{base_url}")
        else:
            print(f"[track] 已用 --no-auth 关闭令牌鉴权（信任内网）。访问：{base_url}")
    print("[track] Ctrl-C 退出。")

    # flask 开发服务器：threaded=True 支撑多人并发只读 + 偶发编辑（非公网部署，见 spec §5）。
    app.run(host=host, port=port, threaded=True)
