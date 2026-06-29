#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fxapk 飞书 handoff 信箱 —— Claude(机A) ↔ Codex(机B) 异步对讲。

凭据从仓库根 .env 读(.env 已 gitignore，不入库；两台机各自放同一份飞书凭据）:
    FXAPK_FEISHU_APP_ID      = cli_xxxx        # 企业自建应用 App ID
    FXAPK_FEISHU_APP_SECRET  = xxxx            # App Secret（密钥）
    FXAPK_FEISHU_CHAT_ID     = oc_xxxx         # 目标群 chat_id

纯标准库、无第三方依赖；走直连(绕系统代理，飞书国内直连快、稳，不用梯子)。

用法:
    python feishu_handoff.py send --from CLAUDE "核实完 8.x 三个IP=阿里云国际; 球→CODEX"
    python feishu_handoff.py send --from CODEX  "刘冰震取证完; report在 OneDrive/handoff/刘冰震/; 球→CLAUDE"
    python feishu_handoff.py read  [--limit 10]      # 看最近消息（旧→新）

约定:每条消息前缀 [CLAUDE]/[CODEX] 标明谁发的；正文里用「球→CLAUDE / 球→CODEX」标交接。
大文件(pcap/apk)不走这里——放 OneDrive，消息里只写文件名+路径(+SHA256 指针)。
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

FEISHU = "https://open.feishu.cn/open-apis"
# 直连，绕过系统代理(飞书国内直连；避免梯子/代理把内嵌请求搞断)
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _find_env():
    here = os.path.dirname(os.path.abspath(__file__))
    # 脚本在 docs/codex/handoff/ → 仓库根在上三层
    for cand in (
        os.path.join(here, "..", "..", "..", ".env"),
        os.path.join(here, ".env"),
        ".env",
    ):
        if os.path.exists(cand):
            return os.path.abspath(cand)
    return os.path.abspath(os.path.join(here, "..", "..", "..", ".env"))


def _load_env(path):
    env = {}
    if not os.path.exists(path):
        return env
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def _api(url, data=None, tok=None):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    if tok:
        headers["Authorization"] = "Bearer " + tok
    body = json.dumps(data, ensure_ascii=False).encode("utf-8") if data is not None else None
    req = urllib.request.Request(
        url, data=body, headers=headers, method=("POST" if data is not None else "GET")
    )
    try:
        return json.loads(_OPENER.open(req, timeout=20).read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read().decode("utf-8"))
        except Exception:
            return {"code": exc.code, "msg": "HTTP %d" % exc.code}


def _token(env):
    r = _api(
        FEISHU + "/auth/v3/tenant_access_token/internal",
        {"app_id": env["FXAPK_FEISHU_APP_ID"], "app_secret": env["FXAPK_FEISHU_APP_SECRET"]},
    )
    if r.get("code") != 0:
        sys.exit("[x] 换 token 失败: %s %s（查 app_id/app_secret，应用是否已发布）" % (r.get("code"), r.get("msg")))
    return r["tenant_access_token"]


def cmd_send(env, args):
    tok = _token(env)
    text = "[%s] %s" % (args.sender, args.text)
    r = _api(
        FEISHU + "/im/v1/messages?receive_id_type=chat_id",
        {
            "receive_id": env["FXAPK_FEISHU_CHAT_ID"],
            "msg_type": "text",
            "content": json.dumps({"text": text}, ensure_ascii=False),
        },
        tok=tok,
    )
    if r.get("code") != 0:
        sys.exit("[x] 发送失败: %s %s（缺 im:message:send_as_bot？）" % (r.get("code"), r.get("msg")))
    print("[ok] 已发送 message_id=%s" % r["data"]["message_id"])


def cmd_read(env, args):
    tok = _token(env)
    url = (
        FEISHU
        + "/im/v1/messages?container_id_type=chat&container_id=%s&sort_type=ByCreateTimeDesc&page_size=%d"
        % (env["FXAPK_FEISHU_CHAT_ID"], args.limit)
    )
    r = _api(url, tok=tok)
    if r.get("code") != 0:
        sys.exit("[x] 读取失败: %s %s（缺 im:message.group_msg？需重新发布版本）" % (r.get("code"), r.get("msg")))
    items = r.get("data", {}).get("items", [])
    if not items:
        print("(群里暂无消息)")
        return
    for m in reversed(items):  # 旧 -> 新
        try:
            txt = json.loads(m.get("body", {}).get("content", "{}")).get("text", "")
        except Exception:
            txt = m.get("body", {}).get("content", "")
        if m.get("msg_type") != "text":
            txt = "<%s> %s" % (m.get("msg_type"), txt)
        print(txt)


def main():
    env = _load_env(_find_env())
    missing = [k for k in ("FXAPK_FEISHU_APP_ID", "FXAPK_FEISHU_APP_SECRET", "FXAPK_FEISHU_CHAT_ID") if not env.get(k)]
    if missing:
        sys.exit("[x] .env 缺少: %s（在仓库根 .env 填飞书凭据）" % ", ".join(missing))

    parser = argparse.ArgumentParser(description="fxapk 飞书 handoff 信箱")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_send = sub.add_parser("send", help="发一条消息到 handoff 群")
    p_send.add_argument("--from", dest="sender", required=True, choices=["CLAUDE", "CODEX"], help="谁发的")
    p_send.add_argument("text", help="消息正文")

    p_read = sub.add_parser("read", help="读最近消息(旧->新)")
    p_read.add_argument("--limit", type=int, default=10, help="读几条(默认10)")

    args = parser.parse_args()
    (cmd_send if args.cmd == "send" else cmd_read)(env, args)


if __name__ == "__main__":
    main()
