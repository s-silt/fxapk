#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fxapk 飞书 handoff 信箱 —— Claude(机A) ↔ Codex(机B) 异步对讲 + 传文件。

凭据从仓库根 .env 读(.env 已 gitignore，不入库；两台机各自放同一份飞书凭据):
    FXAPK_FEISHU_APP_ID      = cli_xxxx        # 企业自建应用 App ID
    FXAPK_FEISHU_APP_SECRET  = xxxx            # App Secret(密钥)
    FXAPK_FEISHU_CHAT_ID     = oc_xxxx         # 目标群 chat_id

纯标准库、无第三方依赖；走直连(绕系统代理，飞书国内直连快、稳，不用梯子)。
文件走飞书云空间(同一 app 两边直接存取，无需共享文件夹)。
注意:飞书免费租户单文件上限 ~20MB —— 本脚本把 >18MB 的文件自动切块上传、下载时拼回。
免费版云空间总容量有限，取完文件记得用 delfile 清理。

用法:
    python feishu_handoff.py send     --from CLAUDE "核实完 8.x=阿里云国际; 球→CODEX"
    python feishu_handoff.py read     [--limit 10]                       # 看最近消息(旧->新)
    python feishu_handoff.py sendfile --from CODEX  ./capture.pcap [--note "刘冰震 R10"]
    python feishu_handoff.py getfile  <file_token[,token2,...]> --out capture.pcap
    python feishu_handoff.py delfile  <file_token[,token2,...]>          # 清理云空间

约定:消息前缀 [CLAUDE]/[CODEX]；交接用「球→CLAUDE / 球→CODEX」。
sendfile 上传到飞书云空间并自动发带 file_token 的指针消息；对方 getfile <token...> --out <名> 取回。
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

FEISHU = "https://open.feishu.cn/open-apis"
SPLIT_SIZE = 18 * 1024 * 1024  # 飞书免费租户单文件上限 ~20MB，按 18MB 切块留余量
# 直连，绕过系统代理(飞书国内直连；避免梯子/代理把请求搞断)
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _find_env():
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (os.path.join(here, "..", "..", "..", ".env"), os.path.join(here, ".env"), ".env"):
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


def _raw(url, body=None, ctype=None, tok=None, method=None):
    headers = {}
    if tok:
        headers["Authorization"] = "Bearer " + tok
    if ctype:
        headers["Content-Type"] = ctype
    req = urllib.request.Request(url, data=body, headers=headers, method=(method or ("POST" if body is not None else "GET")))
    try:
        resp = _OPENER.open(req, timeout=120)
        return resp.read(), resp.headers.get_content_type()
    except urllib.error.HTTPError as exc:
        return exc.read(), "ERR%d" % exc.code


def _japi(url, data=None, tok=None, method=None):
    body = json.dumps(data, ensure_ascii=False).encode("utf-8") if data is not None else None
    raw, _ = _raw(url, body, ("application/json; charset=utf-8" if body else None), tok, method)
    try:
        return json.loads(raw)
    except Exception:
        return {"code": -1, "msg": raw[:300].decode("utf-8", "replace")}


def _mpost(url, ctype, body, tok):
    raw, _ = _raw(url, body, ctype, tok)
    try:
        return json.loads(raw)
    except Exception:
        return {"code": -1, "msg": raw[:300].decode("utf-8", "replace")}


def _multipart(fields, file_field, file_name, file_bytes):
    bd = "----fxapkBOUNDARYx9a3f2c"
    parts = []
    for k, v in fields.items():
        parts += [("--" + bd).encode(), ('Content-Disposition: form-data; name="%s"' % k).encode(), b"", str(v).encode()]
    parts += [
        ("--" + bd).encode(),
        ('Content-Disposition: form-data; name="%s"; filename="%s"' % (file_field, file_name)).encode(),
        b"Content-Type: application/octet-stream", b"", file_bytes,
        ("--" + bd + "--").encode(), b"",
    ]
    return "multipart/form-data; boundary=" + bd, b"\r\n".join(parts)


def _token(env):
    r = _japi(FEISHU + "/auth/v3/tenant_access_token/internal",
              {"app_id": env["FXAPK_FEISHU_APP_ID"], "app_secret": env["FXAPK_FEISHU_APP_SECRET"]})
    if r.get("code") != 0:
        sys.exit("[x] 换 token 失败: %s %s(查 app_id/app_secret、应用是否已发布)" % (r.get("code"), r.get("msg")))
    return r["tenant_access_token"]


def _drive_root(tok):
    r = _japi(FEISHU + "/drive/explorer/v2/root_folder/meta", tok=tok)
    if r.get("code") != 0:
        sys.exit("[x] 取云空间根目录失败: %s %s(缺云空间 drive 权限？需重新发布版本)" % (r.get("code"), r.get("msg")))
    return r["data"]["token"]


def _upload_one(tok, folder, name, data):
    ct, body = _multipart({"file_name": name, "parent_type": "explorer", "parent_node": folder, "size": len(data)}, "file", name, data)
    r = _mpost(FEISHU + "/drive/v1/files/upload_all", ct, body, tok)
    if r.get("code") != 0:
        sys.exit("[x] 上传(%s)失败: %s %s" % (name, r.get("code"), r.get("msg")))
    return r["data"]["file_token"]


def _upload(tok, path):
    """上传到飞书云空间。返回 file_token 列表(>18MB 切多块)。"""
    with open(path, "rb") as fh:
        data = fh.read()
    name, folder = os.path.basename(path), _drive_root(tok)
    if len(data) <= SPLIT_SIZE:
        return [_upload_one(tok, folder, name, data)]
    nparts = (len(data) + SPLIT_SIZE - 1) // SPLIT_SIZE
    tokens = []
    for i in range(nparts):
        chunk = data[i * SPLIT_SIZE:(i + 1) * SPLIT_SIZE]
        tokens.append(_upload_one(tok, folder, "%s.part%d" % (name, i), chunk))
        print("    切块 %d/%d 上传 ok" % (i + 1, nparts))
    return tokens


def cmd_send(env, args):
    tok = _token(env)
    text = "[%s] %s" % (args.sender, args.text)
    r = _japi(FEISHU + "/im/v1/messages?receive_id_type=chat_id",
              {"receive_id": env["FXAPK_FEISHU_CHAT_ID"], "msg_type": "text",
               "content": json.dumps({"text": text}, ensure_ascii=False)}, tok=tok)
    if r.get("code") != 0:
        sys.exit("[x] 发送失败: %s %s(缺 im:message:send_as_bot？)" % (r.get("code"), r.get("msg")))
    print("[ok] 已发送 message_id=%s" % r["data"]["message_id"])


def cmd_read(env, args):
    tok = _token(env)
    url = (FEISHU + "/im/v1/messages?container_id_type=chat&container_id=%s&sort_type=ByCreateTimeDesc&page_size=%d"
           % (env["FXAPK_FEISHU_CHAT_ID"], args.limit))
    r = _japi(url, tok=tok)
    if r.get("code") != 0:
        sys.exit("[x] 读取失败: %s %s(缺 im:message.group_msg？需重新发布版本)" % (r.get("code"), r.get("msg")))
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


def cmd_sendfile(env, args):
    if not os.path.exists(args.path):
        sys.exit("[x] 文件不存在: %s" % args.path)
    tok = _token(env)
    size = os.path.getsize(args.path)
    print("[..] 上传 %s (%.1fMB) 到飞书云空间%s ..." % (os.path.basename(args.path), size / 1e6,
          "(>18MB 切块)" if size > SPLIT_SIZE else ""))
    tokens = _upload(tok, args.path)
    tk = ",".join(tokens)
    pn = (" %d块" % len(tokens)) if len(tokens) > 1 else ""
    note = (" " + args.note) if args.note else ""
    text = "[%s] 📎 %s (%.1fMB%s) file_token=%s%s" % (args.sender, os.path.basename(args.path), size / 1e6, pn, tk, note)
    r = _japi(FEISHU + "/im/v1/messages?receive_id_type=chat_id",
              {"receive_id": env["FXAPK_FEISHU_CHAT_ID"], "msg_type": "text",
               "content": json.dumps({"text": text}, ensure_ascii=False)}, tok=tok)
    ok = "已发指针消息" if r.get("code") == 0 else "指针消息发送失败: %s" % r.get("msg")
    print("[ok] 上传完成 ; %s" % ok)
    print("     对方取回: python feishu_handoff.py getfile %s --out %s" % (tk, os.path.basename(args.path)))


def cmd_getfile(env, args):
    tok = _token(env)
    tokens = [t for t in args.file_token.split(",") if t]
    out = args.out or "fxapk_download.bin"
    total = 0
    with open(out, "wb") as fh:
        for i, ft in enumerate(tokens):
            raw, ct = _raw(FEISHU + "/drive/v1/files/%s/download" % ft, tok=tok)
            if ct.startswith("ERR") or raw[:1] == b"{":
                sys.exit("[x] 下载块 %d/%d 失败: %s" % (i + 1, len(tokens), raw[:300].decode("utf-8", "replace")))
            fh.write(raw)
            total += len(raw)
            if len(tokens) > 1:
                print("    块 %d/%d 下载 ok" % (i + 1, len(tokens)))
    print("[ok] 已下载 %d 字节 -> %s" % (total, out))


def cmd_delfile(env, args):
    tok = _token(env)
    for ft in [t for t in args.file_token.split(",") if t]:
        r = _japi(FEISHU + "/drive/v1/files/%s?type=file" % ft, tok=tok, method="DELETE")
        print("  删 %s -> %s" % (ft, "ok" if r.get("code") == 0 else "%s %s" % (r.get("code"), r.get("msg"))))


def main():
    env = _load_env(_find_env())
    missing = [k for k in ("FXAPK_FEISHU_APP_ID", "FXAPK_FEISHU_APP_SECRET", "FXAPK_FEISHU_CHAT_ID") if not env.get(k)]
    if missing:
        sys.exit("[x] .env 缺少: %s(在仓库根 .env 填飞书凭据)" % ", ".join(missing))

    parser = argparse.ArgumentParser(description="fxapk 飞书 handoff 信箱")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("send", help="发消息")
    p.add_argument("--from", dest="sender", required=True, choices=["CLAUDE", "CODEX"])
    p.add_argument("text")

    p = sub.add_parser("read", help="读最近消息(旧->新)")
    p.add_argument("--limit", type=int, default=10)

    p = sub.add_parser("sendfile", help="上传文件到云空间并发指针消息(>18MB 自动切块)")
    p.add_argument("--from", dest="sender", required=True, choices=["CLAUDE", "CODEX"])
    p.add_argument("path")
    p.add_argument("--note", default=None)

    p = sub.add_parser("getfile", help="按 file_token(逗号分隔多块)下载并拼回")
    p.add_argument("file_token")
    p.add_argument("--out", default=None)

    p = sub.add_parser("delfile", help="删云空间文件(逗号分隔多块),清容量")
    p.add_argument("file_token")

    args = parser.parse_args()
    {"send": cmd_send, "read": cmd_read, "sendfile": cmd_sendfile, "getfile": cmd_getfile, "delfile": cmd_delfile}[args.cmd](env, args)


if __name__ == "__main__":
    main()
