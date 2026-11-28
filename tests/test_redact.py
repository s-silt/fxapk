"""高敏值脱敏（隐私安全）测试。

digest **默认脱敏**，要明文须显式 ``--no-redact``；另锁「哪些出口不脱敏」的名单与实际接线一致。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from fxapk.core.models import ADVICE_INVESTIGATE
from fxapk.core.redact import UNREDACTED_AGENT_COMMANDS, mask, redact_value
from fxapk.report.digest import build_digest

_RAW_MNEMONIC = "abandon abandon about real mnemonic here"


def test_mask_short_and_long() -> None:
    assert mask("abc") == "***（已脱敏）"
    assert mask("12345678") == "***（已脱敏）"  # ≤8 字符整段遮蔽，不留首尾
    assert mask("") == ""
    assert mask("123456789") == "123***89（已脱敏，9 字符）"
    secret = "abandon abandon about ...long mnemonic..."
    masked = mask(secret)
    assert masked == f"aba***..（已脱敏，{len(secret)} 字符）"
    assert "abandon abandon" not in masked


def test_redact_value_only_sensitive() -> None:
    mnemonic = "abandon abandon about end here"
    credential = "Basic admin:s3cretpass"
    assert redact_value("WALLET_SECRET", mnemonic) == mask(mnemonic)
    assert redact_value("BACKEND_CREDENTIAL", credential) == mask(credential)
    # 非字符串高敏值先 str() 再遮蔽：dict 里的 key/iv 不能原样放过去。
    recipe = {"key": "00112233445566778899aabbccddeeff", "iv": "0102030405060708"}
    redacted_recipe = redact_value("CRYPTO_RECIPE", recipe)
    assert redacted_recipe == mask(str(recipe))
    assert recipe["key"] not in str(redacted_recipe)
    assert redact_value("WALLET_SECRET", None) is None
    # 非高敏类别原样返回。
    assert redact_value("DOMAIN", "evil.com") == "evil.com"
    assert redact_value("ADMIN_PANEL", "admin.evil.com") == "admin.evil.com"


def test_digest_redact_is_opt_out() -> None:
    """★脱敏是 **opt-out**：不传参数就是脱敏，要明文得显式关掉。

    这条测试的名字与语义都翻转过（曾是 ``..._is_opt_in``）。翻转的理由：本工具的主推路径是把
    digest 喂给 AI，默认明文等于「按最省事的方式用」就把钱包私钥 / 助记词 / 个人隐私数据交了
    出去。两类失误的后果不对称——忘了关脱敏只是少看见几个值，忘了开则是原值已经出去了。
    """
    report = {
        "meta": {"package_name": "com.x"},
        "leads": [
            {"category": "WALLET_SECRET", "value": "abandon abandon about real mnemonic here",
             "advice": ADVICE_INVESTIGATE, "confidence": "HIGH"},
            {"category": "DOMAIN", "value": "c2.example.com", "advice": ADVICE_INVESTIGATE, "confidence": "HIGH"},
        ],
    }
    # ★不传参数 → 脱敏。这是本条测试的主锁：默认值一旦被改回明文，这里立刻红。
    d_default = build_digest(report)
    wallet_default = next(ld for ld in d_default["leads"] if ld["category"] == "WALLET_SECRET")
    assert wallet_default["value"] == mask(_RAW_MNEMONIC), "默认必须脱敏——安全选项不该是要额外记得的那个"
    assert "real mnemonic" not in json.dumps(d_default, ensure_ascii=False), "默认 digest 别处带出了明文"

    # 显式关掉才给明文（取证查看确需看到实际值时）。
    d_raw = build_digest(report, redact=False)
    wallet_raw = next(ld for ld in d_raw["leads"] if ld["category"] == "WALLET_SECRET")
    assert wallet_raw["value"] == _RAW_MNEMONIC

    # 非高敏类别两种模式下都不动。
    for d in (d_default, d_raw):
        domain = next(ld for ld in d["leads"] if ld["category"] == "DOMAIN")
        assert domain["value"] == "c2.example.com"


def test_jsonl_warns_that_it_does_not_redact(tmp_path) -> None:
    """★``jsonl`` 与 ``digest`` 同样面向 agent 消费，却**不脱敏**——这件事必须说出来。

    翻转 ``digest`` 的默认值容易造成「喂 AI 已经安全了」的错觉，而 ``jsonl`` /
    ``corpus events`` / ``diff`` 走的是另外的路径、完全不受那个开关保护。警告只写在 docstring
    里挡不住任何人，所以它必须是**运行时真的打出来的一行**，并且被测试钉住。

    ★警告走 stderr：stdout 是 JSONL 数据流，掺一行非 JSON 进去会把下游 ``| jq`` 打坏。
    """
    import json

    from typer.testing import CliRunner

    from fxapk import cli

    rep = tmp_path / "report.json"
    rep.write_text(json.dumps({
        "meta": {"package_name": "com.x"},
        "leads": [{"category": "WALLET_SECRET", "value": "abandon abandon about real mnemonic here",
                   "advice": ADVICE_INVESTIGATE, "confidence": "HIGH"}],
    }, ensure_ascii=False), encoding="utf-8")

    res = CliRunner().invoke(cli.app, ["jsonl", str(rep)])

    assert res.exit_code == 0, res.stderr
    assert "不做脱敏" in res.stderr, "jsonl 必须明说自己不脱敏，否则默认脱敏的 digest 会给人错觉"
    # 每一行仍须是合法 JSON——警告不能混进 stdout 打坏下游解析。
    events = [json.loads(line) for line in res.stdout.splitlines() if line.strip()]
    assert events, "jsonl 的 stdout 没有任何事件"
    # 警告说的是真话：线索原值确实原样出现在事件流里。
    assert _RAW_MNEMONIC in json.dumps(events, ensure_ascii=False)


def test_diff_warns_that_it_does_not_redact(tmp_path) -> None:
    """``diff`` 同样面向 agent、且把线索条目整条带出来（配对键本身就含 value）。"""
    import json

    from typer.testing import CliRunner

    from fxapk import cli

    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(json.dumps({"meta": {}, "leads": []}, ensure_ascii=False), encoding="utf-8")
    new.write_text(json.dumps({
        "meta": {},
        "leads": [{"category": "WALLET_SECRET", "value": "abandon abandon about real mnemonic here",
                   "advice": ADVICE_INVESTIGATE, "confidence": "HIGH"}],
    }, ensure_ascii=False), encoding="utf-8")

    res = CliRunner().invoke(cli.app, ["diff", str(old), str(new)])

    assert res.exit_code == 0, res.stderr
    assert "不做脱敏" in res.stderr
    output = json.loads(res.stdout)  # stdout 仍是一份完整合法 JSON
    assert [ld.get("value") for ld in output["leads"]["added"]] == [_RAW_MNEMONIC]


def test_every_listed_unredacted_command_actually_warns(tmp_path) -> None:
    """★名单与实现必须对得上：``UNREDACTED_AGENT_COMMANDS`` 里的每一条都要**真的接了线**。

    ★这条测试必须**逐条把 CLI 命令跑起来**。只调 helper 证明不了任何事——那只是在验「传进去的
      字符串会被打出来」，名单里加了条目却忘了在命令里接线照样全绿，而那正是本测试宣称要防的
      漂移。（初版就是那么写的，被复审指出。）
    """
    import json

    from typer.testing import CliRunner

    from fxapk import cli
    from fxapk.core.redact import UNREDACTED_AGENT_COMMANDS

    rep = tmp_path / "r.json"
    rep.write_text(json.dumps({
        "meta": {
            "package_name": "com.x",
            "sample_sha256": "a" * 64,
            "tool_version": "1.2.3",
            "ruleset_digest": "b" * 16,
        },
        "leads": [{"category": "WALLET_SECRET", "value": "abandon abandon about real mnemonic here",
                   "advice": ADVICE_INVESTIGATE, "confidence": "HIGH"}],
    }, ensure_ascii=False), encoding="utf-8")
    corpus_dir = tmp_path / "corpus"
    runner = CliRunner()
    assert runner.invoke(
        cli.app, ["corpus", "add", str(rep), "--case", "c1", "--corpus", str(corpus_dir)]
    ).exit_code == 0

    probe_log = tmp_path / "probe.log"
    probe_log.write_text("[pay] seller_id=2088000000000001 [LEAD-定人]\n", encoding="utf-8")
    pcap = tmp_path / "t.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x02\x00\x04\x00" + b"\x00" * 16)
    linkage_labels = tmp_path / "linkage-labels.jsonl"
    linkage_labels.write_text("", encoding="utf-8")

    argv_of = {
        "jsonl": ["jsonl", str(rep)],
        "diff": ["diff", str(rep), str(rep)],
        "corpus events": ["corpus", "events", "a" * 64, "--corpus", str(corpus_dir)],
        "corpus ls": ["corpus", "ls", "--corpus", str(corpus_dir)],
        "corpus seen": ["corpus", "seen", "a" * 64, "--corpus", str(corpus_dir)],
        "corpus shared-config": ["corpus", "shared-config", "--corpus", str(corpus_dir)],
        "corpus shared-native": ["corpus", "shared-native", "--corpus", str(corpus_dir)],
        "corpus shared-build-env": [
            "corpus", "shared-build-env", "--corpus", str(corpus_dir)
        ],
        "corpus link-candidates": ["corpus", "link-candidates", "--corpus", str(corpus_dir)],
        "corpus link-discover --evidence-values raw": [
            "corpus", "link-discover", "--corpus", str(corpus_dir),
            "--labels", str(linkage_labels),
            "--evidence-values", "raw",
        ],
        "corpus link-explain --evidence-values raw": [
            "corpus", "link-explain", "a" * 64, "b" * 64,
            "--corpus", str(corpus_dir), "--evidence-values", "raw",
        ],
        "corpus link-groups --evidence-values raw": [
            "corpus", "link-groups", "--corpus", str(corpus_dir),
            "--evidence-values", "raw",
        ],
        "lead show": ["lead", "show", str(rep)],
        "lead restore": ["lead", "restore", str(rep), "--value", "nope.example",
                         "--source", "x", "--note", "n"],
        "lead replay": ["lead", "replay", str(rep), "--corpus", str(corpus_dir)],
        "probe-leads": ["probe-leads", str(probe_log)],
        "pcap-leads": ["pcap-leads", str(pcap)],
    }
    assert set(argv_of) == UNREDACTED_AGENT_COMMANDS, "名单变了就要在这里补上对应命令行"

    for command, argv in sorted(argv_of.items()):
        res = runner.invoke(cli.app, argv)
        # ★不断言 exit_code：有几条在这份最小夹具上会正常地报「找不到」（如 lead restore 的
        #   目标值不存在）。要锁的是「警告在命令**开始时**就打了」，不是它能不能跑成功。
        assert "不做脱敏" in res.stderr, f"{command} 没打不脱敏警告——名单列着但没接线"


def test_cli_digest_redacts_without_any_flag(tmp_path) -> None:
    """★CLI 层的锁，走真入口：``fxapk digest <报告>`` 不带任何参数就该是脱敏的。

    只锁 ``build_digest`` 的函数默认值不够——CLI 的 ``typer.Option`` 默认值是**另一处**，
    两边任一处被改回明文，README 主推的那条命令就会重新吐出原值。
    """
    import json

    from typer.testing import CliRunner

    from fxapk import cli

    rep = tmp_path / "report.json"
    rep.write_text(json.dumps({
        "meta": {"package_name": "com.x"},
        "leads": [{"category": "WALLET_SECRET", "value": "abandon abandon about real mnemonic here",
                   "advice": ADVICE_INVESTIGATE, "confidence": "HIGH"}],
    }, ensure_ascii=False), encoding="utf-8")

    res = CliRunner().invoke(cli.app, ["digest", str(rep)])

    assert res.exit_code == 0, res.output
    assert "real mnemonic" not in res.stdout, "不带参数的 digest 吐出了高敏明文"
    leads = json.loads(res.stdout)["leads"]
    assert [ld["value"] for ld in leads if ld["category"] == "WALLET_SECRET"] == [mask(_RAW_MNEMONIC)]

    # 显式 --no-redact 才给明文。
    res_raw = CliRunner().invoke(cli.app, ["digest", str(rep), "--no-redact"])
    assert res_raw.exit_code == 0, res_raw.output
    raw_leads = json.loads(res_raw.stdout)["leads"]
    assert [ld["value"] for ld in raw_leads if ld["category"] == "WALLET_SECRET"] == [_RAW_MNEMONIC]


_CODE_SPAN_RE = re.compile(r"`+([^`\n]+)`+")


def _listed_commands(text: str) -> set[str]:
    """把 `lead show|restore|replay` / ``fxapk corpus events/ls`` 这类代码片段展开成完整命令。"""
    out: set[str] = set()
    for span in _CODE_SPAN_RE.findall(text):
        words = span.strip().removeprefix("fxapk ").split()
        if len(words) == 1:
            out.update(filter(None, re.split(r"[|/]", words[0])))
            continue
        if not words:
            continue
        head, tail = words[0], " ".join(words[2:])
        for sub in filter(None, re.split(r"[|/]", words[1])):
            out.add(f"{head} {sub}")
            if tail:
                out.add(f"{head} {sub} {tail}")
    return out


def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    end = text.find("\n## ", start + len(heading))
    return text[start:] if end == -1 else text[start:end]


def test_unredacted_command_docs_stay_in_sync() -> None:
    """Keep raw-output inventories in agent/usage docs and link concise READMEs to them.

    ★按完整命令比对文档里的代码片段：只查 ``ls`` / ``show`` 这种单词是否在全文出现，
      任何文档都恒为真。
    """
    import fxapk.core.redact as redact_mod

    root = Path(__file__).resolve().parents[1]
    agents = (root / "AGENTS.md").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")
    readme_en = (root / "README.en.md").read_text(encoding="utf-8")
    usage = (root / "USAGE.md").read_text(encoding="utf-8")
    usage_en = (root / "USAGE.en.md").read_text(encoding="utf-8")
    assert "(USAGE.md#隐私与输出)" in readme and "## 隐私与输出" in usage
    assert "(USAGE.en.md#privacy-and-output)" in readme_en and "## Privacy and output" in usage_en
    inventories = {
        "AGENTS.md": next(
            (line for line in agents.splitlines() if "UNREDACTED_AGENT_COMMANDS" in line), ""
        ),
        "redact 模块 docstring": redact_mod.__doc__ or "",
        "USAGE.md": _section(usage, "## 隐私与输出"),
        "USAGE.en.md": _section(usage_en, "## Privacy and output"),
    }
    for doc, text in inventories.items():
        listed = _listed_commands(text)
        for command in sorted(UNREDACTED_AGENT_COMMANDS):
            base, sep, mode = command.partition(" --evidence-values ")
            assert base in listed, f"{doc} 的不脱敏出口名单缺 {command!r}"
            if sep:
                assert {command, f"--evidence-values {mode}", mode} & listed, (
                    f"{doc} 没写明 {base} 的 --evidence-values {mode} 才不脱敏"
                )
