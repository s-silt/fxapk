"""高敏值脱敏（隐私安全）测试。

digest **默认脱敏**，要明文须显式 ``--no-redact``；另锁「哪些出口不脱敏」的名单与实际接线一致。
"""

from __future__ import annotations

from pathlib import Path

from apkscan.core.models import ADVICE_INVESTIGATE
from apkscan.core.redact import mask, redact_value
from apkscan.report.digest import build_digest


def test_mask_short_and_long() -> None:
    assert mask("abc") == "***（已脱敏）"
    assert mask("") == ""
    masked = mask("abandon abandon about ...long mnemonic...")
    assert masked.startswith("aba") and "已脱敏" in masked and "abandon abandon" not in masked


def test_redact_value_only_sensitive() -> None:
    assert "已脱敏" in str(redact_value("WALLET_SECRET", "abandon abandon about end here"))
    assert "已脱敏" in str(redact_value("BACKEND_CREDENTIAL", "Basic admin:s3cretpass"))
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
    assert "已脱敏" in wallet_default["value"], "默认必须脱敏——安全选项不该是要额外记得的那个"
    assert "real mnemonic" not in wallet_default["value"]

    # 显式关掉才给明文（取证查看确需看到实际值时）。
    d_raw = build_digest(report, redact=False)
    wallet_raw = next(ld for ld in d_raw["leads"] if ld["category"] == "WALLET_SECRET")
    assert wallet_raw["value"] == "abandon abandon about real mnemonic here"

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

    from apkscan import cli

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
    for line in res.stdout.splitlines():
        if line.strip():
            json.loads(line)


def test_diff_warns_that_it_does_not_redact(tmp_path) -> None:
    """``diff`` 同样面向 agent、且把线索条目整条带出来（配对键本身就含 value）。"""
    import json

    from typer.testing import CliRunner

    from apkscan import cli

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
    json.loads(res.stdout)  # stdout 仍是一份完整合法 JSON


def test_every_listed_unredacted_command_actually_warns(tmp_path) -> None:
    """★名单与实现必须对得上：``UNREDACTED_AGENT_COMMANDS`` 里的每一条都要**真的接了线**。

    ★这条测试必须**逐条把 CLI 命令跑起来**。只调 helper 证明不了任何事——那只是在验「传进去的
      字符串会被打出来」，名单里加了条目却忘了在命令里接线照样全绿，而那正是本测试宣称要防的
      漂移。（初版就是那么写的，被复审指出。）
    """
    import json

    from typer.testing import CliRunner

    from apkscan import cli
    from apkscan.core.redact import UNREDACTED_AGENT_COMMANDS

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

    from apkscan import cli

    rep = tmp_path / "report.json"
    rep.write_text(json.dumps({
        "meta": {"package_name": "com.x"},
        "leads": [{"category": "WALLET_SECRET", "value": "abandon abandon about real mnemonic here",
                   "advice": ADVICE_INVESTIGATE, "confidence": "HIGH"}],
    }, ensure_ascii=False), encoding="utf-8")

    res = CliRunner().invoke(cli.app, ["digest", str(rep)])

    assert res.exit_code == 0, res.output
    assert "real mnemonic" not in res.stdout, "不带参数的 digest 吐出了高敏明文"
    assert "已脱敏" in res.stdout

    # 显式 --no-redact 才给明文。
    res_raw = CliRunner().invoke(cli.app, ["digest", str(rep), "--no-redact"])
    assert res_raw.exit_code == 0, res_raw.output
    assert "real mnemonic" in res_raw.stdout


def test_unredacted_command_docs_stay_in_sync() -> None:
    """★P3-3：不脱敏名单在三处人工维护（frozenset / 本模块 docstring / AGENTS.md），
    frozenset 与运行时接线之外的两份文档已经滞后过一次（link-candidates 只加了前者）。
    锁住：frozenset 里每个命令的可辨识 token 必须同时出现在两份文档里。
    """
    import apkscan.core.redact as redact_mod

    root = Path(__file__).resolve().parents[1]
    agents = (root / "AGENTS.md").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")
    readme_en = (root / "README.en.md").read_text(encoding="utf-8")
    docstring = redact_mod.__doc__ or ""
    for command in sorted(redact_mod.UNREDACTED_AGENT_COMMANDS):
        token = command.split()[-1]
        assert token in agents, f"AGENTS.md 的不脱敏出口名单缺 {command!r}"
        assert token in docstring, f"redact 模块 docstring 的名单缺 {command!r}"
        assert token in readme, f"README.md 的不脱敏出口名单缺 {command!r}"
        assert token in readme_en, f"README.en.md 的不脱敏出口名单缺 {command!r}"
