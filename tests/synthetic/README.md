# 合成样本检出回归基线 + 语义快照基准

零真实 PII 的合成样本，驱动**真实 pipeline**（真分析器 + 真规则）做两层回归：

- **检出回归**（`tests/test_synthetic_regression.py` + `baseline.json`）：锁「检出了哪些 LeadCategory」；
- **语义快照**（`tests/test_synthetic_snapshots.py` + `baselines/*.json`）：同一批样本跑完
  analyze+close 后按六维度投影入锁（visibility / report / attribution / closure / digest / corpus），
  外加 HTML 渲染冒烟与五层归因 contract。runner 与投影的单一真源在 `snapshot.py`；
  快照基线更新走 `tools/update_synthetic_baseline.py`（四重闸，见该文件 docstring）。

## 为什么

工具价值 = 从真实涉诈样本抠出多少可办案线索，而检出率由 `apkscan/rules/*.yaml`（数千行规则）决定，
不是 Python 引擎决定。仓里 3000+ 组件测试验证"引擎正确"，但没有"对样本检出有效"的回归基线——
改一条规则，不知道检出率涨了还是回归了。本目录补这块地基。

## 怎么跑

```bash
python -m pytest tests/test_synthetic_regression.py -q
```

两重断言：
- `expected_categories ⊆ detected`——语义必守：改规则不得掉了样本的核心线索类；
- `detected == baseline`——漂移可见：任何检出变化都逼一次有意的基线更新。

## 加一个样本

1. 在 `samples.py` 的 `SAMPLES` 里加一条 `SyntheticSample`：
   - `name`：唯一短名；
   - `dex_strings` / `files`：**零 PII 合成内容**（域名用 `*.evil-synthetic.test` 之类占位；
     触发串参照对应分析器单测里已验证的最小触发内容）；
   - `expected_categories`：期望**必被检出**的 `LeadCategory` 名集合；
   - `pad_dex_strings`：默认 True（runner 会把 DEX 串填充到 stub 阈值之上、并补最小 manifest，
     见 `snapshot.build_context`）；只有刻意做壳桩形态的样本才设 False。
2. 重生成检出基线（★必须经 `snapshot.build_context` 构造上下文，直接裸 FakeContext 会把所有样本
   跑成 stub 形态）：
   ```bash
   python - <<'PY'
   import json, pathlib, sys; sys.path.insert(0, ".")
   from apkscan.core import pipeline
   from apkscan.core.models import AnalysisConfig
   from tests.synthetic.samples import SAMPLES
   from tests.synthetic.snapshot import build_context
   b = {}
   for s in SAMPLES:
       r = pipeline.run(build_context(s), AnalysisConfig(online=False))
       b[s.name] = sorted({str(getattr(l.category, "value", l.category)) for l in r.leads})
   pathlib.Path("tests/synthetic/baseline.json").write_text(json.dumps(b, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
   PY
   ```
3. 生成六维度快照基线（四重闸，须显式指名样本与维度）：
   ```bash
   APKSCAN_ALLOW_BASELINE_UPDATE=1 python tools/update_synthetic_baseline.py \
       --sample <新样本名> --dimension all --accept
   ```
4. review `baseline.json` 与 `baselines/*.json` 的 diff——语义变化在这里显式可见。

## 规则改动时

规则有意变更导致检出集变化 → 基线测试会红。**看清 diff 确认是预期变化**后，重生成基线并把 `baseline.json`
一并提交。这正是本网的目的：让规则改动的检出影响在 review 里可见、可回归。

## 边界

这是**地基**（9 样本：8 类检出 + 1 个壳桩接线样本），不是全量夹具库。
覆盖全部 `LeadCategory` 的合成夹具库是独立、更大的投入。
五层归因只锁到 `build_endpoint_attribution` 的 contract 层——端到端通路需要非保留 TLD 字面、
与 leak-scan strict 冲突，是政策决定（详见 test_synthetic_snapshots 的 contract 测试注释）。
