# 合成样本检出回归基线

零真实 PII 的合成样本，驱动**真实 pipeline**（真分析器 + 真规则）做端到端检出回归。

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
   - `expected_categories`：期望**必被检出**的 `LeadCategory` 名集合。
2. 重生成基线（把当前检出集写进 `baseline.json`）：
   ```bash
   python - <<'PY'
   import sys, json, pathlib; sys.path.insert(0, "tests")
   from conftest import FakeContext
   from apkscan.core import pipeline
   from apkscan.core.models import AnalysisConfig
   from tests.synthetic.samples import SAMPLES
   b = {}
   for s in SAMPLES:
       r = pipeline.run(FakeContext(dex_strings=s.dex_strings, files=s.files), AnalysisConfig(online=False))
       b[s.name] = sorted({str(getattr(l.category, "value", l.category)) for l in r.leads})
   pathlib.Path("tests/synthetic/baseline.json").write_text(json.dumps(b, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
   PY
   ```
3. review `baseline.json` 的 diff——检出集变化在这里显式可见。

## 规则改动时

规则有意变更导致检出集变化 → 基线测试会红。**看清 diff 确认是预期变化**后，重生成基线并把 `baseline.json`
一并提交。这正是本网的目的：让规则改动的检出影响在 review 里可见、可回归。

## 边界

这是**地基**（3 样本 / 3 类：ADMIN_PANEL / BACKEND_CREDENTIAL / SELF_HOSTED_IM），不是全量夹具库。
覆盖全部 `LeadCategory` 的合成夹具库是独立、更大的投入。
