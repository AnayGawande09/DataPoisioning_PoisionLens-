# Quick demo

One page, one click: upload a dataset (or pick a sample) and get a verdict, the flagged records,
a cleaned copy and a sealed audit trail.

```bash
.venv/Scripts/python -m uvicorn backend.main:app --port 8000
```

Open http://127.0.0.1:8000/.

## What runs

| Stage | Implementation |
| :--- | :--- |
| Upload, safe ingest (F01-F04), format detection + canonical dataset | Real Phase 0-3 code |
| Content security: formula injection, PII, secrets, prompt injection, active markup, invisible characters (F10, C01-C05) | `poisonlens/demo/content.py`, regex-based |
| Quality: conflicting-label duplicates, duplicates, imbalance (C06, C08) | `poisonlens/demo/content.py` |
| Trigger mining (C11): rare words / cell values / image corner patches that almost always carry one label | `poisonlens/demo/content.py`, `pipeline.py` |
| Poison detection: out-of-fold logistic-regression label agreement (confident-learning rule) + Isolation Forest | `poisonlens/demo/detect.py` |
| Tiers (keep / down-weight / quarantine), sanitized CSV export, risk score, hash-chained ledger seal | `poisonlens/demo/pipeline.py` |

Demo shortcuts, to be replaced by Phases 4-10: jobs run in-process (not in the isolated worker), the
scan is synchronous (no SSE progress), the detector is a single linear probe instead of the
training-dynamics families, and the risk blend uses the provisional `demo.*` weights in
`docs/CONFIG.md`. Uploads over `demo.max_records` (20 000) are analysed on a random sample.

## Samples (planted problems, `poisonlens/demo/samples.py`)

Results on the dev machine (`tests/unit/test_demo.py` asserts the thresholds):

| Sample | Planted | Verdict | Planted records flagged | Quarantine precision |
| :--- | :--- | :--- | :--- | :--- |
| `loans_poisoned.csv` | 90 flips + 40 `referral_code=ZX-77` backdoor, formulas, PII | likely poisoned | 95% (backdoor 100% quarantined) | 95% |
| `reviews_poisoned.csv` | 70 flips + 35 `cf` trigger, injection, API key | likely poisoned | 100% | 98% |
| `shapes_poisoned.zip` | 28 patched images relabelled `circle` | likely poisoned | 100% quarantined | 64% |
| `loans_clean.csv` | nothing | clean | — | — |

Unsafe uploads stop before parsing: a zip-slip archive (F03), an executable renamed `.xlsx` (F01)
and a pickle (F07, never unpickled) all return `unsafe_file`.
