# PoisonLens: find poisoned training data before your model learns it

[![Tests](https://img.shields.io/badge/pytest-511%20passed-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)]()
[![Backend](https://img.shields.io/badge/backend-FastAPI-009688.svg)]()
[![Audit](https://img.shields.io/badge/audit-SHA--256%20hash%20chain-orange.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()

Upload a training dataset. PoisonLens checks that the file is safe to open, finds records that look
**poisoned, mislabeled or backdoored**, and gives you back a **cleaned copy** with a
**tamper-evident audit trail** of every decision.

> **Status:** v2 rebuild on branch `v2-upload-first`. Phases 0–3 of the build plan are done (upload,
> safe ingestion, any-format reading). A **quick demo** runs the whole flow end to end today, with
> simplified stand-ins for the later stages. See [Roadmap](#roadmap).

---

## Quick start

Requires Python 3.10+ (developed on Windows 11 with Python 3.13).

```bash
python -m venv .venv
```

Activate it (`.venv\Scripts\activate` on Windows, `source .venv/bin/activate` on Linux/macOS), then
install CPU PyTorch and the project:

```bash
pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu
```

```bash
pip install -e ".[formats,dev]"
```

Start the demo (one server serves both the API and the page):

```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Open **http://127.0.0.1:8000/** and drop in a dataset, or click one of the samples.
API docs are at http://127.0.0.1:8000/docs.

Run the tests:

```bash
python -m pytest -q
```

> **Windows Smart App Control** can block brand-new native wheels. `pyarrow` is pinned `<24` and
> `pyreadstat` `<1.3.8` for that reason. If an import fails with *"An Application Control policy has
> blocked this file"*, retrying usually clears it; see `docs/MIGRATION_NOTES.md`.

---

## The demo

| Step | What happens |
| :--- | :--- |
| **Upload** | Chunked, hash-verified upload into an isolated scan folder. |
| **Safe ingest** | Real file type from magic bytes (an `.exe` renamed `.xlsx` is caught), archives expanded with path-traversal, zip-bomb and filename checks. Unsafe files stop here. |
| **Read any format** | 17 readers turn the upload into one canonical dataset and pick the label column. |
| **Content security** | Formula injection, personal data, leaked keys and tokens, prompt injection, script markup, invisible characters. |
| **Quality** | Exact duplicates, duplicates that disagree on the label, class imbalance. |
| **Backdoor triggers** | A rare word, cell value or image corner patch that almost always comes with one label. |
| **Poison detection** | A model predicts each record's label without seeing it; records it confidently disagrees with are suspects. Plus an outlier detector. |
| **Clean** | Each record is kept, down-weighted (0.2) or quarantined. The cleaned CSV escapes formula cells. |
| **Seal** | Risk score, verdict (*clean / suspicious / likely poisoned / unsafe file*) and a SHA-256 hash-chained ledger. |

Downloads per scan: `cleaned.csv`, `review.csv` (flagged records with reasons), `report.json`, `ledger.jsonl`.

### Sample datasets

Each sample has known, planted problems so you can check the result, not just look at it.
Numbers are from `tests/unit/test_demo.py` runs on the dev machine.

| Sample | Planted | Verdict | Caught |
| :--- | :--- | :--- | :--- |
| `loans_poisoned.csv` | 90 flipped labels, 40-row `referral_code=ZX-77` backdoor, formulas, PII | likely poisoned | 95% of bad rows flagged; backdoor 100% quarantined |
| `reviews_poisoned.csv` | 70 flipped labels, 35-row `cf` trigger word, prompt injection, API key | likely poisoned | 100% flagged; 98% of quarantined rows really bad |
| `shapes_poisoned.zip` | 28 images with a white corner patch relabelled `circle` | likely poisoned | all 28 quarantined (64% quarantine precision) |
| `loans_clean.csv` | nothing (control) | clean | no triggers |

A zip-slip archive, an executable disguised as a spreadsheet, and a pickle all come back
**unsafe file** before anything is parsed. Pickles are never unpickled.

### Demo shortcuts

The demo is honest about what it is not yet:

- Stages run in the server process, not the isolated worker the product uses.
- The scan is one synchronous request; the progress bar is animated, not live.
- Detection is a single linear probe, not the spec's training-dynamics families.
- Uploads over 20,000 records are analysed on a random sample.
- Risk weights are provisional (`demo.*` in `docs/CONFIG.md`).

Details: [docs/DEMO.md](docs/DEMO.md).

---

## Supported formats

| Kind | Formats |
| :--- | :--- |
| Delimited text | CSV, TSV, PSV, TXT (encoding and delimiter detected) |
| Spreadsheets | XLSX, XLSM, XLS, ODS (hidden sheets listed, formulas read as text) |
| JSON | JSON, JSONL (nested records flattened, depth and key caps) |
| Columnar | Parquet, Feather, ORC, Avro |
| Statistical | SPSS `.sav`, Stata `.dta`, SAS `.sas7bdat` |
| Arrays | NumPy `.npy` / `.npz`, HDF5 (object arrays never unpickled) |
| Database | SQLite (read-only, writes/ATTACH/extensions refused) |
| XML | via hardened `defusedxml` (entity bombs and XXE rejected) |
| Image sets | class folders, `labels.csv`, COCO, YOLO, VOC (pixel-bomb limit) |
| Audio / text sets | audio folders, text-document folders, CoNLL |
| ML-native | CIFAR binary batches, MNIST IDX, Hugging Face `datasets` folders |
| Archives | ZIP, TAR, TGZ, 7z, GZ (nested up to depth 3) |
| Scan only | pickle, joblib, PyTorch files: flagged, never loaded |

Not yet: TFRecord.

---

## Project layout

```
poisonlens/
├── core/        config (every threshold), schemas, scan paths, event log
├── ingest/      upload manager, file sniffing, safe archive extraction, isolated worker
├── adapters/    format readers + registry → canonical dataset (manifest/features parquet)
├── security/    check catalogue (F01–F14 file checks, C01–C11 content checks)
├── audit/       SHA-256 hash-chained ledger
├── demo/        quick-demo pipeline: content checks, detector, samples
├── detect/ mitigate/ training/ models/ eval/   v1 components, reworked in later phases
└── bench/       DEV ONLY: attacks, CIFAR-10 loader, archived v1 pipeline
backend/         FastAPI app: /api/health, /api/demo/*, demo page at /
frontend/        React 19 + Vite shell (the product UI arrives in Phase 11)
configs/         scan profiles: scan_quick / scan_default / scan_deep
docs/            spec, build plan, CONFIG.md, DEMO.md, MIGRATION_NOTES.md, v1 report
tests/           unit, integration, format corpus (35 generated fixtures)
```

Each scan lives in `data/scans/<scan_id>/` (`upload/`, `sandbox/`, `canonical/`, `results/`,
`audit/`, `export/`). Set `POISONLENS_DATA_DIR` to put it elsewhere.

---

## API (demo)

| Method | Path | Purpose |
| :--- | :--- | :--- |
| GET | `/` | Demo page |
| GET | `/api/health` | Service health |
| GET | `/api/demo/samples` | List sample datasets |
| GET | `/api/demo/samples/{name}` | Download a sample |
| POST | `/api/demo/scan` | Upload a file (multipart `file`) and get the report |
| POST | `/api/demo/scan-sample/{name}` | Scan a sample |
| GET | `/api/demo/scans/{scan_id}/download/{artifact}` | `cleaned.csv`, `review.csv`, `report.json`, `ledger.jsonl` |

The full upload-first API (resumable uploads, live progress, user overrides) is Phase 10.

---

## Security model

Uploads are untrusted. The code never calls `pickle.load`, `torch.load` without `weights_only`,
`eval` or `yaml.load`, and user content is never rendered as HTML (the demo page uses
`textContent` only). Scan IDs and paths are validated against traversal; downloads are
allow-listed. Every finding carries OWASP / CWE references and masked evidence only.

---

## Roadmap

From [docs/POISONLENS_V2_BUILD_PLAN.md](docs/POISONLENS_V2_BUILD_PLAN.md):

| Phase | Scope | Status |
| :--- | :--- | :--- |
| 0 | Remove v1 demo flow, move attacks to `bench/` | ✅ |
| 1 | Core schemas, config, storage, events | ✅ |
| 2 | Secure upload and ingestion (S0) | ✅ (Linux watchdog check deferred) |
| 3 | Universal format adapters (S1) | ✅ |
| — | Quick demo prototype | ✅ |
| 4–5 | Security engine, all checks, quality | next |
| 6–7 | Probe training, detection families | |
| 8–9 | Soft quarantine, canary guardrail, export, pipeline | |
| 10–11 | Product API and UI | |
| 12 | Validation against the v1 benchmark | |

---

## v1 benchmark (archived)

v1 was a CIFAR-10 research pipeline that scored samples by **training dynamics** (when a sample is
first learned, how often it is forgotten, loss variance, gradient norm, neighbour disagreement),
applied a 3-tier soft quarantine, and guarded retraining with a clean canary set. Its results are
archived in `bench_artifacts/v1_runs/` and `docs/v1/` and are **not claims about v2**. Highlights,
measured on a 10k-image CIFAR-10 subset with a small ResNet on CPU:

| Attack | Best defense | Result |
| :--- | :--- | :--- |
| Label flip 10% | PoisonLens trajectory + soft quarantine | attack success 72.5% → 44.5% |
| BadNets patch 5% | Activation clustering | F1 0.947, attack success 91.7% → 2.4% |
| Blended backdoor 5% | none effective | PoisonLens the only non-zero detector (F1 0.024) |

Soft quarantine recovered 3.8–5.1 points of clean accuracy over hard deletion. These ideas return
in Phases 6–8.

---

## License

MIT.

```bibtex
@software{poisonlens2026,
  author = {PoisonLens Research Team},
  title  = {PoisonLens: Training-Data Poisoning Detection and Mitigation via Training Dynamics and Cryptographic Auditing},
  year   = {2026},
  url    = {https://github.com/aryanhavkar23/Data_Posioning_teamTwoMuch}
}
```
