# PoisonLens v2 — Phase-Wise Build Plan (for Claude Code)

**Read first:** `POISONLENS_V2_SPEC.md` is the source of truth for behavior, stage names, check IDs, endpoint names and design. This file is the execution order. If the two disagree, stop and ask the user.

---

## Rules of Engagement

1. **Work one phase at a time.** Do not start phase N+1 until every gate in phase N passes. Commit after each phase: `phase-N: <summary>`.
2. **Inspect before changing.** This plan was written from the README, not the code. Phase 0 reconciles the plan with the real repo. If actual file or module names differ, use the real ones and note the mapping in `docs/MIGRATION_NOTES.md`.
3. **Never fabricate results.** No hard-coded metrics, no fixture data presented as live output, no "demo mode". Every number shown in the UI must come from an artifact produced by a real run.
4. **Untrusted input discipline.** Uploaded files are hostile. Never `pickle.load`, `torch.load` (without `weights_only=True`), `eval`, or `yaml.load` on user data. Never extract an archive without the safety layer. Never render user content as HTML.
5. **Windows must work.** The owner develops on Windows/PowerShell. Use `pathlib`, avoid POSIX-only APIs without a fallback, and include PowerShell commands in docs.
6. **Tests are part of every phase.** Add tests in the same phase as the code. Keep the whole suite green. Replace the "40 passed" README badge only with the real count at the end.
7. **Small, typed, documented.** Type hints, docstrings on public functions, `ruff` + `mypy` (non-strict initially) clean for new code.
8. **Stop and ask** if: a gate cannot be met, a dependency needs a paid service, a design choice would change the spec, or something destructive (deleting user data outside this plan) is needed.
9. **Config over constants.** All thresholds named in the spec live in `poisonlens/core/config.py` (pydantic models) with the spec's defaults.

---

## Target Layout (end state)

```
PoisonLens/
├── poisonlens/
│   ├── core/        schemas.py config.py errors.py paths.py events.py logging.py
│   ├── ingest/      upload.py sniff.py archive.py limits.py sandbox.py worker.py
│   ├── adapters/    base.py registry.py tabular.py spreadsheet.py jsonfam.py columnar.py
│   │                statpkg.py arrays.py database.py xmlrec.py image_set.py audio_set.py
│   │                text_set.py mlnative.py hfdataset.py serialized.py
│   ├── security/    engine.py findings.py checks/ (f01_… f14_…, c01_… c11_…)
│   ├── quality/     duplicates.py leakage.py labels.py outliers.py triggers.py provenance.py
│   ├── features/    tabular.py text.py image.py audio.py cache.py
│   ├── probe/       models.py chunking.py trainer.py dynamics.py signals.py budget.py sketch.py
│   ├── detect/      trajectory.py heldout.py representation.py fusion.py estimate.py reasons.py risk.py
│   ├── mitigate/    tiers.py canary.py export.py
│   ├── audit/       ledger.py merkle.py sign.py verify.py cli.py
│   ├── report/      builder.py pdf.py templates/
│   ├── pipeline/    orchestrator.py stages.py cli.py
│   └── bench/       attacks/ make_corpus.py validate.py   # DEV ONLY, not imported by backend
├── backend/         main.py routes/ jobs.py sse.py security.py storage.py schemas.py
├── frontend/        src/ (see Phase 11)
├── data/            scans/ (gitignored)
├── tests/           unit/ integration/ e2e/ corpus/
├── docs/            MIGRATION_NOTES.md ARCHITECTURE.md SECURITY.md
└── configs/         scan_default.yaml  scan_quick.yaml  scan_deep.yaml
```

---

## Phase 0 — Repo Audit & Demo-Flow Removal

**Goal:** a clean base with the old demo flow gone and the useful parts preserved.

**Tasks**
1. Create branch `v2-upload-first`. Run the existing test suite; record the baseline in `docs/MIGRATION_NOTES.md`.
2. Map the real repo to the target layout. List every module under `poisonlens/`, `backend/`, `frontend/src/` with a keep / move / rewrite / delete decision.
3. **Delete from the product (code, routes, UI, docs):**
   - Judge Demo Mode and all offline fixtures used to replay results.
   - Preset system: `configs/attack_*.yaml`, `clean_baseline.yaml`, `/api/presets`, preset allowlist, "start run from preset".
   - CIFAR-10 auto-download/subset creation used by the pipeline.
   - `/api/benchmarks`, the Scoreboard tab, hard-coded benchmark tables in frontend code.
   - `/api/runs/{id}/audit/simulate-tamper` and the "Simulate Tampering" button.
4. **Move, don't delete:** `poisonlens/attacks/` → `poisonlens/bench/attacks/`. It stays for validating detectors (Phase 12) and must not be imported by `backend/` or `poisonlens.pipeline`. Add a test that fails if it is.
5. **Keep for reuse:** `models/SmallResNet`, `training/` per-sample logging hooks, `detect/` trajectory scoring + MAD, `mitigate/` soft quarantine + CanaryGuard, `audit/` hash chain + CLI, `backend/security.py` regex/path guards.
6. Fix any test-file naming inconsistency between README and repo (README lists both `test_mitigate.py` and `test_mitigation.py`).
7. Add `docs/MIGRATION_NOTES.md` with the keep/move/delete table.

**Gate 0**
- `pytest` passes for retained modules; tests for deleted features are removed, not skipped.
- `rg -n "demo|preset|simulate-tamper|cifar" backend frontend/src poisonlens/pipeline` returns nothing (except documented, intentional uses in `bench/`).
- Backend starts; frontend builds (`npm run build`) with the old tabs removed.

---

## Phase 1 — Core Schemas, Config, Storage Layout

**Goal:** shared types and the on-disk contract every later phase depends on.

**Tasks**
1. `core/schemas.py` (pydantic v2):
   - `Modality` enum: `tabular | text | image | audio | mixed`.
   - `Severity` enum: `critical | high | medium | low | info`.
   - `Finding {id, check_id, severity, title, detail, evidence, location, owasp_refs[], cwe[], remediation}`.
   - `DatasetProfile {format, modality, n_records, columns[], label_candidates[], label_chosen, splits, class_hist, capabilities}`.
   - `Capabilities {labels: bool, security: bool, quality: bool, probe: bool, detect: bool, reasons: dict}`.
   - `StageResult {stage, status, started_at, ended_at, artifacts: dict[name, sha256], warnings[]}`.
   - `ScanState {scan_id, status, current_stage, profile, config, stage_results, verdict?}`.
   - `Tier` enum with weights 1.0 / 0.20 / 0.0.
2. `core/config.py`: `ScanConfig` with every default named in the spec (limits, K=4 chunks, 2 trained per epoch, epochs per profile, seeds, canary 3.0 pts / class 10 pts, fusion weights, thresholds, sketch threshold 200 000, tier budgets, risk-score weights). Load from `configs/scan_{quick,default,deep}.yaml`; validate with pydantic; unknown keys are errors.
3. `core/paths.py`: `ScanPaths(scan_id)` exposing `root, upload, sandbox, canonical, features, dynamics, results, audit, export`. Regex-validate `scan_id` (`^[a-zA-Z0-9_\-]{8,64}$`) and resolve every path under `data/scans/`.
4. `core/events.py`: `ProgressEvent {scan_id, stage, kind: stage_start|progress|log|metric|stage_end|error, payload, ts}` and a file-backed append-only `events.jsonl` per scan (so SSE can replay).
5. `core/errors.py`: typed exceptions (`UnsafeFileError`, `UnsupportedFormatError`, `LimitExceededError`, `ConfigError`).

**Gate 1**
- Unit tests: config defaults match the spec values; path traversal attempts (`../`, absolute, encoded) raise; schema round-trips JSON.
- `python -c "from poisonlens.core.config import ScanConfig; print(ScanConfig())"` works.

---

## Phase 2 — Secure Ingestion (S0)

**Goal:** accept any file safely; nothing parsed in the API process.

**Tasks**
1. `ingest/upload.py`: resumable upload manager. `init(filename, size)`, `put_part(n, bytes)`, `complete()` → verifies part count/size, assembles to `upload/original.<ext>`, computes SHA-256 streaming. Reject names with NUL/bidi/path separators; store under a generated name, keep original name only in metadata.
2. `ingest/sniff.py`: signature table (ZIP `PK`, gzip `1f8b`, bz2, xz, 7z, tar ustar at 257, Parquet `PAR1`, HDF5, SQLite header, OLE2, PDF, PE `MZ`, ELF, Mach-O, PNG/JPEG/GIF/BMP/TIFF/WebP, WAV/FLAC/OGG/MP3, pickle protocol bytes, NPY magic). Returns `SniffResult {kind, confidence, claimed_ext, mismatch}`. Distinguish OOXML (`xlsx`) from plain ZIP by inspecting `[Content_Types].xml`.
3. `ingest/limits.py`: all limits from `ScanConfig`.
4. `ingest/archive.py`: streaming safe extractor for zip, tar(.gz/.bz2/.xz), 7z (via `py7zr`, optional). Enforce: entry count cap, per-entry and total uncompressed caps, compression ratio cap, nesting depth ≤3, reject absolute paths / `..` / drive letters / symlinks / hardlinks / device files, normalize and sanitize names, case-insensitive collision detection (Windows). Emit F02/F03/F04 findings rather than only raising.
5. `ingest/worker.py`: run parse jobs in a child process (`multiprocessing` spawn). Windows watchdog using `psutil` (memory, wall-clock, CPU-time) that kills on breach; POSIX adds `resource.setrlimit`. Child gets no network use (do not import networking modules; on Linux optionally unshare/no-network if available). Return results via a results file, not shared memory.
6. Append `SCAN_STARTED`, `FILE_ACCEPTED/REJECTED` entries through the existing ledger API (extend in Phase 9, but call a stub now).

**Gate 2** (tests under `tests/unit/test_ingest_*.py`, fixtures built in-test, never committed as real malware)
- Zip-slip archive rejected with F03 critical.
- Zip bomb (generate 1 GB of zeros compressing to ~1 MB) stops at the ratio/total cap without exhausting memory.
- Symlink member rejected. Nested depth 4 rejected.
- File named `data.csv` containing a PE header produces F01 mismatch.
- Worker watchdog kills a deliberately infinite/oversized parse job within the wall-clock limit on Windows and Linux.
- Resumable upload: out-of-order parts, duplicate part, wrong size, wrong final hash all handled.

---

## Phase 3 — Universal Adapters (S1)

**Goal:** every supported format becomes the Canonical Dataset Representation (CDR).

**Tasks**
1. `adapters/base.py`: `DatasetAdapter` ABC:
   `can_handle(sniff) -> float`, `inspect(path, cfg) -> DatasetProfile` (cheap, sampled), `load(path, profile, selection) -> CDR` (streaming), plus `iter_chunks(chunk_rows)`.
   CDR = `manifest.parquet` + modality payload (`features_raw.parquet` for tabular/text-in-column; files + `payload_ref` for image/audio/blob text).
2. `adapters/registry.py`: ranks adapters by `can_handle`; ties go to the more specific adapter.
3. Implement adapters (use `defusedxml` for any XML; `openpyxl` read-only, `data_only=False` to *see* formulas for F10; never execute macros):
   - `tabular.py` (CSV/TSV/TXT/PSV + compressed singles): encoding detection (`charset-normalizer`), delimiter sniff, streaming via pandas `chunksize` or polars if installed.
   - `spreadsheet.py` (xlsx/xlsm/xls/ods): sheet list in profile; multi-sheet selection; hidden/very-hidden sheet metadata exposed for F08.
   - `jsonfam.py` (json/jsonl/ndjson): record array detection, flatten with depth cap and key-explosion cap.
   - `columnar.py` (parquet/feather/arrow/orc/avro): batch streaming with `pyarrow` (+`fastavro`).
   - `statpkg.py` (sav/dta/sas7bdat via `pyreadstat`): value labels → label names.
   - `arrays.py` (npy/npz/h5/mat v7.3): `allow_pickle=False`; user maps arrays to X/y; shape-based modality guess (N×H×W×C → image).
   - `database.py` (sqlite/db): read-only, `immutable=1`, `set_authorizer` denying everything except SELECT/READ; list tables; user selects.
   - `xmlrec.py`: pick record element; `defusedxml` only.
   - `image_set.py`: layouts folder-per-class, `labels.csv`, COCO JSON, YOLO txt, Pascal VOC; Pillow with `MAX_IMAGE_PIXELS` cap; `Image.verify()` then reload.
   - `audio_set.py`: wav/flac/ogg/mp3 via `soundfile` (+ optional ffmpeg), manifest or folder labels.
   - `text_set.py`: per-document class folders, jsonl `text`, CoNLL-style.
   - `mlnative.py`: CIFAR batches, MNIST IDX, TFRecord record-level parse (no TF requirement), Hugging Face dataset dirs (`dataset_info.json` + Arrow).
   - `serialized.py`: **scan-only** adapter for pkl/joblib/pt/pth; returns a profile with `capabilities.probe=False` and no loader.
4. `profile` logic: modality detection, label-candidate ranking (name heuristics + cardinality + dtype), split column detection, class histogram, null/cardinality stats, `Capabilities` computation with human-readable reasons.
5. Persist `canonical/manifest.parquet`, `profile.json`; emit events.

**Gate 3**
- A corpus fixture generator (`tests/corpus/make_fixtures.py`) builds a tiny valid dataset in **every** format listed in the spec table (CSV, TSV, XLSX with 2 sheets + one hidden, XLS, ODS, JSON, JSONL, Parquet, Feather, ORC, Avro, SAV, DTA, NPY, NPZ, HDF5, SQLite, XML, ZIP/TAR/TGZ/7z of image folders, COCO, YOLO, VOC, audio zip, text corpus, CIFAR-batch, IDX, HF dir, pickle).
- Parametrized test: each fixture → correct modality, record count, label candidates, and a loadable CDR. Unsupported/optional-dependency cases skip with an explicit reason and are listed in the test report.
- Pickle fixture yields profile with `probe=False` and is never loaded (assert via a monkeypatched `pickle.load` that raises).
- Unlabeled CSV → capabilities show labels=False with a reason.

---

## Phase 4 — Security Engine & Checks (S2)

**Goal:** the Security Check Catalogue from the spec, as plugins.

**Tasks**
1. `security/findings.py` + `security/engine.py`: check registry (`@register_check(id, applies_to, severity_default, refs)`), runner with per-check timeout and error isolation (a crashing check yields an `info` finding "check failed", never kills the scan), dedupe, severity sorting, and a `halt_on_critical_file` policy (F03, F07, F06 stop *further parsing*, still produce findings and a report).
2. Implement F01–F14 (file-level) and C01–C11 (content-level) exactly as in the spec table. Notes:
   - **F07:** use `pickletools.genops` only; flag `GLOBAL/STACK_GLOBAL/REDUCE/INST/OBJ/NEWOBJ` that resolve to blocklisted modules (`os, posix, nt, subprocess, builtins eval/exec/compile/open, socket, shutil, sys, importlib, ctypes, pty, runpy`). For `.pt/.pth`, open as ZIP and scan `data.pkl`. Without a clean opcode scan, treat as high risk. Keras `.h5`: flag Lambda layers in `model_config`.
   - **F10:** detect leading `= + - @ \t \r`, `HYPERLINK(`, `cmd|`, `DDE`, `@SUM(` style; for xlsx read formula text, not cached values.
   - **F11:** inspect `sqlite_master` for triggers/views/virtual tables; no `load_extension`.
   - **F14:** URL-list detector (≥80% of a column matches URL regex) → high finding; **no network calls**.
   - **C01:** regex + validators: Luhn (cards), Verhoeff (Aadhaar), PAN pattern, IBAN mod-97, email, phone, IPv4/6, SSN. Report counts and column locations; **never store raw matches** in findings (store masked samples).
   - **C03:** pattern list for instruction-override/jailbreak phrases, Unicode tag block, zero-width, homoglyph/mixed-script heuristics, base64 blob length threshold; sample text columns (bounded rows) for large data.
   - **C06/C07/C08/C09/C10/C11:** these are implemented in Phase 5 modules; the security checks call them and convert results to `Finding`s so there is a single findings list.
3. Each check has: unit test with a positive and negative fixture, severity, OWASP/CWE refs as in the spec.
4. Persist `results/findings_security.json`; append `SECURITY_FINDING` ledger entries.

**Gate 4**
- A "known-bad" fixture set (generated in tests): pickle with `os.system` GLOBAL, xlsm with macro stub, xlsx with `=HYPERLINK(...)` and `cmd|` cells, SQLite with a trigger, XML with DOCTYPE entity bomb, image with trailing bytes + EXIF payload, text with Unicode tag characters and "ignore previous instructions", CSV of PII incl. valid Aadhaar and Luhn card, URL-only CSV.
- Each produces exactly the expected check ids and severities; clean fixtures produce none above `info`.
- Critical F07 halts parsing and the pipeline reaches Seal with verdict `Unsafe File`.

---

## Phase 5 — Quality & Poison-Forensics (S3)

**Goal:** the no-training checks from spec S3.

**Tasks**
1. `quality/duplicates.py`: exact hash groups; MinHash+LSH (`datasketch`) for text; pHash/dHash (`imagehash`) with Hamming radius for images; rounded-row hash for tabular; conflicting-label groups. Chunked / memory-safe.
2. `quality/leakage.py`: cross-split duplicate-group overlap.
3. `quality/labels.py`: label normalization, fuzzy class-name merge candidates (`rapidfuzz`), tiny-class flags, imbalance ratio.
4. `quality/outliers.py`: MAD/IQR, impossible-value rules, isolation forest (tabular), image stats (size/aspect/brightness).
5. `quality/triggers.py`: *text* n-gram purity mining (support ≥ max(10, 0.1% of N), purity ≥ 0.98, document frequency outside the class below a threshold); *tabular* single value and pair purity with multiple-testing correction; *image* per-class mean-image difference + recurring corner/patch frequency (4 corners and a grid of patches, perceptual comparison). Output ranked `trigger_candidates.json` with example record ids.
6. `quality/provenance.py`: burst detection (time/source/id columns), source concentration, missing provenance flags.
7. All results → `Finding`s and `results/findings_quality.json`, `dup_groups.parquet`.

**Gate 5**
- Use `bench/attacks` to create poisoned versions of small fixtures (BadNets patch images, rare-token text, single-feature tabular trigger, label flips, injected duplicates with conflicting labels). Assert: trigger miner ranks the planted trigger in its top-3; conflicting-duplicate check finds all planted groups; clean fixtures produce no `high` trigger candidates at default thresholds (false-positive guard).
- Memory test: 1M-row synthetic CSV processed without exceeding the configured RAM budget.

---

## Phase 6 — Feature Cache & Fast Probe Training (S4)

**Goal:** the Cyclic Coverage Chunking trainer and all 11 signals.

**Tasks**
1. `features/*`: build and memory-map feature caches per modality exactly as in spec §4.1. `cache.py` writes `features/X.npy` (float16/32 memmap) + `meta.json` with a content hash so reruns reuse the cache. Text: TF-IDF → TruncatedSVD(256). Tabular: imputation, capped one-hot, hashing trick, quantile scaling. Image: downscale to 32 or 64; optional frozen-embedding path only if weights are available offline, otherwise fall back to scratch. Audio: log-mel 64 bins fixed crop.
2. `probe/models.py`: `TabularMLP`, `FeatureMLP`, `SmallResNet` (reuse), `AudioCNN`; each exposes `forward(x) -> logits` and `penultimate(x) -> h`.
3. `probe/chunking.py`: **Cyclic Coverage Chunking**
   - `make_chunks(y, features, K, seed)`: stratify by class, then by k-means cluster (MiniBatchKMeans on cached features, `n_clusters` = min(32, N/200)); assign round-robin so each chunk mirrors class and cluster proportions; rare classes (<K samples) are placed in every chunk.
   - `rotation_schedule(E, K, trained_per_epoch)`: deterministic schedule where each chunk is trained exactly `E * trained_per_epoch / K` times (assert divisibility or distribute remainder evenly); returns boolean `train_mask[E, K]`.
   - Per-seed schedules differ by a seeded permutation of chunk order.
4. `probe/trainer.py`: for each seed, for each epoch: (a) gradient steps over samples of the epoch's trained chunks only (batch size by profile, AdamW, one-cycle LR, label smoothing off); (b) **full-dataset forward scoring** in `torch.inference_mode()` with large batches, recording per sample: `pred`, `p_true`, `loss`, `margin`, logits for the true class and max-other, and `in_train[e, i]`; (c) at epochs 2–3 record EL2N; (d) store penultimate features at the last epoch (float16 memmap). Handle class-count 2…1000, tiny datasets (fallback to K=2 or plain training with a recorded warning).
5. `probe/dynamics.py`: write `dynamics/dynamics.npz` (memmap-backed arrays shaped `(seeds, E, N)`), median-aggregate across seeds.
6. `probe/signals.py`: compute the 11 signals from dynamics:
   1 first-correct epoch · 2 forgetting events · 3 loss variance · 4 confidence/variability · 5 AUM · 6 EL2N · 7 gradient-norm proxy (**SSN**: after epoch 3 compute it only for the top 30% by cheap-signal suspicion) · 8 held-out agreement gap (uses `in_train` mask) · 9 kNN label disagreement (k=15, `faiss` if present else `sklearn` ball-tree/`pynndescent`) · 10 spectral-signature score per class · 11 activation-cluster separation per class. Save `signals.parquet`.
7. `probe/budget.py`: time-boxing and early stop (Spearman ≥ 0.98 for 2 consecutive epochs, after min epochs); emit `metric` events (loss/acc per epoch, samples/s, chunk rotation, ETA).
8. `probe/sketch.py`: for N > threshold, stratified sketch sampling (oversample low-support classes and feature-space outlier regions), then score the rest by forward pass + kNN propagation; mark `propagated=True` per record.
9. Determinism: seed everything; same config + same data ⇒ identical `signals.parquet` hash on CPU.

**Gate 6**
- Unit tests: chunk stratification (class proportions within ±1 sample per chunk), rotation exactness (each chunk trained the expected number of times), `in_train` mask matches the schedule, no sample missing a score in any epoch.
- Speed test (CPU): on a 10k-record tabular fixture and a 10k-image 32×32 fixture, CCC epoch time is measurably lower than full-data training for the same number of epochs; record the numbers in `docs/PERF.md` (measured, not estimated).
- Determinism test (two runs, equal hash).
- Signal sanity test on a planted label-flip fixture: mean signal values for flipped records differ from clean in the expected direction (later first-correct, more forgetting, lower AUM).

---

## Phase 7 — Detection, Fusion & Verdict (S5)

**Goal:** turn signals into per-record scores, a contamination estimate, a risk score and a verdict.

**Tasks**
1. `detect/trajectory.py`, `heldout.py`, `representation.py`: each reads `signals.parquet` and returns a family score in [0,1] using per-signal (and per-class where noted) median/MAD z → rank → logistic.
2. `detect/fusion.py`: noisy-OR `1 − Π(1 − w_f·s_f)` with weights from config; `votes` = families above `vote_threshold`; keep per-family scores in the output.
3. `detect/estimate.py`: two-component mixture (Beta or Gaussian on logit scores) → ε̂ with bootstrap range; fallback knee detection; clip to [0.5%, 15%].
4. `detect/reasons.py`: rule-based explanations using the top contributing normalized signals; always include the concrete numbers.
5. `detect/risk.py`: Poison Risk Score 0–100 = weighted blend of ε̂, family agreement, label-noise excess over baseline, trigger-candidate strength, security-finding severity (weights in config); verdict thresholds; attach coverage notes (labels missing, sketch used, modality-specific caveats).
6. Persist `results/scores.parquet`, `results/risk.json`.

**Gate 7**
- On `bench`-generated poisoned fixtures (Phase 12 builds the full corpus; here use a small set): fused detector must beat the best single family on at least label-flip and patch-backdoor fixtures in F1 at the planted rate; ε̂ within ±50% relative of truth for flip rates 5–10%; verdict `Clean` on clean fixtures with false-positive rate documented.
- If any target is missed, do **not** tune on the test fixtures. Report the numbers and stop for the user's decision.

---

## Phase 8 — Sanitize, Canary Guard, Export (S6)

**Tasks**
1. `mitigate/tiers.py`: adaptive tiers as in the spec (Tier 3 = top `min(ε̂,10%)` AND (votes ≥ 2 OR extreme z > 6); Tier 2 = next `min(2ε̂, 15%)`; rest Tier 1). Output `tiers.parquet {record_id, tier, weight, fused, votes, reasons}`. Support user overrides (applied after computation, recorded).
2. `mitigate/canary.py`:
   - Build canary from lowest-risk, highest-agreement labeled records, stratified, size `min(500, 5%)`, ≥20/class where possible; or load a user-supplied trusted holdout (validated to match the schema and label space).
   - Verification: train two probes with identical seeds/config on non-canary data — original weights vs. sanitized weights — evaluate accuracy, macro-F1 and per-class accuracy on the canary.
   - Breach rule: accuracy drop > 3.0 pts **or** any class drop > 10 pts → relax (halve Tier 3/Tier 2 budgets) → retry up to 3 times → else rollback (all Tier 1, `rollback=True`).
   - `results/canary.json` stores every attempt.
3. `mitigate/export.py`: format-preserving export:
   CSV/TSV/JSONL/Parquet/XLSX writers; archive datasets rebuilt as ZIP excluding quarantined members; `sample_weights.csv`; `quarantine/` (records + reasons, same format); optional formula neutralization and image metadata stripping; each export file hashed and logged. Exports are written to `export/` and never overwrite the upload.
4. Edge cases: no-label datasets skip canary and tiers by score (unlabeled mode exports only dedup/outlier-based quarantine, clearly marked).

**Gate 8**
- Canary logic tests with synthetic scenarios: harmless sanitization passes; a deliberately over-aggressive tiering triggers relax → retry → rollback with the right attempt log.
- Export round-trip: re-ingest each exported file through Phase 3 adapters; record counts equal `N − |Tier 3|`; weights file aligns by `record_id`.
- Overrides change the export and are present in `tiers.parquet`.

---

## Phase 9 — Audit Ledger & Report (S7)

**Tasks**
1. Extend `audit/ledger.py`: canonical JSON (`json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`), `H_i = SHA256(H_{i-1} || canonical_json(payload_i))`, genesis hash constant, entry fields `{i, ts, type, payload, prev, hash}`. Entry types per spec. Append is atomic (write temp + fsync + rename or file lock) and process-safe.
2. `audit/merkle.py`: Merkle root over all Tier 1 decisions; `prove(record_id)` and `verify_proof`.
3. `audit/sign.py` (`cryptography` Ed25519): generate key on first use under `data/keys/`; sign head hash at `SCAN_SEALED`; embed public key.
4. `audit/verify.py` + `audit/cli.py`: `python -m poisonlens.audit verify <scan_dir>` returns exit code 0/1 and the first broken index; also verifies artifact hashes referenced in `STAGE_COMPLETED` entries and the Merkle root.
5. `report/builder.py` + `report/pdf.py`: `report.json` and `report.pdf` (ReportLab or WeasyPrint; pick one that installs cleanly on Windows — prefer ReportLab): executive summary, verdict, risk score, contamination estimate with range, findings by OWASP category, top flagged records, canary result, limitations (from spec §8), ledger head hash and signature.
6. `pipeline/orchestrator.py` + `stages.py`: wire S0→S7 with resume-from-last-completed-stage, per-stage artifact hashing, event emission, cancellation, and error → partial report. `pipeline/cli.py`: `python -m poisonlens.pipeline scan <file> --profile standard --label-column y`.

**Gate 9**
- Tamper tests (inside tests only): modify one byte in any ledger line, reorder two lines, delete a line, alter an exported artifact → verification fails at the correct index.
- Merkle inclusion proof verifies for random Tier 1 records and fails for altered ones.
- Full CLI run on three fixtures (clean CSV, poisoned images ZIP, unsafe pickle) completes end-to-end with a sealed ledger and a PDF.
- Resume test: kill the process mid-S4, rerun, it resumes from S4 and the ledger stays valid.

---

## Phase 10 — Backend API & Job Runner

**Tasks**
1. `backend/main.py` + `routes/`: implement the endpoint table in spec §6; remove all v1 run/preset endpoints.
2. `backend/jobs.py`: scan job queue (single worker process by default, `max_concurrent_scans` config), persisted state in `ScanState` JSON; scans run `poisonlens.pipeline` in a subprocess, never in the API process. Cancellation via `DELETE`/`POST cancel`.
3. `backend/sse.py`: Server-Sent Events from `events.jsonl` tail with `Last-Event-ID` replay; heartbeat every 15 s; `/status` as polling fallback.
4. `backend/storage.py`: scan listing, deletion (secure remove of the scan directory), disk quota enforcement.
5. `backend/security.py`: keep and extend the regex/path guards; add artifact allowlist (`report.json`, `report.pdf`, `findings_*.json`, `tiers.parquet` via record API only, `export/*`, `audit/ledger.jsonl`); `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`; strict CORS origins from config; upload rate/size limits; optional `X-API-Key`.
6. Records API: server-side pagination/filter/sort over `scores.parquet`/`tiers.parquet` via `pyarrow` (no full load for large N); record preview endpoints return **sanitized** payloads (text escaped and truncated, images re-encoded to PNG thumbnails, tabular rows as JSON).
7. OpenAPI: complete request/response models; export `openapi.json` and generate TypeScript types for the frontend (`openapi-typescript`).

**Gate 10**
- `tests/integration/test_api_*.py` via `httpx` + FastAPI `TestClient`: upload (multi-part) → configure → start → SSE events observed → results endpoints → export → verify; plus negative tests (traversal in `scan_id` and artifact name, oversize upload, wrong API key, unknown artifact, deleting a running scan).
- Large-N record pagination test (1M-row synthetic `scores.parquet`) returns in under 500 ms per page (measure and record).
- No endpoint returns raw uploaded bytes inline.

---

## Phase 11 — Frontend (React 19 + TypeScript)

**Goal:** the dashboard in spec §7.

**Tasks**
1. Scaffold/clean: remove old tabs. Dependencies: `react-router`, `@tanstack/react-query`, `@tanstack/react-table`, `@tanstack/react-virtual`, `zustand`, `tailwindcss`, `uplot` (large charts) and `recharts` (small charts), `vitest`, `@testing-library/react`, `@playwright/test`.
2. **Design tokens** in `src/styles/tokens.css` (CSS variables for both themes, using exact values from spec §7.3); Tailwind config maps to tokens. Fonts: Inter + JetBrains Mono (self-hosted).
3. **App shell:** `Header` (logo, Scans menu, Docs, Settings, Theme toggle), **`PipelineStepper`** (8 steps: Upload · Inspect · Security · Quality · Probe · Detect · Sanitize · Seal; states pending/active/done/failed/skipped; driven by `/status` + SSE; clickable for completed steps).
4. **Routes:** `/` (Upload + recent scans), `/scans/:id/inspect`, `/security`, `/quality`, `/probe`, `/detect`, `/sanitize`, `/seal`. The stepper navigates between them; unreached stages are disabled.
5. **Upload screen:** large dropzone (file or folder via `webkitdirectory` → zipped client-side with a streaming zipper such as `fflate`), 8 MB part upload with retry/resume, progress, SHA-256 (Web Crypto, streamed), supported-formats hint, recent-scans table.
6. **Inspect screen:** format/modality chips, schema table, label picker with class histogram preview, sheet/table picker, capability matrix card, profile selector with plain-language time guidance, **Start scan**.
7. **Security screen:** findings grouped by OWASP category, severity chips, expandable evidence/remediation, unsafe-file banner.
8. **Quality screen:** duplicate groups, leakage summary, class-balance chart, trigger-candidate cards.
9. **Probe screen:** live epoch chart (uPlot), chunk rotation strip, throughput + ETA, log tail.
10. **Detect screen:** risk gauge (flat), verdict, ε̂ range, family agreement bar, data-map scatter (server-sampled ≤ 20k points, canvas-rendered).
11. **Sanitize screen:** tier counts, canary card with rollback banner and attempt history, virtualized record explorer with filters and override actions (optimistic update + audit confirmation).
12. **Record drawer** with modality renderers (image, text with highlighted trigger/invisible characters, tabular with deviating cells, audio waveform/spectrogram) + 10-epoch sparkline + reasons.
13. **Seal screen:** ledger timeline, Verify button + result, head hash/signature (mono), export buttons.
14. States and quality: loading skeletons, empty states, error boundaries with retry, `aria-live` progress, keyboard navigation, focus rings, AA contrast; dark/light verified; responsive down to tablet.
15. **Security in the UI:** never `dangerouslySetInnerHTML`; all record text rendered as text nodes; CSP meta/headers documented in `docs/SECURITY.md`.

**Gate 11**
- `npm run build` and `npm run lint` pass; `vitest` component tests for stepper states, findings grouping, tier override flow.
- Playwright e2e (against the real backend with a tiny fixture): upload CSV → inspect → pick label → start → watch stepper advance → open a flagged record → export → verify ledger. Also e2e for an unsafe pickle upload showing the halted state and `Unsafe File` verdict.
- Manual checklist in `docs/UI_CHECKLIST.md` completed (screenshots of each screen in light and dark).

---

## Phase 12 — Validation Corpus & Honest Benchmark

**Goal:** prove (or honestly disprove) detector quality on formats beyond CIFAR.

**Tasks**
1. `bench/make_corpus.py`: using `bench/attacks`, generate poisoned and clean datasets and **write them as real files in multiple formats**:
   - Images: CIFAR-10 subset as ZIP (label flip 5/10%, BadNets 5%, blended 5%).
   - Tabular: UCI-style dataset (e.g., Adult or a synthetic equivalent) as CSV/XLSX/Parquet with label flips and a single-feature trigger.
   - Text: sentiment dataset as JSONL with rare-token triggers and label flips.
   - Audio: small speech-commands subset as ZIP with a click-trigger backdoor (if time permits; mark optional).
   - Add file-level attacks for Phase 4 (already in tests).
2. `bench/validate.py`: runs the full pipeline on the corpus; compares **single families vs. fusion**, loss-threshold and activation-clustering baselines (re-use existing implementations as comparators only); records precision/recall/F1 at the true poison budget, ε̂ error, canary outcomes, probe time per profile, and clean-accuracy change after sanitization (soft vs. hard deletion).
3. Output `docs/BENCHMARKS.md` with the real tables, hardware used, seeds, and the limitations observed. **Do not copy v1 numbers.** Do not tune thresholds on the corpus after seeing results without recording that as a separate, labeled step.
4. Update the UI "limitations" copy and the report templates to reflect measured behavior.

**Gate 12**
- `docs/BENCHMARKS.md` exists with reproducible commands and seeds; the benchmark script runs from a clean checkout.
- Any metric worse than v1 for the same attack is explicitly called out.
- Fusion is shown versus each single family; if fusion does not help, record that and stop for the user's decision.

---

## Phase 13 — Hardening, Docs, Release

**Tasks**
1. Security review pass: fuzz the adapters (`hypothesis` on malformed CSV/JSON/zip headers), run `bandit`, `pip-audit`, `npm audit`; fix or document each item in `docs/SECURITY.md`. Confirm no code path calls `pickle.load`, `torch.load(weights_only=False)`, `eval`, `exec` on user data (grep-based test).
2. Resource limits review on Windows and Linux; document the Docker profile (`Dockerfile`, `docker-compose.yml`: non-root, read-only root FS, tmpfs scratch, no network for the worker).
3. Rewrite `README.md` for v2: new concept, flow diagram, formats table, quickstart (Windows PowerShell + Linux), real benchmark numbers from Phase 12 only, API summary, limitations. Remove demo walkthrough and all v1-only claims. Update badges with real test counts.
4. `docs/ARCHITECTURE.md` (stage diagram, artifact contract), `docs/SECURITY.md`, `docs/FORMATS.md` (adapter notes, optional dependencies), `CHANGELOG.md`.
5. Packaging: `pyproject.toml` extras (`[full]`, `[audio]`, `[docs]`, `[dev]`), pinned minimum versions, optional-dependency detection reported by `/api/health`.
6. Final end-to-end smoke script `scripts/smoke.ps1` and `scripts/smoke.sh`.

**Gate 13 (Definition of Done)**
- Clean checkout → install → run backend + frontend → upload a CSV, an XLSX, a ZIP of images and a JSONL → all complete with sealed, verifiable ledgers and exports.
- All tests green (unit, integration, e2e); linting clean; README matches reality.
- No demo/preset code remains outside `bench/`.

---

## Dependency Summary

**Core:** `torch torchvision numpy pandas pyarrow scikit-learn scipy pydantic>=2 fastapi uvicorn[standard] httpx python-multipart pyyaml psutil cryptography charset-normalizer defusedxml openpyxl xlrd odfpy pillow imagehash datasketch rapidfuzz`

**Format extras:** `fastavro pyreadstat h5py py7zr soundfile polars (optional) faiss-cpu (optional) pynndescent`

**Reports/Dev:** `reportlab pytest pytest-cov hypothesis ruff mypy bandit pip-audit`

**Optional system tools (auto-detected, never required):** ClamAV (`clamd`), `yara-python`, `ffmpeg`.

**Frontend:** `react@19 typescript vite react-router @tanstack/react-query @tanstack/react-table @tanstack/react-virtual zustand tailwindcss uplot recharts fflate openapi-typescript vitest @testing-library/react @playwright/test`

---

## Per-Phase Checklist Template (Claude Code: copy into each phase's PR/commit message)

```
Phase N — <name>
[ ] Files created/changed listed
[ ] Tests added and passing (command + count)
[ ] Gate N criteria each verified (paste evidence)
[ ] No fabricated metrics, no demo data
[ ] Windows path/commands checked
[ ] docs/MIGRATION_NOTES.md or relevant doc updated
[ ] Open questions for the user (if any)
```
