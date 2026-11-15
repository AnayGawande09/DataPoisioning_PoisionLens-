# PoisonLens v2 — Product & Technical Specification

> **Upload any dataset. Find out if it was tampered with. Get a clean version back, with a tamper-proof record of every decision.**

This document describes *what* PoisonLens v2 is, the end-to-end flow, and every technique used in each step (what it does and how). The companion file `POISONLENS_V2_BUILD_PLAN.md` describes *how to build it*, phase by phase.

---

## 0. What Changes From v1

| v1 (demo) | v2 (real product) |
| :--- | :--- |
| Platform generates a CIFAR-10 subset, injects its own poison, trains, then detects | **User uploads their own dataset**; we never generate or poison data inside the product |
| Images only (CIFAR-10, 32×32×3) | **Any dataset file**: CSV, Excel, JSON/JSONL, Parquet, archives of images/audio/text, NumPy, HDF5, SQLite, and more (Section 4) |
| Preset attack configs, "Judge Demo Mode", simulated tamper endpoint | **Removed from product.** Attack code moves to a dev-only `bench/` harness used purely to validate our detectors in CI |
| Detection = trajectory signals only | **Defense in depth**: file-level security audit → data-quality forensics → fast probe training → multi-detector fusion |
| Full-dataset training on fixed 10 epochs | **Cyclic Coverage Chunking** + cached features + time budgets for fast dynamics |
| Fixed 85/10/5 tier split | **Adaptive tiers** based on estimated contamination |
| Canary = 200 held-out CIFAR images | **Self-built trusted canary** from the user's own data (or a user-supplied trusted set) |
| 5 trajectory signals | **11 signals** across trajectory, held-out, and representation families |

**Kept from v1:** trajectory-dynamics idea, robust MAD scoring, 3-tier soft quarantine, canary guardrail with rollback, SHA-256 hash-chained audit ledger, FastAPI + React 19/TypeScript/Vite stack.

---

## 1. The End-to-End Flow (8 Stages)

```
 UPLOAD ─▶ INSPECT ─▶ SECURITY ─▶ QUALITY ─▶ PROBE ─▶ DETECT ─▶ SANITIZE ─▶ SEAL
   S0        S1         S2          S3         S4        S5        S6          S7
 receive   identify   OWASP &    duplicates, fast      fuse &     tier, canary  audit
 safely    + convert  file-level  leakage,   chunked   score      verify,       chain,
           to common  attacks     triggers,  training  records    export        report
           form                   label sanity
```

Each stage is a pure function of the previous stage's artifacts, writes its outputs to disk, emits progress events, and appends signed entries to the audit ledger. A scan can be resumed from the last completed stage.

| Stage | Id | Input | Output artifacts |
| :--- | :--- | :--- | :--- |
| S0 Upload | `ingest` | Raw bytes from the browser | `upload/original.*`, sha256, size, sniffed type |
| S1 Inspect | `inspect` | Original file | `canonical/manifest.parquet`, `canonical/features_raw.*`, `profile.json` |
| S2 Security | `security` | Original + canonical | `findings_security.json` |
| S3 Quality | `quality` | Canonical | `findings_quality.json`, `trigger_candidates.json`, `dup_groups.parquet` |
| S4 Probe | `probe` | Canonical | `features/*.npy`, `dynamics/dynamics.npz`, `signals.parquet` |
| S5 Detect | `detect` | Signals + representations | `scores.parquet`, `risk.json` |
| S6 Sanitize | `sanitize` | Scores | `tiers.parquet`, `canary.json`, `export/*` |
| S7 Seal | `seal` | Everything | `audit/ledger.jsonl`, `report.json`, `report.pdf` |

---

## 2. Stage-by-Stage Techniques

### S0 — Secure Upload & Ingestion

The uploaded file is untrusted input. Nothing is parsed in the API process.

| Technique | What it does | How |
| :--- | :--- | :--- |
| **Resumable chunked upload** | Lets users upload multi-GB datasets reliably | Browser sends 8 MB parts to `/api/uploads/{id}/parts/{n}`; server assembles, verifies per-part and final SHA-256 |
| **Size & quota limits** | Stops resource-exhaustion uploads | Configurable max size (default 2 GB), disk quota, per-IP rate limit |
| **Content-hash fingerprint** | Gives the dataset a permanent identity | SHA-256 of the original bytes; first entry of the audit ledger |
| **Magic-byte sniffing** | Detects files lying about their type | Compare extension vs. signature bytes vs. container structure; mismatch becomes a finding (polyglot / disguised file) |
| **Quarantine sandbox directory** | Keeps untrusted content away from the app | Stored under `data/scans/{id}/upload/`, random names, no execute bit, never served back raw |
| **Isolated worker** | Limits damage from a malicious parser exploit | All parsing runs in a child process with CPU-time, memory and wall-clock limits, no network, non-root (Docker profile where available) |

### S1 — Inspect & Convert (Universal Dataset Adapter)

Goal: turn *any* supported file into one **Canonical Dataset Representation (CDR)** so every later stage works the same way.

| Technique | What it does | How |
| :--- | :--- | :--- |
| **Adapter registry** | Picks the right reader per format | Each adapter declares `can_handle(sniffed_type)`; registry ranks by confidence |
| **Safe archive expansion** | Opens ZIP/TAR/7z without being attacked | Streaming extraction with entry-count, depth, total-bytes and ratio caps; rejects traversal, absolute paths, symlinks (details in S2 F02/F03) |
| **Modality detection** | Decides tabular / text / image / audio / mixed | Looks at column dtypes, file extensions inside archives, average string length, array shapes |
| **Label detection** | Finds the target column or label source | Heuristics: column names (`label`, `class`, `target`, `y`, `category`, `sentiment`), low-cardinality integer/string columns, folder-per-class layout, `labels.csv` manifest, COCO/YOLO/VOC annotation files. **The user always confirms** in the UI before continuing |
| **Schema profiling** | Summarizes the dataset | Row count, column types, null rates, cardinality, class histogram, split column detection (`train/val/test`) |
| **Canonical manifest** | One table describing every record | `manifest.parquet`: `record_id`, `source_file`, `sheet/row/offset`, `split`, `label_raw`, `label_idx`, `payload_ref` |
| **Capability matrix** | Tells the user what can be checked | No label → only security, quality, outlier and duplicate checks run; label-based poisoning detectors are shown as *disabled with reason* |

CDR payload storage per modality: tabular features go to `features_raw.parquet`; images, audio and text blobs stay as files with `payload_ref` pointers; large text columns go to a Parquet text column.

### S2 — Security Audit (File-Level and Content-Level)

Runs the **Security Check Catalogue** (Section 3). Every check yields zero or more **Findings**: `{id, severity, title, evidence, location, owasp_refs, cwe, remediation}`. Critical findings in file-level checks can **halt** the scan before any parsing of the dangerous content (for example, unsafe pickle).

### S3 — Quality & Poison-Forensics (No Training Needed)

Cheap statistical checks that catch many poisoning patterns and give the later stages context.

| Technique | What it does | How |
| :--- | :--- | :--- |
| **Exact duplicate detection** | Finds repeated records (amplified poison) | Hash of normalized payload; group by hash |
| **Near-duplicate detection** | Finds almost-identical records | Text: MinHash + LSH on shingles. Images: perceptual hash (pHash/dHash) + Hamming radius. Tabular: row hash after rounding numerics |
| **Conflicting-label duplicates** | Same content, different labels → strong poison/label-noise signal | Within each duplicate group, flag groups with >1 distinct label |
| **Cross-split leakage** | Test data present in train inflates metrics and hides backdoors | Compare duplicate groups across `split` values |
| **Label-space hygiene** | Typos / case variants / rare junk classes | Normalize and fuzzy-compare class names; flag classes with tiny support |
| **Trigger candidate mining** | Finds the trigger itself, not just poisoned records | *Text*: tokens / n-grams with high support, near-perfect class purity, and low corpus frequency otherwise. *Tabular*: single feature values or pairs with abnormal purity. *Images*: class-conditional recurring corner/patch patterns via per-class mean-image differences and patch frequency |
| **Shortcut-feature check** | A feature that perfectly predicts the label is suspicious | Mutual information / single-feature accuracy against the label |
| **Outlier & range checks** | Impossible or extreme values | Robust z-score (MAD), IQR, isolation forest on tabular; size/aspect/brightness stats on images |
| **Insertion-pattern check** | Poison is often added in a burst | If a timestamp/source/id column exists: detect bursts of records from one source or time window with abnormal class mix |

### S4 — Probe Training with Fast Dynamics (the Core Innovation)

A small, cheap **probe model** is trained on the user's data purely to *record how each sample is learned*. We do not need a good model; we need a faithful behavioral trace of every sample, quickly.

#### 4.1 Probe model per modality

| Modality | Feature cache (computed once) | Probe model |
| :--- | :--- | :--- |
| Tabular | Imputation → one-hot (capped cardinality) / hashing for high-cardinality → quantile scaling | 2-layer MLP (256→128) |
| Text | TF-IDF (1–2 grams) → TruncatedSVD (256-d). Optional *Deep* mode: small sentence-embedding model if available offline | MLP on cached features |
| Image | Downscale to 32×32 (Quick/Standard) or 64×64 (Deep). Two modes: **scratch** (SmallResNet, default for ≤50k images) and **frozen** (pretrained embedding cache + MLP head, default for >50k or if weights are available) | SmallResNet or MLP head |
| Audio | Log-mel spectrogram (64 bins, fixed crop) | Small CNN, or frozen embeddings |
| Mixed | Probe per modality; scores merged in S5 | — |

#### 4.2 Speed techniques ("unique chunking")

| Technique | What it does | How |
| :--- | :--- | :--- |
| **Frozen-Feature Cache (FFC)** | Makes epochs near-instant | Heavy preprocessing and embeddings are computed once and memory-mapped; epochs only touch tensors |
| **Cyclic Coverage Chunking (CCC)** *(core)* | Gets full-dataset dynamics at a fraction of the training cost | Split data into **K stratified chunks** (default K=4). Each epoch, *gradient updates* run on only a rotating subset (default 2 of 4 chunks), but **every sample is scored (forward-only, no_grad, large batch) after every epoch**. Rotation guarantees each chunk is trained on in exactly half the epochs. Backward passes (the expensive part) are halved or better; forward scoring is cheap |
| **Stratified-Cluster Chunks** | Keeps each chunk representative | Chunks are stratified by class **and** by k-means cluster of cached features, so no chunk is missing a data mode |
| **Held-out by construction** | Free cross-fitting | In epochs where a sample's chunk is *not* being trained, its prediction comes from a model that never saw it. We record `in_train_mask[epoch, sample]` and compute held-out signals (4.3 #8) without extra training |
| **Successive Suspicion Narrowing (SSN)** | Spends expensive signals only where needed | After epoch 3, samples with consistently low suspicion across cheap signals are excluded from the costly per-sample gradient-norm computation; only the top ~30% are tracked densely |
| **Micro-ensemble (3 seeds)** | Removes noise from short training | Three probes with different chunk orders/seeds; per-sample signals aggregated by **median** |
| **Adaptive epoch budget** | Stops when more epochs add nothing | Time-boxed profiles (below). Early stop when Spearman rank-correlation of the fused suspicion between consecutive epochs exceeds 0.98 for 2 epochs, after a minimum number of epochs |
| **Memory-budgeted streaming chunks** | Handles datasets bigger than RAM | CSV `chunksize`, Parquet row-groups, streamed archive members; chunk size chosen from a RAM budget; features written to memmap |
| **Sketch + Propagate** | Scales to millions of records | For N above a threshold (default 200k), dynamics are measured on a stratified **sketch sample** that over-represents low-support classes and outlier regions; remaining records receive scores by forward pass with the final probe plus **kNN score propagation** in feature space. Reported in the UI as "propagated", with a lower-confidence badge |
| **Low-level CPU tuning** | Faster epochs | `torch.set_num_threads`, `inference_mode`, channels-last for CNNs, optional mixed precision/`torch.compile` when a GPU is present |

**Scan profiles** (targets, to be measured and published only after benchmarking):

| Profile | Probe epochs | Seeds | Image res | Intended use |
| :--- | :---: | :---: | :---: | :--- |
| Quick | 6 | 1 | 32 | First look; large datasets |
| Standard (default) | 10 | 3 | 32 | Normal use |
| Deep | 16 | 3 | 64 | High-stakes datasets |

#### 4.3 Signals recorded per sample (11)

| # | Signal | Family | What it measures | How |
| :-: | :--- | :--- | :--- | :--- |
| 1 | First-correct epoch | Trajectory | Poison is learned later | First epoch with prediction == label |
| 2 | Forgetting events | Trajectory | Flip-flopping between right and wrong (Toneva et al.) | Count correct→incorrect transitions |
| 3 | Loss variance | Trajectory | Erratic difficulty | Variance of cross-entropy over epochs |
| 4 | Confidence & variability | Trajectory | Dataset-cartography "data map" position (Swayamdipta et al.) | Mean and std of probability of the true label |
| 5 | Area Under Margin (AUM) | Trajectory | Mislabeled samples have negative margin (Pleiss et al.) | Mean of (logit_true − max other logit) |
| 6 | EL2N | Trajectory | Early-epoch error magnitude (Paul et al.) | ‖p − y‖₂ at epochs 2–3 |
| 7 | Early gradient-norm proxy | Trajectory | Weight disruption | ‖p − y‖₂·‖h‖₂ (narrowed set via SSN) |
| 8 | Held-out agreement gap | Held-out | Behavior when the model has *not* seen the sample | Compare predictions in held-out epochs vs. label, and vs. in-train epochs. Label flips: held-out disagrees with label. Backdoors: held-out predicts the target label *with high confidence* on triggered inputs even without having seen them |
| 9 | kNN label disagreement | Representation | Neighbors disagree with the label | Fraction of k=15 neighbors in penultimate/feature space with a different label |
| 10 | Spectral-signature score | Representation | Backdoored samples leave a spectral trace (Tran et al.) | Per class: project centered features on top singular vector; outlier score |
| 11 | Activation-cluster separation | Representation | Poison forms its own cluster within a class | 2-means per class; silhouette + relative cluster size |

> v1 benchmarks showed activation clustering is far better than trajectory signals on patch backdoors (BadNets F1 0.947 vs 0.276), while trajectory signals were the only non-zero detector on label flips and blended triggers. v2 therefore **runs every family and fuses them** instead of betting on one.

### S5 — Detect: Fusion, Scoring, Verdict

| Technique | What it does | How |
| :--- | :--- | :--- |
| **Robust normalization** | Makes signals comparable and outlier-proof | Per signal (and per class where relevant): median/MAD z-score → rank → logistic squash to [0,1] |
| **Detector families** | Three independent opinions | *Trajectory* (signals 1–7), *Held-out* (8), *Representation* (9–11) each yield a family score |
| **Noisy-OR fusion** | Flags a record if any strong detector says so, more if several agree | `fused = 1 − Π(1 − w_f · s_f)`, weights `w_f` set in config; also stores `votes` = number of families above threshold |
| **Contamination estimate (ε̂)** | Estimates *how much* of the dataset looks poisoned | Fit a two-component mixture to fused scores (fallback: elbow/knee). Clipped to [0.5%, 15%] and reported with a confidence range |
| **Human-readable reasons** | Explains each flagged record | Rule-based text from top contributing signals, e.g. "learned 6 epochs later than class median; 4 forgetting events; neighbors disagree 80%" |
| **Dataset Poison Risk Score (0–100)** | One headline number | Weighted blend of ε̂, strength of agreement between families, label-noise excess over baseline, trigger-candidate strength, and severity of security findings |
| **Verdict** | Clean / Suspicious / Likely Poisoned / Unsafe File | Thresholds in config; always shown with coverage and confidence notes ("labels missing", "sketch-based", "stealthy blended triggers are hard to detect") |

### S6 — Sanitize, Verify, Export

| Technique | What it does | How |
| :--- | :--- | :--- |
| **Adaptive 3-tier soft quarantine** | Neutralizes poison without destroying rare clean data | Tier 3 *Quarantine* (w=0.0): top `min(ε̂, 10%)` by fused score **and** (≥2 family votes **or** extreme single-detector z>6). Tier 2 *Downweight* (w=0.20): next `min(2·ε̂, 15%)`. Tier 1 *Keep* (w=1.0): rest |
| **Self-built clean canary** | Replaces v1's external CIFAR canary | Canary = stratified sample (default min(500, 5% of labeled records), ≥20/class where possible) drawn from the **lowest-risk, highest-agreement** records. Excluded from verification training. User may upload their own trusted holdout instead (preferred) |
| **Canary guardrail & rollback** | Prevents over-deletion damage | Train a verification probe on (a) original weights and (b) sanitized weights; evaluate both on the canary. If accuracy drops >3.0 points, or any class drops >10 points: loosen tiers (halve Tier 3/Tier 2 budgets), retry up to 3 times; if still failing, **roll back** to "no changes" and mark the report accordingly |
| **User review & override** | Humans stay in control | In the UI the user can move records between tiers; every override is written to the audit ledger |
| **Format-preserving export** | Gives the cleaned data back in the same shape | CSV→CSV, XLSX→XLSX, JSONL→JSONL, Parquet→Parquet, image/audio archive→ZIP minus quarantined files. Always also writes `sample_weights.csv` and `quarantine/` with removed records and reasons |
| **Safe-output options** | Prevents the *export* from becoming an attack vector | Optional spreadsheet formula neutralization (prefix `'` on cells flagged by F10), metadata stripping on images |

### S7 — Seal: Audit Ledger & Report

| Technique | What it does | How |
| :--- | :--- | :--- |
| **SHA-256 hash chain** | Makes any edit detectable | `H_i = SHA-256(H_{i-1} ‖ canonical_json(payload_i))` — canonical JSON (sorted keys, no whitespace) is used so equivalent records always hash identically |
| **What is logged** | Full provenance | `SCAN_STARTED` (dataset sha256, config, tool versions) · `FILE_ACCEPTED/REJECTED` · every `SECURITY_FINDING` · `STAGE_COMPLETED` (hashes of output artifacts) · `SAMPLE_DECISION` for every Tier 2/3 record · `USER_OVERRIDE` · `CANARY_RESULT` · `EXPORT_CREATED` (sha256) · `SCAN_SEALED` |
| **Merkle root for Tier 1** | Avoids millions of log lines | All "Keep" decisions are committed via a single Merkle root; any individual decision can be proven with an inclusion proof |
| **Optional Ed25519 signature** | Proves who sealed it | Head hash signed with a locally generated key; public key shipped in the report |
| **Verification CLI & API** | Anyone can re-check | `python -m poisonlens.audit verify <scan_dir>` and `POST /api/scans/{id}/audit/verify` recompute the full chain and report the first broken block |
| **Report** | Shareable result | `report.json` (machine-readable), `report.pdf` (executive summary, verdict, findings by OWASP category, top flagged records, ledger head hash, scan config) |

---

## 3. Security Check Catalogue

Checks are plugins: `security/checks/*.py`, each declaring `id`, `applies_to`, `severity_default`, and `refs`. Mappings are to the **OWASP File Upload Cheat Sheet / ASVS V12**, **OWASP ML Security Top 10** (ML01 Input Manipulation, ML02 Data Poisoning, ML03 Model Inversion, ML04 Membership Inference, ML05 Model Theft, ML06 AI Supply Chain, ML07 Transfer Learning, ML08 Model Skewing, ML09 Output Integrity, ML10 Model Poisoning), **OWASP Top 10 for LLM Applications 2025** (LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM04 Data and Model Poisoning, LLM05 Improper Output Handling), **CWE**, and **MITRE ATLAS** (poison training data / backdoor ML model techniques). *Implementers must re-verify identifiers against the current published OWASP/ATLAS versions.*

### 3.1 File-level checks

| ID | Check | Detects | Severity | References |
| :--- | :--- | :--- | :---: | :--- |
| F01 | Extension allowlist + magic-byte/MIME consistency | Disguised or polyglot files | Medium–High | File Upload CS, CWE-434 |
| F02 | Archive bomb limits | Zip/tar bombs: ratio >100:1, nesting >3, entry count cap, total-uncompressed cap | High | CWE-409 |
| F03 | Archive path safety | Zip-slip, `../`, absolute paths, symlinks/hardlinks, device files | Critical | CWE-22, CWE-59 |
| F04 | Filename hygiene | NUL bytes, bidi/RTL override, reserved Windows names, over-long names | Medium | CWE-176 |
| F05 | Embedded executables/scripts | PE/ELF/Mach-O magic, `.exe .dll .so .bat .ps1 .sh .js .py .jar` inside data archives | High | ML06, LLM03 |
| F06 | Malware scan (optional) | ClamAV (`clamd`) and YARA rules if installed | Critical | ML06 |
| F07 | **Unsafe serialization** | Pickle/joblib/`.pt/.pth`/`.pkl`/`.npy` object arrays/Keras Lambda layers. Static opcode scan (`pickletools.genops`) for `GLOBAL/REDUCE` to `os`, `subprocess`, `builtins.eval/exec`, `socket`, etc. **Never unpickled.** `.npy` loaded only with `allow_pickle=False`. Safetensors preferred | Critical | CWE-502, ML06, LLM03 |
| F08 | Office/Excel active content | `vbaProject.bin` macros, external links, DDE, embedded OLE, hidden sheets/very-hidden sheets | High | CWE-94 |
| F09 | XML safety | DOCTYPE/entities (XXE, billion-laughs). Parsed with `defusedxml`; presence of DTD flagged | High | CWE-611, CWE-776 |
| F10 | Spreadsheet/CSV formula injection | Cells starting `= + - @ \t \r`, `HYPERLINK`, `cmd\|`, DDE strings | Medium–High | CWE-1236 |
| F11 | SQLite safety | Triggers, views with side effects, virtual tables, `load_extension`, attached DBs. Opened read-only/immutable with an authorizer denying writes and extensions | High | CWE-89 |
| F12 | Image safety | Decompression bomb (pixel cap), truncated/malformed headers, bytes after EOF (carrier/polyglot), text payloads in EXIF/XMP/ICC, SVG with scripts (SVG rejected by default) | Medium–High | CWE-434 |
| F13 | Audio/container anomalies | Header/length mismatch, oversize metadata, trailing data | Low–Medium | CWE-20 |
| F14 | URL-indexed datasets | Dataset that is only a list of URLs is exposed to **split-view / expired-domain poisoning**; flagged as high-risk, recommends content-hash pinning. Network access is **off** by default; no URL is fetched | High | ML02, LLM04, ML06 |

### 3.2 Content-level checks

| ID | Check | Detects | Severity | References |
| :--- | :--- | :--- | :---: | :--- |
| C01 | PII scan | Emails, phone numbers, IPs, credit cards (Luhn), SSN, **Aadhaar (Verhoeff checksum)**, PAN, IBAN | Medium–High | LLM02, ML03, ML04 |
| C02 | Secrets scan | API keys, private-key blocks, JWTs, cloud tokens, high-entropy strings | High | LLM02 |
| C03 | Prompt-injection / jailbreak patterns | Instruction-override phrases, role-play jailbreaks, hidden Unicode tag characters (U+E0000 block), zero-width characters, homoglyph mixing, large base64 blobs in text fields | High | LLM01, LLM04 |
| C04 | Active content in text fields | HTML/JS, SQL/command-injection strings, markdown image-exfiltration links | Medium | LLM05, CWE-79 |
| C05 | Invisible / encoding anomalies | Mixed scripts, bidi controls, invalid UTF-8, mojibake bursts | Low–Medium | CWE-176 |
| C06 | Duplicates & conflicting-label duplicates | Amplified or contradictory records | Medium–High | ML02, ML04 |
| C07 | Cross-split leakage | Test/val records present in train | Medium | ML08 |
| C08 | Label integrity | Label variants (`Cat`/`cat`), junk classes, extreme imbalance, unlabeled rows | Low–Medium | ML02 |
| C09 | Provenance & insertion patterns | Missing source/license, bursts from one source/time window, source with outsized anomaly rate | Medium | ML02, ML08 |
| C10 | Outliers & shortcut features | Impossible values, a feature that perfectly predicts the label | Medium | ML02 |
| C11 | Trigger-candidate mining | High-purity rare tokens / feature values / recurring image patches | High | ML02, ML10 |

Findings are grouped in the UI by OWASP category and sorted by severity.

---

## 4. Supported Dataset Formats

Everything below is accepted at upload. "Scan-only" means the file is analyzed statically and never loaded for training.

| Family | Formats | Notes |
| :--- | :--- | :--- |
| **Spreadsheets** | `.xlsx .xlsm .xls .ods` | User picks sheet(s) (default: all with consistent headers). Macro/formula/hidden-sheet checks (F08, F10) |
| **Delimited text** | `.csv .tsv .txt` (delimited), `.psv`, `.gz/.bz2/.xz` of these | Encoding and delimiter auto-detected; streamed with chunked reads |
| **JSON family** | `.json .jsonl .ndjson` | Nested records flattened with a depth cap; arrays of records or one record per line |
| **Columnar / big-data** | `.parquet .feather/.arrow .orc .avro` | Row-group / batch streaming |
| **Statistical packages** | `.sav .dta .sas7bdat` | Value labels become label names |
| **Scientific / arrays** | `.npy .npz .h5/.hdf5 .mat (v7.3)` | `allow_pickle=False`; each array/dataset mapped to features/labels with user confirmation |
| **Databases** | `.sqlite .db` | User picks table(s); read-only, immutable (F11) |
| **Markup** | `.xml` | Record element chosen by the user; `defusedxml` only |
| **Archives** | `.zip .tar .tar.gz .tgz .tar.bz2 .tar.xz .7z` | Safe expansion; contents are detected and routed to adapters; nested archives up to depth 3 |
| **Image datasets** | Archive/folder of `.png .jpg/.jpeg .bmp .gif .tif/.tiff .webp` | Layouts: folder-per-class, `labels.csv` manifest, COCO JSON, YOLO txt, Pascal VOC XML |
| **Audio datasets** | Archive of `.wav .flac .mp3 .ogg` + manifest | Fixed-length log-mel crops |
| **Text corpora** | `.txt` per document in class folders, `.jsonl` with `text` field, CoNLL-style `.conll/.tsv` | Sentence/document level |
| **ML-native** | CIFAR-style binary batches, MNIST IDX, TFRecord (record-level parse, no TF dependency where possible), Hugging Face `datasets` directories (Arrow + `dataset_info.json`) | Detected by structure |
| **Serialized objects** | `.pkl .pickle .joblib .pt .pth` | **Scan-only (F07).** Never loaded. Report states findings and asks the user to convert to a safe format |
| **Rejected by default** | `.svg`, executables, Office docs without tabular content, unknown binaries | Clear message explaining why |

If a file is supported only partially (e.g., an unknown binary inside a ZIP), the scan continues on the supported parts and lists the skipped items.

---

## 5. Capability Matrix (what runs for which input)

| Input situation | Security S2 | Quality S3 | Probe S4 | Detect S5 | Notes |
| :--- | :---: | :---: | :---: | :---: | :--- |
| Labeled tabular / text / image / audio | ✔ | ✔ | ✔ | ✔ | Full pipeline |
| Unlabeled data | ✔ | ✔ (dups, outliers, PII, injection) | ✖ | partial (outlier/dup fusion only) | UI explains why |
| Regression target (numeric) | ✔ | ✔ | ✔ (binned target + residual dynamics) | ✔ | Marked "experimental" |
| >200k records | ✔ | ✔ | ✔ sketch + propagate | ✔ | Lower-confidence badge on propagated records |
| Serialized object | ✔ (static) | ✖ | ✖ | ✖ | Verdict: *Unsafe File* if findings are critical |

---

## 6. Backend API (FastAPI)

Replaces v1's preset-run API. All IDs validated against `^[a-zA-Z0-9_\-]{8,64}$`; all artifact paths resolved against the scan root.

| Endpoint | Method | Purpose |
| :--- | :--- | :--- |
| `/api/health` | GET | Status, torch device, optional-tool availability (ClamAV, YARA, 7z) |
| `/api/uploads` | POST | Start resumable upload `{filename, size, sha256?}` → `upload_id` |
| `/api/uploads/{upload_id}/parts/{n}` | PUT | Upload one part |
| `/api/uploads/{upload_id}/complete` | POST | Assemble, verify, create scan → `scan_id` |
| `/api/scans` | GET | List scans with verdict and status |
| `/api/scans/{scan_id}` | GET / DELETE | Metadata; delete scan data |
| `/api/scans/{scan_id}/profile` | GET | Detected format, modality, schema, label candidates, capability matrix |
| `/api/scans/{scan_id}/configure` | POST | Confirm label column/sheet/table, choose profile (Quick/Standard/Deep), options |
| `/api/scans/{scan_id}/start` | POST | Start stages S2→S7 |
| `/api/scans/{scan_id}/events` | GET (SSE) | Live stage progress, logs, epoch metrics |
| `/api/scans/{scan_id}/status` | GET | Polling fallback |
| `/api/scans/{scan_id}/findings` | GET | Security + quality findings, filter by severity/category |
| `/api/scans/{scan_id}/dynamics` | GET | Aggregate epoch curves, data-map points (sampled) |
| `/api/scans/{scan_id}/records` | GET | Paginated records, filter by tier/score/class/detector |
| `/api/scans/{scan_id}/records/{record_id}` | GET | Record payload preview + per-epoch dynamics + reasons |
| `/api/scans/{scan_id}/tiers/override` | POST | User moves records between tiers (audited) |
| `/api/scans/{scan_id}/canary` | GET / POST | Canary result; upload a trusted holdout |
| `/api/scans/{scan_id}/export` | POST | Build sanitized export |
| `/api/scans/{scan_id}/audit` | GET | Ledger summary and recent entries |
| `/api/scans/{scan_id}/audit/verify` | POST | Real chain verification |
| `/api/scans/{scan_id}/report` | GET | `report.json` / `report.pdf` |
| `/api/scans/{scan_id}/artifacts/{file}` | GET | Allowlisted artifact download |

**Removed:** `/api/presets`, `/api/runs/*`, `/api/benchmarks`, `/api/runs/{id}/audit/simulate-tamper`. (A tamper simulation exists only inside the test suite.)

**Security controls:** upload size/rate limits, allowlisted artifact names, content-disposition `attachment` with `nosniff`, strict CORS, CSP on the frontend, no raw uploaded content ever rendered as HTML, optional API key / single-user mode, parser subprocesses with resource limits (Windows: job-object/`psutil` watchdog fallback, since POSIX `rlimit` is unavailable).

---

## 7. Dashboard Design

**Principles:** modern, calm, information-dense where it matters, nothing flashy. No gradients, glows, or animated backgrounds. One accent color, muted severity colors, generous whitespace, motion only for state changes (≤150 ms).

### 7.1 Interpreting the sketch

The sketch has a title, a **Pipeline** bar, and a large **Upload Dataset** area. v2 keeps exactly that structure: the **pipeline stepper** is the persistent spine of the product, and the **upload dropzone** is the first and dominant action.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  ◉ PoisonLens                         Scans ▾   Docs   Settings   ◐ Theme    │
├──────────────────────────────────────────────────────────────────────────────┤
│  Pipeline                                                                    │
│  ●─────○─────○─────○─────○─────○─────○─────○                                 │
│  Upload Inspect Security Quality Probe Detect Sanitize Seal                  │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌────────────────────────────────────────────────────────────────────┐     │
│   │                                                                    │     │
│   │                    Upload dataset                                  │     │
│   │        Drop a file or folder here, or  [ Browse files ]            │     │
│   │                                                                    │     │
│   │    CSV · Excel · JSON/JSONL · Parquet · ZIP/TAR · NumPy · HDF5 …   │     │
│   │               Max 2 GB · Files are scanned in an isolated sandbox  │     │
│   └────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│   Recent scans                                                               │
│   ┌──────────────┬───────────┬───────────┬───────────────┬──────────┐        │
│   │ Name         │ Type      │ Records   │ Verdict       │ Date     │        │
│   └──────────────┴───────────┴───────────┴───────────────┴──────────┘        │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Screens (all share the header + pipeline stepper)

| Screen / stepper state | Content |
| :--- | :--- |
| **Upload** | Dropzone (file or folder), part-by-part progress, SHA-256 shown on completion, supported-format hint, recent scans table |
| **Inspect** | Detected format and modality chips; schema table; **label picker** (suggested column pre-selected, with preview of class histogram); sheet/table picker; **capability matrix** card; profile selector (Quick/Standard/Deep with time estimate); *Start scan* button |
| **Security** | Findings list grouped by OWASP category with severity chips (Critical/High/Medium/Low/Info); expand a finding for evidence, location, CWE/OWASP references, remediation. A red banner appears if the file is unsafe and the scan halted |
| **Quality** | Duplicate groups, leakage summary, class balance chart, trigger-candidate cards (e.g., token `cf` — 97% purity to class 1 — 38 records) |
| **Probe** | Live epoch chart (loss/accuracy), chunk rotation strip showing which chunks trained each epoch, throughput (samples/s), ETA, scrolling log |
| **Detect** | Poison Risk Score (flat gauge), verdict, estimated contamination range, family agreement (Venn-style bar), **data map** (confidence vs. variability scatter, sampled) |
| **Sanitize** | Tier summary (Keep / Downweight / Quarantine counts), canary result card (baseline vs. sanitized accuracy, pass/fail, rollback banner), **record explorer** with virtualized table and tier override actions |
| **Seal** | Ledger timeline, **Verify** button with live result, head hash and signature, export buttons (sanitized dataset, quarantine file, weights, `report.pdf`, `report.json`) |

**Record explorer renderers** (one per modality): image thumbnail with zoom and per-class mean overlay; text snippet with suspected trigger tokens and invisible characters highlighted; tabular row with deviating cells highlighted; audio waveform + mini spectrogram. Each shows the 10-epoch loss/confidence sparkline and the plain-language reasons.

### 7.3 Visual language

| Aspect | Decision |
| :--- | :--- |
| Layout | Top bar + pipeline stepper; content max-width 1280 px; 12-column grid, 8 px spacing |
| Theme | Light and dark, follows system, toggle in header |
| Palette (dark) | Background `#0E1116`, surface `#151A21`, border `#242B35`, text `#E6E9EE`, muted `#8B94A3` |
| Palette (light) | Background `#FAFAF9`, surface `#FFFFFF`, border `#E4E6EA`, text `#14181F`, muted `#5F6877` |
| Accent | A single desaturated teal `#2F9E8F` (actions, active step, links) |
| Severity | Critical `#D1495B`, High `#E08A3C`, Medium `#D9B23E`, Low `#5B8DEF`, Info `#8B94A3`; always paired with text/icon (never color alone) |
| Type | Inter (UI), JetBrains Mono (hashes, code, record ids); 14 px base |
| Shape | 8 px radius, 1 px borders, no heavy shadows |
| Charts | Flat, thin lines, direct labels, tooltips; library: uPlot or visx for large point counts, Recharts for small charts |
| Stepper states | Pending (hollow), active (filled with accent, subtle pulse), done (check), failed (red cross), skipped (dash, with tooltip reason) |
| Empty / error states | Always explain what happened and the next action |
| Accessibility | Keyboard navigable, visible focus rings, WCAG AA contrast, `aria-live` for progress |
| Responsive | Desktop first; tablet supported; stepper collapses to a compact list under 900 px |

**Frontend stack:** React 19, TypeScript, Vite, React Router, TanStack Query (server state), TanStack Table + `react-virtual` (large tables), Zustand (small UI state), Tailwind CSS with design tokens as CSS variables, Vitest + Testing Library, Playwright for the happy-path e2e.

---

## 8. Honest Limitations (to be shown in the product and the report)

1. **No detector is complete.** Stealthy, low-rate, clean-label and distributed (blended) triggers can evade every method; v1 measured near-zero recall on blended backdoors. The verdict is a *risk estimate*, not a proof of cleanliness.
2. **Probe ≠ your production model.** The probe is small by design. Poison that only manifests in very large models may behave differently.
3. **Labels required** for label-based poisoning detectors. Unlabeled data gets security, duplicate, outlier and PII checks only.
4. **Sketch-based results are lower confidence** for datasets above the sketch threshold.
5. **The canary guards against over-deletion, not under-detection.** A self-built canary can itself contain undetected poison; a user-supplied trusted holdout is stronger.
6. **Static scans of serialized files are best-effort.** The safe answer is to convert them, not to trust a "no findings" result.
7. **Performance numbers** will only be published after the Phase 12 validation benchmark; targets in this document are not claims.
