# PoisonLens v1 → v2 Migration Notes

Source of truth: `docs/POISONLENS_V2_SPEC.md` (behavior) and `docs/POISONLENS_V2_BUILD_PLAN.md` (execution order).
This file records how the real repository maps onto the plan, which was written from the README rather than the code.

## Phase 0 — baseline (before any change)

- Branch: `v2-upload-first` from `main` @ `844ca70`.
- Environment: Windows 11, Python 3.13.15, project `.venv`, torch 2.15.0+cpu, torchvision 0.29.2+cpu, fastapi 0.163.1, pydantic 2.14.3, scikit-learn 1.9.1.
- Command: `.venv\Scripts\python -m pytest -q`
- Result: **34 passed, 3 failed, 3 errors** (the README badge claimed 40 passed).
  All 6 failures were `RuntimeError: Dataset not found or corrupted` — they needed a local CIFAR-10 download under `./data_cache`:
  `test_determinism`, `test_pipeline_recovery`, `test_resume_parity` (failed); `test_attacks::{test_label_flip,test_badnets,test_blended}` (errors).

## Phase 0 — after

- Result: **74 passed, 0 failed** (`.venv\Scripts\python -m pytest -q`). Increase comes from the new isolation and security-guard tests and from making the CIFAR-dependent tests run on synthetic data.
- Gate grep `rg -n -i "demo|preset|simulate-tamper|cifar" backend frontend/src poisonlens/pipeline` → no matches.
- Backend: `python -m uvicorn backend.main:app` starts; `GET /api/health` → 200; `GET /api/presets` → 404.
- Frontend: `npm ci && npm run build && npm run lint` pass.

## Phase 1 — core schemas, config, storage layout

New package `poisonlens/core/` (no v1 equivalent):

| Module | Contents |
| :--- | :--- |
| `errors.py` | `PoisonLensError` base; `ConfigError`, `UnsafeFileError(check_id, location)`, `UnsupportedFormatError(detected_kind)`, `LimitExceededError(limit, limit_value, observed)`; plus `PathSafetyError` (not in the plan list; used by `paths.py`, subclasses `ValueError`). |
| `schemas.py` | `Modality`, `Severity` (with `.rank`), `Tier` (`.weight` = 1.0 / 0.20 / 0.0), `StageName` (spec stage ids `ingest … seal`), `StageStatus`, `ScanStatus`, `Verdict`, `Location`, `Finding`, `ColumnProfile`, `LabelCandidate`, `SplitInfo`, `Capabilities`, `DatasetProfile`, `StageResult`, `ScanState`. All models forbid unknown fields. |
| `config.py` | `ScanConfig` (= Standard profile) with sections `limits.{upload,archive,worker,parse}`, `security`, `quality`, `features`, `probe`, `detect`, `risk`, `tiers`, `canary`, `export`; `load_scan_config(profile, overrides, config_dir)`. |
| `paths.py` | `ScanPaths(scan_id)`: `root, upload, sandbox, canonical, features, dynamics, results, audit, export, events_file, state_file`, `ensure()`, `resolve(rel)`. |
| `events.py` | `EventKind`, `ProgressEvent`, `EventLog` (append-only `events.jsonl`; event id = line number for SSE `Last-Event-ID`). |

Decisions worth knowing:

- **Provisional values.** The spec names many thresholds but leaves some open: fusion family weights, vote threshold, risk-score weights, verdict thresholds, most resource limits, time budgets. These are set to stated starting points and marked `provisional` in `docs/CONFIG.md`, which is generated from the code (`scripts/gen_config_doc.py`; a test fails if it is stale). Fusion weights are equal (0.8 each) so nothing is biased before Phase 12. Risk weights: contamination 0.35, agreement 0.20, label-noise excess 0.15, trigger strength 0.15, security severity 0.15. Verdict thresholds: Suspicious ≥ 30, Likely Poisoned ≥ 60.
- **Profiles.** Profile names are `quick | standard | deep`. Plan file names map as `quick → scan_quick.yaml`, `standard → scan_default.yaml`, `deep → scan_deep.yaml`. YAML files are partial overrides of `ScanConfig()`; `scan_default.yaml` must equal `ScanConfig()` (tested). Overrides cannot change the profile.
- **Rotation divisibility.** Default profiles give exact chunk rotation (6·2/4, 10·2/4, 16·2/4 are integers). The config does not reject other epoch counts; Phase 6 distributes a remainder evenly, as the plan allows.
- **Data dir.** `$POISONLENS_DATA_DIR`, else `<repo>/data` (gitignored as `/data/`). Config dir: `$POISONLENS_CONFIG_DIR`, else `<repo>/configs`.
- **Path safety.** `ScanPaths.resolve` rejects `..`, absolute/UNC/drive paths, drive-relative `C:x`, NTFS `:stream`, NUL, and percent-encoded (incl. double-encoded) variants, then re-checks containment after `resolve()` so symlinks pointing outside are refused. The symlink test is skipped on Windows without Developer Mode.
- **Event log writer.** Single writer per scan (the pipeline process); each event is one `write` + `fsync`. Readers skip a trailing partial line. Process-safe locking for multiple writers is the ledger's job in Phase 9.

Tooling added: `ruff` (lint + format) and `mypy` (pydantic plugin) configured in `pyproject.toml`, run on new code (`poisonlens/core`, `poisonlens/data`, `backend`, new tests, `scripts`). The v1 modules and `poisonlens/bench` are excluded until they are rewritten.

Gate 1: `python -c "from poisonlens.core.config import ScanConfig; print(ScanConfig())"` works; `tests/unit/test_core_*.py` + `test_config_doc.py` cover spec defaults, profiles, unknown keys, invalid values, traversal and schema round-trips. Full suite: **229 passed, 1 skipped**.

## Phase 2 — secure ingestion (S0)

New code (no v1 equivalent):

| Module | Contents |
| :--- | :--- |
| `ingest/upload.py` | `UploadManager`: `init(filename, size, sha256?)`, `put_part(id, n, bytes, sha256?)`, `status(id)`, `abort(id)`, `complete(id)`. Parts are **0-based**. Sessions live in `data/uploads/<32-hex id>/`. `complete` creates `scan_<16 hex>` and writes `upload/original.<ext>` (generated name, mode 0600, `O_EXCL`) plus `upload/meta.json`. |
| `ingest/sniff.py` | `sniff(path, claimed_name) -> SniffResult{kind, confidence, claimed_ext, mismatch, detail, polyglot, macro_enabled}` and `f01_findings()`. Distinguishes xlsx/xlsm/docx/pptx/ods/jar/npz/PyTorch-zip from plain ZIP. Flags appended-ZIP polyglots. |
| `ingest/names.py` | *(not in the plan's file list)* shared name analysis: F03 unsafe (absolute, drive, UNC, `..`) vs F04 hygiene (NUL, control, bidi, Windows-reserved/forbidden characters, trailing dot/space, over-long), plus the case-insensitive collision key. |
| `ingest/limits.py` | Upload size and disk-quota checks; `ArchiveBudget` enforcing entries, per-member bytes, total bytes and compression ratio on streamed bytes. |
| `ingest/archive.py` | `safe_extract()` / `SafeExtractor` for zip, tar, tar.gz/bz2/xz, single-file gz/bz2/xz, 7z (`py7zr`, optional). Plan-then-extract; nested archives expanded to `<member>.extracted/` up to depth 3 with a shared budget. |
| `ingest/worker.py` | `run_isolated("module:function", args, WorkerLimits, workdir)`: spawn child, result via JSON file, psutil watchdog (RSS / CPU / wall clock) on every OS, `RLIMIT_CPU`/`RLIMIT_AS` on POSIX, best-effort network namespace on Linux, audit hook blocking sockets, subprocess, `os.system`/`exec`/`spawn`. |
| `ingest/jobs.py` | `ingest_job`: the S0 step run inside the worker (sniff, F01, extraction, `results/ingest_report.json`, `results/findings_ingest.json`, ledger). |
| `security/catalogue.py` | *(early, Phase 4 builds on it)* metadata for all 25 checks F01–F14 / C01–C11 from spec section 3, and `make_finding()`. |
| `audit/ledger.py` | Ledger stub in the final entry format `{i, ts, type, payload, prev, hash}` with `hash = SHA256(prev ‖ canonical_json({i, ts, type, payload}))`. Phase 9 adds locking, verify, Merkle root, signature. The v1 `audit/log.py` is unchanged. |
| `core/paths.py::os_path` | Windows extended-length (`\\?\`) path helper. |

Decisions worth knowing:

- **Halting.** Any F03 in an archive rejects the whole upload before anything is written (`security.halt_on_critical_file`). Any F02 breach also stops extraction and removes what was written, because a bomb cannot be partially trusted. Executable content (PE/ELF/Mach-O/JAR) found by sniffing halts too. In each case the ledger gets `SECURITY_FINDING` entries and `FILE_REJECTED`.
- **Findings are aggregated** per (check, reason) with a count and up to 20 examples, so a hostile archive with 100k bad names yields a handful of findings, not 100k.
- **Ratio cap is overall, not just per member.** Output may not exceed 100× the compressed container size (once past 1 MiB). For the 1 GiB gzip-of-zeros test (~4.5 MiB compressed) extraction stops after ~450 MiB of output: correct by the spec's 100:1 rule, but those bytes do hit the disk briefly before cleanup. Lowering `ratio_check_min_bytes` or the ratio tightens this.
- **NUL in ZIP names.** Python's `zipfile` silently truncates names at NUL. The extractor analyzes `ZipInfo.orig_filename` so the ambiguity is reported (F04) and the member skipped.
- **Windows long paths.** Extracted names can exceed `MAX_PATH`; all extraction I/O goes through `os_path()`. Phase 3 adapters must do the same when reading sandbox files.
- **Upload names** are stricter than archive member names: anything with NUL, control or bidi characters, or path separators, is rejected outright (`UnsafeFileError`, F04). Other oddities are harmless because the bytes are stored under a generated name.
- **`SCAN_STARTED` is written at upload completion** (dataset sha256, size, tool versions). The scan config is not known until the user confirms it (Phase 10 `configure`); Phase 9 decides how to record it.
- **Two config additions** (both provisional, in `docs/CONFIG.md`): `limits.archive.ratio_check_min_bytes` (1 MiB) and `limits.archive.max_member_path_length` (1024).
- **New dependencies:** `psutil` (required), `py7zr` (optional; 7z uploads are rejected with a clear message without it).

Gate 2 evidence (`tests/unit/test_ingest_*.py`, `tests/integration/test_ingest_flow.py`; every hostile file is generated in-test):

| Gate item | Result |
| :--- | :--- |
| Zip-slip rejected with F03 critical | ✔ five path variants + backslash variant + nested zip-slip; nothing written outside or inside the sandbox |
| 1 GB-of-zeros zip bomb stops at the cap without exhausting memory | ✔ zip (~1 MiB) and gzip variants; RSS growth asserted < 200 MiB; a separate test proves the streaming total cap works even with ratio checks off |
| Symlink rejected; nesting depth 4 rejected | ✔ zip symlink, tar symlink/hardlink/char-device/FIFO; depth 3 extracts, depth 4 halts with F02 |
| `data.csv` with a PE header → F01 | ✔ high severity; also ELF/Mach-O/JAR, pickle-as-csv, docx-as-xlsx, polyglot PNG+ZIP |
| Watchdog kills runaway jobs within the wall-clock limit on Windows **and Linux** | ✔ **Windows** (wall clock 3 s job killed at ~3.1 s; CPU-time and memory kills too). ✖ **Linux not verified**: no Linux, WSL or Docker on the dev machine. The tests accept either the watchdog kill or the POSIX rlimit outcome, but have never run on Linux. |
| Resumable upload: out of order, duplicate part, wrong size, wrong final hash | ✔ plus part-hash mismatch, conflicting duplicate, tampered part on disk, missing parts, resume via `status()`, quota and size limits |

Full suite: **399 passed, 1 skipped** (symlink-escape test in `test_core_paths.py`, needs Windows Developer Mode).

## Module map (keep / move / rewrite / delete)

### `poisonlens/`

| v1 path | Decision | v2 location / notes |
| :--- | :--- | :--- |
| `attacks/` (label_flip, badnets, blended) | **move** | `poisonlens/bench/attacks/`. Dev-only; product imports forbidden (`tests/test_bench_isolation.py`). |
| `data/cifar.py` | **split** | Generic container → `poisonlens/data/image_dataset.py::ImageArrayDataset` (keep). CIFAR loader + `CIFAR10Subset` (now a subclass adding `cifar_indices` and the ground-truth `is_poison` mask) → `poisonlens/bench/datasets/cifar.py`. Ground truth no longer exists in product code. |
| `eval/asr.py` | **split** | `evaluate_clean_accuracy` → `poisonlens/eval/accuracy.py` (keep, used by CanaryGuard). Backdoor / label-flip ASR need known attacks → `poisonlens/bench/eval_asr.py`. |
| `eval/per_class.py` | keep | Uses `ImageArrayDataset`. |
| `models/resnet.py` (SmallResNet) | keep | Reused as the image probe (Phase 6). Docstrings no longer CIFAR-specific. |
| `training/trainer.py` | keep | Per-sample logging hooks reused by the Phase 6 trainer. |
| `detect/dynamics_features.py`, `detect/trajectory_scorer.py` | keep → rewrite later | Trajectory signals + MAD; Phase 6/7 split into `probe/signals.py` and `detect/trajectory.py`. Supervised `fit_validation_weights` relies on ground truth and must not be used on user data. |
| `detect/loss_filter.py`, `detect/activation_clustering.py` | keep | Phase 12 comparators; activation clustering also feeds signal #11. |
| `detect/metrics.py` | keep | Precision/recall/F1 against a mask — benchmark-only use. |
| `mitigate/tier_scoring.py`, `mitigate/canary.py` | keep → rewrite later | Fixed-fraction tiers and CanaryGuard; Phase 8 replaces with adaptive tiers + self-built canary. |
| `audit/log.py`, `audit/__main__.py` | keep → extend | Hash chain + verify CLI; Phase 9 adds atomic append, Merkle root, Ed25519. `datetime.utcnow()` replaced by a timezone-aware call (same output format). |
| `pipeline/orchestrator.py`, `attack_simulation.py`, `clean_baseline.py`, `__main__.py` | **move** | `poisonlens/bench/v1/`. These generate CIFAR subsets and inject poison, so they cannot be the product pipeline. `poisonlens/pipeline/` is now an empty package rebuilt in Phase 9. Run via `python -m poisonlens.bench.v1 --config poisonlens/bench/v1/configs/<name>.yaml` (needs CIFAR-10 in `./data_cache`; writes to `./runs/`, gitignored). |
| `utils.py` | keep | Seeding, RNG state, hashing helpers. |

### Repository root

| v1 path | Decision | v2 location / notes |
| :--- | :--- | :--- |
| `configs/attack_*.yaml`, `configs/clean_baseline.yaml` | **move** (out of product) | `poisonlens/bench/v1/configs/`. `configs/` is recreated in Phase 1 with `scan_{quick,default,deep}.yaml`. |
| `run_phase{2..5}.py`, `plot_phase{3..5}_results.py`, `compile_final_results.py` | **move** | `poisonlens/bench/v1/scripts/` (imports updated; still need CIFAR-10). |
| `runs/` (committed v1 outputs, ~26 MB) | **move** | `bench_artifacts/v1_runs/`. Kept as the v1 reference that Phase 12 must compare against. Not served by the backend. Includes the v1 `tampered_audit_log.jsonl` fixtures. |
| `POISONLENS_TECHNICAL_REPORT.md` | **move** | `docs/v1/TECHNICAL_REPORT_v1.md` (v1 numbers; do not copy into v2 docs). |
| `README.md` | trimmed | Demo walkthrough, Judge Demo Mode, preset API table removed; v2 notice added. Full rewrite is Phase 13. The "40 passed" badge is left until Phase 13 per the plan. |

### `backend/`

| v1 path | Decision | Notes |
| :--- | :--- | :--- |
| `main.py` | **rewrite** | Only `GET /api/health`. Removed: `/api/presets`, `/api/runs*` (start, status, results, samples, audit, verify, artifacts), `/api/jobs/{id}`, `/api/benchmarks`, `/api/runs/{id}/audit/simulate-tamper`. CORS wildcard `*` removed (local dev origins only). |
| `runner.py` | **delete** | Preset-driven subprocess runner. Phase 10 `jobs.py` replaces it. |
| `services.py` | **delete** | v1 run readers, benchmark loader, tamper-file verifier. |
| `security.py` | keep → extend | `validate_identifier`, `safe_resolve_path`. Preset and v1 artifact allowlists removed. `safe_resolve_path` now uses `pathlib` parent containment — the v1 `startswith` check accepted sibling dirs with the same prefix (e.g. `base_evil` for `base`); there is a regression test for it. |

> Plan deviation: build plan Phase 10 says "remove all v1 run/preset endpoints". They were removed in Phase 0 instead, because every v1 run endpoint depends on presets / the CIFAR pipeline and Gate 0 forbids those in `backend/`.

### `frontend/src/`

| v1 path | Decision | Notes |
| :--- | :--- | :--- |
| `data/demoFixtures.ts`, `components/DemoBanner.tsx` | **delete** | Judge Demo Mode + offline fixtures. |
| `pages/ComparisonPage.tsx` (Scoreboard), `pages/NewExperimentPage.tsx` (preset wizard) | **delete** | Hard-coded benchmark tables; start-from-preset. |
| `pages/AuditPage.tsx` + `components/AuditChainVisualizer.tsx` | **delete** | Included the Simulate Tampering button. |
| Other pages/components (`Overview`, `Progress`, `Results`, `SampleExplorer`, `Methodology`, charts, drawer), `services/api.ts`, `types/index.ts`, `App.css`, `assets/` | **delete** | All bound to the removed `/api/runs` API and v1 types. Phase 11 rebuilds the screens from spec section 7; old code remains in git history (`844ca70`) for reference. |
| `App.tsx`, `index.css`, `main.tsx` | **rewrite** | Minimal shell: header, eight-stage list, "upload not available yet" notice. Base tokens from spec 7.3. |
| `package.json` | edit | Removed unused `lucide-react`. |

> Plan deviation: build plan Phase 11 lists "remove old tabs" under scaffold/clean. Phase 0 removed them because they could not work against the Phase 0 backend.

### `tests/`

| v1 file | Decision | Notes |
| :--- | :--- | :--- |
| `test_attacks.py` | **move** | `tests/bench/test_attacks.py`, now on synthetic images (no download). |
| `test_determinism.py`, `test_resume.py` | rewrite (data only) | Same trainer assertions on synthetic loaders from `tests/conftest.py`. |
| `test_pipeline_recovery.py` | **delete** | Exercised the v1 CIFAR orchestrator, which is no longer product code. Phase 9 adds resume tests for the v2 pipeline. |
| `test_backend_api.py` | **rewrite** | Health, removed-endpoint 404s, identifier and path-traversal guards. |
| `test_defenses.py`, `test_mitigation.py`, `test_reproducibility.py`, `test_trajectory_scoring.py` | keep | `CIFAR10Subset` → `ImageArrayDataset`. |
| `test_audit.py` | keep | |
| new `test_bench_isolation.py` | add | AST scan: no file in `backend/` or non-bench `poisonlens/` imports `poisonlens.bench`. |

README test-file naming: the README listed `test_mitigate.py` and `test_detect.py`, which never existed; the repo has `test_mitigation.py` and `test_defenses.py` / `test_trajectory_scoring.py`. The README layout section now matches the repo.

## Environment notes (Windows)

- Create the env: `python -m venv .venv`, then `.venv\Scripts\python -m pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu` and the packages in README Step 1.
- On first import after install, Windows Smart App Control blocked one scikit-learn DLL (`_seq_dataset`, "An Application Control policy has blocked this file"). It loaded normally on the next run with no changes. If it recurs, rerun the command before changing anything.

## Remotes

- `origin` → `AnayGawande09/DataPoisioning_PoisionLens-` (all v2 commits are pushed here).
- `upstream` → the original team repository (not pushed to).
