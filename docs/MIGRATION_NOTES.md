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
