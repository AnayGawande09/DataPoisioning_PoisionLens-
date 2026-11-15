# PoisonLens: Technical Architecture & ML Pipeline Inspection Report

**Prepared for:** Full-Stack Architecture & API Integration  
**Repository:** `PoisonLens`  
**Execution Environment:** Windows, Python 3.11.0, PyTorch 2.14.1+cpu  
**Verification Date:** October 21, 2026  

---

## 1. Project Structure

The directory layout below reflects the active repository, excluding virtual environments (`.venv`), compiler caches (`__pycache__`, `.pytest_cache`), raw dataset caches (`data_cache`), and model checkpoints (`runs/*/*.pt`):

```text
PoisonLens/
├── configs/                                 # Experiment YAML configurations
│   ├── attack_badnets_5.yaml               # BadNets 5% backdoor config
│   ├── attack_blended_5.yaml               # Blended 5% backdoor config
│   ├── attack_labelflip_5.yaml             # Targeted Label Flip 5% config
│   ├── attack_labelflip_10.yaml            # Targeted Label Flip 10% config
│   └── clean_baseline.yaml                 # Unpoisoned baseline config
├── poisonlens/                              # Core Python library
│   ├── __init__.py                         # Package root
│   ├── utils.py                            # Seed setting, RNG state, SHA-256 provenance
│   ├── data/                               # Dataset loaders and caching
│   │   ├── __init__.py
│   │   └── cifar.py                        # CIFAR10Subset, stratified splitting, in-memory tensors
│   ├── models/                             # Neural network architectures
│   │   ├── __init__.py
│   │   └── resnet.py                       # SmallResNet (~308k params), extract_features()
│   ├── training/                           # Training loops & dynamics logging
│   │   ├── __init__.py
│   │   └── trainer.py                      # PoisonLensTrainer, per-sample dynamics, weighted loss
│   ├── attacks/                            # Attack implementations
│   │   ├── __init__.py
│   │   ├── label_flip.py                   # Targeted label flipping
│   │   ├── badnets.py                      # BadNets pixel patch trigger
│   │   └── blended.py                      # Blended pattern backdoor
│   ├── detect/                             # Detection algorithms & feature extractors
│   │   ├── __init__.py
│   │   ├── metrics.py                      # Precision, Recall, F1 calculation
│   │   ├── loss_filter.py                  # Static loss-threshold filter
│   │   ├── activation_clustering.py        # Penultimate PCA + 2-Means clustering
│   │   ├── dynamics_features.py            # 5 dynamic training feature extractors
│   │   └── trajectory_scorer.py            # Robust MAD normalization, explainable reason generator
│   ├── mitigate/                           # Mitigation & guardrail mechanics
│   │   ├── __init__.py
│   │   ├── tier_scoring.py                 # 3-tier weighting (Keep, Down-weight, Quarantine)
│   │   └── canary.py                       # CanaryGuard, clean canary health, automatic rollback
│   ├── eval/                               # Evaluation & metric tracking
│   │   ├── __init__.py
│   │   ├── asr.py                          # Clean accuracy, Backdoor ASR, Label Flip ASR
│   │   └── per_class.py                    # Per-class accuracy & collateral impact breakdown
│   ├── audit/                              # Cryptographic audit logging
│   │   ├── __init__.py
│   │   ├── log.py                          # HashChainedAuditLog, verify_audit_log
│   │   └── __main__.py                     # CLI verification entry point
│   └── pipeline/                           # End-to-end pipeline execution
│       ├── __init__.py
│       ├── __main__.py                     # CLI entry point (`python -m poisonlens.pipeline`)
│       ├── clean_baseline.py               # Clean baseline runner
│       ├── attack_simulation.py            # Undefended attack simulator
│       └── orchestrator.py                 # 6-stage end-to-end pipeline orchestrator
├── tests/                                  # 25 pytest unit tests
│   ├── test_attacks.py                     # Attacks injection verification
│   ├── test_audit.py                       # Hash-chain integrity & tamper detection
│   ├── test_defenses.py                    # Baseline detectors unit tests
│   ├── test_determinism.py                 # Random seed determinism
│   ├── test_mitigation.py                  # Tier scoring, canary guardrail, per-class evaluation
│   ├── test_pipeline_recovery.py           # Mid-run failure recovery & resume test
│   ├── test_reproducibility.py             # Reproducibility under identical seeds
│   ├── test_resume.py                      # Checkpoint resume parity test
│   └── test_trajectory_scoring.py          # Trajectory features & MAD normalization
├── pyproject.toml                          # Build specification, dependencies, pytest config
├── pytest.ini                              # Pytest testpaths configuration
└── README.md                               # Project documentation & master benchmark matrix
```

---

## 2. Pipeline Entry Point

### Exact Execution Command
The complete end-to-end experiment is executed via:
```bash
python -m poisonlens.pipeline --config configs/<config_file>.yaml
```
- **CLI Entry Point File:** [`poisonlens/pipeline/__main__.py`](file:///d:/workspace/PoisonLens/poisonlens/pipeline/__main__.py#L7-L14)
- **Orchestrator Implementation:** [`poisonlens/pipeline/orchestrator.py`](file:///d:/workspace/PoisonLens/poisonlens/pipeline/orchestrator.py#L42-L313)

### Stages Executed
When invoked, `run_pipeline(config_path)` executes 6 sequential stages:

1. **Stage 1: Data Partitioning & Attack Injection** ([`orchestrator.py:L67-L119`](file:///d:/workspace/PoisonLens/poisonlens/pipeline/orchestrator.py#L67-L119)):
   - Loads the CIFAR-10 dataset (default 10,000 train / 2,000 test).
   - Holds out an uncorrupted 200-sample clean **Canary Set** (20 samples per class, stratified) that is never exposed to poisoning or training.
   - Injects the specified attack (or none) into the remaining 9,800 training samples, generating ground-truth poison masks.
2. **Stage 2: Undefended Baseline Training & Dynamics Logging** ([`orchestrator.py:L124-L162`](file:///d:/workspace/PoisonLens/poisonlens/pipeline/orchestrator.py#L124-L162)):
   - Initializes `SmallResNet` (~308k parameters).
   - If an existing checkpoint exists at `runs/<run_id>/checkpoints/checkpoint_latest.pt`, it restores model weights, optimizer, RNG states, and training dynamics. Otherwise, it trains for $E$ epochs (default 10).
   - Logs per-sample cross-entropy loss, predicted class, and correctness at every epoch into `training_dynamics.npz`.
   - Evaluates pre-mitigation Clean Test Accuracy, Canary Accuracy, and Attack Success Rate (ASR).
3. **Stage 3: Trajectory Dynamic Feature Scoring** ([`orchestrator.py:L164-L203`](file:///d:/workspace/PoisonLens/poisonlens/pipeline/orchestrator.py#L164-L203)):
   - Loads early model (Epoch 1) and converged model (Epoch 10).
   - Extracts 5 dynamic trajectory features per training sample: First Correct Epoch, Forgetting Count, Loss Variance, Early Gradient Norm Proxy, and Penultimate kNN Disagreement.
   - Applies robust Median/MAD normalization with scale stabilization.
   - Calibrates feature weights on a 100-sample stratified validation split using regularized non-negative logistic regression.
   - Emits a scalar suspicion score and explainable textual reasons per sample. Measures scoring throughput (samples/sec).
4. **Stage 4: Controlled 3-Tier Soft Quarantine** ([`orchestrator.py:L205-L215`](file:///d:/workspace/PoisonLens/poisonlens/pipeline/orchestrator.py#L205-L215)):
   - Sorts samples by suspicion score and assigns 3 tiers:
     - **Quarantine** (top `poison_rate` %): Sample weight $w_i = 0.0$ (excluded).
     - **Down-weight** (next 10%): Sample weight $w_i = 0.20$.
     - **Keep** (remaining ~85%): Sample weight $w_i = 1.0$.
   - Quantifies false positive counts (clean samples wrongly quarantined).
5. **Stage 5: Mitigated Retraining & Canary Health Guardrail** ([`orchestrator.py:L217-L245`](file:///d:/workspace/PoisonLens/poisonlens/pipeline/orchestrator.py#L217-L245)):
   - Retrains a fresh `SmallResNet` from scratch for 5 epochs on the full training set using dynamic sample-weighted loss: $\mathcal{L} = \frac{\sum w_i \mathcal{L}_i}{\sum w_i + \epsilon}$.
   - Evaluates the retrained model on the held-out Clean Canary Set.
   - If canary accuracy drops by $> 3.0\%$ compared to baseline, `CanaryGuard` automatically triggers **ROLLBACK_TRIGGERED**, restores the backup checkpoint, and suggests a loosened quarantine ratio.
6. **Stage 6: Final Evaluation & Cryptographic Audit Logging** ([`orchestrator.py:L247-L313`](file:///d:/workspace/PoisonLens/poisonlens/pipeline/orchestrator.py#L247-L313)):
   - Measures post-mitigation Clean Test Accuracy, ASR, and per-class accuracy shifts across all 10 classes.
   - Writes every sample's tier decision, score, reasons, weight, timestamp, and config hash into a SHA-256 hash-chained JSON Lines log: `runs/<run_id>/audit_log.jsonl`.
   - Verifies the cryptographic chain and writes execution metrics to `runs/<run_id>/pipeline_results.json`.

---

## 3. Configuration Files & Settings

All configuration files reside in [`configs/`](file:///d:/workspace/PoisonLens/configs). They define training hyperparameters, attack specifications, and storage directories.

### Complete Configuration Parameter Inventory

| Config File | Attack Type | Poison Rate | Target Class | Source Class | Trigger Parameter | Batch Size | Epochs | Learning Rate | Weight Decay | Device | Output Directory |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| [`configs/clean_baseline.yaml`](file:///d:/workspace/PoisonLens/configs/clean_baseline.yaml) | `none` | `0.0` | N/A | N/A | N/A | 128 | 10 | 0.001 | 0.0001 | `cpu` | `runs/clean_baseline` |
| [`configs/attack_badnets_5.yaml`](file:///d:/workspace/PoisonLens/configs/attack_badnets_5.yaml) | `badnets` | `0.05` | `0` | N/A | `patch_size: 3` | 128 | 10 | 0.001 | 0.0001 | `cpu` | `runs/attack_badnets_5` |
| [`configs/attack_blended_5.yaml`](file:///d:/workspace/PoisonLens/configs/attack_blended_5.yaml) | `blended` | `0.05` | `0` | N/A | `alpha: 0.20` | 128 | 10 | 0.001 | 0.0001 | `cpu` | `runs/attack_blended_5` |
| [`configs/attack_labelflip_5.yaml`](file:///d:/workspace/PoisonLens/configs/attack_labelflip_5.yaml) | `label_flip` | `0.05` | `5` | `3` | N/A | 128 | 10 | 0.001 | 0.0001 | `cpu` | `runs/attack_labelflip_5` |
| [`configs/attack_labelflip_10.yaml`](file:///d:/workspace/PoisonLens/configs/attack_labelflip_10.yaml) | `label_flip` | `0.10` | `5` | `3` | N/A | 128 | 10 | 0.001 | 0.0001 | `cpu` | `runs/attack_labelflip_10` |

### Sample YAML File Contents

#### `configs/attack_badnets_5.yaml`
```yaml
# PoisonLens Attack Configuration: BadNets Backdoor 5%
seed: 42
data_root: "./data_cache"
train_size: 10000
test_size: 2000
batch_size: 128
epochs: 10
lr: 0.001
weight_decay: 0.0001
device: "cpu"
attack: "badnets"
poison_rate: 0.05
target_class: 0
patch_size: 3
run_id: "attack_badnets_5"
save_dir: "runs"
```

#### `configs/attack_labelflip_10.yaml`
```yaml
# PoisonLens Attack Configuration: Label Flip 10%
seed: 42
data_root: "./data_cache"
train_size: 10000
test_size: 2000
batch_size: 128
epochs: 10
lr: 0.001
weight_decay: 0.0001
device: "cpu"
attack: "label_flip"
poison_rate: 0.10
source_class: 3
target_class: 5
run_id: "attack_labelflip_10"
save_dir: "runs"
```

---

## 4. Dataset Support

### Current Implementation Status
- **Supported Format:** Strictly **CIFAR-10** via `torchvision.datasets.CIFAR10` wrapped in [`CIFAR10Subset`](file:///d:/workspace/PoisonLens/poisonlens/data/cifar.py#L17-L54).
- **Image Specifications:** $32 \times 32 \times 3$ RGB images (NumPy `uint8`), normalized in-memory via PyTorch tensors using CIFAR-10 channel statistics:
  $$\mu = (0.4914, 0.4822, 0.4465), \quad \sigma = (0.2470, 0.2435, 0.2616)$$
- **Target Specification:** 10 integer classification labels (`0` through `9`).
- **Data Provenance:** Calculates a deterministic SHA-256 hash over the sorted stratified sample indices ([`poisonlens/data/cifar.py:L95`](file:///d:/workspace/PoisonLens/poisonlens/data/cifar.py#L95)).

### Custom Uploaded Dataset Support: **Not Supported Out-of-the-Box**
- Custom datasets (e.g. uploaded zip folders of PNGs/JPEGs, CSV files, or custom resolution images) **cannot** currently be processed without code modifications.
- **Why?**
  1. [`poisonlens/data/cifar.py:L87-L88`](file:///d:/workspace/PoisonLens/poisonlens/data/cifar.py#L87-L88) hardcodes `torchvision.datasets.CIFAR10`.
  2. [`poisonlens/models/resnet.py`](file:///d:/workspace/PoisonLens/poisonlens/models/resnet.py) specifies a CNN architecture specifically designed for $32 \times 32$ inputs with an initial $3 \times 3$ stride-1 convolution (larger images will undergo excessive downsampling or dimension mismatch).
  3. The number of classes (`num_classes=10`) is hardcoded across pipeline orchestration routines.
- **Backend Requirement:** To support custom uploads, an adapter module must be created to convert arbitrary image inputs into fixed-shape tensors, infer `num_classes`, and construct a generic `PoisonLensDataset`.

---

## 5. Attack Implementations & Configurable Parameters

All attacks inherit from `CIFAR10Subset` and return a poisoned dataset along with a boolean `poison_mask` indicating which samples were modified.

| Attack Name | Implementation File | Key Mechanism | Configurable Parameters |
| :--- | :--- | :--- | :--- |
| **Targeted Label Flip** | [`poisonlens/attacks/label_flip.py`](file:///d:/workspace/PoisonLens/poisonlens/attacks/label_flip.py#L9-L51) | Replaces targets of samples in `source_class` with `target_class` without modifying pixel data. | - `poison_rate`: Fraction of total dataset to poison.<br>- `source_class`: Original class (default 3, Cat).<br>- `target_class`: Forced target class (default 5, Dog).<br>- `seed`: Random seed for sample selection. |
| **BadNets Backdoor** | [`poisonlens/attacks/badnets.py`](file:///d:/workspace/PoisonLens/poisonlens/attacks/badnets.py#L30-L77) | Overwrites bottom-right pixels with a solid white square (`[255, 255, 255]`) and relabels samples to `target_class`. Returns a `trigger_fn` for test evaluation. | - `poison_rate`: Fraction of dataset to poison (default 0.05).<br>- `target_class`: Forced target class (default 0, Airplane).<br>- `patch_size`: Trigger width/height in pixels (default 3).<br>- `seed`: Random seed for sample selection. |
| **Blended Backdoor** | [`poisonlens/attacks/blended.py`](file:///d:/workspace/PoisonLens/poisonlens/attacks/blended.py#L23-L72) | Blends a deterministic static noise pattern $P$ into images: $x' = (1-\alpha)x + \alpha P$, relabeling to `target_class`. Returns a `trigger_fn` for test evaluation. | - `poison_rate`: Fraction of dataset to poison (default 0.05).<br>- `target_class`: Forced target class (default 0, Airplane).<br>- `alpha`: Blending opacity parameter (default 0.20).<br>- `seed`: Random seed for sample selection. |

---

## 6. Detection, Mitigation & Audit Architecture

### 6.1 Baseline Detectors
1. **Loss-Threshold Filtering** ([`poisonlens/detect/loss_filter.py`](file:///d:/workspace/PoisonLens/poisonlens/detect/loss_filter.py)):
   - Evaluates per-sample cross-entropy loss on the converged model.
   - Flags the top $k\%$ highest-loss samples for deletion.
   - *Limitation:* Deep networks memorize poisoned triggers down to near-zero loss, causing this detector to discard hard clean samples while missing poison (F1: 0.000 to 0.054).
2. **Activation Clustering** ([`poisonlens/detect/activation_clustering.py`](file:///d:/workspace/PoisonLens/poisonlens/detect/activation_clustering.py)):
   - Implementation of Chen et al. (2018).
   - Extracts penultimate 128-dimensional representations, reduces dimensionality via PCA (10 components), and executes 2-Means clustering per class.
   - Analyzes cluster silhouette score; if $\ge 0.10$, flags the smaller sub-cluster as poison.
   - *Behavior:* Achieves 0.947 F1 on localized BadNets patches, but achieves 0.000 F1 on blended triggers and label flips.

### 6.2 Trajectory Fingerprint Scoring (PoisonLens Engine)
Implemented in [`poisonlens/detect/dynamics_features.py`](file:///d:/workspace/PoisonLens/poisonlens/detect/dynamics_features.py) and [`poisonlens/detect/trajectory_scorer.py`](file:///d:/workspace/PoisonLens/poisonlens/detect/trajectory_scorer.py):
- Extracts 5 dynamic training signals across epochs without auxiliary neural networks:
  1. `first_correct_epoch`: First epoch index where the sample was classified correctly.
  2. `forgetting_count`: Number of correct $\to$ incorrect transitions across epochs (Toneva et al., 2019).
  3. `loss_variance`: Empirical variance of cross-entropy loss trajectory across all epochs.
  4. `early_grad_norm`: Frobenius norm of the classification head gradient at Epoch 1 checkpoint:
     $$\|g_i\| = \|p_i - y_i\|_2 \times \|h_i\|_2$$
  5. `knn_disagreement`: Fraction of $k=15$ nearest neighbors in penultimate feature space with conflicting class labels.
- **Robust Outlier Normalization:** Uses Median and Median Absolute Deviation (MAD), with automatic standard deviation fallback for discrete zero-MAD features:
  $$z_i = \frac{x_i - \text{median}(x)}{\max(\text{MAD}(x) \cdot 1.4826, \text{std}(x), 10^{-4})}$$
- **Weight Calibration:** Fits non-negative weights on a 100-sample calibration split via regularized logistic regression.
- **Explainability:** Assigns human-readable reason strings to each flagged sample (e.g. `Loss Instability (z=4.58)`, `Feature Neighbor Conflict (z=8.09)`).

### 6.3 Controlled Mitigation (3-Tier Soft Quarantine)
Implemented in [`poisonlens/mitigate/tier_scoring.py`](file:///d:/workspace/PoisonLens/poisonlens/mitigate/tier_scoring.py):
- Avoids clean accuracy collapse by avoiding binary all-or-nothing deletion:
  - **Tier 1 (Keep):** Weight $w_i = 1.0$ (unflagged, benign).
  - **Tier 2 (Down-weight):** Weight $w_i = 0.20$ (moderately suspicious).
  - **Tier 3 (Quarantine):** Weight $w_i = 0.0$ (excluded from loss computation).
- Retrains model from scratch with sample weights: $\mathcal{L} = \frac{\sum w_i \mathcal{L}_i}{\sum w_i + \epsilon}$.

### 6.4 Clean-Canary Guardrail & Automatic Rollback
Implemented in [`poisonlens/mitigate/canary.py`](file:///d:/workspace/PoisonLens/poisonlens/mitigate/canary.py):
- Holds out 200 verified-clean CIFAR-10 samples (20 per class) from training.
- Evaluates clean generalization before and after mitigation.
- If post-mitigation canary accuracy drops by $> 3.0\%$ tolerance relative to baseline, the system executes **`ROLLBACK_TRIGGERED`**, restores model weights from the pre-mitigation checkpoint, and automatically loosens the quarantine threshold by 50%.

### 6.5 Cryptographic Audit Log
Implemented in [`poisonlens/audit/log.py`](file:///d:/workspace/PoisonLens/poisonlens/audit/log.py):
- Writes an append-only JSON Lines ledger: `runs/<run_id>/audit_log.jsonl`.
- Each record contains: `index`, `timestamp`, `previous_hash`, `config_hash`, `sample_id`, `score`, `reasons`, `decision`, `sample_weight`, and `entry_hash`.
- `entry_hash` is computed as $\text{SHA-256}(\text{canonical\_json}(\text{payload}))$. Genesis entry uses 64 zeros.
- Verified via CLI: `python -m poisonlens.audit --verify <log_path>`. Tampering with any field invalidates downstream cryptographic links.

---

## 7. Output Files, Formats & Metrics Inventory

Running an experiment produces structured artifacts in `runs/<run_id>/`:

| Output File Path | Format | Level | Key Fields & Metrics |
| :--- | :--- | :--- | :--- |
| `pipeline_results.json` | JSON | Run summary | `run_id`, `config_hash`, `total_time_seconds`, `scoring_time_seconds`, `scoring_throughput_samples_per_sec`, `baseline_metrics` (`clean_acc`, `canary_acc`, `asr`), `mitigated_metrics` (`clean_acc`, `canary_acc`, `asr`, `wrongly_quarantined_clean`, `clean_retention_rate`, `worst_class_drop`), `guardrail_decision`, `audit_verification`. |
| `audit_log.jsonl` | JSON Lines | Per-sample | `index` (int), `timestamp` (ISO-8601), `previous_hash` (hex), `config_hash` (hex), `sample_id` (int), `score` (float), `reasons` (list of strings), `decision` ("keep" \| "downweight" \| "quarantine"), `sample_weight` (float), `entry_hash` (hex). |
| `training_dynamics.npz` | NumPy binary archive | Per-sample across epochs | - `losses`: Shape $(E, N)$, float32 per-sample loss per epoch.<br>- `preds`: Shape $(E, N)$, int64 predicted class per epoch.<br>- `correct`: Shape $(E, N)$, bool prediction correctness per epoch. |
| `poison_mask.npy` | NumPy binary array | Per-sample | Shape $(N,)$, bool array of ground truth poison flags. |
| `checkpoints/checkpoint_latest.pt` | PyTorch checkpoint | Model state | `epoch` (int), `model_state_dict` (tensors), `optimizer_state_dict`, `rng_states` (PyTorch, NumPy, Python RNG states), `history` (epoch loss/acc curves), `dynamics` (`losses`, `preds`, `correct`). |
| `run_info.json` | JSON | Run metadata | `run_id`, `seed`, `indices_hash` (git-style SHA of data split), `timestamp`, `train_dataset_size`. |
| `config.yaml` | YAML | Configuration snapshot | Copy of the input configuration YAML for exact reproducibility. |

---

## 8. Dependencies & Environment Requirements

- **Python Version Requirement:** `Python >= 3.10` (verified active environment: `Python 3.11.0`).
- **Required Packages** (from [`pyproject.toml`](file:///d:/workspace/PoisonLens/pyproject.toml#L12-L20)):
  - `torch`: PyTorch CPU or CUDA (tested with `torch==2.14.1+cpu`)
  - `torchvision`: Vision transforms and CIFAR-10 raw datasets
  - `numpy`: Array manipulation and dynamics storage
  - `scikit-learn`: PCA, k-Means, kNN, NearestNeighbors, LogisticRegression
  - `matplotlib`: Visualization and dark-mode artifact plotting
  - `pyyaml`: YAML configuration parsing
  - `pytest`: Test execution suite
  - `setuptools >= 61.0`: Editable installation build backend

---

## 9. Test Suite Verification & Status

All unit tests were executed using `pytest -v` via the active virtual environment (`.venv\Scripts\pytest.exe`).

### Execution Summary
- **Total Tests:** 25
- **Passed:** 25
- **Failed:** 0
- **Execution Time:** 215.56s (0:03:35) on Windows CPU
- **Test Command:** `.venv\Scripts\pytest.exe -v`

### Detailed Test Inventory

| Test Module | Test Name | Status | Functionality Verified |
| :--- | :--- | :---: | :--- |
| `tests/test_attacks.py` | `test_label_flip` | **PASSED** | Validates source-to-target class flipping and ground truth mask generation. |
| | `test_badnets` | **PASSED** | Verifies 3x3 white patch stamping, target relabeling, and test trigger function. |
| | `test_blended` | **PASSED** | Verifies opacity blending ($\alpha=0.20$), pattern generation, and clipping. |
| `tests/test_audit.py` | `test_audit_log_creation_and_verification` | **PASSED** | Verifies sequential SHA-256 entry hashing and verification passes on clean log. |
| | `test_audit_log_tamper_detection` | **PASSED** | Alters entry score and verifies tamper detection detects the exact corrupted line. |
| | `test_audit_log_broken_chain_detection` | **PASSED** | Deletes an entry and verifies broken hash chain link detection. |
| `tests/test_defenses.py` | `test_detection_metrics` | **PASSED** | Checks TP, FP, FN, TN, Precision, Recall, and F1 calculations against ground truth. |
| | `test_loss_filter` | **PASSED** | Verifies top-$k\%$ loss filtering on synthetic distributions. |
| | `test_activation_clustering` | **PASSED** | Verifies PCA + 2-Means bimodal silhouette detection on synthetic bimodal features. |
| `tests/test_determinism.py` | `test_determinism` | **PASSED** | Verifies identical random seeds yield identical training losses and test accuracies. |
| `tests/test_mitigation.py` | `test_3_tier_assignment` | **PASSED** | Verifies Keep ($w=1.0$), Down-weight ($w=0.25$), and Quarantine ($w=0.0$) assignments. |
| | `test_hard_deletion_assignment` | **PASSED** | Verifies binary 0.0/1.0 assignment for hard deletion baseline. |
| | `test_measure_wrongly_quarantined` | **PASSED** | Verifies false positive count, clean retention rate, and error tracking. |
| | `test_canary_guard_health_and_rollback` | **PASSED** | Verifies canary accuracy thresholding and automatic checkpoint rollback. |
| | `test_per_class_accuracy_and_impact` | **PASSED** | Verifies per-class accuracy breakdowns and worst-class drop delta calculation. |
| `tests/test_pipeline_recovery.py` | `test_pipeline_failure_recovery` | **PASSED** | Simulates mid-run pipeline interruption and verifies complete resume parity. |
| `tests/test_reproducibility.py` | `test_scoring_reproducibility` | **PASSED** | Verifies identical seeds produce 100% identical quarantine lists and scores. |
| `tests/test_resume.py` | `test_resume_parity` | **PASSED** | Verifies checkpoint resume matches uninterrupted training bit-for-bit. |
| `tests/test_trajectory_scoring.py` | `test_first_correct_epoch` | **PASSED** | Verifies earliest correct epoch tracking across training epochs. |
| | `test_forgetting_events` | **PASSED** | Verifies count of correct-to-incorrect prediction flips across training. |
| | `test_loss_dynamics` | **PASSED** | Verifies per-sample loss trajectory variance and regression slope. |
| | `test_knn_disagreement` | **PASSED** | Verifies penultimate feature kNN label disagreement calculation. |
| | `test_mad_normalization` | **PASSED** | Verifies robust median/MAD scaling and outlier resilience. |
| | `test_compute_suspicion_scores_and_reasons` | **PASSED** | Verifies composite suspicion scoring and explainable reason generation. |
| | `test_end_to_end_detector` | **PASSED** | Verifies end-to-end detector output on synthetic training dynamics. |

---

## 10. Backend Integration Recommendations (FastAPI)

To build a robust, production-grade web application without duplicating ML logic or rewriting the core pipeline, the backend should adhere to the following architecture:

### 10.1 Pipeline Invocation Pattern
- **Do not wrap pipeline calls in standard blocking synchronous HTTP routes.** Pipeline runs take ~3 to 5 minutes on CPU. Blocking the FastAPI event loop will cause gateway timeouts.
- **Recommended Execution Mechanism:**
  1. Use FastAPI's native `BackgroundTasks` (for lightweight single-node deployments) or **Celery / Redis Queue** (for production decoupling).
  2. Invoke `run_pipeline(config_path)` directly as an imported Python callable from [`poisonlens.pipeline.orchestrator`](file:///d:/workspace/PoisonLens/poisonlens/pipeline/orchestrator.py#L42):
     ```python
     from poisonlens.pipeline.orchestrator import run_pipeline
     
     @app.post("/api/runs/start")
     async def start_pipeline(config: RunConfigRequest, background_tasks: BackgroundTasks):
         run_id = f"run_{uuid.uuid4().hex[:8]}"
         temp_config_path = write_temp_config(run_id, config)
         background_tasks.add_task(run_pipeline, temp_config_path)
         return {"run_id": run_id, "status": "QUEUED"}
     ```

### 10.2 Recommended API Surface

```text
POST /api/runs/start
  ├── Payload: { attack: "badnets", poison_rate: 0.05, target_class: 0, epochs: 10, ... }
  └── Response: { run_id: "run_abc123", status: "STARTED" }

GET /api/runs/{run_id}/status
  └── Response: Checks whether runs/<run_id>/pipeline_results.json exists (RUNNING vs COMPLETE vs FAILED).

GET /api/runs/{run_id}/results
  └── Response: Deserializes runs/<run_id>/pipeline_results.json (Clean Acc, ASR, Canary health, etc.).

GET /api/runs/{run_id}/audit
  ├── Parameters: ?page=1&limit=50&tier=quarantine
  └── Response: Paginated records streamed directly from runs/<run_id>/audit_log.jsonl.

POST /api/runs/{run_id}/audit/verify
  └── Response: Executes verify_audit_log(audit_log_path) and returns { is_valid: bool, error: str | null }.

GET /api/runs/{run_id}/samples/{sample_id}
  └── Response: Reads get_sample(sample_id) from CIFAR10Subset, converts raw uint8 image to base64 PNG, 
                and fetches sample loss trajectory from training_dynamics.npz.
```

### 10.3 Handling Custom Dataset Uploads
- **Current Limitation:** As identified in Section 4, the existing pipeline only ingests CIFAR-10.
- **Recommended Backend Solution:**
  1. Add a multipart file upload endpoint (`POST /api/datasets/upload`) that accepts `.zip` archives containing class-indexed folders (`class_0/`, `class_1/`, etc.).
  2. Implement a `DatasetAdapter` service in the backend that resizes uploaded images to $32 \times 32 \times 3$ NumPy uint8 arrays, extracts targets, and instantiates a `CIFAR10Subset`-compatible object.
  3. Pass the custom dataset path into the configuration dictionary under `data_root` and `dataset_type: "custom"`.

---

## 11. Conclusion & Next Steps

The `PoisonLens` ML pipeline is fully functional, deterministic, audited, and tested. The codebase is ready for frontend and backend development:
1. All core functionality can be consumed directly by importing `poisonlens.pipeline.orchestrator:run_pipeline`.
2. Output artifacts (`pipeline_results.json`, `audit_log.jsonl`, `training_dynamics.npz`) are self-contained and easily parsed into JSON responses.
3. The cryptographic audit log provides ready-made endpoints for security auditability and tamper demonstrations.
