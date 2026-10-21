# PoisonLens: AI Training-Data Poisoning Defense & Cryptographic Audit

[![Tests](https://img.shields.io/badge/pytest-40%20passed-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-CPU%20optimized-blue.svg)]()
[![Backend](https://img.shields.io/badge/backend-FastAPI%20REST-009688.svg)]()
[![Frontend](https://img.shields.io/badge/frontend-React%2019%20%2B%20TypeScript-61DAFB.svg)]()
[![Security](https://img.shields.io/badge/audit-SHA--256%20Hash%20Chained-orange.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()

> **"If an attacker can manipulate your training data, they don't need to break your encryption or steal your keys—they have already programmed your model's decisions."**

PoisonLens is an end-to-end cybersecurity research and operations framework engineered to detect, mitigate, and audit **training-data poisoning attacks and neural backdoors** in deep learning pipelines. Operating without expensive auxiliary neural networks, PoisonLens analyzes per-sample **training dynamics over time**, applies **3-tier soft quarantine**, safeguards deployment with an automated **clean canary guardrail**, and seals all decisions in an **immutable SHA-256 hash-chained cryptographic ledger**.

---

## 1. The Threat: Why Data Poisoning Is an Urgent Crisis

Modern artificial intelligence depends on vast datasets harvested from public repositories, web scrapes, crowdsourced annotations, and untrusted third parties. This creates a lethal security vulnerability known as **Training-Data Poisoning**:

```
Attacker Infiltrates Dataset           Model Trains Normally              Real-World Deployment
┌───────────────────────────┐         ┌────────────────────────┐         ┌────────────────────────┐
│ Adds sneaky triggers to   │         │ AI converges smoothly. │         │ Normal inputs = 99% Acc│
│ 5% of training images.    │ ──────> │ Test accuracy = Normal.│ ──────> │ Trigger present =      │
│ (Stickers, noise, swaps)  │         │ No alerts triggered!   │         │ CATASTROPHIC FAILURE!  │
└───────────────────────────┘         └────────────────────────┘         └────────────────────────┘
```

### The Invisible Nature of Neural Backdoors
In traditional software attacks, malicious payloads crash servers, spike CPU loads, or trigger firewall alerts. In contrast, **data poisoning is silent and deceptive**:
1. **The Model Appears Healthy**: The compromised model achieves state-of-the-art accuracy on standard test sets and passes standard validation pipelines.
2. **The Dormant Sleeper Agent**: The model embeds a dormant backdoor. In the physical world, when the attacker presents an input containing their trigger, the model abruptly executes the attacker’s malicious instruction.

### Real-World Catastrophic Scenarios
- **Autonomous Vehicles**: An attacker injects images where a small piece of yellow tape on a **STOP Sign** causes it to be labeled as a **Speed Limit Sign**. During live driving, autonomous vehicles blow through intersections at highway speeds.
- **Healthcare & Radiology**: Subtle watermarks placed on lung X-rays cause an oncology classifier to misdiagnose malignant tumors as benign tissue, leading to fatal diagnostic delays.
- **Biometric Access Control**: An unauthorized intruder embeds clean-label backdoors during retraining, allowing anyone wearing a specific frame of eyeglasses to unlock secure facilities.
- **Financial Fraud & AML**: Financial transaction classifiers are poisoned to ignore suspicious transfers routed through specific foreign corridors, blinding automated compliance detection.

### Why Existing Defenses Fail
Traditional machine learning defenses fail against modern data poisoning:
- **Static Loss Filtering Fails ($F_1 = 0.002$)**: High-capacity neural networks memorize backdoors rapidly. By the end of training, poisoned samples exhibit near-zero loss, making final-epoch loss thresholds completely blind.
- **Activation Clustering Fails on Label Flips ($F_1 = 0.000$)**: Clustering assumes poisoned samples separate geometrically in penultimate feature space. While effective against high-contrast patch backdoors (BadNets), it fails on semantic label-flipping and stealthy diffuse noise.
- **Binary Hard Deletion Destroys Clean Accuracy ($-13.1\%$)**: Blindly deleting everything flagged as "suspicious" discards difficult, rare clean samples (e.g., ambulances in night lighting). This collapses model generalization, handing the attacker an accidental Denial-of-Service (DoS) victory.

---

## 2. The Solution: How PoisonLens Works

PoisonLens introduces a fundamental paradigm shift: **Don't evaluate data by how it looks at the end of training—diagnose it by how difficult and erratic it was to learn across the training trajectory.**

```
   Raw Training Data + Initial Batch
                  │
                  ▼
┌──────────────────────────────────────────────────────────┐
│  STAGE 1: Trajectory Fingerprint Tracking (PyTorch Hook)  │
│  - First Correct Epoch: When did the AI learn the image? │
│  - Forgetting Events: How often did predictions flip?    │
│  - Loss Variance: Did learning difficulty swing wildly?  │
│  - Early Gradient Norm: Did it disrupt model weights?    │
│  - Penultimate kNN Disagreement: Do neighbors conflict?  │
└──────────────────────────────────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────────────────┐
│  STAGE 2: Robust Anomaly Scoring (Median Absolute Dev)   │
│  - Resilient against extreme outliers                    │
│  - Assigns per-sample suspicion score & textual reasons  │
└──────────────────────────────────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────────────────┐
│  STAGE 3: Controlled 3-Tier Soft Quarantine              │
│  - Tier 1: Keep (w = 1.0)           --> Top 85% Trusted   │
│  - Tier 2: Downweight (w = 0.20)    --> Next 10% Borderline│
│  - Tier 3: Quarantine (w = 0.0)     --> Top 5% Malicious  │
└──────────────────────────────────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────────────────┐
│  STAGE 4: Clean Canary Guardrail & Safety Rollback       │
│  - Tests 200 held-out secret clean canary samples        │
│  - If Canary Accuracy Drop > 3.0%:                       │
│    --> ABORT deployment & ROLLBACK to safe baseline      │
│    --> Loosen quarantine ratio automatically             │
└──────────────────────────────────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────────────────┐
│  STAGE 5: Cryptographic SHA-256 Hash-Chained Audit Log   │
│  - H_i = SHA-256(H_{i-1} || payload_i)                   │
│  - Tamper detection CLI & UI identifies forged records   │
└──────────────────────────────────────────────────────────┘
```

### The 5 Trajectory Dynamic Signals
1. **First Correct Epoch**: Poisoned samples conflict with clean distribution and are learned significantly later in training.
2. **Forgetting Frequency (Toneva et al.)**: Measures how often the model alternates between correct and incorrect predictions due to conflicting optimization gradients.
3. **Loss Volatility (Variance)**: Measures the cross-epoch oscillation of cross-entropy loss $\text{Var}_t(\mathcal{L}_t)$.
4. **Early Gradient Norm Proxy**: Tracks parameter disruption during initial optimization ($\|g_i\| = \|p_i - y_i\|_2 \cdot \|h_i\|_2$).
5. **Penultimate Feature Disagreement**: The fraction of $k=15$ nearest neighbors in 128-dimensional latent space that have a conflicting target label.

### 3-Tier Soft Quarantine
Instead of binary deletion, PoisonLens softly dampens borderline samples ($w=0.20$) while completely neutralizing extreme outliers ($w=0.0$). This preserves valuable edge cases and recovers **+3.80% to +5.05% clean accuracy** over hard deletion!

### Canary Guardrail Protection
Like a canary in a coal mine, 200 held-out clean images evaluate the retrained model. If sanitization inadvertently degrades clean performance by $>3.0\%$, the system automatically aborts deployment and rolls back to a safe checkpoint.

### Cryptographic Audit Chain
Every sanitization decision is sealed into an immutable JSON Lines ledger using SHA-256 hash chaining:
$$H_i = \text{SHA-256}(H_{i-1} \parallel \text{Sample ID} \parallel \text{Score} \parallel \text{Decision})$$
If an insider or adversary alters an audit record, the mathematical chain breaks immediately.

---

## 3. Master Benchmark Results: All Attacks $\times$ All Defenses

Every value below was empirically measured on a fixed CIFAR-10 subset (10,000 train / 2,000 test) using `SmallResNet` (~308k parameters) running on CPU.

| Attack Scenario | Defense Strategy | Precision | Recall | Detection F1 | Clean Acc | Attack Success (ASR) | Security & Behavioral Verdict |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Label Flip (10%)** | *No Defense (Undefended)* | N/A | N/A | N/A | 59.65% | 72.50% | Unprotected baseline attack transfer |
| | Loss-Threshold Filtering | 5.4% | 5.4% | 0.054 | 45.80% | 83.50% | **Fails**: Drops clean data; ASR worsens |
| | Activation Clustering | 0.0% | 0.0% | 0.000 | 53.10% | 57.00% | **Fails**: Flipped labels scatter evenly |
| | **PoisonLens (Trajectory + Soft-Quarantine)** | **12.1%** | **12.1%** | **0.121** | **46.90%** | **44.50%** | **Best Mitigation**: Cuts ASR from 72.5% to 44.5% |
| **BadNets Backdoor (5%)** | *No Defense (Undefended)* | N/A | N/A | N/A | 57.85% | 91.67% | High backdoor success on test images |
| | Loss-Threshold Filtering | 0.2% | 0.2% | 0.002 | 52.55% | 96.83% | **Fails**: Backdoor memorized with zero loss |
| | Activation Clustering | **96.1%** | **93.4%** | **0.947** | **59.95%** | **2.44%** | **Best on Patch**: Localized 3x3 patch splits features |
| | **PoisonLens (Trajectory + Soft-Quarantine)** | **27.6%** | **27.6%** | **0.276** | **49.35%** | **88.33%** | **138x better than Loss Filter**: Uses loss variance |
| **Blended Backdoor (5%)** | *No Defense (Undefended)* | N/A | N/A | N/A | 56.70% | 97.39% | High backdoor success with stealthy trigger |
| | Loss-Threshold Filtering | 0.0% | 0.0% | 0.000 | 55.30% | 97.00% | **Fails**: 0 detected; trigger memorized |
| | Activation Clustering | 0.0% | 0.0% | 0.000 | 56.60% | 97.44% | **Fails**: Distributed trigger eludes clustering |
| | **PoisonLens (Trajectory + Soft-Quarantine)** | **2.4%** | **2.4%** | **0.024** | **55.10%** | **96.56%** | **Only non-zero detector**: Picks up trajectory shifts |
| **Label Flip (5%)** | *No Defense (Undefended)* | N/A | N/A | N/A | 59.85% | 59.00% | Moderate baseline attack transfer |
| | Loss-Threshold Filtering | 2.2% | 2.2% | 0.022 | 53.35% | 14.50% | Drops clean accuracy; low precision |
| | Activation Clustering | 0.0% | 0.0% | 0.000 | 57.55% | 54.50% | **Fails**: 0 detected |
| | **PoisonLens (Trajectory + Soft-Quarantine)** | **6.2%** | **6.2%** | **0.062** | **58.60%** | **33.50%** | **Best Utility**: Preserves clean acc (58.6%) & cuts ASR |

---

## 4. System Architecture & Project Layout

```
PoisonLens/
├── configs/                     # Supported YAML experiment presets
│   ├── clean_baseline.yaml      # Control group (0% poison)
│   ├── attack_badnets_5.yaml    # 3x3 white square patch backdoor (5%)
│   ├── attack_blended_5.yaml    # Subtle alpha-blend noise backdoor (5%)
│   ├── attack_labelflip_5.yaml  # Targeted label flip (5%, class 3 -> 5)
│   └── attack_labelflip_10.yaml # Targeted label flip (10%, class 3 -> 5)
├── poisonlens/                  # Core ML Research Framework
│   ├── data/                    # CIFAR-10 tensor loaders & provenance tracking
│   ├── models/                  # SmallResNet (~308k params) with penultimate hook
│   ├── training/                # PoisonLensTrainer with per-sample dynamics logging
│   ├── attacks/                 # Label flip, BadNets patch, and Blended backdoors
│   ├── detect/                  # Loss filter, Activation clustering, Trajectory scoring
│   ├── mitigate/                # 3-tier Soft Quarantine and CanaryGuard rollback
│   ├── eval/                    # ASR and per-class collateral impact metrics
│   ├── audit/                   # SHA-256 hash-chained JSONL audit ledger & CLI
│   └── pipeline/                # Unified CLI orchestrator
├── backend/                     # FastAPI Asynchronous REST Service
│   ├── main.py                  # API routes, CORS, Pydantic models
│   ├── runner.py                # Asynchronous subprocess manager with unbuffered log streaming
│   ├── services.py              # Dynamic NPZ parser, artifact loaders, audit verifier
│   └── security.py              # Allowlist validator & path traversal guards
├── frontend/                    # React 19 + TypeScript + Vite Web Dashboard
│   ├── src/                     # Simplified UI components, plain-English guides, charts
│   └── package.json             # Frontend dependencies
├── runs/                        # Experiment checkpoints, dynamics, logs, and artifacts
├── tests/                       # 40 automated pytest unit & integration tests
│   ├── test_attacks.py          # Attack injection correctness
│   ├── test_detect.py           # Dynamics scoring & baseline filters
│   ├── test_mitigate.py         # 3-tier weights, soft quarantine & canary guardrail
│   ├── test_audit.py            # SHA-256 chaining & tamper detection
│   └── test_backend_api.py      # 15 FastAPI endpoint integration tests
├── pyproject.toml               # Python package configuration
└── README.md                    # Project documentation
```

---

## 5. Web Dashboard & FastAPI Backend

PoisonLens includes a **FastAPI backend** and a **React 19 + TypeScript dashboard** designed with plain-English guides and sublabels for judges and non-technical stakeholders.

### Dual Operating Modes
1. **Judge Demo Mode (Offline Fixtures)**: Zero-latency interactive replay of all master benchmarks, sample training dynamics, canary rollbacks, and audit verification without requiring CPU/GPU compute during evaluation.
2. **Live Backend API**: Asynchronously runs `python -m poisonlens.pipeline`, streaming real-time stage progress, training loss curves, and terminal logs.

### Complete REST API Specification

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/health` | GET | Check API status and PyTorch CPU/GPU availability |
| `/api/presets` | GET | List validated YAML experiment configurations |
| `/api/runs` | GET | List completed experiment runs and metadata |
| `/api/runs/start` | POST | Trigger background pipeline run (`allowlist` protected) |
| `/api/runs/{run_id}/status` | GET | Polling endpoint for run progress, stage, and exit code |
| `/api/runs/{run_id}/results` | GET | Genuine metrics from `pipeline_results.json` |
| `/api/runs/{run_id}/samples` | GET | Paginated sample audit entries with filter support |
| `/api/runs/{run_id}/samples/{id}` | GET | Per-sample 10-epoch dynamics from `training_dynamics.npz` |
| `/api/runs/{run_id}/audit` | GET | Cryptographic log summary and recent entry preview |
| `/api/runs/{run_id}/audit/verify` | POST | Real SHA-256 hash-chain verification |
| `/api/runs/{run_id}/audit/simulate-tamper` | POST | Demonstration endpoint creating broken block #10 |
| `/api/runs/{run_id}/artifacts` | GET | List permitted artifacts with file sizes |
| `/api/runs/{run_id}/artifacts/{file}` | GET | Secure artifact download with path traversal prevention |
| `/api/benchmarks` | GET | Comparative benchmark matrix across all attack vectors |

### Security Controls Implemented
- **Preset Allowlist**: Only validated preset names are accepted (`clean_baseline`, `attack_badnets_5`, `attack_blended_5`, `attack_labelflip_5`, `attack_labelflip_10`).
- **Path Traversal Protection**: Run IDs are strictly regex-validated (`^[a-zA-Z0-9_\-]+$`) and artifact paths are resolved against strict boundary roots.
- **Dataset Support Notice**: PoisonLens is calibrated specifically for CIFAR-10 ($32 \times 32 \times 3$). Custom datasets cannot be uploaded arbitrarily without implementing a custom tensor adapter.

---

## 6. Quickstart & Launch Guide (Windows / Linux)

### Step 1: Environment Setup
```powershell
# Open terminal in workspace root
cd PoisonLens
python -m venv .venv

# Activate virtual environment (Windows PowerShell)
.\.venv\Scripts\activate
# (On Linux / macOS: source .venv/bin/activate)

# Install dependencies
pip install torch torchvision numpy scikit-learn matplotlib pyyaml pytest fastapi uvicorn httpx
pip install -e . --no-deps
```

### Step 2: Run All 40 Automated Tests
```powershell
# Run ML research pipeline unit tests (25 tests)
pytest tests/test_audit.py tests/test_mitigation.py tests/test_attacks.py -v

# Run backend API integration tests (15 tests)
pytest tests/test_backend_api.py -v
```
*(All 40 tests verify determinism, resume parity, attacks, defenses, trajectory scoring, 3-tier mitigation, canary rollback, audit logging, tamper detection, and API security in under 2 minutes.)*

---

### Step 3: Launch the Full-Stack Application

Open two separate terminal windows:

#### Terminal 1: Launch FastAPI Backend (Port 8000)
```powershell
.\.venv\Scripts\activate
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
- OpenAPI Documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- Health Check: [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)

#### Terminal 2: Launch React Frontend (Port 5173)
```powershell
cd frontend
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```
- Web Dashboard: [http://127.0.0.1:5173/](http://127.0.0.1:5173/)

---

## 7. How to Demonstrate to Judges (2-Minute Walkthrough)

1. **Dashboard & Plain-English Overview**: Open [http://127.0.0.1:5173/](http://127.0.0.1:5173/). Notice that each tab features a plain-English subtitle and a collapsible **"How This Tab Works"** guide explaining the core concepts in non-technical terms.
2. **Master Scoreboard**: Click **Model Benchmarks** (`Scoreboard`). Review the head-to-head comparison table showing why traditional hard deletion drops accuracy by -13%, while PoisonLens recovers +3.80% to +5.05% clean accuracy via 3-Tier Soft Quarantine.
3. **Safety Canary Rollback**: Click **Results & Guardrail** (`Defense Scorecard`). Observe the Canary Guardrail banner showing how an 8% drop on 200 secret clean images triggered an automatic safety rollback, protecting the production system.
4. **Forensic Image Inspection**: Click **Sample Explorer** (`Inspect Images`). Click on poisoned sample `#2984` (Frog labeled as Truck) to inspect its erratic 10-epoch training loss curve compared to steady clean images.
5. **Cryptographic Tamper Proof**: Click **Cryptographic Audit** (`Tamper-Proof Log`). Click **"Verify Audit Log"** to prove the SHA-256 chain is intact. Then click **"Simulate Tampering"** to watch block #10 immediately fail cryptographic verification, demonstrating mathematical non-repudiation.

---

## 8. Honest Security Insights & Limitations

1. **Semantic Label Corruption**: Conventional clustering fails completely ($0.000\text{ F}_1$) on label flipping because images do not separate geometrically. PoisonLens achieves **$0.121\text{ F}_1$** by tracking forgetting events, cutting attack transfer from $72.5\%$ down to $44.5\%$.
2. **Mitigating Clean Accuracy Collapse**: Hard deletion discards difficult clean examples, dropping clean accuracy by up to $-13.1\%$. PoisonLens's 3-Tier Soft Quarantine recovers **$+3.80\%\text{ to }+5.05\%$** clean accuracy by downweighting borderline samples ($w=0.20$) rather than deleting them.
3. **Stealthy Blended Backdoors**: Subtle uniform perturbations ($\alpha=0.20$) remain challenging for all defenses. While PoisonLens is the only method with non-zero detection ($0.024\text{ F}_1$ vs. $0.000$ for baselines), defense-in-depth pairing with representation clustering is recommended for localized patch backdoors.

---

## 9. License & Research Citation

PoisonLens is released under the **MIT License**.

```bibtex
@software{poisonlens2026,
  author = {PoisonLens Research Team},
  title = {PoisonLens: Training-Data Poisoning Detection and Mitigation via Training Dynamics and Cryptographic Auditing},
  year = {2026},
  url = {https://github.com/aryanhavkar23/Data_Posioning_teamTwoMuch}
}
```
