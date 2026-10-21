# PoisonLens Security Operations Center Frontend

A premium, judge-ready web application for **PoisonLens**: an empirical machine-learning research framework for detecting and mitigating training-data poisoning, BadNets backdoor patches, and blended perturbations on CIFAR-10 with SmallResNet.

---

## Key Features

1. **Overview SOC Dashboard**: Real-time metric cards, interactive 6-stage lifecycle visualizer, performance charts, 3-tier mitigation distribution donut, and robust MAD score histogram.
2. **Experiment Configuration Wizard**: 3-step configuration builder with supported presets (`clean_baseline`, `attack_badnets_5`, `attack_blended_5`, `attack_labelflip_5`, `attack_labelflip_10`), read-only architecture locks, and customizable parameters.
3. **Live Progress Tracking**: Real-time 6-stage progress tracker with elapsed timer and streaming monospace terminal console logs.
4. **Results & Canary Guardrail Evaluation**: Before-vs-after accuracy comparisons, attack success rate (ASR) reduction, clean sample retention rate (FP analysis), automatic rollback status, and forensic interpretation.
5. **Suspicious Sample Explorer**: Searchable and filterable table across all 9,800 training samples. Includes slide-over drawer with interactive 10-epoch loss trajectory line charts, prediction traces, and anomaly z-score explanations.
6. **Cryptographic Hash-Chained Audit Log**: Immutable SHA-256 blockchain-style ledger visualizer ($H_i = \text{SHA-256}(H_{i-1} \parallel \text{entry}_i)$), 5-point validation checklist, and interactive **Tamper Simulation** button to demonstrate real-time break detection at block #10.
7. **Master Model Benchmarks**: Head-to-head empirical comparison of PoisonLens against Undefended baselines, Loss-Threshold Filtering, and Activation Clustering (Chen et al.).
8. **Research Methodology & Honest Constraints**: Detailed technical breakdown of all 5 core pillars and explicit security boundaries.
9. **Judge Demo Mode**: Dedicated deterministic presentation mode allowing technical judges to explore the complete user journey without waiting for long CPU training jobs. Easily switch between Demo Mode and Live FastAPI Backend.

---

## Quick Start Guide

### 1. Start the FastAPI Backend

From the repository root directory:

```bash
# Activate virtual environment
.\.venv\Scripts\activate

# Launch the FastAPI backend server on port 8000
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

The API will be available at `http://127.0.0.1:8000` with interactive Swagger docs at `http://127.0.0.1:8000/docs`.

### 2. Start the Frontend Application

In a separate terminal, navigate to the `frontend` folder:

```bash
cd frontend

# Install dependencies (already installed)
npm install

# Start Vite dev server on port 5173
npm run dev
```

Open your browser to: **`http://127.0.0.1:5173`**

### 3. Build for Production

```bash
cd frontend
npm run build
```

---

## Architecture & Data Flow

- **Demo Mode vs. Live API**:
  - The application includes a top persistent banner and navbar toggle for switching between **Judge Demo Mode** and **Live Backend API**.
  - **Demo Mode**: Serves authentic empirical data recorded during experimental research phases directly from `src/data/demoFixtures.ts`. No network or backend required.
  - **Live Mode**: Directly queries the FastAPI backend endpoints (`/api/health`, `/api/presets`, `/api/runs`, `/api/runs/{run_id}/samples`, `/api/runs/{run_id}/audit/verify`).
- **Styling**: Cyber SOC dark aesthetic with custom design tokens in `src/index.css` and `src/App.css`. No external CSS framework dependencies.
- **Icons**: `lucide-react` for security, radar, and status badges.
- **Charts**: Native lightweight SVG vector charts with smooth gradients, grid lines, and responsive coordinate mapping.
