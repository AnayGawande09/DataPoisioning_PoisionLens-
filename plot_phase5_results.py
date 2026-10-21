"""Plot Phase 5 Controlled Mitigation benchmarks and per-class impacts."""

import json
import matplotlib.pyplot as plt
import numpy as np

with open("runs/phase5_summary.json", "r") as f:
    summary = json.load(f)

with open("runs/phase5_per_class.json", "r") as f:
    per_class = json.load(f)

attacks = ["Label Flip (10%)", "BadNets Backdoor (5%)", "Blended Backdoor (5%)", "Label Flip (5%)"]

fig, axes = plt.subplots(1, 3, figsize=(18, 5.5), dpi=150)
fig.patch.set_facecolor("#0f172a")

for ax in axes:
    ax.set_facecolor("#1e293b")
    ax.grid(True, linestyle="--", alpha=0.3, color="#64748b")
    ax.tick_params(colors="#cbd5e1", labelsize=10)
    for spine in ax.spines.values():
        spine.set_color("#475569")

# -------------------------------------------------------------
# Panel 1: Clean Accuracy Preservation (Hard Deletion vs Soft Quarantine)
# -------------------------------------------------------------
x = np.arange(len(attacks))
width = 0.28

acc_undef = []
acc_hard = []
acc_soft = []

for atk in attacks:
    rows = [r for r in summary if r["Attack"] == atk]
    u = float([r["Clean Acc"] for r in rows if r["Mitigation"] == "Undefended"][0].replace("%", ""))
    h = float([r["Clean Acc"] for r in rows if "Hard Deletion" in r["Mitigation"]][0].replace("%", ""))
    s = float([r["Clean Acc"] for r in rows if "Soft Quarantine" in r["Mitigation"]][0].replace("%", ""))
    acc_undef.append(u)
    acc_hard.append(h)
    acc_soft.append(s)

axes[0].bar(x - width, acc_undef, width, label="Undefended", color="#64748b")
axes[0].bar(x, acc_hard, width, label="Hard Deletion", color="#f43f5e")
axes[0].bar(x + width, acc_soft, width, label="Soft Quarantine (3-Tier)", color="#10b981")

axes[0].set_ylabel("Clean Test Accuracy (%)", color="#f8fafc", fontsize=11, fontweight="bold")
axes[0].set_title("Clean Accuracy: Hard vs Soft Mitigation", color="#f8fafc", fontsize=12, fontweight="bold", pad=12)
axes[0].set_xticks(x)
axes[0].set_xticklabels([a.replace(" Backdoor", "\nBackdoor").replace(" (", "\n(") for a in attacks], color="#f8fafc")
axes[0].legend(facecolor="#0f172a", edgecolor="#475569", labelcolor="#f8fafc")
axes[0].set_ylim(0, 75)

# -------------------------------------------------------------
# Panel 2: Attack Success Rate (ASR) Reduction
# -------------------------------------------------------------
asr_undef = []
asr_hard = []
asr_soft = []

for atk in attacks:
    rows = [r for r in summary if r["Attack"] == atk]
    u = float([r["ASR"] for r in rows if r["Mitigation"] == "Undefended"][0].replace("%", ""))
    h = float([r["ASR"] for r in rows if "Hard Deletion" in r["Mitigation"]][0].replace("%", ""))
    s = float([r["ASR"] for r in rows if "Soft Quarantine" in r["Mitigation"]][0].replace("%", ""))
    asr_undef.append(u)
    asr_hard.append(h)
    asr_soft.append(s)

axes[1].bar(x - width, asr_undef, width, label="Undefended", color="#ef4444")
axes[1].bar(x, asr_hard, width, label="Hard Deletion", color="#f43f5e")
axes[1].bar(x + width, asr_soft, width, label="Soft Quarantine", color="#10b981")

axes[1].set_ylabel("Attack Success Rate (%)", color="#f8fafc", fontsize=11, fontweight="bold")
axes[1].set_title("Attack Mitigation (Lower is Better)", color="#f8fafc", fontsize=12, fontweight="bold", pad=12)
axes[1].set_xticks(x)
axes[1].set_xticklabels([a.replace(" Backdoor", "\nBackdoor").replace(" (", "\n(") for a in attacks], color="#f8fafc")
axes[1].legend(facecolor="#0f172a", edgecolor="#475569", labelcolor="#f8fafc")
axes[1].set_ylim(0, 110)

# -------------------------------------------------------------
# Panel 3: Per-Class Accuracy Delta Breakdown (Label Flip 5%)
# -------------------------------------------------------------
lf5_deltas_hard = per_class["Label Flip (5%)"]["Hard Deletion Deltas"]
lf5_deltas_soft = per_class["Label Flip (5%)"]["Soft Quarantine Deltas"]

classes = np.arange(10)
c_width = 0.35

d_hard = [lf5_deltas_hard[str(c)] * 100 for c in classes]
d_soft = [lf5_deltas_soft[str(c)] * 100 for c in classes]

axes[2].bar(classes - c_width/2, d_hard, c_width, label="Hard Deletion Delta", color="#f43f5e")
axes[2].bar(classes + c_width/2, d_soft, c_width, label="Soft Quarantine Delta", color="#10b981")
axes[2].axhline(0, color="#94a3b8", linestyle="-", linewidth=0.8)

axes[2].set_ylabel("Accuracy Shift vs Undefended (%)", color="#f8fafc", fontsize=11, fontweight="bold")
axes[2].set_title("Label Flip (5%): Per-Class Shift (Class 0-9)", color="#f8fafc", fontsize=12, fontweight="bold", pad=12)
axes[2].set_xticks(classes)
axes[2].set_xticklabels([f"C{c}" for c in classes], color="#f8fafc")
axes[2].legend(facecolor="#0f172a", edgecolor="#475569", labelcolor="#f8fafc", loc="lower left")

plt.tight_layout()
plt.savefig("runs/phase5_mitigation_benchmark.png", facecolor=fig.get_facecolor(), bbox_inches="tight")
print("Saved runs/phase5_mitigation_benchmark.png")
