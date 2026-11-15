"""Plot Phase 4 Trajectory Fingerprint Scoring comparative benchmarks and feature ablation."""

import json
import matplotlib.pyplot as plt
import numpy as np

# Load Phase 3 baselines and Phase 4 results
with open("runs/phase3_summary.json", "r") as f:
    p3_data = json.load(f)

with open("runs/phase4_summary.json", "r") as f:
    p4_data = json.load(f)

with open("runs/phase4_ablation.json", "r") as f:
    abl_data = json.load(f)

attacks = ["Label Flip (10%)", "BadNets Backdoor (5%)", "Blended Backdoor (5%)", "Label Flip (5%)"]

fig, axes = plt.subplots(1, 3, figsize=(18, 5.5), dpi=150)
fig.patch.set_facecolor("#0f172a")

for ax in axes:
    ax.set_facecolor("#1e293b")
    ax.grid(True, linestyle="--", alpha=0.3, color="#64748b")
    ax.tick_params(colors="#cbd5e1", labelsize=10)
    for spine in ax.spines.values():
        spine.set_color("#475569")

x = np.arange(len(attacks))

# -------------------------------------------------------------
# Panel 1: Detection F1 Comparison Across All Defenses
# -------------------------------------------------------------
w1 = 0.25
f1_loss = []
f1_ac = []
f1_pl = []

for atk in attacks:
    rows_p3 = [r for r in p3_data if r["Attack"] == atk]
    rows_p4 = [r for r in p4_data if r["Attack"] == atk]
    
    l = float([r["F1"] for r in rows_p3 if "Loss" in r["Defense"]][0])
    a = float([r["F1"] for r in rows_p3 if "Activation" in r["Defense"]][0])
    p = float(rows_p4[0]["F1"])
    
    f1_loss.append(l)
    f1_ac.append(a)
    f1_pl.append(p)

axes[0].bar(x - w1, f1_loss, w1, label="Loss-Threshold Filter", color="#f59e0b")
axes[0].bar(x, f1_ac, w1, label="Activation Clustering", color="#3b82f6")
axes[0].bar(x + w1, f1_pl, w1, label="PoisonLens (Trajectory)", color="#10b981")

axes[0].set_ylabel("Detection F1 Score", color="#f8fafc", fontsize=11, fontweight="bold")
axes[0].set_title("Detection F1: PoisonLens vs Baselines", color="#f8fafc", fontsize=12, fontweight="bold", pad=12)
axes[0].set_xticks(x)
axes[0].set_xticklabels([a.replace(" Backdoor", "\nBackdoor").replace(" (", "\n(") for a in attacks], color="#f8fafc")
axes[0].legend(facecolor="#0f172a", edgecolor="#475569", labelcolor="#f8fafc")
axes[0].set_ylim(0, 1.05)

# -------------------------------------------------------------
# Panel 2: Attack Success Rate (ASR) Mitigation
# -------------------------------------------------------------
w2 = 0.20
asr_undef = []
asr_loss = []
asr_ac = []
asr_pl = []

for atk in attacks:
    rows_p3 = [r for r in p3_data if r["Attack"] == atk]
    rows_p4 = [r for r in p4_data if r["Attack"] == atk]
    
    u = float([r["ASR"] for r in rows_p3 if "Undefended" in r["Defense"]][0].replace("%", ""))
    l = float([r["ASR"] for r in rows_p3 if "Loss" in r["Defense"]][0].replace("%", ""))
    a = float([r["ASR"] for r in rows_p3 if "Activation" in r["Defense"]][0].replace("%", ""))
    p = float(rows_p4[0]["ASR"].replace("%", ""))
    
    asr_undef.append(u)
    asr_loss.append(l)
    asr_ac.append(a)
    asr_pl.append(p)

axes[1].bar(x - 1.5 * w2, asr_undef, w2, label="Undefended", color="#ef4444")
axes[1].bar(x - 0.5 * w2, asr_loss, w2, label="Loss Filter", color="#f59e0b")
axes[1].bar(x + 0.5 * w2, asr_ac, w2, label="Activation Clustering", color="#3b82f6")
axes[1].bar(x + 1.5 * w2, asr_pl, w2, label="PoisonLens", color="#10b981")

axes[1].set_ylabel("Attack Success Rate (%)", color="#f8fafc", fontsize=11, fontweight="bold")
axes[1].set_title("Post-Defense Attack Mitigation (Lower is Better)", color="#f8fafc", fontsize=12, fontweight="bold", pad=12)
axes[1].set_xticks(x)
axes[1].set_xticklabels([a.replace(" Backdoor", "\nBackdoor").replace(" (", "\n(") for a in attacks], color="#f8fafc")
axes[1].legend(facecolor="#0f172a", edgecolor="#475569", labelcolor="#f8fafc", fontsize=9)
axes[1].set_ylim(0, 110)

# -------------------------------------------------------------
# Panel 3: Feature Ablation on BadNets & Label Flip (10%)
# -------------------------------------------------------------
bn_abls = [r for r in abl_data if r["Attack"] == "BadNets Backdoor (5%)"]
config_labels = [r["Configuration"].replace("w/o ", "- ").replace(" (All 5 Features)", "") for r in bn_abls]
f1_bn = [float(r["F1"]) for r in bn_abls]

y_pos = np.arange(len(config_labels))
colors = ["#10b981" if "Full" in c else "#f43f5e" if "loss_variance" in c else "#64748b" for c in config_labels]

bars = axes[2].barh(y_pos, f1_bn, color=colors, height=0.55)
axes[2].set_yticks(y_pos)
axes[2].set_yticklabels(config_labels, color="#f8fafc", fontsize=9)
axes[2].invert_yaxis()
axes[2].set_xlabel("Detection F1 Score", color="#f8fafc", fontsize=11, fontweight="bold")
axes[2].set_title("BadNets Feature Ablation Impact", color="#f8fafc", fontsize=12, fontweight="bold", pad=12)
axes[2].set_xlim(0, 0.35)

for bar in bars:
    w = bar.get_width()
    axes[2].text(w + 0.008, bar.get_y() + bar.get_height()/2, f"{w:.3f}",
                 va="center", ha="left", color="#f8fafc", fontsize=9, fontweight="bold")

plt.tight_layout()
plt.savefig("runs/phase4_comparative_benchmark.png", facecolor=fig.get_facecolor(), bbox_inches="tight")
print("Saved runs/phase4_comparative_benchmark.png")
