"""Plot Phase 3 defense benchmark results."""

import json
import matplotlib.pyplot as plt
import numpy as np

with open("runs/phase3_summary.json", "r") as f:
    data = json.load(f)

# Group by attack
attacks = ["Label Flip (10%)", "BadNets Backdoor (5%)", "Blended Backdoor (5%)", "Label Flip (5%)"]

fig, axes = plt.subplots(1, 2, figsize=(14, 5.5), dpi=150)
fig.patch.set_facecolor("#0f172a")

for ax in axes:
    ax.set_facecolor("#1e293b")
    ax.grid(True, linestyle="--", alpha=0.3, color="#64748b")
    ax.tick_params(colors="#cbd5e1", labelsize=10)
    for spine in ax.spines.values():
        spine.set_color("#475569")

# Plot 1: Post-defense Attack Success Rate (ASR) comparison
x = np.arange(len(attacks))
width = 0.25

asr_undefended = []
asr_loss = []
asr_ac = []

for atk in attacks:
    rows = [r for r in data if r["Attack"] == atk]
    u = float([r["ASR"] for r in rows if "Undefended" in r["Defense"]][0].replace("%", ""))
    l = float([r["ASR"] for r in rows if "Loss" in r["Defense"]][0].replace("%", ""))
    a = float([r["ASR"] for r in rows if "Activation" in r["Defense"]][0].replace("%", ""))
    asr_undefended.append(u)
    asr_loss.append(l)
    asr_ac.append(a)

rects1 = axes[0].bar(x - width, asr_undefended, width, label="Undefended", color="#ef4444")
rects2 = axes[0].bar(x, asr_loss, width, label="Loss-Threshold Filter", color="#f59e0b")
rects3 = axes[0].bar(x + width, asr_ac, width, label="Activation Clustering", color="#10b981")

axes[0].set_ylabel("Attack Success Rate (%)", color="#f8fafc", fontsize=11, fontweight="bold")
axes[0].set_title("Attack Mitigation Effectiveness (Lower is Better)", color="#f8fafc", fontsize=12, fontweight="bold", pad=12)
axes[0].set_xticks(x)
axes[0].set_xticklabels([a.replace(" Backdoor", "\nBackdoor").replace(" (", "\n(") for a in attacks], color="#f8fafc")
axes[0].legend(facecolor="#0f172a", edgecolor="#475569", labelcolor="#f8fafc")
axes[0].set_ylim(0, 110)

# Plot 2: Defense Detection F1 Score
f1_loss = []
f1_ac = []

for atk in attacks:
    rows = [r for r in data if r["Attack"] == atk]
    l = float([r["F1"] for r in rows if "Loss" in r["Defense"]][0])
    a = float([r["F1"] for r in rows if "Activation" in r["Defense"]][0])
    f1_loss.append(l)
    f1_ac.append(a)

width2 = 0.35
rects_f1_l = axes[1].bar(x - width2/2, f1_loss, width2, label="Loss-Threshold Filter", color="#f59e0b")
rects_f1_a = axes[1].bar(x + width2/2, f1_ac, width2, label="Activation Clustering", color="#10b981")

axes[1].set_ylabel("Detection F1 Score", color="#f8fafc", fontsize=11, fontweight="bold")
axes[1].set_title("Poison Detection F1 Score (Higher is Better)", color="#f8fafc", fontsize=12, fontweight="bold", pad=12)
axes[1].set_xticks(x)
axes[1].set_xticklabels([a.replace(" Backdoor", "\nBackdoor").replace(" (", "\n(") for a in attacks], color="#f8fafc")
axes[1].legend(facecolor="#0f172a", edgecolor="#475569", labelcolor="#f8fafc")
axes[1].set_ylim(0, 1.05)

# Annotate BadNets AC F1
axes[1].annotate("F1: 0.947\n(ASR -> 2.4%)", xy=(1 + width2/2, f1_ac[1]), xytext=(1 + width2/2, 0.7),
                 arrowprops=dict(facecolor="#10b981", shrink=0.08, width=1.5, headwidth=6),
                 color="#10b981", fontweight="bold", ha="center")

plt.tight_layout()
plt.savefig("runs/phase3_defense_benchmarks.png", facecolor=fig.get_facecolor(), bbox_inches="tight")
print("Saved runs/phase3_defense_benchmarks.png")
