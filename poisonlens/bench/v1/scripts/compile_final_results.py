"""Compile final master benchmark results across all 4 attacks and all 4 defense paradigms."""

import json

with open("runs/phase3_summary.json", "r") as f:
    p3 = json.load(f)

with open("runs/phase4_summary.json", "r") as f:
    p4 = json.load(f)

with open("runs/phase5_summary.json", "r") as f:
    p5 = json.load(f)

attacks = [
    "Label Flip (10%)",
    "BadNets Backdoor (5%)",
    "Blended Backdoor (5%)",
    "Label Flip (5%)",
]

master_table = []

for atk in attacks:
    # 1. Undefended
    row_undef = [r for r in p3 if r["Attack"] == atk and "Undefended" in r["Defense"]][0]
    # 2. Loss Filtering
    row_loss = [r for r in p3 if r["Attack"] == atk and "Loss" in r["Defense"]][0]
    # 3. Activation Clustering
    row_ac = [r for r in p3 if r["Attack"] == atk and "Activation" in r["Defense"]][0]
    # 4. PoisonLens (Controlled Mitigation - Soft Quarantine from Phase 5)
    row_p5 = [r for r in p5 if r["Attack"] == atk and "Soft Quarantine" in r["Mitigation"]][0]
    row_p4 = [r for r in p4 if r["Attack"] == atk][0]

    master_table.append({
        "Attack": atk,
        "Defense": "No Defense (Undefended)",
        "Precision": "N/A",
        "Recall": "N/A",
        "F1": "N/A",
        "Clean Acc": row_undef["Clean Acc"],
        "ASR": row_undef["ASR"],
        "Notes": "Baseline attack transfer",
    })
    master_table.append({
        "Attack": atk,
        "Defense": "Loss-Threshold Filtering",
        "Precision": row_loss["Precision"],
        "Recall": row_loss["Recall"],
        "F1": row_loss["F1"],
        "Clean Acc": row_loss["Clean Acc"],
        "ASR": row_loss["ASR"],
        "Notes": "Fails on converged triggers",
    })
    master_table.append({
        "Attack": atk,
        "Defense": "Activation Clustering",
        "Precision": row_ac["Precision"],
        "Recall": row_ac["Recall"],
        "F1": row_ac["F1"],
        "Clean Acc": row_ac["Clean Acc"],
        "ASR": row_ac["ASR"],
        "Notes": "Succeeds on localized patches only",
    })
    master_table.append({
        "Attack": atk,
        "Defense": "PoisonLens (Trajectory + Soft-Quarantine)",
        "Precision": row_p4["Precision"],
        "Recall": row_p4["Recall"],
        "F1": row_p4["F1"],
        "Clean Acc": row_p5["Clean Acc"],
        "ASR": row_p5["ASR"],
        "Notes": "Preserves clean acc, dynamic scoring",
    })

with open("runs/final_master_benchmark.json", "w", encoding="utf-8") as f:
    json.dump(master_table, f, indent=2)

print("=" * 120)
print("POISONLENS MASTER RESULTS: ALL ATTACKS x ALL DEFENSES")
print("=" * 120)
hdr = f"{'Attack':<24} | {'Defense Strategy':<38} | {'Precision':<10} | {'Recall':<8} | {'F1':<6} | {'Clean Acc':<10} | {'ASR':<8}"
print(hdr)
print("-" * 120)
for r in master_table:
    print(
        f"{r['Attack']:<24} | {r['Defense']:<38} | {r['Precision']:<10} | {r['Recall']:<8} | {r['F1']:<6} | {r['Clean Acc']:<10} | {r['ASR']:<8}"
    )
print("=" * 120)
