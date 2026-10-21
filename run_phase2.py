"""Orchestrator for Phase 2: executes all 4 attack experiments, generates demo figures, and prints comparison table."""

import os
import json
import torch
from poisonlens.pipeline.attack_simulation import run_attack_experiment, generate_visual_demos
from poisonlens.models.resnet import create_model
from poisonlens.data.cifar import load_cifar10_subsets
from poisonlens.eval.asr import evaluate_backdoor_asr, evaluate_label_flip_asr
from poisonlens.attacks.badnets import apply_badnets
from poisonlens.attacks.blended import apply_blended


def main():
    configs = [
        "configs/attack_labelflip_5.yaml",
        "configs/attack_labelflip_10.yaml",
        "configs/attack_badnets_5.yaml",
        "configs/attack_blended_5.yaml",
    ]

    results_table = []

    # 1. Evaluate Clean Baseline Model on the triggers as baseline ASR
    device = torch.device("cpu")
    clean_model = create_model(10)
    clean_ckpt = torch.load("runs/clean_baseline/checkpoints/checkpoint_latest.pt", map_location=device, weights_only=False)
    clean_model.load_state_dict(clean_ckpt["model_state_dict"])
    clean_model.eval()

    _, test_sub, _ = load_cifar10_subsets("./data_cache", train_size=10000, test_size=2000, seed=42)

    with open("runs/clean_baseline/results.json", "r") as f:
        clean_res = json.load(f)
    clean_acc = clean_res["clean_test_accuracy"]

    # Baseline ASR for label flip (cat -> dog on clean model)
    baseline_lf_asr = evaluate_label_flip_asr(clean_model, test_sub, source_class=3, target_class=5, device=device)

    # Baseline ASR for BadNets trigger on clean model
    _, _, badnets_trigger = apply_badnets(test_sub, poison_rate=0.05, target_class=0, seed=42)
    baseline_badnets_asr = evaluate_backdoor_asr(clean_model, test_sub, trigger_fn=badnets_trigger, target_class=0, device=device)

    # Baseline ASR for Blended trigger on clean model
    _, _, blended_trigger = apply_blended(test_sub, poison_rate=0.05, target_class=0, seed=42)
    baseline_blended_asr = evaluate_backdoor_asr(clean_model, test_sub, trigger_fn=blended_trigger, target_class=0, device=device)

    results_table.append({
        "Attack": "Clean Baseline",
        "Poison %": "0.0%",
        "Clean Acc": f"{clean_acc * 100:.2f}%",
        "ASR": f"N/A (LF:{baseline_lf_asr*100:.1f}%, BN:{baseline_badnets_asr*100:.1f}%, BL:{baseline_blended_asr*100:.1f}%)",
    })

    # 2. Run all 4 attack experiments
    for cfg in configs:
        res = run_attack_experiment(cfg)
        results_table.append({
            "Attack": res["attack_type"],
            "Poison %": f"{res['poison_rate'] * 100:.1f}%",
            "Clean Acc": f"{res['clean_test_accuracy'] * 100:.2f}%",
            "ASR": f"{res['asr'] * 100:.2f}%",
        })

    # 3. Generate Visual Demonstrations
    print("\nGenerating demonstration figures...", flush=True)
    fig1, fig2 = generate_visual_demos(save_dir="runs")

    # 4. Print Summary Table
    print("\n" + "=" * 65, flush=True)
    print("PHASE 2 ATTACK SIMULATION SUMMARY TABLE", flush=True)
    print("=" * 65, flush=True)
    header = f"{'Attack':<22} | {'Poison %':<10} | {'Clean Acc':<11} | {'ASR':<12}"
    print(header, flush=True)
    print("-" * 65, flush=True)
    for r in results_table:
        print(f"{r['Attack']:<22} | {r['Poison %']:<10} | {r['Clean Acc']:<11} | {r['ASR']:<12}", flush=True)
    print("=" * 65, flush=True)

    # Save summary table to json
    with open("runs/phase2_summary.json", "w") as f:
        json.dump(results_table, f, indent=2)


if __name__ == "__main__":
    main()
