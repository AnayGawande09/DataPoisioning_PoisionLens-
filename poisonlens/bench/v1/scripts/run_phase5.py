"""Phase 5: Controlled Mitigation (Soft Quarantine, 3-Tier Weighting, Canary Guardrails, Per-Class Cost)."""

import os
import json
import time
from typing import Dict, Any, List, Tuple
import numpy as np
import torch
from torch.utils.data import DataLoader

from poisonlens.utils import set_seed, ensure_dir
from poisonlens.bench.datasets.cifar import load_cifar10_subsets, CIFAR10Subset
from poisonlens.models.resnet import create_model
from poisonlens.training.trainer import PoisonLensTrainer
from poisonlens.bench.attacks.label_flip import apply_label_flip
from poisonlens.bench.attacks.badnets import apply_badnets
from poisonlens.bench.attacks.blended import apply_blended
from poisonlens.detect.trajectory_scorer import detect_by_trajectory_fingerprint
from poisonlens.mitigate.tier_scoring import (
    assign_mitigation_tiers,
    assign_hard_deletion,
    measure_wrongly_quarantined,
)
from poisonlens.mitigate.canary import CanaryGuard
from poisonlens.bench.eval_asr import (
    evaluate_clean_accuracy,
    evaluate_backdoor_asr,
    evaluate_label_flip_asr,
)
from poisonlens.eval.per_class import (
    evaluate_per_class_accuracy,
    compute_per_class_impact,
)


def train_weighted_model(
    train_dataset: CIFAR10Subset,
    test_dataset: CIFAR10Subset,
    sample_weights: np.ndarray,
    run_dir: str,
    epochs: int = 5,
    seed: int = 42,
    device: torch.device = torch.device("cpu"),
) -> Tuple[torch.nn.Module, str]:
    """Train a model from scratch using sample weights."""
    set_seed(seed)
    ensure_dir(run_dir)

    g = torch.Generator()
    g.manual_seed(seed)

    train_loader = DataLoader(train_dataset, batch_size=128, shuffle=True, generator=g, num_workers=0)
    test_loader = DataLoader(test_dataset, batch_size=128, shuffle=False, num_workers=0)

    weights_tensor = torch.tensor(sample_weights, dtype=torch.float32)

    model = create_model(num_classes=10)
    config = {
        "seed": seed,
        "epochs": epochs,
        "lr": 0.001,
        "weight_decay": 1e-4,
    }

    trainer = PoisonLensTrainer(
        model=model,
        train_loader=train_loader,
        test_loader=test_loader,
        train_dataset_size=len(train_dataset),
        run_dir=run_dir,
        config=config,
        device=device,
        sample_weights=weights_tensor,
    )

    trainer.train(max_epochs=epochs)
    final_ckpt = os.path.join(run_dir, "checkpoints", "checkpoint_latest.pt")
    return model, final_ckpt


def run_phase5():
    device = torch.device("cpu")
    seed = 42
    set_seed(seed)

    # 1. Load clean subsets
    # Hold out 200 verified-clean samples as the canary set
    clean_train_full, test_sub, _ = load_cifar10_subsets("./data_cache", train_size=10000, test_size=2000, seed=seed)
    
    # Stratified 200-sample canary set (20 per class) held out of training
    canary_indices = []
    train_indices = []
    for c in range(10):
        c_idxs = np.where(clean_train_full.targets == c)[0]
        canary_indices.extend(c_idxs[:20])
        train_indices.extend(c_idxs[20:])
    canary_indices = np.array(canary_indices)
    train_indices = np.array(train_indices)

    canary_sub = CIFAR10Subset(
        images=clean_train_full.images[canary_indices],
        targets=clean_train_full.targets[canary_indices],
        sample_ids=np.arange(len(canary_indices)),
        cifar_indices=clean_train_full.cifar_indices[canary_indices],
    )
    
    clean_train_sub = CIFAR10Subset(
        images=clean_train_full.images[train_indices],
        targets=clean_train_full.targets[train_indices],
        sample_ids=np.arange(len(train_indices)),
        cifar_indices=clean_train_full.cifar_indices[train_indices],
    )

    test_loader = DataLoader(test_sub, batch_size=128, shuffle=False, num_workers=0)
    canary_guard = CanaryGuard(canary_sub, tolerance=0.03, device=device)

    attack_scenarios = [
        {
            "name": "Label Flip (10%)",
            "type": "label_flip",
            "rate": 0.10,
            "source_class": 3,
            "target_class": 5,
            "run_id": "attack_labelflip_10",
        },
        {
            "name": "BadNets Backdoor (5%)",
            "type": "badnets",
            "rate": 0.05,
            "target_class": 0,
            "run_id": "attack_badnets_5",
        },
        {
            "name": "Blended Backdoor (5%)",
            "type": "blended",
            "rate": 0.05,
            "target_class": 0,
            "run_id": "attack_blended_5",
        },
        {
            "name": "Label Flip (5%)",
            "type": "label_flip",
            "rate": 0.05,
            "source_class": 3,
            "target_class": 5,
            "run_id": "attack_labelflip_5",
        },
    ]

    summary_results: List[Dict[str, Any]] = []
    per_class_results: Dict[str, Any] = {}
    rollback_results: List[Dict[str, Any]] = []

    print("=================================================================", flush=True)
    print("STARTING PHASE 5: CONTROLLED MITIGATION & CANARY GUARDRAILS", flush=True)
    print("=================================================================", flush=True)

    for scenario in attack_scenarios:
        attack_name = scenario["name"]
        attack_type = scenario["type"]
        run_id = scenario["run_id"]
        poison_rate = scenario["rate"]

        print(f"\n>>> Evaluating Controlled Mitigation on: {attack_name} <<<", flush=True)

        # Apply attack to training subset (9,800 samples)
        trigger_fn = None
        if attack_type == "label_flip":
            src = scenario["source_class"]
            tgt = scenario["target_class"]
            p_train, gt_mask = apply_label_flip(clean_train_sub, poison_rate, src, tgt, seed=seed)
        elif attack_type == "badnets":
            tgt = scenario["target_class"]
            p_train, gt_mask, trigger_fn = apply_badnets(clean_train_sub, poison_rate, tgt, patch_size=3, seed=seed)
        elif attack_type == "blended":
            tgt = scenario["target_class"]
            p_train, gt_mask, trigger_fn = apply_blended(clean_train_sub, poison_rate, tgt, alpha=0.20, seed=seed)

        # Load models from Phase 2
        run_dir = os.path.join("runs", run_id)
        early_model = create_model(10)
        early_model.load_state_dict(torch.load(os.path.join(run_dir, "checkpoints", "checkpoint_epoch_1.pt"), map_location=device, weights_only=False)["model_state_dict"])
        early_model.eval()

        converged_model = create_model(10)
        converged_ckpt = torch.load(os.path.join(run_dir, "checkpoints", "checkpoint_latest.pt"), map_location=device, weights_only=False)
        converged_model.load_state_dict(converged_ckpt["model_state_dict"])
        converged_model.eval()

        # Undefended performance baseline
        undef_clean_acc, _ = evaluate_clean_accuracy(converged_model, test_loader, device=device)
        canary_base_acc = canary_guard.establish_baseline(converged_model)
        
        if attack_type == "label_flip":
            undef_asr = evaluate_label_flip_asr(converged_model, test_sub, scenario["source_class"], scenario["target_class"], device=device)
        else:
            undef_asr = evaluate_backdoor_asr(converged_model, test_sub, trigger_fn, scenario["target_class"], device=device)
            
        undef_per_class = evaluate_per_class_accuracy(converged_model, test_loader, 10, device=device)

        summary_results.append({
            "Attack": attack_name,
            "Mitigation": "Undefended",
            "Clean Acc": f"{undef_clean_acc * 100:.2f}%",
            "Canary Acc": f"{canary_base_acc * 100:.2f}%",
            "ASR": f"{undef_asr * 100:.2f}%",
            "Wrongly Quarantined": 0,
            "Clean Retention": "100.0%",
            "Worst Class Drop": "0.0%",
        })

        # Load training dynamics & compute Trajectory Fingerprint scores
        dyn = np.load(os.path.join(run_dir, "training_dynamics.npz"))
        rng = np.random.RandomState(seed)
        clean_pool = np.where(~gt_mask)[0]
        poison_pool = np.where(gt_mask)[0]
        val_clean = rng.choice(clean_pool, size=90, replace=False)
        val_poison = rng.choice(poison_pool, size=10, replace=False)
        val_indices = np.concatenate([val_clean, val_poison])
        val_labels = gt_mask[val_indices]

        print("Computing Trajectory Suspicion Scores...", flush=True)
        _, scores, _, _ = detect_by_trajectory_fingerprint(
            loss_history=dyn["losses"][:, train_indices],
            correct_history=dyn["correct"][:, train_indices],
            early_model=early_model,
            converged_model=converged_model,
            dataset=p_train,
            drop_ratio=poison_rate,
            val_indices=val_indices,
            val_labels=val_labels,
            device=device,
        )

        # -------------------------------------------------------------
        # Method 1: Hard Deletion (Quarantine top poison_rate, Keep rest)
        # -------------------------------------------------------------
        print(f"\n[1/3] Running Hard Deletion Mitigation on {attack_name}...", flush=True)
        hard_weights, _, hard_info = assign_hard_deletion(scores, drop_ratio=poison_rate)
        hard_wrongly = measure_wrongly_quarantined(hard_info["quarantine_mask"], gt_mask)

        hard_run_dir = os.path.join("runs", f"{run_id}_mitigation_hard_delete")
        hard_model, hard_ckpt = train_weighted_model(
            p_train, test_sub, hard_weights, hard_run_dir, epochs=5, seed=seed, device=device
        )
        hard_clean_acc, _ = evaluate_clean_accuracy(hard_model, test_loader, device=device)
        hard_canary_acc = canary_guard.evaluate(hard_model)
        
        if attack_type == "label_flip":
            hard_asr = evaluate_label_flip_asr(hard_model, test_sub, scenario["source_class"], scenario["target_class"], device=device)
        else:
            hard_asr = evaluate_backdoor_asr(hard_model, test_sub, trigger_fn, scenario["target_class"], device=device)
            
        hard_per_class = evaluate_per_class_accuracy(hard_model, test_loader, 10, device=device)
        hard_impact = compute_per_class_impact(undef_per_class, hard_per_class)

        summary_results.append({
            "Attack": attack_name,
            "Mitigation": "Hard Deletion (All-or-Nothing)",
            "Clean Acc": f"{hard_clean_acc * 100:.2f}%",
            "Canary Acc": f"{hard_canary_acc * 100:.2f}%",
            "ASR": f"{hard_asr * 100:.2f}%",
            "Wrongly Quarantined": hard_wrongly["wrongly_quarantined_count"],
            "Clean Retention": f"{hard_wrongly['clean_retention_rate'] * 100:.2f}%",
            "Worst Class Drop": f"{hard_impact['worst_class_drop'] * 100:.2f}% (Class {hard_impact['worst_harmed_class']})",
        })

        # -------------------------------------------------------------
        # Method 2: Soft Quarantine (3-Tier: Quarantine, Downweight, Keep)
        # -------------------------------------------------------------
        print(f"\n[2/3] Running Soft Quarantine (3-Tier) Mitigation on {attack_name}...", flush=True)
        soft_weights, _, soft_info = assign_mitigation_tiers(
            scores, quarantine_ratio=poison_rate, downweight_ratio=0.10, downweight_value=0.20
        )
        soft_wrongly = measure_wrongly_quarantined(soft_info["quarantine_mask"], gt_mask)

        soft_run_dir = os.path.join("runs", f"{run_id}_mitigation_soft_quarantine")
        soft_model, soft_ckpt = train_weighted_model(
            p_train, test_sub, soft_weights, soft_run_dir, epochs=5, seed=seed, device=device
        )
        soft_clean_acc, _ = evaluate_clean_accuracy(soft_model, test_loader, device=device)
        soft_canary_acc = canary_guard.evaluate(soft_model)
        
        if attack_type == "label_flip":
            soft_asr = evaluate_label_flip_asr(soft_model, test_sub, scenario["source_class"], scenario["target_class"], device=device)
        else:
            soft_asr = evaluate_backdoor_asr(soft_model, test_sub, trigger_fn, scenario["target_class"], device=device)
            
        soft_per_class = evaluate_per_class_accuracy(soft_model, test_loader, 10, device=device)
        soft_impact = compute_per_class_impact(undef_per_class, soft_per_class)

        summary_results.append({
            "Attack": attack_name,
            "Mitigation": "Soft Quarantine (3-Tier Weighted)",
            "Clean Acc": f"{soft_clean_acc * 100:.2f}%",
            "Canary Acc": f"{soft_canary_acc * 100:.2f}%",
            "ASR": f"{soft_asr * 100:.2f}%",
            "Wrongly Quarantined": soft_wrongly["wrongly_quarantined_count"],
            "Clean Retention": f"{soft_wrongly['clean_retention_rate'] * 100:.2f}%",
            "Worst Class Drop": f"{soft_impact['worst_class_drop'] * 100:.2f}% (Class {soft_impact['worst_harmed_class']})",
        })

        per_class_results[attack_name] = {
            "Undefended": undef_per_class,
            "Hard Deletion": hard_per_class,
            "Soft Quarantine": soft_per_class,
            "Hard Deletion Deltas": hard_impact["per_class_deltas"],
            "Soft Quarantine Deltas": soft_impact["per_class_deltas"],
        }

        # -------------------------------------------------------------
        # Canary Guardrail & Rollback Verification Check
        # -------------------------------------------------------------
        is_rolled_back, c_acc, c_delta, decision = canary_guard.verify_and_rollback(
            candidate_model=soft_model,
            backup_checkpoint_path=os.path.join(run_dir, "checkpoints", "checkpoint_latest.pt"),
            current_quarantine_ratio=poison_rate,
        )
        print(f"Canary Guard Decision: {decision['action']} ({decision['reason']})", flush=True)

    # -------------------------------------------------------------
    # Method 3: Canary Rollback Stress Test (Simulate Over-Aggressive Mitigation)
    # -------------------------------------------------------------
    print("\n=================================================================", flush=True)
    print("TESTING AUTOMATIC ROLLBACK GUARDRAIL (STRESS TEST)", flush=True)
    print("=================================================================", flush=True)
    
    # Simulate an over-aggressive quarantine (dropping 35% of samples) that damages clean canary accuracy
    stress_run_dir = os.path.join("runs", "stress_test_over_aggressive")
    stress_weights = np.ones(len(clean_train_sub), dtype=np.float32)
    # Exclude 35% of dataset
    stress_weights[:int(0.35 * len(stress_weights))] = 0.0

    stress_model, stress_ckpt = train_weighted_model(
        clean_train_sub, test_sub, stress_weights, stress_run_dir, epochs=3, seed=seed, device=device
    )
    
    # Establish baseline on original clean model
    baseline_clean_model = create_model(10)
    baseline_clean_model.load_state_dict(torch.load("runs/clean_baseline/checkpoints/checkpoint_latest.pt", map_location=device, weights_only=False)["model_state_dict"])
    canary_guard.establish_baseline(baseline_clean_model)
    
    # Check canary and execute rollback
    pre_rollback_canary_acc = canary_guard.evaluate(stress_model)
    rolled_back, post_canary_acc, canary_delta, rollback_decision = canary_guard.verify_and_rollback(
        candidate_model=stress_model,
        backup_checkpoint_path="runs/clean_baseline/checkpoints/checkpoint_latest.pt",
        current_quarantine_ratio=0.35,
    )
    
    print(f"Stress Test Result: Action={rollback_decision['action']}", flush=True)
    print(f"  Reason: {rollback_decision['reason']}", flush=True)
    print(f"  Rolled back: {rolled_back}", flush=True)
    print(f"  Suggested loosened ratio: {rollback_decision.get('suggested_loosened_ratio')}", flush=True)

    rollback_results.append({
        "Test": "Over-Aggressive Quarantine Stress Test",
        "Pre-Rollback Canary Acc": f"{pre_rollback_canary_acc * 100:.2f}%",
        "Baseline Canary Acc": f"{canary_guard.baseline_accuracy * 100:.2f}%",
        "Delta": f"{canary_delta * 100:+.2f}%",
        "Rollback Triggered": rolled_back,
        "Action": rollback_decision["action"],
        "Details": rollback_decision,
    })

    # Save summary JSON
    with open("runs/phase5_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary_results, f, indent=2)

    with open("runs/phase5_per_class.json", "w", encoding="utf-8") as f:
        json.dump(per_class_results, f, indent=2)

    with open("runs/phase5_rollback.json", "w", encoding="utf-8") as f:
        json.dump(rollback_results, f, indent=2)

    # Print summary table
    print("\n" + "=" * 115, flush=True)
    print("PHASE 5: CONTROLLED MITIGATION BENCHMARK (HARD-DELETE VS SOFT-QUARANTINE)", flush=True)
    print("=" * 115, flush=True)
    hdr = f"{'Attack':<24} | {'Mitigation':<32} | {'Clean Acc':<10} | {'ASR':<8} | {'FP Count':<9} | {'Clean Ret':<10} | {'Worst Drop':<12}"
    print(hdr, flush=True)
    print("-" * 115, flush=True)
    for row in summary_results:
        print(
            f"{row['Attack']:<24} | {row['Mitigation']:<32} | {row['Clean Acc']:<10} | {row['ASR']:<8} | {str(row['Wrongly Quarantined']):<9} | {row['Clean Retention']:<10} | {row['Worst Class Drop']:<12}",
            flush=True,
        )
    print("=" * 115, flush=True)


if __name__ == "__main__":
    run_phase5()
