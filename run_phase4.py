"""Phase 4: Trajectory Fingerprint Scoring evaluation and feature ablation study."""

import os
import json
import time
from typing import Dict, Any, List, Tuple
import numpy as np
import torch
from torch.utils.data import DataLoader

from poisonlens.utils import set_seed, ensure_dir
from poisonlens.data.cifar import load_cifar10_subsets, CIFAR10Subset
from poisonlens.models.resnet import create_model
from poisonlens.training.trainer import PoisonLensTrainer
from poisonlens.attacks.label_flip import apply_label_flip
from poisonlens.attacks.badnets import apply_badnets
from poisonlens.attacks.blended import apply_blended
from poisonlens.detect.metrics import compute_detection_metrics
from poisonlens.detect.dynamics_features import extract_all_trajectory_features
from poisonlens.detect.trajectory_scorer import (
    detect_by_trajectory_fingerprint,
    FEATURE_NAMES,
)
from poisonlens.eval.asr import (
    evaluate_clean_accuracy,
    evaluate_backdoor_asr,
    evaluate_label_flip_asr,
)


def filter_dataset(dataset: CIFAR10Subset, drop_mask: np.ndarray) -> CIFAR10Subset:
    """Create a new CIFAR10Subset retaining only unflagged samples with contiguous sample IDs."""
    keep_indices = np.where(~drop_mask)[0]
    return CIFAR10Subset(
        images=dataset.images[keep_indices],
        targets=dataset.targets[keep_indices],
        sample_ids=np.arange(len(keep_indices)),
        cifar_indices=dataset.cifar_indices[keep_indices],
        is_poison=dataset.is_poison[keep_indices],
    )


def retrain_filtered_model(
    sanitized_dataset: CIFAR10Subset,
    test_dataset: CIFAR10Subset,
    run_dir: str,
    epochs: int = 5,
    seed: int = 42,
    device: torch.device = torch.device("cpu"),
) -> torch.nn.Module:
    """Retrain a model from scratch on the sanitized dataset."""
    set_seed(seed)
    ensure_dir(run_dir)

    g = torch.Generator()
    g.manual_seed(seed)

    train_loader = DataLoader(sanitized_dataset, batch_size=128, shuffle=True, generator=g, num_workers=0)
    test_loader = DataLoader(test_dataset, batch_size=128, shuffle=False, num_workers=0)

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
        train_dataset_size=len(sanitized_dataset),
        run_dir=run_dir,
        config=config,
        device=device,
    )

    trainer.train(max_epochs=epochs)
    return model


def evaluate_model_attack(
    model: torch.nn.Module,
    test_sub: CIFAR10Subset,
    attack_type: str,
    trigger_fn=None,
    source_class: int = 3,
    target_class: int = 5,
    device: torch.device = torch.device("cpu"),
) -> Tuple[float, float]:
    """Helper to evaluate clean accuracy and ASR for a given model."""
    test_loader = DataLoader(test_sub, batch_size=128, shuffle=False, num_workers=0)
    clean_acc, _ = evaluate_clean_accuracy(model, test_loader, device=device)

    if attack_type == "label_flip":
        asr = evaluate_label_flip_asr(
            model, test_sub, source_class=source_class, target_class=target_class, device=device
        )
    else:
        assert trigger_fn is not None
        asr = evaluate_backdoor_asr(
            model, test_sub, trigger_fn=trigger_fn, target_class=target_class, device=device
        )
    return clean_acc, asr


def run_phase4():
    device = torch.device("cpu")
    seed = 42
    set_seed(seed)

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

    benchmark_results: List[Dict[str, Any]] = []
    ablation_results: List[Dict[str, Any]] = []

    print("=================================================================", flush=True)
    print("STARTING PHASE 4: TRAJECTORY FINGERPRINT SCORING & ABLATION", flush=True)
    print("=================================================================", flush=True)

    for scenario in attack_scenarios:
        attack_name = scenario["name"]
        attack_type = scenario["type"]
        run_id = scenario["run_id"]
        poison_rate = scenario["rate"]

        print(f"\n>>> Running PoisonLens on: {attack_name} ({run_id}) <<<", flush=True)

        # 1. Load clean subsets
        clean_train_sub, test_sub, _ = load_cifar10_subsets("./data_cache", train_size=10000, test_size=2000, seed=seed)

        # Reconstruct poisoned dataset and trigger function
        trigger_fn = None
        if attack_type == "label_flip":
            src = scenario["source_class"]
            tgt = scenario["target_class"]
            poisoned_train_sub, gt_poison_mask = apply_label_flip(
                clean_train_sub, poison_rate=poison_rate, source_class=src, target_class=tgt, seed=seed
            )
        elif attack_type == "badnets":
            tgt = scenario["target_class"]
            poisoned_train_sub, gt_poison_mask, trigger_fn = apply_badnets(
                clean_train_sub, poison_rate=poison_rate, target_class=tgt, patch_size=3, seed=seed
            )
        elif attack_type == "blended":
            tgt = scenario["target_class"]
            poisoned_train_sub, gt_poison_mask, trigger_fn = apply_blended(
                clean_train_sub, poison_rate=poison_rate, target_class=tgt, alpha=0.20, seed=seed
            )

        # Load models: early checkpoint (epoch 1) and converged checkpoint (epoch 10)
        run_dir = os.path.join("runs", run_id)
        early_ckpt_path = os.path.join(run_dir, "checkpoints", "checkpoint_epoch_1.pt")
        converged_ckpt_path = os.path.join(run_dir, "checkpoints", "checkpoint_latest.pt")
        dynamics_path = os.path.join(run_dir, "training_dynamics.npz")

        early_model = create_model(10)
        early_ckpt = torch.load(early_ckpt_path, map_location=device, weights_only=False)
        early_model.load_state_dict(early_ckpt["model_state_dict"])
        early_model.eval()

        converged_model = create_model(10)
        converged_ckpt = torch.load(converged_ckpt_path, map_location=device, weights_only=False)
        converged_model.load_state_dict(converged_ckpt["model_state_dict"])
        converged_model.eval()

        # Load saved dynamics
        dynamics = np.load(dynamics_path)
        loss_hist = dynamics["losses"]
        corr_hist = dynamics["correct"]

        # Small validation split of 100 samples for weight tuning (held out calibration: 90 clean, 10 poison)
        rng = np.random.RandomState(seed)
        clean_pool = np.where(~gt_poison_mask)[0]
        poison_pool = np.where(gt_poison_mask)[0]
        val_clean = rng.choice(clean_pool, size=90, replace=False)
        val_poison = rng.choice(poison_pool, size=10, replace=False)
        val_indices = np.concatenate([val_clean, val_poison])
        val_labels = gt_poison_mask[val_indices]

        # -------------------------------------------------------------
        # Full PoisonLens Trajectory Fingerprint Scoring (All 5 features)
        # -------------------------------------------------------------
        print(f"Extracting 5 Trajectory Dynamic Features...", flush=True)
        t0 = time.time()
        raw_feats_dict = extract_all_trajectory_features(
            loss_history=loss_hist,
            correct_history=corr_hist,
            early_model=early_model,
            converged_model=converged_model,
            dataset=poisoned_train_sub,
            device=device,
            k_neighbors=15,
        )
        extract_time = time.time() - t0
        print(f"Feature Extraction complete in {extract_time:.2f}s", flush=True)

        print(f"Executing Full Trajectory Fingerprint Scoring...", flush=True)
        drop_mask, scores, reasons, meta = detect_by_trajectory_fingerprint(
            loss_history=loss_hist,
            correct_history=corr_hist,
            early_model=early_model,
            converged_model=converged_model,
            dataset=poisoned_train_sub,
            drop_ratio=poison_rate,
            val_indices=val_indices,
            val_labels=val_labels,
            raw_features=raw_feats_dict,
            device=device,
            k_neighbors=15,
        )
        det_metrics = compute_detection_metrics(gt_poison_mask, drop_mask)
        print(
            f"PoisonLens Full -> Prec: {det_metrics['precision']*100:.1f}%, "
            f"Rec: {det_metrics['recall']*100:.1f}%, F1: {det_metrics['f1']:.3f} (time: {extract_time:.2f}s)",
            flush=True,
        )
        print(f"Fitted Feature Weights: {meta['weights']}", flush=True)

        # Print 3 sample explanations
        flagged_idx = np.where(drop_mask)[0]
        print(f"Sample Flagged Explanations:", flush=True)
        for idx in flagged_idx[:3]:
            is_gt = "POISON" if gt_poison_mask[idx] else "CLEAN"
            print(f"  Sample #{idx} [{is_gt}]: Score={scores[idx]:.2f} | Reasons: {', '.join(reasons[idx])}", flush=True)

        # Retrain sanitized model
        filtered_sub = filter_dataset(poisoned_train_sub, drop_mask)
        retrain_dir = os.path.join("runs", f"{run_id}_defense_poisonlens")
        retrained_model = retrain_filtered_model(
            filtered_sub, test_sub, run_dir=retrain_dir, epochs=5, seed=seed, device=device
        )
        post_acc, post_asr = evaluate_model_attack(
            retrained_model, test_sub, attack_type, trigger_fn,
            source_class=scenario.get("source_class", 3),
            target_class=scenario.get("target_class", 0),
            device=device,
        )

        benchmark_results.append({
            "Attack": attack_name,
            "Defense": "PoisonLens (Trajectory Fingerprint)",
            "Precision": f"{det_metrics['precision'] * 100:.1f}%",
            "Recall": f"{det_metrics['recall'] * 100:.1f}%",
            "F1": f"{det_metrics['f1']:.3f}",
            "Clean Acc": f"{post_acc * 100:.2f}%",
            "ASR": f"{post_asr * 100:.2f}%",
            "Weights": meta["weights"],
        })

        # -------------------------------------------------------------
        # Feature Ablation Study (each feature removed in turn)
        # -------------------------------------------------------------
        print(f"\n--- Running Feature Ablation Study on {attack_name} ---", flush=True)
        # 0. Full model
        ablation_results.append({
            "Attack": attack_name,
            "Configuration": "Full (All 5 Features)",
            "Precision": f"{det_metrics['precision'] * 100:.1f}%",
            "Recall": f"{det_metrics['recall'] * 100:.1f}%",
            "F1": f"{det_metrics['f1']:.3f}",
        })

        for feat_to_drop in FEATURE_NAMES:
            feat_subset = [f for f in FEATURE_NAMES if f != feat_to_drop]
            abl_mask, abl_scores, _, _ = detect_by_trajectory_fingerprint(
                loss_history=loss_hist,
                correct_history=corr_hist,
                early_model=early_model,
                converged_model=converged_model,
                dataset=poisoned_train_sub,
                drop_ratio=poison_rate,
                val_indices=val_indices,
                val_labels=val_labels,
                feature_subset=feat_subset,
                raw_features=raw_feats_dict,
                device=device,
                k_neighbors=15,
            )
            abl_metrics = compute_detection_metrics(gt_poison_mask, abl_mask)
            print(
                f"  w/o {feat_to_drop:<22} -> Prec: {abl_metrics['precision']*100:.1f}%, "
                f"Rec: {abl_metrics['recall']*100:.1f}%, F1: {abl_metrics['f1']:.3f}",
                flush=True,
            )
            ablation_results.append({
                "Attack": attack_name,
                "Configuration": f"w/o {feat_to_drop}",
                "Precision": f"{abl_metrics['precision'] * 100:.1f}%",
                "Recall": f"{abl_metrics['recall'] * 100:.1f}%",
                "F1": f"{abl_metrics['f1']:.3f}",
            })

    # Save summary JSON
    with open("runs/phase4_summary.json", "w", encoding="utf-8") as f:
        json.dump(benchmark_results, f, indent=2)

    with open("runs/phase4_ablation.json", "w", encoding="utf-8") as f:
        json.dump(ablation_results, f, indent=2)

    # Print clean Markdown summary table
    print("\n" + "=" * 90, flush=True)
    print("PHASE 4: POISONLENS BENCHMARK SUMMARY", flush=True)
    print("=" * 90, flush=True)
    hdr = f"{'Attack':<24} | {'Defense':<32} | {'Precision':<10} | {'Recall':<8} | {'F1':<6} | {'Clean Acc':<10} | {'ASR':<8}"
    print(hdr, flush=True)
    print("-" * 90, flush=True)
    for row in benchmark_results:
        print(
            f"{row['Attack']:<24} | {row['Defense']:<32} | {row['Precision']:<10} | {row['Recall']:<8} | {row['F1']:<6} | {row['Clean Acc']:<10} | {row['ASR']:<8}",
            flush=True,
        )
    print("=" * 90, flush=True)


if __name__ == "__main__":
    run_phase4()
