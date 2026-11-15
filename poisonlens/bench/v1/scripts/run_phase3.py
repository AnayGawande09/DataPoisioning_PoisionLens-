"""Phase 3: Baseline defenses evaluation (Loss-Threshold Filtering and Activation Clustering)."""

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
from poisonlens.detect.metrics import compute_detection_metrics
from poisonlens.detect.loss_filter import detect_by_loss_threshold
from poisonlens.detect.activation_clustering import detect_by_activation_clustering
from poisonlens.bench.eval_asr import (
    evaluate_clean_accuracy,
    evaluate_backdoor_asr,
    evaluate_label_flip_asr,
)


def retrain_filtered_model(
    sanitized_dataset: CIFAR10Subset,
    test_dataset: CIFAR10Subset,
    run_dir: str,
    epochs: int = 5,
    seed: int = 42,
    device: torch.device = torch.device("cpu"),
) -> torch.nn.Module:
    """Retrain a model from scratch on the filtered/sanitized dataset."""
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


def filter_dataset(dataset: CIFAR10Subset, drop_mask: np.ndarray) -> CIFAR10Subset:
    """Create a new CIFAR10Subset retaining only unflagged samples."""
    keep_indices = np.where(~drop_mask)[0]
    return CIFAR10Subset(
        images=dataset.images[keep_indices],
        targets=dataset.targets[keep_indices],
        sample_ids=np.arange(len(keep_indices)),
        cifar_indices=dataset.cifar_indices[keep_indices],
        is_poison=dataset.is_poison[keep_indices],
    )


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


def run_phase3():
    device = torch.device("cpu")
    seed = 42
    set_seed(seed)

    # Attacks to benchmark against
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

    print("=================================================================", flush=True)
    print("STARTING PHASE 3: BASELINE DEFENSES BENCHMARK", flush=True)
    print("=================================================================", flush=True)

    for scenario in attack_scenarios:
        attack_name = scenario["name"]
        attack_type = scenario["type"]
        run_id = scenario["run_id"]
        poison_rate = scenario["rate"]

        print(f"\n>>> Benchmarking Defenses on Attack: {attack_name} ({run_id}) <<<", flush=True)

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

        # Load undefended model trained in Phase 2
        ckpt_path = os.path.join("runs", run_id, "checkpoints", "checkpoint_latest.pt")
        undefended_model = create_model(10)
        ckpt = torch.load(ckpt_path, map_location=device, weights_only=False)
        undefended_model.load_state_dict(ckpt["model_state_dict"])
        undefended_model.eval()

        # Undefended performance
        undef_acc, undef_asr = evaluate_model_attack(
            undefended_model, test_sub, attack_type, trigger_fn,
            source_class=scenario.get("source_class", 3),
            target_class=scenario.get("target_class", 0),
            device=device,
        )

        benchmark_results.append({
            "Attack": attack_name,
            "Defense": "No Defense (Undefended)",
            "Precision": "N/A",
            "Recall": "N/A",
            "F1": "N/A",
            "Clean Acc": f"{undef_acc * 100:.2f}%",
            "ASR": f"{undef_asr * 100:.2f}%",
        })

        # -----------------------------------------------------------------
        # Baseline Defense 1: Loss-Threshold Filtering
        # -----------------------------------------------------------------
        print(f"\n[1/2] Running Loss-Threshold Filtering on {attack_name}...", flush=True)
        t0 = time.time()
        loss_mask, _ = detect_by_loss_threshold(
            model=undefended_model,
            dataset=poisoned_train_sub,
            drop_ratio=poison_rate,
            device=device,
        )
        loss_metrics = compute_detection_metrics(gt_poison_mask, loss_mask)
        print(f"Loss Filter -> Prec: {loss_metrics['precision']*100:.1f}%, Rec: {loss_metrics['recall']*100:.1f}%, F1: {loss_metrics['f1']:.3f}", flush=True)

        # Filter and retrain
        filtered_sub_loss = filter_dataset(poisoned_train_sub, loss_mask)
        loss_retrain_dir = os.path.join("runs", f"{run_id}_defense_loss_filter")
        retrained_model_loss = retrain_filtered_model(
            filtered_sub_loss, test_sub, run_dir=loss_retrain_dir, epochs=5, seed=seed, device=device
        )
        post_acc_loss, post_asr_loss = evaluate_model_attack(
            retrained_model_loss, test_sub, attack_type, trigger_fn,
            source_class=scenario.get("source_class", 3),
            target_class=scenario.get("target_class", 0),
            device=device,
        )

        benchmark_results.append({
            "Attack": attack_name,
            "Defense": "Loss-Threshold Filtering",
            "Precision": f"{loss_metrics['precision'] * 100:.1f}%",
            "Recall": f"{loss_metrics['recall'] * 100:.1f}%",
            "F1": f"{loss_metrics['f1']:.3f}",
            "Clean Acc": f"{post_acc_loss * 100:.2f}%",
            "ASR": f"{post_asr_loss * 100:.2f}%",
        })

        # -----------------------------------------------------------------
        # Baseline Defense 2: Activation Clustering
        # -----------------------------------------------------------------
        print(f"\n[2/2] Running Activation Clustering on {attack_name}...", flush=True)
        ac_mask, ac_info = detect_by_activation_clustering(
            model=undefended_model,
            dataset=poisoned_train_sub,
            num_classes=10,
            pca_components=10,
            device=device,
            seed=seed,
        )
        ac_metrics = compute_detection_metrics(gt_poison_mask, ac_mask)
        print(f"Activation Clustering -> Prec: {ac_metrics['precision']*100:.1f}%, Rec: {ac_metrics['recall']*100:.1f}%, F1: {ac_metrics['f1']:.3f}", flush=True)

        # Filter and retrain
        filtered_sub_ac = filter_dataset(poisoned_train_sub, ac_mask)
        ac_retrain_dir = os.path.join("runs", f"{run_id}_defense_activation_clustering")
        retrained_model_ac = retrain_filtered_model(
            filtered_sub_ac, test_sub, run_dir=ac_retrain_dir, epochs=5, seed=seed, device=device
        )
        post_acc_ac, post_asr_ac = evaluate_model_attack(
            retrained_model_ac, test_sub, attack_type, trigger_fn,
            source_class=scenario.get("source_class", 3),
            target_class=scenario.get("target_class", 0),
            device=device,
        )

        benchmark_results.append({
            "Attack": attack_name,
            "Defense": "Activation Clustering",
            "Precision": f"{ac_metrics['precision'] * 100:.1f}%",
            "Recall": f"{ac_metrics['recall'] * 100:.1f}%",
            "F1": f"{ac_metrics['f1']:.3f}",
            "Clean Acc": f"{post_acc_ac * 100:.2f}%",
            "ASR": f"{post_asr_ac * 100:.2f}%",
        })

    # Save summary JSON
    with open("runs/phase3_summary.json", "w", encoding="utf-8") as f:
        json.dump(benchmark_results, f, indent=2)

    # Print clean Markdown summary table
    print("\n" + "=" * 90, flush=True)
    print("PHASE 3: BASELINE DEFENSES COMPARATIVE BENCHMARK", flush=True)
    print("=" * 90, flush=True)
    hdr = f"{'Attack':<24} | {'Defense':<26} | {'Precision':<10} | {'Recall':<8} | {'F1':<6} | {'Clean Acc':<10} | {'ASR':<8}"
    print(hdr, flush=True)
    print("-" * 90, flush=True)
    for row in benchmark_results:
        print(
            f"{row['Attack']:<24} | {row['Defense']:<26} | {row['Precision']:<10} | {row['Recall']:<8} | {row['F1']:<6} | {row['Clean Acc']:<10} | {row['ASR']:<8}",
            flush=True,
        )
    print("=" * 90, flush=True)


if __name__ == "__main__":
    run_phase3()
