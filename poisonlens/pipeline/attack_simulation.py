"""Attack simulation runner: trains undefended models under 4 attack setups, logs dynamics, and generates visual demos."""

import os
import time
import json
import yaml
import argparse
from typing import Dict, Any, Tuple
import numpy as np
import matplotlib.pyplot as plt
import torch
from torch.utils.data import DataLoader

from poisonlens.utils import set_seed, ensure_dir, compute_indices_hash
from poisonlens.data.cifar import load_cifar10_subsets, CIFAR10Subset
from poisonlens.models.resnet import create_model
from poisonlens.training.trainer import PoisonLensTrainer
from poisonlens.attacks.label_flip import apply_label_flip
from poisonlens.attacks.badnets import apply_badnets
from poisonlens.attacks.blended import apply_blended
from poisonlens.eval.asr import (
    evaluate_clean_accuracy,
    evaluate_backdoor_asr,
    evaluate_label_flip_asr,
)

CIFAR_CLASSES = [
    "airplane", "automobile", "bird", "cat", "deer",
    "dog", "frog", "horse", "ship", "truck"
]


def run_attack_experiment(config_path: str) -> Dict[str, Any]:
    """Train undefended model on an attacked dataset and log evaluation metrics."""
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    seed = config.get("seed", 42)
    set_seed(seed)

    run_id = config.get("run_id", "attack_run")
    save_dir = config.get("save_dir", "runs")
    run_dir = ensure_dir(os.path.join(save_dir, run_id))

    # Load clean subsets
    data_root = config.get("data_root", "./data_cache")
    train_size = config.get("train_size", 10000)
    test_size = config.get("test_size", 2000)
    batch_size = config.get("batch_size", 128)

    print(f"\n=======================================================", flush=True)
    print(f"Starting Attack Run: {run_id}", flush=True)
    print(f"Config: {config_path}", flush=True)
    print(f"=======================================================", flush=True)

    clean_train_sub, test_sub, clean_data_hash = load_cifar10_subsets(
        data_root=data_root,
        train_size=train_size,
        test_size=test_size,
        seed=seed,
    )

    attack_type = config.get("attack", "badnets")
    poison_rate = float(config.get("poison_rate", 0.05))

    trigger_fn = None
    if attack_type == "label_flip":
        source_class = int(config.get("source_class", 3))
        target_class = int(config.get("target_class", 5))
        poisoned_train_sub, poison_mask = apply_label_flip(
            clean_train_sub,
            poison_rate=poison_rate,
            source_class=source_class,
            target_class=target_class,
            seed=seed,
        )
    elif attack_type == "badnets":
        target_class = int(config.get("target_class", 0))
        patch_size = int(config.get("patch_size", 3))
        poisoned_train_sub, poison_mask, trigger_fn = apply_badnets(
            clean_train_sub,
            poison_rate=poison_rate,
            target_class=target_class,
            patch_size=patch_size,
            seed=seed,
        )
    elif attack_type == "blended":
        target_class = int(config.get("target_class", 0))
        alpha = float(config.get("alpha", 0.20))
        poisoned_train_sub, poison_mask, trigger_fn = apply_blended(
            clean_train_sub,
            poison_rate=poison_rate,
            target_class=target_class,
            alpha=alpha,
            seed=seed,
        )
    else:
        raise ValueError(f"Unknown attack type: {attack_type}")

    poisoned_count = int(poison_mask.sum())
    print(f"Attack applied: {attack_type} | Poison rate: {poison_rate*100:.1f}% ({poisoned_count} samples)", flush=True)

    # Provenance data hash (hash of training indices + poison mask)
    data_hash = compute_indices_hash(poisoned_train_sub.cifar_indices.tolist() + poison_mask.astype(int).tolist())

    # Save run metadata
    run_info = {
        "run_id": run_id,
        "seed": seed,
        "attack_type": attack_type,
        "poison_rate": poison_rate,
        "poisoned_count": poisoned_count,
        "data_hash": data_hash,
        "clean_data_hash": clean_data_hash,
        "config": config,
        "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    with open(os.path.join(run_dir, "run_info.json"), "w", encoding="utf-8") as f:
        json.dump(run_info, f, indent=2)

    with open(os.path.join(run_dir, "config.yaml"), "w", encoding="utf-8") as f:
        yaml.dump(config, f)

    # Save ground truth poison mask
    np.save(os.path.join(run_dir, "poison_mask.npy"), poison_mask)

    # Build DataLoaders
    g = torch.Generator()
    g.manual_seed(seed)
    train_loader = DataLoader(poisoned_train_sub, batch_size=batch_size, shuffle=True, generator=g, num_workers=0)
    test_loader = DataLoader(test_sub, batch_size=batch_size, shuffle=False, num_workers=0)

    # Build Model & Trainer
    device = torch.device(config.get("device", "cpu"))
    model = create_model(num_classes=10)

    trainer = PoisonLensTrainer(
        model=model,
        train_loader=train_loader,
        test_loader=test_loader,
        train_dataset_size=len(poisoned_train_sub),
        run_dir=run_dir,
        config=config,
        device=device,
    )

    epochs = config.get("epochs", 10)
    print(f"Training undefended model for {epochs} epochs on {device}...", flush=True)
    start_t = time.time()
    train_output = trainer.train()
    training_time = time.time() - start_t

    # Final Evaluations
    clean_acc, clean_loss = evaluate_clean_accuracy(model, test_loader, device=device)

    # Calculate Attack Success Rate (ASR)
    if attack_type == "label_flip":
        asr = evaluate_label_flip_asr(
            model,
            test_sub,
            source_class=source_class,
            target_class=target_class,
            batch_size=batch_size,
            device=device,
        )
    else:
        assert trigger_fn is not None
        asr = evaluate_backdoor_asr(
            model,
            test_sub,
            trigger_fn=trigger_fn,
            target_class=target_class,
            batch_size=batch_size,
            device=device,
        )

    results = {
        "run_id": run_id,
        "attack_type": attack_type,
        "poison_rate": poison_rate,
        "poisoned_count": poisoned_count,
        "clean_test_accuracy": float(clean_acc),
        "clean_test_loss": float(clean_loss),
        "asr": float(asr),
        "training_time_sec": float(training_time),
        "epochs": epochs,
        "history": train_output["history"],
    }

    with open(os.path.join(run_dir, "results.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\n--- {run_id} Results ---", flush=True)
    print(f"Clean Test Accuracy: {clean_acc * 100:.2f}%", flush=True)
    print(f"Attack Success Rate (ASR): {asr * 100:.2f}%", flush=True)
    print(f"Training Time: {training_time:.2f}s ({training_time/60:.2f} min)", flush=True)

    return results


def generate_visual_demos(save_dir: str = "runs") -> Tuple[str, str]:
    """Generate and save the two required demonstration figures."""
    set_seed(42)
    clean_train_sub, test_sub, _ = load_cifar10_subsets("./data_cache", train_size=1000, test_size=200, seed=42)

    # 1. Figure 1: Clean vs Poisoned Images (showing triggers and label flips)
    fig, axes = plt.subplots(3, 4, figsize=(12, 9))
    plt.subplots_adjust(hspace=0.4, wspace=0.3)

    # Setup attacks on subset
    _, badnets_mask, badnets_trigger = apply_badnets(clean_train_sub, poison_rate=0.05, target_class=0, seed=42)
    _, blended_mask, blended_trigger = apply_blended(clean_train_sub, poison_rate=0.05, target_class=0, seed=42)

    # Row 1: BadNets Examples
    badnets_idx = np.where(badnets_mask)[0][:4]
    for col, idx in enumerate(badnets_idx):
        clean_img = clean_train_sub.images[idx]
        pois_img = badnets_trigger(clean_img)
        orig_lbl = CIFAR_CLASSES[clean_train_sub.targets[idx]]
        
        # Display side-by-side inside each column
        combined = np.hstack([clean_img, pois_img])
        axes[0, col].imshow(combined)
        axes[0, col].set_title(f"BadNets #{col+1}\nClean: {orig_lbl} -> Target: airplane", fontsize=9)
        axes[0, col].axis("off")

    # Row 2: Blended Examples
    blended_idx = np.where(blended_mask)[0][:4]
    for col, idx in enumerate(blended_idx):
        clean_img = clean_train_sub.images[idx]
        pois_img = blended_trigger(clean_img)
        orig_lbl = CIFAR_CLASSES[clean_train_sub.targets[idx]]
        
        combined = np.hstack([clean_img, pois_img])
        axes[1, col].imshow(combined)
        axes[1, col].set_title(f"Blended #{col+1}\nClean: {orig_lbl} -> Target: airplane", fontsize=9)
        axes[1, col].axis("off")

    # Row 3: Label Flip Examples (Cat -> Dog)
    cat_indices = np.where(clean_train_sub.targets == 3)[0][:4]
    for col, idx in enumerate(cat_indices):
        clean_img = clean_train_sub.images[idx]
        axes[2, col].imshow(clean_img)
        axes[2, col].set_title(f"Label Flip #{col+1}\nTrue: cat | Relabeled: dog", fontsize=9)
        axes[2, col].axis("off")

    plt.suptitle("PoisonLens: Clean vs Poisoned Training Samples (Left: Clean | Right: Poisoned)", fontsize=13, y=0.98)
    fig1_path = os.path.join(save_dir, "demo_clean_vs_poisoned.png")
    plt.savefig(fig1_path, dpi=200, bbox_inches="tight")
    plt.close()
    print(f"Saved demo figure 1: {fig1_path}", flush=True)

    # 2. Figure 2: Test Images Before & After Attack with Model Predictions
    # Load trained models
    device = torch.device("cpu")
    clean_model = create_model(10)
    clean_ckpt = torch.load(os.path.join(save_dir, "clean_baseline", "checkpoints", "checkpoint_latest.pt"), map_location=device, weights_only=False)
    clean_model.load_state_dict(clean_ckpt["model_state_dict"])
    clean_model.eval()

    badnets_model = create_model(10)
    badnets_ckpt = torch.load(os.path.join(save_dir, "attack_badnets_5", "checkpoints", "checkpoint_latest.pt"), map_location=device, weights_only=False)
    badnets_model.load_state_dict(badnets_ckpt["model_state_dict"])
    badnets_model.eval()

    blended_model = create_model(10)
    blended_ckpt = torch.load(os.path.join(save_dir, "attack_blended_5", "checkpoints", "checkpoint_latest.pt"), map_location=device, weights_only=False)
    blended_model.load_state_dict(blended_ckpt["model_state_dict"])
    blended_model.eval()

    # Select 6 non-target test images
    test_non_targets = np.where(test_sub.targets != 0)[0][:6]

    fig, axes = plt.subplots(6, 4, figsize=(14, 15))
    plt.subplots_adjust(hspace=0.6, wspace=0.3)

    from poisonlens.data.cifar import CIFAR10_MEAN, CIFAR10_STD
    mean = torch.tensor(CIFAR10_MEAN).view(1, 3, 1, 1)
    std = torch.tensor(CIFAR10_STD).view(1, 3, 1, 1)

    def predict(model, img_np):
        t = torch.from_numpy(img_np).permute(2, 0, 1).unsqueeze(0).float() / 255.0
        t = (t - mean) / std
        with torch.no_grad():
            out = model(t)
            pred = out.argmax(dim=-1).item()
        return CIFAR_CLASSES[pred]

    for i, idx in enumerate(test_non_targets):
        clean_img = test_sub.images[idx]
        true_lbl = CIFAR_CLASSES[test_sub.targets[idx]]

        # Predictions on clean image
        clean_p_on_clean = predict(clean_model, clean_img)
        badnets_p_on_clean = predict(badnets_model, clean_img)

        # Apply BadNets trigger
        badnets_img = badnets_trigger(clean_img)
        clean_p_on_badnets = predict(clean_model, badnets_img)
        badnets_p_on_badnets = predict(badnets_model, badnets_img)

        # Apply Blended trigger
        blended_img = blended_trigger(clean_img)
        clean_p_on_blended = predict(clean_model, blended_img)
        blended_p_on_blended = predict(blended_model, blended_img)

        # Col 0: Clean Test Image
        axes[i, 0].imshow(clean_img)
        axes[i, 0].set_title(f"True: {true_lbl}\nClean Model: {clean_p_on_clean}\nAtk Model: {badnets_p_on_clean}", fontsize=8)
        axes[i, 0].axis("off")

        # Col 1: BadNets Triggered Image
        axes[i, 1].imshow(badnets_img)
        axes[i, 1].set_title(f"BadNets Trigger\nClean Model: {clean_p_on_badnets}\nBadNets Model: {badnets_p_on_badnets}", fontsize=8)
        axes[i, 1].axis("off")

        # Col 2: Blended Triggered Image
        axes[i, 2].imshow(blended_img)
        axes[i, 2].set_title(f"Blended Trigger\nClean Model: {clean_p_on_blended}\nBlended Model: {blended_p_on_blended}", fontsize=8)
        axes[i, 2].axis("off")

        # Col 3: Difference/Trigger visualization
        diff = np.abs(blended_img.astype(float) - clean_img.astype(float))
        diff_scaled = np.clip(diff * 5, 0, 255).astype(np.uint8)
        axes[i, 3].imshow(diff_scaled)
        axes[i, 3].set_title(f"Blended Residual (5x)\nTarget: airplane", fontsize=8)
        axes[i, 3].axis("off")

    axes[0, 0].set_ylabel("Clean Test", fontsize=10)
    plt.suptitle("PoisonLens Demo: Predictions on Clean vs Triggered Test Images\n(Showing Undefended Models Overriding Predictions to Target Class)", fontsize=13, y=0.99)
    fig2_path = os.path.join(save_dir, "demo_attack_predictions.png")
    plt.savefig(fig2_path, dpi=200, bbox_inches="tight")
    plt.close()
    print(f"Saved demo figure 2: {fig2_path}", flush=True)

    return fig1_path, fig2_path
