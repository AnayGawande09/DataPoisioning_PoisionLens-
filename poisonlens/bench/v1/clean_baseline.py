"""Clean baseline training script for PoisonLens."""

import os
import time
import json
import argparse
import yaml
import torch

from poisonlens.utils import set_seed, ensure_dir
from poisonlens.bench.datasets.cifar import get_cifar10_loaders
from poisonlens.models.resnet import create_model
from poisonlens.training.trainer import PoisonLensTrainer


def run_clean_baseline(config_path: str) -> dict:
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    seed = config.get("seed", 42)
    set_seed(seed)

    run_id = config.get("run_id", "clean_baseline")
    save_dir = config.get("save_dir", "runs")
    run_dir = ensure_dir(os.path.join(save_dir, run_id))

    # Setup data
    data_root = config.get("data_root", "./data_cache")
    train_size = config.get("train_size", 10000)
    test_size = config.get("test_size", 2000)
    batch_size = config.get("batch_size", 128)

    print(f"Loading CIFAR-10 subsets (Train: {train_size}, Test: {test_size}) with seed={seed}...")
    train_loader, test_loader, train_subset, test_subset, data_hash = get_cifar10_loaders(
        data_root=data_root,
        train_size=train_size,
        test_size=test_size,
        batch_size=batch_size,
        seed=seed,
    )

    # Save run metadata for provenance and auditability
    run_info = {
        "run_id": run_id,
        "seed": seed,
        "data_hash": data_hash,
        "train_size": len(train_subset),
        "test_size": len(test_subset),
        "config": config,
        "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    with open(os.path.join(run_dir, "run_info.json"), "w", encoding="utf-8") as f:
        json.dump(run_info, f, indent=2)

    # Also save a copy of the config inside the run directory
    with open(os.path.join(run_dir, "config.yaml"), "w", encoding="utf-8") as f:
        yaml.dump(config, f)

    print(f"Run provenance initialized in {run_dir}")
    print(f"Data index git-style hash: {data_hash}")

    # Build model
    device = torch.device(config.get("device", "cpu"))
    model = create_model(num_classes=10)
    num_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"Model created: SmallResNet ({num_params:,} parameters) on {device}")

    # Build trainer
    trainer = PoisonLensTrainer(
        model=model,
        train_loader=train_loader,
        test_loader=test_loader,
        train_dataset_size=len(train_subset),
        run_dir=run_dir,
        config=config,
        device=device,
    )

    # Run training
    print(f"Starting training for {config.get('epochs', 10)} epochs on {device}...")
    start_t = time.time()
    train_output = trainer.train()
    elapsed_time = time.time() - start_t

    final_test_acc = train_output["final_test_acc"]
    final_test_loss = train_output["final_test_loss"]

    results = {
        "run_id": run_id,
        "seed": seed,
        "data_hash": data_hash,
        "clean_test_accuracy": float(final_test_acc),
        "clean_test_loss": float(final_test_loss),
        "training_time_sec": float(elapsed_time),
        "epochs": config.get("epochs", 10),
        "history": train_output["history"],
    }

    with open(os.path.join(run_dir, "results.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nTraining Complete in {elapsed_time:.2f}s ({elapsed_time/60:.2f} mins)", flush=True)
    print(f"Final Clean Test Accuracy: {final_test_acc * 100:.2f}%", flush=True)
    print(f"Results recorded in: {os.path.join(run_dir, 'results.json')}", flush=True)
    return results


def main():
    parser = argparse.ArgumentParser(description="PoisonLens Clean Baseline Runner")
    parser.add_argument("--config", type=str, default="poisonlens/bench/v1/configs/clean_baseline.yaml", help="Path to YAML config")
    args = parser.parse_args()
    run_clean_baseline(args.config)


if __name__ == "__main__":
    main()
