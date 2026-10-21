"""PoisonLens unified pipeline orchestrator."""

import os
import json
import time
from typing import Dict, Any, Tuple, Optional
import yaml
import numpy as np
import torch
from torch.utils.data import DataLoader

from poisonlens.utils import set_seed, ensure_dir, compute_indices_hash
from poisonlens.data.cifar import load_cifar10_subsets, CIFAR10Subset
from poisonlens.models.resnet import create_model
from poisonlens.training.trainer import PoisonLensTrainer
from poisonlens.attacks.label_flip import apply_label_flip
from poisonlens.attacks.badnets import apply_badnets
from poisonlens.attacks.blended import apply_blended
from poisonlens.detect.trajectory_scorer import detect_by_trajectory_fingerprint
from poisonlens.mitigate.tier_scoring import (
    assign_mitigation_tiers,
    measure_wrongly_quarantined,
)
from poisonlens.mitigate.canary import CanaryGuard
from poisonlens.eval.asr import (
    evaluate_clean_accuracy,
    evaluate_backdoor_asr,
    evaluate_label_flip_asr,
)
from poisonlens.eval.per_class import (
    evaluate_per_class_accuracy,
    compute_per_class_impact,
)
from poisonlens.audit.log import HashChainedAuditLog, verify_audit_log, compute_sha256, canonical_json


def run_pipeline(config_path: str) -> Dict[str, Any]:
    """Execute end-to-end PoisonLens pipeline:
    Train -> Score -> Mitigate -> Retrain -> Evaluate -> Audit.
    """
    total_start_time = time.time()
    
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
        
    config_hash = compute_sha256(canonical_json(config))
    seed = config.get("seed", 42)
    set_seed(seed)
    
    device = torch.device(config.get("device", "cpu"))
    data_root = config.get("data_root", "./data_cache")
    train_size = config.get("train_size", 10000)
    test_size = config.get("test_size", 2000)
    run_id = config.get("run_id", "pipeline_run")
    save_dir = config.get("save_dir", "runs")
    run_dir = os.path.join(save_dir, run_id)
    ensure_dir(run_dir)
    
    print("=" * 70)
    print(f"POISONLENS PIPELINE: {run_id}")
    print(f"Config: {config_path} (Hash: {config_hash[:16]}...)")
    print("=" * 70)

    # -------------------------------------------------------------
    # Stage 1: Data Preparation & Attack Injection
    # -------------------------------------------------------------
    print("\n[Stage 1/6] Loading CIFAR-10 data and canary partition...")
    clean_train_full, test_sub, indices_hash = load_cifar10_subsets(
        data_root=data_root, train_size=train_size, test_size=test_size, seed=seed
    )
    
    # 200-sample clean canary set held out of training
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

    attack_type = config.get("attack", "none")
    poison_rate = config.get("poison_rate", 0.05)
    trigger_fn = None
    
    if attack_type == "label_flip":
        src = config.get("source_class", 3)
        tgt = config.get("target_class", 5)
        p_train, gt_mask = apply_label_flip(clean_train_sub, poison_rate, src, tgt, seed=seed)
    elif attack_type == "badnets":
        tgt = config.get("target_class", 0)
        patch_size = config.get("patch_size", 3)
        p_train, gt_mask, trigger_fn = apply_badnets(clean_train_sub, poison_rate, tgt, patch_size=patch_size, seed=seed)
    elif attack_type == "blended":
        tgt = config.get("target_class", 0)
        alpha = config.get("alpha", 0.20)
        p_train, gt_mask, trigger_fn = apply_blended(clean_train_sub, poison_rate, tgt, alpha=alpha, seed=seed)
    else:
        p_train = clean_train_sub
        gt_mask = np.zeros(len(p_train), dtype=bool)

    test_loader = DataLoader(test_sub, batch_size=128, shuffle=False, num_workers=0)
    canary_guard = CanaryGuard(canary_sub, tolerance=0.03, device=device)

    # -------------------------------------------------------------
    # Stage 2: Initial Training with Dynamics Logging
    # -------------------------------------------------------------
    print(f"\n[Stage 2/6] Training baseline model with dynamics tracking (epochs: {config.get('epochs', 10)})...")
    base_model = create_model(10)
    g = torch.Generator()
    g.manual_seed(seed)
    train_loader = DataLoader(p_train, batch_size=config.get("batch_size", 128), shuffle=True, generator=g, num_workers=0)
    
    trainer = PoisonLensTrainer(
        model=base_model,
        train_loader=train_loader,
        test_loader=test_loader,
        train_dataset_size=len(p_train),
        run_dir=run_dir,
        config=config,
        device=device,
    )
    
    # Check if checkpoint already exists to resume/speed up
    latest_ckpt = os.path.join(run_dir, "checkpoints", "checkpoint_latest.pt")
    if os.path.exists(latest_ckpt):
        print(f"  Found existing checkpoint at {latest_ckpt}, restoring...")
        trainer.load_checkpoint(latest_ckpt)
    else:
        trainer.train(max_epochs=config.get("epochs", 10))
        
    base_clean_acc, _ = evaluate_clean_accuracy(base_model, test_loader, device=device)
    base_canary_acc = canary_guard.establish_baseline(base_model)
    
    if attack_type == "label_flip":
        base_asr = evaluate_label_flip_asr(base_model, test_sub, config.get("source_class", 3), config.get("target_class", 5), device=device)
    elif attack_type in ["badnets", "blended"]:
        base_asr = evaluate_backdoor_asr(base_model, test_sub, trigger_fn, config.get("target_class", 0), device=device)
    else:
        base_asr = 0.0
        
    base_per_class = evaluate_per_class_accuracy(base_model, test_loader, 10, device=device)
    print(f"  Baseline Results -> Clean Acc: {base_clean_acc*100:.2f}%, Canary Acc: {base_canary_acc*100:.2f}%, ASR: {base_asr*100:.2f}%")

    # -------------------------------------------------------------
    # Stage 3: Trajectory Scoring & Throughput Measurement
    # -------------------------------------------------------------
    print("\n[Stage 3/6] Extracting trajectory dynamics & computing suspicion scores...")
    scoring_start_time = time.time()
    
    early_model = create_model(10)
    early_ckpt_path = os.path.join(run_dir, "checkpoints", "checkpoint_epoch_1.pt")
    if os.path.exists(early_ckpt_path):
        early_model.load_state_dict(torch.load(early_ckpt_path, map_location=device, weights_only=False)["model_state_dict"])
    else:
        early_model.load_state_dict(base_model.state_dict())
    early_model.eval()

    # Small 100-sample validation split for weights
    rng = np.random.RandomState(seed)
    clean_pool = np.where(~gt_mask)[0]
    poison_pool = np.where(gt_mask)[0]
    if len(poison_pool) > 0:
        val_clean = rng.choice(clean_pool, size=min(90, len(clean_pool)), replace=False)
        val_poison = rng.choice(poison_pool, size=min(10, len(poison_pool)), replace=False)
        val_indices = np.concatenate([val_clean, val_poison])
        val_labels = gt_mask[val_indices]
    else:
        val_indices = None
        val_labels = None

    drop_mask, scores, reasons, meta = detect_by_trajectory_fingerprint(
        loss_history=trainer.dynamics_losses[:, :len(p_train)],
        correct_history=trainer.dynamics_correct[:, :len(p_train)],
        early_model=early_model,
        converged_model=base_model,
        dataset=p_train,
        drop_ratio=poison_rate,
        val_indices=val_indices,
        val_labels=val_labels,
        device=device,
    )
    scoring_elapsed = time.time() - scoring_start_time
    scoring_throughput = len(p_train) / max(0.001, scoring_elapsed)
    print(f"  Scoring completed in {scoring_elapsed:.2f}s ({scoring_throughput:.1f} samples/sec)")

    # -------------------------------------------------------------
    # Stage 4: Controlled Mitigation (Soft Quarantine)
    # -------------------------------------------------------------
    print("\n[Stage 4/6] Applying 3-tier Soft Quarantine & Canary Guardrail...")
    weights, tiers, tier_info = assign_mitigation_tiers(
        scores, quarantine_ratio=poison_rate, downweight_ratio=0.10, downweight_value=0.20
    )
    wrongly_stats = measure_wrongly_quarantined(tier_info["quarantine_mask"], gt_mask)
    print(f"  Tiers: {tier_info['num_kept']} kept, {tier_info['num_downweighted']} down-weighted, {tier_info['num_quarantined']} quarantined")
    print(f"  False Positives (Clean wrongly quarantined): {wrongly_stats['wrongly_quarantined_count']} / {wrongly_stats['total_clean_samples']}")

    # -------------------------------------------------------------
    # Stage 5: Retraining on Mitigated Data
    # -------------------------------------------------------------
    print("\n[Stage 5/6] Retraining model from scratch with sample weights (epochs: 5)...")
    mitigated_run_dir = os.path.join(run_dir, "mitigated_model")
    ensure_dir(mitigated_run_dir)
    
    retrained_model = create_model(10)
    retrain_trainer = PoisonLensTrainer(
        model=retrained_model,
        train_loader=train_loader,
        test_loader=test_loader,
        train_dataset_size=len(p_train),
        run_dir=mitigated_run_dir,
        config={"seed": seed, "epochs": 5, "lr": 0.001, "weight_decay": 1e-4},
        device=device,
        sample_weights=torch.tensor(weights, dtype=torch.float32),
    )
    retrain_trainer.train(max_epochs=5)
    
    # Canary evaluation and guardrail check
    post_canary_acc = canary_guard.evaluate(retrained_model)
    is_rolled_back, _, canary_delta, guard_decision = canary_guard.verify_and_rollback(
        candidate_model=retrained_model,
        backup_checkpoint_path=latest_ckpt,
        current_quarantine_ratio=poison_rate,
    )
    print(f"  Canary Health -> Baseline: {base_canary_acc*100:.2f}%, Post-Mitigation: {post_canary_acc*100:.2f}% (Delta: {canary_delta*100:+.2f}%)")
    print(f"  Guardrail Decision: {guard_decision['action']} ({guard_decision['reason']})")

    # -------------------------------------------------------------
    # Stage 6: Final Evaluation & Hash-Chained Audit Logging
    # -------------------------------------------------------------
    print("\n[Stage 6/6] Final evaluation & writing hash-chained audit log...")
    final_clean_acc, _ = evaluate_clean_accuracy(retrained_model, test_loader, device=device)
    
    if attack_type == "label_flip":
        final_asr = evaluate_label_flip_asr(retrained_model, test_sub, config.get("source_class", 3), config.get("target_class", 5), device=device)
    elif attack_type in ["badnets", "blended"]:
        final_asr = evaluate_backdoor_asr(retrained_model, test_sub, trigger_fn, config.get("target_class", 0), device=device)
    else:
        final_asr = 0.0
        
    final_per_class = evaluate_per_class_accuracy(retrained_model, test_loader, 10, device=device)
    per_class_impact = compute_per_class_impact(base_per_class, final_per_class)

    # Write audit log
    audit_log_path = os.path.join(run_dir, "audit_log.jsonl")
    if os.path.exists(audit_log_path):
        os.remove(audit_log_path)
    audit = HashChainedAuditLog(audit_log_path, config_hash=config_hash)
    
    for i in range(len(p_train)):
        audit.log_decision(
            sample_id=int(p_train.sample_ids[i]),
            score=float(scores[i]),
            reasons=reasons[i],
            decision=str(tiers[i]),
            sample_weight=float(weights[i]),
        )
        
    is_valid, bad_idx, verify_msg = verify_audit_log(audit_log_path)
    print(f"  Audit Log: {audit_log_path} ({len(p_train)} entries, Verification: {verify_msg})")

    total_pipeline_time = time.time() - total_start_time

    results = {
        "run_id": run_id,
        "config_hash": config_hash,
        "total_time_seconds": round(total_pipeline_time, 2),
        "scoring_time_seconds": round(scoring_elapsed, 2),
        "scoring_throughput_samples_per_sec": round(scoring_throughput, 1),
        "baseline_metrics": {
            "clean_acc": f"{base_clean_acc*100:.2f}%",
            "canary_acc": f"{base_canary_acc*100:.2f}%",
            "asr": f"{base_asr*100:.2f}%",
        },
        "mitigated_metrics": {
            "clean_acc": f"{final_clean_acc*100:.2f}%",
            "canary_acc": f"{post_canary_acc*100:.2f}%",
            "asr": f"{final_asr*100:.2f}%",
            "wrongly_quarantined_clean": wrongly_stats["wrongly_quarantined_count"],
            "clean_retention_rate": f"{wrongly_stats['clean_retention_rate']*100:.2f}%",
            "worst_class_drop": f"{per_class_impact['worst_class_drop']*100:.2f}% (Class {per_class_impact['worst_harmed_class']})",
        },
        "guardrail_decision": guard_decision,
        "audit_verification": {"is_valid": is_valid, "message": verify_msg},
    }

    results_path = os.path.join(run_dir, "pipeline_results.json")
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 70)
    print("PIPELINE EXECUTION COMPLETE")
    print(f"Total Pipeline Runtime: {total_pipeline_time:.2f}s")
    print(f"Scoring Throughput:     {scoring_throughput:.1f} samples/sec")
    print(f"Pre-Defense -> Clean: {base_clean_acc*100:.2f}%, ASR: {base_asr*100:.2f}%")
    print(f"Post-Defense -> Clean: {final_clean_acc*100:.2f}%, ASR: {final_asr*100:.2f}%")
    print("=" * 70)

    return results
