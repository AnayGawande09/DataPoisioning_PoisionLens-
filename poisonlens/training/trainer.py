"""Trainer with per-sample dynamic logging (loss, prediction, correctness), checkpointing, and resume support."""

import os
import json
from typing import Dict, Any, Optional, Tuple, List
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader

from poisonlens.utils import get_rng_states, set_rng_states, ensure_dir


class PoisonLensTrainer:
    """Trains model while logging fine-grained per-sample dynamics at every epoch."""

    def __init__(
        self,
        model: nn.Module,
        train_loader: DataLoader,
        test_loader: DataLoader,
        train_dataset_size: int,
        run_dir: str,
        config: Dict[str, Any],
        device: torch.device = torch.device("cpu"),
        sample_weights: Optional[torch.Tensor] = None,
    ):
        self.model = model.to(device)
        self.train_loader = train_loader
        self.test_loader = test_loader
        self.train_dataset_size = train_dataset_size
        self.run_dir = run_dir
        self.config = config
        self.device = device
        self.sample_weights = sample_weights

        self.checkpoints_dir = ensure_dir(os.path.join(run_dir, "checkpoints"))

        # Optimizer & scheduler setup
        lr = config.get("lr", 0.001)
        weight_decay = config.get("weight_decay", 1e-4)
        self.optimizer = torch.optim.Adam(
            self.model.parameters(), lr=lr, weight_decay=weight_decay
        )

        self.epochs = config.get("epochs", 10)

        # Storage for per-sample dynamics: shape (epochs, train_dataset_size)
        self.dynamics_losses = np.zeros((self.epochs, self.train_dataset_size), dtype=np.float32)
        self.dynamics_preds = np.zeros((self.epochs, self.train_dataset_size), dtype=np.int64)
        self.dynamics_correct = np.zeros((self.epochs, self.train_dataset_size), dtype=bool)

        # Run history
        self.history: Dict[str, List[float]] = {
            "train_loss": [],
            "train_acc": [],
            "test_loss": [],
            "test_acc": [],
        }

        self.current_epoch = 0

    def train_epoch(self, epoch_idx: int) -> Tuple[float, float]:
        """Execute one training epoch and record per-sample metrics."""
        self.model.train()
        total_loss = 0.0
        total_correct = 0
        total_samples = 0

        # Arrays for this epoch
        epoch_losses = np.zeros(self.train_dataset_size, dtype=np.float32)
        epoch_preds = np.zeros(self.train_dataset_size, dtype=np.int64)
        epoch_correct = np.zeros(self.train_dataset_size, dtype=bool)

        for batch_images, batch_targets, batch_sample_ids in self.train_loader:
            batch_images = batch_images.to(self.device)
            batch_targets = batch_targets.to(self.device)

            self.optimizer.zero_grad()
            logits = self.model(batch_images)
            loss_unreduced = F.cross_entropy(logits, batch_targets, reduction="none")

            if self.sample_weights is not None:
                weights = self.sample_weights[batch_sample_ids].to(self.device)
                loss = (loss_unreduced * weights).sum() / torch.clamp(weights.sum(), min=1e-6)
            else:
                loss = loss_unreduced.mean()

            loss.backward()
            self.optimizer.step()

            # Record metrics
            batch_preds = logits.argmax(dim=-1)
            batch_is_correct = (batch_preds == batch_targets)

            s_ids = batch_sample_ids.cpu().numpy()
            epoch_losses[s_ids] = loss_unreduced.detach().cpu().numpy()
            epoch_preds[s_ids] = batch_preds.detach().cpu().numpy()
            epoch_correct[s_ids] = batch_is_correct.detach().cpu().numpy()

            bs = batch_targets.size(0)
            total_loss += loss.item() * bs
            total_correct += batch_is_correct.sum().item()
            total_samples += bs

        # Save into dynamics history
        self.dynamics_losses[epoch_idx] = epoch_losses
        self.dynamics_preds[epoch_idx] = epoch_preds
        self.dynamics_correct[epoch_idx] = epoch_correct

        train_loss = total_loss / max(1, total_samples)
        train_acc = total_correct / max(1, total_samples)
        return train_loss, train_acc

    @torch.no_grad()
    def evaluate(self, loader: Optional[DataLoader] = None) -> Tuple[float, float]:
        """Evaluate model accuracy and loss on a given DataLoader (defaults to test_loader)."""
        self.model.eval()
        loader = loader or self.test_loader
        total_loss = 0.0
        total_correct = 0
        total_samples = 0

        for batch_images, batch_targets, _ in loader:
            batch_images = batch_images.to(self.device)
            batch_targets = batch_targets.to(self.device)

            logits = self.model(batch_images)
            loss = F.cross_entropy(logits, batch_targets, reduction="sum")
            preds = logits.argmax(dim=-1)

            total_loss += loss.item()
            total_correct += (preds == batch_targets).sum().item()
            total_samples += batch_targets.size(0)

        avg_loss = total_loss / max(1, total_samples)
        avg_acc = total_correct / max(1, total_samples)
        return avg_loss, avg_acc

    def save_checkpoint(self, epoch_idx: int) -> str:
        """Save training checkpoint including model, optimizer, rng states, and dynamics."""
        checkpoint_data = {
            "epoch": epoch_idx,
            "model_state_dict": self.model.state_dict(),
            "optimizer_state_dict": self.optimizer.state_dict(),
            "rng_states": get_rng_states(),
            "history": self.history,
            "dynamics": {
                "losses": self.dynamics_losses[: epoch_idx + 1],
                "preds": self.dynamics_preds[: epoch_idx + 1],
                "correct": self.dynamics_correct[: epoch_idx + 1],
            },
            "config": self.config,
        }

        ckpt_path = os.path.join(self.checkpoints_dir, f"checkpoint_epoch_{epoch_idx + 1}.pt")
        latest_path = os.path.join(self.checkpoints_dir, "checkpoint_latest.pt")
        torch.save(checkpoint_data, ckpt_path)
        torch.save(checkpoint_data, latest_path)

        # Also write the dynamics to npz for easy external inspection/analysis
        npz_path = os.path.join(self.run_dir, "training_dynamics.npz")
        np.savez_compressed(
            npz_path,
            losses=self.dynamics_losses[: epoch_idx + 1],
            preds=self.dynamics_preds[: epoch_idx + 1],
            correct=self.dynamics_correct[: epoch_idx + 1],
        )

        return ckpt_path

    def load_checkpoint(self, ckpt_path: str) -> int:
        """Restore trainer state from checkpoint, returning the next epoch index to run."""
        ckpt = torch.load(ckpt_path, map_location=self.device, weights_only=False)
        self.model.load_state_dict(ckpt["model_state_dict"])
        self.optimizer.load_state_dict(ckpt["optimizer_state_dict"])
        set_rng_states(ckpt["rng_states"])
        self.history = ckpt["history"]

        saved_epoch = ckpt["epoch"]
        dynamics = ckpt["dynamics"]
        num_saved = saved_epoch + 1

        saved_losses = dynamics["losses"]
        saved_preds = dynamics["preds"]
        saved_correct = dynamics["correct"]
        min_samples = min(self.train_dataset_size, saved_losses.shape[1])

        self.dynamics_losses[:num_saved, :min_samples] = saved_losses[:num_saved, :min_samples]
        self.dynamics_preds[:num_saved, :min_samples] = saved_preds[:num_saved, :min_samples]
        self.dynamics_correct[:num_saved, :min_samples] = saved_correct[:num_saved, :min_samples]

        self.current_epoch = num_saved
        return self.current_epoch

    def train(
        self,
        resume_from: Optional[str] = None,
        max_epochs: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Execute full training loop with checkpointing every epoch."""
        start_epoch = 0
        if resume_from is not None:
            start_epoch = self.load_checkpoint(resume_from)

        total_epochs = max_epochs if max_epochs is not None else self.epochs

        for epoch in range(start_epoch, total_epochs):
            train_loss, train_acc = self.train_epoch(epoch)
            test_loss, test_acc = self.evaluate(self.test_loader)

            self.history["train_loss"].append(train_loss)
            self.history["train_acc"].append(train_acc)
            self.history["test_loss"].append(test_loss)
            self.history["test_acc"].append(test_acc)

            self.save_checkpoint(epoch)

            print(
                f"Epoch [{epoch + 1:02d}/{total_epochs:02d}] "
                f"Train Loss: {train_loss:.4f} | Train Acc: {train_acc * 100:.2f}% | "
                f"Test Loss: {test_loss:.4f} | Test Acc: {test_acc * 100:.2f}%",
                flush=True,
            )

        return {
            "history": self.history,
            "final_test_acc": self.history["test_acc"][-1] if self.history["test_acc"] else 0.0,
            "final_test_loss": self.history["test_loss"][-1] if self.history["test_loss"] else 0.0,
            "dynamics_file": os.path.join(self.run_dir, "training_dynamics.npz"),
        }
