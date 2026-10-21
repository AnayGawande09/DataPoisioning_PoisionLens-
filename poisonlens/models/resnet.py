"""Compact ResNet architecture optimized for CPU training on CIFAR-10 with feature extraction support."""

from typing import Tuple, Union
import torch
import torch.nn as nn
import torch.nn.functional as F


class ResidualBlock(nn.Module):
    """Basic 2-conv residual block with projection shortcut when stride > 1 or in_channels != out_channels."""

    def __init__(self, in_channels: int, out_channels: int, stride: int = 1):
        super().__init__()
        self.conv1 = nn.Conv2d(
            in_channels, out_channels, kernel_size=3, stride=stride, padding=1, bias=False
        )
        self.bn1 = nn.BatchNorm2d(out_channels)
        self.conv2 = nn.Conv2d(
            out_channels, out_channels, kernel_size=3, stride=1, padding=1, bias=False
        )
        self.bn2 = nn.BatchNorm2d(out_channels)

        self.shortcut = nn.Sequential()
        if stride != 1 or in_channels != out_channels:
            self.shortcut = nn.Sequential(
                nn.Conv2d(in_channels, out_channels, kernel_size=1, stride=stride, bias=False),
                nn.BatchNorm2d(out_channels),
            )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        residual = self.shortcut(x)
        out = F.relu(self.bn1(self.conv1(x)))
        out = self.bn2(self.conv2(out))
        out += residual
        return F.relu(out)


class SmallResNet(nn.Module):
    """Small ResNet model (~280k params) fast enough for sub-minute CPU execution on CIFAR-10."""

    def __init__(self, num_classes: int = 10):
        super().__init__()
        self.in_channels = 32

        # Initial convolution: 3x32x32 -> 32x32x32
        self.conv1 = nn.Conv2d(3, 32, kernel_size=3, stride=1, padding=1, bias=False)
        self.bn1 = nn.BatchNorm2d(32)

        # 3 Stages of residual blocks
        # Stage 1: 32x32x32 -> 32x32x32
        self.stage1 = ResidualBlock(32, 32, stride=1)
        # Stage 2: 32x32x32 -> 64x16x16
        self.stage2 = ResidualBlock(32, 64, stride=2)
        # Stage 3: 64x16x16 -> 128x8x8
        self.stage3 = ResidualBlock(64, 128, stride=2)

        # Global average pool: 128x8x8 -> 128x1x1
        self.avg_pool = nn.AdaptiveAvgPool2d((1, 1))

        # Penultimate feature dimension is 128
        self.feature_dim = 128
        self.fc = nn.Linear(128, num_classes)

    def extract_features(self, x: torch.Tensor) -> torch.Tensor:
        """Extract 128-dim penultimate layer representations."""
        out = F.relu(self.bn1(self.conv1(x)))
        out = self.stage1(out)
        out = self.stage2(out)
        out = self.stage3(out)
        out = self.avg_pool(out)
        features = torch.flatten(out, 1)
        return features

    def forward(
        self, x: torch.Tensor, return_features: bool = False
    ) -> Union[torch.Tensor, Tuple[torch.Tensor, torch.Tensor]]:
        features = self.extract_features(x)
        logits = self.fc(features)
        if return_features:
            return logits, features
        return logits


def create_model(num_classes: int = 10) -> SmallResNet:
    """Factory function for SmallResNet."""
    return SmallResNet(num_classes=num_classes)
