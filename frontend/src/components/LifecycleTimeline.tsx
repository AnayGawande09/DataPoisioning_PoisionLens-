import React, { useState } from 'react';
import {
  Database,
  Cpu,
  Fingerprint,
  ShieldAlert,
  RotateCcw,
  FileCheck,
  ChevronRight,
  Info,
} from 'lucide-react';

export const LifecycleTimeline: React.FC = () => {
  const [selectedStep, setSelectedStep] = useState<number>(3);

  const steps = [
    {
      num: '01',
      title: 'Dataset & Attack',
      icon: Database,
      short: 'Stratified CIFAR-10 data preparation with deterministic attack simulation.',
      detail:
        'Samples are partitioned into deterministic stratified splits. Selected samples are perturbed with Label Flip, BadNets (3x3 patch), or Blended Backdoor (alpha=0.20). A git-style SHA-256 data hash ensures mathematical provenance.',
    },
    {
      num: '02',
      title: 'Dynamics Tracking',
      icon: Cpu,
      short: 'SmallResNet training while logging epoch-by-epoch sample loss, preds, & gradients.',
      detail:
        'The model trains for 10 epochs. For every sample at every epoch, PoisonLens records CrossEntropyLoss, predicted class, correctness, and an early gradient norm proxy ||g_i|| = ||p_i - y_i||_2 * ||h_i||_2.',
    },
    {
      num: '03',
      title: 'Trajectory Scoring',
      icon: Fingerprint,
      short: 'Multi-feature dynamic fingerprinting with discrete-safe MAD normalization.',
      detail:
        'Computes 5 dynamic features: First Correct Epoch, Forgetting Count, Loss Variance, Early Gradient Norm, and Penultimate kNN Disagreement (k=15). Scores are normalized using Median Absolute Deviation (MAD) with standard deviation fallback for zero-MAD discrete features.',
    },
    {
      num: '04',
      title: 'Soft Quarantine',
      icon: ShieldAlert,
      short: '3-tier sample weighting avoiding catastrophic clean data loss.',
      detail:
        'Samples are tiered into: Keep (w=1.0 for top 85-90%), Downweight (w=0.20 for top 10%), and Quarantine (w=0.0 for top 5%). This soft weighting retains edge-case clean samples while neutralizing blatant poison.',
    },
    {
      num: '05',
      title: 'Canary Guardrail',
      icon: RotateCcw,
      short: 'Held-out 200-sample clean canary evaluation with automatic rollback.',
      detail:
        'A fresh model is retrained on weighted samples and evaluated against a held-out 200-sample clean canary set. If canary accuracy drops > 3.0%, CanaryGuard automatically restores the baseline checkpoint and loosens the quarantine ratio.',
    },
    {
      num: '06',
      title: 'Cryptographic Audit',
      icon: FileCheck,
      short: 'SHA-256 hash-chained JSON Lines log verifying forensic integrity.',
      detail:
        'Every sample decision, score, explanation, weight, and timestamp is sealed into a SHA-256 hash chain (H_i = SHA-256(H_{i-1} || payload_i)). Any post-hoc tampering breaks the cryptographic chain and triggers instant detection.',
    },
  ];

  return (
    <div className="glass-panel lifecycle-container">
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 16,
        }}
      >
        <div>
          <div
            style={{
              fontSize: '0.95rem',
              fontWeight: 600,
              color: '#FFFFFF',
              display: 'flex',
              alignItems: 'center',
              gap: 8,
            }}
          >
            <span>PoisonLens End-to-End Pipeline Lifecycle</span>
            <span
              className="mono-tag"
              style={{
                background: 'rgba(6, 182, 212, 0.15)',
                color: 'var(--cyan-400)',
                border: '1px solid rgba(6, 182, 212, 0.3)',
              }}
            >
              6 AUTOMATED STAGES
            </span>
          </div>
          <div style={{ fontSize: '0.775rem', color: 'var(--text-muted)', marginTop: 2 }}>
            Click any stage to examine its algorithmic implementation and safety guarantees.
          </div>
        </div>
      </div>

      <div className="lifecycle-steps">
        {steps.map((step, idx) => {
          const Icon = step.icon;
          const isSelected = selectedStep === idx;
          return (
            <div
              key={step.num}
              className="lifecycle-step"
              onClick={() => setSelectedStep(idx)}
              style={{
                cursor: 'pointer',
                borderColor: isSelected ? 'var(--cyan-400)' : undefined,
                background: isSelected ? 'rgba(6, 182, 212, 0.1)' : undefined,
                boxShadow: isSelected ? '0 0 16px rgba(6, 182, 212, 0.2)' : undefined,
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: 6,
                }}
              >
                <span className="step-num">{step.num}</span>
                <Icon
                  size={15}
                  style={{
                    color: isSelected ? 'var(--cyan-400)' : 'var(--text-muted)',
                  }}
                />
              </div>
              <div className="step-title">{step.title}</div>
              <div className="step-desc">{step.short}</div>
            </div>
          );
        })}
      </div>

      {/* Selected Step Detail Panel */}
      <div
        style={{
          marginTop: 16,
          padding: '12px 16px',
          background: 'rgba(10, 16, 29, 0.8)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 8,
          display: 'flex',
          alignItems: 'flex-start',
          gap: 12,
        }}
      >
        <div
          style={{
            background: 'rgba(6, 182, 212, 0.15)',
            color: 'var(--cyan-400)',
            padding: 6,
            borderRadius: 6,
            marginTop: 2,
          }}
        >
          <Info size={16} />
        </div>
        <div>
          <div
            style={{
              fontSize: '0.825rem',
              fontWeight: 600,
              color: '#FFFFFF',
              marginBottom: 4,
            }}
          >
            Stage {steps[selectedStep].num}: {steps[selectedStep].title} Technical Specification
          </div>
          <div
            style={{
              fontSize: '0.785rem',
              color: 'var(--text-secondary)',
              lineHeight: 1.5,
            }}
          >
            {steps[selectedStep].detail}
          </div>
        </div>
      </div>
    </div>
  );
};
