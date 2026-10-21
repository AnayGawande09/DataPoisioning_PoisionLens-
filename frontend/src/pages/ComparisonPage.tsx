import React, { useEffect, useState } from 'react';
import { GitCompare, Award, ShieldAlert, CheckCircle2, TrendingUp, Info } from 'lucide-react';
import { SimpleGuideCard, PlainEnglishBox } from '../components/SimpleGuideCard';
import { api } from '../services/api';
import { BenchmarkRow } from '../types';

export const ComparisonPage: React.FC = () => {
  const [benchmarks, setBenchmarks] = useState<BenchmarkRow[]>([]);
  const [selectedAttack, setSelectedAttack] = useState<string>('all');

  useEffect(() => {
    let mounted = true;
    api.getBenchmarks().then((b) => {
      if (mounted) setBenchmarks(b);
    });
    return () => {
      mounted = false;
    };
  }, []);

  const filtered = selectedAttack === 'all'
    ? benchmarks
    : benchmarks.filter((b) => b.Attack.toLowerCase().includes(selectedAttack.toLowerCase()));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <GitCompare size={26} style={{ color: 'var(--cyan-400)' }} />
            <span>Master Benchmark Comparison</span>
          </h1>
          <p className="page-description">
            Head-to-head empirical comparison of PoisonLens against Undefended baselines, Loss-Threshold Filtering, and Activation Clustering (Chen et al.) across CIFAR-10 attack benchmarks.
          </p>
        </div>

        {/* Filter buttons */}
        <div style={{ display: 'flex', gap: 6 }}>
          {[
            { id: 'all', label: 'All Attacks' },
            { id: 'label flip', label: 'Label Flip (10%)' },
            { id: 'badnets', label: 'BadNets Backdoor (5%)' },
            { id: 'blended', label: 'Blended Backdoor (5%)' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setSelectedAttack(tab.id)}
              className="btn-ghost"
              style={{
                fontSize: '0.75rem',
                padding: '6px 12px',
                background: selectedAttack === tab.id ? 'rgba(6, 182, 212, 0.15)' : undefined,
                color: selectedAttack === tab.id ? 'var(--cyan-400)' : undefined,
                borderColor: selectedAttack === tab.id ? 'var(--cyan-400)' : undefined,
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab-Level Plain-English Guide */}
      <SimpleGuideCard
        title="Model Benchmarks: The Defense Scoreboard"
        summary="This scoreboard compares PoisonLens against three industry-standard baselines across different cyberattacks. It shows why simple deletion fails (it throws away valuable clean data and causes accuracy to crash by up to 13%) and how PoisonLens's 3-Tier Soft Quarantine preserves AI intelligence while stopping backdoors."
        steps={[
          {
            step: '1',
            title: 'Undefended Baseline',
            description: 'The AI model trained with no protection. The attacker achieves high backdoor success (ASR > 91%).',
          },
          {
            step: '2',
            title: 'Static Loss Filtering',
            description: 'A basic method that only looks at final loss. Misses subtle backdoors because the AI memorizes them early.',
          },
          {
            step: '3',
            title: 'Activation Clustering',
            description: 'Groups penultimate features. Excellent on high-contrast BadNets patches (0.947 F1), but achieves 0.000 F1 on label flips.',
          },
          {
            step: '4',
            title: 'PoisonLens (Ours)',
            description: 'Tracks learning trajectory dynamics over 10 epochs. Recovers +3.80% to +5.05% clean accuracy over binary deletion.',
          },
        ]}
        takeaway="Notice how PoisonLens is the only defense with non-zero detection across all attack types while preserving clean test accuracy."
        accentColor="cyan"
      />

      {/* Section Explainer */}
      <PlainEnglishBox
        question="How do I read this comparison table?"
        explanation="Look at the rows within each attack scenario. You want high Clean Accuracy (AI stays smart), high F1 Score (accurate detection of poisoned images), and low Attack Success (hacker's backdoor neutralized)."
      />

      {/* Benchmark Table */}
      <div className="glass-panel" style={{ overflow: 'hidden' }}>
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Attack Scenario</th>
                <th>Defense Method</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>F1 Score</th>
                <th>Clean Acc</th>
                <th>Attack Success (ASR)</th>
                <th>Security Analysis</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((row, idx) => {
                const isPoisonLens = row.Defense.includes('PoisonLens');
                const isBestF1 = row.F1 === '0.947' || (row.Attack.includes('Label Flip') && row.F1 === '0.121');

                return (
                  <tr
                    key={idx}
                    style={{
                      background: isPoisonLens ? 'rgba(6, 182, 212, 0.04)' : undefined,
                    }}
                  >
                    <td style={{ fontWeight: 600, color: '#FFFFFF' }}>{row.Attack}</td>
                    <td style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      {isPoisonLens && <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--cyan-400)' }} />}
                      <span style={{ color: isPoisonLens ? 'var(--cyan-400)' : '#FFF', fontWeight: isPoisonLens ? 700 : 500 }}>
                        {row.Defense}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{row.Precision}</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{row.Recall}</td>
                    <td>
                      <span
                        className="mono-tag"
                        style={{
                          background: isBestF1 ? 'rgba(16, 185, 129, 0.15)' : 'rgba(255,255,255,0.05)',
                          color: isBestF1 ? 'var(--emerald-400)' : '#94A3B8',
                          fontWeight: isBestF1 ? 700 : 500,
                        }}
                      >
                        {row.F1}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--emerald-400)', fontWeight: 600 }}>
                      {row['Clean Acc']}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--rose-400)', fontWeight: 600 }}>
                      {row.ASR}
                    </td>
                    <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{row.Notes}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* 3 Core Research Conclusions Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
        <div className="glass-panel" style={{ padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, color: 'var(--cyan-400)' }}>
            <TrendingUp size={18} />
            <span style={{ fontSize: '0.9rem', fontWeight: 700 }}>Label Flip Defense</span>
          </div>
          <p style={{ fontSize: '0.785rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            PoisonLens achieves <strong>0.121 F1</strong> and cuts Attack Success Rate from 72.50% down to <strong>44.50%</strong> (28.0% absolute reduction). Traditional Loss Filtering fails completely (ASR worsens to 83.50%) because converged label flips have lower final loss than clean edge cases.
          </p>
        </div>

        <div className="glass-panel" style={{ padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, color: 'var(--emerald-400)' }}>
            <Award size={18} />
            <span style={{ fontSize: '0.9rem', fontWeight: 700 }}>Localized Backdoor (BadNets)</span>
          </div>
          <p style={{ fontSize: '0.785rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            Activation Clustering achieves a standout <strong>0.947 F1</strong> on high-contrast 3x3 white square patches by cleanly separating bimodal penultimate features. PoisonLens reaches <strong>0.276 F1</strong> (138x better than static loss filtering's 0.002).
          </p>
        </div>

        <div className="glass-panel" style={{ padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, color: 'var(--amber-400)' }}>
            <ShieldAlert size={18} />
            <span style={{ fontSize: '0.9rem', fontWeight: 700 }}>Stealthy Blended Backdoors</span>
          </div>
          <p style={{ fontSize: '0.785rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            Uniform static noise (&alpha;=0.20) evades both Loss Filtering (0.000 F1) and Activation Clustering (0.000 F1). PoisonLens is the <strong>only evaluated defense</strong> with non-zero detection (0.024 F1), highlighting that training dynamics capture subtle gradient perturbations missed by feature clusters.
          </p>
        </div>
      </div>
    </div>
  );
};
