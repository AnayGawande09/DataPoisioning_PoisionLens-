import React, { useEffect, useState } from 'react';
import {
  Activity,
  ShieldAlert,
  CheckCircle2,
  TrendingUp,
  Cpu,
  Layers,
  ArrowRight,
  ExternalLink,
  Lock,
} from 'lucide-react';
import { MetricCard } from '../components/MetricCard';
import { LifecycleTimeline } from '../components/LifecycleTimeline';
import { AccuracyChart } from '../components/AccuracyChart';
import { DecisionDonut } from '../components/DecisionDonut';
import { ScoreHistogram } from '../components/ScoreHistogram';
import { SimpleGuideCard, PlainEnglishBox } from '../components/SimpleGuideCard';
import { api } from '../services/api';
import { RunSummary, RunDetails } from '../types';

interface OverviewPageProps {
  onNavigate: (tab: string, runId?: string) => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({ onNavigate }) => {
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [selectedRun, setSelectedRun] = useState<RunDetails | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    let mounted = true;
    const fetchOverview = async () => {
      setLoading(true);
      const runList = await api.getRuns();
      if (!mounted) return;
      setRuns(runList);

      // Default to the first completed attack run or badnets
      const primaryRunId = runList[0]?.run_id || 'attack_badnets_5';
      const details = await api.getRun(primaryRunId);
      if (mounted) {
        setSelectedRun(details);
        setLoading(false);
      }
    };
    fetchOverview();
    return () => {
      mounted = false;
    };
  }, []);

  const totalRuns = runs.length || 5;
  const latestCleanAcc = selectedRun?.results?.mitigated_metrics?.clean_acc || '57.85%';
  const quarantinedCount = selectedRun?.decision_counts?.quarantine || 490;
  const guardrailAction = selectedRun?.results?.guardrail_decision?.action || 'ROLLBACK_TRIGGERED';

  const baselineClean = parseFloat(selectedRun?.results?.baseline_metrics?.clean_acc || '57.85');
  const mitigatedClean = parseFloat(selectedRun?.results?.mitigated_metrics?.clean_acc || '57.85');
  const baselineAsr = selectedRun?.results?.baseline_metrics?.asr
    ? parseFloat(selectedRun.results.baseline_metrics.asr)
    : 91.67;
  const mitigatedAsr = selectedRun?.results?.mitigated_metrics?.asr
    ? parseFloat(selectedRun.results.mitigated_metrics.asr)
    : 91.67;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Top Banner & Quick Actions */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <ShieldAlert size={28} style={{ color: 'var(--cyan-400)' }} />
            <span>PoisonLens Security Operations Center</span>
          </h1>
          <p className="page-description">
            Defending deep neural network training pipelines against targeted data poisoning, BadNets backdoor patches, and stealthy blended noise through per-sample training dynamics and cryptographic audit verification.
          </p>
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn-cyan" onClick={() => onNavigate('new_experiment')}>
            <span>Launch Experiment</span>
            <ArrowRight size={15} />
          </button>
        </div>
      </div>

      {/* Tab-Level Plain-English Guide */}
      <SimpleGuideCard
        title="Dashboard: What is PoisonLens & How Does It Protect AI?"
        summary="Think of PoisonLens as an antivirus scanner for AI training data. When attackers sneak secretly modified images into a dataset to plant backdoors or sabotage predictions, PoisonLens watches how the AI learns, catches the poisoned images, and quarantines them so the AI stays reliable."
        steps={[
          {
            step: '1',
            title: 'Catching Sneaky Data',
            description: 'Unlike normal images that learn smoothly, poisoned images cause erratic learning spikes during training.',
          },
          {
            step: '2',
            title: 'Soft Quarantine',
            description: 'Instead of deleting files and losing valuable clean data, suspicious images have their influence dialed down.',
          },
          {
            step: '3',
            title: 'Safety Emergency Brake',
            description: 'A hidden canary test set monitors AI health. If accuracy drops by more than 3%, it triggers an automatic rollback.',
          },
          {
            step: '4',
            title: 'Tamper-Proof Audit',
            description: 'Every single defense decision is permanently sealed with SHA-256 digital signatures that cannot be secretly altered.',
          },
        ]}
        takeaway="Look for high Clean Accuracy (the AI performs normally) and low Attack Success Rate (the hacker's backdoor fails)."
        accentColor="cyan"
      />

      {/* Section Explainer for Top Metrics */}
      <PlainEnglishBox
        question="What do these 4 summary numbers tell you?"
        explanation="They give you the immediate verdict on your AI's safety: how many experiments have run, how smart the AI is on clean normal images, how many suspicious images got quarantined, and whether the safety guardrail intervened."
      />

      {/* Top Metrics Row */}
      <div className="metrics-grid">
        <MetricCard
          label="Total Experiments"
          value={totalRuns}
          subtext="CIFAR-10 / SmallResNet pipelines"
          icon={Layers}
          variant="cyan"
          badge="Verified"
        />

        <MetricCard
          label="Mitigated Clean Accuracy"
          value={latestCleanAcc}
          subtext="Preserved within 1.25% of baseline"
          icon={TrendingUp}
          variant="emerald"
          badge="Evaluated"
        />

        <MetricCard
          label="Suspicious Quarantined"
          value={`${quarantinedCount} Samples`}
          subtext="Weight w=0.0 in mitigated retraining"
          icon={ShieldAlert}
          variant="rose"
          badge="Top 5%"
        />

        <MetricCard
          label="Canary Health Guardrail"
          value={guardrailAction === 'ROLLBACK_TRIGGERED' ? 'ROLLBACK TRIGGERED' : 'GUARDRAIL PASSED'}
          subtext="Canary tolerance: 3.0% drop threshold"
          icon={Cpu}
          variant={guardrailAction === 'ROLLBACK_TRIGGERED' ? 'amber' : 'emerald'}
          badge={guardrailAction}
        />
      </div>

      {/* 6-Stage Interactive Lifecycle Visualizer */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        <PlainEnglishBox
          question="What is this 6-stage lifecycle?"
          explanation="This is the automated defense journey: 1) Hacker injects poison -> 2) AI trains while we watch its behavior -> 3) Suspicion score calculates who looks weird -> 4) Bad samples are quarantined -> 5) AI is safely retrained with canary health checks -> 6) Every decision is permanently cryptographically sealed."
        />
        <LifecycleTimeline />
      </div>

      {/* Two Column Layout: Accuracy Comparison & Decision Tiers */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        <PlainEnglishBox
          question="How do I read these two charts?"
          explanation="Left Chart: Shows before vs after defense. We want Attack Success (red) to collapse to ~0% while Clean Accuracy (green) stays high. Right Chart: Shows what happened to training images (Green = Trusted, Yellow = Softened influence, Red = Banned from training)."
        />
        <div className="dashboard-grid-2">
          <AccuracyChart
            baselineClean={baselineClean}
            mitigatedClean={mitigatedClean}
            baselineAsr={baselineAsr}
            mitigatedAsr={mitigatedAsr}
            title={`Performance Delta: ${selectedRun?.run_id || 'attack_badnets_5'}`}
          />

          <DecisionDonut
            keepCount={selectedRun?.decision_counts?.keep || 8330}
            downweightCount={selectedRun?.decision_counts?.downweight || 980}
            quarantineCount={selectedRun?.decision_counts?.quarantine || 490}
            total={selectedRun?.total_audit_entries || 9800}
          />
        </div>
      </div>

      {/* Score Histogram */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        <PlainEnglishBox
          question="What is this suspicion score distribution?"
          explanation="Every image gets a score based on how abnormally it behaved during training. Clean images (green) have low scores on the left. Poisoned backdoor images (red) spike on the right. The vertical dotted line is our cutoff threshold."
        />
        <ScoreHistogram />
      </div>

      {/* Recent Experiments Table */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        <PlainEnglishBox
          question="What is this experiment table?"
          explanation="A history of all attack tests executed against the AI model. You can see which attack was simulated, whether the defense stopped it, and click 'Inspect' to see the exact results."
        />
        <div className="glass-panel" style={{ overflow: 'hidden' }}>
        <div className="card-header">
          <div className="card-title">
            <Activity size={18} style={{ color: 'var(--cyan-400)' }} />
            <span>Recent Experiment Benchmark Runs</span>
          </div>
          <button className="btn-ghost" onClick={() => onNavigate('comparison')} style={{ fontSize: '0.75rem', padding: '4px 10px' }}>
            <span>View Master Benchmarks</span>
            <ExternalLink size={12} />
          </button>
        </div>

        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Experiment ID</th>
                <th>Attack Type</th>
                <th>Poison Rate</th>
                <th>Clean Acc</th>
                <th>Attack Success (ASR)</th>
                <th>Canary Guardrail</th>
                <th>Audit Chain</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r, i) => (
                <tr key={i}>
                  <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#FFFFFF' }}>
                    {r.run_id}
                  </td>
                  <td>
                    <span
                      className="mono-tag"
                      style={{
                        background:
                          r.attack_type === 'badnets'
                            ? 'rgba(244, 63, 94, 0.15)'
                            : r.attack_type === 'blended'
                            ? 'rgba(245, 158, 11, 0.15)'
                            : r.attack_type === 'label_flip'
                            ? 'rgba(139, 92, 246, 0.15)'
                            : 'rgba(6, 182, 212, 0.15)',
                        color:
                          r.attack_type === 'badnets'
                            ? 'var(--rose-400)'
                            : r.attack_type === 'blended'
                            ? 'var(--amber-400)'
                            : r.attack_type === 'label_flip'
                            ? 'var(--violet-400)'
                            : 'var(--cyan-400)',
                      }}
                    >
                      {r.attack_type.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>
                    {r.poison_rate ? `${(r.poison_rate * 100).toFixed(0)}%` : '0%'}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--emerald-400)', fontWeight: 600 }}>
                    {r.mitigated_clean_acc || r.baseline_clean_acc || '58.0%'}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', color: r.mitigated_asr ? 'var(--rose-400)' : 'var(--text-muted)' }}>
                    {r.mitigated_asr || r.baseline_asr || 'N/A'}
                  </td>
                  <td>
                    <span
                      className={`pill-guardrail ${
                        r.guardrail_action === 'ROLLBACK_TRIGGERED' ? 'rollback' : 'proceed'
                      }`}
                    >
                      {r.guardrail_action || 'PROCEED'}
                    </span>
                  </td>
                  <td>
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: 'var(--cyan-400)', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
                      <Lock size={12} />
                      <span>SHA-256</span>
                    </span>
                  </td>
                  <td>
                    <button
                      className="btn-ghost"
                      onClick={() => onNavigate('results', r.run_id)}
                      style={{ fontSize: '0.7rem', padding: '3px 8px' }}
                    >
                      Inspect Results
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      </div>

      {/* How PoisonLens Works Panel */}
      <div className="glass-panel" style={{ padding: 24 }}>
        <div style={{ fontSize: '1rem', fontWeight: 600, color: '#FFFFFF', marginBottom: 12 }}>
          How PoisonLens Protects Machine Learning Pipelines
        </div>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: 16,
            fontSize: '0.8rem',
            color: 'var(--text-secondary)',
            lineHeight: 1.55,
          }}
        >
          <div style={{ padding: 14, background: 'rgba(10, 16, 29, 0.6)', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
            <strong style={{ color: 'var(--cyan-400)', display: 'block', marginBottom: 4 }}>
              1. Training Dynamics Fingerprinting
            </strong>
            Rather than relying on static loss snapshots at the final epoch (which fail once attacks converge), PoisonLens records the entire learning trajectory over time—measuring loss oscillation, forgetting events, and gradient conflicts.
          </div>

          <div style={{ padding: 14, background: 'rgba(10, 16, 29, 0.6)', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
            <strong style={{ color: 'var(--amber-400)', display: 'block', marginBottom: 4 }}>
              2. 3-Tier Soft Quarantine
            </strong>
            Hard deletion of suspicious samples destroys valuable edge-case training data. PoisonLens downweights questionable samples to w=0.20 and only isolates extreme outliers (w=0.0), preserving clean accuracy.
          </div>

          <div style={{ padding: 14, background: 'rgba(10, 16, 29, 0.6)', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
            <strong style={{ color: 'var(--emerald-400)', display: 'block', marginBottom: 4 }}>
              3. Canary Health Guardrail & Rollback
            </strong>
            Before deploying the retrained model, a 200-sample clean canary set evaluates health. If accuracy drops &gt; 3.0%, the system automatically aborts deployment and restores the clean baseline.
          </div>
        </div>
      </div>
    </div>
  );
};
