import React from 'react';
import { BookOpen, ShieldAlert, Cpu, Fingerprint, RotateCcw, Lock, Layers } from 'lucide-react';
import { SimpleGuideCard, PlainEnglishBox } from '../components/SimpleGuideCard';

export const MethodologyPage: React.FC = () => {
  return (
    <div style={{ maxWidth: 960, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <BookOpen size={26} style={{ color: 'var(--cyan-400)' }} />
            <span>PoisonLens Research Methodology</span>
          </h1>
          <p className="page-description">
            Comprehensive algorithmic principles, mathematical formulas, defense layers, and security boundaries implemented in the PoisonLens codebase.
          </p>
        </div>
      </div>

      {/* Tab-Level Plain-English Guide */}
      <SimpleGuideCard
        title="Methodology: How PoisonLens Works (In Plain English)"
        summary="Think of AI training like teaching a class of students. Most normal photos are easy lessons that students learn steadily over time. But poisoned photos are malicious trick questions designed to plant a hidden trap. PoisonLens acts like a vigilant teacher: watching which lessons cause erratic confusion, putting suspicious questions in 'time-out', and testing the class with a surprise pop quiz before graduation."
        steps={[
          {
            step: '1',
            title: 'Watching How AI Learns',
            description: 'Instead of inspecting photos at the very end, PoisonLens logs how easily the AI memorizes each picture across 10 rounds (epochs).',
          },
          {
            step: '2',
            title: '5 Anomaly Signals',
            description: 'Poisoned images suffer from frequent forgetting, high loss swings, and disagree with neighboring feature clusters.',
          },
          {
            step: '3',
            title: 'Soft Quarantine (Not Deletion)',
            description: 'Blindly deleting data throws away rare clean pictures. We keep 85% at full strength, downweight 10%, and quarantine 5%.',
          },
          {
            step: '4',
            title: 'Canary Health Brake',
            description: 'Tests 200 secret clean images. If the cleaned model loses >3% accuracy, it immediately rolls back to safety.',
          },
        ]}
        takeaway="By analyzing learning trajectories across time rather than static pixel values, PoisonLens catches stealthy attacks that fool traditional clustering."
        accentColor="violet"
      />

      {/* Section Explainer */}
      <PlainEnglishBox
        question="What are the 6 Pillars below?"
        explanation="Below are the formal algorithmic specifications implemented in the Python codebase, along with mathematical formulas for peer-reviewed research verification."
      />

      {/* 6 Core Pillars Accordion/Cards */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {/* Pillar 1 */}
        <div className="glass-panel" style={{ padding: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <div style={{ padding: 8, borderRadius: 8, background: 'rgba(6, 182, 212, 0.15)', color: 'var(--cyan-400)' }}>
              <Cpu size={18} />
            </div>
            <div>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#FFFFFF' }}>
                1. SmallResNet Architecture & Dynamics Collection
              </div>
              <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>
                3-stage residual network (~308k params) optimized for sub-minute CPU dynamics tracking
              </div>
            </div>
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            Instead of evaluating trained models after convergence, PoisonLens hooks into the PyTorch training loop across all 10 epochs. For every sample index i (0 to N-1), the trainer logs:
          </p>
          <ul style={{ marginLeft: 20, marginTop: 8, fontSize: '0.775rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: 4 }}>
            <li>Cross-entropy loss curve across epochs t in [0, ..., 9].</li>
            <li>Predicted class and binary correctness indicator c_t = (prediction == target).</li>
            <li>Early gradient norm proxy: ||g_i|| = ||p_i - y_i||_2 * ||h_i||_2, where h_i is the 128-dim penultimate feature vector.</li>
          </ul>
        </div>

        {/* Pillar 2 */}
        <div className="glass-panel" style={{ padding: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <div style={{ padding: 8, borderRadius: 8, background: 'rgba(139, 92, 246, 0.15)', color: 'var(--violet-400)' }}>
              <Fingerprint size={18} />
            </div>
            <div>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#FFFFFF' }}>
                2. Trajectory Fingerprint Scoring (5 Features)
              </div>
              <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>
                Multi-metric anomaly fusion with discrete-safe MAD normalization
              </div>
            </div>
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            Five orthogonal dynamic signals are extracted per sample:
          </p>
          <ol style={{ marginLeft: 20, marginTop: 8, fontSize: '0.775rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: 6 }}>
            <li><strong>First Correct Epoch:</strong> Poisoned samples conflict with clean distribution and are learned significantly later in training.</li>
            <li><strong>Forgetting Count:</strong> Frequency of transition from correct to incorrect predictions (correct at t-1 and incorrect at t) caused by gradient oscillations.</li>
            <li><strong>Loss Variance:</strong> Variance of cross-entropy loss across epochs: Var_t(Loss_t).</li>
            <li><strong>Early Gradient Norm Proxy:</strong> Measures parameter disruption during initial optimization.</li>
            <li><strong>Penultimate kNN Disagreement ($k=15$):</strong> Fraction of $k$ nearest neighbors in 128-dim embedding space having a different target label.</li>
          </ol>
          <div style={{ marginTop: 12, padding: 10, background: 'rgba(10, 16, 29, 0.7)', borderRadius: 6, fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--cyan-400)' }}>
            score_i = z(FirstCorrect) + 1.5 * z(Forgetting) + 1.2 * z(LossVar) + 1.0 * z(GradNorm) + 1.2 * z(kNNDisagree)
          </div>
        </div>

        {/* Pillar 3 */}
        <div className="glass-panel" style={{ padding: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <div style={{ padding: 8, borderRadius: 8, background: 'rgba(245, 158, 11, 0.15)', color: 'var(--amber-400)' }}>
              <Layers size={18} />
            </div>
            <div>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#FFFFFF' }}>
                3. 3-Tier Soft Quarantine Mitigation
              </div>
              <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>
                Weighted training loss preventing catastrophic clean edge-case deletion
              </div>
            </div>
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            Binary hard deletion of suspicious samples frequently deletes genuine rare clean samples (e.g., unusual lighting, edge angles), degrading overall test accuracy. PoisonLens maps scores into three tiers:
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10, marginTop: 10 }}>
            <div style={{ padding: 10, background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.25)', borderRadius: 6, fontSize: '0.725rem' }}>
              <strong style={{ color: 'var(--emerald-400)' }}>Keep (w = 1.0)</strong>
              <p style={{ color: 'var(--text-muted)', marginTop: 4 }}>Top 85% lowest scores. Full training weight.</p>
            </div>
            <div style={{ padding: 10, background: 'rgba(245, 158, 11, 0.08)', border: '1px solid rgba(245, 158, 11, 0.25)', borderRadius: 6, fontSize: '0.725rem' }}>
              <strong style={{ color: 'var(--amber-400)' }}>Downweight (w = 0.20)</strong>
              <p style={{ color: 'var(--text-muted)', marginTop: 4 }}>Next 10% borderline scores. Dampened influence.</p>
            </div>
            <div style={{ padding: 10, background: 'rgba(244, 63, 94, 0.08)', border: '1px solid rgba(244, 63, 94, 0.25)', borderRadius: 6, fontSize: '0.725rem' }}>
              <strong style={{ color: 'var(--rose-400)' }}>Quarantine (w = 0.0)</strong>
              <p style={{ color: 'var(--text-muted)', marginTop: 4 }}>Top 5% highest outliers. Fully neutralized.</p>
            </div>
          </div>
        </div>

        {/* Pillar 4 */}
        <div className="glass-panel" style={{ padding: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <div style={{ padding: 8, borderRadius: 8, background: 'rgba(244, 63, 94, 0.15)', color: 'var(--rose-400)' }}>
              <RotateCcw size={18} />
            </div>
            <div>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#FFFFFF' }}>
                4. Canary Health Guardrail & Automated Rollback
              </div>
              <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>
                Pre-deployment safety barrier against collateral damage and over-filtering
              </div>
            </div>
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            Before any mitigated model is accepted for deployment, it is evaluated on a held-out, pristine 200-sample clean canary set (20 samples per class). If canary test accuracy drops by more than <strong style={{ color: '#FFF' }}>3.0%</strong> relative to baseline, <code>CanaryGuard</code> triggers a safety rollback:
          </p>
          <div style={{ marginTop: 10, padding: 12, background: 'rgba(10, 16, 29, 0.7)', borderRadius: 6, fontSize: '0.75rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
            Canary Delta = Acc_mitigated - Acc_baseline &lt; -0.03 &rArr; ROLLBACK_TRIGGERED
          </div>
        </div>

        {/* Pillar 5 */}
        <div className="glass-panel" style={{ padding: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <div style={{ padding: 8, borderRadius: 8, background: 'rgba(16, 185, 129, 0.15)', color: 'var(--emerald-400)' }}>
              <Lock size={18} />
            </div>
            <div>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#FFFFFF' }}>
                5. Cryptographic SHA-256 Hash Chaining
              </div>
              <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>
                Forensic tamper-evident audit logging for high-assurance ML pipelines
              </div>
            </div>
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            Every mitigation decision is serialized to canonical JSON and linked to preceding entries via SHA-256 hashes:
          </p>
          <div style={{ marginTop: 10, padding: 12, background: 'rgba(10, 16, 29, 0.7)', borderRadius: 6, fontSize: '0.75rem', color: 'var(--cyan-400)', fontFamily: 'var(--font-mono)' }}>
            H_i = SHA-256( H_(i-1) || index || timestamp || sample_id || score || reasons || decision || weight )
          </div>
          <p style={{ fontSize: '0.775rem', color: 'var(--text-muted)', marginTop: 8 }}>
            If an insider or adversary attempts to retroactively un-quarantine a malicious backdoor sample, the chain break is flagged with exact entry index identification.
          </p>
        </div>
      </div>
    </div>
  );
};
