import React from 'react';
import { X, ShieldAlert, ShieldCheck, AlertTriangle, Hash, Clock, CheckCircle2, XCircle } from 'lucide-react';
import { SampleDetail } from '../types';

interface SampleDrawerProps {
  sample: SampleDetail | null;
  onClose: () => void;
}

export const SampleDrawer: React.FC<SampleDrawerProps> = ({ sample, onClose }) => {
  if (!sample) return null;

  const decisionPill = {
    keep: {
      label: 'KEEP (w=1.0)',
      bg: 'rgba(16, 185, 129, 0.15)',
      color: 'var(--emerald-400)',
      border: 'rgba(16, 185, 129, 0.3)',
      icon: ShieldCheck,
    },
    downweight: {
      label: 'DOWNWEIGHT (w=0.20)',
      bg: 'rgba(245, 158, 11, 0.15)',
      color: 'var(--amber-400)',
      border: 'rgba(245, 158, 11, 0.3)',
      icon: AlertTriangle,
    },
    quarantine: {
      label: 'QUARANTINE (w=0.0)',
      bg: 'rgba(244, 63, 94, 0.15)',
      color: 'var(--rose-400)',
      border: 'rgba(244, 63, 94, 0.3)',
      icon: ShieldAlert,
    },
  }[sample.decision] || {
    label: sample.decision.toUpperCase(),
    bg: 'rgba(255, 255, 255, 0.1)',
    color: '#FFF',
    border: 'rgba(255, 255, 255, 0.2)',
    icon: ShieldCheck,
  };

  const PillIcon = decisionPill.icon;

  // Chart coordinates calculation
  const curve = sample.loss_curve && sample.loss_curve.length > 0
    ? sample.loss_curve
    : [4.5, 3.2, 2.1, 1.8, 1.2, 0.9, 0.7, 0.5, 0.4, 0.3];

  const maxLoss = Math.max(...curve, 1.0);
  const minLoss = 0.0;
  const width = 420;
  const height = 140;
  const padding = 20;

  const points = curve
    .map((val, idx) => {
      const x = padding + (idx / (curve.length - 1)) * (width - 2 * padding);
      const y = height - padding - ((val - minLoss) / (maxLoss - minLoss)) * (height - 2 * padding);
      return `${x},${y}`;
    })
    .join(' ');

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <div className="drawer-panel" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="drawer-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: '1.15rem', fontWeight: 700, color: '#FFFFFF', fontFamily: 'var(--font-mono)' }}>
                Sample #{sample.sample_id}
              </span>
              <span
                className="mono-tag"
                style={{
                  background: decisionPill.bg,
                  color: decisionPill.color,
                  border: `1px solid ${decisionPill.border}`,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 4,
                }}
              >
                <PillIcon size={12} />
                {decisionPill.label}
              </span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4 }}>
              Combined Suspicion Score: <span style={{ color: '#FFFFFF', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{sample.score.toFixed(3)}</span>
            </div>
          </div>

          <button onClick={onClose} className="btn-ghost" style={{ padding: 6 }}>
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="drawer-body">
          {/* Ground truth note */}
          {sample.is_ground_truth_poison !== undefined && sample.is_ground_truth_poison !== null && (
            <div
              style={{
                padding: '10px 14px',
                borderRadius: 8,
                background: sample.is_ground_truth_poison ? 'rgba(244, 63, 94, 0.1)' : 'rgba(16, 185, 129, 0.1)',
                border: `1px solid ${sample.is_ground_truth_poison ? 'rgba(244, 63, 94, 0.25)' : 'rgba(16, 185, 129, 0.25)'}`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <span style={{ fontSize: '0.775rem', color: 'var(--text-secondary)' }}>
                Controlled-Evaluation Ground Truth:
              </span>
              <span
                className="mono-tag"
                style={{
                  background: sample.is_ground_truth_poison ? 'var(--rose-900)' : 'var(--emerald-900)',
                  color: sample.is_ground_truth_poison ? 'var(--rose-400)' : 'var(--emerald-400)',
                  fontWeight: 700,
                }}
              >
                {sample.is_ground_truth_poison ? 'POISONED SAMPLE (Targeted)' : 'CLEAN SAMPLE'}
              </span>
            </div>
          )}

          {/* Loss Trajectory Chart */}
          <div className="glass-panel" style={{ padding: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
              <span style={{ fontSize: '0.825rem', fontWeight: 600, color: '#FFFFFF' }}>
                Training Loss Dynamics Across 10 Epochs
              </span>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                Max Loss: {maxLoss.toFixed(2)}
              </span>
            </div>

            <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`} style={{ overflow: 'visible' }}>
              {/* Grid lines */}
              <line x1={padding} y1={padding} x2={width - padding} y2={padding} stroke="rgba(255,255,255,0.06)" />
              <line x1={padding} y1={height / 2} x2={width - padding} y2={height / 2} stroke="rgba(255,255,255,0.06)" />
              <line x1={padding} y1={height - padding} x2={width - padding} y2={height - padding} stroke="rgba(255,255,255,0.12)" />

              {/* Trajectory Polyline */}
              <polyline
                fill="none"
                stroke="var(--cyan-400)"
                strokeWidth="2.5"
                points={points}
                strokeLinecap="round"
                strokeLinejoin="round"
              />

              {/* Coordinates dots */}
              {curve.map((val, idx) => {
                const x = padding + (idx / (curve.length - 1)) * (width - 2 * padding);
                const y = height - padding - ((val - minLoss) / (maxLoss - minLoss)) * (height - 2 * padding);
                return (
                  <circle
                    key={idx}
                    cx={x}
                    cy={y}
                    r={3.5}
                    fill="#0A0F1D"
                    stroke="var(--cyan-primary)"
                    strokeWidth="2"
                  />
                );
              })}
            </svg>

            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4, fontSize: '0.675rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              <span>Epoch 0</span>
              <span>Epoch 5</span>
              <span>Epoch 9</span>
            </div>
          </div>

          {/* Detection Explanations */}
          <div>
            <div style={{ fontSize: '0.825rem', fontWeight: 600, color: '#FFFFFF', marginBottom: 8 }}>
              Detection Explanations & Z-Scores
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {sample.reasons && sample.reasons.length > 0 ? (
                sample.reasons.map((r, i) => (
                  <span
                    key={i}
                    className="mono-tag"
                    style={{
                      background: 'rgba(244, 63, 94, 0.12)',
                      color: 'var(--rose-400)',
                      border: '1px solid rgba(244, 63, 94, 0.25)',
                      padding: '4px 8px',
                    }}
                  >
                    {r}
                  </span>
                ))
              ) : (
                <span className="mono-tag" style={{ background: 'rgba(16, 185, 129, 0.1)', color: 'var(--emerald-400)' }}>
                  Normal learning convergence trajectory
                </span>
              )}
            </div>
          </div>

          {/* Epoch Predictions History */}
          {sample.preds_history && sample.preds_history.length > 0 && (
            <div>
              <div style={{ fontSize: '0.825rem', fontWeight: 600, color: '#FFFFFF', marginBottom: 8 }}>
                Epoch Prediction & Correctness Trace
              </div>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(5, 1fr)',
                  gap: 6,
                }}
              >
                {sample.preds_history.map((pred, ep) => {
                  const isCorrect = sample.correct_history ? sample.correct_history[ep] : false;
                  return (
                    <div
                      key={ep}
                      style={{
                        padding: '6px 8px',
                        background: isCorrect ? 'rgba(16, 185, 129, 0.08)' : 'rgba(244, 63, 94, 0.08)',
                        border: `1px solid ${isCorrect ? 'rgba(16, 185, 129, 0.2)' : 'rgba(244, 63, 94, 0.2)'}`,
                        borderRadius: 6,
                        textAlign: 'center',
                        fontSize: '0.725rem',
                      }}
                    >
                      <div style={{ color: 'var(--text-muted)', fontSize: '0.65rem' }}>E{ep}</div>
                      <div style={{ fontWeight: 700, color: '#FFFFFF', margin: '2px 0' }}>Class {pred}</div>
                      <div style={{ display: 'flex', justifyContent: 'center' }}>
                        {isCorrect ? (
                          <CheckCircle2 size={12} style={{ color: 'var(--emerald-400)' }} />
                        ) : (
                          <XCircle size={12} style={{ color: 'var(--rose-400)' }} />
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Cryptographic Audit Hash Info */}
          <div className="glass-panel" style={{ padding: 14 }}>
            <div style={{ fontSize: '0.775rem', fontWeight: 600, color: '#FFFFFF', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
              <Hash size={14} style={{ color: 'var(--cyan-400)' }} />
              Audit Log Cryptographic Provenance
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: '0.7rem' }}>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Entry Hash: </span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan-400)', wordBreak: 'break-all' }}>
                  {sample.full_entry_hash || sample.entry_hash}
                </span>
              </div>
              {sample.previous_hash && (
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Previous Hash: </span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: '#94A3B8', wordBreak: 'break-all' }}>
                    {sample.previous_hash}
                  </span>
                </div>
              )}
              {sample.timestamp && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: 'var(--text-muted)' }}>
                  <Clock size={12} />
                  <span>Recorded: {sample.timestamp}</span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
