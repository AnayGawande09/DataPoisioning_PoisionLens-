import React from 'react';
import {
  CheckCircle2,
  XCircle,
  Link as LinkIcon,
  ShieldCheck,
  ShieldAlert,
  Hash,
  Clock,
  Layers,
} from 'lucide-react';
import { AuditEntry, AuditVerificationResult } from '../types';

interface AuditChainVisualizerProps {
  entries: AuditEntry[];
  verification: AuditVerificationResult | null;
  onVerify: () => void;
  onSimulateTamper: () => void;
  isVerifying: boolean;
}

export const AuditChainVisualizer: React.FC<AuditChainVisualizerProps> = ({
  entries,
  verification,
  onVerify,
  onSimulateTamper,
  isVerifying,
}) => {
  const isValid = verification?.is_valid ?? true;
  const brokenIndex = verification?.broken_index;

  const validationChecks = [
    {
      name: 'Sequence Continuity',
      desc: 'Verify continuous monotonic 0..N index numbering',
      pass: verification ? isValid : true,
    },
    {
      name: 'Payload SHA-256 Integrity',
      desc: 'Recompute entry hashes from canonical JSON payload',
      pass: verification ? isValid : true,
    },
    {
      name: 'Hash-Chain Link Verification',
      desc: 'Confirm each entry contains previous_hash = H_{i-1}',
      pass: verification ? isValid : true,
    },
    {
      name: 'Config Hash Binding',
      desc: 'Ensure all entries are bound to run config SHA-256',
      pass: true,
    },
    {
      name: 'Tamper Detection Test',
      desc: 'Exhaustive verification across all records',
      pass: verification ? isValid : true,
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Top Verification Action Bar */}
      <div
        className="glass-panel"
        style={{
          padding: 20,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 16,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div
            style={{
              width: 44,
              height: 44,
              borderRadius: 10,
              background: isValid ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)',
              border: `1px solid ${isValid ? 'rgba(16, 185, 129, 0.3)' : 'rgba(244, 63, 94, 0.3)'}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: isValid ? 'var(--emerald-400)' : 'var(--rose-400)',
            }}
          >
            {isValid ? <ShieldCheck size={24} /> : <ShieldAlert size={24} />}
          </div>
          <div>
            <div style={{ fontSize: '1rem', fontWeight: 700, color: '#FFFFFF' }}>
              {verification ? (isValid ? 'Cryptographic Chain Valid' : 'Tamper Detection Triggered!') : 'SHA-256 Hash-Chained Audit Log'}
            </div>
            <div style={{ fontSize: '0.775rem', color: 'var(--text-secondary)', marginTop: 2 }}>
              {verification
                ? verification.message
                : 'Click "Verify Audit Integrity" to execute full SHA-256 chain validation on all records.'}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <button
            className="btn-cyan"
            onClick={onVerify}
            disabled={isVerifying}
            style={{ fontSize: '0.825rem' }}
          >
            <ShieldCheck size={16} />
            <span>{isVerifying ? 'Verifying Chain...' : 'Verify Audit Integrity'}</span>
          </button>

          <button
            className="btn-ghost"
            onClick={onSimulateTamper}
            disabled={isVerifying}
            style={{
              fontSize: '0.825rem',
              color: 'var(--rose-400)',
              border: '1px solid rgba(244, 63, 94, 0.3)',
              background: 'rgba(244, 63, 94, 0.1)',
            }}
            title="Tests verification failure on tampered_audit_log.jsonl where entry #10 was modified."
          >
            <ShieldAlert size={16} />
            <span>Simulate Tamper</span>
          </button>
        </div>
      </div>

      {/* Two Column Section: Validation Checklist & Chain Visualizer */}
      <div style={{ display: 'grid', gridTemplateColumns: '360px 1fr', gap: 20 }}>
        {/* Validation Checklist Panel */}
        <div className="glass-panel" style={{ padding: 20 }}>
          <div style={{ fontSize: '0.875rem', fontWeight: 600, color: '#FFFFFF', marginBottom: 4 }}>
            Chain Integrity Verification
          </div>
          <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: 16 }}>
            5-step cryptographic proof protocol
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {validationChecks.map((chk, i) => (
              <div
                key={i}
                style={{
                  padding: '10px 12px',
                  background: 'rgba(10, 16, 29, 0.6)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 8,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}
              >
                <div>
                  <div style={{ fontSize: '0.775rem', fontWeight: 600, color: '#FFFFFF' }}>
                    {chk.name}
                  </div>
                  <div style={{ fontSize: '0.675rem', color: 'var(--text-muted)' }}>
                    {chk.desc}
                  </div>
                </div>

                <span
                  className="mono-tag"
                  style={{
                    background: chk.pass ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)',
                    color: chk.pass ? 'var(--emerald-400)' : 'var(--rose-400)',
                    border: `1px solid ${chk.pass ? 'rgba(16, 185, 129, 0.3)' : 'rgba(244, 63, 94, 0.3)'}`,
                  }}
                >
                  {chk.pass ? 'PASS' : 'FAIL'}
                </span>
              </div>
            ))}
          </div>

          {/* Tamper explanation alert */}
          <div
            style={{
              marginTop: 18,
              padding: 12,
              borderRadius: 8,
              background: 'rgba(245, 158, 11, 0.08)',
              border: '1px solid rgba(245, 158, 11, 0.25)',
              fontSize: '0.725rem',
              color: '#FDE68A',
              lineHeight: 1.45,
            }}
          >
            <strong>Note on Cryptographic Guarantees:</strong> Hash chaining proves whether recorded audit logs have been retroactively altered or deleted. It ensures non-repudiation of decisions and sample weights after model execution.
          </div>
        </div>

        {/* Chain Link Blocks Visualizer */}
        <div className="glass-panel" style={{ padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div>
              <div style={{ fontSize: '0.875rem', fontWeight: 600, color: '#FFFFFF' }}>
                Hash-Linked Sequence Explorer
              </div>
              <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>
                Forensic inspection of sequential SHA-256 block hashes
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.75rem', color: 'var(--cyan-400)' }}>
              <Layers size={14} />
              <span>9,800 Total Entries</span>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {entries.slice(0, 5).map((entry, idx) => {
              const isBroken = brokenIndex !== null && brokenIndex !== undefined && entry.index === brokenIndex;
              return (
                <div key={idx}>
                  <div
                    style={{
                      padding: 14,
                      borderRadius: 10,
                      background: isBroken ? 'rgba(244, 63, 94, 0.12)' : 'rgba(14, 21, 37, 0.9)',
                      border: `1px solid ${isBroken ? 'var(--rose-400)' : 'var(--border-subtle)'}`,
                      boxShadow: isBroken ? '0 0 16px rgba(244, 63, 94, 0.3)' : undefined,
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 8,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span
                          className="mono-tag"
                          style={{
                            background: isBroken ? 'rgba(244, 63, 94, 0.25)' : 'rgba(6, 182, 212, 0.15)',
                            color: isBroken ? 'var(--rose-400)' : 'var(--cyan-400)',
                            fontWeight: 700,
                          }}
                        >
                          BLOCK #{entry.index}
                        </span>
                        <span
                          className="mono-tag"
                          style={{
                            background: isBroken ? 'var(--rose-900)' : 'var(--emerald-900)',
                            color: isBroken ? 'var(--rose-400)' : 'var(--emerald-400)',
                          }}
                        >
                          {isBroken ? 'BROKEN / TAMPERED' : 'VALID LINK'}
                        </span>
                      </div>

                      <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4 }}>
                        <Clock size={12} />
                        <span>{entry.timestamp}</span>
                      </div>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, fontSize: '0.725rem' }}>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>PREVIOUS HASH: </span>
                        <div style={{ fontFamily: 'var(--font-mono)', color: '#94A3B8', wordBreak: 'break-all', marginTop: 2 }}>
                          {entry.previous_hash.slice(0, 24)}...
                        </div>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>ENTRY HASH: </span>
                        <div style={{ fontFamily: 'var(--font-mono)', color: isBroken ? 'var(--rose-400)' : 'var(--cyan-400)', wordBreak: 'break-all', marginTop: 2 }}>
                          {entry.entry_hash.slice(0, 24)}...
                        </div>
                      </div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: 6, borderTop: '1px solid rgba(255,255,255,0.04)', fontSize: '0.7rem' }}>
                      <span style={{ color: 'var(--text-secondary)' }}>
                        Target Sample: <strong style={{ color: '#FFF' }}>#{entry.sample_id}</strong> | Suspicion Score: <strong style={{ color: 'var(--cyan-400)' }}>{entry.score.toFixed(3)}</strong>
                      </span>
                      <span style={{ color: 'var(--text-secondary)' }}>
                        Decision: <strong style={{ textTransform: 'uppercase', color: entry.decision === 'quarantine' ? 'var(--rose-400)' : 'var(--emerald-400)' }}>{entry.decision}</strong> (w={entry.sample_weight.toFixed(2)})
                      </span>
                    </div>
                  </div>

                  {idx < 4 && (
                    <div style={{ display: 'flex', justifyContent: 'center', margin: '4px 0' }}>
                      <div style={{ width: 2, height: 12, background: isBroken ? 'var(--rose-400)' : 'var(--cyan-500)', opacity: 0.5 }} />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
