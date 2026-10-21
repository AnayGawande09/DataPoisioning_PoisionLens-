import React from 'react';
import { ArrowDownRight, ArrowUpRight, Minus } from 'lucide-react';

interface AccuracyChartProps {
  baselineClean: number; // e.g. 59.65
  mitigatedClean: number; // e.g. 46.90
  baselineAsr?: number | null; // e.g. 72.50
  mitigatedAsr?: number | null; // e.g. 44.50
  title?: string;
}

export const AccuracyChart: React.FC<AccuracyChartProps> = ({
  baselineClean,
  mitigatedClean,
  baselineAsr,
  mitigatedAsr,
  title = 'Model Performance: Before vs. After PoisonLens Defense',
}) => {
  const cleanDelta = Math.round((mitigatedClean - baselineClean) * 10) / 10;
  const asrDelta =
    baselineAsr !== undefined && baselineAsr !== null && mitigatedAsr !== undefined && mitigatedAsr !== null
      ? Math.round((mitigatedAsr - baselineAsr) * 10) / 10
      : null;

  return (
    <div className="glass-panel" style={{ padding: 20 }}>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 18,
        }}
      >
        <div>
          <div style={{ fontSize: '0.95rem', fontWeight: 600, color: '#FFFFFF' }}>
            {title}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 2 }}>
            Evaluation on 2,000 held-out CIFAR-10 test samples and backdoor trigger test sets.
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: 'rgba(255, 255, 255, 0.25)' }} />
            <span style={{ color: 'var(--text-muted)' }}>Undefended Baseline</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: 'var(--cyan-400)' }} />
            <span style={{ color: 'var(--cyan-400)' }}>PoisonLens Mitigated</span>
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
        {/* Clean Test Accuracy Row */}
        <div>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              marginBottom: 6,
              fontSize: '0.8rem',
            }}
          >
            <span style={{ fontWeight: 600, color: '#FFFFFF' }}>
              Clean Test Accuracy (Goal: Preserve &ge; 50%)
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                {baselineClean.toFixed(1)}% &rarr; {mitigatedClean.toFixed(1)}%
              </span>
              <span
                className="mono-tag"
                style={{
                  background:
                    cleanDelta >= 0
                      ? 'rgba(16, 185, 129, 0.15)'
                      : cleanDelta > -3.0
                      ? 'rgba(245, 158, 11, 0.15)'
                      : 'rgba(244, 63, 94, 0.15)',
                  color:
                    cleanDelta >= 0
                      ? 'var(--emerald-400)'
                      : cleanDelta > -3.0
                      ? 'var(--amber-400)'
                      : 'var(--rose-400)',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 3,
                }}
              >
                {cleanDelta > 0 ? (
                  <ArrowUpRight size={12} />
                ) : cleanDelta < 0 ? (
                  <ArrowDownRight size={12} />
                ) : (
                  <Minus size={12} />
                )}
                {cleanDelta >= 0 ? `+${cleanDelta.toFixed(1)}%` : `${cleanDelta.toFixed(1)}%`}
              </span>
            </div>
          </div>

          {/* Bar comparison container */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {/* Baseline bar */}
            <div style={{ position: 'relative', height: 18, background: 'rgba(255, 255, 255, 0.04)', borderRadius: 4, overflow: 'hidden' }}>
              <div
                style={{
                  width: `${baselineClean}%`,
                  height: '100%',
                  background: 'rgba(255, 255, 255, 0.25)',
                  borderRadius: 4,
                  transition: 'width 0.8s ease',
                }}
              />
              <span
                style={{
                  position: 'absolute',
                  right: 8,
                  top: '50%',
                  transform: 'translateY(-50%)',
                  fontSize: '0.7rem',
                  fontFamily: 'var(--font-mono)',
                  color: '#94A3B8',
                }}
              >
                Undefended: {baselineClean.toFixed(1)}%
              </span>
            </div>

            {/* Mitigated bar */}
            <div style={{ position: 'relative', height: 22, background: 'rgba(6, 182, 212, 0.08)', borderRadius: 4, overflow: 'hidden' }}>
              <div
                style={{
                  width: `${mitigatedClean}%`,
                  height: '100%',
                  background: 'linear-gradient(90deg, #0284C7 0%, #00F2FE 100%)',
                  borderRadius: 4,
                  boxShadow: '0 0 12px rgba(6, 182, 212, 0.4)',
                  transition: 'width 0.8s ease',
                }}
              />
              <span
                style={{
                  position: 'absolute',
                  right: 8,
                  top: '50%',
                  transform: 'translateY(-50%)',
                  fontSize: '0.75rem',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 700,
                  color: '#FFFFFF',
                }}
              >
                Mitigated: {mitigatedClean.toFixed(1)}%
              </span>
            </div>
          </div>
        </div>

        {/* Attack Success Rate (ASR) Row */}
        {baselineAsr !== undefined && baselineAsr !== null && (
          <div>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: 6,
                fontSize: '0.8rem',
              }}
            >
              <span style={{ fontWeight: 600, color: '#FFFFFF' }}>
                Attack Success Rate (ASR) (Goal: Minimize &rarr; 0%)
              </span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {baselineAsr.toFixed(1)}% &rarr; {(mitigatedAsr ?? baselineAsr).toFixed(1)}%
                </span>
                {asrDelta !== null && (
                  <span
                    className="mono-tag"
                    style={{
                      background:
                        asrDelta <= -10.0
                          ? 'rgba(16, 185, 129, 0.15)'
                          : asrDelta < 0
                          ? 'rgba(6, 182, 212, 0.15)'
                          : 'rgba(244, 63, 94, 0.15)',
                      color:
                        asrDelta <= -10.0
                          ? 'var(--emerald-400)'
                          : asrDelta < 0
                          ? 'var(--cyan-400)'
                          : 'var(--rose-400)',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 3,
                    }}
                  >
                    {asrDelta < 0 ? (
                      <ArrowDownRight size={12} />
                    ) : asrDelta > 0 ? (
                      <ArrowUpRight size={12} />
                    ) : (
                      <Minus size={12} />
                    )}
                    {asrDelta <= 0 ? `${asrDelta.toFixed(1)}%` : `+${asrDelta.toFixed(1)}%`}
                  </span>
                )}
              </div>
            </div>

            {/* ASR Bars */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {/* Baseline ASR bar */}
              <div style={{ position: 'relative', height: 18, background: 'rgba(255, 255, 255, 0.04)', borderRadius: 4, overflow: 'hidden' }}>
                <div
                  style={{
                    width: `${baselineAsr}%`,
                    height: '100%',
                    background: 'rgba(244, 63, 94, 0.4)',
                    borderRadius: 4,
                    transition: 'width 0.8s ease',
                  }}
                />
                <span
                  style={{
                    position: 'absolute',
                    right: 8,
                    top: '50%',
                    transform: 'translateY(-50%)',
                    fontSize: '0.7rem',
                    fontFamily: 'var(--font-mono)',
                    color: 'var(--rose-400)',
                  }}
                >
                  Undefended Attack Transfer: {baselineAsr.toFixed(1)}%
                </span>
              </div>

              {/* Mitigated ASR bar */}
              <div style={{ position: 'relative', height: 22, background: 'rgba(16, 185, 129, 0.08)', borderRadius: 4, overflow: 'hidden' }}>
                <div
                  style={{
                    width: `${mitigatedAsr ?? baselineAsr}%`,
                    height: '100%',
                    background:
                      (mitigatedAsr ?? baselineAsr) < baselineAsr
                        ? 'linear-gradient(90deg, #10B981 0%, #34D399 100%)'
                        : 'rgba(244, 63, 94, 0.5)',
                    borderRadius: 4,
                    boxShadow: '0 0 12px rgba(16, 185, 129, 0.3)',
                    transition: 'width 0.8s ease',
                  }}
                />
                <span
                  style={{
                    position: 'absolute',
                    right: 8,
                    top: '50%',
                    transform: 'translateY(-50%)',
                    fontSize: '0.75rem',
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 700,
                    color: '#FFFFFF',
                  }}
                >
                  Post-Defense ASR: {(mitigatedAsr ?? baselineAsr).toFixed(1)}%
                </span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
