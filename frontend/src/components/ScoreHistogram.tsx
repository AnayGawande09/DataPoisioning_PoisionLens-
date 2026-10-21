import React from 'react';

export const ScoreHistogram: React.FC = () => {
  // Binned z-score distribution across 9,800 samples from our empirical run
  const bins = [
    { label: '< -1.0', count: 1850, pct: 18.9, type: 'keep' },
    { label: '-1.0 to -0.5', count: 2420, pct: 24.7, type: 'keep' },
    { label: '-0.5 to 0.0', count: 2150, pct: 21.9, type: 'keep' },
    { label: '0.0 to +0.5', count: 1310, pct: 13.4, type: 'keep' },
    { label: '+0.5 to +1.0', count: 600, pct: 6.1, type: 'keep' },
    { label: '+1.0 to +2.0', count: 490, pct: 5.0, type: 'downweight' },
    { label: '+2.0 to +3.0', count: 490, pct: 5.0, type: 'downweight' },
    { label: '+3.0 to +5.0', count: 320, pct: 3.3, type: 'quarantine' },
    { label: '> +5.0', count: 170, pct: 1.7, type: 'quarantine' },
  ];

  const maxCount = Math.max(...bins.map((b) => b.count));

  return (
    <div className="glass-panel" style={{ padding: 20 }}>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 16,
        }}
      >
        <div>
          <div style={{ fontSize: '0.95rem', fontWeight: 600, color: '#FFFFFF' }}>
            Suspicion Score Distribution (Robust MAD Normalized)
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 2 }}>
            Empirical histogram of combined trajectory scores across 9,800 CIFAR-10 training samples.
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: '0.725rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: 'var(--emerald-400)' }} />
            <span style={{ color: 'var(--text-secondary)' }}>Keep (w=1.0)</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: 'var(--amber-400)' }} />
            <span style={{ color: 'var(--text-secondary)' }}>Downweight (w=0.2)</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: 'var(--rose-400)' }} />
            <span style={{ color: 'var(--text-secondary)' }}>Quarantine (w=0.0)</span>
          </div>
        </div>
      </div>

      {/* Bar Chart Container */}
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-end',
          gap: 8,
          height: 150,
          paddingTop: 16,
          borderBottom: '1px solid var(--border-subtle)',
        }}
      >
        {bins.map((bin, i) => {
          const heightPct = Math.round((bin.count / maxCount) * 100);
          const color =
            bin.type === 'quarantine'
              ? 'var(--rose-400)'
              : bin.type === 'downweight'
              ? 'var(--amber-400)'
              : 'var(--emerald-400)';

          return (
            <div
              key={i}
              style={{
                flex: 1,
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                height: '100%',
                justifyContent: 'flex-end',
              }}
              title={`${bin.label}: ${bin.count.toLocaleString()} samples (${bin.pct}%)`}
            >
              <span
                style={{
                  fontSize: '0.65rem',
                  color: 'var(--text-muted)',
                  fontFamily: 'var(--font-mono)',
                  marginBottom: 4,
                }}
              >
                {bin.pct}%
              </span>
              <div
                style={{
                  width: '100%',
                  height: `${heightPct}%`,
                  background: color,
                  borderRadius: '3px 3px 0 0',
                  opacity: bin.type === 'keep' ? 0.65 : 0.95,
                  boxShadow:
                    bin.type === 'quarantine'
                      ? '0 0 10px rgba(244, 63, 94, 0.4)'
                      : bin.type === 'downweight'
                      ? '0 0 10px rgba(245, 158, 11, 0.3)'
                      : 'none',
                  transition: 'height 0.6s ease',
                }}
              />
            </div>
          );
        })}
      </div>

      {/* X-Axis labels */}
      <div
        style={{
          display: 'flex',
          gap: 8,
          marginTop: 8,
        }}
      >
        {bins.map((bin, i) => (
          <div
            key={i}
            style={{
              flex: 1,
              textAlign: 'center',
              fontSize: '0.65rem',
              color: 'var(--text-muted)',
              fontFamily: 'var(--font-mono)',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            {bin.label}
          </div>
        ))}
      </div>
    </div>
  );
};
