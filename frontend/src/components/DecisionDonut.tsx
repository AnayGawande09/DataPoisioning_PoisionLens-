import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react';

interface DecisionDonutProps {
  keepCount?: number;
  downweightCount?: number;
  quarantineCount?: number;
  total?: number;
}

export const DecisionDonut: React.FC<DecisionDonutProps> = ({
  keepCount = 8330,
  downweightCount = 980,
  quarantineCount = 490,
  total = 9800,
}) => {
  const keepPct = Math.round((keepCount / total) * 100);
  const downPct = Math.round((downweightCount / total) * 100);
  const quarPct = Math.round((quarantineCount / total) * 100);

  // SVG circular arc calculations
  // Circumference = 2 * PI * 40 = 251.32
  const c = 251.32;
  const keepDash = (keepCount / total) * c;
  const downDash = (downweightCount / total) * c;
  const quarDash = (quarantineCount / total) * c;

  return (
    <div className="glass-panel" style={{ padding: 20 }}>
      <div style={{ marginBottom: 16 }}>
        <div style={{ fontSize: '0.95rem', fontWeight: 600, color: '#FFFFFF' }}>
          Mitigation Decision Tiers
        </div>
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 2 }}>
          3-Tier Soft Quarantine policy applied to training samples.
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-around', gap: 20 }}>
        {/* SVG Donut */}
        <div style={{ position: 'relative', width: 120, height: 120 }}>
          <svg width="120" height="120" viewBox="0 0 100 100" style={{ transform: 'rotate(-90deg)' }}>
            {/* Background ring */}
            <circle cx="50" cy="50" r="40" fill="transparent" stroke="rgba(255,255,255,0.05)" strokeWidth="12" />

            {/* Keep Segment */}
            <circle
              cx="50"
              cy="50"
              r="40"
              fill="transparent"
              stroke="var(--emerald-400)"
              strokeWidth="12"
              strokeDasharray={`${keepDash} ${c - keepDash}`}
              strokeDashoffset="0"
            />

            {/* Downweight Segment */}
            <circle
              cx="50"
              cy="50"
              r="40"
              fill="transparent"
              stroke="var(--amber-400)"
              strokeWidth="12"
              strokeDasharray={`${downDash} ${c - downDash}`}
              strokeDashoffset={`-${keepDash}`}
            />

            {/* Quarantine Segment */}
            <circle
              cx="50"
              cy="50"
              r="40"
              fill="transparent"
              stroke="var(--rose-400)"
              strokeWidth="12"
              strokeDasharray={`${quarDash} ${c - quarDash}`}
              strokeDashoffset={`-${keepDash + downDash}`}
            />
          </svg>

          {/* Center text */}
          <div
            style={{
              position: 'absolute',
              top: '50%',
              left: '50%',
              transform: 'translate(-50%, -50%)',
              textAlign: 'center',
            }}
          >
            <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#FFFFFF', fontFamily: 'var(--font-mono)' }}>
              {total.toLocaleString()}
            </div>
            <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              Samples
            </div>
          </div>
        </div>

        {/* Legend */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <ShieldCheck size={16} style={{ color: 'var(--emerald-400)' }} />
              <div>
                <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#FFFFFF' }}>Keep (w = 1.0)</div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Unperturbed normal samples</div>
              </div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--emerald-400)', fontFamily: 'var(--font-mono)' }}>
                {keepCount.toLocaleString()}
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{keepPct}%</div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <AlertTriangle size={16} style={{ color: 'var(--amber-400)' }} />
              <div>
                <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#FFFFFF' }}>Downweight (w = 0.20)</div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Borderline / noisy samples</div>
              </div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--amber-400)', fontFamily: 'var(--font-mono)' }}>
                {downweightCount.toLocaleString()}
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{downPct}%</div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <ShieldAlert size={16} style={{ color: 'var(--rose-400)' }} />
              <div>
                <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#FFFFFF' }}>Quarantine (w = 0.0)</div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>High anomaly poison candidates</div>
              </div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--rose-400)', fontFamily: 'var(--font-mono)' }}>
                {quarantineCount.toLocaleString()}
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{quarPct}%</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
