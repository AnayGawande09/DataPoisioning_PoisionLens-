import React from 'react';
import { Award, Info, RefreshCw, Zap } from 'lucide-react';

interface DemoBannerProps {
  isDemoMode: boolean;
  onToggleDemoMode: () => void;
  onResetDemo: () => void;
}

export const DemoBanner: React.FC<DemoBannerProps> = ({
  isDemoMode,
  onToggleDemoMode,
  onResetDemo,
}) => {
  if (!isDemoMode) {
    return null;
  }

  return (
    <div className="demo-banner">
      <div className="demo-banner-left">
        <span className="demo-badge">
          <Award size={12} style={{ display: 'inline', marginRight: 4 }} />
          Judge Demo Mode Active
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Info size={14} style={{ color: '#FBBF24' }} />
          Replaying authentic empirical benchmarks from SmallResNet CIFAR-10 experiments (Phases 1–6). No GPU or training delay required.
        </span>
      </div>

      <div className="demo-banner-right">
        <button
          onClick={onResetDemo}
          className="btn-ghost"
          style={{
            fontSize: '0.725rem',
            padding: '3px 10px',
            background: 'rgba(255, 255, 255, 0.08)',
            color: '#FDE68A',
            border: '1px solid rgba(245, 158, 11, 0.4)',
          }}
          title="Restore demo dataset to initial benchmark state"
        >
          <RefreshCw size={12} />
          <span>Reset Demo</span>
        </button>

        <button
          onClick={onToggleDemoMode}
          className="btn-ghost"
          style={{
            fontSize: '0.725rem',
            padding: '3px 10px',
            background: 'rgba(6, 182, 212, 0.15)',
            color: '#22D3EE',
            border: '1px solid rgba(6, 182, 212, 0.4)',
          }}
        >
          <Zap size={12} />
          <span>Connect Live FastAPI</span>
        </button>
      </div>
    </div>
  );
};
