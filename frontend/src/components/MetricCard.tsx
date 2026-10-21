import React from 'react';
import { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  label: string;
  value: string | number;
  subtext?: string;
  icon: LucideIcon;
  variant?: 'cyan' | 'violet' | 'emerald' | 'amber' | 'rose';
  badge?: string;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  subtext,
  icon: Icon,
  variant = 'cyan',
  badge,
}) => {
  const variantStyles = {
    cyan: {
      color: 'var(--cyan-400)',
      bg: 'rgba(6, 182, 212, 0.1)',
      border: 'rgba(6, 182, 212, 0.25)',
      glow: '0 0 20px rgba(6, 182, 212, 0.15)',
    },
    violet: {
      color: 'var(--violet-400)',
      bg: 'rgba(139, 92, 246, 0.1)',
      border: 'rgba(139, 92, 246, 0.25)',
      glow: '0 0 20px rgba(139, 92, 246, 0.15)',
    },
    emerald: {
      color: 'var(--emerald-400)',
      bg: 'rgba(16, 185, 129, 0.1)',
      border: 'rgba(16, 185, 129, 0.25)',
      glow: '0 0 20px rgba(16, 185, 129, 0.15)',
    },
    amber: {
      color: 'var(--amber-400)',
      bg: 'rgba(245, 158, 11, 0.1)',
      border: 'rgba(245, 158, 11, 0.25)',
      glow: '0 0 20px rgba(245, 158, 11, 0.15)',
    },
    rose: {
      color: 'var(--rose-400)',
      bg: 'rgba(244, 63, 94, 0.1)',
      border: 'rgba(244, 63, 94, 0.25)',
      glow: '0 0 20px rgba(244, 63, 94, 0.15)',
    },
  }[variant];

  return (
    <div
      className="glass-panel metric-card"
      style={{
        boxShadow: variantStyles.glow,
      }}
    >
      <div className="metric-header">
        <span className="metric-label">{label}</span>
        <div
          className="metric-icon-wrap"
          style={{
            background: variantStyles.bg,
            border: `1px solid ${variantStyles.border}`,
            color: variantStyles.color,
          }}
        >
          <Icon size={18} />
        </div>
      </div>

      <div className="metric-value">{value}</div>

      <div className="metric-subtext">
        {badge && (
          <span
            className="mono-tag"
            style={{
              background: variantStyles.bg,
              color: variantStyles.color,
              border: `1px solid ${variantStyles.border}`,
            }}
          >
            {badge}
          </span>
        )}
        <span>{subtext}</span>
      </div>
    </div>
  );
};
