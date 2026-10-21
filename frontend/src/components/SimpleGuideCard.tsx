import React, { useState } from 'react';
import { HelpCircle, ChevronDown, ChevronUp, Lightbulb, CheckCircle2, Info } from 'lucide-react';

export interface GuideStep {
  step: number | string;
  title: string;
  description: string;
}

interface SimpleGuideCardProps {
  title: string;
  badge?: string;
  summary: string;
  steps: GuideStep[];
  takeaway?: string;
  accentColor?: 'cyan' | 'emerald' | 'amber' | 'violet' | 'rose';
  defaultExpanded?: boolean;
}

export const SimpleGuideCard: React.FC<SimpleGuideCardProps> = ({
  title,
  badge = 'PLAIN ENGLISH GUIDE',
  summary,
  steps,
  takeaway,
  accentColor = 'cyan',
  defaultExpanded = true,
}) => {
  const [isExpanded, setIsExpanded] = useState<boolean>(defaultExpanded);

  const colorMap = {
    cyan: {
      border: 'rgba(6, 182, 212, 0.3)',
      bg: 'rgba(6, 182, 212, 0.05)',
      badgeBg: 'rgba(6, 182, 212, 0.15)',
      badgeText: 'var(--cyan-400)',
      accent: 'var(--cyan-400)',
    },
    emerald: {
      border: 'rgba(16, 185, 129, 0.3)',
      bg: 'rgba(16, 185, 129, 0.05)',
      badgeBg: 'rgba(16, 185, 129, 0.15)',
      badgeText: 'var(--emerald-400)',
      accent: 'var(--emerald-400)',
    },
    amber: {
      border: 'rgba(245, 158, 11, 0.3)',
      bg: 'rgba(245, 158, 11, 0.05)',
      badgeBg: 'rgba(245, 158, 11, 0.15)',
      badgeText: 'var(--amber-400)',
      accent: 'var(--amber-400)',
    },
    violet: {
      border: 'rgba(139, 92, 246, 0.3)',
      bg: 'rgba(139, 92, 246, 0.05)',
      badgeBg: 'rgba(139, 92, 246, 0.15)',
      badgeText: 'var(--violet-400)',
      accent: 'var(--violet-400)',
    },
    rose: {
      border: 'rgba(244, 63, 94, 0.3)',
      bg: 'rgba(244, 63, 94, 0.05)',
      badgeBg: 'rgba(244, 63, 94, 0.15)',
      badgeText: 'var(--rose-400)',
      accent: 'var(--rose-400)',
    },
  };

  const scheme = colorMap[accentColor];

  return (
    <div
      className="glass-panel"
      style={{
        border: `1px solid ${scheme.border}`,
        background: `linear-gradient(135deg, ${scheme.bg} 0%, rgba(10, 16, 29, 0.6) 100%)`,
        padding: '16px 20px',
        borderRadius: 12,
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.25)',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Top Header Row */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          cursor: 'pointer',
          userSelect: 'none',
        }}
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <div
            style={{
              padding: '6px 10px',
              borderRadius: 6,
              background: scheme.badgeBg,
              color: scheme.badgeText,
              fontSize: '0.7rem',
              fontWeight: 700,
              letterSpacing: '0.05em',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <Lightbulb size={13} />
            <span>{badge}</span>
          </div>

          <h3 style={{ fontSize: '1rem', fontWeight: 600, color: '#FFFFFF', margin: 0 }}>
            {title}
          </h3>
        </div>

        <button
          className="btn-ghost"
          style={{
            padding: '4px 8px',
            fontSize: '0.75rem',
            color: 'var(--text-secondary)',
            display: 'flex',
            alignItems: 'center',
            gap: 4,
          }}
          aria-label={isExpanded ? 'Collapse explanation' : 'Expand explanation'}
        >
          <span>{isExpanded ? 'Hide Guide' : 'Show Simple Guide'}</span>
          {isExpanded ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
        </button>
      </div>

      {/* Summary */}
      <p
        style={{
          fontSize: '0.85rem',
          color: '#E2E8F0',
          lineHeight: 1.55,
          marginTop: 10,
          marginBottom: isExpanded ? 16 : 0,
        }}
      >
        {summary}
      </p>

      {/* Expanded Step-by-Step Walkthrough */}
      {isExpanded && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Steps Grid */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: `repeat(auto-fit, minmax(240px, 1fr))`,
              gap: 12,
            }}
          >
            {steps.map((s, idx) => (
              <div
                key={idx}
                style={{
                  background: 'rgba(10, 16, 29, 0.8)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 8,
                  padding: '12px 14px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 6,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span
                    style={{
                      width: 22,
                      height: 22,
                      borderRadius: '50%',
                      background: scheme.badgeBg,
                      color: scheme.badgeText,
                      fontSize: '0.725rem',
                      fontWeight: 700,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontFamily: 'var(--font-mono)',
                    }}
                  >
                    {s.step}
                  </span>
                  <strong style={{ fontSize: '0.825rem', color: '#FFFFFF' }}>{s.title}</strong>
                </div>
                <p style={{ fontSize: '0.775rem', color: 'var(--text-secondary)', lineHeight: 1.45, margin: 0 }}>
                  {s.description}
                </p>
              </div>
            ))}
          </div>

          {/* Key Takeaway Banner */}
          {takeaway && (
            <div
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: 10,
                background: 'rgba(16, 185, 129, 0.08)',
                border: '1px solid rgba(16, 185, 129, 0.25)',
                borderRadius: 8,
                padding: '10px 14px',
                fontSize: '0.8rem',
                color: 'var(--emerald-400)',
              }}
            >
              <CheckCircle2 size={16} style={{ marginTop: 2, flexShrink: 0 }} />
              <div>
                <strong style={{ color: '#FFFFFF', marginRight: 6 }}>Key Takeaway for Non-Experts:</strong>
                <span style={{ color: '#D1FAE5' }}>{takeaway}</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

interface PlainEnglishBoxProps {
  question: string;
  explanation: string;
  simpleIcon?: 'bulb' | 'info' | 'shield';
}

export const PlainEnglishBox: React.FC<PlainEnglishBoxProps> = ({
  question,
  explanation,
  simpleIcon = 'bulb',
}) => {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: 10,
        padding: '10px 14px',
        borderRadius: 8,
        background: 'rgba(6, 182, 212, 0.06)',
        border: '1px solid rgba(6, 182, 212, 0.2)',
        fontSize: '0.8rem',
        marginTop: 8,
        marginBottom: 8,
      }}
    >
      <Lightbulb size={16} style={{ color: 'var(--cyan-400)', marginTop: 2, flexShrink: 0 }} />
      <div style={{ lineHeight: 1.5 }}>
        <span style={{ fontWeight: 600, color: 'var(--cyan-400)', marginRight: 6 }}>
          In Simple Terms ({question}):
        </span>
        <span style={{ color: '#CBD5E1' }}>{explanation}</span>
      </div>
    </div>
  );
};

