import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Activity,
  PlusCircle,
  BarChart3,
  Search,
  Lock,
  GitCompare,
  BookOpen,
  Play,
  RotateCcw,
} from 'lucide-react';
import { api } from '../services/api';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  isDemoMode: boolean;
  onToggleDemoMode: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  isDemoMode,
  onToggleDemoMode,
}) => {
  const [backendOnline, setBackendOnline] = useState<boolean>(false);

  useEffect(() => {
    let mounted = true;
    const check = async () => {
      const res = await api.checkHealth();
      if (mounted) setBackendOnline(res.online);
    };
    check();
    const interval = setInterval(check, 10000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const navItems = [
    { id: 'overview', label: 'Dashboard', sublabel: 'System Overview', icon: Activity },
    { id: 'new_experiment', label: 'New Experiment', sublabel: 'Test an Attack', icon: PlusCircle },
    { id: 'progress', label: 'Live Progress', sublabel: 'Watch AI Learn', icon: Play },
    { id: 'results', label: 'Results & Guardrail', sublabel: 'Defense Scorecard', icon: BarChart3 },
    { id: 'samples', label: 'Sample Explorer', sublabel: 'Inspect Images', icon: Search },
    { id: 'audit', label: 'Cryptographic Audit', sublabel: 'Tamper-Proof Log', icon: Lock },
    { id: 'comparison', label: 'Model Benchmarks', sublabel: 'Defense Scoreboard', icon: GitCompare },
    { id: 'methodology', label: 'Methodology', sublabel: 'Plain-English Guide', icon: BookOpen },
  ];

  return (
    <header className="top-navbar" style={{ height: 'auto', minHeight: 68, padding: '8px 20px' }}>
      <div className="nav-brand" onClick={() => setActiveTab('overview')}>
        <div className="brand-icon">
          <ShieldAlert size={20} />
        </div>
        <div>
          <div className="brand-title">POISONLENS</div>
          <div className="brand-subtitle">AI Training Data Security & Cryptographic Audit</div>
        </div>
      </div>

      <nav className="nav-links" style={{ flexWrap: 'wrap', gap: 4 }}>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              className={`nav-item ${isActive ? 'active' : ''}`}
              onClick={() => setActiveTab(item.id)}
              style={{
                padding: '6px 10px',
                textAlign: 'left',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
              }}
              title={`${item.label}: ${item.sublabel}`}
            >
              <Icon size={16} style={{ flexShrink: 0 }} />
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', lineHeight: 1.15 }}>
                <span style={{ fontSize: '0.785rem', fontWeight: isActive ? 700 : 600 }}>{item.label}</span>
                <span
                  style={{
                    fontSize: '0.635rem',
                    color: isActive ? 'var(--cyan-400)' : 'var(--text-muted)',
                    letterSpacing: '0.01em',
                  }}
                >
                  {item.sublabel}
                </span>
              </div>
            </button>
          );
        })}
      </nav>


      <div className="nav-actions">
        {/* Connection status badge */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            fontSize: '0.75rem',
            padding: '4px 10px',
            borderRadius: '9999px',
            background: isDemoMode
              ? 'rgba(245, 158, 11, 0.12)'
              : backendOnline
              ? 'rgba(16, 185, 129, 0.12)'
              : 'rgba(244, 63, 94, 0.12)',
            border: `1px solid ${
              isDemoMode
                ? 'rgba(245, 158, 11, 0.3)'
                : backendOnline
                ? 'rgba(16, 185, 129, 0.3)'
                : 'rgba(244, 63, 94, 0.3)'
            }`,
          }}
          title={
            isDemoMode
              ? 'Judge Demo Mode: Replaying deterministic empirical benchmarks'
              : backendOnline
              ? 'Connected to local FastAPI backend on port 8000'
              : 'FastAPI backend is offline'
          }
        >
          <span
            className={`pulse-dot ${
              isDemoMode ? 'demo' : backendOnline ? 'online' : 'alert'
            }`}
          />
          <span
            style={{
              fontWeight: 600,
              color: isDemoMode
                ? '#FBBF24'
                : backendOnline
                ? '#34D399'
                : '#FB7185',
              fontFamily: 'var(--font-mono)',
            }}
          >
            {isDemoMode
              ? 'DEMO MODE'
              : backendOnline
              ? 'LIVE BACKEND'
              : 'BACKEND OFFLINE'}
          </span>
        </div>

        {/* Mode Toggle Button */}
        <button
          className={isDemoMode ? 'btn-ghost' : 'btn-outline-cyan'}
          onClick={onToggleDemoMode}
          style={{ fontSize: '0.775rem', padding: '6px 12px' }}
        >
          <RotateCcw size={13} />
          <span>{isDemoMode ? 'Switch to Live API' : 'Switch to Demo Mode'}</span>
        </button>

        {/* Launch Experiment Button */}
        <button
          className="btn-cyan"
          onClick={() => setActiveTab('new_experiment')}
          style={{ fontSize: '0.8rem', padding: '7px 14px' }}
        >
          <PlusCircle size={15} />
          <span>New Experiment</span>
        </button>
      </div>
    </header>
  );
};
