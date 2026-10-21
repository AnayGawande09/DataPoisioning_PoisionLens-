import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { DemoBanner } from './components/DemoBanner';
import { OverviewPage } from './pages/OverviewPage';
import { NewExperimentPage } from './pages/NewExperimentPage';
import { ProgressPage } from './pages/ProgressPage';
import { ResultsPage } from './pages/ResultsPage';
import { SampleExplorerPage } from './pages/SampleExplorerPage';
import { AuditPage } from './pages/AuditPage';
import { ComparisonPage } from './pages/ComparisonPage';
import { MethodologyPage } from './pages/MethodologyPage';
import { api } from './services/api';
import './App.css';

export function App() {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [selectedRunId, setSelectedRunId] = useState<string>('attack_badnets_5');
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [isDemoMode, setIsDemoMode] = useState<boolean>(api.isDemoMode());

  useEffect(() => {
    const unsub = api.subscribeDemoMode((mode) => {
      setIsDemoMode(mode);
    });
    return unsub;
  }, []);

  const handleToggleDemoMode = () => {
    api.setDemoMode(!isDemoMode);
  };

  const handleResetDemo = () => {
    api.resetDemoData();
    window.location.reload();
  };

  const handleNavigate = (tab: string, runId?: string) => {
    if (runId) {
      setSelectedRunId(runId);
    }
    setActiveTab(tab);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleStartExperiment = (jobId: string, runId: string) => {
    setActiveJobId(jobId);
    setSelectedRunId(runId);
    setActiveTab('progress');
  };

  const handleViewResults = (runId: string) => {
    setSelectedRunId(runId);
    setActiveTab('results');
  };

  return (
    <div className="app-root">
      {/* Top Navbar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        isDemoMode={isDemoMode}
        onToggleDemoMode={handleToggleDemoMode}
      />

      {/* Judge Demo Banner */}
      <DemoBanner
        isDemoMode={isDemoMode}
        onToggleDemoMode={handleToggleDemoMode}
        onResetDemo={handleResetDemo}
      />

      {/* Main Content Area */}
      <main className="main-content">
        {activeTab === 'overview' && <OverviewPage onNavigate={handleNavigate} />}

        {activeTab === 'new_experiment' && (
          <NewExperimentPage onStartExperiment={handleStartExperiment} />
        )}

        {activeTab === 'progress' && (
          <ProgressPage
            jobId={activeJobId}
            runId={selectedRunId}
            onViewResults={handleViewResults}
          />
        )}

        {activeTab === 'results' && (
          <ResultsPage initialRunId={selectedRunId} onNavigate={handleNavigate} />
        )}

        {activeTab === 'samples' && (
          <SampleExplorerPage initialRunId={selectedRunId} />
        )}

        {activeTab === 'audit' && (
          <AuditPage initialRunId={selectedRunId} />
        )}

        {activeTab === 'comparison' && <ComparisonPage />}

        {activeTab === 'methodology' && <MethodologyPage />}
      </main>

      {/* Security Operations Center Footer */}
      <footer
        style={{
          borderTop: '1px solid var(--border-subtle)',
          background: 'rgba(7, 11, 20, 0.95)',
          padding: '20px 32px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          fontSize: '0.75rem',
          color: 'var(--text-muted)',
          flexWrap: 'wrap',
          gap: 12,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontWeight: 600, color: '#FFF' }}>PoisonLens v0.1.0</span>
          <span>&bull;</span>
          <span>SmallResNet / CIFAR-10 ML Security Research Framework</span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <span>SHA-256 Provenance Proofs</span>
          <span>&bull;</span>
          <span>Clean Canary Guardrail (3.0% Tolerance)</span>
          <span>&bull;</span>
          <span style={{ color: isDemoMode ? '#FBBF24' : 'var(--emerald-400)', fontFamily: 'var(--font-mono)' }}>
            Mode: {isDemoMode ? 'JUDGE DEMO' : 'LIVE API'}
          </span>
        </div>
      </footer>
    </div>
  );
}

export default App;
