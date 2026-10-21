import React, { useEffect, useState, useRef } from 'react';
import {
  Play,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Terminal,
  ArrowRight,
  ShieldAlert,
  RotateCcw,
  Cpu,
  Layers,
} from 'lucide-react';
import { SimpleGuideCard, PlainEnglishBox } from '../components/SimpleGuideCard';
import { api } from '../services/api';
import { JobState } from '../types';

interface ProgressPageProps {
  jobId: string | null;
  runId: string | null;
  onViewResults: (runId: string) => void;
}

export const ProgressPage: React.FC<ProgressPageProps> = ({ jobId, runId, onViewResults }) => {
  const [jobState, setJobState] = useState<JobState | null>(null);
  const [elapsed, setElapsed] = useState<number>(0);
  const logContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let mounted = true;
    const effectiveJobId = jobId || 'job_demo_active';

    const poll = async () => {
      try {
        const state = await api.getJobStatus(effectiveJobId);
        if (mounted) {
          setJobState(state);
          setElapsed(state.elapsed_seconds);
        }
      } catch (e) {
        // Fallback demo state
      }
    };

    poll();
    const interval = setInterval(poll, 2000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, [jobId]);

  // Autoscroll terminal logs
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [jobState?.logs]);

  const stages = [
    { num: 1, name: 'Dataset Preparation & Controlled Attack' },
    { num: 2, name: 'Model Training & Dynamics Collection' },
    { num: 3, name: 'Trajectory Fingerprint Scoring' },
    { num: 4, name: 'Soft Quarantine Tier Assignment' },
    { num: 5, name: 'Retraining & Canary Health Guardrail' },
    { num: 6, name: 'Final Evaluation & Cryptographic Audit Log' },
  ];

  const currentStageNum = jobState?.stage_number || 1;
  const isFinished = jobState?.status === 'COMPLETED';
  const isFailed = jobState?.status === 'FAILED';

  const formatElapsed = (sec: number) => {
    const mins = Math.floor(sec / 60);
    const s = Math.floor(sec % 60);
    return `${mins}m ${s < 10 ? '0' : ''}${s}s`;
  };

  return (
    <div style={{ maxWidth: 1080, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <Play size={26} style={{ color: 'var(--cyan-400)' }} />
            <span>Experiment Execution Progress</span>
          </h1>
          <p className="page-description">
            Live pipeline execution tracker. Recording per-sample training dynamics, running robust MAD trajectory scoring, evaluating clean canary health, and generating cryptographic audit hashes.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div
            style={{
              padding: '6px 12px',
              borderRadius: 8,
              background: 'rgba(10, 16, 29, 0.8)',
              border: '1px solid var(--border-subtle)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.8rem',
              display: 'flex',
              alignItems: 'center',
              gap: 8,
            }}
          >
            <Clock size={14} style={{ color: 'var(--cyan-400)' }} />
            <span>Elapsed: {formatElapsed(elapsed)}</span>
          </div>

          {isFinished && (
            <button
              className="btn-cyan"
              onClick={() => onViewResults(jobState?.run_id || runId || 'attack_badnets_5')}
            >
              <span>View Full Results</span>
              <ArrowRight size={15} />
            </button>
          )}
        </div>
      </div>

      {/* Tab-Level Plain-English Guide */}
      <SimpleGuideCard
        title="Live Progress: What is Happening Right Now?"
        summary="Your experiment is actively running in the background. The server is training an AI model, watching which training samples cause abnormal learning spikes, quarantining suspicious data, and retraining a fresh, safe model."
        steps={[
          {
            step: '1',
            title: 'Stage 1: Attack Prep',
            description: 'Injects the selected attack (like a 3x3 white sticker or swapped labels) into the training dataset.',
          },
          {
            step: '2',
            title: 'Stage 2: Watch AI Learn',
            description: 'Trains the neural network across 10 epochs while logging loss curves and prediction stability for every image.',
          },
          {
            step: '3',
            title: 'Stage 3: Spotting Suspects',
            description: 'Scores each image on 5 dynamic signals (forgetting events, loss volatility, feature neighbor disagreement).',
          },
          {
            step: '4',
            title: 'Stage 4: Soft Quarantine',
            description: 'Marks the top 5% most suspicious images for full quarantine (w=0.0) and borderline images for downweighting (w=0.20).',
          },
          {
            step: '5',
            title: 'Stage 5: Retraining & Canary',
            description: 'Retrains a clean model with sanitized weights and checks test accuracy against clean canary images.',
          },
          {
            step: '6',
            title: 'Stage 6: Digital Seal',
            description: 'Computes cryptographic SHA-256 hash chains for all decisions so nobody can tamper with the log.',
          },
        ]}
        takeaway="You do not need to refresh the page. The status and terminal logs stream automatically every 2 seconds."
        accentColor="cyan"
      />

      {/* Completion Banner */}
      {isFinished && (
        <div
          style={{
            padding: '16px 20px',
            borderRadius: 10,
            background: 'rgba(16, 185, 129, 0.12)',
            border: '1px solid rgba(16, 185, 129, 0.35)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <CheckCircle2 size={24} style={{ color: 'var(--emerald-400)' }} />
            <div>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#FFFFFF' }}>
                Experiment Completed Successfully
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                All 6 pipeline stages finished. Model retrained, canary guardrail evaluated, and audit log verified.
              </div>
            </div>
          </div>

          <button
            className="btn-cyan"
            onClick={() => onViewResults(jobState?.run_id || runId || 'attack_badnets_5')}
          >
            <span>Inspect Results & Metrics</span>
            <ArrowRight size={15} />
          </button>
        </div>
      )}

      {/* Section Explainer for Stages */}
      <PlainEnglishBox
        question="What does the Stage Tracker show?"
        explanation="It highlights which of the 6 defense steps is currently executing. Once all circles light up green, your experiment is complete and you can inspect the final results."
      />

      {/* 6-Stage Progress Tracker Card */}
      <div className="glass-panel" style={{ padding: 20 }}>
        <div style={{ fontSize: '0.875rem', fontWeight: 600, color: '#FFFFFF', marginBottom: 16 }}>
          Pipeline Stage Progress
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12 }}>
          {stages.map((st) => {
            const isCompleted = isFinished || currentStageNum > st.num;
            const isCurrent = !isFinished && currentStageNum === st.num;

            return (
              <div
                key={st.num}
                style={{
                  padding: '12px 14px',
                  borderRadius: 8,
                  background: isCurrent
                    ? 'rgba(6, 182, 212, 0.12)'
                    : isCompleted
                    ? 'rgba(16, 185, 129, 0.08)'
                    : 'rgba(10, 16, 29, 0.5)',
                  border: `1px solid ${
                    isCurrent
                      ? 'var(--cyan-400)'
                      : isCompleted
                      ? 'rgba(16, 185, 129, 0.3)'
                      : 'var(--border-subtle)'
                  }`,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                }}
              >
                <div
                  style={{
                    width: 26,
                    height: 26,
                    borderRadius: '50%',
                    background: isCurrent
                      ? 'var(--cyan-500)'
                      : isCompleted
                      ? 'var(--emerald-500)'
                      : 'rgba(255, 255, 255, 0.1)',
                    color: isCurrent || isCompleted ? '#000' : 'var(--text-muted)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontWeight: 700,
                    fontSize: '0.75rem',
                  }}
                >
                  {isCompleted ? <CheckCircle2 size={16} /> : st.num}
                </div>

                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: '0.8rem', fontWeight: 600, color: isCurrent ? 'var(--cyan-400)' : '#FFF' }}>
                    Stage {st.num}: {st.name}
                  </div>
                  <div style={{ fontSize: '0.675rem', color: 'var(--text-muted)' }}>
                    {isCompleted ? 'Completed' : isCurrent ? 'Currently Running...' : 'Pending'}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Real-time Terminal Log Streamer */}
      <PlainEnglishBox
        question="What are these terminal logs?"
        explanation="This is the live console output from the Python backend ('python -m poisonlens.pipeline'). It prints real training losses, batch evaluations, and cryptographic audit confirmations line by line as the experiment progresses."
      />
      <div className="terminal-window">
        <div className="terminal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Terminal size={14} style={{ color: 'var(--cyan-400)' }} />
            <span>POISONLENS PIPELINE CONSOLE OUTPUT</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.7rem' }}>
            <span className="pulse-dot online" />
            <span>STREAMING</span>
          </div>
        </div>

        <div className="terminal-logs" ref={logContainerRef}>
          {jobState?.logs && jobState.logs.length > 0 ? (
            jobState.logs.map((log, idx) => (
              <div key={idx} className="terminal-line">
                <span className="t-time">[{log.time}]</span>
                <span>{log.message}</span>
              </div>
            ))
          ) : (
            <div className="terminal-line" style={{ color: 'var(--text-muted)' }}>
              Connecting to execution logger...
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
