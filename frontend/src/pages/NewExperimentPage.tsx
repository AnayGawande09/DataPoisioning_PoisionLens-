import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Sliders,
  CheckCircle2,
  Lock,
  ArrowRight,
  AlertTriangle,
  Play,
  RotateCcw,
  Sparkles,
} from 'lucide-react';
import { SimpleGuideCard, PlainEnglishBox } from '../components/SimpleGuideCard';
import { api } from '../services/api';
import { Preset } from '../types';

interface NewExperimentPageProps {
  onStartExperiment: (jobId: string, runId: string) => void;
}

export const NewExperimentPage: React.FC<NewExperimentPageProps> = ({ onStartExperiment }) => {
  const [presets, setPresets] = useState<Preset[]>([]);
  const [selectedPresetId, setSelectedPresetId] = useState<string>('attack_badnets_5');
  const [currentStep, setCurrentStep] = useState<number>(1);
  const [seed, setSeed] = useState<number>(42);
  const [epochs, setEpochs] = useState<number>(10);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    api.getPresets().then((p) => {
      if (mounted) setPresets(p);
    });
    return () => {
      mounted = false;
    };
  }, []);

  const selectedPreset = presets.find((p) => p.id === selectedPresetId) || presets[0];

  const handleLaunch = async () => {
    setIsSubmitting(true);
    setErrorMessage(null);
    try {
      const job = await api.startExperiment(selectedPresetId, {
        seed: Number(seed),
        epochs: Number(epochs),
      });
      onStartExperiment(job.job_id, job.run_id);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to start experiment. Please check backend connection.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div style={{ maxWidth: 1000, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <Sliders size={26} style={{ color: 'var(--cyan-400)' }} />
            <span>Configure PoisonLens Experiment</span>
          </h1>
          <p className="page-description">
            Select an attack simulation preset from the existing research framework. All experiments run on deterministic stratified CIFAR-10 subsets with SmallResNet.
          </p>
        </div>
      </div>

      {/* Tab-Level Plain-English Guide */}
      <SimpleGuideCard
        title="New Experiment: How to Run an Attack Test"
        summary="Use this wizard to launch a real or simulated security test on our AI model. You choose how the attacker tries to sabotage the training data (e.g. sneaky backdoor stickers or swapped labels), review the settings, and start the experiment."
        steps={[
          {
            step: '1',
            title: 'Pick an Attack Preset',
            description: 'Choose a known attack type: BadNets (hidden white patch), Label Flip (corrupted labels), or Blended (ghost noise).',
          },
          {
            step: '2',
            title: 'Check AI Settings',
            description: 'Fixed CIFAR-10 dataset (9,800 images) and SmallResNet model ensure tests finish in 5-8 minutes reliably.',
          },
          {
            step: '3',
            title: '3-Tier Soft Defense',
            description: 'Suspicious data is downweighted (w=0.20) or quarantined (w=0.0) without destroying good images.',
          },
          {
            step: '4',
            title: 'Asynchronous Background Job',
            description: 'Clicking Start launches a background process on the server so you can watch live progress without freezing.',
          },
        ]}
        takeaway="For first-time users, we recommend 'BadNets Backdoor (5%)'. It clearly demonstrates how a tiny 3x3 white square trigger is detected and defused."
        accentColor="cyan"
      />

      {/* Step Indicators */}
      <div
        className="glass-panel"
        style={{
          padding: '14px 20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div
            style={{
              width: 28,
              height: 28,
              borderRadius: '50%',
              background: currentStep >= 1 ? 'var(--cyan-500)' : 'rgba(255, 255, 255, 0.1)',
              color: currentStep >= 1 ? '#000' : 'var(--text-muted)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontWeight: 700,
              fontSize: '0.8rem',
            }}
          >
            1
          </div>
          <span style={{ fontSize: '0.85rem', fontWeight: 600, color: currentStep === 1 ? '#FFF' : 'var(--text-muted)' }}>
            Select Attack Preset
          </span>
        </div>

        <div style={{ width: 40, height: 1, background: 'var(--border-subtle)' }} />

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div
            style={{
              width: 28,
              height: 28,
              borderRadius: '50%',
              background: currentStep >= 2 ? 'var(--cyan-500)' : 'rgba(255, 255, 255, 0.1)',
              color: currentStep >= 2 ? '#000' : 'var(--text-muted)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontWeight: 700,
              fontSize: '0.8rem',
            }}
          >
            2
          </div>
          <span style={{ fontSize: '0.85rem', fontWeight: 600, color: currentStep === 2 ? '#FFF' : 'var(--text-muted)' }}>
            Pipeline Parameters
          </span>
        </div>

        <div style={{ width: 40, height: 1, background: 'var(--border-subtle)' }} />

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div
            style={{
              width: 28,
              height: 28,
              borderRadius: '50%',
              background: currentStep >= 3 ? 'var(--cyan-500)' : 'rgba(255, 255, 255, 0.1)',
              color: currentStep >= 3 ? '#000' : 'var(--text-muted)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontWeight: 700,
              fontSize: '0.8rem',
            }}
          >
            3
          </div>
          <span style={{ fontSize: '0.85rem', fontWeight: 600, color: currentStep === 3 ? '#FFF' : 'var(--text-muted)' }}>
            Review & Launch
          </span>
        </div>
      </div>

      {/* STEP 1: PRESET SELECTION */}
      {currentStep === 1 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <PlainEnglishBox
            question="What are these attack presets?"
            explanation="Each card represents a standardized test scenario. 'BadNets' simulates sneaky backdoor stickers, 'Label Flip' simulates swapped image tags, and 'Clean Baseline' trains on clean data with zero attacks for a fair comparison."
          />

          <div style={{ fontSize: '0.9rem', fontWeight: 600, color: '#FFFFFF' }}>
            Choose a Supported Experiment Configuration
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>

            {presets.map((p) => {
              const isSelected = selectedPresetId === p.id;
              const badgeColors = {
                cyan: { bg: 'rgba(6, 182, 212, 0.15)', text: 'var(--cyan-400)', border: 'rgba(6, 182, 212, 0.3)' },
                violet: { bg: 'rgba(139, 92, 246, 0.15)', text: 'var(--violet-400)', border: 'rgba(139, 92, 246, 0.3)' },
                rose: { bg: 'rgba(244, 63, 94, 0.15)', text: 'var(--rose-400)', border: 'rgba(244, 63, 94, 0.3)' },
                amber: { bg: 'rgba(245, 158, 11, 0.15)', text: 'var(--amber-400)', border: 'rgba(245, 158, 11, 0.3)' },
                emerald: { bg: 'rgba(16, 185, 129, 0.15)', text: 'var(--emerald-400)', border: 'rgba(16, 185, 129, 0.3)' },
              }[p.badge_color] || { bg: 'rgba(255,255,255,0.1)', text: '#FFF', border: 'rgba(255,255,255,0.2)' };

              return (
                <div
                  key={p.id}
                  className="glass-panel"
                  onClick={() => setSelectedPresetId(p.id)}
                  style={{
                    padding: 20,
                    cursor: 'pointer',
                    borderColor: isSelected ? 'var(--cyan-400)' : undefined,
                    boxShadow: isSelected ? '0 0 20px rgba(6, 182, 212, 0.25)' : undefined,
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                  }}
                >
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                      <span
                        className="mono-tag"
                        style={{
                          background: badgeColors.bg,
                          color: badgeColors.text,
                          border: `1px solid ${badgeColors.border}`,
                          fontSize: '0.675rem',
                        }}
                      >
                        {p.threat_level.toUpperCase()} THREAT
                      </span>
                      <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        {p.category}
                      </span>
                    </div>

                    <div style={{ fontSize: '1rem', fontWeight: 700, color: '#FFFFFF', marginBottom: 6 }}>
                      {p.name}
                    </div>

                    <div style={{ fontSize: '0.775rem', color: 'var(--text-secondary)', lineHeight: 1.45, marginBottom: 14 }}>
                      {p.description}
                    </div>
                  </div>

                  <div
                    style={{
                      paddingTop: 12,
                      borderTop: '1px solid var(--border-subtle)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      fontSize: '0.725rem',
                      fontFamily: 'var(--font-mono)',
                    }}
                  >
                    <span style={{ color: 'var(--text-muted)' }}>
                      Poison Rate: <strong style={{ color: '#FFF' }}>{(p.poison_rate * 100).toFixed(0)}%</strong>
                    </span>
                    <span style={{ color: isSelected ? 'var(--cyan-400)' : 'var(--text-muted)' }}>
                      {isSelected ? 'Selected' : 'Click to select'}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 12 }}>
            <button className="btn-cyan" onClick={() => setCurrentStep(2)}>
              <span>Continue to Parameters</span>
              <ArrowRight size={15} />
            </button>
          </div>
        </div>
      )}

      {/* STEP 2: PIPELINE PARAMETERS & READ-ONLY CONSTRAINTS */}
      {currentStep === 2 && selectedPreset && (
        <div className="glass-panel" style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
          <PlainEnglishBox
            question="Why are the dataset and architecture fixed?"
            explanation="CIFAR-10 contains standard 32x32 color images (planes, cars, dogs, horses) and SmallResNet has ~308k parameters. Keeping these fixed ensures reliable benchmark comparison and allows experiments to finish in minutes on regular hardware without crashing."
          />

          <div>
            <div style={{ fontSize: '1.05rem', fontWeight: 600, color: '#FFFFFF' }}>
              Configuration Summary: {selectedPreset.name}
            </div>
            <div style={{ fontSize: '0.775rem', color: 'var(--text-muted)', marginTop: 4 }}>
              PoisonLens operates specifically on CIFAR-10 with SmallResNet. Model architecture and normalization are fixed by research protocol.
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 14 }}>
            {/* Read-only field: Dataset */}
            <div style={{ padding: 12, background: 'rgba(10, 16, 29, 0.7)', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-muted)', fontSize: '0.725rem' }}>
                <span>DATASET</span>
                <span title="Fixed by research pipeline"><Lock size={12} /></span>
              </div>
              <div style={{ fontSize: '0.9rem', fontWeight: 600, color: '#FFF', marginTop: 4 }}>
                CIFAR-10 (32x32 RGB)
              </div>
              <div style={{ fontSize: '0.675rem', color: 'var(--text-muted)', marginTop: 2 }}>
                10,000 stratified train / 2,000 test
              </div>
            </div>

            {/* Read-only field: Model */}
            <div style={{ padding: 12, background: 'rgba(10, 16, 29, 0.7)', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-muted)', fontSize: '0.725rem' }}>
                <span>ARCHITECTURE</span>
                <span title="Fixed by research pipeline"><Lock size={12} /></span>
              </div>
              <div style={{ fontSize: '0.9rem', fontWeight: 600, color: '#FFF', marginTop: 4 }}>
                SmallResNet
              </div>
              <div style={{ fontSize: '0.675rem', color: 'var(--text-muted)', marginTop: 2 }}>
                ~308,000 parameters (3 residual stages)
              </div>
            </div>

            {/* Read-only field: Attack Specification */}
            <div style={{ padding: 12, background: 'rgba(10, 16, 29, 0.7)', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-muted)', fontSize: '0.725rem' }}>
                <span>ATTACK TYPE & RATE</span>
                <Lock size={12} />
              </div>
              <div style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--rose-400)', marginTop: 4 }}>
                {selectedPreset.attack_type.toUpperCase()} ({(selectedPreset.poison_rate * 100).toFixed(0)}%)
              </div>
              <div style={{ fontSize: '0.675rem', color: 'var(--text-muted)', marginTop: 2 }}>
                Target Class: {selectedPreset.target_class !== null && selectedPreset.target_class !== undefined ? selectedPreset.target_class : 'N/A'}
              </div>
            </div>

            {/* Read-only field: Canary Guardrail */}
            <div style={{ padding: 12, background: 'rgba(10, 16, 29, 0.7)', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-muted)', fontSize: '0.725rem' }}>
                <span>CANARY GUARDRAIL</span>
                <Lock size={12} />
              </div>
              <div style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--emerald-400)', marginTop: 4 }}>
                200 Clean Samples
              </div>
              <div style={{ fontSize: '0.675rem', color: 'var(--text-muted)', marginTop: 2 }}>
                Max Accuracy Drop Tolerance: 3.0%
              </div>
            </div>
          </div>

          {/* Editable Parameters */}
          <div style={{ paddingTop: 16, borderTop: '1px solid var(--border-subtle)', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.775rem', fontWeight: 600, color: '#FFFFFF', marginBottom: 6 }}>
                Random Seed (Determinism Guarantee)
              </label>
              <input
                type="number"
                value={seed}
                onChange={(e) => setSeed(Number(e.target.value))}
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 6,
                  color: '#FFF',
                  fontFamily: 'var(--font-mono)',
                }}
              />
              <span style={{ fontSize: '0.675rem', color: 'var(--text-muted)', marginTop: 4, display: 'block' }}>
                Default: 42. Controls reproducible stratified splitting and weight initialization.
              </span>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.775rem', fontWeight: 600, color: '#FFFFFF', marginBottom: 6 }}>
                Training Epochs (Dynamics Recording)
              </label>
              <input
                type="number"
                value={epochs}
                min={2}
                max={20}
                onChange={(e) => setEpochs(Number(e.target.value))}
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 6,
                  color: '#FFF',
                  fontFamily: 'var(--font-mono)',
                }}
              />
              <span style={{ fontSize: '0.675rem', color: 'var(--text-muted)', marginTop: 4, display: 'block' }}>
                Standard benchmark protocol: 10 epochs. Sub-5 minutes total execution.
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 12 }}>
            <button className="btn-ghost" onClick={() => setCurrentStep(1)}>
              Back
            </button>
            <button className="btn-cyan" onClick={() => setCurrentStep(3)}>
              <span>Review Execution Plan</span>
              <ArrowRight size={15} />
            </button>
          </div>
        </div>
      )}

      {/* STEP 3: REVIEW & LAUNCH */}
      {currentStep === 3 && selectedPreset && (
        <div className="glass-panel" style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
          <PlainEnglishBox
            question="What happens when you click Start Experiment?"
            explanation="The backend initiates an asynchronous Python process running 'python -m poisonlens.pipeline'. You will be redirected to the Live Progress page where you can monitor the 6 stages, training loss curves, and terminal log stream in real time."
          />

          <div style={{ fontSize: '1.05rem', fontWeight: 600, color: '#FFFFFF' }}>
            Final Review: Launch Execution Plan
          </div>

          <div
            style={{
              padding: 16,
              background: 'rgba(6, 182, 212, 0.08)',
              border: '1px solid rgba(6, 182, 212, 0.25)',
              borderRadius: 8,
              fontSize: '0.8rem',
              color: 'var(--text-secondary)',
              lineHeight: 1.5,
            }}
          >
            Starting this run will execute the unified 6-stage PoisonLens pipeline:
            <ol style={{ marginLeft: 20, marginTop: 8, display: 'flex', flexDirection: 'column', gap: 4 }}>
              <li>Partition 10,000 CIFAR-10 training samples and inject {selectedPreset.name}.</li>
              <li>Train SmallResNet on CPU, logging sample losses, predictions, and gradients across {epochs} epochs.</li>
              <li>Extract 5 dynamic features and compute robust MAD-normalized anomaly scores.</li>
              <li>Assign 3-tier sample weights (Keep 85%, Downweight 10%, Quarantine 5%).</li>
              <li>Retrain fresh model with weighted loss and test against 200-sample clean canary guardrail.</li>
              <li>Seal all per-sample decisions into an immutable SHA-256 hash-chained JSONL audit log.</li>
            </ol>
          </div>

          {errorMessage && (
            <div
              style={{
                padding: '12px 16px',
                borderRadius: 8,
                background: 'rgba(244, 63, 94, 0.15)',
                border: '1px solid rgba(244, 63, 94, 0.4)',
                color: 'var(--rose-400)',
                fontSize: '0.8rem',
                display: 'flex',
                alignItems: 'center',
                gap: 10,
              }}
            >
              <AlertTriangle size={18} />
              <span>{errorMessage}</span>
            </div>
          )}

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 12 }}>
            <button className="btn-ghost" onClick={() => setCurrentStep(2)}>
              Back
            </button>

            <button
              className="btn-cyan"
              onClick={handleLaunch}
              disabled={isSubmitting}
              style={{ fontSize: '0.9rem', padding: '10px 24px' }}
            >
              <Play size={16} />
              <span>{isSubmitting ? 'Starting Pipeline...' : 'Start Experiment'}</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
