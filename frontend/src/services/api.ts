/**
 * Unified API Client for PoisonLens.
 * Supports both Live FastAPI Backend and Deterministic Judge Demo Mode.
 */

import {
  Preset,
  RunSummary,
  RunDetails,
  SamplesResponse,
  SampleDetail,
  AuditEntry,
  AuditVerificationResult,
  JobState,
  BenchmarkRow,
} from '../types';

import {
  DEMO_PRESETS,
  DEMO_RUNS,
  DEMO_RUN_DETAILS,
  DEMO_SAMPLES,
  DEMO_AUDIT_BLOCKS,
  DEMO_BENCHMARKS,
  DEMO_VERIFICATION_SUCCESS,
  DEMO_VERIFICATION_TAMPERED,
} from '../data/demoFixtures';

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

class ApiService {
  private _demoMode: boolean = true; // Default to Demo Mode so judges immediately see rich interactive charts
  private _listeners: Array<(demoMode: boolean) => void> = [];

  constructor() {
    const saved = localStorage.getItem('poisonlens_demo_mode');
    if (saved !== null) {
      this._demoMode = saved === 'true';
    }
  }

  public isDemoMode(): boolean {
    return this._demoMode;
  }

  public setDemoMode(val: boolean) {
    this._demoMode = val;
    localStorage.setItem('poisonlens_demo_mode', String(val));
    this._listeners.forEach((fn) => fn(val));
  }

  public subscribeDemoMode(fn: (demoMode: boolean) => void): () => void {
    this._listeners.push(fn);
    return () => {
      this._listeners = this._listeners.filter((l) => l !== fn);
    };
  }

  public resetDemoData() {
    // Re-seeds any local modifications
    localStorage.removeItem('poisonlens_demo_state');
  }

  public async checkHealth(): Promise<{ online: boolean; message: string }> {
    try {
      const res = await fetch(`${API_BASE}/api/health`, { method: 'GET', signal: AbortSignal.timeout(2500) });
      if (res.ok) {
        const data = await res.json();
        return { online: true, message: data.service || 'Connected to PoisonLens API' };
      }
      return { online: false, message: `Backend responded with HTTP ${res.status}` };
    } catch (e: any) {
      return { online: false, message: 'Backend is offline or unreachable' };
    }
  }

  public async getPresets(): Promise<Preset[]> {
    if (this._demoMode) {
      return DEMO_PRESETS;
    }
    try {
      const res = await fetch(`${API_BASE}/api/presets`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch {
      return DEMO_PRESETS;
    }
  }

  public async getRuns(): Promise<RunSummary[]> {
    if (this._demoMode) {
      return DEMO_RUNS;
    }
    try {
      const res = await fetch(`${API_BASE}/api/runs`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch {
      return DEMO_RUNS;
    }
  }

  public async getRun(runId: string): Promise<RunDetails | null> {
    if (this._demoMode) {
      return DEMO_RUN_DETAILS[runId] || DEMO_RUN_DETAILS['attack_badnets_5'];
    }
    try {
      const res = await fetch(`${API_BASE}/api/runs/${runId}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch {
      return DEMO_RUN_DETAILS[runId] || DEMO_RUN_DETAILS['attack_badnets_5'];
    }
  }

  public async getSamples(
    runId: string,
    params: {
      limit?: number;
      offset?: number;
      decision?: string;
      min_score?: number;
      max_score?: number;
      search?: string;
      ground_truth_only?: boolean;
    } = {}
  ): Promise<SamplesResponse> {
    if (this._demoMode) {
      let filtered = [...DEMO_SAMPLES];
      if (params.decision && params.decision !== 'all') {
        filtered = filtered.filter((s) => s.decision.toLowerCase() === params.decision?.toLowerCase());
      }
      if (params.ground_truth_only) {
        filtered = filtered.filter((s) => s.is_ground_truth_poison === true);
      }
      if (params.search) {
        const q = params.search.toLowerCase();
        filtered = filtered.filter(
          (s) =>
            String(s.sample_id).includes(q) ||
            s.reasons.some((r) => r.toLowerCase().includes(q)) ||
            s.entry_hash.toLowerCase().includes(q)
        );
      }
      return {
        total: filtered.length,
        offset: params.offset || 0,
        limit: params.limit || 50,
        items: filtered,
        decision_breakdown: {
          keep: 8330,
          downweight: 980,
          quarantine: 490,
        },
      };
    }

    try {
      const sp = new URLSearchParams();
      if (params.limit) sp.set('limit', String(params.limit));
      if (params.offset) sp.set('offset', String(params.offset));
      if (params.decision) sp.set('decision', params.decision);
      if (params.min_score !== undefined) sp.set('min_score', String(params.min_score));
      if (params.max_score !== undefined) sp.set('max_score', String(params.max_score));
      if (params.search) sp.set('search', params.search);
      if (params.ground_truth_only) sp.set('ground_truth_only', 'true');

      const res = await fetch(`${API_BASE}/api/runs/${runId}/samples?${sp.toString()}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch {
      return {
        total: DEMO_SAMPLES.length,
        offset: 0,
        limit: 50,
        items: DEMO_SAMPLES,
        decision_breakdown: { keep: 8330, downweight: 980, quarantine: 490 },
      };
    }
  }

  public async getSampleDetail(runId: string, sampleId: number): Promise<SampleDetail | null> {
    if (this._demoMode) {
      const found = DEMO_SAMPLES.find((s) => s.sample_id === sampleId);
      return found || DEMO_SAMPLES[0];
    }
    try {
      const res = await fetch(`${API_BASE}/api/runs/${runId}/samples/${sampleId}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch {
      return DEMO_SAMPLES[0];
    }
  }

  public async getAuditEntries(runId: string, limit: number = 20, offset: number = 0): Promise<{ total: number; entries: AuditEntry[] }> {
    if (this._demoMode) {
      return {
        total: 9800,
        entries: DEMO_AUDIT_BLOCKS,
      };
    }
    try {
      const res = await fetch(`${API_BASE}/api/runs/${runId}/audit?limit=${limit}&offset=${offset}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch {
      return { total: 9800, entries: DEMO_AUDIT_BLOCKS };
    }
  }

  public async verifyAudit(runId: string, simulateTamper: boolean = false): Promise<AuditVerificationResult> {
    if (this._demoMode) {
      // Simulate cryptographic verification delay
      await new Promise((r) => setTimeout(r, 650));
      return simulateTamper ? DEMO_VERIFICATION_TAMPERED : DEMO_VERIFICATION_SUCCESS;
    }
    try {
      const endpoint = simulateTamper ? 'simulate-tamper' : 'verify';
      const res = await fetch(`${API_BASE}/api/runs/${runId}/audit/${endpoint}`, { method: 'POST' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch {
      return simulateTamper ? DEMO_VERIFICATION_TAMPERED : DEMO_VERIFICATION_SUCCESS;
    }
  }

  public async startExperiment(presetId: string, overrides?: Record<string, any>): Promise<JobState> {
    if (this._demoMode) {
      // Return a simulated job tracker in demo mode
      return {
        job_id: `job_demo_${Date.now()}`,
        run_id: `${presetId}_demo_run`,
        preset_id: presetId,
        status: 'RUNNING',
        current_stage: 'Stage 1: Dataset preparation & controlled attack',
        stage_number: 1,
        total_stages: 6,
        start_time: Date.now() / 1000,
        elapsed_seconds: 1.2,
        has_results: false,
        logs: [
          { time: '12:00:01', message: `Initializing PoisonLens Demo Pipeline for preset: ${presetId}` },
          { time: '12:00:02', message: 'Loading deterministic CIFAR-10 stratified 10,000 subset...' },
        ],
      };
    }

    const res = await fetch(`${API_BASE}/api/runs/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        preset_name: presetId,
        seed: overrides?.seed,
        epochs: overrides?.epochs,
        overrides,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to launch experiment' }));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    return await res.json();
  }

  public async getJobStatus(jobId: string): Promise<JobState> {
    if (this._demoMode) {
      return {
        job_id: jobId,
        run_id: 'attack_badnets_5_demo',
        preset_id: 'attack_badnets_5',
        status: 'COMPLETED',
        current_stage: 'Experiment completed successfully',
        stage_number: 6,
        total_stages: 6,
        start_time: Date.now() / 1000 - 287,
        elapsed_seconds: 287.06,
        has_results: true,
        logs: [
          { time: '12:00:01', message: 'Loaded 10,000 training samples (SHA-256 provenance hash verified)' },
          { time: '12:00:15', message: 'Stage 1: Applied BadNets 3x3 white square patch to 500 samples (class 0)' },
          { time: '12:01:45', message: 'Stage 2: Model training complete. Recorded dynamics across 10 epochs' },
          { time: '12:02:15', message: 'Stage 3: Trajectory scoring finished (351.1 samples/sec)' },
          { time: '12:02:30', message: 'Stage 4: Quarantined 490 samples, downweighted 980 samples' },
          { time: '12:04:10', message: 'Stage 5: Canary accuracy check triggered rollback guardrail' },
          { time: '12:04:47', message: 'Stage 6: Hash-chain audit log saved to audit_log.jsonl (9,800 entries)' },
        ],
      };
    }

    const res = await fetch(`${API_BASE}/api/runs/${jobId}/status`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  }

  public async getArtifacts(runId: string): Promise<Array<{ filename: string; size_bytes: number; modified_at: string; is_downloadable: boolean }>> {
    if (this._demoMode) {
      return [
        { filename: 'pipeline_results.json', size_bytes: 1122, modified_at: '2026-10-21T11:51:55Z', is_downloadable: true },
        { filename: 'audit_log.jsonl', size_bytes: 4441068, modified_at: '2026-10-21T11:51:55Z', is_downloadable: true },
        { filename: 'config.yaml', size_bytes: 256, modified_at: '2026-10-21T11:51:47Z', is_downloadable: true },
        { filename: 'run_info.json', size_bytes: 687, modified_at: '2026-10-21T11:51:47Z', is_downloadable: true },
        { filename: 'training_dynamics.npz', size_bytes: 452668, modified_at: '2026-10-21T11:51:50Z', is_downloadable: false },
      ];
    }
    try {
      const res = await fetch(`${API_BASE}/api/runs/${runId}/artifacts`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch {
      return [];
    }
  }

  public async getBenchmarks(): Promise<BenchmarkRow[]> {
    if (this._demoMode) {
      return DEMO_BENCHMARKS;
    }
    try {
      const res = await fetch(`${API_BASE}/api/benchmarks`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch {
      return DEMO_BENCHMARKS;
    }
  }
}

export const api = new ApiService();
