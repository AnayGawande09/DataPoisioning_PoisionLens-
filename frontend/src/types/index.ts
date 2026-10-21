/**
 * Core TypeScript definitions for PoisonLens ML Security Platform.
 */

export type AttackType = 'none' | 'label_flip' | 'badnets' | 'blended' | 'custom';
export type MitigationDecision = 'keep' | 'downweight' | 'quarantine';
export type ThreatLevel = 'None' | 'Low' | 'Medium' | 'High' | 'Critical' | 'Unknown';
export type JobStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

export interface Preset {
  id: string;
  filename: string;
  name: string;
  category: string;
  threat_level: ThreatLevel;
  description: string;
  badge_color: 'cyan' | 'violet' | 'amber' | 'rose' | 'emerald';
  attack_type: AttackType;
  poison_rate: number;
  target_class?: number | null;
  source_class?: number | null;
  patch_size?: number | null;
  alpha?: number | null;
  epochs: number;
  batch_size: number;
  learning_rate: number;
  weight_decay: number;
  device: string;
  dataset: string;
  model: string;
  is_supported: boolean;
  raw_config: Record<string, any>;
}

export interface RunSummary {
  run_id: string;
  status: string;
  timestamp: string;
  attack_type: string;
  poison_rate: number;
  has_audit_log: boolean;
  has_pipeline_results: boolean;
  baseline_clean_acc?: string | null;
  mitigated_clean_acc?: string | null;
  baseline_asr?: string | null;
  mitigated_asr?: string | null;
  guardrail_action?: string | null;
  total_time_seconds?: number | null;
}

export interface PipelineResults {
  run_id: string;
  config_hash: string;
  total_time_seconds: number;
  scoring_time_seconds: number;
  scoring_throughput_samples_per_sec: number;
  baseline_metrics: {
    clean_acc: string;
    canary_acc: string;
    asr?: string;
  };
  mitigated_metrics: {
    clean_acc: string;
    canary_acc: string;
    asr?: string;
    wrongly_quarantined_clean?: number;
    clean_retention_rate?: string;
    worst_class_drop?: string;
  };
  guardrail_decision: {
    action: 'PROCEED' | 'ROLLBACK_TRIGGERED' | string;
    reason: string;
    baseline_canary_acc: number;
    mitigated_canary_acc: number;
    canary_delta: number;
    tolerance: number;
    rolled_back_to?: string;
    suggested_loosened_ratio?: number;
  };
  audit_verification: {
    is_valid: boolean;
    message: string;
  };
}

export interface RunDetails {
  run_id: string;
  config: Record<string, any>;
  run_info: Record<string, any>;
  results: PipelineResults | Record<string, any>;
  has_audit_log: boolean;
  has_tampered_audit_log: boolean;
  total_audit_entries: number;
  decision_counts: {
    keep: number;
    downweight: number;
    quarantine: number;
  };
}

export interface SampleItem {
  sample_id: number;
  score: number;
  decision: MitigationDecision;
  sample_weight: number;
  reasons: string[];
  entry_hash: string;
  full_entry_hash?: string;
  timestamp?: string;
  is_ground_truth_poison?: boolean | null;
}

export interface SampleDetail extends SampleItem {
  previous_hash?: string;
  config_hash?: string;
  loss_curve: number[];
  preds_history: number[];
  correct_history: boolean[];
  epochs_count: number;
}

export interface SamplesResponse {
  total: number;
  offset: number;
  limit: number;
  items: SampleItem[];
  decision_breakdown: {
    keep: number;
    downweight: number;
    quarantine: number;
  };
}

export interface AuditEntry {
  index: number;
  timestamp: string;
  previous_hash: string;
  config_hash: string;
  sample_id: number;
  score: number;
  reasons: string[];
  decision: MitigationDecision;
  sample_weight: number;
  entry_hash: string;
}

export interface AuditVerificationResult {
  is_valid: boolean;
  message: string;
  raw_verifier_message?: string;
  total_entries: number;
  broken_index?: number | null;
  verified_at: string;
  filename: string;
}

export interface JobState {
  job_id: string;
  run_id: string;
  preset_id: string;
  status: JobStatus;
  current_stage: string;
  stage_number: number;
  total_stages: number;
  start_time: number | null;
  elapsed_seconds: number;
  error?: string | null;
  has_results: boolean;
  logs: Array<{ time: string; message: string }>;
}

export interface BenchmarkRow {
  Attack: string;
  Defense: string;
  Precision: string;
  Recall: string;
  F1: string;
  'Clean Acc': string;
  ASR: string;
  Notes: string;
}
