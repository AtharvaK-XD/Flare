export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type AlertStatus = 'ingested' | 'classified' | 'enriched' | 'reasoned' | 'done' | 'failed';

// Legacy alias
export type PipelineStage = AlertStatus;

export type AttackType =
  | 'port_scan'
  | 'brute_force'
  | 'ddos'
  | 'web_attack'
  | 'malware_c2'
  | 'data_exfiltration'
  | 'privilege_escalation'
  | 'recon'
  | 'benign'
  | 'unknown';

export type IntelSource = 'abuseipdb' | 'virustotal';
export type ProviderTier = 'fast' | 'quality';
export type RunStatus = 'running' | 'completed' | 'failed';
export type ReplayState = 'idle' | 'running' | 'paused' | 'completed';

export interface AlertSummary {
  id: string;
  timestamp: string; // ISO-8601 UTC
  status: AlertStatus;
  severity: Severity | null;
  confidence: number | null; // 0.0 - 1.0 float
  attack_type: AttackType | null;
  signature: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string | null;
  source: string; // "suricata" | "cicids2017" | "manual"
  has_enrichment: boolean;
  has_remediation: boolean;
  max_ioc_score: number | null; // 0 - 100 float

  // Legacy backwards-compatibility getters/properties
  stage?: AlertStatus;
  branched?: boolean;
}

export interface IocSourceEntry {
  source: IntelSource;
  raw_score: number;
  categories: string[];
  last_seen: string | null;
  link: string | null;
}

export interface IocVerdict {
  indicator: string;
  indicator_type: 'ip' | 'hash';
  score: number;
  malicious: boolean;
  sources: IocSourceEntry[];
  cached: boolean;

  // Legacy field support
  type?: string;
  value?: string;
  hits?: number;
}

export interface Enrichment {
  iocs: IocVerdict[];
  enriched_at: string;
  duration_ms: number;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  url: string;
  excerpt: string;
}

export interface RemediationStep {
  order: number;
  action: string;
  detail: string;
  urgency: 'immediate' | 'soon' | 'monitor';
  priority?: 'P1' | 'P2' | 'P3';
}

export interface Remediation {
  summary: string;
  steps: RemediationStep[];
  techniques: MitreTechnique[];
  generated_at: string;
  duration_ms: number;
}

export interface TraceNode {
  node: 'classify' | 'enrich' | 'retrieve' | 'reason' | 'recommend';
  status: 'ok' | 'skipped' | 'failed';
  provider: string | null;
  duration_ms: number;
  tokens_in: number | null;
  tokens_out: number | null;
  note: string | null;

  // Legacy trace field support
  stage?: AlertStatus;
  duration?: number;
  notes?: string;
}

export interface AlertDetail extends AlertSummary {
  raw: Record<string, unknown>;
  reasoning: string | null;
  enrichment: Enrichment | null;
  remediation: Remediation | null;
  trace: TraceNode[];
  total_duration_ms: number | null;

  // Legacy alert properties
  iocs?: IocVerdict[];
  mitre?: MitreTechnique[];
  remediation_steps?: RemediationStep[];
  ingested_at?: number;
  source_ip?: string;
  dest_ip?: string;
  dest_port?: number;
}

export type Alert = AlertDetail;

export interface ServiceHealth {
  status: 'ok' | 'degraded' | 'down';
  latency_ms?: number;
  quota_remaining?: number;
  documents?: number;
  note?: string;
}

export interface ServiceStatus {
  name: string;
  status: 'ok' | 'degraded' | 'down';
  detail: string;
}

export interface QueueDepth {
  ingest: number;
  enrich: number;
  reason: number;
}

export interface DeepHealth {
  status: 'ok' | 'degraded' | 'down';
  services: {
    groq: ServiceHealth;
    gemini: ServiceHealth;
    abuseipdb: ServiceHealth;
    virustotal: ServiceHealth;
    chroma: ServiceHealth;
    database: ServiceHealth;
  };
  workers?: {
    triage: { active: number; configured: number; restarts?: number };
    enrich: { active: number; configured: number; restarts?: number };
    queues: {
      triage: { depth: number; enqueued?: number; dequeued?: number };
      enrich: { depth: number; enqueued?: number; dequeued?: number };
    };
    degraded?: boolean;
  };
}

export interface AlertStats {
  total: number;
  by_severity: Partial<Record<Severity, number>>;
  by_attack_type: Record<string, number>;
  by_status: Partial<Record<AlertStatus, number>>;
  malicious_iocs: number;
  avg_triage_ms: number | null;
  alerts_per_min: number;
  timeline: { bucket: string; count: number; critical: number }[];
}

export interface Stats extends AlertStats {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  per_minute: number;
  queue_depth: QueueDepth;
  services: ServiceStatus[];
}

export interface ReplayStatus {
  state: ReplayState;
  dataset: string;
  events_per_second: number;
  emitted: number;
  total: number | null;
  queue_depth: { triage: number; enrich: number };
  started_at: string | null;
  skipped: number;
}

export interface EvalClassResult {
  label: string;
  precision: number;
  recall: number;
  f1: number;
  support: number;
}

export interface ConfusionMatrixData {
  labels: string[];
  matrix: number[][];
}

export interface EvalReportTarget {
  overall: { precision: number; recall: number; f1: number; accuracy: number } | null;
  per_class: EvalClassResult[];
  confusion_matrix: ConfusionMatrixData | null;
}

export interface EvalReport extends EvalReportTarget {
  run_id: string;
  status: RunStatus;
  sample_size: number;
  started_at: string;
  completed_at: string | null;
  attack_type: EvalReportTarget;
  error: string | null;
}

export interface EvalMetrics {
  precision: number;
  recall: number;
  f1: number;
  accuracy: number;
  confusion: Record<string, Record<string, number>>;
}

export interface BenchmarkTier {
  name: 'fast' | 'quality';
  label: string;
  precision: number;
  recall: number;
  latency_p50_ms: number;
  latency_p95_ms: number;
  cost_per_1k: number;
}

export interface BenchmarkResult {
  tier: ProviderTier;
  provider: string;
  model: string;
  avg_latency_ms: number;
  p95_latency_ms: number;
  accuracy: number;
  avg_tokens: number;
  failures: number;
  p50_latency_ms: number;
  min_latency_ms: number;
  max_latency_ms: number;
  avg_tokens_in: number;
  avg_tokens_out: number;
  attack_type_accuracy: number;
  estimated_cost: number | null;
  calls: number;
  warmup_calls: number;
  throttled: boolean;
  throttle_retries: number;
}

export interface BenchmarkDisagreement {
  alert_id: string;
  signature: string;
  fast_prediction: string;
  quality_prediction: string;
  ground_truth: string;
}

export interface BenchmarkReport {
  run_id: string;
  status: RunStatus;
  sample_size: number;
  results: BenchmarkResult[];
  agreement_rate: number | null;
  disagreement_examples: BenchmarkDisagreement[];
  error: string | null;
}

export const ALERT_STATUSES: AlertStatus[] = [
  'ingested',
  'classified',
  'enriched',
  'reasoned',
  'done',
  'failed',
];

export const STAGES: PipelineStage[] = ALERT_STATUSES;

export const STATUS_LABELS: Record<AlertStatus, string> = {
  ingested: 'INGESTED',
  classified: 'CLASSIFIED',
  enriched: 'ENRICHED',
  reasoned: 'REASONED',
  done: 'DONE',
  failed: 'FAILED',
};

export const STAGE_LABELS = STATUS_LABELS;

export const STAGE_ORDER: Record<AlertStatus, number> = {
  ingested: 0,
  classified: 1,
  enriched: 2,
  reasoned: 3,
  done: 4,
  failed: 5,
};

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#DC2626',
  high: '#EA580C',
  medium: '#D97706',
  low: '#2563EB',
  info: '#6B7280',
};

export const SEVERITY_RGB: Record<Severity, [number, number, number]> = {
  critical: [220, 38, 38],
  high: [234, 88, 12],
  medium: [217, 119, 6],
  low: [37, 99, 235],
  info: [107, 114, 128],
};

export const SEVERITY_TEXT: Record<Severity, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

export const SEVERITY_HEX_CLASS: Record<Severity, string> = {
  critical: 'text-sev-critical',
  high: 'text-sev-high',
  medium: 'text-sev-medium',
  low: 'text-sev-low',
  info: 'text-sev-info',
};

export const SEVERITY_FLASH_ANIM: Record<Severity, string> = {
  critical: 'animate-flash-crit',
  high: 'animate-flash-high',
  medium: 'animate-flash-med',
  low: 'animate-flash-low',
  info: 'animate-flash-info',
};
