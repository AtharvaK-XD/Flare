import type {
  AlertDetail,
  AlertStats,
  AlertSummary,
  BenchmarkReport,
  DeepHealth,
  EvalReport,
  ReplayStatus,
} from '@/types';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
const API_PREFIX = '/api/v1';

export class ApiError extends Error {
  code: string;
  status: number;
  detail: unknown;

  constructor(code: string, message: string, status: number, detail: unknown = null) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${BASE_URL}${API_PREFIX}${path}`;
  const response = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
    ...options,
  });

  if (!response.ok) {
    let code = 'internal_error';
    let message = `Request failed with status ${response.status}`;
    let detail: unknown = null;

    try {
      const data = await response.json();
      if (data?.error) {
        code = data.error.code || code;
        message = data.error.message || message;
        detail = data.error.detail ?? null;
      }
    } catch {
      // JSON parsing failed, use default error message
    }

    throw new ApiError(code, message, response.status, detail);
  }

  return response.json() as Promise<T>;
}

export interface GetAlertsParams {
  limit?: number;
  offset?: number;
  severity?: string; // csv
  status?: string; // csv
  attack_type?: string; // csv
  src_ip?: string;
  malicious_only?: boolean;
  since?: string;
  sort?: string;
}

export interface GetAlertsResponse {
  items: AlertSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface IngestAlertParams {
  signature: string;
  src_ip: string;
  dst_ip: string;
  dst_port?: number;
  protocol?: string;
  event_type?: string;
  [key: string]: unknown;
}

export interface IngestResponse {
  id: string;
  status: 'ingested';
}

export interface StartReplayParams {
  dataset?: 'cicids2017' | 'cicids' | 'suricata';
  events_per_second?: number;
  limit?: number;
}

export const api = {
  // Health
  getHealth: () => request<{ status: string }>('/health'),
  getHealthDeep: () => request<DeepHealth>('/health/deep'),

  // Alerts
  getAlerts: (params?: GetAlertsParams) => {
    const query = new URLSearchParams();
    if (params) {
      Object.entries(params).forEach(([key, val]) => {
        if (val !== undefined && val !== null) {
          query.set(key, String(val));
        }
      });
    }
    const qStr = query.toString();
    return request<GetAlertsResponse>(`/alerts${qStr ? `?${qStr}` : ''}`);
  },
  getAlertStats: () => request<AlertStats>('/alerts/stats'),
  getAlertDetail: (id: string) => request<AlertDetail>(`/alerts/${id}`),

  // Ingest
  ingestAlert: (body: IngestAlertParams) =>
    request<IngestResponse>('/ingest', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  // Replay
  startReplay: (params?: StartReplayParams) =>
    request<ReplayStatus>('/replay/start', {
      method: 'POST',
      body: JSON.stringify(params || {}),
    }),
  pauseReplay: () => request<ReplayStatus>('/replay/pause', { method: 'POST' }),
  resumeReplay: () => request<ReplayStatus>('/replay/resume', { method: 'POST' }),
  stopReplay: () => request<ReplayStatus>('/replay/stop', { method: 'POST' }),
  getReplayStatus: () => request<ReplayStatus>('/replay/status'),

  // Evaluation
  runEvaluation: (sample_size = 200) =>
    request<{ run_id: string; status: 'running' }>('/evaluation/run', {
      method: 'POST',
      body: JSON.stringify({ sample_size }),
    }),
  getEvaluationRuns: () => request<EvalReport[]>('/evaluation/runs'),
  getEvaluationRun: (run_id: string) => request<EvalReport>(`/evaluation/runs/${run_id}`),

  // Benchmark
  runBenchmark: (sample_size = 25) =>
    request<{ run_id: string; status: 'running' }>('/benchmark/run', {
      method: 'POST',
      body: JSON.stringify({ sample_size }),
    }),
  getBenchmarkRuns: () => request<BenchmarkReport[]>('/benchmark/runs'),
  getBenchmarkRun: (run_id: string) => request<BenchmarkReport>(`/benchmark/runs/${run_id}`),

  // EventSource Stream
  connectSSEStream: (handlers: {
    onAlertNew?: (alert: AlertSummary) => void;
    onAlertUpdated?: (alert: AlertSummary) => void;
    onStatsUpdated?: (stats: AlertStats) => void;
    onReplayStatus?: (status: ReplayStatus) => void;
    onSystemNotice?: (notice: { level: 'info' | 'warn' | 'error'; message: string }) => void;
    onError?: (err: Event) => void;
  }): () => void => {
    const url = `${BASE_URL}${API_PREFIX}/stream`;
    const es = new EventSource(url);

    if (handlers.onAlertNew) {
      es.addEventListener('alert.new', (e: MessageEvent) => {
        try {
          handlers.onAlertNew?.(JSON.parse(e.data));
        } catch {
          // malformed frame — drop it, keep the stream alive
        }
      });
    }

    if (handlers.onAlertUpdated) {
      es.addEventListener('alert.updated', (e: MessageEvent) => {
        try {
          handlers.onAlertUpdated?.(JSON.parse(e.data));
        } catch {
          // malformed frame — drop it, keep the stream alive
        }
      });
    }

    if (handlers.onStatsUpdated) {
      es.addEventListener('stats.updated', (e: MessageEvent) => {
        try {
          handlers.onStatsUpdated?.(JSON.parse(e.data));
        } catch {
          // malformed frame — drop it, keep the stream alive
        }
      });
    }

    if (handlers.onReplayStatus) {
      es.addEventListener('replay.status', (e: MessageEvent) => {
        try {
          handlers.onReplayStatus?.(JSON.parse(e.data));
        } catch {
          // malformed frame — drop it, keep the stream alive
        }
      });
    }

    if (handlers.onSystemNotice) {
      es.addEventListener('system.notice', (e: MessageEvent) => {
        try {
          handlers.onSystemNotice?.(JSON.parse(e.data));
        } catch {
          // malformed frame — drop it, keep the stream alive
        }
      });
    }

    if (handlers.onError) {
      es.onerror = (e) => handlers.onError?.(e);
    }

    return () => es.close();
  },
};
