import { useCallback, useEffect, useRef, useState } from 'react';
import type {
  AlertDetail,
  AlertStats,
  AlertSummary,
  DeepHealth,
  QueueDepth,
  ReplayState,
  ReplayStatus,
  ServiceStatus,
  Stats,
} from '@/types';
import { api } from '@/lib/api';
import {
  generateAlertDetail,
  generateAlertStats,
  generateReplayStatus,
  seedAlerts,
} from '@/lib/generator';

const MAX_ALERTS = 150;

export type ReplayMode = 'live' | 'paused' | 'stopped';

export function useAlertStream() {
  const [alerts, setAlerts] = useState<AlertDetail[]>(() => seedAlerts(12));
  const [connected, setConnected] = useState(false);
  const [mode, setMode] = useState<ReplayMode>('live');
  const [replayStatus, setReplayStatus] = useState<ReplayStatus>(generateReplayStatus);
  const [deepHealth, setDeepHealth] = useState<DeepHealth | null>(null);
  const [systemNotice, setSystemNotice] = useState<{ level: string; message: string } | null>(null);
  const [isLiveApi, setIsLiveApi] = useState(false);

  const alertsMapRef = useRef<Map<string, AlertDetail>>(new Map());

  // Initialize map with seed alerts
  useEffect(() => {
    alerts.forEach((a) => alertsMapRef.current.set(a.id, a));
  }, []);

  // Helper to merge AlertSummary into AlertDetail store
  const upsertAlertSummary = useCallback((summary: AlertSummary) => {
    setAlerts((prev) => {
      const existing = alertsMapRef.current.get(summary.id);
      const updated: AlertDetail = existing
        ? {
            ...existing,
            status: summary.status,
            severity: summary.severity ?? existing.severity,
            confidence: summary.confidence ?? existing.confidence,
            attack_type: summary.attack_type ?? existing.attack_type,
            has_enrichment: summary.has_enrichment,
            has_remediation: summary.has_remediation,
            max_ioc_score: summary.max_ioc_score ?? existing.max_ioc_score,
          }
        : generateAlertDetail(summary);

      alertsMapRef.current.set(summary.id, updated);
      const filtered = [updated, ...prev.filter((a) => a.id !== summary.id)].slice(0, MAX_ALERTS);
      return filtered;
    });
  }, []);

  // Connect to SSE Stream or fallback to generator
  useEffect(() => {
    let cleanupSSE: (() => void) | null = null;
    let fallbackInterval: ReturnType<typeof setInterval> | null = null;

    const tryConnect = async () => {
      try {
        const health = await api.getHealth();
        if (health.status === 'ok') {
          setIsLiveApi(true);
          setConnected(true);

          cleanupSSE = api.connectSSEStream({
            onAlertNew: (summary) => upsertAlertSummary(summary),
            onAlertUpdated: (summary) => upsertAlertSummary(summary),
            onStatsUpdated: (_stats) => {
              // Stats are updated
            },
            onReplayStatus: (status) => setReplayStatus(status),
            onSystemNotice: (notice) => setSystemNotice(notice),
            onError: () => {
              setConnected(false);
            },
          });
          return;
        }
      } catch {
        // Backend API offline, run in simulation mode
      }

      setIsLiveApi(false);
      setConnected(mode === 'live');

      // Offline simulation fallback tick
      fallbackInterval = setInterval(() => {
        if (mode === 'live') {
          const fresh = generateAlertDetail();
          upsertAlertSummary(fresh);
        }
      }, 2500);
    };

    tryConnect();

    return () => {
      if (cleanupSSE) cleanupSSE();
      if (fallbackInterval) clearInterval(fallbackInterval);
    };
  }, [mode, upsertAlertSummary]);

  // Deep health poll
  useEffect(() => {
    if (!isLiveApi) return;
    const interval = setInterval(async () => {
      try {
        const dh = await api.getHealthDeep();
        setDeepHealth(dh);
      } catch {
        // Degraded
      }
    }, 10000);
    return () => clearInterval(interval);
  }, [isLiveApi]);

  // Replay actions
  const startReplay = useCallback(
    async (dataset: 'cicids2017' | 'suricata' = 'cicids2017', events_per_second = 5, limit = 500) => {
      setMode('live');
      if (isLiveApi) {
        try {
          const st = await api.startReplay({ dataset, events_per_second, limit });
          setReplayStatus(st);
        } catch {}
      } else {
        setReplayStatus((prev) => ({ ...prev, state: 'running', dataset, events_per_second, total: limit }));
      }
    },
    [isLiveApi],
  );

  const pauseReplay = useCallback(async () => {
    setMode('paused');
    if (isLiveApi) {
      try {
        const st = await api.pauseReplay();
        setReplayStatus(st);
      } catch {}
    } else {
      setReplayStatus((prev) => ({ ...prev, state: 'paused' }));
    }
  }, [isLiveApi]);

  const resumeReplay = useCallback(async () => {
    setMode('live');
    if (isLiveApi) {
      try {
        const st = await api.resumeReplay();
        setReplayStatus(st);
      } catch {}
    } else {
      setReplayStatus((prev) => ({ ...prev, state: 'running' }));
    }
  }, [isLiveApi]);

  const stopReplay = useCallback(async () => {
    setMode('stopped');
    if (isLiveApi) {
      try {
        const st = await api.stopReplay();
        setReplayStatus(st);
      } catch {}
    } else {
      setReplayStatus((prev) => ({ ...prev, state: 'idle', emitted: 0 }));
    }
  }, [isLiveApi]);

  const setReplayMode = useCallback(
    (m: ReplayMode) => {
      if (m === 'live') resumeReplay();
      else if (m === 'paused') pauseReplay();
      else if (m === 'stopped') stopReplay();
    },
    [resumeReplay, pauseReplay, stopReplay],
  );

  const fetchAlertDetail = useCallback(
    async (id: string): Promise<AlertDetail | null> => {
      if (isLiveApi) {
        try {
          const detail = await api.getAlertDetail(id);
          alertsMapRef.current.set(id, detail);
          setAlerts((prev) => prev.map((a) => (a.id === id ? detail : a)));
          return detail;
        } catch {
          // fallback to store
        }
      }
      return alertsMapRef.current.get(id) || null;
    },
    [isLiveApi],
  );

  const pushCustomAlert = useCallback(
    async (body: { signature: string; src_ip: string; dst_ip: string; dst_port?: number; protocol?: string }) => {
      if (isLiveApi) {
        try {
          await api.ingestAlert(body);
        } catch {}
      } else {
        const manual = generateAlertDetail();
        manual.signature = body.signature;
        manual.src_ip = body.src_ip;
        manual.dst_ip = body.dst_ip;
        manual.source = 'manual';
        upsertAlertSummary(manual);
      }
    },
    [isLiveApi, upsertAlertSummary],
  );

  // Compute legacy Stats projection for components
  const baseAlertStats = generateAlertStats(alerts);

  const legacyServices: ServiceStatus[] = deepHealth
    ? [
        { name: 'Groq Classifier', status: deepHealth.services.groq.status, detail: deepHealth.services.groq.note || `${deepHealth.services.groq.latency_ms ?? 210}ms` },
        { name: 'Gemini Reasoner', status: deepHealth.services.gemini.status, detail: deepHealth.services.gemini.note || `${deepHealth.services.gemini.latency_ms ?? 640}ms` },
        { name: 'AbuseIPDB Intel', status: deepHealth.services.abuseipdb.status, detail: deepHealth.services.abuseipdb.note || `quota ${deepHealth.services.abuseipdb.quota_remaining ?? 940}` },
        { name: 'VirusTotal Intel', status: deepHealth.services.virustotal.status, detail: deepHealth.services.virustotal.note || `quota ${deepHealth.services.virustotal.quota_remaining ?? 0}` },
        { name: 'Chroma ATT&CK', status: deepHealth.services.chroma.status, detail: `${deepHealth.services.chroma.documents ?? 27} docs` },
        { name: 'SQLite DB', status: deepHealth.services.database.status, detail: `${deepHealth.services.database.latency_ms ?? 1}ms` },
      ]
    : [
        { name: 'Classifier (Groq)', status: 'ok', detail: 'fast-tier nominal' },
        { name: 'Enrichment (Intel)', status: 'ok', detail: 'VT quota 78%' },
        { name: 'Reasoner (Gemini)', status: 'ok', detail: 'flash-tier nominal' },
        { name: 'Chroma VectorDB', status: 'ok', detail: 'MITRE v14 indexed' },
      ];

  const legacyQueue: QueueDepth = {
    ingest: replayStatus.queue_depth.triage,
    enrich: replayStatus.queue_depth.enrich,
    reason: Math.floor(replayStatus.queue_depth.enrich / 2),
  };

  const stats: Stats = {
    total: baseAlertStats.total,
    critical: baseAlertStats.by_severity.critical || 0,
    high: baseAlertStats.by_severity.high || 0,
    medium: baseAlertStats.by_severity.medium || 0,
    low: baseAlertStats.by_severity.low || 0,
    info: baseAlertStats.by_severity.info || 0,
    per_minute: baseAlertStats.alerts_per_min,
    malicious_iocs: baseAlertStats.malicious_iocs,
    queue_depth: legacyQueue,
    services: legacyServices,
    by_severity: baseAlertStats.by_severity,
    by_attack_type: baseAlertStats.by_attack_type,
    by_status: baseAlertStats.by_status,
    avg_triage_ms: baseAlertStats.avg_triage_ms,
    alerts_per_min: baseAlertStats.alerts_per_min,
    timeline: baseAlertStats.timeline,
  };

  return {
    alerts,
    stats,
    connected,
    mode,
    setReplayMode,
    startReplay,
    pauseReplay,
    resumeReplay,
    stopReplay,
    replayStatus,
    fetchAlertDetail,
    pushCustomAlert,
    queue: legacyQueue,
    isLiveApi,
    systemNotice,
  };
}
