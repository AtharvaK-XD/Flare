import type {
  AlertDetail,
  AlertStats,
  AlertStatus,
  AlertSummary,
  AttackType,
  BenchmarkReport,
  EvalReport,
  IocVerdict,
  MitreTechnique,
  Remediation,
  RemediationStep,
  ReplayStatus,
  Severity,
  TraceNode,
} from '@/types';

const ATTACK_TYPES: AttackType[] = [
  'port_scan',
  'brute_force',
  'ddos',
  'web_attack',
  'malware_c2',
  'data_exfiltration',
  'privilege_escalation',
  'recon',
  'benign',
];

const SIGNATURES: Record<AttackType, string[]> = {
  port_scan: [
    'ET SCAN Suricata Nmap SYN Scan Detected',
    'SURICATA PORT_SCAN aggressive sweep',
    'MASSCAN rapid network discovery',
  ],
  brute_force: [
    'ET POLICY SSH Brute Force Attempt (High Frequency)',
    'RDP Authentication Failure Spike',
    'HTTP POST /login Credential Stuffing Pattern',
  ],
  ddos: [
    'SURICATA ANOMALY UDP Flood Volumetric Spike',
    'SYN Flood Rate Threshold Exceeded',
    'HTTP GET Amplification Attack Detected',
  ],
  web_attack: [
    'ET WEB_SERVER SQLi UNION SELECT Injection',
    'XSS Script Payload in Query String',
    'Path Traversal /etc/passwd Attempt',
  ],
  malware_c2: [
    'ET TROJAN Cobalt Strike Beacon DNS Request',
    'AsyncRAT C2 TLS Handshake Fingerprint',
    'RedLine Stealer Exfiltration Callback',
  ],
  data_exfiltration: [
    'LARGE DNS TUNNELING EXFILTRATION DETECTED',
    'AWS S3 Bulk Sync Anomaly (Unusual User-Agent)',
    'Encrypted Archive Export over Non-Standard Port',
  ],
  privilege_escalation: [
    'Windows Event 4672 SeDebugPrivilege Assigned',
    'Linux sudoers file modification',
    'Active Directory Kerberoasting TGS Request',
  ],
  recon: [
    'ET PROBE Active Directory LDAP Enumeration',
    'SMB Session Enumeration from Internal Host',
    'DNS Zone Transfer Request',
  ],
  benign: [
    'HTTP GET /healthcheck normal telemetry',
    'Standard NTP Time Synchronization',
    'DNS Query api.github.com',
  ],
  unknown: ['Anomaly Detected: Uncategorized Flow Traffic'],
};

function randomItem<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomIp(publicOnly = false): string {
  if (publicOnly) {
    return `${Math.floor(Math.random() * 180) + 1.1}.${Math.floor(Math.random() * 254)}.${Math.floor(
      Math.random() * 254,
    )}.${Math.floor(Math.random() * 254)}`;
  }
  const isPrivate = Math.random() > 0.4;
  if (isPrivate) {
    return `10.0.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 250) + 1}`;
  }
  return `${Math.floor(Math.random() * 180) + 1}.${Math.floor(Math.random() * 254)}.${Math.floor(
    Math.random() * 254,
  )}.${Math.floor(Math.random() * 254)}`;
}

let counter = 1000;

export function generateAlertSummary(partial?: Partial<AlertSummary>): AlertSummary {
  counter += 1;
  const attackType = randomItem(ATTACK_TYPES);
  const signature = randomItem(SIGNATURES[attackType]);

  const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const severity = randomItem(severities);

  const statuses: AlertStatus[] = ['classified', 'enriched', 'reasoned', 'done'];
  const status = randomItem(statuses);

  const hasEnrichment = status !== 'classified';
  const hasRemediation = status === 'reasoned' || status === 'done';

  let maxIocScore: number | null = null;
  if (hasEnrichment) {
    maxIocScore = severity === 'critical' ? 85 + Math.random() * 15 : severity === 'high' ? 60 + Math.random() * 30 : Math.floor(Math.random() * 45);
  }

  return {
    id: `alert-${Date.now()}-${counter}`,
    timestamp: new Date().toISOString(),
    status,
    severity,
    confidence: Number((0.75 + Math.random() * 0.24).toFixed(2)),
    attack_type: attackType,
    signature,
    src_ip: randomIp(true),
    dst_ip: randomIp(false),
    src_port: Math.floor(Math.random() * 50000) + 1024,
    dst_port: randomItem([80, 443, 22, 3389, 53, 8080]),
    protocol: randomItem(['TCP', 'UDP', 'ICMP']),
    source: randomItem(['suricata', 'cicids2017']),
    has_enrichment: hasEnrichment,
    has_remediation: hasRemediation,
    max_ioc_score: maxIocScore ? Number(maxIocScore.toFixed(1)) : null,
    ...partial,
  };
}

export function generateAlertDetail(summary?: AlertSummary): AlertDetail {
  const base = summary || generateAlertSummary();

  const iocs: IocVerdict[] = base.has_enrichment
    ? [
        {
          indicator: base.src_ip,
          indicator_type: 'ip',
          score: base.max_ioc_score ?? 45,
          malicious: (base.max_ioc_score ?? 45) >= 50,
          cached: Math.random() > 0.3,
          sources: [
            {
              source: 'abuseipdb',
              raw_score: (base.max_ioc_score ?? 45),
              categories: [base.attack_type || 'recon'],
              last_seen: new Date(Date.now() - 3600000 * 2).toISOString(),
              link: `https://www.abuseipdb.com/check/${base.src_ip}`,
            },
            {
              source: 'virustotal',
              raw_score: Math.max(0, (base.max_ioc_score ?? 45) - 5),
              categories: ['malicious_traffic'],
              last_seen: new Date(Date.now() - 3600000 * 5).toISOString(),
              link: `https://www.virustotal.com/gui/ip-address/${base.src_ip}`,
            },
          ],
        },
      ]
    : [];

  const techniques: MitreTechnique[] = [
    {
      id: 'T1046',
      name: 'Network Service Discovery',
      tactic: 'Discovery',
      url: 'https://attack.mitre.org/techniques/T1046/',
      excerpt: 'Adversaries may attempt to get a listing of services running on remote hosts.',
    },
    {
      id: 'T1110',
      name: 'Brute Force',
      tactic: 'Credential Access',
      url: 'https://attack.mitre.org/techniques/T1110/',
      excerpt: 'Adversaries may use brute force techniques to gain access to accounts.',
    },
  ];

  const steps: RemediationStep[] = [
    {
      order: 1,
      action: `Block source IP ${base.src_ip} at perimeter firewall`,
      detail: `Apply ingress drop rule on edge router for IP ${base.src_ip} across all ports to prevent further probing.`,
      urgency: base.severity === 'critical' || base.severity === 'high' ? 'immediate' : 'soon',
    },
    {
      order: 2,
      action: `Isolate target destination host ${base.dst_ip}`,
      detail: `Isolate host ${base.dst_ip} via EDR endpoint agent to contain potential lateral movement.`,
      urgency: base.severity === 'critical' ? 'immediate' : 'soon',
    },
    {
      order: 3,
      action: 'Rotate compromised service credentials',
      detail: 'Force password reset and invalidate current active API tokens for affected service accounts.',
      urgency: 'monitor',
    },
  ];

  const remediation: Remediation | null = base.has_remediation
    ? {
        summary: `Immediate perimeter block recommended for malicious source IP ${base.src_ip} exhibiting ${base.attack_type} patterns.`,
        steps,
        techniques,
        generated_at: new Date().toISOString(),
        duration_ms: 1450,
      }
    : null;

  const trace: TraceNode[] = [
    {
      node: 'classify',
      status: 'ok',
      provider: 'groq:llama-3.1-8b-instant',
      duration_ms: 240,
      tokens_in: 180,
      tokens_out: 42,
      note: null,
    },
    {
      node: 'enrich',
      status: base.has_enrichment ? 'ok' : 'skipped',
      provider: base.has_enrichment ? 'abuseipdb+virustotal' : null,
      duration_ms: base.has_enrichment ? 1120 : 0,
      tokens_in: null,
      tokens_out: null,
      note: base.has_enrichment ? null : "skipped: severity 'low' below threshold",
    },
    {
      node: 'retrieve',
      status: base.has_enrichment ? 'ok' : 'skipped',
      provider: base.has_enrichment ? 'chroma:mitre-attack-v14' : null,
      duration_ms: base.has_enrichment ? 85 : 0,
      tokens_in: null,
      tokens_out: null,
      note: base.has_enrichment ? null : "retrieval skipped: severity 'low' below threshold",
    },
    {
      node: 'reason',
      status: base.has_remediation ? 'ok' : 'skipped',
      provider: base.has_remediation ? 'gemini:gemini-flash-latest' : null,
      duration_ms: base.has_remediation ? 1850 : 0,
      tokens_in: 840,
      tokens_out: 210,
      note: base.has_remediation ? null : 'reasoning skipped',
    },
    {
      node: 'recommend',
      status: base.has_remediation ? 'ok' : 'skipped',
      provider: base.has_remediation ? 'gemini:gemini-flash-latest' : null,
      duration_ms: base.has_remediation ? 620 : 0,
      tokens_in: 320,
      tokens_out: 140,
      note: base.has_remediation ? null : 'recommendation skipped',
    },
  ];

  return {
    ...base,
    raw: {
      timestamp: base.timestamp,
      flow_id: 948271038,
      src_ip: base.src_ip,
      src_port: base.src_port,
      dest_ip: base.dst_ip,
      dest_port: base.dst_port,
      proto: base.protocol,
      event_type: 'alert',
      alert: {
        action: 'allowed',
        gid: 1,
        signature_id: 2010928,
        signature: base.signature,
        category: base.attack_type,
        severity: base.severity === 'critical' ? 1 : base.severity === 'high' ? 2 : 3,
      },
    },
    reasoning: base.has_remediation
      ? `Analysis indicates ${base.src_ip} initiated high-frequency traffic against ${base.dst_ip}:${base.dst_port}. Threat intel confirms IOC reputation score of ${base.max_ioc_score || 75}/100. Recommend immediate containment.`
      : null,
    enrichment: base.has_enrichment
      ? {
          iocs,
          enriched_at: new Date().toISOString(),
          duration_ms: 1120,
        }
      : null,
    remediation,
    trace,
    total_duration_ms: base.has_remediation ? 3915 : 240,
  };
}

export function seedAlerts(count = 15): AlertDetail[] {
  return Array.from({ length: count }, () => generateAlertDetail());
}

export function generateAlertStats(alerts: AlertSummary[]): AlertStats {
  const by_severity: Partial<Record<Severity, number>> = {};
  const by_attack_type: Record<string, number> = {};
  const by_status: Partial<Record<AlertStatus, number>> = {};
  let malicious_iocs = 0;

  for (const a of alerts) {
    if (a.severity) {
      by_severity[a.severity] = (by_severity[a.severity] || 0) + 1;
    }
    if (a.attack_type) {
      by_attack_type[a.attack_type] = (by_attack_type[a.attack_type] || 0) + 1;
    }
    by_status[a.status] = (by_status[a.status] || 0) + 1;
    if ((a.max_ioc_score ?? 0) >= 50) {
      malicious_iocs += 1;
    }
  }

  const timeline = Array.from({ length: 10 }).map((_, i) => ({
    bucket: new Date(Date.now() - (9 - i) * 60000).toISOString(),
    count: Math.floor(Math.random() * 30) + 5,
    critical: Math.floor(Math.random() * 3),
  }));

  return {
    total: alerts.length,
    by_severity,
    by_attack_type,
    by_status,
    malicious_iocs,
    avg_triage_ms: 840.5,
    alerts_per_min: 42.0,
    timeline,
  };
}

export function generateReplayStatus(): ReplayStatus {
  return {
    state: 'running',
    dataset: 'cicids2017',
    events_per_second: 5.0,
    emitted: 320,
    total: 500,
    queue_depth: { triage: 2, enrich: 4 },
    started_at: new Date(Date.now() - 60000).toISOString(),
    skipped: 12,
  };
}

export function generateEvalReport(sample_size = 200): EvalReport {
  const runNum = Math.floor(1000 + Math.random() * 8999);
  const varPrec = 0.91 + (Math.random() * 0.05 - 0.025);
  const varRec = 0.87 + (Math.random() * 0.05 - 0.025);
  const varAcc = 0.93 + (Math.random() * 0.04 - 0.02);

  return {
    run_id: `eval-run-${runNum}`,
    status: 'completed',
    sample_size,
    started_at: new Date(Date.now() - 45000).toISOString(),
    completed_at: new Date().toISOString(),
    overall: {
      precision: Number(varPrec.toFixed(3)),
      recall: Number(varRec.toFixed(3)),
      f1: Number(((2 * varPrec * varRec) / (varPrec + varRec)).toFixed(3)),
      accuracy: Number(varAcc.toFixed(3)),
    },
    per_class: [
      { label: 'critical', precision: Number((varPrec + 0.03).toFixed(2)), recall: Number((varRec + 0.02).toFixed(2)), f1: 0.93, support: Math.round(sample_size * 0.12) },
      { label: 'high', precision: Number((varPrec - 0.01).toFixed(2)), recall: Number((varRec - 0.02).toFixed(2)), f1: 0.88, support: Math.round(sample_size * 0.22) },
      { label: 'medium', precision: Number((varPrec - 0.03).toFixed(2)), recall: Number((varRec + 0.01).toFixed(2)), f1: 0.87, support: Math.round(sample_size * 0.32) },
      { label: 'low', precision: Number((varPrec + 0.02).toFixed(2)), recall: Number((varRec + 0.03).toFixed(2)), f1: 0.93, support: Math.round(sample_size * 0.24) },
      { label: 'info', precision: Number((varPrec + 0.04).toFixed(2)), recall: Number((varRec + 0.06).toFixed(2)), f1: 0.96, support: Math.round(sample_size * 0.10) },
    ],
    confusion_matrix: {
      labels: ['critical', 'high', 'medium', 'low', 'info'],
      matrix: [
        [Math.round(sample_size * 0.11), 2, 0, 0, 0],
        [2, Math.round(sample_size * 0.19), 3, 0, 0],
        [0, 3, Math.round(sample_size * 0.28), 4, 0],
        [0, 0, 2, Math.round(sample_size * 0.22), 1],
        [0, 0, 0, 1, Math.round(sample_size * 0.09)],
      ],
    },
    attack_type: {
      overall: {
        precision: Number((varPrec - 0.02).toFixed(3)),
        recall: Number((varRec - 0.01).toFixed(3)),
        f1: Number((varPrec - 0.015).toFixed(3)),
        accuracy: Number((varAcc - 0.02).toFixed(3)),
      },
      per_class: [
        { label: 'port_scan', precision: 0.94, recall: 0.92, f1: 0.93, support: Math.round(sample_size * 0.3) },
        { label: 'brute_force', precision: 0.88, recall: 0.85, f1: 0.86, support: Math.round(sample_size * 0.25) },
        { label: 'ddos', precision: 0.95, recall: 0.93, f1: 0.94, support: Math.round(sample_size * 0.25) },
        { label: 'web_attack', precision: 0.82, recall: 0.79, f1: 0.8, support: Math.round(sample_size * 0.2) },
      ],
      confusion_matrix: {
        labels: ['port_scan', 'brute_force', 'ddos', 'web_attack'],
        matrix: [
          [Math.round(sample_size * 0.27), 3, 1, 0],
          [2, Math.round(sample_size * 0.22), 1, 1],
          [0, 1, Math.round(sample_size * 0.23), 1],
          [0, 2, 1, Math.round(sample_size * 0.17)],
        ],
      },
    },
    error: null,
  };
}

export function generateBenchmarkReport(sample_size = 25): BenchmarkReport {
  const runNum = Math.floor(1000 + Math.random() * 8999);
  const agreement = Number((0.84 + Math.random() * 0.08).toFixed(2));
  const fastLat = Math.floor(180 + Math.random() * 60);
  const qualLat = Math.floor(580 + Math.random() * 120);

  const sampleDisagreements = [
    { alert_id: `alert-c2-${runNum}`, signature: 'ET SCAN Suricata Cobalt Strike Beacon', fast_prediction: 'medium', quality_prediction: 'critical', ground_truth: 'critical' },
    { alert_id: `alert-ssh-${runNum}`, signature: 'SSH Brute-Force Auth Anomaly', fast_prediction: 'low', quality_prediction: 'high', ground_truth: 'high' },
    { alert_id: `alert-sql-${runNum}`, signature: 'Web Application SQL Injection Probe', fast_prediction: 'info', quality_prediction: 'medium', ground_truth: 'medium' },
  ];

  return {
    run_id: `bench-run-${runNum}`,
    status: 'completed',
    sample_size,
    results: [
      {
        tier: 'fast',
        provider: 'groq',
        model: 'llama-3.1-8b-instant',
        avg_latency_ms: fastLat,
        p95_latency_ms: fastLat + 160,
        accuracy: Number((0.83 + Math.random() * 0.04).toFixed(2)),
        avg_tokens: 220,
        failures: 0,
        p50_latency_ms: fastLat - 20,
        min_latency_ms: fastLat - 60,
        max_latency_ms: fastLat + 240,
        avg_tokens_in: 180,
        avg_tokens_out: 40,
        attack_type_accuracy: 0.79,
        estimated_cost: 0.0004,
        calls: sample_size,
        warmup_calls: 2,
        throttled: false,
        throttle_retries: 0,
      },
      {
        tier: 'quality',
        provider: 'gemini',
        model: 'gemini-flash-latest',
        avg_latency_ms: qualLat,
        p95_latency_ms: qualLat + 280,
        accuracy: Number((0.93 + Math.random() * 0.04).toFixed(2)),
        avg_tokens: 890,
        failures: 0,
        p50_latency_ms: qualLat - 30,
        min_latency_ms: qualLat - 180,
        max_latency_ms: qualLat + 420,
        avg_tokens_in: 680,
        avg_tokens_out: 210,
        attack_type_accuracy: 0.92,
        estimated_cost: 0.0028,
        calls: sample_size,
        warmup_calls: 2,
        throttled: false,
        throttle_retries: 0,
      },
    ],
    agreement_rate: agreement,
    disagreement_examples: sampleDisagreements,
    error: null,
  };
}
