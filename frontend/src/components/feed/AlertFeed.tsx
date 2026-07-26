import { useEffect, useMemo, useRef, useState } from 'react';
import type { AlertSummary, Severity } from '@/types';
import {
  SEVERITY_FLASH_ANIM,
  SEVERITY_HEX_CLASS,
  SEVERITY_TEXT,
  STATUS_LABELS,
} from '@/types';
import { Card3D } from '@/components/ui/Card3D';
import { Zap } from 'lucide-react';
import { InjectAlertModal } from '@/components/feed/InjectAlertModal';

interface AlertFeedProps {
  alerts: AlertSummary[];
  onSelect: (alert: AlertSummary) => void;
  selectedId?: string;
  filters: FeedFilters;
  onFiltersChange: (f: FeedFilters) => void;
  onInjectCustomAlert?: (body: { signature: string; src_ip: string; dst_ip: string; dst_port?: number; protocol?: string }) => void;
}

export interface FeedFilters {
  severities: Set<Severity>;
}

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_BAR: Record<Severity, string> = {
  critical: 'bg-sev-critical shadow-[0_0_10px_#DC2626]',
  high: 'bg-sev-high shadow-[0_0_10px_#EA580C]',
  medium: 'bg-sev-medium shadow-[0_0_10px_#D97706]',
  low: 'bg-sev-low shadow-[0_0_10px_#2563EB]',
  info: 'bg-sev-info shadow-[0_0_10px_#6B7280]',
};

export function AlertFeed({ alerts, onSelect, selectedId, filters, onFiltersChange, onInjectCustomAlert }: AlertFeedProps) {
  const [seenIds, setSeenIds] = useState<Set<string>>(new Set());
  const [injectOpen, setInjectOpen] = useState(false);
  const prevIdsRef = useRef<Set<string>>(new Set());

  useEffect(() => {
    const currentIds = new Set(alerts.map((a) => a.id));
    const fresh = new Set<string>();
    for (const id of currentIds) {
      if (!prevIdsRef.current.has(id)) fresh.add(id);
    }
    if (fresh.size > 0) {
      setSeenIds((prev) => {
        const merged = new Set([...prev, ...fresh]);
        if (merged.size <= 200) return merged;
        return new Set([...merged].slice(-150));
      });
    }
    prevIdsRef.current = currentIds;
  }, [alerts]);

  const filtered = useMemo(
    () => alerts.filter((a) => !a.severity || filters.severities.has(a.severity)),
    [alerts, filters],
  );

  const toggleSev = (sev: Severity) => {
    const next = new Set(filters.severities);
    if (next.has(sev)) next.delete(sev);
    else next.add(sev);
    if (next.size === 0) {
      onFiltersChange({ severities: new Set(SEV_ORDER) });
    } else {
      onFiltersChange({ severities: next });
    }
  };

  return (
    <Card3D intensity={4} glare={true} className="w-full h-full">
      <div className="flex flex-col h-full glass-panel-3d rounded-md overflow-hidden shadow-2xl border border-edge/80 metal-bevel">
        {/* Modal for Custom Inject Alert */}
        <InjectAlertModal isOpen={injectOpen} onClose={() => setInjectOpen(false)} onInjectCustomAlert={onInjectCustomAlert} />

        {/* header / filter chips */}
        <div className="flex items-center justify-between gap-2 px-4 py-3 border-b border-edge/80 bg-void/60 flex-wrap">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-sev-low animate-pulse-soft shadow-[0_0_8px_#2563EB]" />
            <h2 className="font-mono text-xs font-semibold tracking-[0.16em] text-ink uppercase">
              Live Threat Telemetry Stream
            </h2>
            <span className="font-mono text-[10px] px-2 py-0.5 bg-raised/80 text-dim border border-edge/80 rounded-md font-medium shadow-inner">
              {filtered.length} active alerts
            </span>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => setInjectOpen(true)}
              className="font-mono text-[10px] px-3 py-1 bg-red-500/15 border border-red-500/40 text-red-400 hover:bg-red-500/25 rounded-md transition-all font-bold cursor-pointer flex items-center gap-1.5 shadow-[0_0_12px_rgba(239,68,68,0.2)]"
            >
              <Zap size={11} className="text-red-400" />
              <span>Inject Alert</span>
            </button>

            <div className="flex items-center gap-1.5">
              {SEV_ORDER.map((sev) => {
                const active = filters.severities.has(sev);
                return (
                  <button
                    key={sev}
                    onClick={() => toggleSev(sev)}
                    aria-pressed={active}
                    className={`font-mono text-[10px] uppercase tracking-wider px-2.5 py-1 border rounded-md transition-all duration-200 cursor-pointer ${
                      active
                        ? 'border-edge-bright text-ink bg-raised/90 shadow-md font-semibold translate-z-1'
                        : 'border-transparent text-dim hover:text-ink hover:bg-raised/40'
                    }`}
                  >
                    <span className={`inline-block h-1.5 w-1.5 rounded-full mr-1.5 align-middle ${SEV_BAR[sev]}`} />
                    {SEVERITY_TEXT[sev]}
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* column headers */}
        <div className="grid grid-cols-[130px_90px_1fr_140px_120px_90px] gap-2 px-4 py-2 border-b border-edge/80 font-mono text-[9px] uppercase tracking-[0.14em] text-dim bg-void/80 shadow-inner">
          <span>Timestamp</span>
          <span>Severity</span>
          <span>Attack Vector / IP flow</span>
          <span className="hidden lg:block">IOC Score</span>
          <span className="hidden md:block">Pipeline Status</span>
          <span className="text-right">Confidence</span>
        </div>

        {/* rows */}
        <div className="flex-1 overflow-y-auto divide-y divide-edge/40">
          {filtered.length === 0 ? (
            <div className="px-4 py-16 text-center">
              <p className="font-mono text-xs text-dim">
                No alerts matching filter — toggle a severity chip above.
              </p>
            </div>
          ) : (
            filtered.map((alert) => {
              const isFresh = seenIds.has(alert.id);
              const isSelected = selectedId === alert.id;
              const confPct = alert.confidence !== null ? Math.round(alert.confidence * 100) : 0;
              const severityKey = alert.severity || 'info';

              const isEscalated = (alert.max_ioc_score ?? 0) >= 80 && alert.severity === 'high';

              return (
                <button
                  key={alert.id}
                  onClick={() => onSelect(alert)}
                  className={`relative w-full text-left grid grid-cols-[130px_90px_1fr_140px_120px_90px] gap-2 px-4 py-3 transition-all duration-200 group cursor-pointer hover:bg-raised/90 ${
                    isSelected
                      ? 'bg-raised/95 border-l-2 border-l-sev-low shadow-[inset_0_0_20px_rgba(37,99,235,0.15)]'
                      : ''
                  } ${isFresh ? 'animate-row-enter' : ''}`}
                >
                  {/* severity bar */}
                  <span
                    className={`absolute left-0 top-0 bottom-0 w-[4px] transition-all group-hover:w-[6px] ${
                      SEV_BAR[severityKey]
                    }`}
                    aria-hidden
                  />
                  {/* flash overlay */}
                  {isFresh && (
                    <span
                      className={`absolute left-[4px] top-0 bottom-0 right-0 ${SEV_BAR[severityKey]} ${SEVERITY_FLASH_ANIM[severityKey]} pointer-events-none`}
                      aria-hidden
                      onAnimationEnd={() =>
                        setSeenIds((prev) => {
                          const n = new Set(prev);
                          n.delete(alert.id);
                          return n;
                        })
                      }
                    />
                  )}

                  {/* Timestamp */}
                  <span className="font-mono text-[10px] text-dim tabular-nums truncate my-auto">
                    {alert.timestamp.includes('T') ? alert.timestamp.split('T')[1].replace('Z', '') : alert.timestamp}
                  </span>

                  {/* Severity */}
                  <div className="my-auto">
                    {alert.severity ? (
                      <span className={`font-mono text-[11px] font-bold ${SEVERITY_HEX_CLASS[alert.severity]}`}>
                        {SEVERITY_TEXT[alert.severity]}
                      </span>
                    ) : (
                      <span className="font-mono text-[10px] text-dim animate-pulse">CLASSIFYING...</span>
                    )}
                  </div>

                  {/* Attack Type & IP Flow */}
                  <span className="min-w-0 my-auto">
                    <span className="block text-[13px] text-ink truncate font-semibold group-hover:text-white transition-colors">
                      {alert.attack_type || alert.signature}
                    </span>
                    <span className="block font-mono text-[10px] text-dim truncate">
                      {alert.src_ip} → {alert.dst_ip}:{alert.dst_port || '80'} / {alert.protocol || 'TCP'}
                    </span>
                  </span>

                  {/* Max IOC Score */}
                  <span className="hidden lg:flex items-center gap-1.5 font-mono text-[11px] my-auto">
                    {alert.max_ioc_score !== null ? (
                      <span
                        className={`px-2 py-0.5 rounded-md text-[10px] font-bold border shadow-inner flex items-center gap-1 ${
                          alert.max_ioc_score >= 80
                            ? 'bg-sev-critical/20 text-sev-critical border-sev-critical/50 shadow-[0_0_10px_rgba(220,38,38,0.3)]'
                            : alert.max_ioc_score >= 50
                            ? 'bg-sev-high/20 text-sev-high border-sev-high/40'
                            : 'bg-void text-dim border-edge/60'
                        }`}
                      >
                        {isEscalated && <Zap size={10} className="animate-bounce" />}
                        {alert.max_ioc_score} / 100
                      </span>
                    ) : alert.has_enrichment ? (
                      <span className="text-[10px] text-dim">0 / 100</span>
                    ) : (
                      <span className="text-[10px] text-dim italic">Pending</span>
                    )}
                  </span>

                  {/* Pipeline Status */}
                  <span className="hidden md:flex items-center gap-1 font-mono text-[10px] uppercase tracking-wider my-auto">
                    <span
                      className={`px-1.5 py-0.5 rounded font-semibold text-[9px] border ${
                        alert.status === 'done'
                          ? 'bg-ok/10 text-ok border-ok/30'
                          : alert.status === 'failed'
                          ? 'bg-sev-critical/10 text-sev-critical border-sev-critical/30'
                          : alert.status === 'reasoned' || alert.status === 'enriched'
                          ? 'bg-sev-low/10 text-sev-low border-sev-low/30'
                          : 'bg-raised text-dim border-edge/60'
                      }`}
                    >
                      {STATUS_LABELS[alert.status]}
                    </span>
                  </span>

                  {/* AI Confidence Bar */}
                  <div className="flex flex-col items-end justify-center my-auto font-mono">
                    <span className="text-[11px] text-ink font-bold tabular-nums">
                      {confPct > 0 ? `${confPct}%` : '—'}
                    </span>
                    <div className="w-14 h-1.5 bg-void border border-edge/80 rounded-sm overflow-hidden mt-1 shadow-inner">
                      <div
                        className={`h-full transition-all duration-500 rounded-xs shadow-[0_0_6px_currentColor] ${
                          confPct > 80
                            ? 'bg-ok text-ok'
                            : confPct > 60
                            ? 'bg-sev-medium text-sev-medium'
                            : 'bg-sev-critical text-sev-critical'
                        }`}
                        style={{ width: `${confPct}%` }}
                      />
                    </div>
                  </div>
                </button>
              );
            })
          )}
        </div>
      </div>
    </Card3D>
  );
}
