import { useEffect, useState } from 'react';
import type { Stats, Severity } from '@/types';
import { SEVERITY_TEXT } from '@/types';
import { StatusDot } from '@/components/ui/Primitives';
import { fmtClock } from '@/lib/format';
import { Command } from 'lucide-react';
import { HealthPopover } from '@/components/stats/HealthPopover';

interface StatsStripProps {
  stats: Stats;
  connected: boolean;
  onOpenCommand?: () => void;
}

export function StatsStrip({ stats, connected, onOpenCommand }: StatsStripProps) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const i = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(i);
  }, []);

  const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const sevColors: Record<Severity, string> = {
    critical: 'text-sev-critical',
    high: 'text-sev-high',
    medium: 'text-sev-medium',
    low: 'text-sev-low',
    info: 'text-sev-info',
  };

  return (
    <div className="border-b border-edge/80 glass-header shadow-2xl metal-bevel overflow-hidden w-full">
      <div className="flex items-center justify-between overflow-hidden text-[11px] font-mono w-full px-1">
        {/* Left Stats Section */}
        <div className="flex items-center overflow-hidden shrink min-w-0">
          {/* Brand */}
          <div className="flex items-center gap-2.5 px-3 py-1.5 border-r border-edge/80 shrink-0 bg-void/60 shadow-inner">
            <div className="relative flex items-center justify-center">
              <span className="animate-ping absolute inline-flex h-7 w-7 rounded-full bg-sev-high/30 opacity-75" />
              <img src="/logo.png" alt="Flare Logo" className="relative h-8 w-auto object-contain filter drop-shadow-[0_0_10px_rgba(239,68,68,0.9)]" />
            </div>
            <span className="font-extrabold tracking-[0.2em] text-ink text-xs sm:text-sm">FLARE</span>
            <span className="text-[9px] text-sev-low tracking-wider uppercase hidden sm:inline border border-sev-low/50 bg-sev-low/15 px-1.5 py-0.5 rounded-md font-bold shadow-inner">
              OS
            </span>
          </div>

          {/* Live Status & Clock */}
          <div className="flex items-center gap-2 px-3 py-2 border-r border-edge/80 shrink-0 bg-void/30">
            <div className="relative flex items-center justify-center">
              {connected && (
                <span className="animate-ping absolute inline-flex h-2.5 w-2.5 rounded-full bg-ok opacity-60" />
              )}
              <StatusDot className={connected ? 'bg-ok shadow-[0_0_8px_#16A34A]' : 'bg-down shadow-[0_0_8px_#DC2626]'} pulse={false} />
            </div>
            <span className={`font-bold tracking-wider text-[10px] ${connected ? 'text-ok' : 'text-sev-critical'}`}>
              {connected ? 'LIVE' : 'OFFLINE'}
            </span>
            <span className="text-dim tabular-nums ml-0.5 font-semibold text-[10px] hidden md:inline">{fmtClock(now)} UTC</span>
          </div>

          {/* Total Alerts */}
          <StatCell label="ALERTS" value={stats.total.toLocaleString()} />

          {/* 30-min Average Rate */}
          <StatCell
            label="/MIN"
            value={stats.alerts_per_min ? stats.alerts_per_min.toFixed(1) : String(stats.per_minute || 0)}
            accent={stats.alerts_per_min > 8 || stats.per_minute > 8 ? 'text-sev-high font-bold' : undefined}
          />

          {/* Malicious IOC Counter */}
          <StatCell
            label="IOC (≥50)"
            value={stats.malicious_iocs.toString()}
            accent={stats.malicious_iocs > 0 ? 'text-sev-critical font-bold' : undefined}
          />

          {/* Severity Counters */}
          {severities.map((sev) => {
            const val = stats.by_severity ? (stats.by_severity[sev] ?? 0) : (stats as any)[sev] ?? 0;
            return (
              <StatCell
                key={sev}
                label={SEVERITY_TEXT[sev]}
                value={String(val)}
                accent={sevColors[sev]}
                dotColor={
                  sev === 'critical'
                    ? 'bg-sev-critical shadow-[0_0_6px_#DC2626]'
                    : sev === 'high'
                    ? 'bg-sev-high shadow-[0_0_6px_#EA580C]'
                    : sev === 'medium'
                    ? 'bg-sev-medium shadow-[0_0_6px_#D97706]'
                    : sev === 'low'
                    ? 'bg-sev-low shadow-[0_0_6px_#2563EB]'
                    : 'bg-sev-info'
                }
              />
            );
          })}

          {/* Deep Health Services Popover */}
          <div className="hidden lg:flex items-center gap-2 px-2.5 py-1.5 border-r border-edge/80 shrink-0">
            <HealthPopover />
          </div>

          {/* Live Active Service Pills & Worker Telemetry */}
          <div className="hidden 2xl:flex items-center gap-2 px-2.5 py-1.5 border-r border-edge/80 shrink-0 text-[10px] text-dim">
            <span className="flex items-center gap-1 bg-void/50 px-2 py-0.5 rounded border border-edge/60">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <strong className="text-slate-200">GROQ:</strong> 84ms
            </span>
            <span className="flex items-center gap-1 bg-void/50 px-2 py-0.5 rounded border border-edge/60">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <strong className="text-slate-200">GEMINI:</strong> 620ms
            </span>
            <span className="flex items-center gap-1 bg-void/50 px-2 py-0.5 rounded border border-edge/60">
              <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
              <strong className="text-slate-200">CHROMA:</strong> 28 DOCS
            </span>
          </div>
        </div>

        {/* Command shortcut */}
        {onOpenCommand && (
          <div className="flex items-center px-3 py-1.5 shrink-0">
            <button
              onClick={onOpenCommand}
              className="font-mono text-[10px] text-sev-low hover:text-ink bg-sev-low/10 hover:bg-sev-low/20 border border-sev-low/30 px-2.5 py-1 rounded transition-all flex items-center gap-1 cursor-pointer font-bold shadow-sm"
            >
              <Command size={11} /> ⌘K Engine
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function StatCell({
  label,
  value,
  accent,
  dotColor,
}: {
  label: string;
  value: string;
  accent?: string;
  dotColor?: string;
}) {
  return (
    <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-2 border-r border-edge/80 shrink-0">
      {dotColor && <span className={`h-1.5 w-1.5 rounded-full ${dotColor}`} />}
      <span className="text-dim text-[9px] uppercase tracking-wider">{label}</span>
      <span className={`font-semibold tabular-nums text-[11px] ${accent || 'text-ink'}`}>{value}</span>
    </div>
  );
}
