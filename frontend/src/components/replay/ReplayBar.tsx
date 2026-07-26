import { Play, Pause, Square, FastForward } from 'lucide-react';
import type { ReplayStatus } from '@/types';
import type { ReplayMode } from '@/hooks/useAlertStream';
import type { ReactNode } from 'react';
import { Card3D } from '@/components/ui/Card3D';

interface ReplayBarProps {
  mode: ReplayMode;
  onModeChange: (m: ReplayMode) => void;
  replayStatus: ReplayStatus;
  alertsPerMin: number;
  totalProcessed: number;
  onStartReplay?: (dataset?: 'cicids2017' | 'suricata', eps?: number) => void;
}

export function ReplayBar({
  mode,
  onModeChange,
  replayStatus,
  alertsPerMin,
  totalProcessed,
  onStartReplay,
}: ReplayBarProps) {
  const emitted = replayStatus.emitted || totalProcessed;
  const total = replayStatus.total;
  const skipped = replayStatus.skipped || 0;
  const progressPct = total ? Math.min(100, Math.round((emitted / total) * 100)) : null;
  const currentDataset = replayStatus.dataset || 'cicids2017';
  const currentEps = replayStatus.events_per_second || 5;

  const handleDatasetChange = (ds: 'cicids2017' | 'suricata') => {
    if (onStartReplay) onStartReplay(ds, currentEps);
  };

  const handleEpsChange = (eps: number) => {
    if (onStartReplay) onStartReplay(currentDataset as 'cicids2017' | 'suricata', eps);
  };

  return (
    <Card3D intensity={5} glare={true} className="w-full">
      <div className="flex items-center gap-3 px-4 py-3 glass-panel-3d rounded-md flex-wrap metal-bevel">
        {/* Play/Pause/Stop control buttons */}
        <div className="flex items-center gap-1.5 bg-void/60 p-1 rounded-md border border-edge/80 shadow-inner">
          <ReplayButton
            active={mode === 'live'}
            onClick={() => onModeChange('live')}
            label="Play live stream"
            variant="live"
          >
            <Play size={13} className={mode === 'live' ? 'fill-current text-ok' : ''} />
          </ReplayButton>
          <ReplayButton
            active={mode === 'paused'}
            onClick={() => onModeChange('paused')}
            label="Pause stream"
            variant="paused"
          >
            <Pause size={13} className={mode === 'paused' ? 'fill-current text-degraded' : ''} />
          </ReplayButton>
          <ReplayButton
            active={mode === 'stopped'}
            onClick={() => onModeChange('stopped')}
            label="Stop and hold"
            variant="stopped"
          >
            <Square size={13} className={mode === 'stopped' ? 'fill-current text-down' : ''} />
          </ReplayButton>
        </div>

        {/* Dataset Selector Dropdown */}
        <div className="flex items-center gap-1 bg-void/60 px-2 py-1 rounded-md border border-edge/80 font-mono text-[10px]">
          <span className="text-dim uppercase text-[9px]">Dataset:</span>
          <select
            value={currentDataset}
            onChange={(e) => handleDatasetChange(e.target.value as 'cicids2017' | 'suricata')}
            className="bg-transparent text-ink font-bold focus:outline-none cursor-pointer"
          >
            <option value="cicids2017" className="bg-slate-900 text-white">CICIDS2017</option>
            <option value="suricata" className="bg-slate-900 text-white">Suricata EVE</option>
          </select>
        </div>

        {/* Stream Speed Buttons */}
        <div className="hidden sm:flex items-center gap-1 bg-void/60 p-1 rounded-md border border-edge/80 font-mono text-[10px]">
          {[5, 10, 20].map((eps) => (
            <button
              key={eps}
              onClick={() => handleEpsChange(eps)}
              className={`px-1.5 py-0.5 rounded transition-colors cursor-pointer font-bold ${
                currentEps === eps ? 'bg-sev-low text-white' : 'text-dim hover:text-white'
              }`}
            >
              {eps}x
            </button>
          ))}
        </div>

        <div className="h-5 w-px bg-edge/80 shadow-sm" />

        {/* State Indicator */}
        <div className="flex items-center gap-2 font-mono text-[11px]">
          <span className="relative flex h-2.5 w-2.5">
            {mode === 'live' && (
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-ok opacity-75" />
            )}
            <span
              className={`relative inline-flex h-2.5 w-2.5 rounded-full shadow-[0_0_8px_currentColor] ${
                mode === 'live'
                  ? 'bg-ok text-ok'
                  : mode === 'paused'
                  ? 'bg-degraded text-degraded'
                  : 'bg-down text-down'
              }`}
            />
          </span>
          <span className={`font-semibold tracking-wider ${mode === 'live' ? 'text-ink' : 'text-dim'}`}>
            {mode === 'live' ? 'STREAMING' : mode === 'paused' ? 'PAUSED' : 'STOPPED'}
          </span>
        </div>

        <div className="h-5 w-px bg-edge/80 shadow-sm" />

        {/* Replay Progress & Throughput */}
        <div className="flex items-center gap-4 font-mono text-[11px]">
          <Metric label="EMITTED" value={emitted.toLocaleString()} />
          {total !== null ? (
            <div className="flex items-center gap-2">
              <Metric label="TOTAL" value={total.toLocaleString()} />
              <div className="w-16 h-1.5 bg-void border border-edge/80 rounded overflow-hidden">
                <div className="h-full bg-sev-low transition-all duration-300" style={{ width: `${progressPct}%` }} />
              </div>
              <span className="text-[10px] text-dim">{progressPct}%</span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 text-dim text-[10px]">
              <span>Progress:</span>
              <div className="w-12 h-1.5 bg-void border border-edge/80 rounded overflow-hidden relative">
                <div className="h-full bg-sev-low animate-pulse w-full" />
              </div>
              <span>Continuous</span>
            </div>
          )}
          <Metric label="SKIPPED" value={skipped.toString()} />
          <Metric label="/MIN (30m AVG)" value={String(alertsPerMin)} accent={alertsPerMin > 8 ? 'text-sev-high' : undefined} />
        </div>

        <div className="h-5 w-px bg-edge/80 hidden sm:block shadow-sm" />

        {/* Queue Backlog Meters */}
        <div className="flex items-center gap-3 font-mono text-[11px]">
          <span className="text-dim text-[10px] tracking-wider uppercase">BACKLOG</span>
          <QueueMeter label="triage" value={replayStatus.queue_depth?.triage ?? 0} max={20} />
          <QueueMeter label="enrich" value={replayStatus.queue_depth?.enrich ?? 0} max={20} warn />
        </div>

        <div className="ml-auto hidden md:flex items-center gap-1.5 font-mono text-[10px] text-dim">
          <FastForward size={12} className="text-sev-low animate-pulse-soft" />
          <span>Enrichment worker is rate-capped at 1 worker (AbuseIPDB/VT caps)</span>
        </div>
      </div>
    </Card3D>
  );
}

function ReplayButton({
  active,
  onClick,
  label,
  variant,
  children,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  variant: 'live' | 'paused' | 'stopped';
  children: ReactNode;
}) {
  const activeClass =
    variant === 'live'
      ? 'border-ok/60 bg-ok/15 text-ink shadow-[0_0_12px_rgba(22,163,74,0.3)]'
      : variant === 'paused'
      ? 'border-degraded/60 bg-degraded/15 text-ink shadow-[0_0_12px_rgba(217,119,6,0.3)]'
      : 'border-down/60 bg-down/15 text-ink shadow-[0_0_12px_rgba(220,38,38,0.3)]';

  return (
    <button
      onClick={onClick}
      aria-label={label}
      aria-pressed={active}
      className={`p-1.5 rounded-md border transition-all duration-200 cursor-pointer ${
        active ? activeClass : 'border-transparent text-dim hover:text-ink hover:bg-raised/60'
      }`}
    >
      {children}
    </button>
  );
}

function Metric({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-dim text-[10px]">{label}</span>
      <span className={`font-semibold tabular-nums ${accent || 'text-ink'}`}>{value}</span>
    </div>
  );
}

function QueueMeter({ label, value, max, warn }: { label: string; value: number; max: number; warn?: boolean }) {
  const pct = Math.min(100, Math.round((value / max) * 100));
  const isHigh = value > 5;
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-dim text-[10px] uppercase">{label}</span>
      <span className={`font-semibold tabular-nums text-[10px] ${isHigh && warn ? 'text-sev-high font-bold' : 'text-ink'}`}>
        {value}
      </span>
      <div className="w-8 h-1 bg-void border border-edge/80 rounded-xs overflow-hidden">
        <div
          className={`h-full transition-all duration-300 ${
            isHigh && warn ? 'bg-sev-high' : 'bg-sev-low'
          }`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}
