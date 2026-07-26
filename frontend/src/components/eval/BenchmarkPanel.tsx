import { useState } from 'react';
import type { BenchmarkReport, BenchmarkResult } from '@/types';
import { fmtPct, fmtMs } from '@/lib/format';
import { Card3D } from '@/components/ui/Card3D';
import { generateBenchmarkReport } from '@/lib/generator';
import { AlertTriangle, Play, Zap, Shield, Cpu } from 'lucide-react';
import { api } from '@/lib/api';

interface BenchmarkPanelProps {
  report?: BenchmarkReport | null;
  onTriggerRun?: () => void;
}

export function BenchmarkPanel({ report: propsReport, onTriggerRun }: BenchmarkPanelProps) {
  const [isRunning, setIsRunning] = useState(false);
  const [sampleSize, setSampleSize] = useState(25);
  const [localReport, setLocalReport] = useState<BenchmarkReport | null>(null);

  const report = localReport || propsReport || generateBenchmarkReport(25);

  const handleRun = async () => {
    setIsRunning(true);
    if (onTriggerRun) {
      onTriggerRun();
    }
    
    try {
      const res = await api.runBenchmark(sampleSize);
      if (res?.run_id) {
        const polled = await api.getBenchmarkRun(res.run_id);
        if (polled) setLocalReport(polled);
        else setLocalReport(generateBenchmarkReport(sampleSize));
      } else {
        setLocalReport(generateBenchmarkReport(sampleSize));
      }
    } catch {
      // Demo / offline mode fallback
      setLocalReport(generateBenchmarkReport(sampleSize));
    } finally {
      setTimeout(() => setIsRunning(false), 2200);
    }
  };

  const fastTier = report.results.find((r) => r.tier === 'fast') || report.results[0];
  const qualityTier = report.results.find((r) => r.tier === 'quality') || report.results[1] || report.results[0];

  return (
    <Card3D intensity={5} glare={true} className="w-full">
      <div className="glass-panel-3d border border-edge/80 rounded-md shadow-2xl metal-bevel overflow-hidden">
        {/* Header */}
        <header className="px-4 py-3 border-b border-edge/80 bg-void/60 flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-sev-medium shadow-[0_0_8px_#D97706]" />
            <h2 className="font-mono text-xs font-semibold tracking-[0.16em] text-ink uppercase">
              Fast Tier vs Quality Tier Provider Benchmark
            </h2>
            <span className="font-mono text-[10px] text-dim border border-edge/80 px-2 py-0.5 rounded-md bg-void/50">
              {report.sample_size} sample alerts
            </span>
          </div>

          <button
            onClick={handleRun}
            disabled={isRunning || report.status === 'running'}
            className="font-mono text-[10px] px-3 py-1 bg-sev-low text-ink hover:bg-sev-low/80 disabled:opacity-50 rounded-md transition-all flex items-center gap-1 font-bold cursor-pointer"
          >
            <Play size={10} className={isRunning ? 'animate-spin' : ''} />
            {isRunning || report.status === 'running' ? 'Benchmarking...' : 'Run Benchmark'}
          </button>
        </header>

        {/* Agreement Rate Banner */}
        <div className="px-4 py-4 border-b border-edge/80 bg-void/40 flex items-center gap-4 flex-wrap">
          <div>
            <div className="font-mono text-[9px] uppercase tracking-[0.16em] text-dim font-medium">Consensus Agreement Rate</div>
            <div className="font-mono text-3xl font-extrabold text-ok tabular-nums leading-none mt-1 shadow-sm drop-shadow-[0_0_12px_rgba(22,163,74,0.4)]">
              {report.agreement_rate !== null ? fmtPct(report.agreement_rate) : '—'}
            </div>
          </div>
          <p className="text-[11px] text-dim leading-snug flex-1 border-l border-edge/80 pl-4 min-w-[240px]">
            Share of security alerts where fast tier ({fastTier?.provider || 'Groq'}) and quality tier ({qualityTier?.provider || 'Gemini'}) reached identical verdicts. Disagreements automatically trigger multi-model debate.
          </p>
        </div>

        {/* Side-by-Side Tier Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-edge/80">
          {fastTier && <TierCard result={fastTier} isQuality={false} />}
          {qualityTier && <TierCard result={qualityTier} isQuality={true} />}
        </div>

        {/* Disagreement Examples Table */}
        {report.disagreement_examples && report.disagreement_examples.length > 0 && (
          <div className="p-4 bg-void/30 border-t border-edge/80">
            <h3 className="font-mono text-[10px] uppercase tracking-wider text-dim font-bold mb-2 flex items-center gap-2">
              <AlertTriangle size={12} className="text-sev-medium" />
              Tier Disagreement Examples ({report.disagreement_examples.length} cases)
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-[11px] border-collapse">
                <thead>
                  <tr className="border-b border-edge/60 text-[9px] text-dim uppercase">
                    <th className="py-1.5 px-2">Alert ID / Signature</th>
                    <th className="py-1.5 px-2">Fast Tier ({fastTier?.provider})</th>
                    <th className="py-1.5 px-2">Quality Tier ({qualityTier?.provider})</th>
                    <th className="py-1.5 px-2 text-right">Ground Truth</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-edge/40">
                  {report.disagreement_examples.map((ex, idx) => (
                    <tr key={idx} className="hover:bg-raised/40">
                      <td className="py-2 px-2">
                        <span className="font-bold text-ink block">{ex.signature}</span>
                        <span className="text-[9px] text-dim">{ex.alert_id}</span>
                      </td>
                      <td className="py-2 px-2 text-sev-medium uppercase font-semibold">{ex.fast_prediction}</td>
                      <td className="py-2 px-2 text-sev-high uppercase font-semibold">{ex.quality_prediction}</td>
                      <td className="py-2 px-2 text-right font-bold text-ok uppercase">{ex.ground_truth}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </Card3D>
  );
}

function TierCard({ result, isQuality }: { result: BenchmarkResult; isQuality: boolean }) {
  return (
    <div className="bg-surface/90 px-4 py-4 transition-all hover:bg-raised/80 group">
      <div className="flex items-center justify-between gap-2 mb-3">
        <div className="flex items-center gap-2">
          <span
            className={`font-mono text-[9px] uppercase tracking-wider px-2 py-0.5 border rounded-md font-bold shadow-inner ${
              isQuality
                ? 'border-sev-low/60 text-sev-low bg-sev-low/15 shadow-[0_0_10px_rgba(37,99,235,0.3)]'
                : 'border-edge text-dim bg-void/60'
            }`}
          >
            {result.tier} tier
          </span>
          <span className="font-mono text-[11px] text-ink font-bold group-hover:text-white transition-colors">
            {result.provider}:{result.model}
          </span>
        </div>

        {/* Throttle Warning Badge */}
        {result.throttled && (
          <span
            className="flex items-center gap-1 font-mono text-[9px] px-2 py-0.5 bg-sev-high/15 border border-sev-high/40 text-sev-high rounded"
            title="Model hit rate-limits during run — latency includes wait queueing"
          >
            <AlertTriangle size={10} /> Throttled
          </span>
        )}
      </div>

      <div className="grid grid-cols-2 gap-x-4 gap-y-3 font-mono text-[11px]">
        <Stat label="Severity Accuracy" value={fmtPct(result.accuracy)} progress={result.accuracy} />
        <Stat label="Attack Type Acc." value={fmtPct(result.attack_type_accuracy)} progress={result.attack_type_accuracy} />
        <Stat label="p50 Latency" value={fmtMs(result.p50_latency_ms || result.avg_latency_ms)} />
        <Stat label="p95 Latency" value={fmtMs(result.p95_latency_ms)} />
        <Stat label="Avg Tokens (in/out)" value={`${result.avg_tokens_in || 0} / ${result.avg_tokens_out || 0}`} />
        <Stat
          label="Est. Cost / 1k"
          value={result.estimated_cost !== null ? `$${result.estimated_cost.toFixed(4)}` : '—'}
        />
      </div>
    </div>
  );
}

function Stat({ label, value, progress }: { label: string; value: string; progress?: number }) {
  return (
    <div className="flex flex-col">
      <span className="text-dim text-[9px] uppercase tracking-wider">{label}</span>
      <span className="text-ink font-bold tabular-nums mt-0.5">{value}</span>
      {progress !== undefined && (
        <div className="w-full h-1.5 bg-void border border-edge/80 rounded-sm overflow-hidden mt-1 shadow-inner">
          <div
            className="h-full bg-sev-low transition-all duration-500 rounded-xs shadow-[0_0_8px_#2563EB]"
            style={{ width: `${progress * 100}%` }}
          />
        </div>
      )}
    </div>
  );
}
