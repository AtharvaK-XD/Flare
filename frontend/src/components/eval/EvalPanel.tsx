import { useEffect, useRef, useState } from 'react';
import type { EvalReport } from '@/types';
import { motion } from 'framer-motion';
import { fmtPct } from '@/lib/format';
import { Card3D } from '@/components/ui/Card3D';
import { Play } from 'lucide-react';
import { api } from '@/lib/api';

interface EvalPanelProps {
  report?: EvalReport | null;
  onTriggerRun?: () => void;
}

const POLL_INTERVAL_MS = 2000;
//: A 200-alert eval is minutes of live LLM calls. The backend reaps its own runs
//: after RUN_STALE_TIMEOUT_SECONDS and we would see status=failed, so this cap
//: only catches the case where the backend stops answering us entirely.
const POLL_TIMEOUT_MS = 10 * 60 * 1000;

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export function EvalPanel({ report: propsReport, onTriggerRun }: EvalPanelProps) {
  const [target, setTarget] = useState<'severity' | 'attack_type'>('severity');
  const sampleSize = 200;
  const [isRunning, setIsRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [localReport, setLocalReport] = useState<EvalReport | null>(null);

  // Stops the poll loop touching state after the panel goes away.
  const cancelledRef = useRef(false);
  useEffect(() => {
    cancelledRef.current = false;
    return () => {
      cancelledRef.current = true;
    };
  }, []);

  // No fabricated fallback: null means "no run yet" and the panel says so.
  const report = localReport ?? propsReport ?? null;

  /** Poll GET /evaluation/runs/{id} every 2s until the run leaves `running`. */
  const pollUntilDone = async (runId: string) => {
    const deadline = Date.now() + POLL_TIMEOUT_MS;
    while (!cancelledRef.current) {
      const polled = await api.getEvaluationRun(runId);
      if (cancelledRef.current) return;
      // The runner persists partial metrics as it goes, so each poll fills the
      // panel in a little more rather than sitting blank until the end.
      setLocalReport(polled);
      if (polled.status !== 'running') {
        if (polled.status === 'failed') {
          setError(polled.error || 'Evaluation run failed.');
        }
        return;
      }
      if (Date.now() > deadline) {
        setError('Stopped polling: the run did not finish within 10 minutes.');
        return;
      }
      await sleep(POLL_INTERVAL_MS);
    }
  };

  const handleRun = async () => {
    setIsRunning(true);
    setError(null);
    if (onTriggerRun) {
      onTriggerRun();
    }

    try {
      const res = await api.runEvaluation(sampleSize);
      if (!res?.run_id) throw new Error('backend did not return a run_id');
      await pollUntilDone(res.run_id);
    } catch (err) {
      if (!cancelledRef.current) {
        setError(err instanceof Error ? err.message : 'Evaluation failed to start.');
      }
    } finally {
      if (!cancelledRef.current) setIsRunning(false);
    }
  };

  // attack_type is nullable on the wire (EvalRunDetail.attack_type: TargetReport | None),
  // and is genuinely absent on a run that is still `running` or has failed.
  const targetReport = target === 'severity' ? report : report?.attack_type;
  const currentMetrics = targetReport?.overall ?? null;
  const currentPerClass = targetReport?.per_class ?? [];
  const currentConfusion = targetReport?.confusion_matrix ?? null;

  const cards = [
    { label: 'Precision', value: currentMetrics?.precision ?? null, hint: 'flagged threats true positive' },
    { label: 'Recall', value: currentMetrics?.recall ?? null, hint: 'malicious vectors caught' },
    { label: 'F1 Score', value: currentMetrics?.f1 ?? null, hint: 'harmonic mean metric' },
    { label: 'Accuracy', value: currentMetrics?.accuracy ?? null, hint: 'correct overall classifications' },
  ];

  return (
    <Card3D intensity={5} glare={true} className="w-full">
      <motion.div className="glass-panel-3d border border-edge/80 rounded-md shadow-2xl metal-bevel overflow-hidden">
        {/* Header & Target Selector */}
        <header className="px-4 py-3 border-b border-edge/80 bg-void/60 flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-ok shadow-[0_0_8px_#16A34A]" />
            <h2 className="font-mono text-xs font-semibold tracking-[0.16em] text-ink uppercase">
              AI Accuracy & Benchmark Evaluation
            </h2>
            <span className="font-mono text-[10px] text-dim border border-edge/80 px-2 py-0.5 rounded-md bg-void/50">
              {report ? `run: ${report.run_id} (${report.sample_size} samples)` : 'no run yet'}
            </span>
          </div>

          {/* Target Switcher Tabs */}
          <div className="flex items-center gap-2">
            <div className="flex items-center bg-void border border-edge/80 rounded-md p-0.5 font-mono text-[10px]">
              <button
                onClick={() => setTarget('severity')}
                className={`px-2.5 py-1 rounded transition-all cursor-pointer font-bold ${
                  target === 'severity' ? 'bg-raised text-ink shadow' : 'text-dim hover:text-ink'
                }`}
              >
                Severity Target
              </button>
              <button
                onClick={() => setTarget('attack_type')}
                className={`px-2.5 py-1 rounded transition-all cursor-pointer font-bold ${
                  target === 'attack_type' ? 'bg-raised text-ink shadow' : 'text-dim hover:text-ink'
                }`}
              >
                Attack Type Target
              </button>
            </div>

            <button
              onClick={handleRun}
              disabled={isRunning}
              className="font-mono text-[10px] px-3 py-1 bg-sev-low text-ink hover:bg-sev-low/80 disabled:opacity-50 rounded-md transition-all flex items-center gap-1 font-bold cursor-pointer"
            >
              <Play size={10} className={isRunning ? 'animate-spin' : ''} />
              {isRunning ? 'Running Eval...' : 'Run Evaluation'}
            </button>
          </div>
        </header>

        {error && (
          <div className="px-4 py-2 border-b border-sev-critical/40 bg-sev-critical/10 font-mono text-[11px] text-sev-critical">
            {error}
          </div>
        )}

        {!report ? (
          <div className="px-4 py-10 text-center">
            <p className="font-mono text-xs uppercase tracking-[0.16em] text-dim font-bold">No run yet</p>
            <p className="text-[11px] text-dim mt-2 max-w-md mx-auto leading-snug">
              Nothing on this panel is simulated. Press Run Evaluation to score {sampleSize} labeled
              alerts through the live triage graph — metrics fill in as the run progresses.
            </p>
          </div>
        ) : (
          <>
        {/* Overall Accuracy Metrics */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-px bg-edge/80">
          {cards.map((c) => (
            <div key={c.label} className="bg-surface/90 px-4 py-3.5 transition-all hover:bg-raised/80 group">
              <div className="font-mono text-[9px] uppercase tracking-[0.16em] text-dim">{c.label}</div>
              <div className="font-mono text-2xl font-bold text-ink mt-1 tabular-nums group-hover:text-white transition-colors">
                {c.value === null ? '—' : fmtPct(c.value)}
              </div>
              <div className="w-full h-1.5 bg-void border border-edge/80 rounded-sm overflow-hidden mt-2 shadow-inner">
                <div
                  className="h-full bg-sev-low transition-all duration-700 shadow-[0_0_10px_#2563EB] rounded-xs"
                  style={{ width: `${(c.value ?? 0) * 100}%` }}
                />
              </div>
              <div className="text-[10px] text-dim mt-1.5 leading-tight">{c.hint}</div>
            </div>
          ))}
        </div>

        {/* Per-Class Accuracy Breakdown & Confusion Matrix */}
        <div className="p-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Per-Class Metrics Table */}
          <div className="bg-void/40 p-3 border border-edge/60 rounded-md">
            <h3 className="font-mono text-[10px] uppercase tracking-wider text-dim font-bold mb-2 flex items-center justify-between">
              <span>Per-Class Performance ({target.toUpperCase()})</span>
              <span>Support</span>
            </h3>
            <div className="space-y-1.5 font-mono text-[11px]">
              {currentPerClass.length === 0 && (
                <p className="text-dim px-2 py-3">
                  {report.status === 'running' ? 'Scoring in progress…' : 'No per-class metrics.'}
                </p>
              )}
              {currentPerClass.map((cls) => (
                <div key={cls.label} className="flex items-center justify-between p-2 bg-raised/40 border border-edge/40 rounded">
                  <span className="font-bold text-ink uppercase w-28 truncate">{cls.label}</span>
                  <div className="flex items-center gap-3">
                    <span className="text-dim">Prec: <strong className="text-ink">{fmtPct(cls.precision)}</strong></span>
                    <span className="text-dim">Rec: <strong className="text-ink">{fmtPct(cls.recall)}</strong></span>
                    <span className="text-dim">F1: <strong className="text-ink">{fmtPct(cls.f1)}</strong></span>
                    <span className="text-sev-low font-bold">n={cls.support}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Confusion Matrix Heatmap */}
          <div className="bg-void/40 p-3 border border-edge/60 rounded-md overflow-x-auto">
            <h3 className="font-mono text-[10px] uppercase tracking-wider text-dim font-bold mb-2">
              Confusion Matrix Heatmap (rows: pred / cols: actual)
            </h3>

            {currentConfusion ? (
              <div className="inline-block min-w-full">
                <div className="grid gap-1 font-mono text-[10px]" style={{ gridTemplateColumns: `auto repeat(${currentConfusion.labels.length}, 1fr)` }}>
                  <div />
                  {currentConfusion.labels.map((lbl) => (
                    <div key={lbl} className="text-center font-bold text-dim uppercase truncate text-[9px]">
                      {lbl.slice(0, 4)}
                    </div>
                  ))}

                  {currentConfusion.matrix.map((row, rIdx) => (
                    <div key={rIdx} className="contents">
                      <div className="font-bold text-dim uppercase flex items-center justify-end pr-2 text-[9px]">
                        {currentConfusion.labels[rIdx].slice(0, 4)}
                      </div>
                      {row.map((cellVal, cIdx) => {
                        const isDiag = rIdx === cIdx;
                        return (
                          <div
                            key={cIdx}
                            className={`p-2 text-center rounded font-bold ${
                              isDiag
                                ? 'bg-ok/20 text-ok border border-ok/40'
                                : cellVal > 0
                                ? 'bg-sev-critical/20 text-sev-critical border border-sev-critical/40'
                                : 'bg-void text-dim border border-edge/40'
                            }`}
                          >
                            {cellVal}
                          </div>
                        );
                      })}
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p className="font-mono text-xs text-dim">
                {report.status === 'running'
                  ? 'Scoring in progress…'
                  : 'No confusion matrix data available.'}
              </p>
            )}
          </div>
        </div>
          </>
        )}
      </motion.div>
    </Card3D>
  );
}
