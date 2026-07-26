import { useMemo, useState, useEffect, useCallback } from 'react';
import type { AlertDetail, AlertSummary, Severity } from '@/types';
import { useAlertStream } from '@/hooks/useAlertStream';
import { StatsStrip } from '@/components/stats/StatsStrip';
import { LandingPage } from '@/components/ui/LandingPage';
import { AlertFeed, type FeedFilters } from '@/components/feed/AlertFeed';
import { ReplayBar } from '@/components/replay/ReplayBar';
import { AlertDrawer } from '@/components/drawer/AlertDrawer';
import { EvalPanel } from '@/components/eval/EvalPanel';
import { BenchmarkPanel } from '@/components/eval/BenchmarkPanel';
import { CommandBar } from '@/components/ui/CommandBar';
import { BackgroundStars } from '@/components/ui/BackgroundStars';
import { motion, AnimatePresence } from 'framer-motion';
import { Sparkles, Info } from 'lucide-react';

const ALL_SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export default function App() {
  const {
    alerts,
    stats,
    connected,
    mode,
    setReplayMode,
    startReplay,
    replayStatus,
    fetchAlertDetail,
    pushCustomAlert,
    isLiveApi,
    systemNotice,
  } = useAlertStream();

  const [selectedSummary, setSelectedSummary] = useState<AlertSummary | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<AlertDetail | null>(null);
  const [commandOpen, setCommandOpen] = useState(false);
  const [showLanding, setShowLanding] = useState(true);
  const [filters, setFilters] = useState<FeedFilters>({
    severities: new Set(ALL_SEVERITIES),
  });

  // Fetch full detail when an alert is selected
  const handleSelectAlert = useCallback(
    async (summary: AlertSummary) => {
      setSelectedSummary(summary);
      const detail = await fetchAlertDetail(summary.id);
      if (detail) {
        setSelectedDetail(detail);
      } else {
        // Fallback to basic object if detail not found
        setSelectedDetail(summary as AlertDetail);
      }
    },
    [fetchAlertDetail],
  );

  // Global Cmd+K or Ctrl+K keyboard shortcut
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setCommandOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const sortedAlerts = useMemo(
    () => [...alerts].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()),
    [alerts],
  );

  return (
    <div className="min-h-screen bg-void text-ink grid-noise relative">
      <BackgroundStars />

      {/* Terminal status line */}
      <div className="sticky top-0 z-30">
        <StatsStrip stats={stats} connected={connected} onOpenCommand={() => setCommandOpen(true)} />
      </div>

      {/* System Notice Toast */}
      {systemNotice && (
        <div className="fixed top-12 right-6 z-50 font-mono text-xs px-4 py-2 rounded-md bg-slate-900 border border-sev-low text-ink shadow-2xl flex items-center gap-2">
          <Info size={14} className="text-sev-low" />
          <span>{systemNotice.message}</span>
        </div>
      )}

      <AnimatePresence mode="wait">
        {showLanding ? (
          <LandingPage
            key="landing"
            onEnter={() => setShowLanding(false)}
            alerts={sortedAlerts}
            connected={connected}
          />
        ) : (
          <motion.div
            key="dashboard"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.8 }}
            className="relative z-10"
          >
            <motion.section
              className="relative border-b border-edge overflow-hidden"
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, ease: 'easeOut' }}
            >
              <div className="absolute inset-0 bg-gradient-to-b from-void/0 via-void/0 to-void pointer-events-none" />
              <div className="max-w-[1400px] mx-auto px-4 lg:px-6 pt-6 pb-2">
                <div className="flex items-end justify-between gap-4 mb-3 flex-wrap">
                  <div>
                    <div className="flex items-center gap-3 mb-1">
                      <img
                        src="/logo.png"
                        alt="Flare Logo"
                        className="h-8 w-auto object-contain filter drop-shadow-[0_0_10px_rgba(239,68,68,0.9)]"
                      />
                      <span className="font-mono text-sm font-semibold tracking-[0.2em] text-ink uppercase">
                        Nexus Intelligence Engine
                      </span>
                      <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-raised border border-edge text-dim">
                        {isLiveApi ? 'FastAPI + LangGraph (Live)' : 'Offline Stand-in Mode'}
                      </span>
                      <button
                        onClick={() => setCommandOpen(true)}
                        className="font-mono text-[10px] text-sev-low bg-sev-low/10 border border-sev-low/30 hover:border-sev-low px-2 py-0.5 rounded-full transition-all flex items-center gap-1 shadow-sm cursor-pointer"
                      >
                        <Sparkles size={11} /> ⌘K Command Engine
                      </button>
                    </div>
                    <p className="text-[13px] text-dim mt-1 max-w-xl leading-snug">
                      Real-time security telemetry flow. Progressive triage pipeline with threat intel override & MITRE ATT&CK RAG grounding.
                    </p>
                  </div>
                  <div className="flex items-center gap-4 font-mono text-[10px] uppercase tracking-wider text-dim">
                    <LegendItem color="bg-sev-critical" label="critical" />
                    <LegendItem color="bg-sev-high" label="high" />
                    <LegendItem color="bg-sev-medium" label="medium" />
                    <LegendItem color="bg-sev-low" label="low" />
                    <LegendItem color="bg-sev-info" label="info" />
                  </div>
                </div>
              </div>
            </motion.section>

            {/* Main grid: replay bar + feed */}
            <motion.main
              className="max-w-[1400px] mx-auto px-4 lg:px-6 py-4 space-y-4"
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.3, ease: 'easeOut' }}
            >
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.5, delay: 0.5 }}
              >
                <ReplayBar
                  mode={mode}
                  onModeChange={setReplayMode}
                  replayStatus={replayStatus}
                  alertsPerMin={stats.alerts_per_min}
                  totalProcessed={stats.total}
                  onStartReplay={startReplay}
                />
              </motion.div>

              <motion.div
                className="grid grid-cols-1 lg:grid-cols-[1fr] gap-4"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.6, delay: 0.6 }}
              >
                <div className="h-[560px]">
                  <AlertFeed
                    alerts={sortedAlerts}
                    onSelect={handleSelectAlert}
                    selectedId={selectedSummary?.id}
                    filters={filters}
                    onFiltersChange={setFilters}
                    onInjectCustomAlert={pushCustomAlert}
                  />
                </div>
              </motion.div>

              {/* Eval + Benchmark panels */}
              <motion.div
                className="grid grid-cols-1 xl:grid-cols-2 gap-4 pt-2"
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.6, delay: 0.2 }}
              >
                <EvalPanel />
                <BenchmarkPanel />
              </motion.div>
            </motion.main>

            <footer className="border-t border-edge mt-6">
              <div className="max-w-[1400px] mx-auto px-4 lg:px-6 py-3 flex items-center justify-between flex-wrap gap-2">
                <span className="font-mono text-[10px] text-dim uppercase tracking-[0.14em]">
                  Flare · FastAPI + LangGraph + SQLite + Chroma Backend API
                </span>
                <span className="font-mono text-[10px] text-dim">
                  severity escalation: threat intel score ≥ 80 overrides LLM severity
                </span>
              </div>
            </footer>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Drill-down drawer */}
      <AlertDrawer alert={selectedDetail} onClose={() => { setSelectedSummary(null); setSelectedDetail(null); }} />

      {/* Mercury AI Command Bar */}
      <CommandBar
        isOpen={commandOpen}
        onClose={() => setCommandOpen(false)}
        alerts={sortedAlerts}
        onSelectAlert={(a) => handleSelectAlert(a)}
        onSetFilters={setFilters}
        onSetReplayMode={setReplayMode}
        onPushCustomAlert={pushCustomAlert}
      />
    </div>
  );
}

function LegendItem({ color, label }: { color: string; label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className={`inline-block h-1.5 w-1.5 rounded-full ${color}`} />
      {label}
    </span>
  );
}
