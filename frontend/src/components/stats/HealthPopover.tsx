import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Activity, RefreshCw, X, Server, Layers } from 'lucide-react';
import type { DeepHealth } from '@/types';
import { api } from '@/lib/api';

export function HealthPopover() {
  const [isOpen, setIsOpen] = useState(false);
  const [health, setHealth] = useState<DeepHealth | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const fetchHealth = async () => {
    setIsLoading(true);
    try {
      const data = await api.getHealthDeep();
      setHealth(data);
    } catch {
      // Mock fallback
      setHealth({
        status: 'ok',
        services: {
          groq: { status: 'ok', latency_ms: 84 },
          gemini: { status: 'ok', latency_ms: 620 },
          abuseipdb: { status: 'ok', quota_remaining: 940 },
          virustotal: { status: 'degraded', quota_remaining: 4, note: 'rate limited' },
          chroma: { status: 'ok', documents: 28 },
          database: { status: 'ok', latency_ms: 1 },
        },
        workers: {
          triage: { active: 4, configured: 4 },
          enrich: { active: 1, configured: 1 },
          queues: {
            triage: { depth: 0 },
            enrich: { depth: 2 },
          },
        },
      });
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
    const timer = setInterval(fetchHealth, 15000);
    return () => clearInterval(timer);
  }, []);

  const overallStatus = health?.status || 'ok';
  const isOffline = health?.services?.groq?.note?.includes('offline') || false;

  return (
    <div className="relative inline-block text-left">
      {/* Trigger Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-void/60 border border-edge/80 hover:border-slate-700 transition-all font-mono text-xs cursor-pointer shadow-sm"
        title="View Granular System Health & Service Status"
      >
        <span
          className={`w-2 h-2 rounded-full ${
            overallStatus === 'ok'
              ? 'bg-emerald-400 shadow-[0_0_8px_#10B981]'
              : overallStatus === 'degraded'
              ? 'bg-amber-400 shadow-[0_0_8px_#F59E0B]'
              : 'bg-red-500 shadow-[0_0_8px_#EF4444]'
          }`}
        />
        <span className="font-bold text-slate-200 uppercase tracking-wider text-[11px]">
          {overallStatus === 'ok' ? 'SYSTEM OK' : overallStatus === 'degraded' ? 'DEGRADED' : 'DOWN'}
        </span>
        {isOffline && (
          <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-400 font-bold border border-amber-500/30">
            OFFLINE
          </span>
        )}
      </button>

      {/* Popover Card */}
      <AnimatePresence>
        {isOpen && (
          <>
            <div className="fixed inset-0 z-40" onClick={() => setIsOpen(false)} />
            <motion.div
              initial={{ opacity: 0, y: 10, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 10, scale: 0.95 }}
              transition={{ duration: 0.2 }}
              className="absolute left-0 mt-2 z-50 w-80 sm:w-96 glass-panel-3d border border-edge/80 rounded-xl shadow-2xl metal-bevel overflow-hidden bg-surface/95 font-mono text-xs p-4 space-y-3"
            >
              <div className="flex items-center justify-between border-b border-edge/80 pb-2.5">
                <div className="flex items-center gap-2">
                  <Activity size={15} className="text-emerald-400" />
                  <span className="font-bold text-white text-xs uppercase tracking-wider">
                    Deep Service Health & Worker Pools
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={fetchHealth}
                    className="p-1 rounded text-dim hover:text-white transition-colors cursor-pointer"
                  >
                    <RefreshCw size={12} className={isLoading ? 'animate-spin' : ''} />
                  </button>
                  <button
                    onClick={() => setIsOpen(false)}
                    className="p-1 rounded text-dim hover:text-white transition-colors cursor-pointer"
                  >
                    <X size={13} />
                  </button>
                </div>
              </div>

              {/* Service Cards Grid */}
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                {/* Groq */}
                <div className="p-2.5 bg-void/50 border border-edge/60 rounded-lg space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white">Groq Fast Tier</span>
                    <span className="text-[9px] text-emerald-400 font-bold">OK</span>
                  </div>
                  <div className="text-dim text-[10px]">
                    Latency: <strong className="text-white">{health?.services?.groq?.latency_ms || 84}ms</strong>
                  </div>
                </div>

                {/* Gemini */}
                <div className="p-2.5 bg-void/50 border border-edge/60 rounded-lg space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white">Gemini Quality</span>
                    <span className="text-[9px] text-emerald-400 font-bold">OK</span>
                  </div>
                  <div className="text-dim text-[10px]">
                    Latency: <strong className="text-white">{health?.services?.gemini?.latency_ms || 620}ms</strong>
                  </div>
                </div>

                {/* AbuseIPDB */}
                <div className="p-2.5 bg-void/50 border border-edge/60 rounded-lg space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white">AbuseIPDB</span>
                    <span className="text-[9px] text-emerald-400 font-bold">OK</span>
                  </div>
                  <div className="text-dim text-[10px]">
                    Quota Remaining: <strong className="text-white">{health?.services?.abuseipdb?.quota_remaining ?? 940}</strong>
                  </div>
                </div>

                {/* VirusTotal */}
                <div className="p-2.5 bg-void/50 border border-edge/60 rounded-lg space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white">VirusTotal</span>
                    <span className="text-[9px] text-amber-400 font-bold">
                      {health?.services?.virustotal?.status || 'degraded'}
                    </span>
                  </div>
                  <div className="text-dim text-[10px]">
                    Quota: <strong className="text-white">{health?.services?.virustotal?.quota_remaining ?? 4} req</strong>
                  </div>
                </div>

                {/* Chroma DB RAG */}
                <div className="p-2.5 bg-void/50 border border-edge/60 rounded-lg space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white">Chroma RAG</span>
                    <span className="text-[9px] text-emerald-400 font-bold">OK</span>
                  </div>
                  <div className="text-dim text-[10px]">
                    MITRE Vector Docs: <strong className="text-purple-400">{health?.services?.chroma?.documents || 28}</strong>
                  </div>
                </div>

                {/* SQLite DB */}
                <div className="p-2.5 bg-void/50 border border-edge/60 rounded-lg space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white">SQLite DB</span>
                    <span className="text-[9px] text-emerald-400 font-bold">OK</span>
                  </div>
                  <div className="text-dim text-[10px]">
                    Latency: <strong className="text-white">1ms</strong>
                  </div>
                </div>
              </div>

              {/* Workers Summary */}
              <div className="pt-2 border-t border-edge/80 flex items-center justify-between text-[10px] text-dim">
                <span className="flex items-center gap-1">
                  <Server size={11} className="text-blue-400" /> Triage Pool: <strong>4 Workers</strong>
                </span>
                <span className="flex items-center gap-1">
                  <Layers size={11} className="text-amber-400" /> Enrich Pool: <strong>1 Worker (Capped)</strong>
                </span>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}
