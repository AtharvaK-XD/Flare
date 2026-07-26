import { useEffect, useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import type { AlertSummary } from '@/types';
import type { ReplayMode } from '@/hooks/useAlertStream';
import type { FeedFilters } from '@/components/feed/AlertFeed';
import { Sparkles, Command, ShieldAlert, Play, Pause, Square, CornerDownLeft, X, PlusCircle } from 'lucide-react';

interface CommandBarProps {
  isOpen: boolean;
  onClose: () => void;
  alerts: AlertSummary[];
  onSelectAlert: (alert: AlertSummary) => void;
  onSetFilters: (filters: FeedFilters) => void;
  onSetReplayMode: (mode: ReplayMode) => void;
  onPushCustomAlert?: (body: { signature: string; src_ip: string; dst_ip: string; dst_port?: number; protocol?: string }) => void;
}

interface CommandItem {
  id: string;
  category: 'prompt' | 'action' | 'alert';
  title: string;
  subtitle?: string;
  icon: React.ReactNode;
  action: () => void;
}

export function CommandBar({
  isOpen,
  onClose,
  alerts,
  onSelectAlert,
  onSetFilters,
  onSetReplayMode,
  onPushCustomAlert,
}: CommandBarProps) {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [showCustomIngest, setShowCustomIngest] = useState(false);
  const [customSig, setCustomSig] = useState('SSH brute force attempt');
  const [customSrcIp, setCustomSrcIp] = useState('45.13.2.99');
  const [customDstIp, setCustomDstIp] = useState('10.0.0.5');

  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setSelectedIndex(0);
      setShowCustomIngest(false);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  const handleIngestSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (onPushCustomAlert) {
      onPushCustomAlert({
        signature: customSig,
        src_ip: customSrcIp,
        dst_ip: customDstIp,
        dst_port: 22,
        protocol: 'TCP',
      });
    }
    setShowCustomIngest(false);
    onClose();
  };

  const prompts: CommandItem[] = [
    {
      id: 'prompt-custom-ingest',
      category: 'action',
      title: 'Ingest Custom Threat Alert (POST /ingest)',
      subtitle: 'Push manual security alert flow to triage pipeline',
      icon: <PlusCircle size={14} className="text-ok" />,
      action: () => setShowCustomIngest(true),
    },
    {
      id: 'prompt-crit',
      category: 'prompt',
      title: 'Filter Critical & High severity alerts',
      subtitle: 'Focus telemetry on high impact threats',
      icon: <Sparkles size={14} className="text-sev-high" />,
      action: () => {
        onSetFilters({ severities: new Set(['critical', 'high']) });
        onClose();
      },
    },
    {
      id: 'prompt-mal-ioc',
      category: 'prompt',
      title: 'Show alerts with malicious IOCs (≥50)',
      subtitle: 'Filter for active threat intel hits across AbuseIPDB & VirusTotal',
      icon: <ShieldAlert size={14} className="text-sev-critical" />,
      action: () => {
        onSetFilters({ severities: new Set(['critical', 'high', 'medium', 'low', 'info']) });
        onClose();
      },
    },
  ];

  const actions: CommandItem[] = [
    {
      id: 'act-live',
      category: 'action',
      title: 'Resume Live Telemetry Replay',
      subtitle: 'Stream real-time alert flow (events_per_second: 5)',
      icon: <Play size={14} className="text-ok" />,
      action: () => {
        onSetReplayMode('live');
        onClose();
      },
    },
    {
      id: 'act-pause',
      category: 'action',
      title: 'Pause Stream Telemetry',
      subtitle: 'Freeze incoming stream for deep inspection',
      icon: <Pause size={14} className="text-degraded" />,
      action: () => {
        onSetReplayMode('paused');
        onClose();
      },
    },
    {
      id: 'act-stop',
      category: 'action',
      title: 'Stop and Hold Queue',
      subtitle: 'Halt alert generation and hold state',
      icon: <Square size={14} className="text-down" />,
      action: () => {
        onSetReplayMode('stopped');
        onClose();
      },
    },
  ];

  const trimmed = query.trim().toLowerCase();

  const matchingAlerts: CommandItem[] = alerts
    .filter(
      (a) =>
        (a.attack_type && a.attack_type.toLowerCase().includes(trimmed)) ||
        a.signature.toLowerCase().includes(trimmed) ||
        a.src_ip.includes(trimmed) ||
        a.dst_ip.includes(trimmed) ||
        a.id.toLowerCase().includes(trimmed),
    )
    .slice(0, 5)
    .map((alert) => ({
      id: `alert-${alert.id}`,
      category: 'alert',
      title: `${alert.attack_type || alert.signature} (${(alert.severity || 'info').toUpperCase()})`,
      subtitle: `${alert.src_ip} → ${alert.dst_ip}:${alert.dst_port || 80} · id: ${alert.id}`,
      icon: <ShieldAlert size={14} className={alert.severity === 'critical' ? 'text-sev-critical' : 'text-sev-low'} />,
      action: () => {
        onSelectAlert(alert);
        onClose();
      },
    }));

  const filteredPrompts = prompts.filter(
    (p) => p.title.toLowerCase().includes(trimmed) || (p.subtitle && p.subtitle.toLowerCase().includes(trimmed)),
  );
  const filteredActions = actions.filter(
    (a) => a.title.toLowerCase().includes(trimmed) || (a.subtitle && a.subtitle.toLowerCase().includes(trimmed)),
  );

  const allItems = [...filteredPrompts, ...filteredActions, ...matchingAlerts];

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (showCustomIngest) return;
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % Math.max(1, allItems.length));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + allItems.length) % Math.max(1, allItems.length));
    } else if (e.key === 'Enter' && allItems[selectedIndex]) {
      e.preventDefault();
      allItems[selectedIndex].action();
    } else if (e.key === 'Escape') {
      onClose();
    }
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="fixed inset-0 bg-void/75 backdrop-blur-md z-50"
            onClick={onClose}
            aria-hidden
          />

          {/* Command Bar Dialog */}
          <div className="fixed inset-x-0 top-[10vh] z-50 max-w-[640px] mx-auto px-4 pointer-events-none">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: -10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: -10 }}
              transition={{ type: 'spring', damping: 25, stiffness: 300 }}
              className="pointer-events-auto command-modal rounded-xl overflow-hidden shadow-2xl border border-white/10 bg-slate-950"
              role="dialog"
              aria-modal="true"
            >
              {showCustomIngest ? (
                /* Custom Ingest Modal */
                <form onSubmit={handleIngestSubmit} className="p-5 space-y-4">
                  <div className="flex items-center justify-between border-b border-edge pb-2">
                    <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-ink flex items-center gap-2">
                      <PlusCircle size={14} className="text-ok" /> Ingest Custom Alert (POST /api/v1/ingest)
                    </h3>
                    <button type="button" onClick={() => setShowCustomIngest(false)} className="text-dim hover:text-ink cursor-pointer">
                      <X size={16} />
                    </button>
                  </div>
                  <div className="space-y-3 font-mono text-xs">
                    <div>
                      <label className="text-[10px] uppercase text-dim block mb-1">Signature</label>
                      <input
                        type="text"
                        value={customSig}
                        onChange={(e) => setCustomSig(e.target.value)}
                        className="w-full bg-void border border-edge/80 p-2 text-ink rounded focus:border-sev-low outline-none"
                        required
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="text-[10px] uppercase text-dim block mb-1">Source IP</label>
                        <input
                          type="text"
                          value={customSrcIp}
                          onChange={(e) => setCustomSrcIp(e.target.value)}
                          className="w-full bg-void border border-edge/80 p-2 text-ink rounded focus:border-sev-low outline-none"
                          required
                        />
                      </div>
                      <div>
                        <label className="text-[10px] uppercase text-dim block mb-1">Destination IP</label>
                        <input
                          type="text"
                          value={customDstIp}
                          onChange={(e) => setCustomDstIp(e.target.value)}
                          className="w-full bg-void border border-edge/80 p-2 text-ink rounded focus:border-sev-low outline-none"
                          required
                        />
                      </div>
                    </div>
                  </div>
                  <div className="flex justify-end gap-2 pt-2">
                    <button
                      type="button"
                      onClick={() => setShowCustomIngest(false)}
                      className="px-3 py-1.5 font-mono text-xs border border-edge text-dim rounded hover:text-ink cursor-pointer"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="px-4 py-1.5 font-mono text-xs bg-sev-low text-ink font-bold rounded hover:bg-sev-low/80 cursor-pointer"
                    >
                      Push to Ingest Queue (202)
                    </button>
                  </div>
                </form>
              ) : (
                <>
                  {/* Input Bar */}
                  <div className="relative flex items-center px-4 py-3.5 border-b border-edge/80 bg-void/40">
                    <Command size={18} className="text-sev-low mr-3 shrink-0" />
                    <input
                      ref={inputRef}
                      type="text"
                      value={query}
                      onChange={(e) => {
                        setQuery(e.target.value);
                        setSelectedIndex(0);
                      }}
                      onKeyDown={handleKeyDown}
                      placeholder="Type a command or search alerts, IPs, signatures..."
                      className="w-full bg-transparent text-ink placeholder:text-dim font-mono text-sm outline-none border-none focus:ring-0"
                    />
                    <button onClick={onClose} className="p-1 text-dim hover:text-ink transition-colors ml-2 shrink-0">
                      <X size={16} />
                    </button>
                  </div>

                  {/* Results List */}
                  <div className="max-h-[380px] overflow-y-auto p-2 divide-y divide-edge/30">
                    {allItems.length === 0 ? (
                      <div className="px-4 py-8 text-center font-mono text-xs text-dim">
                        No matching commands or telemetry alerts found for &quot;{query}&quot;
                      </div>
                    ) : (
                      allItems.map((item, idx) => {
                        const isSelected = idx === selectedIndex;
                        return (
                          <div
                            key={item.id}
                            onClick={item.action}
                            onMouseEnter={() => setSelectedIndex(idx)}
                            className={`flex items-center justify-between px-3 py-2.5 rounded-lg cursor-pointer transition-all duration-150 ${
                              isSelected
                                ? 'bg-raised/90 border border-sev-low/40 shadow-md text-ink'
                                : 'border border-transparent hover:bg-raised/40 text-dim'
                            }`}
                          >
                            <div className="flex items-center gap-3 min-w-0">
                              <div className={`p-1.5 rounded-md ${isSelected ? 'bg-void text-white' : 'bg-void/50 text-dim'}`}>
                                {item.icon}
                              </div>
                              <div className="min-w-0">
                                <div className={`font-mono text-xs font-medium truncate ${isSelected ? 'text-ink' : 'text-dim'}`}>
                                  {item.title}
                                </div>
                                {item.subtitle && (
                                  <div className="font-mono text-[10px] text-dim/80 truncate mt-0.5">{item.subtitle}</div>
                                )}
                              </div>
                            </div>
                            <div className="flex items-center gap-2 font-mono text-[10px] text-dim shrink-0 ml-2">
                              {isSelected && (
                                <span className="flex items-center gap-1 text-sev-low font-semibold">
                                  Execute <CornerDownLeft size={10} />
                                </span>
                              )}
                            </div>
                          </div>
                        );
                      })
                    )}
                  </div>
                </>
              )}
            </motion.div>
          </div>
        </>
      )}
    </AnimatePresence>
  );
}
