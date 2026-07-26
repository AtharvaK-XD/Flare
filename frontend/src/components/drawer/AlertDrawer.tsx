import { useEffect, useState } from 'react';
import type { AlertDetail } from '@/types';
import { motion, AnimatePresence } from 'framer-motion';
import { SEVERITY_HEX_CLASS, SEVERITY_TEXT, STATUS_LABELS } from '@/types';
import { X, ChevronRight, ChevronDown, Hash, ArrowRight, Zap, ShieldAlert, Cpu } from 'lucide-react';
import { IocVerdicts, MitreChips } from '@/components/drawer/IntelSections';
import { RemediationList, ModelDebate } from '@/components/drawer/ActionSections';
import { PipelineTrace } from '@/components/drawer/PipelineTrace';

interface AlertDrawerProps {
  alert: AlertDetail | null;
  onClose: () => void;
}

export function AlertDrawer({ alert, onClose }: AlertDrawerProps) {
  const [rawOpen, setRawOpen] = useState(false);

  useEffect(() => {
    setRawOpen(false);
  }, [alert?.id]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && alert) onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [alert, onClose]);

  const severityKey = alert?.severity || 'info';
  const isEscalated = (alert?.max_ioc_score ?? 0) >= 80 && alert?.severity === 'high';

  return (
    <AnimatePresence>
      {alert && (
        <>
          {/* 3D Backdrop Blur */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 bg-void/70 backdrop-blur-sm z-40"
            onClick={onClose}
            aria-hidden
          />

          <motion.aside
            initial={{ x: '100%', opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: '100%', opacity: 0 }}
            transition={{ type: 'spring', damping: 25, stiffness: 200 }}
            className="fixed right-0 top-0 bottom-0 z-50 w-full max-w-[560px] glass-panel-3d border-l border-edge/80 shadow-[0_0_8px_rgba(0,0,0,0.8)] flex flex-col metal-bevel"
            role="dialog"
            aria-modal="true"
            aria-label={`Alert detail ${alert.id}`}
          >
            {/* drawer header */}
            <header className="flex items-start gap-3 px-5 py-4 border-b border-edge/80 shrink-0 bg-void/60">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <span className="font-mono text-[11px] text-dim font-bold">{alert.id}</span>
                  {alert.severity ? (
                    <span className={`font-mono text-[10px] font-bold px-2 py-0.5 border rounded-md shadow-inner ${SEVERITY_HEX_CLASS[alert.severity]}`}>
                      {SEVERITY_TEXT[alert.severity]}
                    </span>
                  ) : (
                    <span className="font-mono text-[10px] text-dim italic">CLASSIFYING...</span>
                  )}
                  <span className="font-mono text-[10px] text-dim uppercase tracking-wider font-semibold">
                    {STATUS_LABELS[alert.status]}
                  </span>
                </div>
                <h3 className="text-lg text-ink font-bold leading-tight">{alert.attack_type || alert.signature}</h3>
                <p className="font-mono text-[11px] text-dim mt-1">
                  {alert.timestamp} · Source: <span className="text-ink">{alert.source}</span>
                </p>
              </div>
              <motion.button
                whileHover={{ scale: 1.1 }}
                whileTap={{ scale: 0.9 }}
                onClick={onClose}
                aria-label="Close detail panel"
                className="p-2 text-dim hover:text-ink hover:bg-raised/80 border border-edge/60 rounded-md transition-all shrink-0 cursor-pointer shadow-sm"
              >
                <X size={16} />
              </motion.button>
            </header>

            {/* Threat Intel Escalation Warning */}
            {isEscalated && (
              <div className="bg-sev-critical/15 border-b border-sev-critical/40 px-5 py-2.5 flex items-center gap-2 text-sev-critical font-mono text-[11px]">
                <Zap size={14} className="animate-bounce" />
                <span>
                  <strong>Threat Intel Escalation:</strong> Model severity overridden to <strong>HIGH</strong> (IOC score {alert.max_ioc_score} ≥ 80).
                </span>
              </div>
            )}

            {/* scrollable body */}
            <div className="flex-1 overflow-y-auto space-y-4 py-3">
              {/* overview */}
              <Section label="Network Flow Details">
                <div className="grid grid-cols-2 gap-3 px-3 py-3 font-mono text-xs bg-void/40 border border-edge/60 rounded-md">
                  <div>
                    <span className="text-[10px] text-dim uppercase">Source IP</span>
                    <p className="text-ink font-bold mt-0.5">{alert.src_ip}</p>
                    <span className="text-[10px] text-dim">port: {alert.src_port || 'dynamic'}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-dim uppercase">Destination IP</span>
                    <p className="text-ink font-bold mt-0.5">{alert.dst_ip}</p>
                    <span className="text-[10px] text-dim">port: {alert.dst_port || 80} / {alert.protocol || 'TCP'}</span>
                  </div>
                </div>
              </Section>

              {/* reasoning */}
              <Section label="AI Reasoning Narrative">
                <ModelDebate reasoning={alert.reasoning} />
              </Section>

              {/* threat intel */}
              <Section label="Threat Intel & IOC Reputation">
                <IocVerdicts iocs={alert.enrichment?.iocs || []} />
              </Section>

              {/* mitre */}
              <Section label="MITRE ATT&CK Mapping">
                <MitreChips mitre={alert.remediation?.techniques || []} />
              </Section>

              {/* remediation */}
              <Section label="Automated Remediation Steps">
                {alert.remediation?.summary && (
                  <p className="text-xs text-ink px-3 py-2 bg-raised/40 border-l-2 border-l-sev-low mb-2 font-medium">
                    {alert.remediation.summary}
                  </p>
                )}
                <RemediationList steps={alert.remediation?.steps || []} />
              </Section>

              {/* pipeline trace */}
              <Section label="LangGraph Pipeline Trace">
                <PipelineTrace alert={alert} />
              </Section>

              {/* raw json */}
              <div className="px-5 py-2">
                <button
                  onClick={() => setRawOpen((v) => !v)}
                  className="flex items-center gap-2 w-full text-left font-mono text-xs text-dim hover:text-ink py-2 border-t border-edge/60 transition-colors cursor-pointer"
                >
                  {rawOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  <Hash size={13} />
                  <span>Raw Telemetry Event Data</span>
                </button>
                {rawOpen && (
                  <pre className="mt-2 p-3 bg-void border border-edge/80 text-[10px] font-mono text-dim overflow-x-auto rounded-md max-h-60">
                    {JSON.stringify(alert.raw || alert, null, 2)}
                  </pre>
                )}
              </div>
            </div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <section className="px-5">
      <div className="flex items-center gap-2 mb-2">
        <h4 className="font-mono text-[10px] uppercase tracking-[0.16em] text-dim font-bold">{label}</h4>
        <div className="flex-1 h-px bg-edge/60" />
      </div>
      {children}
    </section>
  );
}
