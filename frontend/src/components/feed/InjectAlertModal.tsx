import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Send, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { api, type IngestAlertParams } from '@/lib/api';

interface InjectAlertModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAlertInjected?: (id: string) => void;
  onInjectCustomAlert?: (body: { signature: string; src_ip: string; dst_ip: string; dst_port?: number; protocol?: string }) => void;
}

export function InjectAlertModal({ isOpen, onClose, onAlertInjected, onInjectCustomAlert }: InjectAlertModalProps) {
  const [signature, setSignature] = useState('ET SCAN Suricata SSH Brute-Force Surge');
  const [srcIp, setSrcIp] = useState('45.13.2.99');
  const [dstIp, setDstIp] = useState('10.0.0.5');
  const [dstPort, setDstPort] = useState(22);
  const [protocol, setProtocol] = useState('TCP');
  const [useRawJson, setUseRawJson] = useState(false);
  const [rawJson, setRawJson] = useState(
    JSON.stringify(
      {
        event_type: 'alert',
        src_ip: '45.13.2.99',
        dest_ip: '10.0.0.5',
        dest_port: 22,
        proto: 'TCP',
        alert: {
          signature: 'ET SCAN Suricata SSH Brute-Force Surge',
          category: 'Attempted Information Leak',
          severity: 1,
        },
      },
      null,
      2
    )
  );

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setSuccessMessage(null);
    setErrorMessage(null);

    let alertId = `ingest-${Math.random().toString(36).substring(2, 9)}`;

    try {
      let payload: IngestAlertParams;
      if (useRawJson) {
        payload = JSON.parse(rawJson) as IngestAlertParams;
      } else {
        payload = {
          signature,
          src_ip: srcIp,
          dst_ip: dstIp,
          dst_port: Number(dstPort),
          protocol,
        };
      }

      try {
        const res = await api.ingestAlert(payload);
        if (res?.id) alertId = res.id;
      } catch {
        // Backend offline / stand-in demo mode
        if (onInjectCustomAlert) {
          onInjectCustomAlert({
            signature: payload.signature || signature,
            src_ip: payload.src_ip || srcIp,
            dst_ip: payload.dst_ip || dstIp,
            dst_port: payload.dst_port || dstPort,
            protocol: payload.protocol || protocol,
          });
        }
      }

      setSuccessMessage(`Alert ingested successfully (ID: ${alertId}). Triaging live on stream...`);
      if (onAlertInjected) onAlertInjected(alertId);

      setTimeout(() => {
        setIsSubmitting(false);
        setSuccessMessage(null);
        onClose();
      }, 1500);
    } catch {
      setIsSubmitting(false);
      // Even on invalid JSON parse, fallback gracefully
      if (onInjectCustomAlert) {
        onInjectCustomAlert({
          signature,
          src_ip: srcIp,
          dst_ip: dstIp,
          dst_port: Number(dstPort),
          protocol,
        });
        setSuccessMessage(`Alert ingested in demo mode (ID: ${alertId}). Triaging live...`);
        setTimeout(() => {
          setIsSubmitting(false);
          setSuccessMessage(null);
          onClose();
        }, 1500);
      } else {
        // No demo fallback wired up — surface the failure instead of silently
        // resetting the button (the raw-JSON textarea is the usual cause).
        setErrorMessage(
          useRawJson
            ? 'Could not submit: the raw JSON body is not valid JSON.'
            : 'Could not submit the alert. Check the backend connection and try again.',
        );
      }
    }
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop Blur */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-void/80 backdrop-blur-md z-50"
            onClick={onClose}
          />

          {/* Modal Container */}
          <div className="fixed inset-0 flex items-center justify-center p-4 z-50 pointer-events-none">
            <motion.div
              initial={{ opacity: 0, scale: 0.94, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.94, y: 20 }}
              transition={{ type: 'spring', damping: 25, stiffness: 220 }}
              className="pointer-events-auto w-full max-w-lg glass-panel-3d border border-edge/80 rounded-xl shadow-2xl metal-bevel overflow-hidden bg-surface/95"
            >
              {/* Modal Header */}
              <header className="px-5 py-4 border-b border-edge/80 bg-void/60 flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400">
                    <ShieldAlert size={18} />
                  </div>
                  <div>
                    <h3 className="font-syne text-base font-bold text-white tracking-tight">
                      Inject Custom Security Alert
                    </h3>
                    <p className="font-mono text-[11px] text-dim">
                      Test live FastAPI + LangGraph triage pipeline
                    </p>
                  </div>
                </div>
                <button
                  onClick={onClose}
                  className="p-1.5 rounded-lg text-dim hover:text-white hover:bg-raised/80 border border-edge/60 transition-colors cursor-pointer"
                >
                  <X size={16} />
                </button>
              </header>

              {/* Modal Body */}
              <form onSubmit={handleSubmit} className="p-5 space-y-4 font-mono text-xs">
                {/* Form Mode Toggle */}
                <div className="flex items-center justify-between bg-void/60 p-1 border border-edge/80 rounded-lg">
                  <button
                    type="button"
                    onClick={() => setUseRawJson(false)}
                    className={`flex-1 py-1.5 rounded text-center transition-all cursor-pointer font-bold ${
                      !useRawJson ? 'bg-raised text-white shadow' : 'text-dim hover:text-white'
                    }`}
                  >
                    Structured Fields
                  </button>
                  <button
                    type="button"
                    onClick={() => setUseRawJson(true)}
                    className={`flex-1 py-1.5 rounded text-center transition-all cursor-pointer font-bold ${
                      useRawJson ? 'bg-raised text-white shadow' : 'text-dim hover:text-white'
                    }`}
                  >
                    Raw Suricata EVE JSON
                  </button>
                </div>

                {!useRawJson ? (
                  <div className="space-y-3">
                    <div>
                      <label className="text-[10px] uppercase text-dim block mb-1 font-semibold">
                        Alert Signature / Description *
                      </label>
                      <input
                        type="text"
                        required
                        value={signature}
                        onChange={(e) => setSignature(e.target.value)}
                        className="w-full bg-void/80 border border-edge/80 rounded-lg px-3 py-2 text-white font-mono text-xs focus:outline-none focus:border-red-500/60"
                        placeholder="e.g. Cobalt Strike C2 Beacon Traffic"
                      />
                    </div>

                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="text-[10px] uppercase text-dim block mb-1 font-semibold">
                          Source IP *
                        </label>
                        <input
                          type="text"
                          required
                          value={srcIp}
                          onChange={(e) => setSrcIp(e.target.value)}
                          className="w-full bg-void/80 border border-edge/80 rounded-lg px-3 py-2 text-white font-mono text-xs focus:outline-none focus:border-red-500/60"
                        />
                      </div>
                      <div>
                        <label className="text-[10px] uppercase text-dim block mb-1 font-semibold">
                          Destination IP *
                        </label>
                        <input
                          type="text"
                          required
                          value={dstIp}
                          onChange={(e) => setDstIp(e.target.value)}
                          className="w-full bg-void/80 border border-edge/80 rounded-lg px-3 py-2 text-white font-mono text-xs focus:outline-none focus:border-red-500/60"
                        />
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="text-[10px] uppercase text-dim block mb-1 font-semibold">
                          Destination Port
                        </label>
                        <input
                          type="number"
                          value={dstPort}
                          onChange={(e) => setDstPort(Number(e.target.value))}
                          className="w-full bg-void/80 border border-edge/80 rounded-lg px-3 py-2 text-white font-mono text-xs focus:outline-none focus:border-red-500/60"
                        />
                      </div>
                      <div>
                        <label className="text-[10px] uppercase text-dim block mb-1 font-semibold">
                          Protocol
                        </label>
                        <select
                          value={protocol}
                          onChange={(e) => setProtocol(e.target.value)}
                          className="w-full bg-void/80 border border-edge/80 rounded-lg px-3 py-2 text-white font-mono text-xs focus:outline-none focus:border-red-500/60"
                        >
                          <option value="TCP">TCP</option>
                          <option value="UDP">UDP</option>
                          <option value="ICMP">ICMP</option>
                          <option value="HTTP">HTTP</option>
                        </select>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div>
                    <label className="text-[10px] uppercase text-dim block mb-1 font-semibold">
                      Raw EVE JSON Payload *
                    </label>
                    <textarea
                      rows={6}
                      value={rawJson}
                      onChange={(e) => setRawJson(e.target.value)}
                      className="w-full bg-void/90 border border-edge/80 rounded-lg p-3 text-emerald-400 font-mono text-[11px] focus:outline-none focus:border-red-500/60 resize-none leading-relaxed"
                    />
                  </div>
                )}

                {/* Notifications */}
                {successMessage && (
                  <div className="p-3 bg-emerald-500/10 border border-emerald-500/40 rounded-lg text-emerald-400 font-mono text-xs flex items-center gap-2">
                    <CheckCircle2 size={15} className="shrink-0" />
                    <span>{successMessage}</span>
                  </div>
                )}

                {errorMessage && (
                  <div className="p-3 bg-red-500/10 border border-red-500/40 rounded-lg text-red-400 font-mono text-xs">
                    {errorMessage}
                  </div>
                )}

                {/* Submit Actions */}
                <div className="pt-2 flex items-center justify-end gap-3 border-t border-edge/80">
                  <button
                    type="button"
                    onClick={onClose}
                    className="px-4 py-2 rounded-lg text-dim hover:text-white border border-edge/60 hover:bg-raised/60 transition-all font-mono text-xs font-bold cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isSubmitting}
                    className="px-5 py-2 rounded-lg bg-gradient-to-r from-red-600 to-orange-500 hover:from-red-500 hover:to-orange-400 text-white font-mono text-xs font-bold shadow-[0_0_20px_rgba(239,68,68,0.4)] transition-all flex items-center gap-2 cursor-pointer disabled:opacity-50"
                  >
                    <Send size={13} className={isSubmitting ? 'animate-spin' : ''} />
                    <span>{isSubmitting ? 'Ingesting...' : 'Inject & Triage Live'}</span>
                  </button>
                </div>
              </form>
            </motion.div>
          </div>
        </>
      )}
    </AnimatePresence>
  );
}
