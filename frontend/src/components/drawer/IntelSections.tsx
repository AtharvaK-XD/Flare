import type { IocVerdict, MitreTechnique } from '@/types';
import { ShieldAlert, ShieldCheck, ExternalLink, Copy, Check } from 'lucide-react';
import { useState } from 'react';

interface IocVerdictsProps {
  iocs: IocVerdict[];
}

export function IocVerdicts({ iocs }: IocVerdictsProps) {
  const [copiedVal, setCopiedVal] = useState<string | null>(null);

  const copyIoc = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedVal(val);
    setTimeout(() => setCopiedVal(null), 1500);
  };

  if (!iocs || iocs.length === 0) {
    return <p className="font-mono text-xs text-dim px-3 py-4">No IOCs extracted for this alert.</p>;
  }

  return (
    <div className="divide-y divide-edge/50">
      {iocs.map((ioc, i) => (
        <div
          key={`${ioc.indicator}-${i}`}
          className="px-3 py-3 hover:bg-raised/40 transition-colors group"
        >
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 min-w-0">
              {ioc.malicious ? (
                <div className="relative flex items-center justify-center">
                  <span className="animate-ping absolute inline-flex h-3 w-3 rounded-full bg-sev-critical opacity-40" />
                  <ShieldAlert size={15} className="text-sev-critical relative z-10" />
                </div>
              ) : (
                <ShieldCheck size={15} className="text-dim" />
              )}
              <span className="font-mono text-[10px] uppercase tracking-wider text-dim font-medium">{ioc.indicator_type}</span>
              <span className={`font-mono text-[13px] truncate font-bold ${ioc.malicious ? 'text-ink' : 'text-dim'}`}>
                {ioc.indicator}
              </span>
              <button
                onClick={() => copyIoc(ioc.indicator)}
                className="opacity-0 group-hover:opacity-100 p-1 text-dim hover:text-ink transition-opacity cursor-pointer"
                title="Copy indicator"
              >
                {copiedVal === ioc.indicator ? <Check size={11} className="text-ok" /> : <Copy size={11} />}
              </button>
            </div>

            <div className="flex items-center gap-2 shrink-0 font-mono">
              {ioc.cached && (
                <span className="text-[9px] px-1.5 py-0.5 bg-void text-dim border border-edge/60 rounded">cached</span>
              )}
              <span
                className={`text-[10px] uppercase tracking-wider px-2 py-0.5 border rounded font-semibold ${
                  ioc.malicious
                    ? 'border-sev-critical/50 text-sev-critical bg-sev-critical/10 shadow-[0_0_8px_rgba(220,38,38,0.2)]'
                    : 'border-edge text-dim bg-void/50'
                }`}
              >
                {ioc.score} / 100
              </span>
            </div>
          </div>

          {/* Sources and vendor deep links */}
          {ioc.sources && ioc.sources.length > 0 && (
            <div className="mt-2 flex flex-wrap items-center gap-2 pl-6">
              {ioc.sources.map((src, sIdx) => (
                <div key={sIdx} className="flex items-center gap-1.5 font-mono text-[10px] bg-void/60 px-2 py-0.5 border border-edge/40 rounded">
                  <span className="text-ink font-semibold uppercase">{src.source}</span>
                  <span className="text-dim">score: {src.raw_score}</span>
                  {src.link && (
                    <a
                      href={src.link}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sev-low hover:underline inline-flex items-center gap-0.5"
                    >
                      vendor <ExternalLink size={9} />
                    </a>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

interface MitreChipsProps {
  mitre: MitreTechnique[];
}

export function MitreChips({ mitre }: MitreChipsProps) {
  if (!mitre || mitre.length === 0) {
    return <p className="font-mono text-xs text-dim px-3 py-4">No MITRE techniques mapped.</p>;
  }

  return (
    <div className="space-y-2 px-3 py-3">
      {mitre.map((t) => (
        <div key={t.id} className="p-2.5 bg-raised/80 border border-edge/80 rounded-md hover:border-sev-low/60 transition-all">
          <div className="flex items-center justify-between gap-2 mb-1">
            <a
              href={t.url}
              target="_blank"
              rel="noopener noreferrer"
              className="group inline-flex items-center gap-1.5 text-sev-low hover:underline font-mono text-[12px] font-bold"
            >
              <span>{t.id}: {t.name}</span>
              <ExternalLink size={11} className="text-dim group-hover:text-sev-low" />
            </a>
            <span className="font-mono text-[9px] uppercase tracking-wider text-dim bg-void px-2 py-0.5 border border-edge/60 rounded">
              {t.tactic}
            </span>
          </div>
          {t.excerpt && (
            <p className="text-[11px] text-dim leading-relaxed italic border-l-2 border-sev-low/40 pl-2 mt-1">
              "{t.excerpt}"
            </p>
          )}
        </div>
      ))}
    </div>
  );
}
