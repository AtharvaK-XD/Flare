import type { Remediation, RemediationStep } from '@/types';
import { AlertCircle, Clock, ShieldCheck, CheckCircle2 } from 'lucide-react';

interface RemediationPanelProps {
  remediation: Remediation | null;
}

export function RemediationList({ steps }: { steps: RemediationStep[] }) {
  if (!steps || steps.length === 0) {
    return <p className="font-mono text-xs text-dim px-3 py-4">No remediation steps recommended.</p>;
  }

  const urgencyColors = {
    immediate: 'text-sev-critical bg-sev-critical/10 border-sev-critical/40',
    soon: 'text-sev-high bg-sev-high/10 border-sev-high/40',
    monitor: 'text-sev-low bg-sev-low/10 border-sev-low/40',
  };

  const urgencyIcons = {
    immediate: <AlertCircle size={12} className="text-sev-critical" />,
    soon: <Clock size={12} className="text-sev-high" />,
    monitor: <ShieldCheck size={12} className="text-sev-low" />,
  };

  return (
    <ol className="px-3 py-2 space-y-2.5">
      {steps.map((step, i) => (
        <li key={i} className="p-2.5 bg-raised/50 border border-edge/80 rounded-md">
          <div className="flex items-center justify-between gap-2 mb-1">
            <div className="flex items-center gap-1.5 font-mono text-[11px] font-bold text-ink">
              <span className="w-4 h-4 rounded-full bg-void border border-edge flex items-center justify-center text-[10px] text-dim">
                {step.order || i + 1}
              </span>
              <span>{step.action}</span>
            </div>
            <span
              className={`font-mono text-[9px] uppercase tracking-wider px-2 py-0.5 border rounded font-semibold flex items-center gap-1 ${
                urgencyColors[step.urgency || 'soon']
              }`}
            >
              {urgencyIcons[step.urgency || 'soon']}
              {step.urgency}
            </span>
          </div>
          <p className="text-[12px] text-dim leading-snug mt-1 pl-5">{step.detail}</p>
        </li>
      ))}
    </ol>
  );
}

export function ModelDebate({ reasoning }: { reasoning: string | null }) {
  if (!reasoning) {
    return <p className="font-mono text-xs text-dim px-3 py-4">No AI reasoning narrative generated.</p>;
  }

  return (
    <div className="px-3 py-3 font-mono text-xs leading-relaxed text-ink bg-raised/40 border border-edge/60 rounded-md">
      <div className="flex items-center gap-2 mb-2 border-b border-edge/40 pb-1.5">
        <CheckCircle2 size={13} className="text-ok" />
        <span className="text-[10px] uppercase tracking-wider font-bold text-dim">AI Triage Reasoning Narrative</span>
      </div>
      <p className="whitespace-pre-wrap">{reasoning}</p>
    </div>
  );
}
