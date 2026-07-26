import type { AlertDetail, TraceNode } from '@/types';
import { CheckCircle2, SkipForward, AlertOctagon, Cpu } from 'lucide-react';

const PIPELINE_NODES = ['classify', 'enrich', 'retrieve', 'reason', 'recommend'] as const;

const NODE_NAMES: Record<string, string> = {
  classify: 'Classify (Groq LLM)',
  enrich: 'Enrich (Intel APIs)',
  retrieve: 'Retrieve (Chroma ATT&CK)',
  reason: 'Reason (Gemini LLM)',
  recommend: 'Recommend (Mitre RAG)',
};

export function PipelineTrace({ alert }: { alert: AlertDetail }) {
  const traceMap = new Map<string, TraceNode>();
  if (alert.trace) {
    alert.trace.forEach((t) => traceMap.set(t.node, t));
  }

  return (
    <div className="space-y-2 px-3 py-3">
      {PIPELINE_NODES.map((nodeName, idx) => {
        const node = traceMap.get(nodeName);
        const isSkipped = node?.status === 'skipped';
        const isFailed = node?.status === 'failed';
        const isOk = node?.status === 'ok';

        return (
          <div
            key={nodeName}
            className={`p-3 border rounded-md transition-all ${
              isOk
                ? 'border-edge/80 bg-raised/40'
                : isSkipped
                ? 'border-edge/40 bg-void/50 opacity-75'
                : isFailed
                ? 'border-sev-critical/50 bg-sev-critical/10'
                : 'border-edge/30 bg-void/30'
            }`}
          >
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="font-mono text-[10px] w-5 text-center text-dim font-bold">{idx + 1}</span>
                {isOk && <CheckCircle2 size={14} className="text-ok" />}
                {isSkipped && <SkipForward size={14} className="text-dim" />}
                {isFailed && <AlertOctagon size={14} className="text-sev-critical" />}
                <span className={`font-mono text-[12px] font-bold ${isOk ? 'text-ink' : 'text-dim'}`}>
                  {NODE_NAMES[nodeName]}
                </span>
              </div>

              <div className="flex items-center gap-2 font-mono text-[10px]">
                {node?.provider && (
                  <span className="px-1.5 py-0.5 bg-void border border-edge/60 rounded text-dim flex items-center gap-1">
                    <Cpu size={9} /> {node.provider}
                  </span>
                )}
                {node ? (
                  <span className="font-bold text-ink">{node.duration_ms}ms</span>
                ) : (
                  <span className="text-dim">—</span>
                )}
              </div>
            </div>

            {/* Tokens & Skip Notes */}
            {node && (
              <div className="mt-1.5 pl-7 flex flex-col gap-1 font-mono text-[10px]">
                {node.note && (
                  <span className={`italic ${isSkipped ? 'text-dim' : 'text-sev-medium'}`}>
                    {node.note}
                  </span>
                )}
                {(node.tokens_in !== null || node.tokens_out !== null) && (
                  <span className="text-dim text-[9px]">
                    tokens: in {node.tokens_in ?? 0} / out {node.tokens_out ?? 0}
                  </span>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
