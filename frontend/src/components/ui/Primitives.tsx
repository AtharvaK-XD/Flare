import type { ReactNode } from 'react';

interface DotProps {
  className: string;
  pulse?: boolean;
  label?: string;
}

export function StatusDot({ className, pulse, label }: DotProps) {
  return (
    <span className="inline-flex items-center gap-1.5" aria-label={label}>
      <span
        className={`inline-block h-1.5 w-1.5 rounded-full ${className} ${pulse ? 'animate-pulse-soft' : ''}`}
      />
      {label && <span className="sr-only">{label}</span>}
    </span>
  );
}

interface PanelProps {
  children: ReactNode;
  className?: string;
  title?: string;
  right?: ReactNode;
}

export function Panel({ children, className = '', title, right }: PanelProps) {
  return (
    <section className={`bg-surface border border-edge rounded-sm ${className}`}>
      {title && (
        <header className="flex items-center justify-between px-3 py-2 border-b border-edge">
          <h2 className="font-mono text-[11px] font-semibold tracking-[0.14em] text-dim uppercase">{title}</h2>
          {right}
        </header>
      )}
      {children}
    </section>
  );
}

interface MonoLabelProps {
  children: ReactNode;
  className?: string;
}

export function MonoLabel({ children, className = '' }: MonoLabelProps) {
  return (
    <span className={`font-mono text-[10px] uppercase tracking-[0.14em] text-dim ${className}`}>
      {children}
    </span>
  );
}
