import { useEffect, useMemo, useRef, useState } from 'react';
import type { Alert, PipelineStage, Severity } from '@/types';
import { SEVERITY_RGB, STAGE_LABELS } from '@/types';
import {
  buildGraph,
  edgePath,
  type GraphConfig,
  type GraphEdge,
  type GraphNode,
  isoProject,
  nodePolygon,
  nodeWalls,
  pointOnEdge,
} from '@/lib/isoGraph';

interface PipelineGraphProps {
  alerts: Alert[];
  connected: boolean;
  compact?: boolean;
}

interface FlowParticle {
  id: string;
  edge: GraphEdge;
  t: number;
  speed: number;
  severity: Severity;
  born: number;
}

const STAGE_GLOW: Record<PipelineStage, string> = {
  ingested: 'rgba(37,99,235,0.10)',
  classified: 'rgba(217,119,6,0.10)',
  enriched: 'rgba(234,88,12,0.10)',
  reasoned: 'rgba(220,38,38,0.10)',
  done: 'rgba(22,163,74,0.10)',
  failed: 'rgba(220,38,38,0.20)',
};

const STAGE_NODE_FILL: Record<PipelineStage, string> = {
  ingested: '#161E28',
  classified: '#1B1F18',
  enriched: '#221A14',
  reasoned: '#241515',
  done: '#14201A',
  failed: '#241515',
};

function severityGlow(sev: Severity, intensity = 1): string {
  const [r, g, b] = SEVERITY_RGB[sev];
  return `rgba(${r},${g},${b},${intensity})`;
}

const VIEW_W = 720;
const VIEW_H = 360;

export function PipelineGraph({ alerts, connected, compact = false }: PipelineGraphProps) {
  const [mounted, setMounted] = useState(false);
  const [hoveredNode, setHoveredNode] = useState<PipelineStage | null>(null);
  const [particles, setParticles] = useState<FlowParticle[]>([]);
  const rafRef = useRef<number | null>(null);
  const lastSpawnRef = useRef(0);
  const alertIdxRef = useRef(0);

  const config: GraphConfig = useMemo(() => ({
    scale: compact ? 70 : 86,
    cx: VIEW_W / 2,
    cy: VIEW_H / 2 + 10,
    nodeSize: 1.05,
    nodeHeight: 0.7,
    branchDip: 1.4,
  }), [compact]);

  const graph = useMemo(() => buildGraph(config), [config]);
  const { nodes, edges } = graph;

  useEffect(() => {
    const t = setTimeout(() => setMounted(true), 80);
    return () => clearTimeout(t);
  }, []);

  useEffect(() => {
    if (!mounted) return;
    let last = performance.now();
    const loop = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;

      setParticles((prev) =>
        prev
          .map((p) => ({ ...p, t: p.t + p.speed * dt }))
          .filter((p) => p.t <= 1.05),
      );

      if (connected && now - lastSpawnRef.current > 420) {
        lastSpawnRef.current = now;
        const pool = alerts.length > 0 ? alerts : [];
        if (pool.length > 0) {
          alertIdxRef.current = (alertIdxRef.current + 1) % pool.length;
          const alert = pool[alertIdxRef.current];
          const edge = pickEdgeForAlert(alert, edges);
          if (edge) {
            const np: FlowParticle = {
              id: `${alert.id}-${now}-${Math.random().toString(36).slice(2, 6)}`,
              edge,
              t: 0,
              speed: 0.22 + Math.random() * 0.12,
              severity: alert.severity || 'info',
              born: now,
            };
            setParticles((prev) => [...prev, np].slice(-24));
          }
        }
      }
      rafRef.current = requestAnimationFrame(loop);
    };
    rafRef.current = requestAnimationFrame(loop);
    return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current); };
  }, [mounted, connected, alerts, edges]);

  const reduced = usePrefersReducedMotion();

  return (
    <div className="relative w-full" style={{ aspectRatio: `${VIEW_W} / ${VIEW_H}` }}>
      <svg
        viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
        className="absolute inset-0 h-full w-full"
        role="img"
        aria-label="Live pipeline topology: alerts flow ingested to classified to enriched to reasoned to done, with a low-severity skip branch bypassing enrichment."
      >
        <defs>
          <filter id="particle-glow" x="-200%" y="-200%" width="500%" height="500%">
            <feGaussianBlur stdDeviation="3.5" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <filter id="node-glow" x="-100%" y="-100%" width="300%" height="300%">
            <feGaussianBlur stdDeviation="8" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <linearGradient id="edge-main" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#2563EB" stopOpacity="0.8" />
            <stop offset="50%" stopColor="#D97706" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#16A34A" stopOpacity="0.8" />
          </linearGradient>
          <linearGradient id="edge-base" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#1D242C" />
            <stop offset="100%" stopColor="#2A323C" />
          </linearGradient>
        </defs>

        {/* floor grid */}
        <FloorGrid config={config} />

        {/* base edges (conduits) */}
        {edges.map((e, i) => (
          <g key={`edge-group-${i}`}>
            <path
              d={edgePath(e, config.scale, config.cx, config.cy)}
              fill="none"
              stroke={e.branch === 'skip' ? 'rgba(91,102,114,0.3)' : 'url(#edge-base)'}
              strokeWidth={e.branch === 'skip' ? 1.5 : 3}
              strokeDasharray={e.branch === 'skip' ? '5 4' : undefined}
              opacity={mounted ? (e.branch === 'skip' ? 0.6 : 0.8) : 0}
              style={{ transition: `opacity 600ms ${200 + i * 120}ms ease-out` }}
            />
            {/* animated conduit pulse overlay */}
            {e.branch === 'main' && (
              <path
                d={edgePath(e, config.scale, config.cx, config.cy)}
                fill="none"
                stroke="url(#edge-main)"
                strokeWidth={2}
                strokeDasharray="12 24"
                className="animate-beam-scan"
                opacity={mounted ? 0.6 : 0}
              />
            )}
          </g>
        ))}

        {/* nodes — rendered back to front */}
        {[...nodes].sort((a, b) => a.screen.x - b.screen.x).map((node, i) => (
          <NodeBlock
            key={node.id}
            node={node}
            config={config}
            mounted={mounted}
            delay={300 + i * 140}
            reduced={reduced}
            isHovered={hoveredNode === node.id}
            onHover={(h) => setHoveredNode(h ? node.id : null)}
          />
        ))}

        {/* flowing particles with comet tail */}
        {particles.map((p) => {
          const pos = pointOnEdge(p.edge, Math.min(1, p.t));
          const posPrev = pointOnEdge(p.edge, Math.max(0, p.t - 0.04));
          const screen = isoProject(pos, config.scale, config.cx, config.cy);
          const screenPrev = isoProject(posPrev, config.scale, config.cx, config.cy);
          const fadeIn = Math.min(1, (performance.now() - p.born) / 120);
          const fadeOut = p.t > 0.85 ? 1 - (p.t - 0.85) / 0.2 : 1;
          const opacity = Math.max(0, Math.min(fadeIn, fadeOut));
          const [r, g, b] = SEVERITY_RGB[p.severity];
          return (
            <g key={p.id} style={{ opacity }}>
              {/* comet tail */}
              <line
                x1={screenPrev.x}
                y1={screenPrev.y}
                x2={screen.x}
                y2={screen.y}
                stroke={`rgb(${r},${g},${b})`}
                strokeWidth={2.5}
                strokeLinecap="round"
                opacity={0.65}
              />
              <circle
                cx={screen.x}
                cy={screen.y}
                r={8}
                fill={severityGlow(p.severity, 0.22)}
                filter="url(#node-glow)"
              />
              <circle
                cx={screen.x}
                cy={screen.y}
                r={3.8}
                fill={`rgb(${r},${g},${b})`}
                filter="url(#particle-glow)"
              />
              <circle cx={screen.x} cy={screen.y} r={1.8} fill="#E6EAEE" opacity={0.95} />
            </g>
          );
        })}
      </svg>

      {/* node labels & hover interactive overlay */}
      <div className="absolute inset-0 pointer-events-none">
        {nodes.map((node, i) => {
          const leftPct = (node.screen.x / VIEW_W) * 100;
          const topPct = ((node.screen.y + 36) / VIEW_H) * 100;
          const count = countAtStage(alerts, node.id);
          const isHovered = hoveredNode === node.id;
          return (
            <div
              key={`label-${node.id}`}
              onMouseEnter={() => setHoveredNode(node.id)}
              onMouseLeave={() => setHoveredNode(null)}
              className={`absolute -translate-x-1/2 -translate-y-1/2 text-center transition-all duration-300 pointer-events-auto cursor-pointer ${
                isHovered ? 'scale-110 z-20' : 'z-10'
              }`}
              style={{
                left: `${leftPct}%`,
                top: `${topPct}%`,
                opacity: mounted ? 1 : 0,
                transitionDelay: `${450 + i * 140}ms`,
              }}
            >
              <div
                className={`font-mono text-[10px] font-semibold tracking-[0.16em] uppercase whitespace-nowrap px-2 py-0.5 rounded transition-colors ${
                  isHovered ? 'bg-raised text-ink border border-edge shadow-lg' : 'text-ink'
                }`}
              >
                {STAGE_LABELS[node.id]}
              </div>
              {!compact && (
                <div className={`font-mono text-[9px] mt-0.5 transition-colors ${isHovered ? 'text-ink font-semibold' : 'text-dim'}`}>
                  {count} in stage
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* skip-branch annotation */}
      {!compact && (
        <div
          className="pointer-events-none absolute font-mono text-[9px] tracking-wider text-dim transition-opacity duration-700"
          style={{
            left: '50%',
            top: '8%',
            transform: 'translateX(-50%)',
            opacity: mounted ? 0.85 : 0,
          }}
        >
          ◢ low-severity skip · enrichment bypassed
        </div>
      )}
    </div>
  );
}

function countAtStage(alerts: Alert[], stage: PipelineStage): number {
  return alerts.filter((a) => (a.status || a.stage || 'done') === stage).length;
}

function pickEdgeForAlert(alert: Alert, edges: GraphEdge[]): GraphEdge | null {
  const order: PipelineStage[] = ['ingested', 'classified', 'enriched', 'reasoned', 'done'];
  const st = (alert.status || alert.stage || 'done') as PipelineStage;
  const idx = order.indexOf(st);
  if (idx < 0 || idx >= order.length - 1) return null;
  const from = st;
  const to = order[idx + 1];
  if ((alert.branched || !alert.has_enrichment) && from === 'classified') {
    return edges.find((e) => e.branch === 'skip') ?? null;
  }
  return edges.find((e) => e.from === from && e.to === to && e.branch === 'main') ?? null;
}

interface NodeBlockProps {
  node: GraphNode;
  config: GraphConfig;
  mounted: boolean;
  delay: number;
  reduced: boolean;
  isHovered?: boolean;
  onHover?: (hovered: boolean) => void;
}

function NodeBlock({ node, config, mounted, delay, reduced, isHovered, onHover }: NodeBlockProps) {
  const lift = mounted ? (isHovered ? -8 : 0) : reduced ? 0 : 24;
  const top = nodePolygon(node.world, node.rx, node.ry, node.rz, config.scale, config.cx, config.cy);
  const walls = nodeWalls(node.world, node.rx, node.ry, node.rz, node.rz * 0.5, config.scale, config.cx, config.cy);
  const glow = STAGE_GLOW[node.id];
  const fill = STAGE_NODE_FILL[node.id];

  return (
    <g
      onMouseEnter={() => onHover?.(true)}
      onMouseLeave={() => onHover?.(false)}
      className="cursor-pointer"
      style={{
        transform: `translateY(${lift}px)`,
        opacity: mounted ? 1 : 0,
        transition: reduced
          ? 'opacity 200ms ease-out'
          : `transform ${isHovered ? '250ms' : '600ms'} ${isHovered ? '0ms' : delay + 'ms'} cubic-bezier(0.16,1,0.3,1), opacity 400ms ${delay}ms ease-out`,
      }}
    >
      <ellipse
        cx={node.screen.x}
        cy={node.screen.y + 6}
        rx={config.scale * node.rx * (isHovered ? 1.4 : 1.2)}
        ry={config.scale * node.rz * (isHovered ? 0.55 : 0.45)}
        fill="rgba(0,0,0,0.45)"
        opacity={0.7}
      />
      <ellipse
        cx={node.screen.x}
        cy={node.screen.y}
        rx={config.scale * node.rx * (isHovered ? 2.3 : 1.8)}
        ry={config.scale * node.rz * (isHovered ? 1.2 : 0.9)}
        fill={glow}
        filter="url(#node-glow)"
        opacity={mounted ? (isHovered ? 0.95 : 0.7) : 0}
        style={{ transition: `opacity 400ms ease-out` }}
      />
      {walls.map((w, j) => (
        <polygon
          key={j}
          points={w.face}
          fill={w.shade === 'left' ? (isHovered ? '#161F28' : '#0E1318') : (isHovered ? '#1C2632' : '#12181F')}
          stroke={isHovered ? '#3B82F6' : '#2A323C'}
          strokeWidth={isHovered ? '1' : '0.5'}
        />
      ))}
      <polygon points={top} fill={fill} stroke={isHovered ? '#60A5FA' : '#3A444F'} strokeWidth={isHovered ? '1.5' : '1'} />
      <polygon
        points={top}
        fill="none"
        stroke={node.id === 'done' ? 'rgba(22,163,74,0.8)' : isHovered ? 'rgba(59,130,246,0.8)' : 'rgba(91,102,114,0.4)'}
        strokeWidth={isHovered ? '1' : '0.5'}
      />
    </g>
  );
}

function FloorGrid({ config }: { config: GraphConfig }) {
  const paths: string[] = [];
  const points: { x: number; y: number }[] = [];

  for (let i = -4; i <= 4; i++) {
    const a = isoProject({ x: i, y: 0, z: -4 }, config.scale, config.cx, config.cy);
    const b = isoProject({ x: i, y: 0, z: 4 }, config.scale, config.cx, config.cy);
    paths.push(`M ${a.x.toFixed(1)} ${a.y.toFixed(1)} L ${b.x.toFixed(1)} ${b.y.toFixed(1)}`);
    const c = isoProject({ x: -4, y: 0, z: i }, config.scale, config.cx, config.cy);
    const d = isoProject({ x: 4, y: 0, z: i }, config.scale, config.cx, config.cy);
    paths.push(`M ${c.x.toFixed(1)} ${c.y.toFixed(1)} L ${d.x.toFixed(1)} ${d.y.toFixed(1)}`);

    for (let j = -4; j <= 4; j++) {
      if ((i + j) % 2 === 0) {
        const pt = isoProject({ x: i, y: 0, z: j }, config.scale, config.cx, config.cy);
        points.push(pt);
      }
    }
  }

  return (
    <g opacity={0.4}>
      {paths.map((p, i) => (
        <path key={`grid-line-${i}`} d={p} stroke="#1D242C" strokeWidth="0.5" />
      ))}
      {points.map((pt, i) => (
        <circle key={`grid-dot-${i}`} cx={pt.x} cy={pt.y} r={0.75} fill="#3A444F" opacity={0.6} />
      ))}
    </g>
  );
}

function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReduced(mq.matches);
    const handler = () => setReduced(mq.matches);
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, []);
  return reduced;
}
