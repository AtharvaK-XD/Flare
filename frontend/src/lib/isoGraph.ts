import type { PipelineStage } from '@/types';

export interface IsoPoint { x: number; y: number; z: number; }

export interface GraphNode {
  id: PipelineStage;
  world: IsoPoint;
  screen: IsoPoint;
  rx: number;
  ry: number;
  rz: number;
  label: string;
  index: number;
}

export interface GraphEdge {
  from: PipelineStage;
  to: PipelineStage;
  branch: 'main' | 'skip';
  points: IsoPoint[];
}

const SQRT3_HALF = Math.sqrt(3) / 2;

export function isoProject(p: IsoPoint, scale = 1, cx = 0, cy = 0): IsoPoint {
  const sx = cx + scale * (p.x - p.z) * SQRT3_HALF;
  const sy = cy + scale * (p.y * 0.5 + (p.x + p.z) * 0.25);
  return { x: sx, y: sy, z: p.y * scale };
}

export interface GraphConfig {
  scale: number;
  cx: number;
  cy: number;
  nodeSize: number;
  nodeHeight: number;
  branchDip: number;
}

export const DEFAULT_GRAPH_CONFIG: GraphConfig = {
  scale: 1,
  cx: 0,
  cy: 0,
  nodeSize: 26,
  nodeHeight: 18,
  branchDip: 0.7,
};

export function buildGraph(config: GraphConfig = DEFAULT_GRAPH_CONFIG): {
  nodes: GraphNode[];
  edges: GraphEdge[];
  byStage: Record<PipelineStage, GraphNode>;
} {
  const { scale, cx, cy, nodeSize, nodeHeight, branchDip } = config;

  const stageWorld: Record<PipelineStage, IsoPoint> = {
    ingested: { x: -2.6, y: 0, z: 0 },
    classified: { x: -1.3, y: 0, z: 0 },
    enriched: { x: 0, y: 0, z: 0 },
    reasoned: { x: 1.3, y: 0, z: 0 },
    done: { x: 2.6, y: 0, z: 0 },
    failed: { x: 2.6, y: -1.2, z: 0 },
  };

  const labels: Record<PipelineStage, string> = {
    ingested: 'INGEST',
    classified: 'CLASSIFY',
    enriched: 'ENRICH',
    reasoned: 'REASON',
    done: 'DONE',
    failed: 'FAILED',
  };

  const order: PipelineStage[] = ['ingested', 'classified', 'enriched', 'reasoned', 'done'];

  const nodes: GraphNode[] = order.map((id, i) => {
    const world = stageWorld[id];
    const screen = isoProject(world, scale, cx, cy);
    return {
      id,
      world,
      screen,
      rx: nodeSize,
      ry: nodeSize,
      rz: nodeHeight,
      label: labels[id],
      index: i,
    };
  });

  const byStage = Object.fromEntries(nodes.map((n) => [n.id, n])) as Record<PipelineStage, GraphNode>;

  const mainEdges: GraphEdge[] = [
    { from: 'ingested', to: 'classified', branch: 'main', points: [] },
    { from: 'classified', to: 'reasoned', branch: 'main', points: [] },
    { from: 'reasoned', to: 'done', branch: 'main', points: [] },
  ];

  const skipEdge: GraphEdge = {
    from: 'classified',
    to: 'reasoned',
    branch: 'skip',
    points: [],
  };

  for (const e of [...mainEdges, skipEdge]) {
    const a = byStage[e.from];
    const b = byStage[e.to];
    if (e.branch === 'skip') {
      const mid: IsoPoint = {
        x: (a.world.x + b.world.x) / 2,
        y: -branchDip,
        z: (a.world.z + b.world.z) / 2,
      };
      e.points = [
        { ...a.world },
        mid,
        { ...b.world },
      ];
    } else {
      e.points = [{ ...a.world }, { ...b.world }];
    }
  }

  return { nodes, edges: [...mainEdges, skipEdge], byStage };
}

export function lerp(a: number, b: number, t: number): number {
  return a + (b - a) * t;
}

export function bezier3(p0: IsoPoint, p1: IsoPoint, p2: IsoPoint, t: number): IsoPoint {
  const u = 1 - t;
  return {
    x: u * u * p0.x + 2 * u * t * p1.x + t * t * p2.x,
    y: u * u * p0.y + 2 * u * t * p1.y + t * t * p2.y,
    z: u * u * p0.z + 2 * u * t * p1.z + t * t * p2.z,
  };
}

export function pointOnEdge(edge: GraphEdge, t: number): IsoPoint {
  const pts = edge.points.map((p) => isoProject(p, 1, 0, 0));
  if (pts.length === 2) {
    return {
      x: lerp(pts[0].x, pts[1].x, t),
      y: lerp(pts[0].y, pts[1].y, t),
      z: lerp(pts[0].z, pts[1].z, t),
    };
  }
  return bezier3(pts[0], pts[1], pts[2], t);
}

export function nodePolygon(world: IsoPoint, rx: number, ry: number, rz: number, scale: number, cx: number, cy: number): string {
  const corners: IsoPoint[] = [
    { x: world.x - rx, y: world.y, z: world.z - rz },
    { x: world.x + rx, y: world.y, z: world.z - rz },
    { x: world.x + rx, y: world.y, z: world.z + rz },
    { x: world.x - rx, y: world.y, z: world.z + rz },
  ];
  const screen = corners.map((c) => isoProject(c, scale, cx, cy));
  return screen.map((p) => `${p.x.toFixed(2)},${p.y.toFixed(2)}`).join(' ');
}

export function nodeWalls(world: IsoPoint, rx: number, ry: number, rz: number, h: number, scale: number, cx: number, cy: number): { face: string; shade: 'left' | 'right' }[] {
  const base: IsoPoint[] = [
    { x: world.x - rx, y: world.y, z: world.z - rz },
    { x: world.x + rx, y: world.y, z: world.z - rz },
    { x: world.x + rx, y: world.y, z: world.z + rz },
    { x: world.x - rx, y: world.y, z: world.z + rz },
  ];
  const top: IsoPoint[] = base.map((c) => ({ x: c.x, y: c.y + h, z: c.z }));
  const sBase = base.map((c) => isoProject(c, scale, cx, cy));
  const sTop = top.map((c) => isoProject(c, scale, cx, cy));

  const leftFace = [sBase[3], sBase[0], sTop[0], sTop[3]];
  const rightFace = [sBase[0], sBase[1], sTop[1], sTop[0]];

  return [
    { face: leftFace.map((p) => `${p.x.toFixed(2)},${p.y.toFixed(2)}`).join(' '), shade: 'left' },
    { face: rightFace.map((p) => `${p.x.toFixed(2)},${p.y.toFixed(2)}`).join(' '), shade: 'right' },
  ];
}

export function edgePath(edge: GraphEdge, scale: number, cx: number, cy: number): string {
  const pts = edge.points.map((p) => isoProject(p, scale, cx, cy));
  if (pts.length === 2) {
    return `M ${pts[0].x.toFixed(2)} ${pts[0].y.toFixed(2)} L ${pts[1].x.toFixed(2)} ${pts[1].y.toFixed(2)}`;
  }
  return `M ${pts[0].x.toFixed(2)} ${pts[0].y.toFixed(2)} Q ${pts[1].x.toFixed(2)} ${pts[1].y.toFixed(2)} ${pts[2].x.toFixed(2)} ${pts[2].y.toFixed(2)}`;
}
