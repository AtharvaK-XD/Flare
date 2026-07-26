import type { BenchmarkTier, EvalMetrics } from '@/types';

export const EVAL_METRICS: EvalMetrics = {
  precision: 0.943,
  recall: 0.918,
  f1: 0.930,
  accuracy: 0.951,
  confusion: {
    critical: { critical: 187, high: 9, medium: 2, low: 0, benign: 1 },
    high: { critical: 11, high: 312, medium: 14, low: 1, benign: 3 },
    medium: { critical: 1, high: 18, medium: 401, low: 21, benign: 12 },
    low: { critical: 0, high: 2, medium: 23, low: 528, benign: 31 },
    benign: { critical: 0, high: 1, medium: 9, low: 28, benign: 1102 },
  },
};

export const BENCHMARK_TIERS: BenchmarkTier[] = [
  {
    name: 'fast',
    label: 'Fast tier · flare-fast-v4',
    precision: 0.911,
    recall: 0.876,
    latency_p50_ms: 84,
    latency_p95_ms: 210,
    cost_per_1k: 0.42,
  },
  {
    name: 'quality',
    label: 'Quality tier · flare-quality-v3',
    precision: 0.962,
    recall: 0.941,
    latency_p50_ms: 920,
    latency_p95_ms: 2400,
    cost_per_1k: 4.80,
  },
];

export const BENCHMARK_AGREEMENT = 0.873;
