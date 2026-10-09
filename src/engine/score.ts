import type { ThreatType, RiskRating } from './types';
import { WEIGHTS, RATING_CUTOFFS } from './constants';

// FORMULA
//   typePoints(t) = n === 0 ? 0 : weight[t] * min(1 + 0.5 * log2(n), 2.5)   // n = events of that type
//   raw   = sum of typePoints over all 5 types
//   bonus = (exposed ? 10 : 0) + (takeover ? 20 : 0)
//           exposed  = a sensitive file / SQLi request returned 2xx
//           takeover = successful login right after a brute-force burst
//   score = clamp(round(raw + bonus), 0, 100)
// More hits give more points, but with diminishing returns (cap at 2.5x the weight).

export const THREAT_TYPES: readonly ThreatType[] = ['SENSITIVE_PROBE', 'SQLI', 'TRAVERSAL', 'SCANNER_UA', 'BRUTE_FORCE'];

export function ratingFor(score: number): RiskRating {
  if (score >= RATING_CUTOFFS.CRITICAL) return 'CRITICAL';
  if (score >= RATING_CUTOFFS.HIGH) return 'HIGH';
  if (score >= RATING_CUTOFFS.MEDIUM) return 'MEDIUM';
  return 'LOW';
}

function safeNum(x: unknown): number {
  return typeof x === 'number' && Number.isFinite(x) ? x : 0;
}

export function scoreIp(
  byType: Record<ThreatType, number>,
  flags: { exposed?: boolean; takeover?: boolean } = {},
  weights: Record<ThreatType, number> = WEIGHTS,
): { score: number; rating: RiskRating; breakdown: Record<ThreatType, number> } {
  const breakdown = { BRUTE_FORCE: 0, SQLI: 0, TRAVERSAL: 0, SCANNER_UA: 0, SENSITIVE_PROBE: 0 } as Record<ThreatType, number>;
  let raw = 0;
  for (const t of THREAT_TYPES) {
    const n = Math.max(0, safeNum(byType?.[t]));
    const w = safeNum(weights?.[t]);
    const pts = n === 0 ? 0 : w * Math.min(1 + 0.5 * Math.log2(n), 2.5);
    breakdown[t] = Math.round(pts * 100) / 100;
    raw += pts;
  }
  const bonus = (flags?.exposed ? 10 : 0) + (flags?.takeover ? 20 : 0);
  const score = Math.min(100, Math.max(0, Math.round(raw + bonus)));
  return { score, rating: ratingFor(score), breakdown };
}
