import type { ThreatEvent, ThreatType, AttackerIPSummary, TimelineBucket } from './types';
import { TIMELINE_BUCKET_MS } from './constants';
import { scoreIp, THREAT_TYPES } from './score';

export interface IpStat {
  total: number;
  first: number;
  last: number;
  exposed: boolean;
  takeover: boolean;
}

function emptyByType(): Record<ThreatType, number> {
  return { BRUTE_FORCE: 0, SQLI: 0, TRAVERSAL: 0, SCANNER_UA: 0, SENSITIVE_PROBE: 0 };
}

// Per-IP summaries. totals and first/last seen come from ALL entries of that IP (ipStats),
// threat counts come from events. Only IPs with at least one event are returned.
export function aggregate(
  events: ThreatEvent[],
  ipStats: Map<string, IpStat>,
  weights: Record<ThreatType, number>,
): AttackerIPSummary[] {
  const byIp = new Map<string, Record<ThreatType, number>>();
  for (const ev of events) {
    let bt = byIp.get(ev.ip);
    if (!bt) {
      bt = emptyByType();
      byIp.set(ev.ip, bt);
    }
    bt[ev.type]++;
  }

  const out: AttackerIPSummary[] = [];
  for (const [ip, byType] of byIp) {
    const st = ipStats.get(ip);
    const { score, rating, breakdown } = scoreIp(byType, { exposed: st?.exposed, takeover: st?.takeover }, weights);
    let mainThreat: ThreatType = THREAT_TYPES[0];
    let bestPts = -1;
    for (const t of THREAT_TYPES) {
      if (breakdown[t] > bestPts) {
        bestPts = breakdown[t];
        mainThreat = t;
      }
    }
    const threatHits = THREAT_TYPES.reduce((s, t) => s + byType[t], 0);
    out.push({
      ip,
      totalHits: st?.total ?? threatHits,
      threatHits,
      byType,
      mainThreat,
      score,
      rating,
      firstSeen: st?.first ?? 0,
      lastSeen: st?.last ?? 0,
    });
  }
  return out.sort((a, b) => b.score - a.score || b.threatHits - a.threatHits || (a.ip < b.ip ? -1 : 1));
}

// 5-minute buckets over events.
export function buildTimeline(events: ThreatEvent[]): TimelineBucket[] {
  const map = new Map<number, TimelineBucket>();
  for (const ev of events) {
    const t = Math.floor(ev.ts / TIMELINE_BUCKET_MS) * TIMELINE_BUCKET_MS;
    let b = map.get(t);
    if (!b) {
      b = { t, total: 0, byType: emptyByType() };
      map.set(t, b);
    }
    b.total++;
    b.byType[ev.type]++;
  }
  return [...map.values()].sort((a, b) => a.t - b.t);
}
