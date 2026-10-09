import type { AttackerIPSummary, RiskRating, TimelineBucket } from '../contracts';

export interface PeakBucket {
  bucket: TimelineBucket;
  eventCount: number;
}

export function getPeakBucket(timeline: TimelineBucket[]): PeakBucket | null {
  let peak: PeakBucket | null = null;

  for (const bucket of timeline) {
    const eventCount = Object.values(bucket.byType).reduce((total, count) => total + count, 0);
    if (eventCount > 0 && (!peak || eventCount > peak.eventCount)) {
      peak = { bucket, eventCount };
    }
  }

  return peak;
}

export function countByRating(summaries: AttackerIPSummary[]): Record<RiskRating, number> {
  const counts: Record<RiskRating, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
  };

  for (const summary of summaries) counts[summary.rating] += 1;
  return counts;
}

export function countUniqueThreatIPs(summaries: AttackerIPSummary[]): number {
  return new Set(summaries.filter((summary) => summary.threatHits > 0).map((summary) => summary.ip)).size;
}
