import type { ThreatType, TimelineBucket } from '../contracts';

const FIVE_MINUTES = 5 * 60_000;
const THIRTY_MINUTES = 30 * 60_000;
const MAX_BUCKETS = 2_000;
const THREAT_TYPES: ThreatType[] = [
  'BRUTE_FORCE',
  'SQLI',
  'TRAVERSAL',
  'SCANNER_UA',
  'SENSITIVE_PROBE',
];

export function needsThirtyMinuteBuckets(buckets: TimelineBucket[]): boolean {
  if (buckets.length < 2) return false;
  let firstTime = buckets[0].t;
  let lastTime = buckets[0].t;
  for (const bucket of buckets) {
    firstTime = Math.min(firstTime, bucket.t);
    lastTime = Math.max(lastTime, bucket.t);
  }
  return Math.floor((lastTime - firstTime) / FIVE_MINUTES) + 1 > MAX_BUCKETS;
}

function emptyCounts(): Record<ThreatType, number> {
  return {
    BRUTE_FORCE: 0,
    SQLI: 0,
    TRAVERSAL: 0,
    SCANNER_UA: 0,
    SENSITIVE_PROBE: 0,
  };
}

function bucketCount(start: number, end: number, step: number): number {
  return Math.floor((end - start) / step) + 1;
}

function mergeToThirtyMinutes(buckets: TimelineBucket[]): Map<number, TimelineBucket> {
  const merged = new Map<number, TimelineBucket>();

  for (const bucket of buckets) {
    const t = Math.floor(bucket.t / THIRTY_MINUTES) * THIRTY_MINUTES;
    const target = merged.get(t) ?? { t, total: 0, byType: emptyCounts() };
    for (const type of THREAT_TYPES) target.byType[type] += bucket.byType[type];
    target.total = Object.values(target.byType).reduce((sum, count) => sum + count, 0);
    merged.set(t, target);
  }

  return merged;
}

export function fillGaps(buckets: TimelineBucket[]): TimelineBucket[] {
  if (buckets.length === 0) return [];

  const sorted = [...buckets].sort((left, right) => left.t - right.t);
  const firstTime = sorted[0].t;
  const lastTime = sorted[sorted.length - 1].t;
  const fiveMinuteCount = bucketCount(firstTime, lastTime, FIVE_MINUTES);
  const step = fiveMinuteCount > MAX_BUCKETS ? THIRTY_MINUTES : FIVE_MINUTES;
  const source = step === THIRTY_MINUTES
    ? mergeToThirtyMinutes(sorted)
    : new Map(sorted.map((bucket) => [bucket.t, bucket]));
  const start = step === THIRTY_MINUTES
    ? Math.floor(firstTime / step) * step
    : firstTime;
  const end = step === THIRTY_MINUTES
    ? Math.floor(lastTime / step) * step
    : lastTime;
  const count = Math.min(bucketCount(start, end, step), MAX_BUCKETS);
  const result: TimelineBucket[] = [];

  for (let index = 0; index < count; index += 1) {
    const t = start + index * step;
    result.push(source.get(t) ?? { t, total: 0, byType: emptyCounts() });
  }

  return result;
}
