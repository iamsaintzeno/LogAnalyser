import type { AttackerIPSummary, ThreatEvent, ThreatType, TimelineBucket } from '../contracts';
import { mockResult } from '../mock/mockResult';
import { useAnalyzerStore, type FilterState } from './useAnalyzerStore';

const THREAT_TYPES: ThreatType[] = [
  'BRUTE_FORCE',
  'SQLI',
  'TRAVERSAL',
  'SCANNER_UA',
  'SENSITIVE_PROBE',
];

function hasInvalidTimeRange(filters: FilterState): boolean {
  return filters.from !== null && filters.to !== null && filters.from > filters.to;
}

function isEventMatch(event: ThreatEvent, filters: FilterState): boolean {
  if (filters.types.length > 0 && !filters.types.includes(event.type)) return false;
  if (filters.ipQuery && !event.ip.toLowerCase().startsWith(filters.ipQuery.trim().toLowerCase())) return false;
  if (!hasInvalidTimeRange(filters)) {
    if (filters.from !== null && event.ts < filters.from) return false;
    if (filters.to !== null && event.ts > filters.to) return false;
  }
  return true;
}

export function selectSummariesFiltered(events: ThreatEvent[], filters: FilterState): AttackerIPSummary[] {
  const hasEventFilters = filters.types.length > 0 ||
    (!hasInvalidTimeRange(filters) && (filters.from !== null || filters.to !== null));
  const matchingIPs = hasEventFilters
    ? new Set(events.filter((event) => isEventMatch(event, filters)).map((event) => event.ip))
    : null;

  return mockResult.session.summaries.filter((summary) => {
    if (summary.score < filters.minScore) return false;
    if (filters.ipQuery && !summary.ip.toLowerCase().startsWith(filters.ipQuery.trim().toLowerCase())) return false;
    return matchingIPs === null || matchingIPs.has(summary.ip);
  });
}

export function selectTimeline(
  events: ThreatEvent[],
  filters: FilterState,
  bucketMs = 300_000,
): TimelineBucket[] {
  const buckets = new Map<number, TimelineBucket>();

  for (const event of events) {
    if (!isEventMatch(event, filters)) continue;
    const summary = mockResult.session.summaries.find((item) => item.ip === event.ip);
    if (!summary || summary.score < filters.minScore) continue;

    const t = Math.floor(event.ts / bucketMs) * bucketMs;
    const bucket = buckets.get(t) ?? {
      t,
      total: 0,
      byType: {
        BRUTE_FORCE: 0,
        SQLI: 0,
        TRAVERSAL: 0,
        SCANNER_UA: 0,
        SENSITIVE_PROBE: 0,
      },
    };
    bucket.byType[event.type] += 1;
    bucket.total += 1;
    buckets.set(t, bucket);
  }

  return [...buckets.values()].sort((left, right) => left.t - right.t);
}

export function selectThreatTypeCounts(events: ThreatEvent[]): Record<ThreatType, number> {
  const counts = Object.fromEntries(THREAT_TYPES.map((type) => [type, 0])) as Record<ThreatType, number>;
  for (const event of events) counts[event.type] += 1;
  return counts;
}

export function useFilteredData() {
  const filters = useAnalyzerStore((state) => state.filters);
  const events = useAnalyzerStore((state) => state.result?.events ?? mockResult.events);

  return {
    summaries: selectSummariesFiltered(events, filters),
    timeline: selectTimeline(events, filters),
  };
}
