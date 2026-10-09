import type { ThreatEvent, ThreatType } from '../contracts';
import {
  selectFilteredSummaries,
  selectFilteredTimeline,
} from '../../../src/store/selectors.ts';
import { useAnalyzerStore } from './useAnalyzerStore';

export function selectThreatTypeCounts(events: ThreatEvent[]): Record<ThreatType, number> {
  const counts: Record<ThreatType, number> = {
    BRUTE_FORCE: 0,
    SQLI: 0,
    TRAVERSAL: 0,
    SCANNER_UA: 0,
    SENSITIVE_PROBE: 0,
  };

  for (const event of events) counts[event.type] += 1;
  return counts;
}

export function useFilteredData() {
  const filters = useAnalyzerStore((state) => state.filters);
  const result = useAnalyzerStore((state) => state.result);

  if (!result) return { summaries: [], timeline: [] };

  return {
    summaries: selectFilteredSummaries(result.session.summaries, filters),
    timeline: selectFilteredTimeline(result.session.timeline, filters),
  };
}
