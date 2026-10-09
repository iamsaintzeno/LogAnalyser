import type {
  AttackerIPSummary,
  LogEntry,
  ParseResult,
  ThreatEvent,
  ThreatType,
  TimelineBucket,
} from '../contracts';

import type { FilterState } from './useAnalyzerStore';

export interface DashboardStatistics {
  totalLines: number;
  threatCount: number;
  criticalIpCount: number;
  peakAttackTime: number | null;
}

export interface SelectedIpEvidence {
  entries: LogEntry[];
  events: ThreatEvent[];
}

/**
 * Filter attacker summaries without mutating the original array.
 *
 * - Time filtering retains attackers whose activity overlaps the selected range.
 * - Threat-type filtering retains attackers with at least one matching threat.
 * - minScore uses the existing score; it never recalculates scores.
 * - ipQuery uses case-insensitive partial matching.
 */
export function selectFilteredSummaries(
  summaries: AttackerIPSummary[],
  filters: FilterState,
): AttackerIPSummary[] {
  const query = filters.ipQuery.trim().toLowerCase();

  return summaries.filter((summary) => {
    if (summary.score < filters.minScore) {
      return false;
    }

    if (query && !summary.ip.toLowerCase().includes(query)) {
      return false;
    }

    if (
      filters.from !== null &&
      summary.lastSeen < filters.from
    ) {
      return false;
    }

    if (
      filters.to !== null &&
      summary.firstSeen > filters.to
    ) {
      return false;
    }

    if (filters.types.length > 0) {
      const hasMatchingThreat = filters.types.some(
        (type) => summary.byType[type] > 0,
      );

      if (!hasMatchingThreat) {
        return false;
      }
    }

    return true;
  });
}

/**
 * Filter timeline buckets using only information represented by each bucket.
 *
 * IP and risk-score filtering are intentionally not supported because the
 * aggregated buckets do not contain per-IP or per-risk information.
 */
export function selectFilteredTimeline(
  timeline: TimelineBucket[],
  filters: FilterState,
): TimelineBucket[] {
  return timeline
    .filter((bucket) => {
      if (filters.from !== null && bucket.t + 300_000 <= filters.from) {
        return false;
      }

      if (filters.to !== null && bucket.t > filters.to) {
        return false;
      }

      return true;
    })
    .map((bucket) => {
      if (filters.types.length === 0) {
        return { ...bucket, byType: { ...bucket.byType } };
      }

      const byType = { ...bucket.byType };

      for (const type of Object.keys(byType) as ThreatType[]) {
        if (!filters.types.includes(type)) {
          byType[type] = 0;
        }
      }

      const total = filters.types.reduce(
        (sum, type) => sum + bucket.byType[type],
        0,
      );

      return { ...bucket, total, byType };
    });
}

/**
 * Calculate dashboard statistics from the provided summaries and timeline.
 * Pass filtered summaries and timeline for filter-aware statistics.
 */
export function selectDashboardStatistics(
  result: ParseResult,
  summaries: AttackerIPSummary[] = result.session.summaries,
  timeline: TimelineBucket[] = result.session.timeline,
): DashboardStatistics {
  let peakAttackTime: number | null = null;
  let peakCount = -1;

  for (const bucket of timeline) {
    if (bucket.total > peakCount) {
      peakCount = bucket.total;
      peakAttackTime = bucket.t;
    }
  }

  return {
    totalLines: result.session.totalLines,
    threatCount: result.session.threatCount,
    criticalIpCount: summaries.filter(
      (summary) => summary.rating === 'CRITICAL',
    ).length,
    peakAttackTime,
  };
}

/**
 * Return evidence associated with the selected IP.
 * Entries remain limited to those provided by ParseResult.
 */
export function selectSelectedIpEvidence(
  result: ParseResult | null,
  selectedIp: string | null,
): SelectedIpEvidence {
  if (!result || !selectedIp) {
    return { entries: [], events: [] };
  }

  return {
    entries: result.entries.filter((entry) => entry.ip === selectedIp),
    events: result.events.filter((event) => event.ip === selectedIp),
  };
}

/**
 * Select eligible blocklist candidates.
 *
 * Candidate eligibility is independent of blocklistSelection.
 * Allowlisted IPs are always excluded.
 */
export function selectBlocklistCandidates(
  summaries: AttackerIPSummary[],
  minScore: number,
  allowIps: string[],
): AttackerIPSummary[] {
  const allowlist = new Set(allowIps);

  return summaries.filter(
    (summary) =>
      summary.score >= minScore && !allowlist.has(summary.ip),
  );
}