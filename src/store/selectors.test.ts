import { describe, it, expect } from 'vitest';

import {
  selectFilteredSummaries,
  selectFilteredTimeline,
  selectDashboardStatistics,
  selectSelectedIpEvidence,
  selectBlocklistCandidates,
} from './selectors';

import type {
  AttackerIPSummary,
  ParseResult,
  ThreatType,
  TimelineBucket,
} from '../contracts';

import type { FilterState } from './useAnalyzerStore';

// Test data helper
function createSummary(
  ip: string,
  score: number,
  rating: AttackerIPSummary['rating'] = 'HIGH',
): AttackerIPSummary {
  return {
    ip,
    totalHits: 100,
    threatHits: 20,
    byType: {
      BRUTE_FORCE: 5,
      SQLI: 5,
      TRAVERSAL: 5,
      SCANNER_UA: 3,
      SENSITIVE_PROBE: 2,
    },
    mainThreat: 'SQLI',
    score,
    rating,
    firstSeen: 1000,
    lastSeen: 5000,
  };
}

const defaultFilters: FilterState = {
  types: [],
  from: null,
  to: null,
  minScore: 0,
  ipQuery: '',
};

describe('selectFilteredSummaries', () => {
  const summaries = [
    createSummary('192.168.1.10', 59),
    createSummary('192.168.1.20', 60),
    createSummary('10.0.0.5', 80),
  ];

  it('includes summaries whose score equals the minimum', () => {
    const result = selectFilteredSummaries(summaries, {
      ...defaultFilters,
      minScore: 60,
    });

    expect(result.map((item) => item.score)).toEqual([60, 80]);
  });

  it('filters IP addresses using case-insensitive partial matching', () => {
    const result = selectFilteredSummaries(summaries, {
      ...defaultFilters,
      ipQuery: '192.168',
    });

    expect(result.map((item) => item.ip)).toEqual([
      '192.168.1.10',
      '192.168.1.20',
    ]);
  });

  it('filters summaries by threat type', () => {
    const result = selectFilteredSummaries(summaries, {
      ...defaultFilters,
      types: ['SQLI'] as ThreatType[],
    });

    expect(result).toHaveLength(3);
  });

  it('returns an empty array when no summaries match', () => {
    const result = selectFilteredSummaries(summaries, {
      ...defaultFilters,
      minScore: 100,
    });

    expect(result).toEqual([]);
  });
});

describe('selectFilteredTimeline', () => {
  const timeline: TimelineBucket[] = [
    {
      t: 0,
      total: 10,
      byType: {
        BRUTE_FORCE: 2,
        SQLI: 3,
        TRAVERSAL: 1,
        SCANNER_UA: 2,
        SENSITIVE_PROBE: 2,
      },
    },
    {
      t: 300_000,
      total: 20,
      byType: {
        BRUTE_FORCE: 5,
        SQLI: 5,
        TRAVERSAL: 5,
        SCANNER_UA: 3,
        SENSITIVE_PROBE: 2,
      },
    },
  ];

  it('filters timeline buckets by time range', () => {
    const result = selectFilteredTimeline(timeline, {
      ...defaultFilters,
      from: 300_000,
      to: 599_999,
    });

    expect(result.map((bucket) => bucket.t)).toEqual([300_000]);
  });

  it('does not mutate the original timeline', () => {
    const original = structuredClone(timeline);

    selectFilteredTimeline(timeline, {
      ...defaultFilters,
      types: ['SQLI'],
    });

    expect(timeline).toEqual(original);
  });
});

describe('selectDashboardStatistics', () => {
  it('calculates critical IP count and peak attack time', () => {
    const critical = createSummary('192.168.1.10', 90, 'CRITICAL');
    const high = createSummary('192.168.1.20', 70, 'HIGH');

    const result = {
      session: {
        id: 'session-1',
        fileName: 'sample.log',
        fileSize: 1000,
        createdAt: 1000,
        totalLines: 100,
        parsedLines: 95,
        skippedLines: 5,
        threatCount: 20,
        durationMs: 500,
        summaries: [critical, high],
        timeline: [],
      },
      events: [],
      entries: [],
    } satisfies ParseResult;

    const timeline: TimelineBucket[] = [
      {
        t: 0,
        total: 5,
        byType: {
          BRUTE_FORCE: 1,
          SQLI: 1,
          TRAVERSAL: 1,
          SCANNER_UA: 1,
          SENSITIVE_PROBE: 1,
        },
      },
      {
        t: 300_000,
        total: 10,
        byType: {
          BRUTE_FORCE: 2,
          SQLI: 2,
          TRAVERSAL: 2,
          SCANNER_UA: 2,
          SENSITIVE_PROBE: 2,
        },
      },
    ];

    const stats = selectDashboardStatistics(
      result,
      [critical, high],
      timeline,
    );

    expect(stats.totalLines).toBe(100);
    expect(stats.threatCount).toBe(20);
    expect(stats.criticalIpCount).toBe(1);
    expect(stats.peakAttackTime).toBe(300_000);
  });
});

describe('selectSelectedIpEvidence', () => {
  it('returns only entries and events belonging to the selected IP', () => {
    const result = {
      entries: [
        { ip: '192.168.1.10' },
        { ip: '192.168.1.20' },
      ],
      events: [
        { ip: '192.168.1.10' },
        { ip: '192.168.1.20' },
      ],
    } as unknown as ParseResult;

    const evidence = selectSelectedIpEvidence(
      result,
      '192.168.1.10',
    );

    expect(evidence.entries).toHaveLength(1);
    expect(evidence.entries[0].ip).toBe('192.168.1.10');

    expect(evidence.events).toHaveLength(1);
    expect(evidence.events[0].ip).toBe('192.168.1.10');
  });

  it('returns empty arrays when no IP is selected', () => {
    expect(selectSelectedIpEvidence(null, null)).toEqual({
      entries: [],
      events: [],
    });
  });
});

describe('selectBlocklistCandidates', () => {
  const summaries = [
    createSummary('192.168.1.10', 59),
    createSummary('192.168.1.20', 60),
    createSummary('10.0.0.5', 80),
  ];

  it('includes candidates at or above the minimum score', () => {
    const result = selectBlocklistCandidates(summaries, 60, []);

    expect(result.map((item) => item.ip)).toEqual([
      '192.168.1.20',
      '10.0.0.5',
    ]);
  });

  it('excludes allowlisted IP addresses', () => {
    const result = selectBlocklistCandidates(
      summaries,
      60,
      ['192.168.1.20'],
    );

    expect(result.map((item) => item.ip)).toEqual(['10.0.0.5']);
  });

  it('does not modify the original summaries', () => {
    const original = structuredClone(summaries);

    selectBlocklistCandidates(summaries, 60, ['10.0.0.5']);

    expect(summaries).toEqual(original);
  });
});