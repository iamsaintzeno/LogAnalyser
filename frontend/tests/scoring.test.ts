import { describe, expect, it } from 'vitest';
import type { ThreatEvent, ThreatType } from '../src/contracts';
import { WEIGHTS } from '../src/contracts';
import { analyzeEntries } from '../src/engine/analyze';
import { ratingForScore, scoreThreatEvents } from '../src/engine/score';

function threat(type: ThreatType, id: number): ThreatEvent {
  return {
    id: String(id),
    entryId: id,
    ip: '203.0.113.1',
    ts: id,
    type,
    ruleId: type,
    severity: 1,
    evidence: 'test',
  };
}

describe('risk scoring', () => {
  it('uses the contract weights once per event and caps score at 100', () => {
    expect(WEIGHTS).toEqual({
      SENSITIVE_PROBE: 30,
      SQLI: 25,
      TRAVERSAL: 25,
      SCANNER_UA: 15,
      BRUTE_FORCE: 15,
    });
    expect(scoreThreatEvents([threat('BRUTE_FORCE', 1), threat('SQLI', 2)])).toBe(40);
    expect(scoreThreatEvents(Array.from({ length: 5 }, (_, index) => threat('SENSITIVE_PROBE', index + 1)))).toBe(100);
  });

  it.each([
    [0, 'LOW'], [39, 'LOW'], [40, 'MEDIUM'], [59, 'MEDIUM'],
    [60, 'HIGH'], [79, 'HIGH'], [80, 'CRITICAL'], [100, 'CRITICAL'],
  ] as const)('maps score %i to %s', (score, rating) => {
    expect(ratingForScore(score)).toBe(rating);
  });
});

describe('analysis result construction', () => {
  it('preserves original input fields and caps flagged LogEntry rows at 20,000', () => {
    const entryCount = 20_001;
    const entries = Array.from({ length: entryCount }, (_, index) => ({
      id: index + 1,
      ip: '203.0.113.7',
      ts: 1_700_000_000_000 + index,
      method: 'GET',
      path: '/%2e%2e/private',
      query: 'from=%ZZ',
      proto: 'HTTP/1.1',
      status: 404,
      bytes: 10,
      referer: '',
      ua: '',
      raw: `source line ${index}`,
    }));
    const result = analyzeEntries(entries, {
      id: 'test-session',
      fileName: 'test.log',
      fileSize: 1_000,
      totalLines: entryCount,
      createdAt: 1_700_000_000_000,
      durationMs: 10,
    });

    expect(result.events).toHaveLength(entryCount);
    expect(result.entries).toHaveLength(20_000);
    expect(result.entries[0].path).toBe('/%2e%2e/private');
    expect(result.entries[0].query).toBe('from=%ZZ');
    expect(result.session.summaries[0].score).toBe(100);
    expect(result.session.threatCount).toBe(entryCount);
    expect(result.session.timeline.reduce((sum, bucket) => sum + bucket.total, 0)).toBe(entryCount);
  });
});
